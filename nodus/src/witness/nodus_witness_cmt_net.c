/**
 * @file nodus_witness_cmt_net.c
 * @brief The transport glue for `cmt_conr_t` / `cmt_memr_t` over the
 *        witness TCP mesh. Contract and every file:line:
 *        nodus_witness_cmt_net.h.
 *
 * Delta 1 (ORCHESTRATOR-verified, re-verified here): two things a first
 * pass over this file reported as unresolved QUESTIONS are answered —
 *   1. `stop_peer_for_error` DOES have a disconnect path: the server
 *      owns the witness listener's TCP handle (`nodus_server.h:408`
 *      `nodus_tcp_t witness_tcp;`, wired at `nodus_server.c:6038-6050`),
 *      reachable from here as `net->w->server->witness_tcp` — the same
 *      handle `w->server->identity.sk` already reaches through `w->server`.
 *      `nodus_tcp_disconnect(tcp, conn)` calls `tcp->on_disconnect(conn,
 *      tcp->cb_ctx)` SYNCHRONOUSLY before freeing the connection
 *      (`nodus_tcp.c:1396-1399`); the witness port's `on_disconnect` is
 *      `on_witness_disconnect` (`nodus_server.c:5049-5055`,
 *      `cb_ctx = srv`), which calls `nodus_witness_peer_conn_closed(w,
 *      conn)`; that function scans `w->peers[]` for the matching `conn`
 *      and sets `.conn = NULL; .identified = false;`
 *      (`nodus_witness_peer.c:1899-1908`). So calling
 *      `nodus_tcp_disconnect` here really does clear the SAME peer slot
 *      the next tick's scan reads — verified by reading the chain, not
 *      assumed.
 *   2. `net_memr_peer_height` DOES have a public accessor: `cmt_conr_t`
 *      (`cmt_conr.h:484-504`) carries a public `cmt_conr_peer_slot_t
 *      *peers` (`:496`), and `cmt_conr_peer_slot_t` (`:449-469`) carries
 *      public `bool in_set` (`:452`) and `cmt_ps_t ps` (`:455`); reading
 *      `cmt_ps_get_height(&net->conr->peers[idx].ps)` (`cmt_ps.h:335`)
 *      is the reference's `peer.Get(PeerStateKey).(PeerState).
 *      GetHeight()` (mempool/reactor.go:212-230) with "no PeerState
 *      yet" answered by `!in_set`.
 */

#include "witness/nodus_witness_cmt_net.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/nodus_sign.h"       /* nodus_random */
#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_mem.h"            /* CMT_MEM_CHANNEL */
#include "dnac/cmt_part_set.h"       /* CMT_BLOCK_PART_SIZE_BYTES */
#include "server/nodus_server.h"     /* w->server->identity.sk, w->server->witness_tcp */
#include "transport/nodus_tcp.h"     /* nodus_tcp_send, nodus_tcp_disconnect */

#define LOG_TAG "W_CMTNET"

/* The header's "PEER SLOT" section (nodus_witness_cmt_net.h:30-36)
 * asserts one shared index space across all three peer tables — this
 * glue never re-numbers a slot when it crosses from `w->peers[]` to
 * `cmt_conr_t.peers[]` / `cmt_memr_t`'s peer table, so the three arrays
 * MUST be the same size or a valid `w->peers[]` index could run past
 * the end of one of the reactor arrays. cmt_mem.h:254 already pins
 * CMT_MEM_MAX_PEERS to the literal 128, not to NODUS_T3_MAX_WITNESSES;
 * pin both reactor macros against THIS module's own index space here,
 * where a future change to either constant would actually be caught. */
_Static_assert((int)CMT_CONR_MAX_PEERS == (int)NODUS_T3_MAX_WITNESSES,
               "cmt_conr's peer table size drifted from NODUS_T3_MAX_WITNESSES");
_Static_assert((int)CMT_MEM_MAX_PEERS == (int)NODUS_T3_MAX_WITNESSES,
               "cmt_memr's peer table size drifted from NODUS_T3_MAX_WITNESSES");

/* ══════════════════════════════════════════════════════════════════════
 * Small helpers
 * ══════════════════════════════════════════════════════════════════════ */

/* Forward declaration: net_send (item D) needs net_slot_up before that
 * predicate's own definition, further down with net_scan_peers. One
 * predicate, three call sites (the scan, the receive lookup's
 * classifier, and this one) — see net_slot_up's doc comment for why. */
static bool net_slot_up(const nodus_cmt_net_t *net, int i);

/**
 * nodus_witness_bft.c's generate_nonce() (~:930) is `static` to that
 * file, so this is the glue's own copy of the same CRITICAL-3 rule:
 * abort rather than fall back to a weak nonce source. The nonce is an
 * envelope field only, informational, and never a consensus input.
 */
static uint64_t net_generate_nonce(void)
{
    uint64_t nonce;

    if (nodus_random((uint8_t *)&nonce, sizeof(nonce)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "FATAL: cannot generate secure nonce");
        abort();
    }
    return nonce;
}

/** Channel id -> verb (D-16 rev 5's mapping, the four CONR channel-id
 *  macros from cmt_ps.h:152-158 and CMT_MEM_CHANNEL from cmt_mem.h:231
 *  — never a bare literal). 0 is "not one of ours", the same convention
 *  nodus_t3_method_to_type uses. */
static nodus_t3_msg_type_t net_channel_to_type(uint8_t channel_id)
{
    switch (channel_id) {
        case CMT_CONR_STATE_CHANNEL:         return NODUS_T3_CMT_STATE;
        case CMT_CONR_DATA_CHANNEL:          return NODUS_T3_CMT_DATA;
        case CMT_CONR_VOTE_CHANNEL:          return NODUS_T3_CMT_VOTE;
        case CMT_CONR_VOTE_SET_BITS_CHANNEL: return NODUS_T3_CMT_VOTE_SET_BITS;
        case CMT_MEM_CHANNEL:                return NODUS_T3_CMT_TXS;
        default:                             return (nodus_t3_msg_type_t)0;
    }
}

/** `net->now`, re-wrapped so the reactor's `host_ctx` (== `net`) reaches
 *  the ORIGINAL callback's own ctx (`net->now_ctx`), not `net` itself —
 *  cmt_conr_t calls `host.now(host_ctx, out)` (cmt_conr.c) and
 *  cmt_memr_t calls `host->now(host->ctx, out)` (cmt_memr.c); both end
 *  up here with ctx == net. */
static int net_now(void *ctx, cmt_time_t *out)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net || !net->now || !out) return CMT_FAULT;
    return net->now(net->now_ctx, out);
}

/** wh.cid = the derived 32-byte chain id (D-16 rev 5 F10) — NOT
 *  w->chain_id, the legacy witness header's field. wh.rnd / wh.vw are
 *  written 0 and never read (the same F10 rule).
 *  @return CMT_OK; CMT_FAULT if `now` is missing or fails (item H) — a
 *  failing clock is a node-local fault class, never silently stamped
 *  as a 0 timestamp on the wire. The caller (`net_send`) decides what
 *  a fault here means for the send; this function never guesses. */
static int net_fill_header(const nodus_cmt_net_t *net, nodus_t3_header_t *hdr)
{
    cmt_time_t t;

    memset(hdr, 0, sizeof(*hdr));
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round   = 0;
    hdr->view    = 0;
    memcpy(hdr->sender_id, net->w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(hdr->chain_id, net->w->v2_chain32, 32);
    if (!net->now || net->now(net->now_ctx, &t) != CMT_OK) {
        return CMT_FAULT;
    }
    hdr->timestamp = (uint64_t)(cmt_time_unix_nano(t) / (int64_t)1000000);
    hdr->nonce     = net_generate_nonce();
    return CMT_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * cmt_ps_send_fn / cmt_memr_host_t.send — ONE function, both tables.
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * p2p/peer.go:258-268 `Send` / `TrySend`: the reactor has already
 * marshalled the message (peer.go:277-280); this builds the T3
 * envelope around those bytes, signs and sends it synchronously.
 *
 * DEVIATION R3-A-1 (cmt_conr.h): the reference's `Send` blocks up to
 * `defaultSendTimeout` when the peer's send queue is full; `TrySend`
 * returns false at once. Neither row here blocks — the witness TCP
 * mesh (`nodus_tcp_send`) already buffers and flushes on the next
 * poll — so `send == try_send`, one function for both rows of both
 * host tables.
 */
static bool net_send(void *ctx, int peer_idx, uint8_t channel_id,
                     const uint8_t *bytes, size_t len)
{
    nodus_cmt_net_t     *net = (nodus_cmt_net_t *)ctx;
    nodus_t3_msg_type_t  type;
    nodus_t3_msg_t       msg;
    size_t               out_len = 0;

    if (!net || !net->w || peer_idx < 0 || peer_idx >= NODUS_T3_MAX_WITNESSES) {
        return false;
    }

    type = net_channel_to_type(channel_id);
    if (type == (nodus_t3_msg_type_t)0) {
        QGP_LOG_WARN(LOG_TAG, "send: unknown channel 0x%02x", channel_id);
        return false;
    }

    /* net_slot_up (item D), not `conn && identified` inline: the SAME
     * predicate the scan and the receive lookup's classifier use, so a
     * close_pending slot refuses a send too — one door for "is this
     * peer routable", not three that could drift apart. */
    if (!net_slot_up(net, peer_idx)) {
        return false;   /* peer not up — the reference's peer.IsRunning() == false */
    }

    if (!net->w->server) {
        /* No identity to sign with — a fixture or a startup ordering
         * defect, never a live witness (w->server is set before the
         * peer table exists). Guarded so this reads as a clean false,
         * not a NULL dereference of identity.sk below (delta 2). */
        QGP_LOG_WARN(LOG_TAG, "send: w->server is NULL, cannot sign");
        return false;
    }

    /* item I: `w->v2_chain32` is valid ONLY while `v2_successor` is true
     * (nodus_witness.h:1237-1239) and is explicitly ZEROED otherwise
     * (nodus_witness.c:755, nodus_witness_sync.c:311) — this glue must
     * NEVER derive the chain id itself (see the PRECONDITION in the
     * header); package C2a populates it from the stored genesis
     * document before nodus_cmt_net_init. A zero here means that
     * binding never ran — defense in depth, refused every time, warned
     * only once. */
    {
        static const uint8_t zero32[32] = { 0 };
        if (memcmp(net->w->v2_chain32, zero32, 32) == 0) {
            if (!net->warned_zero_chain32) {
                net->warned_zero_chain32 = true;
                QGP_LOG_WARN(LOG_TAG, "send: w->v2_chain32 is all-zero — "
                                     "the binding never populated it "
                                     "before nodus_cmt_net_init; refusing "
                                     "to sign an envelope with a zero "
                                     "derived chain id");
            }
            return false;
        }
    }

    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    if (net_fill_header(net, &msg.header) != CMT_OK) {
        /* item H: a failing clock is a node-local fault class, never a
         * silent 0 timestamp on the wire. */
        QGP_LOG_WARN(LOG_TAG, "send: net_fill_header failed (now() faulted)");
        return false;
    }
    msg.w_cmt.m     = bytes;    /* caller-owned for the duration of this call */
    msg.w_cmt.m_len = len;

    if (nodus_t3_encode(&msg, &net->w->server->identity.sk,
                        net->encode_buf, net->encode_cap, &out_len) != 0) {
        QGP_LOG_WARN(LOG_TAG, "send: nodus_t3_encode failed (type %d, len %zu)",
                     (int)type, len);
        return false;
    }

    return nodus_tcp_send(net->w->peers[peer_idx].conn, net->encode_buf,
                          out_len) == 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * stop_peer_for_error
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * p2p/switch.go:335-358 `StopPeerForError` -> `stopAndRemovePeer`
 * (:367-388). ITEM E CORRECTION: this glue's ORDER is a DEVIATION from
 * the reference, not a match to it — `stopAndRemovePeer`'s real order
 * is `sw.transport.Cleanup(peer)` (:368), THEN `peer.Stop()` (:369-371),
 * THEN the reactors' `RemovePeer` loop (:373-375, which is ALL that
 * span covers — not "the order"), THEN `sw.peers.Remove(peer)` (:381).
 * The reference tears the TRANSPORT down FIRST and the reactor tables
 * SECOND. This glue does the OPPOSITE — reactor tables HERE,
 * synchronously; the transport-side close DEFERRED to the next
 * `nodus_cmt_net_tick` (delta 6), never run from inside this call —
 * because a synchronous close here would use-after-free the connection
 * (below). This is a DOCUMENTED ORDER DEVIATION from :367-388, carried
 * as its own register row; do not read this function as reproducing
 * the reference's sequence.
 *
 * WHY DEFERRED (delta 6, a live-node defect, not a fixture artefact):
 * on the witness port this function is reached synchronously from
 * INSIDE `nodus_tcp`'s own frame-reading loop — server poll ->
 * `try_parse_frames` -> `tcp->on_frame` (`nodus_tcp.c:501-502`) ->
 * `on_witness_frame` -> `nodus_witness_dispatch_t3` ->
 * `nodus_cmt_net_receive` -> `cmt_conr_receive` -> this row. Calling
 * `nodus_tcp_disconnect` from here would run `on_disconnect` and then
 * `conn_free` (`nodus_tcp.c:1396-1401`), which `free()`s the connection
 * (`nodus_tcp.c:248`) — but AFTER `on_frame` returns, `try_parse_frames`
 * still reads `conn->channel_crypto.established` and then
 * `conn->rlen` / `memmove(conn->rbuf, …)` (`nodus_tcp.c:508-519`) to
 * keep parsing any remaining frames from the SAME read — a
 * USE-AFTER-FREE of the connection this function would just have
 * freed. `try_parse_frames` only knows a conn is gone via its OWN
 * `return true` paths (`nodus_tcp.c:394-405`); nothing on the witness
 * port disconnects from inside a frame callback today (grep: no
 * `nodus_tcp_disconnect` call in `nodus_witness*.c` before this
 * module) — this was new ground, not an existing pattern being
 * followed. The reference does not have this hazard: `StopPeerForError`
 * -> `stopAndRemovePeer` -> `peer.Stop()` / `MConnection.Stop()` tear
 * down asynchronously, on their OWN goroutines, never inside the
 * goroutine still reading the peer's socket — so the faithful
 * single-threaded equivalent is a deferred close, run from the
 * server's own tick, outside any `on_frame` callback (see
 * `nodus_cmt_net_tick`'s doc comment for the contract this places on
 * the caller).
 *
 * `nodus_witness_peer_conn_closed` — reached synchronously through
 * `nodus_tcp_disconnect`'s `on_disconnect` callback
 * (`nodus_tcp.c:1396-1399` -> `nodus_server.c:5049-5055`) — is what
 * NULLs `net->w->peers[peer_idx].conn` / `.identified`
 * (`nodus_witness_peer.c:1899-1908`) once the tick's close pass
 * actually runs the disconnect; this function does not also NULL them
 * itself, so there is exactly one writer of that field on this path.
 */
static void net_stop_peer(nodus_cmt_net_t *net, int peer_idx, int reason_code)
{
    if (!net || peer_idx < 0 || peer_idx >= NODUS_T3_MAX_WITNESSES) return;

    QGP_LOG_WARN(LOG_TAG,
                 "stop_peer_for_error: slot %d reason %d — clearing "
                 "reactor state now, closing the connection at the "
                 "next tick (delta 6: never from inside a frame "
                 "callback)",
                 peer_idx, reason_code);

    /* Tables first — a DEVIATION from switch.go's stopAndRemovePeer
     * (:367-388), which tears the transport down BEFORE the reactors'
     * RemovePeer loop (:373-375); see this function's doc comment. */
    if (net->conr) (void)cmt_conr_remove_peer(net->conr, peer_idx);
    if (net->memr) (void)cmt_memr_remove_peer(net->memr, peer_idx);
    net->slot_up[peer_idx]   = false;
    net->slot_conn[peer_idx] = NULL;

    /* The socket close is DEFERRED (delta 6) — see the doc comment
     * above. Capture which connection to close, in case a NEW
     * connection takes this slot before the tick's close pass runs
     * (net_scan_peers/net_slot_up keep the slot DOWN in the meantime,
     * regardless of conn/identified, so a fresh connection cannot be
     * mistaken for the one being closed). */
    net->close_conn[peer_idx]    = net->w ? net->w->peers[peer_idx].conn : NULL;
    net->close_pending[peer_idx] = true;
}

/** cmt_conr_host_t's row: reactor.go:239, :245, :266, :285's four call
 *  sites, each with the reference's own reason code. */
static void net_conr_stop_peer_for_error(void *ctx, int peer_idx, int reason_code)
{
    net_stop_peer((nodus_cmt_net_t *)ctx, peer_idx, reason_code);
}

/** cmt_memr_host_t's row: mempool/reactor.go:172's one call site — no
 *  reason code in the reference's signature, so 0. */
static void net_memr_stop_peer_for_error(void *ctx, int peer_slot)
{
    net_stop_peer((nodus_cmt_net_t *)ctx, peer_slot, 0);
}

/* ══════════════════════════════════════════════════════════════════════
 * BlockStore rows (cmt_conr_host_t only — cmt_memr_host_t has none)
 * ══════════════════════════════════════════════════════════════════════ */

/* nodus_witness_cmt_host.c's `host_bs_height` / `host_bs_load_block_commit`
 * / `host_bs_load_block_extended_commit` are `static` to that file (grep
 * evidence in the report) — no public handle exists to reach the cs
 * host's rows directly, so these are the glue's OWN thin rows over the
 * public store API (nodus_witness_cmt_store.h:253-312), duplicating the
 * SHAPE of host.c's forwarders but not their bodies (reported, not
 * copied). */

static int net_bs_base(void *ctx, int64_t *out)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net || !out) return CMT_FAULT;
    *out = nodus_cmt_bs_base(net->store);
    return CMT_OK;
}

static int net_bs_height(void *ctx, int64_t *out)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net || !out) return CMT_FAULT;
    *out = nodus_cmt_bs_height(net->store);
    return CMT_OK;
}

/** reactor.go:581-587 / :651-663's BlockID projection of LoadBlockMeta —
 *  the same projection cmt_conr.h:407-408 documents; cmt_cs.h's own row
 *  (`host_bs_load_block_meta`, host.c) projects the HEADER instead. Two
 *  projections of one BlockMeta, each named for what its reader takes. */
static int net_bs_load_block_meta_block_id(void *ctx, int64_t height,
                                           cmt_block_id_t *out, bool *out_found)
{
    nodus_cmt_net_t        *net = (nodus_cmt_net_t *)ctx;
    nodus_cmt_block_meta_t *meta;
    int                      rc;

    if (!net || !out || !out_found) return CMT_FAULT;
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (!meta) return CMT_FAULT;
    rc = nodus_cmt_bs_load_block_meta(net->store, height, meta, out_found);
    if (rc == CMT_OK && *out_found) {
        *out = meta->block_id;
    }
    free(meta);
    return rc;
}

/** reactor.go:664 LoadBlockPart. Storage contract (cmt_conr.h:410-417):
 *  `out->bytes` points at storage THIS row owns, valid until the next
 *  call of this same row — `part_arena`, reset here before every call,
 *  is exactly that storage. */
static int net_bs_load_block_part(void *ctx, int64_t height, int index,
                                  cmt_part_t *out, bool *out_found)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net || !out || !out_found) return CMT_FAULT;
    net->part_arena.used = 0;
    return nodus_cmt_bs_load_block_part(net->store, height, index,
                                        &net->part_arena, out, out_found);
}

/** reactor.go:756 LoadBlockCommit — the same row and storage contract
 *  as cmt_cs.h's (cmt_conr.h:419-422). `commit_sigs` is CMT_VALSET_MAX
 *  entries, the same cap the cs host's `host_bs_load_block_commit`
 *  uses (nodus_witness_cmt_host.c). */
static int net_bs_load_block_commit(void *ctx, int64_t height,
                                    cmt_commit_t *out, bool *out_found)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net) return CMT_FAULT;
    return nodus_cmt_bs_load_block_commit(net->store, height, net->commit_sigs,
                                          (size_t)CMT_VALSET_MAX, out, out_found);
}

/** reactor.go:754 LoadBlockExtendedCommit — same idiom, `ext_load_arena`
 *  reset before every call (nodus_witness_cmt_host.c's
 *  `host_bs_load_block_extended_commit` resets its own the same way). */
static int net_bs_load_block_extended_commit(void *ctx, int64_t height,
                                             cmt_extended_commit_t *out,
                                             bool *out_found)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net) return CMT_FAULT;
    net->ext_load_arena.used = 0;
    return nodus_cmt_bs_load_block_extended_commit(net->store, height,
                                                   net->ext_sigs,
                                                   (size_t)CMT_VALSET_MAX,
                                                   &net->ext_load_arena, out,
                                                   out_found);
}

/* ══════════════════════════════════════════════════════════════════════
 * cmt_memr_host_t.peer_height
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * `peer.Get(types.PeerStateKey).(PeerState).GetHeight()`
 * (mempool/reactor.go:212-230). The consensus reactor's own PeerState
 * (`cmt_conr_t.peers[idx].ps`, `cmt_conr.h:449-455`) is that PeerState —
 * one peer, one PeerState, shared by both reactors exactly as the
 * reference's single `p2p.Peer` carries one `PeerStateKey` value both
 * reactors read. `!in_set` (`:452`) is the reference's "no PeerState
 * yet" branch (:213-221): the height is then ignored by the caller
 * (cmt_memr.c), matching *out_known = false.
 */
static int64_t net_memr_peer_height(void *ctx, int peer_slot, bool *out_known)
{
    nodus_cmt_net_t *net = (nodus_cmt_net_t *)ctx;

    if (!net || !net->conr || peer_slot < 0 ||
        peer_slot >= NODUS_T3_MAX_WITNESSES ||
        !net->conr->peers[peer_slot].in_set) {
        if (out_known) *out_known = false;
        return 0;
    }
    if (out_known) *out_known = true;
    return cmt_ps_get_height(&net->conr->peers[peer_slot].ps);
}

/* ══════════════════════════════════════════════════════════════════════
 * The peer-set scan (delta 5: factored out of nodus_cmt_net_tick so
 * nodus_cmt_net_receive can run it too — see that function's doc
 * comment in the header for why).
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * ONE definition of "up" (delta 5 addendum, extended by delta 6). Used
 * by BOTH `net_scan_peers` (which slot gets added to the reactors) and
 * `nodus_cmt_net_receive`'s sender lookup (which slot a frame may be
 * routed from) — the SAME expression, not two call sites that happen
 * to agree today. Without this a slot that is `identified` but has
 * `conn == NULL` would be skipped by the scan (never `in_set`) yet
 * still matched by a lookup keyed on `identified` alone, routing into
 * an absent reactor slot — the identical "Peer has no state" fault
 * this delta's other half closes.
 *
 * Delta 6: a slot with `close_pending` is NEVER up, regardless of
 * `conn`/`identified` — it is quarantined until `nodus_cmt_net_tick`'s
 * close pass actually runs the deferred disconnect (or discovers a new
 * connection already took the slot). This is what stops a frame
 * arriving between the stop and the next tick from being routed into a
 * slot the reactors were just told to forget.
 */
static bool net_slot_up(const nodus_cmt_net_t *net, int i)
{
    if (net->close_pending[i]) return false;
    return net->w->peers[i].conn != NULL && net->w->peers[i].identified;
}

/**
 * ASCENDING index order — the only order this glue ever iterates the
 * peer table in (determinism). Assumes net / net->w / net->conr /
 * net->memr are already non-NULL; both callers check that first.
 */
static int net_scan_peers(nodus_cmt_net_t *net)
{
    int i;

    /* p2p/switch.go `OnStart` (:234-247) starts every reactor first
     * (:236-241, `reactor.Start()`) and only THEN starts
     * `go sw.acceptRoutine()` (:244), the goroutine that admits peers —
     * a peer can only be InitPeer'd/AddPeer'd once every reactor is
     * already running. `cmt_conr_add_peer` mirrors :192-193 exactly
     * (CMT_OK, `started` left false, cmt_conr.c:615-617) if called
     * early, but `cmt_conr_init_peer` does NOT check `running` at all
     * (cmt_conr.c:570-605) — it would still set `in_set = true`. Without
     * this guard the scan would record `slot_up[i] = true` for a slot
     * that is `in_set` with no gossip routines running, FOREVER (the
     * scan never retries a slot it already believes is up). Both fields
     * are public (cmt_conr.h:487, cmt_memr.h:265): a tick before both
     * reactors are started is a NO-OP for the peer set, no state
     * changed, so the very next tick after both start sees every
     * already-up slot as a fresh transition and adds it correctly. */
    if (!net->conr->running || !net->memr->running) return CMT_OK;

    for (i = 0; i < NODUS_T3_MAX_WITNESSES; i++) {
        const struct nodus_tcp_conn *conn_now = net->w->peers[i].conn;
        bool up_now    = net_slot_up(net, i);
        bool up_before = net->slot_up[i];
        int  rc;

        if (up_before && up_now && conn_now != net->slot_conn[i]) {
            /* A reconnect is a new peer (switch.go's Broadcast/AddPeer
             * discipline, cmt_conr.h): tear the old slot down first.
             * `cmt_memr_remove_peer` reclaims the mempool peer id
             * (cmt_mem_ids_reclaim, cmt_memr.c:351, ids.go's Reclaim) —
             * so re-adding below, after a reconnect, reserves a FRESH
             * id for the slot. That is the reference's own behaviour
             * (ids.go's ReserveForPeer always calls nextPeerID()), not
             * a shortcut this glue is taking. */
            (void)cmt_conr_remove_peer(net->conr, i);
            (void)cmt_memr_remove_peer(net->memr, i);
            up_before = false;
        }

        if (!up_before && up_now) {
            /* DELTA 8 — LIVE DEFECT FOUND BY THE GENESIS PROTOCOL
             * HARNESS AT PRODUCTION CONSTANTS: `cmt_memr_init_peer`
             * (mempool/reactor.go:50-53's `InitPeer`,
             * `memR.ids.ReserveForPeer(peer)`) was never called by
             * this glue — only `cmt_memr_add_peer` was. Without a
             * reservation `cmt_mem_ids_get_for_peer` answers 0 for
             * EVERY peer slot (cmt_mem.c:790-796, "the map's zero
             * value when absent"), which is also
             * `CMT_MEM_UNKNOWN_PEER_ID` — the reference reserves 0 for
             * exactly one sender: the RPC/CheckTx submitter itself
             * (mempool/ids.go:69, "reserve unknownPeerID(0) for
             * mempoolReactor.BroadcastTx"). A client-submitted tx is
             * stamped with sender id 0 on admission
             * (cmt_mem_tx_add_sender); `isSender` then reads true for
             * EVERY peer slot too (since every slot's id ALSO reads
             * 0), so `routine_pass`'s own sender check
             * (cmt_memr.c) refuses to gossip the tx to anyone — a
             * transaction submitted through the client lane on one
             * node was never broadcast to the fleet at all, only
             * included when that SAME node happened to be proposer
             * again. Fixed by reserving a real id, in the reference's
             * OWN loop order (switch.go:829-831 InitPeer for every
             * reactor, THEN :858-860 AddPeer for every reactor — not
             * interleaved per-reactor): conr init, memr init, conr
             * add, memr add. */
            rc = cmt_conr_init_peer(net->conr, i, net->w->peers[i].witness_id);
            if (rc == CMT_FAULT) return CMT_FAULT;
            rc = cmt_memr_init_peer(net->memr, i);
            if (rc == CMT_FAULT) return CMT_FAULT;
            rc = cmt_conr_add_peer(net->conr, i);
            if (rc == CMT_FAULT) return CMT_FAULT;
            /* Roster witnesses are peers this node ALWAYS dials — the
             * switch's PERSISTENT peers, is_persistent=true /
             * is_unconditional=false. Re-read cmt_memr.c:27-41
             * choose_semaphore after the first pass got this wrong:
             * when the persistent cap is 0 (the DEFAULT,
             * cmt_mem.c:41-42), the `> 0` term at :33-34 fails and the
             * peer falls through to the final `return
             * CMT_MEMR_SEM_NONE` at :41 — NO semaphore, the routine
             * starts at once. A zero cap is the reference's "no limit
             * configured" (mempool/reactor.go:98-99's
             * `…ToPersistentPeers > 0`), not a zero-capacity semaphore
             * that never admits anyone. is_unconditional is reserved
             * for peers the switch keeps regardless of any p2p
             * membership rule at all, which is not what a roster
             * witness is. */
            rc = cmt_memr_add_peer(net->memr, i, true, false);
            if (rc == CMT_FAULT) return CMT_FAULT;
        } else if (up_before && !up_now) {
            (void)cmt_conr_remove_peer(net->conr, i);
            (void)cmt_memr_remove_peer(net->memr, i);
        }

        net->slot_up[i]   = up_now;
        net->slot_conn[i] = conn_now;
    }
    return CMT_OK;
}

/**
 * DEFERRED CLOSE PASS (delta 6), ascending slot order, run from
 * `nodus_cmt_net_tick` BEFORE `net_scan_peers` so the scan sees the
 * cleared state in the SAME tick. `net_stop_peer` never closes the
 * socket itself — its doc comment has the full use-after-free citation
 * this avoids; this is where the close actually runs, from OUTSIDE any
 * `on_frame` callback (`nodus_cmt_net_tick`'s doc comment states the
 * caller contract this requires).
 *
 * RESIDUAL, DOCUMENTED, NOT FIXED (item K, outside this module's
 * whitelist — the real fix is a transport-side deferred-close API, a
 * later wave): this pass compares connection POINTERS, and within ONE
 * epoll batch a pointer can be reused. `handle_accept`
 * (nodus_tcp.c:716-770) calls `handle_read_fwd` on a freshly accepted
 * connection in the SAME poll iteration, and `conn_alloc` is a plain
 * per-connection `calloc(1, sizeof(*conn))` (nodus_tcp.c:172-179) — so
 * within one batch: old conn's bad frame -> stop (`close_conn = P`) ->
 * old conn's EOF read in the SAME `handle_read` -> `conn_free(P)` ->
 * `on_disconnect` NULLs the slot -> a NEW accept -> `calloc` returns P
 * again (a common allocator behaviour, not guaranteed, but plausible
 * and unguarded against) -> that connection's IDENT frame is parsed at
 * once -> the SAME witness re-occupies slot i with `conn == P`. The
 * next tick's close pass then sees `P == close_conn[i]` and disconnects
 * the NEW connection by mistake. Consequence: one spurious disconnect
 * of a peer that reconnected inside the same poll batch — the pointer
 * is live and owned at that moment, so this is NOT a use-after-free,
 * only a wrong-target disconnect; the peer reconnects on its own after.
 * Neither the transport (nodus_tcp.h) nor the witness peer table
 * (nodus_witness.h:476-500) carries a generation counter that would let
 * this pass distinguish "the same connection" from "a different
 * connection that happens to share an address".
 */
static void net_close_pass(nodus_cmt_net_t *net)
{
    int i;

    for (i = 0; i < NODUS_T3_MAX_WITNESSES; i++) {
        struct nodus_tcp_conn *conn;

        if (!net->close_pending[i]) continue;

        conn = net->w->peers[i].conn;
        if (conn != net->close_conn[i]) {
            /* Already gone (torn down some other way), or a NEW
             * connection already took this slot: the connection we
             * meant to close no longer occupies it, so there is
             * nothing left here to close. Leave the new conn alone —
             * net_scan_peers, run right after this pass, decides
             * whether it is a fresh peer. */
            net->close_pending[i] = false;
            net->close_conn[i]    = NULL;
            continue;
        }

        if (net->w->server) {
            /* The on_disconnect chain NULLs conn/identified for us
             * (nodus_witness_peer.c:1899-1908) — net_stop_peer's doc
             * comment: this module is not also a second writer of
             * those fields. */
            nodus_tcp_disconnect(&net->w->server->witness_tcp, conn);
            net->close_pending[i] = false;
            net->close_conn[i]    = NULL;
        } else {
            /* Fixture-only: a live witness always has w->server set
             * before its peer table exists (file header, delta 1), so
             * production never takes this branch. No real transport to
             * close through — the slot STAYS quarantined (net_slot_up
             * keeps refusing it) until a real server is bound. Logged
             * once per PASS over this slot, not deduplicated across
             * repeated tick calls: a fixture calling tick many times
             * with w->server still NULL sees this line every time. */
            QGP_LOG_WARN(LOG_TAG,
                         "tick: slot %d has a deferred close pending "
                         "but no server to close through — staying "
                         "quarantined", i);
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_net_init(nodus_cmt_net_t *net, nodus_witness_t *w,
                       nodus_cmt_store_t *store, cmt_now_fn now, void *now_ctx)
{
    if (!net || !w || !store || !now) return CMT_FAULT;

    memset(net, 0, sizeof(*net));
    net->w       = w;
    net->store   = store;
    net->now     = now;
    net->now_ctx = now_ctx;

    /* The two host tables — delta 3. Filled ONCE, here, directly into
     * the EMBEDDED fields (see nodus_cmt_net_t's doc comment in the
     * header for why cmt_memr_t's borrow forces this). `net` is already
     * fully zeroed above, so every row not set explicitly stays NULL. */
    net->conr_host.send                          = net_send;
    net->conr_host.try_send                      = net_send;  /* R3-A-1: identical */
    net->conr_host.stop_peer_for_error           = net_conr_stop_peer_for_error;
    net->conr_host.bs_base                       = net_bs_base;
    net->conr_host.bs_height                     = net_bs_height;
    net->conr_host.bs_load_block_meta_block_id   = net_bs_load_block_meta_block_id;
    net->conr_host.bs_load_block_part            = net_bs_load_block_part;
    net->conr_host.bs_load_block_commit          = net_bs_load_block_commit;
    net->conr_host.bs_load_block_extended_commit = net_bs_load_block_extended_commit;
    net->conr_host.now                           = net_now;

    net->memr_host.ctx                = (void *)net;
    net->memr_host.send                = net_send;
    net->memr_host.stop_peer_for_error = net_memr_stop_peer_for_error;
    net->memr_host.peer_height         = net_memr_peer_height;
    net->memr_host.now                 = net_now;

    /* ONE encode scratch buffer, sized to the largest of the five
     * classes (D-16 rev 5's "envelope overhead on top"). */
    net->encode_cap = nodus_t3_max_msg_size(NODUS_T3_CMT_TXS);
    net->encode_buf = (uint8_t *)malloc(net->encode_cap);

    /* The reactor's receive arena — sized to exactly one message
     * (NODUS_CMT_NET_RECV_ARENA_BYTES == CMT_CONR_MAX_MSG_SIZE, tied by
     * a _Static_assert in the .h file); cmt_conr_receive resets `.used`
     * to 0 at the top of every call, closing register R3-A-5 — see the
     * macro's comment for the exhaustion proof. Eagerly allocated, one
     * node one arena; a failure here fails nodus_cmt_net_init loudly
     * (the combined NULL check below), never silently degrades to a
     * smaller buffer. */
    net->recv_arena.cap  = (size_t)NODUS_CMT_NET_RECV_ARENA_BYTES;
    net->recv_arena.buf  = (uint8_t *)malloc(net->recv_arena.cap);
    net->recv_arena.used = 0;
    net->recv_arena_warned_50 = false;
    net->recv_arena_warned_90 = false;

    net->commit_sigs = (cmt_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                  sizeof(*net->commit_sigs));
    net->ext_sigs    = (cmt_extended_commit_sig_t *)calloc(
                           (size_t)CMT_VALSET_MAX, sizeof(*net->ext_sigs));

    net->ext_load_arena.cap  = (size_t)CMT_VALSET_MAX * 4096u;
    net->ext_load_arena.buf  = (uint8_t *)malloc(net->ext_load_arena.cap);
    net->ext_load_arena.used = 0;

    /* One block part: BlockPartSizeBytes plus slack for the proto
     * envelope around the raw bytes (index, proof, field headers). */
    net->part_arena.cap  = (size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u;
    net->part_arena.buf  = (uint8_t *)malloc(net->part_arena.cap);
    net->part_arena.used = 0;

    if (!net->encode_buf || !net->recv_arena.buf || !net->commit_sigs ||
        !net->ext_sigs || !net->ext_load_arena.buf || !net->part_arena.buf) {
        nodus_cmt_net_free(net);
        return CMT_FAULT;
    }
    return CMT_OK;
}

void nodus_cmt_net_free(nodus_cmt_net_t *net)
{
    if (!net) return;
    free(net->encode_buf);
    free(net->recv_arena.buf);
    free(net->commit_sigs);
    free(net->ext_sigs);
    free(net->ext_load_arena.buf);
    free(net->part_arena.buf);
    memset(net, 0, sizeof(*net));
}

int nodus_cmt_net_bind(nodus_cmt_net_t *net, cmt_conr_t *conr, cmt_memr_t *memr)
{
    if (!net || !conr || !memr) return CMT_FAULT;
    net->conr = conr;
    net->memr = memr;
    return CMT_OK;
}

int nodus_cmt_net_tick(nodus_cmt_net_t *net, int64_t *out_next_deadline_ns)
{
    int64_t d_conr = INT64_MAX;
    int64_t d_memr = INT64_MAX;
    bool    memr_has_deadline = false;

    if (!net || !net->w || !net->conr || !net->memr) return CMT_FAULT;

    /* (0) the deferred close pass (delta 6) — BEFORE the scan, so a
     * slot closed just now is already DOWN when (a) looks at it in
     * this SAME tick. See net_close_pass's doc comment. */
    net_close_pass(net);

    /* (a) the peer-set scan (delta 5: factored into net_scan_peers so
     * nodus_cmt_net_receive can run the identical scan too). */
    if (net_scan_peers(net) == CMT_FAULT) return CMT_FAULT;

    /* (b) the two reactors' own ticks, once each, in this order. */
    if (cmt_conr_tick(net->conr, &d_conr) == CMT_FAULT) return CMT_FAULT;
    if (cmt_memr_tick(net->memr, &d_memr, &memr_has_deadline) == CMT_FAULT) {
        return CMT_FAULT;
    }

    /* DEAD-BY-PROOF REGRESSION LATCHES (package C2e, closing register
     * R3-A-5): `recv_arena.used` at this point is the size of the LAST
     * message `cmt_conr_receive` decoded (it resets to 0 at the top of
     * every call), never a cumulative occupancy, and the arena is sized
     * to exactly one message's bound (CMT_CONR_MAX_MSG_SIZE). Real
     * messages are far smaller than that bound (a BlockPart's payload
     * tops out around 65 536 B, a Vote's extension a few KB), so these
     * should never fire; if one ever does, it means a single decode
     * approached the full channel capacity, which is worth investigating
     * on its own — it is NOT the exhaustion register R3-A-5 described,
     * which the per-message reset and the bound make unreachable (see
     * NODUS_CMT_NET_RECV_ARENA_BYTES's comment, the .h file). */
    if (net->recv_arena.cap > 0) {
        if (!net->recv_arena_warned_50 &&
            net->recv_arena.used * 2 >= net->recv_arena.cap) {
            net->recv_arena_warned_50 = true;
            QGP_LOG_WARN(LOG_TAG,
                         "recv_arena: a single message used 50%% of the "
                         "%u-byte channel bound — unexpected under normal "
                         "load (register R3-A-5, closed by package C2e)",
                         (unsigned)NODUS_CMT_NET_RECV_ARENA_BYTES);
        }
        if (!net->recv_arena_warned_90 &&
            net->recv_arena.used * 10 >= net->recv_arena.cap * 9) {
            net->recv_arena_warned_90 = true;
            QGP_LOG_ERROR(LOG_TAG,
                          "recv_arena: a single message used 90%% of the "
                          "%u-byte channel bound — investigate; exhaustion "
                          "itself is unreachable for an admitted message "
                          "(register R3-A-5, closed by package C2e)",
                          (unsigned)NODUS_CMT_NET_RECV_ARENA_BYTES);
        }
    }

    if (out_next_deadline_ns) {
        int64_t earliest = d_conr;
        if (memr_has_deadline && d_memr < earliest) earliest = d_memr;
        *out_next_deadline_ns = earliest;
    }
    return CMT_OK;
}

size_t nodus_cmt_net_recv_arena_used(const nodus_cmt_net_t *net)
{
    return net ? net->recv_arena.used : 0;
}

int nodus_cmt_net_receive(nodus_cmt_net_t *net, const uint8_t sender_id[32],
                          const nodus_t3_msg_t *msg)
{
    int      idx = -1;
    int      i;
    int      rc;
    uint8_t  channel = 0;

    if (!net || !net->w || !net->conr || !net->memr || !sender_id || !msg) {
        return CMT_FAULT;
    }

    /* Delta 5: InitPeer/AddPeer before Receive (switch.go:813-860) —
     * see this function's doc comment in the header for the ordering
     * hazard this closes. Idempotent for every slot with no transition
     * since the last tick, so the cost here is one pass over
     * NODUS_T3_MAX_WITNESSES slots comparing two fields each. */
    if (net_scan_peers(net) == CMT_FAULT) return CMT_FAULT;

    /* item C: a receive before both reactors are started is ALSO a
     * no-op, the same contract as the tick (net_scan_peers's own doc
     * comment). This is NOT redundant with that early return:
     * `cmt_conr_receive` has its own `!running` guard
     * (cmt_conr.c:739, "return CMT_OK") so it is safe either way, but
     * `cmt_memr_receive` does NOT — it has only a bounds check
     * (`slot_ok`, cmt_memr.c:378) and would process a Txs message
     * against a peer slot the scan never added (attributing it via
     * `cmt_mem_ids_get_for_peer` on an unregistered slot) instead of
     * refusing it. This glue enforces the contract centrally rather
     * than relying on that asymmetry between the two reactors. */
    if (!net->conr->running || !net->memr->running) return CMT_OK;

    /* item G: find the slot by witness_id among EVERY identified slot
     * FIRST — ascending, deterministic, first match wins — THEN
     * classify why an unroutable match is unroutable. A slot that is
     * NOT `identified` never has a witness_id worth matching (a stale
     * value from whoever occupied the slot before), so "identified" is
     * the search predicate; `net_slot_up` is now the CLASSIFIER, not
     * the search key, giving three distinct outcomes instead of one
     * blanket "unidentified sender" text. */
    for (i = 0; i < NODUS_T3_MAX_WITNESSES; i++) {
        if (net->w->peers[i].identified &&
            memcmp(net->w->peers[i].witness_id, sender_id,
                  NODUS_T3_WITNESS_ID_LEN) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        /* the reference's switch never delivers from a peer it has not
         * added (p2p/switch.go) — drop, do not fault. */
        QGP_LOG_WARN(LOG_TAG, "receive: dropping frame — unknown witness id");
        return CMT_OK;
    }
    if (!net_slot_up(net, idx)) {
        if (net->close_pending[idx]) {
            QGP_LOG_WARN(LOG_TAG, "receive: dropping frame from slot %d — "
                                 "close pending (quarantined)", idx);
        } else {
            QGP_LOG_WARN(LOG_TAG, "receive: dropping frame from slot %d — "
                                 "identified but no live connection", idx);
        }
        return CMT_OK;
    }

    switch (msg->type) {
        case NODUS_T3_CMT_STATE:         channel = CMT_CONR_STATE_CHANNEL; break;
        case NODUS_T3_CMT_DATA:          channel = CMT_CONR_DATA_CHANNEL;  break;
        case NODUS_T3_CMT_VOTE:          channel = CMT_CONR_VOTE_CHANNEL;  break;
        case NODUS_T3_CMT_VOTE_SET_BITS: channel = CMT_CONR_VOTE_SET_BITS_CHANNEL; break;
        case NODUS_T3_CMT_TXS:
            rc = cmt_memr_receive(net->memr, idx, msg->w_cmt.m, msg->w_cmt.m_len,
                                  sender_id, NODUS_T3_WITNESS_ID_LEN);
            if (rc == CMT_FAULT) return CMT_FAULT;
            if (rc == CMT_REJECT) {
                QGP_LOG_WARN(LOG_TAG, "memr receive: REJECT from slot %d", idx);
            }
            return CMT_OK;
        default:
            /* not one of the five — the caller's dispatcher (package
             * C2a) is the gate; this is defense in depth. */
            QGP_LOG_WARN(LOG_TAG, "receive: verb %d not routed here", (int)msg->type);
            return CMT_OK;
    }

    rc = cmt_conr_receive(net->conr, idx, channel, msg->w_cmt.m, msg->w_cmt.m_len);
    if (rc == CMT_FAULT) return CMT_FAULT;
    if (rc == CMT_REJECT) {
        QGP_LOG_WARN(LOG_TAG, "conr receive: REJECT from slot %d channel 0x%02x",
                     idx, channel);
    }
    return CMT_OK;
}
