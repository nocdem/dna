/**
 * @file nodus/src/witness/nodus_witness_cmt_net.h
 * @brief The transport glue for the cometbft port's two reactors
 *        (`cmt_conr_t`, `shared/dnac/cmt_conr.h`; `cmt_memr_t`,
 *        `shared/dnac/cmt_memr.h`) over the witness TCP mesh — the C
 *        stand-in for cometbft's `p2p.Switch` / `p2p.Peer`
 *        (p2p/switch.go, p2p/peer.go).
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * R3 wave W3 package C2b. Nothing in the running witness constructs a
 * `nodus_cmt_net_t` yet; the dispatcher that would call
 * `nodus_cmt_net_receive` for verbs 35-39 is package C2a's.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT THIS STANDS IN FOR, AND WHAT IT DOES NOT ──────────────────────
 * `createConsensusReactor` / `createMempoolAndMempoolReactor`
 * (node/node.go) wire each reactor's host table to `p2p.Switch`, which
 * hands `p2p.Switch.AddReactor` a peer set whose transport is TCP with
 * an ed25519 station-to-station handshake and an X25519-derived
 * MConnection cipher (p2p/conn/secret_connection.go). NONE OF THE
 * REFERENCE'S P2P LAYER IS PORTED — PQ POLICY
 * (atlas-dec-652be084b95d02d253834906271e9fb0,
 * `feedback_pq_security_primary_over_consensus`): a classical-curve
 * handshake is not substituted for anything here. The witness TCP mesh
 * on port 4004 — already ML-DSA-87-signed, already authenticated via
 * `w_ident` — is the transport; this module is the seam between that
 * mesh's peer table (`nodus_witness_t.peers[]`) and the two reactors'
 * host tables, nothing more.
 *
 * PEER SLOT = the witness peer index `i` in `w->peers[]`
 * (`nodus/src/witness/nodus_witness.h`), the SAME index space
 * `cmt_conr_t` / `cmt_memr_t` use for their own peer arrays
 * (`CMT_CONR_MAX_PEERS` / mempool's peer table, both sized
 * `DNA_MAX_ACTIVE_VALIDATORS` == `NODUS_T3_MAX_WITNESSES` == 128). A
 * roster witness's slot index is therefore the SAME small integer on
 * every one of the three tables; nothing here re-numbers it.
 *
 * ── DETERMINISM ─────────────────────────────────────────────────────────
 * No clock read except through the caller's `cmt_now_fn`. Peer-slot
 * iteration is always ascending index order (`nodus_cmt_net_tick`'s
 * scan, part (a), before the two reactors' own ticks, part (b), in ONE
 * call — see the .c file). The per-envelope nonce is the only
 * randomness, and it is an ENVELOPE field, never a consensus input.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_CMT_NET_H
#define NODUS_WITNESS_CMT_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dnac/cmt_conr.h"
#include "dnac/cmt_memr.h"
#include "dnac/cmt_time.h"

#include "protocol/nodus_tier3.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The reactor's receive arena's bound — PACKAGE C2e, CLOSING REGISTER
 * R3-A-5. `cmt_conr_receive` (cmt_conr.c) resets `recv_arena->used = 0`
 * at the top of every call, so this arena holds ONE decoded message at a
 * time, never more; see `cmt_conr.h`'s "THE RECEIVE ARENA" section for
 * the three consumers (the queue element, the part-set payload store,
 * `cs->ext_arena`) that now copy what they need to keep before the NEXT
 * call resets this one.
 *
 * THE BOUND IS EXACTLY `CMT_CONR_MAX_MSG_SIZE` (1 048 576 B, the
 * reactor's own `maxMsgSize`, cmt_ps.h:160-164) — the SAME bound the
 * tier-3 wire decoder already enforces on every consensus-channel
 * envelope (`nodus_tier3.c`'s `dec_w_cmt_args`,
 * `NODUS_T3_CMT_CONS_M_MAX`, tied to `CMT_CONR_MAX_MSG_SIZE` by that
 * file's own `_Static_assert` at nodus_tier3.c:151) before it ever
 * reaches `cmt_conr_receive`. Since every `r_copy_arena` call reachable
 * from `cmt_pb_cons_message_unmarshal` copies a SUB-SLICE of the message
 * it decodes, one decode can never copy more bytes than the message's
 * own wire length — so an arena of this size can NEVER exhaust for a
 * message the channel admitted (proof and citations: cmt_conr.h "THE
 * RECEIVE ARENA"). The `_Static_assert` below makes that equality a
 * compile-time fact rather than a coincidence of two numbers.
 *
 * WHAT USED TO BE HERE: a 64 MiB "runway" (67 108 864 B) that was NEVER
 * reset (nothing in the tree ever lowered `.used`) and therefore filled
 * monotonically until `r_copy_arena` (cmt_pb_wire.h:298-315) returned
 * CMT_REJECT, which `cmt_conr_receive` turned into
 * `stop_peer_for_error(CMT_CONR_STOP_DECODE)` against whichever HONEST
 * peer's message happened to hit the wall. Measured in production
 * (`/tmp/stagef-20260917T024138Z`, seven nodes, production constants):
 * the chain stopped at height 347 after ≈ 1 hour — one block cost
 * ≈ 174 KB of arena (one ≈ 33.8 KB part gossiped from ≈ 5 peers) against
 * the 64 MiB runway, an exhaustion horizon of ≈ 380 heights. This
 * package replaces that runway with the per-message reset above. */
#define NODUS_CMT_NET_RECV_ARENA_BYTES ((uint32_t)CMT_CONR_MAX_MSG_SIZE)

/** Ties the two numbers by construction rather than by comment: a future
 *  edit to either constant that breaks the equality fails the build
 *  instead of silently reopening register R3-A-5. */
_Static_assert(NODUS_CMT_NET_RECV_ARENA_BYTES == (uint32_t)CMT_CONR_MAX_MSG_SIZE,
              "NODUS_CMT_NET_RECV_ARENA_BYTES must equal cmt_ps.h's "
              "CMT_CONR_MAX_MSG_SIZE — see the receive-arena bound proof "
              "in cmt_conr.h \"THE RECEIVE ARENA\"");

/**
 * The glue's own state: the witness it scans, the store its bs_* rows
 * read, the clock it forwards untouched, the two reactors it feeds once
 * bound, and every scratch buffer the host rows need. One instance
 * feeds BOTH `cmt_conr_host_t` and `cmt_memr_host_t` — they share one
 * transport and one peer table.
 */
typedef struct {
    nodus_witness_t   *w;        /* BORROWED; outlives this struct        */
    nodus_cmt_store_t *store;    /* BORROWED; the bs_* rows' backing store */
    cmt_now_fn         now;
    void              *now_ctx;

    /* Bound by nodus_cmt_net_bind; NULL until then. BORROWED — this
     * module never constructs or frees a reactor. */
    cmt_conr_t *conr;
    cmt_memr_t *memr;

    /* The two host tables, EMBEDDED here and filled ONCE by
     * nodus_cmt_net_init — delta 3. cmt_memr_init BORROWS its table for
     * the reactor's entire lifetime: shared/dnac/cmt_memr.h:264 declares
     * the field a borrowed const pointer, and cmt_memr.c:170 stores that
     * pointer as given, so whatever a caller passes MUST outlive the
     * reactor — never a stack local of a setup function that returns.
     * cmt_conr_init instead COPIES its table by value (cmt_conr.c:380,
     * an assignment from the dereferenced pointer), so for cmt_conr_t a
     * stack local would have been safe on its own — but a caller passes
     * &net->conr_host for symmetry with the memr row, one source of
     * truth, so the same field keeps working if cmt_conr_t ever starts
     * borrowing too. Fill ONCE, at init; the row function pointers
     * never change afterward. */
    cmt_conr_host_t conr_host;
    cmt_memr_host_t memr_host;

    /* The peer-set scan's memory of the previous tick, one entry per
     * witness slot: whether the slot was "up" (conn set and
     * identified) and through which connection pointer — so a
     * reconnect (a changed pointer while still up) is read as a
     * down-then-up transition, matching switch.go's "a new peer". */
    bool                          slot_up[NODUS_T3_MAX_WITNESSES];
    const struct nodus_tcp_conn  *slot_conn[NODUS_T3_MAX_WITNESSES];

    /* DEFERRED close bookkeeping (delta 6): `net_stop_peer` clears both
     * reactors' tables for a slot synchronously but never closes the
     * socket itself — see its doc comment (the .c file) for the
     * use-after-free this avoids. `close_pending[i]` marks a slot whose
     * transport-side close is still owed; `close_conn[i]` is the exact
     * connection pointer to close, captured at stop time, so a NEW
     * connection that takes the slot before the next tick is never
     * mistaken for the one being torn down. Both are cleared by
     * `nodus_cmt_net_tick`'s close pass, which runs the real
     * `nodus_tcp_disconnect` from outside any `on_frame` callback.
     * While `close_pending[i]` is set, `net_slot_up` treats the slot as
     * DOWN unconditionally — see that function's doc comment. */
    bool                          close_pending[NODUS_T3_MAX_WITNESSES];
    const struct nodus_tcp_conn  *close_conn[NODUS_T3_MAX_WITNESSES];

    /* One-shot latch (item I of the wire-correctness pass): `net_send`
     * refuses EVERY send while `w->v2_chain32` is all-zero (the
     * placeholder it carries whenever `v2_successor` is false —
     * nodus_witness.h:1237-1239), but logs the WARN only the first
     * time, so a node stuck in this state before its binding runs does
     * not flood its log once per outbound message. */
    bool warned_zero_chain32;

    /* ONE encode scratch buffer, sized to the largest of the five
     * classes (nodus_t3_max_msg_size(NODUS_T3_CMT_TXS)). Every send is
     * synchronous: nodus_t3_encode fills it and nodus_tcp_send drains
     * it before the call returns, so one buffer serves every peer. */
    uint8_t *encode_buf;
    size_t   encode_cap;

    /* The reactor's receive arena, sized to NODUS_CMT_NET_RECV_ARENA_BYTES
     * (the bound, above): BORROWED by cmt_conr_init for cmt_conr_t's
     * lifetime, OWNED here. Reset EVERY receive, by cmt_conr_receive
     * itself (cmt_conr.c) — this module never resets it and does not
     * need to, since it never reads or writes `.buf` directly. */
    cmt_pb_arena_t recv_arena;
    /* DEAD-BY-PROOF REGRESSION LATCHES (package C2e; formerly the "R3-A-5
     * wall" warning). With the bound above, `.used` after any receive is
     * the size of the ONE message just decoded, never a cumulative
     * occupancy: a BlockPart tops out around 65 536 B of payload plus a
     * merkle proof and field overhead (well under 100 KB), a Vote's
     * extension a few KB at most — both far below 50%, let alone 90%, of
     * the 1 048 576 B bound. These latches should therefore never fire in
     * normal operation; if one ever does, it is a regression (a decode
     * approaching the FULL channel capacity in one message) worth
     * investigating, not evidence of the exhaustion register R3-A-5
     * described — that class is now unreachable by construction (see
     * cmt_conr.h "THE RECEIVE ARENA"). */
    bool recv_arena_warned_50;
    bool recv_arena_warned_90;

    /* bs_* row scratch, the same per-class heap rule
     * nodus_witness_cmt_host.c's cs host already uses (CMT_VALSET_MAX
     * signature slots; a 4 KiB-per-validator arena for extended-commit
     * vote extensions; one block-part-sized arena). */
    cmt_commit_sig_t          *commit_sigs;
    cmt_extended_commit_sig_t *ext_sigs;
    cmt_pb_arena_t             ext_load_arena;
    cmt_pb_arena_t             part_arena;
} nodus_cmt_net_t;

/**
 * Allocates the encode scratch buffer, the reactor receive arena and
 * the bs_* row scratch. Does NOT bind a reactor — call
 * nodus_cmt_net_bind once cmt_conr_t / cmt_memr_t exist.
 *
 * PRECONDITION (item I): the caller (package C2a) MUST populate
 * `w->v2_chain32` from the stored genesis document BEFORE calling this
 * function. This module never derives a chain id itself — `net_send`
 * only checks the field is not the all-zero placeholder
 * (nodus_witness.h:1237-1239, nodus_witness.c:755,
 * nodus_witness_sync.c:311) and refuses to send if it is; it does not,
 * and must not, call `nodus_witness_v2_chain_id()` or any equivalent.
 * @return CMT_OK; CMT_FAULT on NULL or an allocation failure.
 */
int nodus_cmt_net_init(nodus_cmt_net_t *net, nodus_witness_t *w,
                       nodus_cmt_store_t *store, cmt_now_fn now,
                       void *now_ctx);

/** Frees every buffer nodus_cmt_net_init allocated. Does not touch
 *  `conr` / `memr` (borrowed). NULL is a no-op. */
void nodus_cmt_net_free(nodus_cmt_net_t *net);

/** Binds the two reactors this glue drives. Call once, after both are
 *  constructed. @return CMT_OK; CMT_FAULT on NULL. */
int nodus_cmt_net_bind(nodus_cmt_net_t *net, cmt_conr_t *conr,
                       cmt_memr_t *memr);

/**
 * One tick: (0) the DEFERRED CLOSE PASS (delta 6) — for every slot
 * `net_stop_peer` marked `close_pending`, either runs the real
 * `nodus_tcp_disconnect` (if the connection it captured is still the
 * one in the slot and a server is bound) or clears the flag without
 * closing anything (if a different connection already took the slot) —
 * THEN (a) the peer-set scan over `w->peers[]` in ascending index
 * order — a slot that became up gets, in the reference's OWN loop
 * order (switch.go:829-831 then :858-860 — every reactor's InitPeer
 * before any reactor's AddPeer), `cmt_conr_init_peer` +
 * `cmt_memr_init_peer` (delta 8 — the mempool peer-id reservation this
 * glue used to skip entirely) + `cmt_conr_add_peer` +
 * `cmt_memr_add_peer`; a slot that became down,
 * or whose connection pointer changed while up (a reconnect), gets
 * `cmt_conr_remove_peer` + `cmt_memr_remove_peer` (and, for a
 * reconnect, the added calls right after) — THEN (b)
 * `cmt_conr_tick` and `cmt_memr_tick`, in that order, once each. The
 * scan itself (delta 5) also runs at the top of `nodus_cmt_net_receive`
 * — see that function's doc comment for why.
 *
 * CALLER CONTRACT (delta 6): this function MUST be called from the
 * server's own event loop, OUTSIDE any `on_frame` callback — that is
 * where step (0)'s close actually happens. `net_stop_peer` (the .c
 * file) never closes a connection from inside a frame callback because
 * `nodus_tcp`'s own frame-reading loop keeps reading the connection
 * after the callback returns; calling `nodus_tcp_disconnect` from
 * there frees it out from under that loop. Package C2a must not call
 * this from inside `nodus_witness_dispatch_t3` or any handler it
 * reaches.
 * @param out_next_deadline_ns the earlier of the two reactors' next
 *        deadlines; INT64_MAX if neither is pending. May be NULL.
 * @return CMT_OK; CMT_FAULT on NULL or a reactor fault.
 */
int nodus_cmt_net_tick(nodus_cmt_net_t *net, int64_t *out_next_deadline_ns);

/**
 * The receive arena's occupancy AFTER THE MOST RECENT RECEIVE (package
 * C2e: `cmt_conr_receive` now resets it to 0 at the top of every call, so
 * this is the size of ONE decoded message, never a cumulative total) —
 * for the live test to print bytes-per-message and for the ORCHESTRATOR
 * to check it against NODUS_CMT_NET_RECV_ARENA_BYTES.
 * @return `net->recv_arena.used`; 0 on NULL or when nothing has been
 *         received yet.
 */
size_t nodus_cmt_net_recv_arena_used(const nodus_cmt_net_t *net);

/**
 * Routes one decoded, wsig-verified, version-gated cometbft envelope
 * (verbs 35-39 only — the caller's dispatcher, package C2a, is the
 * gate) to the reactor its channel belongs to. `sender_id` is the
 * envelope's `wh.sid`; the slot is found by an ascending scan over
 * `w->peers[]` matching an `identified` slot's `witness_id` (item G: a
 * slot that is not `identified` never has a witness_id worth matching,
 * a stale value from whoever occupied the slot before), THEN
 * classified by `net_slot_up` (the SAME predicate the scan and
 * `net_send` use) into three distinct outcomes, each with its own WARN:
 * no slot matches the id at all (unknown witness); a match exists but
 * has no live connection; or a match exists but is `close_pending`
 * (quarantined, delta 6) — every one of the three is dropped, CMT_OK,
 * never routed, the same refusal the reference's switch gives a peer
 * it never added (or has already told to stop).
 *
 * RUNS THE PEER-SET SCAN FIRST (delta 5), before looking up the sender,
 * and REFUSES TO ROUTE AT ALL WHILE EITHER REACTOR IS NOT RUNNING (item
 * C — see net_scan_peers's doc comment for the reference citation):
 * `cmt_conr_receive` has its own `!running` early return
 * (cmt_conr.c:739) but `cmt_memr_receive` does not, so this function
 * enforces the contract itself rather than depending on that asymmetry.
 * On a live node the server dispatches every T3 frame of a poll batch
 * (`nodus_server.c:5046`/`:5106`, `nodus_witness_dispatch_t3`) BEFORE
 * the event loop reaches `nodus_witness_tick` (`nodus_server.c:6349`),
 * and `identified` is set the moment a peer's IDENT/handshake frame is
 * processed (`nodus_witness_peer.c:234, :805, :1758, :1875`) — so the
 * very first cometbft frame from a freshly identified peer can arrive
 * here before `nodus_cmt_net_tick` next runs and adds that slot to
 * either reactor. Without this, `cmt_conr_receive` would read an
 * absent slot and hit the reference's own panic path
 * (`cmt_conr.c:795-801`, "Peer %d has no state", the reactor_test.go
 * :278-305 panic) as CMT_FAULT, and `cmt_memr_receive` faults the same
 * way on an absent slot. The reference never reaches this state:
 * `Switch.addPeer` (p2p/switch.go:813-860) runs EVERY reactor's
 * `InitPeer` (:830, including the mempool reactor's — delta 8's own
 * fix to `net_scan_peers`) and `AddPeer` (:859) before that peer's
 * receive loop starts (`p.Start()`, :836) — so C2a does not need to
 * order its own tick before its dispatch; this function does it. The
 * scan is
 * idempotent for a slot with no up/down transition since the last
 * call, so the added cost on this path is one pass over
 * NODUS_T3_MAX_WITNESSES slots comparing two fields each.
 * @return CMT_OK — routed, including a logged CMT_REJECT from the
 *         reactor; CMT_FAULT — a node-local fault from the reactor (or
 *         from the peer-set scan itself), returned to the caller to
 *         decide (nodus_cmt_net does not disconnect on a FAULT by
 *         itself).
 */
int nodus_cmt_net_receive(nodus_cmt_net_t *net, const uint8_t sender_id[32],
                          const nodus_t3_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_NET_H */
