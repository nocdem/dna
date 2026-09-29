/**
 * @file shared/dnac/cmt_bsync_reactor.c
 * @brief cometbft `blocksync/reactor.go` in C (pin v0.38.26; unmarked
 *        line cites are still @709fd12b — header "REFERENCE PIN") — see
 *        the header for the tick form, the clock sites and deviations
 *        BS-5..BS-9, BS-11, BS-12.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_bsync_reactor.h"
#include "dnac/cmt_pb_store.h"      /* cmt_pb_block_unmarshal            */
#include "dnac/cmt_validation.h"    /* cmt_verify_commit                 */
#include "dnac/cmt_vote.h"          /* cmt_vote_verify_extension         */
#include "dnac/cmt_vote_set.h"      /* CMT_MAX_VOTES_COUNT               */

#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_BSYNC"

/* ══ helpers ══════════════════════════════════════════════════════════ */

static bool id_ok(const char *id)
{
    return id != NULL && strlen(id) < (size_t)CMT_P2P_ID_CAP;
}

static void deadline_min(int64_t *earliest, int64_t t)
{
    if (t < *earliest) {
        *earliest = t;
    }
}

/* Read the host clock (header, "THE CLOCK"). */
static int reactor_now(const cmt_bsync_reactor_t *bcR, int64_t *out_ns)
{
    cmt_time_t t;

    if (bcR->host.now == NULL ||
        bcR->host.now(bcR->host.now_ctx, &t) != CMT_OK) {
        return CMT_FAULT;
    }
    *out_ns = cmt_time_unix_nano(t);
    return CMT_OK;
}

/* Marshal `m` and hand it to one peer through `row` (send or try_send).
 * @return the row's answer; false on a marshal failure (logged). */
static bool send_msg(const cmt_bsync_reactor_t *bcR,
                     bool (*row)(void *, const char *, const uint8_t *, size_t),
                     const char *peer_id, const cmt_bsync_msg_t *m)
{
    uint8_t  small[64];
    uint8_t *buf = small;
    size_t   need = cmt_bsync_msg_size(m);
    size_t   n = 0;
    bool     ok;

    if (need > sizeof(small)) {
        buf = (uint8_t *)malloc(need);
        if (buf == NULL) {
            QGP_LOG_ERROR(LOG_TAG, "out of memory marshalling a %zu-byte "
                          "blocksync message", need);
            return false;
        }
    }
    if (cmt_bsync_msg_marshal(m, buf, need > sizeof(small) ? need : sizeof(small),
                              &n) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "could not marshal blocksync message kind %d",
                      (int)m->kind);
        if (buf != small) {
            free(buf);
        }
        return false;
    }
    ok = row(bcR->host.ctx, peer_id, buf, n);
    if (buf != small) {
        free(buf);
    }
    return ok;
}

static void stop_peer(const cmt_bsync_reactor_t *bcR, const char *peer_id,
                      cmt_bsync_stop_reason_t why)
{
    bcR->host.stop_peer_for_error(bcR->host.ctx, peer_id, (int)why);
}

/* ══ the pool's two outputs (reactor.go:346-377) ══════════════════════ */

/* :353-364 — a request from the pool: TrySend a BlockRequest; a peer no
 * longer connected is skipped (:354-357), a full queue is logged (:362). */
static void pool_send_request(void *ctx, int64_t height, const char *peer_id)
{
    cmt_bsync_reactor_t *bcR = (cmt_bsync_reactor_t *)ctx;
    cmt_bsync_msg_t      m;

    cmt_bsync_msg_init(&m);
    m.kind   = CMT_BSYNC_MSG_BLOCK_REQUEST;
    m.height = height;                                             /* :360 */
    if (!send_msg(bcR, bcR->host.try_send, peer_id, &m)) {         /* :358 */
        QGP_LOG_DEBUG(LOG_TAG, "Send queue is full, drop block request "
                      "(peer %s, height %lld)", peer_id,
                      (long long)height);                          /* :363 */
    }
}

/* :365-369 — an error from the pool: stop that peer if still connected
 * (the host's row checks `Switch.Peers().Get`). */
static void pool_send_error(void *ctx, const char *peer_id,
                            cmt_bsync_peer_err_t err)
{
    cmt_bsync_reactor_t *bcR = (cmt_bsync_reactor_t *)ctx;

    QGP_LOG_WARN(LOG_TAG, "stopping peer %s: block pool error %d", peer_id,
                 (int)err);
    stop_peer(bcR, peer_id, CMT_BSYNC_STOP_POOL_ERROR);            /* :368 */
}

/* ══ construction (reactor.go:71-146) ═════════════════════════════════ */

int cmt_bsync_reactor_init(cmt_bsync_reactor_t *bcR, const cmt_state_t *state,
                           bool block_sync, const uint8_t *local_addr,
                           size_t local_addr_len, const cmt_bsync_host_t *host,
                           const cmt_bsync_limits_t *limits)
{
    cmt_bsync_pool_host_t ph;
    int64_t               store_height = 0;
    int64_t               start_height;

    if (bcR == NULL || state == NULL || host == NULL || limits == NULL) {
        return CMT_FAULT;
    }
    if (host->try_send == NULL || host->send == NULL ||
        host->broadcast == NULL || host->stop_peer_for_error == NULL ||
        host->bs_base == NULL || host->bs_height == NULL ||
        host->bs_load_block == NULL ||
        host->bs_load_block_extended_commit == NULL ||
        host->bs_save_block == NULL ||
        host->bs_save_block_with_extended_commit == NULL ||
        host->ss_load_abci_params == NULL || host->validate_block == NULL ||
        host->apply_verified_block == NULL || host->now == NULL) {
        return CMT_FAULT;
    }
    if (local_addr_len > sizeof(bcR->local_addr) ||
        (local_addr == NULL && local_addr_len != 0)) {
        return CMT_FAULT;
    }
    memset(bcR, 0, sizeof(*bcR));
    bcR->host       = *host;
    bcR->limits     = *limits;
    bcR->block_sync = block_sync;                                  /* :115 */
    if (local_addr_len != 0) {
        memcpy(bcR->local_addr, local_addr, local_addr_len);       /* :116 */
    }
    bcR->local_addr_len = local_addr_len;
    bcR->step_budget    = CMT_BSYNC_DEFAULT_STEP_BUDGET;

    /* setup.go:296 — `state.Copy()` into the reactor's own storage. */
    bcR->state_storage = (cmt_state_storage_t *)calloc(1, sizeof(*bcR->state_storage));
    if (bcR->state_storage == NULL ||
        cmt_state_init(&bcR->state, bcR->state_storage) != CMT_OK ||
        cmt_state_copy(state, &bcR->state) != CMT_OK) {
        free(bcR->state_storage);
        memset(bcR, 0, sizeof(*bcR));
        return CMT_FAULT;
    }

    /* :83-96 — the store and the state must agree. `offlineStateSyncHeight`
     * is always 0 in this port (no state sync, BS-9). */
    if (host->bs_height(host->exec_ctx, &store_height) != CMT_OK) {
        cmt_bsync_reactor_free(bcR);
        return CMT_FAULT;
    }
    if (state->last_block_height != store_height) {                /* :93 */
        QGP_LOG_ERROR(LOG_TAG, "state (%lld) and store (%lld) height "
                      "mismatch, stores were left in an inconsistent state",
                      (long long)state->last_block_height,
                      (long long)store_height);                    /* :94-95 */
        cmt_bsync_reactor_free(bcR);
        return CMT_FAULT;
    }
    start_height = store_height + 1;                               /* :105 */
    if (start_height == 1) {
        start_height = state->initial_height;                      /* :106-108 */
    }
    ph.ctx          = bcR;
    ph.send_request = pool_send_request;
    ph.send_error   = pool_send_error;
    if (cmt_bsync_pool_init(&bcR->pool, start_height, &ph) != CMT_OK) { /* :109 */
        cmt_bsync_reactor_free(bcR);
        return CMT_FAULT;
    }
    return CMT_OK;
}

void cmt_bsync_reactor_free(cmt_bsync_reactor_t *bcR)
{
    if (bcR == NULL) {
        return;
    }
    cmt_bsync_pool_free(&bcR->pool);
    free(bcR->state_storage);
    memset(bcR, 0, sizeof(*bcR));
}

/* :132-146 OnStart() */
int cmt_bsync_reactor_start(cmt_bsync_reactor_t *bcR)
{
    int64_t now_ns;

    if (bcR == NULL) {
        return CMT_FAULT;
    }
    if (bcR->running) {
        return CMT_OK;                        /* ErrAlreadyStarted */
    }
    bcR->running = true;
    if (!bcR->block_sync) {                                        /* :134 */
        return CMT_OK;
    }
    if (reactor_now(bcR, &now_ns) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_bsync_pool_start(&bcR->pool, now_ns) != CMT_OK) {      /* :135 */
        return CMT_FAULT;
    }
    /* :139-143 → poolRoutine(false): its start-of-routine lines. */
    if (bcR->switch_to_consensus_ms == 0) {                        /* :328-330 */
        bcR->switch_to_consensus_ms =
            CMT_BSYNC_SWITCH_TO_CONSENSUS_INTERVAL_NS / CMT_BSYNC_NS_PER_MS;
    }
    bcR->try_sync_next_ns = now_ns + CMT_BSYNC_TRY_SYNC_INTERVAL_NS;  /* :322 */
    bcR->status_next_ns   = now_ns + CMT_BSYNC_STATUS_UPDATE_INTERVAL_NS; /* :325 */
    bcR->switch_next_ns   = now_ns +
        bcR->switch_to_consensus_ms * CMT_BSYNC_NS_PER_MS;          /* :331 */
    bcR->blocks_synced    = 0;                                     /* :334 */
    bcR->state_synced     = false;                                 /* :142 */
    bcR->did_process      = false;                                 /* :342 */
    /* :344 — initialCommitHasExtensions */
    bcR->initial_commit_has_extensions = false;
    if (bcR->state.last_block_height > 0) {
        cmt_extended_commit_t ec;
        bool                  found = false;

        memset(&ec, 0, sizeof(ec));
        if (bcR->host.bs_load_block_extended_commit(
                bcR->host.exec_ctx, bcR->state.last_block_height, &ec,
                &found) != CMT_OK) {
            return CMT_FAULT;
        }
        bcR->initial_commit_has_extensions = found;
    }
    bcR->routine_running = true;
    return CMT_OK;
}

/* :166-174 OnStop() */
void cmt_bsync_reactor_stop(cmt_bsync_reactor_t *bcR)
{
    if (bcR == NULL) {
        return;
    }
    bcR->running = false;
    if (bcR->block_sync) {                                         /* :168 */
        cmt_bsync_pool_stop(&bcR->pool);                           /* :169 */
    }
    bcR->routine_running = false;                                  /* :172 */
}

/* :177-188 GetChannels() */
void cmt_bsync_reactor_get_channels(cmt_bsync_channel_desc_t *out)
{
    if (out == NULL) {
        return;
    }
    out->id                    = (uint8_t)CMT_BSYNC_CHANNEL;       /* :180 */
    out->priority              = CMT_BSYNC_CHANNEL_PRIORITY;       /* :181 */
    out->send_queue_capacity   = CMT_BSYNC_CHANNEL_SEND_QUEUE_CAPACITY; /* :182 */
    out->recv_buffer_capacity  = CMT_BSYNC_CHANNEL_RECV_BUFFER_CAPACITY; /* :183 */
    out->recv_message_capacity = CMT_BSYNC_MAX_MSG_SIZE;           /* :184 */
}

/* ══ peers (reactor.go:190-208) ═══════════════════════════════════════ */

/* Our StatusResponse{height, base} (:194-197, :291-294). */
static int status_response(const cmt_bsync_reactor_t *bcR, cmt_bsync_msg_t *m)
{
    int64_t base = 0, height = 0;

    if (bcR->host.bs_base(bcR->host.exec_ctx, &base) != CMT_OK ||
        bcR->host.bs_height(bcR->host.exec_ctx, &height) != CMT_OK) {
        return CMT_FAULT;
    }
    cmt_bsync_msg_init(m);
    m->kind   = CMT_BSYNC_MSG_STATUS_RESPONSE;
    m->base   = base;
    m->height = height;
    return CMT_OK;
}

/* :190-203 AddPeer() */
int cmt_bsync_reactor_add_peer(cmt_bsync_reactor_t *bcR, const char *peer_id)
{
    cmt_bsync_msg_t m;

    if (bcR == NULL || !id_ok(peer_id)) {
        return CMT_FAULT;
    }
    if (status_response(bcR, &m) != CMT_OK) {
        return CMT_FAULT;
    }
    (void)send_msg(bcR, bcR->host.send, peer_id, &m);   /* :192-199 "OK if send fails" */
    /* :201-202 — the peer joins the pool at its StatusResponse. */
    return CMT_OK;
}

/* :205-208 RemovePeer() */
void cmt_bsync_reactor_remove_peer(cmt_bsync_reactor_t *bcR,
                                   const char *peer_id)
{
    if (bcR == NULL || !id_ok(peer_id)) {
        return;
    }
    cmt_bsync_pool_remove_peer(&bcR->pool, peer_id);               /* :207 */
}

/* ══ respondToPeer (reactor.go:210-249) ═══════════════════════════════ */

/* Marshal with a buffer that grows until it fits (BS-7), up to `limit`.
 * `fn` is cmt_block_marshal or the extended-commit marshal. */
typedef int (*marshal_fn)(const void *m, uint8_t *out, size_t cap,
                          size_t *out_len);

static int block_marshal_fn(const void *m, uint8_t *out, size_t cap,
                            size_t *out_len)
{
    return cmt_block_marshal((const cmt_block_t *)m, out, cap, out_len);
}

static int ext_marshal_fn(const void *m, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    return cmt_pb_extended_commit_marshal((const cmt_pb_extended_commit_t *)m,
                                          out, cap, out_len);
}

static int marshal_grow(marshal_fn fn, const void *m, size_t first_cap,
                        size_t limit, uint8_t **out, size_t *out_len)
{
    size_t cap = first_cap < 4096u ? 4096u : first_cap;

    *out = NULL;
    for (;;) {
        uint8_t *buf = (uint8_t *)malloc(cap);
        int      rc;

        if (buf == NULL) {
            return CMT_FAULT;
        }
        rc = fn(m, buf, cap, out_len);
        if (rc == CMT_OK) {
            *out = buf;
            return CMT_OK;
        }
        free(buf);
        if (rc == CMT_FAULT || cap >= limit) {
            return rc == CMT_FAULT ? CMT_FAULT : CMT_REJECT;
        }
        cap = cap > limit / 2u ? limit : cap * 2u;
    }
}

/* An upper bound for one ExtendedCommit's marshalled size, used as the
 * first guess of marshal_grow. */
static size_t ext_commit_size_guess(const cmt_extended_commit_t *ec)
{
    size_t n = 512u;
    size_t i;

    for (i = 0; i < ec->extended_signatures_len; i++) {
        n += 2u * (size_t)CMT_PB_SIG_MAX + (size_t)CMT_PB_ADDRESS_MAX + 64u +
             ec->extended_signatures[i].extension.len;
    }
    return n;
}

static bool respond_to_peer(cmt_bsync_reactor_t *bcR, int64_t height,
                            const char *peer_id)
{
    cmt_block_t          *block = NULL;
    size_t                size_hint = 0;
    bool                  found = false;
    cmt_abci_params_t     abci;
    bool                  ext_enabled = false;
    cmt_extended_commit_t ec;
    uint8_t              *bbuf = NULL;
    uint8_t              *ebuf = NULL;
    size_t                blen = 0, elen = 0;
    cmt_bsync_msg_t       m;
    bool                  queued;

    /* :213 LoadBlock */
    if (bcR->host.bs_load_block(bcR->host.exec_ctx, height, &block,
                                &size_hint, &found) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "loading block %lld to serve failed",
                      (long long)height);
        return false;
    }
    if (!found || block == NULL) {                                 /* :214 */
        QGP_LOG_INFO(LOG_TAG, "Peer asking for a block we don't have (peer "
                     "%s, height %lld)", peer_id, (long long)height); /* :215 */
        cmt_bsync_msg_init(&m);
        m.kind   = CMT_BSYNC_MSG_NO_BLOCK_RESPONSE;
        m.height = height;                                         /* :218 */
        return send_msg(bcR, bcR->host.try_send, peer_id, &m);     /* :216 */
    }
    /* :222-226 — the state, for its consensus params. */
    if (bcR->host.ss_load_abci_params(bcR->host.exec_ctx, &abci) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "loading state failed");            /* :224 */
        return false;
    }
    /* :228 — `height` >= 1 here: the store holds no block below 1. */
    if (cmt_abci_params_vote_extensions_enabled(abci, height,
                                                &ext_enabled) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "VoteExtensionsEnabled(%lld) refused",
                      (long long)height);
        return false;
    }
    memset(&ec, 0, sizeof(ec));
    if (ext_enabled) {
        found = false;
        if (bcR->host.bs_load_block_extended_commit(bcR->host.exec_ctx, height,
                                                    &ec, &found) != CMT_OK ||
            !found) {                                              /* :229-230 */
            QGP_LOG_ERROR(LOG_TAG, "found block in store with no extended "
                          "commit (height %lld)", (long long)height); /* :231 */
            return false;                                          /* :232 */
        }
    }
    /* :236-240 — block.ToProto(), marshalled (BS-7 buffer). */
    if (marshal_grow(block_marshal_fn, block, size_hint + 4096u,
                     2u * (size_t)CMT_MAX_BLOCK_SIZE_BYTES, &bbuf,
                     &blen) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "could not convert msg to protobuf (block "
                      "%lld)", (long long)height);                 /* :238 */
        return false;
    }
    if (ext_enabled &&
        marshal_grow(ext_marshal_fn, &ec, ext_commit_size_guess(&ec),
                     2u * (size_t)CMT_MAX_BLOCK_SIZE_BYTES, &ebuf,
                     &elen) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "could not marshal the extended commit of "
                      "block %lld", (long long)height);
        free(bbuf);
        return false;
    }
    cmt_bsync_msg_init(&m);
    m.kind           = CMT_BSYNC_MSG_BLOCK_RESPONSE;
    m.has_block      = true;                                       /* :245 */
    m.block          = bbuf;
    m.block_len      = blen;
    m.has_ext_commit = ext_enabled;          /* :246 — nil ToProto() is nil */
    m.ext_commit     = ebuf;
    m.ext_commit_len = elen;
    queued = send_msg(bcR, bcR->host.try_send, peer_id, &m);       /* :242 */
    free(bbuf);
    free(ebuf);
    return queued;
}

/* ══ BlockResponse decode (reactor.go:264-282) — BS-6 ═════════════════ */

static size_t min_sz(size_t a, size_t b)
{
    return a < b ? a : b;
}

/* `types.BlockFromProto(msg.Block)` (:265) and, when present,
 * `types.ExtendedCommitFromProto(msg.ExtCommit)` (:274) into one held
 * block. @return CMT_OK; CMT_REJECT for the block (`*which` 0) or the
 * extended commit (`*which` 1) not decoding; CMT_FAULT on memory. */
static int decode_block_response(const cmt_bsync_reactor_t *bcR,
                                 const cmt_bsync_msg_t *m,
                                 cmt_bsync_block_t **out, int *which)
{
    cmt_bsync_block_t *b;
    cmt_block_t        view;
    cmt_commit_t       view_commit;
    cmt_commit_sig_t  *view_sigs = NULL;
    cmt_pb_evidence_t *view_ev = NULL;
    cmt_pb_arena_t     arena;
    size_t             txs_cap, ev_cap;
    int                rc;

    *out   = NULL;
    *which = 0;
    if (!m->has_block) {
        /* :265 — BlockFromProto(nil) is "nil block" (types/block.go:247). */
        return CMT_REJECT;
    }
    b = (cmt_bsync_block_t *)calloc(1, sizeof(*b));
    if (b == NULL) {
        return CMT_FAULT;
    }
    /* Storage sized from the message, capped by the node's limits: an
     * element of a repeated field is at least two bytes on the wire. */
    txs_cap = min_sz(m->block_len / 2u + 1u, bcR->limits.max_txs);
    ev_cap  = min_sz(m->block_len / 2u + 1u, bcR->limits.max_evidence);
    b->txs       = (cmt_pb_bytes_t *)calloc(txs_cap ? txs_cap : 1u, sizeof(*b->txs));
    b->arena_buf = (uint8_t *)malloc(m->block_len + 1u);
    view_ev      = (cmt_pb_evidence_t *)calloc(ev_cap ? ev_cap : 1u, sizeof(*view_ev));
    b->evidence  = (cmt_pb_evidence_t *)calloc(ev_cap ? ev_cap : 1u, sizeof(*b->evidence));
    view_sigs    = (cmt_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX, sizeof(*view_sigs));
    b->sigs      = (cmt_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX, sizeof(*b->sigs));
    if (b->txs == NULL || b->arena_buf == NULL || view_ev == NULL ||
        b->evidence == NULL || view_sigs == NULL || b->sigs == NULL) {
        rc = CMT_FAULT;
        goto done;
    }
    arena.buf  = b->arena_buf;
    arena.cap  = m->block_len + 1u;
    arena.used = 0;

    /* proto.Unmarshal into the view (the nodus_cmt_block_decode shape). */
    memset(&view, 0, sizeof(view));
    view.data.txs              = b->txs;
    view.data.txs_cap          = txs_cap;
    view.evidence.evidence     = view_ev;
    view.evidence.evidence_cap = ev_cap;
    memset(&view_commit, 0, sizeof(view_commit));
    view_commit.signatures     = view_sigs;
    view_commit.signatures_cap = (size_t)CMT_VALSET_MAX;
    rc = cmt_pb_block_unmarshal(m->block, m->block_len, &view, &view_commit,
                                &arena);
    if (rc != CMT_OK) {
        goto done;
    }
    /* types.BlockFromProto (types/block.go:246-277), ending in
     * ValidateBasic (:276). */
    memset(&b->last_commit, 0, sizeof(b->last_commit));
    b->last_commit.signatures     = b->sigs;
    b->last_commit.signatures_cap = (size_t)CMT_VALSET_MAX;
    rc = cmt_block_from_proto(&view, CMT_BLOCK_PROTOCOL, b->sigs,
                              (size_t)CMT_VALSET_MAX, b->evidence, ev_cap,
                              &b->last_commit, &b->block);
    if (rc != CMT_OK) {
        goto done;
    }
    b->size = m->block_len;                                        /* :284 */

    /* Shrink the per-block storage to what the block holds (BS-6): the
     * signature array is ~600 KB at CMT_VALSET_MAX. Every pointer that
     * names it is re-pointed. */
    {
        size_t            ns = b->last_commit.signatures_len ?
                               b->last_commit.signatures_len : 1u;
        cmt_commit_sig_t *s  = (cmt_commit_sig_t *)realloc(b->sigs, ns * sizeof(*s));

        if (s != NULL) {
            b->sigs = s;
            b->last_commit.signatures     = s;
            b->last_commit.signatures_cap = ns;
        }
    }
    if (b->block.last_commit != NULL) {
        b->block.last_commit = &b->last_commit;
    }
    {
        size_t             ne = b->block.evidence.evidence_len ?
                                b->block.evidence.evidence_len : 1u;
        cmt_pb_evidence_t *e  = (cmt_pb_evidence_t *)realloc(b->evidence,
                                                             ne * sizeof(*e));

        if (e != NULL) {
            b->evidence = e;
            b->block.evidence.evidence     = e;
            b->block.evidence.evidence_cap = ne;
        }
    }

    if (m->has_ext_commit) {                                       /* :272 */
        cmt_pb_extended_commit_t      ev;
        cmt_pb_extended_commit_sig_t *evs;
        cmt_pb_arena_t                earena;
        size_t                        n;

        *which = 1;
        evs = (cmt_pb_extended_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                     sizeof(*evs));
        b->ext_arena_buf = (uint8_t *)malloc(m->ext_commit_len + 1u);
        if (evs == NULL || b->ext_arena_buf == NULL) {
            free(evs);
            rc = CMT_FAULT;
            goto done;
        }
        earena.buf  = b->ext_arena_buf;
        earena.cap  = m->ext_commit_len + 1u;
        earena.used = 0;
        memset(&ev, 0, sizeof(ev));
        ev.extended_signatures     = evs;
        ev.extended_signatures_cap = (size_t)CMT_VALSET_MAX;
        cmt_pb_extended_commit_init(&ev);
        rc = cmt_pb_extended_commit_unmarshal(m->ext_commit, m->ext_commit_len,
                                              &ev, &earena);
        if (rc == CMT_OK) {
            n = ev.extended_signatures_len ? ev.extended_signatures_len : 1u;
            b->ext_sigs = (cmt_extended_commit_sig_t *)calloc(n, sizeof(*b->ext_sigs));
            if (b->ext_sigs == NULL) {
                rc = CMT_FAULT;
            } else {
                rc = cmt_extended_commit_from_proto(&ev, b->ext_sigs, n,
                                                    &b->ext_commit); /* :274 */
            }
        }
        free(evs);
        if (rc != CMT_OK) {
            goto done;
        }
        b->has_ext_commit = true;
    }
    rc = CMT_OK;

done:
    free(view_sigs);
    free(view_ev);
    if (rc == CMT_OK) {
        *out = b;
    } else {
        cmt_bsync_block_free(b);
    }
    return rc;
}

/* ══ handlePeerResponse (cometbft@v0.38.26 reactor.go:256-277) ════════ */

/* The BlockResponse case of Receive (v0.38.26 :361-362), in its own
 * function as upstream moved it. @return CMT_OK; CMT_REJECT when the peer
 * was stopped; CMT_FAULT on memory or the clock. */
static int handle_peer_response(cmt_bsync_reactor_t *bcR,
                                const cmt_bsync_msg_t *m, const char *peer_id)
{
    cmt_bsync_block_t *b = NULL;
    int                which = 0;
    int64_t            now_ns;
    int                rc;

    rc = decode_block_response(bcR, m, &b, &which);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        if (which == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Peer %s sent us invalid block",
                          peer_id);                                /* :259 */
            stop_peer(bcR, peer_id, CMT_BSYNC_STOP_INVALID_BLOCK); /* :260 */
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Failed to convert extended commit "
                          "from proto (peer %s)", peer_id);        /* :268 */
            stop_peer(bcR, peer_id, CMT_BSYNC_STOP_INVALID_EXT);   /* :269 */
        }
        return CMT_REJECT;
    }
    if (reactor_now(bcR, &now_ns) != CMT_OK) {
        cmt_bsync_block_free(b);
        return CMT_FAULT;
    }
    /* :274 — AddBlock takes the block in every case. */
    if (cmt_bsync_pool_add_block(&bcR->pool, peer_id, b, now_ns) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add block (peer %s)", peer_id); /* :275 */
    }
    return CMT_OK;
}

/* ══ FilterMsgBytes (cometbft@v0.38.26 reactor.go:279-346) ════════════ */

/* :324-346 validateMaxVotes() */
static cmt_bsync_filter_err_t validate_max_votes(size_t commit_sigs,
                                                 size_t ext_sigs)
{
    if (commit_sigs > (size_t)CMT_MAX_VOTES_COUNT) {               /* :338 */
        return CMT_BSYNC_FILTER_TOO_MANY_COMMIT_SIGS;
    }
    if (ext_sigs > (size_t)CMT_MAX_VOTES_COUNT) {                  /* :341 */
        return CMT_BSYNC_FILTER_TOO_MANY_EXT_SIGS;
    }
    return CMT_BSYNC_FILTER_OK;                                    /* :345 */
}

int cmt_bsync_reactor_filter_msg_bytes(const cmt_bsync_reactor_t *bcR,
                                       const char *peer_id,
                                       const uint8_t *bytes, size_t len,
                                       cmt_bsync_filter_err_t *why)
{
    cmt_bsync_filter_err_t e = CMT_BSYNC_FILTER_OK;
    bool                   is_br = false;
    size_t                 commit_sigs = 0, ext_sigs = 0;
    int                    rc;

    if (why != NULL) {
        *why = CMT_BSYNC_FILTER_OK;
    }
    if (bcR == NULL || !id_ok(peer_id) || (bytes == NULL && len != 0)) {
        return CMT_FAULT;
    }
    if (len == 0) {
        return CMT_OK;                                             /* :283-285 */
    }
    /* :287-292 — the allocation-free stub view */
    rc = cmt_bsync_msg_sig_count(bytes, len, &is_br, &commit_sigs, &ext_sigs);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        e = CMT_BSYNC_FILTER_MALFORMED;                            /* :291 */
    } else if (!is_br) {
        return CMT_OK;                                             /* :293-297 */
    } else if (!bcR->block_sync) {
        e = CMT_BSYNC_FILTER_NOT_ACTIVE;                           /* :300-302 */
    } else if (!cmt_bsync_pool_is_running(&bcR->pool)) {
        e = validate_max_votes(commit_sigs, ext_sigs);             /* :307-309 */
    } else if (!cmt_bsync_pool_has_pending_request_from(&bcR->pool, peer_id)) {
        e = CMT_BSYNC_FILTER_UNSOLICITED;                          /* :312-314 */
    } else {
        e = validate_max_votes(commit_sigs, ext_sigs);             /* :317-319 */
    }
    if (why != NULL) {
        *why = e;
    }
    return e == CMT_BSYNC_FILTER_OK ? CMT_OK : CMT_REJECT;         /* :321 */
}

/* ══ Receive (reactor.go:251-305; v0.38.26 :349-384) ══════════════════ */

int cmt_bsync_reactor_receive(cmt_bsync_reactor_t *bcR, const char *peer_id,
                              const uint8_t *bytes, size_t len)
{
    cmt_bsync_msg_t        m;
    cmt_bsync_msg_err_t    verr = CMT_BSYNC_MSG_ERR_NONE;
    cmt_bsync_filter_err_t ferr = CMT_BSYNC_FILTER_OK;
    int                    rc = CMT_OK;

    if (bcR == NULL || !id_ok(peer_id) || (bytes == NULL && len != 0)) {
        return CMT_FAULT;
    }
    /* :184 RecvMessageCapacity — enforced at the reactor boundary, as
     * cmt_memr.c:385-391 does for 0x30. */
    if (len > CMT_BSYNC_MAX_MSG_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "blocksync message of %zu bytes exceeds "
                      "MaxMsgSize; stopping peer %s", len, peer_id);
        stop_peer(bcR, peer_id, CMT_BSYNC_STOP_OVERSIZE);
        return CMT_REJECT;
    }
    /* v0.38.26 p2p/peer.go:408-413 — the filter, before the unmarshal. */
    rc = cmt_bsync_reactor_filter_msg_bytes(bcR, peer_id, bytes, len, &ferr);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "rejected msg on chID 0x40 from %s (filter "
                      "%d); stopping peer", peer_id, (int)ferr);   /* peer.go:411 */
        stop_peer(bcR, peer_id, ferr == CMT_BSYNC_FILTER_MALFORMED ?
                  CMT_BSYNC_STOP_UNDECODABLE : CMT_BSYNC_STOP_FILTER);
        return CMT_REJECT;
    }
    cmt_bsync_msg_init(&m);
    rc = cmt_bsync_msg_unmarshal(bytes, len, &m);                  /* peer.go:407-412 */
    if (rc == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "unmarshaling blocksync message from peer %s "
                      "failed; stopping peer", peer_id);
        stop_peer(bcR, peer_id, CMT_BSYNC_STOP_UNDECODABLE);
        return CMT_REJECT;
    }
    if (cmt_bsync_validate_msg(&m, &verr) != CMT_OK) {             /* :253 */
        QGP_LOG_ERROR(LOG_TAG, "Peer %s sent us invalid msg (kind %d, err "
                      "%d)", peer_id, (int)m.kind, (int)verr);     /* :254 */
        stop_peer(bcR, peer_id, CMT_BSYNC_STOP_INVALID_MSG);       /* :255 */
        cmt_bsync_msg_release(&m);
        return CMT_REJECT;                                         /* :256 */
    }
    QGP_LOG_DEBUG(LOG_TAG, "Receive from %s kind %d", peer_id, (int)m.kind); /* :259 */

    switch (m.kind) {
    case CMT_BSYNC_MSG_BLOCK_REQUEST:                              /* :262 */
        (void)respond_to_peer(bcR, m.height, peer_id);             /* :263 */
        break;
    case CMT_BSYNC_MSG_BLOCK_RESPONSE:              /* v0.38.26 :361-362 */
        rc = handle_peer_response(bcR, &m, peer_id);
        break;
    case CMT_BSYNC_MSG_STATUS_REQUEST: {                           /* :287 */
        cmt_bsync_msg_t resp;

        if (status_response(bcR, &resp) != CMT_OK) {
            rc = CMT_FAULT;
            break;
        }
        (void)send_msg(bcR, bcR->host.try_send, peer_id, &resp);   /* :289-295 */
        break;
    }
    case CMT_BSYNC_MSG_STATUS_RESPONSE: {                          /* :296 */
        int64_t now_ns;

        if (reactor_now(bcR, &now_ns) != CMT_OK) {
            rc = CMT_FAULT;
            break;
        }
        /* :297-298 "Got a peer status. Unverified." */
        rc = cmt_bsync_pool_set_peer_range(&bcR->pool, peer_id, m.base,
                                           m.height, now_ns);
        break;
    }
    case CMT_BSYNC_MSG_NO_BLOCK_RESPONSE:                          /* :299 */
        QGP_LOG_DEBUG(LOG_TAG, "Peer %s does not have requested block %lld",
                      peer_id, (long long)m.height);               /* :300 */
        cmt_bsync_pool_redo_request_from(&bcR->pool, m.height, peer_id); /* :301 */
        break;
    default:                                                       /* :302-303 */
        QGP_LOG_ERROR(LOG_TAG, "Unknown message type %d", (int)m.kind);
        break;
    }
    cmt_bsync_msg_release(&m);
    return rc;
}

/* ══ poolRoutine (reactor.go:307-572) ═════════════════════════════════ */

/* :307-314 localNodeBlocksTheChain() */
static bool local_node_blocks_the_chain(cmt_bsync_reactor_t *bcR)
{
    int32_t idx = -1;
    int64_t total = 0;

    if (bcR->local_addr_len == 0) {
        return false;                        /* GetByAddress(nil) finds none */
    }
    if (cmt_validator_set_get_by_address(&bcR->state.validators,
                                         bcR->local_addr,
                                         bcR->local_addr_len,
                                         &idx, NULL) != CMT_OK ||
        idx < 0) {                                                 /* :308-311 */
        return false;
    }
    if (cmt_validator_set_total_voting_power(&bcR->state.validators,
                                             &total) != CMT_OK) {  /* :312 */
        return false;
    }
    return bcR->state.validators.validators[idx].voting_power >= total / 3; /* :313 */
}

/* cometbft@v0.38.26 types/validator_set.go:717-757 —
 * `(vals *ValidatorSet) VerifyCommitExtended(chainID, blockID, height,
 * extCommit)` over the reactor's own validator set (reactor.go:591
 * `state.Validators`). BS-12: placed here, built from the types layer's
 * API. "extCommit must already be validated by ValidateBasic" (:718) —
 * cmt_extended_commit_from_proto ran it at decode (cmt_block.h:654-656).
 * @return CMT_OK; CMT_REJECT (the reference's error — a peer's fault);
 *         CMT_FAULT on memory or a backend failure. */
static int verify_commit_extended(cmt_bsync_reactor_t *bcR,
                                  const cmt_block_id_t *block_id,
                                  int64_t height,
                                  const cmt_extended_commit_t *ec)
{
    cmt_validator_set_t *vals = &bcR->state.validators;
    cmt_commit_sig_t    *sigs = NULL;
    cmt_commit_t         commit;
    cmt_pb_vote_t       *vote = NULL;
    size_t               n;
    size_t               i;
    int                  rc;

    if (ec == NULL) {
        return CMT_REJECT;                     /* :725-727 "nil extended commit" */
    }
    /* :729-733 — 1. ensure vote extensions */
    rc = cmt_extended_commit_ensure_extensions(ec, true);
    if (rc != CMT_OK) {
        return rc;
    }
    /* :735-739 — 2. verify regular commit (extCommit.ToCommit()) */
    n    = ec->extended_signatures_len;
    sigs = (cmt_commit_sig_t *)calloc(n != 0u ? n : 1u, sizeof(*sigs));
    if (sigs == NULL) {
        return CMT_FAULT;
    }
    rc = cmt_extended_commit_to_commit(ec, sigs, n != 0u ? n : 1u, &commit);
    if (rc == CMT_OK) {
        rc = cmt_verify_commit(bcR->state.chain_id, bcR->state.chain_id_len,
                               vals, block_id, height, &commit, NULL);
    }
    if (rc != CMT_OK) {
        free(sigs);
        return rc;
    }
    /* :741-754 — 3. check signatures */
    vote = (cmt_pb_vote_t *)malloc(sizeof(*vote));
    if (vote == NULL) {
        free(sigs);
        return CMT_FAULT;
    }
    for (i = 0; i < n && rc == CMT_OK; i++) {
        cmt_validator_t val;
        uint8_t        *scratch;
        size_t          cap;

        /* :743-748 — "should not happen as we verified the commit above" */
        if (cmt_validator_set_get_by_index(vals, (int32_t)i, &val) != CMT_OK ||
            !val.pub_key.present) {
            QGP_LOG_ERROR(LOG_TAG, "unable to find val #%zu out of %zu vals",
                          i, cmt_validator_set_size(vals));
            rc = CMT_REJECT;
            break;
        }
        /* :750 extCommit.GetExtendedVote(idx) */
        rc = cmt_extended_commit_get_extended_vote(ec, (int32_t)i, vote);
        if (rc != CMT_OK) {
            break;
        }
        /* :751 vote.VerifyExtension(chainID, val.PubKey); the scratch
         * holds the extension sign bytes (cmt_vote.h: 64 + 11 + the
         * extension's length, plus the chain ID). */
        cap = 128u + bcR->state.chain_id_len + vote->extension.len;
        scratch = (uint8_t *)malloc(cap);
        if (scratch == NULL) {
            rc = CMT_FAULT;
            break;
        }
        rc = cmt_vote_verify_extension(bcR->state.chain_id,
                                       bcR->state.chain_id_len, vote,
                                       val.pub_key.key, scratch, cap);
        free(scratch);
        if (rc == CMT_REJECT) {
            QGP_LOG_ERROR(LOG_TAG, "invalid vote extension signature (val "
                          "#%zu)", i);                             /* :752 */
        }
    }
    free(vote);
    free(sigs);
    return rc;                                                     /* :756 */
}

/* cometbft@v0.38.26 blocksync/reactor.go:655-677 handleValidationFailure()
 * — the peers that delivered `height_a` and `height_b` are removed,
 * banned, their requests redone, and stopped with ErrReactorValidation;
 * the second only when it is a different peer (:668-670).
 * @return CMT_OK; CMT_FAULT when the pool has no requester (a Go panic). */
static int handle_validation_failure(cmt_bsync_reactor_t *bcR,
                                     int64_t height_a, int64_t height_b,
                                     int64_t now_ns)
{
    char id_a[CMT_P2P_ID_CAP];
    char id_b[CMT_P2P_ID_CAP];

    QGP_LOG_ERROR(LOG_TAG, "Error in validation (height %lld)",
                  (long long)height_a);                            /* :656 */
    if (cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
            &bcR->pool, height_a, now_ns, id_a) != CMT_OK) {       /* :660 */
        return CMT_FAULT;
    }
    if (id_a[0] != '\0') {
        stop_peer(bcR, id_a, CMT_BSYNC_STOP_VALIDATION);           /* :661-665 */
    }
    if (cmt_bsync_pool_remove_peer_and_redo_all_peer_requests(
            &bcR->pool, height_b, now_ns, id_b) != CMT_OK) {       /* :667 */
        return CMT_FAULT;
    }
    if (strcmp(id_a, id_b) == 0) {
        return CMT_OK;                                             /* :668-670 */
    }
    if (id_b[0] != '\0') {
        stop_peer(bcR, id_b, CMT_BSYNC_STOP_VALIDATION);           /* :672-676 */
    }
    return CMT_OK;
}

/* :480-555 (v0.38.26 :556-645) — one block: MakePartSet, the extension
 * presence rule, VerifyCommit, VerifyCommitExtended, ValidateBlock, then
 * PopRequest → Save → Apply.
 * @return CMT_OK (processed or refused-and-redone); CMT_FAULT (BS-8);
 *         CMT_REJECT when MakePartSet failed — the routine ends (BS-7). */
static int process_first(cmt_bsync_reactor_t *bcR, cmt_bsync_block_t *first,
                         cmt_bsync_block_t *second, int64_t now_ns)
{
    uint8_t          *scratch = NULL;
    size_t            cap;
    cmt_part_t       *parts = NULL;
    size_t            parts_cap;
    cmt_part_set_t    first_parts;
    cmt_block_id_t    first_id;
    int               verr = CMT_OK;   /* the reference's `err` (nil = OK) */
    bool              ext_enabled = false;
    bool              present_ext;
    cmt_bsync_block_t *popped = NULL;
    int               rc;

    /* :482 — first.MakePartSet(BlockPartSizeBytes); BS-7 growth. */
    cap = first->size + 65536u;
    for (;;) {
        parts_cap = cap / (size_t)CMT_BLOCK_PART_SIZE_BYTES + 2u;
        scratch = (uint8_t *)malloc(cap);
        parts   = (cmt_part_t *)calloc(parts_cap, sizeof(*parts));
        if (scratch == NULL || parts == NULL) {
            free(scratch);
            free(parts);
            return CMT_FAULT;
        }
        memset(&first_parts, 0, sizeof(first_parts));
        rc = cmt_block_make_part_set(&first->block,
                                     (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                     scratch, cap, parts, parts_cap,
                                     &first_parts);
        if (rc == CMT_OK) {
            break;
        }
        free(scratch);
        free(parts);
        scratch = NULL;
        parts = NULL;
        if (rc == CMT_FAULT) {
            return CMT_FAULT;
        }
        if (cap >= 2u * (size_t)CMT_MAX_BLOCK_SIZE_BYTES) {
            QGP_LOG_ERROR(LOG_TAG, "failed to make part set (height %lld) — "
                          "the block sync routine ENDS (reactor.go:482-488)",
                          (long long)first->block.header.height); /* :484-486 */
            return CMT_REJECT;                                     /* :487 */
        }
        cap *= 2u;
    }

    /* :489-490 firstID = {first.Hash(), firstParts.Header()} */
    cmt_pb_block_id_init(&first_id);
    rc = cmt_block_hash(&first->block, first_id.hash);
    if (rc == CMT_OK) {
        first_id.hash_len = CMT_TMHASH_SIZE;
        rc = cmt_part_set_header(&first_parts, &first_id.part_set_header);
    } else if (rc == CMT_HASH_NIL) {
        first_id.hash_len = 0;       /* a nil hash: the commit will not match */
        rc = cmt_part_set_header(&first_parts, &first_id.part_set_header);
    }
    if (rc != CMT_OK) {
        free(scratch);
        free(parts);
        return CMT_FAULT;
    }

    /* v0.38.26 :568-578 — vote extension validations FIRST: an extended
     * commit present iff extensions are enabled at this height. */
    present_ext = first->has_ext_commit;
    if (cmt_abci_params_vote_extensions_enabled(
            bcR->state.consensus_params.abci, first->block.header.height,
            &ext_enabled) != CMT_OK) {
        /* first.Height >= 1 always (ValidateBasic); the reference panics
         * on h < 1 (params.go:76-78). */
        free(scratch);
        free(parts);
        return CMT_FAULT;
    }
    if (present_ext != ext_enabled) {                              /* :571 */
        QGP_LOG_ERROR(LOG_TAG, "non-nil extended commit must be received iff "
                      "vote extensions are enabled for its height (height "
                      "%lld, non-nil extended commit %d, extensions enabled "
                      "%d)", (long long)first->block.header.height,
                      (int)present_ext, (int)ext_enabled);         /* :572-575 */
        verr = CMT_REJECT;                                         /* :576-577 */
    }

    /* v0.38.26 :580-585 — "Fully verify second.LastCommit to ensure all
     * signatures are valid." VerifyCommit, not VerifyCommitLight: every
     * non-absent signature is checked, so the commit saved below as this
     * block's seen commit (:625) cannot carry a bad one (R1-1). */
    if (verr == CMT_OK) {
        if (second->block.last_commit == NULL) {
            verr = CMT_REJECT;       /* ValidateBasic refuses a nil one */
        } else {
            verr = cmt_verify_commit(bcR->state.chain_id,
                                     bcR->state.chain_id_len,
                                     &bcR->state.validators, &first_id,
                                     first->block.header.height,
                                     second->block.last_commit, NULL); /* :581 */
        }
    }
    /* v0.38.26 :587-595 — "Fully verify extended commit if present". */
    if (verr == CMT_OK && ext_enabled) {
        verr = verify_commit_extended(bcR, &first_id,
                                      first->block.header.height,
                                      &first->ext_commit);         /* :591 */
    }
    /* v0.38.26 :597-613 — validate the block before it is persisted.
     * BS-11: the full ValidateBlock for EVERY block (the reference uses
     * ValidateBlockSkipLastCommit once blocksSynced > 0, :605-608). */
    if (verr == CMT_OK) {
        verr = bcR->host.validate_block(bcR->host.exec_ctx, &bcR->state,
                                        &first->block);            /* :610 */
    }
    if (verr == CMT_FAULT) {
        free(scratch);
        free(parts);
        return CMT_FAULT;
    }
    if (verr != CMT_OK) {                          /* :576, :583, :592, :611 */
        int64_t h1 = first->block.header.height;
        int64_t h2 = second->block.header.height;

        free(scratch);
        free(parts);
        /* `first` and `second` are freed inside (the requesters are
         * reset), so only their heights are passed. */
        return handle_validation_failure(bcR, h1, h2, now_ns);     /* continue FOR_LOOP */
    }

    /* :534 PopRequest — `first` now belongs to this function. */
    if (cmt_bsync_pool_pop_request(&bcR->pool, &popped) != CMT_OK ||
        popped != first) {
        cmt_bsync_block_free(popped);
        free(scratch);
        free(parts);
        return CMT_FAULT;
    }

    /* :536-545 — save BEFORE apply. */
    if (ext_enabled) {
        rc = bcR->host.bs_save_block_with_extended_commit(
                 bcR->host.exec_ctx, &first->block, &first_parts,
                 &first->ext_commit);                              /* :538 */
    } else {
        /* :539-544 "We use LastCommit here instead of extCommit." */
        rc = bcR->host.bs_save_block(bcR->host.exec_ctx, &first->block,
                                     &first_parts,
                                     second->block.last_commit);   /* :544 */
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "saving block %lld failed (%d)",
                      (long long)first->block.header.height, rc);
        cmt_bsync_block_free(first);
        free(scratch);
        free(parts);
        return CMT_FAULT;                   /* store.go panics inside Save */
    }

    /* :549 ApplyVerifiedBlock — overwrites the reactor's own state. */
    rc = bcR->host.apply_verified_block(bcR->host.exec_ctx, &first_id,
                                        &first->block, &bcR->state);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to process committed block (%lld): "
                      "%d", (long long)first->block.header.height, rc); /* :552 */
        cmt_bsync_block_free(first);
        free(scratch);
        free(parts);
        return CMT_FAULT;
    }
    bcR->blocks_synced++;                                          /* :555 */
    if (bcR->blocks_synced % 100u == 0u) {                         /* :557-562 */
        QGP_LOG_INFO(LOG_TAG, "Block Sync: height %lld, max_peer_height "
                     "%lld", (long long)cmt_bsync_pool_height(&bcR->pool),
                     (long long)cmt_bsync_pool_max_peer_height(&bcR->pool));
    }
    cmt_bsync_block_free(first);
    free(scratch);
    free(parts);
    return CMT_OK;                                                 /* :564 */
}

/* :382-438 — the switchToConsensusTicker case. */
static int switch_check(cmt_bsync_reactor_t *bcR, int64_t now_ns)
{
    int64_t height = 0;
    int32_t num_pending = 0;
    size_t  len_requesters = 0;
    bool    missing_extension = true;
    bool    ve_last = false;

    cmt_bsync_pool_get_status(&bcR->pool, &height, &num_pending,
                              &len_requesters);                    /* :383 */
    QGP_LOG_DEBUG(LOG_TAG, "Consensus ticker: numPending %d, total %zu, "
                  "lastHeight %lld", (int)num_pending, len_requesters,
                  (long long)bcR->state.last_block_height);        /* :385-386 */

    /* :405-411 */
    if (bcR->state.last_block_height != 0 &&
        cmt_abci_params_vote_extensions_enabled(
            bcR->state.consensus_params.abci, bcR->state.last_block_height,
            &ve_last) != CMT_OK) {
        return CMT_FAULT;
    }
    if (bcR->state.last_block_height == 0 || !ve_last ||
        bcR->blocks_synced > 0 || bcR->initial_commit_has_extensions) {
        missing_extension = false;
    }
    if (missing_extension) {                                       /* :414 */
        QGP_LOG_INFO(LOG_TAG, "no extended commit yet (height %lld, "
                     "last_block_height %lld, initial_height %lld, "
                     "max_peer_height %lld)", (long long)height,
                     (long long)bcR->state.last_block_height,
                     (long long)bcR->state.initial_height,
                     (long long)cmt_bsync_pool_max_peer_height(&bcR->pool));
        return CMT_OK;                                             /* :422 */
    }
    if (cmt_bsync_pool_is_caught_up(&bcR->pool, now_ns) ||
        local_node_blocks_the_chain(bcR)) {                        /* :424 */
        QGP_LOG_INFO(LOG_TAG, "Time to switch to consensus reactor! (height "
                     "%lld, blocks synced %llu)", (long long)height,
                     (unsigned long long)bcR->blocks_synced);      /* :425 */
        cmt_bsync_pool_stop(&bcR->pool);                           /* :426 */
        bcR->routine_running = false;                              /* :437 */
        if (bcR->host.switch_to_consensus != NULL) {               /* :429-430 */
            int rc = bcR->host.switch_to_consensus(
                         bcR->host.exec_ctx, &bcR->state,
                         bcR->blocks_synced > 0 || bcR->state_synced); /* :431 */

            if (rc != CMT_OK) {
                return CMT_FAULT;   /* consensus/reactor.go:132-140 panics */
            }
        }
        bcR->switched = true;
    }
    return CMT_OK;
}

int cmt_bsync_reactor_tick(cmt_bsync_reactor_t *bcR, int64_t *out_deadline_ns)
{
    int64_t now_ns;
    int64_t earliest = INT64_MAX;
    int64_t pool_deadline = INT64_MAX;
    size_t  processed = 0;

    if (out_deadline_ns != NULL) {
        *out_deadline_ns = INT64_MAX;
    }
    if (bcR == NULL) {
        return CMT_FAULT;
    }
    if (!bcR->running || !bcR->routine_running) {
        return CMT_OK;
    }
    if (reactor_now(bcR, &now_ns) != CMT_OK) {
        return CMT_FAULT;
    }

    /* :371-373 — the helper goroutine's statusUpdateTicker. */
    if (now_ns >= bcR->status_next_ns) {
        bcR->status_next_ns = now_ns + CMT_BSYNC_STATUS_UPDATE_INTERVAL_NS;
        if (cmt_bsync_reactor_broadcast_status_request(bcR) != CMT_OK) {
            return CMT_FAULT;
        }
    }
    deadline_min(&earliest, bcR->status_next_ns);

    /* the pool's goroutines (pool.go:120-156, :597-603, :838-902) */
    if (cmt_bsync_pool_tick(&bcR->pool, now_ns, &pool_deadline) != CMT_OK) {
        return CMT_FAULT;
    }
    deadline_min(&earliest, pool_deadline);

    /* :440-444 — trySyncTicker primes didProcessCh (1-deep). */
    if (now_ns >= bcR->try_sync_next_ns) {
        bcR->try_sync_next_ns = now_ns + CMT_BSYNC_TRY_SYNC_INTERVAL_NS;
        bcR->did_process = true;
    }
    deadline_min(&earliest, bcR->try_sync_next_ns);

    /* :446-564 — didProcessCh, back to back while blocks are ready,
     * bounded by step_budget (header). */
    while (bcR->did_process && processed < bcR->step_budget) {
        cmt_bsync_block_t *first = NULL;
        cmt_bsync_block_t *second = NULL;
        int                rc;

        bcR->did_process = false;                    /* the receive */
        cmt_bsync_pool_peek_two_blocks(&bcR->pool, &first, &second); /* :456 */
        if (first == NULL || second == NULL) {                     /* :457-461 */
            break;
        }
        /* :462-470 — the reference panics on these. */
        if (bcR->state.last_block_height > 0 &&
            bcR->state.last_block_height + 1 != first->block.header.height) {
            QGP_LOG_ERROR(LOG_TAG, "peeked first block has unexpected "
                          "height; expected %lld, got %lld",
                          (long long)(bcR->state.last_block_height + 1),
                          (long long)first->block.header.height);  /* :465 */
            return CMT_FAULT;
        }
        if (first->block.header.height + 1 != second->block.header.height) {
            QGP_LOG_ERROR(LOG_TAG, "heights of first and second block are "
                          "not consecutive; expected %lld, got %lld",
                          (long long)bcR->state.last_block_height,
                          (long long)first->block.header.height);  /* :469 */
            return CMT_FAULT;
        }
        /* :476-478 */
        if (!bcR->running || !cmt_bsync_pool_is_running(&bcR->pool)) {
            bcR->routine_running = false;
            return CMT_OK;
        }
        bcR->did_process = true;                                   /* :480 */
        rc = process_first(bcR, first, second, now_ns);
        processed++;
        if (rc == CMT_FAULT) {
            return CMT_FAULT;
        }
        if (rc == CMT_REJECT) {                                    /* BS-7 */
            bcR->routine_running = false;
            bcR->routine_dead = true;
            return CMT_OK;
        }
        /* The requesters' goroutines run between two passes of the
         * reference's FOR_LOOP: a redo raised by a validation failure
         * (:517-530) or the newHeight notices of a pop (pool.go:262-266)
         * are served before the next peek — otherwise the same refused
         * pair would be peeked and refused again in this very tick. */
        pool_deadline = INT64_MAX;
        if (cmt_bsync_pool_tick(&bcR->pool, now_ns, &pool_deadline) != CMT_OK) {
            return CMT_FAULT;
        }
        deadline_min(&earliest, pool_deadline);
    }
    if (bcR->did_process) {
        deadline_min(&earliest, now_ns);     /* blocks still waiting */
    }

    /* :382-438 — switchToConsensusTicker. */
    if (now_ns >= bcR->switch_next_ns) {
        bcR->switch_next_ns = now_ns +
            bcR->switch_to_consensus_ms * CMT_BSYNC_NS_PER_MS;
        if (switch_check(bcR, now_ns) != CMT_OK) {
            return CMT_FAULT;
        }
        if (!bcR->routine_running) {
            return CMT_OK;                   /* break FOR_LOOP (:437) */
        }
    }
    deadline_min(&earliest, bcR->switch_next_ns);

    if (out_deadline_ns != NULL) {
        *out_deadline_ns = earliest;
    }
    return CMT_OK;
}

/* :574-580 BroadcastStatusRequest() */
int cmt_bsync_reactor_broadcast_status_request(cmt_bsync_reactor_t *bcR)
{
    cmt_bsync_msg_t m;
    uint8_t         buf[8];
    size_t          n = 0;

    if (bcR == NULL) {
        return CMT_FAULT;
    }
    cmt_bsync_msg_init(&m);
    m.kind = CMT_BSYNC_MSG_STATUS_REQUEST;                         /* :578 */
    if (cmt_bsync_msg_marshal(&m, buf, sizeof(buf), &n) != CMT_OK) {
        return CMT_FAULT;
    }
    bcR->host.broadcast(bcR->host.ctx, buf, n);                    /* :576 */
    return CMT_OK;
}

/* ── accessors ─────────────────────────────────────────────────────── */

bool cmt_bsync_reactor_is_syncing(const cmt_bsync_reactor_t *bcR)
{
    return bcR != NULL && bcR->routine_running;
}

bool cmt_bsync_reactor_switched(const cmt_bsync_reactor_t *bcR)
{
    return bcR != NULL && bcR->switched;
}

uint64_t cmt_bsync_reactor_blocks_synced(const cmt_bsync_reactor_t *bcR)
{
    return bcR != NULL ? bcR->blocks_synced : 0u;
}

const cmt_state_t *cmt_bsync_reactor_state(const cmt_bsync_reactor_t *bcR)
{
    return bcR != NULL ? &bcR->state : NULL;
}

cmt_bsync_pool_t *cmt_bsync_reactor_pool(cmt_bsync_reactor_t *bcR)
{
    return bcR != NULL ? &bcR->pool : NULL;
}
