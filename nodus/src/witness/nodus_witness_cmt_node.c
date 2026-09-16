/**
 * @file nodus/src/witness/nodus_witness_cmt_node.c
 * @brief THE STARTUP TABLE — see nodus_witness_cmt_node.h for what is
 *        here, what is not, whose the missing halves are, and the
 *        governing records. Every function below carries the
 *        `cometbft@709fd12b <file>:<lines>` it was ported from.
 *
 * ⚠ LINE NUMBERS. Every citation in this file is the line range as it
 * reads in the extracted pinned tarball @709fd12b (pin rev 19). Where a
 * dispatch prose quoted a slightly different range for the same function
 * the FILE was taken as the authority.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_cmt_node.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>       /* `cmtos.FileExists`' os.Stat (os.go:58-61) */

#include <sqlite3.h>

#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_merkle.h"
#include "dnac/cmt_params.h"
#include "dnac/cmt_tmhash.h"
#include "dnac/cmt_validator_set.h"

#include "server/nodus_server.h"                /* w->server->identity    */
#include "witness/nodus_witness_v2_apply.h"    /* committed_global_root  */
#include "witness/nodus_witness_v2_produce.h"  /* tip_height             */

#define LOG_TAG "CMT_NODE"

/** The default evidence bound of `nodus_cmt_node_init`. The reference
 *  bounds evidence by `Evidence.MaxBytes` alone; this port sizes arrays,
 *  and the chain's own evidence lane is W3's, so a small explicit bound
 *  is used and named rather than derived from a parameter nothing here
 *  reads yet. */
#define NODE_DEFAULT_MAX_EVIDENCE 8u

/* ═══════════════════════════════════════════════════════════════════════
 * Info — abci/types/application.go:11, proxy/app_conn.go:42
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_node_app_info(nodus_witness_t *w, nodus_cmt_app_info_t *out)
{
    uint64_t tip = 0;

    if (!w || !out) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));

    /* The last block this APPLICATION has applied — the successor tip.
     * A chain whose only committed state is its genesis answers 0, which
     * is exactly what sends the Handshaker down the InitChain branch
     * (replay.go:320). */
    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "Info: the ledger's tip height is unreadable");
        return CMT_FAULT;
    }
    if (tip > (uint64_t)INT64_MAX) {
        /* replay.go:256-258 refuses a NEGATIVE height from the app; a
         * uint64 tip above INT64_MAX would become one. The ledger is
         * this node's own database, so this is a node-local invariant
         * broken — umbrella rev 6's panic rule. */
        QGP_LOG_ERROR(LOG_TAG, "Info: the ledger tip %" PRIu64 " does not fit "
                      "an int64 block height", tip);
        return CMT_FAULT;
    }
    out->last_block_height = (int64_t)tip;

    /* The root after that block: the stored row's, or the genesis
     * composition where no row exists (nodus_witness_v2_apply.h:992-1020).
     * This is the SAME reader the application's InitChain uses — one
     * quantity, one reader. */
    if (nodus_witness_v2_committed_global_root(w, out->last_block_app_hash)
        != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "Info: the ledger's committed global root is unreadable");
        return CMT_FAULT;
    }
    out->last_block_app_hash_len = 64u;

    /* ResponseInfo field 3. This application declares no ABCI app
     * version, and D-4 rev 3 (2) writes `Version.App 0` into the genesis
     * document, so the two agree by construction. */
    out->app_version = 0u;
    /* Field 2 — the port's counterpart of `version.TMCoreSemVer`
     * (proxy/version.go:12): the build's own string, which
     * `cmt_state_make_genesis` also writes into `State.Version.Software`
     * (cmt_state.c:423-424). */
    out->version = CMT_SOFTWARE_VERSION;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The mock application — consensus/replay_stubs.go:60-79
 * ═══════════════════════════════════════════════════════════════════════ */

/** replay_stubs.go:77-79 — `FinalizeBlock` returns the stored response,
 *  unchanged, for every request. The request is not read at all: the
 *  reference's parameters are both `_`. */
static int mock_finalize_block(void *vctx,
                               const nodus_abci_request_finalize_block_t *req,
                               nodus_abci_response_finalize_block_t *resp)
{
    nodus_cmt_mock_app_t *m = (nodus_cmt_mock_app_t *)vctx;

    (void)req;
    if (!m || !resp) {
        return CMT_FAULT;
    }
    m->finalize_calls++;
    /* A shallow copy, which is what returning the Go pointer is: the
     * arrays stay the mock's and must outlive the caller's use of
     * `resp` — the same ownership rule every row in this port has
     * (proxy/app_conn.go). */
    *resp = m->resp;
    return CMT_OK;
}

/**
 * The COMMIT of the transaction the host opened before `finalize_block`
 * (D-23 rev 5 (5)). See nodus_witness_cmt_node.h's note on
 * `nodus_cmt_mock_app_t` for why this is NOT BaseApplication's empty
 * answer (application.go:56-58).
 *
 * `retain_height` stays 0: the reference's mock returns an empty
 * `ResponseCommit` and no pruning happens on a replay.
 */
static int mock_commit(void *vctx, nodus_abci_response_commit_t *resp)
{
    nodus_cmt_mock_app_t *m = (nodus_cmt_mock_app_t *)vctx;
    char *err = NULL;

    if (!m || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    if (!m->db) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "mock Commit: no ledger connection");
        return CMT_FAULT;
    }
    if (sqlite3_get_autocommit(m->db)) {
        /* The host ALWAYS opens the transaction before calling us
         * (nodus_witness_cmt_host.c:1459, :1624). Finding none is a
         * node-local invariant broken, never a peer's doing. */
        QGP_LOG_ERROR(LOG_TAG, "%s", "mock Commit: no open transaction to "
                      "commit — the host's bracket was not entered");
        return CMT_FAULT;
    }
    if (sqlite3_exec(m->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "mock Commit: COMMIT failed: %s",
                      err ? err : "?");
        sqlite3_free(err);
        return CMT_FAULT;
    }
    m->commit_calls++;
    return CMT_OK;
}

/** abci/types/application.go:64-66 — `BaseApplication.InitChain` returns
 *  an empty `ResponseInitChain`. */
static int mock_init_chain(void *ctx,
                           const nodus_abci_request_init_chain_t *req,
                           nodus_abci_response_init_chain_t *resp)
{
    (void)ctx;
    (void)req;
    if (!resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    return CMT_OK;
}

/** abci/types/application.go:84-95 — `BaseApplication.PrepareProposal`
 *  echoes the request's transactions, stopping at the FIRST one whose
 *  inclusion would push the running total past `MaxTxBytes` (:89-91:
 *  the total is incremented BEFORE the test, so the transaction that
 *  crosses the bound is excluded and the loop breaks). */
static int mock_prepare_proposal(
        void *ctx, const nodus_abci_request_prepare_proposal_t *req,
        nodus_abci_response_prepare_proposal_t *resp)
{
    nodus_cmt_mock_app_t *m = (nodus_cmt_mock_app_t *)ctx;
    int64_t total = 0;
    size_t  i;

    if (!m || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    for (i = 0; i < req->txs_len; i++) {
        total += (int64_t)req->txs[i].len;                       /* :88 */
        if (total > req->max_tx_bytes) {                         /* :89 */
            break;                                               /* :90 */
        }
    }
    resp->txs     = req->txs;                                    /* :92 */
    resp->txs_len = i;
    return CMT_OK;
}

/** abci/types/application.go:97-99 — ACCEPT. */
static int mock_process_proposal(
        void *ctx, const nodus_abci_request_process_proposal_t *req,
        nodus_abci_response_process_proposal_t *resp)
{
    (void)ctx;
    (void)req;
    if (!resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    resp->status = (int32_t)NODUS_ABCI_PROPOSAL_STATUS_ACCEPT;
    return CMT_OK;
}

/** abci/types/application.go:101-103 — an EMPTY `ResponseExtendVote`. */
static int mock_extend_vote(void *ctx,
                            const nodus_abci_request_extend_vote_t *req,
                            nodus_abci_response_extend_vote_t *resp)
{
    (void)ctx;
    (void)req;
    if (!resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    return CMT_OK;
}

/** abci/types/application.go:105-109 — status ACCEPT. */
static int mock_verify_vote_extension(
        void *ctx, const nodus_abci_request_verify_vote_extension_t *req,
        nodus_abci_response_verify_vote_extension_t *resp)
{
    (void)ctx;
    (void)req;
    if (!resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    resp->status = (int32_t)NODUS_ABCI_VERIFY_STATUS_ACCEPT;
    return CMT_OK;
}

int nodus_cmt_mock_app_build(nodus_cmt_app_t *out, nodus_cmt_mock_app_t *m)
{
    if (!out || !m) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->ctx                   = m;
    out->init_chain            = mock_init_chain;
    out->prepare_proposal      = mock_prepare_proposal;
    out->process_proposal      = mock_process_proposal;
    out->extend_vote           = mock_extend_vote;
    out->verify_vote_extension = mock_verify_vote_extension;
    out->finalize_block        = mock_finalize_block;
    out->commit                = mock_commit;
    return CMT_OK;
}

void nodus_cmt_mock_app_close(nodus_cmt_mock_app_t *m)
{
    if (!m) {
        return;
    }
    free(m->pool_events);
    free(m->pool_attributes);
    free(m->pool_tx_results);
    free(m->pool_validator_updates);
    free(m->arena.buf);
    memset(m, 0, sizeof(*m));
}

int nodus_cmt_mock_app_open(nodus_cmt_mock_app_t *m, nodus_cmt_store_t *store,
                            sqlite3 *db, int64_t height,
                            const uint8_t *info_app_hash,
                            size_t info_app_hash_len, size_t max_txs)
{
    size_t n_events, n_attrs, arena_cap;
    int    rc;

    if (!m || !store || !db || max_txs == 0) {
        return CMT_FAULT;
    }
    memset(m, 0, sizeof(*m));
    m->db = db;

    /* THE POOL BOUNDS. The response being loaded is this node's OWN
     * FinalizeBlock product, written by the ledger application at the
     * height being replayed — never a peer's message. So the bounds
     * below are the application's own, and a stored response above them
     * is a node-local invariant broken (the decoder REFUSES, and this
     * function reports CMT_FAULT):
     *   tx_results        the application's per-request item bound;
     *   validator_updates the validator-set bound the state carries;
     *   events            the ledger application emits NONE
     *                     (nodus_witness_cmt_app.h's "WHAT THIS LANE
     *                     DOES NOT DO YET"), so the pool exists only so
     *                     that a response carrying one decodes rather
     *                     than being silently dropped. */
    n_events  = max_txs + 8u;
    n_attrs   = 4u * n_events;
    arena_cap = (64u * 1024u) + (256u * max_txs);

    m->pool_events = (cmt_pb_event_t *)calloc(n_events, sizeof(cmt_pb_event_t));
    m->pool_attributes = (cmt_pb_event_attribute_t *)
        calloc(n_attrs, sizeof(cmt_pb_event_attribute_t));
    m->pool_tx_results = (cmt_pb_stored_exec_tx_result_t *)
        calloc(max_txs, sizeof(cmt_pb_stored_exec_tx_result_t));
    m->pool_validator_updates = (cmt_pb_validator_update_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_pb_validator_update_t));
    m->arena.buf = (uint8_t *)malloc(arena_cap);
    m->arena.cap = arena_cap;
    if (!m->pool_events || !m->pool_attributes || !m->pool_tx_results ||
        !m->pool_validator_updates || !m->arena.buf) {
        nodus_cmt_mock_app_close(m);
        return CMT_FAULT;
    }
    m->storage.events                = m->pool_events;
    m->storage.events_cap            = n_events;
    m->storage.attributes            = m->pool_attributes;
    m->storage.attributes_cap        = n_attrs;
    m->storage.tx_results            = m->pool_tx_results;
    m->storage.tx_results_cap        = max_txs;
    m->storage.validator_updates     = m->pool_validator_updates;
    m->storage.validator_updates_cap = CMT_VALSET_MAX;
    m->storage.arena                 = &m->arena;

    /* replay.go:439 — LoadLastFinalizeBlockResponse(storeBlockHeight). */
    rc = nodus_cmt_ss_load_last_finalize_block_response(store, height,
                                                        &m->storage, &m->resp);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "no stored FinalizeBlock response at height %"
                      PRId64 " (rc %d) — the \"ran Commit, didn't save the "
                      "state\" branch cannot be replayed", height, rc);
        /* :440-442 returns the store's error and the handshake fails.
         * CMT_REJECT is kept distinct from CMT_FAULT here so the caller
         * can say WHICH happened; both stop the node. */
        nodus_cmt_mock_app_close(m);
        return rc;
    }
    /* :443-449 — the rare upgrade edge case: a response saved without an
     * app hash takes the one the Info handshake returned. Ported because
     * the reference has it; on this chain the application always writes
     * one, so it is expected to be unreachable. */
    if (m->resp.app_hash_len == 0 && info_app_hash && info_app_hash_len > 0) {
        if (info_app_hash_len > CMT_PB_HASH_MAX) {
            nodus_cmt_mock_app_close(m);
            return CMT_FAULT;
        }
        memcpy(m->resp.app_hash, info_app_hash, info_app_hash_len);
        m->resp.app_hash_len = info_app_hash_len;
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The Handshaker — consensus/replay.go:201-565
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * replay.go:545-553 — `assertAppHashEqualsOneFromBlock`. The reference
 * PANICS; umbrella rev 6's rule maps a node-local invariant to
 * CMT_FAULT, and this one is node-local by construction: both sides come
 * from this node's own database.
 */
static int hs_assert_app_hash_from_block(const uint8_t *app_hash, size_t len,
                                         const cmt_block_t *block)
{
    if (len != block->header.app_hash_len ||
        (len > 0 && memcmp(app_hash, block->header.app_hash, len) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "block.AppHash does not match AppHash after "
                      "replay at height %" PRId64, block->header.height);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/** replay.go:555-565 — `assertAppHashEqualsOneFromState`. Same class. */
static int hs_assert_app_hash_from_state(const uint8_t *app_hash, size_t len,
                                         const cmt_state_t *state)
{
    if (len != state->app_hash_len ||
        (len > 0 && memcmp(app_hash, state->app_hash, len) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "state.AppHash does not match AppHash after "
                      "replay (state height %" PRId64 "). Did you reset the "
                      "consensus store without resetting the ledger?",
                      state->last_block_height);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/**
 * `sm.NewBlockExecutor(h.stateStore, h.logger, proxyApp, emptyMempool{},
 * sm.EmptyEvidencePool{}, h.store)` — replay.go:531, and the same
 * collaborators ExecCommitBlock needs at :503.
 *
 * The reference constructs one per `replayBlock` call because Go's
 * constructor allocates nothing; this port's allocates every scratch
 * buffer, so the object is built where the reference builds it and
 * released immediately after. `slots`, `ext_arena`, `wal` and `pv` are
 * NULL: none of the rows reached on a replay path touches them
 * (nodus_witness_cmt_host.c:366-390 stores them without dereferencing,
 * and test_cmt_app.c:804 drives the same construction).
 *
 * THE CLOCK IS NOT NULL, and it is not read either. `blockexec_init`
 * refuses a NULL `now` outright (host.c:381), so one must be passed; the
 * only two readers of `ctx->now` in the whole host are `host_now`
 * (host.c:2020-2027) and `host_timer_arm` (:2032-2050), which are the
 * `cmt_cs` seam's clock and ticker rows — neither is reachable from
 * `ExecCommitBlock` or `ApplyBlock`, the only entries a replay uses. The
 * handshake therefore reads no clock, exactly as the reference's does.
 */
static int hs_exec_open(nodus_cmt_handshaker_t *h, nodus_cmt_app_t *app,
                        nodus_cmt_blockexec_t **out)
{
    nodus_cmt_blockexec_t *be;

    *out = NULL;
    be = (nodus_cmt_blockexec_t *)calloc(1, sizeof(*be));
    if (!be) {
        return CMT_FAULT;
    }
    if (nodus_cmt_blockexec_init(be, h->store, app, &h->nop_mempool,
                                 &h->empty_evpool, NULL, NULL,
                                 h->now, h->now_ctx, NULL, NULL,
                                 &h->limits) != CMT_OK) {
        free(be);
        return CMT_FAULT;
    }
    *out = be;
    return CMT_OK;
}

static void hs_exec_close(nodus_cmt_blockexec_t *be)
{
    if (be) {
        nodus_cmt_blockexec_release(be);
        free(be);
    }
}

/** store.go:137-167 `LoadBlock(height)` into the handshaker's storage.
 *  The reference panics on a missing block inside `replayBlocks`'
 *  loop (it dereferences the nil); a height the store said it has and
 *  then cannot produce is node-local — CMT_FAULT. */
static int hs_load_block(nodus_cmt_handshaker_t *h, int64_t height,
                         cmt_block_t *out)
{
    bool found = false;

    h->dec_arena.used = 0;
    if (nodus_cmt_bs_load_block(h->store, height, h->dec_buf, h->dec_buf_cap,
                                &h->dec, out, &found) != CMT_OK) {
        return CMT_FAULT;
    }
    if (!found) {
        QGP_LOG_ERROR(LOG_TAG, "the block store has no block at height %"
                      PRId64 " it claims to hold", height);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/**
 * replay.go:525-543 — `replayBlock(state, height, proxyApp)`: the block
 * and its meta from the store, a fresh BlockExecutor over the stubs, and
 * `ApplyBlock(state, meta.BlockID, block)`.
 *
 * `state` is mutated in place; the reference returns a new `sm.State`
 * and its caller assigns it to the same variable (:434, :452, :513).
 */
static int hs_replay_block(nodus_cmt_handshaker_t *h, cmt_state_t *state,
                           int64_t height, nodus_cmt_app_t *app)
{
    nodus_cmt_blockexec_t *be = NULL;
    nodus_cmt_block_meta_t *meta;
    cmt_block_t            *block;
    bool                    found = false;
    int                     rc;

    block = (cmt_block_t *)calloc(1, sizeof(*block));
    meta  = (nodus_cmt_block_meta_t *)calloc(1, sizeof(*meta));
    if (!block || !meta) {
        free(block);
        free(meta);
        return CMT_FAULT;
    }
    rc = hs_load_block(h, height, block);                            /* :526 */
    if (rc != CMT_OK) {
        goto done;
    }
    rc = nodus_cmt_bs_load_block_meta(h->store, height, meta, &found); /* :527 */
    if (rc != CMT_OK || !found) {
        QGP_LOG_ERROR(LOG_TAG, "no block meta at height %" PRId64, height);
        rc = CMT_FAULT;
        goto done;
    }
    rc = hs_exec_open(h, app, &be);                                  /* :531 */
    if (rc != CMT_OK) {
        goto done;
    }
    /* :535 — ApplyBlock, which VALIDATES the block first
     * (execution.go:215) and then applies it inside the host's ledger
     * transaction. A REJECT here means this node's own stored block does
     * not validate against its own stored state: node-local, CMT_FAULT.
     * :536-538's error return makes NewNode fail either way. */
    rc = nodus_cmt_blockexec_apply_block(be, &meta->block_id, block, state);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "replaying block %" PRId64 " failed (rc %d)",
                      height, rc);
        rc = CMT_FAULT;
        goto done;
    }
    h->nblocks++;                                                    /* :540 */
done:
    hs_exec_close(be);
    free(block);
    free(meta);
    return rc;
}

/**
 * replay.go:462-522 — `replayBlocks(ctx, state, proxyApp, appBlockHeight,
 * storeBlockHeight, mutateState)`.
 *
 * `io_app_hash` carries the reference's local `appHash` in and out: it
 * arrives EMPTY (`var appHash []byte`, :479) and is written by every
 * `ExecCommitBlock`.
 */
static int hs_replay_blocks(nodus_cmt_handshaker_t *h, cmt_state_t *state,
                            nodus_cmt_app_t *app, int64_t app_block_height,
                            int64_t store_block_height, bool mutate_state,
                            uint8_t *io_app_hash, size_t *io_app_hash_len)
{
    nodus_cmt_blockexec_t *be = NULL;
    cmt_block_t           *block;
    int64_t                final_block, first_block, i;
    int                    rc;

    /* :479-480 — appHash starts EMPTY for this function, whatever the
     * caller's Info answer was. */
    *io_app_hash_len = 0;

    final_block = store_block_height;                                /* :481 */
    if (mutate_state) {
        final_block--;                                               /* :483 */
    }
    first_block = app_block_height + 1;                              /* :485 */
    if (first_block == 1) {
        first_block = state->initial_height;                         /* :487 */
    }

    block = (cmt_block_t *)calloc(1, sizeof(*block));
    if (!block) {
        return CMT_FAULT;
    }
    /* ⚠ DEVIATION R3-C1c-3, reported: ONE executor for the whole loop —
     * a stated substitution, not a
     * shape change: the reference calls `sm.ExecCommitBlock(
     * proxyApp.Consensus(), …)` (:503) with no executor at all, but this
     * port's `nodus_cmt_exec_commit_block` needs the scratch its
     * BlockExecutor owns. The collaborators are the ones :503 has
     * (the real application; no mempool, no evidence pool), so nothing
     * the loop can observe differs. */
    rc = hs_exec_open(h, app, &be);
    if (rc != CMT_OK) {
        free(block);
        return rc;
    }
    for (i = first_block; i <= final_block; i++) {                   /* :489 */
        QGP_LOG_INFO(LOG_TAG, "applying block %" PRId64, i);         /* :496 */
        rc = hs_load_block(h, i, block);                             /* :497 */
        if (rc != CMT_OK) {
            goto done;
        }
        if (*io_app_hash_len > 0) {                                  /* :499 */
            rc = hs_assert_app_hash_from_block(io_app_hash, *io_app_hash_len,
                                               block);              /* :500 */
            if (rc != CMT_OK) {
                goto done;
            }
        }
        /* :503 — ExecCommitBlock(proxyApp.Consensus(), block, logger,
         * stateStore, genDoc.InitialHeight). */
        rc = nodus_cmt_exec_commit_block(be, block, h->gendoc->initial_height,
                                         io_app_hash, io_app_hash_len);
        if (rc != CMT_OK) {                                          /* :504-506 */
            QGP_LOG_ERROR(LOG_TAG, "ExecCommitBlock failed at height %" PRId64
                          " (rc %d)", i, rc);
            rc = CMT_FAULT;
            goto done;
        }
        h->nblocks++;                                                /* :508 */
    }
    /* The loop's executor is released BEFORE `replayBlock` builds its
     * own, so the two never hold the ledger at once — the reference's
     * `replayBlock` likewise constructs a fresh executor at :531. */
    hs_exec_close(be);
    be = NULL;

    if (mutate_state) {                                              /* :511 */
        rc = hs_replay_block(h, state, store_block_height, app);     /* :513 */
        if (rc != CMT_OK) {                                          /* :514-516 */
            goto done;
        }
        memcpy(io_app_hash, state->app_hash, state->app_hash_len);   /* :517 */
        *io_app_hash_len = state->app_hash_len;
    }
    rc = hs_assert_app_hash_from_state(io_app_hash, *io_app_hash_len, state);
                                                                     /* :520 */
done:
    hs_exec_close(be);
    free(block);
    return rc;
}

/** types/params.go:325-346 — `(params *ConsensusParams) ToProto()`. All
 *  five sub-messages are non-nil in the reference's literal, so all five
 *  `has_*` flags are true. */
static void hs_params_to_proto(const cmt_consensus_params_t *in,
                               cmt_pb_consensus_params_t *out)
{
    memset(out, 0, sizeof(*out));
    out->has_block    = true;  out->block    = in->block;      /* :327-330 */
    out->has_evidence = true;  out->evidence = in->evidence;   /* :331-335 */
    out->has_validator = true; out->validator = in->validator; /* :336-338 */
    out->has_version  = true;  out->version  = in->version;    /* :339-341 */
    out->has_abci     = true;  out->abci     = in->abci;       /* :342-344 */
}

/**
 * replay.go:320-373 — the `appBlockHeight == 0` InitChain branch.
 *
 * `state` is the replay's working state; `io_app_hash` carries `appHash`
 * in and out (:341).
 */
static int hs_init_chain(nodus_cmt_handshaker_t *h, cmt_state_t *state,
                         nodus_cmt_app_t *app, int64_t state_block_height,
                         uint8_t *io_app_hash, size_t *io_app_hash_len)
{
    nodus_abci_request_init_chain_t  req;
    nodus_abci_response_init_chain_t resp;
    cmt_pb_consensus_params_t        pbparams;
    cmt_validator_t                 *valz = NULL;
    cmt_validator_t                 *vstor = NULL;
    cmt_pb_validator_update_t       *next_vals = NULL;
    cmt_validator_set_t              vset;
    cmt_valset_scratch_t            *scratch = NULL;
    size_t                           n, i;
    int                              rc = CMT_FAULT;

    n = h->gendoc->validators_len;

    /* :321-325 — one `types.NewValidator(val.PubKey, val.Power)` per
     * genesis entry, then `NewValidatorSet(validators)`. The SET's order
     * (ValidatorsByVotingPower, after one IncrementProposerPriority) is
     * what TM2PB then emits, and it is not the document's order — which
     * is why the application's InitChain compares the two lists as
     * MULTISETS (nodus_witness_cmt_app.c's check 3).
     *
     * `vstor` is storage SEPARATE from `valz`: `cmt_validator_set_new`
     * copies the source list into the set's storage, and letting the two
     * alias would be a self-copy. The tests build a set the same way
     * (test_cmt_host.c:692-719 `valset_make`). */
    valz      = (cmt_validator_t *)calloc(n ? n : 1, sizeof(cmt_validator_t));
    vstor     = (cmt_validator_t *)calloc(n ? n : 1, sizeof(cmt_validator_t));
    next_vals = (cmt_pb_validator_update_t *)
        calloc(n ? n : 1, sizeof(cmt_pb_validator_update_t));
    scratch   = (cmt_valset_scratch_t *)calloc(1, sizeof(*scratch));
    if (!valz || !vstor || !next_vals || !scratch) {
        goto done;
    }
    for (i = 0; i < n; i++) {
        if (cmt_validator_new(&h->gendoc->validators[i].pub_key,
                              h->gendoc->validators[i].power,
                              &valz[i]) != CMT_OK) {                 /* :323 */
            QGP_LOG_ERROR(LOG_TAG, "genesis validator %zu is not a validator "
                          "this port can build", i);
            goto done;
        }
    }
    if (cmt_validator_set_init(&vset, vstor, n ? n : 1) != CMT_OK ||
        cmt_validator_set_new(&vset, valz, n, scratch) != CMT_OK) {  /* :325 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "the genesis validator set is not a set "
                      "this port can build");
        goto done;
    }
    /* :326 — types/protobuf.go:75-81 TM2PB.ValidatorUpdates, which is
     * :63-72 TM2PB.ValidatorUpdate per member: {PubKey, VotingPower}. */
    for (i = 0; i < vset.validators_len; i++) {
        next_vals[i].pub_key = vset.validators[i].pub_key;           /* :69 */
        next_vals[i].power   = vset.validators[i].voting_power;      /* :70 */
    }
    hs_params_to_proto(&h->gendoc->consensus_params, &pbparams);     /* :327 */

    /* :328-335 — the six fields RequestInitChain carries, and no more.
     * `app_state_bytes` is EMPTY: this chain's genesis is applied by the
     * derivation, not by the application (D-18 rev 4, D-23 rev 5 (7)),
     * and the version-3 document carries no AppState. */
    memset(&req, 0, sizeof(req));
    req.time = h->gendoc->genesis_time;                              /* :329 */
    if (h->gendoc->chain_id_len > CMT_PB_CHAINID_MAX) {
        goto done;
    }
    memcpy(req.chain_id, h->gendoc->chain_id, h->gendoc->chain_id_len);
    req.chain_id_len          = h->gendoc->chain_id_len;             /* :330 */
    req.initial_height        = h->gendoc->initial_height;           /* :331 */
    req.has_consensus_params  = true;                                /* :332 */
    req.consensus_params      = pbparams;
    req.validators            = next_vals;                           /* :333 */
    req.validators_len        = vset.validators_len;
    req.app_state_bytes.data  = NULL;                                /* :334 */
    req.app_state_bytes.len   = 0;

    memset(&resp, 0, sizeof(resp));
    if (app->init_chain(app->ctx, &req, &resp) != CMT_OK) {          /* :336 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "InitChain was refused by the "
                      "application — the committed genesis state is not the "
                      "one the stored document describes");
        goto done;                                                   /* :337-339 */
    }
    /* :341 */
    if (resp.app_hash_len > CMT_PB_HASH_MAX) {
        goto done;
    }
    memcpy(io_app_hash, resp.app_hash, resp.app_hash_len);
    *io_app_hash_len = resp.app_hash_len;

    if (state_block_height == 0) {                                   /* :343 */
        /* :344-349 — only a NON-EMPTY app hash replaces the document's. */
        if (resp.app_hash_len > 0) {
            memcpy(state->app_hash, resp.app_hash, resp.app_hash_len);
            state->app_hash_len = resp.app_hash_len;
        }
        /* :350-361 — validator updates from InitChain. The C1a
         * application returns NONE (nodus_witness_cmt_app.h's "WHAT THIS
         * LANE DOES NOT DO YET"), and the genesis document's validator
         * list is non-empty on every chain this port can open (the
         * version-3 rules refuse a document without validators), so
         * :358-360's "validator set is nil in genesis and still empty
         * after InitChain" is UNREACHABLE here. It is ported anyway,
         * because a document with no validators is a shape this function
         * must not silently accept if a later wave produces one. */
        if (resp.validators_len > 0) {                               /* :351 */
            cmt_validator_t *changes = (cmt_validator_t *)
                calloc(resp.validators_len, sizeof(cmt_validator_t));

            if (!changes) {
                goto done;
            }
            if (nodus_cmt_pb2tm_validator_updates(resp.validators,
                                                  resp.validators_len,
                                                  changes,
                                                  resp.validators_len)
                != CMT_OK) {                                         /* :352 */
                free(changes);
                QGP_LOG_ERROR(LOG_TAG, "%s", "InitChain returned validator "
                              "updates this port cannot convert");
                goto done;                                           /* :353-355 */
            }
            if (cmt_validator_set_init(&state->validators,
                                       state->storage->validators,
                                       CMT_VALSET_MAX) != CMT_OK ||
                cmt_validator_set_new(&state->validators, changes,
                                      resp.validators_len, scratch)
                    != CMT_OK ||                                     /* :356 */
                cmt_validator_set_init(&state->next_validators,
                                       state->storage->next_validators,
                                       CMT_VALSET_MAX) != CMT_OK ||
                cmt_validator_set_new(&state->next_validators, changes,
                                      resp.validators_len, scratch)
                    != CMT_OK ||
                cmt_validator_set_increment_proposer_priority(
                        &state->next_validators, 1) != CMT_OK) {     /* :357 */
                free(changes);
                goto done;
            }
            free(changes);
        } else if (h->gendoc->validators_len == 0) {                 /* :358 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "validator set is nil in genesis and "
                          "still empty after InitChain");
            goto done;                                               /* :360 */
        }
        if (resp.has_consensus_params) {                             /* :363 */
            cmt_consensus_params_t updated;

            if (cmt_consensus_params_update(&state->consensus_params,
                                            &resp.consensus_params,
                                            &updated) != CMT_OK) {   /* :364 */
                goto done;
            }
            state->consensus_params     = updated;
            state->version.consensus.app = updated.version.app;      /* :365 */
        }
        /* :367-368 — "We update the last results hash with the empty
         * hash, to conform with RFC-6962": merkle.HashFromByteSlices(nil)
         * = crypto/merkle/hash.go:16-18 emptyHash() = H(""). */
        if (cmt_merkle_empty_hash(state->last_results_hash) != CMT_OK) {
            goto done;
        }
        state->last_results_hash_len = CMT_TMHASH_SIZE;
        if (nodus_cmt_ss_save(h->store, state) != CMT_OK) {          /* :369 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "the genesis state could not be "
                          "saved");
            goto done;                                               /* :370 */
        }
    }
    rc = CMT_OK;
done:
    free(valz);
    free(vstor);
    free(next_vals);
    free(scratch);
    return rc;
}

/**
 * replay.go:300-460 — `ReplayBlocksWithContext(ctx, state, appHash,
 * appBlockHeight, proxyApp)`.
 *
 * ── THE FAULT CLASSES, ONCE ────────────────────────────────────────────
 * Five of the reference's exits below are `panic` and three are `return
 * …, err`. All eight become CMT_FAULT, and the reason is the same for
 * every one: the handshake has NO PEER INPUT. Its three heights come
 * from this node's own ledger, its own block store and its own state
 * store, and its genesis document from its own `cmt_state` row. CMT_REJECT
 * in this port is a verdict about somebody else's bytes (umbrella rev 6);
 * there are none here. The `return …, err` cases differ from the panics
 * only in that the reference unwinds instead of aborting — in both,
 * `NewNode` fails and the node does not start, which is what CMT_FAULT
 * means to this function's caller.
 */
static int hs_replay_blocks_with_context(nodus_cmt_handshaker_t *h,
                                         cmt_state_t *state,
                                         nodus_cmt_app_t *app,
                                         int64_t app_block_height,
                                         uint8_t *io_app_hash,
                                         size_t *io_app_hash_len)
{
    int64_t store_block_base   = nodus_cmt_bs_base(h->store);        /* :307 */
    int64_t store_block_height = nodus_cmt_bs_height(h->store);      /* :308 */
    int64_t state_block_height = state->last_block_height;           /* :309 */
    int     rc;

    QGP_LOG_INFO(LOG_TAG, "ABCI replay blocks: app %" PRId64 ", store %" PRId64
                 ", state %" PRId64, app_block_height, store_block_height,
                 state_block_height);

    if (app_block_height == 0) {                                     /* :320 */
        rc = hs_init_chain(h, state, app, state_block_height,
                           io_app_hash, io_app_hash_len);
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    }

    /* :376-400 — the edge cases, in the reference's order. */
    if (store_block_height == 0) {                                   /* :377 */
        return hs_assert_app_hash_from_state(io_app_hash, *io_app_hash_len,
                                             state);                 /* :378-379 */
    }
    if (app_block_height == 0 && state->initial_height < store_block_base) {
        /* :381-383 ErrAppBlockHeightTooLow — the app has no state and
         * the block store is truncated above the initial height. */
        QGP_LOG_ERROR(LOG_TAG, "app block height %" PRId64 " is too low for a "
                      "block store based at %" PRId64, app_block_height,
                      store_block_base);
        return CMT_FAULT;
    }
    if (app_block_height > 0 && app_block_height < store_block_base - 1) {
        /* :385-387 ErrAppBlockHeightTooLow. */
        QGP_LOG_ERROR(LOG_TAG, "app block height %" PRId64 " is too far behind "
                      "a block store based at %" PRId64, app_block_height,
                      store_block_base);
        return CMT_FAULT;
    }
    if (store_block_height < app_block_height) {
        /* :389-391 ErrAppBlockHeightTooHigh — "the app should never be
         * ahead of the store (but this is under app's control)". In this
         * port the application IS this node's ledger, so "under the
         * app's control" still means node-local. */
        QGP_LOG_ERROR(LOG_TAG, "the ledger is at height %" PRId64 " but the "
                      "block store only at %" PRId64, app_block_height,
                      store_block_height);
        return CMT_FAULT;
    }
    if (store_block_height < state_block_height) {
        QGP_LOG_ERROR(LOG_TAG, "state block height (%" PRId64 ") > store block "
                      "height (%" PRId64 ")", state_block_height,
                      store_block_height);
        return CMT_FAULT;                                            /* :393-395 */
    }
    if (store_block_height > state_block_height + 1) {
        QGP_LOG_ERROR(LOG_TAG, "store block height (%" PRId64 ") > state block "
                      "height + 1 (%" PRId64 ")", store_block_height,
                      state_block_height + 1);
        return CMT_FAULT;                                            /* :397-399 */
    }

    /* :405-456 — the store is equal to the state, or one ahead. */
    if (store_block_height == state_block_height) {                  /* :406 */
        if (app_block_height < store_block_height) {                 /* :409 */
            /* :411 — replay, no WAL: the state is already at the store. */
            return hs_replay_blocks(h, state, app, app_block_height,
                                    store_block_height, false,
                                    io_app_hash, io_app_hash_len);
        }
        if (app_block_height == store_block_height) {                /* :413 */
            return hs_assert_app_hash_from_state(io_app_hash,
                                                 *io_app_hash_len, state);
                                                                     /* :415-416 */
        }
    } else if (store_block_height == state_block_height + 1) {       /* :419 */
        if (app_block_height < state_block_height) {                 /* :423 */
            /* :426 — replay, leaving the last block to the WAL. */
            return hs_replay_blocks(h, state, app, app_block_height,
                                    store_block_height, true,
                                    io_app_hash, io_app_hash_len);
        }
        if (app_block_height == state_block_height) {                /* :428 */
            /* :429-435 — we never ran Commit; replay the last block with
             * the REAL application. */
            QGP_LOG_INFO(LOG_TAG, "%s", "replay last block using real app");
            rc = hs_replay_block(h, state, store_block_height, app);
            if (rc != CMT_OK) {
                return rc;
            }
            memcpy(io_app_hash, state->app_hash, state->app_hash_len);
            *io_app_hash_len = state->app_hash_len;
            return CMT_OK;
        }
        if (app_block_height == store_block_height) {                /* :437 */
            /* :438-453 — we ran Commit but did not save the state;
             * replay the last block with the MOCK application over the
             * stored response, so the ledger is not committed twice. */
            nodus_cmt_mock_app_t *mock;
            nodus_cmt_app_t       mock_if;

            mock = (nodus_cmt_mock_app_t *)calloc(1, sizeof(*mock));
            if (!mock) {
                return CMT_FAULT;
            }
            rc = nodus_cmt_mock_app_open(mock, h->store, h->store->db,
                                         store_block_height, io_app_hash,
                                         *io_app_hash_len, h->limits.max_txs);
            if (rc != CMT_OK) {                                      /* :440-442 */
                free(mock);
                return CMT_FAULT;
            }
            if (nodus_cmt_mock_app_build(&mock_if, mock) != CMT_OK) { /* :450 */
                nodus_cmt_mock_app_close(mock);
                free(mock);
                return CMT_FAULT;
            }
            QGP_LOG_INFO(LOG_TAG, "%s", "replay last block using mock app");
            rc = hs_replay_block(h, state, store_block_height, &mock_if);
                                                                     /* :452 */
            if (rc == CMT_OK) {
                memcpy(io_app_hash, state->app_hash, state->app_hash_len);
                *io_app_hash_len = state->app_hash_len;
            }
            nodus_cmt_mock_app_close(mock);
            free(mock);
            return rc;
        }
    }
    /* :458-459 — "uncovered case!". */
    QGP_LOG_ERROR(LOG_TAG, "uncovered case! app %" PRId64 ", store %" PRId64
                  ", state %" PRId64, app_block_height, store_block_height,
                  state_block_height);
    return CMT_FAULT;
}

int nodus_cmt_handshaker_init(nodus_cmt_handshaker_t *h,
                              nodus_cmt_store_t *store,
                              const cmt_state_t *state,
                              const cmt_genesis_doc_t *gendoc,
                              nodus_witness_t *w,
                              cmt_now_fn now, void *now_ctx,
                              const nodus_cmt_host_limits_t *limits)
{
    int rc;

    if (!h || !store || !state || !gendoc || !w || !now || !limits ||
        limits->max_txs == 0 || limits->tx_arena_cap == 0) {
        return CMT_FAULT;
    }
    memset(h, 0, sizeof(*h));
    h->store        = store;                                    /* :216-218 */
    h->gendoc       = gendoc;                                   /* :220     */
    h->w            = w;
    h->now          = now;
    h->now_ctx      = now_ctx;
    h->limits       = *limits;
    h->nblocks      = 0;                                        /* :222     */
    h->nop_mempool  = nodus_cmt_nop_mempool;                    /* :531     */
    h->empty_evpool = nodus_cmt_empty_evpool;

    h->initial_storage = (cmt_state_storage_t *)
        calloc(1, sizeof(cmt_state_storage_t));
    h->initial_state = (cmt_state_t *)calloc(1, sizeof(cmt_state_t));
    if (!h->initial_storage || !h->initial_state) {
        nodus_cmt_handshaker_release(h);
        return CMT_FAULT;
    }
    if (cmt_state_init(h->initial_state, h->initial_storage) != CMT_OK) {
        nodus_cmt_handshaker_release(h);
        return CMT_FAULT;
    }
    /* :217 `initialState: state` — Go copies the struct by value. */
    rc = cmt_state_copy(state, h->initial_state);
    if (rc != CMT_OK) {
        nodus_cmt_handshaker_release(h);
        return rc;
    }

    /* The `LoadBlock` storage (store.go:137-167). */
    h->dec.txs = (cmt_pb_bytes_t *)
        calloc(limits->max_txs, sizeof(cmt_pb_bytes_t));
    h->dec.txs_cap = limits->max_txs;
    h->dec.pb_evidence = (cmt_pb_evidence_t *)
        calloc(limits->max_evidence ? limits->max_evidence : 1,
               sizeof(cmt_pb_evidence_t));
    h->dec.pb_evidence_cap = limits->max_evidence;
    h->dec.evidence = (cmt_pb_evidence_t *)
        calloc(limits->max_evidence ? limits->max_evidence : 1,
               sizeof(cmt_pb_evidence_t));
    h->dec.evidence_cap = limits->max_evidence;
    h->dec.pb_sigs = (cmt_commit_sig_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    h->dec.pb_sigs_cap = CMT_VALSET_MAX;
    h->dec.sigs = (cmt_commit_sig_t *)
        calloc(CMT_VALSET_MAX, sizeof(cmt_commit_sig_t));
    h->dec.sigs_cap = CMT_VALSET_MAX;
    h->dec_arena.buf = (uint8_t *)malloc(limits->tx_arena_cap);
    h->dec_arena.cap = limits->tx_arena_cap;
    h->dec.arena     = &h->dec_arena;
    h->dec_buf       = (uint8_t *)malloc(limits->tx_arena_cap);
    h->dec_buf_cap   = limits->tx_arena_cap;
    if (!h->dec.txs || !h->dec.pb_evidence || !h->dec.evidence ||
        !h->dec.pb_sigs || !h->dec.sigs || !h->dec_arena.buf || !h->dec_buf) {
        nodus_cmt_handshaker_release(h);
        return CMT_FAULT;
    }
    return CMT_OK;
}

void nodus_cmt_handshaker_release(nodus_cmt_handshaker_t *h)
{
    if (!h) {
        return;
    }
    free(h->initial_state);
    free(h->initial_storage);
    free(h->dec.txs);
    free(h->dec.pb_evidence);
    free(h->dec.evidence);
    free(h->dec.pb_sigs);
    free(h->dec.sigs);
    free(h->dec_arena.buf);
    free(h->dec_buf);
    memset(h, 0, sizeof(*h));
}

int nodus_cmt_handshaker_handshake(nodus_cmt_handshaker_t *h,
                                   nodus_cmt_app_t *app)
{
    nodus_cmt_app_info_t info;
    uint8_t              app_hash[CMT_PB_HASH_MAX];
    size_t               app_hash_len;
    int                  rc;

    if (!h || !app || !h->initial_state) {
        return CMT_FAULT;
    }
    /* :250 — the handshake is an ABCI Info on the query connection. */
    if (nodus_cmt_node_app_info(h->w, &info) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "error calling Info");
        return CMT_FAULT;                                            /* :251-253 */
    }
    if (info.last_block_height < 0) {                                /* :256 */
        QGP_LOG_ERROR(LOG_TAG, "got a negative last block height (%" PRId64
                      ") from the app", info.last_block_height);
        return CMT_FAULT;                                            /* :257 */
    }
    memcpy(app_hash, info.last_block_app_hash, info.last_block_app_hash_len);
    app_hash_len = info.last_block_app_hash_len;                     /* :259 */

    QGP_LOG_INFO(LOG_TAG, "ABCI handshake app info: height %" PRId64
                 ", software-version %s, protocol-version %" PRIu64,
                 info.last_block_height,
                 info.version ? info.version : "?", info.app_version);
                                                                     /* :261-266 */
    /* :268-271 — only set the version if there is no existing state. */
    if (h->initial_state->last_block_height == 0) {
        h->initial_state->version.consensus.app = info.app_version;
    }
    /* :274 — replay blocks up to the latest in the block store. */
    rc = hs_replay_blocks_with_context(h, h->initial_state, app,
                                       info.last_block_height,
                                       app_hash, &app_hash_len);
    if (rc != CMT_OK) {                                              /* :275-277 */
        QGP_LOG_ERROR(LOG_TAG, "error on replay (rc %d)", rc);
        return CMT_FAULT;
    }
    QGP_LOG_INFO(LOG_TAG, "completed ABCI handshake — consensus and the "
                 "ledger are synced at height %" PRId64,
                 info.last_block_height);                            /* :279-280 */
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The mempool adapter — mempool/mempool.go:31-102 over cmt_mem
 * ═══════════════════════════════════════════════════════════════════════ */

/** mempool.go:46 — `ReapMaxBytesMaxGas(maxBytes, maxGas) Txs`. */
static int node_mem_reap(void *vctx, int64_t max_bytes, int64_t max_gas,
                         cmt_pb_bytes_t *out, size_t out_cap, size_t *out_len)
{
    nodus_cmt_node_mempool_t *c = (nodus_cmt_node_mempool_t *)vctx;

    if (!c || !c->mem) {
        return CMT_FAULT;
    }
    return cmt_mem_reap_max_bytes_max_gas(c->mem, max_bytes, max_gas, out,
                                          out_cap, out_len);
}

/** mempool.go:57 — `Lock()`. The reference returns nothing; `cmt_mem_lock`
 *  returns what clist_mempool.go:156 LOGS (whether `recheckFull`
 *  flipped), which this row discards exactly as the reference's caller
 *  does. */
static void node_mem_lock(void *vctx)
{
    nodus_cmt_node_mempool_t *c = (nodus_cmt_node_mempool_t *)vctx;

    if (c && c->mem) {
        (void)cmt_mem_lock(c->mem);
    }
}

/** mempool.go:60 — `Unlock()`. */
static void node_mem_unlock(void *vctx)
{
    nodus_cmt_node_mempool_t *c = (nodus_cmt_node_mempool_t *)vctx;

    if (c && c->mem) {
        cmt_mem_unlock(c->mem);
    }
}

/** mempool.go:68-74 — `Update(height, txs, txResults, preCheck, postCheck)`. */
static int node_mem_update(void *vctx, int64_t height,
                           const cmt_pb_bytes_t *txs, size_t txs_len,
                           const cmt_pb_stored_exec_tx_result_t *tx_results,
                           size_t tx_results_len, nodus_cmt_pre_check_t pre,
                           nodus_cmt_post_check_t post)
{
    nodus_cmt_node_mempool_t *c = (nodus_cmt_node_mempool_t *)vctx;
    cmt_mem_pre_check_t       pre_fn;
    cmt_mem_post_check_t      post_fn;
    size_t                    i;

    if (!c || !c->mem) {
        return CMT_FAULT;
    }
    if (tx_results_len > c->det_cap) {
        /* The results are this node's own FinalizeBlock product and the
         * pool is sized to the executor's transaction bound; more of
         * them than that is a node-local invariant broken. */
        QGP_LOG_ERROR(LOG_TAG, "mempool update: %zu results exceed the %zu the "
                      "adapter is sized for", tx_results_len, c->det_cap);
        return CMT_FAULT;
    }
    /* The STORED eight-field result carries the deterministic four in
     * `.det` (cmt_pb_store.h:270-278), which is the form
     * `cmt_mem_update` takes (clist_mempool.go:603 reads only `Code`). */
    for (i = 0; i < tx_results_len; i++) {
        c->det[i] = tx_results[i].det;
    }
    /* state/tx_filter.go:10-26's two closures, rebuilt from the captured
     * values the host row hands over. Their storage is the context's, not
     * this frame's: the mempool KEEPS the pair (clist_mempool.go:595-600)
     * and calls it on every later CheckTx. */
    if (cmt_mem_pre_check_max_bytes(pre.max_bytes, &c->pre_storage, &pre_fn)
            != CMT_OK ||
        cmt_mem_post_check_max_gas(post.max_gas, &c->post_storage, &post_fn)
            != CMT_OK) {
        return CMT_FAULT;
    }
    return cmt_mem_update(c->mem, height, txs, txs_len, c->det,
                          tx_results_len, &pre_fn, &post_fn);
}

/** mempool.go:81 — `FlushAppConn()`. */
static int node_mem_flush_app_conn(void *vctx)
{
    nodus_cmt_node_mempool_t *c = (nodus_cmt_node_mempool_t *)vctx;
    cmt_mem_error_t           err;

    if (!c || !c->mem) {
        return CMT_FAULT;
    }
    cmt_mem_error_init(&err);
    return cmt_mem_flush_app_conn(c->mem, &err);
}

static void node_mem_table(nodus_cmt_mempool_if_t *t,
                           nodus_cmt_node_mempool_t *c)
{
    memset(t, 0, sizeof(*t));
    t->ctx                    = c;
    t->reap_max_bytes_max_gas = node_mem_reap;
    t->lock                   = node_mem_lock;
    t->unlock                 = node_mem_unlock;
    t->update                 = node_mem_update;
    t->flush_app_conn         = node_mem_flush_app_conn;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The genesis document — node/setup.go:551-611
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * `LoadStateFromDBOrGenesisDocProvider` (setup.go:556-587) with the port's
 * substitutions, in the reference's ORDER.
 *
 * :561 `loadGenesisDoc(stateDB)` is the ROW PROBE plus
 * `nodus_witness_v2_gen_stored_doc` — the canonical-strict reader of
 * D-18 rev 5 (3) (rev 5 is PROPOSED; rev 4 is the APPROVED revision).
 * The reader is the same four checks the chain-id
 * accessor runs, because it IS that accessor's body (gen.c).
 *
 * ── THE THREE-WAY TABLE OF `loadGenesisDoc` (setup.go:589-603) ─────────
 * The reference distinguishes THREE outcomes, and only ONE of them
 * reaches the provider. This port must distinguish them too, because
 * `..._stored_doc` answers -1 for all three (an absent row and every one
 * of the four refusals), and treating a refused row as an absent one
 * would let a provider OVERWRITE a stored document — a thing the
 * reference cannot do at all:
 *
 *   · `db.Get` FAILS (:590-593 `panic(err)`) → CMT_FAULT. A read error on
 *     this node's own database is node-local, so it is a FAULT and not a
 *     REJECT (umbrella rev 6). Here: `nodus_cmt_store_get` != CMT_OK.
 *   · THE ROW IS ABSENT (:594-596, `len(b) == 0` → an error the CALLER
 *     turns into the provider call at :563) → the provider path below.
 *     Here: `nodus_cmt_store_get` returns CMT_OK with `*out_len == 0`,
 *     which is the store's own rendering of `len(bz) == 0`
 *     (nodus_witness_cmt_store.c:107-109).
 *   · THE ROW IS PRESENT AND UNREADABLE (:597-601, `panic` on the
 *     unmarshal error) → CMT_FAULT, the provider is NOT consulted and
 *     NOTHING is written. Here: a present row that any of the four checks
 *     refuses. The reference panics rather than replacing the document
 *     because a chain's genesis is not a thing a start-up argument may
 *     silently change, and neither is it here.
 *
 * :563 the provider is `opts->genesis_doc_bytes`, and it is therefore
 * consulted ONLY in the second case — a document that is already stored
 * is authority, readable or not.
 *
 * ── HOW THE PROVIDER'S BYTES ARE ACCEPTED, AND WHY IN THAT ORDER ───────
 * ⚠ DEVIATION R3-C1c-4, reported. It applies to the ABSENT-ROW case
 * ONLY: nothing below runs when a row is present.
 * The reference validates the provided document IN MEMORY (:567-571
 * `ValidateAndComplete`) and then saves it (:574). This port's acceptance
 * test is `..._stored_doc`, which reads the ROW — there is no in-memory
 * form of it, and writing a second composition of the four checks here
 * would be a second reader of one rule (the thing D-18 rev 5 (3) exists
 * to prevent). So the bytes are written inside a transaction, read back
 * through the ONE reader, and the transaction is ROLLED BACK if the
 * reader refuses. Nothing is ever stored that would not have passed, so
 * the observable outcome is the reference's; only the order inside the
 * refusal path differs, and it differs so that one rule keeps one
 * implementation.
 */
static int node_load_genesis_doc(nodus_cmt_node_t *n,
                                 const nodus_cmt_node_opts_t *opts)
{
    const uint8_t *row     = NULL;
    size_t         row_len = 0;
    char          *err     = NULL;
    int            rc;

    /* :590 `b, err := db.Get(genesisDocKey)` — the SAME reader, the same
     * table and the same key the canonical-strict loader itself reads
     * with (nodus_witness_v2_gen.c:2600-2605), so "present" here means
     * exactly what it means there. */
    if (nodus_cmt_store_get(&n->store, /*state_table=*/true,
                            NODUS_V2_GEN_GENESIS_DOC_KEY, &row, &row_len)
        != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the genesis document row could not be "
                      "read from this chain's database");
        return CMT_FAULT;                                            /* :591-593 */
    }

    if (row_len > 0) {
        /* A ROW EXISTS. Whatever it says, this chain's genesis is stored
         * and the provider is out of the picture (:597-602). `row` is a
         * pointer into a live statement and the loader below steps its
         * own; it is not touched again. */
        rc = nodus_witness_v2_gen_stored_doc(n->w, n->gen_cfg, &n->gen_allocs);
        if (rc != 0) {
            free(n->gen_allocs);
            n->gen_allocs = NULL;
            /* :598-600 `panic(...)`. The row is LEFT AS IT IS: a start-up
             * argument does not get to replace a chain's genesis
             * document, and the operator is told which row to look at. */
            QGP_LOG_ERROR(LOG_TAG,
                          "this chain's stored genesis document (%zu bytes "
                          "under \"%s\") is not one this build accepts — "
                          "refusing to start, and leaving it untouched",
                          row_len, NODUS_V2_GEN_GENESIS_DOC_KEY);
            return CMT_FAULT;
        }
        return CMT_OK;                                               /* :561 */
    }

    /* :594-596 — the row is absent, so the caller consults the provider
     * (:563). */
    if (!opts->genesis_doc_bytes || opts->genesis_doc_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "this chain has no stored genesis document and no "
                      "document was supplied — refusing to start");
        return CMT_FAULT;                                            /* :564-566 */
    }
    if (sqlite3_exec(n->w->db, "BEGIN IMMEDIATE", NULL, NULL, &err)
        != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: BEGIN IMMEDIATE failed: %s",
                      err ? err : "?");
        sqlite3_free(err);
        return CMT_FAULT;
    }
    /* :574 / :606-611 saveGenesisDoc — `db.SetSync(genesisDocKey, b)`. */
    if (nodus_cmt_store_set(&n->store, /*state_table=*/true,
                            NODUS_V2_GEN_GENESIS_DOC_KEY,
                            opts->genesis_doc_bytes,
                            opts->genesis_doc_len) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the supplied genesis document could not "
                      "be stored");
        (void)sqlite3_exec(n->w->db, "ROLLBACK", NULL, NULL, NULL);
        return CMT_FAULT;
    }
    /* :567-571 ValidateAndComplete, as the four checks of D-18 rev 5 (3)
     * (PROPOSED) — read back through the ONE reader (see the function
     * header). */
    rc = nodus_witness_v2_gen_stored_doc(n->w, n->gen_cfg, &n->gen_allocs);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the supplied genesis document is not one "
                      "this build accepts — nothing was stored");
        free(n->gen_allocs);
        n->gen_allocs = NULL;
        (void)sqlite3_exec(n->w->db, "ROLLBACK", NULL, NULL, NULL);
        return CMT_FAULT;                                            /* :572 */
    }
    if (sqlite3_exec(n->w->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: COMMIT failed: %s",
                      err ? err : "?");
        sqlite3_free(err);
        /* A failed COMMIT can leave the transaction open; close it so the
         * caller's release does not run against one. */
        (void)sqlite3_exec(n->w->db, "ROLLBACK", NULL, NULL, NULL);
        free(n->gen_allocs);
        n->gen_allocs = NULL;
        return CMT_FAULT;                                            /* :575-577 */
    }
    QGP_LOG_INFO(LOG_TAG, "%s", "the supplied genesis document was accepted "
                 "and stored");
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The node — node/node.go:285-422
 * ═══════════════════════════════════════════════════════════════════════ */

void nodus_cmt_node_release(nodus_cmt_node_t *n)
{
    if (!n) {
        return;
    }
    /* Reverse construction order. The state machine stops FIRST so that
     * nothing writes to the WAL after it is closed. */
    if (n->cs_ready) {
        if (n->cs_started) {
            (void)cmt_cs_stop(n->cs);          /* state.go:432-441 OnStop */
            n->cs_started = false;
        }
        cmt_cs_free(n->cs);
        n->cs_ready = false;
    }
    free(n->cs);
    n->cs = NULL;
    free(n->cs_storage);
    n->cs_storage = NULL;
    free(n->cs_scratch_storage);
    n->cs_scratch_storage = NULL;

    if (n->wal_open) {
        nodus_cmt_wal_close(&n->wal);          /* wal.go:164-173 OnStop,
                                                * FlushAndSync at :166   */
        n->wal_open = false;
    }
    if (n->be_ready) {
        nodus_cmt_blockexec_release(n->be);
        n->be_ready = false;
    }
    free(n->be);
    n->be = NULL;
    if (n->slots) {
        int k;

        for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
            free(n->slots->parts[k]);
            free(n->slots->payload[k]);
        }
        free(n->slots->marshal_parts);
        free(n->slots->marshal_scratch);
        free(n->slots);
        n->slots = NULL;
    }
    free(n->ext_arena.buf);
    n->ext_arena.buf = NULL;
    n->ext_arena.cap = 0;

    if (n->mem_ready) {
        cmt_mem_free(n->mem);
        n->mem_ready = false;
    }
    free(n->mem);
    n->mem = NULL;
    free(n->mem_ctx.det);
    n->mem_ctx.det = NULL;

    if (n->pv_file_open) {
        nodus_cmt_privval_close(&n->pv_file);
        n->pv_file_open = false;
    }
    free(n->pv);
    n->pv = NULL;

    free(n->app_ctx);
    n->app_ctx = NULL;

    free(n->state);
    n->state = NULL;
    free(n->state_storage);
    n->state_storage = NULL;
    free(n->gvals);
    n->gvals = NULL;
    free(n->gen_allocs);
    n->gen_allocs = NULL;
    free(n->gen_cfg);
    n->gen_cfg = NULL;

    if (n->store_ready) {
        nodus_cmt_store_release(&n->store);
        n->store_ready = false;
    }
    memset(n, 0, sizeof(*n));
}

/** The three block slots of cmt_cs.h "OWNERSHIP" (1) plus the proposer's
 *  own marshal target. `payload_cap` must cover `Block.MaxBytes`, which
 *  is what `limits.tx_arena_cap` is (see the header's DETERMINISM note
 *  on `nodus_cmt_node_opts_t.limits`). */
static int node_slots_alloc(nodus_cmt_node_t *n)
{
    size_t payload_cap = n->limits.tx_arena_cap;
    size_t parts_cap   = (payload_cap / (size_t)CMT_BLOCK_PART_SIZE_BYTES) + 1u;
    int    k;

    if (parts_cap > (size_t)CMT_PART_SET_MAX_PARTS) {
        parts_cap = (size_t)CMT_PART_SET_MAX_PARTS;
    }
    n->slots = (cmt_cs_slots_t *)calloc(1, sizeof(*n->slots));
    if (!n->slots) {
        return CMT_FAULT;
    }
    for (k = 0; k < CMT_CS_BLOCK_SLOTS; k++) {
        n->slots->parts[k] = (cmt_part_t *)calloc(parts_cap, sizeof(cmt_part_t));
        n->slots->parts_cap[k] = parts_cap;
        n->slots->payload[k] = (uint8_t *)malloc(payload_cap);
        n->slots->payload_cap[k] = payload_cap;
        if (!n->slots->parts[k] || !n->slots->payload[k]) {
            return CMT_FAULT;
        }
    }
    n->slots->marshal_parts = (cmt_part_t *)calloc(parts_cap, sizeof(cmt_part_t));
    n->slots->marshal_parts_cap = parts_cap;
    n->slots->marshal_scratch = (uint8_t *)malloc(payload_cap);
    n->slots->marshal_scratch_cap = payload_cap;
    if (!n->slots->marshal_parts || !n->slots->marshal_scratch) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_node_init(nodus_cmt_node_t *n, nodus_witness_t *w,
                        const nodus_cmt_node_opts_t *opts)
{
    nodus_cmt_handshaker_t *hs = NULL;
    cmt_valset_scratch_t   *scratch = NULL;
    cmt_lss_t              *lss = NULL;
    int                     rc = CMT_FAULT;

    if (!n || !w || !w->db || !opts || !opts->now ||
        !opts->privval_state_path || !opts->privval_state_path[0]) {
        return CMT_FAULT;
    }
    memset(n, 0, sizeof(*n));
    n->w       = w;
    n->now     = opts->now;
    n->now_ctx = opts->now_ctx;

    /* ── 1. node.go:296-303 — initDBs + NewStore ──────────────────────
     * `DiscardABCIResponses` is false, config/config.go:1154's default
     * — and it MUST be: the Handshaker's "ran Commit, didn't save the
     * state" branch replays through the stored response. */
    if (nodus_cmt_store_init(&n->store, w->db, /*discard=*/false) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the Comet stores could not be opened");
        goto fail;
    }
    n->store_ready = true;

    /* ── 2. node.go:305 — LoadStateFromDBOrGenesisDocProvider ────────── */
    n->gen_cfg = (nodus_v2_gen_config_t *)calloc(1, sizeof(*n->gen_cfg));
    if (!n->gen_cfg) {
        goto fail;
    }
    if (node_load_genesis_doc(n, opts) != CMT_OK) {
        goto fail;
    }
    n->gvals = (cmt_genesis_validator_t *)
        calloc(NODUS_V2_GEN_MAX_VALIDATORS, sizeof(cmt_genesis_validator_t));
    if (!n->gvals) {
        goto fail;
    }
    /* setup.go:568 `genDoc.ValidateAndComplete()` — inside
     * `nodus_witness_v2_gen_to_cmt_doc`, which projects the version-3
     * document onto the port's `cmt_genesis_doc_t` and runs
     * types/genesis.go:69-106 over it. */
    if (nodus_witness_v2_gen_to_cmt_doc(n->gen_cfg, &n->doc, n->gvals,
                                        NODUS_V2_GEN_MAX_VALIDATORS) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document is not a "
                      "document this port can complete");
        goto fail;
    }

    /* The capacity bounds every allocation below is sized from. */
    n->limits = opts->limits;
    if (n->limits.max_txs == 0) {
        n->limits.max_txs = (size_t)NODUS_CMT_APP_MAX_TXS;
    }
    if (n->limits.tx_arena_cap == 0) {
        int64_t mb = n->doc.consensus_params.block.max_bytes;

        if (mb <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "the genesis document's Block.MaxBytes is %"
                          PRId64 " — there is no block size to size for", mb);
            goto fail;
        }
        n->limits.tx_arena_cap = (size_t)mb;
    }
    if (n->limits.max_evidence == 0) {
        n->limits.max_evidence = NODE_DEFAULT_MAX_EVIDENCE;
    }
    /* INVARIANT (found by C1a): the application REFUSES a request above
     * its own array bound, so an executor sized larger would build
     * blocks its own application faults on. */
    if (n->limits.max_txs > (size_t)NODUS_CMT_APP_MAX_TXS) {
        QGP_LOG_ERROR(LOG_TAG, "the executor's transaction bound %zu is above "
                      "the application's %u", n->limits.max_txs,
                      (unsigned)NODUS_CMT_APP_MAX_TXS);
        goto fail;
    }

    /* ── THE CONSENSUS CONFIG ─────────────────────────────────────────
     * Built here rather than at `createConsensusReactor` because the
     * reference's `config` is a PARAMETER of NewNodeWithContext
     * (node.go:286) and is read before then — `WaitForTxs()` at
     * setup.go:252 decides whether the mempool signals, which happens
     * earlier than :395. It is a pure function of compile-time values,
     * so building it early changes nothing.
     *
     * `cmt_config_default` is config/config.go:1017-1034 verbatim; the
     * project overrides exactly the two values D-4 rev 3 (4) names —
     * both cometbft NODE settings, both compile-time constants of this
     * build (changed only by a build plus a stop-all deploy). The old
     * lane's `DNAC_CFG_BLOCK_INTERVAL_SEC` (param 2) has NO effect on
     * this lane and is not read. */
    if (cmt_config_default(&n->config) != CMT_OK) {
        goto fail;
    }
    n->config.timeout_commit               = 5000 * CMT_MILLISECOND;
    n->config.create_empty_blocks_interval = 60000 * CMT_MILLISECOND;

    /* node.go:305's second product — `stateStore.LoadFromDBOrGenesisDoc`
     * (setup.go:581, state/store.go:136-151). */
    n->state_storage = (cmt_state_storage_t *)
        calloc(1, sizeof(cmt_state_storage_t));
    n->state   = (cmt_state_t *)calloc(1, sizeof(cmt_state_t));
    scratch    = (cmt_valset_scratch_t *)calloc(1, sizeof(*scratch));
    if (!n->state_storage || !n->state || !scratch) {
        goto fail;
    }
    if (cmt_state_init(n->state, n->state_storage) != CMT_OK) {
        goto fail;
    }
    /* ⚠ THE CLOCK IS PASSED AS NULL, DELIBERATELY. The only clock under
     * this call is `ValidateAndComplete`'s genesis_time completion
     * (cmt_genesis.c:145-155, genesis.go:101-103), and D-18 rev 2 makes
     * genesis_time MANDATORY on this chain, so reaching it means the
     * stored document is malformed. With NULL that branch is a CMT_FAULT
     * instead of an invented time — the same argument, and the same
     * argument value, as the two call sites that already exist
     * (nodus_witness_v2_gen.c:2570, test_cmt_app.c:810). The node's own
     * `n->now` is for the vote stamp and the timeouts, never for this. */
    rc = nodus_cmt_ss_load_from_db_or_genesis_doc(&n->store, &n->doc,
                                                  NULL, NULL,
                                                  scratch, n->state);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the state could not be loaded or made from "
                      "the genesis document (rc %d)", rc);
        goto fail;
    }

    /* ── 3. node.go:313 — createAndStartProxyAppConns ─────────────────
     * The EventBus and the indexer of :317-329 are NOT PORTED: this
     * build has no indexer and no RPC to serve one, so there is nothing
     * for them to feed (file header). */
    n->app_ctx = (nodus_cmt_app_ledger_t *)calloc(1, sizeof(*n->app_ctx));
    if (!n->app_ctx) {
        goto fail;
    }
    if (nodus_cmt_app_ledger_init(n->app_ctx, w, &n->doc) != CMT_OK ||
        nodus_cmt_app_ledger_build(&n->app_if, n->app_ctx) != CMT_OK ||
        nodus_cmt_app_ledger_build_mempool(&n->app_mem_if, n->app_ctx)
            != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the application could not be bound to "
                      "this ledger");
        goto fail;
    }
    /* INVARIANT (found by C1a): the host opens its transaction on the
     * STORE's connection and the ledger apply runs on the APPLICATION's.
     * Two handles would make the bracket a lie — the apply would commit
     * on one connection while the bracket rolled back the other. */
    if (n->app_ctx->w->db != n->store.db) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the application and the consensus store "
                      "are on different SQLite connections");
        goto fail;
    }

    /* ── 4. node.go:333-347 — the private validator ───────────────────
     * FilePVKey (privval/file.go:47-53) is not ported: this chain never
     * writes a private key to disk (PQ POLICY). What IS loaded is the
     * LAST-SIGN STATE, which is what stops a double sign across a
     * restart, and `raw_sign` is the caller's (R3-C2's in production).
     * `PrivValidatorListenAddr` (:342-347, an external signer socket)
     * has no counterpart here.
     *
     * `NewNodeWithContext` receives an ALREADY-BUILT privValidator; the
     * caller that builds it is `DefaultNewNode`, and it builds it with
     * `privval.LoadOrGenFilePV` (setup.go:71). That function is what
     * decides between loading and generating, so it is ported HERE —
     * without it a first boot cannot come up at all, which is how this
     * was found (the run died on a missing state file).
     *
     * ⚠ DEVIATION R3-C1c-5, reported. `LoadOrGenFilePV`
     * (file.go:237-245) takes its predicate on the KEY file:
     * `cmtos.FileExists(keyFilePath)` → LoadFilePV (:240), else
     * GenFilePV + `pv.Save()` (:242-243). This port has NO key file —
     * the private key is never written to disk — so the predicate is
     * taken on the STATE file, the only file it has. `FileExists`
     * (libs/os/os.go:58-61) is `os.Stat` plus `!os.IsNotExist(err)`, so
     * it is TRUE for every stat outcome EXCEPT ENOENT; that is
     * reproduced exactly, and it matters: a state file that exists but
     * cannot be statted must NOT be silently regenerated over.
     */
    n->pv  = (cmt_file_pv_t *)calloc(1, sizeof(*n->pv));
    lss    = (cmt_lss_t *)calloc(1, sizeof(*lss));
    if (!n->pv || !lss) {
        goto fail;
    }
    {
        struct stat sb;
        bool        exists;

        /* os.go:59-60 — `os.Stat`, then `!os.IsNotExist(err)`. */
        errno  = 0;
        exists = (stat(opts->privval_state_path, &sb) == 0) ||
                 (errno != ENOENT);
        if (nodus_cmt_privval_open(&n->pv_file, opts->privval_state_path,
                                   n->now, n->now_ctx,
                                   /*load_state=*/exists, lss) != CMT_OK) {
            /* :240 LoadFilePV on a present file: unreadable or malformed
             * is the reference's `cmtos.Exit` (:219, :223). */
            QGP_LOG_ERROR(LOG_TAG, "%s", "the last-sign state file could not be "
                          "opened");
            goto fail;
        }
        n->pv_file_open = true;
        if (!exists) {
            /* :242-243 `GenFilePV(...); pv.Save()`. The state is the
             * empty one `NewFilePV` builds — `Step: stepNone` and
             * nothing else (file.go:171-174) — which is exactly what
             * `..._privval_open` just produced with load_state false.
             * Save it, so a first boot leaves the file on disk the way
             * the reference's does; a failure there is `Save`'s panic
             * (file.go:138, :142, :146) → CMT_FAULT. */
            if (nodus_cmt_privval_save_lss(&n->pv_file, lss) != CMT_OK) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the last-sign state file could "
                              "not be created on this node's first start");
                goto fail;
            }
            QGP_LOG_INFO(LOG_TAG, "%s", "no last-sign state file existed: an "
                         "empty one was generated and saved (file.go:242-243)");
        }
    }
    n->pv->last_sign_state = *lss;                       /* file.go:159 */
    n->pv->raw_sign            = opts->raw_sign;         /* file.go:50  */
    n->pv->sign_ctx            = opts->sign_ctx;
    n->pv->save_last_sign_state = nodus_cmt_privval_save_lss; /* :421   */
    n->pv->save_ctx            = &n->pv_file;
    n->pv->now                 = n->now;                 /* :441, :461  */
    n->pv->now_ctx             = n->now_ctx;
    /* node.go:343-347 `privValidator.GetPubKey()` — this node's own
     * identity key, which is what the address is derived from
     * (types/validator.go:29). The server identity is the one the ledger
     * seams already sign with. */
    if (!w->server) {
        /* node.go:343-345 returns an error on `can't get pubkey`, so a
         * node with no identity to sign with does NOT come up. Leaving
         * `pub_key` zero and continuing would hand `cmt_cs` an all-zero
         * validator address that matches no member of the set: it would
         * start, believe it is not a validator, and never say so. */
        QGP_LOG_ERROR(LOG_TAG, "%s", "this node has no identity: the private "
                      "validator's public key cannot be taken (node.go:343)");
        goto fail;
    }
    memcpy(n->pv->pub_key, w->server->identity.pk.bytes,
           (size_t)CMT_PB_PUBKEY_LEN);
    {
        cmt_pb_public_key_t pk;

        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, n->pv->pub_key, (size_t)CMT_PB_PUBKEY_LEN);
        if (cmt_pub_key_address(&pk, n->pv->address) != CMT_OK) {   /* :346 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "this node's validator address is "
                          "not derivable from its identity key");
            goto fail;
        }
    }
    free(lss);
    lss = NULL;

    /* ── 5. node.go:356-362 — doHandshake (setup.go:173-190) ──────────
     * Every ledger apply the handshake performs COMMITS before it
     * returns; nothing below it opens a transaction. That is what lets
     * the WAL open in `nodus_cmt_node_start` outside one. */
    hs = (nodus_cmt_handshaker_t *)calloc(1, sizeof(*hs));
    if (!hs) {
        goto fail;
    }
    if (nodus_cmt_handshaker_init(hs, &n->store, n->state, &n->doc, w,
                                  n->now, n->now_ctx, &n->limits) != CMT_OK) {
        goto fail;
    }
    if (nodus_cmt_handshaker_handshake(hs, &n->app_if) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "error during handshake");
        nodus_cmt_handshaker_release(hs);
        free(hs);
        hs = NULL;
        goto fail;                                       /* setup.go:186-188 */
    }
    n->handshake_nblocks = hs->nblocks;
    nodus_cmt_handshaker_release(hs);
    free(hs);
    hs = NULL;

    /* ── 6. node.go:364-370 — reload the state ────────────────────────
     * "It will have the Version.Consensus.App set by the Handshake, and
     * may have other modifications as well (ie. depending on what
     * happened during block replay)." */
    if (nodus_cmt_ss_load(&n->store, n->state) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "cannot load state");
        goto fail;                                       /* node.go:368-370 */
    }

    /* ── 7a. node.go:379 — createMempoolAndMempoolReactor ─────────────
     * The Flood mempool (setup.go:237-257) on cometbft's defaults
     * (D-4 rev 3 (1)). The REACTOR (:248-251) is W3's and is NOT built:
     * a mempool with no reactor accepts transactions from this node and
     * gossips none, which is exactly the W2 state. */
    if (cmt_mempool_config_default(&n->mem_config) != CMT_OK) {
        goto fail;
    }
    n->mem = (cmt_mem_t *)calloc(1, sizeof(*n->mem));
    n->mem_ctx.det = (cmt_pb_exec_tx_result_t *)
        calloc(n->limits.max_txs, sizeof(cmt_pb_exec_tx_result_t));
    n->mem_ctx.det_cap = n->limits.max_txs;
    if (!n->mem || !n->mem_ctx.det) {
        goto fail;
    }
    {
        nodus_cmt_pre_check_t  pre;
        nodus_cmt_post_check_t post;
        cmt_mem_pre_check_t    pre_fn;
        cmt_mem_post_check_t   post_fn;

        /* setup.go:244-245 — WithPreCheck(sm.TxPreCheck(state)) /
         * WithPostCheck(sm.TxPostCheck(state)), over the state as it is
         * AFTER the handshake. */
        if (nodus_cmt_tx_pre_check(n->state, &pre) != CMT_OK) {
            goto fail;
        }
        post = nodus_cmt_tx_post_check(n->state);
        if (cmt_mem_pre_check_max_bytes(pre.max_bytes, &n->mem_ctx.pre_storage,
                                        &pre_fn) != CMT_OK ||
            cmt_mem_post_check_max_gas(post.max_gas, &n->mem_ctx.post_storage,
                                       &post_fn) != CMT_OK) {
            goto fail;
        }
        /* :239-246 NewCListMempool(cfg, proxyApp.Mempool(),
         * state.LastBlockHeight, …). */
        if (cmt_mem_init(n->mem, &n->mem_config, &n->app_mem_if,
                         n->state->last_block_height, &pre_fn, &post_fn)
            != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the mempool could not be built");
            goto fail;
        }
    }
    n->mem_ready   = true;
    n->mem_ctx.mem = n->mem;
    node_mem_table(&n->mem_if, &n->mem_ctx);
    /* setup.go:252-254 — `if config.Consensus.WaitForTxs() {
     * mp.EnableTxsAvailable() }`. Under this chain's settings
     * (CreateEmptyBlocks true, CreateEmptyBlocksInterval 60 000 ms) the
     * predicate is TRUE (config.go:1054-1057), so the signal is enabled.
     * The CONSUMER is NULL: the reference's channel is read by the
     * consensus state's event loop, which is W3's — "a channel nobody
     * reads; the flag still flips" (cmt_mem.h). */
    if (cmt_config_wait_for_txs(&n->config)) {
        if (cmt_mem_enable_txs_available(n->mem, NULL, NULL) != CMT_OK) {
            goto fail;
        }
    }

    /* ── 7b. node.go:381 — createEvidenceReactor ──────────────────────
     * The evidence pool and its reactor are not ported; the BlockExecutor
     * gets `sm.EmptyEvidencePool{}` (state/services.go:57-68), W1's
     * binding, so a block carries no evidence and none is checked. The
     * evidence lane is W3's. */
    n->ev_if = nodus_cmt_empty_evpool;

    /* ── 7c. node.go:386-395 — NewBlockExecutor + the host table ──────
     * The WAL pointer is handed over here and OPENED in
     * `nodus_cmt_node_start`: `nodus_cmt_blockexec_init` stores it
     * without dereferencing (nodus_witness_cmt_host.c:389), and the
     * first row that reads it runs inside the event loop, which cannot
     * turn before `start`. */
    n->ext_arena.cap = 64u * 1024u;
    n->ext_arena.buf = (uint8_t *)malloc(n->ext_arena.cap);
    n->be            = (nodus_cmt_blockexec_t *)calloc(1, sizeof(*n->be));
    if (!n->ext_arena.buf || !n->be) {
        goto fail;
    }
    if (node_slots_alloc(n) != CMT_OK) {
        goto fail;
    }
    if (nodus_cmt_blockexec_init(n->be, &n->store, &n->app_if, &n->mem_if,
                                 &n->ev_if, &n->wal, n->pv, n->now,
                                 n->now_ctx, n->slots, &n->ext_arena,
                                 &n->limits) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the block executor could not be built");
        goto fail;
    }
    n->be_ready = true;
    if (nodus_cmt_host_build(&n->host, n->be) != CMT_OK) {
        goto fail;
    }

    /* ── 8. node.go:397-403 — offlineStateSyncHeight ──────────────────
     * The reference reads it only when the block store is empty and
     * tolerates exactly one error, the string "value empty" (:388).
     *
     * ⚠ DEVIATION R3-C1c-2, reported: this port's accessor returns
     * CMT_REJECT for BOTH "value empty" (state/store.go:745-747, the
     * port's nodus_witness_cmt_store.c:2222-2224) and a NEGATIVE stored
     * height (state/store.go:750-752, store.c:2227-2230), and the return
     * code cannot tell
     * them apart. The reference PANICS on the second. Here both leave
     * the height at 0, which is the answer for the first and a silent
     * tolerance for the second. Distinguishing them needs a second
     * return class from `nodus_cmt_ss_get_offline_state_sync_height`,
     * which lives in a file this package may not edit. */
    n->offline_state_sync_height = 0;
    if (nodus_cmt_bs_height(&n->store) == 0) {                       /* :386 */
        int64_t h = 0;

        rc = nodus_cmt_ss_get_offline_state_sync_height(&n->store, &h);
        if (rc == CMT_OK) {
            n->offline_state_sync_height = h;
        } else if (rc == CMT_FAULT) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "failed to retrieve the state-synced "
                          "height from the store");
            goto fail;                                               /* :389-391 */
        }
    }

    /* ── 9. node.go:410-413 — createConsensusReactor → NewState ───────
     * The REACTOR (setup.go:334-338) is W3's; `cmt_cs_init` is
     * consensus/state.go:154-208 and is all that is built here. The
     * config it is given was built above, with its two project
     * overrides. */
    n->cs_storage = (cmt_state_storage_t *)
        calloc(1, sizeof(cmt_state_storage_t));
    n->cs_scratch_storage = (cmt_state_storage_t *)
        calloc(1, sizeof(cmt_state_storage_t));
    n->cs = (cmt_cs_t *)calloc(1, sizeof(*n->cs));
    if (!n->cs_storage || !n->cs_scratch_storage || !n->cs) {
        goto fail;
    }
    /* :396 `state.Copy()` — `cmt_cs_init` copies the state it is given
     * into `state_storage`, so the node's own `n->state` stays the
     * node's (cmt_cs.h:877-892). */
    rc = cmt_cs_init(n->cs, &n->config, n->state, &n->host, n->be, n->slots,
                     n->cs_storage, n->cs_scratch_storage, &n->ext_arena,
                     n->offline_state_sync_height);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the consensus state could not be built (rc %d)",
                      rc);
        goto fail;
    }
    n->cs_ready = true;
    /* setup.go:331-333 — SetPrivValidator when there is one. There
     * always is here: the last-sign state file opened above IS the
     * private validator's file half, and the public key is this node's
     * identity. `cmt_cs_set_priv_validator` memoizes the key through the
     * host's `get_pub_key` row (state.go:291). */
    if (cmt_cs_set_priv_validator(n->cs, true) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the private validator could not be set");
        goto fail;
    }

    /* ── 10. node.go:415-418 — SetOfflineStateSyncHeight(0) ───────────
     * The reference PANICS on failure; node-local, CMT_FAULT. */
    if (nodus_cmt_ss_set_offline_state_sync_height(&n->store, 0) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "failed to reset the offline state sync "
                      "height");
        goto fail;
    }

    /* ── THE W3 SEAM ──────────────────────────────────────────────────
     * node.go:405-408 builds the blocksync reactor, :410-413 the
     * consensus reactor (its NewState half is ported above), :423-470
     * the state-sync reactor and the p2p switch; OnStart (node.go:518-585)
     * starts them. W3
     * registers the consensus reactor's three callbacks here with
     * `cmt_cs_add_listener(n->cs, &listener, ctx)` (reactor.go:411-433,
     * cmt_cs.h:912-928) and drives `cmt_cs_step` from the tick. Nothing
     * else in this file changes when it does. */

    free(scratch);
    return CMT_OK;

fail:
    free(lss);
    free(scratch);
    if (hs) {
        nodus_cmt_handshaker_release(hs);
        free(hs);
    }
    nodus_cmt_node_release(n);
    return CMT_FAULT;
}

int nodus_cmt_node_start(nodus_cmt_node_t *n)
{
    int rc;

    if (!n || !n->cs_ready || !n->store_ready) {
        return CMT_FAULT;
    }
    if (n->cs_started || n->wal_open) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "this node has already been started");
        return CMT_FAULT;
    }
    /* ── state.go:319-325 — OpenWAL ───────────────────────────────────
     * The reference opens a FILE WAL inside `OnStart`; this port's WAL is
     * SQLite rows on a second connection (D-15), opened by the HOST and
     * handed to the executor. It is opened HERE, and not in
     * `nodus_cmt_node_init`, for the §B.4 caller contract
     * (nodus_witness_cmt_wal.h): a WAL write must not happen while a
     * store transaction is open on the main connection. Nothing holds a
     * transaction at this point — the Handshaker's applies all committed
     * during init, which is the reference's own order (node.go:360
     * precedes state.go:319). */
    if (!sqlite3_get_autocommit(n->w->db)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "start: the ledger connection is inside a "
                      "transaction — the WAL must not be opened here");
        return CMT_FAULT;
    }
    if (nodus_cmt_wal_open(&n->wal, n->w->db, n->now, n->now_ctx) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the consensus WAL could not be opened");
        return CMT_FAULT;
    }
    n->wal_open = true;
    /* wal.go:124-131 — the EndHeight{0} seed when the log is empty. */
    if (nodus_cmt_wal_start(&n->wal) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the consensus WAL could not be started");
        return CMT_FAULT;
    }

    /* ── state.go:332-402 ─────────────────────────────────────────────
     * The ticker start (:332-334), the catch-up replay (:338-343 with
     * the :344-350 classification), the double-sign check (:393-395) and
     * `scheduleRound0` (:402) are all inside `cmt_cs_start` — read at
     * shared/dnac/cmt_cs.h:960-982 ("PORTED: the catch-up replay …, the
     * double-signing check … and scheduleRound0"). NOT ported there and
     * not here: the WAL repair loop (:352-385), `evsw.Start` (:388) and
     * `go cs.receiveRoutine` (:398) — the caller drives `cmt_cs_step`,
     * which is W3's tick. */
    rc = cmt_cs_start(n->cs);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the consensus state machine refused to start "
                      "(rc %d)", rc);
        return rc;
    }
    n->cs_started = true;
    return CMT_OK;
}
