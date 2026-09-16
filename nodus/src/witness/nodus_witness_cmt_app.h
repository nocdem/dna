/**
 * @file nodus/src/witness/nodus_witness_cmt_app.h
 * @brief The APPLICATION behind cometbft's `AppConnConsensus`
 *        (proxy/app_conn.go:18-27) and `AppConnMempool`
 *        (proxy/app_conn.go:29-36), implemented over the Ledger V2
 *        engine — cometbft @709fd12b `abci/types/application.go:11-34`
 *        method set, D-23 rev 5.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * FLEET-TM-R3 wave W2, package R3-C1a. Nothing in the running chain calls
 * anything here. The tests drive it; R3-C1c (the startup table) is the
 * first production constructor.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── WHAT IS HERE ───────────────────────────────────────────────────────
 * All seven `AppConnConsensus` rows over the ledger — `init_chain`,
 * `prepare_proposal`, `process_proposal`, `extend_vote`,
 * `verify_vote_extension`, `finalize_block`, `commit` — plus
 * `AppConnMempool`'s `check_tx`. `finalize_block` drives the ledger's
 * COMETBFT APPLY LANE (`nodus_v2_block_t.cmt`, apply.h): every item is
 * executed inside its own SAVEPOINT, a failing item gets a nonzero
 * `nodus_v2_tx_code_t` and the block goes on, and `app_hash` is the
 * ledger's global root after the block.
 *
 * ── WHAT THIS LANE DOES NOT DO YET (named, not hidden) ─────────────────
 *   · VALIDATOR UPDATES. `finalize_block` returns none, so a Comet
 *     chain's validator set never moves (R3-T).
 *   · `ExecTxResult.data` is EMPTY — the engine retains no per-item
 *     effect bytes.
 * CLAIMS ARE APPLIED: a claim-classified item is decoded here and
 * applied by the engine inside its own SAVEPOINT, exactly as an
 * envelope is. Only bytes that do not DECODE are coded at this
 * boundary.
 *
 * ── THE TRANSACTION (D-23 rev 5 (5)) ───────────────────────────────────
 * `commit` issues the `COMMIT` of the ONE transaction the HOST opened
 * before `finalize_block` (nodus_witness_cmt_host.c `apply_block`). The
 * application never issues `BEGIN` and never issues `ROLLBACK`: a failure
 * before the commit leaves the open transaction to the host, which rolls
 * it back and stops the node (CMT_FAULT). `commit` called outside a
 * transaction is a node-local invariant broken — CMT_FAULT, umbrella
 * rev 6's panic rule.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No clock is read here (D-20 rev 3: the application is not a clock
 * consumer). `prepare_proposal` sorts by a STABLE insertion sort over a
 * total key — fee descending, ties in arrival order — so the output is a
 * function of the request's bytes and their order alone. The ledger seams
 * this module calls (`nodus_witness_v2_block_ctx_build`,
 * `nodus_witness_v2_env_preflight_batch`,
 * `nodus_witness_v2_produce_batch_check_ex`) read committed state in a
 * stable total order and write nothing. No randomness, no hash-map
 * iteration, no wall-clock branch.
 *
 * Reference @709fd12b (read for the rules cited at each site):
 *   proxy/app_conn.go        the two connection interfaces
 *   abci/types/application.go the method set and BaseApplication's
 *                            defaults
 *   consensus/replay.go:318-373  the InitChain call
 *   state/execution.go:101-323   the caller of every row here
 * Governing records: D-23 rev 5 (atlas-dec-cb08dde681aa3c4ab1d1f1b33cdb68e1,
 * APPROVED; rev 6 PROPOSED records the lane as built), D-17 rev 7
 * (atlas-dec-9d96e2ec31ad4840cf258df21732b67f, APPROVED; rev 9 PROPOSED),
 * D-19 rev 6 (atlas-dec-d106407a31d7d16d49d51990b75c36c6),
 * D-4 rev 3 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718), umbrella rev 6
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8), pin rev 19
 * (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_CMT_APP_H
#define NODUS_WITNESS_CMT_APP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac/cmt_genesis.h"
#include "dnac/cmt_mem.h"
#include "dnac/cmt_pb.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_host.h"
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_v2_apply.h"   /* the Comet apply lane   */
#include "witness/nodus_witness_v2_env.h"     /* nodus_v2_envelope_t    */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * How many transactions one request to this application may carry.
 *
 * The reference bounds a proposal only by `ConsensusParams.Block.MaxBytes`
 * (D-25 rev 3); this port makes every wire-derived count explicit
 * (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07), so the arrays
 * below are sized and a request above the bound is REFUSED rather than
 * silently truncated. The value is the block-transaction bound the ledger
 * seam this module calls already enforces —
 * `nodus_witness_v2_produce_batch_check_ex` refuses `count >
 * NODUS_W_MAX_BLOCK_TXS` (nodus_witness_v2_produce.c:358-360).
 *
 * ⚠ DEVIATION R3-C1a-4, reported: D-4 rev 3 (2) retires the old lane's
 * per-block transaction cap for the Comet lane, but the seam D-23 rev 5
 * (9) tells this module to reuse still enforces it. Until the seam's bound
 * is raised — a change to nodus_witness_v2_produce.c, outside this
 * package's whitelist — the Comet lane inherits it.
 *
 * ⚠ AND THE CONSEQUENCE, stated where the bound is rather than only in
 * the tests: a DECIDED block carrying more than this many items STOPS
 * THE NODE. `finalize_block` cannot answer it with a verdict —
 * consensus already committed to the block — so it returns CMT_FAULT,
 * the host rolls its transaction back and the node halts. That is the
 * honest behaviour for a limit this lane should not have, and it is why
 * raising the seam is W3 work rather than a nicety.
 */
#define NODUS_CMT_APP_MAX_TXS  NODUS_W_MAX_BLOCK_TXS

/**
 * The application's context: the ledger handle, the genesis document and
 * the scratch every row needs. One instance per node; the rows are
 * single-threaded (the consensus event loop calls them in line).
 *
 * `w` and `gendoc` are BORROWED and must outlive the context.
 *
 * ⚠ SIZE: the seam's entry views dominate — `nodus_witness_mempool_entry_t`
 * carries a 2 592-byte public key and a 4 627-byte signature
 * (nodus_types.h:66, :68), so the struct is on the order of 85 KB.
 * Production callers heap-allocate it.
 */
typedef struct {
    nodus_witness_t         *w;       /* the ledger                       */
    const cmt_genesis_doc_t *gendoc;  /* BORROWED; InitChain's app_hash   */

    /* ── prepare_proposal scratch (app-owned until the next call of the
     * same method, proxy/app_conn.go's ownership rule) ──────────────── */
    cmt_pb_bytes_t prep_txs[NODUS_CMT_APP_MAX_TXS];
    size_t         prep_txs_len;

    /* ── the per-request working set, index-aligned to the request ───── */
    uint64_t prep_fee[NODUS_CMT_APP_MAX_TXS];     /* ordering key         */
    uint8_t  prep_class[NODUS_CMT_APP_MAX_TXS];   /* NODUS_W_TX_V2_*      */
    bool     prep_is_cc[NODUS_CMT_APP_MAX_TXS];   /* a chain_config leg   */
    size_t   prep_order[NODUS_CMT_APP_MAX_TXS];   /* request indices      */

    /* ── the seam's entry views (bytes BORROWED from the request) ────── */
    nodus_witness_mempool_entry_t  seam_entry[NODUS_CMT_APP_MAX_TXS];
    nodus_witness_mempool_entry_t *seam_ptr[NODUS_CMT_APP_MAX_TXS];

    /* ── finalize_block's working set (app-owned until the next call of
     * the same method, proxy/app_conn.go's ownership rule) ─────────────
     * `fb_results` holds TWICE the item bound because the engine writes
     * envelopes then claims into one array and a block may be all of
     * either; `fb_of` maps a block position to its slot in whichever
     * list that item went to, or (size_t)-1 for bytes the engine never
     * saw. `fb_claim` is ~5 KB per entry — the reason this context is
     * heap-allocated. */
    /**
     * TEST-ONLY fault injection, runtime, off by default — the same
     * discipline as the engine's own `V2AP_FAIL_*`
     * (nodus_witness_v2_apply.h): a field a test sets, never a
     * production caller. `finalize_block` copies it into the block it
     * hands the engine, which is the ONLY way a test can reach a fault
     * point inside the apply — the block struct is built here, not by
     * the caller. `V2AP_FAIL_NONE` (0) means no injection, so a zeroed
     * context injects nothing. The two index fields select WHICH item
     * and which of its effects a point that takes an index fires on
     * (F27, F37, F38); they are the engine's own `fail_env_index` /
     * `fail_effect_index` and carry the same meaning.
     */
    nodus_v2_apply_fail_t          test_fail_at;
    uint32_t                       test_fail_env_index;
    uint32_t                       test_fail_effect_index;

    uint8_t                        fb_class[NODUS_CMT_APP_MAX_TXS];
    size_t                         fb_of[NODUS_CMT_APP_MAX_TXS];
    nodus_v2_envelope_t            fb_env[NODUS_CMT_APP_MAX_TXS];
    dna_claim_t                    fb_claim[NODUS_CMT_APP_MAX_TXS];
    nodus_v2_tx_result_t           fb_results[NODUS_CMT_APP_MAX_TXS * 2];
    cmt_pb_stored_exec_tx_result_t fb_pb[NODUS_CMT_APP_MAX_TXS];
} nodus_cmt_app_ledger_t;

/**
 * Bind the application to a ledger.
 *
 * @param ctx    zeroed and filled.
 * @param w      the witness handle; `w->db` must be open and the chain
 *               must be a Ledger V2 successor (`w->v2_successor`) — every
 *               seam this module calls refuses otherwise, so binding a
 *               legacy chain here would produce a table whose rows all
 *               fault. Refused at bind time instead.
 * @param gendoc the genesis document, BORROWED. Mandatory for ONE
 *               comparison: `init_chain` checks the ledger's committed
 *               global root against the document's `app_hash`, and
 *               cometbft's `RequestInitChain` (abci/types.proto:76-83)
 *               carries no app_hash field to compare against (verified
 *               at consensus/replay.go:326-334 — the reference sends
 *               Time/ChainId/InitialHeight/ConsensusParams/Validators/
 *               AppStateBytes and nothing else). DEVIATION R3-C1a-1,
 *               now HALF its round-1 size: the CHAIN ID no longer comes
 *               from here but from the stored document
 *               (`nodus_witness_v2_gen_stored_chain_id`). The app_hash
 *               still does, because no accessor returns the stored
 *               document's app_hash — `..._stored_chain_id` loads and
 *               decodes it but yields only the chain id, and
 *               reproducing that load here would be a second reader of
 *               the same row.
 * @return CMT_OK, CMT_FAULT on NULL / a closed db / a non-successor chain.
 */
int nodus_cmt_app_ledger_init(nodus_cmt_app_ledger_t *ctx, nodus_witness_t *w,
                              const cmt_genesis_doc_t *gendoc);

/**
 * Fill all seven rows of `out` (proxy/app_conn.go:18-27). `ctx` becomes
 * the table's `ctx`. @return CMT_OK, CMT_FAULT on NULL.
 */
int nodus_cmt_app_ledger_build(nodus_cmt_app_t *out,
                               nodus_cmt_app_ledger_t *ctx);

/**
 * Fill the `check_tx`, `error` and `flush` rows of the MEMPOOL connection
 * (proxy/app_conn.go:29-36, `cmt_mem_app_t`). Same context object: the
 * reference's two connections speak to ONE application.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int nodus_cmt_app_ledger_build_mempool(cmt_mem_app_t *out,
                                       nodus_cmt_app_ledger_t *ctx);

/* ── the rows, exposed so the tests drive exactly what the host calls ── */

/** consensus/replay.go:318-373's callee — D-23 rev 5 (7). */
int nodus_cmt_app_init_chain(void *ctx,
                             const nodus_abci_request_init_chain_t *req,
                             nodus_abci_response_init_chain_t *resp);

/** state/execution.go:129-153's callee — D-4 rev 3 (3)'s two rules. */
int nodus_cmt_app_prepare_proposal(
        void *ctx, const nodus_abci_request_prepare_proposal_t *req,
        nodus_abci_response_prepare_proposal_t *resp);

/** state/execution.go:162-188's callee — the ledger's whole-block check. */
int nodus_cmt_app_process_proposal(
        void *ctx, const nodus_abci_request_process_proposal_t *req,
        nodus_abci_response_process_proposal_t *resp);

/** abci/types/application.go:100-102 — `BaseApplication.ExtendVote`
 *  returns an EMPTY `ResponseExtendVote`. */
int nodus_cmt_app_extend_vote(void *ctx,
                              const nodus_abci_request_extend_vote_t *req,
                              nodus_abci_response_extend_vote_t *resp);

/** abci/types/application.go:104-108 —
 *  `BaseApplication.VerifyVoteExtension` returns Status ACCEPT. */
int nodus_cmt_app_verify_vote_extension(
        void *ctx, const nodus_abci_request_verify_vote_extension_t *req,
        nodus_abci_response_verify_vote_extension_t *resp);

/**
 * state/execution.go:224-258's callee: the ledger's Comet apply lane.
 * Returns one `ExecTxResult` per item in block order; a failing item is
 * a nonzero code and does NOT fail the block. CMT_FAULT means the ledger
 * could not APPLY a decided block — the host rolls back and stops.
 */
int nodus_cmt_app_finalize_block(void *ctx,
                                 const nodus_abci_request_finalize_block_t *req,
                                 nodus_abci_response_finalize_block_t *resp);

/** abci/types/application.go's `Commit` — the COMMIT of the host's ONE
 *  transaction (D-23 rev 5 (5)). `retain_height` 0: no pruning in W2. */
int nodus_cmt_app_commit(void *ctx, nodus_abci_response_commit_t *resp);

/** proxy/app_conn.go:33-34 — `CheckTx`, the ledger's ADMISSION check
 *  (D-23 rev 5 (9)). */
int nodus_cmt_app_check_tx(void *ctx, const cmt_mem_request_check_tx_t *req,
                           cmt_mem_response_check_tx_t *res);

/**
 * ENGINE-INTERNAL, exposed for direct test: the identity
 * `nodus_witness_verify_transaction` demands for one candidate entry —
 * SHA3-512 of the bytes for a CLAIM (nodus_witness_verify.c:564-572), the
 * DERIVED `wire_id` for an ENVELOPE (:750, `memcmp(tx_hash,
 * pf->wire_id, …)`). `*out_class` receives the byte-driven entry class
 * (`nodus_witness_v2_classify_entry`).
 *
 * @return CMT_OK; CMT_REJECT when the bytes cannot yield an identity (a
 *         malformed envelope), CMT_FAULT on a node-local failure.
 */
int nodus_cmt_app_entry_identity(nodus_cmt_app_ledger_t *ctx,
                                 const uint8_t *bytes, size_t len,
                                 uint8_t out_id[64], uint8_t *out_class);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_CMT_APP_H */
