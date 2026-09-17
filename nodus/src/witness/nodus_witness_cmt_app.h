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
 * ORCHESTRATOR delta 1+2, item B (D-23 rev 7 (24), APPROVED, CLOSED) —
 * THE BYTE-BOUND CAPACITY SEAM, replacing NODUS_CMT_APP_MAX_TXS
 * (= NODUS_W_MAX_BLOCK_TXS = 10, the old lane's per-block cap that D-4
 * rev 3 (2) explicitly retires for the Comet lane).
 *
 * delta 2 — PER-REQUEST, NOT INIT-TIME: the record's own words are "over
 * heap-allocated PER-REQUEST arrays" (D-23 rev 7 (24)). delta 1's first
 * pass pre-allocated every scratch array ONCE, at bind time, sized to
 * the worst case — ≈118 MiB resident for the life of the node, always,
 * whether or not a request ever approaches that size. delta 2 instead
 * allocates every WORKING-SCRATCH array (`prep_fee`/`class`/`is_cc`/
 * `order`, the seam's item view, `fb_class`/`of`/`env`/`claim`/`results`)
 * fresh, INSIDE each ABCI row, sized to THAT REQUEST's own
 * `req->txs_len` (or a classified subcount, where one is meaningful —
 * `fb_claim`'s size is the number of CLAIM-classified items in the block,
 * not the whole block), and frees it before returning on every path
 * (goto-cleanup). Only TWO arrays remain context-owned across calls
 * (`prep_txs`, `fb_pb` — see their own fields below): the ABCI ownership
 * rule ("app-owned until the next call of the same method",
 * proxy/app_conn.go) requires the RESPONSE the caller reads AFTER this
 * row returns to stay valid, so those two are reallocated per request
 * but never freed within the same call that fills them.
 *
 * THREE BOUNDS remain, now used as REFUSAL CEILINGS rather than array
 * sizes — a request whose OWN count exceeds one is refused (a verdict,
 * not a crash) before anything is allocated for it:
 *
 *   PREP_BOUND — `nodus_cmt_app_ledger_t.prep_bound`, from
 *   `cmt_mempool_config_default()`'s own `.size` (5 000, config.go:796,
 *   D-4 rev 3): the largest batch PrepareProposal can EVER be handed
 *   (`ReapMaxBytesMaxGas` walks at most `mem.txs.Len()`, itself capped at
 *   `size` — mempool/clist_mempool.go:536). `req->txs_len > prep_bound`
 *   in PrepareProposal is CMT_FAULT (a node-local mempool/executor
 *   mismatch, unchanged from delta 1). delta 2 DROPS this bound's use in
 *   ProcessProposal: with per-request sizing there is no fixed array it
 *   protects any more, and the reference imposes no such rule there —
 *   ProcessProposal's own ceiling is env_bound (below), the true
 *   byte-derived limit, exactly as FinalizeBlock's already was.
 *
 *   ENV_BOUND — `nodus_cmt_app_ledger_t.env_bound`. `MaxDataBytes`
 *   (types/block.go:281-300, ported as `cmt_max_data_bytes_no_evidence`,
 *   shared/dnac/cmt_block.c:1747-1752) divided by the SMALLEST canonical
 *   item the chain's own codecs accept — an envelope of
 *   `DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN` = 43 + 30 = 73 bytes
 *   (shared/dnac/env_wire.h:198-199; a claim's own fixed minimum,
 *   DNA_CLAIM_FIXED_LEN = 7 404 bytes, manifest_wire.h:452-454, is two
 *   orders of magnitude larger, so an envelope-only block is always the
 *   worst case for TOTAL item count). Computed at `vals_count = 1` — the
 *   smallest possible committee, the largest possible byte budget, the
 *   safe UPPER bound regardless of how large the committee grows toward
 *   DNAC_MAX_ACTIVE_VALIDATORS. At Block.MaxBytes = 22 020 096 (D-4
 *   rev 3) this is 293 525 (the arithmetic, every constant cited, is in
 *   `nodus_cmt_app_ledger_init`). `req->txs_len > env_bound` in
 *   ProcessProposal is REJECT (a malformed-block verdict — physically
 *   impossible under this chain's own consensus params); in
 *   FinalizeBlock it is CMT_FAULT (a decided block is never refused a
 *   verdict, so a request that could not exist under the params is this
 *   node's own invariant broken).
 *
 *   CLAIM_BOUND — `nodus_cmt_app_ledger_t.claim_bound`, `MaxDataBytes`
 *   divided by a claim's own minimum wire size (DNA_CLAIM_FIXED_LEN),
 *   ~2 972 at the same `vals_count = 1`. Used ONLY as FinalizeBlock's
 *   defensive ceiling on the CLASSIFIED claim subcount within one
 *   request (`fb_claim`'s per-request size), never as a whole-request
 *   admission bound — a request could not exceed it in claims alone
 *   without also exceeding env_bound in total items first.
 *
 * A FOURTH bound joins these three (ORCHESTRATOR delta 11,
 * R3-W3-C2a-19), unlike them in kind: it is NOT one of the "three
 * bounds" the paragraph above enumerates, NOT a `nodus_cmt_app_ledger_t`
 * field, and NOT derived from this chain's genesis document at bind
 * time —
 *
 *   ITEM_CAP — the compile-time constant `NODUS_V2_APPLY_MAX_OPS`
 *   (nodus_witness_v2_apply.h, currently 16), the engine's own RELEASE
 *   RESOURCE bound on its per-block scratch (`claim_nuls[MAX_OPS][64]`
 *   and the universal envelope-batch cap `NODUS_V2_ENV_BATCH_MAX`,
 *   nodus_witness_v2_env.h:121, sized to the same figure) — exactly
 *   like `MAX_DOMS` elsewhere in this port, a property of THIS BUILD of
 *   the engine, never a consensus parameter this chain's genesis could
 *   set differently. `nodus_cmt_app_prepare_proposal` trims its KEPT
 *   count to this bound (after the fee ordering and the byte budget,
 *   before the engine's own admission seam); `nodus_cmt_app_
 *   process_proposal` REJECTs any proposal above it before any per-item
 *   work. Before delta 11 NEITHER gate existed: the Comet lane's own
 *   count cap (the retired `NODUS_CMT_APP_MAX_TXS` = 10) happened to
 *   keep every block inside this bound by accident until D-4 rev 3 (2)
 *   retired it, and the Genesis Protocol harness then decided a 40-claim
 *   block that FAULTED every node's FinalizeBlock at height 7
 *   (`/tmp/stagef-20260917T034259Z`) — the live defect this bound
 *   closes. The derived-bounds log line in `nodus_cmt_app_ledger_init`
 *   reports it as `item_cap=%u` beside the three DERIVED bounds so an
 *   operator reading the log sees all four together, even though only
 *   three are computed there.
 *
 * NODUS_CMT_APP_MAX_TXS is RETIRED. It does not survive as a compile-
 * time bound anywhere in this file, this file's tests, or
 * nodus_witness_cmt_node.c's `limits.max_txs` derivation — replaced by
 * the SAME three runtime bounds, read from the application context that
 * already computed them once.
 */

/**
 * The application's context: the ledger handle, the genesis document,
 * the three derived bounds, and the TWO response buffers the ABCI
 * ownership rule requires to persist past the call that fills them. One
 * instance per node; the rows are single-threaded (the consensus event
 * loop calls them in line).
 *
 * `w` and `gendoc` are BORROWED and must outlive the context.
 *
 * delta 2 — PER-REQUEST, NOT PRE-ALLOCATED: every WORKING-SCRATCH array
 * delta 1 kept here (`prep_fee`/`class`/`is_cc`/`order`, the seam's item
 * view, `fb_class`/`of`/`env`/`claim`/`results`) is now a LOCAL variable
 * inside the row that needs it, calloc'd at the top of the call sized to
 * that request, freed via goto-cleanup before every return — see
 * `nodus_cmt_app_prepare_proposal` / `_process_proposal` /
 * `_finalize_block` in the .c file. Only `prep_txs` and `fb_pb` remain
 * context fields, because the RESPONSE each row returns points into
 * them and proxy/app_conn.go's ownership rule keeps that pointer valid
 * until the NEXT call to the SAME method — each row frees its own
 * previous buffer at the TOP of its next call (not at the bottom of the
 * call that filled it) and reallocates sized to what THIS call
 * produces. `nodus_cmt_app_ledger_init` no longer allocates anything;
 * it only computes the three bounds. `nodus_cmt_app_ledger_release`
 * frees whichever of `prep_txs` / `fb_pb` happen to be non-NULL at
 * teardown.
 */
typedef struct {
    nodus_witness_t         *w;       /* the ledger                       */
    const cmt_genesis_doc_t *gendoc;  /* BORROWED; InitChain's app_hash   */

    /* The three bounds this context was built for — see the block
     * comment above. Set ONCE, at init; every row below trusts these
     * over any compile-time constant. */
    size_t prep_bound;
    size_t env_bound;
    size_t claim_bound;

    /* ── prepare_proposal's RESPONSE (app-owned until the next call of
     * the same method, proxy/app_conn.go's ownership rule) — REALLOCATED
     * per request, sized to the KEPT count (after byte-budget trimming
     * and the seam's own drops), never to prep_bound. `prep_txs_cap` is
     * the capacity currently allocated, so the next call knows whether
     * it must grow or may reuse — it always reallocates fresh, so this
     * is bookkeeping for the free/alloc pair, not a growth heuristic. */
    cmt_pb_bytes_t *prep_txs;
    size_t          prep_txs_len;
    size_t          prep_txs_cap;

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
     *
     * ⚠ delta 2 / register R3-C2a-B: THESE THREE FIELDS ARE STICKY. They
     * are set by a test and never cleared by any production row, so a
     * fixture that shares one `nodus_cmt_app_ledger_t` (or one block
     * built from it) across cases MUST reset them itself before a case
     * that expects an un-injected FinalizeBlock — see
     * `test_cmt_app.c`'s own fix for exactly this (a shared `blk->cmt`
     * fault field surviving into `t_byte_bound_prepare_and_process`).
     */
    nodus_v2_apply_fail_t          test_fail_at;
    uint32_t                       test_fail_env_index;
    uint32_t                       test_fail_effect_index;

    /* ── finalize_block's RESPONSE (app-owned until the next call of the
     * same method, same rule as prep_txs above) — REALLOCATED per
     * request, sized to `req->txs_len` (one result per block position),
     * never to env_bound. */
    cmt_pb_stored_exec_tx_result_t *fb_pb;
    size_t                          fb_pb_cap;
} nodus_cmt_app_ledger_t;

/**
 * Frees `prep_txs` and `fb_pb` if either is non-NULL — the only two
 * arrays this context still owns across calls (delta 2). Does NOT free
 * `ctx` itself (production callers heap-allocate the context and free
 * it themselves — nodus_witness_cmt_node.c's `nodus_cmt_node_release`).
 * NULL-safe throughout; a partially-built or freshly-bound context (no
 * row has run yet) is safe to release.
 */
void nodus_cmt_app_ledger_release(nodus_cmt_app_ledger_t *ctx);

/**
 * Bind the application to a ledger.
 *
 * ORCHESTRATOR delta 1, item B (delta 2 narrows this): this is where
 * `prep_bound` / `env_bound` / `claim_bound` are COMPUTED (from
 * `gendoc`'s own `consensus_params.block.max_bytes` and a local
 * `cmt_mempool_config_default()` call — the real mempool config is not
 * built yet at this point in `nodus_cmt_node_init`'s sequence, but the
 * default is a pure function of no state, so calling it here for the
 * bound and again later for the real mempool yields the identical
 * value). delta 2: NOTHING IS ALLOCATED HERE any more — `prep_txs` and
 * `fb_pb` start NULL and are built by their own rows on first use, sized
 * to that call's own request, exactly like every other row's now-local
 * scratch. This function's only failure modes are the bound computation
 * itself.
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
 *               the same row. ALSO now mandatory for `block.max_bytes`,
 *               the byte-bound seam's own input.
 * @return CMT_OK, CMT_FAULT on NULL / a closed db / a non-successor chain /
 *         a `block.max_bytes` too small to be believed / the mempool
 *         default config being unreadable.
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
