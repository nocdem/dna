/**
 * @file nodus/src/witness/nodus_witness_v2_produce.h
 * @brief Ledger V2 O15D — the SUCCESSOR block-production seam: the handoff
 *        between the live BFT round machinery and the ONE V2 engine.
 *
 * ═══ SCOPE ══════════════════════════════════════════════════════════════
 * Runs ONLY on a chain whose handle carries `w->v2_successor` — a fact
 * derived at database open from COMMITTED state (the height-0 successor
 * genesis manifest with the "DNA.LEGACY.TERM.v1" source binding; the same
 * committed authority the activation gate reads). On every other chain the
 * legacy lane is byte-identically untouched, and on non-activation builds
 * the successor cannot exist at all (deriving one is compile-gated).
 *
 * ═══ ONE ENGINE ═════════════════════════════════════════════════════════
 * Execution, ordering (SYSTEM → cross-domain → domain-local ASC), root
 * computation, header/BlockID derivation, atomic persistence and rollback
 * are ALL `nodus_witness_v2_apply_block` (O14): this module builds the
 * block INPUT from the agreed BFT batch and maps the engine's typed result
 * back onto the round. It computes no root, no BlockID and no header of
 * its own, and it opens no transaction.
 *
 * ═══ QC FORMATION — the shipped post-commit certificate shape ═══════════
 * The QC V2 preimage binds the BlockID, which binds the global state root
 * (execution results), so a QC certificate can only be SIGNED after
 * execution — while the BFT round votes BEFORE execution (the legacy
 * PREVOTE/PRECOMMIT machinery binds the batch digest, unchanged here).
 * The legacy lane resolves the same tension the same way: it commits in
 * commit_batch and stores/broadcasts its finalization certificates
 * afterwards (nodus_witness_bft.c cert_store + the COMMIT broadcast), so
 * a committed-but-not-yet-certified window is the SHIPPED production
 * behavior, not a new shape — and `qc IS NULL` on a fresh row is
 * explicitly contract-legal (nodus_witness_v2_apply.h, qc_bytes).
 *
 * Flow: after its local engine commit each validator signs the 216-byte
 * DNA.CERT.v2 preimage over ITS OWN derived BlockID and carries the
 * signature on its ordinary COMMIT broadcast (two successor-only fields).
 * Every node collects incoming certificates into a bounded per-height
 * pool, verifies each against the committed authority snapshot for that
 * height (the O12 resolver — never against roster or wire input), and at
 * `dna_bft_quorum(N)` matching certificates assembles the canonical QC,
 * verifies it through `nodus_witness_v2_qc_verify` (the ONE verifier),
 * and attaches it: UPDATE v2_blocks SET qc WHERE the height's stored
 * block_id matches AND qc IS NULL. Idempotent; never stores unverified
 * bytes; QC bytes are NOT part of any cross-node identity comparison
 * (each node may hold a different valid >=quorum subset).
 *
 * HONEST LIMIT: certificates ride the round's COMMIT frames only. A node
 * that never completes the round holds no pool, and a block finalized
 * immediately before a shutdown may persist with qc NULL on some nodes.
 * Certificate re-request / backfill is a named open item, not built here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NODUS_WITNESS_V2_PRODUCE_H
#define NODUS_WITNESS_V2_PRODUCE_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_mempool.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Outputs of one successful successor commit, for the COMMIT broadcast. */
typedef struct {
    uint8_t block_id[64];       /* engine-derived BlockID                */
    uint8_t global_root[64];    /* engine-derived global state root      */
    uint8_t cert_sig[NODUS_SIG_BYTES];  /* our DNA.CERT.v2 signature     */
    int     have_cert;          /* 0 when signing failed (rare fault) —
                                 * the block is still committed          */
} nodus_v2_produce_out_t;

/**
 * Execute and commit ONE successor block from the agreed BFT batch,
 * through the one engine.
 *
 * Every entry MUST be a successor envelope entry (tx_type
 * NODUS_W_TX_V2_ENVELOPE, bytes classified by the wire-family marker at
 * admission). `expected_global_root` is the C3-analog follower assertion
 * (the COMMIT frame's state_root field) — NULL on the own-quorum path.
 *
 * On success fills `out`, stamps each entry's committed_block_height /
 * committed_tx_index (client receipts), records our own certificate in
 * the pool and tries QC assembly.
 *
 * @return 0 committed (or idempotent replay of the identical block),
 *        -1 deterministic verdict (the batch is invalid — round fails,
 *           mirrors the legacy batch_failed handling),
 *        -2 node-local fault OR not-yet-linkable (this node could not
 *           compute/sequence — the caller must NOT broadcast a COMMIT
 *           and must NOT blame the batch).
 */
int nodus_witness_v2_produce_commit(nodus_witness_t *w,
                                    nodus_witness_mempool_entry_t **entries,
                                    int count,
                                    uint64_t height,
                                    uint64_t timestamp,
                                    const uint8_t *proposer_id,
                                    const uint8_t *expected_global_root,
                                    nodus_v2_produce_out_t *out);

/**
 * Record one peer certificate (from a successor COMMIT frame).
 *
 * Bounded, dedup-by-voter, height-scoped: accepted only for the pool's
 * height, or (when the pool is empty/behind) for exactly the next height
 * this node would commit — anything else is dropped. Verification is
 * deferred until our own block at that height is committed, then runs
 * against the committed authority snapshot. Triggers QC assembly when
 * quorum is reached. Never a consensus verdict — a bad certificate is
 * simply not counted.
 */
void nodus_witness_v2_cert_note(nodus_witness_t *w,
                                uint64_t height,
                                const uint8_t voter_id[32],
                                const uint8_t block_id[64],
                                const uint8_t sig[NODUS_SIG_BYTES]);

/**
 * Try to assemble and attach the QC for the pool's committed height.
 * Idempotent; safe to call any time. @return 0 attached-or-already,
 * 1 not yet (quorum not reached / nothing committed), -1 fault.
 */
int nodus_witness_v2_qc_try_attach(nodus_witness_t *w);

/**
 * The authoritative successor tip height (MAX(global_height) of
 * v2_blocks; 0 with only genesis committed). @return 0 / -1 fault.
 */
int nodus_witness_v2_tip_height(nodus_witness_t *w, uint64_t *height_out);

/**
 * Transport-local classification of a successor mempool entry from its
 * LEADING bytes: an entry beginning with the 16-byte "DNA.ENVWIRE.v1"
 * family marker (env_wire.c:25-27) is a Ledger V2 ENVELOPE
 * (NODUS_W_TX_V2_ENVELOPE); anything else on a successor is a CLAIM
 * (NODUS_W_TX_V2_CLAIM) — strict dna_claim_decode + admission decide its
 * validity. Deterministic and byte-driven: every honest node classifies
 * the identical bytes identically, so admission, ingress and round entry
 * share ONE classification authority. Buffers shorter than the marker
 * cannot carry it, so they classify as CLAIM (and fail their own decode).
 */
uint8_t nodus_witness_v2_classify_entry(const uint8_t *bytes, uint32_t len);

/**
 * Derive the committed nullifier of a class-201 CLAIM entry from its wire
 * bytes (READ-ONLY): strict decode then the ONE admission function
 * (nodus_witness_v2_claim_admit), whose adm.nullifier is exactly the
 * value the apply engine binds. Used to record the nullifier on the
 * class-201 mempool entry so batch selection dedups claims semantically.
 * Fail-closed — a caller MUST NOT enqueue a claim entry if this fails.
 * @return 0 with out_nullifier filled / -1.
 */
int nodus_witness_v2_claim_entry_nullifier(nodus_witness_t *w,
                                           const uint8_t *bytes, uint32_t len,
                                           uint8_t out_nullifier[64]);

/**
 * Run the engine's own pre-commit seam over a candidate BATCH of
 * envelope entries at the next successor height: strict decode,
 * contextual ruleset match against the committed registry, chain
 * binding, expiry, canonical commitments, and wire- AND intent-level
 * duplicate rejection. The leader runs it before proposing (a duplicate
 * intent in one batch is a whole-block verdict at apply — better to
 * drop the offender than burn the round); followers run it on a
 * received proposal (deterministic: bytes + committed state only).
 *
 * IT ALSO METERS. Until O15I this ran the BARE preflight — no policy, no
 * budget, no meters — while the reserve variant (the one that charges the
 * global and per-domain unit budgets and enforces max_block_env_bytes)
 * had a single caller: the commit engine. So a batch that no budget could
 * pay for passed here, won its votes, and died at apply as
 * "BATCH COMMIT FAILED", answering every client with DNAC_STATUS_ERROR.
 * Measured cost before the fix: 120 failed blocks in one 20-node
 * rehearsal, 71 of them DNA_METER_ERR_GLOBAL_BUDGET at batch index 5.
 * The check now builds the SAME block context the engine builds and runs
 * the reserve seam against a scratch budget.
 *
 * This wrapper keeps the original tri-state for callers that only need a
 * verdict. `..._batch_check_ex` additionally reports the refusal KIND, so
 * the leader can tell "this batch is too big" (truncate and requeue the
 * tail) from "this entry is invalid" (drop it) — see
 * nodus_witness_bft_shape_successor_batch.
 *
 * @param fail_index_out on -1, the index of the offending entry.
 * @return 0 clean / -1 entry rejected / -2 node-local fault.
 */
int nodus_witness_v2_produce_batch_check(nodus_witness_t *w,
                                         nodus_witness_mempool_entry_t **entries,
                                         int count,
                                         int *fail_index_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_PRODUCE_H */
