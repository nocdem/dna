/**
 * Nodus — Witness BFT Internal API
 *
 * Declarations for primitives that nodus_witness_bft.c defines as
 * non-static but does NOT publish in any production-facing header.
 * Test executables include this header (gated on
 * NODUS_WITNESS_INTERNAL_API) to call the primitives directly without
 * having to go through the public commit_block / commit wrappers.
 *
 * The functions are non-static in the library because static + test
 * linkage is incompatible in CMake's normal flow. The protection is
 * "no public header references them" rather than "static qualifier".
 * Production code reaching into these symbols is treated as a code
 * review failure.
 *
 * Guards:
 *   - The CMake `register_witness_test` macro (Task 0.16) defines
 *     NODUS_WITNESS_INTERNAL_API on the test executable's compilation
 *     so this header becomes visible.
 *   - The CMakeLists.txt guard from Task 4.4 forbids
 *     NODUS_WITNESS_INTERNAL_API in Release builds, so the test-only
 *     header path never compiles into a release binary.
 *
 * @file nodus_witness_bft_internal.h
 */

#ifndef NODUS_WITNESS_BFT_INTERNAL_H
#define NODUS_WITNESS_BFT_INTERNAL_H

#ifndef NODUS_WITNESS_INTERNAL_API
#error "nodus_witness_bft_internal.h is only available with NODUS_WITNESS_INTERNAL_API defined"
#endif

#include "witness/nodus_witness.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Phase 3 / Task 3.0 — supply invariant check, lifted from the inline
 * body of commit_block_inner. Returns true if any current invariant is
 * violated. Read-only on w->db. Emits ERROR log lines on violation. */
bool supply_invariant_violated(nodus_witness_t *w);

/* Phase 3 / Task 3.1 — apply a single TX's effects to witness state.
 *
 * This is the per-TX body of the legacy commit_block_inner: nullifier
 * insertion, UTXO set update, fee burn tracking, tx_outputs storage,
 * sender_fp extraction, ledger_add, and TOKEN_CREATE registration.
 * It does NOT compute state_root or call block_add — those are the
 * job of finalize_block (Task 3.2).
 *
 * Parameters:
 *   w               witness context (DB writes happen inside the
 *                   caller's open transaction)
 *   tx_hash         32-byte TX hash
 *   tx_type         NODUS_W_TX_GENESIS / SPEND / BURN / TOKEN_CREATE
 *   nullifiers      array of nullifier_count nullifier blobs (64 bytes
 *                   each); may be NULL for genesis
 *   nullifier_count number of nullifiers
 *   tx_data         serialized TX bytes
 *   tx_len          length of tx_data
 *   block_height    explicit block height the TX is committed at
 *                   (Phase 3 multi-tx batches share a height across N
 *                   apply_tx_to_state calls)
 *   batch_ctx       optional intra-batch chained-UTXO context (Phase 4
 *                   adds the layer-3 check). NULL is legal — the chained
 *                   detection is skipped, used by single-TX paths and
 *                   the SAVEPOINT attribution replay.
 *
 * Returns 0 on success, -1 on any per-TX failure.
 */
int apply_tx_to_state(nodus_witness_t *w,
                       const uint8_t *tx_hash,
                       uint8_t tx_type,
                       const uint8_t *const *nullifiers,
                       uint8_t nullifier_count,
                       const uint8_t *tx_data,
                       uint32_t tx_len,
                       uint64_t block_height,
                       uint64_t block_timestamp,
                       nodus_witness_batch_ctx_t *batch_ctx,
                       const uint8_t *client_pubkey,
                       const uint8_t *client_sig);

/* Phase 8 Task 41 — DELEGATE state mutation, the legacy lane's half of
 * the per-validator delegator cap (O15J Block 2).
 *
 * apply_tx_to_state's NODUS_W_TX_DELEGATE branch is the only production
 * caller. Exported here so the cap regression can drive the rule with a
 * synthetic tx_data and an explicitly supplied committed_fee: the fee is
 * an INPUT to this function (update_utxo_set computes it earlier in the
 * batch), and the UTXO/nullifier machinery that produces it has no
 * bearing on the delegation rules under test.
 *
 * Parameters:
 *   tx_data / tx_len  serialized DELEGATE TX; the type-specific fields
 *                     validator_pubkey(2592) ‖ delegation_amount(u64 BE)
 *                     are appended after the signer section
 *   block_height      height the TX commits at (becomes
 *                     delegation.delegated_at_block)
 *   committed_fee     the fee update_utxo_set already committed; enters
 *                     the Σin == Σout + fee + amount consistency rule
 *
 * Returns 0 on success, -1 on ANY rejection — the legacy lane has a
 * single failure class and the caller turns it into a whole-block
 * rollback. Rejections are deterministic functions of committed state
 * (Rule S, validator status, the delegator cap), so honest nodes agree.
 */
int apply_delegate(nodus_witness_t *w,
                    const uint8_t *tx_data, uint32_t tx_len,
                    uint64_t block_height,
                    uint64_t committed_fee);

/* Phase 3 / Task 3.2 — finalize a block from N already-applied TXs.
 *
 * Computes state_root via merkle_compute_utxo_root, runs the supply
 * invariant check (now per-block instead of per-TX — Task 3.4),
 * computes tx_root via merkle_tx_root over the batch's TX hashes,
 * and writes the block row via nodus_witness_block_add.
 *
 * The batch's TXs must have ALREADY been applied via apply_tx_to_state
 * inside the same outer DB transaction. finalize_block does not retry
 * or roll back on its own — supply violations or block_add errors
 * propagate as -1 and the caller's outer transaction handles rollback.
 *
 * Parameters:
 *   w                witness context
 *   tx_hashes        flat buffer of n * 64 bytes of raw TX hashes for
 *                    tx_root computation
 *   tx_count         number of TXs in the batch (1..NODUS_W_MAX_BLOCK_TXS)
 *   proposer_id      32-byte witness ID of the BFT round leader
 *   timestamp        block timestamp (from BFT proposal, deterministic)
 *   expected_height  the height the block should land at; equals
 *                    nodus_witness_block_height(w) + 1 in normal flow
 *
 * Returns 0 on success, -1 on supply violation or block_add failure.
 */
/* C3 fix — expected_state_root (non-NULL on follower replay paths)
 *   Compared against the locally computed state_root after the per-block
 *   mutations. Mismatch → safety halt + rollback. Pass NULL for genesis
 *   and leader-originated commits. */
int finalize_block(nodus_witness_t *w,
                    const uint8_t *tx_hashes,
                    uint32_t tx_count,
                    const uint8_t *proposer_id,
                    uint64_t timestamp,
                    uint64_t expected_height,
                    const uint8_t *chain_def_blob,
                    size_t chain_def_blob_len,
                    const uint8_t *expected_state_root);

/* Phase 6 commit wrappers.
 *
 * These three wrappers compose apply_tx_to_state + finalize_block into
 * the named operations that the BFT round (Phase 7) and sync handler
 * (Phase 11) call. Each wrapper manages its own outer DB transaction
 * and handles rollback. The underlying primitives stay single-purpose. */

/* Task 6.1 — single-TX genesis commit with chain DB bootstrap.
 *
 * Derives the chain_id from the genesis TX fingerprint, creates the
 * witness DB (if !w->db), then runs one apply_tx_to_state + one
 * finalize_block inside an outer BEGIN/COMMIT. Idempotent: safe to
 * call twice with the same tx_hash. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id);

/* Task 6.2 — multi-TX batch commit with SAVEPOINT attribution replay.
 *
 * Each entry in `entries` is applied in order under one outer
 * transaction, with one finalize_block at the end. batch_ctx
 * accumulates each TX's output future-nullifiers so layer-3 sees the
 * full history as the loop progresses. On any failure the outer
 * transaction rolls back, then a secondary replay loop runs each TX
 * individually under a SAVEPOINT to identify the specific offender
 * — emits "attribution: TX %d ..." log lines — then discards the
 * replay transaction. */
/* expected_height (2026-05-02 audit M-1 fix): the height the block
 * should land at. Caller MUST pass leader's claim (cmt->block_height
 * from a remote COMMIT, or local_chain_head + 1 for leader path).
 * Mismatch with local_chain_head + 1 inside commit_batch → rollback +
 * return -1, defends against TOCTOU race between handle_commit's
 * pre-check and commit_batch entry. Bug ref:
 * project_witness_commit_height_asymmetry. */
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t expected_height,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root);

/* Task 6.3 — replay a block from a sync_rsp.
 *
 * Used by follower witnesses catching up via the sync protocol. Takes
 * the block height, tx array, and block metadata from the wire message
 * and runs the same apply + finalize pair inside an outer transaction.
 * Rejects out-of-order replay (rsp_height != local_height + 1) up
 * front. Phase 11 wires this into the sync handler. */
int nodus_witness_replay_block(nodus_witness_t *w,
                                 uint64_t rsp_height,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root);

/* MED-28 (O15C-D) — move the current round's batch into the reproposal
 * holder instead of freeing it.
 *
 * Called on round timeout, i.e. exactly when a view change is starting
 * and a prepared cert may bind the next view's first PROPOSE to this
 * batch's tx_root. The C5 binding is a DIGEST; last_prepared carries no
 * transaction bytes, so before this existed the round-timeout free left
 * NO copy of the bytes anywhere on the network and the bound height
 * could never be satisfied.
 *
 * Ownership TRANSFERS out of round_state (batch_count is left at 0, so
 * the following round_state reset frees nothing). Only one batch is
 * held: a newer timeout supersedes and frees an older one, matching the
 * C5 rule that binds to the HIGHEST prepared height. No-op when the
 * round holds no batch.
 *
 * Exported here for the retention regression only; production callers
 * are inside nodus_witness_bft.c. Release with
 * nodus_witness_retained_batch_clear (nodus_witness_bft.h). */
void nodus_witness_retained_batch_take(nodus_witness_t *w);

/* Phase 9 / Task 48 — nodus_witness_record_attendance is declared
 * publicly in nodus_witness_bft.h. Tests include that header. */

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BFT_INTERNAL_H */
