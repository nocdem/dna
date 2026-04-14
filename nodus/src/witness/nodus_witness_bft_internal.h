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
                       nodus_witness_batch_ctx_t *batch_ctx,
                       const uint8_t *client_pubkey,
                       const uint8_t *client_sig);

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
int finalize_block(nodus_witness_t *w,
                    const uint8_t *tx_hashes,
                    uint32_t tx_count,
                    const uint8_t *proposer_id,
                    uint64_t timestamp,
                    uint64_t expected_height);

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
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id);

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
                                 const uint8_t *proposer_id);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_BFT_INTERNAL_H */
