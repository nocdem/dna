/**
 * @file nodus_witness_epoch.h
 * @brief v0.16 push-settlement epoch state — CRUD over the `epoch_state`
 *        table.
 *
 * The epoch_state table holds one row per ACTIVE epoch (bounded to the
 * current epoch; previous rows are deleted in apply_epoch_settlement —
 * see design §3.1). Each row carries:
 *
 *   epoch_start_height — first block height of the epoch (k * DNAC_EPOCH_LENGTH).
 *   epoch_pool_accum   — cumulative inflation mint accrued over this epoch.
 *   snapshot_hash      — SHA3-512 over the epoch-start committee + delegation snapshot.
 *   snapshot_blob      — serialized snapshot bytes, decoded at settlement.
 *
 * The schema is populated by Stage B.1 (this header), read by Stage D
 * (snapshot), mutated by Stage C.2 (emission) + Stage E (settlement).
 */

#ifndef NODUS_WITNESS_EPOCH_H
#define NODUS_WITNESS_EPOCH_H

#include "witness/nodus_witness.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_EPOCH_SNAPSHOT_HASH_LEN  64   /* SHA3-512 */

/** Epoch-state row (v0.16 push-settlement model). */
typedef struct {
    uint64_t epoch_start_height;
    uint64_t epoch_pool_accum;
    uint8_t  snapshot_hash[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    uint8_t *snapshot_blob;   /* Heap-allocated; caller frees or returns to DB row. */
    size_t   snapshot_blob_len;
} nodus_epoch_state_t;

/**
 * Insert a new epoch_state row. Fails with -2 on duplicate
 * `epoch_start_height`.
 */
int nodus_witness_epoch_insert(nodus_witness_t *w,
                               const nodus_epoch_state_t *e);

/**
 * Fetch the row for `epoch_start_height`. Returns 0 on hit, 1 on miss,
 * -1 on DB error. On hit, `out->snapshot_blob` is heap-allocated — the
 * caller must free() it.
 */
int nodus_witness_epoch_get(nodus_witness_t *w,
                            uint64_t epoch_start_height,
                            nodus_epoch_state_t *out);

/**
 * Fetch the current (highest-height) epoch_state row. Returns 0 on hit,
 * 1 on empty table, -1 on DB error.
 */
int nodus_witness_epoch_get_current(nodus_witness_t *w,
                                    nodus_epoch_state_t *out);

/**
 * Update `epoch_pool_accum` on the row keyed by `epoch_start_height`.
 * Used by Stage C.2's per-block emission accrual.
 */
int nodus_witness_epoch_set_pool_accum(nodus_witness_t *w,
                                       uint64_t epoch_start_height,
                                       uint64_t new_pool_accum);

/**
 * Add `delta` to `epoch_pool_accum` (convenience wrapper for the
 * per-block emission path).
 */
int nodus_witness_epoch_add_pool(nodus_witness_t *w,
                                 uint64_t epoch_start_height,
                                 uint64_t delta);

/**
 * Delete the row for `epoch_start_height`. Called by Stage E at
 * settlement boundary to retire the outgoing epoch row.
 */
int nodus_witness_epoch_delete(nodus_witness_t *w,
                               uint64_t epoch_start_height);

/** Release the heap-allocated snapshot_blob inside an epoch_state row. */
void nodus_witness_epoch_free(nodus_epoch_state_t *e);

/**
 * v0.16 Stage D.1 — capture the committee + delegation snapshot for the
 * epoch that starts at `epoch_start_height` and persist
 * (snapshot_hash, snapshot_blob) onto the epoch_state row.
 *
 * The snapshot IS the distribution basis for Stage E's settlement —
 * once written, it is immutable for the epoch. Idempotent: a second
 * call with the same height overwrites with identical bytes.
 *
 * Canonical serialization (design §3.3 + RT-C3):
 *   committee_count (u16 BE)
 *   for each committee validator (sorted by pubkey ASC):
 *     pubkey(2592) || self_stake(u64 BE) || total_delegated(u64 BE)
 *     || commission_bps(u16 BE) || status(u8)
 *   delegation_count (u32 BE)
 *   for each delegation to any committee validator
 *        (sorted by validator_pubkey then delegator_pubkey ASC):
 *     delegator_pubkey(2592) || validator_pubkey(2592) || amount(u64 BE)
 *
 * snapshot_hash = SHA3-512(snapshot_blob)
 *
 * If the epoch_state row is missing the function inserts one with
 * epoch_pool_accum = 0.
 *
 * ── A DB FAULT IS NOT A VALUE (O15J Block 2, A1). ────────────────────
 * snapshot_hash is a direct state_root input (it is scanned into the
 * epoch_state leaves), so every input this function reads must be the
 * real one or the function must fail. Three legs used to substitute a
 * legitimate-looking value and still return 0 — an unreadable committee
 * became "empty chain", an unreadable `validators` row became an
 * all-zero record, and a failed delegation scan became "no delegators".
 * Each of them let one node's transient IOERR commit a snapshot_hash no
 * peer could reproduce. All three now propagate -1.
 *
 * ABSENT is still not a fault, and the distinction is the point:
 *   - a committee lookup that SUCCEEDS with zero members (pre-genesis /
 *     empty chain) still serializes the canonical empty snapshot;
 *   - a `validators` row that is genuinely missing for a committee
 *     member is still zero-filled with the member's pubkey carried
 *     through — reachable and deterministic since S3, where the
 *     committee can come from a committed validator_set_snapshots row.
 *
 * Residual tolerance, deliberately UNCHANGED and NOT part of A1: the
 * final epoch_state UPDATE still treats a prepare failure as an
 * advisory no-op and returns 0 (see the "schema missing (test fixture)"
 * exit in nodus_witness_epoch.c, and the same tolerance inside
 * nodus_witness_epoch_insert). Same defect class, different leg.
 *
 * @return 0 on success, -1 on any fault — including a committee,
 *         validator or delegation read this node could not complete.
 *         Callers are consensus paths and MUST fail the block: see
 *         nodus_witness_bft.c (finalize_block, V1 lane) and
 *         nodus_witness_v2_econ.c (emission_apply, V2 lane).
 */
int nodus_witness_epoch_snapshot_apply(nodus_witness_t *w,
                                        uint64_t epoch_start_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_EPOCH_H */
