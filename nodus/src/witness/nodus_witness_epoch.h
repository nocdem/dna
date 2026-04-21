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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_EPOCH_H */
