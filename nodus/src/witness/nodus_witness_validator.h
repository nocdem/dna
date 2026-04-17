/**
 * Nodus — Witness Validator CRUD
 *
 * SQLite CRUD primitives over the `validators` table (design §3.7).
 * Wraps sqlite3 prepared statements and exposes a stable C API over
 * dnac_validator_record_t.
 *
 * Scope (Task 12):
 *   - insert / get / update by pubkey (primary key = SHA3-512 leaf-tagged pubkey hash)
 *   - top-N by (self_stake + external_delegated) DESC, pubkey ASC
 *   - active_count read from validator_stats (write-path lives in Phase 8)
 *
 * Not included (out of scope for Task 12):
 *   - Delete path (validators never truly delete; UNSTAKE transitions status)
 *   - Counter maintenance (delegated to Phase 8 state-mutation code)
 *
 * @file nodus_witness_validator.h
 */

#ifndef NODUS_WITNESS_VALIDATOR_H
#define NODUS_WITNESS_VALIDATOR_H

#include "witness/nodus_witness.h"
#include "dnac/validator.h"      /* dnac_validator_record_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Insert a new validator row. Caller is responsible for ensuring the
 * pubkey is not already present (call nodus_validator_get first or rely
 * on the STAKE verify rule I). pubkey_hash is computed internally as
 * SHA3-512(0x02 || pubkey) matching the validator-tree domain-separation
 * tag (NODUS_TREE_TAG_VALIDATOR).
 *
 * @return 0 on success, -1 on SQLite error, -2 on constraint violation
 *         (e.g. duplicate pubkey_hash).
 */
int nodus_validator_insert(nodus_witness_t *w,
                            const dnac_validator_record_t *v);

/**
 * Fetch a validator row by pubkey. `pubkey` must point to
 * DNAC_PUBKEY_SIZE bytes (2592). On hit, *out is fully populated.
 *
 * @return 0 if found, 1 if not found, -1 on error.
 */
int nodus_validator_get(nodus_witness_t *w,
                         const uint8_t *pubkey,
                         dnac_validator_record_t *out);

/**
 * Update an existing validator row. Identified by pubkey.
 *
 * @return 0 on success, 1 if row did not exist, -1 on error.
 */
int nodus_validator_update(nodus_witness_t *w,
                            const dnac_validator_record_t *v);

/**
 * Return the top-N validators sorted by
 *   (self_stake + external_delegated) DESC, pubkey ASC.
 *
 * Filters:
 *   status == DNAC_VALIDATOR_ACTIVE
 *   active_since_block + DNAC_MIN_TENURE_BLOCKS <= lookback_block
 *
 * Caller supplies `out` with capacity >= n. `*count_out` is set to the
 * actual number returned (may be less than n).
 *
 * @return 0 on success, -1 on error.
 */
int nodus_validator_top_n(nodus_witness_t *w,
                           int n,
                           uint64_t lookback_block,
                           dnac_validator_record_t *out,
                           int *count_out);

/**
 * Return the ACTIVE validator count from the validator_stats key-value
 * row ('active_count'). Used by STAKE verify rule M
 * (|validator_tree| < MAX_VALIDATORS). This is a read; mutation of the
 * counter is Phase 8 territory.
 *
 * @return 0 on success, -1 on error.
 */
int nodus_validator_active_count(nodus_witness_t *w, int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VALIDATOR_H */
