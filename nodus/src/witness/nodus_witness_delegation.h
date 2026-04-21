/**
 * Nodus — Witness Delegation CRUD
 *
 * SQLite CRUD primitives over the `delegations` table (design §3.7).
 * One row per (delegator, validator) pair. Composite primary key
 * (delegator_hash, validator_hash) where each hash is a tag-prefixed
 * SHA3-512 of the corresponding single pubkey:
 *
 *     delegator_hash  = SHA3-512(0x03 || delegator_pubkey)
 *     validator_hash  = SHA3-512(0x03 || validator_pubkey)
 *
 * (The 0x03 tag is NODUS_TREE_TAG_DELEGATION — identical for both
 * hashes because both identify rows within the delegation subtree.
 * The Merkle-tree leaf key for the delegation subtree uses the
 * composite SHA3-512(0x03 || delegator || validator) per design §3.3,
 * but the DB PK is split into two single-pubkey hashes so SQLite can
 * enforce the composite PK as a tuple and so idx_delegator /
 * idx_validator can provide O(log N) prefix scans.)
 *
 * Scope (Task 13):
 *   - insert / get / update / delete by (delegator, validator) pair
 *   - count-by-delegator (feeds STAKE verify rule G: max 64/delegator)
 *   - list-by-delegator / list-by-validator (O(K) bounded scan)
 *
 * @file nodus_witness_delegation.h
 */

#ifndef NODUS_WITNESS_DELEGATION_H
#define NODUS_WITNESS_DELEGATION_H

#include "witness/nodus_witness.h"
#include "dnac/validator.h"   /* dnac_delegation_record_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Insert a delegation row. The PK (delegator_hash, validator_hash) is
 * computed internally from the record's delegator_pubkey and
 * validator_pubkey using the NODUS_TREE_TAG_DELEGATION (0x03) domain tag.
 *
 * @return 0 on success, -2 on PK collision (duplicate pair), -1 on
 *         SQLite error.
 */
int nodus_delegation_insert(nodus_witness_t *w,
                             const dnac_delegation_record_t *d);

/**
 * Fetch one delegation row by (delegator, validator) pair.
 *
 * @return 0 if found, 1 if not found, -1 on error.
 */
int nodus_delegation_get(nodus_witness_t *w,
                          const uint8_t *delegator_pubkey,
                          const uint8_t *validator_pubkey,
                          dnac_delegation_record_t *out);

/**
 * Update a delegation row (amount, delegated_at_block).
 * Delegator and validator keys are immutable — identified by the
 * composite PK derived from the record's pubkey fields.
 *
 * @return 0 on success, 1 if not found, -1 on error.
 */
int nodus_delegation_update(nodus_witness_t *w,
                             const dnac_delegation_record_t *d);

/**
 * Delete a delegation row.
 *
 * @return 0 on success, 1 if not found, -1 on error.
 */
int nodus_delegation_delete(nodus_witness_t *w,
                             const uint8_t *delegator_pubkey,
                             const uint8_t *validator_pubkey);

/**
 * Count the number of delegations owned by the given delegator pubkey.
 * Used by DELEGATE verify rule G (max 64 delegations per delegator).
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_count_by_delegator(nodus_witness_t *w,
                                         const uint8_t *delegator_pubkey,
                                         int *count_out);

/**
 * Count the number of delegations targeting the given validator pubkey.
 * Used by UNSTAKE verify Rule A — UNSTAKE is rejected if any delegation
 * record references the signer as validator.
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_count_by_validator(nodus_witness_t *w,
                                         const uint8_t *validator_pubkey,
                                         int *count_out);

/**
 * List all delegations owned by the given delegator (up to max_entries).
 * Output records are read in undefined order — caller may sort if needed.
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_list_by_delegator(nodus_witness_t *w,
                                        const uint8_t *delegator_pubkey,
                                        dnac_delegation_record_t *out,
                                        int max_entries,
                                        int *count_out);

/**
 * List all delegations targeting the given validator (up to max_entries).
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_list_by_validator(nodus_witness_t *w,
                                        const uint8_t *validator_pubkey,
                                        dnac_delegation_record_t *out,
                                        int max_entries,
                                        int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DELEGATION_H */
