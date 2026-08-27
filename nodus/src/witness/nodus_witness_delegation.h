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
 * The ONE authority for how many DISTINCT delegators may reference a
 * single validator (O15J Block 2 — the OPEN HIGH in nodus/BUGS.md).
 *
 * WHY THIS EXISTS. nodus_witness_epoch.c serializes at most
 * NODUS_EPOCH_MAX_DELEGS_PER_VAL delegators per committee member into
 * the epoch snapshot blob, but nothing ever bounded the underlying row
 * count. A validator with more delegators than the snapshot can hold
 * had its FULL total_delegated written into the blob while only a
 * SUBSET of its delegators appeared in it; settlement then divides by
 * the full figure and the excluded delegators are never paid — their
 * share falls into the inner-dust burn, permanently. The truncating
 * query (delegation_list_by_hash, "... WHERE %s = ? LIMIT ?") has no
 * ORDER BY, so WHICH delegators were dropped was decided by SQLite's
 * scan order, i.e. by physical row layout, which two witnesses need
 * not share after a resync / VACUUM / table rebuild.
 *
 * The fix is to make the bound REAL at admission rather than paper
 * over it at snapshot time: a DELEGATE that would introduce a NEW
 * delegator to an already-full validator is REJECTED, in both lanes
 *   - legacy: apply_delegate (nodus_witness_bft.c)
 *   - Ledger V2: rtn_delegate_exec (nodus_witness_rt_native.c)
 * so the snapshot can never be ASKED to truncate.
 *
 * WHY NOT DNAC_MAX_DELEGATIONS_PER_DELEGATOR. That constant is also
 * 64, which is exactly why the stale comment this replaces claimed the
 * snapshot bound "matches STAKE rule G cap". It does not: rule G caps
 * how many validators ONE DELEGATOR may back (see
 * nodus_delegation_count_by_delegator below), which is the transposed
 * relation and bounds nothing about a validator's delegator count.
 * Reusing it here would re-encode the very misattribution that let
 * this bug live. Numerically equal today, semantically unrelated, and
 * either may move without the other.
 *
 * COUNTING IS FAIL-CLOSED. A count that cannot be read is never
 * treated as "zero, therefore admit" — see the two enforcement sites.
 */
#define NODUS_MAX_DELEGATORS_PER_VALIDATOR 64

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
