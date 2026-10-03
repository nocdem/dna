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
 *   - insert / get / delete by (delegator, validator) pair. update was
 *     removed by tokenomics-v3 P2 revision 2: it had no production
 *     caller (the version-3 runtime rewrites a delegation row through
 *     its typed effect, nodus_witness_rt_native.c rtn_sys_mutate), only
 *     the rev-1 reward tests used it.
 *   - count-by-delegator (feeds STAKE verify rule G: max 64/delegator)
 *   - list-by-delegator (O(K) bounded scan). list-by-validator was
 *     removed by tokenomics-v3 P2 with its only caller, the O15J epoch
 *     snapshot (nodus_witness_epoch.c, deleted).
 *
 * @file nodus_witness_delegation.h
 */

#ifndef NODUS_WITNESS_DELEGATION_H
#define NODUS_WITNESS_DELEGATION_H

#include "nodus/nodus_types.h"   /* NODUS_MAX_DELEGATORS_PER_VALIDATOR */
#include "witness/nodus_witness.h"
#include "dnac/validator.h"   /* dnac_delegation_record_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NODUS_MAX_DELEGATORS_PER_VALIDATOR — the per-validator delegator cap
 * (2048) — is defined in nodus/include/nodus/nodus_types.h with its full
 * history (included above, directly and through nodus_witness.h). */

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
 * (It used to feed UNSTAKE Rule A — "no delegation may still reference
 * the validator" — which tokenomics-v3 P3-4 REMOVED: a validator with
 * delegators may exit, and its delegations are released to their owners
 * at its graduation boundary, nodus_witness_v2_epoch.c v2ep_graduate.
 * The version-3 runtime counts through its own mediated read,
 * nodus_witness_rt_native.c rtn_sys_delegcnt_fetch.)
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_count_by_validator(nodus_witness_t *w,
                                         const uint8_t *validator_pubkey,
                                         int *count_out);

/**
 * List all delegations owned by the given delegator (up to max_entries).
 *
 * O15O Faz 7 — output is ordered by `validator_pubkey` ASC (byte order;
 * SQLite compares BLOBs with memcmp), and the ORDER BY is applied BEFORE
 * the LIMIT. So when the result is truncated, every node keeps the same
 * subset. Was "undefined order — caller may sort if needed", which was
 * true and was the bug: sorting after a truncation orders the survivors,
 * not the selection.
 *
 * @return 0 on success, -1 on error. *count_out is set on success.
 */
int nodus_delegation_list_by_delegator(nodus_witness_t *w,
                                        const uint8_t *delegator_pubkey,
                                        dnac_delegation_record_t *out,
                                        int max_entries,
                                        int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DELEGATION_H */
