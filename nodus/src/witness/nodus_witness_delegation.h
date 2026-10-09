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

/* ══ HF-6 sub-slice 3a — v2 delegation access (INERT) ═══════════════════
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.1, §6.4, §7.3; plan tasks/hf6-slice3-plan.md §1 (decision D1 option
 * (i)): under the HF-6 generation the SAME `delegations` table is keyed by
 *   delegator_hash = delegator_fp = SHA3-512(delegator pubkey), UNTAGGED
 *   validator_hash = validator_id
 * (re-valued in place at the activation edge, sub-slice 3b; the column
 * names are historical). The *_pubkey columns are zero-length blobs for
 * rows a gen-4 writer creates and are NEVER read here. The key values are
 * bound as given — nothing is hashed.
 *
 * Every function checks each step against SQLITE_ROW / SQLITE_DONE; a
 * malformed committed row (a key column not 64 bytes, amount outside
 * [1, INT64_MAX] — UNDELEGATE deletes a drained row, so no committed row
 * holds 0 — or a negative delegated_at_block) is a FAULT (-1), never a
 * zero-filled value.
 *
 * NO PRODUCTION CALLER YET (the HF-6 boundary readers, sub-slice 3d). The
 * v1 functions above are unchanged. */

#define NODUS_V2_DELEGATION_KEY_LEN  64u

typedef struct {
    uint8_t  delegator_fp[NODUS_V2_DELEGATION_KEY_LEN];
    uint8_t  validator_id[NODUS_V2_DELEGATION_KEY_LEN];
    uint64_t amount;
    uint64_t delegated_at_block;
} nodus_v2_delegation_row_t;

/**
 * Fetch one delegation row by (delegator_fp, validator_id).
 * @return 0 found (*out set); 1 not found; -1 fault (SQLite error or a
 *         malformed row).
 */
int nodus_delegation_v2_get(nodus_witness_t *w,
                            const uint8_t delegator_fp[NODUS_V2_DELEGATION_KEY_LEN],
                            const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                            nodus_v2_delegation_row_t *out);

/**
 * Delete the delegation row (delegator_fp, validator_id).
 * @return 0 deleted; 1 not found; -1 SQLite error.
 */
int nodus_delegation_v2_delete(nodus_witness_t *w,
                               const uint8_t delegator_fp[NODUS_V2_DELEGATION_KEY_LEN],
                               const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN]);

/**
 * Count the delegation rows whose validator_hash is `validator_id`.
 * @return 0 (*count_out set); -1 fault (SQLite error, or a count outside
 *         [0, INT_MAX]).
 */
int nodus_delegation_v2_count_by_validator(nodus_witness_t *w,
                                           const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                                           int *count_out);

/**
 * EVERY delegation row whose validator_hash is `validator_id`, ordered by
 * delegator_hash (= delegator_fp) ASC — a TOTAL order: the validator is
 * pinned by the WHERE and (delegator_hash, validator_hash) is the PRIMARY
 * KEY. Never ordered by a *_pubkey column (empty under gen 4).
 *
 * @param cap  capacity of `out`. More matching rows than `cap` is a FAULT
 *             (-1), never a truncation — the graduation release that will
 *             consume this (3d) must see every row on every node.
 * @return 0 (*count_out set, may be 0); -1 fault.
 */
int nodus_delegation_v2_list_by_validator(nodus_witness_t *w,
                                          const uint8_t validator_id[NODUS_V2_DELEGATION_KEY_LEN],
                                          nodus_v2_delegation_row_t *out,
                                          int cap,
                                          int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_DELEGATION_H */
