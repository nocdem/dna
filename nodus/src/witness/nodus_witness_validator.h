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
/* S3: the third parameter is the TENURE ANCHOR — the epoch start height
 * (or INT64_MAX from the bootstrap path to disable the gate). The old
 * lookback anchor made the gap epochs (E, 3E] unsatisfiable; genesis-
 * seeded rows (active_since_block <= 1) are always tenured. */
int nodus_validator_top_n(nodus_witness_t *w,
                           int n,
                           uint64_t tenure_anchor,
                           dnac_validator_record_t *out,
                           int *count_out);

/**
 * tokenomics-v3 P3-1 ("okuma B") — EVERY bonded, tenured validator row,
 * in pubkey ASC order, unranked and untruncated: the candidate set of
 * the post-bootstrap committee selection
 * (nodus_committee_compute_for_epoch), which ranks it by the FROZEN
 * balances of the previous boundary's copy rather than by the live
 * stake nodus_validator_top_n orders on.
 *
 * Filters — identical to nodus_validator_top_n, both LIVE:
 *   status IN (ACTIVE, ELIGIBLE)
 *   active_since_block + DNAC_MIN_TENURE_BLOCKS <= tenure_anchor
 *     OR active_since_block <= 1 (the genesis-seeded carve-out)
 *
 * @param cap  capacity of `out`. More matching rows than `cap` is a
 *             FAULT (-1), never a truncation — two nodes must rank the
 *             same set.
 * @return 0 on success (*count_out set, may be 0), -1 on error.
 */
int nodus_validator_bonded_tenured(nodus_witness_t *w,
                                   uint64_t tenure_anchor,
                                   dnac_validator_record_t *out,
                                   int cap,
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

/**
 * Paged validator listing for the dnac_validator_list RPC
 * (Phase 14 / Task 63).
 *
 * Unlike nodus_validator_top_n this helper does NOT force status=ACTIVE
 * and does NOT gate on MIN_TENURE — it is a raw view of the validators
 * table with an optional status filter and standard offset/limit
 * pagination.
 *
 *   filter_status < 0  : all statuses.
 *   filter_status >= 0 : rows where status == filter_status.
 *
 * Results are ordered by (self_stake + external_delegated) DESC,
 * pubkey ASC — identical to top_n so rankings remain stable across
 * calls regardless of filter.
 *
 * On success *count_out holds the number of rows written to `out`, and
 * *total_out holds the total row count matching the filter (ignoring
 * offset/limit) so callers can drive pagination UIs.
 *
 * @return 0 on success, -1 on error.
 */
int nodus_validator_list_paged(nodus_witness_t *w,
                                int filter_status,
                                int offset,
                                int limit,
                                dnac_validator_record_t *out,
                                int *count_out,
                                int *total_out);

/* ══ HF-6 sub-slice 3a — the v2 validator row (INERT) ═══════════════════
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.1-§1.2 (validator_id, owner_fp, the consensus-key fields), §6.3 (the
 * row's fields; "no pending key" has ONE encoding — 2592 × 0x00 AND
 * effective epoch 0 — enforced at write), §7 (keys re-valued in place at
 * the activation edge); plan tasks/hf6-slice3-plan.md §1, decision D1
 * option (i).
 *
 * Under the HF-6 generation a validator row is TWO table rows joined on
 * one key:
 *   validators.pubkey_hash          = validator_id (re-keyed at the edge;
 *                                     the column name is historical)
 *   validators.pubkey               = consensus_pubkey
 *   v2_validator_roles.validator_id = validator_id
 *   v2_validator_roles.{owner_fp, pending_consensus_pubkey,
 *                       consensus_key_effective_epoch}
 * A validators row with no roles row (or the reverse) is a half-migrated
 * state: every function below reports it as a FAULT (-1), never as
 * "absent" (1) — a DB failure or an inconsistency is never a value.
 *
 * CALLERS (sub-slice 3d, every one behind a generation-4 test): the
 * distribution's v1-snapshot bridge (get_by_pubkey, nodus_witness_v2_
 * econ.c), the graduation (get + update, nodus_witness_v2_epoch.c), the
 * committee (bonded_tenured, nodus_witness_committee.c) and the v5 root's
 * validator leaves (scan + leaf_encode below, nodus_witness_merkle.c).
 * Every function above is unchanged.
 * `dnac/include/dnac/validator.h` (a client header) is NOT extended — the
 * row type is witness-local. ~5.4 KB per row: callers heap-allocate
 * arrays. */

#define NODUS_V2_VALIDATOR_ID_LEN  64u
#define NODUS_V2_OWNER_FP_LEN      64u

typedef struct {
    /** Today's 13 mutable columns + the pubkey, exactly as the v1 functions
     *  read them; `rec.pubkey` IS the consensus_pubkey. */
    dnac_validator_record_t rec;
    /** validators.pubkey_hash = v2_validator_roles.validator_id. */
    uint8_t  validator_id[NODUS_V2_VALIDATOR_ID_LEN];
    /** SHA3-512 of one key, or a dna_msig_address (§1.2). Immutable: HF-6
     *  has no TRANSFER_OWNER (design K3, goal G10). */
    uint8_t  owner_fp[NODUS_V2_OWNER_FP_LEN];
    /** 2592 × 0x00 iff no rotation is pending. */
    uint8_t  pending_consensus_pubkey[DNAC_PUBKEY_SIZE];
    /** 0 iff no rotation is pending. */
    uint64_t consensus_key_effective_epoch;
} nodus_v2_validator_row_t;

/**
 * Fetch the v2 row whose key (validators.pubkey_hash) is `validator_id`.
 * The row read must be well formed: blob lengths exact, validator_id and
 * owner_fp not all-zero, the one "no pending key" encoding, the effective
 * epoch within INT64.
 *
 * @return 0 found (*out set); 1 neither table holds the key;
 *         -1 fault — SQLite error, a malformed row, or only ONE of the two
 *         tables holds the key.
 */
int nodus_validator_v2_get(nodus_witness_t *w,
                           const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                           nodus_v2_validator_row_t *out);

/**
 * Fetch the v2 row whose consensus pubkey (validators.pubkey) is `pubkey`
 * (DNAC_PUBKEY_SIZE bytes). `pubkey` carries no UNIQUE constraint, so the
 * scan continues past the first hit: a SECOND matching row is a fault.
 *
 * @return 0 found (*out set); 1 no validators row holds the pubkey;
 *         -1 fault — SQLite error, two rows with the pubkey, a malformed
 *         row, or a validators row without its roles row.
 */
int nodus_validator_v2_get_by_pubkey(nodus_witness_t *w,
                                     const uint8_t *pubkey,
                                     nodus_v2_validator_row_t *out);

/**
 * Write a v2 row back: the 13 mutable `validators` columns (the
 * bind_validator_mutable_fields set) and the roles row's
 * pending_consensus_pubkey + consensus_key_effective_epoch.
 *
 * IMMUTABLE and checked, never written: validator_id (the key), the
 * consensus pubkey (validators.pubkey — its ONE writer is
 * nodus_validator_v2_rotate_apply, below), owner_fp
 * (no TRANSFER_OWNER in HF-6). The UPDATEs are keyed by
 * (validator_id, pubkey) and (validator_id, owner_fp): a row whose stored
 * pubkey or owner differs is NOT updated and the call is a fault.
 *
 * Runs INSIDE THE CALLER'S TRANSACTION — called in autocommit mode it
 * refuses (-1) before writing anything. On -1 one table may already have
 * been written; the caller rolls the transaction back (the host does so on
 * every block fault).
 *
 * Refused before any write (-1): an all-zero validator_id or owner_fp, a
 * mixed "pending" encoding (a nonzero key with epoch 0, or a zero key with
 * a nonzero epoch — design §6.3), an effective epoch above INT64_MAX.
 *
 * @return 0 both rows updated; 1 neither table holds validator_id;
 *         -1 fault (above, an SQLite error, only one table holding the
 *         key, or a pubkey / owner mismatch).
 */
int nodus_validator_v2_update(nodus_witness_t *w,
                              const nodus_v2_validator_row_t *row);

/**
 * The HF-6 generation's arm of nodus_validator_bonded_tenured — a NEW
 * function (the existing one stays byte-identical, so generations 1-3
 * read exactly what they read today). SAME WHERE (status IN (ACTIVE,
 * ELIGIBLE), Rule R tenure at `tenure_anchor` or the genesis carve-out
 * active_since_block <= 1), SAME collect order (pubkey ASC — slice 3 keeps
 * the pubkey tiebreak), no LIMIT; each candidate is returned as a full v2
 * row whose validator_id is the row's pubkey_hash value (after the HF-6
 * edge that value IS the validator_id — `dna_validator_id_migrated` would
 * be wrong for rows a v2 STAKE creates later).
 *
 * @param out  heap array of capacity `cap` (~5.4 KB per row).
 * @return 0 (*count_out set, may be 0); -1 fault — SQLite error, a
 *         malformed row, a candidate with no roles row, or more matching
 *         rows than `cap` (never a truncation: two nodes must rank the
 *         same set).
 */
int nodus_validator_v2_bonded_tenured(nodus_witness_t *w,
                                      uint64_t tenure_anchor,
                                      nodus_v2_validator_row_t *out,
                                      int cap,
                                      int *count_out);

/* ══ HF-6 sub-slice 3d — the v2 validator leaf and the full scan ════════
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §6.3 (APPROVED bytes, operator 2026-10-08 "hepsi onaylı"): the
 * validator leaf v2 is 5390 bytes — the tree tag 0x02 (unchanged,
 * NODUS_TREE_TAG_VALIDATOR) followed by the BODY below, all integers
 * big-endian:
 *
 *   off  field                              len
 *      0 validator_id                         64
 *     64 owner_fp                             64
 *    128 consensus_pubkey                   2592
 *   2720 pending_consensus_pubkey           2592
 *   5312 consensus_key_effective_epoch u64     8
 *   5320 self_stake u64                        8
 *   5328 total_delegated u64                   8
 *   5336 external_delegated u64                8
 *   5344 commission_bps u16                    2
 *   5346 pending_commission_bps u16            2
 *   5348 pending_effective_block u64           8
 *   5356 status u8                             1
 *   5357 active_since_block u64                8
 *   5365 unstake_commit_block u64              8
 *   5373 last_validator_update_block u64       8
 *   5381 consecutive_missed_epochs u64         8
 *   5389 (end)
 *
 * unstake_destination_fp / unstake_destination_pubkey are NOT in it
 * (§6.3 "v1'den çıkan"). The body is also the value plan
 * tasks/hf6-slice3-plan.md §2 "3c" names for the gen-4 SYSTEM adapter op
 * (leaf minus tag) — ONE encoder for both. */

#define NODUS_V2_VALIDATOR_LEAF_BODY_LEN  5389u

/**
 * Encode `row` as the §6.3 leaf body. Every u64 field must be within
 * [0, INT64_MAX] — the stored SQLite INTEGER range; a value above it can
 * only come from a negative stored integer cast through uint64_t, i.e.
 * local corruption — and is refused rather than hashed.
 * @return 0 / -1.
 */
int nodus_validator_v2_leaf_encode(const nodus_v2_validator_row_t *row,
                                   uint8_t out[NODUS_V2_VALIDATOR_LEAF_BODY_LEN]);

/** Visitor of nodus_validator_v2_scan: nonzero stops the scan (fault). */
typedef int (*nodus_v2_validator_visit_fn)(const nodus_v2_validator_row_t *row,
                                           void *ud);

/**
 * EVERY v2 validator row, in validators.pubkey_hash (= validator_id) ASC
 * order — the §6.3 leaf order — each decoded by the same strict reader as
 * nodus_validator_v2_get (blob lengths exact, the one "no pending key"
 * encoding, a validators row without its roles row is a FAULT). After
 * the scan the v2_validator_roles row count must equal the number of
 * validators rows visited: a roles row with no validators row (an
 * orphan) is a FAULT too, so neither table can hold state the other —
 * and therefore the root — does not see.
 *
 * Read-only; one statement open at a time (the visitor must not write
 * either table). `row` passed to the visitor is a scratch buffer reused
 * per row (~5.4 KB, heap).
 *
 * @return 0 every row visited (none is fine); -1 fault (SQLite error, a
 *         malformed / half-migrated row, an orphan roles row, an
 *         allocation failure, or a visitor returning nonzero).
 */
int nodus_validator_v2_scan(nodus_witness_t *w,
                            nodus_v2_validator_visit_fn fn, void *ud);

/* ══ HF-6 slice 4 — the consensus-key reservation (design rev 6 §4) ════
 *
 * `v2_consensus_keys (consensus_pk_hash PK, validator_id, role)` — the ONE
 * table with a unique key column that makes "a consensus key appears at
 * most once (active + pending)" a primary-key fact (§4: a composite UNIQUE
 * over two columns would not catch current(A) = pending(B)).
 * consensus_pk_hash = SHA3-512(consensus pubkey), UNTAGGED. Role 1 = an
 * active consensus key; role 2 = a pending key (ROTATE, slice 6). The rows
 * are a pure function of committed state: role 1 for the CURRENT key of
 * every validators row not UNSTAKED, PLUS the PREVIOUS key of a row
 * swapped at boundary U, from U until the sweep at U+E (khan decision A2,
 * 2026-10-12: the old key stays reserved while its snapshot S(F) is still
 * read — so from U to U+E a rotated validator holds TWO role-1 rows; one
 * that graduates at U+E holds only the previous one between its
 * graduation (step 2) and the sweep (step 3d) of that boundary, inside its
 * transaction); role 2 for every non-zero pending_consensus_pubkey. A count of role-1
 * rows equals the count of non-UNSTAKED rows only outside every such
 * window. Writers: the generation-4 edge (nodus_witness_v2_migrate.c),
 * the generation-4 STAKE and ROTATE (SYSTEM adapter op 17,
 * nodus_witness_rt_native.c — STAKE role 1, ROTATE role 2), the swap
 * (nodus_validator_v2_rotate_apply: the new key role 2 → 1) and the
 * generation-4 graduation (nodus_validator_v2_key_release,
 * nodus_witness_v2_epoch.c) and the sweep at U+E
 * (nodus_validator_v2_key_sweep_previous, slice 6d). */

#define NODUS_V2_KEY_HASH_LEN      64u
#define NODUS_V2_KEY_ROLE_ACTIVE   1u
#define NODUS_V2_KEY_ROLE_PENDING  2u

/**
 * The reservation of `key_hash`.
 * @return 0 found (*validator_id_out, *role_out set); 1 absent; -1 fault
 *         (SQLite error, a validator_id not exactly 64 bytes or all-zero,
 *         a role outside {1, 2}).
 */
int nodus_validator_v2_key_get(nodus_witness_t *w,
                               const uint8_t key_hash[NODUS_V2_KEY_HASH_LEN],
                               uint8_t validator_id_out[NODUS_V2_VALIDATOR_ID_LEN],
                               uint8_t *role_out);

/**
 * STRICT insert of one reservation, INSIDE THE CALLER'S TRANSACTION
 * (autocommit → -1, nothing written). Refused (-1) before writing: a role
 * outside {1, 2}, an all-zero key_hash or validator_id. A held key is a
 * PRIMARY KEY conflict → -1 (the caller proved it absent first).
 * @return 0 one row inserted / -1.
 */
int nodus_validator_v2_key_insert(nodus_witness_t *w,
                                  const uint8_t key_hash[NODUS_V2_KEY_HASH_LEN],
                                  const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                                  uint8_t role);

/**
 * Release every reservation of a graduating validator (design §4 last
 * sentence: a released key can be STAKEd again under a new validator_id).
 * INSIDE THE CALLER'S TRANSACTION. Deletes the role-1 row keyed by
 * SHA3-512(`consensus_pubkey`) and naming `validator_id` — EXACTLY one
 * row, else -1 (missing or foreign: a bonded-or-exiting row without its
 * reservation is corruption, never "nothing to release") — then every
 * role-2 row naming `validator_id` (a pending key; any count). A previous
 * key kept at role 1 (swapped at U, graduating at U+E) is NOT deleted: the
 * sweep of the same boundary releases it with the previous voter's
 * attendance row (HF-6 slice 6e; nodus_validator_v2_key_sweep_previous).
 * @param consensus_pubkey DNAC_PUBKEY_SIZE bytes (validators.pubkey).
 * @return 0 / -1.
 */
int nodus_validator_v2_key_release(nodus_witness_t *w,
                                   const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                                   const uint8_t *consensus_pubkey);

/* ══ HF-6 slice 6d — the previous key's reservation (khan A2) ══════════
 *
 * Design rev 6 §3, khan decision A2 (2026-10-12): the key a validator
 * rotated away from at boundary U stays reserved (role 1) until the sweep
 * at U + E (nodus_witness_v2_epoch.c v2ep_rotate_sweep) releases it. The
 * reservation table is the ONLY committed record of that key for a
 * validator that was not seated in S(F) (khan A3 accepts such a rotation),
 * so the sweep finds its candidates here. */

/**
 * Every validator_id holding MORE THAN ONE role-1 reservation — exactly
 * the validators swapped at this boundary or the previous one (a STAKE,
 * the migration and a swap's promotion each give a validator ONE role-1
 * key; only the swap's kept previous key makes a second) — and (HF-6 6e)
 * every validator_id whose validators row is UNSTAKED and still holds a
 * role-1 reservation: a validator swapped at the previous boundary that
 * graduated at this one (key_release keeps the previous key). Read-only;
 * one id per validator (UNION), validator_id ASC (ordered explicitly).
 * @param ids_out [out] heap array (free()) of *n_out ids; NULL when 0.
 * @return 0 / -1 (SQLite error, a malformed id, allocation).
 */
int nodus_validator_v2_key_rotated_ids(nodus_witness_t *w,
                                       uint8_t (**ids_out)[NODUS_V2_VALIDATOR_ID_LEN],
                                       size_t *n_out);

/**
 * Release the PREVIOUS consensus key of a swapped validator. INSIDE THE
 * CALLER'S TRANSACTION (autocommit → -1, nothing written). Reads the
 * role-1 rows naming `validator_id`: with `graduated` == 0 there must be
 * EXACTLY two and EXACTLY one of them keyed by SHA3-512(`consensus_pubkey`)
 * (the row's current key); with `graduated` != 0 (the row is UNSTAKED —
 * it graduated at this boundary and key_release took its current key's
 * row) EXACTLY one, NOT keyed by the current key. The previous key's row
 * is deleted (one row, else -1) and its consensus_pk_hash written to
 * `prev_hash_out` (the caller derives the previous key's voter_id from
 * it: SHA3-512(pk)[0..31] is the same untagged digest's prefix). Any other
 * shape is refused before a write. Role-2 rows (a NEW pending key) are
 * not touched.
 * @param consensus_pubkey DNAC_PUBKEY_SIZE bytes (validators.pubkey).
 * @param graduated        nonzero iff the validators row is UNSTAKED.
 * @return 0 / -1.
 */
int nodus_validator_v2_key_sweep_previous(nodus_witness_t *w,
                                          const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                                          const uint8_t *consensus_pubkey,
                                          int graduated,
                                          uint8_t prev_hash_out[NODUS_V2_KEY_HASH_LEN]);

/* ══ HF-6 slice 6c — the rotation swap writer (design rev 6 §3) ═══════ */

/**
 * The row switch of an accepted rotation (design §3 "Satır değişimi":
 * consensus_pubkey := pending; pending := 0; effective_epoch := 0; plan
 * tasks/hf6-slice6-plan.md §1.4, B3). Three UPDATEs, in this order, each
 * required to change EXACTLY one row:
 *   1. validators SET pubkey = new_pk
 *      WHERE pubkey_hash = validator_id AND pubkey = old_pk;
 *   2. v2_validator_roles SET pending_consensus_pubkey = 2592 × 0x00,
 *      consensus_key_effective_epoch = 0
 *      WHERE validator_id = validator_id AND pending_consensus_pubkey =
 *      new_pk;
 *   3. v2_consensus_keys SET role = 1
 *      WHERE consensus_pk_hash = SHA3-512(new_pk) AND validator_id =
 *      validator_id AND role = 2.
 * The OLD key's role-1 reservation is NOT touched — it is released at U+E
 * by the sweep (khan A2; slice 6d). This is the ONE writer allowed to
 * change validators.pubkey (nodus_validator_v2_update and the SYSTEM
 * adapter's op-13 SET never do).
 *
 * INSIDE THE CALLER'S TRANSACTION — autocommit → -1, nothing written.
 * Refused before any write (-1): an all-zero validator_id or new_pk,
 * new_pk == old_pk. A wrong old key fails step 1, so nothing is written;
 * a failure at step 2 or 3 leaves the earlier steps written and the caller
 * rolls the transaction back (the host does so on every block fault) — the
 * nodus_validator_v2_update discipline.
 *
 * Caller: the boundary swap step (nodus_witness_v2_epoch.c
 * v2ep_rotate_swap, slice 6d), for a row whose entry in the snapshot S(U)
 * taking effect at the boundary carries the row's pending key.
 *
 * @param old_pk, new_pk DNAC_PUBKEY_SIZE bytes.
 * @return 0 / -1.
 */
int nodus_validator_v2_rotate_apply(nodus_witness_t *w,
                                    const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                                    const uint8_t *old_pk,
                                    const uint8_t *new_pk);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VALIDATOR_H */
