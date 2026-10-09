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
 * consensus pubkey (validators.pubkey — rotation is slice 6's), owner_fp
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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_VALIDATOR_H */
