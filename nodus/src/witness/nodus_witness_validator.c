/**
 * Nodus — Witness Validator CRUD Implementation
 *
 * Follows the nodus_witness_db.c conventions:
 *   - fprintf(stderr, "%s: ...\n", LOG_TAG) for errors
 *   - sqlite3_prepare_v2 → bind → step → finalize flow
 *   - SQLITE_STATIC for caller-owned buffers
 *
 * pubkey_hash is the validator-tree leaf key:
 *   SHA3-512(NODUS_TREE_TAG_VALIDATOR || pubkey)
 * computed via nodus_merkle_leaf_key(). Any change to the tree-tag
 * domain separator is consensus-breaking — this helper is the single
 * source of truth.
 *
 * @file nodus_witness_validator.c
 */

#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_merkle.h"
#include "dnac/dnac.h"
#include "crypto/utils/qgp_log.h"   /* the P3-1 function logs through
                                     * QGP_LOG_*, the project rule; the
                                     * older functions keep fprintf */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

#define LOG_TAG "WITNESS_VALIDATOR"

/* ── Helpers ────────────────────────────────────────────────────────── */

/* Compute the 64-byte validator-tree leaf key for a given pubkey. */
static void compute_pubkey_hash(const uint8_t *pubkey, uint8_t out[64]) {
    nodus_merkle_leaf_key(NODUS_TREE_TAG_VALIDATOR, pubkey,
                          DNAC_PUBKEY_SIZE, out);
}

/* Bind the 13 columns of the INSERT/UPDATE statement starting at
 * parameter index `start` in order:
 *   1  self_stake
 *   2  total_delegated
 *   3  external_delegated
 *   4  commission_bps
 *   5  pending_commission_bps
 *   6  pending_effective_block
 *   7  status
 *   8  active_since_block
 *   9  unstake_commit_block
 *   10 unstake_destination_fp  (TEXT, fingerprint is null-terminated ASCII hex)
 *   11 unstake_destination_pubkey (BLOB, DNAC_PUBKEY_SIZE)
 *   12 last_validator_update_block
 *   13 consecutive_missed_epochs
 *
 * tokenomics-v3 P1 (Q2, clean path): `last_signed_block` and
 * `signed_blocks_this_epoch` DROPPED — attendance lives out-of-root in
 * `v2_attendance` (nodus_witness_v2_epoch.c), never in this row.
 */
static void bind_validator_mutable_fields(sqlite3_stmt *stmt, int start,
                                          const dnac_validator_record_t *v) {
    sqlite3_bind_int64(stmt, start +  0, (int64_t)v->self_stake);
    sqlite3_bind_int64(stmt, start +  1, (int64_t)v->total_delegated);
    sqlite3_bind_int64(stmt, start +  2, (int64_t)v->external_delegated);
    sqlite3_bind_int(  stmt, start +  3, (int)v->commission_bps);
    sqlite3_bind_int(  stmt, start +  4, (int)v->pending_commission_bps);
    sqlite3_bind_int64(stmt, start +  5, (int64_t)v->pending_effective_block);
    sqlite3_bind_int(  stmt, start +  6, (int)v->status);
    sqlite3_bind_int64(stmt, start +  7, (int64_t)v->active_since_block);
    sqlite3_bind_int64(stmt, start +  8, (int64_t)v->unstake_commit_block);
    sqlite3_bind_text( stmt, start +  9,
                       (const char *)v->unstake_destination_fp,
                       -1, SQLITE_STATIC);
    sqlite3_bind_blob( stmt, start + 10,
                       v->unstake_destination_pubkey,
                       DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, start + 11,
                       (int64_t)v->last_validator_update_block);
    sqlite3_bind_int64(stmt, start + 12,
                       (int64_t)v->consecutive_missed_epochs);
}

/* Populate a dnac_validator_record_t from a SELECT row. Column layout
 * assumed (0-indexed):
 *   0  pubkey (BLOB, DNAC_PUBKEY_SIZE)
 *   1  self_stake
 *   2  total_delegated
 *   3  external_delegated
 *   4  commission_bps
 *   5  pending_commission_bps
 *   6  pending_effective_block
 *   7  status
 *   8  active_since_block
 *   9  unstake_commit_block
 *   10 unstake_destination_fp (TEXT)
 *   11 unstake_destination_pubkey (BLOB, DNAC_PUBKEY_SIZE)
 *   12 last_validator_update_block
 *   13 consecutive_missed_epochs
 *
 * Returns 0 on success, -1 on unexpected blob size.
 */
static int row_to_record(sqlite3_stmt *stmt, dnac_validator_record_t *out) {
    memset(out, 0, sizeof(*out));

    const void *pk = sqlite3_column_blob(stmt, 0);
    int pk_len = sqlite3_column_bytes(stmt, 0);
    if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
        fprintf(stderr, "%s: unexpected pubkey size %d\n", LOG_TAG, pk_len);
        return -1;
    }
    memcpy(out->pubkey, pk, DNAC_PUBKEY_SIZE);

    out->self_stake              = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->total_delegated         = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->external_delegated      = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->commission_bps          = (uint16_t)sqlite3_column_int(stmt, 4);
    out->pending_commission_bps  = (uint16_t)sqlite3_column_int(stmt, 5);
    out->pending_effective_block = (uint64_t)sqlite3_column_int64(stmt, 6);
    out->status                  = (uint8_t)sqlite3_column_int(stmt, 7);
    out->active_since_block      = (uint64_t)sqlite3_column_int64(stmt, 8);
    out->unstake_commit_block    = (uint64_t)sqlite3_column_int64(stmt, 9);

    const char *fp = (const char *)sqlite3_column_text(stmt, 10);
    if (fp) {
        /* Copy up to DNAC_FINGERPRINT_SIZE - 1 chars then NUL-terminate. */
        size_t len = strlen(fp);
        if (len >= DNAC_FINGERPRINT_SIZE) len = DNAC_FINGERPRINT_SIZE - 1;
        memcpy(out->unstake_destination_fp, fp, len);
        out->unstake_destination_fp[len] = '\0';
    }

    const void *dpk = sqlite3_column_blob(stmt, 11);
    int dpk_len = sqlite3_column_bytes(stmt, 11);
    if (dpk && dpk_len == DNAC_PUBKEY_SIZE) {
        memcpy(out->unstake_destination_pubkey, dpk, DNAC_PUBKEY_SIZE);
    } else if (dpk_len != 0) {
        fprintf(stderr, "%s: unexpected unstake_destination_pubkey size %d\n",
                LOG_TAG, dpk_len);
        return -1;
    }

    out->last_validator_update_block =
        (uint64_t)sqlite3_column_int64(stmt, 12);
    out->consecutive_missed_epochs =
        (uint64_t)sqlite3_column_int64(stmt, 13);

    return 0;
}

/* ── Insert ─────────────────────────────────────────────────────────── */

int nodus_validator_insert(nodus_witness_t *w,
                            const dnac_validator_record_t *v) {
    if (!w || !w->db || !v) return -1;

    uint8_t pubkey_hash[64];
    compute_pubkey_hash(v->pubkey, pubkey_hash);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO validators ("
        "  pubkey_hash, pubkey,"
        "  self_stake, total_delegated, external_delegated,"
        "  commission_bps, pending_commission_bps, pending_effective_block,"
        "  status, active_since_block, unstake_commit_block,"
        "  unstake_destination_fp, unstake_destination_pubkey,"
        "  last_validator_update_block, consecutive_missed_epochs"
        ") VALUES (?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?,  ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: insert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, pubkey_hash, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, v->pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    bind_validator_mutable_fields(stmt, /*start=*/3, v);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_CONSTRAINT) {
        return -2;
    }
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: insert failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── Get ────────────────────────────────────────────────────────────── */

int nodus_validator_get(nodus_witness_t *w,
                         const uint8_t *pubkey,
                         dnac_validator_record_t *out) {
    if (!w || !w->db || !pubkey || !out) return -1;

    uint8_t pubkey_hash[64];
    compute_pubkey_hash(pubkey, pubkey_hash);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, self_stake, total_delegated, external_delegated,"
        "       commission_bps, pending_commission_bps,"
        "       pending_effective_block, status, active_since_block,"
        "       unstake_commit_block, unstake_destination_fp,"
        "       unstake_destination_pubkey, last_validator_update_block,"
        "       consecutive_missed_epochs "
        "FROM validators WHERE pubkey_hash = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: get prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, pubkey_hash, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 1;  /* Not found */
    }
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "%s: get step failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        sqlite3_finalize(stmt);
        return -1;
    }

    int ret = row_to_record(stmt, out);
    sqlite3_finalize(stmt);
    if (ret != 0) return -1;
    return 0;
}

/* ── Update ─────────────────────────────────────────────────────────── */

int nodus_validator_update(nodus_witness_t *w,
                            const dnac_validator_record_t *v) {
    if (!w || !w->db || !v) return -1;

    uint8_t pubkey_hash[64];
    compute_pubkey_hash(v->pubkey, pubkey_hash);

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET "
        "  self_stake = ?, total_delegated = ?, external_delegated = ?,"
        "  commission_bps = ?, pending_commission_bps = ?,"
        "  pending_effective_block = ?, status = ?,"
        "  active_since_block = ?, unstake_commit_block = ?,"
        "  unstake_destination_fp = ?, unstake_destination_pubkey = ?,"
        "  last_validator_update_block = ?, consecutive_missed_epochs = ? "
        "WHERE pubkey_hash = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: update prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    bind_validator_mutable_fields(stmt, /*start=*/1, v);
    sqlite3_bind_blob(stmt, 14, pubkey_hash, 64, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(w->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: update failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    if (changes == 0) return 1;  /* Row did not exist */
    return 0;
}

/* ── Top-N ──────────────────────────────────────────────────────────── */

int nodus_validator_top_n(nodus_witness_t *w,
                           int n,
                           uint64_t lookback_block,
                           dnac_validator_record_t *out,
                           int *count_out) {
    if (!w || !w->db || !out || !count_out || n <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, self_stake, total_delegated, external_delegated,"
        "       commission_bps, pending_commission_bps,"
        "       pending_effective_block, status, active_since_block,"
        "       unstake_commit_block, unstake_destination_fp,"
        "       unstake_destination_pubkey, last_validator_update_block,"
        "       consecutive_missed_epochs "
        "FROM validators "
        /* S3: the candidate set is every BONDED validator. ACTIVE and
         * ELIGIBLE are both bonded — ELIGIBLE simply means "not in the
         * active set of the CURRENT epoch". Filtering on ACTIVE alone
         * would make the boundary flips absorbing: a validator that lost
         * its seat once could never be re-selected. RETIRING / UNSTAKED /
         * AUTO_RETIRED stay excluded (exit states). */
        "WHERE status IN (?, ?) "
        /* Tenure (Rule R): bonded two full epochs by the TENURE ANCHOR —
         * the epoch start height (see the S3 tenure-anchor comment in
         * nodus_witness_committee.c; the old lookback anchor made the
         * gap epochs (E, 3E] unsatisfiable even for the seed set).
         * Genesis-seeded validators (active_since_block <= 1, written by
         * genesis_seed at block 1) are the constitutional seed set and
         * are always tenured — Rule R gates LATER joiners. */
        "  AND (active_since_block + ? <= ? OR active_since_block <= 1) "
        "ORDER BY (self_stake + external_delegated) DESC, pubkey ASC "
        "LIMIT ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: top_n prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_int(  stmt, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(  stmt, 2, (int)DNAC_VALIDATOR_ELIGIBLE);
    sqlite3_bind_int64(stmt, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS);
    sqlite3_bind_int64(stmt, 4, (int64_t)lookback_block);
    sqlite3_bind_int(  stmt, 5, n);

    int count = 0;
    int rc_step;
    while ((rc_step = sqlite3_step(stmt)) == SQLITE_ROW && count < n) {
        if (row_to_record(stmt, &out[count]) != 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
        count++;
    }
    /* Fail closed on a mid-scan fault: a truncated candidate set is a
     * DIFFERENT committee on this node than on its peers, i.e. a
     * state_root divergence with no Byzantine actor. `count < n` is the
     * legitimate early exit and leaves rc_step == SQLITE_ROW. */
    if (count < n && rc_step != SQLITE_DONE) {
        fprintf(stderr, "%s: top_n scan aborted mid-stream (rc=%d) — "
                "refusing a truncated candidate set\n", LOG_TAG, rc_step);
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Bonded + tenured candidate set (tokenomics-v3 P3-1) ───────────── */

int nodus_validator_bonded_tenured(nodus_witness_t *w,
                                   uint64_t tenure_anchor,
                                   dnac_validator_record_t *out,
                                   int cap,
                                   int *count_out) {
    if (!w || !w->db || !out || !count_out || cap <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, self_stake, total_delegated, external_delegated,"
        "       commission_bps, pending_commission_bps,"
        "       pending_effective_block, status, active_since_block,"
        "       unstake_commit_block, unstake_destination_fp,"
        "       unstake_destination_pubkey, last_validator_update_block,"
        "       consecutive_missed_epochs "
        "FROM validators "
        /* The SAME status and tenure filters as nodus_validator_top_n
         * (S3 bonded set; Rule R tenure anchored at the epoch start, the
         * genesis-seeded carve-out) — the STATUS and TENURE of "okuma B"
         * come from the LIVE row (decision file §3 2026-09-24 "P3
         * soruları" (1)). NO stake ORDER BY and NO LIMIT: the ranking is
         * by FROZEN balances the caller reads from the copy, so the
         * whole set must reach it — a LIMIT on the live stake would cut a
         * candidate whose frozen total ranks it in. pubkey ASC is only
         * the stable collect order. */
        "WHERE status IN (?, ?) "
        "  AND (active_since_block + ? <= ? OR active_since_block <= 1) "
        "ORDER BY pubkey ASC",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "bonded_tenured prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_int(  stmt, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(  stmt, 2, (int)DNAC_VALIDATOR_ELIGIBLE);
    sqlite3_bind_int64(stmt, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS);
    sqlite3_bind_int64(stmt, 4, (int64_t)tenure_anchor);

    int count = 0;
    int rc_step;
    while ((rc_step = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (count >= cap) {
            /* More bonded rows than the caller's capacity
             * (DNAC_MAX_VALIDATORS, which STAKE's Rule M keeps the
             * ACTIVE + ELIGIBLE count within). Truncating would rank a
             * DIFFERENT set than a node with a larger buffer; fail
             * closed — v2ep_rule_n refuses the same condition at the
             * same boundary. */
            QGP_LOG_ERROR(LOG_TAG, "bonded_tenured: more than %d bonded, "
                          "tenured rows — refusing a truncated set", cap);
            sqlite3_finalize(stmt);
            return -1;
        }
        if (row_to_record(stmt, &out[count]) != 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
        count++;
    }
    if (rc_step != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "bonded_tenured scan aborted mid-stream "
                      "(rc=%d) — refusing a truncated candidate set",
                      rc_step);
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Paged list (Task 63) ──────────────────────────────────────────── */

int nodus_validator_list_paged(nodus_witness_t *w,
                                int filter_status,
                                int offset,
                                int limit,
                                dnac_validator_record_t *out,
                                int *count_out,
                                int *total_out) {
    if (!w || !w->db || !out || !count_out || !total_out ||
        limit <= 0 || offset < 0) return -1;
    *count_out = 0;
    *total_out = 0;

    /* Total count with filter (no offset/limit). */
    sqlite3_stmt *stmt = NULL;
    const char *count_sql = (filter_status < 0)
        ? "SELECT COUNT(*) FROM validators"
        : "SELECT COUNT(*) FROM validators WHERE status = ?";
    int rc = sqlite3_prepare_v2(w->db, count_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: list_paged count prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    if (filter_status >= 0) {
        sqlite3_bind_int(stmt, 1, filter_status);
    }
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_out = (int)sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    /* Page the filtered rows. */
    const char *list_sql = (filter_status < 0)
        ? "SELECT pubkey, self_stake, total_delegated, external_delegated,"
          "       commission_bps, pending_commission_bps,"
          "       pending_effective_block, status, active_since_block,"
          "       unstake_commit_block, unstake_destination_fp,"
          "       unstake_destination_pubkey, last_validator_update_block,"
          "       consecutive_missed_epochs "
          "FROM validators "
          "ORDER BY (self_stake + external_delegated) DESC, pubkey ASC "
          "LIMIT ? OFFSET ?"
        : "SELECT pubkey, self_stake, total_delegated, external_delegated,"
          "       commission_bps, pending_commission_bps,"
          "       pending_effective_block, status, active_since_block,"
          "       unstake_commit_block, unstake_destination_fp,"
          "       unstake_destination_pubkey, last_validator_update_block,"
          "       consecutive_missed_epochs "
          "FROM validators WHERE status = ? "
          "ORDER BY (self_stake + external_delegated) DESC, pubkey ASC "
          "LIMIT ? OFFSET ?";

    rc = sqlite3_prepare_v2(w->db, list_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: list_paged prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    int idx = 1;
    if (filter_status >= 0) {
        sqlite3_bind_int(stmt, idx++, filter_status);
    }
    sqlite3_bind_int(stmt, idx++, limit);
    sqlite3_bind_int(stmt, idx++, offset);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < limit) {
        if (row_to_record(stmt, &out[count]) != 0) {
            sqlite3_finalize(stmt);
            return -1;
        }
        count++;
    }
    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Active count ───────────────────────────────────────────────────── */

int nodus_validator_active_count(nodus_witness_t *w, int *count_out) {
    if (!w || !w->db || !count_out) return -1;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT value FROM validator_stats WHERE key = 'active_count'",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: active_count prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count_out = (int)sqlite3_column_int64(stmt, 0);
    } else {
        /* Seed row missing — shouldn't happen post-schema, but fail safe. */
        *count_out = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

/* ══ HF-6 sub-slice 3a — the v2 validator row ═══════════════════════════
 * Contract: nodus_witness_validator.h. Every function here logs through
 * QGP_LOG_* and checks every step's rc against SQLITE_ROW / SQLITE_DONE.
 * The v1 functions above are untouched. */

/* The v2 SELECT: columns 0..13 are EXACTLY row_to_record's layout (so the
 * v1 decoder is reused unchanged), then
 *   14 v.pubkey_hash
 *   15 r.validator_id                    (NULL = no roles row)
 *   16 r.owner_fp
 *   17 r.pending_consensus_pubkey
 *   18 r.consensus_key_effective_epoch
 * LEFT JOIN, deliberately: an INNER JOIN would report a validators row
 * with no roles row as "absent", the silent default this layer refuses. */
#define V2_VAL_SELECT                                                       \
    "SELECT v.pubkey, v.self_stake, v.total_delegated,"                     \
    "       v.external_delegated, v.commission_bps,"                        \
    "       v.pending_commission_bps, v.pending_effective_block, v.status," \
    "       v.active_since_block, v.unstake_commit_block,"                  \
    "       v.unstake_destination_fp, v.unstake_destination_pubkey,"        \
    "       v.last_validator_update_block, v.consecutive_missed_epochs,"    \
    "       v.pubkey_hash, r.validator_id, r.owner_fp,"                     \
    "       r.pending_consensus_pubkey, r.consensus_key_effective_epoch "   \
    "FROM validators v "                                                    \
    "LEFT JOIN v2_validator_roles r ON r.validator_id = v.pubkey_hash "

static int v2_all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* Design §6.3: "no pending key" has ONE encoding — 2592 × 0x00 AND epoch
 * 0. 1 = consistent, 0 = a mixed encoding. */
static int v2_pending_consistent(const uint8_t *pending, uint64_t epoch) {
    int zero_key = v2_all_zero(pending, DNAC_PUBKEY_SIZE);
    return zero_key == (epoch == 0);
}

/* Copy a BLOB column of EXACTLY `len` bytes into `dst`.
 * 0 = copied, -1 = NULL or another length. */
static int v2_blob_exact(sqlite3_stmt *st, int col, uint8_t *dst,
                         size_t len) {
    const void *p = sqlite3_column_blob(st, col);
    int n = sqlite3_column_bytes(st, col);
    if (!p || n < 0 || (size_t)n != len) return -1;
    memcpy(dst, p, len);
    return 0;
}

/* Decode one V2_VAL_SELECT row. 0 = a well-formed v2 row; -1 = malformed,
 * or the validators row has no roles row. */
static int v2_row_from_stmt(sqlite3_stmt *st, nodus_v2_validator_row_t *out) {
    memset(out, 0, sizeof(*out));
    if (row_to_record(st, &out->rec) != 0) return -1;

    uint8_t key[NODUS_V2_VALIDATOR_ID_LEN];
    if (v2_blob_exact(st, 14, key, sizeof(key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2 row: pubkey_hash is not 64 bytes");
        return -1;
    }
    if (sqlite3_column_type(st, 15) == SQLITE_NULL) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2 row: a validators row has no "
                      "v2_validator_roles row (half-migrated) — fault");
        return -1;
    }
    if (v2_blob_exact(st, 15, out->validator_id,
                      sizeof(out->validator_id)) != 0 ||
        v2_blob_exact(st, 16, out->owner_fp, sizeof(out->owner_fp)) != 0 ||
        v2_blob_exact(st, 17, out->pending_consensus_pubkey,
                      sizeof(out->pending_consensus_pubkey)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2 row: a roles column has the wrong "
                      "length");
        return -1;
    }
    sqlite3_int64 ep = sqlite3_column_int64(st, 18);
    if (sqlite3_column_type(st, 18) != SQLITE_INTEGER || ep < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2 row: consensus_key_effective_epoch "
                      "is not a non-negative integer");
        return -1;
    }
    out->consensus_key_effective_epoch = (uint64_t)ep;

    if (memcmp(key, out->validator_id, sizeof(key)) != 0 ||
        v2_all_zero(out->validator_id, sizeof(out->validator_id)) ||
        v2_all_zero(out->owner_fp, sizeof(out->owner_fp)) ||
        !v2_pending_consistent(out->pending_consensus_pubkey,
                               out->consensus_key_effective_epoch)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2 row: malformed (key mismatch, an "
                      "all-zero validator_id / owner_fp, or a mixed pending-"
                      "key encoding)");
        return -1;
    }
    return 0;
}

/* Is `validator_id` held by v2_validator_roles?  1 yes, 0 no, -1 fault. */
static int v2_roles_has(nodus_witness_t *w, const uint8_t *validator_id) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_validator_roles WHERE validator_id = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 roles probe prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, validator_id, NODUS_V2_VALIDATOR_ID_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    QGP_LOG_ERROR(LOG_TAG, "v2 roles probe step failed (rc=%d)", rc);
    return -1;
}

/* Is `validator_id` held by validators.pubkey_hash?  1 / 0 / -1. */
static int v2_validators_has(nodus_witness_t *w, const uint8_t *validator_id) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM validators WHERE pubkey_hash = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2 validators probe prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, validator_id, NODUS_V2_VALIDATOR_ID_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    if (rc == SQLITE_DONE) return 0;
    QGP_LOG_ERROR(LOG_TAG, "v2 validators probe step failed (rc=%d)", rc);
    return -1;
}

int nodus_validator_v2_get(nodus_witness_t *w,
                           const uint8_t validator_id[NODUS_V2_VALIDATOR_ID_LEN],
                           nodus_v2_validator_row_t *out) {
    if (!w || !w->db || !validator_id || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, V2_VAL_SELECT "WHERE v.pubkey_hash = ?",
                           -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_get prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, validator_id, NODUS_V2_VALIDATOR_ID_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        /* No validators row. A roles row alone is an orphan — fault. */
        int r = v2_roles_has(w, validator_id);
        if (r < 0) return -1;
        if (r == 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "v2_get: a v2_validator_roles row "
                          "has no validators row (half-migrated) — fault");
            return -1;
        }
        return 1;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "v2_get step failed (rc=%d): %s", rc,
                      sqlite3_errmsg(w->db));
        sqlite3_finalize(st);
        return -1;
    }
    int ret = v2_row_from_stmt(st, out);
    sqlite3_finalize(st);   /* pubkey_hash is the PRIMARY KEY: one row */
    return ret == 0 ? 0 : -1;
}

int nodus_validator_v2_get_by_pubkey(nodus_witness_t *w,
                                     const uint8_t *pubkey,
                                     nodus_v2_validator_row_t *out) {
    if (!w || !w->db || !pubkey || !out) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, V2_VAL_SELECT "WHERE v.pubkey = ?",
                           -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_get_by_pubkey prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, pubkey, DNAC_PUBKEY_SIZE,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st);
        return 1;
    }
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "v2_get_by_pubkey step failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        sqlite3_finalize(st);
        return -1;
    }
    if (v2_row_from_stmt(st, out) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    /* `pubkey` is not UNIQUE: a second row with it is a fault, never "the
     * first one wins" (which one is first is not a committed fact). */
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return 0;
    if (rc == SQLITE_ROW)
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_get_by_pubkey: two validators rows "
                      "hold the same consensus pubkey — fault");
    else
        QGP_LOG_ERROR(LOG_TAG, "v2_get_by_pubkey second step failed "
                      "(rc=%d)", rc);
    memset(out, 0, sizeof(*out));
    return -1;
}

int nodus_validator_v2_update(nodus_witness_t *w,
                              const nodus_v2_validator_row_t *row) {
    if (!w || !w->db || !row) return -1;

    /* The caller's transaction, or nothing. In autocommit mode the two
     * UPDATEs would commit separately and a fault between them would
     * leave the two tables disagreeing on disk. */
    if (sqlite3_get_autocommit(w->db)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_update called outside a "
                      "transaction — refused, nothing written");
        return -1;
    }
    if (v2_all_zero(row->validator_id, sizeof(row->validator_id)) ||
        v2_all_zero(row->owner_fp, sizeof(row->owner_fp)) ||
        row->consensus_key_effective_epoch > (uint64_t)INT64_MAX ||
        !v2_pending_consistent(row->pending_consensus_pubkey,
                               row->consensus_key_effective_epoch)) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_update: malformed row (all-zero "
                      "validator_id / owner_fp, a mixed pending-key "
                      "encoding, or an epoch above INT64_MAX) — refused, "
                      "nothing written");
        return -1;
    }

    /* 1. validators — the 13 mutable columns; keyed by (validator_id,
     *    pubkey) so a changed consensus pubkey is never silently dropped. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE validators SET "
            "  self_stake = ?, total_delegated = ?, external_delegated = ?,"
            "  commission_bps = ?, pending_commission_bps = ?,"
            "  pending_effective_block = ?, status = ?,"
            "  active_since_block = ?, unstake_commit_block = ?,"
            "  unstake_destination_fp = ?, unstake_destination_pubkey = ?,"
            "  last_validator_update_block = ?, consecutive_missed_epochs = ? "
            "WHERE pubkey_hash = ? AND pubkey = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_update validators prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    bind_validator_mutable_fields(st, /*start=*/1, &row->rec);
    if (sqlite3_bind_blob(st, 14, row->validator_id,
                          NODUS_V2_VALIDATOR_ID_LEN,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(st, 15, row->rec.pubkey, DNAC_PUBKEY_SIZE,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    int rc = sqlite3_step(st);
    int ch_val = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2_update validators step failed (rc=%d): "
                      "%s", rc, sqlite3_errmsg(w->db));
        return -1;
    }

    /* 2. v2_validator_roles — the two consensus-key fields; keyed by
     *    (validator_id, owner_fp): the owner is never rewritten. */
    st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_validator_roles SET "
            "  pending_consensus_pubkey = ?, consensus_key_effective_epoch = ? "
            "WHERE validator_id = ? AND owner_fp = ?",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_update roles prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_blob(st, 1, row->pending_consensus_pubkey,
                          DNAC_PUBKEY_SIZE, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_int64(st, 2, (sqlite3_int64)
                           row->consensus_key_effective_epoch) != SQLITE_OK ||
        sqlite3_bind_blob(st, 3, row->validator_id,
                          NODUS_V2_VALIDATOR_ID_LEN,
                          SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_blob(st, 4, row->owner_fp, NODUS_V2_OWNER_FP_LEN,
                          SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }
    rc = sqlite3_step(st);
    int ch_role = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2_update roles step failed (rc=%d): %s",
                      rc, sqlite3_errmsg(w->db));
        return -1;
    }

    if (ch_val == 1 && ch_role == 1) return 0;
    if (ch_val == 0 && ch_role == 0) {
        /* Nothing matched. Absent only if NEITHER table holds the key;
         * otherwise the stored pubkey or owner differs from the row's. */
        int hv = v2_validators_has(w, row->validator_id);
        int hr = v2_roles_has(w, row->validator_id);
        if (hv < 0 || hr < 0) return -1;
        if (hv == 0 && hr == 0) return 1;
    }
    QGP_LOG_ERROR(LOG_TAG, "v2_update: validators changed %d row(s), roles "
                  "changed %d — a half-migrated row, or the stored consensus "
                  "pubkey / owner_fp differs from the row's; fault (the "
                  "caller rolls back)", ch_val, ch_role);
    return -1;
}

int nodus_validator_v2_bonded_tenured(nodus_witness_t *w,
                                      uint64_t tenure_anchor,
                                      nodus_v2_validator_row_t *out,
                                      int cap,
                                      int *count_out) {
    if (!w || !w->db || !out || !count_out || cap <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            V2_VAL_SELECT
            /* The SAME filters and collect order as
             * nodus_validator_bonded_tenured (above). */
            "WHERE v.status IN (?, ?) "
            "  AND (v.active_since_block + ? <= ? "
            "       OR v.active_since_block <= 1) "
            "ORDER BY v.pubkey ASC",
            -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "v2_bonded_tenured prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (sqlite3_bind_int(  st, 1, (int)DNAC_VALIDATOR_ACTIVE) != SQLITE_OK ||
        sqlite3_bind_int(  st, 2, (int)DNAC_VALIDATOR_ELIGIBLE) != SQLITE_OK ||
        sqlite3_bind_int64(st, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS)
            != SQLITE_OK ||
        sqlite3_bind_int64(st, 4, (int64_t)tenure_anchor) != SQLITE_OK) {
        sqlite3_finalize(st);
        return -1;
    }

    int count = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (count >= cap) {
            QGP_LOG_ERROR(LOG_TAG, "v2_bonded_tenured: more than %d bonded, "
                          "tenured rows — refusing a truncated set", cap);
            sqlite3_finalize(st);
            return -1;
        }
        if (v2_row_from_stmt(st, &out[count]) != 0) {
            sqlite3_finalize(st);
            return -1;
        }
        count++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "v2_bonded_tenured scan aborted mid-stream "
                      "(rc=%d) — refusing a truncated candidate set", rc);
        return -1;
    }
    *count_out = count;
    return 0;
}
