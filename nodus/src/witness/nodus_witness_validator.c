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

/* Bind the 16 columns of the INSERT/UPDATE statement starting at
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
 *   14 last_signed_block
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
    sqlite3_bind_int64(stmt, start + 13, (int64_t)v->last_signed_block);
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
 *   14 last_signed_block
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
    out->last_signed_block =
        (uint64_t)sqlite3_column_int64(stmt, 14);

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
        "  last_validator_update_block, consecutive_missed_epochs,"
        "  last_signed_block"
        ") VALUES (?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?,  ?, ?, ?)",
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
        "       consecutive_missed_epochs, last_signed_block "
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
        "  last_validator_update_block = ?, consecutive_missed_epochs = ?,"
        "  last_signed_block = ? "
        "WHERE pubkey_hash = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: update prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    bind_validator_mutable_fields(stmt, /*start=*/1, v);
    sqlite3_bind_blob(stmt, 15, pubkey_hash, 64, SQLITE_STATIC);

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
        "       consecutive_missed_epochs, last_signed_block "
        "FROM validators "
        "WHERE status = ? "
        "  AND active_since_block + ? <= ? "
        "ORDER BY (self_stake + external_delegated) DESC, pubkey ASC "
        "LIMIT ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: top_n prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_int(  stmt, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int64(stmt, 2, (int64_t)DNAC_MIN_TENURE_BLOCKS);
    sqlite3_bind_int64(stmt, 3, (int64_t)lookback_block);
    sqlite3_bind_int(  stmt, 4, n);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < n) {
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
