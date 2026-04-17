/**
 * Nodus — Witness Reward CRUD implementation (Task 13)
 *
 * CRUD primitives over the `rewards` table (design §3.4 / §3.7).
 * One row per validator, keyed by
 *     validator_hash = SHA3-512(0x04 || validator_pubkey)
 * where 0x04 = NODUS_TREE_TAG_REWARD.
 *
 * All column orders below match the schema in nodus_witness.c
 * WITNESS_DB_SCHEMA. Breaking that alignment corrupts reads.
 */

#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_merkle.h"   /* nodus_merkle_leaf_key */
#include "nodus/nodus_types.h"               /* NODUS_TREE_TAG_REWARD */

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "WITNESS_REWARD"

#define NODUS_REWARD_HASH_LEN    64   /* SHA3-512 */

static void reward_row_hash(const uint8_t *validator_pubkey,
                             uint8_t out_hash[NODUS_REWARD_HASH_LEN]) {
    nodus_merkle_leaf_key(NODUS_TREE_TAG_REWARD,
                          validator_pubkey, DNAC_PUBKEY_SIZE, out_hash);
}

/* ── Upsert ──────────────────────────────────────────────────────── */

int nodus_reward_upsert(nodus_witness_t *w,
                         const dnac_reward_record_t *r) {
    if (!w || !w->db || !r) return -1;

    uint8_t validator_hash[NODUS_REWARD_HASH_LEN];
    reward_row_hash(r->validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "INSERT INTO rewards "
        "(validator_hash, accumulator, validator_unclaimed, "
        " last_update_block, residual_dust) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(validator_hash) DO UPDATE SET "
        "  accumulator = excluded.accumulator, "
        "  validator_unclaimed = excluded.validator_unclaimed, "
        "  last_update_block = excluded.last_update_block, "
        "  residual_dust = excluded.residual_dust";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: upsert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, validator_hash, NODUS_REWARD_HASH_LEN,
                      SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, r->accumulator,
                      (int)sizeof(r->accumulator), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)r->validator_unclaimed);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)r->last_update_block);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)r->residual_dust);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: upsert step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        return -1;
    }

    return 0;
}

/* ── Get by validator pubkey ─────────────────────────────────────── */

int nodus_reward_get(nodus_witness_t *w,
                      const uint8_t *validator_pubkey,
                      dnac_reward_record_t *out) {
    if (!w || !w->db || !validator_pubkey || !out) return -1;

    uint8_t validator_hash[NODUS_REWARD_HASH_LEN];
    reward_row_hash(validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT accumulator, validator_unclaimed, last_update_block, "
        "       residual_dust "
        "FROM rewards WHERE validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: get prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, validator_hash, NODUS_REWARD_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int ret;
    if (rc == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        memcpy(out->validator_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE);

        const void *acc = sqlite3_column_blob(stmt, 0);
        int acc_len = sqlite3_column_bytes(stmt, 0);
        if (acc && acc_len == (int)sizeof(out->accumulator)) {
            memcpy(out->accumulator, acc, sizeof(out->accumulator));
        }
        out->validator_unclaimed = (uint64_t)sqlite3_column_int64(stmt, 1);
        out->last_update_block   = (uint64_t)sqlite3_column_int64(stmt, 2);
        out->residual_dust       = (uint64_t)sqlite3_column_int64(stmt, 3);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    } else {
        fprintf(stderr, "%s: get step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        ret = -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

/* ── Delete ──────────────────────────────────────────────────────── */

int nodus_reward_delete(nodus_witness_t *w,
                         const uint8_t *validator_pubkey) {
    if (!w || !w->db || !validator_pubkey) return -1;

    uint8_t validator_hash[NODUS_REWARD_HASH_LEN];
    reward_row_hash(validator_pubkey, validator_hash);

    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM rewards WHERE validator_hash = ?";

    int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: delete prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, validator_hash, NODUS_REWARD_HASH_LEN,
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: delete step failed rc=%d: %s\n",
                LOG_TAG, rc, sqlite3_errmsg(w->db));
        return -1;
    }

    return (sqlite3_changes(w->db) == 0) ? 1 : 0;
}
