/**
 * Nodus — Task 11 stake/delegation schema migration test
 *
 * Verifies that WITNESS_DB_SCHEMA + the v12 umbrella migration create
 * the four stake-delegation tables (validators, delegations, rewards,
 * validator_stats), seed the validator_stats row, add the
 * unlock_block column to utxo_set, and create the three new indexes
 * (idx_validator_rank, idx_delegator, idx_validator). Also verifies
 * idempotence — running the full schema + migration path twice must
 * succeed without duplicate-seed rows or SQL errors.
 *
 * Uses nodus_witness_create_chain_db() against a real tmp dir so the
 * production witness_db_open_path + WITNESS_DB_SCHEMA + v12 migration
 * path is exercised end-to-end.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define CHECK_NE(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a == _b) { \
        fprintf(stderr, "CHECK_NE fail at %s:%d: %lld == %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define CHECK_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK_TRUE fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

/* Count rows in sqlite_master for a given table/index name. */
static int sqlite_master_count(sqlite3 *db, const char *type,
                               const char *name) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

/* Count columns of a table via PRAGMA table_info. Returns -1 on error. */
static int table_column_count(sqlite3 *db, const char *table) {
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int n = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) n++;
    sqlite3_finalize(stmt);
    return n;
}

/* Check whether table has a column of the given name. */
static int table_has_column(sqlite3 *db, const char *table, const char *col) {
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (name && strcmp((const char *)name, col) == 0) {
            found = 1;
            break;
        }
    }
    sqlite3_finalize(stmt);
    return found;
}

/* Read a single validator_stats row's value; returns -1 if not present. */
static long long validator_stats_value(sqlite3 *db, const char *key) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT value FROM validator_stats WHERE key = ?",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    long long val = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) val = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return val;
}

/* Count rows in validator_stats for a given key. */
static int validator_stats_rowcount(sqlite3 *db, const char *key) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM validator_stats WHERE key = ?",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    int n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

/* rm -rf the test data directory (best-effort). */
static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

int main(void) {
    /* Create a unique tmp dir under /tmp for the test DB. */
    char data_path[] = "/tmp/test_stake_schema_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    /* Use a fixed chain_id for reproducibility. */
    uint8_t chain_id[16];
    memset(chain_id, 0xA1, sizeof(chain_id));

    /* ── First pass: create chain DB end-to-end ─────────────────── */
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK_TRUE(w.db != NULL);

    /* Tables: stake-delegation tables exist. The `rewards` table was
     * dropped in v0.16 stage A.3; epoch_state (Stage B.1) replaces it. */
    CHECK_EQ(sqlite_master_count(w.db, "table", "validators"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "table", "delegations"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "table", "rewards"), 0);
    CHECK_EQ(sqlite_master_count(w.db, "table", "validator_stats"), 1);

    /* Column counts match v0.17 schema (validators gained signed_blocks_this_epoch). */
    CHECK_EQ(table_column_count(w.db, "validators"), 17);
    CHECK_EQ(table_column_count(w.db, "delegations"), 6);
    CHECK_EQ(table_column_count(w.db, "validator_stats"), 2);

    /* validator_stats seeded with ('active_count', 0) */
    CHECK_EQ(validator_stats_rowcount(w.db, "active_count"), 1);
    CHECK_EQ(validator_stats_value(w.db, "active_count"), 0);

    /* utxo_set gained unlock_block column (v15 migration) */
    CHECK_TRUE(table_has_column(w.db, "utxo_set", "unlock_block"));

    /* Indexes: three new ones from the schema */
    CHECK_EQ(sqlite_master_count(w.db, "index", "idx_validator_rank"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "index", "idx_delegator"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "index", "idx_validator"), 1);

    /* ── Idempotence: close, reopen, re-run migrations ──────────── */
    sqlite3_close(w.db);
    w.db = NULL;

    rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK_TRUE(w.db != NULL);

    /* All tables still present — no errors from re-running schema
     * (rewards table intentionally absent after v0.16 stage A.3). */
    CHECK_EQ(sqlite_master_count(w.db, "table", "validators"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "table", "delegations"), 1);
    CHECK_EQ(sqlite_master_count(w.db, "table", "rewards"), 0);
    CHECK_EQ(sqlite_master_count(w.db, "table", "validator_stats"), 1);

    /* Seed row did NOT get duplicated */
    CHECK_EQ(validator_stats_rowcount(w.db, "active_count"), 1);

    /* utxo_set.unlock_block still present after second migration pass */
    CHECK_TRUE(table_has_column(w.db, "utxo_set", "unlock_block"));

    sqlite3_close(w.db);
    w.db = NULL;

    /* Clean up tmp dir (the chain DB + archive subdir both live there). */
    rmrf(data_path);

    printf("test_stake_schema: ALL CHECKS PASSED\n");
    return 0;
}
