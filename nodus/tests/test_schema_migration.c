/**
 * Nodus — Witness DB schema v12 migration test
 *
 * Verifies the Phase 1 / Task 1.1 migration that adds a tx_index column
 * to committed_transactions and replaces the single-column idx_ctx_height
 * with a composite (block_height, tx_index) index. Required by the
 * multi-tx block refactor so per-block TX ordering survives the chain
 * wipe and remains queryable.
 */

#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int setup_pre_v12(sqlite3 **db_out) {
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return -1;

    /* Pre-v12 shape: committed_transactions without tx_index, and a
     * blocks table without the v14 chain_def_blob column. The migration
     * umbrella (migrate_v12) additively upgrades both. */
    const char *schema =
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len  INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0,"
        "  sender_fp TEXT,"
        "  fee INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE INDEX idx_ctx_height ON committed_transactions(block_height);"
        "CREATE TABLE blocks ("
        "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_root BLOB NOT NULL,"
        "  tx_count INTEGER NOT NULL DEFAULT 1,"
        "  timestamp INTEGER NOT NULL,"
        "  proposer_id BLOB,"
        "  prev_hash BLOB NOT NULL DEFAULT x'',"
        "  state_root BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");";

    char *err = NULL;
    if (sqlite3_exec(db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "pre-v12 schema setup failed: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }
    *db_out = db;
    return 0;
}

static int column_exists(sqlite3 *db, const char *table, const char *column) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name='%s'",
             table, column);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) found = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return found > 0 ? 1 : 0;
}

static int index_exists(sqlite3 *db, const char *idx_name) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='%s'",
             idx_name);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) found = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return found > 0 ? 1 : 0;
}

static void test_migration_adds_tx_index_and_composite_index(void) {
    TEST("v12 migration adds tx_index column and composite idx_ctx_block");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    int rc = nodus_witness_db_migrate_v12(&w);
    if (rc != 0) { FAIL("migrate_v12 returned non-zero"); sqlite3_close(db); return; }

    if (column_exists(db, "committed_transactions", "tx_index") != 1) {
        FAIL("tx_index column missing"); sqlite3_close(db); return;
    }
    if (index_exists(db, "idx_ctx_block") != 1) {
        FAIL("idx_ctx_block missing"); sqlite3_close(db); return;
    }
    if (index_exists(db, "idx_ctx_height") != 0) {
        FAIL("idx_ctx_height should have been dropped"); sqlite3_close(db); return;
    }
    /* v14: chain_def_blob column on blocks (anchored merkle proofs). */
    if (column_exists(db, "blocks", "chain_def_blob") != 1) {
        FAIL("chain_def_blob column missing"); sqlite3_close(db); return;
    }

    PASS();
    sqlite3_close(db);
}

static void test_migration_idempotent(void) {
    TEST("v12 migration is idempotent (second run no-op)");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0) { FAIL("first run"); sqlite3_close(db); return; }
    if (nodus_witness_db_migrate_v12(&w) != 0) { FAIL("second run"); sqlite3_close(db); return; }

    if (column_exists(db, "committed_transactions", "tx_index") != 1) {
        FAIL("tx_index missing after re-run"); sqlite3_close(db); return;
    }
    PASS();
    sqlite3_close(db);
}

int main(void) {
    printf("\nNodus Witness Schema v12 Migration Tests\n");
    printf("==========================================\n\n");

    test_migration_adds_tx_index_and_composite_index();
    test_migration_idempotent();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
