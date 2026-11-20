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

    /* Pre-v12 shape: committed_transactions without tx_index, a blocks
     * table without the v14 chain_def_blob column, and a utxo_set table
     * without the v15 unlock_block column. The migration umbrella
     * (migrate_v12) additively upgrades all three. */
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
        ");"
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
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

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
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
    /* v15: unlock_block column on utxo_set (Task 11 stake delegation). */
    if (column_exists(db, "utxo_set", "unlock_block") != 1) {
        FAIL("unlock_block column missing"); sqlite3_close(db); return;
    }

    PASS();
    sqlite3_close(db);
}

static void test_migration_idempotent(void) {
    TEST("v12 migration is idempotent (second run no-op)");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
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

/* Z-18: a real SQLite failure in a migration step is an error RETURN, not an
 * abort(). Each case makes exactly one rung's ALTER fail for real — the
 * connection is put in `PRAGMA query_only = ON`, so a write is refused with
 * SQLITE_READONLY while the no-op statements of the earlier rungs (an ALTER
 * that finds its column present is a duplicate-column no-op; DROP / CREATE
 * INDEX IF [NOT] EXISTS find nothing to do) still succeed.
 *
 * Proves, per rung (v12 tx_index, v13 client_pubkey, v14 chain_def_blob,
 * v15 unlock_block): the migration returns a non-zero sqlite code and the
 * process is alive to say so; after the fault is removed the same migration
 * succeeds and the column is back (idempotent after a failure, no partial
 * state kept). Today each case ends in SIGABRT, which the test runner sees as
 * a crash of the whole test program.
 * Flags/env: none. Leaves behind: nothing (in-memory databases); the
 * "MIGRATION FAILURE: ..." lines on stderr are the pinned log literal.
 * How it can falsely pass: query_only is the fault source, so it proves the
 * return path of those four rungs, not that every possible SQLite error
 * reaches it; the v17 / v18 supply_tracking rungs and the chain-config leg
 * share the same return shape but are not driven (the fixture has no
 * supply_tracking table). */
static int exec_ok(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static void migration_failure_case(const char *label, const char *table,
                                   const char *column) {
    TEST(label);
    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }
    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (table) {
        /* fully migrate, then remove the one column this rung adds */
        char sql[160];
        if (nodus_witness_db_migrate_v12(&w) != 0) { FAIL("first migration"); sqlite3_close(db); return; }
        snprintf(sql, sizeof(sql), "ALTER TABLE %s DROP COLUMN %s", table, column);
        if (exec_ok(db, sql) != 0) { FAIL("drop column"); sqlite3_close(db); return; }
    }
    if (exec_ok(db, "PRAGMA query_only = ON") != 0) { FAIL("query_only"); sqlite3_close(db); return; }

    int rc = nodus_witness_db_migrate_v12(&w);
    if (rc == 0) { FAIL("a failing step returned success"); sqlite3_close(db); return; }

    if (exec_ok(db, "PRAGMA query_only = OFF") != 0) { FAIL("query_only off"); sqlite3_close(db); return; }
    if (nodus_witness_db_migrate_v12(&w) != 0) { FAIL("migration after the fault is gone"); sqlite3_close(db); return; }
    const char *t = table ? table : "committed_transactions";
    const char *c = table ? column : "tx_index";
    if (column_exists(db, t, c) != 1) { FAIL("column not restored"); sqlite3_close(db); return; }
    PASS();
    sqlite3_close(db);
}

static void test_migration_failure_returns(void) {
    migration_failure_case("v12 tx_index ALTER fails: error return, no abort",
                           NULL, NULL);
    migration_failure_case("v13 client_pubkey ALTER fails: error return",
                           "committed_transactions", "client_pubkey");
    migration_failure_case("v14 chain_def_blob ALTER fails: error return",
                           "blocks", "chain_def_blob");
    migration_failure_case("v15 unlock_block ALTER fails: error return",
                           "utxo_set", "unlock_block");
}

int main(void) {
    printf("\nNodus Witness Schema v12 Migration Tests\n");
    printf("==========================================\n\n");

    test_migration_adds_tx_index_and_composite_index();
    test_migration_idempotent();
    test_migration_failure_returns();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
