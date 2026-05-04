/**
 * Nodus — Witness DB schema v16 PBFT-state migration test (PR 3 Yol B)
 *
 * Verifies the schema migration that introduces a singleton pbft_state
 * table holding two new fields:
 *   - current_view       (BFT view number, persisted across restart)
 *   - last_prepared_blob (serialized PBFT-prepared certificate)
 *
 * H-5 mitigation against A15: a HAVE_CHAIN witness restart that loses
 * (current_view, last_prepared) would re-enter consensus at view 0 and
 * find its votes rejected by peers that already advanced past it,
 * stalling the cluster.
 *
 * RED state: nodus_witness_db_migrate_v12 does NOT yet dispatch into a
 * migrate_v16 sub-step, so the pbft_state table does not exist after
 * migration. The asserts below FAIL until B2 lands the GREEN
 * implementation (CREATE TABLE + save/load helpers + bft.c hooks).
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

/* Minimal pre-v12 schema. The PBFT-state migration is independent of
 * the existing v13/v14/v15 ALTERs, but migrate_v12 is the umbrella that
 * dispatches all sub-migrations including the new v16. */
static int setup_pre_v12(sqlite3 **db_out) {
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return -1;

    static const char *schema =
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
        fprintf(stderr, "pre-v12 schema setup failed: %s\n",
                err ? err : "(null)");
        if (err) sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }
    *db_out = db;
    return 0;
}

static int table_exists(sqlite3 *db, const char *table) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM sqlite_master "
             "WHERE type='table' AND name='%s'", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        found = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return found > 0 ? 1 : 0;
}

static int column_exists(sqlite3 *db, const char *table, const char *column) {
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM pragma_table_info('%s') WHERE name='%s'",
             table, column);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        found = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return found > 0 ? 1 : 0;
}

static void test_pbft_state_table_created(void) {
    TEST("v16 migration creates singleton pbft_state table");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("migrate_v12 returned non-zero");
        sqlite3_close(db);
        return;
    }

    if (table_exists(db, "pbft_state") != 1) {
        FAIL("pbft_state table missing — H-5 PBFT state cannot persist");
        sqlite3_close(db);
        return;
    }
    if (column_exists(db, "pbft_state", "current_view") != 1) {
        FAIL("current_view column missing on pbft_state");
        sqlite3_close(db);
        return;
    }
    if (column_exists(db, "pbft_state", "last_prepared_blob") != 1) {
        FAIL("last_prepared_blob column missing on pbft_state");
        sqlite3_close(db);
        return;
    }
    PASS();
    sqlite3_close(db);
}

static void test_pbft_state_singleton_constraint(void) {
    TEST("v16 pbft_state enforces singleton (only id=1 allowed)");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("migrate_v12 returned non-zero");
        sqlite3_close(db);
        return;
    }

    /* Precondition: the table must exist before this constraint test
     * is meaningful. Without this gate the test would report a false
     * PASS in RED state because INSERT into a missing table also
     * returns non-OK — indistinguishable from the CHECK violation we
     * want to verify. */
    if (table_exists(db, "pbft_state") != 1) {
        FAIL("pbft_state table missing — constraint test inconclusive");
        sqlite3_close(db);
        return;
    }

    /* Attempt to insert a second row with id != 1 — must fail. The
     * pbft_state table follows the genesis_state pattern: PRIMARY KEY
     * id INTEGER CHECK(id = 1). */
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "INSERT INTO pbft_state (id, current_view, last_prepared_blob) "
        "VALUES (2, 0, NULL)",
        NULL, NULL, &err);
    if (rc == SQLITE_OK) {
        FAIL("inserting id=2 should violate CHECK(id=1)");
        if (err) sqlite3_free(err);
        sqlite3_close(db);
        return;
    }
    if (err) sqlite3_free(err);
    PASS();
    sqlite3_close(db);
}

static void test_pbft_state_migration_idempotent(void) {
    TEST("v16 pbft_state migration is idempotent (second run no-op)");

    sqlite3 *db = NULL;
    if (setup_pre_v12(&db) != 0) { FAIL("setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("first run");
        sqlite3_close(db);
        return;
    }
    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("second run");
        sqlite3_close(db);
        return;
    }
    if (table_exists(db, "pbft_state") != 1) {
        FAIL("pbft_state missing after re-run");
        sqlite3_close(db);
        return;
    }
    PASS();
    sqlite3_close(db);
}

int main(void) {
    printf("\nNodus Witness Schema v16 PBFT-State Migration Tests\n");
    printf("====================================================\n\n");

    test_pbft_state_table_created();
    test_pbft_state_singleton_constraint();
    test_pbft_state_migration_idempotent();

    printf("\n====================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
