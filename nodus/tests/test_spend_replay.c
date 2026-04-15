/**
 * Nodus — Spend Replay DB Helper Tests (Fix #4 B)
 *
 * Exercises nodus_witness_get_committed_coords() against an in-memory
 * SQLite with the real committed_transactions schema. The full wire
 * handler is integration-level (requires live TCP server + BFT quorum)
 * and exercised via dnac/tests/test_spend_retry.c; this unit test
 * narrowly verifies the DB lookup helper used by the handler.
 *
 * Cases:
 *   - Inserted (tx_hash, block_height, tx_index) → lookup returns coords
 *   - Missing tx_hash → lookup returns -1
 *   - Multiple rows, lookup returns the right one
 *   - NULL args → -1 (defensive)
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define T_START(name) do { printf("  %-55s", name); } while(0)
#define T_PASS()      do { printf("PASS\n"); passed++; } while(0)
#define T_FAIL(msg)   do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int run_sql(sqlite3 *db, const char *sql) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE || rc == SQLITE_ROW) ? 0 : -1;
}

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    /* Mirror the real committed_transactions schema from nodus_witness.c.
     * Only the columns read by get_committed_coords are needed for this
     * test — include the full schema anyway so we catch any drift. */
    if (run_sql(w->db,
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len  INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  tx_index INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0,"
        "  sender_fp TEXT,"
        "  fee INTEGER NOT NULL DEFAULT 0"
        ")") != 0) {
        return -1;
    }
    return 0;
}

static void cleanup_witness(nodus_witness_t *w) {
    if (w->db) sqlite3_close(w->db);
    memset(w, 0, sizeof(*w));
}

static int insert_committed(nodus_witness_t *w,
                             const uint8_t tx_hash[64],
                             uint64_t block_height,
                             uint32_t tx_index) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO committed_transactions "
        "(tx_hash, tx_type, tx_data, tx_len, block_height, tx_index) "
        "VALUES (?, 1, x'deadbeef', 4, ?, ?)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)block_height);
    sqlite3_bind_int(stmt, 3, (int)tx_index);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static void make_hash(uint8_t out[64], uint8_t seed) {
    for (int i = 0; i < 64; i++) out[i] = (uint8_t)(seed + i);
}

static void test_found(void) {
    T_START("lookup after insert returns coords");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { T_FAIL("setup"); return; }

    uint8_t h[64];
    make_hash(h, 0x10);

    if (insert_committed(&w, h, 42, 3) != 0) {
        cleanup_witness(&w);
        T_FAIL("insert");
        return;
    }

    uint64_t bh = 0;
    uint32_t ti = 0xFFFFFFFF;
    int rc = nodus_witness_get_committed_coords(&w, h, &bh, &ti);
    cleanup_witness(&w);

    if (rc != 0) { T_FAIL("rc != 0"); return; }
    if (bh != 42) { T_FAIL("block_height mismatch"); return; }
    if (ti != 3) { T_FAIL("tx_index mismatch"); return; }

    T_PASS();
}

static void test_not_found(void) {
    T_START("lookup of missing tx_hash returns -1");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { T_FAIL("setup"); return; }

    uint8_t h[64];
    make_hash(h, 0x55);

    uint64_t bh = 0;
    uint32_t ti = 0;
    int rc = nodus_witness_get_committed_coords(&w, h, &bh, &ti);
    cleanup_witness(&w);

    if (rc != -1) { T_FAIL("expected -1"); return; }
    T_PASS();
}

static void test_multiple_rows(void) {
    T_START("lookup picks the right row out of many");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { T_FAIL("setup"); return; }

    uint8_t h1[64], h2[64], h3[64];
    make_hash(h1, 0x01);
    make_hash(h2, 0x02);
    make_hash(h3, 0x03);

    if (insert_committed(&w, h1, 10, 0) != 0 ||
        insert_committed(&w, h2, 11, 5) != 0 ||
        insert_committed(&w, h3, 12, 9) != 0) {
        cleanup_witness(&w);
        T_FAIL("insert");
        return;
    }

    uint64_t bh = 0;
    uint32_t ti = 0;
    int rc = nodus_witness_get_committed_coords(&w, h2, &bh, &ti);
    cleanup_witness(&w);

    if (rc != 0) { T_FAIL("rc != 0"); return; }
    if (bh != 11) { T_FAIL("block_height mismatch"); return; }
    if (ti != 5) { T_FAIL("tx_index mismatch"); return; }

    T_PASS();
}

static void test_null_args(void) {
    T_START("NULL args return -1");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { T_FAIL("setup"); return; }

    uint64_t bh = 0;
    uint32_t ti = 0;

    if (nodus_witness_get_committed_coords(NULL, (uint8_t[64]){0}, &bh, &ti) != -1) {
        cleanup_witness(&w); T_FAIL("null witness"); return;
    }
    if (nodus_witness_get_committed_coords(&w, NULL, &bh, &ti) != -1) {
        cleanup_witness(&w); T_FAIL("null tx_hash"); return;
    }

    /* NULL out pointers are permitted — helper only writes when non-NULL. */
    uint8_t h[64];
    make_hash(h, 0x77);
    if (insert_committed(&w, h, 7, 1) != 0) {
        cleanup_witness(&w); T_FAIL("insert"); return;
    }
    if (nodus_witness_get_committed_coords(&w, h, NULL, NULL) != 0) {
        cleanup_witness(&w); T_FAIL("NULL outs should still return 0"); return;
    }

    cleanup_witness(&w);
    T_PASS();
}

int main(void) {
    printf("=== Nodus Spend Replay DB Helper Tests ===\n");

    test_found();
    test_not_found();
    test_multiple_rows();
    test_null_args();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
