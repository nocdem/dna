/**
 * Nodus — Witness DB Savepoint Wrapper Tests
 *
 * Verifies the nodus_witness_db_savepoint and
 * nodus_witness_db_rollback_to_savepoint helpers introduced in
 * Phase 0 / Task 0.15. These wrappers are required by Phase 6
 * commit_batch attribution replay (Task 6.2) — when a multi-tx batch
 * fails finalize_block, the attribution loop replays each TX in
 * isolation under a savepoint to identify which one violated supply.
 *
 * Test scenarios:
 *   1. savepoint + rollback_to_savepoint undoes only the inner inserts
 *   2. outer rollback after savepoint kills everything
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

#define NULLIFIER_LEN 64

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    int rc = sqlite3_open(":memory:", &w->db);
    if (rc != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE IF NOT EXISTS nullifiers ("
        "  nullifier BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  added_at INTEGER NOT NULL DEFAULT 0"
        ");";
    char *err = NULL;
    rc = sqlite3_exec(w->db, schema, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "schema error: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void cleanup_witness(nodus_witness_t *w) {
    if (w->db) sqlite3_close(w->db);
    memset(w, 0, sizeof(*w));
}

static int insert_marker_nullifier(nodus_witness_t *w, uint8_t marker) {
    uint8_t nf[NULLIFIER_LEN];
    uint8_t tx[NULLIFIER_LEN];
    memset(nf, marker, NULLIFIER_LEN);
    memset(tx, marker ^ 0xFF, NULLIFIER_LEN);
    return nodus_witness_nullifier_add(w, nf, tx);
}

static bool marker_present(nodus_witness_t *w, uint8_t marker) {
    uint8_t nf[NULLIFIER_LEN];
    memset(nf, marker, NULLIFIER_LEN);
    return nodus_witness_nullifier_exists(w, nf);
}

static void test_savepoint_rollback_undoes_inner_only(void) {
    TEST("savepoint rollback undoes only inner inserts");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    if (nodus_witness_db_begin(&w) != 0) { FAIL("begin"); cleanup_witness(&w); return; }

    if (insert_marker_nullifier(&w, 0xAA) != 0) {
        FAIL("insert X"); cleanup_witness(&w); return;
    }

    if (nodus_witness_db_savepoint(&w, "sp1") != 0) {
        FAIL("savepoint sp1"); cleanup_witness(&w); return;
    }

    if (insert_marker_nullifier(&w, 0xBB) != 0) {
        FAIL("insert Y"); cleanup_witness(&w); return;
    }

    if (nodus_witness_db_rollback_to_savepoint(&w, "sp1") != 0) {
        FAIL("rollback to sp1"); cleanup_witness(&w); return;
    }

    if (!marker_present(&w, 0xAA)) { FAIL("X missing after sp rollback"); cleanup_witness(&w); return; }
    if (marker_present(&w, 0xBB))  { FAIL("Y still present after sp rollback"); cleanup_witness(&w); return; }

    if (nodus_witness_db_commit(&w) != 0) { FAIL("commit"); cleanup_witness(&w); return; }

    if (!marker_present(&w, 0xAA)) { FAIL("X gone after commit"); cleanup_witness(&w); return; }

    PASS();
    cleanup_witness(&w);
}

static void test_outer_rollback_kills_everything(void) {
    TEST("outer rollback kills inserts before and after savepoint");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    if (nodus_witness_db_begin(&w) != 0) { FAIL("begin"); cleanup_witness(&w); return; }
    if (insert_marker_nullifier(&w, 0xAA) != 0) { FAIL("insert X"); cleanup_witness(&w); return; }
    if (nodus_witness_db_savepoint(&w, "sp1") != 0) { FAIL("savepoint"); cleanup_witness(&w); return; }
    if (insert_marker_nullifier(&w, 0xBB) != 0) { FAIL("insert Y"); cleanup_witness(&w); return; }

    if (nodus_witness_db_rollback(&w) != 0) { FAIL("outer rollback"); cleanup_witness(&w); return; }

    if (marker_present(&w, 0xAA)) { FAIL("X survived outer rollback"); cleanup_witness(&w); return; }
    if (marker_present(&w, 0xBB)) { FAIL("Y survived outer rollback"); cleanup_witness(&w); return; }

    PASS();
    cleanup_witness(&w);
}

int main(void) {
    printf("\nNodus Witness DB Savepoint Wrapper Tests\n");
    printf("==========================================\n\n");

    test_savepoint_rollback_undoes_inner_only();
    test_outer_rollback_kills_everything();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
