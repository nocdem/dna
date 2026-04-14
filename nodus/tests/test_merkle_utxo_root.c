/**
 * Nodus — UTXO state_root determinism tests
 *
 * Verifies the Phase 2 / Task 2.5 rewrite of compute_utxo_root that
 * applies the RFC 6962 leaf domain tag and reduces through the new
 * merkle_root_rfc6962 §2.1 recursion.
 */

#include "witness/nodus_witness_merkle.h"
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

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL DEFAULT x'"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "',"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema error: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

static int insert_utxo(nodus_witness_t *w, uint8_t marker) {
    uint8_t nullifier[64];
    uint8_t token_id[64];
    uint8_t tx_hash[64];
    memset(nullifier, marker, 64);
    memset(token_id, 0, 64);
    memset(tx_hash, marker ^ 0x55, 64);

    char owner[129];
    for (int i = 0; i < 128; i++) owner[i] = "0123456789abcdef"[(marker + i) & 0xf];
    owner[128] = '\0';

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, tx_hash, output_index) "
        "VALUES (?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)((uint64_t)marker * 1000));
    sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, marker);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_root_independent_of_insertion_order(void) {
    TEST("UTXO root independent of insertion order");

    nodus_witness_t w1, w2;
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    for (uint8_t m = 0x10; m <= 0x18; m++) {
        if (insert_utxo(&w1, m) != 0) { FAIL("insert w1"); goto done; }
    }
    for (int m = 0x18; m >= 0x10; m--) {
        if (insert_utxo(&w2, (uint8_t)m) != 0) { FAIL("insert w2"); goto done; }
    }

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) != 0) { FAIL("roots differ"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

static void test_root_changes_on_amount_flip(void) {
    TEST("UTXO root changes when an amount flips by 1");

    nodus_witness_t w1, w2;
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    for (uint8_t m = 0x20; m <= 0x25; m++) {
        if (insert_utxo(&w1, m) != 0) { FAIL("insert w1"); goto done; }
        if (insert_utxo(&w2, m) != 0) { FAIL("insert w2"); goto done; }
    }

    sqlite3_exec(w2.db,
        "UPDATE utxo_set SET amount = amount + 1 WHERE rowid = 3",
        NULL, NULL, NULL);

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) == 0) { FAIL("amount flip not detected"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

static void test_empty_utxo_set_root_deterministic(void) {
    TEST("empty UTXO set has deterministic non-zero root");

    nodus_witness_t w1, w2;
    if (setup_witness(&w1) != 0) { FAIL("setup w1"); return; }
    if (setup_witness(&w2) != 0) { FAIL("setup w2"); sqlite3_close(w1.db); return; }

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_utxo_root(&w1, r1) != 0) { FAIL("r1"); goto done; }
    if (nodus_witness_merkle_compute_utxo_root(&w2, r2) != 0) { FAIL("r2"); goto done; }

    if (memcmp(r1, r2, 64) != 0) { FAIL("empty roots differ"); goto done; }

    uint8_t zero[64] = {0};
    if (memcmp(r1, zero, 64) == 0) { FAIL("empty root is all zeros"); goto done; }

    PASS();
done:
    sqlite3_close(w1.db);
    sqlite3_close(w2.db);
}

int main(void) {
    printf("\nNodus UTXO state_root Tests\n");
    printf("==========================================\n\n");

    test_empty_utxo_set_root_deterministic();
    test_root_independent_of_insertion_order();
    test_root_changes_on_amount_flip();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
