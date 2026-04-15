/**
 * Nodus - RFC 6962 tx_root inclusion proof tests
 *
 * Verifies nodus_witness_merkle_build_tx_proof (Tasks 32-35). The
 * function is symmetric to nodus_witness_merkle_build_proof but
 * operates on the block-scoped tx_root tree, fetching committed TX
 * hashes for a given block_height in tx_index order, applying the
 * RFC 6962 leaf domain tag, and driving the same rfc6962_path
 * recursion used for UTXO inclusion proofs.
 *
 * Coverage:
 *   - positive round-trip: 4 TXs in block 1, prove tx #2, verify OK
 *   - the built root equals nodus_witness_merkle_tx_root() over the
 *     same raw tx_hashes (determinism cross-check)
 *   - tampered sibling: verify rejects
 *   - tampered target tx_hash: verify rejects
 *   - unknown tx_hash: build returns -1
 *   - wrong block_height: build returns -1
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; return; } while(0)

static int passed = 0;
static int failed = 0;

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  sender_fp TEXT,"
        "  fee INTEGER NOT NULL DEFAULT 0,"
        "  tx_index INTEGER NOT NULL DEFAULT 0,"
        "  client_pubkey BLOB,"
        "  client_sig BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

/* Insert a TX with a marker-filled 64-byte tx_hash into the given block
 * at the given tx_index. Mirrors the pattern from test_block_txs_get.c. */
static int insert_tx(nodus_witness_t *w, uint8_t marker, uint64_t height,
                     int tx_index) {
    uint8_t tx_hash[64];
    uint8_t tx_data[32];
    memset(tx_hash, marker, sizeof(tx_hash));
    memset(tx_data, marker ^ 0x55, sizeof(tx_data));

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO committed_transactions "
        "(tx_hash, tx_type, tx_data, tx_len, block_height, timestamp, "
        "fee, tx_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, sizeof(tx_hash), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, 1);
    sqlite3_bind_blob(stmt, 3, tx_data, sizeof(tx_data), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, (int)sizeof(tx_data));
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)height);
    sqlite3_bind_int64(stmt, 6, 1700000000);
    sqlite3_bind_int64(stmt, 7, 0);
    sqlite3_bind_int(stmt, 8, tx_index);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void fill_tx_hash(uint8_t marker, uint8_t out[64]) {
    memset(out, marker, 64);
}

static void test_positive_round_trip(void) {
    TEST("build_tx_proof round-trip (4 TXs, block 1)");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    /* 4 TXs in block 1 at indices 0..3 with distinct markers. */
    const uint8_t markers[4] = { 0xA0, 0xA1, 0xA2, 0xA3 };
    for (int i = 0; i < 4; i++) {
        if (insert_tx(&w, markers[i], 1, i) != 0) {
            sqlite3_close(w.db);
            FAIL("insert");
        }
    }

    /* Compute the expected tx_root via the public aggregate helper. */
    uint8_t raw_hashes[4 * 64];
    for (int i = 0; i < 4; i++) fill_tx_hash(markers[i], raw_hashes + i * 64);
    uint8_t expected_root[64];
    if (nodus_witness_merkle_tx_root(raw_hashes, 4, expected_root) != 0) {
        sqlite3_close(w.db);
        FAIL("tx_root");
    }

    /* Prove TX #2 (marker 0xA2). */
    uint8_t target[64];
    fill_tx_hash(0xA2, target);

    uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
    uint32_t positions = 0;
    int depth = 0;
    uint8_t built_root[64];

    if (nodus_witness_merkle_build_tx_proof(&w, 1, target, siblings,
                                              &positions,
                                              NODUS_MERKLE_MAX_DEPTH,
                                              &depth, built_root) != 0) {
        sqlite3_close(w.db);
        FAIL("build_tx_proof");
    }

    if (memcmp(built_root, expected_root, 64) != 0) {
        sqlite3_close(w.db);
        FAIL("built_root != tx_root");
    }

    if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                            depth, expected_root) != 0) {
        sqlite3_close(w.db);
        FAIL("verify_proof rejected a correct proof");
    }

    sqlite3_close(w.db);
    PASS();
}

static void test_all_indices(void) {
    TEST("build_tx_proof every index (4 TXs)");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    const uint8_t markers[4] = { 0x10, 0x11, 0x12, 0x13 };
    for (int i = 0; i < 4; i++) {
        if (insert_tx(&w, markers[i], 7, i) != 0) {
            sqlite3_close(w.db); FAIL("insert");
        }
    }

    for (int i = 0; i < 4; i++) {
        uint8_t target[64];
        fill_tx_hash(markers[i], target);

        uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
        uint32_t positions = 0;
        int depth = 0;
        uint8_t root[64];
        if (nodus_witness_merkle_build_tx_proof(&w, 7, target, siblings,
                                                  &positions,
                                                  NODUS_MERKLE_MAX_DEPTH,
                                                  &depth, root) != 0) {
            sqlite3_close(w.db); FAIL("build");
        }
        if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                                depth, root) != 0) {
            sqlite3_close(w.db); FAIL("verify");
        }
    }

    sqlite3_close(w.db);
    PASS();
}

static void test_tampered_sibling_rejected(void) {
    TEST("tampered sibling - verify rejects");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    const uint8_t markers[4] = { 0x50, 0x51, 0x52, 0x53 };
    for (int i = 0; i < 4; i++) {
        if (insert_tx(&w, markers[i], 2, i) != 0) {
            sqlite3_close(w.db); FAIL("insert");
        }
    }

    uint8_t target[64];
    fill_tx_hash(0x51, target);

    uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
    uint32_t positions = 0;
    int depth = 0;
    uint8_t root[64];
    if (nodus_witness_merkle_build_tx_proof(&w, 2, target, siblings,
                                              &positions,
                                              NODUS_MERKLE_MAX_DEPTH,
                                              &depth, root) != 0) {
        sqlite3_close(w.db); FAIL("build");
    }

    /* Flip a bit in the first sibling. */
    siblings[0] ^= 0x01;
    if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                            depth, root) == 0) {
        sqlite3_close(w.db); FAIL("accepted tampered sibling");
    }

    sqlite3_close(w.db);
    PASS();
}

static void test_tampered_target_rejected(void) {
    TEST("tampered target - verify rejects");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    const uint8_t markers[4] = { 0x60, 0x61, 0x62, 0x63 };
    for (int i = 0; i < 4; i++) {
        if (insert_tx(&w, markers[i], 3, i) != 0) {
            sqlite3_close(w.db); FAIL("insert");
        }
    }

    uint8_t target[64];
    fill_tx_hash(0x62, target);

    uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
    uint32_t positions = 0;
    int depth = 0;
    uint8_t root[64];
    if (nodus_witness_merkle_build_tx_proof(&w, 3, target, siblings,
                                              &positions,
                                              NODUS_MERKLE_MAX_DEPTH,
                                              &depth, root) != 0) {
        sqlite3_close(w.db); FAIL("build");
    }

    target[0] ^= 0x01;
    if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                            depth, root) == 0) {
        sqlite3_close(w.db); FAIL("accepted tampered target");
    }

    sqlite3_close(w.db);
    PASS();
}

static void test_unknown_tx_not_found(void) {
    TEST("unknown tx_hash - build_tx_proof returns -1");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    if (insert_tx(&w, 0x70, 5, 0) != 0 ||
        insert_tx(&w, 0x71, 5, 1) != 0) {
        sqlite3_close(w.db); FAIL("insert");
    }

    uint8_t target[64];
    fill_tx_hash(0xFF, target); /* never inserted */

    uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
    uint32_t positions = 0;
    int depth = 0;
    int rc = nodus_witness_merkle_build_tx_proof(&w, 5, target, siblings,
                                                   &positions,
                                                   NODUS_MERKLE_MAX_DEPTH,
                                                   &depth, NULL);
    if (rc == 0) { sqlite3_close(w.db); FAIL("expected -1 for unknown"); }

    sqlite3_close(w.db);
    PASS();
}

static void test_wrong_block_not_found(void) {
    TEST("wrong block_height - build_tx_proof returns -1");
    nodus_witness_t w;
    if (setup_witness(&w) != 0) FAIL("setup");

    if (insert_tx(&w, 0x80, 9, 0) != 0) {
        sqlite3_close(w.db); FAIL("insert");
    }

    uint8_t target[64];
    fill_tx_hash(0x80, target);

    uint8_t siblings[NODUS_MERKLE_MAX_DEPTH * 64];
    uint32_t positions = 0;
    int depth = 0;
    int rc = nodus_witness_merkle_build_tx_proof(&w, 99, target, siblings,
                                                   &positions,
                                                   NODUS_MERKLE_MAX_DEPTH,
                                                   &depth, NULL);
    if (rc == 0) { sqlite3_close(w.db); FAIL("expected -1 for wrong block"); }

    sqlite3_close(w.db);
    PASS();
}

int main(void) {
    printf("\nNodus RFC 6962 tx_root Inclusion Proof Tests\n");
    printf("==========================================\n\n");

    test_positive_round_trip();
    test_all_indices();
    test_tampered_sibling_rejected();
    test_tampered_target_rejected();
    test_unknown_tx_not_found();
    test_wrong_block_not_found();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
