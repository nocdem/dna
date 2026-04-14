/**
 * Nodus — RFC 6962 Merkle proof round-trip tests
 *
 * Verifies the Phase 2 / Task 2.6 rewrite of build_proof / verify_proof
 * onto the RFC 6962 split rule with leaf_hash / inner_hash domain tags.
 */

#include "witness/nodus_witness_merkle.h"
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

static int compute_target_digest(uint8_t marker, uint8_t out[64]) {
    uint8_t nullifier[64];
    uint8_t token_id[64];
    uint8_t tx_hash[64];
    memset(nullifier, marker, 64);
    memset(token_id, 0, 64);
    memset(tx_hash, marker ^ 0x55, 64);

    char owner[129];
    for (int i = 0; i < 128; i++) owner[i] = "0123456789abcdef"[(marker + i) & 0xf];
    owner[128] = '\0';

    return nodus_witness_merkle_leaf_hash(nullifier, owner,
                                            (uint64_t)marker * 1000,
                                            token_id, tx_hash, marker, out);
}

static void test_proof_round_trip(uint8_t lo, uint8_t hi, const char *label) {
    char name[80];
    snprintf(name, sizeof(name), "proof round-trip %s", label);
    TEST(name);

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    for (uint8_t m = lo; m <= hi; m++) {
        if (insert_utxo(&w, m) != 0) { FAIL("insert"); sqlite3_close(w.db); return; }
    }

    uint8_t expected_root[64];
    if (nodus_witness_merkle_compute_utxo_root(&w, expected_root) != 0) {
        FAIL("compute_root"); sqlite3_close(w.db); return;
    }

    for (uint8_t m = lo; m <= hi; m++) {
        uint8_t target[64];
        if (compute_target_digest(m, target) != 0) {
            FAIL("compute target"); sqlite3_close(w.db); return;
        }

        uint8_t siblings[32 * 64];
        uint32_t positions = 0;
        int depth = 0;
        uint8_t built_root[64];
        if (nodus_witness_merkle_build_proof(&w, target, siblings, &positions,
                                                32, &depth, built_root) != 0) {
            FAIL("build_proof"); sqlite3_close(w.db); return;
        }
        if (memcmp(built_root, expected_root, 64) != 0) {
            FAIL("built_root vs expected"); sqlite3_close(w.db); return;
        }

        if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                                depth, expected_root) != 0) {
            FAIL("verify_proof"); sqlite3_close(w.db); return;
        }
    }

    PASS();
    sqlite3_close(w.db);
}

static void test_proof_rejects_wrong_leaf(void) {
    TEST("verify_proof rejects a tampered leaf");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    for (uint8_t m = 0x40; m <= 0x47; m++) {
        if (insert_utxo(&w, m) != 0) { FAIL("insert"); sqlite3_close(w.db); return; }
    }

    uint8_t expected_root[64];
    nodus_witness_merkle_compute_utxo_root(&w, expected_root);

    uint8_t target[64];
    compute_target_digest(0x42, target);

    uint8_t siblings[32 * 64];
    uint32_t positions = 0;
    int depth = 0;
    nodus_witness_merkle_build_proof(&w, target, siblings, &positions, 32,
                                       &depth, NULL);

    target[0] ^= 0x01;
    if (nodus_witness_merkle_verify_proof(target, siblings, positions,
                                            depth, expected_root) == 0) {
        FAIL("tampered leaf accepted"); sqlite3_close(w.db); return;
    }

    PASS();
    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus RFC 6962 Merkle Proof Tests\n");
    printf("==========================================\n\n");

    test_proof_round_trip(0x10, 0x10, "(1 leaf)");
    test_proof_round_trip(0x20, 0x21, "(2 leaves)");
    test_proof_round_trip(0x30, 0x32, "(3 leaves, odd)");
    test_proof_round_trip(0x50, 0x59, "(10 leaves)");
    test_proof_rejects_wrong_leaf();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
