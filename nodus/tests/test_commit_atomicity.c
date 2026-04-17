/**
 * Nodus - Phase 9 / Task 47 block-commit atomicity test.
 *
 * Verifies design F-STATE-02: the block commit path wraps steps 1-6
 * (apply_tx_to_state * N, apply_epoch_boundary, state_root recompute,
 * block_add, reset block_fee_pool) in ONE SQLite transaction. On any
 * error the transaction ROLLBACK restores the pre-block state with
 * zero partial commits.
 *
 * Scenarios covered:
 *   (1) Happy path - commit_batch(1 TX) commits atomically.
 *   (2) finalize_block outside wrapper - F-STATE-02 guard rejects.
 *   (3) Mid-batch abort - NULL second entry rolls back whole block.
 *   (4) Manual begin/rollback - pre-block state survives.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_bft_internal.h"
#include "nodus/nodus_types.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE nullifiers ("
        "  nullifier BLOB PRIMARY KEY,"
        "  tx_hash BLOB NOT NULL,"
        "  added_at INTEGER NOT NULL DEFAULT 0"
        ");"
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
        "  created_at INTEGER NOT NULL DEFAULT 0,"
        "  unlock_block INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE blocks ("
        "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_root BLOB NOT NULL,"
        "  tx_count INTEGER NOT NULL DEFAULT 1,"
        "  timestamp INTEGER NOT NULL,"
        "  proposer_id BLOB,"
        "  prev_hash BLOB NOT NULL DEFAULT x'',"
        "  state_root BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL DEFAULT 0,"
        "  chain_def_blob BLOB"
        ");"
        "CREATE TABLE supply_state ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL DEFAULT 0,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  genesis_tx_hash BLOB"
        ");"
        "CREATE TABLE tokens ("
        "  token_id BLOB PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  symbol TEXT NOT NULL,"
        "  decimals INTEGER NOT NULL DEFAULT 8,"
        "  supply INTEGER NOT NULL,"
        "  creator_fp TEXT NOT NULL,"
        "  flags INTEGER NOT NULL DEFAULT 0,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0"
        ");";

    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

static int count_rows(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    int n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static nodus_witness_mempool_entry_t *make_entry(uint8_t marker) {
    nodus_witness_mempool_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    memset(e->tx_hash, marker, 64);
    e->tx_type = NODUS_W_TX_SPEND;
    e->nullifier_count = 0;
    e->tx_data = NULL;
    e->tx_len = 0;
    return e;
}

static void test_happy_path(void) {
    printf("  happy path: commit_batch(1 TX) writes block + clears flag\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    CHECK_EQ(w.in_block_transaction, false);

    nodus_witness_mempool_entry_t *e = make_entry(0xA1);
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0x42, 32);

    int rc = nodus_witness_commit_batch(&w, entries, 1, 1700000000, proposer);
    CHECK_EQ(rc, 0);

    CHECK_EQ(w.in_block_transaction, false);

    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM blocks"), 1);

    free(e);
    sqlite3_close(w.db);
}

static void test_finalize_without_wrapper(void) {
    printf("  guard: finalize_block called outside transaction is rejected\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    uint8_t tx_hash[64];
    memset(tx_hash, 0xBB, 64);
    uint8_t proposer[32];
    memset(proposer, 0xCC, 32);

    int rc = finalize_block(&w, tx_hash, 1, proposer, 1700000000, 1, NULL, 0);
    CHECK_EQ(rc, -1);

    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM blocks"), 0);

    sqlite3_close(w.db);
}

static void test_mid_batch_abort_rolls_back(void) {
    printf("  abort: second TX NULL entry -> full rollback, no block row\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM blocks"), 0);
    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM utxo_set"), 0);

    nodus_witness_mempool_entry_t *e0 = make_entry(0xD1);
    nodus_witness_mempool_entry_t *entries[2] = { e0, NULL };

    uint8_t proposer[32];
    memset(proposer, 0x55, 32);

    int rc = nodus_witness_commit_batch(&w, entries, 2, 1700000000, proposer);
    CHECK_EQ(rc, -1);

    CHECK_EQ(w.in_block_transaction, false);

    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM blocks"), 0);
    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM utxo_set"), 0);

    free(e0);
    sqlite3_close(w.db);
}

static void test_manual_rollback_restores_state(void) {
    printf("  manual: begin + rollback restores pre-block state\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(w.db,
            "INSERT INTO utxo_set (nullifier, owner, amount, tx_hash, output_index) "
            "VALUES (?, 'pre-block-owner', 100, x'0011', 0)",
            -1, &stmt, NULL) == SQLITE_OK);
        uint8_t nul[64];
        memset(nul, 0x99, 64);
        sqlite3_bind_blob(stmt, 1, nul, 64, SQLITE_STATIC);
        CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    int pre = count_rows(&w, "SELECT COUNT(*) FROM utxo_set");
    CHECK_EQ(pre, 1);

    CHECK_EQ(nodus_witness_db_begin(&w), 0);
    CHECK_EQ(w.in_block_transaction, true);

    {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(w.db,
            "INSERT INTO utxo_set (nullifier, owner, amount, tx_hash, output_index) "
            "VALUES (?, 'mid-block-owner', 200, x'0022', 0)",
            -1, &stmt, NULL) == SQLITE_OK);
        uint8_t nul[64];
        memset(nul, 0x88, 64);
        sqlite3_bind_blob(stmt, 1, nul, 64, SQLITE_STATIC);
        CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM utxo_set"), 2);

    CHECK_EQ(nodus_witness_db_rollback(&w), 0);
    CHECK_EQ(w.in_block_transaction, false);

    CHECK_EQ(count_rows(&w, "SELECT COUNT(*) FROM utxo_set"), pre);

    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus Task 47 - Block Commit Atomicity Tests\n");
    printf("==========================================\n\n");

    test_happy_path();
    test_finalize_without_wrapper();
    test_mid_batch_abort_rolls_back();
    test_manual_rollback_restores_state();

    printf("\nAll Task 47 atomicity tests passed.\n");
    return 0;
}
