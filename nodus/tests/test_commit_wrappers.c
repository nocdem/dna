/**
 * Nodus — Phase 6 commit wrapper tests
 *
 * Phase 6 / Task 6.4 — covers the commit_genesis / commit_batch /
 * replay_block wrappers that compose apply_tx_to_state + finalize_block.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_bft_internal.h"

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
        "  created_at INTEGER NOT NULL DEFAULT 0"
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
        "CREATE TABLE ledger_entries ("
        "  sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_hash BLOB NOT NULL,"
        "  tx_type INTEGER NOT NULL,"
        "  epoch INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0,"
        "  nullifier_count INTEGER NOT NULL DEFAULT 0"
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
        ");"
        /* C4 fix: record_attendance needs validators table (empty → skip). */
        "CREATE TABLE validators ("
        "  pubkey BLOB PRIMARY KEY,"
        "  status INTEGER NOT NULL DEFAULT 0,"
        "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
        "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
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

static void test_replay_block_out_of_order_rejected(void) {
    TEST("replay_block rejects out-of-order sync_rsp height");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_mempool_entry_t *e = make_entry(0x11);
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0xAA, 32);

    int rc = nodus_witness_replay_block(&w, 5, entries, 1, 1700000000, proposer, NULL);
    if (rc != -1) { FAIL("expected -1"); goto done; }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db, "SELECT COUNT(*) FROM blocks", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (count != 0) { FAIL("block added on rejected replay"); goto done; }

    PASS();
done:
    free(e);
    sqlite3_close(w.db);
}

static void test_commit_batch_empty_or_bad_count_rejected(void) {
    TEST("commit_batch rejects empty and oversize batches");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    uint8_t proposer[32];
    memset(proposer, 0xBB, 32);

    int rc = nodus_witness_commit_batch(&w, NULL, 0, 1700000000, proposer, NULL);
    if (rc != -1) { FAIL("count=0 not rejected"); sqlite3_close(w.db); return; }

    nodus_witness_mempool_entry_t *dummy[20];
    for (int i = 0; i < 20; i++) dummy[i] = NULL;
    rc = nodus_witness_commit_batch(&w, dummy, 20, 1700000000, proposer, NULL);
    if (rc != -1) { FAIL("count=20 not rejected"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_commit_batch_single_tx_writes_block(void) {
    TEST("commit_batch(1 TX) writes one block row");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_mempool_entry_t *e = make_entry(0x22);
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0xCC, 32);

    int rc = nodus_witness_commit_batch(&w, entries, 1, 1700000000, proposer, NULL);
    if (rc != 0) { FAIL("commit_batch returned non-zero"); goto done; }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db, "SELECT COUNT(*), tx_count FROM blocks", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    int tx_count_col = sqlite3_column_int(stmt, 1);
    sqlite3_finalize(stmt);

    if (count != 1) { FAIL("expected exactly 1 block row"); goto done; }
    if (tx_count_col != 1) { FAIL("tx_count column != 1"); goto done; }

    PASS();
done:
    free(e);
    sqlite3_close(w.db);
}

static void test_replay_block_in_order_succeeds(void) {
    TEST("replay_block(local+1) succeeds");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_mempool_entry_t *e = make_entry(0x33);
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0xDD, 32);

    int rc = nodus_witness_replay_block(&w, 1, entries, 1, 1700000000, proposer, NULL);
    if (rc != 0) { FAIL("replay_block returned non-zero"); goto done; }

    PASS();
done:
    free(e);
    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus Commit Wrapper Tests\n");
    printf("==========================================\n\n");

    test_replay_block_out_of_order_rejected();
    test_commit_batch_empty_or_bad_count_rejected();
    test_commit_batch_single_tx_writes_block();
    test_replay_block_in_order_succeeds();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
