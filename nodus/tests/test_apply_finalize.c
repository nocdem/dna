/**
 * Nodus — apply_tx_to_state + finalize_block isolation tests
 *
 * Verifies the Phase 3 / Tasks 3.1, 3.2, 3.4, 3.5, 3.6 split of the
 * legacy commit_block_inner. The tests use the NODUS_WITNESS_INTERNAL_API
 * surface to call apply_tx_to_state and finalize_block directly.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_merkle.h"
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

static int setup_full_witness(nodus_witness_t *w) {
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
        /* ── state_root subtree tables (2026-07-31) ────────────────────
         * compute_state_root now fails CLOSED on every subtree, so a
         * fixture that omits one of these no longer gets a fabricated
         * root — the loader's SELECT fails and the whole state_root
         * fails with it. finalize_block computes a state_root, so this
         * fixture needs all five.
         *
         * Definitions copied VERBATIM from production so the loaders'
         * column lists cannot drift away from this fixture:
         *   validators / delegations / epoch_state / supply_tracking
         *     — nodus_witness.c WITNESS_DB_SCHEMA :146 / :167 / :181 / :199
         *   chain_config_history
         *     — nodus_witness_chain_config.c
         *       nodus_chain_config_db_migrate :96
         *
         * All are left EMPTY. Each subtree then yields its tagged-empty
         * sentinel, which is a REAL computed value, not a substituted
         * one. supply_tracking gets no id = 1 row on purpose: absent is
         * the pre-genesis state, nodus_witness_supply_get returns 1
         * ("row genuinely absent"), and the supply gate correctly
         * skips. */
        "CREATE TABLE IF NOT EXISTS validators ("
        "  pubkey_hash BLOB PRIMARY KEY,"
        "  pubkey BLOB NOT NULL,"
        "  self_stake INTEGER NOT NULL,"
        "  total_delegated INTEGER NOT NULL DEFAULT 0,"
        "  external_delegated INTEGER NOT NULL DEFAULT 0,"
        "  commission_bps INTEGER NOT NULL,"
        "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
        "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
        "  status INTEGER NOT NULL,"
        "  active_since_block INTEGER NOT NULL,"
        "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
        "  unstake_destination_fp TEXT NOT NULL,"
        "  unstake_destination_pubkey BLOB NOT NULL,"
        "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
        "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
        "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
        "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE IF NOT EXISTS delegations ("
        "  delegator_hash BLOB,"
        "  validator_hash BLOB,"
        "  delegator_pubkey BLOB NOT NULL,"
        "  validator_pubkey BLOB NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  delegated_at_block INTEGER NOT NULL,"
        "  PRIMARY KEY (delegator_hash, validator_hash)"
        ");"
        "CREATE TABLE IF NOT EXISTS epoch_state ("
        "  epoch_start_height INTEGER PRIMARY KEY,"
        "  epoch_pool_accum   INTEGER NOT NULL DEFAULT 0,"
        "  snapshot_hash      BLOB NOT NULL,"
        "  snapshot_blob      BLOB"
        ");"
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  total_minted INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS chain_config_history ("
        "    param_id          INTEGER NOT NULL,"
        "    new_value         INTEGER NOT NULL,"
        "    effective_block   INTEGER NOT NULL,"
        "    commit_block      INTEGER NOT NULL,"
        "    tx_hash           BLOB    NOT NULL,"
        "    proposal_nonce    INTEGER NOT NULL,"
        "    created_at_unix   INTEGER NOT NULL,"
        "    PRIMARY KEY (param_id, effective_block)"
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

static int seed_utxo(nodus_witness_t *w, uint8_t marker) {
    uint8_t nullifier[64], token_id[64], tx_hash[64];
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
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_finalize_block_no_proposer_is_noop(void) {
    TEST("finalize_block with NULL proposer_id is a no-op");

    nodus_witness_t w;
    if (setup_full_witness(&w) != 0) { FAIL("setup"); return; }

    int rc = finalize_block(&w, NULL, 0, NULL, 0, 0, NULL, 0, NULL);
    if (rc != 0) { FAIL("expected 0"); sqlite3_close(w.db); return; }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db, "SELECT COUNT(*) FROM blocks", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (count != 0) { FAIL("block row appeared"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_finalize_block_writes_row(void) {
    TEST("finalize_block writes a block row with tx_root and state_root");

    nodus_witness_t w;
    if (setup_full_witness(&w) != 0) { FAIL("setup"); return; }

    if (seed_utxo(&w, 0x33) != 0) { FAIL("seed"); sqlite3_close(w.db); return; }
    if (seed_utxo(&w, 0x44) != 0) { FAIL("seed"); sqlite3_close(w.db); return; }

    uint8_t fake_tx_hash[64];
    for (int i = 0; i < 64; i++) fake_tx_hash[i] = (uint8_t)(0xC0 + i);

    uint8_t proposer[32];
    for (int i = 0; i < 32; i++) proposer[i] = (uint8_t)(0xAA + i);

    /* Task 47 — finalize_block asserts in_block_transaction. Wrap. */
    if (nodus_witness_db_begin(&w) != 0) {
        FAIL("begin"); sqlite3_close(w.db); return;
    }
    int rc = finalize_block(&w, fake_tx_hash, 1, proposer, 1700000000, 1, NULL, 0, NULL);
    if (rc != 0) {
        nodus_witness_db_rollback(&w);
        FAIL("finalize_block returned non-zero"); sqlite3_close(w.db); return;
    }
    nodus_witness_db_commit(&w);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db,
        "SELECT height, tx_root, tx_count, timestamp, state_root FROM blocks", -1,
        &stmt, NULL);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        FAIL("no block row"); sqlite3_finalize(stmt); sqlite3_close(w.db); return;
    }
    int64_t height = sqlite3_column_int64(stmt, 0);
    int blen = sqlite3_column_bytes(stmt, 1);
    const uint8_t *tx_root = sqlite3_column_blob(stmt, 1);
    int64_t tx_count = sqlite3_column_int64(stmt, 2);
    int64_t timestamp = sqlite3_column_int64(stmt, 3);
    int srlen = sqlite3_column_bytes(stmt, 4);
    const uint8_t *state_root = sqlite3_column_blob(stmt, 4);

    uint8_t expected_tx_root[64];
    nodus_witness_merkle_tx_root(fake_tx_hash, 1, expected_tx_root);

    if (height != 1)              { FAIL("wrong height"); goto done; }
    if (blen != 64)               { FAIL("tx_root bad length"); goto done; }
    if (memcmp(tx_root, expected_tx_root, 64) != 0) { FAIL("tx_root mismatch"); goto done; }
    if (tx_count != 1)            { FAIL("wrong tx_count"); goto done; }
    if (timestamp != 1700000000)  { FAIL("wrong timestamp"); goto done; }
    if (srlen != 64)              { FAIL("state_root bad length"); goto done; }

    uint8_t zero[64] = {0};
    if (memcmp(state_root, zero, 64) == 0) { FAIL("state_root all zeros"); goto done; }

    PASS();
done:
    sqlite3_finalize(stmt);
    sqlite3_close(w.db);
}

static void test_finalize_block_rejects_zero_tx_count(void) {
    TEST("finalize_block rejects tx_count=0 with non-NULL proposer");

    nodus_witness_t w;
    if (setup_full_witness(&w) != 0) { FAIL("setup"); return; }
    seed_utxo(&w, 0x10);

    uint8_t proposer[32];
    memset(proposer, 0x77, 32);

    int rc = finalize_block(&w, NULL, 0, proposer, 1700000000, 1, NULL, 0, NULL);
    if (rc != -1) { FAIL("expected -1"); sqlite3_close(w.db); return; }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db, "SELECT COUNT(*) FROM blocks", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (count != 0) { FAIL("block row appeared on rejected call"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus apply_tx_to_state + finalize_block Tests\n");
    printf("==========================================\n\n");

    test_finalize_block_no_proposer_is_noop();
    test_finalize_block_writes_row();
    test_finalize_block_rejects_zero_tx_count();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
