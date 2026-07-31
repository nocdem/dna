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
        ");"
        /* C4 fix: attendance is now atomic with block commit — record_attendance
         * prepares against `validators`. Empty table → matched=false → skip.
         *
         * ── state_root subtree tables (2026-07-31) ─────────────────────
         * The 4-column stub that used to stand here is gone: since
         * compute_state_root fails CLOSED on every subtree, a validators
         * table missing self_stake / commission_bps / … fails the
         * loader's 16-column SELECT and takes the whole state_root down
         * with it. The atomicity assertions below run through
         * finalize_block, which computes a state_root, so these five
         * tables are now load-bearing for this fixture.
         *
         * Definitions copied VERBATIM from production so the loaders'
         * column lists cannot drift away from this fixture:
         *   validators / delegations / epoch_state / supply_tracking
         *     — nodus_witness.c WITNESS_DB_SCHEMA :146 / :167 / :181 / :199
         *   chain_config_history
         *     — nodus_witness_chain_config.c
         *       nodus_chain_config_db_migrate :96
         *
         * All are left EMPTY, exactly as the stub was — each subtree then
         * yields its tagged-empty sentinel, a REAL computed value, and
         * record_attendance still matches nothing. supply_tracking gets
         * no id = 1 row on purpose: absent is the pre-genesis state,
         * nodus_witness_supply_get returns 1 ("row genuinely absent"),
         * and the supply gate correctly skips. */
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

    int rc = nodus_witness_commit_batch(&w, entries, 1, 1, 1700000000, proposer, NULL);
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

    int rc = finalize_block(&w, tx_hash, 1, proposer, 1700000000, 1, NULL, 0, NULL);
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

    int rc = nodus_witness_commit_batch(&w, entries, 2, 1, 1700000000, proposer, NULL);
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
