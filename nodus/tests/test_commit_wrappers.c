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
        /* C4 fix: record_attendance needs validators table (empty → skip).
         *
         * ── state_root subtree tables (2026-07-31) ─────────────────────
         * The 4-column stub that used to stand here is gone: since
         * compute_state_root fails CLOSED on every subtree, a validators
         * table missing self_stake / commission_bps / … fails the
         * loader's 16-column SELECT and takes the whole state_root down
         * with it. The commit wrappers under test call finalize_block,
         * which computes a state_root, so these five tables are now
         * load-bearing for this fixture.
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

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
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

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    uint8_t proposer[32];
    memset(proposer, 0xBB, 32);

    /* expected_height=1 placeholder; reject paths fire on entries/count
     * arg validation before the height check (Faz 3B 2026-05-02). */
    int rc = nodus_witness_commit_batch(&w, NULL, 0, 1, 1700000000, proposer, NULL);
    if (rc != -1) { FAIL("count=0 not rejected"); sqlite3_close(w.db); return; }

    nodus_witness_mempool_entry_t *dummy[20];
    for (int i = 0; i < 20; i++) dummy[i] = NULL;
    rc = nodus_witness_commit_batch(&w, dummy, 20, 1, 1700000000, proposer, NULL);
    if (rc != -1) { FAIL("count=20 not rejected"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_commit_batch_single_tx_writes_block(void) {
    TEST("commit_batch(1 TX) writes one block row");

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_mempool_entry_t *e = make_entry(0x22);
    nodus_witness_mempool_entry_t *entries[1] = { e };

    uint8_t proposer[32];
    memset(proposer, 0xCC, 32);

    /* setup_witness leaves h=0; first commit lands at h=1. */
    int rc = nodus_witness_commit_batch(&w, entries, 1, 1, 1700000000, proposer, NULL);
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

    static nodus_witness_t w;   /* multi-MB — static storage, not stack */
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
