/**
 * Nodus — Faz 1.4 — sync_rsp Byzantine state_root reject (concrete)
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_mempool.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_bft_internal.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static const char *SCHEMA =
    "CREATE TABLE nullifiers (nullifier BLOB PRIMARY KEY, tx_hash BLOB NOT NULL,"
    "  added_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE utxo_set (nullifier BLOB PRIMARY KEY, owner TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL DEFAULT x'"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000',"
    "  tx_hash BLOB NOT NULL, output_index INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL DEFAULT 0,"
    "  unlock_block INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE blocks (height INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  tx_root BLOB NOT NULL, tx_count INTEGER NOT NULL DEFAULT 1,"
    "  timestamp INTEGER NOT NULL, proposer_id BLOB,"
    "  prev_hash BLOB NOT NULL DEFAULT x'',"
    "  state_root BLOB NOT NULL,"
    "  created_at INTEGER NOT NULL DEFAULT 0, chain_def_blob BLOB);"
    "CREATE TABLE supply_state (id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  genesis_supply INTEGER NOT NULL DEFAULT 0,"
    "  total_burned INTEGER NOT NULL DEFAULT 0, genesis_tx_hash BLOB);"
    "CREATE TABLE tokens (token_id BLOB PRIMARY KEY, name TEXT NOT NULL,"
    "  symbol TEXT NOT NULL, decimals INTEGER NOT NULL DEFAULT 8,"
    "  supply INTEGER NOT NULL, creator_fp TEXT NOT NULL,"
    "  flags INTEGER NOT NULL DEFAULT 0,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0);"
    /* ── state_root subtree tables (2026-07-31) ────────────────────────
     * The 4-column validators stub that used to stand here is gone:
     * compute_state_root now fails CLOSED on every subtree, so a
     * validators table missing self_stake / commission_bps / … fails the
     * loader's 16-column SELECT and takes the whole state_root down with
     * it. This fixture verifies a sync_rsp against a locally recomputed
     * state_root, so all five tables are load-bearing here — and the
     * verification is now made against a REAL five-subtree root.
     *
     * Definitions copied VERBATIM from production so the loaders' column
     * lists cannot drift away from this fixture:
     *   validators / delegations / epoch_state / supply_tracking
     *     — nodus_witness.c WITNESS_DB_SCHEMA :146 / :167 / :181 / :199
     *   chain_config_history
     *     — nodus_witness_chain_config.c nodus_chain_config_db_migrate :96
     *
     * All are left EMPTY, exactly as the stub was — each subtree then
     * yields its tagged-empty sentinel, a REAL computed value.
     * supply_tracking gets no id = 1 row on purpose: absent is the
     * pre-genesis state, nodus_witness_supply_get returns 1 ("row
     * genuinely absent"), and the supply gate correctly skips. */
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
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS delegations ("
    "  delegator_hash BLOB,"
    "  validator_hash BLOB,"
    "  delegator_pubkey BLOB NOT NULL,"
    "  validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  delegated_at_block INTEGER NOT NULL,"
    "  PRIMARY KEY (delegator_hash, validator_hash));"
    "CREATE TABLE IF NOT EXISTS epoch_state ("
    "  epoch_start_height INTEGER PRIMARY KEY,"
    "  epoch_pool_accum   INTEGER NOT NULL DEFAULT 0,"
    "  snapshot_hash      BLOB NOT NULL,"
    "  snapshot_blob      BLOB);"
    "CREATE TABLE IF NOT EXISTS supply_tracking ("
    "  id INTEGER PRIMARY KEY CHECK(id = 1),"
    "  genesis_supply INTEGER NOT NULL,"
    "  total_burned INTEGER NOT NULL DEFAULT 0,"
    "  total_minted INTEGER NOT NULL DEFAULT 0,"
    "  current_supply INTEGER NOT NULL,"
    "  last_tx_hash BLOB NOT NULL,"
    "  last_sequence INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS chain_config_history ("
    "    param_id          INTEGER NOT NULL,"
    "    new_value         INTEGER NOT NULL,"
    "    effective_block   INTEGER NOT NULL,"
    "    commit_block      INTEGER NOT NULL,"
    "    tx_hash           BLOB    NOT NULL,"
    "    proposal_nonce    INTEGER NOT NULL,"
    "    created_at_unix   INTEGER NOT NULL,"
    "    PRIMARY KEY (param_id, effective_block));";

static int setup_witness(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;
    if (sqlite3_exec(w->db, SCHEMA, NULL, NULL, NULL) != SQLITE_OK) return -1;
    return 0;
}

int main(void) {
    printf("\nFaz 1.4 — sync_rsp Byzantine state_root reject\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    nodus_witness_mempool_entry_t e1 = {0};
    memset(e1.tx_hash, 0xB1, 64);
    e1.tx_type = NODUS_W_TX_SPEND;
    nodus_witness_mempool_entry_t *en1[1] = { &e1 };
    uint8_t proposer[32];
    memset(proposer, 0x42, 32);
    CHECK_EQ(nodus_witness_commit_batch(&w, en1, 1, /*bh*/1,
                                          1700000000, proposer, NULL), 0);
    CHECK_EQ(nodus_witness_block_height(&w), 1);

    nodus_witness_mempool_entry_t e2 = {0};
    memset(e2.tx_hash, 0xB2, 64);
    e2.tx_type = NODUS_W_TX_SPEND;
    nodus_witness_mempool_entry_t *en2[1] = { &e2 };

    uint8_t fake_state_root[NODUS_KEY_BYTES];
    memset(fake_state_root, 0xDE, NODUS_KEY_BYTES);

    int rc = nodus_witness_replay_block(&w, /*rsp_height*/2, en2, 1,
                                          1700000001, proposer,
                                          fake_state_root);
    CHECK(rc != 0);
    CHECK_EQ(nodus_witness_block_height(&w), 1);
    CHECK(w.safety_halt == true);

    sqlite3_close(w.db);
    printf("Faz 1.4 PASS\n");
    return 0;
}
