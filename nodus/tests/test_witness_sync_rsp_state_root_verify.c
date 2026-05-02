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
    "CREATE TABLE validators (pubkey BLOB PRIMARY KEY,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0);";

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
