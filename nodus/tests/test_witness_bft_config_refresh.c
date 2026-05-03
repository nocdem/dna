/**
 * Nodus — PR 1: bft_config follower-path refresh regression
 *
 * Verifies that nodus_witness_commit_batch refreshes w->bft_config
 * (n_witnesses + quorum) AFTER a successful block commit. C-3 fix
 * from design doc 2026-05-03-witness-auto-bootstrap-design.md.
 *
 * Pre-fix, leader-side round-start refreshed bft_config, but
 * follower-side commit_batch / replay_block did not, leaving followers
 * with stale committee → divergent quorum threshold → chain split.
 *
 * Test path uses the F17 A5 bootstrap fallback: empty validators table
 * → load_committee_at_height returns count=0 → refresh falls through
 * to w->roster.n_witnesses. Mutating roster size between commits
 * simulates committee change.
 *
 * Pre-PR-1 (RED): commit_batch never calls refresh → w->bft_config
 *                 stays at memset(0) → first CHECK_EQ(n_witnesses, 7)
 *                 fails (0 != 7).
 * Post-PR-1 (GREEN): commit_batch calls refresh on success →
 *                    n_witnesses tracks roster size on each block.
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
    printf("\nPR 1 — bft_config follower-path refresh\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    /* Empty validators table → load_committee_at_height returns count=0
     * → refresh falls through to roster size (F17 A5 path). */
    w.roster.n_witnesses = 7;

    /* Block 1: commit with roster of 7 → bft_config should reflect 7. */
    nodus_witness_mempool_entry_t e1 = {0};
    memset(e1.tx_hash, 0xB1, 64);
    e1.tx_type = NODUS_W_TX_SPEND;
    nodus_witness_mempool_entry_t *en1[1] = { &e1 };
    uint8_t proposer[32];
    memset(proposer, 0x42, 32);
    CHECK_EQ(nodus_witness_commit_batch(&w, en1, 1, /*bh*/1,
                                          1700000000, proposer, NULL), 0);
    CHECK_EQ(nodus_witness_block_height(&w), 1);

    /* RED on main: bft_config.n_witnesses still 0 (never refreshed).
     * GREEN after PR 1 fix: refresh fires post-commit → 7. */
    CHECK_EQ(w.bft_config.n_witnesses, 7);
    CHECK_EQ(w.bft_config.quorum,      5);  /* (2*7)/3 + 1 */

    /* Simulate committee shrink to 5. The committee cache stays at
     * memset(0) initial state (epoch_start=0, count=0); both blocks
     * fall in epoch 0 and hit the cache with count=0 → refresh
     * fallback re-reads roster each time. Mutating roster is the
     * simplest way to vary refresh output across commits without
     * seeding the full validator schema. */
    w.roster.n_witnesses = 5;

    /* Block 2: commit with roster of 5 → bft_config should reflect 5. */
    nodus_witness_mempool_entry_t e2 = {0};
    memset(e2.tx_hash, 0xB2, 64);
    e2.tx_type = NODUS_W_TX_SPEND;
    nodus_witness_mempool_entry_t *en2[1] = { &e2 };
    CHECK_EQ(nodus_witness_commit_batch(&w, en2, 1, /*bh*/2,
                                          1700000001, proposer, NULL), 0);
    CHECK_EQ(nodus_witness_block_height(&w), 2);

    CHECK_EQ(w.bft_config.n_witnesses, 5);
    CHECK_EQ(w.bft_config.quorum,      4);  /* (2*5)/3 + 1 */

    sqlite3_close(w.db);
    printf("PR 1 PASS\n");
    return 0;
}
