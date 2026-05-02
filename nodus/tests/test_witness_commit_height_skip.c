/**
 * Nodus — Faz 1.1 — round skip detection (concrete)
 *
 * Scenario:
 *   1. Setup witness at chain_head = 114 (one row in blocks table)
 *   2. Build COMMIT with hdr.round = 118, cmt.block_height = 116
 *   3. handle_commit returns -1 (height mismatch — local_next = 115)
 *   4. Chain head unchanged (still 114)
 *
 * Bug ref: project_witness_commit_height_asymmetry (live cluster
 * 2026-05-01: US-1 halted at h=114 due to this exact path).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define CHECK_EQ(a, b) do { \
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

static const char *SCHEMA =
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
    ");";

static int setup_witness(nodus_witness_t *w, uint64_t initial_height) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;
    if (sqlite3_exec(w->db, SCHEMA, NULL, NULL, NULL) != SQLITE_OK) return -1;
    if (initial_height > 0) {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "INSERT INTO blocks (height, tx_root, timestamp, proposer_id, "
            "prev_hash, state_root) VALUES (?, x'00', 0, x'00', x'00', x'00')";
        sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)initial_height);
        if (sqlite3_step(stmt) != SQLITE_DONE) return -1;
        sqlite3_finalize(stmt);
    }
    /* w->chain_id zero-init → verify_chain_id no-pin path (line 237) */
    return 0;
}

int main(void) {
    printf("\nFaz 1.1 — round skip detection\n");

    nodus_witness_t w;
    if (setup_witness(&w, 114) != 0) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }
    CHECK_EQ(nodus_witness_block_height(&w), 114);

    nodus_t3_msg_t msg = {0};
    msg.type = NODUS_T3_COMMIT;
    msg.header.round = 118;

    msg.commit.block_height = 116;        /* skip: expected 115 */
    msg.commit.batch_count = 1;
    msg.commit.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    memset(msg.commit.batch_txs[0].tx_hash, 0xAA, 64);
    static uint8_t tx_data[] = {0xFF};
    msg.commit.batch_txs[0].tx_data = tx_data;
    msg.commit.batch_txs[0].tx_len = sizeof(tx_data);
    msg.commit.n_precommits = 0;          /* skip cert verify */

    int rc = nodus_witness_bft_handle_commit(&w, &msg);
    CHECK_EQ(rc, -1);
    CHECK_EQ(nodus_witness_block_height(&w), 114);

    sqlite3_close(w.db);
    printf("Faz 1.1 PASS\n");
    return 0;
}
