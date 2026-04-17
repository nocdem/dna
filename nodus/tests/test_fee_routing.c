/**
 * Nodus - Task 31 fee-routing test
 *
 * Verifies that SPEND fees accumulate into w->block_fee_pool instead
 * of being burned to DNAC_BURN_ADDRESS.
 *
 * Design section 2.5 (stake-delegation plan):
 *   "DNAC-only fees (unchanged from v0.11.0). Fee previously burned
 *    to 0x00..00; now routes to reward accumulator - fee collection
 *    redirects in the same commit as this feature lands."
 *
 * This test calls apply_tx_to_state directly with a synthetic SPEND
 * TX (1 input of 1000, 1 output of 900 -> fee 100). After the call:
 *   (a) block_fee_pool == 100
 *   (b) no UTXO row owned by DNAC_BURN_ADDRESS exists in utxo_set
 *   (c) the getter nodus_witness_get_block_fee_pool returns 100
 *
 * It then calls a second synthetic SPEND (fee 250) and re-checks that
 * the pool is 350 - confirming the accumulator nature.
 *
 * Finally, a finalize_block path is exercised: after finalize succeeds
 * the pool must reset to 0 (Phase 9 Task 49 will drain it into the
 * reward pool before the reset when that feature lands).
 *
 * The test does NOT drive a full BFT round - that is covered by the
 * Phase 17 integration tests. Here we stay at the per-TX primitive.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft_internal.h"
#include "witness/nodus_witness_db.h"
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

/* In-memory DB setup mirroring test_apply_finalize.c - subset of the
 * production WITNESS_DB_SCHEMA sufficient for update_utxo_set +
 * apply_tx_to_state to run without hitting missing-table errors. */
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
        fprintf(stderr, "schema error: %s\n", err ? err : "(null)");
        sqlite3_free(err);
        sqlite3_close(w->db);
        w->db = NULL;
        return -1;
    }
    return 0;
}

/* Build a synthetic SPEND TX body matching the wire format that
 * update_utxo_set parses:
 *   header:   version(1) + type(1) + timestamp(8) + tx_hash(64) = 74
 *   inputs:   count(1) + N * [nullifier(64) + amount(8) + token_id(64)]
 *   outputs:  count(1) + N * [version(1) + fp(129) + amount(8) +
 *                             token_id(64) + seed(32) + memo_len(1)]
 *
 * Single input of in_amount, single output of out_amount to a
 * fingerprint built deterministically from out_marker. Zero token_id
 * everywhere (native DNAC).
 */
static size_t build_spend_tx(uint8_t *buf, size_t buf_cap,
                              const uint8_t *tx_hash,
                              const uint8_t *input_nullifier,
                              uint64_t in_amount,
                              uint8_t out_marker,
                              uint64_t out_amount,
                              const uint8_t *seed32) {
    size_t off = 0;
    /* Header */
    buf[off++] = 1;                    /* version */
    buf[off++] = NODUS_W_TX_SPEND;     /* type */
    uint64_t ts = 1700000000;
    memcpy(buf + off, &ts, 8); off += 8;
    memcpy(buf + off, tx_hash, NODUS_T3_TX_HASH_LEN);
    off += NODUS_T3_TX_HASH_LEN;

    /* Inputs: 1 */
    buf[off++] = 1;
    memcpy(buf + off, input_nullifier, NODUS_T3_NULLIFIER_LEN);
    off += NODUS_T3_NULLIFIER_LEN;
    memcpy(buf + off, &in_amount, 8); off += 8;
    memset(buf + off, 0, 64);          /* token_id = native */
    off += 64;

    /* Outputs: 1 */
    buf[off++] = 1;
    buf[off++] = 1;                    /* output version */
    /* fingerprint: 128 hex chars + null - deterministic from marker */
    char fp[129];
    for (int i = 0; i < 128; i++) {
        fp[i] = "0123456789abcdef"[(out_marker + i) & 0xf];
    }
    fp[128] = '\0';
    memcpy(buf + off, fp, 129);
    off += 129;
    memcpy(buf + off, &out_amount, 8); off += 8;
    memset(buf + off, 0, 64);          /* token_id = native */
    off += 64;
    memcpy(buf + off, seed32, 32);
    off += 32;
    buf[off++] = 0;                    /* memo_len */

    CHECK(off <= buf_cap);
    return off;
}

/* Count rows in utxo_set whose owner equals DNAC_BURN_ADDRESS. */
static int count_burn_owned_utxos(nodus_witness_t *w) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM utxo_set WHERE owner = ?",
        -1, &stmt, NULL);
    CHECK(rc == SQLITE_OK);
    sqlite3_bind_text(stmt, 1, (const char *)DNAC_BURN_ADDRESS, 128, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

/* Seed a UTXO so the SPEND input has something to consume.
 * input_nullifier is the nullifier of the pre-existing UTXO the SPEND spends. */
static int seed_input_utxo(nodus_witness_t *w,
                            const uint8_t *input_nullifier,
                            uint64_t amount) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, tx_hash, output_index) "
        "VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK) return -1;

    char owner[129];
    for (int i = 0; i < 128; i++) owner[i] = "0123456789abcdef"[i & 0xf];
    owner[128] = '\0';

    uint8_t fake_tx_hash[64];
    memset(fake_tx_hash, 0x77, 64);

    sqlite3_bind_blob(stmt, 1, input_nullifier, 64, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, fake_tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int main(void) {
    printf("test_fee_routing: Task 31 - fees route to block_fee_pool\n");

    nodus_witness_t w;
    CHECK(setup_witness(&w) == 0);

    /* Scenario A: SPEND with fee=100 */
    uint8_t tx_hash_a[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash_a, 0xA1, NODUS_T3_TX_HASH_LEN);
    uint8_t input_nul_a[NODUS_T3_NULLIFIER_LEN];
    memset(input_nul_a, 0xB1, NODUS_T3_NULLIFIER_LEN);
    uint8_t seed_a[32];
    memset(seed_a, 0xC1, 32);

    /* Pre-seed the input UTXO the SPEND consumes. Amount 1000. */
    CHECK(seed_input_utxo(&w, input_nul_a, 1000) == 0);

    uint8_t tx_buf[4096];
    size_t tx_len = build_spend_tx(tx_buf, sizeof(tx_buf),
                                     tx_hash_a, input_nul_a,
                                     1000, 0x33, 900, seed_a);

    /* Initial state: pool zero, no burn UTXOs. */
    CHECK_EQ(w.block_fee_pool, 0);
    CHECK_EQ(count_burn_owned_utxos(&w), 0);

    const uint8_t *nul_ptrs_a[1] = { input_nul_a };
    int rc = apply_tx_to_state(&w, tx_hash_a, NODUS_W_TX_SPEND,
                                 nul_ptrs_a, 1, tx_buf, (uint32_t)tx_len,
                                 1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);

    /* Invariant 1: fee 100 accumulated into block_fee_pool. */
    CHECK_EQ(w.block_fee_pool, 100);

    /* Invariant 2: no burn UTXO created. */
    CHECK_EQ(count_burn_owned_utxos(&w), 0);

    /* Invariant 3: getter returns the same value. */
    uint64_t pool = 0;
    CHECK_EQ(nodus_witness_get_block_fee_pool(&w, &pool), 0);
    CHECK_EQ(pool, 100);

    /* Invariant 4: the SPEND output WAS added (amount 900). */
    {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(w.db,
            "SELECT COUNT(*) FROM utxo_set WHERE amount = 900",
            -1, &stmt, NULL) == SQLITE_OK);
        int out_count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        CHECK_EQ(out_count, 1);
    }

    /* Invariant 5: the SPEND input WAS removed. */
    {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(w.db,
            "SELECT COUNT(*) FROM utxo_set WHERE nullifier = ?",
            -1, &stmt, NULL) == SQLITE_OK);
        sqlite3_bind_blob(stmt, 1, input_nul_a, 64, SQLITE_STATIC);
        int in_count = -1;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            in_count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        CHECK_EQ(in_count, 0);
    }

    /* Scenario B: second SPEND, fee=250, pool accumulates */
    uint8_t tx_hash_b[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash_b, 0xA2, NODUS_T3_TX_HASH_LEN);
    uint8_t input_nul_b[NODUS_T3_NULLIFIER_LEN];
    memset(input_nul_b, 0xB2, NODUS_T3_NULLIFIER_LEN);
    uint8_t seed_b[32];
    memset(seed_b, 0xC2, 32);

    CHECK(seed_input_utxo(&w, input_nul_b, 500) == 0);

    tx_len = build_spend_tx(tx_buf, sizeof(tx_buf),
                             tx_hash_b, input_nul_b,
                             500, 0x44, 250, seed_b);

    const uint8_t *nul_ptrs_b[1] = { input_nul_b };
    rc = apply_tx_to_state(&w, tx_hash_b, NODUS_W_TX_SPEND,
                             nul_ptrs_b, 1, tx_buf, (uint32_t)tx_len,
                             1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);

    /* Pool accumulated 100 + 250 = 350. Still no burn UTXOs. */
    CHECK_EQ(w.block_fee_pool, 350);
    CHECK_EQ(count_burn_owned_utxos(&w), 0);

    /* Scenario C: finalize_block drains the pool */
    uint8_t tx_hashes[2 * NODUS_T3_TX_HASH_LEN];
    memcpy(tx_hashes, tx_hash_a, NODUS_T3_TX_HASH_LEN);
    memcpy(tx_hashes + NODUS_T3_TX_HASH_LEN, tx_hash_b, NODUS_T3_TX_HASH_LEN);

    uint8_t proposer[32];
    memset(proposer, 0x9E, 32);

    rc = finalize_block(&w, tx_hashes, 2, proposer, 1700000001, 1, NULL, 0);
    CHECK_EQ(rc, 0);

    /* After finalize: pool reset to 0. */
    CHECK_EQ(w.block_fee_pool, 0);
    CHECK_EQ(nodus_witness_get_block_fee_pool(&w, &pool), 0);
    CHECK_EQ(pool, 0);

    /* Invariant: block row written. */
    {
        sqlite3_stmt *stmt = NULL;
        CHECK(sqlite3_prepare_v2(w.db,
            "SELECT COUNT(*) FROM blocks", -1, &stmt, NULL) == SQLITE_OK);
        int bc = -1;
        if (sqlite3_step(stmt) == SQLITE_ROW) bc = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        CHECK_EQ(bc, 1);
    }

    /* Getter edge case: NULL witness -> -1 (cast to uint64_t for the macro). */
    CHECK_EQ((uint64_t)nodus_witness_get_block_fee_pool(NULL, &pool),
              (uint64_t)(int64_t)-1);

    /* Getter tolerates NULL out. */
    CHECK_EQ(nodus_witness_get_block_fee_pool(&w, NULL), 0);

    sqlite3_close(w.db);
    w.db = NULL;

    printf("test_fee_routing: ALL CHECKS PASSED\n");
    return 0;
}
