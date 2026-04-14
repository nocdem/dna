/**
 * Nodus — Phase 11 follow-up — block_txs_get DB query test
 *
 * Verifies the multi-tx fetch helper added in Phase 11.1 returns rows
 * in tx_index order and surfaces the client_pubkey / client_sig
 * columns from migration v13.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int setup(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;
    const char *schema =
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  sender_fp TEXT,"
        "  fee INTEGER NOT NULL DEFAULT 0,"
        "  tx_index INTEGER NOT NULL DEFAULT 0,"
        "  client_pubkey BLOB,"
        "  client_sig BLOB"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema: %s\n", err);
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

static int insert_tx(nodus_witness_t *w, uint8_t marker, uint64_t height,
                     int tx_index, int with_pk_sig) {
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t tx_data[64];
    memset(tx_hash, marker, sizeof(tx_hash));
    memset(tx_data, marker ^ 0x55, sizeof(tx_data));

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO committed_transactions "
        "(tx_hash, tx_type, tx_data, tx_len, block_height, timestamp, "
        "fee, tx_index, client_pubkey, client_sig) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, sizeof(tx_hash), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, 1);
    sqlite3_bind_blob(stmt, 3, tx_data, sizeof(tx_data), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, sizeof(tx_data));
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)height);
    sqlite3_bind_int64(stmt, 6, 1700000000);
    sqlite3_bind_int64(stmt, 7, 0);
    sqlite3_bind_int(stmt, 8, tx_index);

    if (with_pk_sig) {
        uint8_t pk[NODUS_PK_BYTES];
        uint8_t sig[NODUS_SIG_BYTES];
        memset(pk, marker ^ 0xAA, sizeof(pk));
        memset(sig, marker ^ 0xBB, sizeof(sig));
        sqlite3_bind_blob(stmt, 9, pk, sizeof(pk), SQLITE_TRANSIENT);
        sqlite3_bind_blob(stmt, 10, sig, sizeof(sig), SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 9);
        sqlite3_bind_null(stmt, 10);
    }

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void test_empty_block_returns_zero(void) {
    TEST("empty block returns 0 rows");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    int count = 99;
    int rc = nodus_witness_block_txs_get(&w, 5, rows, NODUS_W_MAX_BLOCK_TXS, &count);
    if (rc != 0) { FAIL("rc"); sqlite3_close(w.db); return; }
    if (count != 0) { FAIL("count != 0"); sqlite3_close(w.db); return; }
    PASS();
    sqlite3_close(w.db);
}

static void test_rows_ordered_by_tx_index(void) {
    TEST("rows returned in tx_index order");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    insert_tx(&w, 0x33, 7, 2, 0);
    insert_tx(&w, 0x11, 7, 0, 0);
    insert_tx(&w, 0x22, 7, 1, 0);

    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    int count = 0;
    if (nodus_witness_block_txs_get(&w, 7, rows, NODUS_W_MAX_BLOCK_TXS, &count) != 0) {
        FAIL("query"); sqlite3_close(w.db); return;
    }
    if (count != 3) { FAIL("count"); goto done; }
    if (rows[0].tx_hash[0] != 0x11) { FAIL("row 0"); goto done; }
    if (rows[1].tx_hash[0] != 0x22) { FAIL("row 1"); goto done; }
    if (rows[2].tx_hash[0] != 0x33) { FAIL("row 2"); goto done; }
    PASS();
done:
    for (int i = 0; i < count; i++)
        nodus_witness_block_tx_row_free(&rows[i]);
    sqlite3_close(w.db);
}

static void test_client_pk_sig_surfaced(void) {
    TEST("client_pubkey and client_sig surfaced when present");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    insert_tx(&w, 0x55, 9, 0, 1);
    insert_tx(&w, 0x66, 9, 1, 0);

    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    int count = 0;
    if (nodus_witness_block_txs_get(&w, 9, rows, NODUS_W_MAX_BLOCK_TXS, &count) != 0) {
        FAIL("query"); sqlite3_close(w.db); return;
    }
    if (count != 2) { FAIL("count"); goto done; }
    if (!rows[0].client_pubkey || !rows[0].client_sig) {
        FAIL("row 0 pk/sig missing"); goto done;
    }
    if (rows[0].client_pubkey[0] != (0x55 ^ 0xAA)) {
        FAIL("row 0 pk content"); goto done;
    }
    if (rows[0].client_sig[0] != (0x55 ^ 0xBB)) {
        FAIL("row 0 sig content"); goto done;
    }
    if (rows[1].client_pubkey || rows[1].client_sig) {
        FAIL("row 1 pk/sig leaked"); goto done;
    }
    PASS();
done:
    for (int i = 0; i < count; i++)
        nodus_witness_block_tx_row_free(&rows[i]);
    sqlite3_close(w.db);
}

static void test_other_blocks_not_returned(void) {
    TEST("other blocks rows excluded");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    insert_tx(&w, 0xA1, 1, 0, 0);
    insert_tx(&w, 0xA2, 2, 0, 0);
    insert_tx(&w, 0xA3, 3, 0, 0);

    nodus_witness_block_tx_row_t rows[NODUS_W_MAX_BLOCK_TXS];
    int count = 0;
    if (nodus_witness_block_txs_get(&w, 2, rows, NODUS_W_MAX_BLOCK_TXS, &count) != 0) {
        FAIL("query"); sqlite3_close(w.db); return;
    }
    if (count != 1) { FAIL("count"); goto done; }
    if (rows[0].tx_hash[0] != 0xA2) { FAIL("wrong block"); goto done; }
    PASS();
done:
    for (int i = 0; i < count; i++)
        nodus_witness_block_tx_row_free(&rows[i]);
    sqlite3_close(w.db);
}

int main(void) {
    printf("nodus_witness_block_txs_get tests\n");
    printf("=================================\n");

    test_empty_block_returns_zero();
    test_rows_ordered_by_tx_index();
    test_client_pk_sig_surfaced();
    test_other_blocks_not_returned();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
