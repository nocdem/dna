/**
 * Nodus — intra-batch chained UTXO defense tests
 *
 * Phase 4 / Task 4.5 — exercises the layer-3 in-memory check that
 * apply_tx_to_state runs against batch_ctx->seen_nullifiers BEFORE
 * consuming TX inputs.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
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
        "CREATE TABLE ledger_entries ("
        "  sequence INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_hash BLOB NOT NULL,"
        "  tx_type INTEGER NOT NULL,"
        "  epoch INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0,"
        "  nullifier_count INTEGER NOT NULL DEFAULT 0"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        sqlite3_close(w->db);
        return -1;
    }
    return 0;
}

static void marker_nullifier(uint8_t *out, uint8_t marker) {
    memset(out, marker, NODUS_T3_NULLIFIER_LEN);
}

static void test_null_batch_ctx_skips_layer3(void) {
    TEST("NULL batch_ctx skips the layer-3 chained check");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    uint8_t nf[NODUS_T3_NULLIFIER_LEN];
    marker_nullifier(nf, 0xAA);
    const uint8_t *nfs[1] = { nf };

    uint8_t tx_hash[64];
    memset(tx_hash, 0xC1, sizeof(tx_hash));

    int rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_SPEND, nfs, 1,
                                NULL, 0, 1, NULL);
    if (rc != 0) { FAIL("returned non-zero"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_empty_ctx_passes(void) {
    TEST("empty batch_ctx allows any input nullifier");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint8_t nf[NODUS_T3_NULLIFIER_LEN];
    marker_nullifier(nf, 0x33);
    const uint8_t *nfs[1] = { nf };

    uint8_t tx_hash[64];
    memset(tx_hash, 0xD2, sizeof(tx_hash));

    int rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_SPEND, nfs, 1,
                                NULL, 0, 1, &ctx);
    if (rc != 0) { FAIL("returned non-zero"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_populated_ctx_rejects_matching_input(void) {
    TEST("populated batch_ctx rejects matching input");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    marker_nullifier(ctx.seen_nullifiers[0], 0x44);
    ctx.seen_count = 1;

    uint8_t nf[NODUS_T3_NULLIFIER_LEN];
    marker_nullifier(nf, 0x44);
    const uint8_t *nfs[1] = { nf };

    uint8_t tx_hash[64];
    memset(tx_hash, 0xE3, sizeof(tx_hash));

    int rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_SPEND, nfs, 1,
                                NULL, 0, 1, &ctx);
    if (rc != -1) { FAIL("expected -1"); sqlite3_close(w.db); return; }

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(w.db, "SELECT COUNT(*) FROM nullifiers", -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (count != 0) { FAIL("nullifier table polluted"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_transitive_chain_rejected(void) {
    TEST("transitive chain — third input matches third ctx entry");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    marker_nullifier(ctx.seen_nullifiers[0], 0x10);
    marker_nullifier(ctx.seen_nullifiers[1], 0x20);
    marker_nullifier(ctx.seen_nullifiers[2], 0x30);
    ctx.seen_count = 3;

    uint8_t nf1[NODUS_T3_NULLIFIER_LEN], nf2[NODUS_T3_NULLIFIER_LEN], nf3[NODUS_T3_NULLIFIER_LEN];
    marker_nullifier(nf1, 0x77);
    marker_nullifier(nf2, 0x88);
    marker_nullifier(nf3, 0x30);
    const uint8_t *nfs[3] = { nf1, nf2, nf3 };

    uint8_t tx_hash[64];
    memset(tx_hash, 0xF4, sizeof(tx_hash));

    int rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_SPEND, nfs, 3,
                                NULL, 0, 1, &ctx);
    if (rc != -1) { FAIL("expected -1"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

static void test_self_reference_not_flagged(void) {
    TEST("self-reference: input == own future output is NOT flagged");

    nodus_witness_t w;
    if (setup_witness(&w) != 0) { FAIL("setup"); return; }

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    uint8_t nf[NODUS_T3_NULLIFIER_LEN];
    marker_nullifier(nf, 0x55);
    const uint8_t *nfs[1] = { nf };

    uint8_t tx_hash[64];
    memset(tx_hash, 0xA5, sizeof(tx_hash));

    int rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_SPEND, nfs, 1,
                                NULL, 0, 1, &ctx);
    if (rc != 0) { FAIL("returned non-zero"); sqlite3_close(w.db); return; }

    PASS();
    sqlite3_close(w.db);
}

int main(void) {
    printf("\nNodus Intra-Batch Chained UTXO Defense Tests\n");
    printf("==========================================\n\n");

    test_null_batch_ctx_skips_layer3();
    test_empty_ctx_passes();
    test_populated_ctx_rejects_matching_input();
    test_transitive_chain_rejected();
    test_self_reference_not_flagged();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
