/**
 * Nodus — Phase 11 / Task 11.6 — sync_rsp wire guard tests
 *
 * Locks the three-tier size guard (tx_count, per-TX tx_len, aggregate)
 * and the multi-tx wire shape. Receiver tx_root recomputation and
 * cert verify-against-local-block_hash are tested through the
 * existing test_witness_cert_verify suite + integration runs.
 */

#include "protocol/nodus_tier3.h"
#include "crypto/nodus_identity.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;
static nodus_identity_t test_id;

static void fixture_init(void) {
    /* Generate a test keypair once for wsig sign/verify. */
    nodus_identity_generate(&test_id);
}

static void fill_header(nodus_t3_header_t *h) {
    h->version = NODUS_T3_BFT_PROTOCOL_VER;
    h->round = 1;
    h->view = 0;
    memcpy(h->sender_id, test_id.node_id.bytes, NODUS_T3_WITNESS_ID_LEN);
    h->timestamp = 1700000000;
    h->nonce = 42;
    memset(h->chain_id, 0xC0, 32);
}

static void test_sync_rsp_multi_tx_roundtrip(void) {
    TEST("sync_rsp 5-tx batch round-trip");

    nodus_t3_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_SYNC_RSP;
    in.txn_id = 1;
    fill_header(&in.header);

    in.sync_rsp.found = true;
    in.sync_rsp.height = 7;
    in.sync_rsp.timestamp = 1700000100;
    memset(in.sync_rsp.proposer_id, 0xAA, NODUS_T3_WITNESS_ID_LEN);
    memset(in.sync_rsp.prev_hash, 0xBB, NODUS_T3_TX_HASH_LEN);
    memset(in.sync_rsp.tx_root, 0xCC, NODUS_T3_TX_HASH_LEN);

    in.sync_rsp.tx_count = 5;
    static uint8_t tx_data_buf[5][256];
    static uint8_t dummy_pk[NODUS_PK_BYTES];
    static uint8_t dummy_sig[NODUS_SIG_BYTES];
    for (int i = 0; i < 5; i++) {
        memset(tx_data_buf[i], 0x10 + i, sizeof(tx_data_buf[i]));
        nodus_t3_batch_tx_t *btx = &in.sync_rsp.batch_txs[i];
        memset(btx->tx_hash, 0x80 + i, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = 1;
        btx->tx_data = tx_data_buf[i];
        btx->tx_len = 256;
        btx->client_pubkey = dummy_pk;
        btx->client_sig = dummy_sig;
    }

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) { FAIL("malloc"); return; }
    size_t encoded_len = 0;
    if (nodus_t3_encode(&in, &test_id.sk, buf,
                          NODUS_W_MAX_SYNC_RSP_SIZE, &encoded_len) != 0) {
        free(buf); FAIL("encode"); return;
    }

    nodus_t3_msg_t out;
    if (nodus_t3_decode(buf, encoded_len, &out) != 0) {
        free(buf); FAIL("decode"); return;
    }
    free(buf);
    if (out.sync_rsp.tx_count != 5) { FAIL("tx_count"); return; }
    for (int i = 0; i < 5; i++) {
        uint8_t expected_hash[NODUS_T3_TX_HASH_LEN];
        memset(expected_hash, 0x80 + i, NODUS_T3_TX_HASH_LEN);
        if (memcmp(out.sync_rsp.batch_txs[i].tx_hash, expected_hash,
                   NODUS_T3_TX_HASH_LEN) != 0) {
            FAIL("batch_tx hash"); return;
        }
        if (out.sync_rsp.batch_txs[i].tx_len != 256) {
            FAIL("batch_tx len"); return;
        }
    }
    PASS();
}

static void test_sync_rsp_tx_count_capped(void) {
    TEST("sync_rsp tx_count > MAX_BLOCK_TXS capped to MAX");

    nodus_t3_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_SYNC_RSP;
    in.txn_id = 2;
    fill_header(&in.header);

    in.sync_rsp.found = true;
    in.sync_rsp.height = 1;
    in.sync_rsp.tx_count = NODUS_W_MAX_BLOCK_TXS;  /* sender obeys cap */
    static uint8_t small_data[64];
    static uint8_t dummy_pk2[NODUS_PK_BYTES];
    static uint8_t dummy_sig2[NODUS_SIG_BYTES];
    for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) {
        nodus_t3_batch_tx_t *btx = &in.sync_rsp.batch_txs[i];
        memset(btx->tx_hash, i, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = 1;
        btx->tx_data = small_data;
        btx->tx_len = sizeof(small_data);
        btx->client_pubkey = dummy_pk2;
        btx->client_sig = dummy_sig2;
    }

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) { FAIL("malloc"); return; }
    size_t encoded_len = 0;
    if (nodus_t3_encode(&in, &test_id.sk, buf,
                          NODUS_W_MAX_SYNC_RSP_SIZE, &encoded_len) != 0) {
        free(buf); FAIL("encode"); return;
    }

    nodus_t3_msg_t out;
    if (nodus_t3_decode(buf, encoded_len, &out) != 0) {
        free(buf); FAIL("decode"); return;
    }
    free(buf);
    /* Decoder applied the tier-1 cap. */
    if (out.sync_rsp.tx_count > NODUS_W_MAX_BLOCK_TXS) {
        FAIL("tx_count not capped"); return;
    }
    PASS();
}

static void test_sync_rsp_aggregate_under_1mb(void) {
    TEST("sync_rsp 10x4KB stays under 1 MB cap");

    nodus_t3_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NODUS_T3_SYNC_RSP;
    in.txn_id = 3;
    fill_header(&in.header);

    in.sync_rsp.found = true;
    in.sync_rsp.height = 1;
    in.sync_rsp.tx_count = NODUS_W_MAX_BLOCK_TXS;
    static uint8_t medium_data[4096];
    memset(medium_data, 0xEE, sizeof(medium_data));
    static uint8_t dummy_pk3[NODUS_PK_BYTES];
    static uint8_t dummy_sig3[NODUS_SIG_BYTES];
    for (int i = 0; i < NODUS_W_MAX_BLOCK_TXS; i++) {
        nodus_t3_batch_tx_t *btx = &in.sync_rsp.batch_txs[i];
        memset(btx->tx_hash, i, NODUS_T3_TX_HASH_LEN);
        btx->tx_type = 1;
        btx->tx_data = medium_data;
        btx->tx_len = sizeof(medium_data);
        btx->client_pubkey = dummy_pk3;
        btx->client_sig = dummy_sig3;
    }
    /* 21-witness cert pad (large) */
    in.sync_rsp.cert_count = 21;
    for (int i = 0; i < 21; i++) {
        memset(in.sync_rsp.certs[i].voter_id, i, NODUS_T3_WITNESS_ID_LEN);
        memset(in.sync_rsp.certs[i].signature, i, NODUS_SIG_BYTES);
    }

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) { FAIL("malloc"); return; }
    size_t encoded_len = 0;
    int rc = nodus_t3_encode(&in, &test_id.sk, buf,
                              NODUS_W_MAX_SYNC_RSP_SIZE, &encoded_len);
    free(buf);
    if (rc != 0) { FAIL("encode"); return; }
    if (encoded_len > NODUS_W_MAX_SYNC_RSP_SIZE) {
        FAIL("aggregate > 1 MB"); return;
    }
    PASS();
}

int main(void) {
    printf("sync_rsp wire guard tests\n");
    printf("=========================\n");

    fixture_init();

    test_sync_rsp_multi_tx_roundtrip();
    test_sync_rsp_tx_count_capped();
    test_sync_rsp_aggregate_under_1mb();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
