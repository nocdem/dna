/**
 * Nodus — Phase 12 / Task 12.6 — spend_result preimage layout tests
 *
 * Locks the byte-exact 221-byte layout of the dnac_spend response
 * Dilithium5 preimage. Catches regressions in the four latent bugs
 * the Phase 12 fix closed:
 *
 *   - timestamp TOCTOU (single ts source must round-trip)
 *   - missing 'spndrslt' domain tag
 *   - raw 2592-byte witness pubkey vs SHA3-512(wpk) binding
 *   - missing block_height / tx_index / chain_id binding
 */

#include "witness/nodus_witness_spend_preimage.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_domain_tag_byte_exact(void) {
    TEST("domain tag is 'spndrslt'");
    const uint8_t expected[8] = { 's','p','n','d','r','s','l','t' };
    if (memcmp(DNAC_SPEND_RESULT_DOMAIN_TAG, expected, 8) != 0) {
        FAIL("tag mismatch"); return;
    }
    PASS();
}

static void test_preimage_length_constant(void) {
    TEST("preimage length = 221 bytes");
    if (DNAC_SPEND_RESULT_PREIMAGE_LEN != 221) {
        FAIL("constant != 221"); return;
    }
    PASS();
}

static void test_null_inputs_rejected(void) {
    TEST("compute rejects NULL inputs");
    uint8_t buf[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    uint8_t tx[64], wid[32], wpkh[64], cid[32];
    memset(tx, 1, sizeof(tx));
    memset(wid, 2, sizeof(wid));
    memset(wpkh, 3, sizeof(wpkh));
    memset(cid, 4, sizeof(cid));

    if (dnac_compute_spend_result_preimage(NULL, wid, wpkh, cid, 1, 1, 1, 0, buf) != -1) { FAIL("tx"); return; }
    if (dnac_compute_spend_result_preimage(tx, NULL, wpkh, cid, 1, 1, 1, 0, buf) != -1) { FAIL("wid"); return; }
    if (dnac_compute_spend_result_preimage(tx, wid, NULL, cid, 1, 1, 1, 0, buf) != -1) { FAIL("wpkh"); return; }
    if (dnac_compute_spend_result_preimage(tx, wid, wpkh, NULL, 1, 1, 1, 0, buf) != -1) { FAIL("cid"); return; }
    if (dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 1, 1, 1, 0, NULL) != -1) { FAIL("buf"); return; }
    PASS();
}

static void test_layout_offsets(void) {
    TEST("byte-exact field offsets");

    uint8_t tx[64], wid[32], wpkh[64], cid[32];
    for (int i = 0; i < 64; i++) tx[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 32; i++) wid[i] = (uint8_t)(0x80 + i);
    for (int i = 0; i < 64; i++) wpkh[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) cid[i] = (uint8_t)(0xC0 + i);

    uint64_t ts = 0x0123456789ABCDEFULL;
    uint64_t bh = 0xFEDCBA9876543210ULL;
    uint32_t ti = 0xDEADBEEFu;
    uint8_t  status = 0x42;

    uint8_t buf[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    memset(buf, 0xFF, sizeof(buf));
    if (dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, ts, bh, ti, status, buf) != 0) {
        FAIL("compute"); return;
    }

    /* tag */
    const uint8_t tag[8] = { 's','p','n','d','r','s','l','t' };
    if (memcmp(buf, tag, 8) != 0) { FAIL("tag"); return; }
    /* tx_hash */
    if (memcmp(buf + 8, tx, 64) != 0) { FAIL("tx_hash"); return; }
    /* witness_id */
    if (memcmp(buf + 72, wid, 32) != 0) { FAIL("wid"); return; }
    /* wpk_hash */
    if (memcmp(buf + 104, wpkh, 64) != 0) { FAIL("wpkh"); return; }
    /* chain_id */
    if (memcmp(buf + 168, cid, 32) != 0) { FAIL("cid"); return; }
    /* timestamp LE */
    for (int i = 0; i < 8; i++) {
        if (buf[200 + i] != (uint8_t)((ts >> (i * 8)) & 0xFF)) {
            FAIL("ts LE"); return;
        }
    }
    /* block_height LE */
    for (int i = 0; i < 8; i++) {
        if (buf[208 + i] != (uint8_t)((bh >> (i * 8)) & 0xFF)) {
            FAIL("bh LE"); return;
        }
    }
    /* tx_index LE */
    for (int i = 0; i < 4; i++) {
        if (buf[216 + i] != (uint8_t)((ti >> (i * 8)) & 0xFF)) {
            FAIL("ti LE"); return;
        }
    }
    /* status */
    if (buf[220] != status) { FAIL("status"); return; }
    PASS();
}

static void test_distinct_inputs_distinct_preimages(void) {
    TEST("distinct ts/bh/ti/status -> distinct preimages");

    uint8_t tx[64] = {0}, wid[32] = {0}, wpkh[64] = {0}, cid[32] = {0};
    uint8_t a[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    uint8_t b[DNAC_SPEND_RESULT_PREIMAGE_LEN];

    /* timestamp */
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 1, 0, 0, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 2, 0, 0, 0, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("ts not bound"); return; }

    /* block_height */
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 1, 0, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 2, 0, 0, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("bh not bound"); return; }

    /* tx_index */
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 1, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 2, 0, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("ti not bound"); return; }

    /* status */
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 0, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 0, 1, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("status not bound"); return; }

    /* chain_id */
    uint8_t cid2[32];
    memset(cid2, 0xEE, 32);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 0, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid2, 0, 0, 0, 0, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("cid not bound"); return; }

    /* wpk hash */
    uint8_t wpkh2[64];
    memset(wpkh2, 0xDD, 64);
    dnac_compute_spend_result_preimage(tx, wid, wpkh, cid, 0, 0, 0, 0, a);
    dnac_compute_spend_result_preimage(tx, wid, wpkh2, cid, 0, 0, 0, 0, b);
    if (memcmp(a, b, sizeof(a)) == 0) { FAIL("wpkh not bound"); return; }

    PASS();
}

int main(void) {
    printf("DNAC spend_result preimage tests\n");
    printf("================================\n");

    test_domain_tag_byte_exact();
    test_preimage_length_constant();
    test_null_inputs_rejected();
    test_layout_offsets();
    test_distinct_inputs_distinct_preimages();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
