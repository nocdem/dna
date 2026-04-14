/**
 * Nodus — Phase 7.5 / Task 7.5.1 — cert preimage layout tests
 *
 * Locks the byte-exact layout of the 144-byte cert preimage so signers
 * and verifiers always agree. A regression here would silently break
 * sync cert verification in production.
 */

#include "witness/nodus_witness_cert.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_domain_tag_byte_exact(void) {
    TEST("domain tag is 'cert' + 4 NUL");
    const uint8_t expected[8] = { 'c', 'e', 'r', 't', 0, 0, 0, 0 };
    if (memcmp(NODUS_WITNESS_CERT_DOMAIN_TAG, expected, 8) != 0) {
        FAIL("domain tag mismatch");
        return;
    }
    PASS();
}

static void test_preimage_total_length(void) {
    TEST("preimage layout total = 144 bytes");
    if (NODUS_WITNESS_CERT_PREIMAGE_LEN != 144) {
        FAIL("constant != 144");
        return;
    }
    PASS();
}

static void test_null_inputs_rejected(void) {
    TEST("compute_cert_preimage rejects NULL inputs");
    uint8_t buf[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    uint8_t bh[64], vid[32], cid[32];
    memset(bh, 1, sizeof(bh));
    memset(vid, 2, sizeof(vid));
    memset(cid, 3, sizeof(cid));

    if (nodus_witness_compute_cert_preimage(NULL, vid, 1, cid, buf) != -1) {
        FAIL("NULL block_hash"); return;
    }
    if (nodus_witness_compute_cert_preimage(bh, NULL, 1, cid, buf) != -1) {
        FAIL("NULL voter_id"); return;
    }
    if (nodus_witness_compute_cert_preimage(bh, vid, 1, NULL, buf) != -1) {
        FAIL("NULL chain_id"); return;
    }
    if (nodus_witness_compute_cert_preimage(bh, vid, 1, cid, NULL) != -1) {
        FAIL("NULL out_buf"); return;
    }
    PASS();
}

static void test_layout_offsets(void) {
    TEST("preimage offsets: tag/bh/vid/height/cid");

    uint8_t bh[64];
    uint8_t vid[32];
    uint8_t cid[32];
    for (int i = 0; i < 64; i++) bh[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 32; i++) vid[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) cid[i] = (uint8_t)(0xC0 + i);
    uint64_t height = 0x0123456789ABCDEFULL;

    uint8_t buf[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    memset(buf, 0xFF, sizeof(buf));

    if (nodus_witness_compute_cert_preimage(bh, vid, height, cid, buf) != 0) {
        FAIL("compute returned non-zero"); return;
    }

    /* [0..7] tag */
    const uint8_t tag[8] = { 'c','e','r','t',0,0,0,0 };
    if (memcmp(buf, tag, 8) != 0) { FAIL("tag bytes"); return; }

    /* [8..71] block_hash */
    if (memcmp(buf + 8, bh, 64) != 0) { FAIL("block_hash bytes"); return; }

    /* [72..103] voter_id */
    if (memcmp(buf + 72, vid, 32) != 0) { FAIL("voter_id bytes"); return; }

    /* [104..111] height LE */
    for (int i = 0; i < 8; i++) {
        uint8_t expected = (uint8_t)((height >> (i * 8)) & 0xFF);
        if (buf[104 + i] != expected) { FAIL("height LE bytes"); return; }
    }

    /* [112..143] chain_id */
    if (memcmp(buf + 112, cid, 32) != 0) { FAIL("chain_id bytes"); return; }

    PASS();
}

static void test_distinct_height_distinct_preimage(void) {
    TEST("different height -> different preimage");
    uint8_t bh[64] = {0}, vid[32] = {0}, cid[32] = {0};
    uint8_t a[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    uint8_t b[NODUS_WITNESS_CERT_PREIMAGE_LEN];
    nodus_witness_compute_cert_preimage(bh, vid, 1, cid, a);
    nodus_witness_compute_cert_preimage(bh, vid, 2, cid, b);
    if (memcmp(a, b, sizeof(a)) == 0) {
        FAIL("preimages collided across heights");
        return;
    }
    PASS();
}

int main(void) {
    printf("Witness cert preimage layout tests\n");
    printf("==================================\n");

    test_domain_tag_byte_exact();
    test_preimage_total_length();
    test_null_inputs_rejected();
    test_layout_offsets();
    test_distinct_height_distinct_preimage();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
