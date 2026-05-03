/**
 * Nodus — compute_block_hash helper tests
 *
 * Phase 5 / Tasks 5.1 + 5.4 — unit tests for the shared
 * nodus_witness_compute_block_hash pure function that both block_add
 * and sync compute_prev_hash call.
 *
 * Updated 2026-05-03 (PR 2): timestamp removed from preimage; preimage
 * shrunk from 244 to 236 bytes. See
 * docs/plans/2026-05-03-pr2-timestamp-determinism-impl.md.
 *
 * Scenarios:
 *   1. Deterministic — same inputs → same output
 *   2. Sensitivity — any single-byte flip in any non-timestamp field
 *      changes the output (verifies every preimage field enters the
 *      SHA3 input). Timestamp independence is covered separately by
 *      test_block_hash_timestamp_excluded.c.
 *   3. Reference formula — bit-exact match against a manual SHA3-512
 *      of the canonical 236-byte preimage.
 */

#include "witness/nodus_witness_db.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void fill(uint8_t *p, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i);
}

static void test_deterministic(void) {
    TEST("compute_block_hash is deterministic");

    uint8_t prev_hash[64], state_root[64], tx_root[64], proposer[32];
    fill(prev_hash, 64, 0x11);
    fill(state_root, 64, 0x22);
    fill(tx_root, 64, 0x33);
    fill(proposer, 32, 0x44);

    uint8_t h1[64], h2[64];
    nodus_witness_compute_block_hash(5, prev_hash, state_root, tx_root,
                                      10, proposer, h1);
    nodus_witness_compute_block_hash(5, prev_hash, state_root, tx_root,
                                      10, proposer, h2);

    if (memcmp(h1, h2, 64) != 0) { FAIL("two calls differed"); return; }
    PASS();
}

/* Helper: compute, flip one byte of one field, recompute, assert change. */
#define FLIP_TEST(field_name, buf, offset) do {                              \
    uint8_t h_before[64], h_after[64];                                       \
    nodus_witness_compute_block_hash(height, prev_hash, state_root, tx_root, \
                                      tx_count, proposer, h_before);        \
    (buf)[offset] ^= 0x01;                                                   \
    nodus_witness_compute_block_hash(height, prev_hash, state_root, tx_root, \
                                      tx_count, proposer, h_after);         \
    if (memcmp(h_before, h_after, 64) == 0) {                                \
        FAIL("flipping " field_name " did not change hash"); return;         \
    }                                                                        \
    (buf)[offset] ^= 0x01;                                                   \
} while (0)

static void test_each_field_affects_hash(void) {
    TEST("every preimage field flip changes the hash");

    uint64_t height = 7;
    uint32_t tx_count = 3;
    uint8_t prev_hash[64], state_root[64], tx_root[64], proposer[32];
    fill(prev_hash, 64, 0xA0);
    fill(state_root, 64, 0xB0);
    fill(tx_root, 64, 0xC0);
    fill(proposer, 32, 0xD0);

    FLIP_TEST("prev_hash",  prev_hash,  0);
    FLIP_TEST("prev_hash",  prev_hash,  63);
    FLIP_TEST("state_root", state_root, 0);
    FLIP_TEST("state_root", state_root, 63);
    FLIP_TEST("tx_root",    tx_root,    0);
    FLIP_TEST("tx_root",    tx_root,    63);
    FLIP_TEST("proposer",   proposer,   0);
    FLIP_TEST("proposer",   proposer,   31);

    /* Scalar fields: change directly. NOTE (PR 2): timestamp is NOT
     * tested here — it's deliberately excluded from the preimage and
     * tested in test_block_hash_timestamp_excluded.c. */
    uint8_t h_before[64], h_after[64];
    nodus_witness_compute_block_hash(height, prev_hash, state_root, tx_root,
                                      tx_count, proposer, h_before);

    nodus_witness_compute_block_hash(height + 1, prev_hash, state_root, tx_root,
                                      tx_count, proposer, h_after);
    if (memcmp(h_before, h_after, 64) == 0) { FAIL("height not in preimage"); return; }

    nodus_witness_compute_block_hash(height, prev_hash, state_root, tx_root,
                                      tx_count + 1, proposer, h_after);
    if (memcmp(h_before, h_after, 64) == 0) { FAIL("tx_count not in preimage"); return; }

    PASS();
}

static void test_matches_reference_formula(void) {
    TEST("hash matches reference SHA3-512 of the expected 236-byte preimage");

    uint64_t height = 42;
    uint32_t tx_count = 5;
    uint8_t prev_hash[64], state_root[64], tx_root[64], proposer[32];
    for (int i = 0; i < 64; i++) {
        prev_hash[i]  = (uint8_t)(0x10 + i);
        state_root[i] = (uint8_t)(0x20 + i);
        tx_root[i]    = (uint8_t)(0x30 + i);
    }
    for (int i = 0; i < 32; i++) proposer[i] = (uint8_t)(0xF0 + i);

    uint8_t got[64];
    nodus_witness_compute_block_hash(height, prev_hash, state_root, tx_root,
                                      tx_count, proposer, got);

    /* Build the expected preimage manually, then SHA3 it. PR 2: 236 bytes
     * (was 244 before timestamp drop). */
    uint8_t buf[236];
    size_t off = 0;
    for (int i = 0; i < 8; i++) buf[off++] = (uint8_t)((height >> (i*8)) & 0xff);
    memcpy(buf + off, prev_hash, 64);  off += 64;
    memcpy(buf + off, state_root, 64); off += 64;
    memcpy(buf + off, tx_root, 64);    off += 64;
    for (int i = 0; i < 4; i++) buf[off++] = (uint8_t)((tx_count >> (i*8)) & 0xff);
    memcpy(buf + off, proposer, 32);   off += 32;

    uint8_t expected[64];
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(md, buf, off);
    unsigned int n = 0;
    EVP_DigestFinal_ex(md, expected, &n);
    EVP_MD_CTX_free(md);

    if (memcmp(got, expected, 64) != 0) { FAIL("hash != manual SHA3 preimage"); return; }
    PASS();
}

int main(void) {
    printf("\nNodus compute_block_hash Helper Tests\n");
    printf("==========================================\n\n");

    test_deterministic();
    test_each_field_affects_hash();
    test_matches_reference_formula();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
