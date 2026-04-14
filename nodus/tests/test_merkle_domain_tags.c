/**
 * Nodus — RFC 6962 Merkle domain tag tests
 *
 * Verifies the Phase 2 / Tasks 2.1, 2.2 helpers:
 *
 *   leaf_hash(d)        = SHA3-512(0x00 || d)
 *   inner_hash(L, R)    = SHA3-512(0x01 || L || R)
 *   merkle_root_rfc6962 = §2.1 recursion with k = largest pow2 < n
 *
 * Tasks 2.3 + 2.4 add the public merkle_tx_root wrapper and the
 * CVE-2012-2459 adversarial-pair regression test on top of these.
 */

#include "witness/nodus_witness_merkle.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Reference SHA3-512 helper for the expected-value side of each test. */
static void ref_sha3_512(const uint8_t *data, size_t len, uint8_t out[64]) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(md, data, len);
    unsigned int n = 0;
    EVP_DigestFinal_ex(md, out, &n);
    EVP_MD_CTX_free(md);
}

/* The leaf_hash and inner_hash helpers are static inside
 * nodus_witness_merkle.c. We exercise them indirectly via
 * nodus_witness_merkle_tx_root which leaf-hashes its inputs and then
 * calls merkle_root_rfc6962. */

static void test_single_leaf_is_prehashed(void) {
    TEST("single-leaf root equals leaf_hash(input), not raw input");

    uint8_t raw[64];
    for (int i = 0; i < 64; i++) raw[i] = (uint8_t)(0xAA ^ i);

    uint8_t root[64];
    if (nodus_witness_merkle_tx_root(raw, 1, root) != 0) {
        FAIL("merkle_tx_root returned -1");
        return;
    }

    /* Expected: SHA3-512(0x00 || raw) — the RFC 6962 leaf domain tag. */
    uint8_t preimage[1 + 64];
    preimage[0] = 0x00;
    memcpy(preimage + 1, raw, 64);
    uint8_t expected[64];
    ref_sha3_512(preimage, sizeof(preimage), expected);

    if (memcmp(root, expected, 64) != 0) { FAIL("not 0x00 || raw"); return; }
    if (memcmp(root, raw, 64) == 0)      { FAIL("root == raw (no prefix)"); return; }

    PASS();
}

static void test_three_leaf_root(void) {
    TEST("three-leaf root matches manual inner(inner(lh(A),lh(B)),lh(C))");

    uint8_t A[64], B[64], C[64];
    for (int i = 0; i < 64; i++) {
        A[i] = (uint8_t)(0x01 + i);
        B[i] = (uint8_t)(0x40 + i);
        C[i] = (uint8_t)(0x80 + i);
    }

    /* Layout merkle_tx_root expects: tx_hashes[i*64..(i+1)*64] is leaf i,
     * raw (NOT pre-hashed) — the wrapper applies leaf_hash itself. */
    uint8_t leaves_in[3 * 64];
    memcpy(leaves_in + 0,  A, 64);
    memcpy(leaves_in + 64, B, 64);
    memcpy(leaves_in + 128, C, 64);

    uint8_t got[64];
    if (nodus_witness_merkle_tx_root(leaves_in, 3, got) != 0) {
        FAIL("merkle_tx_root returned -1");
        return;
    }

    /* Compute expected manually with reference SHA3 */
    uint8_t lhA[64], lhB[64], lhC[64];
    {
        uint8_t pre[65];
        pre[0] = 0x00;
        memcpy(pre + 1, A, 64); ref_sha3_512(pre, 65, lhA);
        memcpy(pre + 1, B, 64); ref_sha3_512(pre, 65, lhB);
        memcpy(pre + 1, C, 64); ref_sha3_512(pre, 65, lhC);
    }

    /* k = 2 (largest pow2 < 3). Left subtree = inner(lhA, lhB).
     * Right subtree = lhC (single leaf, returned as-is). */
    uint8_t left[64];
    {
        uint8_t pre[1 + 128];
        pre[0] = 0x01;
        memcpy(pre + 1, lhA, 64);
        memcpy(pre + 65, lhB, 64);
        ref_sha3_512(pre, 129, left);
    }
    uint8_t expected[64];
    {
        uint8_t pre[1 + 128];
        pre[0] = 0x01;
        memcpy(pre + 1, left, 64);
        memcpy(pre + 65, lhC, 64);
        ref_sha3_512(pre, 129, expected);
    }

    if (memcmp(got, expected, 64) != 0) { FAIL("root mismatch"); return; }
    PASS();
}

static void test_empty_tree_is_leaf_hash_empty(void) {
    TEST("empty-tree root equals leaf_hash(\"\")");

    uint8_t got[64];
    if (nodus_witness_merkle_tx_root(NULL, 0, got) != 0) {
        FAIL("merkle_tx_root returned -1");
        return;
    }

    uint8_t expected[64];
    const uint8_t prefix = 0x00;
    ref_sha3_512(&prefix, 1, expected);

    if (memcmp(got, expected, 64) != 0) { FAIL("not SHA3(0x00)"); return; }
    PASS();
}

int main(void) {
    printf("\nNodus RFC 6962 Merkle Domain Tag Tests\n");
    printf("==========================================\n\n");

    test_single_leaf_is_prehashed();
    test_three_leaf_root();
    test_empty_tree_is_leaf_hash_empty();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
