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

/* CVE-2012-2459 — under the legacy duplicate-odd-sibling Merkle, the
 * tree {A,B,C} and the tree {A,B,C,C} produce identical roots:
 *
 *   legacy({A,B,C})   = pair( pair(A,B), pair(C,C) )
 *   legacy({A,B,C,C}) = pair( pair(A,B), pair(C,C) )
 *
 * RFC 6962 closes the collision because leaves and inner nodes hash
 * to disjoint preimages (0x00 vs 0x01 prefix), and the second tree's
 * right subtree is inner(lh(C), lh(C)) — distinct from lh(C). */
static void test_cve_2012_2459_rejected(void) {
    TEST("CVE-2012-2459: root({A,B,C}) != root({A,B,C,C})");

    uint8_t A[64], B[64], C[64];
    for (int i = 0; i < 64; i++) {
        A[i] = (uint8_t)(0x11 + i);
        B[i] = (uint8_t)(0x55 + i);
        C[i] = (uint8_t)(0x99 + i);
    }

    uint8_t three[3 * 64];
    memcpy(three + 0,  A, 64);
    memcpy(three + 64, B, 64);
    memcpy(three + 128, C, 64);

    uint8_t four[4 * 64];
    memcpy(four + 0,   A, 64);
    memcpy(four + 64,  B, 64);
    memcpy(four + 128, C, 64);
    memcpy(four + 192, C, 64);   /* duplicated last */

    uint8_t r3[64], r4[64];
    if (nodus_witness_merkle_tx_root(three, 3, r3) != 0) { FAIL("3-leaf"); return; }
    if (nodus_witness_merkle_tx_root(four,  4, r4) != 0) { FAIL("4-leaf"); return; }

    if (memcmp(r3, r4, 64) == 0) { FAIL("CVE collision still present"); return; }

    PASS();
}

int main(void) {
    printf("\nNodus RFC 6962 Merkle Domain Tag Tests\n");
    printf("==========================================\n\n");

    test_single_leaf_is_prehashed();
    test_three_leaf_root();
    test_empty_tree_is_leaf_hash_empty();
    test_cve_2012_2459_rejected();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
