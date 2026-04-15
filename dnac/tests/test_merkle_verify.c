/**
 * @file test_merkle_verify.c
 * @brief Fixed-vector test for dnac_merkle_verify_proof.
 *
 * The vector in merkle_vector.inc was produced by the server-side
 * nodus_witness_merkle_build_proof. If test_positive fails, the
 * direction convention between server and client has drifted — debug
 * dnac_merkle_verify_proof before any other work.
 */

#include "dnac/ledger.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "merkle_vector.inc"

static dnac_merkle_proof_t build_proof_from_vector(void) {
    dnac_merkle_proof_t p;
    memset(&p, 0, sizeof(p));

    memcpy(p.leaf_hash, MERKLE_VECTOR_LEAF, DNAC_MERKLE_ROOT_SIZE);
    memcpy(p.root, MERKLE_VECTOR_ROOT, DNAC_MERKLE_ROOT_SIZE);
    p.proof_length = MERKLE_VECTOR_PROOF_LENGTH;

    /* Convert flat server siblings + bitfield positions to dnac struct.
     * Vector bit layout (per Task 14): bit i = sibling direction at level i,
     * leaf-first. directions[i] == 1 → sibling LEFT. */
    for (int i = 0; i < MERKLE_VECTOR_PROOF_LENGTH; i++) {
        memcpy(p.siblings[i],
               MERKLE_VECTOR_SIBLINGS_FLAT + i * DNAC_MERKLE_ROOT_SIZE,
               DNAC_MERKLE_ROOT_SIZE);
        p.directions[i] = (MERKLE_VECTOR_POSITIONS >> i) & 1u;
    }
    return p;
}

static void test_positive(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    if (!dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_positive — DIRECTION CONVENTION DRIFT!\n");
        fprintf(stderr, "  leaf[0..8]:  ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p.leaf_hash[i]);
        fprintf(stderr, "\n  root[0..8]:  ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p.root[i]);
        fprintf(stderr, "\n  directions:  ");
        for (int i = 0; i < p.proof_length; i++) fprintf(stderr, "%d", p.directions[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Try flipping bit order: p.directions[i] = (POSITIONS >> (PROOF_LENGTH - 1 - i)) & 1\n");
        fprintf(stderr, "Or flip the inner_hash argument order in merkle_verify.c\n");
        assert(0);
    }
    printf("PASS test_positive\n");
}

static void test_tampered_sibling(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.siblings[0][0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_sibling — verifier accepted flipped sibling\n");
        assert(0);
    }
    printf("PASS test_tampered_sibling\n");
}

static void test_tampered_root(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.root[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_root\n");
        assert(0);
    }
    printf("PASS test_tampered_root\n");
}

static void test_tampered_leaf(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.leaf_hash[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_tampered_leaf\n");
        assert(0);
    }
    printf("PASS test_tampered_leaf\n");
}

static void test_null_proof(void) {
    if (dnac_merkle_verify_proof(NULL)) {
        fprintf(stderr, "FAIL test_null_proof\n");
        assert(0);
    }
    printf("PASS test_null_proof\n");
}

static void test_invalid_depth(void) {
    dnac_merkle_proof_t p = build_proof_from_vector();
    p.proof_length = -1;
    if (dnac_merkle_verify_proof(&p)) { fprintf(stderr, "FAIL depth=-1\n"); assert(0); }

    p.proof_length = DNAC_MERKLE_MAX_DEPTH + 1;
    if (dnac_merkle_verify_proof(&p)) { fprintf(stderr, "FAIL depth>max\n"); assert(0); }

    printf("PASS test_invalid_depth\n");
}

static void test_single_leaf(void) {
    /* Single-leaf tree: the root IS the leaf-tagged hash of the
     * composite leaf digest. proof_length == 0, no siblings. */
    dnac_merkle_proof_t p;
    memset(&p, 0, sizeof(p));

    /* Arbitrary 64-byte composite leaf digest (not a real UTXO hash,
     * but the verifier doesn't care — it's just bytes). */
    for (int i = 0; i < DNAC_MERKLE_ROOT_SIZE; i++) {
        p.leaf_hash[i] = (uint8_t)(0x5a ^ i);
    }

    /* Hand-compute the expected root: SHA3-512(0x00 || leaf_hash). */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert(md);
    assert(EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1);
    uint8_t prefix = 0x00;
    assert(EVP_DigestUpdate(md, &prefix, 1) == 1);
    assert(EVP_DigestUpdate(md, p.leaf_hash, DNAC_MERKLE_ROOT_SIZE) == 1);
    unsigned int hash_len = 0;
    assert(EVP_DigestFinal_ex(md, p.root, &hash_len) == 1);
    assert(hash_len == DNAC_MERKLE_ROOT_SIZE);
    EVP_MD_CTX_free(md);

    p.proof_length = 0;

    if (!dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_single_leaf — verifier rejected valid single-leaf proof\n");
        assert(0);
    }

    /* Negative case: flip a bit in the root, expect rejection. */
    p.root[0] ^= 0x01;
    if (dnac_merkle_verify_proof(&p)) {
        fprintf(stderr, "FAIL test_single_leaf — verifier accepted tampered single-leaf root\n");
        assert(0);
    }

    printf("PASS test_single_leaf\n");
}

int main(void) {
    test_positive();
    test_tampered_sibling();
    test_tampered_root();
    test_tampered_leaf();
    test_null_proof();
    test_invalid_depth();
    test_single_leaf();
    printf("ALL PASS\n");
    return 0;
}
