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

int main(void) {
    test_positive();
    test_tampered_sibling();
    test_tampered_root();
    test_tampered_leaf();
    test_null_proof();
    test_invalid_depth();
    printf("ALL PASS\n");
    return 0;
}
