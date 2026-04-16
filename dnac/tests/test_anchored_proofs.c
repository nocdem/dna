/**
 * @file test_anchored_proofs.c
 * @brief End-to-end test for the anchored Merkle proof verification pipeline.
 *
 * Phase 9 (Tasks 50-53). Composes dnac_genesis_verify + dnac_anchor_verify +
 * dnac_utxo_verify_anchored / dnac_tx_verify_anchored in one in-process flow.
 *
 * No network, no witness instance — all inputs are hand-constructed so the
 * test exercises only the verifier side. Server-side Merkle tree builders
 * are covered separately by test_merkle_verify.c's fixed vector.
 *
 * Cases:
 *   1. test_full_pipeline_positive  — genesis + anchor + UTXO proof all pass
 *   2. test_wrong_chain_id           — genesis rejected with bad chain_id
 *   3. test_anchor_below_quorum      — utxo_verify_anchored false with <quorum sigs
 *   4. test_tampered_proof_sibling   — utxo_verify_anchored false on flipped sibling
 *   5. test_proof_root_mismatch      — utxo_verify_anchored false when proof.root != state_root
 *   6. test_tx_root_pipeline         — dnac_tx_verify_anchored positive against tx_root
 */

/* Force assertions ON regardless of -DNDEBUG (Release builds compile them out
 * by default). Test correctness is not optional. */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include "dnac/ledger.h"
#include "dnac/block.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <openssl/evp.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_WITNESSES 4
#define QUORUM      3    /* N=4 -> f=1 -> 2f+1 = 3 */

/* Persistent keypairs shared across all test cases. */
static uint8_t pubkeys[N_WITNESSES][DNAC_PUBKEY_SIZE];
static uint8_t seckeys[N_WITNESSES][QGP_DSA87_SECRETKEYBYTES];

static void gen_keypairs(void) {
    for (int i = 0; i < N_WITNESSES; i++) {
        int rc = qgp_dsa87_keypair(pubkeys[i], seckeys[i]);
        if (rc != 0) {
            fprintf(stderr, "FAIL: qgp_dsa87_keypair %d rc=%d\n", i, rc);
            exit(1);
        }
    }
}

/* Build a genesis block carrying the 4-witness roster and compute its hash. */
static void build_genesis_block(dnac_block_t *g) {
    memset(g, 0, sizeof(*g));
    g->block_height = 0;
    g->is_genesis = true;
    g->tx_count = 1;
    g->timestamp = 1700000000ULL;

    dnac_chain_definition_t *cd = &g->chain_def;
    strcpy(cd->chain_name, "anchored-e2e");
    cd->protocol_version = 1;
    cd->witness_count = N_WITNESSES;
    cd->max_active_witnesses = 21;
    for (int i = 0; i < N_WITNESSES; i++) {
        memcpy(cd->witness_pubkeys[i], pubkeys[i], DNAC_PUBKEY_SIZE);
    }
    cd->block_interval_sec = 5;
    cd->max_txs_per_block = 10;
    cd->view_change_timeout_ms = 5000;
    strcpy(cd->token_symbol, "DNAC");
    cd->token_decimals = 8;
    cd->initial_supply_raw = 100;

    int rc = dnac_block_compute_hash(g);
    assert(rc == 0);
}

/* Compute the SHA3-512(0x00 || leaf_hash) expected root for a single-leaf tree. */
static void single_leaf_root(const uint8_t *leaf_hash, uint8_t *root_out) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert(md);
    assert(EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1);
    uint8_t prefix = 0x00;
    assert(EVP_DigestUpdate(md, &prefix, 1) == 1);
    assert(EVP_DigestUpdate(md, leaf_hash, DNAC_MERKLE_ROOT_SIZE) == 1);
    unsigned int hash_len = 0;
    assert(EVP_DigestFinal_ex(md, root_out, &hash_len) == 1);
    assert(hash_len == DNAC_MERKLE_ROOT_SIZE);
    EVP_MD_CTX_free(md);
}

/* Build a non-genesis block (height 1) whose state_root == expected_state_root
 * and tx_root == expected_tx_root, then compute its hash. */
static void build_anchored_block(dnac_block_t *b,
                                  const uint8_t *expected_state_root,
                                  const uint8_t *expected_tx_root,
                                  const uint8_t *prev_hash) {
    memset(b, 0, sizeof(*b));
    b->block_height = 1;
    b->is_genesis = false;
    b->tx_count = 1;
    b->timestamp = 1700000005ULL;
    memcpy(b->prev_block_hash, prev_hash, DNAC_BLOCK_HASH_SIZE);
    memcpy(b->state_root, expected_state_root, DNAC_BLOCK_HASH_SIZE);
    memcpy(b->tx_root, expected_tx_root, DNAC_BLOCK_HASH_SIZE);
    int rc = dnac_block_compute_hash(b);
    assert(rc == 0);
}

/* Sign block_hash with witness i. */
static void sign_block(const dnac_block_t *block, int witness_idx,
                       dnac_witness_signature_t *out) {
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];
    int rc = qgp_sha3_512(pubkeys[witness_idx], DNAC_PUBKEY_SIZE, fp);
    assert(rc == 0);
    memcpy(out->signer_id, fp, DNAC_WITNESS_ID_SIZE);

    size_t siglen = 0;
    rc = qgp_dsa87_sign(out->signature, &siglen,
                         block->block_hash, DNAC_BLOCK_HASH_SIZE,
                         seckeys[witness_idx]);
    assert(rc == 0);
    assert(siglen == DNAC_DILITHIUM5_SIG_SIZE);
}

/* Build a block anchor with the first n_sigs witnesses signing. */
static void build_anchor_from_block(dnac_block_anchor_t *a,
                                     const dnac_block_t *block,
                                     int n_sigs) {
    memset(a, 0, sizeof(*a));
    memcpy(&a->header, block, sizeof(*block));
    for (int i = 0; i < n_sigs; i++) {
        sign_block(&a->header, i, &a->sigs[i]);
    }
    a->sig_count = n_sigs;
}

/* Fill a merkle_proof_t as a single-leaf tree (proof_length = 0). */
static void build_single_leaf_proof(dnac_merkle_proof_t *p, uint8_t leaf_byte) {
    memset(p, 0, sizeof(*p));
    for (int i = 0; i < DNAC_MERKLE_ROOT_SIZE; i++) {
        p->leaf_hash[i] = (uint8_t)(leaf_byte ^ i);
    }
    single_leaf_root(p->leaf_hash, p->root);
    p->proof_length = 0;
}

/* Convenience: bootstrap a verified trusted_state from freshly-encoded genesis. */
static void bootstrap_trust(dnac_trusted_state_t *trust,
                             uint8_t chain_id_out[DNAC_BLOCK_HASH_SIZE]) {
    static dnac_block_t genesis;
    build_genesis_block(&genesis);

    static uint8_t buf[65536];
    size_t len = 0;
    assert(dnac_block_encode(&genesis, buf, sizeof(buf), &len) == 0);

    memcpy(chain_id_out, genesis.block_hash, DNAC_BLOCK_HASH_SIZE);
    assert(dnac_genesis_verify(buf, len, chain_id_out, trust));
    assert(memcmp(trust->chain_id, chain_id_out, DNAC_BLOCK_HASH_SIZE) == 0);
    assert(trust->chain_def.witness_count == N_WITNESSES);
}

/* ===== Test cases ======================================================= */

static void test_full_pipeline_positive(void) {
    /* 1) Bootstrap trust from genesis. */
    dnac_trusted_state_t trust;
    uint8_t chain_id[DNAC_BLOCK_HASH_SIZE];
    bootstrap_trust(&trust, chain_id);

    /* 2) Build a single-leaf UTXO proof and derive its root. */
    static dnac_merkle_proof_t proof;
    build_single_leaf_proof(&proof, 0x5a);

    /* 3) Build a non-genesis block whose state_root EQUALS proof.root.
     *    tx_root is arbitrary (0xaa) for this test. */
    uint8_t tx_root[DNAC_BLOCK_HASH_SIZE];
    memset(tx_root, 0xaa, sizeof(tx_root));
    static dnac_block_t anchored;
    build_anchored_block(&anchored, proof.root, tx_root, chain_id);

    /* 4) Build an anchor with 3 (quorum) signatures. */
    static dnac_block_anchor_t anchor;
    build_anchor_from_block(&anchor, &anchored, QUORUM);

    /* 5) Full anchored verification MUST pass. */
    if (!dnac_utxo_verify_anchored(&proof, &anchor, &trust)) {
        fprintf(stderr, "FAIL test_full_pipeline_positive\n");
        assert(0);
    }
    printf("PASS test_full_pipeline_positive\n");
}

static void test_wrong_chain_id(void) {
    /* Encode a real genesis, then try to verify against a flipped chain_id. */
    static dnac_block_t genesis;
    build_genesis_block(&genesis);

    static uint8_t buf[65536];
    size_t len = 0;
    assert(dnac_block_encode(&genesis, buf, sizeof(buf), &len) == 0);

    uint8_t wrong_id[DNAC_BLOCK_HASH_SIZE];
    memcpy(wrong_id, genesis.block_hash, DNAC_BLOCK_HASH_SIZE);
    wrong_id[7] ^= 0x01;

    dnac_trusted_state_t trust;
    if (dnac_genesis_verify(buf, len, wrong_id, &trust)) {
        fprintf(stderr, "FAIL test_wrong_chain_id — accepted wrong chain_id\n");
        assert(0);
    }
    printf("PASS test_wrong_chain_id\n");
}

static void test_anchor_below_quorum(void) {
    dnac_trusted_state_t trust;
    uint8_t chain_id[DNAC_BLOCK_HASH_SIZE];
    bootstrap_trust(&trust, chain_id);

    static dnac_merkle_proof_t proof;
    build_single_leaf_proof(&proof, 0x33);

    uint8_t tx_root[DNAC_BLOCK_HASH_SIZE];
    memset(tx_root, 0xbb, sizeof(tx_root));
    static dnac_block_t anchored;
    build_anchored_block(&anchored, proof.root, tx_root, chain_id);

    /* Only QUORUM-1 signatures — anchor_verify must reject. */
    static dnac_block_anchor_t anchor;
    build_anchor_from_block(&anchor, &anchored, QUORUM - 1);

    if (dnac_utxo_verify_anchored(&proof, &anchor, &trust)) {
        fprintf(stderr, "FAIL test_anchor_below_quorum — accepted sub-quorum anchor\n");
        assert(0);
    }
    printf("PASS test_anchor_below_quorum\n");
}

static void test_tampered_proof_sibling(void) {
    dnac_trusted_state_t trust;
    uint8_t chain_id[DNAC_BLOCK_HASH_SIZE];
    bootstrap_trust(&trust, chain_id);

    /* Build a two-leaf Merkle tree so we actually have a sibling to flip.
     * We cheat: fake the sibling and compute the resulting root manually. */
    static dnac_merkle_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    for (int i = 0; i < DNAC_MERKLE_ROOT_SIZE; i++) {
        proof.leaf_hash[i] = (uint8_t)(0x11 ^ i);
        proof.siblings[0][i] = (uint8_t)(0x22 ^ i);
    }
    proof.directions[0] = 0;   /* sibling RIGHT, cur LEFT */
    proof.proof_length = 1;

    /* Compute expected root: inner_hash(leaf_tag(leaf), sibling)
     *   leaf_tag(x)       = SHA3-512(0x00 || x)
     *   inner_hash(L, R)  = SHA3-512(0x01 || L || R)
     */
    uint8_t leaf_tagged[DNAC_MERKLE_ROOT_SIZE];
    single_leaf_root(proof.leaf_hash, leaf_tagged);

    {
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        assert(md);
        assert(EVP_DigestInit_ex(md, EVP_sha3_512(), NULL) == 1);
        uint8_t prefix = 0x01;
        assert(EVP_DigestUpdate(md, &prefix, 1) == 1);
        assert(EVP_DigestUpdate(md, leaf_tagged, DNAC_MERKLE_ROOT_SIZE) == 1);
        assert(EVP_DigestUpdate(md, proof.siblings[0], DNAC_MERKLE_ROOT_SIZE) == 1);
        unsigned int hash_len = 0;
        assert(EVP_DigestFinal_ex(md, proof.root, &hash_len) == 1);
        assert(hash_len == DNAC_MERKLE_ROOT_SIZE);
        EVP_MD_CTX_free(md);
    }

    /* Sanity: untampered proof should verify against itself. */
    assert(dnac_merkle_verify_proof(&proof));

    /* Anchor the root. */
    uint8_t tx_root[DNAC_BLOCK_HASH_SIZE];
    memset(tx_root, 0xcc, sizeof(tx_root));
    static dnac_block_t anchored;
    build_anchored_block(&anchored, proof.root, tx_root, chain_id);
    static dnac_block_anchor_t anchor;
    build_anchor_from_block(&anchor, &anchored, QUORUM);

    /* Now flip a bit in the sibling → proof must fail. */
    proof.siblings[0][5] ^= 0x01;
    if (dnac_utxo_verify_anchored(&proof, &anchor, &trust)) {
        fprintf(stderr, "FAIL test_tampered_proof_sibling — accepted flipped sibling\n");
        assert(0);
    }
    printf("PASS test_tampered_proof_sibling\n");
}

static void test_proof_root_mismatch(void) {
    dnac_trusted_state_t trust;
    uint8_t chain_id[DNAC_BLOCK_HASH_SIZE];
    bootstrap_trust(&trust, chain_id);

    static dnac_merkle_proof_t proof;
    build_single_leaf_proof(&proof, 0x77);

    /* Block's state_root does NOT match proof.root. */
    uint8_t different_root[DNAC_BLOCK_HASH_SIZE];
    memset(different_root, 0xde, sizeof(different_root));
    uint8_t tx_root[DNAC_BLOCK_HASH_SIZE];
    memset(tx_root, 0xad, sizeof(tx_root));

    static dnac_block_t anchored;
    build_anchored_block(&anchored, different_root, tx_root, chain_id);

    static dnac_block_anchor_t anchor;
    build_anchor_from_block(&anchor, &anchored, QUORUM);

    if (dnac_utxo_verify_anchored(&proof, &anchor, &trust)) {
        fprintf(stderr, "FAIL test_proof_root_mismatch — accepted mismatched root\n");
        assert(0);
    }
    printf("PASS test_proof_root_mismatch\n");
}

static void test_tx_root_pipeline(void) {
    dnac_trusted_state_t trust;
    uint8_t chain_id[DNAC_BLOCK_HASH_SIZE];
    bootstrap_trust(&trust, chain_id);

    /* Build a single-leaf TX proof (leaf = tx_hash). */
    static dnac_merkle_proof_t proof;
    build_single_leaf_proof(&proof, 0x9c);

    /* Block's tx_root must match proof.root; state_root is arbitrary. */
    uint8_t state_root[DNAC_BLOCK_HASH_SIZE];
    memset(state_root, 0xee, sizeof(state_root));
    static dnac_block_t anchored;
    build_anchored_block(&anchored, state_root, proof.root, chain_id);

    static dnac_block_anchor_t anchor;
    build_anchor_from_block(&anchor, &anchored, QUORUM);

    if (!dnac_tx_verify_anchored(&proof, &anchor, &trust)) {
        fprintf(stderr, "FAIL test_tx_root_pipeline\n");
        assert(0);
    }
    printf("PASS test_tx_root_pipeline\n");
}

int main(void) {
    gen_keypairs();
    test_full_pipeline_positive();
    test_wrong_chain_id();
    test_anchor_below_quorum();
    test_tampered_proof_sibling();
    test_proof_root_mismatch();
    test_tx_root_pipeline();
    printf("ALL PASS\n");
    return 0;
}
