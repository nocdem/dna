/**
 * @file test_anchor_verify.c
 * @brief Runtime-generated test for dnac_anchor_verify.
 *
 * Generates 4 real Dilithium5 keypairs, constructs a block, signs with 3 of
 * them (exceeds quorum=3 for N=4), verifies the anchor, then flips various
 * bits to test rejection paths.
 *
 * N=4 -> f=1 -> quorum = (2*4)/3 + 1 = 3.
 */

#include "dnac/ledger.h"
#include "dnac/block.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N_WITNESSES 4
#define QUORUM      3    /* (2*4)/3 + 1 = 3 */

/* Keypairs generated once at startup and reused across test cases. */
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

/* Populate trust state with the test roster. */
static void setup_trust(dnac_trusted_state_t *trust) {
    memset(trust, 0, sizeof(*trust));
    trust->chain_def.witness_count = N_WITNESSES;
    trust->chain_def.max_active_witnesses = 21;
    for (int i = 0; i < N_WITNESSES; i++) {
        memcpy(trust->chain_def.witness_pubkeys[i], pubkeys[i], DNAC_PUBKEY_SIZE);
    }
    strcpy(trust->chain_def.chain_name, "test");
    trust->chain_def.protocol_version = 1;
    trust->chain_def.token_decimals = 8;
}

/* Build a synthetic non-genesis block and compute its hash. */
static void build_block(dnac_block_t *block) {
    memset(block, 0, sizeof(*block));
    block->block_height = 1;
    for (int i = 0; i < DNAC_BLOCK_HASH_SIZE; i++) {
        block->state_root[i] = (uint8_t)i;
        block->tx_root[i]    = (uint8_t)(0xff - i);
    }
    block->tx_count = 1;
    block->timestamp = 1234567890;
    block->is_genesis = false;

    int rc = dnac_block_compute_hash(block);
    assert(rc == 0);
}

/* Sign block_hash with witness i. */
static void sign_block(const dnac_block_t *block, int witness_idx,
                       dnac_witness_signature_t *out) {
    /* Fingerprint: first DNAC_WITNESS_ID_SIZE bytes of SHA3-512(pubkey) */
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];
    int rc = qgp_sha3_512(pubkeys[witness_idx], DNAC_PUBKEY_SIZE, fp);
    assert(rc == 0);
    memcpy(out->signer_id, fp, DNAC_WITNESS_ID_SIZE);

    size_t siglen = 0;
    rc = qgp_dsa87_sign(out->signature, &siglen,
                         block->block_hash, DNAC_BLOCK_HASH_SIZE,
                         seckeys[witness_idx]);
    assert(rc == 0);
    /* Dilithium5 signatures have a fixed max size; buffer is sized to it. */
    assert(siglen == DNAC_DILITHIUM5_SIG_SIZE);
}

/* Build a valid anchor with `n_sigs` witnesses signing (indices 0..n_sigs-1). */
static dnac_block_anchor_t *build_anchor(int n_sigs) {
    static dnac_block_anchor_t anchor;  /* large, static to avoid stack blow */
    memset(&anchor, 0, sizeof(anchor));

    build_block(&anchor.header);
    for (int i = 0; i < n_sigs; i++) {
        sign_block(&anchor.header, i, &anchor.sigs[i]);
    }
    anchor.sig_count = n_sigs;
    return &anchor;
}

static void test_positive(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    dnac_block_anchor_t *anchor = build_anchor(QUORUM);
    if (!dnac_anchor_verify(anchor, &trust)) {
        fprintf(stderr, "FAIL test_positive\n");
        assert(0);
    }
    printf("PASS test_positive\n");
}

static void test_below_quorum(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    dnac_block_anchor_t *anchor = build_anchor(QUORUM - 1);
    if (dnac_anchor_verify(anchor, &trust)) {
        fprintf(stderr, "FAIL test_below_quorum - accepted only %d sigs\n", QUORUM - 1);
        assert(0);
    }
    printf("PASS test_below_quorum\n");
}

static void test_tampered_sig(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    dnac_block_anchor_t *anchor = build_anchor(QUORUM);
    anchor->sigs[0].signature[100] ^= 0x01;
    /* One sig now invalid -> only QUORUM-1 valid -> below threshold */
    if (dnac_anchor_verify(anchor, &trust)) {
        fprintf(stderr, "FAIL test_tampered_sig\n");
        assert(0);
    }
    printf("PASS test_tampered_sig\n");
}

static void test_unknown_signer(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    dnac_block_anchor_t *anchor = build_anchor(QUORUM);
    /* Replace signer_id[0] with random bytes -> no roster match -> drops below quorum */
    memset(anchor->sigs[0].signer_id, 0xab, DNAC_WITNESS_ID_SIZE);
    if (dnac_anchor_verify(anchor, &trust)) {
        fprintf(stderr, "FAIL test_unknown_signer\n");
        assert(0);
    }
    printf("PASS test_unknown_signer\n");
}

static void test_duplicate_signer(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    /* Sign with witness 0 three times, then witness 1 once.
     * Dedup -> 2 unique roster members -> below quorum 3. */
    static dnac_block_anchor_t anchor;
    memset(&anchor, 0, sizeof(anchor));
    build_block(&anchor.header);
    sign_block(&anchor.header, 0, &anchor.sigs[0]);
    sign_block(&anchor.header, 0, &anchor.sigs[1]);
    sign_block(&anchor.header, 0, &anchor.sigs[2]);
    sign_block(&anchor.header, 1, &anchor.sigs[3]);
    anchor.sig_count = 4;
    if (dnac_anchor_verify(&anchor, &trust)) {
        fprintf(stderr, "FAIL test_duplicate_signer - dedup broken\n");
        assert(0);
    }
    printf("PASS test_duplicate_signer\n");
}

static void test_tampered_block_hash(void) {
    dnac_trusted_state_t trust;
    setup_trust(&trust);
    dnac_block_anchor_t *anchor = build_anchor(QUORUM);
    /* Flip a bit in stored block_hash -> recompute will catch it */
    anchor->header.block_hash[0] ^= 0x01;
    if (dnac_anchor_verify(anchor, &trust)) {
        fprintf(stderr, "FAIL test_tampered_block_hash\n");
        assert(0);
    }
    printf("PASS test_tampered_block_hash\n");
}

int main(void) {
    gen_keypairs();
    test_positive();
    test_below_quorum();
    test_tampered_sig();
    test_unknown_signer();
    test_duplicate_signer();
    test_tampered_block_hash();
    printf("ALL PASS\n");
    return 0;
}
