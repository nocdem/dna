/**
 * @file test_multi_asset.c
 * @brief Tests for multi-asset TX foundation (signers[], per-token balance)
 *
 * Offline tests — no network, no DHT, no database.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/hash/qgp_sha3.h"

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    printf("  TEST: %s... ", name); \
    fflush(stdout); \
    tests_run++; \
} while(0)

#define PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while(0)

#define FAIL(reason) do { \
    printf("FAIL: %s\n", reason); \
    tests_failed++; \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { FAIL(msg); return; } \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { FAIL(msg); return; } \
} while(0)

#define ASSERT_NEQ(a, b, msg) do { \
    if ((a) == (b)) { FAIL(msg); return; } \
} while(0)

/* ============================================================================
 * Helper: create a fake UTXO for testing (no DB needed)
 * ========================================================================== */

static void make_fake_utxo(dnac_utxo_t *utxo, uint64_t amount,
                           const uint8_t *token_id) {
    memset(utxo, 0, sizeof(*utxo));
    utxo->version = DNAC_PROTOCOL_VERSION;
    utxo->amount = amount;
    utxo->status = DNAC_UTXO_UNSPENT;
    qgp_randombytes(utxo->nullifier, DNAC_NULLIFIER_SIZE);
    qgp_randombytes(utxo->tx_hash, DNAC_TX_HASH_SIZE);
    snprintf(utxo->owner_fingerprint, DNAC_FINGERPRINT_SIZE, "deadbeef%0120d", 0);
    if (token_id) {
        memcpy(utxo->token_id, token_id, DNAC_TOKEN_ID_SIZE);
    }
    /* else token_id stays all-zeros = native DNAC */
}

/* ============================================================================
 * Test 1: dnac_tx_add_signer — count management + overflow
 * ========================================================================== */

static void test_add_signer(void) {
    TEST("add_signer: count management + MAX_SIGNERS overflow");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    /* Initially zero signers */
    ASSERT_EQ(tx->signer_count, 0, "initial signer_count should be 0");

    /* Add signers up to MAX */
    uint8_t dummy_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t dummy_sig[DNAC_SIGNATURE_SIZE];
    memset(dummy_pubkey, 0xAA, DNAC_PUBKEY_SIZE);
    memset(dummy_sig, 0xBB, DNAC_SIGNATURE_SIZE);

    for (int i = 0; i < DNAC_TX_MAX_SIGNERS; i++) {
        dummy_pubkey[0] = (uint8_t)i; /* make each distinct */
        int rc = dnac_tx_add_signer(tx, dummy_pubkey, dummy_sig);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_signer should succeed within MAX");
        ASSERT_EQ(tx->signer_count, (uint8_t)(i + 1), "signer_count mismatch");
    }

    /* One more should fail */
    int rc = dnac_tx_add_signer(tx, dummy_pubkey, dummy_sig);
    ASSERT_NEQ(rc, DNAC_SUCCESS, "add_signer beyond MAX should fail");
    ASSERT_EQ(tx->signer_count, DNAC_TX_MAX_SIGNERS, "signer_count should not exceed MAX");

    /* Verify stored pubkeys */
    for (int i = 0; i < DNAC_TX_MAX_SIGNERS; i++) {
        ASSERT_EQ(tx->signers[i].pubkey[0], (uint8_t)i, "stored pubkey byte mismatch");
    }

    dnac_free_transaction(tx);
    PASS();
}

/* ============================================================================
 * Test 2: serialize/deserialize roundtrip with 1 signer
 * ========================================================================== */

static void test_serialize_roundtrip_single_signer(void) {
    TEST("serialize roundtrip: single signer with real Dilithium5 keypair");

    /* Generate real keypair */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t privkey[4896];
    int rc = qgp_dsa87_keypair(pubkey, privkey);
    ASSERT_EQ(rc, 0, "keypair generation failed");

    /* Build TX */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    dnac_utxo_t utxo;
    make_fake_utxo(&utxo, 1000, NULL);
    rc = dnac_tx_add_input(tx, &utxo);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed");

    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    rc = dnac_tx_add_output(tx, "recipient_fp_aabbccdd", 1000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed");

    /* Sign as signer[0] via finalize */
    rc = dnac_tx_finalize(tx, privkey, pubkey);
    ASSERT_EQ(rc, DNAC_SUCCESS, "finalize failed");
    ASSERT_EQ(tx->signer_count, 1, "signer_count should be 1 after finalize");

    /* Serialize */
    uint8_t buffer[131072];
    size_t written = 0;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "serialize failed");
    ASSERT_TRUE(written > 0, "no data written");

    /* Deserialize */
    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "deserialize failed");
    ASSERT_TRUE(tx2 != NULL, "deserialized tx is NULL");

    /* Verify signer data roundtripped */
    ASSERT_EQ(tx2->signer_count, 1, "deserialized signer_count should be 1");
    ASSERT_TRUE(memcmp(tx2->signers[0].pubkey, pubkey, DNAC_PUBKEY_SIZE) == 0,
                "deserialized pubkey mismatch");
    ASSERT_TRUE(memcmp(tx2->signers[0].signature, tx->signers[0].signature,
                       DNAC_SIGNATURE_SIZE) == 0,
                "deserialized signature mismatch");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

/* ============================================================================
 * Test 3: serialize/deserialize roundtrip with 2 signers
 * ========================================================================== */

static void test_serialize_roundtrip_two_signers(void) {
    TEST("serialize roundtrip: two signers");

    /* Generate two keypairs */
    uint8_t pubkey1[DNAC_PUBKEY_SIZE], privkey1[4896];
    uint8_t pubkey2[DNAC_PUBKEY_SIZE], privkey2[4896];
    int rc = qgp_dsa87_keypair(pubkey1, privkey1);
    ASSERT_EQ(rc, 0, "keypair1 generation failed");
    rc = qgp_dsa87_keypair(pubkey2, privkey2);
    ASSERT_EQ(rc, 0, "keypair2 generation failed");

    /* Build TX with 2 inputs (one per signer) */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    dnac_utxo_t utxo1, utxo2;
    make_fake_utxo(&utxo1, 500, NULL);
    make_fake_utxo(&utxo2, 500, NULL);
    rc = dnac_tx_add_input(tx, &utxo1);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_input 1 failed");
    rc = dnac_tx_add_input(tx, &utxo2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_input 2 failed");

    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    rc = dnac_tx_add_output(tx, "recipient_fp_aabbccdd", 1000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed");

    /* Finalize as signer[0] */
    rc = dnac_tx_finalize(tx, privkey1, pubkey1);
    ASSERT_EQ(rc, DNAC_SUCCESS, "finalize failed");
    ASSERT_EQ(tx->signer_count, 1, "signer_count should be 1 after finalize");

    /* Add second signer manually (sign the tx_hash) */
    uint8_t sig2[DNAC_SIGNATURE_SIZE];
    size_t sig2_len = 0;
    rc = qgp_dsa87_sign(sig2, &sig2_len, tx->tx_hash, DNAC_TX_HASH_SIZE, privkey2);
    ASSERT_EQ(rc, 0, "sign as signer2 failed");

    rc = dnac_tx_add_signer(tx, pubkey2, sig2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_signer 2 failed");
    ASSERT_EQ(tx->signer_count, 2, "signer_count should be 2");

    /* Serialize */
    uint8_t buffer[131072];
    size_t written = 0;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "serialize failed");

    /* Deserialize */
    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "deserialize failed");
    ASSERT_TRUE(tx2 != NULL, "deserialized tx is NULL");

    /* Verify both signers roundtripped */
    ASSERT_EQ(tx2->signer_count, 2, "deserialized signer_count should be 2");
    ASSERT_TRUE(memcmp(tx2->signers[0].pubkey, pubkey1, DNAC_PUBKEY_SIZE) == 0,
                "signer[0] pubkey mismatch");
    ASSERT_TRUE(memcmp(tx2->signers[1].pubkey, pubkey2, DNAC_PUBKEY_SIZE) == 0,
                "signer[1] pubkey mismatch");
    ASSERT_TRUE(memcmp(tx2->signers[1].signature, sig2, DNAC_SIGNATURE_SIZE) == 0,
                "signer[1] signature mismatch");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

/* ============================================================================
 * Test 4: serialize/deserialize with zero signers (genesis TX)
 * ========================================================================== */

static void test_serialize_zero_signers(void) {
    TEST("serialize roundtrip: zero signers (genesis TX)");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_GENESIS);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    /* Genesis: no inputs, one output */
    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    int rc = dnac_tx_add_output(tx, "genesis_recipient_fp", 100000000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed");

    /* signer_count should be 0 (genesis has no sender) */
    ASSERT_EQ(tx->signer_count, 0, "genesis signer_count should be 0");

    /* Compute hash manually (finalize requires privkey + balance check) */
    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    ASSERT_EQ(rc, DNAC_SUCCESS, "compute_hash failed");

    /* Serialize */
    uint8_t buffer[131072];
    size_t written = 0;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "serialize failed");
    ASSERT_TRUE(written > 0, "no data written");

    /* Deserialize */
    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "deserialize failed");
    ASSERT_TRUE(tx2 != NULL, "deserialized tx is NULL");

    ASSERT_EQ(tx2->signer_count, 0, "deserialized genesis signer_count should be 0");
    ASSERT_TRUE(memcmp(tx2->tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE) == 0,
                "tx_hash mismatch after roundtrip");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

/* ============================================================================
 * Test 5: hash includes signer_count (different signer counts = different hash)
 * ========================================================================== */

static void test_hash_includes_signer_count(void) {
    TEST("hash includes signer_count: 1 vs 2 signers produce different hashes");

    /* Generate two keypairs */
    uint8_t pubkey1[DNAC_PUBKEY_SIZE], privkey1[4896];
    uint8_t pubkey2[DNAC_PUBKEY_SIZE], privkey2[4896];
    int rc = qgp_dsa87_keypair(pubkey1, privkey1);
    ASSERT_EQ(rc, 0, "keypair1 generation failed");
    rc = qgp_dsa87_keypair(pubkey2, privkey2);
    ASSERT_EQ(rc, 0, "keypair2 generation failed");

    /* TX1: 1 signer */
    dnac_transaction_t *tx1 = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx1 != NULL, "tx1_create failed");

    dnac_utxo_t utxo;
    make_fake_utxo(&utxo, 1000, NULL);
    rc = dnac_tx_add_input(tx1, &utxo);
    ASSERT_EQ(rc, DNAC_SUCCESS, "tx1 add_input failed");

    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    rc = dnac_tx_add_output(tx1, "recipient_fp_test", 1000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "tx1 add_output failed");

    /* Set signer[0] pubkey manually */
    memcpy(tx1->signers[0].pubkey, pubkey1, DNAC_PUBKEY_SIZE);
    tx1->signer_count = 1;

    /* TX2: identical but with 2 signers */
    dnac_transaction_t *tx2 = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx2 != NULL, "tx2_create failed");

    /* Copy exact same fields */
    tx2->version = tx1->version;
    tx2->type = tx1->type;
    tx2->timestamp = tx1->timestamp;
    tx2->input_count = tx1->input_count;
    memcpy(&tx2->inputs[0], &tx1->inputs[0], sizeof(dnac_tx_input_t));
    tx2->output_count = tx1->output_count;
    memcpy(&tx2->outputs[0], &tx1->outputs[0], sizeof(dnac_tx_output_internal_t));

    /* Same signer[0], plus a second signer */
    memcpy(tx2->signers[0].pubkey, pubkey1, DNAC_PUBKEY_SIZE);
    memcpy(tx2->signers[1].pubkey, pubkey2, DNAC_PUBKEY_SIZE);
    tx2->signer_count = 2;

    /* Compute hashes */
    uint8_t hash1[DNAC_TX_HASH_SIZE];
    uint8_t hash2[DNAC_TX_HASH_SIZE];
    rc = dnac_tx_compute_hash(tx1, hash1);
    ASSERT_EQ(rc, DNAC_SUCCESS, "compute_hash tx1 failed");
    rc = dnac_tx_compute_hash(tx2, hash2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "compute_hash tx2 failed");

    /* Hashes MUST differ */
    ASSERT_TRUE(memcmp(hash1, hash2, DNAC_TX_HASH_SIZE) != 0,
                "hashes should differ when signer_count differs");

    dnac_free_transaction(tx1);
    dnac_free_transaction(tx2);
    PASS();
}

/* ============================================================================
 * Test 6: per-token balance — single token balanced
 * ========================================================================== */

static void test_per_token_balance_single_token(void) {
    TEST("per-token balance: single token via total_input/total_output");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    /* Create a custom token ID */
    uint8_t token_a[DNAC_TOKEN_ID_SIZE];
    memset(token_a, 0x42, DNAC_TOKEN_ID_SIZE);

    /* Add input with custom token */
    dnac_utxo_t utxo;
    make_fake_utxo(&utxo, 1000, token_a);
    int rc = dnac_tx_add_input(tx, &utxo);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed");

    /* Verify token_id propagated to input */
    ASSERT_TRUE(memcmp(tx->inputs[0].token_id, token_a, DNAC_TOKEN_ID_SIZE) == 0,
                "input token_id should match");

    /* Add output with same token */
    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    rc = dnac_tx_add_output(tx, "recipient_fp_token", 1000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed");

    /* Manually set output token_id to match */
    memcpy(tx->outputs[0].token_id, token_a, DNAC_TOKEN_ID_SIZE);

    /* Balance check: total_input == total_output */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);
    ASSERT_EQ(total_in, (uint64_t)1000, "total_input should be 1000");
    ASSERT_EQ(total_out, (uint64_t)1000, "total_output should be 1000");
    ASSERT_EQ(total_in, total_out, "inputs should equal outputs");

    dnac_free_transaction(tx);
    PASS();
}

/* ============================================================================
 * Test 7: finalize signs as signer[0] + signature verifies
 * ========================================================================== */

static void test_finalize_signs_as_signer0(void) {
    TEST("finalize: signs as signer[0], signature verifies against tx_hash");

    /* Generate keypair */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t privkey[4896];
    int rc = qgp_dsa87_keypair(pubkey, privkey);
    ASSERT_EQ(rc, 0, "keypair generation failed");

    /* Build TX */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "tx_create failed");

    dnac_utxo_t utxo;
    make_fake_utxo(&utxo, 5000, NULL);
    rc = dnac_tx_add_input(tx, &utxo);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed");

    uint8_t seed[32];
    qgp_randombytes(seed, 32);
    rc = dnac_tx_add_output(tx, "recipient_fp_finalize", 5000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed");

    /* Finalize */
    rc = dnac_tx_finalize(tx, privkey, pubkey);
    ASSERT_EQ(rc, DNAC_SUCCESS, "finalize failed");

    /* Verify signer[0] state */
    ASSERT_EQ(tx->signer_count, 1, "signer_count should be 1");
    ASSERT_TRUE(memcmp(tx->signers[0].pubkey, pubkey, DNAC_PUBKEY_SIZE) == 0,
                "signer[0].pubkey should match sender pubkey");

    /* Verify tx_hash is not all-zeros */
    uint8_t zero_hash[DNAC_TX_HASH_SIZE];
    memset(zero_hash, 0, DNAC_TX_HASH_SIZE);
    ASSERT_TRUE(memcmp(tx->tx_hash, zero_hash, DNAC_TX_HASH_SIZE) != 0,
                "tx_hash should not be all zeros after finalize");

    /* Verify signature against tx_hash using Dilithium5 */
    rc = qgp_dsa87_verify(tx->signers[0].signature, DNAC_SIGNATURE_SIZE,
                          tx->tx_hash, DNAC_TX_HASH_SIZE, pubkey);
    ASSERT_EQ(rc, 0, "signer[0] signature should verify against tx_hash");

    dnac_free_transaction(tx);
    PASS();
}

/* ============================================================================
 * Test 8: finalize balance check — balanced succeeds, unbalanced fails
 * ========================================================================== */

static void test_finalize_balance_check(void) {
    TEST("finalize: balanced TX succeeds, unbalanced TX fails");

    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t privkey[4896];
    int rc = qgp_dsa87_keypair(pubkey, privkey);
    ASSERT_EQ(rc, 0, "keypair generation failed");

    /* Balanced TX: input=100, output=100 */
    {
        dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
        ASSERT_TRUE(tx != NULL, "tx_create failed (balanced)");

        dnac_utxo_t utxo;
        make_fake_utxo(&utxo, 100, NULL);
        rc = dnac_tx_add_input(tx, &utxo);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed (balanced)");

        uint8_t seed[32];
        qgp_randombytes(seed, 32);
        rc = dnac_tx_add_output(tx, "recipient_fp_bal", 100, seed);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed (balanced)");

        rc = dnac_tx_finalize(tx, privkey, pubkey);
        ASSERT_EQ(rc, DNAC_SUCCESS, "finalize should succeed for balanced TX");

        dnac_free_transaction(tx);
    }

    /* Unbalanced TX: input=100, output=200 → should fail */
    {
        dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
        ASSERT_TRUE(tx != NULL, "tx_create failed (unbalanced)");

        dnac_utxo_t utxo;
        make_fake_utxo(&utxo, 100, NULL);
        rc = dnac_tx_add_input(tx, &utxo);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed (unbalanced)");

        uint8_t seed[32];
        qgp_randombytes(seed, 32);
        rc = dnac_tx_add_output(tx, "recipient_fp_unbal", 200, seed);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed (unbalanced)");

        rc = dnac_tx_finalize(tx, privkey, pubkey);
        ASSERT_NEQ(rc, DNAC_SUCCESS, "finalize should FAIL for unbalanced TX");

        dnac_free_transaction(tx);
    }

    /* Fee TX: input=100, output=90 → should succeed (difference is fee) */
    {
        dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
        ASSERT_TRUE(tx != NULL, "tx_create failed (fee)");

        dnac_utxo_t utxo;
        make_fake_utxo(&utxo, 100, NULL);
        rc = dnac_tx_add_input(tx, &utxo);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_input failed (fee)");

        uint8_t seed[32];
        qgp_randombytes(seed, 32);
        rc = dnac_tx_add_output(tx, "recipient_fp_fee", 90, seed);
        ASSERT_EQ(rc, DNAC_SUCCESS, "add_output failed (fee)");

        rc = dnac_tx_finalize(tx, privkey, pubkey);
        ASSERT_EQ(rc, DNAC_SUCCESS, "finalize should succeed when input > output (fee)");

        dnac_free_transaction(tx);
    }

    PASS();
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(void) {
    printf("\n");
    printf("==============================================\n");
    printf("  DNAC Multi-Asset + Multi-Signer Tests\n");
    printf("==============================================\n\n");

    printf("[Signer Management]\n");
    test_add_signer();
    printf("\n");

    printf("[Serialize/Deserialize Roundtrip]\n");
    test_serialize_roundtrip_single_signer();
    test_serialize_roundtrip_two_signers();
    test_serialize_zero_signers();
    printf("\n");

    printf("[Hash Integrity]\n");
    test_hash_includes_signer_count();
    printf("\n");

    printf("[Balance Verification]\n");
    test_per_token_balance_single_token();
    printf("\n");

    printf("[Finalize + Signing]\n");
    test_finalize_signs_as_signer0();
    test_finalize_balance_check();
    printf("\n");

    printf("==============================================\n");
    printf("  Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);
    printf("==============================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
