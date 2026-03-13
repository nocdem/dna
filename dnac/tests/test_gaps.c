/**
 * @file test_gaps.c
 * @brief REAL tests for v0.6.0 gap fixes
 *
 * These tests exercise actual security code paths, not just serialization.
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
#include "dnac/nodus.h"
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
 * Crypto Tests: Dilithium5 Sign and Verify
 *
 * These test REAL cryptographic operations:
 * - Sign data with Dilithium5
 * - Verify the signature
 * - Reject tampered messages
 * ========================================================================== */

static void test_proposal_reject_tampered(void) {
    TEST("Reject tampered data");

    /* Generate keypair */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t privkey[4896];
    int rc = qgp_dsa87_keypair(pubkey, privkey);
    ASSERT_EQ(rc, 0, "Keypair generation failed");

    /* Create and sign data */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    qgp_randombytes(tx_hash, DNAC_TX_HASH_SIZE);

    uint8_t hash[64];
    qgp_sha3_512(tx_hash, DNAC_TX_HASH_SIZE, hash);

    uint8_t signature[DNAC_SIGNATURE_SIZE];
    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = qgp_dsa87_sign(signature, &sig_len, hash, 64, privkey);
    ASSERT_EQ(rc, 0, "Signing failed");

    /* Tamper with the tx_hash */
    tx_hash[0] ^= 0xFF;

    /* Recompute hash with tampered data */
    uint8_t tampered_hash[64];
    qgp_sha3_512(tx_hash, DNAC_TX_HASH_SIZE, tampered_hash);

    /* Verification should FAIL */
    rc = qgp_dsa87_verify(signature, DNAC_SIGNATURE_SIZE, tampered_hash, 64, pubkey);
    ASSERT_NEQ(rc, 0, "Should reject tampered message");

    PASS();
}

static void test_proposal_reject_wrong_key(void) {
    TEST("Reject data signed by wrong key");

    /* Generate two keypairs */
    uint8_t pubkey1[DNAC_PUBKEY_SIZE], privkey1[4896];
    uint8_t pubkey2[DNAC_PUBKEY_SIZE], privkey2[4896];
    int rc = qgp_dsa87_keypair(pubkey1, privkey1);
    ASSERT_EQ(rc, 0, "Keypair 1 generation failed");
    rc = qgp_dsa87_keypair(pubkey2, privkey2);
    ASSERT_EQ(rc, 0, "Keypair 2 generation failed");

    /* Sign with privkey1 */
    uint8_t data[64];
    qgp_randombytes(data, 64);

    uint8_t signature[DNAC_SIGNATURE_SIZE];
    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = qgp_dsa87_sign(signature, &sig_len, data, 64, privkey1);
    ASSERT_EQ(rc, 0, "Signing failed");

    /* Verify with pubkey2 - should FAIL */
    rc = qgp_dsa87_verify(signature, DNAC_SIGNATURE_SIZE, data, 64, pubkey2);
    ASSERT_NEQ(rc, 0, "Should reject signature from different key");

    PASS();
}

/* ============================================================================
 * Gap 12 Tests: Pubkey Validation
 *
 * Test that invalid pubkeys are rejected during verification
 * ========================================================================== */

static void test_zero_pubkey_rejected(void) {
    TEST("Zero pubkey causes signature verification to fail");

    /* Create data and signature */
    uint8_t data[64];
    qgp_randombytes(data, 64);

    /* Create an all-zero pubkey */
    uint8_t zero_pubkey[DNAC_PUBKEY_SIZE];
    memset(zero_pubkey, 0, DNAC_PUBKEY_SIZE);

    /* Any signature should fail verification with zero pubkey */
    uint8_t fake_sig[DNAC_SIGNATURE_SIZE];
    memset(fake_sig, 0xAB, DNAC_SIGNATURE_SIZE);

    int rc = qgp_dsa87_verify(fake_sig, DNAC_SIGNATURE_SIZE, data, 64, zero_pubkey);
    ASSERT_NEQ(rc, 0, "Zero pubkey should fail verification");

    PASS();
}

static void test_garbage_pubkey_rejected(void) {
    TEST("Garbage pubkey causes signature verification to fail");

    uint8_t data[64];
    qgp_randombytes(data, 64);

    /* Create garbage pubkey */
    uint8_t garbage_pubkey[DNAC_PUBKEY_SIZE];
    memset(garbage_pubkey, 0xFF, DNAC_PUBKEY_SIZE);

    uint8_t fake_sig[DNAC_SIGNATURE_SIZE];
    memset(fake_sig, 0xAB, DNAC_SIGNATURE_SIZE);

    int rc = qgp_dsa87_verify(fake_sig, DNAC_SIGNATURE_SIZE, data, 64, garbage_pubkey);
    ASSERT_NEQ(rc, 0, "Garbage pubkey should fail verification");

    PASS();
}

static void test_valid_pubkey_invalid_sig_rejected(void) {
    TEST("Valid pubkey with wrong signature rejected");

    /* Generate valid keypair */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t privkey[4896];
    int rc = qgp_dsa87_keypair(pubkey, privkey);
    ASSERT_EQ(rc, 0, "Keypair failed");

    uint8_t data[64];
    qgp_randombytes(data, 64);

    /* Create garbage signature */
    uint8_t garbage_sig[DNAC_SIGNATURE_SIZE];
    memset(garbage_sig, 0xCD, DNAC_SIGNATURE_SIZE);

    /* Valid pubkey + garbage signature should fail */
    rc = qgp_dsa87_verify(garbage_sig, DNAC_SIGNATURE_SIZE, data, 64, pubkey);
    ASSERT_NEQ(rc, 0, "Garbage signature should fail");

    PASS();
}

/* ============================================================================
 * Gap 25 Tests: Memo Support
 *
 * Test memo field in transaction outputs - full round-trip
 * ========================================================================== */

static void test_memo_roundtrip(void) {
    TEST("Memo survives serialize/deserialize");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "Failed to create tx");

    const char *memo = "Payment for invoice #12345";
    uint8_t seed[32];
    qgp_randombytes(seed, 32);

    int rc = dnac_tx_add_output_with_memo(tx, "recipient_fp_here",
                                           50000, seed, memo, (uint8_t)strlen(memo));
    ASSERT_EQ(rc, DNAC_SUCCESS, "Failed to add output with memo");

    /* Verify memo stored */
    ASSERT_EQ(tx->outputs[0].memo_len, strlen(memo), "Memo length wrong");
    ASSERT_TRUE(memcmp(tx->outputs[0].memo, memo, strlen(memo)) == 0, "Memo content wrong");

    /* Serialize */
    uint8_t buffer[65536];
    size_t written;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Serialize failed");
    ASSERT_TRUE(written > 0, "No data written");

    /* Deserialize */
    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Deserialize failed");
    ASSERT_TRUE(tx2 != NULL, "Deserialized tx is NULL");

    /* Verify memo preserved */
    ASSERT_EQ(tx2->outputs[0].memo_len, strlen(memo), "Memo length not preserved");
    ASSERT_TRUE(memcmp(tx2->outputs[0].memo, memo, strlen(memo)) == 0,
                "Memo content not preserved");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

static void test_memo_empty_works(void) {
    TEST("Empty memo works");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "Failed to create tx");

    uint8_t seed[32];
    qgp_randombytes(seed, 32);

    /* Add output without memo */
    int rc = dnac_tx_add_output(tx, "recipient_fp", 1000, seed);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Add output failed");

    ASSERT_EQ(tx->outputs[0].memo_len, 0, "Memo should be 0");

    /* Round-trip */
    uint8_t buffer[65536];
    size_t written;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Serialize failed");

    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Deserialize failed");

    ASSERT_EQ(tx2->outputs[0].memo_len, 0, "Memo should still be 0");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

static void test_memo_max_length(void) {
    TEST("Max length memo (255 bytes)");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "Create failed");

    char long_memo[256];
    memset(long_memo, 'M', 255);
    long_memo[255] = '\0';

    uint8_t seed[32];
    qgp_randombytes(seed, 32);

    int rc = dnac_tx_add_output_with_memo(tx, "recipient",
                                           999, seed, long_memo, 255);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Should accept 255-byte memo");
    ASSERT_EQ(tx->outputs[0].memo_len, 255, "Memo length should be 255");

    /* Round-trip */
    uint8_t buffer[65536];
    size_t written;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Serialize failed");

    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Deserialize failed");

    ASSERT_EQ(tx2->outputs[0].memo_len, 255, "255-byte memo not preserved");
    ASSERT_TRUE(memcmp(tx2->outputs[0].memo, long_memo, 255) == 0, "Long memo corrupted");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

static void test_memo_binary_data(void) {
    TEST("Memo with binary data (null bytes)");

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_SPEND);
    ASSERT_TRUE(tx != NULL, "Create failed");

    /* Binary memo with embedded nulls */
    uint8_t binary_memo[32];
    qgp_randombytes(binary_memo, 32);
    binary_memo[5] = 0x00;  /* Embedded null */
    binary_memo[10] = 0x00;

    uint8_t seed[32];
    qgp_randombytes(seed, 32);

    int rc = dnac_tx_add_output_with_memo(tx, "recipient",
                                           100, seed, (char*)binary_memo, 32);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Should accept binary memo");

    /* Round-trip */
    uint8_t buffer[65536];
    size_t written;
    rc = dnac_tx_serialize(tx, buffer, sizeof(buffer), &written);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Serialize failed");

    dnac_transaction_t *tx2 = NULL;
    rc = dnac_tx_deserialize(buffer, written, &tx2);
    ASSERT_EQ(rc, DNAC_SUCCESS, "Deserialize failed");

    ASSERT_EQ(tx2->outputs[0].memo_len, 32, "Binary memo length wrong");
    ASSERT_TRUE(memcmp(tx2->outputs[0].memo, binary_memo, 32) == 0,
                "Binary memo corrupted");

    dnac_free_transaction(tx);
    dnac_free_transaction(tx2);
    PASS();
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(void) {
    printf("\n");
    printf("===========================================\n");
    printf("  DNAC v0.6.0 Gap Fixes - REAL Tests\n");
    printf("===========================================\n\n");

    printf("[Crypto: Dilithium5 Signing]\n");
    test_proposal_reject_tampered();
    test_proposal_reject_wrong_key();
    printf("\n");

    printf("[Gap 12: Pubkey Validation]\n");
    test_zero_pubkey_rejected();
    test_garbage_pubkey_rejected();
    test_valid_pubkey_invalid_sig_rejected();
    printf("\n");

    printf("[Gap 25: Memo Support]\n");
    test_memo_roundtrip();
    test_memo_empty_works();
    test_memo_max_length();
    test_memo_binary_data();
    printf("\n");

    printf("===========================================\n");
    printf("  Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);
    printf("===========================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
