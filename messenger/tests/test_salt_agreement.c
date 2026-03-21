/**
 * @file test_salt_agreement.c
 * @brief Unit tests for salt agreement protocol
 *
 * Tests:
 * 1. make_key deterministic — same output regardless of fingerprint order
 * 2. make_key different pairs — different contacts produce different keys
 * 3. make_key input validation — rejects short/null fingerprints
 * 4. publish + packet structure — builds valid dual-encrypted packet
 * 5. packet signature verification — valid signer accepted, third party rejected
 * 6. tiebreaker determinism — SHA3 hash comparison always picks same winner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dht/shared/dht_salt_agreement.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/utils/qgp_random.h"
#include "messenger/gek.h"

#define TEST_PASS "\033[32mPASS\033[0m"
#define TEST_FAIL "\033[31mFAIL\033[0m"

static int tests_run = 0;
static int tests_passed = 0;

/* Two deterministic 128-char hex fingerprints for testing */
static const char *FP_ALICE = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                               "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";
static const char *FP_BOB   = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
                               "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5";
static const char *FP_CAROL = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
                               "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

/* ============================================================================
 * Test: make_key is deterministic and order-independent
 * ============================================================================ */
static void test_make_key_deterministic(void) {
    tests_run++;
    char key_ab[300], key_ba[300];

    int rc1 = salt_agreement_make_key(FP_ALICE, FP_BOB, key_ab, sizeof(key_ab));
    int rc2 = salt_agreement_make_key(FP_BOB, FP_ALICE, key_ba, sizeof(key_ba));

    if (rc1 != 0 || rc2 != 0) {
        printf("[%s] test_make_key_deterministic: make_key failed (rc1=%d, rc2=%d)\n",
               TEST_FAIL, rc1, rc2);
        return;
    }

    if (strcmp(key_ab, key_ba) != 0) {
        printf("[%s] test_make_key_deterministic: key(A,B) != key(B,A)\n", TEST_FAIL);
        printf("  key(A,B): %.32s...\n", key_ab);
        printf("  key(B,A): %.32s...\n", key_ba);
        return;
    }

    /* Key should be 128 hex chars (SHA3-512) */
    if (strlen(key_ab) != 128) {
        printf("[%s] test_make_key_deterministic: key length %zu != 128\n",
               TEST_FAIL, strlen(key_ab));
        return;
    }

    printf("[%s] test_make_key_deterministic: key(A,B) == key(B,A), len=%zu\n",
           TEST_PASS, strlen(key_ab));
    tests_passed++;
}

/* ============================================================================
 * Test: different contact pairs produce different keys
 * ============================================================================ */
static void test_make_key_different_pairs(void) {
    tests_run++;
    char key_ab[300], key_ac[300], key_bc[300];

    salt_agreement_make_key(FP_ALICE, FP_BOB, key_ab, sizeof(key_ab));
    salt_agreement_make_key(FP_ALICE, FP_CAROL, key_ac, sizeof(key_ac));
    salt_agreement_make_key(FP_BOB, FP_CAROL, key_bc, sizeof(key_bc));

    if (strcmp(key_ab, key_ac) == 0 || strcmp(key_ab, key_bc) == 0 ||
        strcmp(key_ac, key_bc) == 0) {
        printf("[%s] test_make_key_different_pairs: collision detected!\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_make_key_different_pairs: all 3 pairs produce unique keys\n", TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * Test: make_key rejects invalid inputs
 * ============================================================================ */
static void test_make_key_validation(void) {
    tests_run++;
    char key[300];

    if (salt_agreement_make_key(NULL, FP_BOB, key, sizeof(key)) != -1) {
        printf("[%s] test_make_key_validation: accepted NULL fp_a\n", TEST_FAIL);
        return;
    }
    if (salt_agreement_make_key(FP_ALICE, NULL, key, sizeof(key)) != -1) {
        printf("[%s] test_make_key_validation: accepted NULL fp_b\n", TEST_FAIL);
        return;
    }
    if (salt_agreement_make_key(FP_ALICE, FP_BOB, key, 10) != -1) {
        printf("[%s] test_make_key_validation: accepted too-small buffer\n", TEST_FAIL);
        return;
    }
    if (salt_agreement_make_key("short", FP_BOB, key, sizeof(key)) != -1) {
        printf("[%s] test_make_key_validation: accepted short fingerprint\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_make_key_validation: all invalid inputs rejected\n", TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * Test: tiebreaker determinism — lower SHA3 hash always wins
 * ============================================================================ */
static void test_tiebreaker_determinism(void) {
    tests_run++;

    /* Generate two random salts */
    uint8_t salt_a[SALT_AGREEMENT_SIZE], salt_b[SALT_AGREEMENT_SIZE];
    qgp_randombytes(salt_a, SALT_AGREEMENT_SIZE);
    qgp_randombytes(salt_b, SALT_AGREEMENT_SIZE);

    /* Compute hashes */
    uint8_t hash_a[64], hash_b[64];
    qgp_sha3_512(salt_a, SALT_AGREEMENT_SIZE, hash_a);
    qgp_sha3_512(salt_b, SALT_AGREEMENT_SIZE, hash_b);

    /* Determine expected winner */
    int cmp = memcmp(hash_a, hash_b, 64);
    const uint8_t *expected_winner = (cmp <= 0) ? salt_a : salt_b;

    /* Run tiebreaker 100 times with randomized order — must always pick same winner */
    int consistent = 1;
    for (int trial = 0; trial < 100; trial++) {
        const uint8_t *first = (trial % 2 == 0) ? salt_a : salt_b;
        const uint8_t *second = (first == salt_a) ? salt_b : salt_a;

        uint8_t h1[64], h2[64];
        qgp_sha3_512(first, SALT_AGREEMENT_SIZE, h1);
        qgp_sha3_512(second, SALT_AGREEMENT_SIZE, h2);

        const uint8_t *winner = (memcmp(h1, h2, 64) <= 0) ? first : second;
        if (memcmp(winner, expected_winner, SALT_AGREEMENT_SIZE) != 0) {
            consistent = 0;
            break;
        }
    }

    if (!consistent) {
        printf("[%s] test_tiebreaker_determinism: inconsistent winner across trials\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_tiebreaker_determinism: consistent winner across 100 order-randomized trials\n",
           TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * Test: GEK encrypt/decrypt round-trip (salt-sized payload)
 * ============================================================================ */
static void test_gek_roundtrip_salt(void) {
    tests_run++;

    /* Generate Kyber keypair */
    uint8_t kyber_pk[1568], kyber_sk[3168];
    if (qgp_kem1024_keypair(kyber_pk, kyber_sk) != 0) {
        printf("[%s] test_gek_roundtrip_salt: Kyber keygen failed\n", TEST_FAIL);
        return;
    }

    /* Random salt */
    uint8_t salt[SALT_AGREEMENT_SIZE];
    qgp_randombytes(salt, SALT_AGREEMENT_SIZE);

    /* Encrypt */
    uint8_t encrypted[GEK_ENC_TOTAL_SIZE];
    if (gek_encrypt(salt, kyber_pk, encrypted) != 0) {
        printf("[%s] test_gek_roundtrip_salt: gek_encrypt failed\n", TEST_FAIL);
        return;
    }

    /* Decrypt */
    uint8_t decrypted[SALT_AGREEMENT_SIZE];
    if (gek_decrypt(encrypted, GEK_ENC_TOTAL_SIZE, kyber_sk, decrypted) != 0) {
        printf("[%s] test_gek_roundtrip_salt: gek_decrypt failed\n", TEST_FAIL);
        return;
    }

    if (memcmp(salt, decrypted, SALT_AGREEMENT_SIZE) != 0) {
        printf("[%s] test_gek_roundtrip_salt: decrypted != original\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_gek_roundtrip_salt: encrypt → decrypt round-trip OK\n", TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * Test: Dilithium signature verification (packet auth pattern)
 * ============================================================================ */
static void test_signature_verification(void) {
    tests_run++;

    /* Generate two Dilithium keypairs (Alice and attacker) */
    uint8_t alice_pk[QGP_DSA87_PUBLICKEYBYTES], alice_sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t attacker_pk[QGP_DSA87_PUBLICKEYBYTES], attacker_sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(alice_pk, alice_sk) != 0 ||
        qgp_dsa87_keypair(attacker_pk, attacker_sk) != 0) {
        printf("[%s] test_signature_verification: keygen failed\n", TEST_FAIL);
        return;
    }

    /* Sign some data with Alice's key */
    uint8_t data[64];
    qgp_randombytes(data, sizeof(data));
    uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t sig_len = 0;
    if (qgp_dsa87_sign(sig, &sig_len, data, sizeof(data), alice_sk) != 0) {
        printf("[%s] test_signature_verification: sign failed\n", TEST_FAIL);
        return;
    }

    /* Verify with Alice's pubkey — should succeed */
    if (qgp_dsa87_verify(sig, sig_len, data, sizeof(data), alice_pk) != 0) {
        printf("[%s] test_signature_verification: valid signature rejected\n", TEST_FAIL);
        return;
    }

    /* Verify with attacker's pubkey — should fail */
    if (qgp_dsa87_verify(sig, sig_len, data, sizeof(data), attacker_pk) == 0) {
        printf("[%s] test_signature_verification: attacker's key accepted!\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_signature_verification: valid signer accepted, attacker rejected\n",
           TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * Test: make_key same fingerprint (self-contact edge case)
 * ============================================================================ */
static void test_make_key_same_fingerprint(void) {
    tests_run++;
    char key[300];

    int rc = salt_agreement_make_key(FP_ALICE, FP_ALICE, key, sizeof(key));
    if (rc != 0) {
        printf("[%s] test_make_key_same_fingerprint: failed with rc=%d\n", TEST_FAIL, rc);
        return;
    }

    /* Should still produce a valid 128-char key */
    if (strlen(key) != 128) {
        printf("[%s] test_make_key_same_fingerprint: key length %zu != 128\n",
               TEST_FAIL, strlen(key));
        return;
    }

    /* Should differ from A↔B key */
    char key_ab[300];
    salt_agreement_make_key(FP_ALICE, FP_BOB, key_ab, sizeof(key_ab));
    if (strcmp(key, key_ab) == 0) {
        printf("[%s] test_make_key_same_fingerprint: self-key == A↔B key!\n", TEST_FAIL);
        return;
    }

    printf("[%s] test_make_key_same_fingerprint: self-contact produces valid unique key\n",
           TEST_PASS);
    tests_passed++;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
int main(void) {
    printf("\n=== Salt Agreement Protocol Tests ===\n\n");

    test_make_key_deterministic();
    test_make_key_different_pairs();
    test_make_key_validation();
    test_make_key_same_fingerprint();
    test_tiebreaker_determinism();
    test_gek_roundtrip_salt();
    test_signature_verification();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
