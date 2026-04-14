/**
 * Nodus — Phase 12 follow-up — full spend_result sign/verify roundtrip
 *
 * Builds the 221-byte spndrslt preimage with a real Dilithium5 keypair,
 * signs it, then verifies. Catches any future layout drift between the
 * helper and the live signer (handlers.c) and the client-side verifier
 * (dnac/builder.c) — they all bind to the same dnac_compute_spend_result_preimage
 * surface so the test is a single anchor.
 */

#include "witness/nodus_witness_spend_preimage.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_sign_verify_roundtrip(void) {
    TEST("spndrslt sign + verify round-trip");

    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    if (qgp_dsa87_keypair(pk, sk) != 0) { FAIL("keypair"); return; }

    uint8_t wpk_hash[64];
    qgp_sha3_512(pk, sizeof(pk), wpk_hash);

    uint8_t tx[NODUS_T3_TX_HASH_LEN], wid[NODUS_T3_WITNESS_ID_LEN], cid[32];
    for (int i = 0; i < NODUS_T3_TX_HASH_LEN; i++) tx[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < NODUS_T3_WITNESS_ID_LEN; i++) wid[i] = (uint8_t)(0x80 + i);
    for (int i = 0; i < 32; i++) cid[i] = (uint8_t)(0xC0 + i);

    uint8_t preimage[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    if (dnac_compute_spend_result_preimage(tx, wid, wpk_hash, cid,
                                             1700000000ULL, 42, 3, 0,
                                             preimage) != 0) {
        FAIL("compute"); return;
    }

    uint8_t sig[NODUS_SIG_BYTES];
    size_t siglen = 0;
    if (qgp_dsa87_sign(sig, &siglen, preimage, sizeof(preimage), sk) != 0) {
        FAIL("sign"); return;
    }
    if (siglen < NODUS_SIG_BYTES)
        memset(sig + siglen, 0, NODUS_SIG_BYTES - siglen);

    if (qgp_dsa87_verify(sig, NODUS_SIG_BYTES, preimage, sizeof(preimage), pk) != 0) {
        FAIL("verify (legit)"); return;
    }

    PASS();
}

static void test_tampered_field_rejects(void) {
    TEST("tampered preimage byte rejects on verify");

    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    qgp_dsa87_keypair(pk, sk);

    uint8_t wpk_hash[64];
    qgp_sha3_512(pk, sizeof(pk), wpk_hash);

    uint8_t tx[NODUS_T3_TX_HASH_LEN] = {0};
    uint8_t wid[NODUS_T3_WITNESS_ID_LEN] = {0};
    uint8_t cid[32] = {0};

    uint8_t preimage[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    dnac_compute_spend_result_preimage(tx, wid, wpk_hash, cid, 100, 1, 0, 0, preimage);

    uint8_t sig[NODUS_SIG_BYTES];
    size_t siglen = 0;
    qgp_dsa87_sign(sig, &siglen, preimage, sizeof(preimage), sk);

    /* Flip a single bit in the block_height field */
    preimage[208] ^= 0x01;

    if (qgp_dsa87_verify(sig, NODUS_SIG_BYTES, preimage, sizeof(preimage), pk) == 0) {
        FAIL("tampered preimage accepted"); return;
    }
    PASS();
}

static void test_wrong_key_rejects(void) {
    TEST("wrong pubkey rejects on verify");

    uint8_t pk1[QGP_DSA87_PUBLICKEYBYTES], sk1[QGP_DSA87_SECRETKEYBYTES];
    uint8_t pk2[QGP_DSA87_PUBLICKEYBYTES], sk2[QGP_DSA87_SECRETKEYBYTES];
    qgp_dsa87_keypair(pk1, sk1);
    qgp_dsa87_keypair(pk2, sk2);

    uint8_t wpk_hash[64];
    qgp_sha3_512(pk1, sizeof(pk1), wpk_hash);

    uint8_t tx[NODUS_T3_TX_HASH_LEN] = {0};
    uint8_t wid[NODUS_T3_WITNESS_ID_LEN] = {0};
    uint8_t cid[32] = {0};

    uint8_t preimage[DNAC_SPEND_RESULT_PREIMAGE_LEN];
    dnac_compute_spend_result_preimage(tx, wid, wpk_hash, cid, 1, 1, 0, 0, preimage);

    uint8_t sig[NODUS_SIG_BYTES];
    size_t siglen = 0;
    qgp_dsa87_sign(sig, &siglen, preimage, sizeof(preimage), sk1);

    /* Verify against pk2 — should fail */
    if (qgp_dsa87_verify(sig, NODUS_SIG_BYTES, preimage, sizeof(preimage), pk2) == 0) {
        FAIL("wrong key accepted"); return;
    }
    PASS();
}

int main(void) {
    printf("DNAC spend_result sign/verify tests\n");
    printf("===================================\n");

    test_sign_verify_roundtrip();
    test_tampered_field_rejects();
    test_wrong_key_rejects();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
