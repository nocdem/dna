/**
 * @file test_kyber1024.c
 * @brief Test Kyber1024 round-3 (pre-FIPS-203) — LEGACY post-quantum KEM
 *
 * This is the LEGACY round-3 API (shared/crypto/enc/qgp_kyber.h ->
 * kyber_r3_legacy.h), kept only for backward compatibility (see
 * kyber_r3_legacy.h). The FIPS-203-conformant ML-KEM-1024 API has its own
 * test: test_mlkem1024.c.
 *
 * Tests:
 * - Known-answer test against fixtures/kyber_r3_legacy_kat.h (24 vectors
 *   captured from the pre-port binary at commit c86cad72 — proof this
 *   port's legacy path is behaviour-preserving)
 * - Keypair generation
 * - Encapsulation/decapsulation round-trip
 * - Wrong secret key rejection
 * - Corrupted ciphertext handling
 * - Multiple operations consistency
 * - Key size verification
 *
 * Part of DNA Connect beta readiness testing (P1-4).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/kyber_r3_legacy.h"
#include "crypto/enc/kem/fips202.h"   /* namespaced sha3_256 — same standard
                                       * SHA3-256 the fixture generator used
                                       * (old fips202_kyber.c), just reached
                                       * through the post-port kem library. */
#include "crypto/utils/qgp_random.h"
#include "fixtures/kyber_r3_legacy_kat.h"

#define TEST_PASSED(name) printf("   ✓ %s\n", name)
#define TEST_FAILED(name) do { printf("   ✗ %s\n", name); return 1; } while(0)

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t outlen) {
    size_t i;
    if (!hex || strlen(hex) != outlen * 2) return -1;
    for (i = 0; i < outlen; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/**
 * Known-answer test: KYBER_R3_LEGACY_KAT_COUNT vectors captured from the
 * pre-port binary (commit c86cad72). For each vector: derive the keypair
 * from `seed` via kyber_r3_keypair_derand, hash pk/sk with SHA3-256 and
 * compare against the recorded hashes; decapsulate the recorded `ct` with
 * the derived sk and compare against `ss`; flip ct[bad_byte] and confirm
 * decapsulate now returns `ss_bad` (round-3 implicit rejection,
 * SHAKE256(z || H(ct_bad))).
 */
static int test_legacy_kat(void) {
    printf("\n0. Known-answer test (fixtures/kyber_r3_legacy_kat.h, %d vectors)...\n",
           KYBER_R3_LEGACY_KAT_COUNT);

    for (int i = 0; i < KYBER_R3_LEGACY_KAT_COUNT; i++) {
        const kyber_r3_legacy_kat_t *kat = &kyber_r3_legacy_kat[i];
        uint8_t seed[32];
        uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES], sk[QGP_KEM1024_SECRETKEYBYTES];
        uint8_t pk_hash[32], sk_hash[32];
        uint8_t exp_pk_hash[32], exp_sk_hash[32];
        uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES];
        uint8_t ss[QGP_KEM1024_SHAREDSECRET_BYTES];
        uint8_t exp_ss[32], exp_ss_bad[32];

        if (hex_decode(kat->seed, seed, sizeof(seed)) != 0)
            TEST_FAILED("KAT: seed hex decode failed");
        if (hex_decode(kat->ct, ct, sizeof(ct)) != 0)
            TEST_FAILED("KAT: ct hex decode failed");
        if (hex_decode(kat->ss, exp_ss, sizeof(exp_ss)) != 0)
            TEST_FAILED("KAT: ss hex decode failed");
        if (hex_decode(kat->ss_bad, exp_ss_bad, sizeof(exp_ss_bad)) != 0)
            TEST_FAILED("KAT: ss_bad hex decode failed");
        if (hex_decode(kat->pk_sha3_256, exp_pk_hash, sizeof(exp_pk_hash)) != 0)
            TEST_FAILED("KAT: pk_sha3_256 hex decode failed");
        if (hex_decode(kat->sk_sha3_256, exp_sk_hash, sizeof(exp_sk_hash)) != 0)
            TEST_FAILED("KAT: sk_sha3_256 hex decode failed");

        if (kyber_r3_keypair_derand(pk, sk, seed) != 0)
            TEST_FAILED("KAT: kyber_r3_keypair_derand failed");

        sha3_256(pk_hash, pk, sizeof(pk));
        sha3_256(sk_hash, sk, sizeof(sk));
        if (memcmp(pk_hash, exp_pk_hash, 32) != 0)
            TEST_FAILED("KAT: SHA3-256(pk) mismatch");
        if (memcmp(sk_hash, exp_sk_hash, 32) != 0)
            TEST_FAILED("KAT: SHA3-256(sk) mismatch");

        if (kyber_r3_decapsulate(ss, ct, sk) != 0)
            TEST_FAILED("KAT: kyber_r3_decapsulate failed");
        if (memcmp(ss, exp_ss, sizeof(ss)) != 0)
            TEST_FAILED("KAT: decapsulate(sk, ct) != ss");

        ct[kat->bad_byte] ^= 0x01;
        if (kyber_r3_decapsulate(ss, ct, sk) != 0)
            TEST_FAILED("KAT: kyber_r3_decapsulate(corrupted ct) failed");
        if (memcmp(ss, exp_ss_bad, sizeof(ss)) != 0)
            TEST_FAILED("KAT: decapsulate(sk, ct_bad) != ss_bad (implicit rejection)");
    }

    TEST_PASSED("all vectors match the pre-port (c86cad72) legacy KAT");
    return 0;
}

/**
 * Test keypair generation
 */
static int test_keypair_generation(void) {
    printf("\n1. Testing keypair generation...\n");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t sk[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk, sk);
    if (ret != 0) TEST_FAILED("Keypair generation failed");
    TEST_PASSED("Keypair generation succeeded");

    // Verify keys are not all zeros (sanity check)
    int pk_nonzero = 0, sk_nonzero = 0;
    for (size_t i = 0; i < QGP_KEM1024_PUBLICKEYBYTES; i++) {
        if (pk[i] != 0) pk_nonzero = 1;
    }
    for (size_t i = 0; i < QGP_KEM1024_SECRETKEYBYTES; i++) {
        if (sk[i] != 0) sk_nonzero = 1;
    }

    if (!pk_nonzero) TEST_FAILED("Public key is all zeros");
    if (!sk_nonzero) TEST_FAILED("Secret key is all zeros");
    TEST_PASSED("Keys contain non-zero data");

    return 0;
}

/**
 * Test encapsulation/decapsulation round-trip
 */
static int test_encap_decap_round_trip(void) {
    printf("\n2. Testing encapsulation/decapsulation round-trip...\n");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t sk[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk, sk);
    if (ret != 0) TEST_FAILED("Keypair generation failed");

    // Encapsulate: generate shared secret and ciphertext
    uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t ss_enc[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_encapsulate(ct, ss_enc, pk);
    if (ret != 0) TEST_FAILED("Encapsulation failed");
    TEST_PASSED("Encapsulation succeeded");

    // Decapsulate: recover shared secret from ciphertext
    uint8_t ss_dec[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_decapsulate(ss_dec, ct, sk);
    if (ret != 0) TEST_FAILED("Decapsulation failed");
    TEST_PASSED("Decapsulation succeeded");

    // Verify shared secrets match
    if (memcmp(ss_enc, ss_dec, QGP_KEM1024_SHAREDSECRET_BYTES) != 0) {
        TEST_FAILED("Shared secrets don't match!");
    }
    TEST_PASSED("Shared secrets match");

    return 0;
}

/**
 * Test wrong secret key produces different shared secret
 */
static int test_wrong_secret_key(void) {
    printf("\n3. Testing wrong secret key handling...\n");

    // Generate two different keypairs
    uint8_t pk1[QGP_KEM1024_PUBLICKEYBYTES], sk1[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t pk2[QGP_KEM1024_PUBLICKEYBYTES], sk2[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk1, sk1);
    if (ret != 0) TEST_FAILED("Keypair 1 generation failed");

    ret = qgp_kem1024_keypair(pk2, sk2);
    if (ret != 0) TEST_FAILED("Keypair 2 generation failed");

    // Encapsulate with pk1
    uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t ss_enc[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_encapsulate(ct, ss_enc, pk1);
    if (ret != 0) TEST_FAILED("Encapsulation failed");

    // Decapsulate with wrong key (sk2)
    uint8_t ss_wrong[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_decapsulate(ss_wrong, ct, sk2);
    // Note: Kyber decapsulation doesn't fail - it produces garbage output
    // This is by design (implicit rejection)

    // Shared secrets should NOT match
    if (memcmp(ss_enc, ss_wrong, QGP_KEM1024_SHAREDSECRET_BYTES) == 0) {
        TEST_FAILED("Wrong key produced matching shared secret!");
    }
    TEST_PASSED("Wrong key produces different shared secret (implicit rejection)");

    return 0;
}

/**
 * Test corrupted ciphertext handling
 */
static int test_corrupted_ciphertext(void) {
    printf("\n4. Testing corrupted ciphertext handling...\n");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t sk[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk, sk);
    if (ret != 0) TEST_FAILED("Keypair generation failed");

    // Encapsulate
    uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t ss_enc[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_encapsulate(ct, ss_enc, pk);
    if (ret != 0) TEST_FAILED("Encapsulation failed");

    // Corrupt the ciphertext
    ct[100] ^= 0xFF;
    ct[500] ^= 0xFF;

    // Decapsulate corrupted ciphertext
    uint8_t ss_corrupted[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_decapsulate(ss_corrupted, ct, sk);
    // Kyber uses implicit rejection - decapsulation "succeeds" but produces garbage

    // Shared secrets should NOT match
    if (memcmp(ss_enc, ss_corrupted, QGP_KEM1024_SHAREDSECRET_BYTES) == 0) {
        TEST_FAILED("Corrupted ciphertext produced matching shared secret!");
    }
    TEST_PASSED("Corrupted ciphertext produces different shared secret");

    return 0;
}

/**
 * Test multiple operations produce different results
 */
static int test_multiple_encapsulations(void) {
    printf("\n5. Testing multiple encapsulations produce unique results...\n");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t sk[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk, sk);
    if (ret != 0) TEST_FAILED("Keypair generation failed");

    // Perform two encapsulations
    uint8_t ct1[QGP_KEM1024_CIPHERTEXTBYTES], ct2[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t ss1[QGP_KEM1024_SHAREDSECRET_BYTES], ss2[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_encapsulate(ct1, ss1, pk);
    if (ret != 0) TEST_FAILED("First encapsulation failed");

    ret = qgp_kem1024_encapsulate(ct2, ss2, pk);
    if (ret != 0) TEST_FAILED("Second encapsulation failed");

    // Ciphertexts should be different (randomized)
    if (memcmp(ct1, ct2, QGP_KEM1024_CIPHERTEXTBYTES) == 0) {
        TEST_FAILED("Two encapsulations produced identical ciphertexts!");
    }
    TEST_PASSED("Encapsulations produce unique ciphertexts");

    // Shared secrets should be different
    if (memcmp(ss1, ss2, QGP_KEM1024_SHAREDSECRET_BYTES) == 0) {
        TEST_FAILED("Two encapsulations produced identical shared secrets!");
    }
    TEST_PASSED("Encapsulations produce unique shared secrets");

    // But decapsulation should still work for both
    uint8_t ss1_dec[QGP_KEM1024_SHAREDSECRET_BYTES], ss2_dec[QGP_KEM1024_SHAREDSECRET_BYTES];

    ret = qgp_kem1024_decapsulate(ss1_dec, ct1, sk);
    if (ret != 0 || memcmp(ss1, ss1_dec, QGP_KEM1024_SHAREDSECRET_BYTES) != 0) {
        TEST_FAILED("First decapsulation failed");
    }

    ret = qgp_kem1024_decapsulate(ss2_dec, ct2, sk);
    if (ret != 0 || memcmp(ss2, ss2_dec, QGP_KEM1024_SHAREDSECRET_BYTES) != 0) {
        TEST_FAILED("Second decapsulation failed");
    }
    TEST_PASSED("Both decapsulations succeeded");

    return 0;
}

/**
 * Test multiple keypairs are unique
 */
static int test_unique_keypairs(void) {
    printf("\n6. Testing keypair uniqueness...\n");

    uint8_t pk1[QGP_KEM1024_PUBLICKEYBYTES], sk1[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t pk2[QGP_KEM1024_PUBLICKEYBYTES], sk2[QGP_KEM1024_SECRETKEYBYTES];

    int ret = qgp_kem1024_keypair(pk1, sk1);
    if (ret != 0) TEST_FAILED("First keypair generation failed");

    ret = qgp_kem1024_keypair(pk2, sk2);
    if (ret != 0) TEST_FAILED("Second keypair generation failed");

    if (memcmp(pk1, pk2, QGP_KEM1024_PUBLICKEYBYTES) == 0) {
        TEST_FAILED("Two keypairs have identical public keys!");
    }
    TEST_PASSED("Public keys are unique");

    if (memcmp(sk1, sk2, QGP_KEM1024_SECRETKEYBYTES) == 0) {
        TEST_FAILED("Two keypairs have identical secret keys!");
    }
    TEST_PASSED("Secret keys are unique");

    return 0;
}

/**
 * Test key sizes match constants
 */
static int test_key_sizes(void) {
    printf("\n7. Verifying key size constants...\n");

    printf("   Public key:     %d bytes\n", QGP_KEM1024_PUBLICKEYBYTES);
    printf("   Secret key:     %d bytes\n", QGP_KEM1024_SECRETKEYBYTES);
    printf("   Ciphertext:     %d bytes\n", QGP_KEM1024_CIPHERTEXTBYTES);
    printf("   Shared secret:  %d bytes\n", QGP_KEM1024_SHAREDSECRET_BYTES);

    // Verify expected Kyber1024 sizes
    if (QGP_KEM1024_PUBLICKEYBYTES != 1568) TEST_FAILED("Public key size mismatch");
    if (QGP_KEM1024_SECRETKEYBYTES != 3168) TEST_FAILED("Secret key size mismatch");
    if (QGP_KEM1024_CIPHERTEXTBYTES != 1568) TEST_FAILED("Ciphertext size mismatch");
    if (QGP_KEM1024_SHAREDSECRET_BYTES != 32) TEST_FAILED("Shared secret size mismatch");

    TEST_PASSED("All key sizes match Kyber1024 specification");
    return 0;
}

/**
 * Stress test: multiple operations
 */
static int test_stress(void) {
    printf("\n8. Stress testing (100 operations)...\n");

    uint8_t pk[QGP_KEM1024_PUBLICKEYBYTES];
    uint8_t sk[QGP_KEM1024_SECRETKEYBYTES];
    uint8_t ct[QGP_KEM1024_CIPHERTEXTBYTES];
    uint8_t ss_enc[QGP_KEM1024_SHAREDSECRET_BYTES];
    uint8_t ss_dec[QGP_KEM1024_SHAREDSECRET_BYTES];

    for (int i = 0; i < 100; i++) {
        // Generate new keypair each iteration
        if (qgp_kem1024_keypair(pk, sk) != 0) {
            printf("   ✗ Keypair generation failed at iteration %d\n", i);
            return 1;
        }

        // Encapsulate
        if (qgp_kem1024_encapsulate(ct, ss_enc, pk) != 0) {
            printf("   ✗ Encapsulation failed at iteration %d\n", i);
            return 1;
        }

        // Decapsulate
        if (qgp_kem1024_decapsulate(ss_dec, ct, sk) != 0) {
            printf("   ✗ Decapsulation failed at iteration %d\n", i);
            return 1;
        }

        // Verify
        if (memcmp(ss_enc, ss_dec, QGP_KEM1024_SHAREDSECRET_BYTES) != 0) {
            printf("   ✗ Shared secret mismatch at iteration %d\n", i);
            return 1;
        }
    }

    TEST_PASSED("100 operations completed successfully");
    return 0;
}

/**
 * Security information
 */
static void print_security_info(void) {
    printf("\n9. Security Parameters\n");
    printf("   Algorithm: Kyber1024 round-3 (pre-FIPS-203) — LEGACY\n");
    printf("   Standard: none (round-3 is FIPS 203's direct predecessor, not FIPS 203 itself)\n");
    printf("   Security Level: NIST Category 5 (256-bit post-quantum)\n");
    printf("   Public key: 1568 bytes\n");
    printf("   Secret key: 3168 bytes\n");
    printf("   Ciphertext: 1568 bytes\n");
    printf("   Shared secret: 32 bytes (256 bits)\n");
    printf("   Properties: IND-CCA2 secure, implicit rejection\n");
    printf("   See test_mlkem1024.c for the FIPS-203-conformant ML-KEM-1024 API.\n");
}

int main(void) {
    printf("=== Kyber1024 round-3 (LEGACY) Unit Tests (P1-4) ===\n");

    int failed = 0;

    failed += test_legacy_kat();
    failed += test_keypair_generation();
    failed += test_encap_decap_round_trip();
    failed += test_wrong_secret_key();
    failed += test_corrupted_ciphertext();
    failed += test_multiple_encapsulations();
    failed += test_unique_keypairs();
    failed += test_key_sizes();
    failed += test_stress();

    print_security_info();

    printf("\n");
    if (failed == 0) {
        printf("=== All Kyber1024 round-3 (LEGACY) Tests Passed ===\n");
        return 0;
    } else {
        printf("=== %d Test(s) Failed ===\n", failed);
        return 1;
    }
}
