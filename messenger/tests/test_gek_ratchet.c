/**
 * @file test_gek_ratchet.c
 * @brief Test GEK v2 HKDF-SHA3-256 ratchet chain
 *
 * Tests:
 * 1. HKDF determinism — same inputs produce same output
 * 2. HKDF sensitivity — different entropy produces different GEK
 * 3. Ratchet security — removed member without entropy cannot derive new GEK
 * 4. Output quality — no trivial/zero output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "messenger/gek.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/hash/qgp_sha3.h"

#define TEST_PASS "\033[32mPASS\033[0m"
#define TEST_FAIL "\033[31mFAIL\033[0m"

static int tests_run = 0;
static int tests_passed = 0;

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int is_zero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return 0;
    }
    return 1;
}

/* Test 1: HKDF determinism — same inputs → same output */
static void test_hkdf_deterministic(void) {
    tests_run++;
    printf("\n[Test %d] HKDF determinism (same inputs → same output)\n", tests_run);

    uint8_t salt[32], ikm[32];
    memset(salt, 0xAA, sizeof(salt));
    memset(ikm, 0xBB, sizeof(ikm));

    const uint8_t *info = (const uint8_t *)GEK_HKDF_INFO;
    size_t info_len = GEK_HKDF_INFO_LEN;

    uint8_t out1[GEK_KEY_SIZE], out2[GEK_KEY_SIZE];

    int rc1 = gek_hkdf_sha3_256(salt, 32, ikm, 32, info, info_len, out1, GEK_KEY_SIZE);
    int rc2 = gek_hkdf_sha3_256(salt, 32, ikm, 32, info, info_len, out2, GEK_KEY_SIZE);

    if (rc1 != 0 || rc2 != 0) {
        printf("  [%s] HKDF call failed (rc1=%d, rc2=%d)\n", TEST_FAIL, rc1, rc2);
        return;
    }

    print_hex("Run 1", out1, GEK_KEY_SIZE);
    print_hex("Run 2", out2, GEK_KEY_SIZE);

    if (memcmp(out1, out2, GEK_KEY_SIZE) == 0) {
        printf("  [%s] Same inputs produce identical output\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Same inputs produced DIFFERENT output!\n", TEST_FAIL);
    }
}

/* Test 2: Different entropy → different GEK */
static void test_hkdf_entropy_sensitivity(void) {
    tests_run++;
    printf("\n[Test %d] HKDF entropy sensitivity (different salt → different output)\n", tests_run);

    uint8_t ikm[32];
    memset(ikm, 0xCC, sizeof(ikm));

    uint8_t salt1[32], salt2[32];
    memset(salt1, 0x11, sizeof(salt1));
    memset(salt2, 0x22, sizeof(salt2));

    const uint8_t *info = (const uint8_t *)GEK_HKDF_INFO;
    size_t info_len = GEK_HKDF_INFO_LEN;

    uint8_t out1[GEK_KEY_SIZE], out2[GEK_KEY_SIZE];

    int rc1 = gek_hkdf_sha3_256(salt1, 32, ikm, 32, info, info_len, out1, GEK_KEY_SIZE);
    int rc2 = gek_hkdf_sha3_256(salt2, 32, ikm, 32, info, info_len, out2, GEK_KEY_SIZE);

    if (rc1 != 0 || rc2 != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    print_hex("Salt 0x11", out1, GEK_KEY_SIZE);
    print_hex("Salt 0x22", out2, GEK_KEY_SIZE);

    if (memcmp(out1, out2, GEK_KEY_SIZE) != 0) {
        printf("  [%s] Different entropy produces different GEK\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Different entropy produced SAME output!\n", TEST_FAIL);
    }
}

/* Test 3: Different IKM (old GEK) → different output */
static void test_hkdf_ikm_sensitivity(void) {
    tests_run++;
    printf("\n[Test %d] HKDF IKM sensitivity (different old GEK → different output)\n", tests_run);

    uint8_t salt[32];
    memset(salt, 0xDD, sizeof(salt));

    uint8_t ikm1[32], ikm2[32];
    memset(ikm1, 0x01, sizeof(ikm1));
    memset(ikm2, 0x02, sizeof(ikm2));

    const uint8_t *info = (const uint8_t *)GEK_HKDF_INFO;
    size_t info_len = GEK_HKDF_INFO_LEN;

    uint8_t out1[GEK_KEY_SIZE], out2[GEK_KEY_SIZE];

    int rc1 = gek_hkdf_sha3_256(salt, 32, ikm1, 32, info, info_len, out1, GEK_KEY_SIZE);
    int rc2 = gek_hkdf_sha3_256(salt, 32, ikm2, 32, info, info_len, out2, GEK_KEY_SIZE);

    if (rc1 != 0 || rc2 != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    print_hex("IKM 0x01", out1, GEK_KEY_SIZE);
    print_hex("IKM 0x02", out2, GEK_KEY_SIZE);

    if (memcmp(out1, out2, GEK_KEY_SIZE) != 0) {
        printf("  [%s] Different IKM produces different output\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Different IKM produced SAME output!\n", TEST_FAIL);
    }
}

/* Test 4: Output is non-zero (not degenerate) */
static void test_hkdf_nonzero_output(void) {
    tests_run++;
    printf("\n[Test %d] HKDF output quality (non-zero)\n", tests_run);

    uint8_t salt[32], ikm[32];
    if (qgp_randombytes(salt, 32) != 0 || qgp_randombytes(ikm, 32) != 0) {
        printf("  [%s] Random generation failed\n", TEST_FAIL);
        return;
    }

    const uint8_t *info = (const uint8_t *)GEK_HKDF_INFO;
    uint8_t out[GEK_KEY_SIZE];

    if (gek_hkdf_sha3_256(salt, 32, ikm, 32, info, GEK_HKDF_INFO_LEN, out, GEK_KEY_SIZE) != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    print_hex("Output", out, GEK_KEY_SIZE);

    if (!is_zero(out, GEK_KEY_SIZE)) {
        printf("  [%s] Output is non-zero\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Output is all zeros!\n", TEST_FAIL);
    }
}

/* Test 5: Ratchet chain security — removed member cannot derive new GEK */
static void test_ratchet_chain_security(void) {
    tests_run++;
    printf("\n[Test %d] Ratchet chain security (removed member cannot derive)\n", tests_run);

    /* Simulate: old_gek is known to both remaining members and removed member */
    uint8_t old_gek[GEK_KEY_SIZE];
    memset(old_gek, 0x42, sizeof(old_gek));

    /* Generate random entropy (only known to remaining members) */
    uint8_t entropy[GEK_KEY_SIZE];
    if (qgp_randombytes(entropy, GEK_KEY_SIZE) != 0) {
        printf("  [%s] Random generation failed\n", TEST_FAIL);
        return;
    }

    /* Remaining member derives new GEK with entropy */
    uint8_t new_gek_correct[GEK_KEY_SIZE];
    if (gek_hkdf_sha3_256(entropy, 32, old_gek, 32,
                           (const uint8_t *)GEK_HKDF_INFO, GEK_HKDF_INFO_LEN,
                           new_gek_correct, GEK_KEY_SIZE) != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    /* Removed member tries with wrong entropy (they don't have the real one) */
    uint8_t wrong_entropy[GEK_KEY_SIZE];
    memset(wrong_entropy, 0xFF, sizeof(wrong_entropy));

    uint8_t new_gek_wrong[GEK_KEY_SIZE];
    if (gek_hkdf_sha3_256(wrong_entropy, 32, old_gek, 32,
                           (const uint8_t *)GEK_HKDF_INFO, GEK_HKDF_INFO_LEN,
                           new_gek_wrong, GEK_KEY_SIZE) != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    /* Also try: removed member uses old_gek directly as salt (guessing) */
    uint8_t new_gek_guess[GEK_KEY_SIZE];
    if (gek_hkdf_sha3_256(old_gek, 32, old_gek, 32,
                           (const uint8_t *)GEK_HKDF_INFO, GEK_HKDF_INFO_LEN,
                           new_gek_guess, GEK_KEY_SIZE) != 0) {
        printf("  [%s] HKDF call failed\n", TEST_FAIL);
        return;
    }

    print_hex("Correct GEK  ", new_gek_correct, GEK_KEY_SIZE);
    print_hex("Wrong entropy", new_gek_wrong, GEK_KEY_SIZE);
    print_hex("Guessed salt ", new_gek_guess, GEK_KEY_SIZE);

    int wrong_differs = (memcmp(new_gek_correct, new_gek_wrong, GEK_KEY_SIZE) != 0);
    int guess_differs = (memcmp(new_gek_correct, new_gek_guess, GEK_KEY_SIZE) != 0);

    if (wrong_differs && guess_differs) {
        printf("  [%s] Removed member cannot derive correct GEK without entropy\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Removed member CAN derive GEK (wrong=%d, guess=%d)!\n",
               TEST_FAIL, !wrong_differs, !guess_differs);
    }
}

/* Test 6: gek_generate_ratcheted produces valid non-zero output */
static void test_generate_ratcheted(void) {
    tests_run++;
    printf("\n[Test %d] gek_generate_ratcheted (high-level API)\n", tests_run);

    uint8_t old_gek[GEK_KEY_SIZE];
    memset(old_gek, 0x55, sizeof(old_gek));

    uint8_t new_gek1[GEK_KEY_SIZE], new_gek2[GEK_KEY_SIZE];

    if (gek_generate_ratcheted(old_gek, new_gek1) != 0) {
        printf("  [%s] gek_generate_ratcheted call 1 failed\n", TEST_FAIL);
        return;
    }

    if (gek_generate_ratcheted(old_gek, new_gek2) != 0) {
        printf("  [%s] gek_generate_ratcheted call 2 failed\n", TEST_FAIL);
        return;
    }

    print_hex("Ratchet 1", new_gek1, GEK_KEY_SIZE);
    print_hex("Ratchet 2", new_gek2, GEK_KEY_SIZE);

    /* Each call uses fresh random entropy, so outputs must differ */
    int non_zero = !is_zero(new_gek1, GEK_KEY_SIZE) && !is_zero(new_gek2, GEK_KEY_SIZE);
    int different = (memcmp(new_gek1, new_gek2, GEK_KEY_SIZE) != 0);
    int not_old = (memcmp(new_gek1, old_gek, GEK_KEY_SIZE) != 0) &&
                  (memcmp(new_gek2, old_gek, GEK_KEY_SIZE) != 0);

    if (non_zero && different && not_old) {
        printf("  [%s] Ratcheted GEKs are non-zero, unique, and different from input\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Issues: non_zero=%d different=%d not_old=%d\n",
               TEST_FAIL, non_zero, different, not_old);
    }
}

/* Test 7: NULL parameter handling */
static void test_null_params(void) {
    tests_run++;
    printf("\n[Test %d] NULL parameter handling\n", tests_run);

    uint8_t buf[32];
    memset(buf, 0, 32);

    int rc1 = gek_hkdf_sha3_256(NULL, 32, buf, 32, buf, 14, buf, 32);
    int rc2 = gek_hkdf_sha3_256(buf, 32, NULL, 32, buf, 14, buf, 32);
    int rc3 = gek_hkdf_sha3_256(buf, 32, buf, 32, NULL, 14, buf, 32);
    int rc4 = gek_hkdf_sha3_256(buf, 32, buf, 32, buf, 14, NULL, 32);
    int rc5 = gek_generate_ratcheted(NULL, buf);
    int rc6 = gek_generate_ratcheted(buf, NULL);

    if (rc1 == -1 && rc2 == -1 && rc3 == -1 && rc4 == -1 && rc5 == -1 && rc6 == -1) {
        printf("  [%s] All NULL parameter cases return -1\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] Some NULL cases didn't return -1: %d %d %d %d %d %d\n",
               TEST_FAIL, rc1, rc2, rc3, rc4, rc5, rc6);
    }
}

/* Test 8: okm_len > 32 should fail */
static void test_oversized_output(void) {
    tests_run++;
    printf("\n[Test %d] Oversized output request rejected\n", tests_run);

    uint8_t salt[32], ikm[32], out[64];
    memset(salt, 0xAA, 32);
    memset(ikm, 0xBB, 32);

    int rc = gek_hkdf_sha3_256(salt, 32, ikm, 32,
                                (const uint8_t *)GEK_HKDF_INFO, GEK_HKDF_INFO_LEN,
                                out, 64);  /* 64 > 32 = SHA3-256 output */

    if (rc == -1) {
        printf("  [%s] okm_len=64 correctly rejected\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("  [%s] okm_len=64 was NOT rejected (rc=%d)\n", TEST_FAIL, rc);
    }
}

int main(void) {
    printf("=======================================\n");
    printf("  GEK v2 HKDF Ratchet Test Suite\n");
    printf("=======================================\n");

    test_hkdf_deterministic();
    test_hkdf_entropy_sensitivity();
    test_hkdf_ikm_sensitivity();
    test_hkdf_nonzero_output();
    test_ratchet_chain_security();
    test_generate_ratcheted();
    test_null_params();
    test_oversized_output();

    printf("\n=======================================\n");
    printf("  Results: %d/%d passed\n", tests_passed, tests_run);
    printf("=======================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
