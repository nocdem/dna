/*
 * test_bip39_pbkdf2_oom — K-01 regression: a failed allocation inside
 * PBKDF2-HMAC-SHA512 / bip39_mnemonic_to_seed must be reported (-1) with the
 * output wiped, never returned as a (wrong) successful seed.
 *
 * What it proves
 *   - For each allocation index 1..N inside the call (the salt copy, the
 *     salt||INT(block) buffer, and the per-HMAC inner buffers in the first,
 *     second and a late iteration) forcing that malloc to fail gives -1 and an
 *     all-zero output buffer (pre-filled with 0xAA so an untouched buffer is
 *     detected). Covers a 64-byte and a 128-byte (two block) output.
 *   - The success path is unchanged: output equals OpenSSL's independent
 *     PKCS5_PBKDF2_HMAC(SHA-512) for the same inputs (2048 rounds, the BIP-39
 *     "abandon ... about" phrase from test_bip39_bip32.c, passphrases "" and
 *     "TREZOR"; a 128-byte output also exercises block 2). The existing
 *     test_bip39_bip32 shielded-seed KAT pins the same seed bytes indirectly.
 *
 * Test-only seam: no production hook. bip39_pbkdf2.c is compiled into this
 * executable and the target is linked with -Wl,--wrap=malloc, so only malloc
 * calls from this executable's objects (the code under test) reach
 * __wrap_malloc below.
 *
 * Build flags: none beyond the CMake target (-Wl,--wrap=malloc).
 * Leaves behind: nothing. False pass: if the failure index were never reached
 * the call would succeed and the -1 assertion fails, so a miss is not a pass;
 * the "reached" counter assertion also guards the sweep range.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

#include "crypto/key/bip39/bip39.h"

void *__real_malloc(size_t n);

static int g_fail_at = 0;   /* 1-based index of the malloc to fail; 0 = never */
static int g_count = 0;

void *__wrap_malloc(size_t n) {
    if (g_fail_at > 0) {
        g_count++;
        if (g_count == g_fail_at) return NULL;
    }
    return __real_malloc(n);
}

#define MNEMONIC "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("  FAIL: %s\n", msg); g_failures++; } } while (0)

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static void sweep_pbkdf2(size_t out_len) {
    static const uint8_t salt[] = "mnemonic";
    /* malloc indices: 1 = salt||INT(block), 2 = first HMAC, 3 = second HMAC,
     * 7 and 2047 = later HMAC rounds (2049 mallocs per block in total) */
    int idx[] = {1, 2, 3, 7, 2047};
    for (size_t k = 0; k < sizeof(idx) / sizeof(idx[0]); k++) {
        uint8_t out[128];
        memset(out, 0xAA, sizeof(out));
        g_count = 0;
        g_fail_at = idx[k];
        int rc = bip39_pbkdf2_hmac_sha512((const uint8_t *)MNEMONIC, strlen(MNEMONIC),
                                          salt, sizeof(salt) - 1, 2048, out, out_len);
        int reached = g_count >= g_fail_at;
        g_fail_at = 0;
        CHECK(reached, "failure index was reached");
        CHECK(rc == -1, "pbkdf2 returns -1 on allocation failure");
        CHECK(all_zero(out, out_len), "pbkdf2 output wiped on allocation failure");
        CHECK(out[out_len] == 0xAA || out_len == sizeof(out), "bytes past output untouched");
    }
    if (out_len == 128) {
        /* failure inside block 2 (after block 1 wrote its half): the whole
         * output, including the finished first half, must be wiped */
        uint8_t out[128];
        memset(out, 0xAA, sizeof(out));
        g_count = 0;
        g_fail_at = 2049 + 3;   /* block 1 = 2049 mallocs; +3 = third HMAC of block 2 */
        int rc = bip39_pbkdf2_hmac_sha512((const uint8_t *)MNEMONIC, strlen(MNEMONIC),
                                          salt, sizeof(salt) - 1, 2048, out, out_len);
        g_fail_at = 0;
        CHECK(rc == -1, "pbkdf2 block 2 failure returns -1");
        CHECK(all_zero(out, out_len), "pbkdf2 wipes finished block 1 when block 2 fails");
    }
}

static void sweep_seed(void) {
    int idx[] = {1, 2, 3, 2048};
    for (size_t k = 0; k < sizeof(idx) / sizeof(idx[0]); k++) {
        uint8_t seed[BIP39_SEED_SIZE];
        memset(seed, 0xAA, sizeof(seed));
        g_count = 0;
        g_fail_at = idx[k];
        int rc = bip39_mnemonic_to_seed(MNEMONIC, "", seed);
        int reached = g_count >= g_fail_at;
        g_fail_at = 0;
        CHECK(reached, "seed: failure index was reached");
        CHECK(rc == -1, "bip39_mnemonic_to_seed returns -1 on allocation failure");
        CHECK(all_zero(seed, sizeof(seed)), "seed wiped on allocation failure");
    }
}

static void known_answer(const char *pass, size_t out_len) {
    uint8_t salt[64] = "mnemonic";
    size_t salt_len = 8;
    memcpy(salt + salt_len, pass, strlen(pass));
    salt_len += strlen(pass);

    uint8_t ref[128], got[128];
    int ok = PKCS5_PBKDF2_HMAC(MNEMONIC, (int)strlen(MNEMONIC), salt, (int)salt_len,
                               2048, EVP_sha512(), (int)out_len, ref);
    CHECK(ok == 1, "OpenSSL reference computed");
    int rc = bip39_pbkdf2_hmac_sha512((const uint8_t *)MNEMONIC, strlen(MNEMONIC),
                                      salt, salt_len, 2048, got, out_len);
    CHECK(rc == 0, "pbkdf2 succeeds without fault");
    CHECK(memcmp(ref, got, out_len) == 0, "pbkdf2 matches OpenSSL PKCS5_PBKDF2_HMAC");

    if (out_len == BIP39_SEED_SIZE) {
        uint8_t seed[BIP39_SEED_SIZE];
        rc = bip39_mnemonic_to_seed(MNEMONIC, pass, seed);
        CHECK(rc == 0, "bip39_mnemonic_to_seed succeeds without fault");
        CHECK(memcmp(ref, seed, BIP39_SEED_SIZE) == 0, "seed matches OpenSSL reference");
    }
}

int main(void) {
    printf("test_bip39_pbkdf2_oom\n");
    sweep_pbkdf2(64);
    sweep_pbkdf2(128);
    sweep_seed();
    known_answer("", 64);
    known_answer("TREZOR", 64);
    known_answer("", 128);
    if (g_failures) { printf("FAILED (%d)\n", g_failures); return 1; }
    printf("PASSED\n");
    return 0;
}
