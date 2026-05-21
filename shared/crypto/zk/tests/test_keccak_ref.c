/**
 * @file test_keccak_ref.c
 * @brief Cross-validate keccak_ref_sha3_512 against qgp_sha3_512 (OpenSSL).
 *
 * Tests many inputs at boundary lengths (0, 1, rate-1, rate, rate+1, 2*rate,
 * larger), known KAT (Known Answer Tests) for SHA3-512, and random-style
 * deterministic inputs.
 *
 * If our standalone impl byte-matches OpenSSL's SHA3-512 across all inputs,
 * the Keccak-f[1600] + FIPS-202 padding is correct → safe to use as the
 * AIR-encoding reference in Sub-sprint 3.3b.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../keccak_ref.h"
#include "crypto/hash/qgp_sha3.h"

static int total_passed = 0;
static int total_failed = 0;

static void hexdump(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", p[i]);
}

static void check_one(const char *label, const uint8_t *input, size_t len) {
    uint8_t got[64], expected[64];
    keccak_ref_sha3_512(input, len, got);
    int rc = qgp_sha3_512(input, len, expected);
    if (rc != 0) {
        fprintf(stderr, "  %-50s qgp_sha3_512 returned %d\n", label, rc);
        total_failed++;
        return;
    }
    if (memcmp(got, expected, 64) != 0) {
        fprintf(stderr, "  %-50s MISMATCH\n", label);
        fprintf(stderr, "    got      : ");
        hexdump(got, 64);
        fprintf(stderr, "\n    expected : ");
        hexdump(expected, 64);
        fprintf(stderr, "\n");
        total_failed++;
    } else {
        total_passed++;
        printf("  %-50s PASS\n", label);
    }
}

/* Known Answer Test from FIPS-202 / NIST test vectors. */
static void test_kat(const char *label, const uint8_t *input, size_t len,
                     const char *expected_hex) {
    uint8_t got[64], expected[64];
    if (strlen(expected_hex) != 128) {
        fprintf(stderr, "  %s: bad expected_hex length\n", label);
        total_failed++;
        return;
    }
    for (int i = 0; i < 64; i++) {
        unsigned int b;
        sscanf(expected_hex + 2 * i, "%2x", &b);
        expected[i] = (uint8_t)b;
    }
    keccak_ref_sha3_512(input, len, got);
    if (memcmp(got, expected, 64) != 0) {
        fprintf(stderr, "  %-50s MISMATCH against KAT\n", label);
        fprintf(stderr, "    got      : ");
        hexdump(got, 64);
        fprintf(stderr, "\n    expected : ");
        hexdump(expected, 64);
        fprintf(stderr, "\n");
        total_failed++;
    } else {
        total_passed++;
        printf("  %-50s PASS (KAT)\n", label);
    }
}

int main(void) {
    printf("Sub-sprint 3.3a — keccak_ref vs OpenSSL SHA3-512\n");
    printf("====================================================\n\n");

    /* T1: KAT (NIST official test vectors for SHA3-512). */
    printf("T1: NIST KAT\n");
    /* Empty input. */
    test_kat("SHA3-512(\"\") NIST KAT", (const uint8_t *)"", 0,
             "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
             "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    /* "abc" — classic NIST KAT. */
    test_kat("SHA3-512(\"abc\") NIST KAT", (const uint8_t *)"abc", 3,
             "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
             "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" — 56 bytes. */
    test_kat("SHA3-512(56-byte test) NIST KAT",
             (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
             "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
             "ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e");

    /* T2: Boundary lengths against OpenSSL. */
    printf("\nT2: Boundary lengths (vs OpenSSL)\n");
    uint8_t buf[2048];
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i * 31 + 7);

    size_t boundary_lens[] = {0, 1, 7, 8, 9, 31, 32, 63, 64, 71, 72, 73, 143, 144, 145,
                              215, 216, 256, 512, 1024, 2048};
    for (size_t i = 0; i < sizeof(boundary_lens)/sizeof(boundary_lens[0]); i++) {
        char label[64];
        snprintf(label, sizeof(label), "len=%zu", boundary_lens[i]);
        check_one(label, buf, boundary_lens[i]);
    }

    /* T3: Deterministic-random inputs at various lengths. */
    printf("\nT3: Deterministic-random inputs (vs OpenSSL)\n");
    for (size_t k = 0; k < 20; k++) {
        /* Pseudo-random length and content from k. */
        size_t len = ((k * 0x9E3779B9ULL) % 500) + 17;
        for (size_t j = 0; j < len; j++) buf[j] = (uint8_t)((k * 41 + j * 17) ^ 0xA5);
        char label[64];
        snprintf(label, sizeof(label), "rand[%zu] len=%zu", k, len);
        check_one(label, buf, len);
    }

    printf("\n----------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3a (keccak_ref) GATE: GREEN — SHA3-512 byte-matches NIST KAT + OpenSSL\n");
        return 0;
    } else {
        printf("SUB-SPRINT 3.3a (keccak_ref) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
