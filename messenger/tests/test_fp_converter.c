/*
 * test_fp_converter.c — round-trip + error-path tests for the shared
 * fingerprint hex<->raw converters (qgp_fp_raw_to_hex / qgp_fp_hex_to_raw).
 *
 * Consolidates the ad-hoc inline converters that previously lived in
 * dnac/src/transaction/stake.c and nodus/src/witness/nodus_witness_bft.c
 * (plus two sites in dnac/src/nodus/).
 */

#include "crypto/utils/qgp_fingerprint.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "test_fp_converter: FAIL — %s (line %d)\n", \
                #cond, __LINE__); \
        return 1; \
    } \
} while (0)

static int test_roundtrip_random(void) {
    /* Deterministic PRNG: rand(). Seed is fixed so a failure is
     * reproducible in CI. */
    srand(0x5EEDFACE);

    for (int iter = 0; iter < 1000; iter++) {
        uint8_t raw[QGP_FP_RAW_BYTES];
        for (size_t i = 0; i < QGP_FP_RAW_BYTES; i++) {
            raw[i] = (uint8_t)(rand() & 0xFF);
        }

        char hex[QGP_FP_HEX_BUFFER];
        qgp_fp_raw_to_hex(raw, hex);

        /* Must be exactly 128 chars + NUL. */
        CHECK(strlen(hex) == QGP_FP_HEX_CHARS);

        /* All characters must be lowercase hex. */
        for (size_t i = 0; i < QGP_FP_HEX_CHARS; i++) {
            char c = hex[i];
            CHECK((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }

        uint8_t raw_back[QGP_FP_RAW_BYTES];
        CHECK(qgp_fp_hex_to_raw(hex, raw_back) == 0);
        CHECK(memcmp(raw, raw_back, QGP_FP_RAW_BYTES) == 0);
    }
    return 0;
}

static int test_invalid_inputs(void) {
    uint8_t raw[QGP_FP_RAW_BYTES];

    /* NULL */
    CHECK(qgp_fp_hex_to_raw(NULL, raw) == -1);

    /* Empty */
    CHECK(qgp_fp_hex_to_raw("", raw) == -1);

    /* Too short (127 chars) */
    char short_hex[128];
    memset(short_hex, 'a', 127);
    short_hex[127] = '\0';
    CHECK(qgp_fp_hex_to_raw(short_hex, raw) == -1);

    /* Too long (129 chars) */
    char long_hex[130];
    memset(long_hex, 'a', 129);
    long_hex[129] = '\0';
    CHECK(qgp_fp_hex_to_raw(long_hex, raw) == -1);

    /* Uppercase rejected — project convention is lowercase only. */
    char upper_hex[QGP_FP_HEX_BUFFER];
    memset(upper_hex, 'A', QGP_FP_HEX_CHARS);
    upper_hex[QGP_FP_HEX_CHARS] = '\0';
    CHECK(qgp_fp_hex_to_raw(upper_hex, raw) == -1);

    /* Non-hex char in middle: 'g' */
    char bad_hex[QGP_FP_HEX_BUFFER];
    memset(bad_hex, 'a', QGP_FP_HEX_CHARS);
    bad_hex[QGP_FP_HEX_CHARS] = '\0';
    bad_hex[50] = 'g';
    CHECK(qgp_fp_hex_to_raw(bad_hex, raw) == -1);

    /* Embedded NUL at position 10 (string shorter than expected) */
    char nul_hex[QGP_FP_HEX_BUFFER];
    memset(nul_hex, 'a', QGP_FP_HEX_CHARS);
    nul_hex[QGP_FP_HEX_CHARS] = '\0';
    nul_hex[10] = '\0';
    CHECK(qgp_fp_hex_to_raw(nul_hex, raw) == -1);

    return 0;
}

static int test_deterministic(void) {
    /* Same raw must produce identical hex twice. */
    uint8_t raw[QGP_FP_RAW_BYTES];
    for (size_t i = 0; i < QGP_FP_RAW_BYTES; i++) {
        raw[i] = (uint8_t)(i * 3 + 7);
    }

    char hex1[QGP_FP_HEX_BUFFER];
    char hex2[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(raw, hex1);
    qgp_fp_raw_to_hex(raw, hex2);
    CHECK(memcmp(hex1, hex2, QGP_FP_HEX_BUFFER) == 0);

    return 0;
}

static int test_known_vectors(void) {
    /* All-zero raw -> 128 '0' chars. */
    uint8_t raw_zero[QGP_FP_RAW_BYTES];
    memset(raw_zero, 0, sizeof(raw_zero));
    char hex_zero[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(raw_zero, hex_zero);
    for (size_t i = 0; i < QGP_FP_HEX_CHARS; i++) {
        CHECK(hex_zero[i] == '0');
    }
    CHECK(hex_zero[QGP_FP_HEX_CHARS] == '\0');

    /* All-0xFF raw -> 128 'f' chars. */
    uint8_t raw_ff[QGP_FP_RAW_BYTES];
    memset(raw_ff, 0xFF, sizeof(raw_ff));
    char hex_ff[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(raw_ff, hex_ff);
    for (size_t i = 0; i < QGP_FP_HEX_CHARS; i++) {
        CHECK(hex_ff[i] == 'f');
    }

    /* Specific byte pattern 0xDE 0xAD 0xBE 0xEF ... */
    uint8_t raw_vec[QGP_FP_RAW_BYTES];
    for (size_t i = 0; i < QGP_FP_RAW_BYTES; i++) {
        raw_vec[i] = (uint8_t)(i + 0x10);
    }
    char hex_vec[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(raw_vec, hex_vec);

    /* First byte 0x10 -> "10" */
    CHECK(hex_vec[0] == '1' && hex_vec[1] == '0');
    /* Byte at index 10 (value 0x1A) -> "1a" at hex[20..21] */
    CHECK(hex_vec[20] == '1' && hex_vec[21] == 'a');

    /* Parse back and compare. */
    uint8_t raw_back[QGP_FP_RAW_BYTES];
    CHECK(qgp_fp_hex_to_raw(hex_vec, raw_back) == 0);
    CHECK(memcmp(raw_vec, raw_back, QGP_FP_RAW_BYTES) == 0);

    return 0;
}

int main(void) {
    if (test_roundtrip_random() != 0) return 1;
    if (test_invalid_inputs()   != 0) return 1;
    if (test_deterministic()    != 0) return 1;
    if (test_known_vectors()    != 0) return 1;

    printf("test_fp_converter: OK\n");
    return 0;
}
