/**
 * @file test_keccak_air_sha3_512.c
 * @brief Single-block SHA3-512 AIR cross-validation (Sub-sprint 3.3b.7).
 *
 * Tests:
 *   T1: For various input strings ≤ 70 bytes, build witness then
 *       (a) constraints all pass, (b) output_bits decode to bytes
 *           matching keccak_ref_sha3_512.
 *   T2: Tamper output bit → reject ('Q').
 *   T3: Tamper padded bit → reject ('D' or 'S').
 *
 * Each witness is ~6 MB — we heap-allocate.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../keccak_ref.h"
#include "../keccak_air_sha3_512.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) { total_passed++; printf("  %-58s PASS\n", label); }
    else    { total_failed++; printf("  %-58s FAIL\n", label); }
}

/* Reconstruct a byte from 8 binary field cells (bit 0 = LSB). */
static uint8_t bits_to_byte(const gold_fp2_t bits[8]) {
    uint8_t b = 0;
    for (int i = 0; i < 8; i++) {
        if (gold_fp_to_u64(bits[i].a) & 1) b |= (uint8_t)(1u << i);
    }
    return b;
}

static void test_input(const char *label, const uint8_t *input, uint32_t input_len) {
    keccak_air_sha3_512_witness_t *w =
        (keccak_air_sha3_512_witness_t *)calloc(1, sizeof(*w));
    if (!w) { fprintf(stderr, "oom\n"); total_failed++; return; }

    int rc = keccak_air_sha3_512_build_witness(input, input_len, w);
    if (rc != 0) {
        fprintf(stderr, "    (build failed rc=%d)\n", rc);
        total_failed++; free(w); return;
    }

    char phase = 0; uint32_t fi = 0;
    bool constraints_ok = keccak_air_sha3_512_check_constraints(w, &phase, &fi);
    if (!constraints_ok) {
        fprintf(stderr, "    (constraint phase=%c idx=%u)\n", phase, fi);
    }

    /* Decode output bytes from output_bits. */
    uint8_t got[64];
    for (int i = 0; i < 64; i++) got[i] = bits_to_byte(&w->output_bits[i * 8]);

    /* Reference. */
    uint8_t expected[64];
    keccak_ref_sha3_512(input, input_len, expected);
    bool bytes_match = (memcmp(got, expected, 64) == 0);

    assert_pass(label, constraints_ok && bytes_match);
    free(w);
}

static void test_tamper_output_bit(void) {
    const uint8_t input[] = "abc";
    keccak_air_sha3_512_witness_t *w =
        (keccak_air_sha3_512_witness_t *)calloc(1, sizeof(*w));
    keccak_air_sha3_512_build_witness(input, 3, w);
    w->output_bits[0] = gold_fp2_sub(gold_fp2_one(), w->output_bits[0]);

    char phase = 0;
    bool ok = keccak_air_sha3_512_check_constraints(w, &phase, NULL);
    assert_pass("tamper output bit → 'Q' constraint fires", !ok && phase == 'Q');
    free(w);
}

static void test_tamper_padded_bit(void) {
    const uint8_t input[] = "abc";
    keccak_air_sha3_512_witness_t *w =
        (keccak_air_sha3_512_witness_t *)calloc(1, sizeof(*w));
    keccak_air_sha3_512_build_witness(input, 3, w);
    /* Flip a padded zero-byte bit. */
    w->padded_bits[200] = gold_fp2_sub(gold_fp2_one(), w->padded_bits[200]);

    char phase = 0;
    bool ok = keccak_air_sha3_512_check_constraints(w, &phase, NULL);
    /* 'D' padding rule fail or 'S' state binding fail. */
    assert_pass("tamper padded bit → 'D' or 'S'",
                !ok && (phase == 'D' || phase == 'S'));
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.7 — keccak_air_sha3_512 single-block self-test\n");
    printf("============================================================\n\n");
    printf("(~6 MB per witness; building 5 + 2 cases)\n\n");

    printf("T1: Valid SHA3-512 single-block (AIR output matches keccak_ref)\n");
    {
        test_input("empty input", (const uint8_t *)"", 0);
        test_input("'abc' (3 bytes)", (const uint8_t *)"abc", 3);
        const uint8_t pattern16[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        test_input("16-byte pattern", pattern16, 16);

        uint8_t input40[40];
        for (int i = 0; i < 40; i++) input40[i] = (uint8_t)(i * 17 + 3);
        test_input("40-byte pseudo-random", input40, 40);

        uint8_t input70[70];
        for (int i = 0; i < 70; i++) input70[i] = (uint8_t)(i ^ 0xA5);
        test_input("70-byte (max single-block)", input70, 70);
    }

    printf("\nT2: Tamper output bit\n");
    test_tamper_output_bit();

    printf("\nT3: Tamper padded bit (padding rule)\n");
    test_tamper_padded_bit();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.7 (keccak_air_sha3_512) GATE: GREEN — single-block SHA3-512 AIR e2e\n");
        return 0;
    }
    printf("SUB-SPRINT 3.3b.7 (keccak_air_sha3_512) GATE: RED — %d failures\n", total_failed);
    return 1;
}
