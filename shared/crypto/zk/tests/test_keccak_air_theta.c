/**
 * @file test_keccak_air_theta.c
 * @brief Cross-validate Keccak θ step AIR encoding (Sub-sprint 3.3b.2).
 *
 * Tests:
 *   T1: For random states, theta_build_witness using (input, keccak_ref_theta(input))
 *       produces constraints that all pass.
 *   T2: theta_check_constraints rejects:
 *       a. Tampered output bit
 *       b. Tampered input bit
 *       c. Tampered C bit (constraint detects bad column parity)
 *       d. Tampered XOR-5 witness
 *       e. Tampered D bit
 *   T3: theta_check rejects when output_lanes != theta(input_lanes).
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
#include "../keccak_air_bits.h"
#include "../keccak_air_theta.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) {
        total_passed++;
        printf("  %-58s PASS\n", label);
    } else {
        total_failed++;
        printf("  %-58s FAIL\n", label);
    }
}

static void seed_state(uint64_t seed, uint64_t state[KECCAK_NUM_LANES]) {
    for (int i = 0; i < KECCAK_NUM_LANES; i++) {
        uint64_t x = seed + (uint64_t)i;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        x *= 0x9E3779B97F4A7C15ULL;
        x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
        x ^= x >> 27;
        state[i] = x;
    }
}

/* T1: valid theta witness passes. */
static void test_valid_theta(uint64_t seed) {
    char label[80];
    snprintf(label, sizeof(label), "valid θ witness (seed %" PRIu64 ")", seed);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    if (!ok) fprintf(stderr, "    (failed C%c at idx %u)\n", fc, fi);
    assert_pass(label, ok);
    free(w);
}

/* T2a: tamper output bit. */
static void test_tamper_output_bit(uint64_t seed, unsigned tamper_bit_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper output bit %u (expect U)", tamper_bit_idx);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);
    /* Flip an output bit (0 → 1 or 1 → 0). */
    w->output_bits[tamper_bit_idx] = gold_fp2_sub(gold_fp2_one(),
                                                  w->output_bits[tamper_bit_idx]);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok);
    free(w);
}

/* T2b: tamper input bit (after build_witness — output stays unchanged, so XOR-5 fails). */
static void test_tamper_input_bit(uint64_t seed, unsigned tamper_bit_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper input bit %u (expect ≠C5)", tamper_bit_idx);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);
    /* Flip an input bit AFTER witness build → C/D/output rows now inconsistent. */
    w->input_bits[tamper_bit_idx] = gold_fp2_sub(gold_fp2_one(),
                                                 w->input_bits[tamper_bit_idx]);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok);
    free(w);
}

/* T2c: tamper C bit. */
static void test_tamper_c_bit(uint64_t seed, unsigned c_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper C bit %u (expect 5 or 2 fail)", c_idx);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);
    w->c_bits[c_idx] = gold_fp2_sub(gold_fp2_one(), w->c_bits[c_idx]);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok);
    free(w);
}

/* T2d: tamper XOR-5 witness. */
static void test_tamper_xor5_witness(uint64_t seed, unsigned w_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper C xor5 witness idx %u (expect 5)", w_idx);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);
    /* Set witness to 5 (out of {0,1,2}). */
    w->c_xor5_witness[w_idx] = gold_fp2_from_base(gold_fp_from_u64(5));

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok);
    free(w);
}

/* T2e: tamper D bit. */
static void test_tamper_d_bit(uint64_t seed, unsigned d_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper D bit %u (expect 2 or U)", d_idx);
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(seed, input);
    memcpy(output, input, sizeof(output));
    keccak_ref_theta(output);

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);
    w->d_bits[d_idx] = gold_fp2_sub(gold_fp2_one(), w->d_bits[d_idx]);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok);
    free(w);
}

/* T3: wrong output_lanes (not equal to theta of input_lanes). */
static void test_wrong_output_lanes(void) {
    uint64_t input[KECCAK_NUM_LANES], output[KECCAK_NUM_LANES];
    seed_state(0xCAFE, input);
    seed_state(0xBABE, output);  /* unrelated → not theta(input) */

    keccak_air_theta_witness_t *w = (keccak_air_theta_witness_t *)
        calloc(1, sizeof(keccak_air_theta_witness_t));
    keccak_air_theta_build_witness(input, output, w);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_theta_check_constraints(w, &fc, &fi);
    /* C/D are computed correctly from input by builder, output bits decode
     * from arbitrary output_lanes → state-update U constraint fails. */
    assert_pass("wrong output_lanes (not θ(input)) rejected", !ok);
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.2 — keccak_air_theta self-test\n");
    printf("==================================================\n\n");

    printf("T1: Valid θ witnesses\n");
    test_valid_theta(0);
    test_valid_theta(1);
    test_valid_theta(0xDEADBEEFULL);
    test_valid_theta(0xCAFEBABEULL);
    test_valid_theta(0x123456789ABCDEF0ULL);

    printf("\nT2a: Tamper output bit\n");
    test_tamper_output_bit(42, 0);
    test_tamper_output_bit(42, 800);
    test_tamper_output_bit(42, 1599);

    printf("\nT2b: Tamper input bit\n");
    test_tamper_input_bit(42, 0);
    test_tamper_input_bit(42, 800);
    test_tamper_input_bit(42, 1599);

    printf("\nT2c: Tamper C bit\n");
    test_tamper_c_bit(42, 0);
    test_tamper_c_bit(42, 100);
    test_tamper_c_bit(42, 319);

    printf("\nT2d: Tamper XOR-5 witness\n");
    test_tamper_xor5_witness(42, 0);
    test_tamper_xor5_witness(42, 100);
    test_tamper_xor5_witness(42, 319);

    printf("\nT2e: Tamper D bit\n");
    test_tamper_d_bit(42, 0);
    test_tamper_d_bit(42, 100);
    test_tamper_d_bit(42, 319);

    printf("\nT3: Wrong output_lanes\n");
    test_wrong_output_lanes();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.2 (keccak_air_theta) GATE: GREEN — θ step AIR encoding verified\n");
        return 0;
    } else {
        printf("SUB-SPRINT 3.3b.2 (keccak_air_theta) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
