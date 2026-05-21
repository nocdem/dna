/**
 * @file test_keccak_air_rho_pi.c
 * @brief Cross-validate ρ + π step AIR encoding (Sub-sprint 3.3b.3).
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
#include "../keccak_air_rho_pi.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) { total_passed++; printf("  %-58s PASS\n", label); }
    else    { total_failed++; printf("  %-58s FAIL\n", label); }
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

static void test_valid(uint64_t seed) {
    char label[80];
    snprintf(label, sizeof(label), "valid ρ∘π witness (seed %" PRIu64 ")", seed);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_rho_pi(out);

    keccak_air_rho_pi_witness_t *w = (keccak_air_rho_pi_witness_t *)
        calloc(1, sizeof(*w));
    keccak_air_rho_pi_build_witness(in, out, w);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_rho_pi_check_constraints(w, &fc, &fi);
    if (!ok) fprintf(stderr, "    (failed C%c at idx %u)\n", fc, fi);
    assert_pass(label, ok);
    free(w);
}

static void test_tamper_output(uint64_t seed, unsigned tamper_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper output bit %u (expect =)", tamper_idx);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_rho_pi(out);

    keccak_air_rho_pi_witness_t *w = (keccak_air_rho_pi_witness_t *)
        calloc(1, sizeof(*w));
    keccak_air_rho_pi_build_witness(in, out, w);
    w->output_bits[tamper_idx] =
        gold_fp2_sub(gold_fp2_one(), w->output_bits[tamper_idx]);

    bool ok = keccak_air_rho_pi_check_constraints(w, NULL, NULL);
    assert_pass(label, !ok);
    free(w);
}

static void test_tamper_input(uint64_t seed, unsigned tamper_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper input bit %u (expect =)", tamper_idx);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_rho_pi(out);

    keccak_air_rho_pi_witness_t *w = (keccak_air_rho_pi_witness_t *)
        calloc(1, sizeof(*w));
    keccak_air_rho_pi_build_witness(in, out, w);
    w->input_bits[tamper_idx] =
        gold_fp2_sub(gold_fp2_one(), w->input_bits[tamper_idx]);

    bool ok = keccak_air_rho_pi_check_constraints(w, NULL, NULL);
    assert_pass(label, !ok);
    free(w);
}

/* Tamper a bit by setting it to 2 (non-binary) → 'A' or 'O' constraint fires. */
static void test_tamper_nonbinary(uint64_t seed) {
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_rho_pi(out);

    keccak_air_rho_pi_witness_t *w = (keccak_air_rho_pi_witness_t *)
        calloc(1, sizeof(*w));
    keccak_air_rho_pi_build_witness(in, out, w);
    w->input_bits[42] = gold_fp2_from_base(gold_fp_from_u64(2));

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_rho_pi_check_constraints(w, &fc, &fi);
    assert_pass("tamper input bit_42 → 2 (expect 'A')", !ok && fc == 'A');
    free(w);
}

/* Wrong output_lanes — unrelated state. */
static void test_wrong_output(void) {
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(0xCAFE, in);
    seed_state(0xBABE, out);

    keccak_air_rho_pi_witness_t *w = (keccak_air_rho_pi_witness_t *)
        calloc(1, sizeof(*w));
    keccak_air_rho_pi_build_witness(in, out, w);

    bool ok = keccak_air_rho_pi_check_constraints(w, NULL, NULL);
    assert_pass("wrong output_lanes (unrelated state)", !ok);
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.3 — keccak_air_rho_pi self-test\n");
    printf("==================================================\n\n");

    printf("T1: Valid ρ∘π witnesses\n");
    test_valid(0);
    test_valid(1);
    test_valid(0xDEADBEEFULL);
    test_valid(0xCAFEBABEULL);
    test_valid(0x123456789ABCDEF0ULL);

    printf("\nT2a: Tamper output bit\n");
    test_tamper_output(42, 0);
    test_tamper_output(42, 800);
    test_tamper_output(42, 1599);

    printf("\nT2b: Tamper input bit\n");
    test_tamper_input(42, 0);
    test_tamper_input(42, 800);
    test_tamper_input(42, 1599);

    printf("\nT2c: Non-binary bit\n");
    test_tamper_nonbinary(42);

    printf("\nT3: Wrong output_lanes\n");
    test_wrong_output();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.3 (keccak_air_rho_pi) GATE: GREEN\n");
        return 0;
    }
    printf("SUB-SPRINT 3.3b.3 (keccak_air_rho_pi) GATE: RED — %d failures\n", total_failed);
    return 1;
}
