/**
 * @file test_keccak_air_chi.c
 * @brief Cross-validate χ step AIR encoding (Sub-sprint 3.3b.4).
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
#include "../keccak_air_chi.h"

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
    snprintf(label, sizeof(label), "valid χ witness (seed %" PRIu64 ")", seed);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_chi(out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_chi_check_constraints(w, &fc, &fi);
    if (!ok) fprintf(stderr, "    (failed C%c at idx %u)\n", fc, fi);
    assert_pass(label, ok);
    free(w);
}

/* Edge cases — all zeros, all ones. */
static void test_edge_zeros(void) {
    uint64_t in[KECCAK_NUM_LANES] = {0}, out[KECCAK_NUM_LANES];
    memcpy(out, in, sizeof(out));
    keccak_ref_chi(out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);
    bool ok = keccak_air_chi_check_constraints(w, NULL, NULL);
    assert_pass("all-zero state → χ → constraints pass", ok);
    free(w);
}

static void test_edge_ones(void) {
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    for (int i = 0; i < KECCAK_NUM_LANES; i++) in[i] = UINT64_MAX;
    memcpy(out, in, sizeof(out));
    keccak_ref_chi(out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);
    bool ok = keccak_air_chi_check_constraints(w, NULL, NULL);
    assert_pass("all-ones state → χ → constraints pass", ok);
    free(w);
}

/* Tamper output bit → XOR formula fails. */
static void test_tamper_output(uint64_t seed, unsigned tamper_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper output bit %u (expect X)", tamper_idx);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_chi(out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);
    w->output_bits[tamper_idx] = gold_fp2_sub(gold_fp2_one(), w->output_bits[tamper_idx]);

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_chi_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok && fc == 'X');
    free(w);
}

/* Tamper t (aux witness) → t formula fails. */
static void test_tamper_t(uint64_t seed, unsigned tamper_idx) {
    char label[80];
    snprintf(label, sizeof(label), "tamper t aux %u (expect F or T)", tamper_idx);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    keccak_ref_chi(out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);
    /* Force t to non-binary (=2) — will fail either T (binary) or F (formula). */
    w->t_bits[tamper_idx] = gold_fp2_from_base(gold_fp_from_u64(2));

    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_chi_check_constraints(w, &fc, &fi);
    assert_pass(label, !ok && (fc == 'T' || fc == 'F'));
    free(w);
}

/* Wrong output_lanes — unrelated state. */
static void test_wrong_output(void) {
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(0xCAFE, in);
    seed_state(0xBABE, out);

    keccak_air_chi_witness_t *w = (keccak_air_chi_witness_t *)calloc(1, sizeof(*w));
    keccak_air_chi_build_witness(in, out, w);
    bool ok = keccak_air_chi_check_constraints(w, NULL, NULL);
    assert_pass("wrong output_lanes (unrelated state)", !ok);
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.4 — keccak_air_chi self-test\n");
    printf("==================================================\n\n");

    printf("T1: Valid χ witnesses\n");
    test_valid(0);
    test_valid(1);
    test_valid(0xDEADBEEFULL);
    test_valid(0xCAFEBABEULL);
    test_valid(0x123456789ABCDEF0ULL);

    printf("\nT2: Edge states\n");
    test_edge_zeros();
    test_edge_ones();

    printf("\nT3: Tamper output bit\n");
    test_tamper_output(42, 0);
    test_tamper_output(42, 800);
    test_tamper_output(42, 1599);

    printf("\nT4: Tamper t aux witness\n");
    test_tamper_t(42, 0);
    test_tamper_t(42, 800);
    test_tamper_t(42, 1599);

    printf("\nT5: Wrong output_lanes\n");
    test_wrong_output();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.4 (keccak_air_chi) GATE: GREEN\n");
        return 0;
    }
    printf("SUB-SPRINT 3.3b.4 (keccak_air_chi) GATE: RED — %d failures\n", total_failed);
    return 1;
}
