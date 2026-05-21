/**
 * @file test_keccak_air_iota.c
 * @brief Cross-validate ι step AIR encoding (Sub-sprint 3.3b.5).
 *
 * Tests against keccak_ref_iota for all 24 round constants + tamper variants.
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
#include "../keccak_air_iota.h"

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

static void test_round_constant(unsigned round_idx, uint64_t seed) {
    char label[80];
    snprintf(label, sizeof(label), "ι with RC[%u] (seed %" PRIu64 ")", round_idx, seed);

    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(seed, in);
    memcpy(out, in, sizeof(out));
    uint64_t rc = keccak_ref_round_constants[round_idx];
    keccak_ref_iota(out, rc);

    keccak_air_iota_witness_t *w = (keccak_air_iota_witness_t *)calloc(1, sizeof(*w));
    keccak_air_iota_build_witness(in, out, w);
    char fc = 0; uint32_t fi = 0;
    bool ok = keccak_air_iota_check_constraints(w, rc, &fc, &fi);
    if (!ok) fprintf(stderr, "    (failed C%c at idx %u)\n", fc, fi);
    assert_pass(label, ok);
    free(w);
}

static void test_tamper_lane0_output(unsigned z) {
    char label[80];
    snprintf(label, sizeof(label), "tamper output[lane0, z=%u] (expect X)", z);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(42, in);
    memcpy(out, in, sizeof(out));
    uint64_t rc = keccak_ref_round_constants[7];
    keccak_ref_iota(out, rc);

    keccak_air_iota_witness_t *w = (keccak_air_iota_witness_t *)calloc(1, sizeof(*w));
    keccak_air_iota_build_witness(in, out, w);
    w->output_bits[z] = gold_fp2_sub(gold_fp2_one(), w->output_bits[z]);

    char fc = 0;
    bool ok = keccak_air_iota_check_constraints(w, rc, &fc, NULL);
    assert_pass(label, !ok && fc == 'X');
    free(w);
}

static void test_tamper_lane_pass_through(unsigned tamper_lane) {
    char label[80];
    snprintf(label, sizeof(label), "tamper output[lane%u] (expect I)", tamper_lane);
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(42, in);
    memcpy(out, in, sizeof(out));
    uint64_t rc = keccak_ref_round_constants[7];
    keccak_ref_iota(out, rc);

    keccak_air_iota_witness_t *w = (keccak_air_iota_witness_t *)calloc(1, sizeof(*w));
    keccak_air_iota_build_witness(in, out, w);
    /* Flip a bit in a pass-through lane. */
    w->output_bits[tamper_lane * KECCAK_BITS_PER_LANE] =
        gold_fp2_sub(gold_fp2_one(),
                     w->output_bits[tamper_lane * KECCAK_BITS_PER_LANE]);

    char fc = 0;
    bool ok = keccak_air_iota_check_constraints(w, rc, &fc, NULL);
    assert_pass(label, !ok && fc == 'I');
    free(w);
}

/* Tamper: use WRONG round constant in verifier. */
static void test_wrong_rc(void) {
    uint64_t in[KECCAK_NUM_LANES], out[KECCAK_NUM_LANES];
    seed_state(42, in);
    memcpy(out, in, sizeof(out));
    /* Prover uses RC[5]. */
    keccak_ref_iota(out, keccak_ref_round_constants[5]);

    keccak_air_iota_witness_t *w = (keccak_air_iota_witness_t *)calloc(1, sizeof(*w));
    keccak_air_iota_build_witness(in, out, w);

    /* Verifier checks with RC[12] — should reject. */
    char fc = 0;
    bool ok = keccak_air_iota_check_constraints(w,
                                                keccak_ref_round_constants[12],
                                                &fc, NULL);
    assert_pass("verifier uses wrong RC (expect X)", !ok && fc == 'X');
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.5 — keccak_air_iota self-test\n");
    printf("==================================================\n\n");

    printf("T1: All 24 round constants (valid)\n");
    for (unsigned r = 0; r < KECCAK_NUM_ROUNDS; r++) {
        test_round_constant(r, 100 + r);
    }

    printf("\nT2: Tamper output bit in lane 0 (XOR fails)\n");
    test_tamper_lane0_output(0);
    test_tamper_lane0_output(31);
    test_tamper_lane0_output(63);

    printf("\nT3: Tamper pass-through lane bit (identity fails)\n");
    test_tamper_lane_pass_through(1);
    test_tamper_lane_pass_through(12);
    test_tamper_lane_pass_through(24);

    printf("\nT4: Verifier uses wrong RC\n");
    test_wrong_rc();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.5 (keccak_air_iota) GATE: GREEN\n");
        return 0;
    }
    printf("SUB-SPRINT 3.3b.5 (keccak_air_iota) GATE: RED — %d failures\n", total_failed);
    return 1;
}
