/**
 * @file test_keccak_air_f1600.c
 * @brief Cross-validate 24-round Keccak-f[1600] AIR (Sub-sprint 3.3b.6).
 *
 * Witness size is ~5.7 MB; we heap-allocate per test case.
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
#include "../keccak_air_f1600.h"

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
    snprintf(label, sizeof(label), "valid f1600 witness (seed %" PRIu64 ")", seed);
    uint64_t init[KECCAK_NUM_LANES], final_[KECCAK_NUM_LANES];
    seed_state(seed, init);
    memcpy(final_, init, sizeof(final_));
    keccak_ref_f1600(final_);

    keccak_air_f1600_witness_t *w =
        (keccak_air_f1600_witness_t *)calloc(1, sizeof(*w));
    if (!w) { fprintf(stderr, "oom\n"); total_failed++; return; }

    keccak_air_f1600_build_witness(init, final_, w);

    uint32_t fr = 0; char fs = 0, ic = 0; uint32_t fi = 0;
    bool ok = keccak_air_f1600_check_constraints(w, &fr, &fs, &ic, &fi);
    if (!ok) {
        fprintf(stderr, "    (failed round %u step %c inner %c idx %u)\n",
                fr, fs, ic, fi);
    }
    assert_pass(label, ok);
    free(w);
}

static void test_tamper_inter_round_link(void) {
    uint64_t init[KECCAK_NUM_LANES], final_[KECCAK_NUM_LANES];
    seed_state(42, init);
    memcpy(final_, init, sizeof(final_));
    keccak_ref_f1600(final_);

    keccak_air_f1600_witness_t *w =
        (keccak_air_f1600_witness_t *)calloc(1, sizeof(*w));
    keccak_air_f1600_build_witness(init, final_, w);

    /* Flip one bit in round 5's iota output → round 6's theta input mismatch. */
    w->rounds[5].iota.output_bits[100] =
        gold_fp2_sub(gold_fp2_one(), w->rounds[5].iota.output_bits[100]);

    uint32_t fr = 0; char fs = 0, ic = 0;
    bool ok = keccak_air_f1600_check_constraints(w, &fr, &fs, &ic, NULL);
    /* Round 5 iota constraint sees mismatch with chi output AFTER its own
     * constraint check passes — but the linking check 'L' with marker 'N'
     * (next-round) fires for round 5's iota → round 6 theta link OR
     * iota's own state-update constraint 'X'. */
    assert_pass("tamper round 5 iota output → next-round link fails",
                !ok && fr == 5 && (fs == 'L' || fs == 'I'));
    free(w);
}

static void test_tamper_round_chi_output(void) {
    uint64_t init[KECCAK_NUM_LANES], final_[KECCAK_NUM_LANES];
    seed_state(42, init);
    memcpy(final_, init, sizeof(final_));
    keccak_ref_f1600(final_);

    keccak_air_f1600_witness_t *w =
        (keccak_air_f1600_witness_t *)calloc(1, sizeof(*w));
    keccak_air_f1600_build_witness(init, final_, w);

    /* Flip bit in round 10's chi output (lane 0, z=0). */
    w->rounds[10].chi.output_bits[0] =
        gold_fp2_sub(gold_fp2_one(), w->rounds[10].chi.output_bits[0]);

    uint32_t fr = 0; char fs = 0;
    bool ok = keccak_air_f1600_check_constraints(w, &fr, &fs, NULL, NULL);
    assert_pass("tamper round 10 chi output → C constraint or L link",
                !ok && fr == 10);
    free(w);
}

int main(void) {
    printf("Sub-sprint 3.3b.6 — keccak_air_f1600 self-test\n");
    printf("==================================================\n\n");
    printf("(Witness allocation: ~5.7 MB per case)\n\n");

    printf("T1: Valid 24-round witnesses\n");
    test_valid(0);
    test_valid(1);
    test_valid(0xDEADBEEFULL);
    test_valid(0xCAFEBABEULL);

    printf("\nT2: Tamper inter-round link (round 5 iota output)\n");
    test_tamper_inter_round_link();

    printf("\nT3: Tamper round 10 chi output\n");
    test_tamper_round_chi_output();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.6 (keccak_air_f1600) GATE: GREEN — 24-round Keccak-f assembly verified\n");
        return 0;
    }
    printf("SUB-SPRINT 3.3b.6 (keccak_air_f1600) GATE: RED — %d failures\n", total_failed);
    return 1;
}
