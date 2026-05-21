/**
 * @file test_range_air.c
 * @brief Self-test for range_air (Sub-sprint 3.1).
 *
 * Validates:
 *   - Trace generation produces a constraint-satisfying trace for various amounts.
 *   - range_air_recover_amount roundtrips correctly.
 *   - Tamper variants all REJECT with the correct failing constraint:
 *       * Set bit_i = 2 (non-binary) → C1 fails at row i
 *       * Set acc_0 = something other than bit_0 → C2 fails at row 0
 *       * Set acc_i wrong → C3 fails at the transition into row i
 *
 * No oracle vectors — range_air is DNAC-internal AIR; correctness is
 * self-evident from the closed-form constraint equations. Cross-validation
 * against Plonky3 is unnecessary here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../range_air.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) {
        total_passed++;
        printf("  %-50s PASS\n", label);
    } else {
        total_failed++;
        printf("  %-50s FAIL\n", label);
    }
}

static void test_valid_amount(uint64_t amount) {
    char label[80];
    snprintf(label, sizeof(label), "valid amount 0x%016" PRIx64, amount);

    range_air_row_t trace[RANGE_AIR_NUM_BITS];
    range_air_generate_trace(amount, trace);

    char fc = 0;
    uint32_t fr = 0;
    bool ok = range_air_check_constraints(trace, &fc, &fr);
    if (!ok) {
        fprintf(stderr, "    (failed C%c at row %u)\n", fc, fr);
    }
    bool roundtrip_ok = (range_air_recover_amount(trace) == amount);
    assert_pass(label, ok && roundtrip_ok);
}

static void test_tamper_bit_nonbinary(uint64_t amount, uint32_t tamper_row) {
    char label[80];
    snprintf(label, sizeof(label), "tamper bit_%u → 2 (C1 expected)", tamper_row);

    range_air_row_t trace[RANGE_AIR_NUM_BITS];
    range_air_generate_trace(amount, trace);
    /* Set bit_{tamper_row} = 2 (non-binary). */
    trace[tamper_row].bit = gold_fp2_from_base(gold_fp_from_u64(2));

    char fc = 0;
    uint32_t fr = 0;
    bool ok = range_air_check_constraints(trace, &fc, &fr);
    /* Should REJECT, and the first failing constraint should be C1 at the tampered row. */
    bool reject_ok = (!ok) && (fc == '1') && (fr == tamper_row);
    assert_pass(label, reject_ok);
}

static void test_tamper_acc_0(uint64_t amount) {
    /* Force trace to have bit_0 = 0 but acc_0 = 1, breaking C2. */
    range_air_row_t trace[RANGE_AIR_NUM_BITS];
    range_air_generate_trace(amount, trace);
    trace[0].bit = gold_fp2_zero();
    trace[0].acc = gold_fp2_one();  /* Now acc_0 != bit_0. */

    char fc = 0;
    uint32_t fr = 0;
    bool ok = range_air_check_constraints(trace, &fc, &fr);
    /* The bit is binary, so C1 passes. C2 should fail at row 0. */
    bool reject_ok = (!ok) && (fc == '2') && (fr == 0);
    assert_pass("tamper acc_0 ≠ bit_0 (C2 expected)", reject_ok);
}

static void test_tamper_acc_transition(uint64_t amount, uint32_t row) {
    char label[80];
    snprintf(label, sizeof(label), "tamper acc_%u → +1 (C3 expected)", row);

    range_air_row_t trace[RANGE_AIR_NUM_BITS];
    range_air_generate_trace(amount, trace);
    /* Bump acc at the given row by 1 — should break C3 at that row's transition. */
    trace[row].acc = gold_fp2_add(trace[row].acc, gold_fp2_one());

    char fc = 0;
    uint32_t fr = 0;
    bool ok = range_air_check_constraints(trace, &fc, &fr);
    /* When row > 0, C3 fails at row (the transition into it). When row = 0,
     * C2 fails first (acc_0 != bit_0). */
    bool reject_ok = false;
    if (row == 0) {
        reject_ok = (!ok) && (fc == '2') && (fr == 0);
    } else {
        reject_ok = (!ok) && (fc == '3') && (fr == row);
    }
    assert_pass(label, reject_ok);
}

int main(void) {
    printf("Sub-sprint 3.1 — range_air self-test\n");
    printf("==================================================\n\n");

    /* T1: valid amounts < Goldilocks p.
     * (Amounts ≥ p would reduce mod p, breaking roundtrip — that's by design;
     * see range_air.h "Field bound caveat".) */
    printf("T1: Valid amounts → all constraints pass + roundtrip\n");
    test_valid_amount(0);
    test_valid_amount(1);
    test_valid_amount(2);
    test_valid_amount(255);
    test_valid_amount(1ULL << 32);
    test_valid_amount(1ULL << 57);              /* DNAC supply ceiling band */
    test_valid_amount(1ULL << 63);
    test_valid_amount(0x123456789ABCDEF0ULL);   /* fits in [0, p) */
    test_valid_amount(0xDEADBEEFCAFEBABEULL);
    test_valid_amount(0xFFFFFFFF00000000ULL);   /* p - 1 = largest representable */

    printf("\nT2: Tamper bit (C1 violation)\n");
    test_tamper_bit_nonbinary(0xAAAAAAAAAAAAAAAAULL, 0);
    test_tamper_bit_nonbinary(0xAAAAAAAAAAAAAAAAULL, 7);
    test_tamper_bit_nonbinary(0xAAAAAAAAAAAAAAAAULL, 32);
    test_tamper_bit_nonbinary(0xAAAAAAAAAAAAAAAAULL, 63);

    printf("\nT3: Tamper acc_0 (C2 violation)\n");
    test_tamper_acc_0(0xFFFFFFFFFFFFFFFFULL);

    printf("\nT4: Tamper acc transition (C3 violation)\n");
    test_tamper_acc_transition(0x123456789ABCDEF0ULL, 1);
    test_tamper_acc_transition(0x123456789ABCDEF0ULL, 5);
    test_tamper_acc_transition(0x123456789ABCDEF0ULL, 30);
    test_tamper_acc_transition(0x123456789ABCDEF0ULL, 63);

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.1 (range_air) GATE: GREEN — trace gen + constraint eval + tamper rejection all work\n");
        return 0;
    } else {
        printf("SUB-SPRINT 3.1 (range_air) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
