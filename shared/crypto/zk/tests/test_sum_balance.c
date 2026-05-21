/**
 * @file test_sum_balance.c
 * @brief Multi-output range + sum-balance AIR self-test (Sub-sprint 3.2).
 *
 * Tests:
 *   T1: Valid TX shapes (1, 2, 3 outputs) with correct sum balance.
 *   T2: Tamper individual output range → reject at that output.
 *   T3: Tamper sum balance (wrong claimed_input_sum) → reject with C4.
 *   T4: Tamper fee → reject with C4.
 *   T5: Tamper output trace's acc[63] (changes amount, breaks sum) → reject.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../range_air.h"
#include "../sum_balance.h"

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

/* Helper: allocate output_traces for a TX with n outputs. */
static range_air_row_t (*alloc_traces(uint32_t n))[RANGE_AIR_NUM_BITS] {
    return (range_air_row_t (*)[RANGE_AIR_NUM_BITS])
            calloc(n, sizeof(range_air_row_t) * RANGE_AIR_NUM_BITS);
}

/* T1: valid TX */
static void test_valid_tx(const char *label,
                          const uint64_t *amounts, uint32_t n,
                          uint64_t fee, uint64_t claimed_in) {
    range_air_row_t (*traces)[RANGE_AIR_NUM_BITS] = alloc_traces(n);
    sum_balance_witness_t w;
    int rc = sum_balance_generate_witness(amounts, n, fee, claimed_in, traces, &w);
    bool ok = (rc == 0) && sum_balance_check(&w, NULL, NULL, NULL);
    assert_pass(label, ok);
    free(traces);
}

/* T2: tamper an output's range constraint (set bit_5 = 2 on output i). */
static void test_tamper_output_range(const char *label,
                                     const uint64_t *amounts, uint32_t n,
                                     uint64_t fee, uint64_t claimed_in,
                                     uint32_t target_output, uint32_t target_row) {
    range_air_row_t (*traces)[RANGE_AIR_NUM_BITS] = alloc_traces(n);
    sum_balance_witness_t w;
    sum_balance_generate_witness(amounts, n, fee, claimed_in, traces, &w);

    /* Tamper. */
    traces[target_output][target_row].bit = gold_fp2_from_base(gold_fp_from_u64(2));

    uint32_t fo = 0; char fc = 0; uint32_t fr = 0;
    bool ok = sum_balance_check(&w, &fo, &fc, &fr);
    /* Should REJECT with C1 at the tampered output's tampered row. */
    bool correct_reject = (!ok) && (fo == target_output) && (fc == '1') && (fr == target_row);
    assert_pass(label, correct_reject);
    free(traces);
}

/* T3: wrong claimed_input_sum */
static void test_wrong_claimed_sum(const char *label,
                                   const uint64_t *amounts, uint32_t n,
                                   uint64_t fee, uint64_t correct_in,
                                   uint64_t wrong_in) {
    range_air_row_t (*traces)[RANGE_AIR_NUM_BITS] = alloc_traces(n);
    sum_balance_witness_t w;
    /* Generate with correct, then mutate. */
    sum_balance_generate_witness(amounts, n, fee, correct_in, traces, &w);
    w.claimed_input_sum = wrong_in;

    uint32_t fo = 0; char fc = 0; uint32_t fr = 0;
    bool ok = sum_balance_check(&w, &fo, &fc, &fr);
    bool correct_reject = (!ok) && (fo == UINT32_MAX) && (fc == '4');
    assert_pass(label, correct_reject);
    free(traces);
}

/* T4: tamper fee */
static void test_tamper_fee(const char *label,
                            const uint64_t *amounts, uint32_t n,
                            uint64_t correct_fee, uint64_t claimed_in,
                            uint64_t wrong_fee) {
    range_air_row_t (*traces)[RANGE_AIR_NUM_BITS] = alloc_traces(n);
    sum_balance_witness_t w;
    sum_balance_generate_witness(amounts, n, correct_fee, claimed_in, traces, &w);
    w.fee = wrong_fee;

    uint32_t fo = 0; char fc = 0; uint32_t fr = 0;
    bool ok = sum_balance_check(&w, &fo, &fc, &fr);
    bool correct_reject = (!ok) && (fo == UINT32_MAX) && (fc == '4');
    assert_pass(label, correct_reject);
    free(traces);
}

/* T5: tamper the final accumulator of an output trace (changes effective amount). */
static void test_tamper_acc_final(const char *label,
                                  const uint64_t *amounts, uint32_t n,
                                  uint64_t fee, uint64_t claimed_in,
                                  uint32_t target_output) {
    range_air_row_t (*traces)[RANGE_AIR_NUM_BITS] = alloc_traces(n);
    sum_balance_witness_t w;
    sum_balance_generate_witness(amounts, n, fee, claimed_in, traces, &w);

    /* Increment acc[63] by 1 — breaks both C3 (transition into row 63) AND
     * the sum balance. Since C3 is checked per-output first, we expect
     * rejection at output target_output with C3 row 63. */
    traces[target_output][RANGE_AIR_NUM_BITS - 1].acc =
        gold_fp2_add(traces[target_output][RANGE_AIR_NUM_BITS - 1].acc, gold_fp2_one());

    uint32_t fo = 0; char fc = 0; uint32_t fr = 0;
    bool ok = sum_balance_check(&w, &fo, &fc, &fr);
    bool correct_reject = (!ok) && (fo == target_output) && (fc == '3') &&
                          (fr == RANGE_AIR_NUM_BITS - 1);
    assert_pass(label, correct_reject);
    free(traces);
}

int main(void) {
    printf("Sub-sprint 3.2 — sum_balance self-test\n");
    printf("==================================================\n\n");

    /* T1: Valid TX shapes. */
    printf("T1: Valid TX shapes (multi-output + sum balance correct)\n");
    {
        uint64_t a1[] = {1000};
        test_valid_tx("1 output: 1000 + fee=1 → claimed=1001",
                      a1, 1, 1, 1001);
    }
    {
        uint64_t a2[] = {500, 495};
        test_valid_tx("2 outputs: 500+495 + fee=5 → claimed=1000",
                      a2, 2, 5, 1000);
    }
    {
        uint64_t a3[] = {100, 200, 695};
        test_valid_tx("3 outputs: 100+200+695 + fee=5 → claimed=1000",
                      a3, 3, 5, 1000);
    }
    {
        uint64_t a_zero[] = {0};
        test_valid_tx("zero amount: 0 + fee=0 → claimed=0",
                      a_zero, 1, 0, 0);
    }
    {
        uint64_t a_big[] = {1ULL << 56, 1ULL << 55};
        test_valid_tx("big amounts (DNAC supply band)",
                      a_big, 2, 100, (1ULL << 56) + (1ULL << 55) + 100);
    }

    /* T2: Tamper output range. */
    printf("\nT2: Tamper output range (per-output rejection)\n");
    {
        uint64_t a2[] = {500, 495};
        test_tamper_output_range("tamper output[0].bit_5 → 2 (C1 expected)",
                                 a2, 2, 5, 1000, 0, 5);
        test_tamper_output_range("tamper output[1].bit_10 → 2 (C1 expected)",
                                 a2, 2, 5, 1000, 1, 10);
    }

    /* T3: Wrong claimed_input_sum. */
    printf("\nT3: Wrong claimed_input_sum (C4 expected)\n");
    {
        uint64_t a2[] = {500, 495};
        test_wrong_claimed_sum("claimed_in OFF by 1 (1001 vs 1000)",
                               a2, 2, 5, 1000, 1001);
        test_wrong_claimed_sum("claimed_in OFF by lot (5000 vs 1000)",
                               a2, 2, 5, 1000, 5000);
        test_wrong_claimed_sum("claimed_in OFF by -1 (999 vs 1000)",
                               a2, 2, 5, 1000, 999);
    }

    /* T4: Tamper fee. */
    printf("\nT4: Tamper fee (C4 expected)\n");
    {
        uint64_t a2[] = {500, 495};
        test_tamper_fee("fee 5 → 6 (C4 expected)",
                        a2, 2, 5, 1000, 6);
        test_tamper_fee("fee 5 → 4 (C4 expected)",
                        a2, 2, 5, 1000, 4);
    }

    /* T5: Tamper output's final acc (breaks C3 first). */
    printf("\nT5: Tamper output's acc[63] +1 (C3 expected, per-output check)\n");
    {
        uint64_t a2[] = {500, 495};
        test_tamper_acc_final("tamper output[0].acc[63] (C3)",
                              a2, 2, 5, 1000, 0);
        test_tamper_acc_final("tamper output[1].acc[63] (C3)",
                              a2, 2, 5, 1000, 1);
    }

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.2 (sum_balance) GATE: GREEN — multi-output composition + sum balance work\n");
        return 0;
    } else {
        printf("SUB-SPRINT 3.2 (sum_balance) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
