/**
 * @file test_keccak_p3.c
 * @brief Plonky3-style Keccak-f AIR self-test (Sub-sprint 3.4r).
 *
 * Tests:
 *   T1: trace generation byte-matches keccak_ref_f1600 on diverse inputs
 *   T2: valid traces pass keccak_p3_check_constraints
 *   T3: 2-permutation batch (48 rows) — boundary transitions handled
 *   T4: tamper each constraint family → expected failure ID
 *
 * Trace is ~500 KB per permutation; heap-allocate.
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

#include "../keccak_p3_cols.h"
#include "../keccak_p3_trace.h"
#include "../keccak_p3_air.h"
#include "../keccak_ref.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) { total_passed++; printf("  %-58s PASS\n", label); }
    else    { total_failed++; printf("  %-58s FAIL\n", label); }
}

/* T1: trace output byte-match keccak_ref_f1600. */
static void test_trace_matches_ref(const char *label, const uint64_t in[25]) {
    keccak_p3_cols_t *rows = calloc(KECCAK_P3_NUM_ROUNDS, sizeof(*rows));
    if (!rows) { total_failed++; return; }
    keccak_p3_generate_trace_one_perm(rows, in);

    uint64_t out[25], ref[25];
    keccak_p3_extract_output(rows, out);
    memcpy(ref, in, sizeof(ref));
    keccak_ref_f1600(ref);

    assert_pass(label, memcmp(out, ref, sizeof(out)) == 0);
    free(rows);
}

/* T2: valid trace passes constraints. */
static void test_valid_constraints(const char *label, const uint64_t in[25]) {
    keccak_p3_cols_t *rows = calloc(KECCAK_P3_NUM_ROUNDS, sizeof(*rows));
    keccak_p3_generate_trace_one_perm(rows, in);

    char c = 0; uint32_t r = 0, idx = 0;
    bool ok = keccak_p3_check_constraints(rows, KECCAK_P3_NUM_ROUNDS, &c, &r, &idx);
    if (!ok) fprintf(stderr, "    (constraint='%c' row=%u idx=0x%x)\n", c, r, idx);
    assert_pass(label, ok);
    free(rows);
}

/* T3: batch of 2 permutations (48 rows). */
static void test_batch_two(void) {
    uint64_t a[25] = {0}, b[25] = {0};
    for (int i = 0; i < 25; i++) a[i] = (uint64_t)i;
    for (int i = 0; i < 25; i++) b[i] = (uint64_t)i * 0xDEADBEEFULL;

    keccak_p3_cols_t *rows = calloc(2u * KECCAK_P3_NUM_ROUNDS, sizeof(*rows));
    keccak_p3_generate_trace_one_perm(&rows[0],                       a);
    keccak_p3_generate_trace_one_perm(&rows[KECCAK_P3_NUM_ROUNDS],    b);

    char c = 0; uint32_t r = 0, idx = 0;
    bool ok = keccak_p3_check_constraints(rows, 2u * KECCAK_P3_NUM_ROUNDS,
                                          &c, &r, &idx);
    if (!ok) fprintf(stderr, "    (constraint='%c' row=%u idx=0x%x)\n", c, r, idx);

    /* Verify each permutation's output independently. */
    uint64_t out_a[25], out_b[25], ref_a[25], ref_b[25];
    keccak_p3_extract_output(&rows[0],                    out_a);
    keccak_p3_extract_output(&rows[KECCAK_P3_NUM_ROUNDS], out_b);
    memcpy(ref_a, a, sizeof(ref_a)); keccak_ref_f1600(ref_a);
    memcpy(ref_b, b, sizeof(ref_b)); keccak_ref_f1600(ref_b);

    bool match = memcmp(out_a, ref_a, sizeof(out_a)) == 0 &&
                 memcmp(out_b, ref_b, sizeof(out_b)) == 0;
    assert_pass("batch of 2 permutations (48 rows, constraints + outputs)",
                ok && match);
    free(rows);
}

/* Tamper helper: build a valid trace, mutate, run constraint check, return
 * (phase, ok). */
typedef struct {
    char     phase;
    uint32_t row;
    uint32_t idx;
    bool     ok;
} tamper_result_t;

static tamper_result_t tamper_then_check(
    void (*mutate)(keccak_p3_cols_t *rows)) {
    keccak_p3_cols_t *rows = calloc(KECCAK_P3_NUM_ROUNDS, sizeof(*rows));
    uint64_t seed[25] = {0}; for (int i = 0; i < 25; i++) seed[i] = (uint64_t)(i + 1);
    keccak_p3_generate_trace_one_perm(rows, seed);

    mutate(rows);

    tamper_result_t res = {0};
    res.ok = keccak_p3_check_constraints(rows, KECCAK_P3_NUM_ROUNDS,
                                         &res.phase, &res.row, &res.idx);
    free(rows);
    return res;
}

static void tamper_step_flag(keccak_p3_cols_t *rows) {
    rows[0].step_flags[0] = gold_fp_zero();
    rows[0].step_flags[1] = gold_fp_one();
}
static void tamper_preimage(keccak_p3_cols_t *rows) {
    rows[1].preimage[0][0][0] = gold_fp_from_u64(0xBEEFu);
}
static void tamper_c_not_bool(keccak_p3_cols_t *rows) {
    rows[0].c[0][0] = gold_fp_from_u64(2u);
}
static void tamper_a_prime_bit(keccak_p3_cols_t *rows) {
    /* Flip a_prime[0][0][0] (one bit). Likely fires 'A' (limb reconstruct)
     * or 'p' (parity); both are valid signs of detection. */
    gold_fp_t cur = rows[0].a_prime[0][0][0];
    rows[0].a_prime[0][0][0] = gold_fp_is_zero(cur)
        ? gold_fp_one() : gold_fp_zero();
}
static void tamper_a_pp_limb(keccak_p3_cols_t *rows) {
    rows[0].a_prime_prime[0][1][0] =
        gold_fp_add(rows[0].a_prime_prime[0][1][0], gold_fp_one());
}
static void tamper_app_00_bit(keccak_p3_cols_t *rows) {
    gold_fp_t cur = rows[0].a_prime_prime_0_0_bits[0];
    rows[0].a_prime_prime_0_0_bits[0] = gold_fp_is_zero(cur)
        ? gold_fp_one() : gold_fp_zero();
}
static void tamper_app_ppp_limb(keccak_p3_cols_t *rows) {
    rows[0].a_prime_prime_prime_0_0_limbs[0] =
        gold_fp_add(rows[0].a_prime_prime_prime_0_0_limbs[0], gold_fp_one());
}
static void tamper_transition_a(keccak_p3_cols_t *rows) {
    /* Mutate next-row a[0][0][0] so transition check fails. */
    rows[1].a[0][0][0] =
        gold_fp_add(rows[1].a[0][0][0], gold_fp_one());
}

int main(void) {
    printf("Sub-sprint 3.4r — keccak_p3 (Plonky3-style AIR) self-test\n");
    printf("============================================================\n\n");

    uint64_t zero[25] = {0};
    uint64_t one[25]  = {0}; one[0] = 1;
    uint64_t seq[25]; for (int i = 0; i < 25; i++) seq[i] = (uint64_t)i * 0x0123456789ABCDEFULL;

    printf("T1: trace output byte-match vs keccak_ref_f1600\n");
    test_trace_matches_ref("zero input",          zero);
    test_trace_matches_ref("input[0]=1",          one);
    test_trace_matches_ref("sequence",            seq);

    printf("\nT2: valid traces pass AIR constraint check\n");
    test_valid_constraints("zero input constraints",      zero);
    test_valid_constraints("input[0]=1 constraints",      one);
    test_valid_constraints("sequence constraints",        seq);

    printf("\nT3: batch of two permutations (48 rows)\n");
    test_batch_two();

    printf("\nT4: tamper detection per constraint family\n");
    {
        tamper_result_t r = tamper_then_check(tamper_step_flag);
        assert_pass("step_flag tamper → 'R'",
                    !r.ok && r.phase == 'R');
    }
    {
        tamper_result_t r = tamper_then_check(tamper_preimage);
        assert_pass("preimage tamper at row 1 → 'P'",
                    !r.ok && r.phase == 'P');
    }
    {
        tamper_result_t r = tamper_then_check(tamper_c_not_bool);
        assert_pass("c[0][0]=2 → 'C' bool fails",
                    !r.ok && r.phase == 'C');
    }
    {
        tamper_result_t r = tamper_then_check(tamper_a_prime_bit);
        assert_pass("a_prime bit flip → 'A' or 'p'",
                    !r.ok && (r.phase == 'A' || r.phase == 'p'));
    }
    {
        tamper_result_t r = tamper_then_check(tamper_a_pp_limb);
        assert_pass("a_prime_prime limb tamper → 'X' or 'T'",
                    !r.ok && (r.phase == 'X' || r.phase == 'T'));
    }
    {
        tamper_result_t r = tamper_then_check(tamper_app_00_bit);
        assert_pass("a_prime_prime_0_0_bits flip → 'B' or 'I'",
                    !r.ok && (r.phase == 'B' || r.phase == 'I'));
    }
    {
        tamper_result_t r = tamper_then_check(tamper_app_ppp_limb);
        assert_pass("a_prime_prime_prime tamper → 'I' or 'T'",
                    !r.ok && (r.phase == 'I' || r.phase == 'T'));
    }
    {
        tamper_result_t r = tamper_then_check(tamper_transition_a);
        assert_pass("next-row a tamper → 'T' transition fails",
                    !r.ok && r.phase == 'T');
    }

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.4r (keccak_p3 AIR) GATE: GREEN — Plonky3-style port\n");
        return 0;
    }
    printf("SUB-SPRINT 3.4r (keccak_p3 AIR) GATE: RED — %d failures\n", total_failed);
    return 1;
}
