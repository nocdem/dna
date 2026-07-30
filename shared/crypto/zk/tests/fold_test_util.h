/**
 * @file fold_test_util.h
 * @brief s1a — shared harness for the FOLD-form equivalence tests.
 *
 * Build spec: dnac/docs/plans/2026-07-29-composition-s1a-fold-evals-BUILDABLE.md
 * §4 "Eşdeğerlik testleri".
 *
 * The s1a fold modules transcribe a u64 concrete-trace evaluator into the
 * batch-STARK `air_eval` (fp2 alpha-fold) form. Their tests therefore all do the
 * SAME thing: take the u64 trace / preprocessed table / publics that the SHIPPED
 * test suite already builds, lift them into a `dnac_stark_folder_t` window, run
 * `air_eval` with the capture instrumentation on (stark_constraints.h:245-249,
 * :271-274), and look at the captured `received` values:
 *
 *   T-EQ   honest trace  -> EVERY captured `received` is zero, on every row.
 *   T-CNT  `capture_len` is the same on every row and equals the module header's
 *          documented formula (the formula is checked against a MEASURED count,
 *          never asserted from memory).
 *   T-NEG  a tampered trace -> at least ONE non-zero `received` somewhere.
 *   T-TERM a trace whose last row is left "typed" -> the `is_last_row` boundary
 *          constraint is non-zero.
 *
 * ── The lift, stated exactly ────────────────────────────────────────────────
 * Trace / preprocessed cells go into fp2 lane c0 with c1 = 0 (`gold_fp2_from_base`),
 * which is the embedding under which the fold's field arithmetic reproduces the
 * u64 evaluator's base-field arithmetic exactly. Selector values are the CONCRETE
 * row indicators — `is_first_row = 1` on row 0, `is_last_row = 1` on the last row,
 * `is_transition = 1` everywhere except the last row — NOT the unnormalized
 * Lagrange selectors a real verifier passes (`dnac_stark_selectors_at_point`,
 * stark_constraints.h:88-89). That is deliberate: with 0/1 selectors each emitted
 * residual is EXACTLY the u64 evaluator's gated residual for that row, so
 * "captured received == 0" is a per-constraint equivalence statement, not a
 * statement about one alpha-folded sum. The real verifier's unnormalized
 * selectors are a scalar multiple of these, so a zero residual stays zero.
 *
 * The next-row window WRAPS to row 0 on the last row (the trace domain is
 * cyclic). It cannot matter — `is_transition` is 0 there — and the wrap is the
 * honest model rather than a NULL the fold form has no way to represent.
 *
 * `alpha` is a fixed non-trivial constant: the capture records each residual
 * BEFORE the accumulator folds it, so alpha cannot change any verdict; it is
 * pinned only so the run is reproducible.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FOLD_TEST_UTIL_H
#define DNAC_ZK_FOLD_TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../stark_constraints.h"

/** Capture capacity. The widest s1a AIR emits well under this (transcript:
 *  255 + pow_bits + 172); an overflow is REPORTED, never silently truncated. */
#define FOLD_CAP_STEPS ((size_t)2048)

/** Fixed, non-trivial alpha (see the header note: it cannot affect a verdict). */
static inline gold_fp2_t fold_test_alpha(void) {
    return gold_fp2_new(gold_fp_from_u64(UINT64_C(0x0000000CAFEBABE1)),
                        gold_fp_from_u64(UINT64_C(0x00000000DEADBEEF)));
}

/** Result of folding ONE row. */
typedef struct {
    size_t capture_len; /**< fold steps emitted on this row            */
    size_t nonzero;     /**< captured `received` values that are != 0  */
    size_t first_bad;   /**< index of the first non-zero, or SIZE_MAX  */
    int    overflow;    /**< capture_len hit FOLD_CAP_STEPS            */
} fold_row_t;

/** Everything one fold evaluation needs, in u64 form. */
typedef struct {
    const dnac_stark_air_t *air;
    const uint64_t         *trace;      /**< n_rows * main_width          */
    size_t                  n_rows;
    size_t                  main_width;
    const uint64_t         *prep;       /**< n_rows * prep_width, or NULL */
    size_t                  prep_width;
    const uint64_t         *pub;        /**< num_pub, or NULL             */
    size_t                  num_pub;
} fold_input_t;

/** Lift `n` u64 cells into fp2 (c0 = cell, c1 = 0). */
static inline void fold_lift(const uint64_t *src, gold_fp2_t *dst, size_t n) {
    for (size_t i = 0; i < n; i++)
        dst[i] = gold_fp2_from_base(gold_fp_from_u64(src[i]));
}

/**
 * Fold row `r` of `in` and report the capture.
 *
 * Returns a result with `capture_len == 0` and `overflow = 1` on an allocation
 * failure, which a caller must treat as a test error (never as a pass).
 */
static inline fold_row_t fold_eval_row(const fold_input_t *in, size_t r) {
    fold_row_t out;
    out.capture_len = 0;
    out.nonzero = 0;
    out.first_bad = (size_t)-1;
    out.overflow = 0;

    const size_t w = in->main_width;
    const size_t pw = in->prep_width;
    const size_t nxt = (r + 1 < in->n_rows) ? r + 1 : 0; /* cyclic wrap */

    gold_fp2_t *loc = (gold_fp2_t *)calloc(w ? w : 1, sizeof(gold_fp2_t));
    gold_fp2_t *nex = (gold_fp2_t *)calloc(w ? w : 1, sizeof(gold_fp2_t));
    gold_fp2_t *ploc = (gold_fp2_t *)calloc(pw ? pw : 1, sizeof(gold_fp2_t));
    gold_fp2_t *pnex = (gold_fp2_t *)calloc(pw ? pw : 1, sizeof(gold_fp2_t));
    gold_fp_t  *pv = (gold_fp_t *)calloc(in->num_pub ? in->num_pub : 1,
                                         sizeof(gold_fp_t));
    dnac_stark_fold_step_t *cap = (dnac_stark_fold_step_t *)calloc(
        FOLD_CAP_STEPS, sizeof(dnac_stark_fold_step_t));
    if (!loc || !nex || !ploc || !pnex || !pv || !cap) {
        free(loc); free(nex); free(ploc); free(pnex); free(pv); free(cap);
        out.overflow = 1;
        return out;
    }

    fold_lift(in->trace + r * w, loc, w);
    fold_lift(in->trace + nxt * w, nex, w);
    if (in->prep && pw) {
        fold_lift(in->prep + r * pw, ploc, pw);
        fold_lift(in->prep + nxt * pw, pnex, pw);
    }
    for (size_t i = 0; i < in->num_pub; i++)
        pv[i] = gold_fp_from_u64(in->pub[i]);

    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t zero = gold_fp2_zero();

    dnac_stark_folder_t f;
    memset(&f, 0, sizeof(f));
    f.trace_local = loc;
    f.trace_next = nex;
    f.main_width = w;
    f.public_values = in->num_pub ? pv : NULL;
    f.num_public_values = in->num_pub;
    f.is_first_row = (r == 0) ? one : zero;
    f.is_last_row = (r + 1 == in->n_rows) ? one : zero;
    f.is_transition = (r + 1 < in->n_rows) ? one : zero;
    dnac_stark_fold_init(&f.fold, fold_test_alpha());
    f.capture = cap;
    f.capture_cap = FOLD_CAP_STEPS;
    f.capture_len = 0;
    f.preprocessed_local = (in->prep && pw) ? ploc : NULL;
    f.preprocessed_next = (in->prep && pw) ? pnex : NULL;
    f.prep_width = pw;

    in->air->air_eval(&f);

    out.capture_len = f.capture_len;
    out.overflow = (f.capture_len >= FOLD_CAP_STEPS);
    for (size_t i = 0; i < f.capture_len; i++) {
        if (!gold_fp2_eq(cap[i].received, zero)) {
            out.nonzero++;
            if (out.first_bad == (size_t)-1) out.first_bad = i;
        }
    }

    free(loc); free(nex); free(ploc); free(pnex); free(pv); free(cap);
    return out;
}

/** Aggregate of folding every row of a trace. */
typedef struct {
    size_t nonzero;      /**< captured non-zero residuals, all rows   */
    size_t steps_row0;   /**< capture_len on row 0                    */
    int    steps_uniform;/**< 1 iff every row emitted steps_row0      */
    int    overflow;     /**< any row overflowed the capture buffer   */
    size_t bad_row;      /**< first row with a non-zero, or SIZE_MAX  */
} fold_trace_t;

static inline fold_trace_t fold_eval_trace(const fold_input_t *in) {
    fold_trace_t T;
    T.nonzero = 0;
    T.steps_row0 = 0;
    T.steps_uniform = 1;
    T.overflow = 0;
    T.bad_row = (size_t)-1;

    for (size_t r = 0; r < in->n_rows; r++) {
        const fold_row_t R = fold_eval_row(in, r);
        if (r == 0) T.steps_row0 = R.capture_len;
        else if (R.capture_len != T.steps_row0) T.steps_uniform = 0;
        if (R.overflow) T.overflow = 1;
        T.nonzero += R.nonzero;
        if (R.nonzero && T.bad_row == (size_t)-1) T.bad_row = r;
    }
    return T;
}

/**
 * Measure the shared Poseidon2 block's own fold-step count by running
 * `dnac_poseidon2_fold_eval` on an isolated folder — the count is DERIVED from
 * the shipped code, never hand-written (the count-KAFADAN discipline).
 *
 * The caller passes the function pointer so this header does not have to include
 * poseidon2_fold.h (some fold tests link it, all of them have it available).
 */
static inline size_t fold_measure_block(void (*block_eval)(dnac_stark_folder_t *,
                                                           size_t),
                                        size_t block_width) {
    gold_fp2_t *w = (gold_fp2_t *)calloc(block_width ? block_width : 1,
                                         sizeof(gold_fp2_t));
    dnac_stark_fold_step_t *cap = (dnac_stark_fold_step_t *)calloc(
        FOLD_CAP_STEPS, sizeof(dnac_stark_fold_step_t));
    if (!w || !cap) { free(w); free(cap); return 0; }

    dnac_stark_folder_t f;
    memset(&f, 0, sizeof(f));
    f.trace_local = w;
    f.trace_next = w;
    f.main_width = block_width;
    dnac_stark_fold_init(&f.fold, fold_test_alpha());
    f.capture = cap;
    f.capture_cap = FOLD_CAP_STEPS;
    block_eval(&f, 0);
    const size_t n = f.capture_len;

    free(w);
    free(cap);
    return n;
}

#endif /* DNAC_ZK_FOLD_TEST_UTIL_H */
