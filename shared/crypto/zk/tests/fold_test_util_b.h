/**
 * @file fold_test_util_b.h
 * @brief Composition s1a — the shared FOLD-EVAL harness for the two executor-B
 *        fold tests (tests/test_fri_air_fold.c, tests/test_fri_oi_air_fold.c).
 *
 * AIR-AGNOSTIC by construction: it knows only `dnac_stark_air_t` /
 * `dnac_stark_folder_t` (stark_constraints.h:262-291) and the field. It does
 * NOT know a single column offset of either AIR — which is what makes it usable
 * as the same instrument on both, and what keeps it from "helping" the AIR it
 * measures.
 *
 * ── WHAT IT DOES ────────────────────────────────────────────────────────────
 * Drives an `air_eval` callback over EVERY row of a u64 trace, with the
 * row-level selector emulation the s1a spec §4 T-EQ pins:
 *
 *   trace_local        = row r, each base cell embedded in fp2 as (cell, 0)
 *   trace_next         = row (r+1) mod n_rows   (the CYCLIC domain: the last
 *                        row's successor IS row 0 — which is exactly why the
 *                        u64 eval_trace terminality gate has to become a
 *                        constraint in fold form)
 *   preprocessed_*     = the same, from the preprocessed table
 *   is_first_row       = 1 on row 0, else 0
 *   is_last_row        = 1 on row n_rows-1, else 0
 *   is_transition      = 1 except on row n_rows-1
 *
 * and CAPTURES every emitted constraint (`folder.capture`,
 * stark_constraints.h:245-249 — the field exists for exactly this).
 *
 * ⚠ HONEST LABEL — WHAT THE 0/1 SELECTORS ARE. In a real proof the selectors
 * are the UNNORMALIZED Lagrange values at zeta (stark_constraints.h:59-73), not
 * 0/1. The harness substitutes 0/1 because the property under test is
 * "which constraints does this AIR apply to which row, and is the residual
 * zero" — a per-row statement. Both forms agree on ZERO-ness (the real
 * selectors are non-zero off their row), which is the only thing the
 * fold-vs-u64 comparison relies on. It does NOT prove anything about the
 * alpha-fold accumulator value, and it is not a substitute for the real
 * verify-side gate (that lands with the s1b composition entry + a real proof).
 *
 * ── WHAT THE CALLER COMPARES ────────────────────────────────────────────────
 * `nonzero` (the number of captured `received` values that are non-zero, summed
 * over rows) against the u64 evaluator's violation COUNT on the same trace.
 * The two are 1:1 because the fold emits the same forms in the same order with
 * the same values; the only structural difference is the terminality boundary,
 * which the u64 side reports as a fail-close instead of a count.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TESTS_FOLD_TEST_UTIL_B_H
#define DNAC_ZK_TESTS_FOLD_TEST_UTIL_B_H

#include <stddef.h>
#include <stdint.h>

#include "../field_goldilocks.h"
#include "../stark_constraints.h"

/* Caps — fail-closed: ftu_run_trace REFUSES a shape it cannot hold rather than
 * truncating silently. Sized for both B AIRs with headroom (fri: width 21 /
 * prep 73 / 43 publics / 76 steps; oi: width 20-21 / prep 106 / 18-30 publics /
 * 49-70 steps). */
#define FTU_MAX_WIDTH ((size_t)64)
#define FTU_MAX_PREP  ((size_t)128)
#define FTU_MAX_PUB   ((size_t)512)
#define FTU_MAX_STEPS ((size_t)1024)

/** Outcome of one full-trace fold run. */
typedef struct {
    size_t steps;      /**< capture_len (identical on every row, or `ragged`) */
    size_t nonzero;    /**< captured `received` values != 0, summed over rows */
    size_t first_row;  /**< row of the FIRST non-zero (SIZE_MAX if none)      */
    size_t first_step; /**< its step index within that row (SIZE_MAX if none) */
    int    ragged;     /**< capture_len differed between rows (AIR not row-
                            uniform — a defect, the count is meaningless)     */
    int    truncated;  /**< capture_cap was hit; the count is unusable        */
} ftu_result_t;

/** Embed one u64 row into the fp2 window: base cell -> (cell, 0). */
static inline void ftu_embed(gold_fp2_t *dst, const uint64_t *src, size_t n) {
    for (size_t i = 0; i < n; i++)
        dst[i] = gold_fp2_from_base(gold_fp_from_u64(src[i]));
}

/**
 * @brief Run `air->air_eval` over every row of (`main_trace`, `prep`).
 *
 * @return 1 on success (`out` filled), 0 if the shape exceeds a cap or an
 *         argument is NULL — never a partial result.
 */
static inline int ftu_run_trace(const dnac_stark_air_t *air,
                                const uint64_t *main_trace, size_t n_rows,
                                size_t main_width, const uint64_t *prep,
                                size_t prep_width, const uint64_t *pub,
                                size_t n_pub, ftu_result_t *out) {
    if (!air || !air->air_eval || !main_trace || !prep || !pub || !out) return 0;
    if (n_rows == 0 || main_width == 0 || main_width > FTU_MAX_WIDTH) return 0;
    if (prep_width == 0 || prep_width > FTU_MAX_PREP) return 0;
    if (n_pub == 0 || n_pub > FTU_MAX_PUB) return 0;

    gold_fp2_t loc[FTU_MAX_WIDTH], nxt[FTU_MAX_WIDTH];
    gold_fp2_t ploc[FTU_MAX_PREP], pnxt[FTU_MAX_PREP];
    gold_fp_t  pubs[FTU_MAX_PUB];
    dnac_stark_fold_step_t cap[FTU_MAX_STEPS];

    for (size_t i = 0; i < n_pub; i++) pubs[i] = gold_fp_from_u64(pub[i]);

    out->steps = 0;
    out->nonzero = 0;
    out->first_row = (size_t)-1;
    out->first_step = (size_t)-1;
    out->ragged = 0;
    out->truncated = 0;

    const gold_fp2_t zero = gold_fp2_zero();
    const gold_fp2_t one = gold_fp2_one();
    /* Arbitrary fixed alpha — the fold ACCUMULATOR is not what this harness
     * asserts on (it inspects the per-constraint `received`), but a fixed value
     * keeps the run deterministic. */
    const gold_fp2_t alpha =
        gold_fp2_new(gold_fp_from_u64(3), gold_fp_from_u64(5));

    for (size_t r = 0; r < n_rows; r++) {
        const size_t nr = (r + 1) % n_rows; /* CYCLIC successor */
        ftu_embed(loc, main_trace + r * main_width, main_width);
        ftu_embed(nxt, main_trace + nr * main_width, main_width);
        ftu_embed(ploc, prep + r * prep_width, prep_width);
        ftu_embed(pnxt, prep + nr * prep_width, prep_width);

        dnac_stark_folder_t folder;
        folder.trace_local = loc;
        folder.trace_next = nxt;
        folder.main_width = main_width;
        folder.public_values = pubs;
        folder.num_public_values = n_pub;
        folder.is_first_row = (r == 0) ? one : zero;
        folder.is_last_row = (r + 1 == n_rows) ? one : zero;
        folder.is_transition = (r + 1 == n_rows) ? zero : one;
        dnac_stark_fold_init(&folder.fold, alpha);
        folder.capture = cap;
        folder.capture_cap = FTU_MAX_STEPS;
        folder.capture_len = 0;
        folder.preprocessed_local = ploc;
        folder.preprocessed_next = pnxt;
        folder.prep_width = prep_width;

        air->air_eval(&folder);

        if (folder.capture_len >= FTU_MAX_STEPS) out->truncated = 1;
        if (r == 0) {
            out->steps = folder.capture_len;
        } else if (folder.capture_len != out->steps) {
            out->ragged = 1;
        }
        for (size_t s = 0; s < folder.capture_len; s++) {
            if (!gold_fp2_eq(cap[s].received, zero)) {
                if (out->nonzero == 0) {
                    out->first_row = r;
                    out->first_step = s;
                }
                out->nonzero++;
            }
        }
    }
    return 1;
}

#endif /* DNAC_ZK_TESTS_FOLD_TEST_UTIL_B_H */
