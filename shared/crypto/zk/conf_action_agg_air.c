/**
 * @file conf_action_agg_air.c
 * @brief Dual-mode S4 — aggregate Action AIR (C1 ⊕ C3 ⊕ C4). S4a.1: scaffold.
 *
 * See conf_action_agg_air.h for the layout, phase schedule, and build roadmap.
 * is_zk=0 construction-gate style: generate an honest trace, eval returns the
 * count of violated constraints (0 == valid witness). S4a.1 reuses the C1 AIR
 * losslessly (scatter on generate, gather on eval) and adds the forced is_nf
 * phase selector; membership + nullifier regions are RESERVED (S4a.2/3).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_action_agg_air.h"

#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }
static gold_fp_t bool_res(gold_fp_t s) {
    return mul(s, sub(s, gold_fp_one()));
}

/* The forced nullifier-phase index φ = D+1. */
#define CONF_AGG_NF_PHI ((uint64_t)(CONF_AGG_TREE_DEPTH + 1))

bool conf_action_agg_air_generate(unsigned log_height, const uint64_t *value,
                                  const uint64_t *addr, const uint64_t *rcm,
                                  const uint8_t *roles, const uint64_t *pos,
                                  const uint64_t *nk, const uint64_t *ak,
                                  size_t num_notes, uint64_t *trace_out) {
    if (log_height < CONF_ACTION_MIN_LOG_HEIGHT ||
        log_height > CONF_ACTION_MAX_LOG_HEIGHT)
        return false;
    if (!trace_out) return false;

    const size_t rows = (size_t)1 << log_height;

    /* Zero the whole aggregate trace (reserved membership/nf regions stay 0). */
    for (size_t i = 0; i < rows * CONF_AGG_WIDTH; i++) trace_out[i] = 0;

    /* Generate the standalone C1 trace into an 813-wide scratch buffer. */
    uint64_t *c1 = (uint64_t *)calloc(rows * CONF_ACTION_WIDTH, sizeof(uint64_t));
    if (!c1) return false;
    if (!conf_action_air_generate(log_height, value, addr, rcm, roles, pos, nk,
                                  ak, num_notes, c1)) {
        free(c1);
        return false;
    }

    /* Scatter the C1 region into each wide row + fill the forced is_nf selector. */
    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_AGG_WIDTH;
        memcpy(row + CONF_AGG_C1_OFF, c1 + r * CONF_ACTION_WIDTH,
               CONF_ACTION_WIDTH * sizeof(uint64_t));

        const uint64_t phi = (uint64_t)(r % CONF_ACTION_K);
        const uint64_t is_nf = (phi == CONF_AGG_NF_PHI) ? 1u : 0u;
        /* d = φ − (D+1) as a FIELD subtraction (matches eval); inv when is_nf==0. */
        const gold_fp_t d = sub(fp(phi), fp(CONF_AGG_NF_PHI));
        row[CONF_AGG_ISNF_OFF] = is_nf;
        row[CONF_AGG_INVNF_OFF] = is_nf ? 0 : gold_fp_to_u64(gold_fp_inv(d));
    }

    free(c1);
    return true;
}

int conf_action_agg_air_eval(const uint64_t *trace, size_t n_rows) {
    if (!trace || n_rows == 0) return 1;
    int viol = 0;

    /* ── C1 constraints: gather the C1 region + reuse conf_action_air_eval ── */
    uint64_t *c1 = (uint64_t *)calloc(n_rows * CONF_ACTION_WIDTH, sizeof(uint64_t));
    if (!c1) return 1;
    for (size_t r = 0; r < n_rows; r++)
        memcpy(c1 + r * CONF_ACTION_WIDTH,
               trace + r * CONF_AGG_WIDTH + CONF_AGG_C1_OFF,
               CONF_ACTION_WIDTH * sizeof(uint64_t));
    viol += conf_action_air_eval(c1, n_rows);
    free(c1);

    /* ── Forced is_nf phase selector: is_zero(φ − (D+1)) (== C1's phi_is0 gadget,
     * so is_nf is FORCED by the already-forced φ, not a free witness). ── */
    const gold_fp_t one = gold_fp_one();
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_AGG_WIDTH;
        const gold_fp_t phi = fp(row[CONF_AGG_C1_OFF + CONF_ACTION_PHI_OFF]);
        const gold_fp_t is_nf = fp(row[CONF_AGG_ISNF_OFF]);
        const gold_fp_t inv = fp(row[CONF_AGG_INVNF_OFF]);
        const gold_fp_t d = sub(phi, fp(CONF_AGG_NF_PHI));
        /* is_nf² = is_nf ; d·inv = 1 − is_nf ; d·is_nf = 0. */
        if (!gold_fp_is_zero(bool_res(is_nf))) viol++;
        if (!gold_fp_eq(mul(d, inv), sub(one, is_nf))) viol++;
        if (!gold_fp_is_zero(mul(d, is_nf))) viol++;
    }

    return viol;
}
