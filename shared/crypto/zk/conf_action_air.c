/**
 * @file conf_action_air.c
 * @brief Dual-mode shielded Action AIR (C1) — S1a forced phase-counter skeleton.
 *
 * See conf_action_air.h for the row model, constraint spec, and build roadmap.
 * is_zk=0 construction-gate style (like conf_balance_air.c): generate an honest
 * trace, eval returns the number of violated constraints (0 == valid witness).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_action_air.h"

#include "field_goldilocks.h"

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/* Boolean residual s·(s−1) (== 0 iff s ∈ {0,1}). */
static gold_fp_t bool_res(gold_fp_t s) {
    return mul(s, sub(s, gold_fp_one()));
}

bool conf_action_air_generate(unsigned log_height, const uint64_t *cm,
                              size_t num_notes, uint64_t *trace_out) {
    if (log_height < CONF_ACTION_MIN_LOG_HEIGHT ||
        log_height > CONF_ACTION_MAX_LOG_HEIGHT)
        return false;
    if (!trace_out) return false;

    const size_t rows = (size_t)1 << log_height;
    const size_t num_blocks = rows / CONF_ACTION_K;
    /* E7: the last block MUST be dummy, so at most num_blocks-1 real notes. */
    if (num_notes + 1 > num_blocks) return false;
    if (num_notes > 0 && !cm) return false;

    for (size_t i = 0; i < rows * CONF_ACTION_WIDTH; i++) trace_out[i] = 0;

    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_ACTION_WIDTH;
        uint64_t phi = (uint64_t)(r % CONF_ACTION_K); /* forced cycling 0..K−1 */
        size_t blk = r / CONF_ACTION_K;

        row[CONF_ACTION_PHI_OFF] = phi;
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++)
            row[CONF_ACTION_PHIBITS_OFF + i] = (phi >> i) & 1u;

        /* w = 1 iff φ == K−1; inv = is_zero witness for d = φ − (K−1). d MUST be a
         * FIELD subtraction (matching eval); a uint64 subtraction wraps to a
         * different residue mod p and desyncs inv. */
        uint64_t w = (phi == (uint64_t)(CONF_ACTION_K - 1)) ? 1u : 0u;
        gold_fp_t d = sub(fp(phi), fp((uint64_t)(CONF_ACTION_K - 1)));
        uint64_t inv = 0;
        if (w == 0) inv = gold_fp_to_u64(gold_fp_inv(d));
        row[CONF_ACTION_W_OFF] = w;
        row[CONF_ACTION_INV_OFF] = inv;

        /* S1b freeze-carry. Real blocks [0, num_notes): IS_REAL=1, this block's
         * commitment loaded at φ=0 into cm_output, frozen block-wide in cm_carry.
         * Dummy blocks (incl. the E7 last): IS_REAL=0, cm_output/cm_carry = 0. */
        int is_real = (blk < num_notes) ? 1 : 0;
        row[CONF_ACTION_ISREAL_OFF] = (uint64_t)is_real;
        if (is_real) {
            const uint64_t *bc = cm + blk * CONF_ACTION_CM_LANES;
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++) {
                /* cm_output written ONLY at the φ=0 row (E9′ single-row); the
                 * carry holds it for the whole block. */
                if (phi == 0) row[CONF_ACTION_CMOUT_OFF + j] = bc[j];
                row[CONF_ACTION_CMCARRY_OFF + j] = bc[j];
            }
        }
        /* dummy rows already zeroed. */
    }
    return true;
}

int conf_action_air_eval(const uint64_t *trace, size_t n_rows) {
    if (!trace || n_rows == 0) return 1;
    int viol = 0;

    const gold_fp_t km1 = fp((uint64_t)(CONF_ACTION_K - 1)); /* K−1 */

    /* Precompute 2^i for i ∈ [0, LOG_K). */
    gold_fp_t pow2[CONF_ACTION_LOG_K];
    pow2[0] = gold_fp_one();
    for (unsigned i = 1; i < CONF_ACTION_LOG_K; i++)
        pow2[i] = add(pow2[i - 1], pow2[i - 1]);

    const gold_fp_t one = gold_fp_one();

    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_ACTION_WIDTH;
        gold_fp_t phi = fp(row[CONF_ACTION_PHI_OFF]);
        gold_fp_t w = fp(row[CONF_ACTION_W_OFF]);
        gold_fp_t inv = fp(row[CONF_ACTION_INV_OFF]);
        gold_fp_t is_real = fp(row[CONF_ACTION_ISREAL_OFF]);

        /* E1 range gate: φ = Σ b_i·2^i, each b_i boolean. ⇒ φ ∈ {0..K−1}. */
        gold_fp_t recomp = gold_fp_zero();
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++) {
            gold_fp_t bit = fp(row[CONF_ACTION_PHIBITS_OFF + i]);
            if (!gold_fp_is_zero(bool_res(bit))) viol++;
            recomp = add(recomp, mul(bit, pow2[i]));
        }
        if (!gold_fp_eq(recomp, phi)) viol++;

        /* E2 wrap indicator via is_zero on d = φ − (K−1):
         *   d·inv = 1 − w ,  d·w = 0 ,  w² = w   ⇒ w = 1 ⟺ d = 0 ⟺ φ = K−1. */
        gold_fp_t d = sub(phi, km1);
        if (!gold_fp_is_zero(bool_res(w))) viol++;
        if (!gold_fp_eq(mul(d, inv), sub(gold_fp_one(), w))) viol++;
        if (!gold_fp_is_zero(mul(d, w))) viol++;

        /* E13 φ anchor: is_first_row · φ = 0 ⇒ φ[0] = 0. */
        if (r == 0) {
            if (!gold_fp_is_zero(phi)) viol++;
        } else {
            /* E3 forced counter (transition r−1 → r, governed by w_{r−1}):
             *   (1 − w_prev)·(φ − φ_prev − 1) = 0   [climb when prev not wrap]
             *   w_prev·φ = 0                         [reset to 0 when prev wrap]
             * With E1+E2 this FORCES φ at every row incl. the wrap — no free
             * restart. The last row's outgoing wrap (H−1→0) is NOT a transition
             * target here (row 0 is first-row-init), matching is_transition
             * exemption (stark_constraints.c:41). */
            const uint64_t *prev = trace + (r - 1) * CONF_ACTION_WIDTH;
            gold_fp_t phi_prev = fp(prev[CONF_ACTION_PHI_OFF]);
            gold_fp_t w_prev = fp(prev[CONF_ACTION_W_OFF]);
            gold_fp_t climb = mul(sub(gold_fp_one(), w_prev),
                                  sub(sub(phi, phi_prev), gold_fp_one()));
            if (!gold_fp_is_zero(climb)) viol++;
            if (!gold_fp_is_zero(mul(w_prev, phi))) viol++;
        }

        /* ── S1b freeze-carry binding ──────────────────────────────────────── */

        /* E6 booleanity of IS_REAL. */
        if (!gold_fp_is_zero(bool_res(is_real))) viol++;

        /* PZ padding-zero: a dummy block (IS_REAL=0) carries nothing — neither a
         * frozen commitment nor a φ=0 output. Closes dummy-block injection. */
        for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++) {
            gold_fp_t carry = fp(row[CONF_ACTION_CMCARRY_OFF + j]);
            gold_fp_t out = fp(row[CONF_ACTION_CMOUT_OFF + j]);
            if (!gold_fp_is_zero(mul(sub(one, is_real), carry))) viol++;
            if (!gold_fp_is_zero(mul(sub(one, is_real), out))) viol++;
        }

        if (r == 0) {
            /* E8′ block-0 init: is_first_row·IS_REAL·(cm_carry − cm_output) = 0.
             * Row 0 (block 0, φ=0) has no incoming transition (the wrap H−1→0 is
             * exempt), so its carry is seeded here from its own cm_output — the
             * conf_root_fold.c:281-283 frozen-accumulator row-0 seed pattern. */
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++) {
                gold_fp_t carry = fp(row[CONF_ACTION_CMCARRY_OFF + j]);
                gold_fp_t out = fp(row[CONF_ACTION_CMOUT_OFF + j]);
                if (!gold_fp_is_zero(mul(is_real, sub(carry, out)))) viol++;
            }
        } else {
            const uint64_t *prev = trace + (r - 1) * CONF_ACTION_WIDTH;
            gold_fp_t w_prev = fp(prev[CONF_ACTION_W_OFF]);
            gold_fp_t isreal_prev = fp(prev[CONF_ACTION_ISREAL_OFF]);

            /* E6 block-const: IS_REAL constant across a non-wrap adjacent pair;
             * may change ONLY at the forced wrap (w_prev=1 ⇒ block boundary). */
            if (!gold_fp_is_zero(mul(sub(one, w_prev), sub(is_real, isreal_prev))))
                viol++;

            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++) {
                gold_fp_t carry = fp(row[CONF_ACTION_CMCARRY_OFF + j]);
                gold_fp_t carry_prev = fp(prev[CONF_ACTION_CMCARRY_OFF + j]);
                gold_fp_t out = fp(row[CONF_ACTION_CMOUT_OFF + j]);
                /* E4 freeze: non-wrap ⇒ carry held constant into the next row. */
                if (!gold_fp_is_zero(
                        mul(sub(one, w_prev), sub(carry, carry_prev))))
                    viol++;
                /* E11 wrap-load: at a block start (prev row wrapped) ⇒ carry loads
                 * THIS row's φ=0 cm_output. */
                if (!gold_fp_is_zero(mul(w_prev, sub(carry, out)))) viol++;
            }
        }

        /* E7 dummy-last: the final row is dummy ⇒ (with E6) the whole last block
         * is dummy, so the exempt wrap H−1→0 carries no real note. */
        if (r == n_rows - 1) {
            if (!gold_fp_is_zero(is_real)) viol++;
        }
    }
    return viol;
}
