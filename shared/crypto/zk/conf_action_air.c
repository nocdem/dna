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

#include <string.h>

#include "field_goldilocks.h"
#include "poseidon2_air.h"       /* poseidon2_air_eval_row */
#include "poseidon2_air_cols.h"  /* p2air offsets */
#include "poseidon2_air_trace.h" /* poseidon2_air_generate_row */
#include "shielded_domsep.h"     /* DNAC_DOMSEP_NOTE */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t sub(gold_fp_t a, gold_fp_t b) { return gold_fp_sub(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/* Boolean residual s·(s−1) (== 0 iff s ∈ {0,1}). */
static gold_fp_t bool_res(gold_fp_t s) {
    return mul(s, sub(s, gold_fp_one()));
}

/* Read poseidon2-air block output lane k (the final permutation state). */
static uint64_t nc_out(const uint64_t *blk, size_t k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];
}

/* Compute the in-circuit note-commitment (E9′): two poseidon2 blocks realising
 * the S0 note_commit PaddingFreeSponge<8,4,4> over (value, addr[4], rcm[2],
 * DOMSEP_NOTE), all-zero IV, DOMSEP as the last rate element of block 2. Writes
 * NC1/NC2 (P2AIR_NUM_COLS each) and returns cm = NC2.out[0..4]. Mirrors
 * conf_root_air.c do_fold (CA1/CA2 capacity carry). */
static void note_commit_blocks(uint64_t value, const uint64_t addr[4],
                               const uint64_t rcm[2], uint64_t *nc1_out,
                               uint64_t *nc2_out,
                               uint64_t cm_out[CONF_ACTION_CM_LANES]) {
    uint64_t nc1_in[8] = {value, addr[0], addr[1], addr[2], 0, 0, 0, 0};
    poseidon2_air_generate_row(nc1_in, nc1_out);
    uint64_t s1[8];
    for (int k = 0; k < 8; k++) s1[k] = nc_out(nc1_out, (size_t)k);

    uint64_t nc2_in[8] = {addr[3], rcm[0], rcm[1], DNAC_DOMSEP_NOTE,
                          s1[4], s1[5], s1[6], s1[7]};
    poseidon2_air_generate_row(nc2_in, nc2_out);
    for (int k = 0; k < CONF_ACTION_CM_LANES; k++)
        cm_out[k] = nc_out(nc2_out, (size_t)k);
}

bool conf_action_air_generate(unsigned log_height, const uint64_t *value,
                              const uint64_t *addr, const uint64_t *rcm,
                              size_t num_notes, uint64_t *trace_out) {
    if (log_height < CONF_ACTION_MIN_LOG_HEIGHT ||
        log_height > CONF_ACTION_MAX_LOG_HEIGHT)
        return false;
    if (!trace_out) return false;

    const size_t rows = (size_t)1 << log_height;
    const size_t num_blocks = rows / CONF_ACTION_K;
    /* E7: the last block MUST be dummy, so at most num_blocks-1 real notes. */
    if (num_notes + 1 > num_blocks) return false;
    if (num_notes > 0 && (!value || !addr || !rcm)) return false;

    for (size_t i = 0; i < rows * CONF_ACTION_WIDTH; i++) trace_out[i] = 0;

    /* poseidon2 block of the all-zero input — the inert filler for non-φ=0 rows
     * (a valid permutation so poseidon2_air_eval passes every row). */
    uint64_t zero_in[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t zero_blk[P2AIR_NUM_COLS];
    poseidon2_air_generate_row(zero_in, zero_blk);

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

        int is_real = (blk < num_notes) ? 1 : 0;
        row[CONF_ACTION_ISREAL_OFF] = (uint64_t)is_real;

        /* Default: inert poseidon2 blocks (valid perm of zeros) so the always-on
         * poseidon2 constraints hold on every row. */
        memcpy(row + CONF_ACTION_NC1_OFF, zero_blk, sizeof zero_blk);
        memcpy(row + CONF_ACTION_NC2_OFF, zero_blk, sizeof zero_blk);

        if (is_real && phi == 0) {
            /* S1c single-row note-commitment at the block-start φ=0 row. */
            const uint64_t *nv = value + blk;
            const uint64_t *na = addr + blk * CONF_ACTION_ADDR_LANES;
            const uint64_t *nr = rcm + blk * CONF_ACTION_RCM_LANES;
            row[CONF_ACTION_VALUE_OFF] = *nv;
            for (unsigned j = 0; j < CONF_ACTION_ADDR_LANES; j++)
                row[CONF_ACTION_ADDR_OFF + j] = na[j];
            for (unsigned j = 0; j < CONF_ACTION_RCM_LANES; j++)
                row[CONF_ACTION_RCM_OFF + j] = nr[j];

            uint64_t cm[CONF_ACTION_CM_LANES];
            note_commit_blocks(*nv, na, nr, row + CONF_ACTION_NC1_OFF,
                               row + CONF_ACTION_NC2_OFF, cm);
            /* cm_output := NC2.out (E9′); S1b carry freezes it block-wide. */
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++)
                row[CONF_ACTION_CMOUT_OFF + j] = cm[j];
        }

        /* S1b: cm_carry holds the block's commitment (0 for dummy). */
        if (is_real) {
            /* carry = the block's φ=0 cm_output. Recompute once per block at φ=0;
             * for φ>0 rows copy from the block's φ=0 row already filled. */
            const uint64_t *blk0 =
                trace_out + (blk * CONF_ACTION_K) * CONF_ACTION_WIDTH;
            for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++)
                row[CONF_ACTION_CMCARRY_OFF + j] = blk0[CONF_ACTION_CMOUT_OFF + j];
        }
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

        /* ── S1c single-row note-commitment (E9′) ─────────────────────────────
         * The two poseidon2 blocks are valid permutations on EVERY row (the
         * always-on poseidon2 constraints; non-block-start rows hold inert perms,
         * later phases will bind them). The NOTE-COMMITMENT binding fires only at
         * a block-start φ=0 REAL row — detected via is_first_row (r==0) or the
         * previous row's forced wrap (w_prev==1), the same rows E8′/E11 seed the
         * carry. */
        const uint64_t *nc1 = row + CONF_ACTION_NC1_OFF;
        const uint64_t *nc2 = row + CONF_ACTION_NC2_OFF;
        viol += poseidon2_air_eval_row(nc1);
        viol += poseidon2_air_eval_row(nc2);

        int block_start = (r == 0);
        if (r > 0) {
            const uint64_t *prev = trace + (r - 1) * CONF_ACTION_WIDTH;
            if (prev[CONF_ACTION_W_OFF] == 1) block_start = 1;
        }
        if (block_start && row[CONF_ACTION_ISREAL_OFF] == 1) {
            const uint64_t value = row[CONF_ACTION_VALUE_OFF];
            const uint64_t *ad = row + CONF_ACTION_ADDR_OFF;
            const uint64_t *rc = row + CONF_ACTION_RCM_OFF;

            /* NC1.in = [value, addr0, addr1, addr2, 0,0,0,0] (all-zero IV). */
            if (nc1[p2air_input_off(0)] != value) viol++;
            if (nc1[p2air_input_off(1)] != ad[0]) viol++;
            if (nc1[p2air_input_off(2)] != ad[1]) viol++;
            if (nc1[p2air_input_off(3)] != ad[2]) viol++;
            for (size_t k = 4; k < 8; k++)
                if (nc1[p2air_input_off(k)] != 0) viol++;

            /* NC2.in[0..4] = [addr3, rcm0, rcm1, DOMSEP_NOTE];
             * NC2.in[4..8] = NC1.out[4..8] (capacity carry). */
            if (nc2[p2air_input_off(0)] != ad[3]) viol++;
            if (nc2[p2air_input_off(1)] != rc[0]) viol++;
            if (nc2[p2air_input_off(2)] != rc[1]) viol++;
            if (nc2[p2air_input_off(3)] != DNAC_DOMSEP_NOTE) viol++;
            for (size_t k = 4; k < 8; k++)
                if (nc2[p2air_input_off(k)] != nc_out(nc1, k)) viol++;

            /* cm_output == NC2.out[0..4] (E9′ single-row). Then S1b freezes it. */
            for (size_t j = 0; j < CONF_ACTION_CM_LANES; j++)
                if (row[CONF_ACTION_CMOUT_OFF + j] != nc_out(nc2, j)) viol++;
        }

        /* E7 dummy-last: the final row is dummy ⇒ (with E6) the whole last block
         * is dummy, so the exempt wrap H−1→0 carries no real note. */
        if (r == n_rows - 1) {
            if (!gold_fp_is_zero(is_real)) viol++;
        }
    }
    return viol;
}
