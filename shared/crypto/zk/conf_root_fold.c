/**
 * @file conf_root_fold.c
 * @brief B1 Stage-2 — combined confidential AIR, verifier-fold (fp2) form.
 *
 * EMISSION ORDER is the contract: it mirrors the Rust-oracle ConfRootAir::eval
 * (tools/plonky3_oracle/src/main.rs) line for line — see conf_root_fold.h.
 * The Poseidon2 sub-block fold mirrors the VERBATIM-vendored
 * poseidon2-air/src/air.rs:144-323 eval (the (7,1) register S-box form,
 * degree 3); the fp2 linear layers mirror the exposed base-field generic
 * layers (poseidon2_goldilocks.c apply_mat4 / external / internal — themselves
 * pinned to poseidon2/src/external.rs:59-157 + internal.rs matmul_internal
 * with MATRIX_DIAG_8, poseidon2.rs:640) lifted componentwise to fp2 (the
 * matrices have BASE-field entries; linearity makes the lift exact).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_root_fold.h"

#include "conf_balance_air.h"
#include "conf_commit_air.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_goldilocks.h"

/* ============================================================================
 * fp2 Poseidon2 linear layers (base-constant matrices lifted to fp2)
 * ========================================================================== */

/* apply_mat4 (external.rs:59-74), fp2 lift of poseidon2_goldilocks.c. */
static void fp2_apply_mat4(gold_fp2_t x[4]) {
    gold_fp2_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3];
    gold_fp2_t two0 = gold_fp2_add(t0, t0), two1 = gold_fp2_add(t1, t1);
    gold_fp2_t two2 = gold_fp2_add(t2, t2), two3 = gold_fp2_add(t3, t3);
    gold_fp2_t thr0 = gold_fp2_add(two0, t0), thr1 = gold_fp2_add(two1, t1);
    gold_fp2_t thr2 = gold_fp2_add(two2, t2), thr3 = gold_fp2_add(two3, t3);
    x[0] = gold_fp2_add(gold_fp2_add(two0, thr1), gold_fp2_add(t2, t3));
    x[1] = gold_fp2_add(gold_fp2_add(t0, two1), gold_fp2_add(thr2, t3));
    x[2] = gold_fp2_add(gold_fp2_add(t0, t1), gold_fp2_add(two2, thr3));
    x[3] = gold_fp2_add(gold_fp2_add(thr0, t1), gold_fp2_add(t2, two3));
}

/* mds_light_permutation WIDTH=8 arm (external.rs:106-157), fp2 lift. */
static void fp2_external_linear_8(gold_fp2_t state[P2AIR_WIDTH]) {
    fp2_apply_mat4(&state[0]);
    fp2_apply_mat4(&state[4]);
    gold_fp2_t sums[4];
    for (int k = 0; k < 4; k++) sums[k] = gold_fp2_add(state[k], state[k + 4]);
    for (int i = 0; i < P2AIR_WIDTH; i++)
        state[i] = gold_fp2_add(state[i], sums[i % 4]);
}

/* matmul_internal with MATRIX_DIAG_8 (internal.rs; poseidon2.rs:640), fp2 lift. */
static void fp2_internal_linear_8(gold_fp2_t state[P2AIR_WIDTH]) {
    gold_fp2_t sum = state[0];
    for (int i = 1; i < P2AIR_WIDTH; i++) sum = gold_fp2_add(sum, state[i]);
    for (int i = 0; i < P2AIR_WIDTH; i++) {
        const gold_fp2_t diag =
            gold_fp2_from_base(gold_fp_from_u64(POSEIDON2_GOLD_MATRIX_DIAG_8[i]));
        state[i] = gold_fp2_add(gold_fp2_mul(state[i], diag), sum);
    }
}

/* ============================================================================
 * Poseidon2 block fold — mirrors the vendored air.rs:144-323 eval over one
 * 180-col block at `off` in the LOCAL window. (7,1) S-box: one committed x^3
 * register per S-box (assert committed == x^3, then x := committed^2 * x).
 * ========================================================================== */

static gold_fp2_t fp2_cube(gold_fp2_t x) {
    return gold_fp2_mul(gold_fp2_sqr(x), x);
}

/* eval_sbox (7,1) arm (air.rs:305-309): emits ONE constraint, returns the
 * degree-reduced x^7 expression value committed^2 * x. */
static gold_fp2_t fp2_sbox71(dnac_stark_folder_t *f, gold_fp2_t committed,
                             gold_fp2_t x) {
    dnac_stark_folder_assert_eq(f, committed, fp2_cube(x));
    return gold_fp2_mul(gold_fp2_sqr(committed), x);
}

static void p2fold_eval(dnac_stark_folder_t *f, size_t off) {
    const gold_fp2_t *L = f->trace_local;
    gold_fp2_t state[P2AIR_WIDTH];
    for (size_t i = 0; i < P2AIR_WIDTH; i++)
        state[i] = L[off + p2air_input_off(i)];

    /* leading external linear (air.rs:174) */
    fp2_external_linear_8(state);

    /* beginning full rounds (air.rs:176-183 -> eval_full_round :234-256) */
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++) {
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            const gold_fp2_t rc = gold_fp2_from_base(
                gold_fp_from_u64(POSEIDON2_GOLD_RC8_EXT_INITIAL[r][i]));
            state[i] = gold_fp2_add(state[i], rc);
            state[i] = fp2_sbox71(f, L[off + p2air_beg_sbox_off(r, i)], state[i]);
        }
        fp2_external_linear_8(state);
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            const gold_fp2_t post = L[off + p2air_beg_post_off(r, i)];
            dnac_stark_folder_assert_eq(f, state[i], post);
            state[i] = post;
        }
    }

    /* partial rounds (air.rs:185-192 -> eval_partial_round :258-278) */
    for (size_t r = 0; r < P2AIR_PARTIAL_ROUNDS; r++) {
        const gold_fp2_t rc =
            gold_fp2_from_base(gold_fp_from_u64(POSEIDON2_GOLD_RC8_INTERNAL[r]));
        state[0] = gold_fp2_add(state[0], rc);
        state[0] = fp2_sbox71(f, L[off + p2air_partial_sbox_off(r)], state[0]);
        const gold_fp2_t post_sbox = L[off + p2air_partial_postsbox_off(r)];
        dnac_stark_folder_assert_eq(f, state[0], post_sbox);
        state[0] = post_sbox;
        fp2_internal_linear_8(state);
    }

    /* ending full rounds (air.rs:194-201) */
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++) {
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            const gold_fp2_t rc = gold_fp2_from_base(
                gold_fp_from_u64(POSEIDON2_GOLD_RC8_EXT_FINAL[r][i]));
            state[i] = gold_fp2_add(state[i], rc);
            state[i] = fp2_sbox71(f, L[off + p2air_end_sbox_off(r, i)], state[i]);
        }
        fp2_external_linear_8(state);
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            const gold_fp2_t post = L[off + p2air_end_post_off(r, i)];
            dnac_stark_folder_assert_eq(f, state[i], post);
            state[i] = post;
        }
    }
}

/* ============================================================================
 * Combined-AIR fold eval — ORACLE emission order (ConfRootAir::eval mirror)
 * ========================================================================== */

void dnac_conf_root_fold_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t one = gold_fp2_one();

    /* §4b flat publics, promoted to fp2 (folder carries base gold_fp_t). */
    gold_fp2_t pub_root[4], pub_c_claimed[4], pub_c_fee[4];
    for (size_t j = 0; j < 4; j++) {
        pub_root[j] =
            gold_fp2_from_base(f->public_values[CONF_ROOT_FOLD_PUB_ROOT_OFF + j]);
        pub_c_claimed[j] = gold_fp2_from_base(
            f->public_values[CONF_ROOT_FOLD_PUB_C_CLAIMED_OFF + j]);
        pub_c_fee[j] =
            gold_fp2_from_base(f->public_values[CONF_ROOT_FOLD_PUB_C_FEE_OFF + j]);
    }
    const gold_fp2_t pub_hash_id =
        gold_fp2_from_base(f->public_values[CONF_ROOT_FOLD_PUB_HASH_ID_OFF]);
    /* publics[13..17) = tx_binding: FS-observed only, NEVER read here. */

    const gold_fp2_t o = L[CONF_BAL_IS_OUTPUT_OFF];
    const gold_fp2_t c = L[CONF_BAL_IS_CLAIMED_OFF];
    const gold_fp2_t fe = L[CONF_BAL_IS_FEE_OFF];
    const gold_fp2_t r = L[CONF_BAL_IS_REAL_OFF];

    /* ---- BAL block ------------------------------------------------------ */
    /* B1-B4 selector booleanity */
    dnac_stark_folder_assert_bool(f, o);
    dnac_stark_folder_assert_bool(f, c);
    dnac_stark_folder_assert_bool(f, fe);
    dnac_stark_folder_assert_bool(f, r);
    /* B5-B66 bit booleanity */
    for (size_t j = 0; j < CONF_BAL_RANGE_BITS; j++)
        dnac_stark_folder_assert_bool(f, L[CONF_BAL_BITS_OFF + j]);
    /* B67 selector sum: is_real == o + c + fe */
    dnac_stark_folder_assert_eq(f, r, gold_fp2_add(gold_fp2_add(o, c), fe));
    /* B68 padding-zero: (1 - is_real) * amount */
    dnac_stark_folder_when(f, gold_fp2_sub(one, r), L[CONF_BAL_AMOUNT_OFF]);
    /* B69 bit recomposition (weight doubling matches the oracle's
     * weight.double() chain) */
    {
        gold_fp2_t bit_sum = gold_fp2_zero();
        gold_fp2_t weight = one;
        for (size_t j = 0; j < CONF_BAL_RANGE_BITS; j++) {
            bit_sum = gold_fp2_add(bit_sum,
                                   gold_fp2_mul(L[CONF_BAL_BITS_OFF + j], weight));
            weight = gold_fp2_add(weight, weight);
        }
        dnac_stark_folder_assert_eq(f, bit_sum, L[CONF_BAL_AMOUNT_OFF]);
    }
    /* B70-B79 52-bit gate: (o + fe) * bit_j, j = 52..61 */
    for (size_t j = CONF_BAL_OUTPUT_BITS; j < CONF_BAL_RANGE_BITS; j++)
        dnac_stark_folder_when(f, gold_fp2_add(o, fe), L[CONF_BAL_BITS_OFF + j]);
    /* coeff = o + fe - c (local and next) */
    const gold_fp2_t coeff_local = gold_fp2_sub(gold_fp2_add(o, fe), c);
    const gold_fp2_t coeff_next =
        gold_fp2_sub(gold_fp2_add(N[CONF_BAL_IS_OUTPUT_OFF], N[CONF_BAL_IS_FEE_OFF]),
                     N[CONF_BAL_IS_CLAIMED_OFF]);
    /* B80-B82 first row */
    dnac_stark_folder_when(
        f, f->is_first_row,
        gold_fp2_sub(L[CONF_BAL_BAL_OFF],
                     gold_fp2_mul(coeff_local, L[CONF_BAL_AMOUNT_OFF])));
    dnac_stark_folder_when(f, f->is_first_row,
                           gold_fp2_sub(L[CONF_BAL_N_CLAIMED_OFF], c));
    dnac_stark_folder_when(f, f->is_first_row,
                           gold_fp2_sub(L[CONF_BAL_N_FEE_OFF], fe));
    /* B83-B85 transitions (next-row form) */
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_sub(gold_fp2_sub(N[CONF_BAL_BAL_OFF], L[CONF_BAL_BAL_OFF]),
                     gold_fp2_mul(coeff_next, N[CONF_BAL_AMOUNT_OFF])));
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_sub(gold_fp2_sub(N[CONF_BAL_N_CLAIMED_OFF], L[CONF_BAL_N_CLAIMED_OFF]),
                     N[CONF_BAL_IS_CLAIMED_OFF]));
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_sub(gold_fp2_sub(N[CONF_BAL_N_FEE_OFF], L[CONF_BAL_N_FEE_OFF]),
                     N[CONF_BAL_IS_FEE_OFF]));
    /* B86-B88 last row */
    dnac_stark_folder_when(f, f->is_last_row, L[CONF_BAL_BAL_OFF]);
    dnac_stark_folder_when(f, f->is_last_row,
                           gold_fp2_sub(L[CONF_BAL_N_CLAIMED_OFF], one));
    dnac_stark_folder_when(f, f->is_last_row,
                           gold_fp2_sub(L[CONF_BAL_N_FEE_OFF], one));

    /* ---- VC block: value commitment -------------------------------------- */
    /* V1 stock Poseidon2 AIR over the VC slice */
    p2fold_eval(f, CONF_COMMIT_VC_OFF);
    /* V2 COPY (SEC-2, same-window): VC.inputs[0] == BAL.amount */
    dnac_stark_folder_assert_eq(f, L[CONF_COMMIT_VC_OFF + p2air_input_off(0)],
                                L[CONF_BAL_AMOUNT_OFF]);
    /* V3-V7 CAP; V4' hash_id reads PUBLIC #12 (Stage-2/M4) */
    dnac_stark_folder_assert_zero(f, L[CONF_COMMIT_VC_OFF + p2air_input_off(3)]);
    dnac_stark_folder_assert_eq(
        f, L[CONF_COMMIT_VC_OFF + p2air_input_off(4)],
        gold_fp2_from_base(gold_fp_from_u64(CONF_COMMIT_DOMSEP_VAL)));
    dnac_stark_folder_assert_eq(f, L[CONF_COMMIT_VC_OFF + p2air_input_off(5)],
                                pub_hash_id);
    dnac_stark_folder_assert_zero(f, L[CONF_COMMIT_VC_OFF + p2air_input_off(6)]);
    dnac_stark_folder_assert_zero(f, L[CONF_COMMIT_VC_OFF + p2air_input_off(7)]);

    /* c_r = VC end_post(3, .) */
    gold_fp2_t c_r[4];
    for (size_t j = 0; j < 4; j++)
        c_r[j] = L[CONF_COMMIT_VC_OFF + p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, j)];

    /* ---- CA blocks: accumulator fold -------------------------------------- */
    /* R1/R2 stock Poseidon2 AIR over CA1 and CA2 */
    p2fold_eval(f, CONF_ROOT_CA1_OFF);
    p2fold_eval(f, CONF_ROOT_CA2_OFF);
    /* R3-R6 CA1-input chaining (first: IV=0; transition: next.CA1.in[j] ==
     * local.CACC[j]) — interleaved per j, oracle order */
    for (size_t j = 0; j < 4; j++) {
        dnac_stark_folder_when(f, f->is_first_row,
                               L[CONF_ROOT_CA1_OFF + p2air_input_off(j)]);
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_sub(N[CONF_ROOT_CA1_OFF + p2air_input_off(j)],
                         L[CONF_ROOT_CACC_OFF + j]));
    }
    /* R7-R10 CA1 capacity: DOMSEP_ACC + zero pad */
    dnac_stark_folder_assert_eq(
        f, L[CONF_ROOT_CA1_OFF + p2air_input_off(4)],
        gold_fp2_from_base(gold_fp_from_u64(CONF_ROOT_DOMSEP_ACC)));
    dnac_stark_folder_assert_zero(f, L[CONF_ROOT_CA1_OFF + p2air_input_off(5)]);
    dnac_stark_folder_assert_zero(f, L[CONF_ROOT_CA1_OFF + p2air_input_off(6)]);
    dnac_stark_folder_assert_zero(f, L[CONF_ROOT_CA1_OFF + p2air_input_off(7)]);
    /* R11-R14 CA2 rate = c_r */
    for (size_t j = 0; j < 4; j++)
        dnac_stark_folder_assert_eq(f, L[CONF_ROOT_CA2_OFF + p2air_input_off(j)],
                                    c_r[j]);
    /* R15-R18 capacity carry: CA2.in[4+k] == CA1.end_post(3, 4+k) */
    for (size_t k = 4; k < 8; k++)
        dnac_stark_folder_assert_eq(
            f, L[CONF_ROOT_CA2_OFF + p2air_input_off(k)],
            L[CONF_ROOT_CA1_OFF + p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)]);
    /* R19-R22 gated CACC freeze; s2 = CA2.end_post(3, .) */
    for (size_t j = 0; j < 4; j++) {
        const gold_fp2_t s2_local =
            L[CONF_ROOT_CA2_OFF + p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, j)];
        dnac_stark_folder_when(
            f, f->is_first_row,
            gold_fp2_sub(L[CONF_ROOT_CACC_OFF + j], gold_fp2_mul(r, s2_local)));
        const gold_fp2_t rn = N[CONF_BAL_IS_REAL_OFF];
        const gold_fp2_t s2_next =
            N[CONF_ROOT_CA2_OFF + p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, j)];
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_sub(
                gold_fp2_sub(N[CONF_ROOT_CACC_OFF + j], gold_fp2_mul(rn, s2_next)),
                gold_fp2_mul(gold_fp2_sub(one, rn), L[CONF_ROOT_CACC_OFF + j])));
    }
    /* R23-R26 last row: CACC == commitment_root public */
    for (size_t j = 0; j < 4; j++)
        dnac_stark_folder_when(
            f, f->is_last_row,
            gold_fp2_sub(L[CONF_ROOT_CACC_OFF + j], pub_root[j]));

    /* ---- Stage-2 CONSTRUCTED public bindings ------------------------------ */
    /* PB1-PB4: is_claimed * (c_r[j] - c_claimed_pub[j]) */
    for (size_t j = 0; j < 4; j++)
        dnac_stark_folder_when(f, c, gold_fp2_sub(c_r[j], pub_c_claimed[j]));
    /* PB5-PB8: is_fee * (c_r[j] - c_fee_pub[j]) */
    for (size_t j = 0; j < 4; j++)
        dnac_stark_folder_when(f, fe, gold_fp2_sub(c_r[j], pub_c_fee[j]));
}

const dnac_stark_air_t DNAC_CONF_ROOT_FOLD_AIR = {
    CONF_ROOT_WIDTH,               /* main_width = 614 */
    CONF_ROOT_FOLD_NUM_PUBLICS,    /* 17 */
    1,                             /* main_next: accumulators read the next row */
    dnac_conf_root_fold_air_eval,
};
