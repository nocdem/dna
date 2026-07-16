/**
 * @file poseidon2_fold.c
 * @brief Shared fp2 verifier-fold of one stock Poseidon2-AIR block.
 *
 * Extracted verbatim from conf_root_fold.c (the fp2 linear layers + p2fold_eval)
 * so conf_root_fold and conf_action_fold share ONE emission source. See
 * poseidon2_fold.h for the grounding.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_fold.h"

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

void dnac_poseidon2_fold_eval(dnac_stark_folder_t *f, size_t off) {
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
