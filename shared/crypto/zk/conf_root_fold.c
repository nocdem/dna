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
#include "poseidon2_fold.h" /* dnac_poseidon2_fold_eval (shared fp2 block fold) */

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
    dnac_poseidon2_fold_eval(f, CONF_COMMIT_VC_OFF);
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
    dnac_poseidon2_fold_eval(f, CONF_ROOT_CA1_OFF);
    dnac_poseidon2_fold_eval(f, CONF_ROOT_CA2_OFF);
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
