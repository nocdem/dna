/**
 * @file poseidon2_air.c
 * @brief Poseidon2 AIR constraint evaluation — grounded C port (FP1c.3).
 *
 * Mirrors Plonky3 poseidon2-air/src/air.rs eval / eval_full_round /
 * eval_partial_round / eval_sbox (7,1) @ 82cfad73, for the Goldilocks WIDTH=8,
 * SBOX_REGISTERS=1 instance. State is carried between rounds through the
 * COMMITTED post columns (state reset to post / post_sbox), exactly as the
 * symbolic AirBuilder eval does. Reuses the permutation module's external/
 * internal linear layers + round constants.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_air.h"

#include "field_goldilocks.h"
#include "poseidon2_goldilocks.h"

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }
static inline gold_fp_t cube(gold_fp_t x) { return mul(mul(x, x), x); }

/* eval_full_round: for each lane, assert sbox == (state+rc)^3, advance state to
 * committed_x3^2 * (state+rc), apply external MDS, assert post == state, reset
 * state to committed post. (air.rs eval_full_round + eval_sbox (7,1)). */
static void eval_full_round(gold_fp_t state[P2AIR_WIDTH], const uint64_t *row,
                            size_t r, int ending, const uint64_t rc[P2AIR_WIDTH],
                            int *viol) {
    for (size_t i = 0; i < P2AIR_WIDTH; i++) {
        gold_fp_t x = add(state[i], fp(rc[i])); /* input to S-box */
        size_t soff = ending ? p2air_end_sbox_off(r, i) : p2air_beg_sbox_off(r, i);
        gold_fp_t committed_x3 = fp(row[soff]);
        if (!gold_fp_eq(committed_x3, cube(x))) (*viol)++;       /* sbox == x^3 */
        state[i] = mul(mul(committed_x3, committed_x3), x);      /* x3^2 * x = x^7 */
    }
    poseidon2_gold_external_linear_8(state);
    for (size_t i = 0; i < P2AIR_WIDTH; i++) {
        size_t poff = ending ? p2air_end_post_off(r, i) : p2air_beg_post_off(r, i);
        gold_fp_t post = fp(row[poff]);
        if (!gold_fp_eq(state[i], post)) (*viol)++;              /* post == MDS(...) */
        state[i] = post;                                        /* chain via committed */
    }
}

/* eval_partial_round: assert sbox == (state0+rc)^3, post_sbox == sbox^2*(state0+rc),
 * reset state0 to post_sbox, apply internal matmul. (air.rs eval_partial_round). */
static void eval_partial_round(gold_fp_t state[P2AIR_WIDTH], const uint64_t *row,
                               size_t r, uint64_t rc, int *viol) {
    gold_fp_t x = add(state[0], fp(rc));
    gold_fp_t committed_x3 = fp(row[p2air_partial_sbox_off(r)]);
    if (!gold_fp_eq(committed_x3, cube(x))) (*viol)++;          /* sbox == x^3 */
    gold_fp_t out = mul(mul(committed_x3, committed_x3), x);    /* x^7 */
    gold_fp_t post_sbox = fp(row[p2air_partial_postsbox_off(r)]);
    if (!gold_fp_eq(out, post_sbox)) (*viol)++;                 /* post_sbox == x^7 */
    state[0] = post_sbox;                                       /* chain via committed */
    poseidon2_gold_internal_linear_8(state);
}

int poseidon2_air_eval_row(const uint64_t row[P2AIR_NUM_COLS]) {
    int viol = 0;

    gold_fp_t state[P2AIR_WIDTH];
    for (size_t i = 0; i < P2AIR_WIDTH; i++) state[i] = fp(row[p2air_input_off(i)]);

    /* leading external linear layer (air.rs eval: external_linear_layer first). */
    poseidon2_gold_external_linear_8(state);

    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++)
        eval_full_round(state, row, r, 0, POSEIDON2_GOLD_RC8_EXT_INITIAL[r], &viol);

    for (size_t r = 0; r < P2AIR_PARTIAL_ROUNDS; r++)
        eval_partial_round(state, row, r, POSEIDON2_GOLD_RC8_INTERNAL[r], &viol);

    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++)
        eval_full_round(state, row, r, 1, POSEIDON2_GOLD_RC8_EXT_FINAL[r], &viol);

    return viol;
}
