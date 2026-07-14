/**
 * @file poseidon2_air_trace.c
 * @brief Poseidon2 AIR trace-row generation — grounded C port (FP1c.2).
 *
 * Mirrors Plonky3 poseidon2-air/src/generation.rs generate_trace_rows_for_perm
 * + generate_full_round + generate_partial_round + generate_sbox (7,1),
 * @ 82cfad73, for the Goldilocks WIDTH=8, SBOX_REGISTERS=1 instance. Uses the
 * permutation module's external/internal linear layers and round constants.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_air_trace.h"

#include "field_goldilocks.h"
#include "poseidon2_goldilocks.h"

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/* generate_sbox (7,1): commits x3 = x^3, returns it, and updates *x to
 * x^7 = x3*x3*x (generation.rs generate_sbox, (7,1) arm). */
static gold_fp_t sbox_7_1(gold_fp_t *x) {
    gold_fp_t x3 = mul(mul(*x, *x), *x); /* x^3 */
    *x = mul(mul(x3, x3), *x);           /* x3^2 * x = x^7 */
    return x3;
}

void poseidon2_air_generate_row(const uint64_t input[P2AIR_WIDTH],
                                uint64_t row[P2AIR_NUM_COLS]) {
    gold_fp_t s[P2AIR_WIDTH];
    for (size_t i = 0; i < P2AIR_WIDTH; i++) s[i] = fp(input[i]);

    /* inputs columns: raw input, BEFORE the leading linear layer. */
    for (size_t i = 0; i < P2AIR_WIDTH; i++)
        row[p2air_input_off(i)] = gold_fp_to_u64(s[i]);

    /* leading external linear layer (generation.rs: external_linear_layer). */
    poseidon2_gold_external_linear_8(s);

    /* beginning full rounds. */
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++) {
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            s[i] = gold_fp_add(s[i], fp(POSEIDON2_GOLD_RC8_EXT_INITIAL[r][i]));
            gold_fp_t x3 = sbox_7_1(&s[i]);
            row[p2air_beg_sbox_off(r, i)] = gold_fp_to_u64(x3);
        }
        poseidon2_gold_external_linear_8(s);
        for (size_t i = 0; i < P2AIR_WIDTH; i++)
            row[p2air_beg_post_off(r, i)] = gold_fp_to_u64(s[i]);
    }

    /* partial rounds (S-box on lane 0 only, then internal matmul). */
    for (size_t r = 0; r < P2AIR_PARTIAL_ROUNDS; r++) {
        s[0] = gold_fp_add(s[0], fp(POSEIDON2_GOLD_RC8_INTERNAL[r]));
        gold_fp_t x3 = sbox_7_1(&s[0]);
        row[p2air_partial_sbox_off(r)] = gold_fp_to_u64(x3);
        row[p2air_partial_postsbox_off(r)] = gold_fp_to_u64(s[0]); /* lane-0 x^7 */
        poseidon2_gold_internal_linear_8(s);
    }

    /* ending full rounds. */
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++) {
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            s[i] = gold_fp_add(s[i], fp(POSEIDON2_GOLD_RC8_EXT_FINAL[r][i]));
            gold_fp_t x3 = sbox_7_1(&s[i]);
            row[p2air_end_sbox_off(r, i)] = gold_fp_to_u64(x3);
        }
        poseidon2_gold_external_linear_8(s);
        for (size_t i = 0; i < P2AIR_WIDTH; i++)
            row[p2air_end_post_off(r, i)] = gold_fp_to_u64(s[i]);
    }
}
