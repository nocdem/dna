/**
 * @file conf_root_air.c
 * @brief Confidential commitment-set-root accumulator — B1 Stage-1, is_zk=0.
 *
 * capacity-IV sponge fold (2 Poseidon2 perms/fold) binding the ordered commitment
 * set to a single root, is_real-gated (freeze on padding). See conf_root_air.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_root_air.h"

#include <stdlib.h>
#include <string.h>

#include "conf_commit_air.h"
#include "field_goldilocks.h"
#include "poseidon2_air.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_air_trace.h"

#define LANES CONF_COMMIT_C_LANES

/* One capacity-IV sponge fold W(cacc_prev, c): generate the CA1 + CA2 permutation
 * blocks into ca1_out/ca2_out (each P2AIR_NUM_COLS) and return the squeezed
 * digest s2[0..4] in cacc_new. */
static void do_fold(const uint64_t cacc_prev[LANES], const uint64_t c[LANES],
                    uint64_t *ca1_out, uint64_t *ca2_out, uint64_t cacc_new[LANES]) {
    uint64_t ca1_in[8] = {cacc_prev[0], cacc_prev[1], cacc_prev[2], cacc_prev[3],
                          CONF_ROOT_DOMSEP_ACC, 0, 0, 0};
    poseidon2_air_generate_row(ca1_in, ca1_out);
    uint64_t s1[8];
    for (int k = 0; k < 8; k++) s1[k] = ca1_out[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];

    uint64_t ca2_in[8] = {c[0], c[1], c[2], c[3], s1[4], s1[5], s1[6], s1[7]};
    poseidon2_air_generate_row(ca2_in, ca2_out);
    for (int k = 0; k < LANES; k++)
        cacc_new[k] = ca2_out[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, k)];
}

void conf_root_air_recompute_root(const uint64_t *c_list, size_t count,
                                  uint64_t root_out[LANES]) {
    uint64_t cacc[LANES] = {0, 0, 0, 0};
    uint64_t ca1[P2AIR_NUM_COLS], ca2[P2AIR_NUM_COLS];
    for (size_t i = 0; i < count; i++) {
        uint64_t next[LANES];
        do_fold(cacc, c_list + i * LANES, ca1, ca2, next);
        memcpy(cacc, next, sizeof(cacc));
    }
    memcpy(root_out, cacc, sizeof(uint64_t) * LANES);
}

bool conf_root_air_generate(const uint64_t *outputs, size_t n_out,
                            uint64_t claimed, uint64_t fee,
                            const uint64_t *blind, unsigned log_height,
                            uint64_t *trace_out,
                            uint64_t root_out[LANES]) {
    if (!trace_out || !root_out) return false;
    if (log_height == 0 || log_height > CONF_BAL_MAX_LOG_HEIGHT) return false;
    const size_t rows = (size_t)1 << log_height;

    uint64_t *commit = (uint64_t *)malloc(rows * CONF_COMMIT_WIDTH * sizeof(uint64_t));
    if (!commit) return false;
    if (!conf_commit_air_generate(outputs, n_out, claimed, fee, blind, log_height, commit)) {
        free(commit);
        return false;
    }

    uint64_t cacc[LANES] = {0, 0, 0, 0};
    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_ROOT_WIDTH;
        const uint64_t *crow = commit + r * CONF_COMMIT_WIDTH;

        memcpy(row + CONF_ROOT_COMMIT_OFF, crow, CONF_COMMIT_WIDTH * sizeof(uint64_t));

        uint64_t c_r[LANES];
        conf_commit_air_get_commitment(commit, r, c_r);

        uint64_t prev[LANES];
        memcpy(prev, cacc, sizeof(prev));

        uint64_t s2[LANES];
        do_fold(prev, c_r, row + CONF_ROOT_CA1_OFF, row + CONF_ROOT_CA2_OFF, s2);

        uint64_t is_real = crow[CONF_COMMIT_BAL_OFF + CONF_BAL_IS_REAL_OFF];
        for (int j = 0; j < LANES; j++)
            cacc[j] = is_real ? s2[j] : prev[j]; /* gated freeze */
        for (int j = 0; j < LANES; j++) row[CONF_ROOT_CACC_OFF + j] = cacc[j];
    }
    memcpy(root_out, cacc, sizeof(uint64_t) * LANES);
    free(commit);
    return true;
}

int conf_root_air_eval(const uint64_t *trace, size_t n_rows,
                       const uint64_t commitment_root[LANES]) {
    if (!trace || n_rows == 0 || !commitment_root) return 1;
    int viol = 0;

    /* (1) conf_commit constraints on the [0,250) slice. */
    uint64_t *commit = (uint64_t *)malloc(n_rows * CONF_COMMIT_WIDTH * sizeof(uint64_t));
    if (!commit) return 1;
    for (size_t r = 0; r < n_rows; r++)
        memcpy(commit + r * CONF_COMMIT_WIDTH,
               trace + r * CONF_ROOT_WIDTH + CONF_ROOT_COMMIT_OFF,
               CONF_COMMIT_WIDTH * sizeof(uint64_t));
    viol += conf_commit_air_eval(commit, n_rows);
    free(commit);

    const uint64_t zero4[LANES] = {0, 0, 0, 0};

    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_ROOT_WIDTH;
        const uint64_t *ca1 = row + CONF_ROOT_CA1_OFF;
        const uint64_t *ca2 = row + CONF_ROOT_CA2_OFF;

        /* (2) both fold permutations are internally consistent. */
        viol += poseidon2_air_eval_row(ca1);
        viol += poseidon2_air_eval_row(ca2);

        /* prev cacc = previous row's CACC, or [0,0,0,0] at row 0. */
        const uint64_t *prev = (r == 0) ? zero4
                                        : (trace + (r - 1) * CONF_ROOT_WIDTH + CONF_ROOT_CACC_OFF);

        /* (3) CA1 inputs = [cacc_prev, DOMSEP_ACC, 0, 0, 0]. */
        for (int j = 0; j < LANES; j++)
            if (ca1[p2air_input_off((size_t)j)] != prev[j]) viol++;
        if (ca1[p2air_input_off(4)] != CONF_ROOT_DOMSEP_ACC) viol++;
        if (ca1[p2air_input_off(5)] != 0) viol++;
        if (ca1[p2air_input_off(6)] != 0) viol++;
        if (ca1[p2air_input_off(7)] != 0) viol++;

        /* (4) CA2 inputs[0..4] = c_r (this row's VC commitment); inputs[4..8] =
         * CA1.output[4..8] (capacity carry). */
        uint64_t c_r[LANES];
        const uint64_t *vc = row + CONF_ROOT_COMMIT_OFF + CONF_COMMIT_VC_OFF;
        for (int j = 0; j < LANES; j++)
            c_r[j] = vc[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)j)];
        for (int j = 0; j < LANES; j++)
            if (ca2[p2air_input_off((size_t)j)] != c_r[j]) viol++;
        for (int k = 4; k < 8; k++)
            if (ca2[p2air_input_off((size_t)k)] !=
                ca1[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)k)])
                viol++;

        /* (5) gated cacc: cacc_r = is_real·s2 + (1−is_real)·cacc_prev. */
        gold_fp_t is_real = gold_fp_from_u64(
            row[CONF_ROOT_COMMIT_OFF + CONF_COMMIT_BAL_OFF + CONF_BAL_IS_REAL_OFF]);
        gold_fp_t one_minus = gold_fp_sub(gold_fp_one(), is_real);
        for (int j = 0; j < LANES; j++) {
            gold_fp_t s2 = gold_fp_from_u64(
                ca2[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)j)]);
            gold_fp_t expect = gold_fp_add(gold_fp_mul(is_real, s2),
                                           gold_fp_mul(one_minus, gold_fp_from_u64(prev[j])));
            if (!gold_fp_eq(gold_fp_from_u64(row[CONF_ROOT_CACC_OFF + j]), expect)) viol++;
        }

        /* (6) last physical row: cacc == commitment_root. */
        if (r == n_rows - 1)
            for (int j = 0; j < LANES; j++)
                if (row[CONF_ROOT_CACC_OFF + j] != commitment_root[j]) viol++;
    }
    return viol;
}
