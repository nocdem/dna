/**
 * @file conf_commit_air.c
 * @brief Confidential VALUE-COMMITMENT composition AIR — B1 Stage-1, is_zk=0.
 *
 * Composition of conf_balance_air (balance/selector) + poseidon2_air (FP1c value
 * commitment) via the SEC-2 same-window copy. See conf_commit_air.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_commit_air.h"

#include <stdlib.h>
#include <string.h>

#include "conf_balance_air.h"
#include "field_goldilocks.h"
#include "poseidon2_air.h"       /* poseidon2_air_eval_row */
#include "poseidon2_air_cols.h"  /* offsets */
#include "poseidon2_air_trace.h" /* poseidon2_air_generate_row */

/* Build the 8-element VC permutation input for a given amount + blinding. */
static void vc_input(uint64_t amount, uint64_t b0, uint64_t b1, uint64_t in[8]) {
    in[0] = amount;
    in[1] = b0;
    in[2] = b1;
    in[3] = 0;
    in[4] = CONF_COMMIT_DOMSEP_VAL;
    in[5] = CONF_COMMIT_HASH_ID;
    in[6] = 0;
    in[7] = 0;
}

bool conf_commit_air_generate(const uint64_t *outputs, size_t n_out,
                              uint64_t claimed, uint64_t fee,
                              const uint64_t *blind, unsigned log_height,
                              uint64_t *trace_out) {
    if (!blind || !trace_out) return false;
    if (log_height == 0 || log_height > CONF_BAL_MAX_LOG_HEIGHT) return false;
    const size_t rows = (size_t)1 << log_height;

    /* Generate the balance/selector sub-trace (70-wide). */
    uint64_t *bal = (uint64_t *)malloc(rows * CONF_BAL_WIDTH * sizeof(uint64_t));
    if (!bal) return false;
    if (!conf_balance_air_generate(outputs, n_out, claimed, fee, log_height, bal)) {
        free(bal);
        return false;
    }

    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_COMMIT_WIDTH;
        const uint64_t *brow = bal + r * CONF_BAL_WIDTH;

        /* Balance slice. */
        memcpy(row + CONF_COMMIT_BAL_OFF, brow, CONF_BAL_WIDTH * sizeof(uint64_t));

        /* VC block: commit this row's amount. */
        uint64_t in[8];
        vc_input(brow[CONF_BAL_AMOUNT_OFF], blind[2 * r], blind[2 * r + 1], in);
        poseidon2_air_generate_row(in, row + CONF_COMMIT_VC_OFF);
    }

    free(bal);
    return true;
}

int conf_commit_air_eval(const uint64_t *trace, size_t n_rows) {
    if (!trace || n_rows == 0) return 1;
    int viol = 0;

    /* (1) Balance/selector constraints — extract the 70-wide slice and reuse. */
    uint64_t *bal = (uint64_t *)malloc(n_rows * CONF_BAL_WIDTH * sizeof(uint64_t));
    if (!bal) return 1;
    for (size_t r = 0; r < n_rows; r++)
        memcpy(bal + r * CONF_BAL_WIDTH, trace + r * CONF_COMMIT_WIDTH + CONF_COMMIT_BAL_OFF,
               CONF_BAL_WIDTH * sizeof(uint64_t));
    viol += conf_balance_air_eval(bal, n_rows);
    free(bal);

    /* Per-row: VC block + composition constraints. */
    for (size_t r = 0; r < n_rows; r++) {
        const uint64_t *row = trace + r * CONF_COMMIT_WIDTH;
        const uint64_t *vc = row + CONF_COMMIT_VC_OFF;

        /* (2) VC Poseidon2 block is internally consistent. */
        viol += poseidon2_air_eval_row(vc);

        /* (3) SEC-2 same-window copy: VC.inputs[0] == balance amount cell. */
        if (vc[p2air_input_off(0)] != row[CONF_COMMIT_BAL_OFF + CONF_BAL_AMOUNT_OFF])
            viol++;

        /* (4) Capacity / pad constraints. */
        if (vc[p2air_input_off(3)] != 0) viol++;
        if (vc[p2air_input_off(4)] != CONF_COMMIT_DOMSEP_VAL) viol++;
        if (vc[p2air_input_off(5)] != CONF_COMMIT_HASH_ID) viol++;
        if (vc[p2air_input_off(6)] != 0) viol++;
        if (vc[p2air_input_off(7)] != 0) viol++;
    }
    return viol;
}

void conf_commit_air_get_commitment(const uint64_t *trace, size_t r,
                                    uint64_t c_out[CONF_COMMIT_C_LANES]) {
    const uint64_t *vc = trace + r * CONF_COMMIT_WIDTH + CONF_COMMIT_VC_OFF;
    for (size_t j = 0; j < CONF_COMMIT_C_LANES; j++)
        c_out[j] = vc[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, j)];
}
