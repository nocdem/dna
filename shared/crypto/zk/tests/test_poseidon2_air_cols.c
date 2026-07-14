/**
 * @file test_poseidon2_air_cols.c
 * @brief FP1c.1 — Poseidon2 AIR column-layout binding contract.
 *
 * Structural gate: asserts the C offset accessors reproduce the Plonky3
 * Poseidon2Cols<8,7,1,4,22> repr(C) layout (NUM_COLS=180, section boundaries at
 * 8/72/116/180, every column claimed exactly once). Grounding of NUM_COLS==180
 * against the REAL Plonky3 num_cols::<8,7,1,4,22>() arrives with the FP1c.2
 * trace byte-match (which reads real Plonky3 trace columns at these offsets).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include "../poseidon2_air_cols.h"

int main(void) {
    int fails = 0;

    if (!poseidon2_air_cols_layout_check()) {
        fprintf(stderr, "FAIL: poseidon2_air_cols_layout_check() returned false\n");
        fails++;
    }

    /* Spot-check a few compile-time constants directly. */
    if (P2AIR_NUM_COLS != 180) {
        fprintf(stderr, "FAIL: P2AIR_NUM_COLS = %d, expected 180\n", P2AIR_NUM_COLS);
        fails++;
    }
    if (P2AIR_WIDTH != 8 || P2AIR_HALF_FULL_ROUNDS != 4 ||
        P2AIR_PARTIAL_ROUNDS != 22 || P2AIR_SBOX_REGISTERS != 1 ||
        P2AIR_SBOX_DEGREE != 7) {
        fprintf(stderr, "FAIL: instance dims mismatch\n");
        fails++;
    }

    if (fails) {
        printf("Poseidon2-AIR column layout: %d FAIL\n", fails);
        return 1;
    }
    printf("Poseidon2-AIR column layout: NUM_COLS=180, boundaries 8/72/116/180, "
           "no overlap/gap — PASS\n");
    return 0;
}
