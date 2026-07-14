/**
 * @file poseidon2_air_cols.c
 * @brief Poseidon2 AIR column-layout self-check (DNAC v3 ZK, FP1c.1).
 *
 * Verifies the C offset accessors reproduce the Plonky3 `Poseidon2Cols`
 * repr(C) layout for the WIDTH=8, REGISTERS=1, HALF_FULL=4, PARTIAL=22 instance
 * (poseidon2-air/src/columns.rs @ 82cfad73). The offsets are a pure function of
 * the struct field order; this check pins the boundaries so a later edit that
 * shifts a section is caught immediately. The layout is additionally validated
 * transitively by the FP1c.2 trace byte-match (reading real Plonky3 trace
 * columns at these offsets and matching values).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_air_cols.h"

bool poseidon2_air_cols_layout_check(void) {
    /* Section boundaries (must match the repr(C) declaration order). */
    if (P2AIR_INPUTS_OFF != 0) return false;
    if (P2AIR_BEG_OFF != 8) return false;      /* after inputs[8] */
    if (P2AIR_PARTIAL_OFF != 72) return false; /* after 4 full rounds × 16 */
    if (P2AIR_END_OFF != 116) return false;    /* after 22 partial rounds × 2 */
    if (P2AIR_NUM_COLS != 180) return false;   /* after 4 ending full × 16 */

    /* Block sizes. */
    if (P2AIR_FULL_ROUND_COLS != 16) return false;
    if (P2AIR_PARTIAL_ROUND_COLS != 2) return false;

    /* inputs occupy exactly [0, 8). */
    if (p2air_input_off(0) != 0) return false;
    if (p2air_input_off(P2AIR_WIDTH - 1) != 7) return false;

    /* beginning full rounds: [8, 72), each round sbox[0..8] then post[0..8]. */
    if (p2air_beg_sbox_off(0, 0) != 8) return false;
    if (p2air_beg_post_off(0, 0) != 16) return false;
    if (p2air_beg_post_off(0, P2AIR_WIDTH - 1) != 23) return false;
    if (p2air_beg_sbox_off(1, 0) != 24) return false;
    if (p2air_beg_post_off(P2AIR_HALF_FULL_ROUNDS - 1, P2AIR_WIDTH - 1) != 71) return false;

    /* partial rounds: [72, 116), each round sbox then post_sbox. */
    if (p2air_partial_sbox_off(0) != 72) return false;
    if (p2air_partial_postsbox_off(0) != 73) return false;
    if (p2air_partial_sbox_off(1) != 74) return false;
    if (p2air_partial_postsbox_off(P2AIR_PARTIAL_ROUNDS - 1) != 115) return false;

    /* ending full rounds: [116, 180). */
    if (p2air_end_sbox_off(0, 0) != 116) return false;
    if (p2air_end_post_off(0, 0) != 124) return false;
    if (p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, P2AIR_WIDTH - 1) != 179) return false;

    /* Every accessor must stay in range and the sections must tile [0,180)
     * without overlap: verify by marking each column exactly once. */
    unsigned char seen[P2AIR_NUM_COLS];
    for (size_t c = 0; c < (size_t)P2AIR_NUM_COLS; c++) seen[c] = 0;

    for (size_t i = 0; i < P2AIR_WIDTH; i++) seen[p2air_input_off(i)]++;
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++)
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            seen[p2air_beg_sbox_off(r, i)]++;
            seen[p2air_beg_post_off(r, i)]++;
        }
    for (size_t r = 0; r < P2AIR_PARTIAL_ROUNDS; r++) {
        seen[p2air_partial_sbox_off(r)]++;
        seen[p2air_partial_postsbox_off(r)]++;
    }
    for (size_t r = 0; r < P2AIR_HALF_FULL_ROUNDS; r++)
        for (size_t i = 0; i < P2AIR_WIDTH; i++) {
            seen[p2air_end_sbox_off(r, i)]++;
            seen[p2air_end_post_off(r, i)]++;
        }

    for (size_t c = 0; c < (size_t)P2AIR_NUM_COLS; c++)
        if (seen[c] != 1) return false; /* overlap or gap */

    return true;
}
