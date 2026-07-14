/**
 * @file poseidon2_air_cols.h
 * @brief Poseidon2 AIR column layout (DNAC v3 ZK, FP1c.1).
 *
 * Port of the Plonky3 `poseidon2-air` crate `Poseidon2Cols` struct (pinned
 * commit 82cfad73, Apache-2.0), specialized to the DNAC in-AIR instance:
 *
 *     Poseidon2Cols<T, WIDTH=8, SBOX_DEGREE=7, SBOX_REGISTERS=1,
 *                      HALF_FULL_ROUNDS=4, PARTIAL_ROUNDS=22>
 *
 * One Poseidon2 permutation per trace ROW. The struct is `#[repr(C)]` over a
 * single field type, so the layout is a flat, padding-free sequence of columns
 * in declaration order (poseidon2-air/src/columns.rs:11-31):
 *
 *   inputs[WIDTH]                                         (8 cols)
 *   beginning_full_rounds[HALF_FULL_ROUNDS] each:         (4 × 16 = 64 cols)
 *       FullRound { sbox[WIDTH] (each SBox=[T;REGISTERS]=1), post[WIDTH] }
 *       = 8 sbox cols + 8 post cols = 16
 *   partial_rounds[PARTIAL_ROUNDS] each:                  (22 × 2 = 44 cols)
 *       PartialRound { sbox (SBox=[T;1]=1), post_sbox (T=1) } = 2
 *   ending_full_rounds[HALF_FULL_ROUNDS] each:            (4 × 16 = 64 cols)
 *       FullRound { sbox[WIDTH], post[WIDTH] } = 16
 *
 *   NUM_COLS = 8 + 64 + 44 + 64 = 180  (== num_cols::<8,7,1,4,22>() = 94 + 86·R,
 *                                        R = SBOX_REGISTERS = 1).
 *
 * SBOX_REGISTERS = 1 (degree-3 realization of x^7, eval_sbox (7,1) in
 * poseidon2-air/src/air.rs): the single register commits x^3, keeping the max
 * constraint degree at 3 so the AIR stays within DNAC's FRI log_blowup=2
 * (blowup 4). R=0 (direct x^7) would need blowup ≥ 8. Choice pinned in
 * dnac/docs/plans/2026-07-14-sha3-to-poseidon2-decision.md (RF-3).
 *
 * `sbox` column = the committed x^3 for that lane's S-box input.
 * `post`/`post_sbox` semantics are fixed by generation.rs / air.rs and are
 * exercised by the FP1c.2 trace byte-match + FP1c.3 constraint byte-match.
 *
 * Trace cells are `gold_fp_t` (Goldilocks base field), matching the rest of the
 * stack (extension only for FRI soundness amplification).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_AIR_COLS_H
#define DNAC_ZK_POSEIDON2_AIR_COLS_H

#include <stdbool.h>
#include <stddef.h>

#include "poseidon2_goldilocks.h" /* WIDTH / rounds / degree #defines */

#ifdef __cplusplus
extern "C" {
#endif

/* AIR instance dimensions (fixed to the DNAC Goldilocks width-8 instance). */
#define P2AIR_WIDTH             POSEIDON2_GOLD_WIDTH          /* 8  */
#define P2AIR_SBOX_DEGREE       POSEIDON2_GOLD_SBOX_DEGREE    /* 7  */
#define P2AIR_SBOX_REGISTERS    1                            /* (7,1) deg-3 */
#define P2AIR_HALF_FULL_ROUNDS  POSEIDON2_GOLD_HALF_FULL_ROUNDS /* 4 */
#define P2AIR_PARTIAL_ROUNDS    POSEIDON2_GOLD_PARTIAL_ROUNDS   /* 22 */

/* Column-block sizes (in field-element units). */
#define P2AIR_FULL_ROUND_COLS   (P2AIR_WIDTH * P2AIR_SBOX_REGISTERS + P2AIR_WIDTH) /* 16 */
#define P2AIR_PARTIAL_ROUND_COLS (P2AIR_SBOX_REGISTERS + 1)                        /* 2  */

/* Section base offsets. */
#define P2AIR_INPUTS_OFF   0
#define P2AIR_BEG_OFF      (P2AIR_INPUTS_OFF + P2AIR_WIDTH)                          /* 8   */
#define P2AIR_PARTIAL_OFF  (P2AIR_BEG_OFF + P2AIR_HALF_FULL_ROUNDS * P2AIR_FULL_ROUND_COLS) /* 72 */
#define P2AIR_END_OFF      (P2AIR_PARTIAL_OFF + P2AIR_PARTIAL_ROUNDS * P2AIR_PARTIAL_ROUND_COLS) /* 116 */

/** Total trace width for one permutation-per-row. == 180. */
#define P2AIR_NUM_COLS \
    (P2AIR_END_OFF + P2AIR_HALF_FULL_ROUNDS * P2AIR_FULL_ROUND_COLS)                /* 180 */

/* ---- column accessors (offset in [0, P2AIR_NUM_COLS)) ---- */

/** inputs[i], i in [0, WIDTH). */
static inline size_t p2air_input_off(size_t i) { return (size_t)P2AIR_INPUTS_OFF + i; }

/** beginning_full_rounds[r].sbox[i] (committed x^3), r<HALF_FULL, i<WIDTH. */
static inline size_t p2air_beg_sbox_off(size_t r, size_t i) {
    return (size_t)P2AIR_BEG_OFF + r * P2AIR_FULL_ROUND_COLS + i;
}
/** beginning_full_rounds[r].post[i] (state after this full round). */
static inline size_t p2air_beg_post_off(size_t r, size_t i) {
    return (size_t)P2AIR_BEG_OFF + r * P2AIR_FULL_ROUND_COLS + P2AIR_WIDTH + i;
}

/** partial_rounds[r].sbox (committed x^3 for lane 0), r<PARTIAL. */
static inline size_t p2air_partial_sbox_off(size_t r) {
    return (size_t)P2AIR_PARTIAL_OFF + r * P2AIR_PARTIAL_ROUND_COLS;
}
/** partial_rounds[r].post_sbox (lane-0 S-box output). */
static inline size_t p2air_partial_postsbox_off(size_t r) {
    return (size_t)P2AIR_PARTIAL_OFF + r * P2AIR_PARTIAL_ROUND_COLS + P2AIR_SBOX_REGISTERS;
}

/** ending_full_rounds[r].sbox[i], r<HALF_FULL, i<WIDTH. */
static inline size_t p2air_end_sbox_off(size_t r, size_t i) {
    return (size_t)P2AIR_END_OFF + r * P2AIR_FULL_ROUND_COLS + i;
}
/** ending_full_rounds[r].post[i]. */
static inline size_t p2air_end_post_off(size_t r, size_t i) {
    return (size_t)P2AIR_END_OFF + r * P2AIR_FULL_ROUND_COLS + P2AIR_WIDTH + i;
}

/**
 * @brief Static + runtime self-check of the column layout.
 * @return true iff all offsets/boundaries match the Plonky3 repr(C) layout
 *         (NUM_COLS==180, section boundaries at 8/72/116/180, no overlaps).
 */
bool poseidon2_air_cols_layout_check(void);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_AIR_COLS_H */
