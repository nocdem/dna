/**
 * @file poseidon2_goldilocks.h
 * @brief Poseidon2 permutation over the Goldilocks field, width 8 (DNAC v3 ZK).
 *
 * Grounded C port of Plonky3 `p3-poseidon2` @ commit 82cfad73, as instantiated
 * for Goldilocks by `default_goldilocks_poseidon2_8()`
 * (goldilocks/src/poseidon2.rs:570-577). Every round constant, the internal
 * diagonal, the round counts, and the S-box degree are copied verbatim from
 * that pinned source — nothing is invented (ANA HEDEF: KAFADAN KRİPTO YASAK).
 *
 * Parameters (goldilocks/src/poseidon2.rs + poseidon1.rs:44):
 *   - WIDTH t = 8
 *   - S-box degree D = 7                    (GOLDILOCKS_S_BOX_DEGREE)
 *   - full rounds RF = 8 (4 initial + 4 terminal)  (HALF_FULL_ROUNDS = 4)
 *   - partial rounds RP = 22                (PARTIAL_ROUNDS_8; interp. bound + 7.5% margin)
 *   - round constants: Grain LFSR (field=goldilocks, alpha=7, n=64, t=8, R_F=8, R_P=22)
 *
 * Ground truth: the permutation OUTPUT byte-matches the Rust oracle running the
 * real `default_goldilocks_poseidon2_8().permute(...)` for a fixed input set
 * (see tools/vectors/poseidon2_goldilocks.json + test_poseidon2_goldilocks.c).
 *
 * NOT wired into any consensus / proof-internal / AIR path — this is the
 * standalone primitive from phase FP1.2 of the SHA3->Poseidon2 decision
 * (dnac/docs/plans/2026-07-14-sha3-to-poseidon2-decision.md). In-AIR use (M3b)
 * and the poseidon2-air constraint system are separate later phases.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_GOLDILOCKS_H
#define DNAC_ZK_POSEIDON2_GOLDILOCKS_H

#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Poseidon2-Goldilocks width (state size), t. */
#define POSEIDON2_GOLD_WIDTH 8

/** S-box degree D (x -> x^7). Plonky3 poseidon1.rs:44 GOLDILOCKS_S_BOX_DEGREE. */
#define POSEIDON2_GOLD_SBOX_DEGREE 7

/** Full rounds per half (RF/2). poseidon2.rs GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS. */
#define POSEIDON2_GOLD_HALF_FULL_ROUNDS 4

/** Total full (external) rounds RF = 8. */
#define POSEIDON2_GOLD_FULL_ROUNDS 8

/** Partial (internal) rounds RP = 22. poseidon2.rs GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8. */
#define POSEIDON2_GOLD_PARTIAL_ROUNDS 22

/**
 * @brief Apply the width-8 Poseidon2-Goldilocks permutation in place.
 *
 * @param state In/out array of 8 field elements. Each element MUST be a
 *              canonical Goldilocks value in [0, p) on entry; each is canonical
 *              on return. (Non-canonical inputs are reduced by the field ops but
 *              the byte-match contract assumes canonical in, per the oracle.)
 *
 * Determinism (D1): pure function of `state`; fixed constants; no RNG, no
 * wall-clock. Identical output on every platform for identical input.
 */
void poseidon2_goldilocks8_permute(uint64_t state[POSEIDON2_GOLD_WIDTH]);

/* ---- Reusable linear layers (shared with the poseidon2-air trace/eval) ----
 *
 * These are the GenericPoseidon2LinearLayers<Goldilocks, 8> maps: the AIR trace
 * generation and constraint evaluation apply the SAME external/internal linear
 * layers as the permutation, so they are exposed here rather than duplicated
 * (one grounded implementation, one audit surface). Both operate in place on 8
 * canonical Goldilocks elements. */

/** External (full-round) linear layer = mds_light_permutation over MDSMat4
 *  (Plonky3 poseidon2/src/external.rs mds_light_permutation, WIDTH=8 arm). */
void poseidon2_gold_external_linear_8(gold_fp_t state[POSEIDON2_GOLD_WIDTH]);

/** Internal (partial-round) linear layer = matmul_internal with MATRIX_DIAG_8
 *  (Plonky3 poseidon2/src/internal.rs matmul_internal; equal to the unrolled
 *  internal_layer_mat_mul_goldilocks_8, proven by poseidon2.rs:1060-1078). */
void poseidon2_gold_internal_linear_8(gold_fp_t state[POSEIDON2_GOLD_WIDTH]);

/* ---- Round constants (verbatim from Plonky3 82cfad73 goldilocks/src/poseidon2.rs,
 *      the RoundConstants wired by default_goldilocks_poseidon2_8). Exposed so the
 *      poseidon2-air trace/eval use the SAME constants as the permutation. ---- */
extern const uint64_t POSEIDON2_GOLD_RC8_EXT_INITIAL[POSEIDON2_GOLD_HALF_FULL_ROUNDS]
                                                    [POSEIDON2_GOLD_WIDTH];
extern const uint64_t POSEIDON2_GOLD_RC8_EXT_FINAL[POSEIDON2_GOLD_HALF_FULL_ROUNDS]
                                                  [POSEIDON2_GOLD_WIDTH];
extern const uint64_t POSEIDON2_GOLD_RC8_INTERNAL[POSEIDON2_GOLD_PARTIAL_ROUNDS];

/** MATRIX_DIAG_8_GOLDILOCKS (poseidon2.rs:640, [-2,1,2,1/2,3,-1/2,-3,-4]).
 *  Exposed 2026-07-15 (pure static-removal/rename, zero logic change — the
 *  FP1c.4 precedent) so the B1 Stage-2 fp2 fold-form internal linear layer
 *  (conf_root_fold.c) uses the SAME diagonal as the permutation. */
extern const uint64_t POSEIDON2_GOLD_MATRIX_DIAG_8[POSEIDON2_GOLD_WIDTH];

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_GOLDILOCKS_H */
