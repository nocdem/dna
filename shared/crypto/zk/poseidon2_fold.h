/**
 * @file poseidon2_fold.h
 * @brief Shared fp2 verifier-fold of ONE stock Poseidon2-AIR block (180 cols).
 *
 * Extracted verbatim from conf_root_fold.c (B1 Stage-2) so every combined AIR
 * that embeds Poseidon2 sub-blocks (conf_root, conf_action, …) folds them
 * through ONE emission source — the alpha-fold is order-sensitive, so a single
 * shared implementation is the only way to guarantee prover/verifier and
 * cross-AIR consistency.
 *
 * Mirrors the VERBATIM-vendored poseidon2-air/src/air.rs:144-323 eval (the
 * (7,1) register S-box form, degree 3); the fp2 linear layers mirror the
 * exposed base-field generic layers (poseidon2_goldilocks.c apply_mat4 /
 * external / internal — pinned to poseidon2/src/external.rs:59-157 +
 * internal.rs matmul_internal with MATRIX_DIAG_8, poseidon2.rs:640) lifted
 * componentwise to fp2 (the matrices have BASE-field entries; linearity makes
 * the lift exact).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_FOLD_H
#define DNAC_ZK_POSEIDON2_FOLD_H

#include <stddef.h>

#include "stark_constraints.h" /* dnac_stark_folder_t */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fold one Poseidon2-AIR block located at column `off` in the folder's
 *        LOCAL trace window. Emits the block's constraints (leading external
 *        layer, beginning full rounds, partial rounds, ending full rounds) in
 *        the vendored air.rs eval order via the folder helpers.
 * @param f    the alpha-fold context (reads f->trace_local).
 * @param off  the block's base column in the local window.
 */
void dnac_poseidon2_fold_eval(dnac_stark_folder_t *f, size_t off);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_FOLD_H */
