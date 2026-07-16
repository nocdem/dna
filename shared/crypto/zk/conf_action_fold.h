/**
 * @file conf_action_fold.h
 * @brief Dual-mode S1e — the C1 Action AIR in VERIFIER-FOLD form (fp2
 *        alpha-fold over the opened trace window at zeta).
 *
 * The construction-gate module (conf_action_air.c) is a CONCRETE-TRACE checker
 * (per-row residuals over gold_fp_t cells). A STARK verifier instead evaluates
 * the constraint polynomial ONCE at the out-of-domain point zeta over the
 * opened fp2 values, alpha-folding every constraint in the SAME order as the
 * prover (VerifierConstraintFolder, folder.rs:215-218). This module is that
 * fold-form eval.
 *
 * GROUND TRUTH + EMISSION ORDER: the Rust-oracle `ConfActionAir::eval`
 * (tools/plonky3_oracle/src/main.rs) — itself pinned cell-for-cell to
 * conf_action_air.c — proven by a REAL is_zk=1 p3_uni_stark proof
 * (tools/vectors/conf_action_air_zk.json). The order here MUST mirror it
 * exactly (the alpha-fold is order-sensitive): E1 phi-range -> E2 wrap -> E13
 * anchor -> E3 forced counter -> (E6 bool + PZ + E8'/E4/E11 cm freeze + E6
 * block-const) -> E15 pos/nk/addr carries -> NC1/NC2 Poseidon2 -> note-commit
 * gated pins -> AC1/AC2 Poseidon2 -> spend-auth gated pins -> S1d balance
 * (range, role, phi0, E10', E14, BAL first/transition/last, E17, E7).
 *
 * Publics: NONE (the as-built construction gate reads no eval publics; balance
 * conservation is the internal last-row BAL=0 invariant; the dm-c1 boundary
 * publics + tx_binding are C6/S5, not part of this lift).
 *
 * Gate: tests/test_conf_action_verify.c — folded * inv_vanishing must equal the
 * REAL recompose_quotient_from_chunks output on a REAL Plonky3 proof, which
 * pins both the constraint CONTENT and the emission ORDER.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ACTION_FOLD_H
#define DNAC_ZK_CONF_ACTION_FOLD_H

#include "conf_action_air.h"   /* CONF_ACTION_* offsets (width 813) */
#include "stark_constraints.h" /* dnac_stark_air_t / folder */

#ifdef __cplusplus
extern "C" {
#endif

/** Number of public values (as-built C1: none). */
#define CONF_ACTION_FOLD_NUM_PUBLICS 0

/**
 * @brief The C1 Action AIR fold-form eval (dnac_stark_air_t callback). Emits
 *        every constraint in the ORACLE-pinned order via the folder helpers.
 *        Requires folder->main_width == CONF_ACTION_WIDTH and
 *        folder->num_public_values == 0.
 */
void dnac_conf_action_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 813,
 *  0 publics, main_next=1 — the counter/freeze/carry/BAL read the next row). */
extern const dnac_stark_air_t DNAC_CONF_ACTION_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_FOLD_H */
