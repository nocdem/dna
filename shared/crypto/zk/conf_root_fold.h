/**
 * @file conf_root_fold.h
 * @brief B1 Stage-2 — combined confidential AIR in VERIFIER-FOLD form
 *        (fp2 alpha-fold over the opened trace window at zeta).
 *
 * The Stage-1 conf_* modules (conf_balance_air / conf_commit_air /
 * conf_root_air) are CONCRETE-TRACE checkers (per-row residuals over gold_fp_t
 * cells). A STARK verifier instead evaluates the constraint polynomial ONCE at
 * the out-of-domain point zeta over the opened fp2 values, alpha-folding every
 * constraint in the SAME order as the prover (VerifierConstraintFolder,
 * folder.rs:215-218). This module is that fold-form eval.
 *
 * GROUND TRUTH + EMISSION ORDER: the Rust-oracle `ConfRootAir::eval`
 * (tools/plonky3_oracle/src/main.rs, B1 Stage-2 block) — itself pinned
 * cell-for-cell to the Stage-1 C modules — proven by a REAL is_zk=1
 * p3_uni_stark proof (tools/vectors/conf_root_air_zk{,_h16}.json). The order
 * here MUST mirror it exactly (the alpha-fold is order-sensitive): BAL block
 * (booleanity, selector sum, padding-zero, recomposition, 52-bit gate,
 * first/transition/last accumulators) -> VC Poseidon2 + COPY + CAP ->
 * CA1/CA2 Poseidon2 -> CA1 chaining -> CA1 capacity -> CA2 rate/carry ->
 * gated CACC freeze -> root binding -> PB1-PB8 public bindings.
 *
 * Publics (17, design v3.1 §4b FLAT layout):
 *   [commitment_root(4), c_claimed(4), c_fee(4), hash_id(1), tx_binding(4)]
 * tx_binding (publics[13..17]) is FS-observed ONLY — never read by the eval.
 * hash_id is READ from publics[12] (Stage-2/M4; Stage-1 pinned the constant).
 *
 * Gate: tests/test_conf_root_verify.c — folded * inv_vanishing must equal the
 * REAL recompose_quotient_from_chunks output on a REAL Plonky3 proof, which
 * pins both the constraint CONTENT and the emission ORDER.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ROOT_FOLD_H
#define DNAC_ZK_CONF_ROOT_FOLD_H

#include "conf_root_air.h"      /* CONF_ROOT_* offsets (Stage-1 layout, width 614) */
#include "stark_constraints.h"  /* dnac_stark_air_t / folder */

#ifdef __cplusplus
extern "C" {
#endif

/** Number of public values (v3.1 §4b flat layout). */
#define CONF_ROOT_FOLD_NUM_PUBLICS 17

/* Flat public-vector positions (§4b, pinned; closes open item O-4). */
#define CONF_ROOT_FOLD_PUB_ROOT_OFF      0  /* commitment_root[0..4)  */
#define CONF_ROOT_FOLD_PUB_C_CLAIMED_OFF 4  /* c_claimed[0..4)        */
#define CONF_ROOT_FOLD_PUB_C_FEE_OFF     8  /* c_fee[0..4)            */
#define CONF_ROOT_FOLD_PUB_HASH_ID_OFF   12 /* hash_id                */
#define CONF_ROOT_FOLD_PUB_TX_BINDING_OFF 13 /* tx_binding[0..4) — FS-only */

/**
 * @brief The combined-AIR fold-form eval (dnac_stark_air_t callback).
 *        Emits every constraint in the ORACLE-pinned order via the folder
 *        helpers. Requires folder->main_width == CONF_ROOT_WIDTH and
 *        folder->num_public_values == CONF_ROOT_FOLD_NUM_PUBLICS (enforced by
 *        the dnac_stark_verify_constraints* shape gate via the descriptor).
 */
void dnac_conf_root_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 614,
 *  17 publics, main_next=1 — the accumulators read the next row). */
extern const dnac_stark_air_t DNAC_CONF_ROOT_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ROOT_FOLD_H */
