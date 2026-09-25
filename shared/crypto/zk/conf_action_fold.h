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
 * (range, role, S8 IS_FEE zero-pin, phi0, E10', E14, BAL first/transition/last,
 * E17, E7).
 *
 * ── LEDGER-V2 S8 Gate 2 (2026-08-06) ───────────────────────────────────────
 *   · IS_FEE is PINNED ZERO (one new constraint, emitted immediately after the
 *     ROLE sum and before PHI0). The fee LEFT the balance — it is FS/sighash-
 *     bound only. The COLUMN is kept (the aggregate trace width is frozen), so
 *     this is a zero-pin, not a column removal; with IS_FEE ≡ 0 the E14
 *     coefficient BALCON·(ISIN−ISOUT−ISFEE) is identically BALCON·(ISIN−ISOUT).
 *   · The last-row terminal is now BAL == boundary_out − boundary_in, read from
 *     the publics named by the OPTIONAL `dnac_conf_action_bnd_ctx_t` (below)
 *     that the caller installs in the descriptor's `ctx`. It stays in its
 *     ORIGINAL emission position; with ctx == NULL the delta is ZERO and the
 *     terminal is the historical BAL == 0.
 *
 * Publics: NONE for the STANDALONE descriptor (0 publics, ctx NULL). The
 * aggregate reuses this evaluator on ITS folder, so `folder->ctx` /
 * `folder->public_values` there are the AGGREGATE's — that is the intent, and
 * it is the only way the C1 terminal can reach the S8 turnstile publics
 * without moving it out of its emission position.
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

#include <stdint.h>

#include "conf_action_air.h"   /* CONF_ACTION_* offsets (width = CONF_ACTION_WIDTH) */
#include "stark_constraints.h" /* dnac_stark_air_t / folder */

#ifdef __cplusplus
extern "C" {
#endif

/** Number of public values (as-built C1: none). */
#define CONF_ACTION_FOLD_NUM_PUBLICS 0

/**
 * @brief LEDGER-V2 S8 Gate 2 — the caller-owned BOUNDARY BINDING context for
 *        the C1 last-row balance terminal (the FLEET-034 `ctx` pattern: the
 *        state is CALLER-owned, the descriptor carries the pointer, and
 *        `air_eval` reads it back out of `folder->ctx`; the `air_eval`
 *        SIGNATURE is unchanged).
 *
 * The two fields are INDICES into the folder's public-value array:
 *   ctx != NULL :  last_row · (BAL − (PUB[idx_boundary_out] − PUB[idx_boundary_in]))
 *   ctx == NULL :  the delta is ZERO ⇒ last_row · BAL — the HISTORICAL terminal.
 * So STANDALONE C1 (DNAC_CONF_ACTION_FOLD_AIR, 0 publics) is semantically
 * UNCHANGED, while the aggregate installs {CONF_AGGZK_PUB_BIN,
 * CONF_AGGZK_PUB_BOUT} and gets the turnstile-bound balance. The terminal keeps
 * its EMISSION POSITION inside the C1 evaluator either way — the alpha-fold is
 * order-sensitive and the aggregate reuses this evaluator verbatim.
 *
 * ⚠ INDEX SAFETY. `air_eval` has no error channel, so these indices are NOT
 * range-checked at eval time. Every descriptor that installs this ctx MUST
 * `_Static_assert` both indices < its own num_publics — see
 * DNAC_CONF_ACTION_AGG_FOLD_AIR (conf_action_agg_fold.c).
 *
 * ⚠ LIFETIME. The pointed-at object is caller-owned and must outlive every
 * `air_eval` call made through the descriptor (dnac_stark_air_t::ctx contract).
 */
typedef struct {
    uint32_t idx_boundary_in;  /**< public index of the transparent-IN value  */
    uint32_t idx_boundary_out; /**< public index of the transparent-OUT value */
} dnac_conf_action_bnd_ctx_t;

/**
 * @brief The C1 Action AIR fold-form eval (dnac_stark_air_t callback). Emits
 *        every constraint in the ORACLE-pinned order via the folder helpers.
 *        Requires folder->main_width >= CONF_ACTION_WIDTH (the C1 columns are
 *        [0, CONF_ACTION_WIDTH) of any wider embedding row).
 *
 *        `folder->ctx`, when non-NULL, is a `const dnac_conf_action_bnd_ctx_t *`
 *        and switches the last-row terminal to the boundary-bound form; the
 *        caller then also owns the requirement that both indices are < the
 *        folder's num_public_values. NULL ⇒ 0 publics needed.
 */
void dnac_conf_action_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 1002 post-F3,
 *  0 publics, main_next=1 — the counter/freeze/carry/BAL read the next row;
 *  ctx NULL ⇒ the historical BAL == 0 terminal). */
extern const dnac_stark_air_t DNAC_CONF_ACTION_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_FOLD_H */
