/**
 * @file conf_commit_air.h
 * @brief Confidential VALUE-COMMITMENT composition AIR (B1 Stage-1, is_zk=0).
 *
 * Increment 2 of the B1 Stage-1 build: bolts the BUILT Poseidon2 value-commitment
 * (VC) block (FP1c `poseidon2_air`) onto the BUILT balance/selector trace
 * (`conf_balance_air`) via the §3(a) SAME-WINDOW COPY, so that
 *
 *     committed value  ≡  range-checked value  ≡  balance-summed value
 *
 * is ONE physical matrix cell — the SEC-2 amount↔commitment binding, CONSTRUCTED
 * (not asserted). Pure composition of grounded+audited sub-blocks; no new crypto.
 *
 * ── Combined per-row layout (WIDTH = 250) ─────────────────────────────────
 *   [ BAL : 70  ]  conf_balance_air row (amount, 62-bit range, selectors,
 *                  counters, signed balance accumulator)
 *   [ VC  : 180 ]  poseidon2_air block committing this row's amount:
 *                    VC.inputs = [ amount, blind0, blind1, 0,
 *                                  DOMSEP_VAL, HASH_ID, 0, 0 ]
 *                    c_i = VC permutation output[0..4]  (single-block capacity-IV sponge)
 *
 * ── Composition constraints (on top of the two sub-block constraint sets) ──
 *   COPY (SEC-2):  VC.inputs[0] == BAL.amount               (same-window, degree 1)
 *   CAP:           VC.inputs[3] == 0
 *                  VC.inputs[4] == DOMSEP_VAL   (SHA3-512("DNAC value-commitment v1")[0:8] BE)
 *                  VC.inputs[5] == HASH_ID (=1, Poseidon2 dispatch)
 *                  VC.inputs[6] == 0 ; VC.inputs[7] == 0
 *   (VC.inputs[1..3] = blinding, free.)
 *   Plus: conf_balance_air_eval(BAL slice) == 0 and poseidon2_air_eval(VC block) == 0
 *   per row.
 *
 * Grounding: `conf_balance_air` (construction-proven), `poseidon2_air` +
 * `poseidon2_air_trace` (byte-matched to Plonky3 82cfad73, FP1c). The composition
 * is validated by CONSTRUCTION: honest ⇒ 0 violations; every SEC-2 attack (commit
 * X / range Y, wrong capacity IV, tampered VC block, pad-cell grind) rejects.
 *
 * NOT the commitment-accumulator (CA / commitment_root) yet — that binds the SET
 * of commitments and is the next increment.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_COMMIT_AIR_H
#define DNAC_ZK_CONF_COMMIT_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "conf_balance_air.h"
#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Value-commitment domain separator = SHA3-512("DNAC value-commitment v1")[0:8] BE
 * (verified < p; reproducible derivation, design pin per B1 v3.1 §2). */
#define CONF_COMMIT_DOMSEP_VAL ((uint64_t)0x608dc3de4da2455bULL)
/* Poseidon2 hash dispatch id (public). */
#define CONF_COMMIT_HASH_ID ((uint64_t)1)

/* Combined column layout. */
#define CONF_COMMIT_BAL_OFF 0
#define CONF_COMMIT_VC_OFF  CONF_BAL_WIDTH                       /* 70 */
#define CONF_COMMIT_WIDTH   (CONF_COMMIT_VC_OFF + P2AIR_NUM_COLS) /* 250 */

/** Number of Goldilocks lanes in one value commitment c_i. */
#define CONF_COMMIT_C_LANES 4

/**
 * @brief Honest-prover combined-trace generation.
 *
 * @param outputs     N output amounts (< 2^52).
 * @param n_out       N.
 * @param claimed     Σ outputs + fee (< 2^62).
 * @param fee         fee (< 2^52).
 * @param blind       2 blinding elements per row: blind[2*r], blind[2*r+1]
 *                    (length 2 * 2^log_height). Canonical Goldilocks.
 * @param log_height  height = 2^log_height ≤ CONF_BAL_MAX_LOG_HEIGHT.
 * @param trace_out   caller buffer of (2^log_height * CONF_COMMIT_WIDTH) uint64_t.
 * @return true on success.
 */
bool conf_commit_air_generate(const uint64_t *outputs, size_t n_out,
                              uint64_t claimed, uint64_t fee,
                              const uint64_t *blind, unsigned log_height,
                              uint64_t *trace_out);

/**
 * @brief Evaluate ALL combined constraints (balance + VC + copy + capacity).
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_commit_air_eval(const uint64_t *trace, size_t n_rows);

/**
 * @brief Extract the value commitment c_i (4 lanes) from row r of a trace.
 */
void conf_commit_air_get_commitment(const uint64_t *trace, size_t r,
                                    uint64_t c_out[CONF_COMMIT_C_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_COMMIT_AIR_H */
