/**
 * @file poseidon2_air.h
 * @brief Poseidon2 AIR constraint evaluation (DNAC v3 ZK, FP1c.3).
 *
 * Port of Plonky3 `poseidon2-air` `eval` / `eval_full_round` /
 * `eval_partial_round` / `eval_sbox` (poseidon2-air/src/air.rs @ 82cfad73) for
 * the Goldilocks WIDTH=8, SBOX_REGISTERS=1 (deg-3) instance. Given one
 * P2AIR_NUM_COLS-wide trace row, checks every AIR constraint and returns the
 * number of violated (non-zero-residual) constraints — 0 iff the row is a valid
 * Poseidon2 permutation witness.
 *
 * Constraints (all residuals must be 0), chaining state through the COMMITTED
 * post columns exactly as air.rs does:
 *   - full round, lane i:  sbox[i] == (state_i + rc_i)^3        (S-box, deg 3)
 *                          post[i] == external_linear(committed_x3^2 · x)[i]
 *   - partial round:       sbox    == (state_0 + rc)^3
 *                          post_sbox == sbox^2 · (state_0 + rc) (= x^7)
 *
 * Max constraint degree = 3 (SBOX_DEGREE with REGISTERS=1), within FRI blowup 4.
 *
 * Grounding: run on the REAL Plonky3 generate_trace_rows output (FP1c.2 vector)
 * → 0 violations (a valid Plonky3 witness satisfies these ported constraints);
 * any single-column tamper → ≥1 violation (constraints have teeth).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_POSEIDON2_AIR_H
#define DNAC_ZK_POSEIDON2_AIR_H

#include <stdint.h>

#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Evaluate all Poseidon2-AIR constraints on one trace row.
 *
 * @param row P2AIR_NUM_COLS (=180) canonical Goldilocks columns.
 * @return Number of violated constraints (residual != 0). 0 == valid witness.
 */
int poseidon2_air_eval_row(const uint64_t row[P2AIR_NUM_COLS]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_POSEIDON2_AIR_H */
