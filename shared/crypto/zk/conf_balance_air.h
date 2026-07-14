/**
 * @file conf_balance_air.h
 * @brief Confidential balance-conservation + row-type-selector AIR (DNAC v3 ZK,
 *        B1 Stage-1, is_zk=0).
 *
 * DNAC-ORIGINAL combined AIR (NOT a Plonky3 port — the sub-primitives are
 * grounded; the COMPOSITION is DNAC's). This is the load-bearing balance/selector
 * layer that the B1 v3.1 re-red-team (`tasks/w74clzwjd.output`) flagged as
 * "build-to-settle": prose could not make the row-type/row-count/selector
 * soundness a fact. It is BUILT here so "row-type", "row excluded", and "one
 * physical amount cell" are facts, per the v2 meta-conclusion.
 *
 * Scope of THIS module: amounts + row-type selectors + signed balance
 * conservation, NO Poseidon2 value-commitment block yet (that is the next
 * Stage-1 increment; the same-window VC copy binds to the SAME amount cell here).
 *
 * ── Row model ─────────────────────────────────────────────────────────────
 * ONE trace, height = a fixed power of two `H = 2^log_height` (log_height ≤ 11 so
 * N ≤ H−2 ≤ 2046). Row order (PINNED-canonical): rows[0..N) = outputs,
 * row N = claimed, row N+1 = fee, rows[N+2..H) = padding. **N is bounded by the
 * trace HEIGHT structurally** (the prover cannot add more output rows than the
 * trace has) → Σ_out ≤ 2046·2^52 < 2^63 < p, so the field balance accumulator
 * cannot wrap — no software row-count bound needed.
 *
 * ── Per-row columns (WIDTH = 70) ──────────────────────────────────────────
 *   [ AMOUNT   : 1  ]  the row's value (the ONE cell range + balance + (later) VC share)
 *   [ BITS     : 62 ]  little-endian 62-bit decomposition of AMOUNT
 *   [ IS_OUTPUT: 1  ]  \
 *   [ IS_CLAIMED:1  ]   } row-type selectors (prover witness, fully constrained)
 *   [ IS_FEE   : 1  ]  /
 *   [ IS_REAL  : 1  ]  = IS_OUTPUT+IS_CLAIMED+IS_FEE (boolean ⇒ at most one type set)
 *   [ N_CLAIMED: 1  ]  running Σ IS_CLAIMED (== 1 at last row: exactly one claimed)
 *   [ N_FEE    : 1  ]  running Σ IS_FEE     (== 1 at last row: exactly one fee)
 *   [ BAL      : 1  ]  running signed balance Σ coeff·AMOUNT, coeff = IS_OUT+IS_FEE−IS_CLAIMED
 *
 * ── Constraints (all degree ≤ 2) ──────────────────────────────────────────
 *   Booleanity: s² = s for every selector + every bit.
 *   Selector sum: IS_REAL = IS_OUTPUT + IS_CLAIMED + IS_FEE  (with IS_REAL²=IS_REAL
 *                 this forces ≤ 1 type per row).
 *   Padding-zero: (1 − IS_REAL)·AMOUNT = 0  ← closes the re-red-team MINT attack
 *                 (a value-bearing row cannot masquerade as padding: padding ⇒ AMOUNT=0,
 *                  so the (later) VC block commits 0, nothing spendable is excluded).
 *   Range recomp: Σ_j BITS_j·2^j = AMOUNT   (uniform 62-bit; claimed fits).
 *   52-bit gate: (IS_OUTPUT + IS_FEE)·BITS_j = 0 for j ∈ [52,62)  ← outputs+fee ≤ 2^52.
 *   Transition (row r→r+1): next.BAL      = local.BAL      + next.coeff·next.AMOUNT
 *                           next.N_CLAIMED = local.N_CLAIMED + next.IS_CLAIMED
 *                           next.N_FEE     = local.N_FEE     + next.IS_FEE
 *   First row:  BAL = coeff·AMOUNT ; N_CLAIMED = IS_CLAIMED ; N_FEE = IS_FEE.
 *   Last row:   BAL = 0 ; N_CLAIMED = 1 ; N_FEE = 1.
 *   ⇒ Σ_out + fee − claimed = 0 over integers (all terms < 2^63 < p ⇒ no field wrap
 *     ⇒ field-zero ⟺ integer-zero), exactly one claimed + one fee row, padding inert.
 *
 * Determinism: pure function of the witness; every cell canonical.
 * Grounding: the range bit-decomposition mirrors range_air (52→62 bit); the
 * balance-field-wrap argument mirrors sum_balance (2^B·N < p). The composition is
 * validated by CONSTRUCTION: honest trace ⇒ 0 violations; every negative KAT
 * rejects (see test_conf_balance_air.c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_BALANCE_AIR_H
#define DNAC_ZK_CONF_BALANCE_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONF_BAL_RANGE_BITS   62  /* uniform range width (claimed fits) */
#define CONF_BAL_OUTPUT_BITS  52  /* tighter bound gated on outputs+fee */

/* Column offsets (WIDTH = 70). */
#define CONF_BAL_AMOUNT_OFF    0
#define CONF_BAL_BITS_OFF      1                               /* [1, 63)  */
#define CONF_BAL_IS_OUTPUT_OFF (CONF_BAL_BITS_OFF + CONF_BAL_RANGE_BITS) /* 63 */
#define CONF_BAL_IS_CLAIMED_OFF (CONF_BAL_IS_OUTPUT_OFF + 1)   /* 64 */
#define CONF_BAL_IS_FEE_OFF     (CONF_BAL_IS_CLAIMED_OFF + 1)  /* 65 */
#define CONF_BAL_IS_REAL_OFF    (CONF_BAL_IS_FEE_OFF + 1)      /* 66 */
#define CONF_BAL_N_CLAIMED_OFF  (CONF_BAL_IS_REAL_OFF + 1)     /* 67 */
#define CONF_BAL_N_FEE_OFF      (CONF_BAL_N_CLAIMED_OFF + 1)   /* 68 */
#define CONF_BAL_BAL_OFF        (CONF_BAL_N_FEE_OFF + 1)       /* 69 */
#define CONF_BAL_WIDTH          (CONF_BAL_BAL_OFF + 1)         /* 70 */

/** Max log2(height); N ≤ 2^log_height − 2. 11 ⇒ Σ_out < 2^63 < p (no wrap). */
#define CONF_BAL_MAX_LOG_HEIGHT 11

/**
 * @brief Honest-prover trace generation.
 *
 * @param outputs     N output amounts (each < 2^52).
 * @param n_out       N (number of outputs), 0 < N ≤ 2^log_height − 2.
 * @param claimed     claimed input sum (< 2^62); MUST equal Σ outputs + fee.
 * @param fee         fee (< 2^52).
 * @param log_height  trace height = 2^log_height, ≤ CONF_BAL_MAX_LOG_HEIGHT.
 * @param trace_out   caller buffer of (2^log_height * CONF_BAL_WIDTH) uint64_t.
 * @return true on success; false on a parameter/consistency error.
 */
bool conf_balance_air_generate(const uint64_t *outputs, size_t n_out,
                               uint64_t claimed, uint64_t fee,
                               unsigned log_height, uint64_t *trace_out);

/**
 * @brief Evaluate ALL AIR constraints over a trace (the verifier).
 *
 * @param trace   2^log_height rows × CONF_BAL_WIDTH canonical columns.
 * @param n_rows  number of rows (= 2^log_height).
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_balance_air_eval(const uint64_t *trace, size_t n_rows);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_BALANCE_AIR_H */
