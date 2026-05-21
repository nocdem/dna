/**
 * @file range_air.h
 * @brief 64-bit range proof AIR (DNAC v3, Sub-sprint 3.1)
 *
 * Algebraic Intermediate Representation that proves an amount value is in
 * [0, 2^64) via bit decomposition. The trace has 64 rows (one per bit, LSB
 * to MSB) and 2 columns (bit + accumulator).
 *
 * Constraint set:
 *   C1 (transition, all rows i):   bit_i * (1 - bit_i) = 0
 *     — bit cell must hold 0 or 1.
 *   C2 (boundary, row 0):          acc_0 - bit_0 = 0
 *     — accumulator starts at LSB.
 *   C3 (transition, i ∈ [0, 62]):  acc_{i+1} - acc_i - bit_{i+1} * 2^{i+1} = 0
 *     — accumulator add the next bit's weighted contribution.
 *
 * The final accumulator acc_63 equals the amount being proven. The amount
 * itself is a private witness — it's not exposed by the trace; only that
 * (a) the trace passes all constraints, and (b) the trace's structure
 * forces 0 ≤ amount < p (Goldilocks prime = 2^64 - 2^32 + 1).
 *
 * **Field bound caveat:** Because acc is a Goldilocks element, the AIR cannot
 * represent amounts in [p, 2^64). For amounts ≥ p, the recovered acc is
 * `amount mod p`, NOT the original u64. For DNAC this is fine — total supply
 * is bounded at 10^17 ≈ 2^57, well below p (≈ 2^64). If we ever need amounts
 * ≥ p, the design must move to two field elements per amount.
 *
 * For Sub-sprint 3.1, this module is a STANDALONE AIR — no FRI integration
 * yet. We exercise just trace generation + constraint evaluation + tamper
 * rejection. Sub-sprint 3.2+ will wire it into a STARK proof.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_RANGE_AIR_H
#define DNAC_ZK_RANGE_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bits we prove a range over. */
#define RANGE_AIR_NUM_BITS 64

/** Number of trace columns (bit, accumulator). */
#define RANGE_AIR_NUM_COLS 2

/** A single trace row. */
typedef struct {
    gold_fp2_t bit;  /**< 0 or 1 */
    gold_fp2_t acc;  /**< Accumulator = Σ_{j ≤ i} bit_j * 2^j */
} range_air_row_t;

/**
 * @brief Generate the trace for a given amount.
 *
 * @param amount  64-bit value to decompose.
 * @param trace   Output buffer of RANGE_AIR_NUM_BITS rows.
 */
void range_air_generate_trace(uint64_t amount,
                              range_air_row_t trace[RANGE_AIR_NUM_BITS]);

/**
 * @brief Extract the amount value from a valid trace's final accumulator.
 *
 * Returns the canonical u64 stored in trace[NUM_BITS-1].acc. If the trace
 * is malformed (acc is in extension field), the result may be unexpected;
 * caller should ALSO verify constraints.
 */
uint64_t range_air_recover_amount(const range_air_row_t trace[RANGE_AIR_NUM_BITS]);

/**
 * @brief Check all AIR constraints on the trace.
 *
 * Evaluates C1, C2, C3 over the full trace. Returns true iff every
 * constraint polynomial evaluates to zero at its corresponding row(s).
 *
 * @param trace   Input trace of RANGE_AIR_NUM_BITS rows.
 * @param out_first_failing_constraint  If non-NULL, set to constraint
 *        ID ('1', '2', or '3') of the first failing constraint when the
 *        function returns false. Set to 0 on success.
 * @param out_first_failing_row  If non-NULL, set to the row index of the
 *        first failing constraint instance. Set to 0 on success.
 * @return true if all constraints pass.
 */
bool range_air_check_constraints(const range_air_row_t trace[RANGE_AIR_NUM_BITS],
                                 char *out_first_failing_constraint,
                                 uint32_t *out_first_failing_row);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_RANGE_AIR_H */
