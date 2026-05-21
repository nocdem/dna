/**
 * @file keccak_air_f1600.h
 * @brief Full Keccak-f[1600] AIR assembly (DNAC v3, Sub-sprint 3.3b.6)
 *
 * Chains 24 rounds of (θ ∘ ρ ∘ π ∘ χ ∘ ι) into one AIR witness. Each step's
 * output flows into the next step's input; each round's ι output flows into
 * the next round's θ input.
 *
 * Constraint count: ~24 × 24,320 ≈ ~580,000 per Keccak-f[1600].
 *
 * Memory footprint: ~5.7 MB per witness (heap-allocated). Production AIR
 * would use a column-packed layout; here we keep the natural step-by-step
 * representation for clarity.
 *
 * Cross-validated against keccak_ref_f1600 on random initial states.
 *
 * Padding + multi-block absorption (full SHA3-512) lives in a follow-on
 * sub-sprint (3.3b.7).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_F1600_H
#define DNAC_ZK_KECCAK_AIR_F1600_H

#include <stdbool.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_air_theta.h"
#include "keccak_air_rho_pi.h"
#include "keccak_air_chi.h"
#include "keccak_air_iota.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KECCAK_AIR_F1600_ROUNDS KECCAK_NUM_ROUNDS  /* 24 */

/** Per-round step witnesses chained together. */
typedef struct {
    keccak_air_theta_witness_t  theta;
    keccak_air_rho_pi_witness_t rho_pi;
    keccak_air_chi_witness_t    chi;
    keccak_air_iota_witness_t   iota;
} keccak_air_round_witness_t;

typedef struct {
    keccak_air_round_witness_t rounds[KECCAK_AIR_F1600_ROUNDS];
} keccak_air_f1600_witness_t;

/**
 * @brief Build full witness from initial state.
 *
 * Internally runs 24 rounds (using keccak_ref step functions) and populates
 * every step's witness for every round. Output state can be recovered from
 * w->rounds[23].iota.output_bits.
 *
 * @param initial_lanes  25-lane state BEFORE Keccak-f.
 * @param final_lanes    25-lane state AFTER Keccak-f (must equal keccak_ref_f1600(initial)).
 * @param w              Witness to populate (caller-allocated, ~5.7 MB).
 */
void keccak_air_f1600_build_witness(const uint64_t initial_lanes[KECCAK_NUM_LANES],
                                    const uint64_t final_lanes[KECCAK_NUM_LANES],
                                    keccak_air_f1600_witness_t *w);

/**
 * @brief Verify all 24-round constraints + inter-round and inter-step bindings.
 *
 * Checks every sub-witness's constraints + the linking equations:
 *   - theta_R.input == iota_{R-1}.output  (for R ≥ 1)
 *   - rho_pi_R.input == theta_R.output
 *   - chi_R.input    == rho_pi_R.output
 *   - iota_R.input   == chi_R.output
 *
 * @return true iff every constraint and every link binding holds.
 */
bool keccak_air_f1600_check_constraints(const keccak_air_f1600_witness_t *w,
                                        uint32_t *out_failing_round,
                                        char *out_failing_step,        /* 'T','R','C','I' or 'L' link */
                                        char *out_inner_constraint,    /* sub-step constraint id */
                                        uint32_t *out_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_F1600_H */
