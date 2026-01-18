/**
 * @file commitment.h
 * @brief Pedersen Commitment API
 *
 * Pedersen commitments allow hiding a value while still allowing
 * arithmetic operations (addition) on the commitments.
 *
 * Commitment: C = g^v * h^r
 * Where:
 *   g, h = generator points on elliptic curve
 *   v    = value being committed
 *   r    = random blinding factor
 *
 * Properties:
 *   - Hiding: Cannot determine v from C without r
 *   - Binding: Cannot find different (v', r') with same C
 *   - Homomorphic: C1 + C2 = commit(v1 + v2, r1 + r2)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_COMMITMENT_H
#define DNAC_COMMITMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Commitment size (compressed secp256k1 point) */
#define DNAC_PEDERSEN_COMMITMENT_SIZE   33

/** Blinding factor size (32-byte scalar) */
#define DNAC_PEDERSEN_BLINDING_SIZE     32

/** Maximum value that can be committed (64-bit) */
#define DNAC_PEDERSEN_MAX_VALUE         UINT64_MAX

/* ============================================================================
 * Functions
 * ========================================================================== */

/**
 * @brief Initialize Pedersen commitment context
 *
 * Must be called once before using other functions.
 * Sets up generator points.
 *
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_init(void);

/**
 * @brief Shutdown Pedersen commitment context
 */
void dnac_pedersen_shutdown(void);

/**
 * @brief Create a Pedersen commitment
 *
 * C = g^value * h^blinding
 *
 * @param value Value to commit (64-bit unsigned)
 * @param blinding Blinding factor (32 bytes, can be NULL for random)
 * @param commitment_out Output commitment (33 bytes)
 * @param blinding_out Output blinding factor used (33 bytes, can be NULL)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_commit(uint64_t value,
                         const uint8_t *blinding,
                         uint8_t *commitment_out,
                         uint8_t *blinding_out);

/**
 * @brief Add two commitments
 *
 * Result commits to sum of values with sum of blindings.
 * C1 + C2 = commit(v1 + v2, r1 + r2)
 *
 * @param c1 First commitment (33 bytes)
 * @param c2 Second commitment (33 bytes)
 * @param result_out Output commitment (33 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_add(const uint8_t *c1,
                      const uint8_t *c2,
                      uint8_t *result_out);

/**
 * @brief Subtract two commitments
 *
 * Result commits to difference of values with difference of blindings.
 * C1 - C2 = commit(v1 - v2, r1 - r2)
 *
 * @param c1 First commitment (33 bytes)
 * @param c2 Second commitment (33 bytes)
 * @param result_out Output commitment (33 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_sub(const uint8_t *c1,
                      const uint8_t *c2,
                      uint8_t *result_out);

/**
 * @brief Add blinding factors
 *
 * @param b1 First blinding factor (32 bytes)
 * @param b2 Second blinding factor (32 bytes)
 * @param result_out Output blinding factor (32 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_blind_add(const uint8_t *b1,
                            const uint8_t *b2,
                            uint8_t *result_out);

/**
 * @brief Subtract blinding factors
 *
 * @param b1 First blinding factor (32 bytes)
 * @param b2 Second blinding factor (32 bytes)
 * @param result_out Output blinding factor (32 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_blind_sub(const uint8_t *b1,
                            const uint8_t *b2,
                            uint8_t *result_out);

/**
 * @brief Negate blinding factor
 *
 * @param blinding Blinding factor to negate (32 bytes)
 * @param result_out Output negated blinding (32 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_blind_negate(const uint8_t *blinding,
                               uint8_t *result_out);

/**
 * @brief Verify that commitment opens to given value
 *
 * Checks if C == g^value * h^blinding
 *
 * @param commitment Commitment to verify (33 bytes)
 * @param value Claimed value
 * @param blinding Claimed blinding factor (32 bytes)
 * @return true if valid, false otherwise
 */
bool dnac_pedersen_verify(const uint8_t *commitment,
                          uint64_t value,
                          const uint8_t *blinding);

/**
 * @brief Generate random blinding factor
 *
 * @param blinding_out Output blinding factor (32 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_random_blinding(uint8_t *blinding_out);

/**
 * @brief Compute sum of blinding factors for balance proof
 *
 * For a valid transaction: sum(input_blindings) = sum(output_blindings)
 * This computes the excess blinding factor.
 *
 * @param input_blindings Array of input blinding factors
 * @param input_count Number of inputs
 * @param output_blindings Array of output blinding factors
 * @param output_count Number of outputs
 * @param excess_out Output excess blinding (32 bytes)
 * @return 0 on success, -1 on failure
 */
int dnac_pedersen_compute_excess(const uint8_t (*input_blindings)[32],
                                 int input_count,
                                 const uint8_t (*output_blindings)[32],
                                 int output_count,
                                 uint8_t *excess_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_COMMITMENT_H */
