/**
 * @file range_proof.h
 * @brief Bulletproofs Range Proof API
 *
 * Range proofs prove that a committed value lies within a range [0, 2^n)
 * without revealing the actual value.
 *
 * We use Bulletproofs for compact range proofs (~700 bytes for 64-bit range).
 *
 * Properties:
 *   - Zero-knowledge: Reveals nothing about value except it's in range
 *   - Compact: O(log n) proof size
 *   - No trusted setup required
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_RANGE_PROOF_H
#define DNAC_RANGE_PROOF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "commitment.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Maximum range proof size (Bulletproof for 64-bit) */
#define DNAC_RANGE_PROOF_MAX_SIZE       800

/** Range bits (64-bit values) */
#define DNAC_RANGE_BITS                 64

/* ============================================================================
 * Functions
 * ========================================================================== */

/**
 * @brief Initialize range proof context
 *
 * Must be called once before using other functions.
 *
 * @return 0 on success, -1 on failure
 */
int dnac_range_proof_init(void);

/**
 * @brief Shutdown range proof context
 */
void dnac_range_proof_shutdown(void);

/**
 * @brief Create range proof for committed value
 *
 * Proves value is in [0, 2^64) without revealing value.
 *
 * @param commitment Pedersen commitment (33 bytes)
 * @param value Actual value (must match commitment)
 * @param blinding Blinding factor used in commitment (32 bytes)
 * @param proof_out Output proof buffer
 * @param proof_len_out Output proof length
 * @param max_proof_len Maximum buffer size
 * @return 0 on success, -1 on failure
 */
int dnac_range_proof_create(const uint8_t *commitment,
                            uint64_t value,
                            const uint8_t *blinding,
                            uint8_t *proof_out,
                            size_t *proof_len_out,
                            size_t max_proof_len);

/**
 * @brief Verify range proof
 *
 * Verifies that the commitment contains a value in [0, 2^64).
 *
 * @param commitment Pedersen commitment (33 bytes)
 * @param proof Proof to verify
 * @param proof_len Proof length
 * @return true if valid, false otherwise
 */
bool dnac_range_proof_verify(const uint8_t *commitment,
                             const uint8_t *proof,
                             size_t proof_len);

/**
 * @brief Batch verify multiple range proofs
 *
 * More efficient than verifying individually.
 *
 * @param commitments Array of commitments (33 bytes each)
 * @param proofs Array of proofs
 * @param proof_lens Array of proof lengths
 * @param count Number of proofs
 * @return true if all valid, false if any invalid
 */
bool dnac_range_proof_batch_verify(const uint8_t (*commitments)[33],
                                   const uint8_t **proofs,
                                   const size_t *proof_lens,
                                   int count);

/**
 * @brief Create aggregated range proof for multiple values
 *
 * Single proof for multiple values (more compact than individual proofs).
 *
 * @param commitments Array of commitments (33 bytes each)
 * @param values Array of values
 * @param blindings Array of blinding factors (32 bytes each)
 * @param count Number of values
 * @param proof_out Output proof buffer
 * @param proof_len_out Output proof length
 * @param max_proof_len Maximum buffer size
 * @return 0 on success, -1 on failure
 */
int dnac_range_proof_aggregate(const uint8_t (*commitments)[33],
                               const uint64_t *values,
                               const uint8_t (*blindings)[32],
                               int count,
                               uint8_t *proof_out,
                               size_t *proof_len_out,
                               size_t max_proof_len);

/**
 * @brief Verify aggregated range proof
 *
 * @param commitments Array of commitments (33 bytes each)
 * @param count Number of commitments
 * @param proof Aggregated proof
 * @param proof_len Proof length
 * @return true if valid, false otherwise
 */
bool dnac_range_proof_aggregate_verify(const uint8_t (*commitments)[33],
                                       int count,
                                       const uint8_t *proof,
                                       size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_RANGE_PROOF_H */
