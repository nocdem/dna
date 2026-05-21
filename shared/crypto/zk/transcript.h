/**
 * @file transcript.h
 * @brief Fiat-Shamir transcript for STARK range proofs (DNAC v3)
 *
 * Implements strict-ordering hash chain per design doc § 4.3 + F4 fix.
 * Binds T₀ to chain_id, block_height, tx_index, public_input. Prevents
 * intra-block proof replay attacks.
 *
 * Determinism invariants:
 *   - D3: Single SHA3-512 chain; strict left-to-right absorb order.
 *   - D3.1: Challenge rejection sampling is deterministic (fixed byte order).
 *
 * Faz 1 scope: API skeleton only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_TRANSCRIPT_H
#define DNAC_ZK_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** SHA3-512 output size (matches Merkle module). */
#define TRANSCRIPT_HASH_SIZE 64

/** Protocol domain separator for T₀ initialization. */
#define TRANSCRIPT_PROTOCOL_DOMAIN "DNAC_RP_TRANSCRIPT_V1\0\0\0"
#define TRANSCRIPT_PROTOCOL_DOMAIN_LEN 24

/** Domain tag for challenge derivation (per § 4.3). */
#define TRANSCRIPT_CHALLENGE_TAG "CHAL"
#define TRANSCRIPT_CHALLENGE_TAG_LEN 4

/* ============================================================================
 * Types
 * ========================================================================== */

/**
 * @brief Transcript state.
 *
 * Holds the current 64-byte hash chain head plus a challenge counter for
 * deterministic squeeze-to-field.
 */
typedef struct {
    uint8_t state[TRANSCRIPT_HASH_SIZE];  /**< Current SHA3-512 chain head */
    uint32_t challenge_counter;           /**< Monotonic counter for challenge derivation */
} transcript_t;

/* ============================================================================
 * Initialization (F4 fix applied)
 * ========================================================================== */

/**
 * @brief Initialize transcript with TX-binding public input.
 *
 * T₀ = SHA3-512( TRANSCRIPT_PROTOCOL_DOMAIN ||
 *                chain_id[32] || block_height_BE_u64 || tx_index_BE_u32 ||
 *                public_input )
 *
 * @param t Transcript to initialize.
 * @param chain_id 32-byte DNAC chain identifier (from chain_def).
 * @param block_height Block height the TX is admitted into.
 * @param tx_index TX position within block (0-indexed).
 * @param public_input Serialized public input (commitments + input_sum + fee).
 * @param public_input_len Length of public_input in bytes.
 */
void transcript_init(transcript_t *t,
                     const uint8_t chain_id[32],
                     uint64_t block_height,
                     uint32_t tx_index,
                     const uint8_t *public_input,
                     size_t public_input_len);

/* ============================================================================
 * Absorb (prover writes / verifier mirrors)
 * ========================================================================== */

/**
 * @brief Absorb a message into the transcript.
 *
 * T_i+1 = SHA3-512( T_i || message )
 *
 * MUST be called in identical order on prover and verifier sides. Order
 * per design doc § 4.3:
 *   1. trace Merkle root
 *   2. trace evaluation polynomials
 *   3. quotient Merkle root
 *   4. FRI commit phase Merkle roots (one per layer)
 *   5. final polynomial coefficients
 *
 * @param t Transcript state to update.
 * @param msg Message bytes.
 * @param msg_len Length of msg in bytes.
 */
void transcript_absorb(transcript_t *t,
                       const uint8_t *msg,
                       size_t msg_len);

/* ============================================================================
 * Challenge derivation (rejection sampling, deterministic)
 * ========================================================================== */

/**
 * @brief Derive a Goldilocks² challenge from current transcript state.
 *
 * challenge_j = field_from_hash( SHA3-512( T || TRANSCRIPT_CHALLENGE_TAG || j_BE_u32 ) )
 *
 * Increments t->challenge_counter as side effect. Rejection sampling: take
 * 8 bytes as u64; if ≥ p, shift to next 8 bytes; repeat for second component.
 *
 * @param t Transcript state (counter incremented).
 * @return Pseudorandom Goldilocks² element.
 */
gold_fp2_t transcript_challenge_fp2(transcript_t *t);

/**
 * @brief Derive a u32 query index (used for FRI query selection).
 *
 * Returns a uniform u32 in [0, max_index). Uses rejection sampling to
 * avoid modulo bias.
 *
 * @param t Transcript state.
 * @param max_index Upper bound (exclusive).
 * @return Pseudorandom index in [0, max_index).
 */
uint32_t transcript_challenge_query_index(transcript_t *t, uint32_t max_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_TRANSCRIPT_H */
