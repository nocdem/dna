/**
 * @file keccak_air_bits.h
 * @brief Bit decomposition primitives for Keccak-AIR (DNAC v3, Sub-sprint 3.3b.1)
 *
 * Keccak-f[1600] operates on a 1600-bit state. AIR encoding represents each
 * bit as an independent field element constrained to {0, 1}. This module
 * provides the bridge between u64 lanes and 64-element field-bit arrays,
 * plus the constraint helpers for XOR-in-field.
 *
 * Bit ordering convention: bit 0 = LSB of the u64 lane.
 *   lane = Σ_{i=0..63} bits[i] * 2^i
 *
 * XOR encoding in field of characteristic ≠ 2:
 *   For 2-input XOR(a, b) where a, b ∈ {0, 1}:
 *     XOR(a, b) = a + b - 2*a*b
 *   For 5-input XOR (θ column parity), use auxiliary witness:
 *     sum = b0 + b1 + b2 + b3 + b4   (range [0, 5])
 *     result = sum mod 2 = sum - 2*w
 *     where w ∈ {0, 1, 2} is auxiliary
 *     Constraints:
 *       result*(1-result) = 0          (binary)
 *       w*(w-1)*(w-2) = 0              (range)
 *       sum = result + 2*w             (relation)
 *
 * This module supplies the building blocks; full θ/ρ/π/χ/ι step encodings
 * come in subsequent sub-sprints (3.3b.2..3.3b.6).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_BITS_H
#define DNAC_ZK_KECCAK_AIR_BITS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Number of bits in a Keccak lane. */
#define KECCAK_BITS_PER_LANE 64

/* ============================================================================
 * Bit ↔ Lane conversion
 * ========================================================================== */

/**
 * @brief Decompose a u64 lane into 64 field bits.
 *
 * @param lane   Input value.
 * @param bits   Output array of 64 Goldilocks² elements, each ∈ {0, 1}.
 *               bits[0] = LSB.
 */
void keccak_air_lane_to_bits(uint64_t lane,
                             gold_fp2_t bits[KECCAK_BITS_PER_LANE]);

/**
 * @brief Reassemble a u64 from 64 field bits.
 *
 * Assumes each bit is canonical {0, 1}; if not, result is undefined (use
 * keccak_air_check_bits_binary to validate first).
 *
 * @param bits   Input 64 field bits, bit[0] = LSB.
 * @return Reconstructed lane value.
 */
uint64_t keccak_air_bits_to_lane(const gold_fp2_t bits[KECCAK_BITS_PER_LANE]);

/* ============================================================================
 * Constraint helpers
 * ========================================================================== */

/**
 * @brief Verify each of n bits is in {0, 1}.
 *
 * Constraint: bit_i * (1 - bit_i) = 0 for all i ∈ [0, n).
 *
 * @return true iff all n bits are binary.
 */
bool keccak_air_check_bits_binary(const gold_fp2_t *bits, size_t n);

/**
 * @brief XOR two binary field bits.
 *
 * Returns a + b - 2*a*b. Assumes both inputs are in {0, 1}; result is
 * binary iff inputs are binary.
 */
gold_fp2_t keccak_air_xor2(gold_fp2_t a, gold_fp2_t b);

/**
 * @brief Verify 2-input XOR constraint: result == a + b - 2*a*b.
 *
 * Used to verify auxiliary witness columns in θ/χ encoding.
 *
 * @return true iff constraint holds.
 */
bool keccak_air_check_xor2(gold_fp2_t a,
                           gold_fp2_t b,
                           gold_fp2_t result);

/**
 * @brief XOR five binary bits using auxiliary witness.
 *
 * Computes result and witness deterministically from inputs. Caller can
 * later verify (result, w) via keccak_air_check_xor5.
 *
 * @param bits[5]    Input bits, each ∈ {0, 1}.
 * @param result     Output: XOR of all 5 bits.
 * @param witness    Output: auxiliary witness w such that sum = result + 2*w.
 *                   w ∈ {0, 1, 2}.
 */
void keccak_air_xor5(const gold_fp2_t bits[5],
                     gold_fp2_t *result,
                     gold_fp2_t *witness);

/**
 * @brief Verify 5-input XOR constraint system.
 *
 * Constraints:
 *   1. result * (1 - result) = 0    (result is binary)
 *   2. w * (w - 1) * (w - 2) = 0    (witness in {0, 1, 2})
 *   3. (b0+b1+b2+b3+b4) = result + 2*w
 *
 * @return true iff all three constraints hold.
 */
bool keccak_air_check_xor5(const gold_fp2_t bits[5],
                           gold_fp2_t result,
                           gold_fp2_t witness);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_BITS_H */
