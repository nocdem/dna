/**
 * @file keccak_ref.h
 * @brief Standalone Keccak-f[1600] + SHA3-512 reference (DNAC v3, Sub-sprint 3.3a)
 *
 * Pure C implementation of FIPS-202 SHA3-512 used as the AIR-encoding
 * reference. The Plonky3 keccak-air crate proves this exact function in
 * AIR form; our standalone C version is what Sub-sprint 3.3b will encode
 * constraint-by-constraint.
 *
 * Why not use crypto/hash/qgp_sha3.c?
 *   - qgp_sha3 wraps OpenSSL. Opaque to us at the algorithm level.
 *   - The AIR encoding requires explicit control over per-round state
 *     and per-step operations. We need transparent C that mirrors the
 *     AIR's round-by-round trace exactly.
 *
 * Cross-validated against qgp_sha3_512 (OpenSSL) — bit-identical output.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_REF_H
#define DNAC_ZK_KECCAK_REF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Number of Keccak-f rounds. */
#define KECCAK_NUM_ROUNDS 24

/** Lane count in Keccak state (5×5). */
#define KECCAK_NUM_LANES 25

/** SHA3-512 output length (bytes). */
#define KECCAK_SHA3_512_OUT 64

/** SHA3-512 rate in bytes (576 bits). */
#define KECCAK_SHA3_512_RATE 72

/**
 * @brief Apply Keccak-f[1600] permutation in place.
 *
 * @param state  25-lane state (= 1600 bits) in little-endian 64-bit lanes.
 */
void keccak_ref_f1600(uint64_t state[KECCAK_NUM_LANES]);

/* ============================================================================
 * Step-by-step API (used as cross-validation reference for AIR encoding).
 *
 * keccak_round = ι ∘ χ ∘ π ∘ ρ ∘ θ  (applied in this order: theta first).
 * We expose each step separately so AIR encoding tests can validate
 * one step at a time.
 * ========================================================================== */

/** Apply only θ (theta) step in place. */
void keccak_ref_theta(uint64_t state[KECCAK_NUM_LANES]);

/** Apply only ρ + π (rho + pi) steps in place. */
void keccak_ref_rho_pi(uint64_t state[KECCAK_NUM_LANES]);

/** Apply only χ (chi) step in place. */
void keccak_ref_chi(uint64_t state[KECCAK_NUM_LANES]);

/** Apply only ι (iota) step in place with the given round constant. */
void keccak_ref_iota(uint64_t state[KECCAK_NUM_LANES], uint64_t rc);

/** Per-round constants, indexed [0, KECCAK_NUM_ROUNDS). */
extern const uint64_t keccak_ref_round_constants[KECCAK_NUM_ROUNDS];

/**
 * @brief SHA3-512 hash (standalone, no OpenSSL).
 *
 * Output is byte-identical to FIPS-202 SHA3-512.
 *
 * @param input    Message bytes.
 * @param input_len  Length of input in bytes.
 * @param out      Output buffer of KECCAK_SHA3_512_OUT (64) bytes.
 */
void keccak_ref_sha3_512(const uint8_t *input,
                         size_t input_len,
                         uint8_t out[KECCAK_SHA3_512_OUT]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_REF_H */
