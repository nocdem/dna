/**
 * @file keccak_air_sha3_512.h
 * @brief Single-block SHA3-512 AIR encoding (DNAC v3, Sub-sprint 3.3b.7)
 *
 * Closes Faz 3.3b: full SHA3-512 (FIPS-202) in AIR for inputs ≤ rate-2 bytes
 * (= 70 bytes). Single Keccak-f[1600] invocation; padding rule encoded as
 * constraints; squeeze the first 64 bytes (8 lanes) from final state.
 *
 * Multi-block (inputs > 70 bytes) and variable-length AIR are follow-on work.
 * For DNAC range proof commitment input (~188 bytes), Sub-sprint 3.3b.8 will
 * chain multiple blocks through this same primitive.
 *
 * Padding rule (FIPS-202 §B.2):
 *   padded_block[i] = input[i]      for i ∈ [0, L)
 *   padded_block[L] = 0x06
 *   padded_block[i] = 0x00          for i ∈ (L, RATE-1)
 *   padded_block[RATE-1] |= 0x80    (high bit of last byte set)
 *
 * If L == RATE - 1 (i.e., only one byte free), then byte RATE-1 = 0x06 | 0x80
 * = 0x86. We DO NOT support L == RATE - 1 in this single-block version (caller
 * must ensure L ≤ RATE - 2 so 0x06 and 0x80 fit in distinct bytes).
 *
 * Bit ordering inside a byte: bit 0 = LSB, encoded as 8 binary field cells
 * per byte.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_AIR_SHA3_512_H
#define DNAC_ZK_KECCAK_AIR_SHA3_512_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"
#include "keccak_air_f1600.h"

#ifdef __cplusplus
extern "C" {
#endif

/** SHA3-512 rate in bytes (FIPS-202). */
#define SHA3_512_RATE_BYTES 72

/** SHA3-512 output bytes. */
#define SHA3_512_OUT_BYTES 64

/** Max input bytes for single-block AIR. */
#define SHA3_AIR_SINGLE_BLOCK_MAX_INPUT (SHA3_512_RATE_BYTES - 2)  /* 70 */

/** Bits in one block. */
#define SHA3_512_BLOCK_BITS (SHA3_512_RATE_BYTES * 8)  /* 576 */

/** Bits in output. */
#define SHA3_512_OUT_BITS (SHA3_512_OUT_BYTES * 8)  /* 512 */

/**
 * @brief Witness for single-block SHA3-512 AIR.
 */
typedef struct {
    /** Length of input in bytes (public, ≤ 70). */
    uint32_t input_len;
    /** Bit decomposition of input bytes (input_len * 8 binary cells used). */
    gold_fp2_t input_bits[SHA3_AIR_SINGLE_BLOCK_MAX_INPUT * 8];
    /** Bit decomposition of padded block (576 binary cells). */
    gold_fp2_t padded_bits[SHA3_512_BLOCK_BITS];
    /** Full f1600 witness applied to the (padded || zeros) state. */
    keccak_air_f1600_witness_t f1600;
    /** Output bytes as bits (512 binary cells = first 8 lanes of f1600 output). */
    gold_fp2_t output_bits[SHA3_512_OUT_BITS];
} keccak_air_sha3_512_witness_t;

/**
 * @brief Build full witness from an input byte buffer.
 *
 * @param input       Input bytes.
 * @param input_len   Input length (≤ SHA3_AIR_SINGLE_BLOCK_MAX_INPUT).
 * @param w           Witness to populate.
 * @return 0 on success, -1 on invalid input_len.
 */
int keccak_air_sha3_512_build_witness(const uint8_t *input,
                                      uint32_t input_len,
                                      keccak_air_sha3_512_witness_t *w);

/**
 * @brief Verify all SHA3-512 single-block AIR constraints.
 *
 * Checks:
 *   - All bit cells (input, padded, output, f1600 internal) ∈ {0, 1}
 *   - Padding rule: padded bits match input + 0x06 + zeros + 0x80
 *   - Initial state: first 576 bits = padded_bits, remaining 1024 bits = 0
 *   - f1600 constraints (delegates to keccak_air_f1600_check_constraints)
 *   - Output: output_bits == first 512 bits of f1600 final state
 *
 * @return true iff constraints satisfied.
 */
bool keccak_air_sha3_512_check_constraints(const keccak_air_sha3_512_witness_t *w,
                                           char *out_first_failing_phase,
                                           uint32_t *out_first_failing_index);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_AIR_SHA3_512_H */
