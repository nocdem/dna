/**
 * @file keccak_p3_cols.h
 * @brief Plonky3-style Keccak-f AIR column layout (DNAC v3, Sub-sprint 3.4r)
 *
 * Port of Plonky3 `keccak-air` crate's KeccakCols structure (pinned commit
 * 82cfad73, Apache-2.0). Read-for-understanding port per design doc § 9 F19;
 * no copy-paste from upstream Rust source. Same column shape, same constraint
 * semantics, original C99 code.
 *
 * Why this exists alongside 3.3b.*:
 *   The 3.3b.* AIR witnesses store each step (θ/ρπ/χ/ι) as a separate witness
 *   struct with input_bits[1600] + output_bits[1600] + aux. Total ~370k cells
 *   per Keccak-f. Workable for AIR-level constraint checking but too verbose
 *   for STARK proof generation (trace LDE blows up).
 *
 *   Plonky3 keccak-air packs one ROW per round (24 rows per Keccak-f). Each
 *   row holds the full round state in mixed limb/bit representation:
 *     - Lanes as 16-bit limbs where possible (compact, gives free range-check)
 *     - Bits only where χ needs them (`a_prime`)
 *     - Aux witnesses (c, c_prime) minimal — derivable from a but stored for
 *       constraint-evaluation efficiency
 *   Total ~2,633 cells per row × 24 rows = ~63,200 cells per Keccak-f.
 *   This is the trace shape FRI commit + query phases (3.5c+) consume.
 *
 * Trace cells are `gold_fp_t` (Goldilocks base field), not `gold_fp2_t`.
 * Plonky3 uses base field for trace; extension only for FRI soundness amplification.
 *
 * Constants R (rotation offsets) and RC (round constants) come from FIPS-202
 * §3.2.5; same tables Plonky3 uses but originating from the standard, not from
 * Plonky3's source. RC_BITS table is recomputed at startup from RC (not
 * statically tabulated) to avoid any per-byte copy from upstream.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_KECCAK_P3_COLS_H
#define DNAC_ZK_KECCAK_P3_COLS_H

#include <stdbool.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Bits per limb in the lane representation. Plonky3 uses 16; we match. */
#define KECCAK_P3_BITS_PER_LIMB 16

/** Limbs per 64-bit lane (= 64 / BITS_PER_LIMB). */
#define KECCAK_P3_U64_LIMBS 4

/** Keccak-f rounds. */
#define KECCAK_P3_NUM_ROUNDS 24

/** Per-row "side" dimension of the state (5×5 lanes). */
#define KECCAK_P3_DIM 5

/** Bits in a 64-bit lane. */
#define KECCAK_P3_LANE_BITS 64

/**
 * @brief AIR trace row, one per Keccak-f round.
 *
 * Field order is the binding layout for constraints in `keccak_p3_air.c`.
 * Do NOT reorder without updating tests + constraint indexing.
 *
 * Total cells: 24 + 1 + 100 + 100 + 320 + 320 + 1600 + 100 + 64 + 4 = 2633.
 */
typedef struct {
    /** One-hot: step_flags[i] = 1 iff this row encodes round i. */
    gold_fp_t step_flags[KECCAK_P3_NUM_ROUNDS];

    /** Set to 1 on rows whose output should be exported (final round).
     *  Named `export_flag` (not `export`) — the bare `export` is a reserved
     *  keyword in C++ and triggers clang/clang-tidy diagnostics even in C
     *  headers when seen via shared analyzers. */
    gold_fp_t export_flag;

    /** Initial input lanes (persists across all 24 rows of a permutation),
     *  y-major: preimage[y][x][limb]. */
    gold_fp_t preimage[KECCAK_P3_DIM][KECCAK_P3_DIM][KECCAK_P3_U64_LIMBS];

    /** This round's input state lanes, y-major. */
    gold_fp_t a[KECCAK_P3_DIM][KECCAK_P3_DIM][KECCAK_P3_U64_LIMBS];

    /** Column parities (binary): c[x][z] = XOR over y of bit z of a[y][x]. */
    gold_fp_t c[KECCAK_P3_DIM][KECCAK_P3_LANE_BITS];

    /** θ helper (binary): c_prime[x][z] = c[x][z] XOR c[(x-1)%5][z]
     *                                       XOR c[(x+1)%5][(z-1)%64]. */
    gold_fp_t c_prime[KECCAK_P3_DIM][KECCAK_P3_LANE_BITS];

    /** Post-θ state bits, y-major: a_prime[y][x][z]. */
    gold_fp_t a_prime[KECCAK_P3_DIM][KECCAK_P3_DIM][KECCAK_P3_LANE_BITS];

    /** Post-χ state lanes (in 16-bit limbs), y-major. */
    gold_fp_t a_prime_prime[KECCAK_P3_DIM][KECCAK_P3_DIM][KECCAK_P3_U64_LIMBS];

    /** Bit decomposition of a_prime_prime[0][0] (needed for ι RC XOR). */
    gold_fp_t a_prime_prime_0_0_bits[KECCAK_P3_LANE_BITS];

    /** Post-ι lane for position (0,0) (the only position ι touches). */
    gold_fp_t a_prime_prime_prime_0_0_limbs[KECCAK_P3_U64_LIMBS];
} keccak_p3_cols_t;

/** Number of `gold_fp_t` cells per row.
 *  = 24 + 1 + 100 + 100 + 320 + 320 + 1600 + 100 + 64 + 4 = 2633. */
#define KECCAK_P3_NUM_COLS (sizeof(keccak_p3_cols_t) / sizeof(gold_fp_t))

/* Compile-time check that the struct has no padding (C99 idiom — negative
 * array size on mismatch). 2633 cells × 16 bytes (gold_fp_t = u64 wrapper) =
 * 21,064 bytes, but gold_fp_t alignment is 8, so the struct stays packed. */
typedef char _keccak_p3_cols_size_check[
    (sizeof(keccak_p3_cols_t) == 2633u * sizeof(gold_fp_t)) ? 1 : -1];

/* ============================================================================
 * Constants — FIPS-202 §3.2.5 tables. Same numerical content as Plonky3 (they
 * also derive from the standard); originating from the standard, not copied
 * from upstream source.
 * ========================================================================== */

/** ρ rotation offsets, indexed [x][y]. From FIPS-202 §3.2.2 Table 2. */
extern const uint8_t KECCAK_P3_R[KECCAK_P3_DIM][KECCAK_P3_DIM];

/** ι round constants, 24 values. From FIPS-202 §3.2.5 Algorithm 5. */
extern const uint64_t KECCAK_P3_RC[KECCAK_P3_NUM_ROUNDS];

/**
 * @brief Bit b (LSB-first) of round constant `r`.
 *
 * Convenience: equivalent to `(KECCAK_P3_RC[r] >> b) & 1`. Avoids a separate
 * RC_BITS table; the constraint check uses this directly.
 */
static inline uint8_t keccak_p3_rc_bit(unsigned r, unsigned b) {
    return (uint8_t)((KECCAK_P3_RC[r] >> b) & 1ULL);
}

/* ============================================================================
 * Helpers for limb/bit packing (used by trace generator + constraint check).
 * ========================================================================== */

/**
 * @brief Split a 64-bit lane into 4 little-endian 16-bit limbs.
 *
 * limb[i] = (lane >> (i * 16)) & 0xFFFF, i ∈ [0, 4).
 */
void keccak_p3_lane_to_limbs(uint64_t lane,
                             gold_fp_t out_limbs[KECCAK_P3_U64_LIMBS]);

/**
 * @brief Inverse: reassemble a 64-bit lane from 4 little-endian 16-bit limbs.
 *
 * Each limb is expected to be a Goldilocks element in [0, 2^16). Out-of-range
 * limbs are not validated here; constraint check enforces the range.
 */
uint64_t keccak_p3_limbs_to_lane(const gold_fp_t limbs[KECCAK_P3_U64_LIMBS]);

/**
 * @brief Decompose a 64-bit lane into 64 LSB-first binary cells (0/1).
 */
void keccak_p3_lane_to_bits(uint64_t lane,
                            gold_fp_t out_bits[KECCAK_P3_LANE_BITS]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_KECCAK_P3_COLS_H */
