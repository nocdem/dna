/**
 * @file keccak_p3_cols.c
 * @brief Plonky3-style Keccak-f AIR constants + helpers (Sub-sprint 3.4r).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_p3_cols.h"

/* ρ rotation offsets — FIPS-202 §3.2.2 Table 2. */
const uint8_t KECCAK_P3_R[KECCAK_P3_DIM][KECCAK_P3_DIM] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14},
};

/* ι round constants — FIPS-202 §3.2.5 Algorithm 5 output. */
const uint64_t KECCAK_P3_RC[KECCAK_P3_NUM_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

void keccak_p3_lane_to_limbs(uint64_t lane,
                             gold_fp_t out_limbs[KECCAK_P3_U64_LIMBS]) {
    for (unsigned i = 0; i < KECCAK_P3_U64_LIMBS; i++) {
        uint64_t limb = (lane >> (i * KECCAK_P3_BITS_PER_LIMB)) & 0xFFFFULL;
        out_limbs[i] = gold_fp_from_u64(limb);
    }
}

uint64_t keccak_p3_limbs_to_lane(const gold_fp_t limbs[KECCAK_P3_U64_LIMBS]) {
    uint64_t lane = 0;
    for (unsigned i = 0; i < KECCAK_P3_U64_LIMBS; i++) {
        uint64_t limb = gold_fp_to_u64(limbs[i]) & 0xFFFFULL;
        lane |= limb << (i * KECCAK_P3_BITS_PER_LIMB);
    }
    return lane;
}

void keccak_p3_lane_to_bits(uint64_t lane,
                            gold_fp_t out_bits[KECCAK_P3_LANE_BITS]) {
    for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
        out_bits[z] = gold_fp_from_u64((lane >> z) & 1ULL);
    }
}
