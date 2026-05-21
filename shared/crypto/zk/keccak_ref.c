/**
 * @file keccak_ref.c
 * @brief FIPS-202 Keccak-f[1600] + SHA3-512 reference implementation.
 *
 * State layout: 5×5 lanes of 64 bits each, stored linearly as
 * state[x + 5*y] where x,y ∈ [0, 5). Each lane is a u64 in
 * little-endian byte order on the wire (per FIPS-202).
 *
 * Round function: θ ∘ ρ ∘ π ∘ χ ∘ ι (applied right-to-left), 24 rounds.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_ref.h"

#include <string.h>

/* Round constants are defined in keccak_ref_round_constants below (exposed). */

/* ============================================================================
 * ρ rotation offsets (FIPS-202 Table 2), indexed by x + 5*y
 * ========================================================================== */
static const unsigned KECCAK_ROT[KECCAK_NUM_LANES] = {
     0,  1, 62, 28, 27,    /* y = 0 */
    36, 44,  6, 55, 20,    /* y = 1 */
     3, 10, 43, 25, 39,    /* y = 2 */
    41, 45, 15, 21,  8,    /* y = 3 */
    18,  2, 61, 56, 14     /* y = 4 */
};

/* ============================================================================
 * Helpers
 * ========================================================================== */

static inline uint64_t rotl64(uint64_t v, unsigned n) {
    /* n is always in [0, 63] in Keccak; handle n=0 safely. */
    return (n == 0) ? v : ((v << n) | (v >> (64 - n)));
}

/* Read 8 little-endian bytes as u64. */
static inline uint64_t load_le64(const uint8_t *p) {
    return  (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Write u64 as 8 little-endian bytes. */
static inline void store_le64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/* ============================================================================
 * Step-by-step API (exposed for AIR cross-validation).
 * ========================================================================== */

const uint64_t keccak_ref_round_constants[KECCAK_NUM_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

void keccak_ref_theta(uint64_t state[KECCAK_NUM_LANES]) {
    uint64_t C[5], D[5];
    for (int x = 0; x < 5; x++) {
        C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (int x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
    }
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            state[x + 5 * y] ^= D[x];
        }
    }
}

void keccak_ref_rho_pi(uint64_t state[KECCAK_NUM_LANES]) {
    uint64_t B[KECCAK_NUM_LANES];
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            unsigned src = (unsigned)(x + 5 * y);
            unsigned dst = (unsigned)(y + 5 * ((2 * x + 3 * y) % 5));
            B[dst] = rotl64(state[src], KECCAK_ROT[src]);
        }
    }
    for (int i = 0; i < KECCAK_NUM_LANES; i++) state[i] = B[i];
}

void keccak_ref_chi(uint64_t state[KECCAK_NUM_LANES]) {
    uint64_t B[KECCAK_NUM_LANES];
    for (int i = 0; i < KECCAK_NUM_LANES; i++) B[i] = state[i];
    for (int y = 0; y < 5; y++) {
        for (int x = 0; x < 5; x++) {
            state[x + 5 * y] =
                B[x + 5 * y] ^
                ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
        }
    }
}

void keccak_ref_iota(uint64_t state[KECCAK_NUM_LANES], uint64_t rc) {
    state[0] ^= rc;
}

/* ============================================================================
 * One round of Keccak-f — composition of θ ρ π χ ι
 * ========================================================================== */

static void keccak_round(uint64_t state[KECCAK_NUM_LANES], uint64_t rc) {
    keccak_ref_theta(state);
    keccak_ref_rho_pi(state);
    keccak_ref_chi(state);
    keccak_ref_iota(state, rc);
}

/* ============================================================================
 * Public: Keccak-f[1600]
 * ========================================================================== */

void keccak_ref_f1600(uint64_t state[KECCAK_NUM_LANES]) {
    for (unsigned r = 0; r < KECCAK_NUM_ROUNDS; r++) {
        keccak_round(state, keccak_ref_round_constants[r]);
    }
}

/* ============================================================================
 * Public: SHA3-512
 *
 * Rate = 72 bytes (576 bits), capacity = 128 bytes (1024 bits), output = 64.
 * Padding rule (FIPS-202 §B.2): append 0x06, zero-pad to rate-1 bytes,
 * then OR last byte with 0x80.
 * ========================================================================== */

void keccak_ref_sha3_512(const uint8_t *input,
                         size_t input_len,
                         uint8_t out[KECCAK_SHA3_512_OUT]) {
    uint64_t state[KECCAK_NUM_LANES] = {0};
    const size_t rate = KECCAK_SHA3_512_RATE;

    /* Absorb full blocks. */
    while (input_len >= rate) {
        for (size_t i = 0; i < rate; i += 8) {
            state[i / 8] ^= load_le64(input + i);
        }
        keccak_ref_f1600(state);
        input += rate;
        input_len -= rate;
    }

    /* Pad and absorb final block. */
    uint8_t buf[KECCAK_SHA3_512_RATE] = {0};
    if (input_len > 0) {
        memcpy(buf, input, input_len);
    }
    buf[input_len] = 0x06;           /* SHA-3 padding terminator */
    buf[rate - 1] |= 0x80;           /* high bit of last block byte */
    for (size_t i = 0; i < rate; i += 8) {
        state[i / 8] ^= load_le64(buf + i);
    }
    keccak_ref_f1600(state);

    /* Squeeze 64 bytes (≤ rate, so one squeeze suffices). */
    for (size_t i = 0; i < KECCAK_SHA3_512_OUT; i += 8) {
        store_le64(out + i, state[i / 8]);
    }
}
