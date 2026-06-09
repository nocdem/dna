/**
 * @file keccak_p3_trace.c
 * @brief Plonky3-style Keccak-f AIR trace generation (Sub-sprint 3.4r).
 *
 * Port of Plonky3 keccak-air `generate_trace_rows_for_perm` semantics.
 * Read-for-understanding port (per design doc § 9 F19) — no copy-paste.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_p3_trace.h"

#include <string.h>

/* ============================================================================
 * Internal scratch (raw u64 state, indexed as state[x][y]).
 * ========================================================================== */

typedef uint64_t kp3_state_t[KECCAK_P3_DIM][KECCAK_P3_DIM];

/* 64-bit left-rotation (no UB on n=0/64). */
static inline uint64_t rotl64(uint64_t v, unsigned n) {
    n &= 63u;
    if (n == 0) return v;
    return (v << n) | (v >> (64u - n));
}

/* Read a_prime_prime_prime(y, x, limb) — Plonky3's accessor function.
 * For (y,x) == (0,0) returns the ι-output limbs; otherwise returns the
 * χ-output (post_chi) limbs, because ι only touches lane (0,0). */
static inline gold_fp_t kp3_a_ppp(const keccak_p3_cols_t *row,
                                   unsigned y, unsigned x, unsigned limb) {
    if (y == 0u && x == 0u) {
        return row->a_prime_prime_prime_0_0_limbs[limb];
    }
    return row->a_prime_prime[y][x][limb];
}

/* ============================================================================
 * Per-round row generation.
 * ========================================================================== */

static void generate_row_for_round(keccak_p3_cols_t *row,
                                   unsigned round,
                                   kp3_state_t state) {
    /* step_flags one-hot. */
    for (unsigned r = 0; r < KECCAK_P3_NUM_ROUNDS; r++) {
        row->step_flags[r] = (r == round) ? gold_fp_one() : gold_fp_zero();
    }

    /* C[x] = XOR over y of state[x][y]. */
    uint64_t state_c[KECCAK_P3_DIM];
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        uint64_t acc = 0;
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) acc ^= state[x][y];
        state_c[x] = acc;
        keccak_p3_lane_to_bits(acc, row->c[x]);
    }

    /* C'[x] = C[x] XOR C[x-1] XOR ROT(C[x+1], 1). */
    uint64_t state_c_prime[KECCAK_P3_DIM];
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        uint64_t cm1 = state_c[(x + KECCAK_P3_DIM - 1u) % KECCAK_P3_DIM];
        uint64_t cp1 = state_c[(x + 1u) % KECCAK_P3_DIM];
        state_c_prime[x] = state_c[x] ^ cm1 ^ rotl64(cp1, 1u);
        keccak_p3_lane_to_bits(state_c_prime[x], row->c_prime[x]);
    }

    /* θ: state[x][y] ^= C[x] XOR C'[x]  (algebraically equivalent to the
     * canonical D[x] = C[x-1] XOR ROT(C[x+1], 1) substitution). */
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        uint64_t mix = state_c[x] ^ state_c_prime[x];
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            state[x][y] ^= mix;
            keccak_p3_lane_to_bits(state[x][y], row->a_prime[y][x]);
        }
    }

    /* ρ + π: state'[i][j] = ROT(state[(i + 3j) % 5][i], R[(i+3j)%5][i]). */
    kp3_state_t after_rho_pi;
    for (unsigned i = 0; i < KECCAK_P3_DIM; i++) {
        for (unsigned j = 0; j < KECCAK_P3_DIM; j++) {
            unsigned new_i = (i + 3u * j) % KECCAK_P3_DIM;
            unsigned new_j = i;
            after_rho_pi[i][j] = rotl64(state[new_i][new_j],
                                        KECCAK_P3_R[new_i][new_j]);
        }
    }
    memcpy(state, after_rho_pi, sizeof(after_rho_pi));

    /* χ: state[x][y] ^= ((NOT state[(x+1)%5][y]) AND state[(x+2)%5][y]). */
    kp3_state_t after_chi;
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            uint64_t a = state[x][y];
            uint64_t b = state[(x + 1u) % KECCAK_P3_DIM][y];
            uint64_t c = state[(x + 2u) % KECCAK_P3_DIM][y];
            after_chi[x][y] = a ^ ((~b) & c);
        }
    }
    memcpy(state, after_chi, sizeof(after_chi));

    /* Store a_prime_prime[y][x] in limbs. */
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            keccak_p3_lane_to_limbs(state[x][y], row->a_prime_prime[y][x]);
        }
    }

    /* Bits of a_prime_prime[0][0] for ι. */
    keccak_p3_lane_to_bits(state[0][0], row->a_prime_prime_0_0_bits);

    /* ι: state[0][0] ^= RC[round].  Then store result limbs. */
    state[0][0] ^= KECCAK_P3_RC[round];
    keccak_p3_lane_to_limbs(state[0][0], row->a_prime_prime_prime_0_0_limbs);

    /* export_flag is set externally on the final row by the caller's
     * outer loop; we leave it at the calloc'd zero default here. */
    (void)0;
}

/* ============================================================================
 * Public API.
 * ========================================================================== */

void keccak_p3_generate_trace_one_perm(
    keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    const uint64_t input[25]) {
    memset(rows, 0, KECCAK_P3_NUM_ROUNDS * sizeof(*rows));

    /* Build mutable state[x][y] = input[x + 5*y]. */
    kp3_state_t state;
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            state[x][y] = input[x + KECCAK_P3_DIM * y];
        }
    }

    /* Build initial_state[y][x] limbs from current state — used as preimage
     * across all 24 rows AND as round-0 input `a`. */
    gold_fp_t initial[KECCAK_P3_DIM][KECCAK_P3_DIM][KECCAK_P3_U64_LIMBS];
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            keccak_p3_lane_to_limbs(state[x][y], initial[y][x]);
        }
    }

    /* Round 0: preimage = a = initial. */
    memcpy(rows[0].preimage, initial, sizeof(initial));
    memcpy(rows[0].a,        initial, sizeof(initial));
    generate_row_for_round(&rows[0], 0u, state);

    /* Round r ≥ 1: preimage persists; a = previous round's a''' output. */
    for (unsigned round = 1u; round < KECCAK_P3_NUM_ROUNDS; round++) {
        memcpy(rows[round].preimage, initial, sizeof(initial));
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
                for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                    rows[round].a[y][x][limb] =
                        kp3_a_ppp(&rows[round - 1u], y, x, limb);
                }
            }
        }
        generate_row_for_round(&rows[round], round, state);
    }

    /* Mark the final row's export flag. */
    rows[KECCAK_P3_NUM_ROUNDS - 1u].export_flag = gold_fp_one();
}

void keccak_p3_extract_output(
    const keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    uint64_t out[25]) {
    const keccak_p3_cols_t *last = &rows[KECCAK_P3_NUM_ROUNDS - 1u];
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            gold_fp_t limbs[KECCAK_P3_U64_LIMBS];
            for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                limbs[limb] = kp3_a_ppp(last, y, x, limb);
            }
            out[x + KECCAK_P3_DIM * y] = keccak_p3_limbs_to_lane(limbs);
        }
    }
}

void keccak_p3_extract_input(
    const keccak_p3_cols_t rows[KECCAK_P3_NUM_ROUNDS],
    uint64_t out[25]) {
    const keccak_p3_cols_t *first = &rows[0];
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            out[x + KECCAK_P3_DIM * y] =
                keccak_p3_limbs_to_lane(first->preimage[y][x]);
        }
    }
}
