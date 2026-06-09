/**
 * @file keccak_p3_air.c
 * @brief Plonky3-style Keccak-f AIR constraint check (Sub-sprint 3.4r).
 *
 * Port of Plonky3 `keccak-air::air::eval` semantics. Read-for-understanding
 * port per design doc § 9 F19 — no copy-paste from upstream.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_p3_air.h"

/* ============================================================================
 * Field helpers.  Local — these compose field operations into the algebraic
 * primitives the constraints need (bool, xor, xor3, andn).
 * ========================================================================== */

static inline bool fp_is_bool(gold_fp_t x) {
    /* assert x * (1 - x) == 0 → x ∈ {0, 1}. */
    gold_fp_t one_minus = gold_fp_sub(gold_fp_one(), x);
    return gold_fp_is_zero(gold_fp_mul(x, one_minus));
}

/* XOR of two binary cells (assumes inputs are in {0, 1}). */
static inline gold_fp_t fp_xor(gold_fp_t a, gold_fp_t b) {
    /* a + b - 2ab. */
    gold_fp_t sum = gold_fp_add(a, b);
    gold_fp_t ab  = gold_fp_mul(a, b);
    gold_fp_t two_ab = gold_fp_add(ab, ab);
    return gold_fp_sub(sum, two_ab);
}

/* XOR of three binary cells.
 * xor3(a,b,c) = a + b + c - 2(ab + bc + ca) + 4abc. */
static inline gold_fp_t fp_xor3(gold_fp_t a, gold_fp_t b, gold_fp_t c) {
    gold_fp_t ab  = gold_fp_mul(a, b);
    gold_fp_t bc  = gold_fp_mul(b, c);
    gold_fp_t ca  = gold_fp_mul(c, a);
    gold_fp_t abc = gold_fp_mul(ab, c);

    gold_fp_t sum_abc = gold_fp_add(gold_fp_add(a, b), c);
    gold_fp_t sum_pairs = gold_fp_add(gold_fp_add(ab, bc), ca);
    gold_fp_t two_pairs = gold_fp_add(sum_pairs, sum_pairs);
    gold_fp_t four_abc  = gold_fp_add(gold_fp_add(abc, abc),
                                       gold_fp_add(abc, abc));
    gold_fp_t t = gold_fp_sub(sum_abc, two_pairs);
    return gold_fp_add(t, four_abc);
}

/* andn(b, c) = (1 - b) * c, for binary b, c. */
static inline gold_fp_t fp_andn(gold_fp_t b, gold_fp_t c) {
    gold_fp_t one_minus_b = gold_fp_sub(gold_fp_one(), b);
    return gold_fp_mul(one_minus_b, c);
}

/* For a binary lane (16 bits), reconstruct a 16-bit limb:
 * limb = bit_0 * 2^0 + bit_1 * 2^1 + ... + bit_15 * 2^15. */
static gold_fp_t reconstruct_limb_from_bits(const gold_fp_t *bits_16) {
    gold_fp_t acc = gold_fp_zero();
    /* Iterate high-to-low so doubling builds the polynomial cleanly. */
    for (int z = (int)KECCAK_P3_BITS_PER_LIMB - 1; z >= 0; z--) {
        acc = gold_fp_add(acc, acc);            /* double */
        acc = gold_fp_add(acc, bits_16[z]);
    }
    return acc;
}

/* B(x, y, z) = a_prime[b][a][rot_z] where a = (x + 3y) % 5, b = x. */
static inline gold_fp_t kp3_b_bit(const keccak_p3_cols_t *row,
                                  unsigned x, unsigned y, unsigned z) {
    unsigned a = (x + 3u * y) % KECCAK_P3_DIM;
    unsigned b = x;
    unsigned rot = KECCAK_P3_R[a][b];
    /* Inverse rotation by `rot` bits on a 64-bit lane. */
    unsigned rot_z = (z + KECCAK_P3_LANE_BITS - rot) % KECCAK_P3_LANE_BITS;
    return row->a_prime[b][a][rot_z];
}

/* a_prime_prime_prime accessor: (0,0) is the post-ι lane; others equal post-χ. */
static inline gold_fp_t kp3_a_ppp(const keccak_p3_cols_t *row,
                                  unsigned y, unsigned x, unsigned limb) {
    if (y == 0u && x == 0u) {
        return row->a_prime_prime_prime_0_0_limbs[limb];
    }
    return row->a_prime_prime[y][x][limb];
}

/* ============================================================================
 * Failure reporter.
 * ========================================================================== */

static bool kp3_fail(char c, uint32_t row, uint32_t idx,
                     char *out_c, uint32_t *out_r, uint32_t *out_i) {
    if (out_c) *out_c = c;
    if (out_r) *out_r = row;
    if (out_i) *out_i = idx;
    return false;
}

/* ============================================================================
 * Per-row constraint check.
 * ========================================================================== */

static bool check_one_row(const keccak_p3_cols_t *row, uint32_t row_idx,
                          bool is_first_row, bool is_final_step,
                          char *out_c, uint32_t *out_r, uint32_t *out_i) {
    /* 'R' — first-row round flags. */
    if (is_first_row) {
        if (!gold_fp_eq(row->step_flags[0], gold_fp_one())) {
            return kp3_fail('R', row_idx, 0u, out_c, out_r, out_i);
        }
        for (unsigned r = 1; r < KECCAK_P3_NUM_ROUNDS; r++) {
            if (!gold_fp_is_zero(row->step_flags[r])) {
                return kp3_fail('R', row_idx, r, out_c, out_r, out_i);
            }
        }
    }
    /* The flags themselves must be bool (each row). */
    for (unsigned r = 0; r < KECCAK_P3_NUM_ROUNDS; r++) {
        if (!fp_is_bool(row->step_flags[r])) {
            return kp3_fail('R', row_idx, 100u + r, out_c, out_r, out_i);
        }
    }

    /* 'E' — export flag is bool; zero unless final step. */
    if (!fp_is_bool(row->export_flag)) {
        return kp3_fail('E', row_idx, 0u, out_c, out_r, out_i);
    }
    if (!is_final_step && !gold_fp_is_zero(row->export_flag)) {
        return kp3_fail('E', row_idx, 1u, out_c, out_r, out_i);
    }

    /* 'P' — first row: preimage == a. */
    if (is_first_row) {
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
                for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                    if (!gold_fp_eq(row->preimage[y][x][limb],
                                    row->a[y][x][limb])) {
                        uint32_t idx = ((y * KECCAK_P3_DIM + x) *
                                        KECCAK_P3_U64_LIMBS) + limb;
                        return kp3_fail('P', row_idx, idx,
                                        out_c, out_r, out_i);
                    }
                }
            }
        }
    }

    /* 'C' — c[x] bool, c_prime[x][z] = xor3(c[x][z], c[x-1][z], c[(x+1)%5][(z-1)%64]). */
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
            if (!fp_is_bool(row->c[x][z])) {
                return kp3_fail('C', row_idx, x * KECCAK_P3_LANE_BITS + z,
                                out_c, out_r, out_i);
            }
            unsigned xm1 = (x + KECCAK_P3_DIM - 1u) % KECCAK_P3_DIM;
            unsigned xp1 = (x + 1u) % KECCAK_P3_DIM;
            unsigned zm1 = (z + KECCAK_P3_LANE_BITS - 1u) %
                            KECCAK_P3_LANE_BITS;
            gold_fp_t want = fp_xor3(row->c[x][z],
                                     row->c[xm1][z],
                                     row->c[xp1][zm1]);
            if (!gold_fp_eq(row->c_prime[x][z], want)) {
                return kp3_fail('C', row_idx,
                                10000u + x * KECCAK_P3_LANE_BITS + z,
                                out_c, out_r, out_i);
            }
        }
    }

    /* 'A' — a_prime bool, a[y][x] limb reconstruction. */
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
                if (!fp_is_bool(row->a_prime[y][x][z])) {
                    uint32_t idx = ((y * KECCAK_P3_DIM + x) *
                                    KECCAK_P3_LANE_BITS) + z;
                    return kp3_fail('A', row_idx, idx,
                                    out_c, out_r, out_i);
                }
            }
            /* For each 16-bit limb: limb == reconstruct(get_bit(z) for z in window),
             * where get_bit(z) = xor3(a_prime[y][x][z], c[x][z], c_prime[x][z]). */
            gold_fp_t derived_bits[KECCAK_P3_LANE_BITS];
            for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
                derived_bits[z] = fp_xor3(row->a_prime[y][x][z],
                                          row->c[x][z],
                                          row->c_prime[x][z]);
            }
            for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                gold_fp_t want = reconstruct_limb_from_bits(
                    &derived_bits[limb * KECCAK_P3_BITS_PER_LIMB]);
                if (!gold_fp_eq(want, row->a[y][x][limb])) {
                    uint32_t idx = (((y * KECCAK_P3_DIM + x) *
                                     KECCAK_P3_U64_LIMBS) + limb) | 0x80000000u;
                    return kp3_fail('A', row_idx, idx,
                                    out_c, out_r, out_i);
                }
            }
        }
    }

    /* 'p' — parity: for each (x, z), diff * (diff-2) * (diff-4) == 0
     *               where diff = sum_y a_prime[y][x][z] - c_prime[x][z]. */
    gold_fp_t two   = gold_fp_from_u64(2u);
    gold_fp_t four  = gold_fp_from_u64(4u);
    for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
        for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
            gold_fp_t sum = gold_fp_zero();
            for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
                sum = gold_fp_add(sum, row->a_prime[y][x][z]);
            }
            gold_fp_t diff = gold_fp_sub(sum, row->c_prime[x][z]);
            gold_fp_t d_m2 = gold_fp_sub(diff, two);
            gold_fp_t d_m4 = gold_fp_sub(diff, four);
            gold_fp_t prod = gold_fp_mul(gold_fp_mul(diff, d_m2), d_m4);
            if (!gold_fp_is_zero(prod)) {
                return kp3_fail('p', row_idx,
                                x * KECCAK_P3_LANE_BITS + z,
                                out_c, out_r, out_i);
            }
        }
    }

    /* 'X' — χ limb reconstruction for a_prime_prime[y][x]:
     *   limb == reconstruct( xor(B(x,y,z), andn(B(x+1,y,z), B(x+2,y,z))) for z in window). */
    for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
        for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
            gold_fp_t derived_bits[KECCAK_P3_LANE_BITS];
            for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
                gold_fp_t bx   = kp3_b_bit(row, x, y, z);
                gold_fp_t bxp1 = kp3_b_bit(row, (x + 1u) % KECCAK_P3_DIM, y, z);
                gold_fp_t bxp2 = kp3_b_bit(row, (x + 2u) % KECCAK_P3_DIM, y, z);
                gold_fp_t andn = fp_andn(bxp1, bxp2);
                derived_bits[z] = fp_xor(bx, andn);
            }
            for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                gold_fp_t want = reconstruct_limb_from_bits(
                    &derived_bits[limb * KECCAK_P3_BITS_PER_LIMB]);
                if (!gold_fp_eq(want, row->a_prime_prime[y][x][limb])) {
                    uint32_t idx = ((y * KECCAK_P3_DIM + x) *
                                    KECCAK_P3_U64_LIMBS) + limb;
                    return kp3_fail('X', row_idx, idx, out_c, out_r, out_i);
                }
            }
        }
    }

    /* 'B' — a_prime_prime_0_0_bits are bool and reconstruct a_prime_prime[0][0]. */
    for (unsigned z = 0; z < KECCAK_P3_LANE_BITS; z++) {
        if (!fp_is_bool(row->a_prime_prime_0_0_bits[z])) {
            return kp3_fail('B', row_idx, z, out_c, out_r, out_i);
        }
    }
    for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
        gold_fp_t want = reconstruct_limb_from_bits(
            &row->a_prime_prime_0_0_bits[limb * KECCAK_P3_BITS_PER_LIMB]);
        if (!gold_fp_eq(want, row->a_prime_prime[0][0][limb])) {
            return kp3_fail('B', row_idx, 10000u + limb,
                            out_c, out_r, out_i);
        }
    }

    /* 'I' — ι constraint: a_prime_prime_prime_0_0_limbs[limb] ==
     *     reconstruct( xor( a_prime_prime_0_0_bits[z], rc_bit_z ) ),
     * where rc_bit_z = sum_r step_flags[r] * RC_BITS[r][z]. */
    for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
        gold_fp_t derived[KECCAK_P3_BITS_PER_LIMB];
        for (unsigned i = 0; i < KECCAK_P3_BITS_PER_LIMB; i++) {
            unsigned z = limb * KECCAK_P3_BITS_PER_LIMB + i;
            gold_fp_t rc_bit = gold_fp_zero();
            for (unsigned r = 0; r < KECCAK_P3_NUM_ROUNDS; r++) {
                uint8_t bit = keccak_p3_rc_bit(r, z);
                if (bit) {
                    rc_bit = gold_fp_add(rc_bit, row->step_flags[r]);
                }
            }
            derived[i] = fp_xor(row->a_prime_prime_0_0_bits[z], rc_bit);
        }
        gold_fp_t want = reconstruct_limb_from_bits(derived);
        if (!gold_fp_eq(want, row->a_prime_prime_prime_0_0_limbs[limb])) {
            return kp3_fail('I', row_idx, limb, out_c, out_r, out_i);
        }
    }

    return true;
}

/* ============================================================================
 * Transition constraints (between row r and row r+1).
 * ========================================================================== */

static bool check_transition(const keccak_p3_cols_t *local,
                             const keccak_p3_cols_t *next,
                             uint32_t row_idx, bool not_final_step,
                             char *out_c, uint32_t *out_r, uint32_t *out_i) {
    /* 'R' — step_flags rotate forward: local.flags[i] == next.flags[(i+1) % 24]. */
    for (unsigned i = 0; i < KECCAK_P3_NUM_ROUNDS; i++) {
        unsigned ni = (i + 1u) % KECCAK_P3_NUM_ROUNDS;
        if (!gold_fp_eq(local->step_flags[i], next->step_flags[ni])) {
            return kp3_fail('R', row_idx, 200u + i, out_c, out_r, out_i);
        }
    }

    /* 'P' — preimage persists when not final step. */
    if (not_final_step) {
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
                for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                    if (!gold_fp_eq(local->preimage[y][x][limb],
                                    next->preimage[y][x][limb])) {
                        uint32_t idx = ((y * KECCAK_P3_DIM + x) *
                                        KECCAK_P3_U64_LIMBS) + limb;
                        return kp3_fail('P', row_idx,
                                        10000u + idx,
                                        out_c, out_r, out_i);
                    }
                }
            }
        }
    }

    /* 'T' — a''' of local == a of next, when not final step. */
    if (not_final_step) {
        for (unsigned y = 0; y < KECCAK_P3_DIM; y++) {
            for (unsigned x = 0; x < KECCAK_P3_DIM; x++) {
                for (unsigned limb = 0; limb < KECCAK_P3_U64_LIMBS; limb++) {
                    gold_fp_t lhs = kp3_a_ppp(local, y, x, limb);
                    gold_fp_t rhs = next->a[y][x][limb];
                    if (!gold_fp_eq(lhs, rhs)) {
                        uint32_t idx = ((y * KECCAK_P3_DIM + x) *
                                        KECCAK_P3_U64_LIMBS) + limb;
                        return kp3_fail('T', row_idx, idx,
                                        out_c, out_r, out_i);
                    }
                }
            }
        }
    }

    return true;
}

/* ============================================================================
 * Public API.
 * ========================================================================== */

bool keccak_p3_check_constraints(const keccak_p3_cols_t *rows,
                                 uint32_t num_rows,
                                 char *out_first_failing_constraint,
                                 uint32_t *out_first_failing_row,
                                 uint32_t *out_first_failing_index) {
    if (out_first_failing_constraint) *out_first_failing_constraint = 0;
    if (out_first_failing_row)        *out_first_failing_row = 0;
    if (out_first_failing_index)      *out_first_failing_index = 0;

    if (!rows || num_rows == 0u) {
        return kp3_fail('?', 0u, 0u,
                        out_first_failing_constraint,
                        out_first_failing_row,
                        out_first_failing_index);
    }

    for (uint32_t i = 0; i < num_rows; i++) {
        bool is_first = (i % KECCAK_P3_NUM_ROUNDS == 0u);
        bool is_final = (i % KECCAK_P3_NUM_ROUNDS ==
                         KECCAK_P3_NUM_ROUNDS - 1u);

        if (!check_one_row(&rows[i], i, is_first, is_final,
                           out_first_failing_constraint,
                           out_first_failing_row,
                           out_first_failing_index)) {
            return false;
        }

        if (i + 1u < num_rows) {
            bool not_final_step = !is_final;
            if (!check_transition(&rows[i], &rows[i + 1u], i,
                                  not_final_step,
                                  out_first_failing_constraint,
                                  out_first_failing_row,
                                  out_first_failing_index)) {
                return false;
            }
        }
    }

    return true;
}
