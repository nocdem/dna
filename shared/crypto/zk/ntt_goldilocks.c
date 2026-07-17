/**
 * @file ntt_goldilocks.c
 * @brief Number-Theoretic Transform over Goldilocks — COMPLETE Cooley-Tukey
 *        Radix2Dit; test_ntt_goldilocks_oracle byte-matches Plonky3 (64 cases,
 *        0 circular). ("Phase A stub" was a stale label.)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ntt_goldilocks.h"

uint32_t ntt_bit_reverse_u32(uint32_t x, unsigned log_n) {
    /* Mirror the low `log_n` bits, high bits dropped. */
    uint32_t r = 0;
    for (unsigned i = 0; i < log_n; i++) {
        r = (r << 1) | (x & 1u);
        x >>= 1;
    }
    return r;
}

void ntt_bit_reverse_permute(gold_fp_t *vals, unsigned log_n) {
    if (log_n == 0) return;
    uint32_t n = 1u << log_n;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t j = ntt_bit_reverse_u32(i, log_n);
        if (i < j) {
            gold_fp_t t = vals[i]; vals[i] = vals[j]; vals[j] = t;
        }
    }
}

void ntt_bit_reverse_permute_ext(gold_fp2_t *vals, unsigned log_n) {
    if (log_n == 0) return;
    uint32_t n = 1u << log_n;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t j = ntt_bit_reverse_u32(i, log_n);
        if (i < j) {
            gold_fp2_t t = vals[i]; vals[i] = vals[j]; vals[j] = t;
        }
    }
}

void ntt_goldilocks_forward(gold_fp_t *vals, unsigned log_n) {
    if (log_n == 0u || log_n > NTT_GOLDILOCKS_MAX_LOG_N) return;

    ntt_bit_reverse_permute(vals, log_n);

    uint32_t n = 1u << log_n;
    for (unsigned s = 1; s <= log_n; s++) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        gold_fp_t omega_m = gold_fp_two_adic_generator(s);
        for (uint32_t k = 0; k < n; k += m) {
            gold_fp_t w = gold_fp_one();
            for (uint32_t j = 0; j < half; j++) {
                gold_fp_t lo = vals[k + j];
                gold_fp_t hi = vals[k + j + half];
                gold_fp_t t  = gold_fp_mul(w, hi);
                vals[k + j]        = gold_fp_add(lo, t);
                vals[k + j + half] = gold_fp_sub(lo, t);
                w = gold_fp_mul(w, omega_m);
            }
        }
    }
}

void ntt_goldilocks_inverse(gold_fp_t *vals, unsigned log_n) {
    if (log_n == 0u || log_n > NTT_GOLDILOCKS_MAX_LOG_N) return;

    ntt_bit_reverse_permute(vals, log_n);

    uint32_t n = 1u << log_n;
    for (unsigned s = 1; s <= log_n; s++) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        gold_fp_t omega_m     = gold_fp_two_adic_generator(s);
        gold_fp_t omega_m_inv = gold_fp_inv(omega_m);
        for (uint32_t k = 0; k < n; k += m) {
            gold_fp_t w = gold_fp_one();
            for (uint32_t j = 0; j < half; j++) {
                gold_fp_t lo = vals[k + j];
                gold_fp_t hi = vals[k + j + half];
                gold_fp_t t  = gold_fp_mul(w, hi);
                vals[k + j]        = gold_fp_add(lo, t);
                vals[k + j + half] = gold_fp_sub(lo, t);
                w = gold_fp_mul(w, omega_m_inv);
            }
        }
    }

    /* Scale by 1/N. */
    gold_fp_t n_inv = gold_fp_inv(gold_fp_from_u64((uint64_t)n));
    for (uint32_t i = 0; i < n; i++) {
        vals[i] = gold_fp_mul(vals[i], n_inv);
    }
}

void ntt_goldilocks_ext_forward(gold_fp2_t *vals, unsigned log_n) {
    if (log_n == 0u || log_n > NTT_GOLDILOCKS_MAX_LOG_N) return;

    ntt_bit_reverse_permute_ext(vals, log_n);

    uint32_t n = 1u << log_n;
    for (unsigned s = 1; s <= log_n; s++) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        /* Twiddles live in base field (lifted via gold_fp2_from_base). */
        gold_fp_t  omega_m_base = gold_fp_two_adic_generator(s);
        gold_fp2_t omega_m      = gold_fp2_from_base(omega_m_base);
        for (uint32_t k = 0; k < n; k += m) {
            gold_fp2_t w = gold_fp2_one();
            for (uint32_t j = 0; j < half; j++) {
                gold_fp2_t lo = vals[k + j];
                gold_fp2_t hi = vals[k + j + half];
                gold_fp2_t t  = gold_fp2_mul(w, hi);
                vals[k + j]        = gold_fp2_add(lo, t);
                vals[k + j + half] = gold_fp2_sub(lo, t);
                w = gold_fp2_mul(w, omega_m);
            }
        }
    }
}

void ntt_goldilocks_ext_inverse(gold_fp2_t *vals, unsigned log_n) {
    if (log_n == 0u || log_n > NTT_GOLDILOCKS_MAX_LOG_N) return;

    ntt_bit_reverse_permute_ext(vals, log_n);

    uint32_t n = 1u << log_n;
    for (unsigned s = 1; s <= log_n; s++) {
        uint32_t m    = 1u << s;
        uint32_t half = m >> 1;
        gold_fp_t  omega_m_base     = gold_fp_two_adic_generator(s);
        gold_fp_t  omega_m_inv_base = gold_fp_inv(omega_m_base);
        gold_fp2_t omega_m_inv      = gold_fp2_from_base(omega_m_inv_base);
        for (uint32_t k = 0; k < n; k += m) {
            gold_fp2_t w = gold_fp2_one();
            for (uint32_t j = 0; j < half; j++) {
                gold_fp2_t lo = vals[k + j];
                gold_fp2_t hi = vals[k + j + half];
                gold_fp2_t t  = gold_fp2_mul(w, hi);
                vals[k + j]        = gold_fp2_add(lo, t);
                vals[k + j + half] = gold_fp2_sub(lo, t);
                w = gold_fp2_mul(w, omega_m_inv);
            }
        }
    }

    /* Scale by 1/N (base-field scalar lifted into extension). */
    gold_fp_t  n_inv_base = gold_fp_inv(gold_fp_from_u64((uint64_t)n));
    gold_fp2_t n_inv      = gold_fp2_from_base(n_inv_base);
    for (uint32_t i = 0; i < n; i++) {
        vals[i] = gold_fp2_mul(vals[i], n_inv);
    }
}
