/**
 * @file zk_field_helpers.c
 * @brief Phase A helper implementations — byte-equivalent transliterations.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec
 *
 * Every body cites its Plonky3 source location. No design choices, no
 * DNAC variants. If a line is not derivable from Plonky3 source, it is
 * a bug.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "zk_field_helpers.h"

#include <assert.h>
#include <stdint.h>

/* ============================================================================
 * bits_u64
 * ============================================================================
 * Plonky3 field/src/exponentiation.rs:3-5
 *   (64 - n.leading_zeros()) as usize
 *
 * Rust u64::leading_zeros(0) = 64 → bits_u64(0) = 0.
 * C __builtin_clzll(0) is undefined → special case n == 0.
 */
size_t bits_u64(uint64_t n) {
    if (n == 0ULL) {
        return 0;
    }
    return (size_t)(64 - __builtin_clzll((unsigned long long)n));
}

/* ============================================================================
 * log2_strict_usize
 * ============================================================================
 * Plonky3 util/src/lib.rs:78-87
 *   let res = n.trailing_zeros();
 *   assert!(n.wrapping_shr(res) == 1, "Not a power of two");
 *   res as usize
 *
 * Plonky3 panics if n == 0 (n.trailing_zeros() == 64, wrapping_shr(64) wraps
 * to 0, assert fails). We mirror with C assert on n == 0.
 */
size_t log2_strict_usize(size_t n) {
    assert(n != 0 && "log2_strict_usize: n must be nonzero");
    unsigned res = (unsigned)__builtin_ctzll((unsigned long long)n);
    /* Confirm n is a power of two: n >> res must equal 1. */
    assert(((unsigned long long)n >> res) == 1ULL && "log2_strict_usize: Not a power of two");
    return (size_t)res;
}

/* ============================================================================
 * reverse_bits_len_u64
 * ============================================================================
 * Plonky3 util/src/lib.rs:203-211
 *   x.reverse_bits().overflowing_shr(usize::BITS - bit_len as u32).0
 *
 * Plonky3 u64::reverse_bits() reverses the order of all 64 bits.
 * Plonky3 overflowing_shr(shift).0 == self.wrapping_shr(shift % 64), i.e. the
 * shift amount is masked to the low 6 bits. For bit_len == 0, shift == 64, mask
 * → 0; for bit_len in [1, 64], shift in [0, 63].
 */
static inline uint64_t reverse_bits_u64(uint64_t x) {
    /* Classic 5-stage butterfly bit-reverse. Equivalent in value to
       Rust's u64::reverse_bits() intrinsic. */
    x = ((x >> 1)  & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
    x = ((x >> 2)  & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
    x = ((x >> 4)  & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
    x = ((x >> 8)  & 0x00FF00FF00FF00FFULL) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x >> 16) & 0x0000FFFF0000FFFFULL) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    x = (x >> 32) | (x << 32);
    return x;
}

uint64_t reverse_bits_len_u64(uint64_t x, unsigned bit_len) {
    uint64_t r = reverse_bits_u64(x);
    /* Plonky3 overflowing_shr masks shift amount to low log2(BITS) bits. */
    unsigned shift = (64u - bit_len) & 63u;
    return r >> shift;
}

/* ============================================================================
 * gold_fp_halve
 * ============================================================================
 * Plonky3 goldilocks/src/goldilocks.rs:235-244
 *   const HALF_P_PLUS_1: u64 = (P + 1) >> 1; // 0x7FFFFFFF80000001
 *   let lo_bit = self.value & 1;
 *   let half = self.value >> 1;
 *   let mask = 0u64.wrapping_sub(lo_bit);
 *   Self::new(half.wrapping_add(mask & HALF_P_PLUS_1))
 *
 * Canonical input proof: for x.v in [0, P), the formula produces a result in
 * [0, P). Case x.v even: result = half = x.v / 2 < P/2 < P. Case x.v odd:
 * half ≤ (P-1)/2 and result = half + (P+1)/2; since x.v ≤ P-2 when odd (P odd
 * so P-1 even), half ≤ (P-3)/2 and result ≤ (P-3)/2 + (P+1)/2 = P-1 < P.
 */
gold_fp_t gold_fp_halve(gold_fp_t x) {
    /* (P + 1) >> 1 where P = 0xFFFFFFFF00000001. */
    static const uint64_t HALF_P_PLUS_1 = 0x7FFFFFFF80000001ULL;
    uint64_t lo_bit = x.v & 1ULL;
    uint64_t half   = x.v >> 1;
    uint64_t mask   = 0ULL - lo_bit;            /* wrapping_sub(0, lo_bit) */
    gold_fp_t out;
    out.v = half + (mask & HALF_P_PLUS_1);
    return out;
}

/* ============================================================================
 * gold_fp2_halve
 * ============================================================================
 * Plonky3 field/src/extension/binomial_extension.rs:254-256
 *   fn halve(&self) -> Self {
 *       Self::new(array::from_fn(|i| self.value[i].halve()))
 *   }
 *
 * Goldilocks² = BinomialExtensionField<Goldilocks, 2>: per-component fp halve.
 */
gold_fp2_t gold_fp2_halve(gold_fp2_t x) {
    gold_fp2_t out;
    out.a = gold_fp_halve(x.a);
    out.b = gold_fp_halve(x.b);
    return out;
}

/* ============================================================================
 * gold_fp_from_usize
 * ============================================================================
 * Plonky3 reference chain (for F = Goldilocks):
 *   1. integers.rs:23-39 (from_integer_types!): from_prime_subfield(PrimeSubfield::from_int(int))
 *   2. goldilocks.rs:217: PrimeSubfield = Self
 *   3. integers.rs:417-468 (impl_u_i_size!(usize, u8, u16, u32, u64, u128)):
 *      match size_of::<usize>() { 4 => from_int(n as u32), 8 => from_int(n as u64), ... }
 *   4. goldilocks.rs:445: from_int(int: u64) -> Self { Self::new(int) }
 *   5. goldilocks.rs:225-227: from_prime_subfield(f) = f
 *
 * 32-bit usize routes through QuotientMap<u32> → Self::from_canonical_unchecked(int as u64)
 * via quotient_map_small_int!(Goldilocks, u64, [u8, u16, u32]) at goldilocks.rs:421
 * which expands to `Self::from_canonical_unchecked(int as u64)` (integers.rs:97-99).
 *
 * Both 32-bit and 64-bit converge to `Goldilocks::new((uint64_t)n)`.
 * gold_fp_from_u64 canonicalizes the input to [0, p) per field_goldilocks.h invariant.
 */
gold_fp_t gold_fp_from_usize(size_t n) {
    return gold_fp_from_u64((uint64_t)n);
}

/* ============================================================================
 * gold_fp_shifted_powers / gold_fp2_shifted_powers
 * ============================================================================
 * Plonky3 reference chain:
 *   field.rs:305-310  shifted_powers(start) -> Powers { base, current: start }
 *   field.rs:1209-1217 Iterator::next: result = current; current = current * base
 *   field.rs:1246-1248 collect_n(n) = take(n).collect()
 *
 * Scalar loop is byte-equivalent to Plonky3's `BoundedPowers::collect` small-N
 * fallback (field.rs:1267-1269), which Plonky3 itself uses for N < 16.
 */
void gold_fp_shifted_powers(gold_fp_t start, gold_fp_t g, gold_fp_t *out, size_t n) {
    gold_fp_t cur = start;
    for (size_t i = 0; i < n; i++) {
        out[i] = cur;
        cur = gold_fp_mul(cur, g);
    }
}

void gold_fp2_shifted_powers(gold_fp2_t start, gold_fp2_t g, gold_fp2_t *out, size_t n) {
    gold_fp2_t cur = start;
    for (size_t i = 0; i < n; i++) {
        out[i] = cur;
        cur = gold_fp2_mul(cur, g);
    }
}

/* ============================================================================
 * gold_fp_batch_inv_general / gold_fp2_batch_inv_general
 * ============================================================================
 * Plonky3 field/src/batch_inverse.rs:81-104
 *   if n == 0 { return; }
 *   result[0] = ONE;
 *   for i in 1..n { result[i] = result[i-1] * x[i-1]; }
 *   product = result[n-1] * x[n-1];
 *   inv = product.inverse();
 *   for i in (0..n).rev() {
 *       result[i] *= inv;
 *       inv *= x[i];
 *   }
 *
 * Zero element behavior (mirrored from Plonky3):
 *   If any x[i] == 0, product == 0, gold_fp_inv(0) is undefined (per
 *   field_goldilocks.h:108) — same as Rust's `inverse()` panicking on zero.
 *   Caller MUST ensure all inputs are nonzero.
 */
void gold_fp_batch_inv_general(const gold_fp_t *x, gold_fp_t *result, size_t n) {
    if (n == 0) {
        return;
    }

    result[0] = gold_fp_one();
    for (size_t i = 1; i < n; i++) {
        result[i] = gold_fp_mul(result[i - 1], x[i - 1]);
    }

    gold_fp_t product = gold_fp_mul(result[n - 1], x[n - 1]);
    gold_fp_t inv = gold_fp_inv(product);

    /* Plonky3: for i in (0..n).rev() — i runs n-1, n-2, ..., 0. */
    for (size_t i = n; i-- > 0; ) {
        result[i] = gold_fp_mul(result[i], inv);
        inv = gold_fp_mul(inv, x[i]);
    }
}

void gold_fp2_batch_inv_general(const gold_fp2_t *x, gold_fp2_t *result, size_t n) {
    if (n == 0) {
        return;
    }

    result[0] = gold_fp2_one();
    for (size_t i = 1; i < n; i++) {
        result[i] = gold_fp2_mul(result[i - 1], x[i - 1]);
    }

    gold_fp2_t product = gold_fp2_mul(result[n - 1], x[n - 1]);
    gold_fp2_t inv = gold_fp2_inv(product);

    for (size_t i = n; i-- > 0; ) {
        result[i] = gold_fp2_mul(result[i], inv);
        inv = gold_fp2_mul(inv, x[i]);
    }
}

/* ============================================================================
 * reverse_slice_index_bits_fp / _fp2
 * ============================================================================
 * Plonky3 util/src/lib.rs:334-346 (aarch64-style trivial loop)
 *   let mut src = 0;
 *   while src < vals.len() {
 *       let dst = src.reverse_bits().wrapping_shr(usize::BITS - lb_n as u32);
 *       if src < dst { vals.swap(src, dst); }
 *       src += 1;
 *   }
 *
 * Output-equivalent to the non-aarch64 small path (lines 302-331, lookup table
 * via BIT_REVERSE_6BIT) and the large-array path (lines 274-291, transpose +
 * chunked bit-reverse) — all three permutations match byte-for-byte; they
 * differ only in cache locality for large arrays.
 *
 * The dispatcher at util/src/lib.rs:236-292 calls log2_strict_usize(n) and
 * passes lb_n into the small-path function. This C port collapses dispatch +
 * small-path into one function.
 *
 * Oracle coverage (status): this is now consumed by fri_fold.c AND stark_prover.c,
 * BOTH of which are byte-matched against real Plonky3 vectors
 * (test_fri_fold_row_oracle.c / test_fri_fold_matrix_oracle.c;
 * test_prover_prove.c) — a wrong permutation here would break those byte-matches.
 * So this port is TRANSITIVELY oracle-gated. The direct KAT in
 * test_zk_field_helpers.c additionally checks the defining property
 * (vals[i] == bit_reverse(i) for vals = [0,1,...,n-1]). (No standalone
 * dump-reverse-slice oracle vector — the transitive fri_fold/prover gate is
 * stronger, since it exercises the permutation inside a full real proof.)
 */
void reverse_slice_index_bits_fp(gold_fp_t *vals, size_t n) {
    if (n == 0) {
        return;
    }
    size_t lb_n = log2_strict_usize(n);
    for (size_t src = 0; src < n; src++) {
        /* Plonky3 line 339: src.reverse_bits().wrapping_shr(64 - lb_n).
           Identical to reverse_bits_len_u64(src, lb_n). */
        size_t dst = (size_t)reverse_bits_len_u64((uint64_t)src, (unsigned)lb_n);
        if (src < dst) {
            gold_fp_t tmp = vals[src];
            vals[src] = vals[dst];
            vals[dst] = tmp;
        }
    }
}

void reverse_slice_index_bits_fp2(gold_fp2_t *vals, size_t n) {
    if (n == 0) {
        return;
    }
    size_t lb_n = log2_strict_usize(n);
    for (size_t src = 0; src < n; src++) {
        size_t dst = (size_t)reverse_bits_len_u64((uint64_t)src, (unsigned)lb_n);
        if (src < dst) {
            gold_fp2_t tmp = vals[src];
            vals[src] = vals[dst];
            vals[dst] = tmp;
        }
    }
}
