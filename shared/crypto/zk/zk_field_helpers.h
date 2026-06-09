/**
 * @file zk_field_helpers.h
 * @brief Plonky3 helper primitives for fri_fold port.
 *
 * Every function in this header is a byte-equivalent C transliteration of a
 * specific Plonky3 source location (commit 82cfad73cd734d37a0d51953094f970c531817ec).
 *
 * Phase A scope: scalar helpers with no transitive Plonky3 dependencies beyond
 * std intrinsics. Phase B (shifted_powers, batch_inv, reverse_slice_index_bits)
 * builds on these.
 *
 * No design choices. No DNAC variants. If a body cannot be traced to a Plonky3
 * source line, it does not belong here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FIELD_HELPERS_H
#define DNAC_ZK_FIELD_HELPERS_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Phase A — scalar bit / count helpers
 * ========================================================================== */

/**
 * Bit length of n: smallest b such that n < 2^b.
 *
 * Plonky3 reference: field/src/exponentiation.rs:3-5
 *   pub(crate) const fn bits_u64(n: u64) -> usize {
 *       (64 - n.leading_zeros()) as usize
 *   }
 *
 * Semantics: bits_u64(0) == 0; bits_u64(1) == 1; bits_u64(2^k) == k+1.
 */
size_t bits_u64(uint64_t n);

/**
 * log2 of a power of two; asserts n is a power of two.
 *
 * Plonky3 reference: util/src/lib.rs:78-87
 *   pub const fn log2_strict_usize(n: usize) -> usize {
 *       let res = n.trailing_zeros();
 *       assert!(n.wrapping_shr(res) == 1, "Not a power of two");
 *       ...
 *       res as usize
 *   }
 *
 * Aborts if n == 0 or n is not a power of two.
 */
size_t log2_strict_usize(size_t n);

/**
 * Reverse the bottom bit_len bits of x.
 *
 * Plonky3 reference: util/src/lib.rs:203-211
 *   pub const fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
 *       x.reverse_bits()
 *           .overflowing_shr(usize::BITS - bit_len as u32)
 *           .0
 *   }
 *
 * For bit_len == 0 and x == 0, returns 0 (Plonky3 documented case).
 * For bit_len > 0, shift = (64 - bit_len) is in [0, 63], normal right-shift.
 */
uint64_t reverse_bits_len_u64(uint64_t x, unsigned bit_len);

/* ============================================================================
 * Phase A — field halve
 * ========================================================================== */

/**
 * Branchless halve for Goldilocks: returns x / 2 mod p.
 *
 * Plonky3 reference: goldilocks/src/goldilocks.rs:235-244
 *   fn halve(&self) -> Self {
 *       const HALF_P_PLUS_1: u64 = (P + 1) >> 1; // 0x7FFFFFFF80000001
 *       let lo_bit = self.value & 1;
 *       let half = self.value >> 1;
 *       let mask = 0u64.wrapping_sub(lo_bit);
 *       Self::new(half.wrapping_add(mask & HALF_P_PLUS_1))
 *   }
 *
 * Input must be canonical in [0, p) (per field_goldilocks.h invariant).
 * Output is canonical in [0, p).
 */
gold_fp_t gold_fp_halve(gold_fp_t x);

/**
 * Per-component halve for Goldilocks² (BinomialExtensionField<Goldilocks, 2>).
 *
 * Plonky3 reference: field/src/extension/binomial_extension.rs:254-256
 *   fn halve(&self) -> Self {
 *       Self::new(array::from_fn(|i| self.value[i].halve()))
 *   }
 */
gold_fp2_t gold_fp2_halve(gold_fp2_t x);

/* ============================================================================
 * Phase A — integer-to-field conversion
 * ========================================================================== */

/**
 * Convert a usize into a Goldilocks field element.
 *
 * Plonky3 reference chain (for F = Goldilocks):
 *   1. integers.rs:23-39 (from_integer_types! macro):
 *        from_usize(int) = from_prime_subfield(Self::PrimeSubfield::from_int(int))
 *   2. goldilocks.rs:217: type PrimeSubfield = Self;
 *   3. integers.rs:417-468 (impl_u_i_size!(usize, u8, u16, u32, u64, u128)):
 *        match size_of::<usize>() { 4 => from_int(n as u32), 8 => from_int(n as u64), ... }
 *   4. goldilocks.rs:439-447 (impl QuotientMap<u64>):
 *        from_int(int: u64) -> Self { Self::new(int) }
 *   5. goldilocks.rs:225-227: from_prime_subfield(f) -> Self { f }   (identity)
 *
 * Net result on 32-bit or 64-bit platforms:
 *   gold_fp_from_usize(n) == gold_fp_from_u64((uint64_t)n)
 */
gold_fp_t gold_fp_from_usize(size_t n);

/* ============================================================================
 * Phase B — shifted powers + batch inverse + bit-reverse permutation
 * ========================================================================== */

/**
 * Fill out[0..n] with shifted powers of g starting from start:
 *   out[0] = start
 *   out[i] = start * g^i  (for i = 1..n-1)
 *
 * Plonky3 reference chain:
 *   - field/src/field.rs:305-310  shifted_powers(start) constructs Powers { base: g, current: start }
 *   - field/src/field.rs:1209-1217 Iterator::next: yields current, then current *= base
 *   - field/src/field.rs:1246-1248 collect_n(n) = take(n).collect()
 *
 * Sequential scalar implementation. The Plonky3 `BoundedPowers::collect` SIMD
 * fast path (field.rs:1263-1301) is OPTIONAL and not used here; its small-N
 * fallback (`take(n).collect()`, lines 1267-1269) IS byte-equivalent to this
 * scalar loop.
 */
void gold_fp_shifted_powers(gold_fp_t  start, gold_fp_t  g, gold_fp_t  *out, size_t n);
void gold_fp2_shifted_powers(gold_fp2_t start, gold_fp2_t g, gold_fp2_t *out, size_t n);

/**
 * Montgomery's trick: compute multiplicative inverse of every element in x[].
 *
 * Plonky3 reference: field/src/batch_inverse.rs:81-104
 *   `batch_multiplicative_inverse_general` — scalar, allocation-free.
 *
 * Plonky3's public `batch_multiplicative_inverse` (line 29) is the rayon/SIMD
 * parallel wrapper; this port uses the scalar `_general` core directly.
 *
 * Preconditions:
 *   - For every i in [0, n): x[i] != 0  (Plonky3 doc line 25: "Panics if any
 *     input is zero." Underlying mechanism: product would be 0 → product.inverse()
 *     panics. C behavior matches: gold_fp_inv(0) is UB per field_goldilocks.h:108.)
 *   - result[0..n] is caller-allocated, length n
 *
 * On n == 0, function is a no-op (Plonky3 line 88-90 early return).
 */
void gold_fp_batch_inv_general(const gold_fp_t  *x, gold_fp_t  *result, size_t n);
void gold_fp2_batch_inv_general(const gold_fp2_t *x, gold_fp2_t *result, size_t n);

/**
 * In-place bit-reverse permutation: after the call, vals[i] holds the element
 * originally at position reverse_bits_len_u64(i, log2_strict_usize(n)).
 *
 * Plonky3 reference (output-equivalent paths):
 *   - util/src/lib.rs:236-292  outer dispatcher (small / large branches)
 *   - util/src/lib.rs:302-331  non-aarch64 small path (BIT_REVERSE_6BIT table)
 *   - util/src/lib.rs:334-346  aarch64 trivial loop
 *
 * Implementation choice: this port uses the aarch64-style trivial loop form
 * (util/src/lib.rs:334-346) unconditionally for C portability. All three
 * Plonky3 paths produce byte-identical output permutations — they differ only
 * in cache-friendliness for large arrays.
 *
 * REQUIRED BEFORE fri_fold CONSUMES THIS: byte-match against a Plonky3 oracle
 * (`dump-reverse-slice-index-bits` subcommand on real `p3_util::reverse_slice_index_bits`)
 * to confirm output-equivalence under SOURCE-LOCK rules. Phase B internal KAT
 * tests check the permutation against the reference-derived index map; an
 * external Plonky3-vs-C oracle gate is still required.
 *
 * Preconditions:
 *   - n is a power of two (asserted via log2_strict_usize)
 *   - vals[0..n] is caller-allocated
 *
 * On n == 0, function is a no-op.
 */
void reverse_slice_index_bits_fp(gold_fp_t  *vals, size_t n);
void reverse_slice_index_bits_fp2(gold_fp2_t *vals, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FIELD_HELPERS_H */
