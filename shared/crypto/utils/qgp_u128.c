/*
 * qgp_u128.c — portable 128-bit unsigned integer with explicit 64-bit limbs.
 *
 * Authority: DNAC reward accumulator (witness stake v1, F-CRYPTO-08).
 *
 * Design constraints:
 *   - NEVER use compiler __uint128_t. Some targets (MSVC) don't have it,
 *     and when present, codegen can differ across gcc / clang versions
 *     for edge cases like carry and 128-bit multiplication.
 *   - Byte layout for serialization is fixed big-endian, 16 bytes, using
 *     explicit shift+or so it is endian-independent.
 *   - Overflow / underflow / div-by-zero abort(). These represent supply
 *     invariant violation — silently wrapping would break the Merkle
 *     state_root consistency across the 7-node witness cluster.
 */

#include "crypto/utils/qgp_u128.h"

#include <stdlib.h>  /* abort */

/* ------------------------------------------------------------------ */
/* Constructors                                                        */
/* ------------------------------------------------------------------ */

qgp_u128_t qgp_u128_zero(void) {
    qgp_u128_t r = { 0, 0 };
    return r;
}

qgp_u128_t qgp_u128_from_u64(uint64_t v) {
    qgp_u128_t r = { 0, v };
    return r;
}

qgp_u128_t qgp_u128_from_limbs(uint64_t hi, uint64_t lo) {
    qgp_u128_t r = { hi, lo };
    return r;
}

/* ------------------------------------------------------------------ */
/* Comparison                                                          */
/* ------------------------------------------------------------------ */

int qgp_u128_cmp(qgp_u128_t a, qgp_u128_t b) {
    if (a.hi < b.hi) return -1;
    if (a.hi > b.hi) return  1;
    if (a.lo < b.lo) return -1;
    if (a.lo > b.lo) return  1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Arithmetic                                                          */
/* ------------------------------------------------------------------ */

qgp_u128_t qgp_u128_add(qgp_u128_t a, qgp_u128_t b) {
    qgp_u128_t r;
    r.lo = a.lo + b.lo;
    uint64_t carry = (r.lo < a.lo) ? 1ULL : 0ULL;

    /* Check hi addition for overflow: a.hi + b.hi + carry must fit in 64 bits. */
    uint64_t hi_sum = a.hi + b.hi;
    if (hi_sum < a.hi) {
        /* Already overflowed at hi+b.hi */
        abort();
    }
    uint64_t hi_final = hi_sum + carry;
    if (hi_final < hi_sum) {
        abort();
    }
    r.hi = hi_final;
    return r;
}

qgp_u128_t qgp_u128_sub(qgp_u128_t a, qgp_u128_t b) {
    if (qgp_u128_cmp(a, b) < 0) {
        abort();
    }
    qgp_u128_t r;
    r.lo = a.lo - b.lo;
    uint64_t borrow = (a.lo < b.lo) ? 1ULL : 0ULL;
    r.hi = a.hi - b.hi - borrow;
    return r;
}

/*
 * mul_u64: multiply a 128-bit value by a 64-bit scalar.
 *
 * Strategy: split each 64-bit limb into upper/lower 32-bit halves and do
 *   the four 32x32 -> 64 products. a has 4 halves (a3 a2 a1 a0, MSH first)
 *   and b has 2 halves (b1 b0), giving 8 partial products. We walk them in
 *   order of weight (2^0 .. 2^192) accumulating into a 256-bit-wide tally
 *   that exists only implicitly: we only keep the low 128 bits in r and
 *   verify every contribution above that is zero (else overflow -> abort).
 *
 * Weights in units of 2^32:
 *   a0*b0 : weight 0  (bits 0..63)
 *   a0*b1 : weight 1  (bits 32..95)
 *   a1*b0 : weight 1
 *   a1*b1 : weight 2  (bits 64..127)
 *   a2*b0 : weight 2
 *   a2*b1 : weight 3  (bits 96..159)  <- MUST be 0 except possibly its low bits fit in hi
 *   a3*b0 : weight 3
 *   a3*b1 : weight 4  (bits 128..191) <- MUST be 0 entirely
 */
qgp_u128_t qgp_u128_mul_u64(qgp_u128_t a, uint64_t b) {
    const uint64_t MASK32 = 0xFFFFFFFFULL;

    uint64_t a0 = a.lo & MASK32;        /* bits   0..31 */
    uint64_t a1 = (a.lo >> 32) & MASK32;/* bits  32..63 */
    uint64_t a2 = a.hi & MASK32;        /* bits  64..95 */
    uint64_t a3 = (a.hi >> 32) & MASK32;/* bits  96..127 */
    uint64_t b0 = b & MASK32;
    uint64_t b1 = (b >> 32) & MASK32;

    /* 8 partial products, each fits in 64 bits (32*32 <= 64). */
    uint64_t p00 = a0 * b0;   /* weight 0 */
    uint64_t p01 = a0 * b1;   /* weight 1 */
    uint64_t p10 = a1 * b0;   /* weight 1 */
    uint64_t p11 = a1 * b1;   /* weight 2 */
    uint64_t p20 = a2 * b0;   /* weight 2 */
    uint64_t p21 = a2 * b1;   /* weight 3 */
    uint64_t p30 = a3 * b0;   /* weight 3 */
    uint64_t p31 = a3 * b1;   /* weight 4 */

    /*
     * Accumulate column by column. Treat the result as four 32-bit columns
     * c0 (bits 0..31), c1 (32..63), c2 (64..95), c3 (96..127). Each ci is
     * 64-bit-wide to absorb carries; after final propagation every ci must
     * fit in 32 bits. Any bits beyond column 3 (weight >= 4) = overflow.
     */
    uint64_t c0 = p00 & MASK32;
    uint64_t c1 = (p00 >> 32) + (p01 & MASK32) + (p10 & MASK32);
    uint64_t c2 = (p01 >> 32) + (p10 >> 32) + (p11 & MASK32)
                + (p20 & MASK32);
    uint64_t c3 = (p11 >> 32) + (p20 >> 32) + (p21 & MASK32)
                + (p30 & MASK32);
    /* Anything landing at weight 4 or higher -> overflow. */
    uint64_t c4_overflow = (p21 >> 32) + (p30 >> 32) + p31;

    /* Propagate carries up through the columns. */
    uint64_t carry = c0 >> 32; c0 &= MASK32;
    c1 += carry;
    carry = c1 >> 32;          c1 &= MASK32;
    c2 += carry;
    carry = c2 >> 32;          c2 &= MASK32;
    c3 += carry;
    carry = c3 >> 32;          c3 &= MASK32;
    c4_overflow += carry;

    if (c4_overflow != 0) {
        abort();
    }

    qgp_u128_t r;
    r.lo = (c1 << 32) | c0;
    r.hi = (c3 << 32) | c2;
    return r;
}

qgp_u128_t qgp_u128_shl(qgp_u128_t a, unsigned bits) {
    if (bits >= 128) {
        abort();
    }
    qgp_u128_t r;
    if (bits == 0) {
        r = a;
    } else if (bits < 64) {
        r.hi = (a.hi << bits) | (a.lo >> (64 - bits));
        r.lo = a.lo << bits;
    } else if (bits == 64) {
        r.hi = a.lo;
        r.lo = 0;
    } else { /* 64 < bits < 128 */
        r.hi = a.lo << (bits - 64);
        r.lo = 0;
    }
    return r;
}

/*
 * div_u64: 128-bit / 64-bit long division, bit-by-bit from MSB.
 *
 * Classic shift-subtract algorithm: for i = 127..0, shift the remainder
 * left by 1, bring in bit i of the dividend, then if remainder >= divisor
 * subtract and set the corresponding bit in the quotient.
 *
 * O(128) iterations, no hardware 128/64 divide, portable everywhere.
 */
qgp_u128_t qgp_u128_div_u64(qgp_u128_t a, uint64_t b, uint64_t *rem_out) {
    if (b == 0) {
        abort();
    }

    uint64_t q_hi = 0;
    uint64_t q_lo = 0;
    uint64_t r = 0;

    for (int i = 127; i >= 0; --i) {
        /* Bring next dividend bit into remainder's LSB. */
        uint64_t bit;
        if (i >= 64) {
            bit = (a.hi >> (i - 64)) & 1ULL;
        } else {
            bit = (a.lo >> i) & 1ULL;
        }
        r = (r << 1) | bit;

        if (r >= b) {
            r -= b;
            if (i >= 64) {
                q_hi |= (1ULL << (i - 64));
            } else {
                q_lo |= (1ULL << i);
            }
        }
    }

    if (rem_out) {
        *rem_out = r;
    }

    qgp_u128_t q;
    q.hi = q_hi;
    q.lo = q_lo;
    return q;
}

/* ------------------------------------------------------------------ */
/* Big-endian 16-byte serialization                                    */
/* ------------------------------------------------------------------ */

void qgp_u128_serialize_be(qgp_u128_t v, uint8_t out[16]) {
    /* hi first (big end), then lo. Each limb big-endian. */
    out[0]  = (uint8_t)(v.hi >> 56);
    out[1]  = (uint8_t)(v.hi >> 48);
    out[2]  = (uint8_t)(v.hi >> 40);
    out[3]  = (uint8_t)(v.hi >> 32);
    out[4]  = (uint8_t)(v.hi >> 24);
    out[5]  = (uint8_t)(v.hi >> 16);
    out[6]  = (uint8_t)(v.hi >>  8);
    out[7]  = (uint8_t)(v.hi);
    out[8]  = (uint8_t)(v.lo >> 56);
    out[9]  = (uint8_t)(v.lo >> 48);
    out[10] = (uint8_t)(v.lo >> 40);
    out[11] = (uint8_t)(v.lo >> 32);
    out[12] = (uint8_t)(v.lo >> 24);
    out[13] = (uint8_t)(v.lo >> 16);
    out[14] = (uint8_t)(v.lo >>  8);
    out[15] = (uint8_t)(v.lo);
}

qgp_u128_t qgp_u128_deserialize_be(const uint8_t in[16]) {
    qgp_u128_t r;
    r.hi = ((uint64_t)in[0]  << 56) |
           ((uint64_t)in[1]  << 48) |
           ((uint64_t)in[2]  << 40) |
           ((uint64_t)in[3]  << 32) |
           ((uint64_t)in[4]  << 24) |
           ((uint64_t)in[5]  << 16) |
           ((uint64_t)in[6]  <<  8) |
           ((uint64_t)in[7]);
    r.lo = ((uint64_t)in[8]  << 56) |
           ((uint64_t)in[9]  << 48) |
           ((uint64_t)in[10] << 40) |
           ((uint64_t)in[11] << 32) |
           ((uint64_t)in[12] << 24) |
           ((uint64_t)in[13] << 16) |
           ((uint64_t)in[14] <<  8) |
           ((uint64_t)in[15]);
    return r;
}
