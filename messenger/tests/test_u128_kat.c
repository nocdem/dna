/*
 * test_u128_kat.c — Known Answer Tests for portable qgp_u128_t
 *
 * Phase 2 Task 6 of witness stake v1.
 *
 * These vectors pin exact byte layouts and arithmetic results for
 * pathological inputs. Merkle state_root consistency across the 7-node
 * witness cluster requires bit-identical u128 arithmetic on all
 * platforms and compilers. Different compilers or silent code changes
 * that alter results will be caught here.
 *
 * Magic values are pasted deliberately — that IS the point of KAT.
 * If a vector fails: suspect the expected value first (recompute with
 * Python or a calculator), then the library.
 *
 * TODO: fork-based abort tests for add-overflow / sub-underflow /
 * mul-overflow / div-by-zero land in Task 7 alongside determinism CI.
 */

#include "crypto/utils/qgp_u128.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

/* -------------------------------------------------------------------- */
/* helpers                                                               */
/* -------------------------------------------------------------------- */

static int check_limbs(const char *label, qgp_u128_t got,
                       uint64_t want_hi, uint64_t want_lo) {
    if (got.hi != want_hi || got.lo != want_lo) {
        fprintf(stderr,
                "test_u128_kat: FAIL -- %s: got {hi=%016" PRIx64 ", lo=%016" PRIx64 "}, "
                "want {hi=%016" PRIx64 ", lo=%016" PRIx64 "}\n",
                label, got.hi, got.lo, want_hi, want_lo);
        return 1;
    }
    return 0;
}

static int check_bytes(const char *label, const uint8_t got[16], const uint8_t want[16]) {
    if (memcmp(got, want, 16) != 0) {
        fprintf(stderr, "test_u128_kat: FAIL -- %s: byte mismatch\n", label);
        fprintf(stderr, "  got : ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02X ", got[i]);
        fprintf(stderr, "\n  want: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02X ", want[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

static int check_int(const char *label, int got, int want) {
    if (got != want) {
        fprintf(stderr, "test_u128_kat: FAIL -- %s: got %d, want %d\n", label, got, want);
        return 1;
    }
    return 0;
}

static int check_u64(const char *label, uint64_t got, uint64_t want) {
    if (got != want) {
        fprintf(stderr,
                "test_u128_kat: FAIL -- %s: got 0x%016" PRIx64 ", want 0x%016" PRIx64 "\n",
                label, got, want);
        return 1;
    }
    return 0;
}

int main(void) {
    uint8_t buf[16];

    /* =================================================================
     * A. Serialization vectors (BE 16 bytes)
     * ================================================================= */

    /* A1: 0 -> all zeros */
    {
        uint8_t want[16] = {0};
        qgp_u128_serialize_be(qgp_u128_zero(), buf);
        if (check_bytes("A1 serialize(0)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A1 deserialize(0)", back, 0, 0)) return 1;
    }

    /* A2: 1 -> 0x...01 */
    {
        uint8_t want[16] = {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1};
        qgp_u128_serialize_be(qgp_u128_from_u64(1), buf);
        if (check_bytes("A2 serialize(1)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A2 deserialize(1)", back, 0, 1)) return 1;
    }

    /* A3: 0x0123456789ABCDEF (lo only) */
    {
        uint8_t want[16] = {0,0,0,0,0,0,0,0,
                            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
        qgp_u128_serialize_be(qgp_u128_from_u64(0x0123456789ABCDEFULL), buf);
        if (check_bytes("A3 serialize(0x0123...CDEF)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A3 deserialize(0x0123...CDEF)", back, 0, 0x0123456789ABCDEFULL)) return 1;
    }

    /* A4: mixed limbs */
    {
        uint8_t want[16] = {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
        qgp_u128_t v = qgp_u128_from_limbs(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
        qgp_u128_serialize_be(v, buf);
        if (check_bytes("A4 serialize(mixed_limbs)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A4 deserialize(mixed_limbs)", back,
                        0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL)) return 1;
    }

    /* A5: shl(1, 64) = 2^64 -> hi byte 7 is 0x01, rest zero */
    {
        uint8_t want[16] = {0,0,0,0,0,0,0,0x01, 0,0,0,0,0,0,0,0};
        qgp_u128_t v = qgp_u128_shl(qgp_u128_from_u64(1), 64);
        qgp_u128_serialize_be(v, buf);
        if (check_bytes("A5 serialize(2^64)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A5 deserialize(2^64)", back, 1, 0)) return 1;
    }

    /* A6: MAX u128 -> all 0xFF */
    {
        uint8_t want[16];
        memset(want, 0xFF, 16);
        qgp_u128_t v = qgp_u128_from_limbs(UINT64_MAX, UINT64_MAX);
        qgp_u128_serialize_be(v, buf);
        if (check_bytes("A6 serialize(MAX)", buf, want)) return 1;
        qgp_u128_t back = qgp_u128_deserialize_be(buf);
        if (check_limbs("A6 deserialize(MAX)", back, UINT64_MAX, UINT64_MAX)) return 1;
    }

    /* =================================================================
     * B. Addition vectors (carry propagation)
     * ================================================================= */

    /* B1: u64_max + 1 = 2^64 */
    {
        qgp_u128_t r = qgp_u128_add(qgp_u128_from_u64(UINT64_MAX),
                                    qgp_u128_from_u64(1));
        if (check_limbs("B1 u64_max + 1", r, 1, 0)) return 1;
    }

    /* B2: {0, UINT64_MAX} + 1 (explicit from_limbs form) */
    {
        qgp_u128_t r = qgp_u128_add(qgp_u128_from_limbs(0, UINT64_MAX),
                                    qgp_u128_from_u64(1));
        if (check_limbs("B2 {0,MAX} + 1", r, 1, 0)) return 1;
    }

    /* B3: carry lifts an existing hi */
    {
        qgp_u128_t r = qgp_u128_add(qgp_u128_from_limbs(1, UINT64_MAX),
                                    qgp_u128_from_u64(1));
        if (check_limbs("B3 {1,MAX} + 1", r, 2, 0)) return 1;
    }

    /* B4: 0 + 0 */
    {
        qgp_u128_t r = qgp_u128_add(qgp_u128_zero(), qgp_u128_zero());
        if (check_limbs("B4 0 + 0", r, 0, 0)) return 1;
    }

    /* B5: hi-only add (no carry) */
    {
        qgp_u128_t r = qgp_u128_add(qgp_u128_from_limbs(5, 0),
                                    qgp_u128_from_limbs(7, 0));
        if (check_limbs("B5 {5,0} + {7,0}", r, 12, 0)) return 1;
    }

    /* =================================================================
     * C. Subtraction vectors (borrow propagation)
     * ================================================================= */

    /* C1: 0 - 0 */
    {
        qgp_u128_t r = qgp_u128_sub(qgp_u128_zero(), qgp_u128_zero());
        if (check_limbs("C1 0 - 0", r, 0, 0)) return 1;
    }

    /* C2: 1 - 1 */
    {
        qgp_u128_t r = qgp_u128_sub(qgp_u128_from_u64(1), qgp_u128_from_u64(1));
        if (check_limbs("C2 1 - 1", r, 0, 0)) return 1;
    }

    /* C3: 2^64 - 1 = {0, UINT64_MAX} (borrow into hi) */
    {
        qgp_u128_t r = qgp_u128_sub(qgp_u128_from_limbs(1, 0), qgp_u128_from_u64(1));
        if (check_limbs("C3 {1,0} - 1", r, 0, UINT64_MAX)) return 1;
    }

    /* C4: {2,5} - {1,10} = {0, UINT64_MAX - 4}
     * Python: ((2<<64)|5) - ((1<<64)|10) = 0xFFFFFFFFFFFFFFFB
     */
    {
        qgp_u128_t r = qgp_u128_sub(qgp_u128_from_limbs(2, 5),
                                    qgp_u128_from_limbs(1, 10));
        if (check_limbs("C4 {2,5} - {1,10}", r, 0, UINT64_MAX - 4)) return 1;
    }

    /* C5: identity sub (a - 0 = a) */
    {
        qgp_u128_t a = qgp_u128_from_limbs(0xDEADBEEFULL, 0xCAFEBABEULL);
        qgp_u128_t r = qgp_u128_sub(a, qgp_u128_zero());
        if (check_limbs("C5 a - 0 = a", r, 0xDEADBEEFULL, 0xCAFEBABEULL)) return 1;
    }

    /* =================================================================
     * D. Multiplication vectors (mul_u64)
     * ================================================================= */

    /* D1: 0 * 12345 = 0 */
    {
        qgp_u128_t r = qgp_u128_mul_u64(qgp_u128_from_u64(0), UINT64_C(12345));
        if (check_limbs("D1 0 * 12345", r, 0, 0)) return 1;
    }

    /* D2: 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001 (32x32 headroom) */
    {
        qgp_u128_t r = qgp_u128_mul_u64(qgp_u128_from_u64(UINT64_C(0xFFFFFFFF)),
                                        UINT64_C(0xFFFFFFFF));
        if (check_limbs("D2 0xFFFFFFFF * 0xFFFFFFFF", r, 0, 0xFFFFFFFE00000001ULL)) return 1;
    }

    /* D3: UINT64_MAX * 2 = {1, UINT64_MAX - 1} (cross-limb carry)
     * Python: (2^64 - 1) * 2 = 2^65 - 2 = 0x1_FFFFFFFFFFFFFFFE
     */
    {
        qgp_u128_t r = qgp_u128_mul_u64(qgp_u128_from_u64(UINT64_MAX), UINT64_C(2));
        if (check_limbs("D3 UINT64_MAX * 2", r, 1, 0xFFFFFFFFFFFFFFFEULL)) return 1;
    }

    /* D4: (2^64 - 1) * (2^64 - 1) = 2^128 - 2^65 + 1
     *   = 0xFFFFFFFFFFFFFFFE_0000000000000001
     * Python: (2**64-1)*(2**64-1) = 0xFFFFFFFFFFFFFFFE0000000000000001
     * Canonical column-carry propagation boundary test.
     */
    {
        qgp_u128_t r = qgp_u128_mul_u64(qgp_u128_from_limbs(0, UINT64_MAX), UINT64_MAX);
        if (check_limbs("D4 (2^64-1) * (2^64-1)",
                        r, 0xFFFFFFFFFFFFFFFEULL, 0x0000000000000001ULL)) return 1;
    }

    /* D5: 1 * x = x (identity) */
    {
        qgp_u128_t r = qgp_u128_mul_u64(qgp_u128_from_limbs(0, 0xDEADBEEFCAFEBABEULL),
                                        UINT64_C(1));
        if (check_limbs("D5 1 * x", r, 0, 0xDEADBEEFCAFEBABEULL)) return 1;
    }

    /* TODO: fork-based abort test for mul overflow, e.g.
     *   qgp_u128_mul_u64(from_limbs(1, 0), UINT64_MAX) -> abort()
     * Lands in Task 7.
     */

    /* =================================================================
     * E. Shift vectors (shl boundaries)
     * ================================================================= */

    /* E1: shl(1, 0) = 1 (passthrough) */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_u64(1), 0);
        if (check_limbs("E1 shl(1, 0)", r, 0, 1)) return 1;
    }

    /* E2: shl with bits=0 must preserve hi==0 when input has zero hi */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_limbs(0, 0xDEADBEEFCAFEBABEULL), 0);
        if (check_limbs("E2 shl({0,X}, 0)", r, 0, 0xDEADBEEFCAFEBABEULL)) return 1;
    }

    /* E3: shl(1, 1) = 2 */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_u64(1), 1);
        if (check_limbs("E3 shl(1, 1)", r, 0, 2)) return 1;
    }

    /* E4: shl(1, 63) = 0x8000000000000000 */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_u64(1), 63);
        if (check_limbs("E4 shl(1, 63)", r, 0, 0x8000000000000000ULL)) return 1;
    }

    /* E5: shl(1, 64) = 2^64 */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_u64(1), 64);
        if (check_limbs("E5 shl(1, 64)", r, 1, 0)) return 1;
    }

    /* E6: shl(1, 127) = 2^127 (hi MSB set) */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_u64(1), 127);
        if (check_limbs("E6 shl(1, 127)", r, 0x8000000000000000ULL, 0)) return 1;
    }

    /* E7: shl(0xDEADBEEF, 32) = 0xDEADBEEF00000000 (partial-in-lo) */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_limbs(0, 0xDEADBEEFULL), 32);
        if (check_limbs("E7 shl(0xDEADBEEF, 32)", r, 0, 0xDEADBEEF00000000ULL)) return 1;
    }

    /* E8: shl(0xDEADBEEF, 96) = bits land entirely in hi */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_limbs(0, 0xDEADBEEFULL), 96);
        if (check_limbs("E8 shl(0xDEADBEEF, 96)", r, 0xDEADBEEF00000000ULL, 0)) return 1;
    }

    /* E9: top bit carries across limbs via shift 1
     * shl({0, UINT64_MAX}, 1) = {1, UINT64_MAX - 1}
     */
    {
        qgp_u128_t r = qgp_u128_shl(qgp_u128_from_limbs(0, UINT64_MAX), 1);
        if (check_limbs("E9 shl({0,MAX}, 1)", r, 1, 0xFFFFFFFFFFFFFFFEULL)) return 1;
    }

    /* =================================================================
     * F. Division vectors (div_u64 quotient + remainder exactness)
     * ================================================================= */

    /* F1: 100 / 7 = 14 rem 2 */
    {
        uint64_t rem = 0;
        qgp_u128_t q = qgp_u128_div_u64(qgp_u128_from_u64(100), UINT64_C(7), &rem);
        if (check_limbs("F1 100 / 7 (q)", q, 0, 14)) return 1;
        if (check_u64("F1 100 / 7 (rem)", rem, 2)) return 1;
    }

    /* F2: 100 / 1 = 100 rem 0 */
    {
        uint64_t rem = 0xDEAD;
        qgp_u128_t q = qgp_u128_div_u64(qgp_u128_from_u64(100), UINT64_C(1), &rem);
        if (check_limbs("F2 100 / 1 (q)", q, 0, 100)) return 1;
        if (check_u64("F2 100 / 1 (rem)", rem, 0)) return 1;
    }

    /* F3: 2^64 / 2 = 2^63 rem 0 */
    {
        uint64_t rem = 0xDEAD;
        qgp_u128_t q = qgp_u128_div_u64(qgp_u128_from_limbs(1, 0), UINT64_C(2), &rem);
        if (check_limbs("F3 2^64 / 2 (q)", q, 0, 0x8000000000000000ULL)) return 1;
        if (check_u64("F3 2^64 / 2 (rem)", rem, 0)) return 1;
    }

    /* F4: full-width dividend divided by 7
     * value = (0xDEADBEEFCAFEBABE << 64) | 0x0123456789ABCDEF
     * Python: q, r = divmod(value, 7)
     *   q = 0x1FCFAD8FF86D8864_494E2E7C8161AFB4
     *   r = 3
     */
    {
        uint64_t rem = 0xDEAD;
        qgp_u128_t a = qgp_u128_from_limbs(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
        qgp_u128_t q = qgp_u128_div_u64(a, UINT64_C(7), &rem);
        if (check_limbs("F4 big / 7 (q)", q,
                        0x1FCFAD8FF86D8864ULL, 0x494E2E7C8161AFB4ULL)) return 1;
        if (check_u64("F4 big / 7 (rem)", rem, 3)) return 1;
    }

    /* F5: full-width dividend divided by 1000000007 (large non-power-of-two)
     * Python: q, r = divmod(value, 1000000007)
     *   q = 0x00000003BC65CFF8_2EEA412A0035097D
     *   r = 713681284 (0x2A89E984)
     */
    {
        uint64_t rem = 0xDEAD;
        qgp_u128_t a = qgp_u128_from_limbs(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
        qgp_u128_t q = qgp_u128_div_u64(a, UINT64_C(1000000007), &rem);
        if (check_limbs("F5 big / 1000000007 (q)", q,
                        0x00000003BC65CFF8ULL, 0x2EEA412A0035097DULL)) return 1;
        if (check_u64("F5 big / 1000000007 (rem)", rem, 713681284ULL)) return 1;
    }

    /* F6: 0 / 123 = 0 rem 0 */
    {
        uint64_t rem = 0xDEAD;
        qgp_u128_t q = qgp_u128_div_u64(qgp_u128_zero(), UINT64_C(123), &rem);
        if (check_limbs("F6 0 / 123 (q)", q, 0, 0)) return 1;
        if (check_u64("F6 0 / 123 (rem)", rem, 0)) return 1;
    }

    /* TODO: fork-based abort test for div-by-zero lands in Task 7. */

    /* =================================================================
     * G. Comparison vectors
     * ================================================================= */

    /* G1: cmp(0, 0) = 0 */
    if (check_int("G1 cmp(0, 0)",
                  qgp_u128_cmp(qgp_u128_zero(), qgp_u128_zero()), 0)) return 1;

    /* G2: cmp(1, 2) = -1 */
    if (check_int("G2 cmp(1, 2)",
                  qgp_u128_cmp(qgp_u128_from_u64(1), qgp_u128_from_u64(2)), -1)) return 1;

    /* G3: cmp(2, 1) = 1 */
    if (check_int("G3 cmp(2, 1)",
                  qgp_u128_cmp(qgp_u128_from_u64(2), qgp_u128_from_u64(1)), 1)) return 1;

    /* G4: hi dominates -- {1,0} > {0, UINT64_MAX} */
    if (check_int("G4 cmp({1,0}, {0,MAX})",
                  qgp_u128_cmp(qgp_u128_from_limbs(1, 0),
                               qgp_u128_from_limbs(0, UINT64_MAX)), 1)) return 1;

    /* G5: lo decides when hi equal -- {0,MAX} > {0,MAX-1} */
    if (check_int("G5 cmp({0,MAX}, {0,MAX-1})",
                  qgp_u128_cmp(qgp_u128_from_limbs(0, UINT64_MAX),
                               qgp_u128_from_limbs(0, UINT64_MAX - 1)), 1)) return 1;

    /* G6: reflexive -- MAX == MAX */
    if (check_int("G6 cmp(MAX, MAX)",
                  qgp_u128_cmp(qgp_u128_from_limbs(UINT64_MAX, UINT64_MAX),
                               qgp_u128_from_limbs(UINT64_MAX, UINT64_MAX)), 0)) return 1;

    printf("test_u128_kat: PASS\n");
    return 0;
}
