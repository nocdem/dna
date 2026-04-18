/*
 * test_u128_roundtrip.c — smoke test for portable qgp_u128_t
 *
 * Phase 2 Task 5 of witness stake v1. Full KAT suite lives in Task 6.
 * This test only validates: constructors, BE round-trip, basic add,
 * cmp ordering, and one nontrivial shift.
 */

#include "crypto/utils/qgp_u128.h"
#include <stdio.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "test_u128_roundtrip: FAIL — %s (line %d)\n", #cond, __LINE__); \
        return 1; \
    } \
} while (0)

int main(void) {
    /* Zero */
    qgp_u128_t z = qgp_u128_zero();
    CHECK(z.hi == 0 && z.lo == 0);

    /* From u64 */
    qgp_u128_t a = qgp_u128_from_u64(42);
    CHECK(a.hi == 0 && a.lo == 42);

    /* From limbs */
    qgp_u128_t limbs = qgp_u128_from_limbs(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL);
    CHECK(limbs.hi == 0xDEADBEEFCAFEBABEULL);
    CHECK(limbs.lo == 0x0123456789ABCDEFULL);

    /* Round-trip BE serialize */
    uint8_t buf[16];
    qgp_u128_serialize_be(a, buf);
    qgp_u128_t b = qgp_u128_deserialize_be(buf);
    CHECK(b.hi == a.hi && b.lo == a.lo);

    /* BE byte order: hi first, lo second; each limb big-endian */
    qgp_u128_serialize_be(limbs, buf);
    CHECK(buf[0] == 0xDE && buf[1] == 0xAD && buf[2] == 0xBE && buf[3] == 0xEF);
    CHECK(buf[4] == 0xCA && buf[5] == 0xFE && buf[6] == 0xBA && buf[7] == 0xBE);
    CHECK(buf[8] == 0x01 && buf[9] == 0x23 && buf[10] == 0x45 && buf[11] == 0x67);
    CHECK(buf[12] == 0x89 && buf[13] == 0xAB && buf[14] == 0xCD && buf[15] == 0xEF);

    /* Round-trip the nontrivial value */
    qgp_u128_t back = qgp_u128_deserialize_be(buf);
    CHECK(back.hi == limbs.hi && back.lo == limbs.lo);

    /* Add small */
    qgp_u128_t c = qgp_u128_add(qgp_u128_from_u64(10), qgp_u128_from_u64(20));
    CHECK(c.hi == 0 && c.lo == 30);

    /* Add with carry across limb boundary */
    qgp_u128_t max64 = qgp_u128_from_u64(0xFFFFFFFFFFFFFFFFULL);
    qgp_u128_t one   = qgp_u128_from_u64(1);
    qgp_u128_t carry = qgp_u128_add(max64, one);
    CHECK(carry.hi == 1 && carry.lo == 0);

    /* Sub */
    qgp_u128_t d = qgp_u128_sub(qgp_u128_from_u64(100), qgp_u128_from_u64(58));
    CHECK(d.hi == 0 && d.lo == 42);

    /* Sub with borrow across limb boundary */
    qgp_u128_t two_to_64 = qgp_u128_from_limbs(1, 0);
    qgp_u128_t borrow = qgp_u128_sub(two_to_64, one);
    CHECK(borrow.hi == 0 && borrow.lo == 0xFFFFFFFFFFFFFFFFULL);

    /* mul_u64 small */
    qgp_u128_t m1 = qgp_u128_mul_u64(qgp_u128_from_u64(7), 6);
    CHECK(m1.hi == 0 && m1.lo == 42);

    /* mul_u64 crossing 64-bit boundary: 2^32 * 2^32 = 2^64 */
    qgp_u128_t big32 = qgp_u128_from_u64(0x100000000ULL);
    qgp_u128_t m2 = qgp_u128_mul_u64(big32, 0x100000000ULL);
    CHECK(m2.hi == 1 && m2.lo == 0);

    /* div_u64 small */
    uint64_t rem = 0;
    qgp_u128_t q = qgp_u128_div_u64(qgp_u128_from_u64(100), 7, &rem);
    CHECK(q.hi == 0 && q.lo == 14);
    CHECK(rem == 2);

    /* div_u64 across limb boundary: 2^64 / 2 = 2^63 */
    qgp_u128_t big = qgp_u128_from_limbs(1, 0);
    q = qgp_u128_div_u64(big, 2, &rem);
    CHECK(q.hi == 0 && q.lo == 0x8000000000000000ULL);
    CHECK(rem == 0);

    /* Compare */
    CHECK(qgp_u128_cmp(qgp_u128_from_u64(1), qgp_u128_from_u64(2)) == -1);
    CHECK(qgp_u128_cmp(qgp_u128_from_u64(2), qgp_u128_from_u64(2)) == 0);
    CHECK(qgp_u128_cmp(qgp_u128_from_u64(3), qgp_u128_from_u64(2)) == 1);

    /* Compare with hi differing */
    qgp_u128_t hi_a = qgp_u128_from_limbs(2, 0);
    qgp_u128_t hi_b = qgp_u128_from_limbs(1, 0xFFFFFFFFFFFFFFFFULL);
    CHECK(qgp_u128_cmp(hi_a, hi_b) == 1);
    CHECK(qgp_u128_cmp(hi_b, hi_a) == -1);

    /* Shift */
    qgp_u128_t sh0 = qgp_u128_shl(qgp_u128_from_u64(42), 0);
    CHECK(sh0.hi == 0 && sh0.lo == 42);

    qgp_u128_t sh1 = qgp_u128_shl(qgp_u128_from_u64(1), 1);
    CHECK(sh1.hi == 0 && sh1.lo == 2);

    qgp_u128_t sh63 = qgp_u128_shl(qgp_u128_from_u64(1), 63);
    CHECK(sh63.hi == 0 && sh63.lo == 0x8000000000000000ULL);

    qgp_u128_t sh64 = qgp_u128_shl(qgp_u128_from_u64(1), 64);
    CHECK(sh64.hi == 1 && sh64.lo == 0);

    qgp_u128_t sh65 = qgp_u128_shl(qgp_u128_from_u64(1), 65);
    CHECK(sh65.hi == 2 && sh65.lo == 0);

    qgp_u128_t sh127 = qgp_u128_shl(qgp_u128_from_u64(1), 127);
    CHECK(sh127.hi == 0x8000000000000000ULL && sh127.lo == 0);

    /* Shift partial through both limbs */
    qgp_u128_t val = qgp_u128_from_limbs(0, 0xFFFFFFFFFFFFFFFFULL);
    qgp_u128_t sh_part = qgp_u128_shl(val, 4);
    CHECK(sh_part.hi == 0x0F && sh_part.lo == 0xFFFFFFFFFFFFFFF0ULL);

    printf("test_u128_roundtrip: PASS\n");
    return 0;
}
