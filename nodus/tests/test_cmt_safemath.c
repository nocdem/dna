/**
 * Nodus — cometbft @709fd12b C port, wave R1-A: `libs/math/safemath.go`
 * tests (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the five overflow-checked conversions accept exactly the values the
 * reference accepts and refuse exactly the ones it panics or errors on,
 * at the boundary rather than near it. If this file failed, one of these
 * would be false:
 *   · SafeAddInt32 and SafeSubInt32 permit every result that fits in an
 *     int32, including the two extremes, and refuse the first value past
 *     each end — in BOTH directions, since the reference tests the
 *     positive and negative operand separately;
 *   · the checks themselves never overflow: in C the reference's own
 *     expression (`a > MaxInt32-b`) is undefined for some operands, so
 *     this port evaluates it wider. INT32_MIN - INT32_MIN and
 *     INT32_MAX + INT32_MAX are computed here to pin that;
 *   · SafeConvertInt32 refuses anything outside [INT32_MIN, INT32_MAX];
 *   · SafeConvertUint8 uses the reference's ASYMMETRIC bounds — it
 *     compares against MaxUint8 above and against ZERO below, not against
 *     a "MinUint8";
 *   · SafeConvertInt8 refuses outside [INT8_MIN, INT8_MAX];
 *   · a refusal leaves the caller's output ALONE. A caller that ignores
 *     the return code must not silently receive a wrapped value.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no RNG, no allocation. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. These are BOUNDARY tests, not exhaustive ones: the space is 2^64 for
 *     the conversions and 2^64 for the pairs. A defect strictly inside the
 *     accepted range that preserves the boundaries would pass here.
 *  2. Three of the five reference functions PANIC where these return
 *     CMT_REJECT. This file pins the C contract; it cannot show that
 *     turning a panic into a return is safe at every CALL SITE, because
 *     wave R1-A has no call sites. Whoever ports the callers must check
 *     each returned code — an ignored CMT_REJECT is where the substitution
 *     could go wrong, and that is a later wave's obligation.
 *  3. It says nothing about the two functions with no consumer today
 *     (SafeConvertInt8, and SafeConvertInt32 whose only reference caller
 *     is outside the ported set) beyond that they compute what they claim.
 *
 * @file test_cmt_safemath.c
 */

#include "dnac/cmt_safemath.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static int test_add(void)
{
    int32_t out;

    out = 0x5A5A5A5A;
    CHECK(cmt_safe_add_int32(1, 2, &out) == CMT_OK, "1+2");
    CHECK(out == 3, "1+2 = 3");
    CHECK(cmt_safe_add_int32(0, 0, &out) == CMT_OK, "0+0");
    CHECK(out == 0, "0+0 = 0");
    CHECK(cmt_safe_add_int32(-5, 3, &out) == CMT_OK, "-5+3");
    CHECK(out == -2, "-5+3 = -2");
    OK();

    /* Right at the ceiling, then one past it. */
    CHECK(cmt_safe_add_int32(INT32_MAX - 1, 1, &out) == CMT_OK, "max-1+1");
    CHECK(out == INT32_MAX, "reaches INT32_MAX");
    CHECK(cmt_safe_add_int32(INT32_MAX, 1, &out) == CMT_REJECT, "max+1");
    CHECK(out == INT32_MAX, "a refused add must not touch the output");
    CHECK(cmt_safe_add_int32(INT32_MAX, INT32_MAX, &out) == CMT_REJECT,
          "max+max");
    CHECK(cmt_safe_add_int32(1, INT32_MAX, &out) == CMT_REJECT,
          "the check is on the operand's sign, not its position");
    OK();

    /* Right at the floor, then one past it. b < 0 is the second branch. */
    CHECK(cmt_safe_add_int32(INT32_MIN + 1, -1, &out) == CMT_OK, "min+1-1");
    CHECK(out == INT32_MIN, "reaches INT32_MIN");
    CHECK(cmt_safe_add_int32(INT32_MIN, -1, &out) == CMT_REJECT, "min-1");
    CHECK(cmt_safe_add_int32(INT32_MIN, INT32_MIN, &out) == CMT_REJECT,
          "min+min");
    OK();

    /* b == 0 takes neither branch and must always succeed. */
    CHECK(cmt_safe_add_int32(INT32_MAX, 0, &out) == CMT_OK, "max+0");
    CHECK(out == INT32_MAX, "max+0 = max");
    CHECK(cmt_safe_add_int32(INT32_MIN, 0, &out) == CMT_OK, "min+0");
    CHECK(out == INT32_MIN, "min+0 = min");
    /* Opposite extremes cancel; this is the pair whose CHECK would itself
     * overflow if it were evaluated in int32. */
    CHECK(cmt_safe_add_int32(INT32_MAX, INT32_MIN, &out) == CMT_OK,
          "max+min");
    CHECK(out == -1, "max+min = -1");
    OK();

    CHECK(cmt_safe_add_int32(1, 1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

static int test_sub(void)
{
    int32_t out;

    CHECK(cmt_safe_sub_int32(5, 3, &out) == CMT_OK, "5-3");
    CHECK(out == 2, "5-3 = 2");
    CHECK(cmt_safe_sub_int32(3, 5, &out) == CMT_OK, "3-5");
    CHECK(out == -2, "3-5 = -2");
    OK();

    /* b > 0 drives the floor check. */
    CHECK(cmt_safe_sub_int32(INT32_MIN + 1, 1, &out) == CMT_OK, "min+1-1");
    CHECK(out == INT32_MIN, "reaches INT32_MIN");
    CHECK(cmt_safe_sub_int32(INT32_MIN, 1, &out) == CMT_REJECT, "min-1");
    out = 7;
    CHECK(cmt_safe_sub_int32(INT32_MIN, INT32_MAX, &out) == CMT_REJECT,
          "min-max");
    CHECK(out == 7, "a refused sub must not touch the output");
    OK();

    /* b < 0 drives the ceiling check. */
    CHECK(cmt_safe_sub_int32(INT32_MAX - 1, -1, &out) == CMT_OK, "max-1--1");
    CHECK(out == INT32_MAX, "reaches INT32_MAX");
    CHECK(cmt_safe_sub_int32(INT32_MAX, -1, &out) == CMT_REJECT, "max--1");
    CHECK(cmt_safe_sub_int32(0, INT32_MIN, &out) == CMT_REJECT,
          "0-min overflows, because -INT32_MIN does not fit");
    OK();

    /* b == 0 always succeeds; min-min is the self-cancelling extreme. */
    CHECK(cmt_safe_sub_int32(INT32_MIN, 0, &out) == CMT_OK, "min-0");
    CHECK(out == INT32_MIN, "min-0 = min");
    CHECK(cmt_safe_sub_int32(INT32_MIN, INT32_MIN, &out) == CMT_OK,
          "min-min");
    CHECK(out == 0, "min-min = 0");
    CHECK(cmt_safe_sub_int32(INT32_MAX, INT32_MAX, &out) == CMT_OK,
          "max-max");
    CHECK(out == 0, "max-max = 0");
    OK();

    CHECK(cmt_safe_sub_int32(1, 1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

static int test_convert_int32(void)
{
    int32_t out;

    CHECK(cmt_safe_convert_int32(0, &out) == CMT_OK, "0");
    CHECK(out == 0, "0");
    CHECK(cmt_safe_convert_int32((int64_t)INT32_MAX, &out) == CMT_OK, "max");
    CHECK(out == INT32_MAX, "max");
    CHECK(cmt_safe_convert_int32((int64_t)INT32_MIN, &out) == CMT_OK, "min");
    CHECK(out == INT32_MIN, "min");
    OK();

    out = 42;
    CHECK(cmt_safe_convert_int32((int64_t)INT32_MAX + 1, &out) == CMT_REJECT,
          "max+1");
    CHECK(out == 42, "a refused convert must not touch the output");
    CHECK(cmt_safe_convert_int32((int64_t)INT32_MIN - 1, &out) == CMT_REJECT,
          "min-1");
    CHECK(cmt_safe_convert_int32(INT64_MAX, &out) == CMT_REJECT, "int64 max");
    CHECK(cmt_safe_convert_int32(INT64_MIN, &out) == CMT_REJECT, "int64 min");
    CHECK(cmt_safe_convert_int32(1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

static int test_convert_uint8(void)
{
    uint8_t out;

    CHECK(cmt_safe_convert_uint8(0, &out) == CMT_OK, "0");
    CHECK(out == 0, "0");
    CHECK(cmt_safe_convert_uint8(255, &out) == CMT_OK, "255");
    CHECK(out == 255, "255");
    CHECK(cmt_safe_convert_uint8(128, &out) == CMT_OK, "128");
    CHECK(out == 128, "128");
    OK();

    /* The reference's bounds are asymmetric: `> MaxUint8` above and
     * `< 0` below (safemath.go:48-52). */
    out = 9;
    CHECK(cmt_safe_convert_uint8(256, &out) == CMT_REJECT, "256");
    CHECK(out == 9, "a refused convert must not touch the output");
    CHECK(cmt_safe_convert_uint8(-1, &out) == CMT_REJECT, "-1");
    CHECK(cmt_safe_convert_uint8(INT64_MAX, &out) == CMT_REJECT, "int64 max");
    CHECK(cmt_safe_convert_uint8(INT64_MIN, &out) == CMT_REJECT, "int64 min");
    CHECK(cmt_safe_convert_uint8(1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

static int test_convert_int8(void)
{
    int8_t out;

    CHECK(cmt_safe_convert_int8(0, &out) == CMT_OK, "0");
    CHECK(out == 0, "0");
    CHECK(cmt_safe_convert_int8(127, &out) == CMT_OK, "127");
    CHECK(out == 127, "127");
    CHECK(cmt_safe_convert_int8(-128, &out) == CMT_OK, "-128");
    CHECK(out == -128, "-128");
    OK();

    out = 5;
    CHECK(cmt_safe_convert_int8(128, &out) == CMT_REJECT, "128");
    CHECK(out == 5, "a refused convert must not touch the output");
    CHECK(cmt_safe_convert_int8(-129, &out) == CMT_REJECT, "-129");
    CHECK(cmt_safe_convert_int8(INT64_MAX, &out) == CMT_REJECT, "int64 max");
    CHECK(cmt_safe_convert_int8(INT64_MIN, &out) == CMT_REJECT, "int64 min");
    CHECK(cmt_safe_convert_int8(1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

int main(void)
{
    if (test_add() != 0)            { return 1; }
    if (test_sub() != 0)            { return 1; }
    if (test_convert_int32() != 0)  { return 1; }
    if (test_convert_uint8() != 0)  { return 1; }
    if (test_convert_int8() != 0)   { return 1; }

    printf("test_cmt_safemath: OK (%d groups)\n", g_checks);
    return 0;
}
