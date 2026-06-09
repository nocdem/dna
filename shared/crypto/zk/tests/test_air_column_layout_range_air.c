/**
 * @file test_air_column_layout_range_air.c
 * @brief AIR column-layout BINDING contract test for range_air (design doc § 9 F7).
 *
 * Per design doc § 12.4 item 1 + § 9 F7: this test was specified for every AIR
 * module in Faz 3 but **was never written** for the original (now-nuked)
 * range_air.c. Its absence is what allowed the invented column layout to ship
 * without anyone noticing the drift from § 4.5.
 *
 * This file is the canonical example. Items 2-7 in the rework queue will each
 * get an equivalent test pinned to their module's column-binding contract.
 *
 * What this test enforces:
 *   1. Compile-time:  the column offset symbols match the values declared in
 *      range_air.h. A drift in the offsets → compile error.
 *   2. Runtime:       range_air_build_trace places amount bit i at exactly
 *      RANGE_AIR_BIT_OFF(i), and the amount field at RANGE_AIR_AMOUNT_OFF.
 *      A drift in the implementation → assertion failure.
 *
 * Build (Makefile):
 *   make build/test_air_column_layout_range_air
 *
 * Run:
 *   ./build/test_air_column_layout_range_air
 *
 * Exit codes:
 *   0  contract holds
 *   1  contract violated
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../range_air.h"

/* ============================================================================
 * Compile-time binding assertions
 *
 * Uses the negative-array-size trick (C99-compatible, no C11 _Static_assert
 * dependency). A failure here produces a compiler error mentioning the
 * specific binding that drifted.
 * ========================================================================== */

#define RANGE_AIR_CT_ASSERT(cond, tag) \
    typedef char range_air_ct_assert_##tag[(cond) ? 1 : -1]

RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(0)  == 0,  bit0_offset_zero);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(1)  == 1,  bit1_offset_one);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(31) == 31, bit31_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(32) == 32, bit32_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(62) == 62, bit62_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(63) == 63, bit63_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_AMOUNT_OFF  == 64, amount_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_WIDTH       == 65, width);

/* The constraint identifier characters are stable. Drift here breaks
 * diagnostic strings that downstream code (range_proof_air, debug tools)
 * may rely on. */
RANGE_AIR_CT_ASSERT(RANGE_AIR_CONSTRAINT_BOOL   == 'B', cid_bool);
RANGE_AIR_CT_ASSERT(RANGE_AIR_CONSTRAINT_RECOMP == 'S', cid_recomp);

/* ============================================================================
 * Runtime checks
 * ========================================================================== */

static int fail_count = 0;

static void check_eq_size(const char *what, size_t got, size_t want) {
    if (got == want) return;
    fprintf(stderr, "FAIL: %s: got %zu, want %zu\n", what, got, want);
    fail_count++;
}

static void check_eq_u64(const char *what, uint64_t got, uint64_t want) {
    if (got == want) return;
    fprintf(stderr,
            "FAIL: %s: got %" PRIu64 ", want %" PRIu64 "\n",
            what, got, want);
    fail_count++;
}

int main(void) {
    printf("test_air_column_layout_range_air — design doc § 9 F7 BINDING contract\n");
    printf("--------------------------------------------------------------------\n");

    /* (1) Constant exposure: the macros expand to the values their type/comment
     *     claims. */
    check_eq_size("RANGE_AIR_WIDTH",      RANGE_AIR_WIDTH,      65);
    check_eq_size("RANGE_AIR_AMOUNT_OFF", RANGE_AIR_AMOUNT_OFF, 64);
    check_eq_size("RANGE_AIR_BIT_OFF(0)", RANGE_AIR_BIT_OFF(0), 0);
    check_eq_size("RANGE_AIR_BIT_OFF(63)", RANGE_AIR_BIT_OFF(63), 63);

    /* (2) Strict monotonicity: bit offsets are sequential with no gaps. */
    for (size_t i = 0; i < 63; i++) {
        if (RANGE_AIR_BIT_OFF(i + 1) != RANGE_AIR_BIT_OFF(i) + 1) {
            fprintf(stderr,
                    "FAIL: RANGE_AIR_BIT_OFF non-monotone at i=%zu\n", i);
            fail_count++;
            break;
        }
    }

    /* (3) Amount and bits don't collide. */
    if (RANGE_AIR_AMOUNT_OFF < 64) {
        fprintf(stderr, "FAIL: amount offset overlaps a bit column\n");
        fail_count++;
    }

    /* (4) Width = bits + 1 (amount). */
    check_eq_size("RANGE_AIR_WIDTH == bits+1",
                  RANGE_AIR_WIDTH, RANGE_AIR_BIT_OFF(63) + 1 + 1);

    /* (5) build_trace places bit i at offset RANGE_AIR_BIT_OFF(i).
     *     Use single-bit-set amounts (powers of 2) to isolate each position. */
    for (size_t i = 0; i < 64; i++) {
        uint64_t amount = (uint64_t)1 << i;
        uint64_t trace[RANGE_AIR_WIDTH];
        range_air_build_trace(&amount, 1, trace, RANGE_AIR_WIDTH);

        /* The bit at position i should be 1; all other bits 0. */
        for (size_t j = 0; j < 64; j++) {
            uint64_t want = (j == i) ? 1 : 0;
            if (trace[RANGE_AIR_BIT_OFF(j)] != want) {
                fprintf(stderr,
                        "FAIL: amount=2^%zu, expected bit[%zu]=%" PRIu64
                        " at offset %zu, got %" PRIu64 "\n",
                        i, j, want, RANGE_AIR_BIT_OFF(j),
                        trace[RANGE_AIR_BIT_OFF(j)]);
                fail_count++;
            }
        }
        /* The amount cell should equal the field-canonical amount. For
         * amount < p (always true for i < 64) this is just amount. */
        check_eq_u64("amount cell mismatch",
                     trace[RANGE_AIR_AMOUNT_OFF], amount);
    }

    /* (6) build_trace honors row_stride > RANGE_AIR_WIDTH. Embed two
     *     amounts with extra padding columns between rows; assert no
     *     bleed-over. */
    {
        uint64_t amounts[2] = {0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
        const size_t stride = RANGE_AIR_WIDTH + 4; /* 4 padding cells */
        uint64_t buf[2 * (RANGE_AIR_WIDTH + 4)];
        /* Pre-fill padding with a sentinel that must remain untouched. */
        for (size_t k = 0; k < sizeof(buf) / sizeof(buf[0]); k++) {
            buf[k] = 0xDEADBEEFDEADBEEFULL;
        }
        range_air_build_trace(amounts, 2, buf, stride);

        /* Verify cells written. */
        for (size_t r = 0; r < 2; r++) {
            uint64_t *row = &buf[r * stride];
            check_eq_u64("multi-row amount cell",
                         row[RANGE_AIR_AMOUNT_OFF], amounts[r]);
            for (size_t i = 0; i < 64; i++) {
                uint64_t want = (amounts[r] >> i) & 1ULL;
                if (row[RANGE_AIR_BIT_OFF(i)] != want) {
                    fprintf(stderr,
                            "FAIL: multi-row r=%zu bit %zu: got %" PRIu64
                            ", want %" PRIu64 "\n",
                            r, i, row[RANGE_AIR_BIT_OFF(i)], want);
                    fail_count++;
                }
            }
            /* Padding cells must be untouched. */
            for (size_t k = RANGE_AIR_WIDTH; k < stride; k++) {
                if (row[k] != 0xDEADBEEFDEADBEEFULL) {
                    fprintf(stderr,
                            "FAIL: row %zu padding cell %zu overwritten "
                            "(got 0x%016" PRIx64 ")\n", r, k, row[k]);
                    fail_count++;
                }
            }
        }
    }

    /* (7) range_air_amount_from_row reads the cell at RANGE_AIR_AMOUNT_OFF.
     *     Tampering the amount cell directly must be visible through the
     *     accessor. */
    {
        uint64_t row[RANGE_AIR_WIDTH] = {0};
        row[RANGE_AIR_AMOUNT_OFF] = 0xCAFEBABECAFEBABEULL;
        uint64_t got = range_air_amount_from_row(row);
        check_eq_u64("amount accessor",
                     got, 0xCAFEBABECAFEBABEULL);
    }

    printf("\n");
    if (fail_count == 0) {
        printf("F7 BINDING contract: GREEN — column layout pinned, runtime behavior consistent\n");
        return 0;
    }
    printf("F7 BINDING contract: RED — %d failure(s)\n", fail_count);
    return 1;
}
