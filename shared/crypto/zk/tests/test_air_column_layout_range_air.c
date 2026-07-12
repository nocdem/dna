/**
 * @file test_air_column_layout_range_air.c
 * @brief AIR column-layout BINDING contract test for range_air.
 *
 * This test pins the column-binding contract of range_air.h so any layout
 * drift is a compile error or assertion failure, not a silent cross-version
 * proof-acceptance break.
 *
 * 2026-07 soundness fix: the layout is now 52-bit (RANGE_AIR_BITS = 52,
 * amount at 52, width 53). The old 64-bit layout was VACUOUS over Goldilocks
 * (p < 2^64) — see range_air.h header rationale.
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

RANGE_AIR_CT_ASSERT(RANGE_AIR_BITS        == 52, bits_52);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(0)  == 0,  bit0_offset_zero);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(1)  == 1,  bit1_offset_one);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(31) == 31, bit31_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(32) == 32, bit32_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(50) == 50, bit50_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_BIT_OFF(51) == 51, bit51_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_AMOUNT_OFF  == 52, amount_offset);
RANGE_AIR_CT_ASSERT(RANGE_AIR_WIDTH       == 53, width);

/* Soundness precondition: the recomposition is injective ONLY if
 * 2^RANGE_AIR_BITS < p. 52 < 63 gives comfortable margin (2^52 << p). */
RANGE_AIR_CT_ASSERT(RANGE_AIR_BITS < 63, bits_below_p_margin);

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
    printf("test_air_column_layout_range_air — BINDING contract (52-bit layout)\n");
    printf("--------------------------------------------------------------------\n");

    /* (1) Constant exposure: the macros expand to the values their type/comment
     *     claims. */
    check_eq_size("RANGE_AIR_BITS",        RANGE_AIR_BITS,        52);
    check_eq_size("RANGE_AIR_WIDTH",       RANGE_AIR_WIDTH,       53);
    check_eq_size("RANGE_AIR_AMOUNT_OFF",  RANGE_AIR_AMOUNT_OFF,  52);
    check_eq_size("RANGE_AIR_BIT_OFF(0)",  RANGE_AIR_BIT_OFF(0),  0);
    check_eq_size("RANGE_AIR_BIT_OFF(51)", RANGE_AIR_BIT_OFF(51), 51);

    /* (2) Strict monotonicity: bit offsets are sequential with no gaps. */
    for (size_t i = 0; i < RANGE_AIR_BITS - 1; i++) {
        if (RANGE_AIR_BIT_OFF(i + 1) != RANGE_AIR_BIT_OFF(i) + 1) {
            fprintf(stderr,
                    "FAIL: RANGE_AIR_BIT_OFF non-monotone at i=%zu\n", i);
            fail_count++;
            break;
        }
    }

    /* (3) Amount and bits don't collide. */
    if (RANGE_AIR_AMOUNT_OFF < RANGE_AIR_BITS) {
        fprintf(stderr, "FAIL: amount offset overlaps a bit column\n");
        fail_count++;
    }

    /* (4) Width = bits + 1 (amount). */
    check_eq_size("RANGE_AIR_WIDTH == bits+1",
                  RANGE_AIR_WIDTH, RANGE_AIR_BIT_OFF(RANGE_AIR_BITS - 1) + 1 + 1);

    /* (5) build_trace places bit i at offset RANGE_AIR_BIT_OFF(i).
     *     Use single-bit-set amounts (powers of 2) to isolate each position.
     *     Only in-range powers (i < RANGE_AIR_BITS) have a faithful bit image. */
    for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
        uint64_t amount = (uint64_t)1 << i;
        uint64_t trace[RANGE_AIR_WIDTH];
        range_air_build_trace(&amount, 1, trace, RANGE_AIR_WIDTH);

        /* The bit at position i should be 1; all other bits 0. */
        for (size_t j = 0; j < RANGE_AIR_BITS; j++) {
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
         * amount < p (always true here) this is just amount. */
        check_eq_u64("amount cell mismatch",
                     trace[RANGE_AIR_AMOUNT_OFF], amount);
    }

    /* (5b) An out-of-range power (2^RANGE_AIR_BITS) drops out of the bit
     *      columns entirely: bits all 0, amount cell keeps the canonical
     *      value — the recomposition constraint is what rejects it. */
    {
        uint64_t amount = (uint64_t)1 << RANGE_AIR_BITS;
        uint64_t trace[RANGE_AIR_WIDTH];
        range_air_build_trace(&amount, 1, trace, RANGE_AIR_WIDTH);
        for (size_t j = 0; j < RANGE_AIR_BITS; j++) {
            if (trace[RANGE_AIR_BIT_OFF(j)] != 0) {
                fprintf(stderr,
                        "FAIL: oor 2^%zu: bit[%zu] nonzero\n",
                        RANGE_AIR_BITS, j);
                fail_count++;
            }
        }
        check_eq_u64("oor amount cell keeps canonical value",
                     trace[RANGE_AIR_AMOUNT_OFF], amount);
    }

    /* (6) build_trace honors row_stride > RANGE_AIR_WIDTH. Embed two
     *     amounts with extra padding columns between rows; assert no
     *     bleed-over. Both values are < p, so canonical == raw and the low
     *     RANGE_AIR_BITS bits are the raw low bits. */
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
            for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
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
        printf("BINDING contract: GREEN — 52-bit column layout pinned, runtime behavior consistent\n");
        return 0;
    }
    printf("BINDING contract: RED — %d failure(s)\n", fail_count);
    return 1;
}
