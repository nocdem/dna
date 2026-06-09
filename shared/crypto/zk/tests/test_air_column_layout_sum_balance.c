/**
 * @file test_air_column_layout_sum_balance.c
 * @brief AIR column-layout BINDING contract test for sum_balance (§ 9 F7).
 *
 * Per design doc § 9 F7 + § 12.4: each AIR module MUST ship a binding-
 * contract test that asserts every column position by name. This is the
 * sum_balance-side instance, following the canonical example shipped with
 * range_air (test_air_column_layout_range_air.c).
 *
 * What this test enforces:
 *   1. Compile-time:  the column offset symbols match the values declared in
 *      sum_balance.h. A drift in the offsets → compile error.
 *   2. Runtime:       sum_balance_build_trace places the accumulator at
 *      exactly SUM_BALANCE_ACC_OFF for every row, and range_air's columns
 *      remain at their declared offsets (the unified-trace contract).
 *
 * Build (Makefile):
 *   make build/test_air_column_layout_sum_balance
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
#include "../sum_balance.h"

/* ============================================================================
 * Compile-time binding assertions (C99 negative-array-size trick)
 * ========================================================================== */

#define SB_CT_ASSERT(cond, tag) \
    typedef char sb_ct_assert_##tag[(cond) ? 1 : -1]

/* sum_balance contract. */
SB_CT_ASSERT(SUM_BALANCE_ACC_OFF == 65, acc_offset);
SB_CT_ASSERT(SUM_BALANCE_WIDTH   == 66, width);

/* sum_balance constraint identifiers stable. */
SB_CT_ASSERT(SUM_BALANCE_CONSTRAINT_INIT   == 'I', cid_init);
SB_CT_ASSERT(SUM_BALANCE_CONSTRAINT_UPDATE == 'U', cid_update);
SB_CT_ASSERT(SUM_BALANCE_CONSTRAINT_FINAL  == 'F', cid_final);

/* Range_air contract still holds (the unified trace requires both). */
SB_CT_ASSERT(RANGE_AIR_AMOUNT_OFF == 64, range_amount_offset);
SB_CT_ASSERT(RANGE_AIR_BIT_OFF(0)  == 0,  range_bit0);
SB_CT_ASSERT(RANGE_AIR_BIT_OFF(63) == 63, range_bit63);

/* sum_balance must come AFTER range_air's amount column (no overlap). */
SB_CT_ASSERT(SUM_BALANCE_ACC_OFF > RANGE_AIR_AMOUNT_OFF, acc_after_amount);

/* The unified trace width must contain both modules' columns. */
SB_CT_ASSERT(SUM_BALANCE_WIDTH > SUM_BALANCE_ACC_OFF, width_contains_acc);

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
    fprintf(stderr, "FAIL: %s: got %" PRIu64 ", want %" PRIu64 "\n",
            what, got, want);
    fail_count++;
}

int main(void) {
    printf("test_air_column_layout_sum_balance — design doc § 9 F7 BINDING contract\n");
    printf("----------------------------------------------------------------------\n");

    /* (1) Constant exposure. */
    check_eq_size("SUM_BALANCE_WIDTH",      SUM_BALANCE_WIDTH,      66);
    check_eq_size("SUM_BALANCE_ACC_OFF",    SUM_BALANCE_ACC_OFF,    65);
    check_eq_size("RANGE_AIR_AMOUNT_OFF",   RANGE_AIR_AMOUNT_OFF,   64);

    /* (2) Adjacency: acc sits immediately after amount. */
    check_eq_size("acc immediately follows amount",
                  SUM_BALANCE_ACC_OFF, RANGE_AIR_AMOUNT_OFF + 1);

    /* (3) build_trace places amount and acc at their declared offsets for
     *     a multi-row trace. Uses a small but non-trivial amount set. */
    {
        uint64_t amounts[4] = {10, 20, 30, 40};
        uint64_t trace[4 * SUM_BALANCE_WIDTH];
        for (size_t i = 0; i < sizeof(trace) / sizeof(trace[0]); i++) {
            trace[i] = 0xDEADBEEFDEADBEEFULL;
        }
        sum_balance_build_trace(amounts, 4, trace, SUM_BALANCE_WIDTH);

        /* Per-row checks. */
        uint64_t cumulative = 0;
        for (size_t r = 0; r < 4; r++) {
            uint64_t *row = &trace[r * SUM_BALANCE_WIDTH];
            cumulative += amounts[r];

            /* Amount cell at RANGE_AIR_AMOUNT_OFF (the unified contract). */
            check_eq_u64("amount cell offset",
                         row[RANGE_AIR_AMOUNT_OFF], amounts[r]);

            /* Acc cell at SUM_BALANCE_ACC_OFF — cumulative sum so far. */
            check_eq_u64("acc cell offset",
                         row[SUM_BALANCE_ACC_OFF], cumulative);

            /* Bit cells at RANGE_AIR_BIT_OFF(i) — verify LSB. */
            uint64_t lsb_want = amounts[r] & 1ULL;
            check_eq_u64("bit 0 cell offset",
                         row[RANGE_AIR_BIT_OFF(0)], lsb_want);
        }
    }

    /* (4) build_trace honors row_stride > SUM_BALANCE_WIDTH. Pad cells must
     *     remain untouched (the embedded-AIR composition guarantee). */
    {
        uint64_t amounts[3] = {7, 14, 21};
        const size_t stride = SUM_BALANCE_WIDTH + 5;
        uint64_t buf[3 * (SUM_BALANCE_WIDTH + 5)];
        for (size_t k = 0; k < sizeof(buf) / sizeof(buf[0]); k++) {
            buf[k] = 0xCAFEBABECAFEBABEULL;
        }
        sum_balance_build_trace(amounts, 3, buf, stride);

        uint64_t expected_acc = 0;
        for (size_t r = 0; r < 3; r++) {
            uint64_t *row = &buf[r * stride];
            expected_acc += amounts[r];

            check_eq_u64("strided amount cell",
                         row[RANGE_AIR_AMOUNT_OFF], amounts[r]);
            check_eq_u64("strided acc cell",
                         row[SUM_BALANCE_ACC_OFF], expected_acc);
            for (size_t k = SUM_BALANCE_WIDTH; k < stride; k++) {
                if (row[k] != 0xCAFEBABECAFEBABEULL) {
                    fprintf(stderr,
                            "FAIL: row %zu padding cell %zu overwritten "
                            "(got 0x%016" PRIx64 ")\n", r, k, row[k]);
                    fail_count++;
                }
            }
        }
    }

    /* (5) Single-row build (n == 1) places acc == amount in the same row. */
    {
        uint64_t amount = 12345;
        uint64_t trace[SUM_BALANCE_WIDTH] = {0};
        sum_balance_build_trace(&amount, 1, trace, SUM_BALANCE_WIDTH);
        check_eq_u64("n=1 amount cell", trace[RANGE_AIR_AMOUNT_OFF], 12345);
        check_eq_u64("n=1 acc cell",    trace[SUM_BALANCE_ACC_OFF],  12345);
    }

    /* (6) n == 0 yields no writes (defensive — the function returns early). */
    {
        uint64_t trace[SUM_BALANCE_WIDTH];
        for (size_t k = 0; k < SUM_BALANCE_WIDTH; k++) {
            trace[k] = 0x4242424242424242ULL;
        }
        sum_balance_build_trace(NULL, 0, trace, SUM_BALANCE_WIDTH);
        for (size_t k = 0; k < SUM_BALANCE_WIDTH; k++) {
            if (trace[k] != 0x4242424242424242ULL) {
                fprintf(stderr,
                        "FAIL: n=0 overwrote cell %zu (got 0x%016" PRIx64 ")\n",
                        k, trace[k]);
                fail_count++;
            }
        }
    }

    printf("\n");
    if (fail_count == 0) {
        printf("F7 BINDING contract (sum_balance): GREEN — column layout pinned,\n");
        printf("unified-trace adjacency intact, runtime behavior consistent\n");
        return 0;
    }
    printf("F7 BINDING contract (sum_balance): RED — %d failure(s)\n", fail_count);
    return 1;
}
