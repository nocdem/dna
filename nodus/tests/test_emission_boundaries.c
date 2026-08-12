/*
 * v0.16 Stage C.1 — emission_per_block halving-boundary KAT.
 *
 * All 5 halving boundaries plus the perpetual floor far into the
 * future. Any off-by-one on year_index = block_height / BLOCKS_PER_YEAR
 * flips exactly one of these checks. Red-team finding RT-C2.
 */

#include "witness/nodus_witness_emission.h"

#include <stdio.h>

#define CHECK_EQ(a, b) do { \
    uint64_t _a = (uint64_t)(a); \
    uint64_t _b = (uint64_t)(b); \
    if (_a != _b) { \
        fprintf(stderr, "FAIL %s:%d: got %llu, want %llu\n", \
                __FILE__, __LINE__, \
                (unsigned long long)_a, (unsigned long long)_b); \
        return 1; \
    } \
} while (0)

int main(void) {
    const uint64_t BY = DNAC_BLOCKS_PER_YEAR;
    const uint64_t UNIT = DNAC_DECIMAL_UNIT;

    /* Year 0 — block 0 and the last block of year 0. */
    CHECK_EQ(nodus_emission_per_block(0),          32ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(1),          32ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(BY - 1),     32ULL * UNIT);

    /* Y1 → Y2 halving at block BY. */
    CHECK_EQ(nodus_emission_per_block(BY),         16ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(2 * BY - 1), 16ULL * UNIT);

    /* Y2 → Y3. */
    CHECK_EQ(nodus_emission_per_block(2 * BY),      8ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(3 * BY - 1),  8ULL * UNIT);

    /* Y3 → Y4. */
    CHECK_EQ(nodus_emission_per_block(3 * BY),      4ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(4 * BY - 1),  4ULL * UNIT);

    /* Y4 → Y5. */
    CHECK_EQ(nodus_emission_per_block(4 * BY),      2ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(5 * BY - 1),  2ULL * UNIT);

    /* Y5 → floor (1 DNAC perpetual). */
    CHECK_EQ(nodus_emission_per_block(5 * BY),      1ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(5 * BY + 1),  1ULL * UNIT);

    /* Far future — still floor. */
    CHECK_EQ(nodus_emission_per_block(10 * BY),     1ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(1000 * BY),   1ULL * UNIT);
    CHECK_EQ(nodus_emission_per_block(UINT64_MAX / 2), 1ULL * UNIT);

    /* Aggregate sanity: Y1 full year = 32 DNAC/block × BY blocks =
     * 32 × BY × 10^8 raw. Check the math by summing a small window. */
    uint64_t sum = 0;
    for (uint64_t h = 0; h < 10; h++) sum += nodus_emission_per_block(h);
    CHECK_EQ(sum, 10 * 32ULL * UNIT);

    /* ── nodus_emission_total_minted: the advisory's 32-curve cumulative.
     * BRUTE-FORCE EQUIVALENCE — the closed-form window arithmetic MUST
     * equal Σ nodus_emission_per_block(h) block-by-block, at every
     * halving boundary and across the perpetual floor (6+ years). This
     * is the property the advisory supply diagnostic relies on. */
    {
        uint64_t brute = 0;
        for (uint64_t h = 1; h <= 6 * BY + 137; h++) {
            brute += nodus_emission_per_block(h);
            /* spot-check the closed form at boundaries + a scatter of
             * offsets, all against the running brute sum (start = 1) */
            if (h == 1 || h == BY - 1 || h == BY || h == BY + 1 ||
                h == 2 * BY || h == 3 * BY || h == 4 * BY ||
                h == 5 * BY - 1 || h == 5 * BY || h == 5 * BY + 1 ||
                h == 6 * BY || h == 6 * BY + 137)
                CHECK_EQ(nodus_emission_total_minted(h, 1ULL), brute);
        }
        /* disabled / out-of-range contract */
        CHECK_EQ(nodus_emission_total_minted(1000, 0ULL), 0ULL);
        CHECK_EQ(nodus_emission_total_minted(5, 10ULL), 0ULL);
        /* start_block > 1: a window that begins mid-curve (blocks
         * [BY, 2*BY-1] all at 16 DNAC) */
        CHECK_EQ(nodus_emission_total_minted(2 * BY - 1, BY),
                 (uint64_t)BY * 16ULL * UNIT);
        /* whole first five halving windows, start = 0 excluded via
         * start = 1: block 0 is not minted, so Y1 window contributes
         * (BY-1) blocks at 32 DNAC — proven equal to the brute sum
         * above; here assert the full-through-floor cumulative at the
         * 5*BY boundary equals 32-curve five-year total minus block 0 */
        {
            uint64_t y5 = nodus_emission_total_minted(5 * BY - 1, 1ULL);
            uint64_t expect = ((uint64_t)BY - 1) * 32ULL * UNIT      /* Y1 */
                            + (uint64_t)BY * 16ULL * UNIT            /* Y2 */
                            + (uint64_t)BY *  8ULL * UNIT            /* Y3 */
                            + (uint64_t)BY *  4ULL * UNIT            /* Y4 */
                            + (uint64_t)BY *  2ULL * UNIT;           /* Y5 */
            CHECK_EQ(y5, expect);
        }
    }

    printf("test_emission_boundaries: ALL CHECKS PASSED\n");
    return 0;
}
