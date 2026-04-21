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

    printf("test_emission_boundaries: ALL CHECKS PASSED\n");
    return 0;
}
