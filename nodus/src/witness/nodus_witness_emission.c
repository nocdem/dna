/**
 * v0.16 Stage C.1 — per-block emission implementation.
 *
 * See nodus_witness_emission.h for contract + schedule.
 */

#include "witness/nodus_witness_emission.h"

uint64_t nodus_emission_per_block_ex(uint64_t block_height,
                                     uint64_t blocks_per_year,
                                     uint64_t decimal_unit) {
    /* Not a schedule — and the division below would trap. The load path
     * refuses a zero-valued committed row, so reaching this is either the
     * legacy default (impossible: the macro is 6307200) or a caller bug. */
    if (blocks_per_year == 0) return 0;
    uint64_t year_index = block_height / blocks_per_year;
    if (year_index >= DNAC_HALVING_YEARS) {
        return 1ULL * decimal_unit;             /* perpetual floor        */
    }
    /* 32 >> year_index: 32, 16, 8, 4, 2. */
    return (32ULL >> year_index) * decimal_unit;
}

uint64_t nodus_emission_per_block(uint64_t block_height) {
    /* The compiled-constant instance of the SAME curve — one body, so the
     * parameterized and default answers cannot drift apart. */
    return nodus_emission_per_block_ex(block_height, DNAC_BLOCKS_PER_YEAR,
                                       DNAC_DECIMAL_UNIT);
}

uint64_t nodus_emission_total_minted(uint64_t block_height,
                                     uint64_t start_block) {
    if (start_block == 0 || block_height < start_block) return 0;

    uint64_t total = 0;

    /* Whole/partial halving windows [yi*BY, (yi+1)*BY - 1], yi = 0..4,
     * intersected with the minted range [start_block, block_height].
     * Each window's per-block reward is (32 >> yi) DNAC. */
    for (uint64_t yi = 0; yi < DNAC_HALVING_YEARS; yi++) {
        uint64_t win_lo = yi * DNAC_BLOCKS_PER_YEAR;
        uint64_t win_hi = win_lo + DNAC_BLOCKS_PER_YEAR - 1;
        uint64_t lo = win_lo < start_block ? start_block : win_lo;
        uint64_t hi = win_hi > block_height ? block_height : win_hi;
        if (lo > hi) continue;
        uint64_t reward = (32ULL >> yi) * DNAC_DECIMAL_UNIT;
        uint64_t add = reward * (hi - lo + 1);   /* <= 32e8 * 6.3e6, no wrap */
        if (add > UINT64_MAX - total) return UINT64_MAX;
        total += add;
    }

    /* Perpetual floor tail [5*BY, block_height], reward = 1 DNAC/block. */
    uint64_t floor_lo = DNAC_HALVING_YEARS * DNAC_BLOCKS_PER_YEAR;
    if (floor_lo < start_block) floor_lo = start_block;
    if (block_height >= floor_lo) {
        uint64_t blocks = block_height - floor_lo + 1;
        if (blocks > (UINT64_MAX - total) / DNAC_EMISSION_FLOOR)
            return UINT64_MAX;
        total += blocks * DNAC_EMISSION_FLOOR;
    }
    return total;
}
