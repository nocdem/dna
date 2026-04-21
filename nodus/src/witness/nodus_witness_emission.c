/**
 * v0.16 Stage C.1 — per-block emission implementation.
 *
 * See nodus_witness_emission.h for contract + schedule.
 */

#include "witness/nodus_witness_emission.h"

uint64_t nodus_emission_per_block(uint64_t block_height) {
    uint64_t year_index = block_height / DNAC_BLOCKS_PER_YEAR;
    if (year_index >= DNAC_HALVING_YEARS) {
        return DNAC_EMISSION_FLOOR;
    }
    /* 32 >> year_index: 32, 16, 8, 4, 2. */
    return (32ULL >> year_index) * DNAC_DECIMAL_UNIT;
}
