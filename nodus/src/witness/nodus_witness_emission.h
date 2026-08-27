/**
 * @file nodus_witness_emission.h
 * @brief v0.16 Stage C.1 — deterministic per-block emission schedule.
 *
 * Replaces the accumulator-driven reward pipeline. The halving curve
 * is hardcoded (32 → 16 → 8 → 4 → 2 → 1 DNAC/block, one halving per
 * DNAC_BLOCKS_PER_YEAR, perpetual 1 DNAC floor after year 5). Keeping
 * the schedule hardcoded (NOT chain_config-parameterized) means a
 * committee vote cannot alter emission rate — activation-block is the
 * only governance surface (Hard-Fork v1 INFLATION_START_BLOCK).
 *
 * Design: 2026-04-21-reward-tokenomics-redesign-design.md §1.2.
 */

#ifndef NODUS_WITNESS_EMISSION_H
#define NODUS_WITNESS_EMISSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Blocks per tokenomic year at the canonical 5s block interval.
 *
 *  O15B.1 — guarded so a harness build can compile a SHORT tokenomic
 *  year (-DDNAC_BLOCKS_PER_YEAR=20) and actually cross a halving
 *  boundary; at the production value the first one sits 6.3M blocks out
 *  and `test_halving_boundaries` could never run. Same idiom this file
 *  already uses for DNAC_DECIMAL_UNIT, and dnac.h for
 *  DNAC_EPOCH_LENGTH. Production builds never define it, so the value
 *  below is the only one that ships. */
#ifndef DNAC_BLOCKS_PER_YEAR
#define DNAC_BLOCKS_PER_YEAR   6307200ULL
#endif

/** Halving boundary count. Year 0 = 32, year 1 = 16, ... year 5+ = floor. */
#define DNAC_HALVING_YEARS     5

/** Smallest unit: 1 DNAC = 10^8 raw. */
#ifndef DNAC_DECIMAL_UNIT
#define DNAC_DECIMAL_UNIT      100000000ULL
#endif

/** Y1 emission per block (32 DNAC × 10^8 raw). */
#define DNAC_EMISSION_BASE     (32ULL * DNAC_DECIMAL_UNIT)

/** Perpetual floor after 5 halvings (1 DNAC × 10^8 raw). */
#define DNAC_EMISSION_FLOOR    (1ULL * DNAC_DECIMAL_UNIT)

/**
 * Deterministic emission at a given absolute block height.
 *
 *   year_index = block_height / DNAC_BLOCKS_PER_YEAR
 *   year_index == 0: 32 DNAC   (Y1)
 *   year_index == 1: 16 DNAC   (Y2)
 *   year_index == 2:  8 DNAC   (Y3)
 *   year_index == 3:  4 DNAC   (Y4)
 *   year_index == 4:  2 DNAC   (Y5)
 *   year_index >= 5:  1 DNAC   (perpetual floor)
 *
 * The schedule is per-block (not per-wall-clock), so changing the
 * block interval via chain_config DNAC_CFG_BLOCK_INTERVAL_SEC does
 * NOT shift the curve — the halving boundaries stay at fixed block
 * heights. Pure function; deterministic across all witnesses.
 */
uint64_t nodus_emission_per_block(uint64_t block_height);

/**
 * The same schedule, evaluated against EXPLICIT parameters instead of the
 * compiled DNAC_BLOCKS_PER_YEAR / DNAC_DECIMAL_UNIT.
 *
 * O15J Faz 2 Block 2C — the reason this exists. Both macros are
 * `#ifndef`-guarded, so `-D` at compile time changes how much a node
 * mints, and the Stage F halving test expects exactly such a build:
 * it requires a binary carrying -DDNAC_BLOCKS_PER_YEAR=<BY> and SKIPs
 * (exit 99) when the value is not declared
 * (nodus/tests/integration/stagef/tests/test_halving_boundaries.sh:37,
 * :57-65). The override is operator-supplied, not a fixed constant.
 * On a PURE-V2 chain those two values are committed at genesis
 * (nodus_chain_config.h's reserved econ band) and
 * nodus_witness_v2_emission_apply feeds the COMMITTED values in here, so
 * the chain's own genesis decides the curve rather than whichever binary
 * happens to be running. `nodus_emission_per_block` above is exactly this
 * function applied to the compiled constants, and remains the entry point
 * for the legacy lane and for chains that committed nothing.
 *
 * `blocks_per_year == 0` returns 0: it is not a schedule, and dividing by
 * it would trap. Callers must treat a 0 answer at a height that should
 * mint as a fault, never as "this height mints nothing" — which is why
 * the load path refuses a zero-valued committed row before it ever gets
 * here.
 *
 * Pure and deterministic in both parameters.
 */
uint64_t nodus_emission_per_block_ex(uint64_t block_height,
                                     uint64_t blocks_per_year,
                                     uint64_t decimal_unit);

/**
 * Cumulative DNAC minted, in raw units, by summing
 * nodus_emission_per_block(h) over every minted height h in
 * [start_block, block_height] inclusive — the EXACT total the live
 * per-block mint accrues (nodus_witness_bft.c finalize_block mints
 * emission at every height >= inflation_start; genesis height 0 is not
 * minted when start_block >= 1).
 *
 *   start_block == 0 (inflation disabled) or block_height < start_block
 *     -> 0
 *
 * This is the 32-curve counterpart of the retired dnac_total_minted_at
 * (dnac.h, 16-curve). Deterministic, pure, checked (saturates at
 * UINT64_MAX rather than wrapping). Used by the advisory supply
 * diagnostic; it is NOT a consensus gate (the HARD gate is bookkeeping-
 * closed and does not consult a mint curve at all).
 */
uint64_t nodus_emission_total_minted(uint64_t block_height,
                                     uint64_t start_block);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_EMISSION_H */
