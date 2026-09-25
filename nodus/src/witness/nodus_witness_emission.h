/**
 * @file nodus_witness_emission.h
 * @brief The two economic unit constants the committed econ band pins —
 *        and NOTHING that mints.
 *
 * ── tokenomics-v3 P2: THERE IS NO EMISSION ANY MORE ─────────────────
 * This header used to carry the v0.16 per-block emission schedule — the
 * 32 → 16 → 8 → 4 → 2 → 1 DNAC/block halving curve (DNAC_EMISSION_BASE,
 * DNAC_EMISSION_FLOOR, DNAC_HALVING_YEARS) and its three functions
 * nodus_emission_per_block / nodus_emission_per_block_ex /
 * nodus_emission_total_minted (nodus_witness_emission.c). The operator's
 * decision (docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-
 * operator.md §1: "Toplam arz 1.000.000.000 NODUS, sabit. Yeni token
 * basılmayacak"; §3 S-4: "blok başı basım kodu SİLİNİR") deletes the
 * mint; the curve, its constants, the three functions and their source
 * file are DELETED with it (No Dead Code), and validator rewards come
 * from the fixed reward reserve (nodus_witness_v2_econ.h).
 *
 * What survives are the two unit constants below. They are still
 * COMMITTED BUILD IDENTITY: the pure-V2 genesis builder writes both into
 * the chain_config_history econ band (nodus_chain_config.h,
 * NODUS_CC_ECON_*) and refuses a config whose values differ from these
 * (nodus_witness_v2_gen.c gen_plan_build), and DNAC_DECIMAL_UNIT is the
 * voting-power unit (power = total_stake / DNAC_DECIMAL_UNIT — the
 * cometbft ValidatorUpdate, Rule N's weight floor, the reward
 * distribution). The file name is kept so the many includers do not
 * move in the same change.
 */

#ifndef NODUS_WITNESS_EMISSION_H
#define NODUS_WITNESS_EMISSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Blocks per tokenomic year at the canonical 5 s block interval — the
 *  period of the retired halving curve, still committed as the econ
 *  band's NODUS_CC_ECON_BLOCKS_PER_YEAR.
 *
 *  O15B.1 — guarded so a harness build can compile a short value; the
 *  genesis builder refuses a config that disagrees with the compiled
 *  one. Production builds never define it, so the value below is the
 *  only one that ships. */
#ifndef DNAC_BLOCKS_PER_YEAR
#define DNAC_BLOCKS_PER_YEAR   6307200ULL
#endif

/** Smallest unit: 1 DNAC = 10^8 raw. Also the voting-power unit. */
#ifndef DNAC_DECIMAL_UNIT
#define DNAC_DECIMAL_UNIT      100000000ULL
#endif

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_EMISSION_H */
