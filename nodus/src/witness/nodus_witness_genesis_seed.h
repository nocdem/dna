/**
 * @file nodus_witness_genesis_seed.h
 * @brief Phase 12 Task 57 — seed validator_tree + reward_tree from
 *        genesis chain_def at commit time.
 *
 * On genesis commit, the GENESIS TX carries a chain_def trailer whose
 * initial_validators[] block lists the 7 bootstrap committee members.
 * This helper inserts one dnac_validator_record_t + dnac_reward_record_t
 * per entry and sets validator_stats.active_count = count.
 *
 * The parse is inline (does NOT link against libdna) — we only need the
 * initial_validators trailer, not the full chain_def_decode. Layout is
 * pinned by Task 56's chain_def_codec.c.
 */

#ifndef NODUS_WITNESS_GENESIS_SEED_H
#define NODUS_WITNESS_GENESIS_SEED_H

#include "witness/nodus_witness.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Seed validator_tree + reward_tree from the initial_validators[] section
 * of the genesis chain_def blob.
 *
 * @param w              Witness handle (must be in an open DB transaction).
 * @param cd_blob        Raw dnac_chain_def_encode output (MUST include the
 *                       Task-56 initial_validators trailer).
 * @param cd_blob_len    Length of cd_blob in bytes.
 * @return 0 on success (or when no initial_validators trailer is present),
 *         -1 on parse error, DB error, or invalid initial_validator_count.
 *
 * Side effects:
 *   - Inserts N dnac_validator_record_t rows (status=ACTIVE,
 *     active_since_block=1, self_stake=DNAC_SELF_STAKE_AMOUNT).
 *   - Inserts N empty dnac_reward_record_t rows (accumulator=0,
 *     last_update_block=1).
 *   - Sets validator_stats.active_count = N.
 *
 * For a zero initial_validator_count (legacy chain_def), returns 0
 * without side effects — allows old test vectors to continue working.
 */
int nodus_witness_genesis_seed_validators(nodus_witness_t *w,
                                            const uint8_t *cd_blob,
                                            size_t cd_blob_len);

/**
 * Parse the supply-accounting fields out of a genesis chain_def blob.
 *
 * @param cd_blob                      Raw dnac_chain_def_encode output.
 * @param cd_blob_len                  Length of cd_blob in bytes.
 * @param initial_supply_raw_out       On success, gross supply per chain_def.
 * @param initial_validator_count_out  On success, number of bootstrap validators.
 * @return 0 on success, -1 on parse error / truncation.
 *
 * Used by Rule P.2 enforcement on the witness side (genesis ghost stake fix,
 * 2026-04-19). Pure read-only — no DB touch.
 */
int nodus_witness_parse_cd_supply(const uint8_t *cd_blob, size_t cd_blob_len,
                                    uint64_t *initial_supply_raw_out,
                                    uint8_t  *initial_validator_count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_GENESIS_SEED_H */
