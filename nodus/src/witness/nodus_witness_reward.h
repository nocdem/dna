/**
 * Nodus — Witness Reward CRUD
 *
 * SQLite CRUD primitives over the `rewards` table (design §3.7).
 * One row per validator, keyed by validator_hash where
 *
 *     validator_hash = SHA3-512(0x04 || validator_pubkey)
 *
 * (NODUS_TREE_TAG_REWARD = 0x04 per §3.4.)
 *
 * The row holds the validator's per-unit reward accumulator (u128 BE,
 * 18-decimal fixed-point), the validator-specific unclaimed balance
 * (self-stake share + commission skim), and the truncation-dust carry
 * (F-ECON-04 / F-STATE-09).
 *
 * Scope (Task 13):
 *   - upsert (insert or update)
 *   - get by validator pubkey
 *   - delete (invoked when validator graduates to UNSTAKED status)
 *
 * @file nodus_witness_reward.h
 */

#ifndef NODUS_WITNESS_REWARD_H
#define NODUS_WITNESS_REWARD_H

#include "witness/nodus_witness.h"
#include "dnac/validator.h"   /* dnac_reward_record_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Insert or update a reward row for the validator in `r`. If a row
 * already exists for the validator (PK = SHA3-512(0x04 || pubkey)),
 * all non-PK fields are replaced.
 *
 * @return 0 on success, -1 on error.
 */
int nodus_reward_upsert(nodus_witness_t *w,
                         const dnac_reward_record_t *r);

/**
 * Fetch a reward row by validator pubkey.
 *
 * @return 0 if found, 1 if not found, -1 on error.
 */
int nodus_reward_get(nodus_witness_t *w,
                      const uint8_t *validator_pubkey,
                      dnac_reward_record_t *out);

/**
 * Delete a reward row. Called when a validator graduates to the
 * UNSTAKED terminal status and the row is no longer observable.
 *
 * @return 0 on success, 1 if not found, -1 on error.
 */
int nodus_reward_delete(nodus_witness_t *w,
                         const uint8_t *validator_pubkey);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_REWARD_H */
