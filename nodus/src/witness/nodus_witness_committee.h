/**
 * Nodus — Witness Committee Election (Phase 10)
 *
 * Deterministic committee computation per design §3.6.
 *
 * Selection rule:
 *   lookback_block = E_start - EPOCH_LENGTH - 1
 *   snapshot_root  = block_at(lookback_block).validator_tree_root
 *   state_seed     = block_at(lookback_block).state_root
 *
 *   eligible = validators with
 *     status == ACTIVE
 *     AND active_since_block + MIN_TENURE_BLOCKS <= lookback_block
 *
 *   rank by (self_stake + external_delegated) DESC,
 *   tiebreak by SHA3-512(0x02 || pubkey || state_seed) ASC (byte-lex).
 *
 *   committee = eligible[:7]
 *
 * The state_seed tiebreak (F-CRYPTO-11) prevents pubkey-grinding attacks:
 * priority changes every epoch.
 *
 * During bootstrap (first epochs after genesis where lookback would
 * underflow) the committee comes from genesis-seeded validators with the
 * MIN_TENURE gate relaxed — see nodus_committee_bootstrap_for_epoch.
 *
 * @file nodus_witness_committee.h
 */

#ifndef NODUS_WITNESS_COMMITTEE_H
#define NODUS_WITNESS_COMMITTEE_H

#include "witness/nodus_witness.h"
#include "dnac/validator.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Committee member entry — subset of dnac_validator_record_t sufficient
 * for BFT roster + reward distribution math. */
typedef struct {
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];
    uint64_t total_stake;        /* self_stake + external_delegated (snapshot) */
    uint16_t commission_bps;
} nodus_committee_member_t;

/**
 * Compute the committee for the epoch starting at e_start using the
 * post-commit lookback rule (design §3.6).
 *
 * For e_start >= EPOCH_LENGTH + 1 the helper reads state_root of
 * block (e_start - EPOCH_LENGTH - 1) as state_seed and ranks the ACTIVE
 * + MIN_TENURE-gated validators. For earlier epochs the bootstrap
 * variant is invoked internally.
 *
 * @param w           Witness context (DB must be open)
 * @param e_start     Epoch start block height
 * @param out         Caller-allocated array of >= max_entries members
 * @param max_entries out[] capacity (usually DNAC_COMMITTEE_SIZE)
 * @param count_out   [out] Number of members populated (may be < max_entries)
 * @return 0 on success, -1 on error
 */
int nodus_committee_compute_for_epoch(nodus_witness_t *w,
                                        uint64_t e_start,
                                        nodus_committee_member_t *out,
                                        int max_entries,
                                        int *count_out);

/**
 * Bootstrap path for epochs too young to use the post-commit lookback
 * rule (e_start < EPOCH_LENGTH + 1). Uses the genesis block's state_root
 * as state_seed and admits every ACTIVE validator regardless of
 * MIN_TENURE (the gate is meaningless on a fresh chain).
 *
 * Task 52: DB-query implementation; Task 56 will add optional
 * chain_def.initial_validators resolution once the field exists.
 *
 * @return 0 on success, -1 on error.
 */
int nodus_committee_bootstrap_for_epoch(nodus_witness_t *w,
                                          uint64_t e_start,
                                          nodus_committee_member_t *out,
                                          int max_entries,
                                          int *count_out);

/**
 * Return the committee active for a given block height, consulting the
 * per-epoch cache on *w. Computes + caches on first call within an
 * epoch; subsequent calls in the same epoch return the cached result.
 *
 * Task 53: cache consumer + populator.
 *
 * @return 0 on success, -1 on error.
 */
int nodus_committee_get_for_block(nodus_witness_t *w,
                                    uint64_t block_height,
                                    nodus_committee_member_t *out,
                                    int max_entries,
                                    int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_COMMITTEE_H */
