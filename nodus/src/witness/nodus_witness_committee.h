/**
 * Nodus — Witness Committee Election (Phase 10)
 *
 * Deterministic committee computation per design §3.6.
 *
 * Selection rule:
 *   lookback_block = E_start - EPOCH_LENGTH - 1
 *   snapshot_root  = block_at(lookback_block).validator_tree_root
 *   state_seed     = block_at(lookback_block).state_root
 *   tenure_anchor  = E_start        (S3 fix — see committee.c; the old
 *                    lookback anchor made epochs (E, 3E] unsatisfiable
 *                    even for the genesis seed set, and the empty result
 *                    silently fell back to the gossip roster pre-S3)
 *
 *   eligible = validators with
 *     status IN (ACTIVE, ELIGIBLE)            // S3: both are BONDED
 *     AND (active_since_block + MIN_TENURE_BLOCKS <= E_start
 *          OR active_since_block <= 1)   — genesis seed set: always tenured
 *
 *   rank by (self_stake + external_delegated) DESC,
 *   tiebreak by SHA3-512(0x02 || pubkey || state_seed) ASC (byte-lex).
 *
 *   committee = eligible[:target]
 *
 * S3: the cut is `target`, not a literal 7 — see
 * nodus_committee_compute_for_epoch below. `target` is the
 * DNAC_CFG_TARGET_ACTIVE_COUNT chain-config value read at the epoch
 * START height, defaulting to DNAC_COMMITTEE_SIZE. Status ACTIVE vs
 * ELIGIBLE is the marker for "was in the previous boundary's set"; both
 * are candidates here, so a validator that sat out one epoch is not
 * excluded from the next.
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
 * for BFT roster + reward distribution math.
 *
 * `self_stake` (Ledger V2 S3) carries the validator's OWN bond into the
 * validator-set snapshot (shared/dnac/vset_wire.h self_bond). Every
 * producer reports the REAL bond: compute_for_epoch and
 * bootstrap_for_epoch read it from the validator record, and
 * nodus_committee_get_for_block serves it from the
 * cached_committee_self_stakes parallel array on a cache hit. The
 * earlier "0 on the cached path" pin is GONE — a cache hit and a cache
 * miss now produce identical members. */
typedef struct {
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];
    uint64_t total_stake;        /* self_stake + external_delegated (snapshot) */
    uint64_t self_stake;         /* the validator's own bond               */
    uint16_t commission_bps;
} nodus_committee_member_t;

/**
 * Compute the committee for the epoch starting at e_start using the
 * post-commit lookback rule (design §3.6).
 *
 * For e_start >= EPOCH_LENGTH + 1 the helper reads state_root of
 * block (e_start - EPOCH_LENGTH - 1) as state_seed and ranks the bonded
 * (ACTIVE or ELIGIBLE) + MIN_TENURE-gated validators. For earlier epochs
 * the bootstrap variant is invoked internally.
 *
 * ── S3: THE SET SIZE COMES FROM CHAIN STATE ────────────────────────────
 * The per-epoch target is derived INTERNALLY, not from max_entries:
 *
 *     nodus_chain_config_get_u64(w, DNAC_CFG_TARGET_ACTIVE_COUNT,
 *                                e_start, DNAC_COMMITTEE_SIZE, &target)
 *                   clamped to [1, DNAC_MAX_ACTIVE_VALIDATORS]
 *     final_count = min(cand_count, target, max_entries)
 *
 * The lookup is keyed on `e_start` — NOT on the querying block height —
 * so every block of an epoch sees ONE value and a chain_config row whose
 * effective_block falls mid-epoch cannot resize a live committee.
 * nodus_chain_config_get_u64 reads committed chain_config_history rows,
 * which is the same deterministic, cross-node source the
 * INFLATION_START_BLOCK consumer already uses in finalize_block
 * (nodus_witness_bft.c).
 *
 * O15J Block 2 (A2) — the lookup is THREE-VALUED and this function fails
 * closed on its fault code. "No governance row" (every chain today) still
 * yields DNAC_COMMITTEE_SIZE and selects exactly as before; "the override
 * is unreadable" now returns -1 instead of quietly selecting a
 * default-sized committee that a healthy peer would not have selected.
 *
 * max_entries remains a pure BUFFER capacity: it can only shrink the
 * result, never grow it past the chain-derived target.
 *
 * @param w           Witness context (DB must be open)
 * @param e_start     Epoch start block height
 * @param out         Caller-allocated array of >= max_entries members
 * @param max_entries out[] capacity (heap-size it to DNAC_MAX_ACTIVE_VALIDATORS)
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

/**
 * Heap-allocating wrapper around nodus_committee_get_for_block (S3).
 *
 * nodus_committee_member_t is 2608 B, so a DNAC_MAX_ACTIVE_VALIDATORS
 * array is ~334 KB — far past any stack budget in this tree. Every
 * consumer that used to declare `nodus_committee_member_t x[DNAC_COMMITTEE_SIZE]`
 * on the stack calls this instead, so the ceiling lives in exactly one
 * place.
 *
 * On success *members_out is a calloc'd array of DNAC_MAX_ACTIVE_VALIDATORS
 * entries (NOT of *count_out entries) which the caller MUST free() on
 * every path. On failure *members_out is NULL, *count_out is 0, and
 * there is nothing to free.
 *
 * @return 0 on success, -1 on allocation or lookup error.
 */
int nodus_committee_get_for_block_alloc(nodus_witness_t *w,
                                          uint64_t block_height,
                                          nodus_committee_member_t **members_out,
                                          int *count_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_COMMITTEE_H */
