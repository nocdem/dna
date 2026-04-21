/**
 * @file validator.h
 * @brief DNAC - Validator / Delegation / Reward Merkle-tree record types
 *
 * Defines the three Merkle-tree leaf record structs used by the
 * witness stake & delegation v1 system:
 *
 * - dnac_validator_record_t  (validator tree, one leaf per validator)
 * - dnac_delegation_record_t (delegation tree, one leaf per (delegator, validator) pair)
 * - dnac_reward_record_t     (reward accumulator tree, one leaf per validator)
 *
 * Field layouts are frozen — they feed the deterministic CBOR serializer
 * which in turn feeds the Merkle leaf hashes. Any reorder is consensus-breaking.
 *
 * See design spec: dnac/docs/plans/2026-04-17-witness-stake-delegation-design.md
 * (§3.2 validator, §3.3 delegation, §3.4 reward).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_VALIDATOR_H
#define DNAC_VALIDATOR_H

#include <stdint.h>
#include <stddef.h>

#include "dnac/dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Validator Status
 * ========================================================================== */

/**
 * @brief Validator lifecycle status.
 *
 * Values are wire-stable — serialized as a single byte in the validator record
 * and used across CBOR, Merkle, and TX pipelines. Do not renumber.
 */
typedef enum {
    DNAC_VALIDATOR_ACTIVE       = 0,  /**< Eligible for committee selection. */
    DNAC_VALIDATOR_RETIRING     = 1,  /**< UNSTAKE requested, cooldown in progress. */
    DNAC_VALIDATOR_UNSTAKED     = 2,  /**< Cooldown complete, self-stake withdrawn. */
    DNAC_VALIDATOR_AUTO_RETIRED = 3   /**< Auto-retired (Rule N liveness failure). */
} dnac_validator_status_t;

/* ============================================================================
 * Validator Record — design §3.2
 * ========================================================================== */

/**
 * @brief Validator tree leaf value.
 *
 * One record per validator, keyed by Dilithium5 pubkey hash. Field order is
 * consensus-critical — it defines the CBOR serialization order and therefore
 * the Merkle leaf hash.
 */
typedef struct {
    /** Validator Dilithium5 pubkey (used for SPEND verify of the locked self-stake UTXO). */
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];

    /** Always DNAC_SELF_STAKE_AMOUNT while active; zeroed post-UNSTAKE. */
    uint64_t self_stake;

    /** Σ of all delegations to this validator (includes self if Rule S ever lifted). */
    uint64_t total_delegated;

    /** Σ of delegations where delegator != validator — used for committee ranking. */
    uint64_t external_delegated;

    /** Current commission rate, basis points (0–10000). */
    uint16_t commission_bps;

    /** Pending commission rate (0 = no pending change). */
    uint16_t pending_commission_bps;

    /** Block height at which pending_commission_bps takes effect (0 = no pending). */
    uint64_t pending_effective_block;

    /** dnac_validator_status_t value. */
    uint8_t  status;

    /** Block height when validator entered ACTIVE status. */
    uint64_t active_since_block;

    /** Block height when UNSTAKE was committed (0 if not unstaking). */
    uint64_t unstake_commit_block;

    /** Fingerprint that receives the post-cooldown UTXO. */
    uint8_t  unstake_destination_fp[DNAC_FINGERPRINT_SIZE];

    /** Pubkey used to SPEND the locked self-stake UTXO after cooldown. */
    uint8_t  unstake_destination_pubkey[DNAC_PUBKEY_SIZE];

    /** Last block where a VALIDATOR_UPDATE from this validator was accepted (Rule K cooldown). */
    uint64_t last_validator_update_block;

    /** Consecutive epochs where liveness threshold was missed (Rule N). */
    uint64_t consecutive_missed_epochs;

    /** Block height of the most recent block this validator signed. */
    uint64_t last_signed_block;
} dnac_validator_record_t;

/* ============================================================================
 * Delegation Record — design §3.3
 * ========================================================================== */

/**
 * @brief Delegation tree leaf value.
 *
 * One record per (delegator, validator) pair. Tracks the delegated amount
 * and the block it was created/updated at (for Rule O min-hold enforcement).
 */
typedef struct {
    /** Delegator Dilithium5 pubkey. */
    uint8_t  delegator_pubkey[DNAC_PUBKEY_SIZE];

    /** Target validator Dilithium5 pubkey. */
    uint8_t  validator_pubkey[DNAC_PUBKEY_SIZE];

    /** Delegated amount in raw units (8 decimals). */
    uint64_t amount;

    /** Block height this delegation was created/last-modified (Rule O min-hold tracker). */
    uint64_t delegated_at_block;

    /** Snapshot of validator reward accumulator at last claim (u128 big-endian). */
    uint8_t  reward_snapshot[16];
} dnac_delegation_record_t;

/* ============================================================================
 * Reward Record — design §3.4
 * ========================================================================== */

/**
 * @brief Reward accumulator tree leaf value.
 *
 * One record per validator. Holds the per-unit reward accumulator (u128 BE,
 * 18-decimal fixed-point) that delegators snapshot at claim time, plus the
 * validator-specific unclaimed balance (self-stake share + commission skim)
 * and truncation dust carry (per F-ECON-04 / F-STATE-09).
 */
typedef struct {
    /** Validator Dilithium5 pubkey. */
    uint8_t  validator_pubkey[DNAC_PUBKEY_SIZE];

    /** Per-unit reward accumulator, u128 big-endian, 18-decimal fixed-point. */
    uint8_t  accumulator[16];

    /** Validator's unclaimed balance: self-stake share + commission skim. */
    uint64_t validator_unclaimed;

    /** Block height the accumulator was last updated. */
    uint64_t last_update_block;

    /** Truncation dust carry (F-ECON-04 / F-STATE-09). */
    uint64_t residual_dust;
} dnac_reward_record_t;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_VALIDATOR_H */
