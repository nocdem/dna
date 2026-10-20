/**
 * @file verify.c
 * @brief Transaction verification
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include "dnac/safe_math.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

/* libdna crypto utilities */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "DNAC_VERIFY"

/* Zero-filled token_id buffer — matches a native DNAC input/output. */
static const uint8_t DNAC_NATIVE_TOKEN_ID[DNAC_TOKEN_ID_SIZE] = {0};

/**
 * @brief Verify STAKE-type rules (design §2.4, Phase 6 Task 22).
 *
 * Enforces the locally-verifiable subset of the STAKE rule set — rules
 * that a client can check without access to the witness validator_tree
 * database:
 *
 *   - signer_count == 1
 *   - commission_bps <= DNAC_COMMISSION_BPS_MAX
 *   - purpose_tag == DNAC_STAKE_PURPOSE_TAG (defense-in-depth; the wire
 *     layer already rejects mismatches at deserialize time, see Task 16)
 *   - sum(DNAC inputs) >= DNAC_SELF_STAKE_AMOUNT + sum(DNAC outputs)
 *     (equivalently: inputs >= 10M + outputs, which implicitly covers
 *      "inputs >= 10M + fee" for any non-negative fee since
 *      fee == inputs − outputs − 10M)
 *
 * Rules I (pubkey NOT in validator_tree) and M (|validator_tree| < 128)
 * require DB access and are enforced by the witness at state-apply time
 * — Phase 8 Task 40 territory.
 *
 * The stricter "outputs == inputs − 10M − fee" equality check requires
 * knowing the fee externally; the witness enforces the exact fee value
 * against its mempool schedule separately. Client-side can only verify
 * the inequality bound — a TX satisfying the inequality implies SOME
 * non-negative fee == inputs − outputs − 10M is consistent; the witness
 * validates whether that value matches policy.
 */
static int verify_stake_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "STAKE: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* commission_bps <= DNAC_COMMISSION_BPS_MAX (5000 since tokenomics-v3
     * P3-8 — the same macro the witness checks) */
    if (tx->stake_fields.commission_bps > DNAC_COMMISSION_BPS_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "STAKE: commission_bps=%u > %u",
                      (unsigned)tx->stake_fields.commission_bps,
                      (unsigned)DNAC_COMMISSION_BPS_MAX);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* purpose_tag match — defense-in-depth. The deserialize path (Task 16)
     * already rejects any mismatched tag on the wire; an in-memory TX
     * reaching verify should never fail this check unless it was
     * constructed directly without round-tripping through the wire. */
    /* purpose_tag lives on the wire / in the preimage, not as a struct
     * field — it is implicitly validated by dnac_tx_deserialize() and
     * by dnac_tx_compute_hash() binding the literal into the preimage.
     * No runtime field to re-check here. */

    /* Σ DNAC input >= DNAC_SELF_STAKE_AMOUNT + Σ DNAC output.
     * Filter to native DNAC token (token_id == zeros); other tokens are
     * not part of the self-stake accounting and are not checked here. */
    uint64_t dnac_in = 0;
    uint64_t dnac_out = 0;
    for (int i = 0; i < tx->input_count; i++) {
        if (memcmp(tx->inputs[i].token_id, DNAC_NATIVE_TOKEN_ID, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        if (safe_add_u64(dnac_in, tx->inputs[i].amount, &dnac_in) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "STAKE: input amount overflow");
            return DNAC_ERROR_OVERFLOW;
        }
    }
    for (int i = 0; i < tx->output_count; i++) {
        if (memcmp(tx->outputs[i].token_id, DNAC_NATIVE_TOKEN_ID, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        if (safe_add_u64(dnac_out, tx->outputs[i].amount, &dnac_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "STAKE: output amount overflow");
            return DNAC_ERROR_OVERFLOW;
        }
    }

    uint64_t required;
    if (safe_add_u64(DNAC_SELF_STAKE_AMOUNT, dnac_out, &required) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "STAKE: required-sum overflow");
        return DNAC_ERROR_OVERFLOW;
    }
    if (dnac_in < required) {
        QGP_LOG_ERROR(LOG_TAG,
                      "STAKE: inputs=%llu < 10M + outputs=%llu (required=%llu)",
                      (unsigned long long)dnac_in,
                      (unsigned long long)dnac_out,
                      (unsigned long long)required);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* TODO(Phase 8 Task 40 / witness-side):
     *   - Rule I: NO record exists in validator_tree with signer[0].pubkey
     *     (covers F-STATE-07 pubkey-reuse — ALL statuses block, not just ACTIVE)
     *   - Rule M: validator_stats.active_count < DNAC_MAX_VALIDATORS (128)
     *   - Exact-fee check: inputs − outputs − 10M == current_fee
     * Requires nodus_validator_lookup / nodus_validator_active_count; the
     * client has no witness DB so these run server-side at state-apply. */

    return DNAC_SUCCESS;
}

/* Public entry point for STAKE rule verification.
 *
 * Exposed so unit tests can exercise the rule layer without assembling
 * real Dilithium5 signer signatures and witness attestations. */
int dnac_tx_verify_stake_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_STAKE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_stake_rules(tx);
}

/**
 * @brief Verify DELEGATE-type rules (design §2.4, Phase 6 Task 23).
 *
 * Enforces the locally-verifiable subset of the DELEGATE rule set:
 *
 *   - signer_count == 1
 *   - (no Rule S: signer[0].pubkey MAY equal validator_pubkey — a
 *     validator may delegate to itself, as on the chain; decision
 *     2026-09-28-treasury-pools-and-exact-self-stake.md item 6)
 *   - Σ DNAC inputs − Σ DNAC outputs >= DNAC_MIN_DELEGATION (100 DNAC)
 *     (Rule J: minimum delegation amount. The net `input − output` is the
 *     amount being moved into the delegation state minus fee; since fee is
 *     non-negative, `input − output >= 100 DNAC` is a conservative
 *     lower bound — if `input − output < 100 DNAC` the actual delegation
 *     deposit (which is `input − output − fee`) is already below the
 *     minimum, so the TX is rejectable client-side.)
 *     ⚠ DIFFERENCE FROM THE WITNESS, stated not changed (P3 fix round):
 *     this client rule demands the minimum on EVERY delegate, a top-up
 *     of an existing delegation included. The version-3 witness
 *     (nodus_witness_rt_native.c rtn_delegate_exec, tokenomics-v3 P3-5)
 *     demands DNAC_MIN_DELEGATION only when the DELEGATE OPENS a new
 *     row; a top-up needs >= 1 raw. A top-up below 100 DNAC is therefore
 *     chain-valid but refused by this client lane — stricter, never
 *     looser, so it cannot admit what the chain rejects.
 *
 * Rules requiring witness-side DB access are deferred to state-apply:
 *   - Rule B: validator_pubkey IN validator_tree AND status == ACTIVE
 *   - Rule G: count(delegations where delegator==signer[0]) < 64
 *   - Exact balance: outputs == inputs − delegation_amount − fee
 */
static int verify_delegate_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "DELEGATE: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* Σ DNAC input − Σ DNAC output >= DNAC_MIN_DELEGATION (Rule J). */
    uint64_t dnac_in = 0;
    uint64_t dnac_out = 0;
    for (int i = 0; i < tx->input_count; i++) {
        if (memcmp(tx->inputs[i].token_id, DNAC_NATIVE_TOKEN_ID, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        if (safe_add_u64(dnac_in, tx->inputs[i].amount, &dnac_in) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "DELEGATE: input amount overflow");
            return DNAC_ERROR_OVERFLOW;
        }
    }
    for (int i = 0; i < tx->output_count; i++) {
        if (memcmp(tx->outputs[i].token_id, DNAC_NATIVE_TOKEN_ID, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        if (safe_add_u64(dnac_out, tx->outputs[i].amount, &dnac_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "DELEGATE: output amount overflow");
            return DNAC_ERROR_OVERFLOW;
        }
    }
    if (dnac_in < dnac_out) {
        QGP_LOG_ERROR(LOG_TAG,
                      "DELEGATE: inputs=%llu < outputs=%llu",
                      (unsigned long long)dnac_in,
                      (unsigned long long)dnac_out);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    uint64_t net = dnac_in - dnac_out;
    if (net < DNAC_MIN_DELEGATION) {
        QGP_LOG_ERROR(LOG_TAG,
                      "DELEGATE: net=%llu < min=%llu (Rule J)",
                      (unsigned long long)net,
                      (unsigned long long)DNAC_MIN_DELEGATION);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }

    /* TODO(Phase 8 Task 41 / witness-side):
     *   - Rule B: validator_pubkey IN validator_tree AND status == ACTIVE
     *   - Rule G: count(delegations where delegator == signer[0].pubkey) < 64
     *   - Exact-fee equality: outputs == inputs − delegation_amount − fee
     * Requires nodus_validator_lookup / nodus_delegation_count; the client
     * has no witness DB so these run server-side at state-apply. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_delegate_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_DELEGATE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_delegate_rules(tx);
}

/**
 * @brief Verify UNSTAKE-type rules (design §2.4, Phase 6 Task 24).
 *
 * UNSTAKE has no appended fields, no amount fields, no commission.
 * The single locally-verifiable rule is:
 *
 *   - signer_count == 1
 *
 * All substantive checks require witness-side DB access:
 *   - (Rule A — "no delegation records may exist for the validator" —
 *     is GONE since tokenomics-v3 P3-4: the version-3 witness accepts an
 *     UNSTAKE whatever its delegator count and releases the remaining
 *     delegations at graduation, nodus_witness_v2_epoch.c
 *     v2ep_release_delegations. This client lane never enforced it.)
 *   - signer[0].pubkey IN validator_tree AND status == ACTIVE
 *   - Fee paid per current fee schedule
 * These are deferred to Phase 8 Task 42 state-apply.
 */
static int verify_unstake_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "UNSTAKE: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* TODO(Phase 8 Task 42 / witness-side):
     *   - signer[0].pubkey IN validator_tree AND status == ACTIVE
     *   - (Rule A, drain-before-exit, is removed by tokenomics-v3 P3-4 —
     *     see the header above; nothing to add here for it)
     *   - Fee paid per current fee schedule
     * Requires nodus_validator_lookup / nodus_delegation_count_by_validator. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_unstake_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_UNSTAKE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_unstake_rules(tx);
}

/**
 * @brief Verify UNDELEGATE-type rules (design §2.4, Phase 6 Task 25).
 *
 * Enforces the locally-verifiable subset of the UNDELEGATE rule set:
 *
 *   - signer_count == 1
 *   - undelegate_fields.amount > 0
 *
 * Rules requiring witness-side DB access are deferred to state-apply:
 *   - delegation(signer[0], validator_pubkey) exists
 *   - amount <= delegation.amount
 * The old "Rule O" hold on delegated_at_block is superseded by the
 * release UTXO's lock (tokenomics-v3 P2-10) — see the note in the body.
 */
static int verify_undelegate_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "UNDELEGATE: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* amount > 0 — zero-amount undelegate is nonsensical. */
    if (tx->undelegate_fields.amount == 0) {
        QGP_LOG_ERROR(LOG_TAG, "UNDELEGATE: amount == 0");
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Witness-side, at state-apply (the client has no witness DB):
     *   - delegation(signer[0].pubkey, validator_pubkey) exists
     *   - amount <= delegation.amount
     * (nodus/src/witness/nodus_witness_rt_native.c rtn_undelegate_exec).
     *
     * Rule O — a hold measured as current_block −
     * delegation.delegated_at_block — is NOT implemented anywhere and is
     * SUPERSEDED: delegated_at_block is not a hold clock. The delegator's
     * hold is the UNDELEGATE release UTXO's lock (tokenomics-v3 P2-10,
     * design docs/plans/2026-09-23-tokenomics-v3-consensus-binding-
     * design.md §7.1): the witness creates it locked to L(h) +
     * DNAC_UNDELEGATE_LOCK_EPOCHS × DNAC_EPOCH_LENGTH (rtn_sysfund_exec),
     * and every spend gate refuses it until then. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_undelegate_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_UNDELEGATE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_undelegate_rules(tx);
}

/**
 * @brief Verify VALIDATOR_UPDATE-type rules (design §2.4, Phase 6 Task 27).
 *
 * Enforces the locally-verifiable subset of the VALIDATOR_UPDATE rule set:
 *
 *   - signer_count == 1
 *   - new_commission_bps <= DNAC_COMMISSION_BPS_MAX (5000 — P3-8)
 *   - signed_at_block > 0 (zero is the struct default; a valid update
 *     must anchor to a specific block for Rule K freshness to work)
 *
 * Rules requiring chain state are deferred:
 *   - signer[0].pubkey IN validator_tree AND status ∈ {ACTIVE, RETIRING}
 *   - Rule K: current_block − signed_at_block < DNAC_SIGN_FRESHNESS_WINDOW
 *     (32 blocks)
 *   - Cooldown: last_validator_update_block + DNAC_EPOCH_LENGTH <= current_block
 *   - Pending-increase logic: if new_commission_bps > current_commission_bps,
 *     queue as pending; decrease clears pending
 * These run at state-apply in the witness (Phase 8 Task 45).
 */
static int verify_validator_update_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "VALIDATOR_UPDATE: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* new_commission_bps <= DNAC_COMMISSION_BPS_MAX (5000 since
     * tokenomics-v3 P3-8) */
    if (tx->validator_update_fields.new_commission_bps > DNAC_COMMISSION_BPS_MAX) {
        QGP_LOG_ERROR(LOG_TAG,
                      "VALIDATOR_UPDATE: new_commission_bps=%u > %u",
                      (unsigned)tx->validator_update_fields.new_commission_bps,
                      (unsigned)DNAC_COMMISSION_BPS_MAX);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* signed_at_block > 0 — struct default 0 is not a valid anchor. */
    if (tx->validator_update_fields.signed_at_block == 0) {
        QGP_LOG_ERROR(LOG_TAG, "VALIDATOR_UPDATE: signed_at_block == 0");
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* TODO(Phase 8 Task 45 / witness-side):
     *   - signer[0].pubkey IN validator_tree AND status ∈ {ACTIVE, RETIRING}
     *   - Rule K (freshness): current_block − signed_at_block <
     *     DNAC_SIGN_FRESHNESS_WINDOW (32 blocks)
     *   - Cooldown: last_validator_update_block + DNAC_EPOCH_LENGTH <=
     *     current_block
     *   - Pending commission logic: if new > current, queue pending;
     *     if new <= current, apply immediately and clear pending.
     * Requires nodus_validator_lookup / current_block; client has no
     * witness state. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_validator_update_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_VALIDATOR_UPDATE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_validator_update_rules(tx);
}

/**
 * @brief Verify CHAIN_CONFIG local rules (Hard-Fork v1, design §6.3).
 *
 * Locally-verifiable rule subset — does NOT exercise committee-membership
 * lookup or Dilithium5 signature verification (witness-side, §6.4).
 *
 *   - signer_count == 1
 *   - chain_config_fields.param_id ∈ {1..DNAC_CFG_PARAM_MAX_ID}
 *   - dnac_cfg_param_read_by_consensus(param_id) (0.20.3) — the running
 *     consensus reads the parameter; today {4, 5, 6, 7, 8, 9, 10, 11,
 *     12, 13, 14, 15, 17, 18, 19, 20, 21, 22} (16 RETIRED by HF-6 slice
 *     8c)
 *   - chain_config_fields.new_value in per-param range (§5.2):
 *       MAX_TXS_PER_BLOCK      : RETIRED (R3 W4-C delta 2, operator
 *                                "kaldır" 2026-09-18;
 *                                atlas-dec-5b7568512b95e6d2e671c4eaad2c1879
 *                                rev 1) — id 1 is refused unconditionally,
 *                                mirroring nodus_witness_chain_config.c's
 *                                scalar_rules; a block's capacity is
 *                                bytes and units only now
 *                                (nodus_witness_v2_apply.h's derived
 *                                envelope ceiling)
 *       BLOCK_INTERVAL_SEC     : NOT READ by the running consensus
 *                                (0.20.3) — refused; its [1, 15]
 *                                definition stays in dnac.h for a
 *                                consensus that reads it
 *       INFLATION_START_BLOCK  : RETIRED (tokenomics-v3 P2, P2-4) — id 3
 *                                is refused unconditionally, mirroring
 *                                the witness-side scalar_rules; there is
 *                                no per-block mint left to start
 *       RULESET_GEN_STORAGE    : RETIRED (HF-6 slice 8c) — id 16 is
 *                                refused unconditionally, mirroring the
 *                                witness-side scalar_rules; generation 4
 *                                is voted by RULESET_GEN_ROLES (18)
 *       TARGET_ACTIVE_COUNT    : [DNAC_CFG_MIN_TARGET_ACTIVE=7,
 *                                 DNAC_CFG_MAX_TARGET_ACTIVE=128]  (S3)
 *       GAS_PRICE_RAW_PER_UNIT : [0, DNAC_CFG_MAX_GAS_PRICE=1000000] (HF-1;
 *                                0 = the price rule is off)
 *       TOKEN_CREATE_FEE_RAW   : [DNAC_CFG_MIN_TOKEN_CREATE_FEE=10^8,
 *                                 DNAC_CFG_MAX_TOKEN_CREATE_FEE=10^15]
 *                                (final pre-testnet wipe W-C)
 *       HF2_ACTIVE             : exactly DNAC_CFG_HF2_ACTIVE_ON = 1 (HF-2;
 *                                a one-way switch)
 *       HF3_ACTIVE             : exactly DNAC_CFG_HF3_ACTIVE_ON = 1 (HF-3;
 *                                a one-way switch)
 *       RULESET_GEN2           : exactly DNAC_CFG_RULESET_GEN2_D2 (HF-4;
 *                                the vote names its target generation;
 *                                the witness's single-use / HF-2 /
 *                                epoch-boundary rules are not mirrored —
 *                                they need chain state)
 *       NAME_PRICE_3P..6P      : [DNAC_CFG_MIN_NAME_PRICE=10^8,
 *                                 DNAC_CFG_MAX_NAME_PRICE=10^15] (HF-4;
 *                                "generation 2 judges the vote" is
 *                                witness-side only)
 *       EVM_ACTIVE             : exactly DNAC_CFG_EVM_ACTIVE_D (Nodus EVM; the
 *                                stateful rules are witness-side only)
 *       EVM_BLOCK_GAS_LIMIT    : [DNAC_CFG_MIN_EVM_BLOCK_GAS,
 *                                 DNAC_CFG_MAX_EVM_BLOCK_GAS] (Nodus EVM)
 *       DELEGATE_NAME_REQUIRED : exactly DNAC_CFG_DELEGATE_NAME_REQUIRED_ON
 *                                = 1 (HF-8)
 *       RULESET_GEN_ROLES      : exactly DNAC_CFG_RULESET_GEN_ROLES_D (D4;
 *                                HF-6, param 18; the RULESET_GEN2 shape
 *                                — the witness's stateful rules are not
 *                                mirrored)
 *       STAKE_MIN              : [DNAC_HF6_STAKE_MIN_MIN=10^13, INT64_MAX]
 *                                (HF-6, param 19; the upper end is
 *                                checked on new_value itself)
 *       POWER_CAP_BPS          : [DNAC_CFG_MIN_POWER_CAP_BPS=500,
 *                                 DNAC_CFG_MAX_POWER_CAP_BPS=3000]
 *                                (HF-6, param 20)
 *       STORAGE_BOND           : [DNAC_HF6_STORAGE_BOND_MIN=10^13,
 *                                 DNAC_HF6_STORAGE_BOND_MAX=10^14]
 *                                (HF-6, param 21) — for 19-21 the
 *                                witness's "generation 4 judges the vote"
 *                                rule is not mirrored
 *       RULESET_GEN_ROOTS      : exactly DNAC_CFG_RULESET_GEN_ROOTS_D (D5;
 *                                HF-7, param 22; the RULESET_GEN_ROLES
 *                                shape — the witness's stateful rules are
 *                                not mirrored)
 *   - signed_at_block > 0             (CC-AUDIT-008)
 *   - valid_before_block > effective_block_height
 *   - valid_before_block > signed_at_block
 *   - proposal_nonce, signed_at_block, valid_before_block and
 *     effective_block_height each <= INT64_MAX (decision
 *     2026-09-30-chain-config-int64-bounds.md; the witness stores them
 *     as SQLite int64 — mirrors nodus_chain_config_scalar_rules)
 *   - committee_sig_count ∈ [DNAC_CHAIN_CONFIG_MIN_SIGS,
 *                            DNAC_CHAIN_CONFIG_MAX_SIGS] = [5, 128]
 *     (SHAPE only — the quorum rule is witness-side, see the notes on
 *      DNAC_CHAIN_CONFIG_MIN_SIGS in dnac.h)
 *   - committee_votes[0..sig_count-1].witness_id pairwise distinct
 */
static int verify_chain_config_rules(const dnac_transaction_t *tx) {
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "CHAIN_CONFIG: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    const dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;

    /* param_id in whitelisted range (Rule CC-A). */
    if (cc->param_id < 1 || cc->param_id > DNAC_CFG_PARAM_MAX_ID) {
        QGP_LOG_ERROR(LOG_TAG, "CHAIN_CONFIG: param_id=%u out of range",
                      (unsigned)cc->param_id);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* 0.20.3: a parameter the RUNNING consensus does not read is refused
     * (decision file 2026-09-23-height-activated-upgrades-before-testnet.md
     * item 1). The list is dnac.h's dnac_cfg_param_read_by_consensus —
     * the SAME predicate the witness-side nodus_chain_config_scalar_rules
     * consumes, so the client mirror and the witness cannot drift. */
    if (!dnac_cfg_param_read_by_consensus(cc->param_id)) {
        QGP_LOG_ERROR(LOG_TAG,
                      "CHAIN_CONFIG: param_id=%u is not read by the running "
                      "consensus", (unsigned)cc->param_id);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* new_value in per-param range (Rule CC-B). Only ids ON the read list
     * reach here — why 1 (retired), 2 (not read), 3 (retired) and 16
     * (retired, HF-6 slice 8c) are off it is written at
     * nodus_witness_chain_config.c's scalar_rules; their former cases
     * were unreachable after the gate and were removed. */
    switch ((dnac_chain_config_param_id_t)cc->param_id) {
        case DNAC_CFG_TARGET_ACTIVE_COUNT:
            if (cc->new_value < DNAC_CFG_MIN_TARGET_ACTIVE ||
                cc->new_value > DNAC_CFG_MAX_TARGET_ACTIVE) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: TARGET_ACTIVE_COUNT=%llu out of [%llu,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_MIN_TARGET_ACTIVE,
                              (unsigned long long)DNAC_CFG_MAX_TARGET_ACTIVE);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_GAS_PRICE_RAW_PER_UNIT:
            /* HF-1 (decision 2026-09-25-gas-price.md), mirroring
             * nodus_witness_chain_config.c's scalar_rules: [0, MAX].
             * 0 is LEGAL (it switches the price rule off again), so an
             * unsigned value needs no lower-bound test. */
            if (cc->new_value > DNAC_CFG_MAX_GAS_PRICE) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: GAS_PRICE_RAW_PER_UNIT=%llu out of [0,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_MAX_GAS_PRICE);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_TOKEN_CREATE_FEE_RAW:
            /* Final pre-testnet wipe W-C (decision 2026-09-28-token-
             * create-fee-governance.md), mirroring nodus_witness_chain_
             * config.c's scalar_rules: [MIN, MAX] = [10^8, 10^15]. */
            if (cc->new_value < DNAC_CFG_MIN_TOKEN_CREATE_FEE ||
                cc->new_value > DNAC_CFG_MAX_TOKEN_CREATE_FEE) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: TOKEN_CREATE_FEE_RAW=%llu out of [%llu,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_MIN_TOKEN_CREATE_FEE,
                              (unsigned long long)DNAC_CFG_MAX_TOKEN_CREATE_FEE);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_HF2_ACTIVE:
            /* HF-2 (design 2026-09-30-gov-weight-netzero-design.md rev
             * 2), mirroring nodus_witness_chain_config.c's scalar_rules:
             * EXACTLY 1 — a one-way switch, there is no "off" vote. */
            if (cc->new_value != DNAC_CFG_HF2_ACTIVE_ON) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: HF2_ACTIVE=%llu, only %llu is "
                              "a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_HF2_ACTIVE_ON);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_HF3_ACTIVE:
            /* HF-3 (design 2026-10-01-hf3-comet-block-bounds-design.md
             * rev 3), mirroring nodus_witness_chain_config.c's
             * scalar_rules: EXACTLY 1 — a one-way switch, the HF-2 shape
             * above. */
            if (cc->new_value != DNAC_CFG_HF3_ACTIVE_ON) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: HF3_ACTIVE=%llu, only %llu is "
                              "a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_HF3_ACTIVE_ON);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_DELEGATE_NAME_REQUIRED:
            /* HF-8 (design 2026-10-07-delegate-name-required-design.md
             * rev 2 §1), mirroring nodus_witness_chain_config.c's
             * scalar_rules: EXACTLY 1 — the HF-2 one-way switch shape.
             * "Votable only while generation >= 2 judges the vote" is a
             * witness-side stateful rule this mirror cannot apply (the
             * NAME_PRICE divergence). */
            if (cc->new_value != DNAC_CFG_DELEGATE_NAME_REQUIRED_ON) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: DELEGATE_NAME_REQUIRED=%llu, "
                              "only %llu is a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)
                                  DNAC_CFG_DELEGATE_NAME_REQUIRED_ON);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_RULESET_GEN2:
            /* HF-4 (design 2026-10-02-onchain-names-design.md rev 4
             * §1.2), mirroring nodus_witness_chain_config.c's
             * scalar_rules: EXACTLY the compiled vote literal D2 (the
             * same dnac.h literal the witness compares against). The
             * witness's stateful rules — single use, HF-2 active, H-1
             * not an epoch boundary — need chain state this mirror does
             * not have (documented divergence, design §1.2). */
            if (cc->new_value != (uint64_t)DNAC_CFG_RULESET_GEN2_D2) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: RULESET_GEN2=0x%016llx, only "
                              "D2=0x%016llx is a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_RULESET_GEN2_D2);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_RULESET_GEN_ROLES:
            /* HF-6 (design 2026-10-03-hf5-validator-owner-stake-design.md
             * rev 6 §8, §8.1), mirroring nodus_witness_chain_config.c's
             * scalar_rules: EXACTLY the compiled generation-4 vote
             * literal D4 (the same dnac.h literal the witness compares
             * against). The witness's stateful rules — single use, no
             * param-16 row, HF-2 active, judged under generation 3, H-1
             * and H not epoch boundaries — need chain state this mirror
             * does not have (the param-9 divergence). RETIRED param 16
             * has no case: the read-list gate above refuses it. */
            if (cc->new_value != (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: RULESET_GEN_ROLES=0x%016llx, "
                              "only D4=0x%016llx is a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)
                                  DNAC_CFG_RULESET_GEN_ROLES_D);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_RULESET_GEN_ROOTS:
            /* HF-7 (design 2026-09-11-nodus-ledger-snapshot-design.md
             * §10.2 item 1, §10.11), mirroring nodus_witness_chain_
             * config.c's scalar_rules: EXACTLY the compiled generation-5
             * vote literal D5 (the same dnac.h literal the witness
             * compares against). The witness's stateful rules — single
             * use, HF-2 active, judged under generation 4, A-1 and A not
             * epoch boundaries — need chain state this mirror does not
             * have (the param-18 divergence). */
            if (cc->new_value != (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: RULESET_GEN_ROOTS=0x%016llx, "
                              "only D5=0x%016llx is a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)
                                  DNAC_CFG_RULESET_GEN_ROOTS_D);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_NAME_PRICE_3P:
        case DNAC_CFG_NAME_PRICE_4P:
        case DNAC_CFG_NAME_PRICE_5P:
        case DNAC_CFG_NAME_PRICE_6P:
            /* HF-4 (design §2 Price), mirroring the witness scalar
             * rules: [DNAC_CFG_MIN_NAME_PRICE, DNAC_CFG_MAX_NAME_PRICE].
             * "Votable only while generation 2 judges" is a witness-side
             * stateful rule this mirror cannot apply. */
            if (cc->new_value < DNAC_CFG_MIN_NAME_PRICE ||
                cc->new_value > DNAC_CFG_MAX_NAME_PRICE) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: NAME_PRICE (param %u)=%llu out "
                              "of [%llu,%llu]", (unsigned)cc->param_id,
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_MIN_NAME_PRICE,
                              (unsigned long long)DNAC_CFG_MAX_NAME_PRICE);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_EVM_ACTIVE:
            /* Nodus EVM (design 2026-10-04-nodus-evm-chain-integration-design.md
             * rev 3 §9), mirroring the witness scalar rules: EXACTLY the
             * compiled vote literal (the vote names its target
             * generation). The witness's stateful rules — single use,
             * HF-2 / HF-3 / a non-zero gas price active, the registry at
             * the base generation, H-1 not an epoch boundary — need chain
             * state this mirror does not have (the HF-4 divergence). */
            if (cc->new_value != (uint64_t)DNAC_CFG_EVM_ACTIVE_D) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: EVM_ACTIVE=0x%016llx, only "
                              "D=0x%016llx is a legal value",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_EVM_ACTIVE_D);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_EVM_BLOCK_GAS_LIMIT:
            /* Nodus EVM (design §8), mirroring the witness scalar rules. */
            if (cc->new_value < DNAC_CFG_MIN_EVM_BLOCK_GAS ||
                cc->new_value > DNAC_CFG_MAX_EVM_BLOCK_GAS) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: EVM_BLOCK_GAS_LIMIT=%llu out of "
                              "[%llu,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_CFG_MIN_EVM_BLOCK_GAS,
                              (unsigned long long)DNAC_CFG_MAX_EVM_BLOCK_GAS);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_STAKE_MIN:
            /* HF-6 (design 2026-10-03-hf5-validator-owner-stake-design.md
             * rev 6 §1.5, Kurultay #14 K9), mirroring the witness scalar
             * rules: [DNAC_HF6_STAKE_MIN_MIN, INT64_MAX] raw — the upper
             * end checked here on new_value itself (the int64 tests below
             * cover the nonce and the heights only). "Votable only while
             * generation 4 judges the vote" is witness-side. */
            if (cc->new_value < DNAC_HF6_STAKE_MIN_MIN ||
                cc->new_value > (uint64_t)INT64_MAX) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: STAKE_MIN=%llu out of "
                              "[%llu,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_HF6_STAKE_MIN_MIN,
                              (unsigned long long)INT64_MAX);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_POWER_CAP_BPS:
            /* HF-6 (design rev 6 §5, K5), mirroring the witness scalar
             * rules: [500, 3000] bps. Generation 4: witness-side. */
            if (cc->new_value < DNAC_CFG_MIN_POWER_CAP_BPS ||
                cc->new_value > DNAC_CFG_MAX_POWER_CAP_BPS) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: POWER_CAP_BPS=%llu out of "
                              "[%u,%u]",
                              (unsigned long long)cc->new_value,
                              (unsigned)DNAC_CFG_MIN_POWER_CAP_BPS,
                              (unsigned)DNAC_CFG_MAX_POWER_CAP_BPS);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        case DNAC_CFG_STORAGE_BOND:
            /* HF-6 (design rev 6 §11.3, Kurultay #16 khan decision 3),
             * mirroring the witness scalar rules: [DNAC_HF6_STORAGE_BOND_
             * MIN, DNAC_HF6_STORAGE_BOND_MAX] raw. Generation 4:
             * witness-side. */
            if (cc->new_value < DNAC_HF6_STORAGE_BOND_MIN ||
                cc->new_value > DNAC_HF6_STORAGE_BOND_MAX) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: STORAGE_BOND=%llu out of "
                              "[%llu,%llu]",
                              (unsigned long long)cc->new_value,
                              (unsigned long long)DNAC_HF6_STORAGE_BOND_MIN,
                              (unsigned long long)DNAC_HF6_STORAGE_BOND_MAX);
                return DNAC_ERROR_INVALID_PARAM;
            }
            break;
        default:
            return DNAC_ERROR_INVALID_PARAM;  /* Unreachable given bound check above */
    }

    /* Freshness anchor must be non-zero (CC-AUDIT-008). */
    if (cc->signed_at_block == 0) {
        QGP_LOG_ERROR(LOG_TAG, "CHAIN_CONFIG: signed_at_block == 0");
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Effective ordering: valid_before > effective_block (proposal must not
     * expire before it can activate) AND valid_before > signed_at (vote
     * can't expire before it was signed). */
    if (cc->valid_before_block <= cc->effective_block_height) {
        QGP_LOG_ERROR(LOG_TAG,
                      "CHAIN_CONFIG: valid_before=%llu <= effective=%llu",
                      (unsigned long long)cc->valid_before_block,
                      (unsigned long long)cc->effective_block_height);
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (cc->valid_before_block <= cc->signed_at_block) {
        QGP_LOG_ERROR(LOG_TAG,
                      "CHAIN_CONFIG: valid_before=%llu <= signed_at=%llu",
                      (unsigned long long)cc->valid_before_block,
                      (unsigned long long)cc->signed_at_block);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* The int64 bound (decision 2026-09-30-chain-config-int64-bounds.md),
     * mirroring nodus_chain_config_scalar_rules: the witness stores these
     * four as SQLite int64, so a value above INT64_MAX is refused there as
     * a verdict — refused here first, so the client never submits it. */
    if (cc->proposal_nonce         > (uint64_t)INT64_MAX ||
        cc->signed_at_block        > (uint64_t)INT64_MAX ||
        cc->valid_before_block     > (uint64_t)INT64_MAX ||
        cc->effective_block_height > (uint64_t)INT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG,
                      "CHAIN_CONFIG: nonce=%llu signed_at=%llu "
                      "valid_before=%llu effective=%llu — each must be "
                      "<= INT64_MAX",
                      (unsigned long long)cc->proposal_nonce,
                      (unsigned long long)cc->signed_at_block,
                      (unsigned long long)cc->valid_before_block,
                      (unsigned long long)cc->effective_block_height);
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Committee-sig count within the SHAPE window (5..128). This is a cheap
     * structural bound of this legacy type-10 wire shape, NOT the approval
     * decision. The binding rule is witness-side, in the version-3 SYSTEM
     * CHAIN_CONFIG exec over the committee governing the executing height
     * (nodus_witness_rt_native.c nodus_rt_system_exec): seats,
     * dna_bft_quorum(committee_count), below the HF-2 height, and approving
     * voting power > 2/3 of the committee's power from it
     * (DNAC_CFG_HF2_ACTIVE). The version-3 approval carrier (auth_kind 2)
     * has no minimum count; this bound applies to this wire shape only. */
    if (cc->committee_sig_count < DNAC_CHAIN_CONFIG_MIN_SIGS ||
        cc->committee_sig_count > DNAC_CHAIN_CONFIG_MAX_SIGS) {
        QGP_LOG_ERROR(LOG_TAG,
                      "CHAIN_CONFIG: committee_sig_count=%u outside [%d,%d]",
                      (unsigned)cc->committee_sig_count,
                      DNAC_CHAIN_CONFIG_MIN_SIGS,
                      DNAC_CHAIN_CONFIG_MAX_SIGS);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* Distinct witness_ids across the included votes. */
    for (uint8_t i = 0; i < cc->committee_sig_count; i++) {
        for (uint8_t j = (uint8_t)(i + 1); j < cc->committee_sig_count; j++) {
            if (memcmp(cc->committee_votes[i].witness_id,
                       cc->committee_votes[j].witness_id, 32) == 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "CHAIN_CONFIG: duplicate witness_id at votes[%u]==votes[%u]",
                              (unsigned)i, (unsigned)j);
                return DNAC_ERROR_INVALID_SIGNATURE;
            }
        }
    }

    /* TODO(Stage B / witness-side §6.4):
     *   - Each committee_votes[i].witness_id IN current top-7 committee
     *     at commit_block - 1.
     *   - Each signature valid against committee member's Dilithium5 pubkey
     *     over proposal preimage (§5.4).
     *   - commit_block + DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS <=
     *     effective_block_height (for ergonomic params: MAX_TXS).
     *   - commit_block + DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS <=
     *     effective_block_height (for safety-critical params:
     *     TARGET_ACTIVE_COUNT).
     *   - commit_block <= valid_before_block (freshness).
     *   - Exclusive-block rule (Q7): block containing chain_config_tx has
     *     tx_count == 1. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_chain_config_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_CHAIN_CONFIG) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_chain_config_rules(tx);
}

/**
 * @brief Verify all signers' Dilithium5 signatures over tx_hash
 */
int verify_signers(const dnac_transaction_t *tx) {
    if (tx->signer_count == 0) return DNAC_ERROR_INVALID_SIGNATURE;
    if (tx->signer_count > DNAC_TX_MAX_SIGNERS) return DNAC_ERROR_INVALID_PARAM;

    for (int i = 0; i < tx->signer_count; i++) {
        int ret = qgp_dsa87_verify(tx->signers[i].signature, DNAC_SIGNATURE_SIZE,
                                   tx->tx_hash, DNAC_TX_HASH_SIZE,
                                   tx->signers[i].pubkey);
        if (ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "signer %d signature invalid", i);
            return DNAC_ERROR_INVALID_SIGNATURE;
        }
    }
    return DNAC_SUCCESS;
}
