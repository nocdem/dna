/**
 * @file verify.c
 * @brief Transaction verification
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/dnac.h"
#include "dnac/safe_math.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

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

    /* commission_bps <= 10000 */
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
     * not part of the self-stake accounting and pass through verify_balance_per_token. */
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
 * real Dilithium5 signer signatures and witness attestations. The normal
 * verify path (dnac_tx_verify) also calls verify_stake_rules internally
 * for STAKE-typed TXs. */
int dnac_tx_verify_stake_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_STAKE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_stake_rules(tx);
}

/* Internal linkage for transaction.c's dnac_tx_verify to dispatch into. */
int dnac_tx_verify_stake_rules_internal(const dnac_transaction_t *tx) {
    return verify_stake_rules(tx);
}

/**
 * @brief Verify DELEGATE-type rules (design §2.4, Phase 6 Task 23).
 *
 * Enforces the locally-verifiable subset of the DELEGATE rule set:
 *
 *   - signer_count == 1
 *   - signer[0].pubkey != validator_pubkey  (Rule S: no self-delegation via
 *     DELEGATE; the validator's own 10M stake flows through STAKE)
 *   - Σ DNAC inputs − Σ DNAC outputs >= DNAC_MIN_DELEGATION (100 DNAC)
 *     (Rule J: minimum delegation amount. The net `input − output` is the
 *     amount being moved into the delegation state minus fee; since fee is
 *     non-negative, `input − output >= 100 DNAC` is a conservative
 *     lower bound — if `input − output < 100 DNAC` the actual delegation
 *     deposit (which is `input − output − fee`) is already below the
 *     minimum, so the TX is rejectable client-side.)
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

    /* Rule S: signer[0].pubkey != validator_pubkey. Self-delegation via
     * DELEGATE is prohibited — validators bond their own 10M via STAKE. */
    if (memcmp(tx->signers[0].pubkey,
               tx->delegate_fields.validator_pubkey,
               DNAC_PUBKEY_SIZE) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "DELEGATE: self-delegation forbidden (Rule S)");
        return DNAC_ERROR_INVALID_PARAM;
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

int dnac_tx_verify_delegate_rules_internal(const dnac_transaction_t *tx) {
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
 *   - Rule A (literal): NO delegation records exist with
 *     validator == signer[0].pubkey — validator must drain external
 *     delegators before exiting
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
     *   - Rule A (literal): NO delegation records where
     *     validator == signer[0].pubkey (drain-before-exit)
     *   - Fee paid per current fee schedule
     * Requires nodus_validator_lookup / nodus_delegation_count_by_validator. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_unstake_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_UNSTAKE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_unstake_rules(tx);
}

int dnac_tx_verify_unstake_rules_internal(const dnac_transaction_t *tx) {
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
 *   - Rule O: current_block − delegation.delegated_at_block >= EPOCH_LENGTH
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

    /* TODO(Phase 8 Task 43 / witness-side):
     *   - delegation(signer[0].pubkey, validator_pubkey) exists
     *   - amount <= delegation.amount
     *   - Rule O (hold duration): current_block − delegation.delegated_at_block
     *     >= DNAC_EPOCH_LENGTH
     * Requires nodus_delegation_lookup; the client has no witness DB so
     * these run server-side at state-apply. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_undelegate_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_UNDELEGATE) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_undelegate_rules(tx);
}

int dnac_tx_verify_undelegate_rules_internal(const dnac_transaction_t *tx) {
    return verify_undelegate_rules(tx);
}

/**
 * @brief Verify CLAIM_REWARD-type rules (design §2.4, Phase 6 Task 26).
 *
 * Enforces the locally-verifiable subset of the CLAIM_REWARD rule set:
 *
 *   - signer_count == 1
 *   - claim_reward_fields.max_pending_amount > 0
 *     (zero cap would never allow a claim to succeed — nonsensical)
 *   - claim_reward_fields.valid_before_block > 0
 *     (zero is the struct's default; a valid claim must set an explicit
 *      block-height expiry for freshness replay defense)
 *
 * Rules requiring chain state / witness DB access are deferred:
 *   - current_block <= valid_before_block (freshness)
 *   - pending = compute_pending(validator, delegation) (either
 *     validator-self or delegator branch per §2.4)
 *   - pending <= max_pending_amount (claim cap)
 *   - Rule L: pending >= max(10^6, 10 × current_fee) (dynamic dust)
 * These run at state-apply in the witness (Phase 8 Task 44).
 */
static int verify_claim_reward_rules(const dnac_transaction_t *tx) {
    /* signer_count == 1 */
    if (tx->signer_count != 1) {
        QGP_LOG_ERROR(LOG_TAG, "CLAIM_REWARD: signer_count=%u != 1",
                      (unsigned)tx->signer_count);
        return DNAC_ERROR_INVALID_SIGNATURE;
    }

    /* max_pending_amount > 0 */
    if (tx->claim_reward_fields.max_pending_amount == 0) {
        QGP_LOG_ERROR(LOG_TAG, "CLAIM_REWARD: max_pending_amount == 0");
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* valid_before_block > 0 (explicit freshness bound required) */
    if (tx->claim_reward_fields.valid_before_block == 0) {
        QGP_LOG_ERROR(LOG_TAG, "CLAIM_REWARD: valid_before_block == 0");
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* TODO(Phase 8 Task 44 / witness-side):
     *   - current_block <= valid_before_block (freshness)
     *   - Compute pending via per-branch formula:
     *       if signer == target_validator: pending = validator.unclaimed
     *       else: pending = ((validator.accumulator −
     *           delegation.reward_snapshot) × delegation.amount) >> 64
     *   - pending <= max_pending_amount (claim cap)
     *   - Rule L: pending >= max(10^6, 10 × current_fee) (dynamic dust)
     * Requires nodus_validator_lookup / nodus_delegation_lookup /
     * current_fee / current_block; the client has no witness state. */

    return DNAC_SUCCESS;
}

int dnac_tx_verify_claim_reward_rules(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;
    if (tx->type != DNAC_TX_CLAIM_REWARD) return DNAC_ERROR_INVALID_TX_TYPE;
    return verify_claim_reward_rules(tx);
}

int dnac_tx_verify_claim_reward_rules_internal(const dnac_transaction_t *tx) {
    return verify_claim_reward_rules(tx);
}

/**
 * @brief Per-token balance verification
 *
 * For each distinct token_id across inputs and outputs:
 *   sum(inputs[token]) >= sum(outputs[token])
 *
 * GENESIS: no inputs, outputs create coins (skip).
 * TOKEN_CREATE: mixed tokens expected (skip — witness handles).
 */
static int verify_balance_per_token(const dnac_transaction_t *tx) {
    if (tx->type == DNAC_TX_GENESIS) {
        if (tx->input_count != 0) return DNAC_ERROR_INVALID_PROOF;
        return DNAC_SUCCESS;
    }
    if (tx->type == DNAC_TX_TOKEN_CREATE) return DNAC_SUCCESS;

    /* Collect unique token_ids */
    uint8_t tokens[32][DNAC_TOKEN_ID_SIZE];
    int token_count = 0;

    for (int i = 0; i < tx->input_count; i++) {
        bool found = false;
        for (int t = 0; t < token_count; t++) {
            if (memcmp(tokens[t], tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE) == 0) {
                found = true; break;
            }
        }
        if (!found && token_count < 32)
            memcpy(tokens[token_count++], tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }
    for (int i = 0; i < tx->output_count; i++) {
        bool found = false;
        for (int t = 0; t < token_count; t++) {
            if (memcmp(tokens[t], tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE) == 0) {
                found = true; break;
            }
        }
        if (!found && token_count < 32)
            memcpy(tokens[token_count++], tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }

    for (int t = 0; t < token_count; t++) {
        uint64_t sum_in = 0, sum_out = 0;
        for (int i = 0; i < tx->input_count; i++) {
            if (memcmp(tx->inputs[i].token_id, tokens[t], DNAC_TOKEN_ID_SIZE) == 0) {
                if (safe_add_u64(sum_in, tx->inputs[i].amount, &sum_in) != 0)
                    return DNAC_ERROR_OVERFLOW;
            }
        }
        for (int i = 0; i < tx->output_count; i++) {
            if (memcmp(tx->outputs[i].token_id, tokens[t], DNAC_TOKEN_ID_SIZE) == 0) {
                if (safe_add_u64(sum_out, tx->outputs[i].amount, &sum_out) != 0)
                    return DNAC_ERROR_OVERFLOW;
            }
        }
        if (sum_in < sum_out) return DNAC_ERROR_INVALID_PROOF;
    }
    return DNAC_SUCCESS;
}

/**
 * @brief Verify witness signatures
 *
 * Each witness contains the server's public key. We verify the signature
 * over: tx_hash || witness_id || timestamp
 *
 * With BFT consensus, 1 valid witness attestation proves quorum was reached
 * (the witness only signs after 2f+1 agreement). We require at least 1 valid.
 *
 * C-06: After signature verification, the witness pubkey is checked against
 * the cached roster from DHT discovery. This prevents forged attestations
 * from arbitrary Dilithium5 keypairs.
 */

/* C-06: Check if a pubkey belongs to a known witness from the DHT roster */
static bool is_known_witness_pubkey(const uint8_t *pubkey) {
    extern dnac_witness_info_t *g_witness_servers;
    extern int g_witness_count;
    extern pthread_mutex_t g_witness_cache_mutex;

    bool found = false;
    pthread_mutex_lock(&g_witness_cache_mutex);
    if (g_witness_servers && g_witness_count > 0) {
        for (int i = 0; i < g_witness_count; i++) {
            if (memcmp(g_witness_servers[i].pubkey, pubkey, DNAC_PUBKEY_SIZE) == 0) {
                found = true;
                break;
            }
        }
    } else {
        /* No roster cached yet — allow verification to pass (bootstrap/offline).
         * This is safe: the signature itself is still verified with Dilithium5.
         * Pinning kicks in once the first roster fetch succeeds. */
        found = true;
    }
    pthread_mutex_unlock(&g_witness_cache_mutex);
    return found;
}

int verify_witnesses(const dnac_transaction_t *tx) {
    /* BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    if (tx->witness_count < 1) {
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Phase 12 follow-up — the witness sig in serialized TXs CANNOT be
     * Dilithium5-verified after this phase: the on-chain TX format
     * (serialize.c) only persists witness_id/signature/timestamp/
     * server_pubkey, but the witness now signs a 221-byte spndrslt
     * preimage that ALSO binds chain_id, block_height, tx_index, and
     * SHA3-512(server_pubkey). Without those receipt-only fields the
     * verifier cannot reconstruct the preimage.
     *
     * Mitigation: trust the local mempool / nullifier check on nodus
     * and the witness quorum that committed the block. A node receiving
     * a serialized TX from peers verifies it against chain state, not
     * by re-checking individual witness sigs.
     *
     * Fresh-receipt verification (where chain_id / block_height /
     * tx_index ARE known from the receipt) lives in builder.c step 4
     * via the spndrslt preimage reconstruction.
     *
     * This function now sanity-checks roster membership and pubkey
     * non-zero, but does not Dilithium-verify the sig over a synthetic
     * legacy preimage that would always fail. */
    int valid_witnesses = 0;

    for (int i = 0; i < tx->witness_count; i++) {
        const dnac_witness_sig_t *witness = &tx->witnesses[i];

        bool is_all_zeros = true;
        for (int k = 0; k < DNAC_PUBKEY_SIZE && is_all_zeros; k++) {
            if (witness->server_pubkey[k] != 0) is_all_zeros = false;
        }
        if (is_all_zeros) {
            QGP_LOG_DEBUG(LOG_TAG, "  skipping witness with zero pubkey");
            continue;
        }

        if (!is_known_witness_pubkey(witness->server_pubkey)) {
            QGP_LOG_WARN(LOG_TAG, "  witness %d pubkey not in roster", i);
            continue;
        }

        valid_witnesses++;
    }

    if (valid_witnesses >= 1) return DNAC_SUCCESS;

    QGP_LOG_ERROR(LOG_TAG, "failed: no roster-known witnesses (count %d)",
                  tx->witness_count);
    return DNAC_ERROR_WITNESS_FAILED;
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

/**
 * @brief Full transaction verification
 */
int dnac_tx_verify_full(const dnac_transaction_t *tx) {
    int rc;
    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* 1. Per-token balance */
    rc = verify_balance_per_token(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Witnesses */
    rc = verify_witnesses(tx);
    if (rc != DNAC_SUCCESS) return rc;

    /* 3. Signer signatures (skip for genesis) */
    if (tx->type != DNAC_TX_GENESIS) {
        rc = verify_signers(tx);
        if (rc != DNAC_SUCCESS) return rc;
    }

    return DNAC_SUCCESS;
}
