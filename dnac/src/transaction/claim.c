/**
 * @file claim.c
 * @brief CLAIM_REWARD transaction builder (Phase 7, Task 36).
 *
 * Public API (see dnac.h):
 *   - dnac_claim_reward() — build + broadcast a DNAC_TX_CLAIM_REWARD
 *
 * Design-doc references: §2.3 (claim_reward_fields), §2.4 / Rule K
 * (valid_before_block freshness), Rule L (dynamic dust floor).
 *
 * Plan-deviation note: the design sketch for Task 36 specified
 *   dnac_claim_reward(ctx, target_validator)
 * and had the builder internally query pending_rewards + current_block.
 * Those RPCs are Phase 14 Task 61 / 38 work — they don't exist yet. We
 * therefore expose max_pending_amount and valid_before_block as explicit
 * parameters now, so CLI + Flutter can construct the TX in advance of
 * Phase 14 shipping. A future thin wrapper
 *   dnac_claim_reward_auto(ctx, validator)
 * will internally query the witness and call this builder — the builder
 * signature stays stable for the life of the protocol.
 *
 * The actual reward UTXO output is NOT added here; the witness emits it
 * at state-apply time (Phase 8 Task 44) after validating the claim
 * against its internal reward_accrual table. The builder only funds the
 * fee and signs the freshness envelope.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/safe_math.h"

#include <dna/dna_engine.h>

#include "crypto/utils/qgp_log.h"
#include "nodus_init.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DNAC_CLAIM"

/* ============================================================================
 * dnac_claim_reward — build and broadcast a DNAC_TX_CLAIM_REWARD
 * ========================================================================== */

int dnac_claim_reward(dnac_context_t *ctx,
                      const uint8_t *target_validator_pubkey,
                      uint64_t max_pending_amount,
                      uint64_t valid_before_block,
                      dnac_callback_t callback,
                      void *user_data) {
    if (!ctx)                         return DNAC_ERROR_INVALID_PARAM;
    if (!target_validator_pubkey)     return DNAC_ERROR_INVALID_PARAM;
    if (max_pending_amount == 0)      return DNAC_ERROR_INVALID_PARAM;
    if (valid_before_block == 0)      return DNAC_ERROR_INVALID_PARAM;

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!owner_fp || !engine) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    int rc;

    /* 1. Fee. */
    uint64_t fee = 0;
    rc = dnac_get_current_fee(ctx, &fee);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Select native UTXOs for the fee. */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(ctx, fee, NULL,
                                        &selected, &selected_count,
                                        &change_amount);
    if (rc != DNAC_SUCCESS) return rc;

    uint64_t total_input = 0;
    for (int i = 0; i < selected_count; i++) {
        if (safe_add_u64(total_input, selected[i].amount, &total_input) != 0) {
            free(selected);
            return DNAC_ERROR_OVERFLOW;
        }
    }
    if (total_input < fee) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - fee;

    /* 3. Construct TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_CLAIM_REWARD);
    if (!tx) {
        free(selected);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    for (int i = 0; i < selected_count; i++) {
        rc = dnac_tx_add_input(tx, &selected[i]);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            dnac_free_transaction(tx);
            return rc;
        }
    }
    free(selected);
    selected = NULL;

    if (change_amount > 0) {
        uint8_t change_seed[32];
        rc = dnac_tx_add_output(tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
    }

    /* 4. Appended fields. */
    memcpy(tx->claim_reward_fields.target_validator, target_validator_pubkey,
           DNAC_PUBKEY_SIZE);
    tx->claim_reward_fields.max_pending_amount = max_pending_amount;
    tx->claim_reward_fields.valid_before_block = valid_before_block;

    /* 5. Chain_id binding. */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 6. Signer. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;

    /* 7. Hash + sign. */
    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    size_t sig_len = 0;
    rc = dna_engine_sign_data(engine,
                              tx->tx_hash, DNAC_TX_HASH_SIZE,
                              tx->signers[0].signature, &sig_len);
    if (rc != 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    /* 8. Broadcast. */
    rc = dnac_tx_broadcast(ctx, tx, callback, user_data);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG,
                 "CLAIM_REWARD submitted "
                 "(max_pending=%llu, valid_before_block=%llu, change=%llu)",
                 (unsigned long long)max_pending_amount,
                 (unsigned long long)valid_before_block,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}
