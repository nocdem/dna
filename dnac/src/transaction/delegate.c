/**
 * @file delegate.c
 * @brief DELEGATE / UNDELEGATE transaction builders (Phase 7, Task 35).
 *
 * Public API (see dnac.h):
 *   - dnac_delegate()   — build + broadcast a DNAC_TX_DELEGATE
 *   - dnac_undelegate() — build + broadcast a DNAC_TX_UNDELEGATE
 *
 * Design-doc references: §2.3 (appended fields), §2.4 / Rule B (validator
 * ACTIVE), Rule G (<64 delegations/delegator), Rule J (min delegation),
 * Rule O (EPOCH_LENGTH hold), Rule Q (two-UTXO UNDELEGATE payout),
 * Rule S (no self-delegation).
 *
 * Rule S (signer != validator_pubkey) is enforced here at the client.
 * Rules B / G / O run witness-side at state-apply time.
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

#define LOG_TAG "DNAC_DELEGATE"

/* ============================================================================
 * dnac_delegate — build and broadcast a DNAC_TX_DELEGATE
 * ========================================================================== */

int dnac_delegate(dnac_context_t *ctx,
                  const uint8_t *validator_pubkey,
                  uint64_t amount,
                  dnac_callback_t callback,
                  void *user_data) {
    if (!ctx)                    return DNAC_ERROR_INVALID_PARAM;
    if (!validator_pubkey)       return DNAC_ERROR_INVALID_PARAM;
    if (amount < DNAC_MIN_DELEGATION) {
        QGP_LOG_ERROR(LOG_TAG,
            "delegation amount %llu below minimum %llu",
            (unsigned long long)amount,
            (unsigned long long)DNAC_MIN_DELEGATION);
        return DNAC_ERROR_INVALID_PARAM;
    }

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!owner_fp || !engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Fetch caller's pubkey early to enforce Rule S (no self-delegation).
     * This also confirms the engine is usable before doing any network
     * work — symmetric with dnac_stake's guard ordering. */
    uint8_t signer_pubkey[DNAC_PUBKEY_SIZE];
    int rc = dna_engine_get_signing_public_key(engine, signer_pubkey,
                                               sizeof(signer_pubkey));
    if (rc < 0) return DNAC_ERROR_CRYPTO;

    if (memcmp(signer_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "self-delegation rejected (Rule S)");
        return DNAC_ERROR_INVALID_PARAM;
    }

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    /* 1. Current fee. */
    uint64_t fee = 0;
    rc = dnac_get_current_fee(ctx, &fee);
    if (rc != DNAC_SUCCESS) return rc;

    /* 2. Select native UTXOs covering amount + fee. */
    uint64_t need = 0;
    if (safe_add_u64(amount, fee, &need) != 0) return DNAC_ERROR_OVERFLOW;

    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(ctx, need, NULL,
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
    if (total_input < need) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - need;

    /* 3. Construct TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_DELEGATE);
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

    /* 4. Appended fields (v0.17.1: delegation_amount is explicit on wire). */
    memcpy(tx->delegate_fields.validator_pubkey, validator_pubkey,
           DNAC_PUBKEY_SIZE);
    tx->delegate_fields.delegation_amount = amount;

    /* 5. Chain_id binding. */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 6. Signer + committed_fee. */
    memcpy(tx->signers[0].pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;
    tx->committed_fee = fee;   /* v0.17.1 — explicit native fee in wire/preimage */

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
                 "DELEGATE submitted (amount=%llu, change=%llu)",
                 (unsigned long long)amount,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * dnac_undelegate — build and broadcast a DNAC_TX_UNDELEGATE
 * ========================================================================== */

int dnac_undelegate(dnac_context_t *ctx,
                    const uint8_t *validator_pubkey,
                    uint64_t amount,
                    dnac_callback_t callback,
                    void *user_data) {
    if (!ctx)              return DNAC_ERROR_INVALID_PARAM;
    if (!validator_pubkey) return DNAC_ERROR_INVALID_PARAM;
    if (amount == 0)       return DNAC_ERROR_INVALID_PARAM;

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
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_UNDELEGATE);
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
    memcpy(tx->undelegate_fields.validator_pubkey, validator_pubkey,
           DNAC_PUBKEY_SIZE);
    tx->undelegate_fields.amount = amount;

    /* 5. Chain_id binding. */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 6. Signer + committed_fee. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;
    tx->committed_fee = fee;   /* v0.17.1 — explicit native fee in wire/preimage */

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
                 "UNDELEGATE submitted (amount=%llu, change=%llu)",
                 (unsigned long long)amount,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}
