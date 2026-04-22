/**
 * @file chain_config.c
 * @brief DNAC_TX_CHAIN_CONFIG transaction builder (Hard-Fork v1 Stage E).
 *
 * Takes proposal parameters + pre-collected committee votes, builds a
 * DNAC_TX_CHAIN_CONFIG, signs as the proposer, and broadcasts. Modeled
 * after validator_update.c — fee-only TX with no non-change outputs.
 *
 * The witness-side apply path (nodus_chain_config_apply) runs the full
 * consensus rule set: re-verifies every vote signature against current
 * committee pubkeys, checks grace / freshness / monotonicity, and
 * INSERTs into chain_config_history before the state_root is recomputed.
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

#define LOG_TAG "DNAC_CHAIN_CONFIG"

int dnac_chain_config_propose(dnac_context_t *ctx,
                               uint8_t  param_id,
                               uint64_t new_value,
                               uint64_t effective_block,
                               uint64_t proposal_nonce,
                               uint64_t signed_at_block,
                               uint64_t valid_before,
                               const dnac_chain_config_collected_vote_t *votes,
                               uint8_t  vote_count,
                               dnac_callback_t callback,
                               void *user_data) {
    if (!ctx || !votes) return DNAC_ERROR_INVALID_PARAM;
    if (vote_count < DNAC_CHAIN_CONFIG_MIN_SIGS ||
        vote_count > DNAC_CHAIN_CONFIG_MAX_SIGS) {
        QGP_LOG_ERROR(LOG_TAG, "vote_count=%u outside [%d,%d]",
                      (unsigned)vote_count,
                      DNAC_CHAIN_CONFIG_MIN_SIGS,
                      DNAC_CHAIN_CONFIG_MAX_SIGS);
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (param_id < 1 || param_id > DNAC_CFG_PARAM_MAX_ID) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (signed_at_block == 0) return DNAC_ERROR_INVALID_PARAM;
    if (valid_before <= effective_block) return DNAC_ERROR_INVALID_PARAM;
    if (valid_before <= signed_at_block) return DNAC_ERROR_INVALID_PARAM;

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!owner_fp || !engine) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    int rc;

    /* 1. Current fee. */
    uint64_t fee = 0;
    rc = dnac_get_current_fee(ctx, &fee);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "dnac_get_current_fee failed: %d", rc);
        return rc;
    }

    /* 2. Select native UTXOs to cover the fee. */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;
    rc = dnac_wallet_select_utxos_token(ctx, fee, NULL,
                                        &selected, &selected_count,
                                        &change_amount);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO selection failed: %d", rc);
        return rc;
    }

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

    /* 3. Build TX. */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_CHAIN_CONFIG);
    if (!tx) {
        free(selected);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }

    /* 4. Inputs. */
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

    /* 5. Change output (native DNAC, caller) if any. */
    if (change_amount > 0) {
        uint8_t change_seed[32];
        rc = dnac_tx_add_output(tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
    }

    /* 6. Populate chain_config_fields. */
    dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
    cc->param_id               = param_id;
    cc->new_value              = new_value;
    cc->effective_block_height = effective_block;
    cc->proposal_nonce         = proposal_nonce;
    cc->signed_at_block        = signed_at_block;
    cc->valid_before_block     = valid_before;
    cc->committee_sig_count    = vote_count;
    for (uint8_t i = 0; i < vote_count; i++) {
        memcpy(cc->committee_votes[i].witness_id,
               votes[i].witness_id, 32);
        memcpy(cc->committee_votes[i].signature,
               votes[i].signature, DNAC_SIGNATURE_SIZE);
    }

    /* 7. Chain_id binding. */
    {
        const uint8_t *cid = dnac_get_chain_id(ctx);
        if (cid) memcpy(tx->chain_id, cid, 32);
    }

    /* 8. Signer = proposer. */
    rc = dna_engine_get_signing_public_key(engine, tx->signers[0].pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }
    tx->signer_count = 1;
    tx->committed_fee = fee;   /* v0.17.1 — fee-only TX */

    /* 9. Compute tx_hash (binds all chain_config_fields including votes). */
    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    /* 10. Sign as proposer. */
    size_t sig_len = 0;
    rc = dna_engine_sign_data(engine,
                              tx->tx_hash, DNAC_TX_HASH_SIZE,
                              tx->signers[0].signature, &sig_len);
    if (rc != 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    /* 11. Broadcast. */
    rc = dnac_tx_broadcast(ctx, tx, callback, user_data);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG,
                 "CHAIN_CONFIG TX submitted: param=%u value=%llu "
                 "effective=%llu votes=%u change=%llu",
                 (unsigned)param_id,
                 (unsigned long long)new_value,
                 (unsigned long long)effective_block,
                 (unsigned)vote_count,
                 (unsigned long long)change_amount);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}
