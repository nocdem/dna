/**
 * @file token_create.c
 * @brief TOKEN_CREATE client — create, list, info
 *
 * Builds and broadcasts TX_TOKEN_CREATE transactions.
 * Also provides token_list and token_info wrappers around
 * the Nodus client SDK.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "dnac/safe_math.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "nodus_init.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

/* Nodus client SDK */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Nodus singleton access */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "DNAC_TOKEN"

/** Fee for creating a token: 1 DNAC = 100,000,000 raw units.
 *  Must match NODUS_W_TOKEN_CREATE_FEE in nodus_types.h. */
#define TOKEN_CREATE_FEE  100000000ULL

/* ============================================================================
 * dnac_token_create — Build and broadcast TX_TOKEN_CREATE
 * ========================================================================== */

int dnac_token_create(dnac_context_t *ctx,
                      const char *name, const char *symbol,
                      uint8_t decimals, uint64_t supply) {
    if (!ctx || !name || !symbol) return DNAC_ERROR_INVALID_PARAM;
    if (strlen(name) == 0 || strlen(name) > 32) return DNAC_ERROR_INVALID_PARAM;
    if (strlen(symbol) == 0 || strlen(symbol) > 8) return DNAC_ERROR_INVALID_PARAM;
    if (decimals > 18) return DNAC_ERROR_INVALID_PARAM;
    if (supply == 0) return DNAC_ERROR_INVALID_PARAM;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    if (!owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    int rc;

    /* 1. Derive token_id = SHA3-512(creator_fp || name || timestamp) */
    uint64_t nonce = (uint64_t)time(NULL);
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];
    {
        uint8_t hash_input[256];
        size_t fp_len = strlen(owner_fp);
        size_t name_len = strlen(name);
        size_t offset = 0;

        if (fp_len + name_len + 8 > sizeof(hash_input)) {
            return DNAC_ERROR_INVALID_PARAM;
        }

        memcpy(hash_input + offset, owner_fp, fp_len);
        offset += fp_len;
        memcpy(hash_input + offset, name, name_len);
        offset += name_len;
        memcpy(hash_input + offset, &nonce, 8);
        offset += 8;

        if (qgp_sha3_512(hash_input, offset, token_id) != 0) {
            return DNAC_ERROR_CRYPTO;
        }
    }

    /* 2. Select DNAC UTXOs to cover the creation fee */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos(ctx, TOKEN_CREATE_FEE,
                                  &selected, &selected_count, &change_amount);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO selection failed: %d", rc);
        return rc;
    }

    /* Calculate actual total input */
    uint64_t total_input = 0;
    for (int i = 0; i < selected_count; i++) {
        if (safe_add_u64(total_input, selected[i].amount, &total_input) != 0) {
            free(selected);
            return DNAC_ERROR_OVERFLOW;
        }
    }

    if (total_input < TOKEN_CREATE_FEE) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - TOKEN_CREATE_FEE;

    /* 3. Build TOKEN_CREATE transaction */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_TOKEN_CREATE);
    if (!tx) {
        free(selected);
        return DNAC_ERROR_OUT_OF_MEMORY;
    }
    tx->timestamp = nonce;

    /* 4. Add inputs (fee payment, native DNAC — token_id stays zeros) */
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

    /* 5. Add outputs:
     *    output[0] = genesis supply: owner=creator, amount=supply, token_id=new
     *    output[1] = change: owner=creator, amount=change, token_id=zeros (DNAC native)
     *
     * The memo on the genesis output carries "name:symbol:decimals" as metadata.
     */

    /* Output 0: Token genesis supply */
    {
        char memo[DNAC_MEMO_MAX_SIZE];
        int memo_len = snprintf(memo, sizeof(memo), "%s:%s:%u", name, symbol, (unsigned)decimals);
        if (memo_len < 0 || (size_t)memo_len >= sizeof(memo)) {
            dnac_free_transaction(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }

        uint8_t nullifier_seed[32];
        rc = dnac_tx_add_output_with_memo(tx, owner_fp, supply,
                                          nullifier_seed, memo, (uint8_t)memo_len);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }

        /* Set the token_id on this output to the derived new token ID */
        memcpy(tx->outputs[tx->output_count - 1].token_id, token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Output 1: Change (native DNAC, token_id stays zeros) */
    if (change_amount > 0) {
        uint8_t change_seed[32];
        rc = dnac_tx_add_output(tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
        /* token_id on change output is already zeros (native DNAC) from calloc */
    }

    /* 6. Get sender's public key and sign */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    rc = dna_engine_get_signing_public_key(engine, sender_pubkey, sizeof(sender_pubkey));
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    memcpy(tx->signers[0].pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;

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

    /* 7. Serialize + send to witness */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(request.sender_pubkey, tx->signers[0].pubkey, DNAC_PUBKEY_SIZE);
    memcpy(request.signature, tx->signers[0].signature, DNAC_SIGNATURE_SIZE);
    request.timestamp = (uint64_t)time(NULL);

    size_t tx_serialized_len = 0;
    rc = dnac_tx_serialize(tx, request.tx_data, sizeof(request.tx_data), &tx_serialized_len);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }
    request.tx_len = (uint32_t)tx_serialized_len;
    request.fee_amount = TOKEN_CREATE_FEE;

    /* Store pending spends */
    uint64_t expires_at = request.timestamp + 300;
    for (int i = 0; i < tx->input_count; i++) {
        dnac_db_store_pending_spend(db, tx->tx_hash,
                                   tx->inputs[i].nullifier,
                                   DNAC_WITNESSES_REQUIRED, expires_at);
    }

    /* Request witness attestation */
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count = 0;

    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);
    if (rc != DNAC_SUCCESS || witness_count < 1) {
        dnac_db_expire_pending_spends(db);

        if (rc == DNAC_ERROR_DOUBLE_SPEND) {
            for (int i = 0; i < tx->input_count; i++) {
                dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier, tx->tx_hash);
            }
        }

        QGP_LOG_ERROR(LOG_TAG, "Witness request failed: %d (count=%d)", rc, witness_count);
        dnac_free_transaction(tx);
        return (rc != DNAC_SUCCESS) ? rc : DNAC_ERROR_WITNESS_FAILED;
    }

    /* Verify and add witness signatures */
    for (int i = 0; i < witness_count; i++) {
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, tx->tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, witnesses[i].witness_id, 32);
        for (int j = 0; j < 8; j++)
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] =
                (witnesses[i].timestamp >> (j * 8)) & 0xFF;

        if (qgp_dsa87_verify(witnesses[i].signature, DNAC_SIGNATURE_SIZE,
                              signed_data, sizeof(signed_data),
                              witnesses[i].server_pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Witness %d signature verification failed", i);
            dnac_free_transaction(tx);
            return DNAC_ERROR_WITNESS_FAILED;
        }

        rc = dnac_tx_add_witness(tx, &witnesses[i]);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
    }

    /* 8. On success: update local DB */
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    /* Store the token in local registry */
    dnac_token_t token_entry = {0};
    memcpy(token_entry.token_id, token_id, DNAC_TOKEN_ID_SIZE);
    strncpy(token_entry.name, name, sizeof(token_entry.name) - 1);
    strncpy(token_entry.symbol, symbol, sizeof(token_entry.symbol) - 1);
    token_entry.decimals = decimals;
    token_entry.initial_supply = supply;
    strncpy(token_entry.creator_fp, owner_fp, DNAC_FINGERPRINT_SIZE - 1);
    token_entry.flags = 0;
    token_entry.block_height = 0;  /* Will be updated on sync */
    token_entry.timestamp = nonce;

    rc = dnac_db_store_token(db, &token_entry);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_WARN(LOG_TAG, "Failed to store token locally: %d", rc);
    }

    /* Store genesis UTXO (output[0] = token supply) */
    {
        dnac_utxo_t utxo = {0};
        utxo.version = tx->outputs[0].version;
        memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = 0;
        utxo.amount = tx->outputs[0].amount;
        strncpy(utxo.owner_fingerprint, owner_fp, sizeof(utxo.owner_fingerprint) - 1);
        memcpy(utxo.token_id, token_id, DNAC_TOKEN_ID_SIZE);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        /* Derive nullifier from owner fingerprint and seed */
        uint8_t nullifier_data[256];
        size_t fp_len = strlen(owner_fp);
        memcpy(nullifier_data, owner_fp, fp_len);
        memcpy(nullifier_data + fp_len, tx->outputs[0].nullifier_seed, 32);
        if (qgp_sha3_512(nullifier_data, fp_len + 32, utxo.nullifier) == 0) {
            rc = dnac_db_store_utxo(db, &utxo);
            if (rc != DNAC_SUCCESS) {
                QGP_LOG_WARN(LOG_TAG, "Failed to store genesis UTXO: %d", rc);
            }
        }
    }

    /* Store change UTXO if present (output[1] = DNAC change) */
    if (change_amount > 0 && tx->output_count > 1) {
        int ci = 1;  /* Change output index */
        dnac_utxo_t utxo = {0};
        utxo.version = tx->outputs[ci].version;
        memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = (uint32_t)ci;
        utxo.amount = tx->outputs[ci].amount;
        strncpy(utxo.owner_fingerprint, owner_fp, sizeof(utxo.owner_fingerprint) - 1);
        /* token_id stays zeros = native DNAC */
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        uint8_t nullifier_data[256];
        size_t fp_len = strlen(owner_fp);
        memcpy(nullifier_data, owner_fp, fp_len);
        memcpy(nullifier_data + fp_len, tx->outputs[ci].nullifier_seed, 32);
        if (qgp_sha3_512(nullifier_data, fp_len + 32, utxo.nullifier) == 0) {
            rc = dnac_db_store_utxo(db, &utxo);
            if (rc != DNAC_SUCCESS) {
                QGP_LOG_WARN(LOG_TAG, "Failed to store change UTXO: %d", rc);
            }
        }
    }

    /* Mark input UTXOs as spent */
    for (int i = 0; i < tx->input_count; i++) {
        dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier, tx->tx_hash);
    }

    /* Store transaction in history */
    {
        uint8_t *tx_buffer = malloc(65536);
        if (tx_buffer) {
            size_t tx_len = 0;
            rc = dnac_tx_serialize(tx, tx_buffer, 65536, &tx_len);
            if (rc == DNAC_SUCCESS) {
                uint64_t total_out = dnac_tx_total_output(tx);
                dnac_db_store_transaction(db, tx->tx_hash, tx_buffer, tx_len,
                                          tx->type, NULL,
                                          total_input, total_out, TOKEN_CREATE_FEE);
            }
            free(tx_buffer);
        }
    }

    /* Complete pending spends */
    dnac_db_complete_pending_spend(db, tx->tx_hash);

    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    QGP_LOG_INFO(LOG_TAG, "Token created: %s (%s), supply=%llu, decimals=%u",
                 name, symbol, (unsigned long long)supply, (unsigned)decimals);

    dnac_free_transaction(tx);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * dnac_token_list — Query tokens from witness via Nodus SDK
 * ========================================================================== */

int dnac_token_list(dnac_context_t *ctx, dnac_token_t *out, int max, int *count) {
    if (!ctx || !out || !count || max <= 0) return DNAC_ERROR_INVALID_PARAM;

    *count = 0;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_token_list_result_t result = {0};
    int rc = nodus_client_dnac_token_list(client, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "token_list failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Convert nodus types to DNAC types */
    int n = (result.count < max) ? result.count : max;
    for (int i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        memcpy(out[i].token_id, result.tokens[i].token_id, DNAC_TOKEN_ID_SIZE);
        strncpy(out[i].name, result.tokens[i].name, sizeof(out[i].name) - 1);
        strncpy(out[i].symbol, result.tokens[i].symbol, sizeof(out[i].symbol) - 1);
        out[i].decimals = result.tokens[i].decimals;
        out[i].initial_supply = result.tokens[i].supply;
        strncpy(out[i].creator_fp, result.tokens[i].creator_fp, DNAC_FINGERPRINT_SIZE - 1);
    }
    *count = n;

    /* Also store tokens in local DB for offline access */
    sqlite3 *db = dnac_get_db(ctx);
    if (db) {
        for (int i = 0; i < n; i++) {
            dnac_db_store_token(db, &out[i]);
        }
    }

    nodus_client_free_token_list_result(&result);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * dnac_token_info — Query single token from witness via Nodus SDK
 * ========================================================================== */

int dnac_token_info(dnac_context_t *ctx, const uint8_t *token_id, dnac_token_t *out) {
    if (!ctx || !token_id || !out) return DNAC_ERROR_INVALID_PARAM;

    memset(out, 0, sizeof(*out));

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus singleton not initialized");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_token_info_t result = {0};
    int rc = nodus_client_dnac_token_info(client, token_id, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "token_info failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Convert nodus type to DNAC type */
    memcpy(out->token_id, result.token_id, DNAC_TOKEN_ID_SIZE);
    strncpy(out->name, result.name, sizeof(out->name) - 1);
    strncpy(out->symbol, result.symbol, sizeof(out->symbol) - 1);
    out->decimals = result.decimals;
    out->initial_supply = result.supply;
    strncpy(out->creator_fp, result.creator_fp, DNAC_FINGERPRINT_SIZE - 1);

    /* Cache in local DB */
    sqlite3 *db = dnac_get_db(ctx);
    if (db) {
        dnac_db_store_token(db, out);
    }

    return DNAC_SUCCESS;
}
