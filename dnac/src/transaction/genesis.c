/**
 * @file genesis.c
 * @brief GENESIS transaction - one-time token creation
 *
 * GENESIS transactions create the total token supply at system initialization.
 * Unlike the removed MINT:
 * - Can only happen once (checked by witnesses)
 * - Requires 3-of-3 (unanimous) witness approval
 * - Supports multiple recipients for initial distribution
 * - After genesis, only SPEND/BURN transactions are valid
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/dnac.h"
#include "dnac/genesis.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "dnac/ledger.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/crypto_helpers.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/sign/qgp_dilithium.h"
#include <dna/dna_engine.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>
#include "dnac/safe_math.h"

#define LOG_TAG "GENESIS"

#include "nodus_init.h"


/**
 * Derive nullifier from owner fingerprint and seed
 * nullifier = SHA3-512(owner_fingerprint || nullifier_seed)
 */
static int derive_nullifier_for_genesis(const char *owner_fp, const uint8_t *seed,
                                        uint8_t *nullifier_out) {
    uint8_t data[256];
    size_t offset = 0;

    size_t fp_len = strlen(owner_fp);
    memcpy(data, owner_fp, fp_len);
    offset = fp_len;

    memcpy(data + offset, seed, 32);
    offset += 32;

    return qgp_sha3_512(data, offset, nullifier_out);
}

int dnac_tx_create_genesis(const dnac_genesis_recipient_t *recipients,
                           int recipient_count,
                           dnac_transaction_t **tx_out) {
    if (!recipients || recipient_count <= 0 ||
        recipient_count > DNAC_GENESIS_MAX_RECIPIENTS || !tx_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Validate recipients */
    uint64_t total_supply = 0;
    for (int i = 0; i < recipient_count; i++) {
        if (recipients[i].amount == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Recipient %d has zero amount", i);
            return DNAC_ERROR_INVALID_PARAM;
        }
        if (recipients[i].fingerprint[0] == '\0') {
            QGP_LOG_ERROR(LOG_TAG, "Recipient %d has empty fingerprint", i);
            return DNAC_ERROR_INVALID_PARAM;
        }
        /* HIGH-3: Safe overflow check on total supply */
        if (safe_add_u64(total_supply, recipients[i].amount, &total_supply) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Total supply overflow at recipient %d", i);
            return DNAC_ERROR_OVERFLOW;
        }
    }

    /* Create GENESIS transaction */
    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_GENESIS);
    if (!tx) return DNAC_ERROR_OUT_OF_MEMORY;

    tx->input_count = 0;  /* No inputs for GENESIS */

    /* Add outputs for each recipient */
    for (int i = 0; i < recipient_count; i++) {
        uint8_t nullifier_seed[32];
        if (qgp_randombytes(nullifier_seed, 32) != 0) {
            dnac_free_transaction(tx);
            return DNAC_ERROR_RANDOM_FAILED;
        }

        int rc = dnac_tx_add_output(tx, recipients[i].fingerprint,
                                    recipients[i].amount, nullifier_seed);
        if (rc != DNAC_SUCCESS) {
            dnac_free_transaction(tx);
            return rc;
        }
    }

    /* Compute transaction hash */
    int rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG, "Created GENESIS tx: %llu total to %d recipients",
                 (unsigned long long)total_supply, recipient_count);

    *tx_out = tx;
    return DNAC_SUCCESS;
}

int dnac_tx_authorize_genesis(dnac_context_t *ctx, dnac_transaction_t *tx) {
    if (!ctx || !tx || tx->type != DNAC_TX_GENESIS) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Build genesis request - serialize the GENESIS transaction */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);

    /* Serialize the GENESIS transaction into tx_data */
    size_t tx_serialized_len = 0;
    int rc = dnac_tx_serialize(tx, request.tx_data, sizeof(request.tx_data), &tx_serialized_len);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }
    request.tx_len = (uint32_t)tx_serialized_len;

    request.timestamp = (uint64_t)time(NULL);
    request.fee_amount = 0;  /* No fee for genesis */

    rc = dna_engine_get_signing_public_key(engine, request.sender_pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) return DNAC_ERROR_CRYPTO;

    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = dna_engine_sign_data(engine, request.tx_hash, DNAC_TX_HASH_SIZE,
                               request.signature, &sig_len);
    if (rc < 0) return DNAC_ERROR_SIGN_FAILED;

    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count = 0;

    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);

    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Genesis rejected: rc=%d witnesses=%d", rc, witness_count);
        if (rc == DNAC_ERROR_GENESIS_EXISTS) {
            return DNAC_ERROR_GENESIS_EXISTS;
        }
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /*
     * Gap 17 Fix (v0.6.0): Verify genesis witness signatures cryptographically.
     *
     * GENESIS requires 3-of-3 (unanimous) witness approval. In current BFT mode,
     * we receive 1 attestation that proves quorum was reached. The witness-side
     * enforces 3-of-3 during pre-authorization. Here we verify what we received.
     *
     * NOTE: For full 3-of-3 client verification, protocol would need to return
     * all 3 attestations. Currently we verify the signatures we receive.
     */
    if (witness_count < DNAC_GENESIS_WITNESSES_REQUIRED) {
        QGP_LOG_ERROR(LOG_TAG, "Genesis requires %d witness attestations (unanimous), got %d",
                      DNAC_GENESIS_WITNESSES_REQUIRED, witness_count);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Verify each witness signature */
    for (int i = 0; i < witness_count; i++) {
        const dnac_witness_sig_t *witness = &witnesses[i];

        /* Check pubkey is not all zeros (placeholder) */
        bool is_zero = true;
        for (int k = 0; k < DNAC_PUBKEY_SIZE && is_zero; k++) {
            if (witness->server_pubkey[k] != 0) is_zero = false;
        }
        if (is_zero) {
            QGP_LOG_ERROR(LOG_TAG, "Genesis witness %d has invalid pubkey", i);
            return DNAC_ERROR_INVALID_SIGNATURE;
        }

        /* Build signed data: tx_hash + witness_id + timestamp */
        uint8_t signed_data[DNAC_TX_HASH_SIZE + 32 + 8];
        memcpy(signed_data, tx->tx_hash, DNAC_TX_HASH_SIZE);
        memcpy(signed_data + DNAC_TX_HASH_SIZE, witness->witness_id, 32);
        for (int j = 0; j < 8; j++) {
            signed_data[DNAC_TX_HASH_SIZE + 32 + j] = (witness->timestamp >> (j * 8)) & 0xFF;
        }

        /* Verify Dilithium5 signature */
        int verify_rc = qgp_dsa87_verify(witness->signature, DNAC_SIGNATURE_SIZE,
                                          signed_data, sizeof(signed_data),
                                          witness->server_pubkey);
        if (verify_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Genesis witness %d signature invalid", i);
            return DNAC_ERROR_INVALID_SIGNATURE;
        }
        QGP_LOG_DEBUG(LOG_TAG, "Genesis witness %d signature verified", i);
    }

    /* Verify witnesses are distinct (no duplicates) */
    for (int i = 0; i < witness_count; i++) {
        for (int j = i + 1; j < witness_count; j++) {
            if (memcmp(witnesses[i].witness_id, witnesses[j].witness_id, 32) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "Duplicate witness in genesis: witness %d == %d", i, j);
                return DNAC_ERROR_INVALID_PARAM;  /* Duplicate witness */
            }
        }
    }

    for (int i = 0; i < witness_count; i++) {
        dnac_tx_add_witness(tx, &witnesses[i]);
    }

    QGP_LOG_INFO(LOG_TAG, "Genesis authorized: %d witness signature(s) verified",
                 witness_count);
    return DNAC_SUCCESS;
}

int dnac_tx_broadcast_genesis(dnac_context_t *ctx, dnac_transaction_t *tx) {
    if (!ctx || !tx || tx->type != DNAC_TX_GENESIS) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Verify we have unanimous witness signatures (H-14: reject partial genesis) */
    if (tx->witness_count < DNAC_GENESIS_WITNESSES_REQUIRED) {
        QGP_LOG_ERROR(LOG_TAG, "Genesis not authorized - need %d witnesses, have %d",
                      DNAC_GENESIS_WITNESSES_REQUIRED, tx->witness_count);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    int rc;
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    if (!nodus_messenger_wait_for_ready(5000)) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not ready after 5s — cannot broadcast genesis");
        return DNAC_ERROR_NETWORK;
    }

    /* Get our own fingerprint for "genesis to self" detection */
    const char *our_fp = dnac_get_owner_fingerprint(ctx);

    /* Serialize transaction */
    uint8_t *tx_buffer = malloc(65536);
    if (!tx_buffer) return DNAC_ERROR_OUT_OF_MEMORY;
    size_t tx_len = 0;
    rc = dnac_tx_serialize(tx, tx_buffer, 65536, &tx_len);
    if (rc != DNAC_SUCCESS) {
        free(tx_buffer);
        return rc;
    }

    /* Store genesis outputs locally */
    uint64_t total_supply = 0;

    for (int i = 0; i < tx->output_count; i++) {
        total_supply += tx->outputs[i].amount;

        /* If output is for our own wallet, store UTXO immediately */
        if (our_fp && strcmp(tx->outputs[i].owner_fingerprint, our_fp) == 0) {
            dnac_utxo_t utxo = {0};
            utxo.version = tx->outputs[i].version;
            memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
            utxo.output_index = (uint32_t)i;
            utxo.amount = tx->outputs[i].amount;
            strncpy(utxo.owner_fingerprint, our_fp, sizeof(utxo.owner_fingerprint) - 1);
            utxo.status = DNAC_UTXO_UNSPENT;
            utxo.received_at = (uint64_t)time(NULL);

            /* Derive nullifier from seed */
            if (derive_nullifier_for_genesis(our_fp, tx->outputs[i].nullifier_seed,
                                             utxo.nullifier) == 0) {
                rc = dnac_db_store_utxo(db, &utxo);
                if (rc == DNAC_SUCCESS) {
                    QGP_LOG_INFO(LOG_TAG, "Stored genesis UTXO locally: %llu coins",
                                 (unsigned long long)utxo.amount);
                }
            }
        }
    }

    /* Store transaction in history */
    const char *counterparty = NULL;
    if (tx->output_count > 0) {
        counterparty = tx->outputs[0].owner_fingerprint;
    }

    rc = dnac_db_store_transaction(db, tx->tx_hash, tx_buffer, tx_len,
                                    tx->type, counterparty,
                                    0, total_supply, 0);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_WARN(LOG_TAG, "Failed to store genesis transaction in history");
    }

    QGP_LOG_INFO(LOG_TAG, "Genesis broadcast complete: %llu total supply to %d recipients",
                 (unsigned long long)total_supply, tx->output_count);

    free(tx_buffer);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Genesis State Query Functions
 * ========================================================================== */

int dnac_genesis_check_exists(dnac_context_t *ctx, bool *exists_out) {
    if (!ctx || !exists_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Query witnesses for supply state - if genesis exists, supply will be non-zero */
    uint64_t genesis_supply = 0;
    int rc = dnac_ledger_get_supply(ctx, &genesis_supply, NULL, NULL);
    if (rc == DNAC_SUCCESS && genesis_supply > 0) {
        *exists_out = true;
    } else {
        *exists_out = false;
    }
    return DNAC_SUCCESS;
}

int dnac_genesis_get_state(dnac_context_t *ctx, dnac_genesis_state_t *state_out) {
    if (!ctx || !state_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    /* Query witnesses for supply state */
    uint64_t genesis_supply = 0;
    uint64_t total_burned = 0;
    uint64_t current_supply = 0;
    int rc = dnac_ledger_get_supply(ctx, &genesis_supply, &total_burned, &current_supply);
    if (rc != DNAC_SUCCESS) {
        return DNAC_ERROR_NO_GENESIS;
    }

    if (genesis_supply == 0) {
        return DNAC_ERROR_NO_GENESIS;
    }

    memset(state_out, 0, sizeof(*state_out));
    state_out->total_supply = genesis_supply;
    /* Note: genesis_hash and genesis_commitment would require ledger query */
    return DNAC_SUCCESS;
}

int dnac_genesis_get_total_supply(dnac_context_t *ctx, uint64_t *supply_out) {
    if (!ctx || !supply_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_genesis_state_t state;
    int rc = dnac_genesis_get_state(ctx, &state);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    *supply_out = state.total_supply;
    return DNAC_SUCCESS;
}

/* ============================================================================
 * Two-Phase Genesis Flow (v0.11.0 - Chain ID)
 * ========================================================================== */

int dnac_genesis_phase1_create(dnac_context_t *ctx,
                                const dnac_genesis_recipient_t *recipients,
                                int recipient_count,
                                dnac_transaction_t **tx_out,
                                uint8_t *chain_id_out) {
    if (!ctx || !recipients || recipient_count <= 0 || !tx_out || !chain_id_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Phase 1a: Create genesis TX (builds outputs, computes tx_hash) */
    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_create_genesis(recipients, recipient_count, &tx);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Phase 1b: Sign tx_hash with sender's Dilithium5 key */
    rc = dna_engine_get_signing_public_key(engine, tx->sender_pubkey,
                                           DNAC_PUBKEY_SIZE);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = dna_engine_sign_data(engine, tx->tx_hash, DNAC_TX_HASH_SIZE,
                               tx->sender_signature, &sig_len);
    if (rc < 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_SIGN_FAILED;
    }

    /* Phase 1c: Derive chain_id from first recipient's fingerprint + tx_hash */
    rc = dnac_derive_chain_id(recipients[0].fingerprint, tx->tx_hash, chain_id_out);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive chain_id from genesis");
        dnac_free_transaction(tx);
        return DNAC_ERROR_CRYPTO;
    }

    QGP_LOG_INFO(LOG_TAG, "Phase 1 complete: genesis TX created + signed, chain_id derived");

    *tx_out = tx;
    return DNAC_SUCCESS;
}

int dnac_genesis_phase2_submit(dnac_context_t *ctx,
                                dnac_transaction_t *tx,
                                const uint8_t *chain_id) {
    if (!ctx || !tx || !chain_id) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    if (tx->type != DNAC_TX_GENESIS) {
        return DNAC_ERROR_INVALID_TX_TYPE;
    }

    /* Phase 2a: Set chain_id on context so witness requests + inbox keys use it */
    dnac_set_chain_id(ctx, chain_id);

    /* Phase 2b: Submit to witnesses for unanimous BFT authorization */
    int rc = dnac_tx_authorize_genesis(ctx, tx);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Phase 2 authorization failed: %d", rc);
        return rc;
    }

    /* Phase 2c: Broadcast genesis TX to recipient DHT inboxes */
    rc = dnac_tx_broadcast_genesis(ctx, tx);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Phase 2 broadcast failed: %d", rc);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG, "Phase 2 complete: genesis authorized + broadcast");
    return DNAC_SUCCESS;
}
