/**
 * @file mint.c
 * @brief MINT transaction (genesis) - creates coins with witness authorization
 *
 * MINT transactions create new coins from nothing. Unlike SPEND transactions:
 * - No inputs (no UTXOs consumed)
 * - Zero nullifier field (distinguishes MINT from SPEND)
 * - Witness 2-of-3 consensus authorizes instead of sender signature
 *
 * This allows initial coin distribution with the same security model
 * as regular transactions - no special "trusted" minting authority.
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_random.h"
#include <dna/dna_engine.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOG_TAG "MINT"

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_put_signed_permanent(dht_context_t *ctx,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *value, size_t value_len,
                                    uint64_t value_id,
                                    const char *caller);

/**
 * Compute SHA3-512 hash of data (copied from builder.c)
 */
static int compute_sha3_512(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return -1;

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, data, len) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash_out, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

/**
 * Build DHT key for payment inbox
 */
static int build_inbox_key(const char *recipient_fp, uint8_t *key_out) {
    uint8_t key_data[256];
    size_t offset = 0;

    const char *prefix = "dnac:inbox:";
    memcpy(key_data, prefix, strlen(prefix));
    offset = strlen(prefix);

    size_t fp_len = strlen(recipient_fp);
    memcpy(key_data + offset, recipient_fp, fp_len);
    offset += fp_len;

    return compute_sha3_512(key_data, offset, key_out);
}

/**
 * Derive value_id from tx_hash for unique payment storage
 */
static uint64_t derive_value_id(const uint8_t *tx_hash) {
    uint64_t value_id = 0;
    for (int i = 0; i < 8; i++) {
        value_id |= ((uint64_t)tx_hash[i]) << (i * 8);
    }
    return value_id ? value_id : 1;
}

int dnac_tx_create_mint(const char *recipient_fingerprint,
                        uint64_t amount,
                        dnac_transaction_t **tx_out) {
    if (!recipient_fingerprint || amount == 0 || !tx_out) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    if (DNAC_MAX_MINT_AMOUNT > 0 && amount > DNAC_MAX_MINT_AMOUNT) {
        return DNAC_ERROR_SUPPLY_EXCEEDED;
    }

    dnac_transaction_t *tx = dnac_tx_create(DNAC_TX_MINT);
    if (!tx) return DNAC_ERROR_OUT_OF_MEMORY;

    tx->input_count = 0;  /* No inputs for MINT */

    uint8_t nullifier_seed[32];
    if (qgp_randombytes(nullifier_seed, 32) != 0) {
        dnac_free_transaction(tx);
        return DNAC_ERROR_RANDOM_FAILED;
    }

    int rc = dnac_tx_add_output(tx, recipient_fingerprint, amount, nullifier_seed);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    rc = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        dnac_free_transaction(tx);
        return rc;
    }

    QGP_LOG_INFO(LOG_TAG, "Created MINT tx: %llu to %.32s...",
                 (unsigned long long)amount, recipient_fingerprint);

    *tx_out = tx;
    return DNAC_SUCCESS;
}

int dnac_tx_authorize_mint(dnac_context_t *ctx, dnac_transaction_t *tx) {
    if (!ctx || !tx || tx->type != DNAC_TX_MINT) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    /* Build mint request - zeroed nullifier indicates MINT */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
    memset(request.nullifier, 0, DNAC_NULLIFIER_SIZE);  /* Zero = MINT */
    request.timestamp = (uint64_t)time(NULL);
    request.fee_amount = 0;

    int rc = dna_engine_get_signing_public_key(engine, request.sender_pubkey,
                                                DNAC_PUBKEY_SIZE);
    if (rc < 0) return DNAC_ERROR_CRYPTO;

    size_t sig_len = DNAC_SIGNATURE_SIZE;
    rc = dna_engine_sign_data(engine, request.tx_hash, DNAC_TX_HASH_SIZE,
                               request.signature, &sig_len);
    if (rc < 0) return DNAC_ERROR_SIGN_FAILED;

    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count = 0;

    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);
    if (rc != DNAC_SUCCESS || witness_count < DNAC_MINT_WITNESS_REQUIRED) {
        QGP_LOG_ERROR(LOG_TAG, "Mint rejected: rc=%d witnesses=%d", rc, witness_count);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    for (int i = 0; i < witness_count; i++) {
        dnac_tx_add_witness(tx, &witnesses[i]);
    }

    QGP_LOG_INFO(LOG_TAG, "Mint authorized by %d witnesses", witness_count);
    return DNAC_SUCCESS;
}

int dnac_tx_broadcast_mint(dnac_context_t *ctx, dnac_transaction_t *tx) {
    if (!ctx || !tx || tx->type != DNAC_TX_MINT) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    int rc;
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return DNAC_ERROR_NETWORK;

    /* Serialize transaction */
    uint8_t tx_buffer[65536];
    size_t tx_len = 0;
    rc = dnac_tx_serialize(tx, tx_buffer, sizeof(tx_buffer), &tx_len);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Send payment to each recipient via DHT */
    uint64_t payment_value_id = derive_value_id(tx->tx_hash);

    for (int i = 0; i < tx->output_count; i++) {
        /* Build inbox DHT key for recipient */
        uint8_t inbox_key[64];
        if (build_inbox_key(tx->outputs[i].owner_fingerprint, inbox_key) != 0) {
            continue;
        }

        /* PUT payment to recipient's inbox (permanent) */
        rc = dht_put_signed_permanent(dht, inbox_key, 64, tx_buffer, tx_len,
                                      payment_value_id,
                                      "dnac_mint");
        if (rc != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to send mint to recipient %d", i);
        }
    }

    /* Store transaction in history */
    uint64_t total_output = dnac_tx_total_output(tx);
    const char *counterparty = NULL;
    if (tx->output_count > 0) {
        counterparty = tx->outputs[0].owner_fingerprint;
    }

    rc = dnac_db_store_transaction(db, tx->tx_hash, tx_buffer, tx_len,
                                    tx->type, counterparty,
                                    0, total_output, 0);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_WARN(LOG_TAG, "Failed to store mint transaction in history");
    }

    QGP_LOG_INFO(LOG_TAG, "Mint broadcast complete: %llu coins",
                 (unsigned long long)total_output);

    return DNAC_SUCCESS;
}
