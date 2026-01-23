/**
 * @file builder.c
 * @brief Transaction builder (v1 transparent)
 *
 * Builds transactions by:
 * 1. Collecting output specifications
 * 2. Selecting UTXOs to cover amount + fee
 * 3. Adding inputs from selected UTXOs
 * 4. Adding outputs (including change)
 * 5. Signing with sender's Dilithium5 key
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include <dna/dna_engine.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Forward declare DHT context type */
typedef struct dht_context dht_context_t;

/* DHT functions from libdna */
extern void* dna_engine_get_dht_context(dna_engine_t *engine);
extern int dht_put_signed_permanent(dht_context_t *ctx,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t *value, size_t value_len,
                                    uint64_t value_id,
                                    const char *caller);

struct dnac_tx_builder {
    dnac_context_t *ctx;
    dnac_transaction_t *tx;
    dnac_tx_output_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;
    uint64_t total_output_amount;
};

dnac_tx_builder_t* dnac_tx_builder_create(dnac_context_t *ctx) {
    if (!ctx) return NULL;

    dnac_tx_builder_t *builder = calloc(1, sizeof(dnac_tx_builder_t));
    if (!builder) return NULL;

    builder->ctx = ctx;
    builder->tx = dnac_tx_create(DNAC_TX_SPEND);
    if (!builder->tx) {
        free(builder);
        return NULL;
    }

    builder->output_count = 0;
    builder->total_output_amount = 0;

    return builder;
}

int dnac_tx_builder_add_output(dnac_tx_builder_t *builder,
                               const dnac_tx_output_t *output) {
    if (!builder || !output) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count >= DNAC_TX_MAX_OUTPUTS) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (output->amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    builder->outputs[builder->output_count++] = *output;
    builder->total_output_amount += output->amount;

    return DNAC_SUCCESS;
}

int dnac_tx_builder_build(dnac_tx_builder_t *builder,
                          dnac_transaction_t **tx_out) {
    if (!builder || !tx_out) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count == 0) return DNAC_ERROR_INVALID_PARAM;

    int rc;
    *tx_out = NULL;

    /* Calculate fee */
    uint64_t fee = 0;
    rc = dnac_estimate_fee(builder->ctx, builder->total_output_amount, &fee);
    if (rc != DNAC_SUCCESS) return rc;

    uint64_t total_needed = builder->total_output_amount + fee;

    /* Select UTXOs */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos(builder->ctx, total_needed,
                                   &selected, &selected_count, &change_amount);
    if (rc != DNAC_SUCCESS) return rc;

    /* Add inputs from selected UTXOs */
    for (int i = 0; i < selected_count; i++) {
        rc = dnac_tx_add_input(builder->tx, &selected[i]);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
    }

    /* Add outputs */
    for (int i = 0; i < builder->output_count; i++) {
        uint8_t nullifier_seed[32];
        rc = dnac_tx_add_output(builder->tx,
                                 builder->outputs[i].recipient_fingerprint,
                                 builder->outputs[i].amount,
                                 nullifier_seed);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
    }

    /* Add change output if needed */
    if (change_amount > 0) {
        const char *owner_fp = dnac_get_owner_fingerprint(builder->ctx);
        if (!owner_fp) {
            free(selected);
            return DNAC_ERROR_NOT_INITIALIZED;
        }

        uint8_t change_seed[32];
        rc = dnac_tx_add_output(builder->tx, owner_fp, change_amount, change_seed);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
    }

    /* Add fee output to witness server */
    if (fee > 0) {
        /* Discover witness servers to find fee recipient */
        dnac_witness_info_t *witness_servers = NULL;
        int witness_count = 0;
        rc = dnac_witness_discover(builder->ctx, &witness_servers, &witness_count);

        if (rc == DNAC_SUCCESS && witness_count > 0 && witness_servers[0].fingerprint[0] != '\0') {
            /* Add fee output to first available witness server */
            uint8_t fee_seed[32];
            rc = dnac_tx_add_output(builder->tx, witness_servers[0].fingerprint, fee, fee_seed);
            if (rc != DNAC_SUCCESS) {
                dnac_free_witness_list(witness_servers, witness_count);
                free(selected);
                return rc;
            }
            dnac_free_witness_list(witness_servers, witness_count);
        } else {
            /* No witness server available - cannot add fee output */
            if (witness_servers) {
                dnac_free_witness_list(witness_servers, witness_count);
            }
            free(selected);
            return DNAC_ERROR_NETWORK;
        }
    }

    free(selected);

    /* Get sender's public key */
    dna_engine_t *engine = dnac_get_engine(builder->ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    rc = dna_engine_get_signing_public_key(engine, sender_pubkey, sizeof(sender_pubkey));
    if (rc < 0) {  /* Returns size on success, negative on error */
        return DNAC_ERROR_CRYPTO;
    }

    /* Compute transaction hash (before signing) */
    rc = dnac_tx_compute_hash(builder->tx, builder->tx->tx_hash);
    if (rc != DNAC_SUCCESS) return rc;

    /* Copy public key */
    memcpy(builder->tx->sender_pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);

    /* Sign transaction hash with Dilithium5 */
    size_t sig_len = 0;
    rc = dna_engine_sign_data(engine,
                               builder->tx->tx_hash,
                               DNAC_TX_HASH_SIZE,
                               builder->tx->sender_signature,
                               &sig_len);
    if (rc != 0) {
        return DNAC_ERROR_CRYPTO;
    }

    /* Transfer ownership */
    *tx_out = builder->tx;
    builder->tx = NULL;  /* Prevent double-free */

    return DNAC_SUCCESS;
}

/**
 * Compute SHA3-512 hash of data
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
 * Key: SHA3-512("dnac:inbox:" + recipient_fingerprint)
 *
 * All payments to a recipient go to the same key, differentiated by value_id.
 * This allows the receiver to discover all payments by querying their inbox.
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
 * Takes first 8 bytes of tx_hash as little-endian uint64
 */
static uint64_t derive_value_id(const uint8_t *tx_hash) {
    uint64_t value_id = 0;
    for (int i = 0; i < 8; i++) {
        value_id |= ((uint64_t)tx_hash[i]) << (i * 8);
    }
    /* Ensure non-zero */
    return value_id ? value_id : 1;
}

int dnac_tx_broadcast(dnac_context_t *ctx,
                      dnac_transaction_t *tx,
                      dnac_callback_t callback,
                      void *user_data) {
    if (!ctx || !tx) {
        return DNAC_ERROR_INVALID_PARAM;
    }

    int rc;
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) return DNAC_ERROR_NOT_INITIALIZED;

    const char *owner_fp = dnac_get_owner_fingerprint(ctx);
    if (!owner_fp) return DNAC_ERROR_NOT_INITIALIZED;

    dht_context_t *dht = (dht_context_t *)dna_engine_get_dht_context(engine);
    if (!dht) return DNAC_ERROR_NETWORK;

    /* Step 1: Create SpendRequest for witness collection */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(request.sender_pubkey, tx->sender_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(request.signature, tx->sender_signature, DNAC_SIGNATURE_SIZE);
    request.timestamp = (uint64_t)time(NULL);

    /* Use first input's nullifier for spend request */
    if (tx->input_count > 0) {
        memcpy(request.nullifier, tx->inputs[0].nullifier, DNAC_NULLIFIER_SIZE);
    }

    /* Calculate fee */
    uint64_t total_output = dnac_tx_total_output(tx);
    request.fee_amount = dnac_witness_calculate_fee(total_output);

    /* Step 2: Store pending spend in database */
    uint64_t expires_at = request.timestamp + 300;  /* 5 minute expiry */
    for (int i = 0; i < tx->input_count; i++) {
        rc = dnac_db_store_pending_spend(db, tx->tx_hash,
                                          tx->inputs[i].nullifier,
                                          DNAC_WITNESSES_REQUIRED, expires_at);
        if (rc != DNAC_SUCCESS) {
            /* Non-fatal, continue */
        }
    }

    /* Step 3: Request witness signatures */
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count = 0;

    rc = dnac_witness_request(ctx, &request, witnesses, &witness_count);
    if (rc != DNAC_SUCCESS || witness_count < DNAC_WITNESSES_REQUIRED) {
        /* Mark pending spends as failed */
        dnac_db_expire_pending_spends(db);
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Step 4: Add witnesses to transaction */
    for (int i = 0; i < witness_count; i++) {
        rc = dnac_tx_add_witness(tx, &witnesses[i]);
        if (rc != DNAC_SUCCESS) {
            return rc;
        }
    }

    /* Step 5: Serialize transaction */
    uint8_t tx_buffer[65536];  /* 64KB should be enough for most transactions */
    size_t tx_len = 0;
    rc = dnac_tx_serialize(tx, tx_buffer, sizeof(tx_buffer), &tx_len);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }

    /* Step 6: Send payment to each recipient via DHT */
    uint64_t payment_value_id = derive_value_id(tx->tx_hash);

    for (int i = 0; i < tx->output_count; i++) {
        /* Skip change outputs (back to ourselves) */
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) == 0) {
            fprintf(stderr, "[SEND] Skipping change output to self\n");
            continue;
        }

        /* Build inbox DHT key for recipient */
        uint8_t inbox_key[64];
        if (build_inbox_key(tx->outputs[i].owner_fingerprint, inbox_key) != 0) {
            continue;
        }

        /* DEBUG: Print what we're publishing */
        fprintf(stderr, "[SEND] Publishing to recipient: %.16s...\n", tx->outputs[i].owner_fingerprint);
        fprintf(stderr, "[SEND] Inbox key (first 16 bytes): ");
        for (int j = 0; j < 16; j++) fprintf(stderr, "%02x", inbox_key[j]);
        fprintf(stderr, "...\n");
        fprintf(stderr, "[SEND] TX size: %zu bytes, value_id: %llu\n", tx_len, (unsigned long long)payment_value_id);

        /* PUT payment to recipient's inbox (permanent) */
        rc = dht_put_signed_permanent(dht, inbox_key, 64, tx_buffer, tx_len,
                                      payment_value_id,
                                      "dnac_payment");
        fprintf(stderr, "[SEND] dht_put_signed_permanent returned: %d\n", rc);
        if (rc != 0) {
            /* Log but continue - some recipients may still receive */
            fprintf(stderr, "[SEND] WARNING: DHT put failed for output %d\n", i);
        }
    }

    /* Step 7: Mark input UTXOs as spent */
    for (int i = 0; i < tx->input_count; i++) {
        rc = dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier, tx->tx_hash);
        if (rc != DNAC_SUCCESS) {
            /* Non-fatal, UTXO will be marked spent on next sync */
        }
    }

    /* Step 8: Store transaction in history */
    uint64_t total_input = dnac_tx_total_input(tx);

    /* Calculate fee: Sum outputs to non-self recipients, then derive fee.
     * Fee = 0.1% of amount sent to recipients (excluding change and fee itself).
     * With fee as explicit output: total_in == total_out, so we calculate
     * the fee from the non-change output amounts. */
    uint64_t amount_sent = 0;
    for (int i = 0; i < tx->output_count; i++) {
        /* Skip change outputs (to ourselves) */
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) == 0) {
            continue;
        }
        amount_sent += tx->outputs[i].amount;
    }
    /* amount_sent includes the fee output, so: amount_sent = original_amount + fee
     * where fee = original_amount * 0.001, so original_amount = amount_sent / 1.001
     * and fee = amount_sent - original_amount = amount_sent * 0.001 / 1.001 */
    uint64_t fee = (amount_sent * DNAC_FEE_RATE_BPS) / (10000 + DNAC_FEE_RATE_BPS);

    /* Find first non-change recipient for counterparty field */
    const char *counterparty = NULL;
    for (int i = 0; i < tx->output_count; i++) {
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) != 0) {
            counterparty = tx->outputs[i].owner_fingerprint;
            break;
        }
    }

    rc = dnac_db_store_transaction(db, tx->tx_hash, tx_buffer, tx_len,
                                    tx->type, counterparty,
                                    total_input, total_output, fee);
    if (rc != DNAC_SUCCESS) {
        /* Non-fatal */
    }

    /* Step 9: Mark pending spends as complete */
    rc = dnac_db_complete_pending_spend(db, tx->tx_hash);
    if (rc != DNAC_SUCCESS) {
        /* Non-fatal */
    }

    /* Call completion callback if provided */
    if (callback) {
        callback(DNAC_SUCCESS, NULL, user_data);
    }

    return DNAC_SUCCESS;
}

void dnac_tx_builder_free(dnac_tx_builder_t *builder) {
    if (!builder) return;
    if (builder->tx) dnac_free_transaction(builder->tx);
    free(builder);
}
