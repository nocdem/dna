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
#include <limits.h>
#include <openssl/evp.h>

#include "nodus_init.h"
#include "dnac/safe_math.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/hash/qgp_sha3.h"
#include "dnac/crypto_helpers.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "DNAC_BUILDER"

struct dnac_tx_builder {
    dnac_context_t *ctx;
    dnac_transaction_t *tx;
    dnac_tx_output_t outputs[DNAC_TX_MAX_OUTPUTS];
    int output_count;
    uint64_t total_output_amount;
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];  /* Token to send (zeros = native DNAC) */
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
    if (safe_add_u64(builder->total_output_amount, output->amount,
                     &builder->total_output_amount) != 0) {
        builder->output_count--;
        return DNAC_ERROR_OVERFLOW;
    }

    return DNAC_SUCCESS;
}

int dnac_tx_builder_set_token(dnac_tx_builder_t *builder,
                               const uint8_t *token_id) {
    if (!builder || !token_id) return DNAC_ERROR_INVALID_PARAM;
    memcpy(builder->token_id, token_id, DNAC_TOKEN_ID_SIZE);
    return DNAC_SUCCESS;
}

int dnac_tx_builder_build(dnac_tx_builder_t *builder,
                          dnac_transaction_t **tx_out) {
    if (!builder || !tx_out) return DNAC_ERROR_INVALID_PARAM;
    if (builder->output_count == 0) return DNAC_ERROR_INVALID_PARAM;

    int rc;
    *tx_out = NULL;

    /* Estimate fee for initial UTXO selection */
    uint64_t fee = 0;
    rc = dnac_estimate_fee(builder->ctx, builder->total_output_amount, &fee);
    if (rc != DNAC_SUCCESS) return rc;

    uint64_t total_needed = 0;
    if (safe_add_u64(builder->total_output_amount, fee, &total_needed) != 0) {
        return DNAC_ERROR_OVERFLOW;
    }

    /* Select UTXOs */
    dnac_utxo_t *selected = NULL;
    int selected_count = 0;
    uint64_t change_amount = 0;

    rc = dnac_wallet_select_utxos_token(builder->ctx, total_needed,
                                        builder->token_id,
                                        &selected, &selected_count, &change_amount);
    if (rc != DNAC_SUCCESS) return rc;

    /* Calculate fee based on send amount (0.1% of transfer, not input).
     * H-17: Aligned with witness — both use send_amount / 1000 (0.1%), min 1.
     */
    uint64_t total_input = 0;
    for (int i = 0; i < selected_count; i++) {
        if (safe_add_u64(total_input, selected[i].amount, &total_input) != 0) {
            free(selected);
            return DNAC_ERROR_OVERFLOW;
        }
    }
    fee = builder->total_output_amount / 1000;
    if (fee < 1) fee = 1;

    uint64_t output_plus_fee;
    if (safe_add_u64(builder->total_output_amount, fee, &output_plus_fee) != 0) {
        free(selected);
        return DNAC_ERROR_OVERFLOW;
    }
    if (output_plus_fee > total_input) {
        free(selected);
        return DNAC_ERROR_INSUFFICIENT_FUNDS;
    }
    change_amount = total_input - builder->total_output_amount - fee;
    if (rc != DNAC_SUCCESS) return rc;

    /* Add inputs from selected UTXOs */
    for (int i = 0; i < selected_count; i++) {
        rc = dnac_tx_add_input(builder->tx, &selected[i]);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
    }

    /* Add outputs (Gap 25: v0.6.0 - includes memo) */
    for (int i = 0; i < builder->output_count; i++) {
        uint8_t nullifier_seed[32];
        uint8_t memo_len = (uint8_t)strnlen(builder->outputs[i].memo, DNAC_MEMO_MAX_SIZE);
        rc = dnac_tx_add_output_with_memo(builder->tx,
                                           builder->outputs[i].recipient_fingerprint,
                                           builder->outputs[i].amount,
                                           nullifier_seed,
                                           memo_len > 0 ? builder->outputs[i].memo : NULL,
                                           memo_len);
        if (rc != DNAC_SUCCESS) {
            free(selected);
            return rc;
        }
        /* Set token_id on the just-added output */
        memcpy(builder->tx->outputs[builder->tx->output_count - 1].token_id,
               builder->token_id, DNAC_TOKEN_ID_SIZE);
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
        /* Set token_id on change output */
        memcpy(builder->tx->outputs[builder->tx->output_count - 1].token_id,
               builder->token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* v0.8.0: Fees are burned (removed from circulation).
     * sum(inputs) > sum(outputs), the difference is the fee.
     * Fee pool + staking distribution planned for future version. */

    free(selected);

    /* Get sender's public key */
    dna_engine_t *engine = dnac_get_engine(builder->ctx);
    if (!engine) return DNAC_ERROR_NOT_INITIALIZED;

    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    rc = dna_engine_get_signing_public_key(engine, sender_pubkey, sizeof(sender_pubkey));
    if (rc < 0) {  /* Returns size on success, negative on error */
        return DNAC_ERROR_CRYPTO;
    }

    /* Copy public key BEFORE hash (sender_pubkey is part of tx_hash) */
    memcpy(builder->tx->sender_pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);

    /* Compute transaction hash (includes sender_pubkey) */
    rc = dnac_tx_compute_hash(builder->tx, builder->tx->tx_hash);
    if (rc != DNAC_SUCCESS) return rc;

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

    if (!nodus_messenger_wait_for_ready(5000)) {
        return DNAC_ERROR_NETWORK;
    }

    /* Step 1: Create SpendRequest with full serialized transaction
     * v0.4.0: Send full TX instead of single nullifier to enable
     * witnesses to extract and verify ALL input nullifiers.
     */
    dnac_spend_request_t request = {0};
    memcpy(request.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
    memcpy(request.sender_pubkey, tx->sender_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(request.signature, tx->sender_signature, DNAC_SIGNATURE_SIZE);
    request.timestamp = (uint64_t)time(NULL);

    /* Serialize full transaction into request */
    size_t tx_serialized_len = 0;
    rc = dnac_tx_serialize(tx, request.tx_data, sizeof(request.tx_data), &tx_serialized_len);
    if (rc != DNAC_SUCCESS) {
        return rc;
    }
    request.tx_len = (uint32_t)tx_serialized_len;

    /* Declare actual fee (inputs - outputs) to match witness verification */
    uint64_t total_output = dnac_tx_total_output(tx);
    uint64_t total_input_val = dnac_tx_total_input(tx);
    request.fee_amount = total_input_val - total_output;

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
    /* BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    if (rc != DNAC_SUCCESS || witness_count < 1) {
        /* Mark pending spends as failed */
        dnac_db_expire_pending_spends(db);

        /* Double-spend: witnesses already committed these nullifiers.
         * Mark input UTXOs as spent locally so wallet state stays in sync. */
        if (rc == DNAC_ERROR_DOUBLE_SPEND) {
            for (int i = 0; i < tx->input_count; i++) {
                dnac_db_mark_utxo_spent(db, tx->inputs[i].nullifier,
                                         tx->tx_hash);
            }
        }

        /* Propagate the specific error (double-spend, timeout, etc.)
         * instead of masking it as generic witness failure. */
        return (rc != DNAC_SUCCESS) ? rc : DNAC_ERROR_WITNESS_FAILED;
    }

    /* Step 4: Verify and add witnesses to transaction */
    for (int i = 0; i < witness_count; i++) {
        /* Verify witness signature before trusting */
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
            return DNAC_ERROR_WITNESS_FAILED;
        }

        rc = dnac_tx_add_witness(tx, &witnesses[i]);
        if (rc != DNAC_SUCCESS) return rc;
    }

    /* Step 5: Serialize transaction */
    uint8_t *tx_buffer = malloc(65536);
    if (!tx_buffer) return DNAC_ERROR_OUT_OF_MEMORY;
    size_t tx_len = 0;
    rc = dnac_tx_serialize(tx, tx_buffer, 65536, &tx_len);
    if (rc != DNAC_SUCCESS) {
        free(tx_buffer);
        return rc;
    }

    /* Wrap local DB updates in a transaction for crash consistency */
    sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);

    /* Step 6: Store change outputs locally */
    for (int i = 0; i < tx->output_count; i++) {
        /* Only process change outputs (to ourselves) */
        if (strcmp(tx->outputs[i].owner_fingerprint, owner_fp) != 0) {
            continue;
        }

        dnac_utxo_t utxo = {0};
        utxo.version = tx->outputs[i].version;
        memcpy(utxo.tx_hash, tx->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = (uint32_t)i;
        utxo.amount = tx->outputs[i].amount;
        memcpy(utxo.token_id, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
        strncpy(utxo.owner_fingerprint, owner_fp, sizeof(utxo.owner_fingerprint) - 1);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);

        /* Derive nullifier from owner fingerprint and seed */
        uint8_t nullifier_data[256];
        size_t fp_len = strlen(owner_fp);
        memcpy(nullifier_data, owner_fp, fp_len);
        memcpy(nullifier_data + fp_len, tx->outputs[i].nullifier_seed, 32);
        if (qgp_sha3_512(nullifier_data, fp_len + 32, utxo.nullifier) == 0) {
            rc = dnac_db_store_utxo(db, &utxo);
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

    /* v0.8.0: Fees are burned. Fee = sum(inputs) - sum(outputs). */
    uint64_t fee = total_input - total_output;

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

    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);

    /* Call completion callback if provided */
    if (callback) {
        callback(DNAC_SUCCESS, NULL, user_data);
    }

    free(tx_buffer);
    return DNAC_SUCCESS;
}

void dnac_tx_builder_free(dnac_tx_builder_t *builder) {
    if (!builder) return;
    if (builder->tx) dnac_free_transaction(builder->tx);
    free(builder);
}
