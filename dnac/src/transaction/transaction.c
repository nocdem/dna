/**
 * @file transaction.c
 * @brief Transaction creation and management (v1 transparent)
 *
 * Protocol v1: Amounts are transparent (plaintext).
 * Protocol v2: Amounts hidden in Pedersen commitments (future).
 */

#include "dnac/transaction.h"
#include "dnac/nodus.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OpenSSL for SHA3-512 */
#include <openssl/evp.h>

/* libdna crypto utilities */
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"

dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type) {
    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return NULL;

    tx->version = DNAC_PROTOCOL_VERSION;
    tx->type = type;
    tx->timestamp = (uint64_t)time(NULL);
    tx->input_count = 0;
    tx->output_count = 0;
    tx->anchor_count = 0;

    return tx;
}

int dnac_tx_add_input(dnac_transaction_t *tx, const dnac_utxo_t *utxo) {
    if (!tx || !utxo) return DNAC_ERROR_INVALID_PARAM;
    if (tx->input_count >= DNAC_TX_MAX_INPUTS) return DNAC_ERROR_INVALID_PARAM;

    dnac_tx_input_t *input = &tx->inputs[tx->input_count];
    memcpy(input->nullifier, utxo->nullifier, DNAC_NULLIFIER_SIZE);
    input->amount = utxo->amount;  /* v1: store amount for verification */

    tx->input_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_add_output(dnac_transaction_t *tx,
                       const char *recipient_fingerprint,
                       uint64_t amount,
                       uint8_t *nullifier_seed_out) {
    if (!tx || !recipient_fingerprint || amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (tx->output_count >= DNAC_TX_MAX_OUTPUTS) return DNAC_ERROR_INVALID_PARAM;

    dnac_tx_output_internal_t *output = &tx->outputs[tx->output_count];
    output->version = tx->version;
    strncpy(output->owner_fingerprint, recipient_fingerprint, DNAC_FINGERPRINT_SIZE - 1);
    output->owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    output->amount = amount;

    /* Generate random nullifier seed for recipient */
    if (nullifier_seed_out) {
        if (qgp_randombytes(nullifier_seed_out, 32) != 0) {
            return DNAC_ERROR_RANDOM_FAILED;
        }
        memcpy(output->nullifier_seed, nullifier_seed_out, 32);
    }

    /* v1: No commitments or range proofs */
    /* v2: Would create Pedersen commitment and Bulletproof here */

    tx->output_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_finalize(dnac_transaction_t *tx,
                     const uint8_t *sender_privkey,
                     const uint8_t *sender_pubkey) {
    if (!tx || !sender_privkey || !sender_pubkey) return DNAC_ERROR_INVALID_PARAM;

    /* v1: Verify balance equation (sum inputs == sum outputs) */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);

    if (total_in != total_out) {
        return DNAC_ERROR_INVALID_PROOF;  /* Balance mismatch */
    }

    /* Store sender's public key */
    memcpy(tx->sender_pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);

    /* Compute transaction hash */
    int result = dnac_tx_compute_hash(tx, tx->tx_hash);
    if (result != DNAC_SUCCESS) {
        return result;
    }

    /* Sign transaction hash with Dilithium5 */
    size_t sig_len = 0;
    int sign_result = qgp_dsa87_sign(tx->sender_signature, &sig_len,
                                     tx->tx_hash, DNAC_TX_HASH_SIZE,
                                     sender_privkey);
    if (sign_result != 0) {
        return DNAC_ERROR_SIGN_FAILED;
    }

    return DNAC_SUCCESS;
}

int dnac_tx_add_anchor(dnac_transaction_t *tx, const dnac_anchor_t *anchor) {
    if (!tx || !anchor) return DNAC_ERROR_INVALID_PARAM;
    if (tx->anchor_count >= DNAC_TX_MAX_ANCHORS) return DNAC_ERROR_INVALID_PARAM;

    memcpy(&tx->anchors[tx->anchor_count], anchor, sizeof(dnac_anchor_t));
    tx->anchor_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_verify(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* v1: Verify sum(inputs) == sum(outputs) */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);

    if (total_in != total_out) {
        return DNAC_ERROR_INVALID_PROOF;
    }

    /* Verify we have enough anchors */
    if (tx->anchor_count < DNAC_ANCHORS_REQUIRED) {
        return DNAC_ERROR_ANCHOR_FAILED;
    }

    /* TODO: Verify anchor signatures */
    /* TODO: Verify sender signature */

    /* v2: Would also verify balance proof and range proofs */

    return DNAC_SUCCESS;
}

int dnac_tx_compute_hash(const dnac_transaction_t *tx, uint8_t *hash_out) {
    if (!tx || !hash_out) return DNAC_ERROR_INVALID_PARAM;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return DNAC_ERROR_CRYPTO;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return DNAC_ERROR_CRYPTO;
    }

    /* Hash header fields */
    EVP_DigestUpdate(ctx, &tx->version, sizeof(tx->version));
    EVP_DigestUpdate(ctx, &tx->type, sizeof(tx->type));
    EVP_DigestUpdate(ctx, &tx->timestamp, sizeof(tx->timestamp));

    /* Hash inputs */
    for (int i = 0; i < tx->input_count; i++) {
        EVP_DigestUpdate(ctx, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        EVP_DigestUpdate(ctx, &tx->inputs[i].amount, sizeof(uint64_t));
    }

    /* Hash outputs */
    for (int i = 0; i < tx->output_count; i++) {
        EVP_DigestUpdate(ctx, &tx->outputs[i].version, sizeof(uint8_t));
        EVP_DigestUpdate(ctx, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        EVP_DigestUpdate(ctx, &tx->outputs[i].amount, sizeof(uint64_t));
        EVP_DigestUpdate(ctx, tx->outputs[i].nullifier_seed, 32);
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash_out, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return DNAC_ERROR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    return DNAC_SUCCESS;
}

uint64_t dnac_tx_total_input(const dnac_transaction_t *tx) {
    if (!tx) return 0;

    uint64_t total = 0;
    for (int i = 0; i < tx->input_count; i++) {
        total += tx->inputs[i].amount;
    }
    return total;
}

uint64_t dnac_tx_total_output(const dnac_transaction_t *tx) {
    if (!tx) return 0;

    uint64_t total = 0;
    for (int i = 0; i < tx->output_count; i++) {
        total += tx->outputs[i].amount;
    }
    return total;
}

void dnac_free_transaction(dnac_transaction_t *tx) {
    free(tx);
}
