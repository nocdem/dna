/**
 * @file transaction.c
 * @brief Transaction creation and management
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
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
#include "crypto/utils/qgp_log.h"
#include "dnac/safe_math.h"

#define LOG_TAG "DNAC_TX"

/* Forward declarations for verification functions (verify.c) */
extern int verify_witnesses(const dnac_transaction_t *tx);
extern int verify_sender_signature(const dnac_transaction_t *tx);

dnac_transaction_t* dnac_tx_create(dnac_tx_type_t type) {
    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return NULL;

    tx->version = DNAC_PROTOCOL_VERSION;
    tx->type = type;
    tx->timestamp = (uint64_t)time(NULL);
    tx->input_count = 0;
    tx->output_count = 0;
    tx->witness_count = 0;

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
    return dnac_tx_add_output_with_memo(tx, recipient_fingerprint, amount,
                                         nullifier_seed_out, NULL, 0);
}

int dnac_tx_add_output_with_memo(dnac_transaction_t *tx,
                                  const char *recipient_fingerprint,
                                  uint64_t amount,
                                  uint8_t *nullifier_seed_out,
                                  const char *memo,
                                  uint8_t memo_len) {
    if (!tx || !recipient_fingerprint || amount == 0) {
        return DNAC_ERROR_INVALID_PARAM;
    }
    if (tx->output_count >= DNAC_TX_MAX_OUTPUTS) return DNAC_ERROR_INVALID_PARAM;
    if (memo_len > DNAC_MEMO_MAX_SIZE) return DNAC_ERROR_INVALID_PARAM;

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

    /* Gap 25: v0.6.0 - Set memo if provided */
    output->memo_len = 0;
    memset(output->memo, 0, DNAC_MEMO_MAX_SIZE);
    if (memo && memo_len > 0) {
        memcpy(output->memo, memo, memo_len);
        output->memo_len = memo_len;
    }

    tx->output_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_finalize(dnac_transaction_t *tx,
                     const uint8_t *sender_privkey,
                     const uint8_t *sender_pubkey) {
    if (!tx || !sender_privkey || !sender_pubkey) return DNAC_ERROR_INVALID_PARAM;

    /* v0.8.0: sum(inputs) >= sum(outputs), difference is burned fee */
    uint64_t total_in = dnac_tx_total_input(tx);
    uint64_t total_out = dnac_tx_total_output(tx);

    if (total_in < total_out) {
        return DNAC_ERROR_INVALID_PROOF;  /* Outputs exceed inputs */
    }

    /* Store sender's public key BEFORE hash (sender_pubkey is part of tx_hash) */
    memcpy(tx->sender_pubkey, sender_pubkey, DNAC_PUBKEY_SIZE);

    /* Compute transaction hash (includes sender_pubkey) */
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

int dnac_tx_add_witness(dnac_transaction_t *tx, const dnac_witness_sig_t *witness) {
    if (!tx || !witness) return DNAC_ERROR_INVALID_PARAM;
    if (tx->witness_count >= DNAC_TX_MAX_WITNESSES) return DNAC_ERROR_INVALID_PARAM;

    memcpy(&tx->witnesses[tx->witness_count], witness, sizeof(dnac_witness_sig_t));
    tx->witness_count++;
    return DNAC_SUCCESS;
}

int dnac_tx_verify(const dnac_transaction_t *tx) {
    if (!tx) return DNAC_ERROR_INVALID_PARAM;

    /* Genesis: 0 inputs, outputs create coins (witness-authorized) */
    if (tx->type == DNAC_TX_GENESIS) {
        if (tx->input_count != 0) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: genesis must have 0 inputs");
            return DNAC_ERROR_INVALID_PROOF;
        }
    } else {
        /* v0.8.0: sum(inputs) >= sum(outputs), difference is burned fee */
        uint64_t total_in = dnac_tx_total_input(tx);
        uint64_t total_out = dnac_tx_total_output(tx);

        QGP_LOG_DEBUG(LOG_TAG, "verify: total_in=%llu, total_out=%llu",
                      (unsigned long long)total_in, (unsigned long long)total_out);

        if (total_in < total_out) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: outputs exceed inputs");
            return DNAC_ERROR_INVALID_PROOF;
        }
    }

    /* Verify we have enough witnesses
     * BFT mode: 1 attestation proves consensus (quorum agreement happened internally) */
    QGP_LOG_DEBUG(LOG_TAG, "verify: witness_count=%d (BFT: 1 sufficient)", tx->witness_count);
    if (tx->witness_count < 1) {
        QGP_LOG_ERROR(LOG_TAG, "verify failed: no witnesses");
        return DNAC_ERROR_WITNESS_FAILED;
    }

    /* Verify witness signatures */
    int rc = verify_witnesses(tx);
    if (rc != DNAC_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "verify failed: witness sig verify rc=%d", rc);
        return rc;
    }

    /* Sender signature (skip for genesis - witnesses authorize) */
    if (tx->type != DNAC_TX_GENESIS) {
        rc = verify_sender_signature(tx);
        if (rc != DNAC_SUCCESS) {
            QGP_LOG_ERROR(LOG_TAG, "verify failed: sender sig verify rc=%d", rc);
            return rc;
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "verify OK");
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

    /* Hash header fields — type must be cast to uint8_t to match wire format.
     * dnac_tx_type_t is an enum (sizeof(int) = 4), but wire uses 1 byte. */
    uint8_t type_byte = (uint8_t)tx->type;
    EVP_DigestUpdate(ctx, &tx->version, sizeof(tx->version));
    EVP_DigestUpdate(ctx, &type_byte, sizeof(type_byte));
    EVP_DigestUpdate(ctx, &tx->timestamp, sizeof(tx->timestamp));

    /* Hash sender public key (binds TX to sender identity) */
    EVP_DigestUpdate(ctx, tx->sender_pubkey, DNAC_PUBKEY_SIZE);

    /* Hash inputs */
    for (int i = 0; i < tx->input_count; i++) {
        EVP_DigestUpdate(ctx, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        EVP_DigestUpdate(ctx, &tx->inputs[i].amount, sizeof(uint64_t));
    }

    /* Hash outputs (Gap 25: v0.6.0 - includes memo) */
    for (int i = 0; i < tx->output_count; i++) {
        EVP_DigestUpdate(ctx, &tx->outputs[i].version, sizeof(uint8_t));
        EVP_DigestUpdate(ctx, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        EVP_DigestUpdate(ctx, &tx->outputs[i].amount, sizeof(uint64_t));
        EVP_DigestUpdate(ctx, tx->outputs[i].nullifier_seed, 32);
        EVP_DigestUpdate(ctx, &tx->outputs[i].memo_len, sizeof(uint8_t));
        if (tx->outputs[i].memo_len > 0) {
            EVP_DigestUpdate(ctx, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
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
        if (safe_add_u64(total, tx->inputs[i].amount, &total) != 0) {
            return UINT64_MAX;  /* Overflow sentinel */
        }
    }
    return total;
}

uint64_t dnac_tx_total_output(const dnac_transaction_t *tx) {
    if (!tx) return 0;

    uint64_t total = 0;
    for (int i = 0; i < tx->output_count; i++) {
        if (safe_add_u64(total, tx->outputs[i].amount, &total) != 0) {
            return UINT64_MAX;  /* Overflow sentinel */
        }
    }
    return total;
}

void dnac_free_transaction(dnac_transaction_t *tx) {
    free(tx);
}
