/**
 * @file serialize.c
 * @brief Transaction serialization (v1 transparent)
 *
 * v1 Wire Format:
 * - Header: version(1) + type(1) + timestamp(8) + tx_hash(64)
 * - Inputs: count(1) + [nullifier(64) + amount(8)]...
 * - Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + seed(32) + memo_len(1) + memo(n)]...
 * - Witnesses: count(1) + [witness_id(32) + signature(4627) + timestamp(8) + server_pubkey(2592)]...
 * - Sender: pubkey(2592) + signature(4627)
 */

#include "dnac/transaction.h"
#include <string.h>
#include <stdlib.h>

/* Helper macros for serialization */
#define WRITE_U8(buf, val) do { *(buf)++ = (uint8_t)(val); } while(0)
#define WRITE_U64(buf, val) do { \
    uint64_t v = (val); \
    memcpy(buf, &v, 8); \
    buf += 8; \
} while(0)
#define WRITE_BLOB(buf, src, len) do { \
    memcpy(buf, src, len); \
    buf += (len); \
} while(0)

/* Helper macros for deserialization */
#define READ_U8(buf, val) do { (val) = *(buf)++; } while(0)
#define READ_U64(buf, val) do { \
    memcpy(&(val), buf, 8); \
    buf += 8; \
} while(0)
#define READ_BLOB(buf, dst, len) do { \
    memcpy(dst, buf, len); \
    buf += (len); \
} while(0)

/* Calculate v1 transaction size */
static size_t calc_tx_size_v1(const dnac_transaction_t *tx) {
    size_t size = 0;

    /* Header */
    size += 1;  /* version */
    size += 1;  /* type */
    size += 8;  /* timestamp */
    size += DNAC_TX_HASH_SIZE;  /* tx_hash (64) */

    /* Inputs */
    size += 1;  /* input_count */
    size += tx->input_count * (DNAC_NULLIFIER_SIZE + 8);  /* nullifier(64) + amount(8) */

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    size += 1;  /* output_count */
    for (int i = 0; i < tx->output_count; i++) {
        size += 1 + DNAC_FINGERPRINT_SIZE + 8 + 32;  /* version(1) + fp(129) + amount(8) + seed(32) */
        size += 1;  /* memo_len */
        size += tx->outputs[i].memo_len;  /* memo data */
    }

    /* Witnesses */
    size += 1;  /* witness_count */
    size += tx->witness_count * (32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE);  /* witness_id(32) + sig(4627) + timestamp(8) + pubkey(2592) */

    /* Sender */
    size += DNAC_PUBKEY_SIZE;  /* pubkey (2592) */
    size += DNAC_SIGNATURE_SIZE;  /* signature (4627) */

    return size;
}

int dnac_tx_serialize(const dnac_transaction_t *tx,
                      uint8_t *buffer,
                      size_t buffer_len,
                      size_t *written_out) {
    if (!tx || !buffer || !written_out) return DNAC_ERROR_INVALID_PARAM;

    size_t needed = calc_tx_size_v1(tx);
    if (buffer_len < needed) {
        *written_out = needed;  /* Return needed size */
        return DNAC_ERROR_INVALID_PARAM;
    }

    uint8_t *ptr = buffer;

    /* Header */
    WRITE_U8(ptr, tx->version);
    WRITE_U8(ptr, tx->type);
    WRITE_U64(ptr, tx->timestamp);
    WRITE_BLOB(ptr, tx->tx_hash, DNAC_TX_HASH_SIZE);

    /* Inputs */
    WRITE_U8(ptr, tx->input_count);
    for (int i = 0; i < tx->input_count; i++) {
        WRITE_BLOB(ptr, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        WRITE_U64(ptr, tx->inputs[i].amount);
    }

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    WRITE_U8(ptr, tx->output_count);
    for (int i = 0; i < tx->output_count; i++) {
        WRITE_U8(ptr, tx->outputs[i].version);
        WRITE_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        WRITE_U64(ptr, tx->outputs[i].amount);
        WRITE_BLOB(ptr, tx->outputs[i].nullifier_seed, 32);
        WRITE_U8(ptr, tx->outputs[i].memo_len);
        if (tx->outputs[i].memo_len > 0) {
            WRITE_BLOB(ptr, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
    }

    /* Witnesses */
    WRITE_U8(ptr, tx->witness_count);
    for (int i = 0; i < tx->witness_count; i++) {
        WRITE_BLOB(ptr, tx->witnesses[i].witness_id, 32);
        WRITE_BLOB(ptr, tx->witnesses[i].signature, DNAC_SIGNATURE_SIZE);
        WRITE_U64(ptr, tx->witnesses[i].timestamp);
        WRITE_BLOB(ptr, tx->witnesses[i].server_pubkey, DNAC_PUBKEY_SIZE);
    }

    /* Sender */
    WRITE_BLOB(ptr, tx->sender_pubkey, DNAC_PUBKEY_SIZE);
    WRITE_BLOB(ptr, tx->sender_signature, DNAC_SIGNATURE_SIZE);

    *written_out = (size_t)(ptr - buffer);
    return DNAC_SUCCESS;
}

int dnac_tx_deserialize(const uint8_t *buffer,
                        size_t buffer_len,
                        dnac_transaction_t **tx_out) {
    if (!buffer || !tx_out || buffer_len < 74) {  /* Minimum header size */
        return DNAC_ERROR_INVALID_PARAM;
    }

    dnac_transaction_t *tx = calloc(1, sizeof(dnac_transaction_t));
    if (!tx) return DNAC_ERROR_OUT_OF_MEMORY;

    const uint8_t *ptr = buffer;
    const uint8_t *end = buffer + buffer_len;

    /* Header */
    READ_U8(ptr, tx->version);
    READ_U8(ptr, tx->type);
    /* M-32: Validate tx_type is within known range */
    if (tx->type > DNAC_TX_BURN) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    READ_U64(ptr, tx->timestamp);
    READ_BLOB(ptr, tx->tx_hash, DNAC_TX_HASH_SIZE);

    /* Inputs */
    uint8_t input_count;
    READ_U8(ptr, input_count);
    if (input_count > DNAC_TX_MAX_INPUTS) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->input_count = input_count;

    for (int i = 0; i < input_count; i++) {
        if (ptr + DNAC_NULLIFIER_SIZE + 8 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        READ_U64(ptr, tx->inputs[i].amount);
    }

    /* Outputs */
    uint8_t output_count;
    READ_U8(ptr, output_count);
    if (output_count > DNAC_TX_MAX_OUTPUTS) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->output_count = output_count;

    for (int i = 0; i < output_count; i++) {
        /* Check minimum output size (without memo) */
        size_t out_size = 1 + DNAC_FINGERPRINT_SIZE + 8 + 32 + 1;  /* +1 for memo_len */
        if (ptr + out_size > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_U8(ptr, tx->outputs[i].version);
        READ_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        READ_U64(ptr, tx->outputs[i].amount);
        READ_BLOB(ptr, tx->outputs[i].nullifier_seed, 32);
        /* Gap 25: v0.6.0 - read memo */
        READ_U8(ptr, tx->outputs[i].memo_len);
        if (tx->outputs[i].memo_len > 0) {
            /* memo_len is uint8_t (max 255), buffer is DNAC_MEMO_MAX_SIZE (256) — always fits */
            if (ptr + tx->outputs[i].memo_len > end) {
                free(tx);
                return DNAC_ERROR_INVALID_PARAM;
            }
            READ_BLOB(ptr, tx->outputs[i].memo, tx->outputs[i].memo_len);
        }
    }

    /* Witnesses */
    uint8_t witness_count;
    READ_U8(ptr, witness_count);
    if (witness_count > DNAC_TX_MAX_WITNESSES) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    tx->witness_count = witness_count;

    for (int i = 0; i < witness_count; i++) {
        size_t witness_size = 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE;
        if (ptr + witness_size > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->witnesses[i].witness_id, 32);
        READ_BLOB(ptr, tx->witnesses[i].signature, DNAC_SIGNATURE_SIZE);
        READ_U64(ptr, tx->witnesses[i].timestamp);
        READ_BLOB(ptr, tx->witnesses[i].server_pubkey, DNAC_PUBKEY_SIZE);
    }

    /* Sender */
    if (ptr + DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE > end) {
        free(tx);
        return DNAC_ERROR_INVALID_PARAM;
    }
    READ_BLOB(ptr, tx->sender_pubkey, DNAC_PUBKEY_SIZE);
    READ_BLOB(ptr, tx->sender_signature, DNAC_SIGNATURE_SIZE);

    *tx_out = tx;
    return DNAC_SUCCESS;
}
