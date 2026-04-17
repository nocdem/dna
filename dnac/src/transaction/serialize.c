/**
 * @file serialize.c
 * @brief Transaction serialization (v1 transparent)
 *
 * v1 Wire Format:
 * - Header: version(1) + type(1) + timestamp(8) + tx_hash(64)
 * - Inputs: count(1) + [nullifier(64) + amount(8)]...
 * - Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + seed(32) + memo_len(1) + memo(n)]...
 * - Witnesses: count(1) + [witness_id(32) + signature(4627) + timestamp(8) + server_pubkey(2592)]...
 * - Signers: count(1) + [pubkey(2592) + signature(4627)]...
 */

#include "dnac/transaction.h"
#include "dnac/chain_def_codec.h"  /* for optional genesis chain_def payload */
#include <string.h>
#include <stdlib.h>
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

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

/* Big-endian u64 helpers for Phase 5 appended-field encoding (design §2.3).
 * Local to serialize.c so the wire encoding is BE even on LE hosts. */
static inline void be64_to_bytes(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static inline uint64_t be64_from_bytes(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) { v = (v << 8) | (uint64_t)in[i]; }
    return v;
}

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
    size += tx->input_count * (DNAC_NULLIFIER_SIZE + 8 + DNAC_TOKEN_ID_SIZE);  /* nullifier(64) + amount(8) + token_id(64) */

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    size += 1;  /* output_count */
    for (int i = 0; i < tx->output_count; i++) {
        size += 1 + DNAC_FINGERPRINT_SIZE + 8 + DNAC_TOKEN_ID_SIZE + 32;  /* version(1) + fp(129) + amount(8) + token_id(64) + seed(32) */
        size += 1;  /* memo_len */
        size += tx->outputs[i].memo_len;  /* memo data */
    }

    /* Witnesses */
    size += 1;  /* witness_count */
    size += tx->witness_count * (32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE);  /* witness_id(32) + sig(4627) + timestamp(8) + pubkey(2592) */

    /* Signers */
    size += 1;  /* signer_count */
    size += tx->signer_count * (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE);

    /* Type-specific appended fields (Phase 5 Task 16). STAKE carries
     * commission_bps(2) + unstake_destination_fp(64) + purpose_tag(17). */
    if (tx->type == DNAC_TX_STAKE) {
        size += 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE + DNAC_STAKE_PURPOSE_TAG_LEN;
    }
    /* Phase 5 Task 17. DELEGATE carries validator_pubkey(2592). */
    if (tx->type == DNAC_TX_DELEGATE) {
        size += DNAC_PUBKEY_SIZE;
    }
    /* Phase 5 Task 18. UNDELEGATE carries validator_pubkey(2592) + amount(u64). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        size += DNAC_PUBKEY_SIZE + 8;
    }
    /* Phase 5 Task 18. CLAIM_REWARD carries target_validator(2592) +
     * max_pending_amount(u64) + valid_before_block(u64). */
    if (tx->type == DNAC_TX_CLAIM_REWARD) {
        size += DNAC_PUBKEY_SIZE + 8 + 8;
    }

    /* Optional anchored-genesis chain_def trailer (v2 wire extension).
     * Only present when has_chain_def is true (always 0 for non-genesis).
     * Layout: flag(1) [|| chain_def_len(4 LE) || chain_def_bytes] */
    size += 1;  /* has_chain_def flag byte */
    if (tx->has_chain_def) {
        size += 4;  /* chain_def_len */
        size += dnac_chain_def_encoded_size(&tx->chain_def);
    }

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
        WRITE_BLOB(ptr, tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
    }

    /* Outputs (Gap 25: v0.6.0 - now includes memo) */
    WRITE_U8(ptr, tx->output_count);
    for (int i = 0; i < tx->output_count; i++) {
        WRITE_U8(ptr, tx->outputs[i].version);
        WRITE_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        WRITE_U64(ptr, tx->outputs[i].amount);
        WRITE_BLOB(ptr, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
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

    /* Signers */
    WRITE_U8(ptr, tx->signer_count);
    for (int i = 0; i < tx->signer_count; i++) {
        WRITE_BLOB(ptr, tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);
        WRITE_BLOB(ptr, tx->signers[i].signature, DNAC_SIGNATURE_SIZE);
    }

    /* Type-specific appended fields (Phase 5 Task 16).
     * STAKE: commission_bps(u16 BE) || unstake_destination_fp[64] ||
     *        purpose_tag[17] ("DNAC_VALIDATOR_v1"). */
    if (tx->type == DNAC_TX_STAKE) {
        ptr[0] = (uint8_t)((tx->stake_fields.commission_bps >> 8) & 0xff);
        ptr[1] = (uint8_t)(tx->stake_fields.commission_bps & 0xff);
        ptr += 2;
        WRITE_BLOB(ptr, tx->stake_fields.unstake_destination_fp,
                   DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
        WRITE_BLOB(ptr, DNAC_STAKE_PURPOSE_TAG, DNAC_STAKE_PURPOSE_TAG_LEN);
    }
    /* Phase 5 Task 17. DELEGATE: validator_pubkey[2592]. */
    if (tx->type == DNAC_TX_DELEGATE) {
        WRITE_BLOB(ptr, tx->delegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
    }
    /* Phase 5 Task 18. UNDELEGATE: validator_pubkey[2592] || amount(u64 BE). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        WRITE_BLOB(ptr, tx->undelegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        uint8_t amount_be[8];
        be64_to_bytes(tx->undelegate_fields.amount, amount_be);
        WRITE_BLOB(ptr, amount_be, 8);
    }
    /* Phase 5 Task 18. CLAIM_REWARD: target_validator[2592] ||
     *        max_pending_amount(u64 BE) || valid_before_block(u64 BE). */
    if (tx->type == DNAC_TX_CLAIM_REWARD) {
        WRITE_BLOB(ptr, tx->claim_reward_fields.target_validator, DNAC_PUBKEY_SIZE);
        uint8_t max_be[8], valid_be[8];
        be64_to_bytes(tx->claim_reward_fields.max_pending_amount, max_be);
        be64_to_bytes(tx->claim_reward_fields.valid_before_block, valid_be);
        WRITE_BLOB(ptr, max_be, 8);
        WRITE_BLOB(ptr, valid_be, 8);
    }

    /* Anchored-genesis chain_def trailer (optional, genesis TX only). */
    WRITE_U8(ptr, tx->has_chain_def ? 1 : 0);
    if (tx->has_chain_def) {
        size_t cd_len = dnac_chain_def_encoded_size(&tx->chain_def);
        /* Write len as u32 LE (match existing codec convention) */
        ptr[0] = (uint8_t)(cd_len & 0xff);
        ptr[1] = (uint8_t)((cd_len >> 8) & 0xff);
        ptr[2] = (uint8_t)((cd_len >> 16) & 0xff);
        ptr[3] = (uint8_t)((cd_len >> 24) & 0xff);
        ptr += 4;
        size_t written = 0;
        int rc = dnac_chain_def_encode(&tx->chain_def, ptr,
                                         buffer_len - (ptr - buffer), &written);
        if (rc != 0 || written != cd_len) return DNAC_ERROR_INVALID_PARAM;
        ptr += written;
    }

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
    /* M-32: Validate tx_type is within known range.
     * Phase 5 Task 16: admit stake/delegation types (4..9) added in
     * Task 1 (DNAC_TX_VALIDATOR_UPDATE is the highest defined value). */
    if (tx->type > DNAC_TX_VALIDATOR_UPDATE) {
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
        if (ptr + DNAC_NULLIFIER_SIZE + 8 + DNAC_TOKEN_ID_SIZE > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->inputs[i].nullifier, DNAC_NULLIFIER_SIZE);
        READ_U64(ptr, tx->inputs[i].amount);
        READ_BLOB(ptr, tx->inputs[i].token_id, DNAC_TOKEN_ID_SIZE);
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
        size_t out_size = 1 + DNAC_FINGERPRINT_SIZE + 8 + DNAC_TOKEN_ID_SIZE + 32 + 1;  /* +1 for memo_len */
        if (ptr + out_size > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_U8(ptr, tx->outputs[i].version);
        READ_BLOB(ptr, tx->outputs[i].owner_fingerprint, DNAC_FINGERPRINT_SIZE);
        READ_U64(ptr, tx->outputs[i].amount);
        READ_BLOB(ptr, tx->outputs[i].token_id, DNAC_TOKEN_ID_SIZE);
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

    /* Signers */
    if (ptr + 1 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
    uint8_t signer_count;
    READ_U8(ptr, signer_count);
    if (signer_count > DNAC_TX_MAX_SIGNERS) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
    tx->signer_count = signer_count;

    for (int i = 0; i < signer_count; i++) {
        if (ptr + DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->signers[i].pubkey, DNAC_PUBKEY_SIZE);
        READ_BLOB(ptr, tx->signers[i].signature, DNAC_SIGNATURE_SIZE);
    }

    /* Type-specific appended fields (Phase 5 Task 16).
     * STAKE: commission_bps(u16 BE) || unstake_destination_fp[64] ||
     *        purpose_tag[17]. Purpose tag MUST match exactly —
     *        cross-protocol reuse defense (F-CRYPTO-05). */
    if (tx->type == DNAC_TX_STAKE) {
        const size_t stake_appended_len = 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE
                                        + DNAC_STAKE_PURPOSE_TAG_LEN;
        if (ptr + stake_appended_len > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        tx->stake_fields.commission_bps =
            ((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1];
        ptr += 2;
        READ_BLOB(ptr, tx->stake_fields.unstake_destination_fp,
                  DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
        if (memcmp(ptr, DNAC_STAKE_PURPOSE_TAG,
                   DNAC_STAKE_PURPOSE_TAG_LEN) != 0) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        ptr += DNAC_STAKE_PURPOSE_TAG_LEN;
    }
    /* Phase 5 Task 17. DELEGATE: validator_pubkey[2592]. */
    if (tx->type == DNAC_TX_DELEGATE) {
        if (ptr + DNAC_PUBKEY_SIZE > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->delegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
    }
    /* Phase 5 Task 18. UNDELEGATE: validator_pubkey[2592] || amount(u64 BE). */
    if (tx->type == DNAC_TX_UNDELEGATE) {
        if (ptr + DNAC_PUBKEY_SIZE + 8 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->undelegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE);
        tx->undelegate_fields.amount = be64_from_bytes(ptr);
        ptr += 8;
    }
    /* Phase 5 Task 18. CLAIM_REWARD: target_validator[2592] ||
     *        max_pending_amount(u64 BE) || valid_before_block(u64 BE). */
    if (tx->type == DNAC_TX_CLAIM_REWARD) {
        if (ptr + DNAC_PUBKEY_SIZE + 16 > end) {
            free(tx);
            return DNAC_ERROR_INVALID_PARAM;
        }
        READ_BLOB(ptr, tx->claim_reward_fields.target_validator, DNAC_PUBKEY_SIZE);
        tx->claim_reward_fields.max_pending_amount = be64_from_bytes(ptr);
        ptr += 8;
        tx->claim_reward_fields.valid_before_block = be64_from_bytes(ptr);
        ptr += 8;
    }

    /* Optional anchored-genesis chain_def trailer.
     *
     * Backward compat: if ptr reached end, this is a legacy v1 TX with
     * no trailer — leave has_chain_def = false (already zero via calloc).
     * If ptr + 1 > end, same thing. Only actively parse when the flag
     * byte is present. */
    if (ptr < end) {
        uint8_t has_cd;
        READ_U8(ptr, has_cd);
        if (has_cd) {
            if (ptr + 4 > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
            uint32_t cd_len = (uint32_t)ptr[0]
                            | ((uint32_t)ptr[1] << 8)
                            | ((uint32_t)ptr[2] << 16)
                            | ((uint32_t)ptr[3] << 24);
            ptr += 4;
            if (ptr + cd_len > end) { free(tx); return DNAC_ERROR_INVALID_PARAM; }
            if (dnac_chain_def_decode(ptr, cd_len, &tx->chain_def) != 0) {
                free(tx);
                return DNAC_ERROR_INVALID_PARAM;
            }
            tx->has_chain_def = true;
            ptr += cd_len;
        }
    }

    *tx_out = tx;
    return DNAC_SUCCESS;
}
