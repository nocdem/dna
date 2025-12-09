/**
 * @file sol_tx.c
 * @brief Solana Transaction Building Implementation
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#include "sol_tx.h"
#include "sol_rpc.h"
#include "../../crypto/utils/base58.h"
#include "../../crypto/utils/qgp_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_TAG "SOL_TX"

/* System program ID: 11111111111111111111111111111112 (all zeros except last byte) */
const uint8_t SOL_SYSTEM_PROGRAM_ID[32] = {0};

/* System program transfer instruction index */
#define SYSTEM_INSTRUCTION_TRANSFER  2

/* ============================================================================
 * COMPACT-U16 ENCODING
 * ============================================================================ */

/**
 * Encode a number as compact-u16 (Solana's variable-length encoding)
 *
 * 0x00-0x7f: 1 byte
 * 0x80-0x3fff: 2 bytes
 * 0x4000-0xffff: 3 bytes
 */
static size_t encode_compact_u16(uint16_t value, uint8_t *out) {
    if (value < 0x80) {
        out[0] = (uint8_t)value;
        return 1;
    } else if (value < 0x4000) {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(value >> 7);
        return 2;
    } else {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7f) | 0x80);
        out[2] = (uint8_t)(value >> 14);
        return 3;
    }
}

/* ============================================================================
 * TRANSACTION BUILDING
 * ============================================================================ */

int sol_tx_build_transfer(
    const sol_wallet_t *wallet,
    const uint8_t to_pubkey[32],
    uint64_t lamports,
    const uint8_t recent_blockhash[32],
    uint8_t *tx_out,
    size_t tx_out_size,
    size_t *tx_len_out
) {
    if (!wallet || !to_pubkey || !recent_blockhash || !tx_out || !tx_len_out) {
        return -1;
    }

    if (tx_out_size < SOL_TX_MAX_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Output buffer too small");
        return -1;
    }

    /*
     * Transaction format:
     * - Signatures: compact-u16 count + 64-byte signatures
     * - Message:
     *   - Header: 3 bytes (num_required_sigs, num_readonly_signed, num_readonly_unsigned)
     *   - Account keys: compact-u16 count + 32-byte pubkeys
     *   - Recent blockhash: 32 bytes
     *   - Instructions: compact-u16 count + instruction data
     *
     * For transfer:
     * - Accounts: from (signer/writable), to (writable), system_program (readonly)
     * - Instruction: program_id_index, account_indices, data
     */

    uint8_t *p = tx_out;
    size_t offset = 0;

    /* Build message first (we need to sign it) */
    uint8_t message[512];
    size_t msg_offset = 0;

    /* Message header */
    message[msg_offset++] = 1;  /* num_required_signatures */
    message[msg_offset++] = 0;  /* num_readonly_signed_accounts */
    message[msg_offset++] = 1;  /* num_readonly_unsigned_accounts (system program) */

    /* Account keys: from, to, system_program */
    msg_offset += encode_compact_u16(3, message + msg_offset);

    memcpy(message + msg_offset, wallet->public_key, 32);
    msg_offset += 32;

    memcpy(message + msg_offset, to_pubkey, 32);
    msg_offset += 32;

    memcpy(message + msg_offset, SOL_SYSTEM_PROGRAM_ID, 32);
    msg_offset += 32;

    /* Recent blockhash */
    memcpy(message + msg_offset, recent_blockhash, 32);
    msg_offset += 32;

    /* Instructions: 1 transfer instruction */
    msg_offset += encode_compact_u16(1, message + msg_offset);

    /* Transfer instruction */
    message[msg_offset++] = 2;  /* program_id_index (system program = index 2) */

    /* Account indices: [from=0, to=1] */
    msg_offset += encode_compact_u16(2, message + msg_offset);
    message[msg_offset++] = 0;  /* from account index */
    message[msg_offset++] = 1;  /* to account index */

    /* Instruction data: 4-byte LE instruction index + 8-byte LE lamports */
    msg_offset += encode_compact_u16(12, message + msg_offset);

    /* Transfer instruction index (2) as 4-byte LE */
    message[msg_offset++] = SYSTEM_INSTRUCTION_TRANSFER;
    message[msg_offset++] = 0;
    message[msg_offset++] = 0;
    message[msg_offset++] = 0;

    /* Lamports as 8-byte LE */
    for (int i = 0; i < 8; i++) {
        message[msg_offset++] = (lamports >> (i * 8)) & 0xFF;
    }

    /* Sign the message */
    uint8_t signature[64];
    if (sol_sign_message(message, msg_offset,
                         wallet->private_key, wallet->public_key,
                         signature) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign transaction");
        return -1;
    }

    /* Build final transaction: signatures + message */

    /* Signature count */
    offset += encode_compact_u16(1, p + offset);

    /* Signature */
    memcpy(p + offset, signature, 64);
    offset += 64;

    /* Message */
    memcpy(p + offset, message, msg_offset);
    offset += msg_offset;

    *tx_len_out = offset;
    return 0;
}

/* ============================================================================
 * BASE64 ENCODING (for RPC submission)
 * ============================================================================ */

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uint8_t *data, size_t len, char *out) {
    size_t out_len = 0;
    size_t i;

    for (i = 0; i + 2 < len; i += 3) {
        out[out_len++] = base64_chars[(data[i] >> 2) & 0x3F];
        out[out_len++] = base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)];
        out[out_len++] = base64_chars[((data[i + 1] & 0x0F) << 2) | ((data[i + 2] >> 6) & 0x03)];
        out[out_len++] = base64_chars[data[i + 2] & 0x3F];
    }

    if (i < len) {
        out[out_len++] = base64_chars[(data[i] >> 2) & 0x3F];
        if (i + 1 < len) {
            out[out_len++] = base64_chars[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)];
            out[out_len++] = base64_chars[(data[i + 1] & 0x0F) << 2];
        } else {
            out[out_len++] = base64_chars[(data[i] & 0x03) << 4];
            out[out_len++] = '=';
        }
        out[out_len++] = '=';
    }

    out[out_len] = '\0';
    return out_len;
}

/* ============================================================================
 * HIGH-LEVEL SEND FUNCTIONS
 * ============================================================================ */

int sol_tx_send_lamports(
    const sol_wallet_t *wallet,
    const char *to_address,
    uint64_t lamports,
    char *signature_out,
    size_t sig_out_size
) {
    if (!wallet || !to_address || !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* Decode destination address */
    uint8_t to_pubkey[32];
    if (sol_address_to_pubkey(to_address, to_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid destination address: %s", to_address);
        return -1;
    }

    /* Get recent blockhash */
    uint8_t blockhash[32];
    if (sol_rpc_get_recent_blockhash(blockhash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get recent blockhash");
        return -1;
    }

    /* Build transaction */
    uint8_t tx_data[SOL_TX_MAX_SIZE];
    size_t tx_len;
    if (sol_tx_build_transfer(wallet, to_pubkey, lamports, blockhash,
                              tx_data, sizeof(tx_data), &tx_len) != 0) {
        return -1;
    }

    /* Encode as base64 */
    char tx_base64[2048];
    base64_encode(tx_data, tx_len, tx_base64);

    /* Send transaction */
    if (sol_rpc_send_transaction(tx_base64, signature_out, sig_out_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Transaction sent: %s", signature_out);
    return 0;
}

int sol_tx_send_sol(
    const sol_wallet_t *wallet,
    const char *to_address,
    double amount_sol,
    char *signature_out,
    size_t sig_out_size
) {
    /* Convert SOL to lamports */
    uint64_t lamports = (uint64_t)(amount_sol * SOL_LAMPORTS_PER_SOL);
    return sol_tx_send_lamports(wallet, to_address, lamports, signature_out, sig_out_size);
}
