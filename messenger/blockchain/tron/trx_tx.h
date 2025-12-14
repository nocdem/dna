/**
 * @file trx_tx.h
 * @brief TRON Transaction Building and Signing
 *
 * TRON transactions use Protocol Buffers (protobuf) encoding.
 * This implementation provides simplified protobuf encoding without
 * requiring the full protobuf library.
 *
 * Transaction flow:
 * 1. Build transaction via TronGrid API (createtransaction)
 * 2. Sign transaction hash with secp256k1
 * 3. Broadcast via TronGrid API (broadcasttransaction)
 *
 * @author DNA Messenger Team
 * @date 2025-12-14
 */

#ifndef TRX_TX_H
#define TRX_TX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

/* TRON network constants */
#define TRX_DECIMALS            6           /* 1 TRX = 1,000,000 SUN */
#define TRX_SUN_PER_TRX         1000000ULL

/* Maximum transaction size */
#define TRX_TX_MAX_SIZE         4096

/* Gas/bandwidth estimates */
#define TRX_BANDWIDTH_TRANSFER  270         /* Bandwidth for simple transfer */
#define TRX_BANDWIDTH_TRC20     350         /* Bandwidth for TRC-20 transfer */
#define TRX_ENERGY_TRC20        30000       /* Energy for TRC-20 transfer */

/* Fee constants (in SUN) */
#define TRX_FEE_BANDWIDTH       1000        /* Cost per bandwidth point */

/* ============================================================================
 * TRANSACTION STRUCTURES
 * ============================================================================ */

/**
 * TRON unsigned transaction
 */
typedef struct {
    char tx_id[65];                     /* Transaction ID (32 bytes hex) */
    uint8_t raw_data[TRX_TX_MAX_SIZE];  /* Serialized raw_data */
    size_t raw_data_len;                /* Length of raw_data */
    uint64_t timestamp;                 /* Transaction timestamp */
    uint64_t expiration;                /* Expiration timestamp */
} trx_tx_t;

/**
 * TRON signed transaction
 */
typedef struct {
    char tx_id[65];                     /* Transaction ID (hex) */
    uint8_t signature[65];              /* secp256k1 recoverable signature */
    uint8_t raw_data[TRX_TX_MAX_SIZE];  /* Serialized raw_data */
    size_t raw_data_len;                /* Length of raw_data */
} trx_signed_tx_t;

/* ============================================================================
 * TRANSACTION CREATION (via TronGrid API)
 * ============================================================================ */

/**
 * Create TRX transfer transaction via TronGrid API
 *
 * Calls /wallet/createtransaction endpoint.
 *
 * @param from_address  Sender address (Base58Check)
 * @param to_address    Recipient address (Base58Check)
 * @param amount_sun    Amount in SUN (1 TRX = 1,000,000 SUN)
 * @param tx_out        Output: unsigned transaction
 * @return              0 on success, -1 on error
 */
int trx_tx_create_transfer(
    const char *from_address,
    const char *to_address,
    uint64_t amount_sun,
    trx_tx_t *tx_out
);

/**
 * Create TRC-20 transfer transaction via TronGrid API
 *
 * Calls /wallet/triggersmartcontract endpoint.
 *
 * @param from_address  Sender address (Base58Check)
 * @param to_address    Recipient address (Base58Check)
 * @param contract      Token contract address (Base58Check)
 * @param amount        Amount as string with decimals applied
 * @param tx_out        Output: unsigned transaction
 * @return              0 on success, -1 on error
 */
int trx_tx_create_trc20_transfer(
    const char *from_address,
    const char *to_address,
    const char *contract,
    const char *amount,
    trx_tx_t *tx_out
);

/* ============================================================================
 * TRANSACTION SIGNING
 * ============================================================================ */

/**
 * Sign TRON transaction
 *
 * Signs the transaction ID (txID) with secp256k1.
 *
 * @param tx            Unsigned transaction
 * @param private_key   32-byte secp256k1 private key
 * @param signed_out    Output: signed transaction
 * @return              0 on success, -1 on error
 */
int trx_tx_sign(
    const trx_tx_t *tx,
    const uint8_t private_key[32],
    trx_signed_tx_t *signed_out
);

/* ============================================================================
 * TRANSACTION BROADCAST
 * ============================================================================ */

/**
 * Broadcast signed transaction via TronGrid API
 *
 * Calls /wallet/broadcasttransaction endpoint.
 *
 * @param signed_tx     Signed transaction
 * @param tx_id_out     Output: transaction ID (65 bytes min)
 * @return              0 on success, -1 on error
 */
int trx_tx_broadcast(
    const trx_signed_tx_t *signed_tx,
    char *tx_id_out
);

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

/**
 * Send TRX to address (all-in-one)
 *
 * Handles transaction creation, signing, and broadcasting.
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address (Base58Check)
 * @param to_address    Recipient address (Base58Check)
 * @param amount_trx    Amount as decimal string (e.g., "100.5")
 * @param tx_id_out     Output: transaction ID
 * @return              0 on success, -1 on error
 */
int trx_send_trx(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_trx,
    char *tx_id_out
);

/**
 * Parse TRX amount string to SUN
 *
 * @param amount_str    Amount as decimal string (e.g., "100.5")
 * @param sun_out       Output: amount in SUN
 * @return              0 on success, -1 on error
 */
int trx_parse_amount(const char *amount_str, uint64_t *sun_out);

/**
 * Convert hex address to Base58Check
 *
 * @param hex_address   Hex address (41 prefix + 20 bytes = 42 hex chars)
 * @param base58_out    Output: Base58Check address (35 bytes min)
 * @return              0 on success, -1 on error
 */
int trx_hex_to_base58(const char *hex_address, char *base58_out, size_t base58_size);

/**
 * Convert Base58Check address to hex
 *
 * @param base58        Base58Check address
 * @param hex_out       Output: hex address (43 bytes min for 0x prefix)
 * @return              0 on success, -1 on error
 */
int trx_base58_to_hex(const char *base58, char *hex_out, size_t hex_size);

#ifdef __cplusplus
}
#endif

#endif /* TRX_TX_H */
