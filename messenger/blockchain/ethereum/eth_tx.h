/**
 * @file eth_tx.h
 * @brief Ethereum Transaction Building and Signing
 *
 * Supports EIP-155 replay-protected transactions for Ethereum mainnet.
 *
 * Transaction flow:
 * 1. Get nonce (eth_getTransactionCount)
 * 2. Get gas price (eth_gasPrice)
 * 3. Build transaction with eth_tx_build()
 * 4. Sign with private key using eth_tx_sign()
 * 5. Broadcast via eth_tx_send()
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef ETH_TX_H
#define ETH_TX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Chain IDs */
#define ETH_CHAIN_MAINNET       1
#define ETH_CHAIN_GOERLI        5
#define ETH_CHAIN_SEPOLIA       11155111

/* Default gas limit for simple ETH transfer */
#define ETH_GAS_LIMIT_TRANSFER  21000

/* Maximum raw transaction size */
#define ETH_TX_MAX_SIZE         4096

/**
 * Unsigned Ethereum transaction
 */
typedef struct {
    uint64_t nonce;             /* Transaction nonce */
    uint64_t gas_price;         /* Gas price in wei */
    uint64_t gas_limit;         /* Gas limit */
    uint8_t to[20];             /* Recipient address (20 bytes) */
    uint8_t value[32];          /* Value in wei (big-endian 256-bit) */
    uint8_t *data;              /* Transaction data (optional, NULL for ETH transfer) */
    size_t data_len;            /* Length of data */
    uint64_t chain_id;          /* Chain ID for EIP-155 */
} eth_tx_t;

/**
 * Signed transaction result
 */
typedef struct {
    uint8_t raw_tx[ETH_TX_MAX_SIZE];    /* RLP-encoded signed transaction */
    size_t raw_tx_len;                  /* Length of raw_tx */
    char tx_hash[67];                   /* Transaction hash (0x + 64 hex) */
} eth_signed_tx_t;

/* ============================================================================
 * RPC QUERIES
 * ============================================================================ */

/**
 * Get transaction count (nonce) for address
 *
 * @param address       Ethereum address (with 0x prefix)
 * @param nonce_out     Output: current nonce
 * @return              0 on success, -1 on error
 */
int eth_tx_get_nonce(const char *address, uint64_t *nonce_out);

/**
 * Get current gas price
 *
 * @param gas_price_out Output: gas price in wei
 * @return              0 on success, -1 on error
 */
int eth_tx_get_gas_price(uint64_t *gas_price_out);

/**
 * Estimate gas for transaction
 *
 * @param from          Sender address
 * @param to            Recipient address
 * @param value         Value in wei (hex string with 0x)
 * @param gas_out       Output: estimated gas
 * @return              0 on success, -1 on error
 */
int eth_tx_estimate_gas(
    const char *from,
    const char *to,
    const char *value,
    uint64_t *gas_out
);

/* ============================================================================
 * TRANSACTION BUILDING
 * ============================================================================ */

/**
 * Initialize transaction for simple ETH transfer
 *
 * @param tx            Transaction to initialize
 * @param nonce         Transaction nonce
 * @param gas_price     Gas price in wei
 * @param to            Recipient address (20 bytes)
 * @param value_wei     Value in wei (big-endian 256-bit)
 * @param chain_id      Chain ID (ETH_CHAIN_MAINNET for mainnet)
 */
void eth_tx_init_transfer(
    eth_tx_t *tx,
    uint64_t nonce,
    uint64_t gas_price,
    const uint8_t to[20],
    const uint8_t value_wei[32],
    uint64_t chain_id
);

/**
 * Sign transaction with private key
 *
 * Uses secp256k1 ECDSA with EIP-155 replay protection.
 *
 * @param tx            Transaction to sign
 * @param private_key   32-byte secp256k1 private key
 * @param signed_out    Output: signed transaction
 * @return              0 on success, -1 on error
 */
int eth_tx_sign(
    const eth_tx_t *tx,
    const uint8_t private_key[32],
    eth_signed_tx_t *signed_out
);

/**
 * Broadcast signed transaction
 *
 * Calls eth_sendRawTransaction on the configured RPC endpoint.
 *
 * @param signed_tx     Signed transaction from eth_tx_sign
 * @param tx_hash_out   Output: transaction hash (67 bytes min)
 * @return              0 on success, -1 on error
 */
int eth_tx_send(const eth_signed_tx_t *signed_tx, char *tx_hash_out);

/* ============================================================================
 * CONVENIENCE FUNCTIONS
 * ============================================================================ */

/**
 * Send ETH to address (all-in-one)
 *
 * Handles nonce, gas price, signing, and broadcasting.
 *
 * @param private_key   32-byte sender private key
 * @param from_address  Sender address (for nonce query)
 * @param to_address    Recipient address (0x + 40 hex)
 * @param amount_eth    Amount to send as decimal string (e.g., "0.1")
 * @param tx_hash_out   Output: transaction hash (67 bytes min)
 * @return              0 on success, -1 on error
 */
int eth_send_eth(
    const uint8_t private_key[32],
    const char *from_address,
    const char *to_address,
    const char *amount_eth,
    char *tx_hash_out
);

/**
 * Parse ETH amount string to wei (256-bit big-endian)
 *
 * @param amount_str    Amount as decimal string (e.g., "1.5" or "0.001")
 * @param wei_out       Output: 32-byte big-endian wei value
 * @return              0 on success, -1 on error
 */
int eth_parse_amount(const char *amount_str, uint8_t wei_out[32]);

/**
 * Parse hex address to bytes
 *
 * @param hex_address   Address with 0x prefix
 * @param address_out   Output: 20-byte address
 * @return              0 on success, -1 on error
 */
int eth_parse_address(const char *hex_address, uint8_t address_out[20]);

#ifdef __cplusplus
}
#endif

#endif /* ETH_TX_H */
