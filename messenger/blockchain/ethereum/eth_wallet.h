/**
 * @file eth_wallet.h
 * @brief Ethereum Wallet Interface
 *
 * Provides Ethereum wallet creation, storage, and address utilities.
 * Uses BIP-44 derivation (m/44'/60'/0'/0/0) with secp256k1 curve.
 *
 * Key features:
 * - Deterministic key derivation from BIP39 seed
 * - Unencrypted JSON keystore format (simplified)
 * - EIP-55 checksummed addresses
 * - ETH mainnet balance queries via JSON-RPC
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef ETH_WALLET_H
#define ETH_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

/* Key sizes */
#define ETH_PRIVATE_KEY_SIZE    32      /* secp256k1 private key */
#define ETH_PUBLIC_KEY_SIZE     65      /* Uncompressed pubkey (04 || x || y) */
#define ETH_ADDRESS_SIZE        20      /* 160-bit address */

/* String sizes (including null terminator) */
#define ETH_ADDRESS_HEX_SIZE    43      /* "0x" + 40 hex + null */
#define ETH_PRIVKEY_HEX_SIZE    65      /* 64 hex + null */

/* JSON keystore file extension */
#define ETH_WALLET_EXTENSION    ".eth.json"

/* Default RPC endpoint (Ethereum mainnet) */
#define ETH_RPC_ENDPOINT_DEFAULT    "https://eth.llamarpc.com"

/* ============================================================================
 * WALLET STRUCTURE
 * ============================================================================ */

/**
 * Ethereum wallet structure
 *
 * Contains the private key, public key, and derived address.
 */
typedef struct {
    uint8_t private_key[ETH_PRIVATE_KEY_SIZE];  /* 32-byte private key */
    uint8_t public_key[ETH_PUBLIC_KEY_SIZE];    /* 65-byte uncompressed pubkey */
    uint8_t address[ETH_ADDRESS_SIZE];          /* 20-byte address */
    char address_hex[ETH_ADDRESS_HEX_SIZE];     /* Checksummed hex address */
} eth_wallet_t;

/* ============================================================================
 * WALLET CREATION
 * ============================================================================ */

/**
 * Create Ethereum wallet from BIP39 seed
 *
 * Derives the Ethereum key using BIP-44 path: m/44'/60'/0'/0/0
 * Saves wallet to JSON keystore file.
 *
 * @param seed          64-byte BIP39 master seed
 * @param seed_len      Length of seed (should be 64)
 * @param name          Wallet name (used for filename)
 * @param wallet_dir    Directory to save wallet file
 * @param address_out   Output: checksummed address (ETH_ADDRESS_HEX_SIZE)
 * @return              0 on success, -1 on error
 */
int eth_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
);

/**
 * Generate Ethereum wallet in memory (no file)
 *
 * Creates wallet structure from seed without saving to file.
 *
 * @param seed          64-byte BIP39 master seed
 * @param seed_len      Length of seed
 * @param wallet_out    Output: wallet structure
 * @return              0 on success, -1 on error
 */
int eth_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    eth_wallet_t *wallet_out
);

/**
 * Clear wallet from memory securely
 *
 * Zeros out all key material.
 *
 * @param wallet    Wallet to clear
 */
void eth_wallet_clear(eth_wallet_t *wallet);

/* ============================================================================
 * WALLET STORAGE (JSON Keystore)
 * ============================================================================ */

/**
 * Save wallet to JSON keystore file (unencrypted)
 *
 * File format:
 * {
 *   "version": 1,
 *   "address": "0x...",
 *   "private_key": "...",
 *   "created_at": 1234567890
 * }
 *
 * @param wallet        Wallet to save
 * @param name          Wallet name
 * @param wallet_dir    Directory to save to
 * @return              0 on success, -1 on error
 */
int eth_wallet_save(
    const eth_wallet_t *wallet,
    const char *name,
    const char *wallet_dir
);

/**
 * Load wallet from JSON keystore file
 *
 * @param file_path     Path to wallet file
 * @param wallet_out    Output: loaded wallet
 * @return              0 on success, -1 on error
 */
int eth_wallet_load(
    const char *file_path,
    eth_wallet_t *wallet_out
);

/**
 * Get address from wallet file without loading private key
 *
 * @param file_path     Path to wallet file
 * @param address_out   Output: address string
 * @param address_size  Size of address_out buffer
 * @return              0 on success, -1 on error
 */
int eth_wallet_get_address(
    const char *file_path,
    char *address_out,
    size_t address_size
);

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

/**
 * Derive Ethereum address from private key
 *
 * @param private_key   32-byte private key
 * @param address_out   Output: 20-byte address
 * @return              0 on success, -1 on error
 */
int eth_address_from_private_key(
    const uint8_t private_key[32],
    uint8_t address_out[20]
);

/**
 * Format address as checksummed hex string
 *
 * @param address       20-byte address
 * @param hex_out       Output: checksummed hex string (43 bytes min)
 * @return              0 on success, -1 on error
 */
int eth_address_to_hex(
    const uint8_t address[20],
    char hex_out[43]
);

/**
 * Validate Ethereum address format
 *
 * Checks for:
 * - Correct length (42 chars with 0x prefix)
 * - Valid hex characters
 * - Optional: EIP-55 checksum validation
 *
 * @param address   Address string (with or without 0x prefix)
 * @return          true if valid, false otherwise
 */
bool eth_validate_address(const char *address);

/* ============================================================================
 * RPC / BALANCE
 * ============================================================================ */

/**
 * Get ETH balance via JSON-RPC
 *
 * Queries eth_getBalance on the configured RPC endpoint.
 *
 * @param address       Ethereum address (with 0x prefix)
 * @param balance_out   Output: formatted balance string (e.g., "1.234 ETH")
 * @param balance_size  Size of balance_out buffer
 * @return              0 on success, -1 on error
 */
int eth_rpc_get_balance(
    const char *address,
    char *balance_out,
    size_t balance_size
);

/**
 * Set custom RPC endpoint
 *
 * Default is ETH_RPC_ENDPOINT_DEFAULT (llamarpc.com).
 *
 * @param endpoint  New RPC endpoint URL
 * @return          0 on success, -1 on error
 */
int eth_rpc_set_endpoint(const char *endpoint);

/**
 * Get current RPC endpoint
 *
 * @return  Current endpoint URL
 */
const char* eth_rpc_get_endpoint(void);

/* ============================================================================
 * TRANSACTION HISTORY (via Etherscan API)
 * ============================================================================ */

/**
 * ETH transaction record
 */
typedef struct {
    char tx_hash[68];      /* Transaction hash (0x + 64 hex chars) */
    char from[44];         /* Sender address */
    char to[44];           /* Recipient address */
    char value[64];        /* Value in ETH (e.g., "0.123") */
    uint64_t timestamp;    /* Unix timestamp */
    int is_outgoing;       /* 1 if we sent, 0 if we received */
    int is_confirmed;      /* 1 if confirmed, 0 if failed */
} eth_transaction_t;

/**
 * Get ETH transaction history via Blockscout API
 *
 * Uses Blockscout's free API (no API key required).
 * Returns up to 50 most recent transactions.
 *
 * @param address    Ethereum address (with 0x prefix)
 * @param txs_out    Output: array of transactions (caller must free with eth_rpc_free_transactions)
 * @param count_out  Output: number of transactions
 * @return           0 on success, -1 on error
 */
int eth_rpc_get_transactions(
    const char *address,
    eth_transaction_t **txs_out,
    int *count_out
);

/**
 * Free transaction array
 */
void eth_rpc_free_transactions(eth_transaction_t *txs, int count);

#ifdef __cplusplus
}
#endif

#endif /* ETH_WALLET_H */
