/**
 * @file trx_wallet.h
 * @brief TRON Wallet Interface
 *
 * Creates TRON wallets using BIP-44 derivation from BIP39 seeds.
 * Derivation path: m/44'/195'/0'/0/0
 *
 * TRON uses secp256k1 (same as Ethereum) with different address encoding:
 * - Address = Base58Check(0x41 || Keccak256(pubkey[1:65])[-20:])
 * - Addresses start with 'T' and are 34 characters long
 *
 * @author DNA Messenger Team
 * @date 2025-12-11
 */

#ifndef TRX_WALLET_H
#define TRX_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key sizes (secp256k1) */
#define TRX_PRIVATE_KEY_SIZE    32      /* secp256k1 private key */
#define TRX_PUBLIC_KEY_SIZE     65      /* Uncompressed pubkey (04 || x || y) */

/* Address sizes */
#define TRX_ADDRESS_RAW_SIZE    21      /* 0x41 prefix + 20 bytes */
#define TRX_ADDRESS_SIZE        35      /* Base58Check encoded (34 chars + null) */
#define TRX_ADDRESS_PREFIX      0x41    /* TRON mainnet address prefix */

/* Wallet file extension */
#define TRX_WALLET_EXTENSION    ".trx.json"

/* BIP-44 derivation constants */
#define TRX_BIP44_PURPOSE       44
#define TRX_BIP44_COIN_TYPE     195     /* TRON coin type (SLIP-44) */
#define TRX_BIP44_ACCOUNT       0
#define TRX_BIP44_CHANGE        0
#define TRX_BIP44_INDEX         0

/* RPC endpoints (TRON mainnet) with fallbacks */
#define TRX_RPC_ENDPOINT_DEFAULT    "https://api.trongrid.io"
#define TRX_RPC_ENDPOINT_FALLBACK1  "https://rpc.ankr.com/tron_jsonrpc"
#define TRX_RPC_ENDPOINT_FALLBACK2  "https://api.shasta.trongrid.io"  /* Testnet fallback */
#define TRX_RPC_ENDPOINT_COUNT      3

/**
 * TRON wallet structure
 */
typedef struct {
    uint8_t private_key[TRX_PRIVATE_KEY_SIZE];  /* 32-byte secp256k1 private key */
    uint8_t public_key[TRX_PUBLIC_KEY_SIZE];    /* 65-byte uncompressed public key */
    uint8_t address_raw[TRX_ADDRESS_RAW_SIZE];  /* 21-byte raw address (0x41 + hash) */
    char address[TRX_ADDRESS_SIZE];              /* Base58Check encoded address */
} trx_wallet_t;

/**
 * TRON transaction record
 */
typedef struct {
    char tx_hash[68];       /* Transaction hash */
    char from[36];          /* Sender address */
    char to[36];            /* Recipient address */
    char value[64];         /* Value in TRX (decimal string) */
    uint64_t timestamp;     /* Unix timestamp (milliseconds) */
    int is_outgoing;        /* 1 if sent, 0 if received */
    int is_confirmed;       /* 1 if confirmed */
} trx_transaction_t;

/* ============================================================================
 * WALLET GENERATION
 * ============================================================================ */

/**
 * Generate TRON wallet from BIP39 seed
 *
 * Uses BIP-44 derivation with path: m/44'/195'/0'/0/0
 *
 * @param seed          64-byte BIP39 master seed
 * @param seed_len      Length of seed (must be 64)
 * @param wallet_out    Output: generated wallet
 * @return              0 on success, -1 on error
 */
int trx_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    trx_wallet_t *wallet_out
);

/**
 * Create TRON wallet from seed and save to file
 *
 * @param seed          64-byte BIP39 master seed
 * @param seed_len      Length of seed
 * @param name          Wallet name (used for filename)
 * @param wallet_dir    Directory to save wallet
 * @param address_out   Output: Base58Check address string
 * @return              0 on success, -1 on error
 */
int trx_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
);

/**
 * Clear wallet from memory securely
 *
 * @param wallet        Wallet to clear
 */
void trx_wallet_clear(trx_wallet_t *wallet);

/* ============================================================================
 * WALLET STORAGE
 * ============================================================================ */

/**
 * Save wallet to JSON file
 *
 * @param wallet        Wallet to save
 * @param name          Wallet name
 * @param wallet_dir    Directory to save to
 * @return              0 on success, -1 on error
 */
int trx_wallet_save(
    const trx_wallet_t *wallet,
    const char *name,
    const char *wallet_dir
);

/**
 * Load wallet from JSON file
 *
 * @param file_path     Path to wallet file
 * @param wallet_out    Output: loaded wallet
 * @return              0 on success, -1 on error
 */
int trx_wallet_load(
    const char *file_path,
    trx_wallet_t *wallet_out
);

/**
 * Get address from wallet file without loading private key
 *
 * @param file_path     Path to wallet file
 * @param address_out   Output: address string
 * @param address_size  Size of address_out buffer
 * @return              0 on success, -1 on error
 */
int trx_wallet_get_address(
    const char *file_path,
    char *address_out,
    size_t address_size
);

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

/**
 * Derive TRON address from uncompressed public key
 *
 * Address = 0x41 || Keccak256(pubkey[1:65])[-20:]
 *
 * @param pubkey_uncompressed   65-byte uncompressed public key
 * @param address_raw_out       Output: 21-byte raw address
 * @return                      0 on success, -1 on error
 */
int trx_address_from_pubkey(
    const uint8_t pubkey_uncompressed[TRX_PUBLIC_KEY_SIZE],
    uint8_t address_raw_out[TRX_ADDRESS_RAW_SIZE]
);

/**
 * Encode raw address as Base58Check string
 *
 * @param address_raw   21-byte raw address (0x41 prefix + hash)
 * @param address_out   Output: Base58Check encoded address
 * @param address_size  Size of output buffer (min 35 bytes)
 * @return              0 on success, -1 on error
 */
int trx_address_to_base58(
    const uint8_t address_raw[TRX_ADDRESS_RAW_SIZE],
    char *address_out,
    size_t address_size
);

/**
 * Decode Base58Check address to raw bytes
 *
 * @param address       Base58Check encoded address
 * @param address_raw_out   Output: 21-byte raw address
 * @return              0 on success, -1 on error
 */
int trx_address_from_base58(
    const char *address,
    uint8_t address_raw_out[TRX_ADDRESS_RAW_SIZE]
);

/**
 * Validate TRON address format
 *
 * Checks:
 * - Starts with 'T'
 * - Length is 34 characters
 * - Valid Base58Check encoding
 * - Correct checksum
 *
 * @param address   Address string to validate
 * @return          true if valid, false otherwise
 */
bool trx_validate_address(const char *address);

/* ============================================================================
 * RPC ENDPOINT MANAGEMENT
 * ============================================================================ */

/**
 * Set custom RPC endpoint
 *
 * @param endpoint  New RPC endpoint URL
 * @return          0 on success, -1 on error
 */
int trx_rpc_set_endpoint(const char *endpoint);

/**
 * Get current RPC endpoint
 *
 * @return  Current endpoint URL
 */
const char* trx_rpc_get_endpoint(void);

#ifdef __cplusplus
}
#endif

#endif /* TRX_WALLET_H */
