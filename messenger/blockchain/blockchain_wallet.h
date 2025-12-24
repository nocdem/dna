/**
 * @file blockchain_wallet.h
 * @brief Generic Blockchain Wallet Interface
 *
 * Provides a common interface for multi-chain wallet operations.
 * Implementations exist in chain-specific subdirectories:
 *   - cellframe/ : Cellframe blockchain (CF20, post-quantum Dilithium)
 *   - ethereum/  : Ethereum and EVM-compatible chains (secp256k1)
 *   - solana/    : Solana blockchain (Ed25519)
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef BLOCKCHAIN_WALLET_H
#define BLOCKCHAIN_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * BLOCKCHAIN TYPES
 * ============================================================================ */

/**
 * Supported blockchain types
 */
typedef enum {
    BLOCKCHAIN_CELLFRAME = 0,   /* Cellframe (CF20, Dilithium signatures) */
    BLOCKCHAIN_ETHEREUM  = 1,   /* Ethereum mainnet */
    BLOCKCHAIN_TRON      = 2,   /* TRON mainnet (TRC-20, secp256k1) */
    BLOCKCHAIN_SOLANA    = 3,   /* Solana (Ed25519) */
    BLOCKCHAIN_COUNT            /* Number of supported blockchains */
} blockchain_type_t;

/**
 * Get blockchain name string
 */
const char* blockchain_type_name(blockchain_type_t type);

/**
 * Get blockchain ticker symbol
 */
const char* blockchain_type_ticker(blockchain_type_t type);

/* ============================================================================
 * GENERIC WALLET STRUCTURE
 * ============================================================================ */

/**
 * Maximum sizes for wallet fields
 */
#define BLOCKCHAIN_WALLET_NAME_MAX      256
#define BLOCKCHAIN_WALLET_ADDRESS_MAX   128
#define BLOCKCHAIN_WALLET_PATH_MAX      512

/**
 * Generic wallet info structure
 *
 * Used to represent any blockchain wallet in a unified way.
 */
typedef struct {
    blockchain_type_t type;                     /* Blockchain type */
    char name[BLOCKCHAIN_WALLET_NAME_MAX];      /* Wallet name/label */
    char address[BLOCKCHAIN_WALLET_ADDRESS_MAX]; /* Primary address */
    char file_path[BLOCKCHAIN_WALLET_PATH_MAX]; /* Path to wallet file */
    bool is_encrypted;                          /* Is wallet password-protected */
    uint64_t created_at;                        /* Creation timestamp */
} blockchain_wallet_info_t;

/**
 * List of wallets
 */
typedef struct {
    blockchain_wallet_info_t *wallets;
    size_t count;
} blockchain_wallet_list_t;

/* ============================================================================
 * WALLET CREATION INTERFACE
 * ============================================================================ */

/**
 * Create all wallets from BIP39 master seed and mnemonic
 *
 * Derives and creates wallets for all supported blockchains:
 * - Cellframe: SHA3-256(mnemonic) → Dilithium (matches Cellframe wallet app)
 * - Ethereum:  BIP-44 (m/44'/60'/0'/0/0) → secp256k1
 * - Solana:    SLIP-10 Ed25519
 *
 * Wallets are saved to: <wallet_dir>/<fingerprint>.<ext>
 *
 * @param master_seed   64-byte BIP39 master seed (for ETH/SOL)
 * @param mnemonic      Space-separated mnemonic words (for Cellframe)
 * @param fingerprint   Identity fingerprint (used for wallet naming)
 * @param wallet_dir    Directory to store wallet files
 * @return              0 on success, -1 on error
 */
int blockchain_create_all_wallets(
    const uint8_t master_seed[64],
    const char *mnemonic,
    const char *fingerprint,
    const char *wallet_dir
);

/**
 * Create missing wallets from encrypted seed storage
 *
 * Checks which blockchain wallets exist and creates any that are missing.
 * Uses the encrypted master_seed.enc file stored in the identity directory.
 * This allows automatic wallet creation when new blockchain support is added.
 *
 * Called silently on identity load - no user notification.
 *
 * @param fingerprint       Identity fingerprint
 * @param kem_privkey       3168-byte Kyber1024 private key (for seed decryption)
 * @param wallets_created   Output: number of new wallets created (can be NULL)
 * @return                  0 on success, -1 on error
 */
int blockchain_create_missing_wallets(
    const char *fingerprint,
    const uint8_t kem_privkey[3168],
    int *wallets_created
);

/**
 * Create wallet for specific blockchain
 *
 * @param type          Blockchain type
 * @param master_seed   64-byte BIP39 master seed
 * @param fingerprint   Identity fingerprint
 * @param wallet_dir    Directory to store wallet file
 * @param address_out   Output: wallet address (BLOCKCHAIN_WALLET_ADDRESS_MAX bytes)
 * @return              0 on success, -1 on error
 */
int blockchain_create_wallet(
    blockchain_type_t type,
    const uint8_t master_seed[64],
    const char *fingerprint,
    const char *wallet_dir,
    char *address_out
);

/* ============================================================================
 * WALLET LISTING INTERFACE
 * ============================================================================ */

/**
 * List all wallets for an identity
 *
 * @param fingerprint   Identity fingerprint
 * @param list_out      Output: allocated wallet list (caller must free)
 * @return              0 on success, -1 on error
 */
int blockchain_list_wallets(
    const char *fingerprint,
    blockchain_wallet_list_t **list_out
);

/**
 * Free wallet list
 */
void blockchain_wallet_list_free(blockchain_wallet_list_t *list);

/* ============================================================================
 * BALANCE INTERFACE
 * ============================================================================ */

/**
 * Token balance structure
 */
typedef struct {
    char token[32];         /* Token symbol (ETH, CPUNK, etc.) */
    char balance[64];       /* Formatted balance string */
    char balance_raw[128];  /* Raw balance (wei, datoshi, etc.) */
    int decimals;           /* Token decimals */
} blockchain_balance_t;

/**
 * Get balance for wallet
 *
 * @param type          Blockchain type
 * @param address       Wallet address
 * @param balance_out   Output: balance info
 * @return              0 on success, -1 on error
 */
int blockchain_get_balance(
    blockchain_type_t type,
    const char *address,
    blockchain_balance_t *balance_out
);

/* ============================================================================
 * ADDRESS UTILITIES
 * ============================================================================ */

/**
 * Validate address format for blockchain type
 *
 * @param type      Blockchain type
 * @param address   Address string to validate
 * @return          true if valid format, false otherwise
 */
bool blockchain_validate_address(blockchain_type_t type, const char *address);

/**
 * Get address from wallet file
 *
 * @param type          Blockchain type
 * @param wallet_path   Path to wallet file
 * @param address_out   Output: address string
 * @return              0 on success, -1 on error
 */
int blockchain_get_address_from_file(
    blockchain_type_t type,
    const char *wallet_path,
    char *address_out
);

/* ============================================================================
 * SEND INTERFACE
 * ============================================================================ */

/**
 * Gas speed presets
 */
#define BLOCKCHAIN_GAS_SLOW     0   /* 0.8x - cheaper, slower */
#define BLOCKCHAIN_GAS_NORMAL   1   /* 1.0x - balanced */
#define BLOCKCHAIN_GAS_FAST     2   /* 1.5x - faster confirmation */

/**
 * Gas fee estimate
 */
typedef struct {
    char fee_eth[32];       /* Fee in ETH (e.g., "0.00042") */
    char fee_usd[32];       /* Fee in USD (e.g., "$1.23") - placeholder for now */
    uint64_t gas_price;     /* Gas price in wei */
    uint64_t gas_limit;     /* Gas limit */
} blockchain_gas_estimate_t;

/**
 * Estimate gas fee for ETH transaction
 *
 * @param gas_speed     Gas speed preset (0=slow, 1=normal, 2=fast)
 * @param estimate_out  Output: gas estimate
 * @return              0 on success, -1 on error
 */
int blockchain_estimate_eth_gas(
    int gas_speed,
    blockchain_gas_estimate_t *estimate_out
);

/**
 * Send tokens on blockchain
 *
 * @param type          Blockchain type
 * @param wallet_path   Path to sender wallet file
 * @param to_address    Recipient address
 * @param amount        Amount to send (decimal string, e.g., "0.1")
 * @param token         Token symbol (NULL or empty for native token)
 * @param gas_speed     Gas speed preset (ETH only, ignored for others)
 * @param tx_hash_out   Output: transaction hash (128 bytes min)
 * @return              0 on success, -1 on error
 */
int blockchain_send_tokens(
    blockchain_type_t type,
    const char *wallet_path,
    const char *to_address,
    const char *amount,
    const char *token,
    int gas_speed,
    char *tx_hash_out
);

/* ============================================================================
 * ON-DEMAND WALLET DERIVATION (No wallet files required)
 * ============================================================================ */

/**
 * Derive wallet addresses from master seed and mnemonic without creating files
 *
 * Used when wallet files don't exist - derives addresses on-demand.
 * Private keys are NOT stored, only addresses are returned.
 *
 * NOTE: Cellframe requires the mnemonic string (SHA3-256 hash), while
 * ETH/SOL/TRX use the BIP39 master seed. Both are needed for full support.
 *
 * @param master_seed   64-byte BIP39 master seed (for ETH/SOL/TRX)
 * @param mnemonic      Space-separated mnemonic words (for Cellframe, can be NULL)
 * @param fingerprint   Identity fingerprint (used for wallet naming)
 * @param list_out      Output: allocated wallet list (caller must free)
 * @return              0 on success, -1 on error
 */
int blockchain_derive_wallets_from_seed(
    const uint8_t master_seed[64],
    const char *mnemonic,
    const char *fingerprint,
    blockchain_wallet_list_t **list_out
);

/**
 * Send tokens using on-demand derived wallet
 *
 * Derives private key from seed, signs transaction, then immediately clears key.
 * No wallet files are read or created.
 *
 * @param type          Blockchain type
 * @param master_seed   64-byte BIP39 master seed
 * @param to_address    Recipient address
 * @param amount        Amount to send (decimal string, e.g., "0.1")
 * @param token         Token symbol (NULL or empty for native token)
 * @param gas_speed     Gas speed preset (ETH only, ignored for others)
 * @param tx_hash_out   Output: transaction hash (128 bytes min)
 * @return              0 on success, -1 on error
 */
int blockchain_send_tokens_with_seed(
    blockchain_type_t type,
    const uint8_t master_seed[64],
    const char *to_address,
    const char *amount,
    const char *token,
    int gas_speed,
    char *tx_hash_out
);

#ifdef __cplusplus
}
#endif

#endif /* BLOCKCHAIN_WALLET_H */
