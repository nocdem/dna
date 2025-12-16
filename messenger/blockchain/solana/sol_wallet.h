/**
 * @file sol_wallet.h
 * @brief Solana Wallet Interface
 *
 * Creates Solana wallets using SLIP-10 Ed25519 derivation from BIP39 seeds.
 * Derivation path: m/44'/501'/0'/0'
 *
 * @author DNA Messenger Team
 * @date 2025-12-09
 */

#ifndef SOL_WALLET_H
#define SOL_WALLET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key sizes */
#define SOL_PRIVATE_KEY_SIZE    32      /* Ed25519 private key (seed) */
#define SOL_PUBLIC_KEY_SIZE     32      /* Ed25519 public key */
#define SOL_KEYPAIR_SIZE        64      /* Combined private + public */
#define SOL_SIGNATURE_SIZE      64      /* Ed25519 signature */
#define SOL_ADDRESS_SIZE        44      /* Base58 encoded address (max) */
#define SOL_ADDRESS_RAW_SIZE    32      /* Raw address = public key */

/* BIP-44 derivation */
#define SOL_BIP44_PURPOSE       44
#define SOL_BIP44_COIN_TYPE     501     /* Solana */
#define SOL_BIP44_ACCOUNT       0
#define SOL_BIP44_CHANGE        0

/* RPC endpoint */
/* Note: Public Solana RPC is heavily rate limited. Use Ankr free tier for better performance */
#define SOL_RPC_MAINNET         "https://rpc.ankr.com/solana"
#define SOL_RPC_MAINNET_BACKUP  "https://api.mainnet-beta.solana.com"
#define SOL_RPC_DEVNET          "https://api.devnet.solana.com"

/**
 * Solana wallet structure
 */
typedef struct {
    uint8_t private_key[SOL_PRIVATE_KEY_SIZE];  /* Ed25519 seed (32 bytes) */
    uint8_t public_key[SOL_PUBLIC_KEY_SIZE];    /* Ed25519 public key */
    char address[SOL_ADDRESS_SIZE + 1];          /* Base58 encoded address */
} sol_wallet_t;

/**
 * Generate Solana wallet from BIP39 seed
 *
 * Uses SLIP-10 Ed25519 derivation with path m/44'/501'/0'/0'
 *
 * @param seed          64-byte BIP39 seed
 * @param seed_len      Length of seed (must be 64)
 * @param wallet_out    Output: generated wallet
 * @return              0 on success, -1 on error
 */
int sol_wallet_generate(
    const uint8_t *seed,
    size_t seed_len,
    sol_wallet_t *wallet_out
);

/**
 * Create Solana wallet from seed and save to file
 *
 * @param seed          64-byte BIP39 seed
 * @param seed_len      Length of seed
 * @param name          Wallet name (used for filename)
 * @param wallet_dir    Directory to save wallet
 * @param address_out   Output: base58 address string
 * @return              0 on success, -1 on error
 */
int sol_wallet_create_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    const char *name,
    const char *wallet_dir,
    char *address_out
);

/**
 * Load wallet from file
 *
 * @param wallet_path   Path to wallet file
 * @param wallet_out    Output: loaded wallet
 * @return              0 on success, -1 on error
 */
int sol_wallet_load(
    const char *wallet_path,
    sol_wallet_t *wallet_out
);

/**
 * Save wallet to file
 *
 * @param wallet        Wallet to save
 * @param name          Wallet name
 * @param wallet_dir    Directory to save to
 * @return              0 on success, -1 on error
 */
int sol_wallet_save(
    const sol_wallet_t *wallet,
    const char *name,
    const char *wallet_dir
);

/**
 * Clear wallet from memory
 *
 * @param wallet        Wallet to clear
 */
void sol_wallet_clear(sol_wallet_t *wallet);

/**
 * Convert public key to base58 address
 *
 * @param pubkey        32-byte Ed25519 public key
 * @param address_out   Output: base58 address (at least 45 bytes)
 * @return              0 on success, -1 on error
 */
int sol_pubkey_to_address(
    const uint8_t pubkey[SOL_PUBLIC_KEY_SIZE],
    char *address_out
);

/**
 * Convert base58 address to public key
 *
 * @param address       Base58 address string
 * @param pubkey_out    Output: 32-byte public key
 * @return              0 on success, -1 on error
 */
int sol_address_to_pubkey(
    const char *address,
    uint8_t pubkey_out[SOL_PUBLIC_KEY_SIZE]
);

/**
 * Validate Solana address format
 *
 * @param address       Address to validate
 * @return              true if valid, false otherwise
 */
bool sol_validate_address(const char *address);

/**
 * Sign message with Ed25519 private key
 *
 * @param message       Message to sign
 * @param message_len   Length of message
 * @param private_key   32-byte Ed25519 private key
 * @param public_key    32-byte Ed25519 public key
 * @param signature_out Output: 64-byte signature
 * @return              0 on success, -1 on error
 */
int sol_sign_message(
    const uint8_t *message,
    size_t message_len,
    const uint8_t private_key[SOL_PRIVATE_KEY_SIZE],
    const uint8_t public_key[SOL_PUBLIC_KEY_SIZE],
    uint8_t signature_out[SOL_SIGNATURE_SIZE]
);

/* RPC endpoint management */
void sol_rpc_set_endpoint(const char *endpoint);
const char* sol_rpc_get_endpoint(void);

#ifdef __cplusplus
}
#endif

#endif /* SOL_WALLET_H */
