/**
 * @file bip32.h
 * @brief BIP-32 Hierarchical Deterministic Key Derivation
 *
 * Implements BIP-32 HD wallet key derivation for use with secp256k1 curve.
 * Used for Ethereum wallet generation via BIP-44 derivation paths.
 *
 * BIP-32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * BIP-44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 *
 * @author DNA Messenger Team
 * @date 2025-12-08
 */

#ifndef BIP32_H
#define BIP32_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key sizes */
#define BIP32_KEY_SIZE          32      /* Private/public key component size */
#define BIP32_CHAIN_CODE_SIZE   32      /* Chain code size */
#define BIP32_SEED_SIZE         64      /* BIP39 seed size */
#define BIP32_SERIALIZED_SIZE   78      /* Serialized extended key size */

/* Hardened derivation threshold */
#define BIP32_HARDENED_OFFSET   0x80000000

/* BIP-44 coin types (SLIP-44) */
#define BIP44_COIN_BITCOIN      0       /* Bitcoin */
#define BIP44_COIN_ETHEREUM     60      /* Ethereum */
#define BIP44_COIN_TRON         195     /* TRON */
#define BIP44_COIN_SOLANA       501     /* Solana */

/**
 * Extended private key structure
 *
 * Contains both the private key and chain code needed for derivation.
 */
typedef struct {
    uint8_t private_key[BIP32_KEY_SIZE];    /* 32-byte secp256k1 private key */
    uint8_t chain_code[BIP32_CHAIN_CODE_SIZE]; /* 32-byte chain code */
    uint32_t depth;                          /* Derivation depth (0 = master) */
    uint32_t child_index;                    /* Child index (with hardened flag if applicable) */
    uint8_t parent_fingerprint[4];           /* First 4 bytes of parent pubkey hash */
} bip32_extended_key_t;

/**
 * Derive master key from BIP39 seed
 *
 * Uses HMAC-SHA512 with key "Bitcoin seed" as per BIP-32 spec.
 * This is the starting point for all HD derivation.
 *
 * @param seed          64-byte BIP39 seed
 * @param seed_len      Length of seed (should be 64)
 * @param master_out    Output: extended master key
 * @return              0 on success, -1 on error
 */
int bip32_master_key_from_seed(
    const uint8_t *seed,
    size_t seed_len,
    bip32_extended_key_t *master_out
);

/**
 * Derive child key (hardened)
 *
 * Hardened derivation uses the private key, making it impossible
 * to derive child public keys from parent public key.
 * Index should NOT include HARDENED_OFFSET - it's added internally.
 *
 * @param parent        Parent extended key
 * @param index         Child index (0-based, hardened flag added internally)
 * @param child_out     Output: derived child key
 * @return              0 on success, -1 on error
 */
int bip32_derive_hardened(
    const bip32_extended_key_t *parent,
    uint32_t index,
    bip32_extended_key_t *child_out
);

/**
 * Derive child key (normal/non-hardened)
 *
 * Normal derivation allows deriving child public keys from
 * parent public key (useful for watch-only wallets).
 *
 * @param parent        Parent extended key
 * @param index         Child index (0-based)
 * @param child_out     Output: derived child key
 * @return              0 on success, -1 on error
 */
int bip32_derive_normal(
    const bip32_extended_key_t *parent,
    uint32_t index,
    bip32_extended_key_t *child_out
);

/**
 * Derive key from path string
 *
 * Parses and derives along a BIP-32/BIP-44 path string.
 * Supports both ' and h notation for hardened derivation.
 *
 * Example paths:
 *   "m/44'/60'/0'/0/0"  - Ethereum first address (BIP-44)
 *   "m/44h/60h/0h/0/0"  - Same, using h notation
 *
 * @param seed          64-byte BIP39 seed
 * @param seed_len      Length of seed
 * @param path          Derivation path string (e.g., "m/44'/60'/0'/0/0")
 * @param key_out       Output: derived key at path
 * @return              0 on success, -1 on error
 */
int bip32_derive_path(
    const uint8_t *seed,
    size_t seed_len,
    const char *path,
    bip32_extended_key_t *key_out
);

/**
 * Derive Ethereum key using BIP-44 standard path
 *
 * Convenience function for deriving the first Ethereum address.
 * Uses path: m/44'/60'/0'/0/0
 *
 * @param seed          64-byte BIP39 seed
 * @param seed_len      Length of seed
 * @param key_out       Output: derived Ethereum key
 * @return              0 on success, -1 on error
 */
int bip32_derive_ethereum(
    const uint8_t *seed,
    size_t seed_len,
    bip32_extended_key_t *key_out
);

/**
 * Get public key from extended private key
 *
 * Computes the secp256k1 public key (uncompressed, 65 bytes)
 * from the private key.
 *
 * @param key           Extended key with private key
 * @param pubkey_out    Output: 65-byte uncompressed public key (04 || x || y)
 * @return              0 on success, -1 on error
 */
int bip32_get_public_key(
    const bip32_extended_key_t *key,
    uint8_t pubkey_out[65]
);

/**
 * Get compressed public key from extended private key
 *
 * Computes the secp256k1 compressed public key (33 bytes).
 *
 * @param key           Extended key with private key
 * @param pubkey_out    Output: 33-byte compressed public key
 * @return              0 on success, -1 on error
 */
int bip32_get_public_key_compressed(
    const bip32_extended_key_t *key,
    uint8_t pubkey_out[33]
);

/**
 * Securely clear extended key from memory
 *
 * Zeros out all key material to prevent leakage.
 *
 * @param key           Extended key to clear
 */
void bip32_clear_key(bip32_extended_key_t *key);

#ifdef __cplusplus
}
#endif

#endif /* BIP32_H */
