/*
 * cellframe_wallet_create.h - Cellframe Wallet Creation
 *
 * Creates CF20 .dwallet files from deterministic seeds.
 * Used to generate Cellframe wallets during DNA identity creation.
 */

#ifndef CELLFRAME_WALLET_CREATE_H
#define CELLFRAME_WALLET_CREATE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wallet file constants */
#define DWALLET_MAGIC           "DWALLET\0"
#define DWALLET_MAGIC_SIZE      8
#define DWALLET_VERSION_UNPROTECTED  1
#define DWALLET_HEADER_SIZE     23

/* Dilithium MODE_1 key sizes (Cellframe default) */
#define CF_DILITHIUM_PUBLICKEYBYTES  1184
#define CF_DILITHIUM_SECRETKEYBYTES  2800
#define CF_DILITHIUM_KIND_MODE_1     1

/* Cellframe wallet seed size (SHA3-256 output) */
#define CF_WALLET_SEED_SIZE     32

/* Address buffer size */
#define CF_WALLET_ADDRESS_MAX   128

/**
 * Derive Cellframe wallet seed from mnemonic words
 *
 * Matches official Cellframe wallet app derivation:
 * SHA3-256(words joined with spaces) → 32 bytes
 *
 * NOTE: This is NOT BIP39! Cellframe uses direct SHA3-256 hash of mnemonic string.
 *
 * @param mnemonic      Space-separated mnemonic words (e.g., "word1 word2 ... word24")
 * @param seed_out      Output buffer for 32-byte seed
 * @return 0 on success, -1 on error
 */
int cellframe_derive_seed_from_mnemonic(
    const char *mnemonic,
    uint8_t seed_out[CF_WALLET_SEED_SIZE]
);

/**
 * Create a Cellframe wallet from a 32-byte seed
 *
 * Generates a Dilithium MODE_1 keypair deterministically from the seed,
 * writes a .dwallet file, and returns the wallet address.
 *
 * Use cellframe_derive_seed_from_mnemonic() to get the seed from mnemonic.
 *
 * @param seed          32-byte seed (from SHA3-256 of mnemonic)
 * @param wallet_name   Name for the wallet (used in filename, max 64 chars)
 * @param wallet_dir    Directory to save wallet file (e.g., ~/.dna/wallets/)
 * @param address_out   Buffer for generated address (CF_WALLET_ADDRESS_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_wallet_create_from_seed(
    const uint8_t seed[CF_WALLET_SEED_SIZE],
    const char *wallet_name,
    const char *wallet_dir,
    char *address_out
);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_WALLET_CREATE_H */
