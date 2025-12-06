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

/* Address buffer size */
#define CF_WALLET_ADDRESS_MAX   128

/**
 * Create a Cellframe wallet from a 32-byte seed
 *
 * Generates a Dilithium MODE_1 keypair deterministically from the seed,
 * writes a .dwallet file, and returns the wallet address.
 *
 * @param seed          32-byte seed for deterministic key generation
 * @param wallet_name   Name for the wallet (used in filename, max 64 chars)
 * @param wallet_dir    Directory to save wallet file (e.g., ~/.dna/wallets/)
 * @param address_out   Buffer for generated address (CF_WALLET_ADDRESS_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_wallet_create_from_seed(
    const uint8_t seed[32],
    const char *wallet_name,
    const char *wallet_dir,
    char *address_out
);

/**
 * Derive Cellframe wallet seed from BIP39 master seed
 *
 * Uses SHAKE256(master_seed || "cellframe-wallet-v1", 32)
 *
 * @param master_seed       64-byte BIP39 master seed
 * @param wallet_seed_out   32-byte output buffer for wallet seed
 * @return 0 on success, -1 on error
 */
int cellframe_derive_wallet_seed(
    const uint8_t master_seed[64],
    uint8_t wallet_seed_out[32]
);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_WALLET_CREATE_H */
