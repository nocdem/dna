/*
 * cellframe_wallet_create.h - Cellframe Wallet Derivation
 *
 * Derives Cellframe wallet keys and addresses from deterministic seeds.
 * No wallet files are created — all operations are in-memory.
 */

#ifndef CELLFRAME_WALLET_CREATE_H
#define CELLFRAME_WALLET_CREATE_H

#include <stdint.h>
#include <stddef.h>
#include "cellframe_wallet.h"  /* For cellframe_wallet_t */

#ifdef __cplusplus
extern "C" {
#endif

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
 * Derive Cellframe wallet address from seed (address only, no file)
 *
 * Same derivation as cellframe_wallet_create_from_seed but only returns
 * the address without creating any wallet file. Used for on-demand derivation.
 *
 * @param seed          32-byte seed (from SHA3-256 of mnemonic)
 * @param address_out   Buffer for generated address (CF_WALLET_ADDRESS_MAX bytes)
 * @return 0 on success, -1 on error
 */
int cellframe_wallet_derive_address(
    const uint8_t seed[CF_WALLET_SEED_SIZE],
    char *address_out
);

/**
 * Derive Cellframe wallet keys from seed (no file created)
 *
 * Generates a Dilithium keypair from the seed and populates a
 * cellframe_wallet_t structure. Used for on-demand signing without
 * requiring wallet files on disk.
 *
 * IMPORTANT: Caller must free the wallet with wallet_free().
 *
 * @param seed          32-byte seed (from SHA3-256 of mnemonic)
 * @param wallet_out    Output: allocated wallet with keys (caller must free)
 * @return 0 on success, -1 on error
 */
int cellframe_wallet_derive_keys(
    const uint8_t seed[CF_WALLET_SEED_SIZE],
    cellframe_wallet_t **wallet_out
);

/**
 * Send Cellframe tokens using a wallet struct
 *
 * Same as normal Cellframe send but uses a pre-populated wallet struct
 * instead of loading from a file. Used for on-demand wallet derivation.
 *
 * @param wallet        Wallet struct with address and keys
 * @param to_address    Recipient address (Base58)
 * @param amount        Amount to send (decimal string, e.g., "0.1")
 * @param token         Token ticker (NULL or "CELL" for native)
 * @param txhash_out    Output: transaction hash (128 bytes min)
 * @param txhash_out_size Size of output buffer
 * @return 0 on success, -1 on error
 */
int cellframe_send_with_wallet(
    cellframe_wallet_t *wallet,
    const char *to_address,
    const char *amount,
    const char *token,
    char *txhash_out,
    size_t txhash_out_size
);

/**
 * Free a cellframe wallet struct and securely clear key material
 *
 * @param wallet    Wallet to free (NULL-safe)
 */
void wallet_free(cellframe_wallet_t *wallet);

#ifdef __cplusplus
}
#endif

#endif /* CELLFRAME_WALLET_CREATE_H */
