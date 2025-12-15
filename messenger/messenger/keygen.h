/*
 * DNA Messenger - Key Generation Module
 *
 * Key generation, name registration, and identity restoration.
 * Handles BIP39 seed phrases, Dilithium5 + Kyber1024 key derivation,
 * DHT keyserver publishing, and encrypted DHT identity backup.
 */

#ifndef MESSENGER_KEYGEN_H
#define MESSENGER_KEYGEN_H

#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate new identity with random BIP39 seed
 *
 * Creates new Dilithium5 + Kyber1024 keypair from random 24-word BIP39 seed.
 * Fingerprint-first approach: keys saved as ~/.dna/<fingerprint>.{dsa,kem}.
 * Auto-publishes public keys to DHT keyserver (fingerprint-first).
 * Creates encrypted DHT identity backup for permanent DHT operations.
 *
 * @param ctx: Messenger context
 * @param identity: Display name (optional, can be NULL for fingerprint-only)
 * @return: 0 on success, -1 on error
 */
int messenger_generate_keys(messenger_context_t *ctx, const char *identity);

/**
 * Generate identity from existing seed (deterministic)
 *
 * Deterministically derives Dilithium5 + Kyber1024 keypair from seeds.
 * Used for identity restoration across devices (same seed → same keys).
 * Auto-publishes public keys to DHT keyserver.
 * Creates encrypted DHT identity backup.
 * Stores only mnemonic.enc - wallet keys derived on-demand for transactions.
 *
 * Directory structure: ~/.dna/<fingerprint>/keys/, ~/.dna/<fingerprint>/
 *
 * @param name: Identity name (optional display name, can be NULL)
 * @param signing_seed: 32-byte seed for Dilithium5 key derivation
 * @param encryption_seed: 32-byte seed for Kyber1024 key derivation
 * @param wallet_seed: 32-byte seed for Cellframe wallet (DEPRECATED, use mnemonic)
 * @param master_seed: 64-byte BIP39 master seed for multi-chain wallets (optional, can be NULL)
 * @param mnemonic: Space-separated BIP39 mnemonic (for recovery, optional)
 * @param data_dir: Base directory (e.g., ~/.dna)
 * @param password: Password to encrypt keys (NULL for no encryption - not recommended)
 * @param fingerprint_out: Output buffer for fingerprint (129 bytes)
 * @return: 0 on success, -1 on error
 */
int messenger_generate_keys_from_seeds(
    const char *name,
    const uint8_t *signing_seed,
    const uint8_t *encryption_seed,
    const uint8_t *wallet_seed,
    const uint8_t *master_seed,
    const char *mnemonic,
    const char *data_dir,
    const char *password,
    char *fingerprint_out
);

/**
 * Register human-readable name in DHT keyserver
 *
 * Maps display name → fingerprint in DHT (365-day TTL, FREE in alpha).
 * Enables users to find each other by name instead of fingerprint.
 * Also publishes reverse mapping (fingerprint → name) for sender ID display.
 *
 * @param ctx: Messenger context
 * @param identity: Display name to register
 * @param fingerprint: Identity fingerprint (128 hex chars)
 * @return: 0 on success, -1 on error
 */
int messenger_register_name(
    messenger_context_t *ctx,
    const char *identity,
    const char *fingerprint
);

/**
 * Restore identity from BIP39 seed (command-line workflow)
 *
 * Prompts user for 24-word BIP39 seed, validates, and regenerates keys.
 * Used by CLI/GUI restoration wizards.
 *
 * @param ctx: Messenger context
 * @param identity: Display name (optional)
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys(messenger_context_t *ctx, const char *identity);

/**
 * Restore identity from seed file
 *
 * Reads BIP39 seed from file and regenerates keys.
 * Useful for automated recovery or backup restoration.
 *
 * @param ctx: Messenger context
 * @param identity: Display name (optional)
 * @param seed_file: Path to file containing BIP39 seed phrase
 * @return: 0 on success, -1 on error
 */
int messenger_restore_keys_from_file(messenger_context_t *ctx, const char *identity, const char *seed_file);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_KEYGEN_H
