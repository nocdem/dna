/*
 * DNA Messenger - Keys Module
 *
 * Public key storage, retrieval, and contact list management.
 * Integrates with DHT keyserver and local SQLite cache.
 */

#ifndef MESSENGER_KEYS_H
#define MESSENGER_KEYS_H

#include "messenger_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Store public key to DHT keyserver
 *
 * Publishes Dilithium5 and Kyber1024 public keys to DHT with Dilithium5 signature.
 * Uses fingerprint-first approach (fingerprint is primary identifier).
 *
 * @param ctx: Messenger context
 * @param fingerprint: Identity fingerprint (128 hex chars)
 * @param display_name: Optional human-readable name (can be NULL)
 * @param signing_pubkey: Dilithium5 public key (2592 bytes)
 * @param signing_pubkey_len: Signing key length
 * @param encryption_pubkey: Kyber1024 public key (1568 bytes)
 * @param encryption_pubkey_len: Encryption key length
 * @return: 0 on success, -1 on error
 */
int messenger_store_pubkey(
    messenger_context_t *ctx,
    const char *fingerprint,
    const char *display_name,
    const uint8_t *signing_pubkey,
    size_t signing_pubkey_len,
    const uint8_t *encryption_pubkey,
    size_t encryption_pubkey_len
);

/**
 * Load public key from cache or DHT keyserver
 *
 * Cache-first approach: checks local SQLite cache (7-day TTL), then fetches from DHT.
 * Automatically caches fetched keys for future lookups.
 *
 * @param ctx: Messenger context
 * @param identity: Identity name or fingerprint
 * @param signing_pubkey_out: Output Dilithium5 public key (caller must free)
 * @param signing_pubkey_len_out: Output signing key length
 * @param encryption_pubkey_out: Output Kyber1024 public key (caller must free)
 * @param encryption_pubkey_len_out: Output encryption key length
 * @param fingerprint_out: Optional output fingerprint (129 bytes), can be NULL
 * @return: 0 on success, -1 on error (-2 = not found, -3 = signature verification failed)
 */
int messenger_load_pubkey(
    messenger_context_t *ctx,
    const char *identity,
    uint8_t **signing_pubkey_out,
    size_t *signing_pubkey_len_out,
    uint8_t **encryption_pubkey_out,
    size_t *encryption_pubkey_len_out,
    char *fingerprint_out
);

/**
 * List all identities in keyserver
 *
 * Fetches list from cpunk.io API and displays to console.
 * Legacy function - may be deprecated in favor of local contact list.
 *
 * @param ctx: Messenger context
 * @return: 0 on success, -1 on error
 */
int messenger_list_pubkeys(messenger_context_t *ctx);

/**
 * Get contact list from local database
 *
 * Returns array of contact identity strings from per-identity contacts database.
 * Automatically migrates from global contacts.db on first call (Phase 9.5).
 *
 * @param ctx: Messenger context
 * @param identities_out: Output array of identity strings (caller must free each string and array)
 * @param count_out: Number of identities returned
 * @return: 0 on success, -1 on error
 */
int messenger_get_contact_list(messenger_context_t *ctx, char ***identities_out, int *count_out);

#ifdef __cplusplus
}
#endif

#endif // MESSENGER_KEYS_H
