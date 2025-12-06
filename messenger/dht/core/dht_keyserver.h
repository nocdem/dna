/**
 * DHT-based Keyserver
 * Decentralized public key storage and lookup
 *
 * Architecture:
 * - Unified identity stored in DHT (distributed, permanent)
 * - Local cache in keyserver_cache.db (7-day TTL)
 * - Self-signed identities with Dilithium5 signatures
 * - Versioned updates (signature required)
 * - DNA name required for all identities
 *
 * DHT Keys (only 2):
 * - fingerprint:profile  -> dna_unified_identity_t (keys + name + profile)
 * - name:lookup          -> fingerprint (for name-based lookups)
 */

#ifndef DHT_KEYSERVER_H
#define DHT_KEYSERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dna_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

// Dilithium5 sizes (Category 5)
#define DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE 4627

// Kyber1024 sizes (Category 5)
#define DHT_KEYSERVER_KYBER_PUBKEY_SIZE 1568

// NOTE: Old dht_pubkey_entry_t removed - use dna_unified_identity_t instead

/**
 * Publish identity to DHT (NAME-FIRST architecture)
 * Creates dna_unified_identity_t and stores at fingerprint:profile
 * Also publishes name:lookup alias for name-based lookups
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: SHA3-512 fingerprint of Dilithium5 pubkey (128 hex chars)
 * @param name: DNA name (REQUIRED, 3-20 chars, alphanumeric)
 * @param dilithium_pubkey: Dilithium5 public key (2592 bytes)
 * @param kyber_pubkey: Kyber1024 public key (1568 bytes)
 * @param dilithium_privkey: Dilithium5 private key for signing (4896 bytes)
 * @return: 0 on success, -1 on error, -2 if name already taken
 */
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
);

/**
 * Publish name → fingerprint alias (for name-based lookups)
 * Creates alias mapping to enable lookups by name
 *
 * @param dht_ctx: DHT context
 * @param name: DNA name (3-20 chars, alphanumeric)
 * @param fingerprint: SHA3-512 fingerprint (128 hex chars)
 * @return: 0 on success, -1 on error
 */
int dht_keyserver_publish_alias(
    dht_context_t *dht_ctx,
    const char *name,
    const char *fingerprint
);

/**
 * Lookup identity from DHT (supports both fingerprint and name)
 * Fetches from fingerprint:profile and verifies signature
 * - If input is 128 hex chars: direct fingerprint lookup
 * - If input is 3-20 alphanumeric: resolves name → fingerprint first via name:lookup
 *
 * @param dht_ctx: DHT context
 * @param name_or_fingerprint: DNA name OR fingerprint (128 hex chars)
 * @param identity_out: Output identity (caller must free with dna_identity_free)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if signature verification failed
 */
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *name_or_fingerprint,
    dna_unified_identity_t **identity_out
);

/**
 * Update public keys in DHT
 * Requires signature with new private key
 *
 * @param dht_ctx: DHT context
 * @param identity: DNA identity name
 * @param new_dilithium_pubkey: New Dilithium5 public key (2592 bytes)
 * @param new_kyber_pubkey: New Kyber1024 public key (1568 bytes)
 * @param new_dilithium_privkey: New Dilithium5 private key for signing (4896 bytes)
 * @return: 0 on success, -1 on error, -2 if not authorized
 */
int dht_keyserver_update(
    dht_context_t *dht_ctx,
    const char *identity,
    const uint8_t *new_dilithium_pubkey,
    const uint8_t *new_kyber_pubkey,
    const uint8_t *new_dilithium_privkey
);

/**
 * Reverse lookup: Find identity from Dilithium pubkey fingerprint
 * Used when receiving messages from unknown senders (synchronous, blocking)
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: SHA3-512 fingerprint of Dilithium pubkey (128 hex chars)
 * @param identity_out: Output identity string (caller must free)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if signature verification failed
 */
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **identity_out
);

/**
 * Reverse lookup: Find identity from Dilithium pubkey fingerprint (asynchronous, non-blocking)
 * Used when receiving messages from unknown senders
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: SHA3-512 fingerprint of Dilithium pubkey (128 hex chars)
 * @param callback: Function called with (identity, userdata). Identity is NULL on error. Caller must free identity.
 * @param userdata: User data passed to callback
 */
void dht_keyserver_reverse_lookup_async(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    void (*callback)(char *identity, void *userdata),
    void *userdata
);

/**
 * Delete public keys from DHT
 * Note: DHT doesn't support true deletion, this is for completeness
 *
 * @param dht_ctx: DHT context
 * @param identity: DNA identity name
 * @return: 0 on success, -1 on error
 */
int dht_keyserver_delete(
    dht_context_t *dht_ctx,
    const char *identity
);

// NOTE: dht_keyserver_free_entry removed - use dna_identity_free instead

// ===== DNA Name System Functions =====

/**
 * Compute fingerprint from Dilithium5 public key
 * Fingerprint = SHA3-512(dilithium_pubkey) as 128 hex chars
 *
 * @param dilithium_pubkey: Dilithium5 public key (2592 bytes)
 * @param fingerprint_out: Output buffer (must be 129 bytes for 128 hex + null)
 */
void dna_compute_fingerprint(
    const uint8_t *dilithium_pubkey,
    char *fingerprint_out
);

/**
 * Register DNA name for a fingerprint identity
 * Requires valid blockchain transaction hash as proof of payment (0.01 CPUNK)
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param name: DNA name to register (3-36 chars, alphanumeric + . _ -)
 * @param tx_hash: Blockchain transaction hash (proof of payment)
 * @param network: Network where tx was made (e.g., "Backbone")
 * @param dilithium_privkey: Private key for signing
 * @return: 0 on success, -1 on error, -2 on name taken, -3 on invalid tx
 */
int dna_register_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *name,
    const char *tx_hash,
    const char *network,
    const uint8_t *dilithium_privkey
);

/**
 * Update DNA profile data
 * Updates wallet addresses, social profiles, bio, etc.
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param profile: Profile data to update
 * @param dilithium_privkey: Private key for signing
 * @return: 0 on success, -1 on error
 */
int dna_update_profile(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const dna_profile_data_t *profile,
    const uint8_t *dilithium_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey
);

/**
 * Renew DNA name registration
 * Extends expiration by 365 days. Requires new payment tx_hash.
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param renewal_tx_hash: New transaction hash (proof of renewal payment)
 * @param dilithium_privkey: Private key for signing
 * @return: 0 on success, -1 on error, -2 if name not registered, -3 on invalid tx
 */
int dna_renew_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    const char *renewal_tx_hash,
    const uint8_t *dilithium_privkey
);

/**
 * Load complete DNA identity from DHT
 * Fetches unified identity structure with keys, name, profile data
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param identity_out: Output identity (caller must free with dna_identity_free)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if signature verification failed
 */
int dna_load_identity(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    dna_unified_identity_t **identity_out
);

/**
 * Lookup fingerprint by DNA name
 * Searches DHT for registered name and returns fingerprint
 *
 * @param dht_ctx: DHT context
 * @param name: DNA name to lookup
 * @param fingerprint_out: Output fingerprint (caller must free)
 * @return: 0 on success, -1 on error, -2 if not found
 */
int dna_lookup_by_name(
    dht_context_t *dht_ctx,
    const char *name,
    char **fingerprint_out
);

/**
 * Check if DNA name has expired
 *
 * @param identity: Identity structure
 * @return: true if expired, false otherwise
 */
bool dna_is_name_expired(const dna_unified_identity_t *identity);

/**
 * Get display name for fingerprint
 * Returns registered name if available, otherwise shortened fingerprint
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: Fingerprint (128 hex chars)
 * @param display_name_out: Output display name (caller must free)
 * @return: 0 on success, -1 on error
 */
int dna_get_display_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **display_name_out
);

/**
 * Resolve DNA name to wallet address
 * Combines name lookup + wallet address extraction
 *
 * @param dht_ctx: DHT context
 * @param name: DNA name or fingerprint
 * @param network: Network identifier (e.g., "backbone", "eth", "btc")
 * @param address_out: Output address (caller must free)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if no address for network
 */
int dna_resolve_address(
    dht_context_t *dht_ctx,
    const char *name,
    const char *network,
    char **address_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_KEYSERVER_H
