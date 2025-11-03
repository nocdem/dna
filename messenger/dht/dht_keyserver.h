/**
 * DHT-based Keyserver
 * Decentralized public key storage and lookup
 *
 * Architecture:
 * - Public keys stored in DHT (distributed, permanent)
 * - Local cache in keyserver_cache.db (7-day TTL)
 * - Self-signed keys with Dilithium3 signatures
 * - Versioned updates (signature required)
 *
 * DHT Key Format: SHA256(identity + ":pubkey")
 */

#ifndef DHT_KEYSERVER_H
#define DHT_KEYSERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
typedef struct dht_context dht_context_t;

// Dilithium3 sizes
#define DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE 1952
#define DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE 3309

// Kyber512 sizes
#define DHT_KEYSERVER_KYBER_PUBKEY_SIZE 800

/**
 * DHT Public Key Entry
 * Stored in DHT at key: SHA256(identity + ":pubkey")
 */
typedef struct {
    char identity[256];                                  // DNA identity name
    uint8_t dilithium_pubkey[DHT_KEYSERVER_DILITHIUM_PUBKEY_SIZE];  // Dilithium3 public key
    uint8_t kyber_pubkey[DHT_KEYSERVER_KYBER_PUBKEY_SIZE];          // Kyber512 public key
    uint64_t timestamp;                                  // Unix timestamp
    uint32_t version;                                    // Version number (for updates)
    char fingerprint[65];                                // SHA256 hex of dilithium_pubkey
    uint8_t signature[DHT_KEYSERVER_DILITHIUM_SIGNATURE_SIZE];      // Self-signature
} dht_pubkey_entry_t;

/**
 * Publish public keys to DHT
 * Creates self-signed entry and stores in DHT
 *
 * @param dht_ctx: DHT context
 * @param identity: DNA identity name
 * @param dilithium_pubkey: Dilithium3 public key (1952 bytes)
 * @param kyber_pubkey: Kyber512 public key (800 bytes)
 * @param dilithium_privkey: Dilithium3 private key for signing (4032 bytes)
 * @return: 0 on success, -1 on error
 */
int dht_keyserver_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const uint8_t *dilithium_pubkey,
    const uint8_t *kyber_pubkey,
    const uint8_t *dilithium_privkey
);

/**
 * Lookup public keys from DHT
 * Fetches entry and verifies signature
 *
 * @param dht_ctx: DHT context
 * @param identity: DNA identity name
 * @param entry_out: Output entry (caller must free with dht_keyserver_free_entry)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if signature verification failed
 */
int dht_keyserver_lookup(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_pubkey_entry_t **entry_out
);

/**
 * Update public keys in DHT
 * Requires signature with new private key
 *
 * @param dht_ctx: DHT context
 * @param identity: DNA identity name
 * @param new_dilithium_pubkey: New Dilithium3 public key
 * @param new_kyber_pubkey: New Kyber512 public key
 * @param new_dilithium_privkey: New Dilithium3 private key for signing
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
 * Used when receiving messages from unknown senders
 *
 * @param dht_ctx: DHT context
 * @param fingerprint: SHA256 fingerprint of Dilithium pubkey (64 hex chars)
 * @param identity_out: Output identity string (caller must free)
 * @return: 0 on success, -1 on error, -2 if not found, -3 if signature verification failed
 */
int dht_keyserver_reverse_lookup(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **identity_out
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

/**
 * Free public key entry
 *
 * @param entry: Entry to free
 */
void dht_keyserver_free_entry(dht_pubkey_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif // DHT_KEYSERVER_H
