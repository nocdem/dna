/**
 * DHT Contact List Synchronization
 * Per-identity contact list storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity has their own contact list in DHT
 * - Contact lists are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL with 6-day auto-republish
 * - DHT is source of truth (replaces local on fetch)
 *
 * DHT Key Derivation:
 * SHA3-512(identity + ":contactlist") → 64-byte DHT storage key
 *
 * Data Format (before encryption):
 * {
 *   "identity": "alice",
 *   "version": 1,
 *   "timestamp": 1730742000,
 *   "contacts": ["bob", "charlie", "diana"]
 * }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "CLST"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte json_len][encrypted_json_data]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 * - Fingerprint verification in signature validation
 *
 * @file dht_contactlist.h
 * @date 2025-11-04
 */

#ifndef DHT_CONTACTLIST_H
#define DHT_CONTACTLIST_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for contact list format validation
#define DHT_CONTACTLIST_MAGIC 0x434C5354  // "CLST"
#define DHT_CONTACTLIST_VERSION 1

// Default TTL: 7 days (604,800 seconds)
#define DHT_CONTACTLIST_DEFAULT_TTL 604800

// Key sizes (NIST Category 5)
#define DHT_CONTACTLIST_KYBER_PUBKEY_SIZE 1568
#define DHT_CONTACTLIST_KYBER_PRIVKEY_SIZE 3168
#define DHT_CONTACTLIST_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_CONTACTLIST_DILITHIUM_PRIVKEY_SIZE 4896
#define DHT_CONTACTLIST_DILITHIUM_SIGNATURE_SIZE 4627

/**
 * Contact list entry (in-memory representation)
 */
typedef struct {
    char identity[256];              // Owner identity (e.g., "alice")
    uint32_t version;                // Version number (for future updates)
    uint64_t timestamp;              // Unix timestamp when created/updated
    uint64_t expiry;                 // Unix timestamp when expires
    char **contacts;                 // Array of contact identities
    size_t contact_count;            // Number of contacts
} dht_contactlist_t;

/**
 * Initialize DHT contact list subsystem
 * Must be called before using any other functions
 *
 * @return 0 on success, -1 on error
 */
int dht_contactlist_init(void);

/**
 * Cleanup DHT contact list subsystem
 * Call on shutdown
 */
void dht_contactlist_cleanup(void);

/**
 * Publish contact list to DHT (encrypted with self-encryption)
 *
 * Workflow:
 * 1. Serialize contact list to JSON
 * 2. Sign JSON with Dilithium5 private key
 * 3. Encrypt JSON with owner's Kyber1024 public key (self-encryption)
 * 4. Create binary blob: [header][encrypted_json][signature]
 * 5. Store in DHT at SHA3-512(identity + ":contactlist")
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity (e.g., "alice")
 * @param contacts Array of contact identities
 * @param contact_count Number of contacts
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes) - for decryption test
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes) - for encryption
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes) - for signing
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_contactlist_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const char **contacts,
    size_t contact_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds
);

/**
 * Fetch contact list from DHT (decrypt and verify)
 *
 * Workflow:
 * 1. Query DHT at SHA3-512(identity + ":contactlist")
 * 2. Parse binary blob header
 * 3. Decrypt encrypted JSON with Kyber1024 private key
 * 4. Verify Dilithium5 signature
 * 5. Parse JSON to contact list
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param contacts_out Output array of contact identities (caller must free)
 * @param count_out Output number of contacts
 * @param kyber_privkey Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey Owner's Dilithium5 public key (for signature verification)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_contactlist_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    char ***contacts_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey
);

/**
 * Clear contact list from DHT (best-effort)
 * Note: DHT deletion is not guaranteed, values expire naturally
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @return 0 on success (best-effort), -1 on error
 */
int dht_contactlist_clear(
    dht_context_t *dht_ctx,
    const char *identity
);

/**
 * Free contact list array
 *
 * @param contacts Array of contact identity strings
 * @param count Number of contacts
 */
void dht_contactlist_free_contacts(char **contacts, size_t count);

/**
 * Free contact list structure
 *
 * @param list Contact list to free
 */
void dht_contactlist_free(dht_contactlist_t *list);

/**
 * Check if contact list exists in DHT
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @return true if exists, false otherwise
 */
bool dht_contactlist_exists(
    dht_context_t *dht_ctx,
    const char *identity
);

/**
 * Get contact list timestamp from DHT (without full fetch)
 * Useful for checking if local copy is outdated
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param timestamp_out Output timestamp
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_contactlist_get_timestamp(
    dht_context_t *dht_ctx,
    const char *identity,
    uint64_t *timestamp_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_CONTACTLIST_H
