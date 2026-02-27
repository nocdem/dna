/**
 * DHT GEK (Group Encryption Key) Synchronization
 * Per-identity GEK storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity has their own GEK cache in DHT
 * - GEKs are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL with auto-republish
 * - DHT is source of truth (enables multi-device sync)
 *
 * DHT Key Derivation:
 * SHA3-512(identity + ":geks") → 64-byte DHT storage key
 *
 * Data Format (before encryption):
 * {
 *   "identity": "alice_fingerprint",
 *   "version": 1,
 *   "timestamp": 1737820800,
 *   "groups": {
 *     "group-uuid-1": {
 *       "keys": [
 *         {"v": 1737820000, "key": "<base64>", "created": 1737820000, "expires": 1738424800},
 *         {"v": 1737907200, "key": "<base64>", "created": 1737907200, "expires": 1738512000}
 *       ]
 *     }
 *   }
 * }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "GEKS"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte json_len][encrypted_json_data]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 * - Fingerprint verification in signature validation
 *
 * @file dht_geks.h
 * @date 2026-01-25
 */

#ifndef DHT_GEKS_H
#define DHT_GEKS_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for GEK sync format validation
#define DHT_GEKS_MAGIC 0x47454B53  // "GEKS"
#define DHT_GEKS_VERSION 1

// Default TTL: 7 days (604,800 seconds)
#define DHT_GEKS_DEFAULT_TTL 604800

// Key sizes (NIST Category 5)
#define DHT_GEKS_KYBER_PUBKEY_SIZE 1568
#define DHT_GEKS_KYBER_PRIVKEY_SIZE 3168
#define DHT_GEKS_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_GEKS_DILITHIUM_PRIVKEY_SIZE 4896
#define DHT_GEKS_DILITHIUM_SIGNATURE_SIZE 4627

// GEK key size (AES-256)
#define DHT_GEKS_KEY_SIZE 32

// Maximum groups per identity (sanity limit)
#define DHT_GEKS_MAX_GROUPS 256

// Maximum GEK versions per group (usually 1-3 active)
#define DHT_GEKS_MAX_VERSIONS_PER_GROUP 16

/**
 * Single GEK entry for sync
 */
typedef struct {
    char group_uuid[37];           // UUID v4 (36 + null)
    uint32_t gek_version;          // Version (Unix timestamp)
    uint8_t gek[DHT_GEKS_KEY_SIZE]; // AES-256 key (32 bytes)
    uint64_t created_at;           // Creation timestamp
    uint64_t expires_at;           // Expiration timestamp
} dht_gek_entry_t;

/**
 * GEK cache for sync (all GEKs for one identity)
 */
typedef struct {
    char identity[256];            // Owner identity fingerprint
    uint32_t version;              // Sync format version
    uint64_t timestamp;            // Unix timestamp when created/updated
    uint64_t expiry;               // Unix timestamp when expires
    dht_gek_entry_t *entries;      // Array of GEK entries
    size_t entry_count;            // Number of entries
} dht_geks_cache_t;

/**
 * Initialize DHT GEK sync subsystem
 * Must be called before using any other functions
 *
 * @return 0 on success, -1 on error
 */
int dht_geks_init(void);

/**
 * Cleanup DHT GEK sync subsystem
 * Call on shutdown
 */
void dht_geks_cleanup(void);

/**
 * Publish all GEKs to DHT (encrypted with self-encryption)
 *
 * Workflow:
 * 1. Export all local GEKs from database
 * 2. Serialize to JSON
 * 3. Sign JSON with Dilithium5 private key
 * 4. Encrypt JSON with owner's Kyber1024 public key (self-encryption)
 * 5. Create binary blob: [header][encrypted_json][signature]
 * 6. Store in DHT at SHA3-512(identity + ":geks")
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity fingerprint (128-char hex)
 * @param entries Array of GEK entries to publish
 * @param entry_count Number of entries
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes)
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes)
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes)
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_geks_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const dht_gek_entry_t *entries,
    size_t entry_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds
);

/**
 * Fetch GEKs from DHT (decrypt and verify)
 *
 * Workflow:
 * 1. Query DHT at SHA3-512(identity + ":geks")
 * 2. Parse binary blob header
 * 3. Decrypt encrypted JSON with Kyber1024 private key
 * 4. Verify Dilithium5 signature
 * 5. Parse JSON to GEK entries
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity fingerprint
 * @param entries_out Output array of GEK entries (caller must free with dht_geks_free_entries)
 * @param count_out Output number of entries
 * @param kyber_privkey Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey Owner's Dilithium5 public key (for signature verification)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_geks_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_gek_entry_t **entries_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey
);

/**
 * Free GEK entries array
 *
 * @param entries Array of GEK entries
 * @param count Number of entries
 */
void dht_geks_free_entries(dht_gek_entry_t *entries, size_t count);

/**
 * Free GEK cache structure
 *
 * @param cache Cache to free
 */
void dht_geks_free_cache(dht_geks_cache_t *cache);

/**
 * Check if GEKs exist in DHT for identity
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity fingerprint
 * @return true if exists, false otherwise
 */
bool dht_geks_exists(
    dht_context_t *dht_ctx,
    const char *identity
);

/**
 * Get GEKs timestamp from DHT (without full fetch)
 * Useful for checking if local copy is outdated
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity fingerprint
 * @param timestamp_out Output timestamp
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_geks_get_timestamp(
    dht_context_t *dht_ctx,
    const char *identity,
    uint64_t *timestamp_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_GEKS_H
