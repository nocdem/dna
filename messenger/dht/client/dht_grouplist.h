/**
 * DHT Group List Synchronization
 * Per-identity group membership list storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity has their own group list in DHT
 * - Group lists are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL with 6-day auto-republish
 * - DHT is source of truth (replaces local on fetch)
 *
 * DHT Key Derivation:
 * SHA3-512(identity + ":grouplist") -> 64-byte DHT storage key
 *
 * Data Format (before encryption):
 * {
 *   "identity": "alice_fingerprint_128hex",
 *   "version": 1,
 *   "timestamp": 1737196800,
 *   "groups": ["uuid1", "uuid2", "uuid3"]
 * }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "GLST"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte json_len][encrypted_json_data]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 * - Fingerprint verification in signature validation
 *
 * @file dht_grouplist.h
 * @date 2026-01-18
 */

#ifndef DHT_GROUPLIST_H
#define DHT_GROUPLIST_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for group list format validation
#define DHT_GROUPLIST_MAGIC 0x474C5354  // "GLST"
#define DHT_GROUPLIST_VERSION 1

// Default TTL: 7 days (604,800 seconds)
#define DHT_GROUPLIST_DEFAULT_TTL 604800

// Key sizes (NIST Category 5)
#define DHT_GROUPLIST_KYBER_PUBKEY_SIZE 1568
#define DHT_GROUPLIST_KYBER_PRIVKEY_SIZE 3168
#define DHT_GROUPLIST_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_GROUPLIST_DILITHIUM_PRIVKEY_SIZE 4896
#define DHT_GROUPLIST_DILITHIUM_SIGNATURE_SIZE 4627

/**
 * Group list entry (in-memory representation)
 */
typedef struct {
    char identity[256];              // Owner identity (fingerprint)
    uint32_t version;                // Version number (for future updates)
    uint64_t timestamp;              // Unix timestamp when created/updated
    uint64_t expiry;                 // Unix timestamp when expires
    char **groups;                   // Array of group UUIDs
    size_t group_count;              // Number of groups
} dht_grouplist_t;

/**
 * Initialize DHT group list subsystem
 * Must be called before using any other functions
 *
 * @return 0 on success, -1 on error
 */
int dht_grouplist_init(void);

/**
 * Cleanup DHT group list subsystem
 * Call on shutdown
 */
void dht_grouplist_cleanup(void);

/**
 * Publish group list to DHT (encrypted with self-encryption)
 *
 * Workflow:
 * 1. Serialize group list to JSON
 * 2. Sign JSON with Dilithium5 private key
 * 3. Encrypt JSON with owner's Kyber1024 public key (self-encryption)
 * 4. Create binary blob: [header][encrypted_json][signature]
 * 5. Store in DHT at SHA3-512(identity + ":grouplist")
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity (fingerprint, 128 hex chars)
 * @param group_uuids Array of group UUIDs (36 chars each)
 * @param group_count Number of groups
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes) - for decryption test
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes) - for encryption
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes) - for signing
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_grouplist_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const char **group_uuids,
    size_t group_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds
);

/**
 * Fetch group list from DHT (decrypt and verify)
 *
 * Workflow:
 * 1. Query DHT at SHA3-512(identity + ":grouplist")
 * 2. Parse binary blob header
 * 3. Decrypt encrypted JSON with Kyber1024 private key
 * 4. Verify Dilithium5 signature
 * 5. Parse JSON to group list
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param groups_out Output array of group UUIDs (caller must free with dht_grouplist_free_groups)
 * @param count_out Output number of groups
 * @param kyber_privkey Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey Owner's Dilithium5 public key (for signature verification)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_grouplist_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    char ***groups_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey
);

/**
 * Free group list array
 *
 * @param groups Array of group UUID strings
 * @param count Number of groups
 */
void dht_grouplist_free_groups(char **groups, size_t count);

/**
 * Free group list structure
 *
 * @param list Group list to free
 */
void dht_grouplist_free(dht_grouplist_t *list);

/**
 * Check if group list exists in DHT
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @return true if exists, false otherwise
 */
bool dht_grouplist_exists(
    dht_context_t *dht_ctx,
    const char *identity
);

/**
 * Get group list timestamp from DHT (without full fetch)
 * Useful for checking if local copy is outdated
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param timestamp_out Output timestamp
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_grouplist_get_timestamp(
    dht_context_t *dht_ctx,
    const char *identity,
    uint64_t *timestamp_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_GROUPLIST_H
