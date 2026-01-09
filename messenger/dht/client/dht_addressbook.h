/**
 * DHT Address Book Synchronization
 * Per-identity wallet address book storage with encryption and DHT sync
 *
 * Architecture:
 * - Each identity has their own address book in DHT
 * - Address books are self-encrypted with user's own Kyber1024 pubkey
 * - Dilithium5 signature for authenticity (prevent tampering)
 * - 7-day TTL with 6-day auto-republish
 * - DHT is source of truth (replaces local on fetch)
 *
 * DHT Key Derivation:
 * SHA3-512(identity + ":addressbook") → 64-byte DHT storage key
 *
 * Data Format (before encryption):
 * {
 *   "identity": "alice",
 *   "version": 1,
 *   "timestamp": 1730742000,
 *   "addresses": [
 *     {
 *       "address": "0x742d35Cc6634...",
 *       "label": "Binance Hot Wallet",
 *       "network": "ethereum",
 *       "notes": "Trading wallet",
 *       "created_at": 1730740000,
 *       "last_used": 1730742000,
 *       "use_count": 5
 *     }
 *   ]
 * }
 *
 * Encrypted Format (stored in DHT):
 * [4-byte magic "ADDR"][1-byte version][8-byte timestamp]
 * [8-byte expiry][4-byte json_len][encrypted_json_data]
 * [4-byte sig_len][dilithium5_signature]
 *
 * Security:
 * - Kyber1024 self-encryption (only owner can decrypt)
 * - Dilithium5 signature over (json_data || timestamp)
 * - Fingerprint verification in signature validation
 *
 * @file dht_addressbook.h
 * @date 2026-01-09
 */

#ifndef DHT_ADDRESSBOOK_H
#define DHT_ADDRESSBOOK_H

#include "../core/dht_context.h"
#include "database/addressbook_db.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for address book format validation
#define DHT_ADDRESSBOOK_MAGIC 0x41444452  // "ADDR"
#define DHT_ADDRESSBOOK_VERSION 1

// Default TTL: 7 days (604,800 seconds)
#define DHT_ADDRESSBOOK_DEFAULT_TTL 604800

// Key sizes (NIST Category 5)
#define DHT_ADDRESSBOOK_KYBER_PUBKEY_SIZE 1568
#define DHT_ADDRESSBOOK_KYBER_PRIVKEY_SIZE 3168
#define DHT_ADDRESSBOOK_DILITHIUM_PUBKEY_SIZE 2592
#define DHT_ADDRESSBOOK_DILITHIUM_PRIVKEY_SIZE 4896
#define DHT_ADDRESSBOOK_DILITHIUM_SIGNATURE_SIZE 4627

/**
 * Address book entry for DHT sync (in-memory representation)
 */
typedef struct {
    char address[128];         // Wallet address
    char label[64];            // User-defined label
    char network[32];          // Network: backbone, ethereum, solana, tron
    char notes[256];           // Optional notes
    uint64_t created_at;       // When address was added
    uint64_t last_used;        // When address was last used
    uint32_t use_count;        // Number of times used
} dht_addressbook_entry_t;

/**
 * Address book structure (in-memory representation)
 */
typedef struct {
    char identity[256];                // Owner identity (e.g., "alice")
    uint32_t version;                  // Version number (for future updates)
    uint64_t timestamp;                // Unix timestamp when created/updated
    uint64_t expiry;                   // Unix timestamp when expires
    dht_addressbook_entry_t *entries;  // Array of address entries
    size_t entry_count;                // Number of entries
} dht_addressbook_t;

/**
 * Initialize DHT address book subsystem
 * Must be called before using any other functions
 *
 * @return 0 on success, -1 on error
 */
int dht_addressbook_init(void);

/**
 * Cleanup DHT address book subsystem
 * Call on shutdown
 */
void dht_addressbook_cleanup(void);

/**
 * Publish address book to DHT (encrypted with self-encryption)
 *
 * Workflow:
 * 1. Serialize address book to JSON
 * 2. Sign JSON with Dilithium5 private key
 * 3. Encrypt JSON with owner's Kyber1024 public key (self-encryption)
 * 4. Create binary blob: [header][encrypted_json][signature]
 * 5. Store in DHT at SHA3-512(identity + ":addressbook")
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity (e.g., "alice")
 * @param entries Array of address book entries
 * @param entry_count Number of entries
 * @param kyber_pubkey Owner's Kyber1024 public key (1568 bytes)
 * @param kyber_privkey Owner's Kyber1024 private key (3168 bytes) - for decryption test
 * @param dilithium_pubkey Owner's Dilithium5 public key (2592 bytes) - for encryption
 * @param dilithium_privkey Owner's Dilithium5 private key (4896 bytes) - for signing
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on error
 */
int dht_addressbook_publish(
    dht_context_t *dht_ctx,
    const char *identity,
    const dht_addressbook_entry_t *entries,
    size_t entry_count,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey,
    uint32_t ttl_seconds
);

/**
 * Fetch address book from DHT (decrypt and verify)
 *
 * Workflow:
 * 1. Query DHT at SHA3-512(identity + ":addressbook")
 * 2. Parse binary blob header
 * 3. Decrypt encrypted JSON with Kyber1024 private key
 * 4. Verify Dilithium5 signature
 * 5. Parse JSON to address book
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param entries_out Output array of address entries (caller must free with dht_addressbook_free_entries)
 * @param count_out Output number of entries
 * @param kyber_privkey Owner's Kyber1024 private key (for decryption)
 * @param dilithium_pubkey Owner's Dilithium5 public key (for signature verification)
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_addressbook_fetch(
    dht_context_t *dht_ctx,
    const char *identity,
    dht_addressbook_entry_t **entries_out,
    size_t *count_out,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey
);

/**
 * Free address book entries array
 *
 * @param entries Array of address entries
 * @param count Number of entries
 */
void dht_addressbook_free_entries(dht_addressbook_entry_t *entries, size_t count);

/**
 * Free address book structure
 *
 * @param addressbook Address book to free
 */
void dht_addressbook_free(dht_addressbook_t *addressbook);

/**
 * Check if address book exists in DHT
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @return true if exists, false otherwise
 */
bool dht_addressbook_exists(
    dht_context_t *dht_ctx,
    const char *identity
);

/**
 * Get address book timestamp from DHT (without full fetch)
 * Useful for checking if local copy is outdated
 *
 * @param dht_ctx DHT context
 * @param identity Owner identity
 * @param timestamp_out Output timestamp
 * @return 0 on success, -1 on error, -2 if not found
 */
int dht_addressbook_get_timestamp(
    dht_context_t *dht_ctx,
    const char *identity,
    uint64_t *timestamp_out
);

/**
 * Convert database entries to DHT entries
 * Helper for syncing local database to DHT
 *
 * @param db_entries Database entry array
 * @param count Number of entries
 * @return Allocated array of DHT entries (caller must free with dht_addressbook_free_entries)
 */
dht_addressbook_entry_t* dht_addressbook_from_db_entries(
    const addressbook_entry_t *db_entries,
    size_t count
);

/**
 * Convert DHT entries to database entries
 * Helper for syncing DHT to local database
 *
 * @param dht_entries DHT entry array
 * @param count Number of entries
 * @return Allocated array of database entries (caller must free)
 */
addressbook_entry_t* dht_addressbook_to_db_entries(
    const dht_addressbook_entry_t *dht_entries,
    size_t count
);

#ifdef __cplusplus
}
#endif

#endif // DHT_ADDRESSBOOK_H
