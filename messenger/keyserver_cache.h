/**
 * Keyserver Cache - SQLite-based local cache for public keys
 * Phase 4: Reduces redundant keyserver lookups
 *
 * Architecture:
 * - Local SQLite database (~/.dna/keyserver_cache.db)
 * - Caches: Fingerprint (or name), Dilithium5 public key, Kyber1024 public key
 * - TTL: 7 days (configurable)
 * - Automatic cache invalidation and refresh
 * - FINGERPRINT-FIRST: Primary key is fingerprint (128 hex chars)
 */

#ifndef KEYSERVER_CACHE_H
#define KEYSERVER_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Cached Public Key Entry
 * FINGERPRINT-FIRST: identity field stores fingerprint (128 hex chars)
 */
typedef struct {
    char identity[256];              // Fingerprint (128 hex) or name (for backwards compat)
    uint8_t *dilithium_pubkey;       // Dilithium5 public key (2592 bytes)
    size_t dilithium_pubkey_len;
    uint8_t *kyber_pubkey;           // Kyber1024 public key (1568 bytes)
    size_t kyber_pubkey_len;
    uint64_t cached_at;              // Unix timestamp when cached
    uint64_t ttl_seconds;            // Time-to-live (default: 7 days = 604800)
} keyserver_cache_entry_t;

/**
 * Initialize keyserver cache
 * Creates SQLite database if it doesn't exist
 *
 * @param db_path: Path to SQLite database file (NULL = default ~/.dna/keyserver_cache.db)
 * @return: 0 on success, -1 on error
 */
int keyserver_cache_init(const char *db_path);

/**
 * Cleanup keyserver cache
 * Closes database connection
 */
void keyserver_cache_cleanup(void);

/**
 * Get cached public key
 * Returns NULL if not found or expired
 *
 * @param identity: DNA identity to lookup
 * @param entry_out: Output entry (caller must free with keyserver_cache_free_entry)
 * @return: 0 on success (found and not expired), -1 on error, -2 if not found/expired
 */
int keyserver_cache_get(const char *identity, keyserver_cache_entry_t **entry_out);

/**
 * Store public key in cache
 * Updates existing entry or creates new one
 *
 * @param identity: DNA identity
 * @param dilithium_pubkey: Dilithium5 public key (2592 bytes)
 * @param dilithium_pubkey_len: Length of Dilithium key
 * @param kyber_pubkey: Kyber1024 public key (1568 bytes)
 * @param kyber_pubkey_len: Length of Kyber key
 * @param ttl_seconds: Time-to-live in seconds (0 = default 7 days)
 * @return: 0 on success, -1 on error
 */
int keyserver_cache_put(
    const char *identity,
    const uint8_t *dilithium_pubkey,
    size_t dilithium_pubkey_len,
    const uint8_t *kyber_pubkey,
    size_t kyber_pubkey_len,
    uint64_t ttl_seconds
);

/**
 * Delete cached entry
 *
 * @param identity: DNA identity to delete
 * @return: 0 on success, -1 on error
 */
int keyserver_cache_delete(const char *identity);

/**
 * Clear all expired entries
 * Runs garbage collection on the cache
 *
 * @return: Number of entries deleted, -1 on error
 */
int keyserver_cache_expire_old(void);

/**
 * Check if cached entry exists and is valid
 *
 * @param identity: DNA identity to check
 * @return: true if exists and not expired, false otherwise
 */
bool keyserver_cache_exists(const char *identity);

/**
 * Get cache statistics
 *
 * @param total_entries: Total entries in cache (output)
 * @param expired_entries: Number of expired entries (output)
 * @return: 0 on success, -1 on error
 */
int keyserver_cache_stats(int *total_entries, int *expired_entries);

/**
 * Free cache entry
 *
 * @param entry: Entry to free
 */
void keyserver_cache_free_entry(keyserver_cache_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif // KEYSERVER_CACHE_H
