/**
 * Cache Manager - Unified lifecycle management for all cache modules
 * Phase 7: DHT Refactoring
 *
 * Coordinates initialization, cleanup, and statistics for:
 * - Keyserver cache (global, public keys, 7d TTL)
 * - Profile cache (per-identity, profiles, 7d TTL)
 * - Presence cache (in-memory, online status, 5min TTL)
 * - Contacts database (per-identity, permanent)
 *
 * @file cache_manager.h
 * @date 2025-11-16
 */

#ifndef CACHE_MANAGER_H
#define CACHE_MANAGER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Aggregated cache statistics across all modules
 */
typedef struct {
    size_t total_entries;           // Total cached entries across all caches
    size_t total_size_bytes;        // Approximate disk usage (estimated)
    size_t keyserver_entries;       // Keyserver cache count
    size_t profile_entries;         // Profile cache count (current identity)
    size_t presence_entries;        // Presence cache count (in-memory)
    size_t expired_entries;         // Total expired but not yet evicted
} cache_manager_stats_t;

/**
 * Initialize ALL cache modules in dependency order
 *
 * Order:
 * 1. Keyserver cache (global)
 * 2. Profile cache (if identity provided)
 * 3. Contacts database (if identity provided)
 * 4. Presence cache (in-memory)
 * 5. Run startup eviction (clean expired entries)
 *
 * @param identity Current identity fingerprint (NULL = global caches only)
 * @return 0 on success, -1 on error
 */
int cache_manager_init(const char *identity);

/**
 * Cleanup ALL cache modules in reverse order
 *
 * Closes all database connections and frees resources.
 * Safe to call multiple times.
 */
void cache_manager_cleanup(void);

/**
 * Run eviction on ALL caches (remove expired entries)
 *
 * Calls expire/cleanup functions on:
 * - Keyserver cache
 * - Profile cache
 * - Contacts database (no-op, permanent data)
 *
 * @return Number of entries evicted, -1 on error
 */
int cache_manager_evict_expired(void);

/**
 * Get aggregated statistics across all caches
 *
 * @param stats_out Output statistics structure
 * @return 0 on success, -1 on error
 */
int cache_manager_stats(cache_manager_stats_t *stats_out);

/**
 * Clear ALL caches (for testing, logout, etc.)
 *
 * Warning: This deletes all cached data!
 * Use only for testing or explicit user request.
 */
void cache_manager_clear_all(void);

#ifdef __cplusplus
}
#endif

#endif // CACHE_MANAGER_H
