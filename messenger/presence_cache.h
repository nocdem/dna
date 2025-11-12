/**
 * Local Presence Cache - Fast contact status without DHT queries
 *
 * Strategy: Passive presence detection + TTL-based caching
 * - Message received → Sender online
 * - P2P connection → Peer online
 * - P2P disconnection → Peer offline
 * - No explicit DHT queries (zero overhead)
 *
 * @file presence_cache.h
 */

#ifndef PRESENCE_CACHE_H
#define PRESENCE_CACHE_H

#include <stdbool.h>
#include <time.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Presence cache entry
 */
typedef struct {
    char fingerprint[129];    // 128 hex chars + null
    bool is_online;           // Current online status
    time_t last_seen;         // Last time we saw them (message/connection)
    time_t last_updated;      // When this entry was last updated
} presence_entry_t;

/**
 * Initialize presence cache
 *
 * @return 0 on success, -1 on error
 */
int presence_cache_init(void);

/**
 * Update presence for a contact (passive detection)
 *
 * Called when:
 * - Message received from contact
 * - P2P connection established
 * - P2P connection lost
 *
 * @param fingerprint Contact fingerprint (128 hex chars)
 * @param is_online Online status
 * @param timestamp Current time (or message timestamp)
 */
void presence_cache_update(const char *fingerprint, bool is_online, time_t timestamp);

/**
 * Get cached presence status
 *
 * Strategy:
 * 1. Check cache for entry
 * 2. If not found or too old (>5 min): return false (assume offline)
 * 3. Otherwise: return cached status
 *
 * NO DHT queries (fast!)
 *
 * @param fingerprint Contact fingerprint
 * @return true if online, false if offline/unknown
 */
bool presence_cache_get(const char *fingerprint);

/**
 * Get last seen time for a contact
 *
 * @param fingerprint Contact fingerprint
 * @return Last seen timestamp, or 0 if never seen
 */
time_t presence_cache_last_seen(const char *fingerprint);

/**
 * Clear all presence cache entries
 */
void presence_cache_clear(void);

/**
 * Cleanup presence cache
 */
void presence_cache_free(void);

#ifdef __cplusplus
}
#endif

#endif // PRESENCE_CACHE_H
