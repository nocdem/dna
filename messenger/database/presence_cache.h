/**
 * Local Presence Cache - Fast contact status without DHT queries
 *
 * Strategy: Passive presence detection + TTL-based caching
 * - Message received → Sender online
 * - P2P connection → Peer online
 * - P2P disconnection → Peer offline
 * - Fires events on status transitions
 *
 * Online status stored explicitly from server response (not derived from timestamp)
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
    time_t last_seen;         // Last time we saw them (real server timestamp)
    bool is_online;           // Online status from server (not derived from timestamp)
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
 * - Message received from contact → is_online=true
 * - P2P connection established → is_online=true
 * - P2P connection lost → is_online=false
 *
 * Automatically fires DNA_EVENT_CONTACT_ONLINE or DNA_EVENT_CONTACT_OFFLINE
 * when status transitions between online/offline.
 *
 * @param fingerprint Contact fingerprint (128 hex chars)
 * @param is_online Online status (true=seen now, false=went offline)
 * @param timestamp Current time (or message timestamp)
 */
void presence_cache_update(const char *fingerprint, bool is_online, time_t timestamp);

/**
 * Get cached presence status
 *
 * Returns the is_online flag set by the server (fast O(1) lookup)
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
