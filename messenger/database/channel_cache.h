/**
 * Channel Cache Database
 * GLOBAL SQLite cache for channel metadata and posts (shared across all identities)
 *
 * Architecture:
 * - Global database: ~/.dna/channel_cache.db
 * - 5-minute TTL: Staleness check for re-fetching from DHT
 * - 30-day eviction: Old entries removed on evict
 * - Shared across identities (channel data is public DHT data)
 *
 * @file channel_cache.h
 * @author DNA Messenger Team
 * @date 2026-02-26
 */

#ifndef CHANNEL_CACHE_H
#define CHANNEL_CACHE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cache staleness: 60 seconds (listeners handle real-time delivery) */
#define CHANNEL_CACHE_TTL_SECONDS 60

/* Cache eviction: 30 days */
#define CHANNEL_CACHE_EVICT_SECONDS (30 * 24 * 60 * 60)

/* ---- Lifecycle --------------------------------------------------------- */

/**
 * Initialize channel cache database
 * Creates database file at <data_dir>/channel_cache.db if it doesn't exist
 * Idempotent - safe to call multiple times
 *
 * @return 0 on success, -1 on error
 */
int channel_cache_init(void);

/**
 * Close channel cache database
 * Call on shutdown
 */
void channel_cache_close(void);

/* ---- Channel metadata cache -------------------------------------------- */

/**
 * Store or update a channel JSON blob in the cache
 *
 * @param uuid         Channel UUID (primary key)
 * @param channel_json Serialized channel JSON
 * @param created_at   Original creation timestamp (Unix)
 * @param deleted      1 if soft-deleted, 0 otherwise
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int channel_cache_put_channel_json(const char *uuid, const char *channel_json,
                                    uint64_t created_at, int deleted);

/**
 * Get a single channel JSON by UUID
 *
 * @param uuid             Channel UUID
 * @param channel_json_out Output: heap-allocated JSON string (caller must free)
 * @return 0 on success, -1 on error, -2 if not found, -3 if uninitialized
 */
int channel_cache_get_channel_json(const char *uuid, char **channel_json_out);

/* ---- Channel posts cache ----------------------------------------------- */

/**
 * Store or update cached posts for a channel
 *
 * @param channel_uuid Channel UUID
 * @param posts_json   Serialized posts JSON array
 * @param post_count   Number of posts in the JSON
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int channel_cache_put_posts(const char *channel_uuid, const char *posts_json,
                             int post_count);

/**
 * Get cached posts for a channel
 *
 * @param channel_uuid  Channel UUID
 * @param posts_json_out Output: heap-allocated JSON string (caller must free)
 * @param post_count_out Output: number of posts (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found, -3 if uninitialized
 */
int channel_cache_get_posts(const char *channel_uuid, char **posts_json_out,
                             int *post_count_out);

/* ---- Staleness tracking ------------------------------------------------ */

/**
 * Check if a cache key is stale (older than CHANNEL_CACHE_TTL_SECONDS)
 *
 * @param cache_key Key to check
 * @return true if stale or not found, false if still fresh
 */
bool channel_cache_is_stale(const char *cache_key);

/**
 * Update the last-fetched timestamp for a cache key
 * Sets last_fetched to current time
 *
 * @param cache_key Arbitrary key (e.g. "channel:<uuid>", "posts:<uuid>")
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int channel_cache_mark_fresh(const char *cache_key);

/**
 * Invalidate a cache key (force next access to be stale)
 * Deletes the cache_meta entry so is_stale() returns true
 *
 * @param cache_key Key to invalidate
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int channel_cache_invalidate(const char *cache_key);

/* ---- Eviction ---------------------------------------------------------- */

/**
 * Evict entries older than CHANNEL_CACHE_EVICT_SECONDS
 *
 * @return number of rows deleted, or -1 on error
 */
int channel_cache_evict_old(void);

#ifdef __cplusplus
}
#endif
#endif /* CHANNEL_CACHE_H */
