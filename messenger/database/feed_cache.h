/**
 * Feed Cache Database
 * GLOBAL SQLite cache for feed topics and comments (shared across all identities)
 *
 * Architecture:
 * - Global database: ~/.dna/db/feed_cache.db
 * - 5-minute TTL: Staleness check for re-fetching from DHT
 * - 30-day eviction: Old entries removed on evict
 * - Shared across identities (feed data is public DHT data)
 *
 * @file feed_cache.h
 * @author DNA Messenger Team
 * @date 2026-02-22
 */

#ifndef DNA_FEED_CACHE_H
#define DNA_FEED_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Feed cache staleness TTL (5 minutes in seconds)
 * Used to decide when to re-fetch from DHT
 */
#define FEED_CACHE_TTL_SECONDS 300

/**
 * Feed cache eviction age (30 days in seconds)
 * Entries older than this are removed on evict
 */
#define FEED_CACHE_EVICT_SECONDS 2592000

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/**
 * Initialize feed cache database
 * Creates database file at <data_dir>/db/feed_cache.db if it doesn't exist
 *
 * @return 0 on success, -1 on error
 */
int feed_cache_init(void);

/**
 * Close feed cache database
 * Call on shutdown
 */
void feed_cache_close(void);

/**
 * Evict entries older than FEED_CACHE_EVICT_SECONDS
 *
 * @return number of rows deleted, or -1 on error
 */
int feed_cache_evict(void);

/* ── Topic operations ──────────────────────────────────────────────── */

/**
 * Store or update a topic JSON blob in the cache
 *
 * @param uuid        Topic UUID (primary key)
 * @param topic_json  Serialized topic JSON
 * @param category_id Category identifier
 * @param created_at  Original creation timestamp (Unix)
 * @param deleted     1 if soft-deleted, 0 otherwise
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_put_topic_json(const char *uuid, const char *topic_json,
                              const char *category_id, uint64_t created_at,
                              int deleted);

/**
 * Get a single topic JSON by UUID
 *
 * @param uuid           Topic UUID
 * @param topic_json_out Output: heap-allocated JSON string (caller must free)
 * @return 0 on success, -1 on error, -2 if not found, -3 if uninitialized
 */
int feed_cache_get_topic_json(const char *uuid, char **topic_json_out);

/**
 * Delete a topic from the cache
 *
 * @param uuid Topic UUID
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_delete_topic(const char *uuid);

/**
 * Get all non-deleted topics within a date window
 *
 * @param days_back       How many days back to include (0 = all)
 * @param topic_jsons_out Output: heap-allocated array of strdup'd JSON strings
 * @param count           Output: number of entries
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_get_topics_all(int days_back, char ***topic_jsons_out,
                              size_t *count);

/**
 * Get topics filtered by category within a date window
 *
 * @param category_id     Category to filter by
 * @param days_back       How many days back to include (0 = all)
 * @param topic_jsons_out Output: heap-allocated array of strdup'd JSON strings
 * @param count           Output: number of entries
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_get_topics_by_category(const char *category_id, int days_back,
                                      char ***topic_jsons_out, size_t *count);

/**
 * Free an array of JSON strings returned by get_topics_*
 *
 * @param jsons Array of strings
 * @param count Number of entries
 */
void feed_cache_free_json_list(char **jsons, size_t count);

/* ── Comment operations ────────────────────────────────────────────── */

/**
 * Store or update cached comments for a topic
 *
 * @param topic_uuid    Topic UUID
 * @param comments_json Serialized comments JSON array
 * @param comment_count Number of comments in the JSON
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_put_comments(const char *topic_uuid, const char *comments_json,
                            int comment_count);

/**
 * Get cached comments for a topic
 *
 * @param topic_uuid        Topic UUID
 * @param comments_json_out Output: heap-allocated JSON string (caller must free)
 * @param comment_count_out Output: number of comments (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found, -3 if uninitialized
 */
int feed_cache_get_comments(const char *topic_uuid, char **comments_json_out,
                            int *comment_count_out);

/**
 * Invalidate (delete) cached comments for a topic
 *
 * @param topic_uuid Topic UUID
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_invalidate_comments(const char *topic_uuid);

/* ── Meta / staleness ──────────────────────────────────────────────── */

/**
 * Update the last-fetched timestamp for a cache key
 * Sets last_fetched to current time
 *
 * @param cache_key Arbitrary key (e.g. "topics:all", "comments:<uuid>")
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_update_meta(const char *cache_key);

/**
 * Check if a cache key is stale (older than FEED_CACHE_TTL_SECONDS)
 *
 * @param cache_key Key to check
 * @return true if stale or not found, false if still fresh
 */
bool feed_cache_is_stale(const char *cache_key);

/**
 * Get cache statistics
 *
 * @param total_topics   Output: total topic rows (can be NULL)
 * @param total_comments Output: total comment rows (can be NULL)
 * @param expired        Output: topic rows older than evict threshold (can be NULL)
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int feed_cache_stats(int *total_topics, int *total_comments, int *expired);

#ifdef __cplusplus
}
#endif

#endif // DNA_FEED_CACHE_H
