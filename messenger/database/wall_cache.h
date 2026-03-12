/**
 * Wall Cache Database
 * GLOBAL SQLite cache for wall posts (shared across all identities)
 *
 * Architecture:
 * - Global database: ~/.dna/wall_cache.db
 * - 5-minute TTL: Staleness check for re-fetching from DHT
 * - 30-day eviction: Old entries removed on evict
 * - Shared across identities (wall data is public DHT data)
 *
 * @file wall_cache.h
 * @author DNA Connect Team
 * @date 2026-02-25
 */

#ifndef WALL_CACHE_H
#define WALL_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dht/client/dna_wall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WALL_CACHE_TTL_SECONDS   300       /* 5 minutes staleness check */
#define WALL_CACHE_EVICT_SECONDS 2592000   /* 30 days eviction */

/* ── Lifecycle ─────────────────────────────────────────────────────── */

/**
 * Initialize wall cache database
 * Creates database file at <data_dir>/wall_cache.db if it doesn't exist
 *
 * @return 0 on success, -1 on error
 */
int wall_cache_init(void);

/**
 * Close wall cache database
 * Call on shutdown
 */
void wall_cache_close(void);

/**
 * Evict entries older than WALL_CACHE_EVICT_SECONDS
 *
 * @return number of rows deleted, or -1 on error
 */
int wall_cache_evict_expired(void);

/* ── Post operations ──────────────────────────────────────────────── */

/**
 * Store wall posts in local cache (replaces all posts for this author)
 *
 * @param fingerprint  Author's SHA3-512 fingerprint (128 hex chars)
 * @param posts        Array of wall posts
 * @param count        Number of posts in the array
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_store(const char *fingerprint,
                     const dna_wall_post_t *posts, size_t count);

/**
 * Load wall posts from local cache for one user
 *
 * @param fingerprint  Author's SHA3-512 fingerprint
 * @param posts        Output: heap-allocated array (caller must free with wall_cache_free_posts)
 * @param count        Output: number of posts
 * @return 0 on success, -1 on error, -2 if not found, -3 if uninitialized
 */
int wall_cache_load(const char *fingerprint,
                    dna_wall_post_t **posts, size_t *count);

/**
 * Load timeline (all contacts' posts merged, sorted by timestamp DESC)
 *
 * @param fingerprints  Array of fingerprint strings
 * @param fp_count      Number of fingerprints
 * @param posts         Output: heap-allocated array (caller must free with wall_cache_free_posts)
 * @param count         Output: number of posts
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_load_timeline(const char **fingerprints, size_t fp_count,
                             dna_wall_post_t **posts, size_t *count);

/**
 * Delete posts by a specific author from cache
 *
 * @param fingerprint  Author's SHA3-512 fingerprint
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_delete_by_author(const char *fingerprint);

/**
 * Delete a specific post from cache
 *
 * @param post_uuid  UUID of the post to delete
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_delete_post(const char *post_uuid);

/**
 * Insert or replace a single wall post in cache
 * Uses INSERT OR REPLACE on uuid (PRIMARY KEY)
 *
 * @param post  Wall post to insert
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_insert_post(const dna_wall_post_t *post);

/**
 * Delete staleness metadata for a fingerprint
 * Forces next timeline load to re-fetch this user's wall from DHT
 *
 * @param fingerprint  Cache key to delete from wall_cache_meta
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_delete_meta(const char *fingerprint);

/* ── Meta / staleness ──────────────────────────────────────────────── */

/**
 * Check if cache is stale for a fingerprint (older than WALL_CACHE_TTL_SECONDS)
 *
 * @param fingerprint  Cache key to check
 * @return true if stale or not found, false if still fresh
 */
bool wall_cache_is_stale(const char *fingerprint);

/**
 * Update staleness timestamp for a fingerprint
 * Sets last_fetched to current time
 *
 * @param fingerprint  Cache key to update
 * @return 0 on success, -1 on error, -3 if uninitialized
 */
int wall_cache_update_meta(const char *fingerprint);

/**
 * Free posts array from cache
 *
 * @param posts  Array of posts to free
 * @param count  Number of posts
 */
void wall_cache_free_posts(dna_wall_post_t *posts, size_t count);

/* ── Comment cache (v0.7.0+) ─────────────────────────────────────── */

/**
 * Store comments JSON blob for a wall post
 *
 * @param post_uuid      Post UUID
 * @param comments_json  JSON array of comment info structs
 * @param count          Number of comments
 * @return 0 on success, -1 on error
 */
int wall_cache_store_comments(const char *post_uuid, const char *comments_json, int count);

/**
 * Load cached comments for a wall post
 *
 * @param post_uuid       Post UUID
 * @param json_out        Output: heap-allocated JSON string (caller frees)
 * @param count_out       Output: number of comments
 * @return 0 on success, -1 on error, -2 if not found
 */
int wall_cache_load_comments(const char *post_uuid, char **json_out, int *count_out);

/**
 * Invalidate cached comments for a wall post
 *
 * @param post_uuid  Post UUID
 * @return 0 on success, -1 on error
 */
int wall_cache_invalidate_comments(const char *post_uuid);

/**
 * Check if comment cache is stale for a post (older than 5 minutes)
 *
 * @param post_uuid  Post UUID to check
 * @return true if stale or not found, false if still fresh
 */
bool wall_cache_is_stale_comments(const char *post_uuid);

/* ── Likes cache (v0.9.53+) ──────────────────────────────────────── */

/**
 * Store likes JSON blob for a wall post
 *
 * @param post_uuid   Post UUID
 * @param likes_json  JSON array of like info structs
 * @param count       Number of likes
 * @return 0 on success, -1 on error
 */
int wall_cache_store_likes(const char *post_uuid, const char *likes_json, int count);

/**
 * Load cached likes for a wall post
 *
 * @param post_uuid  Post UUID
 * @param json_out   Output: heap-allocated JSON string (caller frees)
 * @param count_out  Output: number of likes
 * @return 0 on success, -1 on error, -2 if not found
 */
int wall_cache_load_likes(const char *post_uuid, char **json_out, int *count_out);

/**
 * Invalidate cached likes for a wall post
 *
 * @param post_uuid  Post UUID
 * @return 0 on success, -1 on error
 */
int wall_cache_invalidate_likes(const char *post_uuid);

/**
 * Check if likes cache is stale for a post (older than 5 minutes)
 *
 * @param post_uuid  Post UUID to check
 * @return true if stale or not found, false if still fresh
 */
bool wall_cache_is_stale_likes(const char *post_uuid);

#ifdef __cplusplus
}
#endif

#endif /* WALL_CACHE_H */
