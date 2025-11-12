/**
 * Profile Cache Database
 * Local SQLite cache for user profiles (per-identity)
 *
 * Architecture:
 * - Per-identity database: ~/.dna/<owner_identity>_profiles.db
 * - 7-day TTL: Profiles expire after 7 days, auto-refresh from DHT
 * - Cache all fetched profiles (not just contacts)
 * - Reduces DHT queries while keeping profiles reasonably fresh
 *
 * Database Schema:
 * CREATE TABLE profiles (
 *     user_fingerprint TEXT PRIMARY KEY,
 *     display_name TEXT NOT NULL,
 *     bio TEXT,
 *     avatar_hash TEXT,
 *     location TEXT,
 *     website TEXT,
 *     created_at INTEGER,
 *     updated_at INTEGER,
 *     fetched_at INTEGER  -- Unix timestamp for TTL check
 * );
 *
 * @file profile_cache.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#ifndef PROFILE_CACHE_H
#define PROFILE_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dht/dht_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Profile cache TTL (7 days in seconds)
 */
#define PROFILE_CACHE_TTL_SECONDS (7 * 24 * 3600)

/**
 * Cached profile entry (includes fetch timestamp)
 */
typedef struct {
    char user_fingerprint[256];     // User fingerprint (128-char hex)
    dht_profile_t profile;          // Profile data
    uint64_t fetched_at;            // When profile was fetched (Unix timestamp)
} profile_cache_entry_t;

/**
 * Profile cache list
 */
typedef struct {
    profile_cache_entry_t *entries;
    size_t count;
} profile_cache_list_t;

/**
 * Initialize profile cache for a specific identity
 * Creates database file at ~/.dna/<owner_identity>_profiles.db if it doesn't exist
 *
 * @param owner_identity Identity who owns this cache (e.g., "alice_fingerprint")
 * @return 0 on success, -1 on error
 */
int profile_cache_init(const char *owner_identity);

/**
 * Add or update profile in cache
 * Sets fetched_at to current time
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param profile Profile data
 * @return 0 on success, -1 on error
 */
int profile_cache_add_or_update(const char *user_fingerprint, const dht_profile_t *profile);

/**
 * Get profile from cache
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param profile_out Output profile data (caller provides buffer)
 * @param fetched_at_out Output fetch timestamp (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found
 */
int profile_cache_get(const char *user_fingerprint, dht_profile_t *profile_out, uint64_t *fetched_at_out);

/**
 * Check if profile exists in cache
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @return true if exists, false otherwise
 */
bool profile_cache_exists(const char *user_fingerprint);

/**
 * Check if cached profile is expired (>7 days old)
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @return true if expired or not found, false if still fresh
 */
bool profile_cache_is_expired(const char *user_fingerprint);

/**
 * Delete profile from cache
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @return 0 on success, -1 on error
 */
int profile_cache_delete(const char *user_fingerprint);

/**
 * Get list of all expired profiles (>7 days old)
 *
 * @param fingerprints_out Output array of fingerprints (caller must free with free())
 * @param count_out Number of expired profiles
 * @return 0 on success, -1 on error
 */
int profile_cache_list_expired(char ***fingerprints_out, size_t *count_out);

/**
 * Get all cached profiles
 *
 * @param list_out Output profile list (caller must free with profile_cache_free_list)
 * @return 0 on success, -1 on error
 */
int profile_cache_list_all(profile_cache_list_t **list_out);

/**
 * Get profile count
 *
 * @return Number of cached profiles, or -1 on error
 */
int profile_cache_count(void);

/**
 * Clear all cached profiles
 * Used for debugging/testing
 *
 * @return 0 on success, -1 on error
 */
int profile_cache_clear_all(void);

/**
 * Free profile list
 *
 * @param list Profile list to free
 */
void profile_cache_free_list(profile_cache_list_t *list);

/**
 * Close profile cache database
 * Call on shutdown
 */
void profile_cache_close(void);

#ifdef __cplusplus
}
#endif

#endif // PROFILE_CACHE_H
