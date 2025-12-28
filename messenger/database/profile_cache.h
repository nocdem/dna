/**
 * Profile Cache Database
 * GLOBAL SQLite cache for user profiles (shared across all identities)
 *
 * Architecture:
 * - Global database: ~/.dna/profile_cache.db
 * - 7-day TTL: Profiles expire after 7 days, auto-refresh from DHT
 * - Cache all fetched profiles (not just contacts)
 * - Shared across identities (profiles are public DHT data)
 * - Can be initialized before identity is loaded (for prefetching)
 *
 * Database Schema (Phase 5: Unified Identity):
 * CREATE TABLE profiles (
 *     fingerprint TEXT PRIMARY KEY,
 *     identity_json TEXT NOT NULL,    -- Full dna_unified_identity_t as JSON
 *     cached_at INTEGER NOT NULL       -- Unix timestamp for TTL check
 * );
 *
 * @file profile_cache.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 * @updated 2025-12-28 (Global cache for prefetching)
 */

#ifndef PROFILE_CACHE_H
#define PROFILE_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dht/client/dna_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Profile cache TTL (7 days in seconds)
 */
#define PROFILE_CACHE_TTL_SECONDS (7 * 24 * 3600)

/**
 * Cached profile entry (Phase 5: Unified Identity)
 * Includes full identity data and fetch timestamp
 */
typedef struct {
    char fingerprint[129];                // User fingerprint (128-char hex + null)
    dna_unified_identity_t *identity;     // Full identity data (heap-allocated)
    uint64_t cached_at;                   // When profile was cached (Unix timestamp)
} profile_cache_entry_t;

/**
 * Profile cache list
 */
typedef struct {
    profile_cache_entry_t *entries;
    size_t count;
} profile_cache_list_t;

/**
 * Initialize global profile cache
 * Creates database file at ~/.dna/profile_cache.db if it doesn't exist
 *
 * @return 0 on success, -1 on error
 */
int profile_cache_init(void);

/**
 * Add or update profile in cache (Phase 5: Unified Identity)
 * Sets cached_at to current time
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param identity Full unified identity data
 * @return 0 on success, -1 on error
 */
int profile_cache_add_or_update(const char *user_fingerprint, const dna_unified_identity_t *identity);

/**
 * Get profile from cache (Phase 5: Unified Identity)
 * Returns heap-allocated identity - caller must free with dna_identity_free()
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param identity_out Output identity data (allocated, caller must free)
 * @param cached_at_out Output cache timestamp (can be NULL)
 * @return 0 on success, -1 on error, -2 if not found
 */
int profile_cache_get(const char *user_fingerprint, dna_unified_identity_t **identity_out, uint64_t *cached_at_out);

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
