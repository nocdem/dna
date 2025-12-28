/**
 * Profile Manager
 * Smart profile fetching layer (cache + DHT)
 *
 * Architecture:
 * - GLOBAL cache (shared across identities, profiles are public)
 * - Tries local cache first (instant)
 * - Falls back to DHT if not cached or expired (>7 days)
 * - Automatically updates cache after DHT fetch
 * - Can be initialized before identity is loaded (for prefetching)
 *
 * Usage:
 * 1. Initialize: profile_manager_init(dht_ctx) - at engine startup
 * 2. Get profile: profile_manager_get_profile(fingerprint, &profile)
 *    - Returns cached if fresh
 *    - Fetches from DHT if expired/missing
 * 3. Manual refresh: profile_manager_refresh_profile(fingerprint)
 * 4. Startup: profile_manager_refresh_all_expired() (async)
 *
 * @file profile_manager.h
 * @author DNA Messenger Team
 * @date 2025-11-12
 * @updated 2025-12-28 (Global cache for prefetching)
 */

#ifndef PROFILE_MANAGER_H
#define PROFILE_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dht/client/dna_profile.h"
#include "dht/core/dht_context.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize profile manager (global, no identity required)
 * Opens global cache database and stores DHT context
 *
 * @param dht_ctx DHT context (must remain valid)
 * @return 0 on success, -1 on error
 */
int profile_manager_init(dht_context_t *dht_ctx);

/**
 * Get user profile (smart fetch: cache first, then DHT)
 * Phase 5: Returns unified identity
 *
 * Flow:
 * 1. Check local cache
 * 2. If found and fresh (<7 days old) → return from cache
 * 3. If expired or not found → fetch from DHT
 * 4. Update cache with DHT result
 * 5. Return identity
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param identity_out Output identity (allocated, caller must free with dna_identity_free())
 * @return 0 on success, -1 on error, -2 if not found
 */
int profile_manager_get_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out);

/**
 * Refresh profile from DHT (force update, ignores cache)
 * Phase 5: Returns unified identity
 * Use for manual "Refresh Profile" button
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @param identity_out Output identity (allocated, caller must free, can be NULL)
 * @return 0 on success, -1 on error, -2 if not found in DHT
 */
int profile_manager_refresh_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out);

/**
 * Refresh all expired profiles from DHT (background task)
 * Call on app startup to update stale profiles
 * Non-blocking: returns immediately, profiles updated asynchronously
 *
 * @return Number of profiles queued for refresh, or -1 on error
 */
int profile_manager_refresh_all_expired(void);

/**
 * Check if profile is cached and fresh
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @return true if cached and <7 days old, false otherwise
 */
bool profile_manager_is_cached_and_fresh(const char *user_fingerprint);

/**
 * Delete profile from cache (forces refresh on next get)
 *
 * @param user_fingerprint Fingerprint of profile owner
 * @return 0 on success, -1 on error
 */
int profile_manager_delete_cached(const char *user_fingerprint);

/**
 * Get cache statistics
 *
 * @param total_out Total cached profiles (can be NULL)
 * @param expired_out Expired profiles (can be NULL)
 * @return 0 on success, -1 on error
 */
int profile_manager_get_stats(int *total_out, int *expired_out);

/**
 * Prefetch profiles for local identities from DHT
 * Called when DHT connects to populate cache for identity selection screen
 *
 * @param data_dir Path to data directory (e.g., ~/.dna)
 * @return Number of profiles prefetched, or -1 on error
 */
int profile_manager_prefetch_local_identities(const char *data_dir);

/**
 * Close profile manager
 * Call on shutdown
 */
void profile_manager_close(void);

#ifdef __cplusplus
}
#endif

#endif // PROFILE_MANAGER_H
