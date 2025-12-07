/**
 * Profile Manager Implementation
 * Smart profile fetching layer (cache + DHT)
 *
 * @file profile_manager.c
 * @author DNA Messenger Team
 * @date 2025-11-12
 */

#include "profile_manager.h"
#include "profile_cache.h"
#include "dht/core/dht_keyserver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DB_PROFILE"

static dht_context_t *g_dht_ctx = NULL;
static bool g_initialized = false;

/**
 * Initialize profile manager
 */
int profile_manager_init(dht_context_t *dht_ctx, const char *owner_identity) {
    if (!dht_ctx || !owner_identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Initialize cache
    if (profile_cache_init(owner_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize cache\n");
        return -1;
    }

    g_dht_ctx = dht_ctx;
    g_initialized = true;

    QGP_LOG_INFO(LOG_TAG, "Initialized for %s\n", owner_identity);
    return 0;
}

/**
 * Get user profile (smart fetch) - Phase 5: Unified Identity
 */
int profile_manager_get_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out) {
    if (!g_initialized || !g_dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    if (!user_fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Step 1: Check cache
    uint64_t cached_at = 0;
    dna_unified_identity_t *cached_identity = NULL;
    int result = profile_cache_get(user_fingerprint, &cached_identity, &cached_at);

    if (result == 0) {
        // Found in cache - check if fresh
        if (!profile_cache_is_expired(user_fingerprint)) {
            // Cache hit (fresh)
            QGP_LOG_INFO(LOG_TAG, "Cache hit (fresh): %s\n", user_fingerprint);
            *identity_out = cached_identity;
            return 0;
        } else {
            // Cache hit but expired - keep for fallback
            QGP_LOG_INFO(LOG_TAG, "Cache hit (expired): %s, refreshing from DHT\n", user_fingerprint);
        }
    } else {
        // Not in cache
        QGP_LOG_INFO(LOG_TAG, "Cache miss: %s, fetching from DHT\n", user_fingerprint);
    }

    // Step 2: Fetch from DHT (using keyserver)
    dna_unified_identity_t *fresh_identity = NULL;
    result = dna_load_identity(g_dht_ctx, user_fingerprint, &fresh_identity);

    if (result == -2) {
        // Not found in DHT
        QGP_LOG_INFO(LOG_TAG, "Identity not found in DHT: %s\n", user_fingerprint);

        // Return cached if available (better than nothing)
        if (cached_identity) {
            QGP_LOG_INFO(LOG_TAG, "Returning stale cached identity as fallback\n");
            *identity_out = cached_identity;
            return 0;
        }

        return -2;
    }

    if (result != 0) {
        // DHT error
        QGP_LOG_ERROR(LOG_TAG, "DHT fetch failed: %s\n", user_fingerprint);

        // Return cached if available (stale fallback)
        if (cached_identity) {
            QGP_LOG_INFO(LOG_TAG, "Returning stale cached identity as fallback\n");
            *identity_out = cached_identity;
            return 0;
        }

        return -1;
    }

    // Step 3: Update cache with fresh data
    QGP_LOG_INFO(LOG_TAG, "Fetched from DHT, updating cache: %s\n", user_fingerprint);
    profile_cache_add_or_update(user_fingerprint, fresh_identity);

    // Free old cached copy if we had one
    if (cached_identity) {
        dna_identity_free(cached_identity);
    }

    *identity_out = fresh_identity;
    return 0;
}

/**
 * Refresh profile from DHT (force) - Phase 5: Unified Identity
 */
int profile_manager_refresh_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out) {
    if (!g_initialized || !g_dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    if (!user_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Force refresh from DHT: %s\n", user_fingerprint);

    // Fetch from DHT (using keyserver)
    dna_unified_identity_t *identity = NULL;
    int result = dna_load_identity(g_dht_ctx, user_fingerprint, &identity);

    if (result == -2) {
        QGP_LOG_INFO(LOG_TAG, "Identity not found in DHT: %s\n", user_fingerprint);
        return -2;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT fetch failed: %s\n", user_fingerprint);
        return -1;
    }

    // Update cache
    profile_cache_add_or_update(user_fingerprint, identity);

    // Return to caller if requested
    if (identity_out) {
        *identity_out = identity;
    } else {
        // Caller doesn't want it, free it
        dna_identity_free(identity);
    }

    QGP_LOG_INFO(LOG_TAG, "Refreshed identity: %s\n", user_fingerprint);
    return 0;
}

/**
 * Refresh all expired profiles (background task)
 */
int profile_manager_refresh_all_expired(void) {
    if (!g_initialized || !g_dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    // Get list of expired profiles
    char **fingerprints = NULL;
    size_t count = 0;

    if (profile_cache_list_expired(&fingerprints, &count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to list expired profiles\n");
        return -1;
    }

    if (count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No expired profiles to refresh\n");
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Refreshing %zu expired profiles\n", count);

    // Refresh each expired profile (Phase 5: Unified Identity)
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        dna_unified_identity_t *identity = NULL;
        int result = dna_load_identity(g_dht_ctx, fingerprints[i], &identity);

        if (result == 0 && identity) {
            // Update cache
            profile_cache_add_or_update(fingerprints[i], identity);
            dna_identity_free(identity);
            success_count++;
        } else if (result == -2) {
            // Not found in DHT - delete from cache
            QGP_LOG_INFO(LOG_TAG, "Identity no longer in DHT, removing from cache: %s\n",
                   fingerprints[i]);
            profile_cache_delete(fingerprints[i]);
        } else {
            // DHT error - keep stale cache
            QGP_LOG_ERROR(LOG_TAG, "Failed to refresh: %s\n", fingerprints[i]);
        }

        free(fingerprints[i]);
    }

    free(fingerprints);

    QGP_LOG_INFO(LOG_TAG, "Refreshed %d of %zu expired profiles\n", success_count, count);
    return success_count;
}

/**
 * Check if profile is cached and fresh
 */
bool profile_manager_is_cached_and_fresh(const char *user_fingerprint) {
    if (!g_initialized || !user_fingerprint) {
        return false;
    }

    if (!profile_cache_exists(user_fingerprint)) {
        return false;
    }

    return !profile_cache_is_expired(user_fingerprint);
}

/**
 * Delete cached profile
 */
int profile_manager_delete_cached(const char *user_fingerprint) {
    if (!g_initialized) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    return profile_cache_delete(user_fingerprint);
}

/**
 * Get cache statistics
 */
int profile_manager_get_stats(int *total_out, int *expired_out) {
    if (!g_initialized) {
        return -1;
    }

    // Get total
    int total = profile_cache_count();
    if (total < 0) {
        return -1;
    }

    if (total_out) {
        *total_out = total;
    }

    // Get expired count
    if (expired_out) {
        char **fingerprints = NULL;
        size_t count = 0;

        if (profile_cache_list_expired(&fingerprints, &count) == 0) {
            *expired_out = (int)count;

            // Free fingerprints
            for (size_t i = 0; i < count; i++) {
                free(fingerprints[i]);
            }
            free(fingerprints);
        } else {
            *expired_out = 0;
        }
    }

    return 0;
}

/**
 * Close profile manager
 */
void profile_manager_close(void) {
    if (g_initialized) {
        profile_cache_close();
        g_dht_ctx = NULL;
        g_initialized = false;
        QGP_LOG_INFO(LOG_TAG, "Closed\n");
    }
}
