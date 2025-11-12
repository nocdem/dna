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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static dht_context_t *g_dht_ctx = NULL;
static bool g_initialized = false;

/**
 * Initialize profile manager
 */
int profile_manager_init(dht_context_t *dht_ctx, const char *owner_identity) {
    if (!dht_ctx || !owner_identity) {
        fprintf(stderr, "[PROFILE_MGR] Invalid parameters\n");
        return -1;
    }

    // Initialize cache
    if (profile_cache_init(owner_identity) != 0) {
        fprintf(stderr, "[PROFILE_MGR] Failed to initialize cache\n");
        return -1;
    }

    g_dht_ctx = dht_ctx;
    g_initialized = true;

    printf("[PROFILE_MGR] Initialized for %s\n", owner_identity);
    return 0;
}

/**
 * Get user profile (smart fetch)
 */
int profile_manager_get_profile(const char *user_fingerprint, dht_profile_t *profile_out) {
    if (!g_initialized || !g_dht_ctx) {
        fprintf(stderr, "[PROFILE_MGR] Not initialized\n");
        return -1;
    }

    if (!user_fingerprint || !profile_out) {
        fprintf(stderr, "[PROFILE_MGR] Invalid parameters\n");
        return -1;
    }

    // Step 1: Check cache
    uint64_t fetched_at = 0;
    int result = profile_cache_get(user_fingerprint, profile_out, &fetched_at);

    if (result == 0) {
        // Found in cache - check if fresh
        if (!profile_cache_is_expired(user_fingerprint)) {
            // Cache hit (fresh)
            printf("[PROFILE_MGR] Cache hit (fresh): %s\n", user_fingerprint);
            return 0;
        } else {
            // Cache hit but expired
            printf("[PROFILE_MGR] Cache hit (expired): %s, refreshing from DHT\n", user_fingerprint);
        }
    } else {
        // Not in cache
        printf("[PROFILE_MGR] Cache miss: %s, fetching from DHT\n", user_fingerprint);
    }

    // Step 2: Fetch from DHT
    result = dht_profile_fetch(g_dht_ctx, user_fingerprint, profile_out);

    if (result == -2) {
        // Not found in DHT
        printf("[PROFILE_MGR] Profile not found in DHT: %s\n", user_fingerprint);
        return -2;
    }

    if (result != 0) {
        // DHT error
        fprintf(stderr, "[PROFILE_MGR] DHT fetch failed: %s\n", user_fingerprint);

        // If we had cached (expired) data, return it as fallback
        if (fetched_at > 0) {
            printf("[PROFILE_MGR] Returning stale cached profile as fallback\n");
            profile_cache_get(user_fingerprint, profile_out, NULL);
            return 0;
        }

        return -1;
    }

    // Step 3: Update cache with fresh data
    printf("[PROFILE_MGR] Fetched from DHT, updating cache: %s\n", user_fingerprint);
    profile_cache_add_or_update(user_fingerprint, profile_out);

    return 0;
}

/**
 * Refresh profile from DHT (force)
 */
int profile_manager_refresh_profile(const char *user_fingerprint, dht_profile_t *profile_out) {
    if (!g_initialized || !g_dht_ctx) {
        fprintf(stderr, "[PROFILE_MGR] Not initialized\n");
        return -1;
    }

    if (!user_fingerprint) {
        fprintf(stderr, "[PROFILE_MGR] Invalid fingerprint\n");
        return -1;
    }

    printf("[PROFILE_MGR] Force refresh from DHT: %s\n", user_fingerprint);

    // Fetch from DHT
    dht_profile_t profile;
    int result = dht_profile_fetch(g_dht_ctx, user_fingerprint, &profile);

    if (result == -2) {
        printf("[PROFILE_MGR] Profile not found in DHT: %s\n", user_fingerprint);
        return -2;
    }

    if (result != 0) {
        fprintf(stderr, "[PROFILE_MGR] DHT fetch failed: %s\n", user_fingerprint);
        return -1;
    }

    // Update cache
    profile_cache_add_or_update(user_fingerprint, &profile);

    // Copy to output if requested
    if (profile_out) {
        memcpy(profile_out, &profile, sizeof(dht_profile_t));
    }

    printf("[PROFILE_MGR] Refreshed profile: %s\n", user_fingerprint);
    return 0;
}

/**
 * Refresh all expired profiles (background task)
 */
int profile_manager_refresh_all_expired(void) {
    if (!g_initialized || !g_dht_ctx) {
        fprintf(stderr, "[PROFILE_MGR] Not initialized\n");
        return -1;
    }

    // Get list of expired profiles
    char **fingerprints = NULL;
    size_t count = 0;

    if (profile_cache_list_expired(&fingerprints, &count) != 0) {
        fprintf(stderr, "[PROFILE_MGR] Failed to list expired profiles\n");
        return -1;
    }

    if (count == 0) {
        printf("[PROFILE_MGR] No expired profiles to refresh\n");
        return 0;
    }

    printf("[PROFILE_MGR] Refreshing %zu expired profiles\n", count);

    // Refresh each expired profile
    int success_count = 0;
    for (size_t i = 0; i < count; i++) {
        dht_profile_t profile;
        int result = dht_profile_fetch(g_dht_ctx, fingerprints[i], &profile);

        if (result == 0) {
            // Update cache
            profile_cache_add_or_update(fingerprints[i], &profile);
            success_count++;
        } else if (result == -2) {
            // Not found in DHT - delete from cache
            printf("[PROFILE_MGR] Profile no longer in DHT, removing from cache: %s\n",
                   fingerprints[i]);
            profile_cache_delete(fingerprints[i]);
        } else {
            // DHT error - keep stale cache
            fprintf(stderr, "[PROFILE_MGR] Failed to refresh: %s\n", fingerprints[i]);
        }

        free(fingerprints[i]);
    }

    free(fingerprints);

    printf("[PROFILE_MGR] Refreshed %d of %zu expired profiles\n", success_count, count);
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
        fprintf(stderr, "[PROFILE_MGR] Not initialized\n");
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
        printf("[PROFILE_MGR] Closed\n");
    }
}
