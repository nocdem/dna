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
#include "dht/client/dht_singleton.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DB_PROFILE"

static bool g_initialized = false;

/**
 * Initialize profile manager (global, no identity required)
 * DHT context is fetched dynamically via dht_singleton_get() to handle reinit
 */
int profile_manager_init(void) {
    if (g_initialized) {
        return 0;  // Already initialized
    }

    // Initialize global cache
    if (profile_cache_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize cache\n");
        return -1;
    }

    g_initialized = true;
    QGP_LOG_INFO(LOG_TAG, "Initialized (global)\n");
    return 0;
}

/**
 * Get user profile (smart fetch) - Phase 5: Unified Identity
 * Check cache FIRST, then DHT only if needed. Returns cached data when DHT unavailable.
 */
int profile_manager_get_profile(const char *user_fingerprint, dna_unified_identity_t **identity_out) {
    if (!g_initialized) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    if (!user_fingerprint || !identity_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Step 1: Check cache FIRST (before requiring DHT)
    uint64_t cached_at = 0;
    dna_unified_identity_t *cached_identity = NULL;
    int result = profile_cache_get(user_fingerprint, &cached_identity, &cached_at);

    if (result == 0) {
        // Found in cache - check if fresh
        if (!profile_cache_is_expired(user_fingerprint)) {
            // Cache hit (fresh) - log full profile data
            size_t avatar_len = cached_identity->avatar_base64[0] ? strlen(cached_identity->avatar_base64) : 0;
            QGP_LOG_DEBUG(LOG_TAG, "Cache hit (fresh): %.16s...\n", user_fingerprint);
            QGP_LOG_DEBUG(LOG_TAG, "  name='%s' bio='%.50s' location='%s' website='%s'\n",
                        cached_identity->display_name, cached_identity->bio,
                        cached_identity->location, cached_identity->website);
            QGP_LOG_DEBUG(LOG_TAG, "  avatar=%zu bytes, backbone='%s' telegram='%s'\n",
                        avatar_len, cached_identity->wallets.backbone, cached_identity->socials.telegram);
            *identity_out = cached_identity;
            return 0;
        } else {
            // Cache hit but expired - keep for fallback
            QGP_LOG_INFO(LOG_TAG, "Cache hit (expired): %.16s..., will try DHT refresh\n", user_fingerprint);
        }
    } else {
        // Not in cache
        QGP_LOG_DEBUG(LOG_TAG, "Cache miss: %.16s...\n", user_fingerprint);
    }

    // Step 2: Get DHT context for refresh (only needed if cache miss or expired)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        // DHT not available - return cached data if we have it (stale > nothing)
        if (cached_identity) {
            QGP_LOG_INFO(LOG_TAG, "DHT unavailable, returning cached profile: %.16s...\n", user_fingerprint);
            *identity_out = cached_identity;
            return 0;
        }
        QGP_LOG_DEBUG(LOG_TAG, "DHT unavailable and no cache for: %.16s...\n", user_fingerprint);
        return -1;
    }

    // Step 3: Fetch from DHT (using keyserver)
    dna_unified_identity_t *fresh_identity = NULL;
    result = dna_load_identity(dht_ctx, user_fingerprint, &fresh_identity);

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

    if (result == -3) {
        // Signature verification failed - security issue
        QGP_LOG_WARN(LOG_TAG, "Signature verification failed: %s\n", user_fingerprint);
        // Delete from cache since profile is invalid
        profile_cache_delete(user_fingerprint);
        if (cached_identity) {
            dna_identity_free(cached_identity);
        }
        return -3;  // Pass through for security handling
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

    // Step 4: Update cache with fresh data - log full profile
    {
        size_t avatar_len = fresh_identity->avatar_base64[0] ? strlen(fresh_identity->avatar_base64) : 0;
        QGP_LOG_DEBUG(LOG_TAG, "Fetched from DHT: %.16s...\n", user_fingerprint);
        QGP_LOG_DEBUG(LOG_TAG, "  name='%s' bio='%.50s' location='%s' website='%s'\n",
                    fresh_identity->display_name, fresh_identity->bio,
                    fresh_identity->location, fresh_identity->website);
        QGP_LOG_DEBUG(LOG_TAG, "  avatar=%zu bytes, backbone='%s' telegram='%s'\n",
                    avatar_len, fresh_identity->wallets.backbone, fresh_identity->socials.telegram);
    }
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
    if (!g_initialized) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    if (!user_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid fingerprint\n");
        return -1;
    }

    // Get current DHT context (handles reinit)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Force refresh from DHT: %s\n", user_fingerprint);

    // Fetch from DHT (using keyserver)
    dna_unified_identity_t *identity = NULL;
    int result = dna_load_identity(dht_ctx, user_fingerprint, &identity);

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
    if (!g_initialized) {
        QGP_LOG_ERROR(LOG_TAG, "Not initialized\n");
        return -1;
    }

    // Get current DHT context (handles reinit)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not available\n");
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
        int result = dna_load_identity(dht_ctx, fingerprints[i], &identity);

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
 * Prefetch profiles for local identities from DHT
 * Called when DHT connects to populate cache for identity selection screen
 */
int profile_manager_prefetch_local_identities(const char *data_dir) {
    if (!g_initialized) {
        QGP_LOG_DEBUG(LOG_TAG, "Not initialized, skipping prefetch\n");
        return -1;
    }

    // Check DHT is available (handles reinit)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_DEBUG(LOG_TAG, "DHT not available, skipping prefetch\n");
        return -1;
    }

    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid data_dir\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Prefetching local identity profiles from DHT...\n");

    // List .identity files in data directory
    DIR *dir = opendir(data_dir);
    if (!dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open data directory: %s\n", data_dir);
        return -1;
    }

    int prefetch_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Look for files ending in .identity
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 9 && strcmp(name + len - 9, ".identity") == 0) {
            // Extract fingerprint (filename without .identity suffix)
            char fingerprint[256];
            size_t fp_len = len - 9;
            if (fp_len > 128) fp_len = 128;  // Fingerprints are 128 chars
            strncpy(fingerprint, name, fp_len);
            fingerprint[fp_len] = '\0';

            // Prefetch profile (uses cache if available)
            QGP_LOG_DEBUG(LOG_TAG, "Prefetching profile: %.16s...\n", fingerprint);
            dna_unified_identity_t *identity = NULL;
            int result = profile_manager_get_profile(fingerprint, &identity);
            if (result == 0 && identity) {
                QGP_LOG_DEBUG(LOG_TAG, "Prefetched: %.16s... name='%s'\n",
                            fingerprint, identity->display_name);
                dna_identity_free(identity);
                prefetch_count++;
            } else if (result == -2) {
                QGP_LOG_DEBUG(LOG_TAG, "Not found in DHT: %.16s...\n", fingerprint);
            } else {
                QGP_LOG_DEBUG(LOG_TAG, "Prefetch failed: %.16s...\n", fingerprint);
            }
        }
    }

    closedir(dir);

    QGP_LOG_INFO(LOG_TAG, "Prefetched %d identity profiles\n", prefetch_count);
    return prefetch_count;
}

/**
 * Get display name for fingerprint
 * Tries reverse lookup first (fast), then full profile, then fallback to shortened fingerprint
 */
int dna_get_display_name(
    dht_context_t *dht_ctx,
    const char *fingerprint,
    char **display_name_out
) {
    if (!fingerprint || !display_name_out) {
        return -1;
    }

    int ret;

    // 1. Try reverse lookup first (fingerprint:reverse key) - fast, small payload
    if (dht_ctx) {
        char *registered_name = NULL;
        ret = dht_keyserver_reverse_lookup(dht_ctx, fingerprint, &registered_name);
        if (ret == 0 && registered_name && registered_name[0] != '\0') {
            *display_name_out = registered_name;
            QGP_LOG_INFO(LOG_TAG, "✓ Display name: %s (from reverse lookup)\n", registered_name);
            return 0;
        }
        if (registered_name) {
            free(registered_name);
        }
    }

    // 2. Reverse lookup failed - try full profile as fallback
    // This is slower but may have name in older profiles without reverse key
    dna_unified_identity_t *identity = NULL;
    ret = dna_load_identity(dht_ctx, fingerprint, &identity);

    if (ret == 0 && identity) {
        // Cache the full profile (including avatar) for later use
        profile_cache_add_or_update(fingerprint, identity);

        // Check if name is registered and not expired
        if (identity->has_registered_name && !dna_is_name_expired(identity)) {
            // Return registered name
            char *display = strdup(identity->registered_name);
            dna_identity_free(identity);

            if (!display) {
                return -1;
            }

            *display_name_out = display;
            QGP_LOG_INFO(LOG_TAG, "✓ Display name: %s (from profile)\n", display);
            return 0;
        }

        dna_identity_free(identity);
    }

    // 3. Fallback: Return shortened fingerprint (first 16 chars + "...")
    char *display = malloc(32);
    if (!display) {
        return -1;
    }

    snprintf(display, 32, "%.16s...", fingerprint);
    *display_name_out = display;

    QGP_LOG_INFO(LOG_TAG, "Display name: %s (fingerprint)\n", display);
    return 0;
}

/**
 * Close profile manager
 */
void profile_manager_close(void) {
    if (g_initialized) {
        profile_cache_close();
        g_initialized = false;
        QGP_LOG_INFO(LOG_TAG, "Closed\n");
    }
}
