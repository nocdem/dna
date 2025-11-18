/**
 * Cache Manager Implementation
 * Unified lifecycle management for all cache modules
 *
 * @file cache_manager.c
 * @date 2025-11-16
 */

#include "cache_manager.h"
#include "keyserver_cache.h"
#include "profile_cache.h"
#include "presence_cache.h"
#include "contacts_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;
static char g_current_identity[256] = {0};

/**
 * Initialize ALL cache modules in dependency order
 * Thread-safe: Uses mutex to prevent concurrent initialization
 */
int cache_manager_init(const char *identity) {
    pthread_mutex_lock(&g_init_mutex);

    if (g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        fprintf(stderr, "[CACHE_MGR] Already initialized\n");
        return 0;
    }

    printf("[CACHE_MGR] Initializing cache subsystem...\n");

    // 1. Global caches first
    printf("[CACHE_MGR] [1/4] Initializing keyserver cache (global)...\n");
    if (keyserver_cache_init(NULL) != 0) {
        fprintf(stderr, "[CACHE_MGR] Failed to initialize keyserver cache\n");
        pthread_mutex_unlock(&g_init_mutex);
        return -1;
    }

    // 2. Per-identity caches (if identity provided)
    if (identity && strlen(identity) > 0) {
        strncpy(g_current_identity, identity, sizeof(g_current_identity) - 1);

        printf("[CACHE_MGR] [2/4] Initializing profile cache for identity: %s\n", identity);
        if (profile_cache_init(identity) != 0) {
            fprintf(stderr, "[CACHE_MGR] Failed to initialize profile cache\n");
            keyserver_cache_cleanup();
            pthread_mutex_unlock(&g_init_mutex);
            return -1;
        }

        printf("[CACHE_MGR] [3/4] Initializing contacts database for identity: %s\n", identity);
        if (contacts_db_init(identity) != 0) {
            fprintf(stderr, "[CACHE_MGR] Failed to initialize contacts database\n");
            profile_cache_close();
            keyserver_cache_cleanup();
            pthread_mutex_unlock(&g_init_mutex);
            return -1;
        }
    } else {
        printf("[CACHE_MGR] [2/4] Skipping profile cache (no identity provided)\n");
        printf("[CACHE_MGR] [3/4] Skipping contacts database (no identity provided)\n");
    }

    // 3. In-memory caches last
    printf("[CACHE_MGR] [4/4] Initializing presence cache (in-memory)...\n");
    if (presence_cache_init() != 0) {
        fprintf(stderr, "[CACHE_MGR] Failed to initialize presence cache\n");
        if (identity && strlen(identity) > 0) {
            contacts_db_close();
            profile_cache_close();
        }
        keyserver_cache_cleanup();
        pthread_mutex_unlock(&g_init_mutex);
        return -1;
    }

    // 4. Run startup eviction (clean expired entries from previous run)
    printf("[CACHE_MGR] Running startup eviction...\n");
    int evicted = cache_manager_evict_expired();
    if (evicted >= 0) {
        printf("[CACHE_MGR] Evicted %d expired entries\n", evicted);
    }

    g_initialized = true;
    pthread_mutex_unlock(&g_init_mutex);
    printf("[CACHE_MGR] Cache subsystem initialized successfully\n");
    return 0;
}

/**
 * Cleanup ALL cache modules in reverse order
 * Thread-safe: Uses mutex to prevent concurrent cleanup
 */
void cache_manager_cleanup(void) {
    pthread_mutex_lock(&g_init_mutex);

    if (!g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }

    printf("[CACHE_MGR] Cleaning up cache subsystem...\n");

    // Reverse order from init
    presence_cache_free();

    if (strlen(g_current_identity) > 0) {
        contacts_db_close();
        profile_cache_close();
    }

    keyserver_cache_cleanup();

    g_initialized = false;
    g_current_identity[0] = '\0';
    pthread_mutex_unlock(&g_init_mutex);
    printf("[CACHE_MGR] Cache subsystem cleaned up\n");
}

/**
 * Run eviction on ALL caches (remove expired entries)
 */
int cache_manager_evict_expired(void) {
    if (!g_initialized) {
        fprintf(stderr, "[CACHE_MGR] Not initialized\n");
        return -1;
    }

    int total_evicted = 0;

    // Keyserver cache eviction
    int evicted = keyserver_cache_expire_old();
    if (evicted >= 0) {
        total_evicted += evicted;
        if (evicted > 0) {
            printf("[CACHE_MGR] Keyserver cache: evicted %d entries\n", evicted);
        }
    }

    // Profile cache eviction (if initialized)
    if (strlen(g_current_identity) > 0) {
        char **expired_fingerprints = NULL;
        size_t expired_count = 0;

        if (profile_cache_list_expired(&expired_fingerprints, &expired_count) == 0 && expired_count > 0) {
            for (size_t i = 0; i < expired_count; i++) {
                profile_cache_delete(expired_fingerprints[i]);
            }
            total_evicted += (int)expired_count;
            printf("[CACHE_MGR] Profile cache: evicted %zu entries\n", expired_count);

            // Free the fingerprint list
            for (size_t i = 0; i < expired_count; i++) {
                free(expired_fingerprints[i]);
            }
            free(expired_fingerprints);
        }
    }

    // Contacts database has no eviction (permanent data)
    // Presence cache is in-memory only (no persistent eviction)

    return total_evicted;
}

/**
 * Get aggregated statistics across all caches
 */
int cache_manager_stats(cache_manager_stats_t *stats_out) {
    if (!stats_out) {
        return -1;
    }

    memset(stats_out, 0, sizeof(cache_manager_stats_t));

    if (!g_initialized) {
        fprintf(stderr, "[CACHE_MGR] Not initialized\n");
        return -1;
    }

    // Keyserver cache stats
    int keyserver_total = 0, keyserver_expired = 0;
    if (keyserver_cache_stats(&keyserver_total, &keyserver_expired) == 0) {
        stats_out->keyserver_entries = (size_t)keyserver_total;
        stats_out->expired_entries += (size_t)keyserver_expired;
        stats_out->total_entries += (size_t)keyserver_total;
        // Estimate: 4160 bytes per entry (2592 Dilithium + 1568 Kyber)
        stats_out->total_size_bytes += (size_t)keyserver_total * 4160;
    }

    // Profile cache stats (if initialized)
    if (strlen(g_current_identity) > 0) {
        int profile_total = profile_cache_count();
        if (profile_total >= 0) {
            stats_out->profile_entries = (size_t)profile_total;
            stats_out->total_entries += (size_t)profile_total;
            // Estimate: 30KB per profile (JSON identity)
            stats_out->total_size_bytes += (size_t)profile_total * 30720;

            // Count expired entries
            char **expired_fps = NULL;
            size_t expired_count = 0;
            if (profile_cache_list_expired(&expired_fps, &expired_count) == 0) {
                stats_out->expired_entries += expired_count;
                // Free the list
                for (size_t i = 0; i < expired_count; i++) {
                    free(expired_fps[i]);
                }
                free(expired_fps);
            }
        }
    }

    // Presence cache (in-memory, no stats API currently)
    // stats_out->presence_entries = 0;  // TODO: Add presence_cache_count() if needed

    return 0;
}

/**
 * Clear ALL caches (for testing, logout, etc.)
 */
void cache_manager_clear_all(void) {
    if (!g_initialized) {
        fprintf(stderr, "[CACHE_MGR] Not initialized\n");
        return;
    }

    printf("[CACHE_MGR] Clearing ALL caches...\n");

    // Clear presence cache (in-memory)
    presence_cache_clear();
    printf("[CACHE_MGR] Cleared presence cache\n");

    // Profile cache (if initialized)
    if (strlen(g_current_identity) > 0) {
        profile_cache_clear_all();
        printf("[CACHE_MGR] Cleared profile cache\n");
    }

    // Keyserver cache - no clear_all function
    // To fully clear keyserver cache, user must delete ~/.dna/keyserver_cache.db manually

    printf("[CACHE_MGR] Cache clear complete\n");
    printf("[CACHE_MGR] Note: Keyserver cache not cleared (delete ~/.dna/keyserver_cache.db manually if needed)\n");
}
