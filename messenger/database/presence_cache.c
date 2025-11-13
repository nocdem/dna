/**
 * Local Presence Cache Implementation
 *
 * Fast O(1) lookup with hash map
 * No DHT queries required
 */

#include "presence_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define PRESENCE_CACHE_SIZE 1024
#define PRESENCE_TTL_SECONDS 300  // 5 minutes

/**
 * Hash map entry (linked list for collisions)
 */
typedef struct presence_node {
    presence_entry_t entry;
    struct presence_node *next;
} presence_node_t;

/**
 * Global presence cache
 */
static presence_node_t *presence_map[PRESENCE_CACHE_SIZE] = {NULL};
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool cache_initialized = false;

/**
 * Simple hash function for fingerprints
 */
static unsigned int hash_fingerprint(const char *fingerprint) {
    unsigned int hash = 5381;
    int c;

    while ((c = *fingerprint++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash % PRESENCE_CACHE_SIZE;
}

/**
 * Initialize presence cache
 */
int presence_cache_init(void) {
    pthread_mutex_lock(&cache_mutex);

    if (cache_initialized) {
        pthread_mutex_unlock(&cache_mutex);
        return 0;
    }

    memset(presence_map, 0, sizeof(presence_map));
    cache_initialized = true;

    pthread_mutex_unlock(&cache_mutex);

    printf("[Presence] Cache initialized (TTL=%d seconds)\n", PRESENCE_TTL_SECONDS);
    return 0;
}

/**
 * Update presence (passive detection)
 */
void presence_cache_update(const char *fingerprint, bool is_online, time_t timestamp) {
    if (!fingerprint || strlen(fingerprint) != 128) {
        return;
    }

    if (!cache_initialized) {
        presence_cache_init();
    }

    pthread_mutex_lock(&cache_mutex);

    unsigned int index = hash_fingerprint(fingerprint);
    presence_node_t *node = presence_map[index];

    // Search for existing entry
    while (node) {
        if (strcmp(node->entry.fingerprint, fingerprint) == 0) {
            // Update existing entry
            node->entry.is_online = is_online;
            node->entry.last_seen = timestamp;
            node->entry.last_updated = time(NULL);

            pthread_mutex_unlock(&cache_mutex);

            char fp_short[20];
            snprintf(fp_short, sizeof(fp_short), "%.8s...%.8s", fingerprint, fingerprint + 120);
            printf("[Presence] Updated %s: %s\n", fp_short, is_online ? "ONLINE" : "OFFLINE");
            return;
        }
        node = node->next;
    }

    // Create new entry
    presence_node_t *new_node = (presence_node_t*)malloc(sizeof(presence_node_t));
    if (!new_node) {
        pthread_mutex_unlock(&cache_mutex);
        return;
    }

    strncpy(new_node->entry.fingerprint, fingerprint, 128);
    new_node->entry.fingerprint[128] = '\0';
    new_node->entry.is_online = is_online;
    new_node->entry.last_seen = timestamp;
    new_node->entry.last_updated = time(NULL);
    new_node->next = presence_map[index];
    presence_map[index] = new_node;

    pthread_mutex_unlock(&cache_mutex);

    char fp_short[20];
    snprintf(fp_short, sizeof(fp_short), "%.8s...%.8s", fingerprint, fingerprint + 120);
    printf("[Presence] Added %s: %s\n", fp_short, is_online ? "ONLINE" : "OFFLINE");
}

/**
 * Get cached presence (NO DHT query)
 */
bool presence_cache_get(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != 128) {
        return false;
    }

    if (!cache_initialized) {
        return false;  // No cache = assume offline
    }

    pthread_mutex_lock(&cache_mutex);

    unsigned int index = hash_fingerprint(fingerprint);
    presence_node_t *node = presence_map[index];
    time_t now = time(NULL);

    // Search for entry
    while (node) {
        if (strcmp(node->entry.fingerprint, fingerprint) == 0) {
            // Check TTL
            if ((now - node->entry.last_updated) > PRESENCE_TTL_SECONDS) {
                // Expired - assume offline
                pthread_mutex_unlock(&cache_mutex);
                return false;
            }

            bool is_online = node->entry.is_online;
            pthread_mutex_unlock(&cache_mutex);
            return is_online;
        }
        node = node->next;
    }

    pthread_mutex_unlock(&cache_mutex);
    return false;  // Not found = assume offline
}

/**
 * Get last seen time
 */
time_t presence_cache_last_seen(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != 128 || !cache_initialized) {
        return 0;
    }

    pthread_mutex_lock(&cache_mutex);

    unsigned int index = hash_fingerprint(fingerprint);
    presence_node_t *node = presence_map[index];

    while (node) {
        if (strcmp(node->entry.fingerprint, fingerprint) == 0) {
            time_t last_seen = node->entry.last_seen;
            pthread_mutex_unlock(&cache_mutex);
            return last_seen;
        }
        node = node->next;
    }

    pthread_mutex_unlock(&cache_mutex);
    return 0;
}

/**
 * Clear all entries
 */
void presence_cache_clear(void) {
    if (!cache_initialized) {
        return;
    }

    pthread_mutex_lock(&cache_mutex);

    for (int i = 0; i < PRESENCE_CACHE_SIZE; i++) {
        presence_node_t *node = presence_map[i];
        while (node) {
            presence_node_t *next = node->next;
            free(node);
            node = next;
        }
        presence_map[i] = NULL;
    }

    pthread_mutex_unlock(&cache_mutex);
    printf("[Presence] Cache cleared\n");
}

/**
 * Cleanup
 */
void presence_cache_free(void) {
    presence_cache_clear();
    cache_initialized = false;
}
