/**
 * Local Presence Cache Implementation
 *
 * Fast O(1) lookup with hash map
 * Online status stored explicitly from server response
 * Fires events on status transitions
 */

#include "presence_cache.h"
#include "contacts_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "crypto/utils/qgp_log.h"
#include "dna/dna_engine.h"

#define LOG_TAG "DB_PRESENCE"

#define PRESENCE_CACHE_SIZE 1024

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
 * Fire status change event (internal helper)
 */
static void fire_status_event(const char *fingerprint, bool is_online) {
    dna_engine_t *engine = dna_engine_get_global();
    if (!engine) {
        return;
    }

    dna_event_t event = {0};
    event.type = is_online ? DNA_EVENT_CONTACT_ONLINE : DNA_EVENT_CONTACT_OFFLINE;
    strncpy(event.data.contact_status.fingerprint, fingerprint, 128);
    event.data.contact_status.fingerprint[128] = '\0';

    char fp_short[20];
    snprintf(fp_short, sizeof(fp_short), "%.8s...%.8s", fingerprint, fingerprint + 120);
    QGP_LOG_INFO(LOG_TAG, "Firing %s event for %s",
           is_online ? "CONTACT_ONLINE" : "CONTACT_OFFLINE", fp_short);

    dna_dispatch_event(engine, &event);
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

    QGP_LOG_INFO(LOG_TAG, "Cache initialized");
    return 0;
}

/**
 * Update presence (with automatic event firing and database persistence)
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
            // Check old status before update
            bool was_online = node->entry.is_online;

            // Update entry — store real timestamp and explicit online flag
            node->entry.last_seen = timestamp;
            node->entry.is_online = is_online;

            bool now_online = is_online;

            pthread_mutex_unlock(&cache_mutex);

            // Persist to database when online (so it survives app restart)
            if (is_online) {
                contacts_db_update_last_seen(fingerprint, (uint64_t)timestamp);
            }

            // Fire event if status changed
            if (was_online != now_online) {
                fire_status_event(fingerprint, now_online);
            }

            char fp_short[20];
            snprintf(fp_short, sizeof(fp_short), "%.8s...%.8s", fingerprint, fingerprint + 120);
            QGP_LOG_DEBUG(LOG_TAG, "Updated %s: %s", fp_short, now_online ? "ONLINE" : "OFFLINE");
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
    new_node->entry.last_seen = timestamp;
    new_node->entry.is_online = is_online;

    new_node->next = presence_map[index];
    presence_map[index] = new_node;

    bool now_online = is_online;

    pthread_mutex_unlock(&cache_mutex);

    // Persist to database when online (so it survives app restart)
    if (is_online) {
        contacts_db_update_last_seen(fingerprint, (uint64_t)timestamp);
    }

    // Fire event for new entry if online
    if (now_online) {
        fire_status_event(fingerprint, true);
    }

    char fp_short[20];
    snprintf(fp_short, sizeof(fp_short), "%.8s...%.8s", fingerprint, fingerprint + 120);
    QGP_LOG_DEBUG(LOG_TAG, "Added %s: %s", fp_short, now_online ? "ONLINE" : "OFFLINE");
}

/**
 * Get cached presence (derived from last_seen)
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

    // Search for entry
    while (node) {
        if (strcmp(node->entry.fingerprint, fingerprint) == 0) {
            bool online = node->entry.is_online;
            pthread_mutex_unlock(&cache_mutex);
            return online;
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
    QGP_LOG_INFO(LOG_TAG, "Cache cleared");
}

/**
 * Cleanup
 */
void presence_cache_free(void) {
    presence_cache_clear();
    cache_initialized = false;
}
