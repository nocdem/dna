/*
 * DNA Engine - Presence Module
 *
 * Presence management: heartbeat, batch query, lookup, network changes.
 *
 * v0.9.0: Nodus-native presence — batch query replaces per-contact DHT listeners.
 * Zero DHT PUT/GET for presence. Single TCP query every 60s.
 *
 * Functions:
 *   - dna_presence_batch_query()         // Batch query all contacts
 *   - presence_heartbeat_thread()        // Background presence loop (60s)
 *   - dna_start_presence_heartbeat()     // Start heartbeat thread
 *   - dna_stop_presence_heartbeat()      // Stop heartbeat thread
 *   - dna_engine_network_changed()       // Handle network change (DHT reinit)
 *   - dna_handle_refresh_presence()      // Manual presence refresh
 *   - dna_handle_lookup_presence()       // Lookup contact presence
 *   - dna_handle_get_registered_name()   // Get own registered name
 */

#define DNA_ENGINE_PRESENCE_IMPL
#include "engine_includes.h"

#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * NODUS-NATIVE BATCH PRESENCE QUERY (v0.9.0)
 *
 * Replaces per-contact DHT listeners with a single TCP query every 60s.
 * Zero DHT PUT, zero listeners, minimal bandwidth.
 * ============================================================================ */

static void dna_presence_batch_query(dna_engine_t *engine) {
    if (!engine || !engine->messenger || !engine->identity_loaded)
        return;

    if (!nodus_ops_is_ready()) {
        QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Nodus not ready, skipping batch query");
        return;
    }

    /* Get all contacts */
    contact_list_t *contacts = NULL;
    if (contacts_db_list(&contacts) != 0 || !contacts || contacts->count == 0) {
        if (contacts) contacts_db_free_list(contacts);
        return;
    }

    int count = (int)contacts->count;
    if (count > NODUS_PRESENCE_MAX_QUERY)
        count = NODUS_PRESENCE_MAX_QUERY;

    /* Build fingerprint array */
    const char **fps = calloc((size_t)count, sizeof(const char *));
    bool *online = calloc((size_t)count, sizeof(bool));
    uint64_t *last_seen = calloc((size_t)count, sizeof(uint64_t));
    if (!fps || !online || !last_seen) {
        free(fps);
        free(online);
        free(last_seen);
        contacts_db_free_list(contacts);
        return;
    }

    for (int i = 0; i < count; i++)
        fps[i] = contacts->contacts[i].identity;

    /* Single TCP query — get real last_seen from server */
    int online_count = nodus_ops_presence_query(fps, count, online, last_seen);
    if (online_count < 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Batch query failed");
        free(fps);
        free(online);
        free(last_seen);
        contacts_db_free_list(contacts);
        return;
    }

    /* Update presence cache with real timestamps from server */
    time_t now = time(NULL);
    for (int i = 0; i < count; i++) {
        if (online[i]) {
            presence_cache_update(fps[i], true, now);
        } else if (last_seen[i] > 0) {
            presence_cache_update(fps[i], false, (time_t)last_seen[i]);
            contacts_db_update_last_seen(fps[i], last_seen[i]);
        } else {
            /* Server has no data — mark offline, preserve existing timestamp */
            time_t existing = presence_cache_last_seen(fps[i]);
            if (existing > 0)
                presence_cache_update(fps[i], false, existing);
            /* No cached data either: leave unknown (no cache entry created) */
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "[PRESENCE] Batch query: %d/%d online", online_count, count);

    free(fps);
    free(online);
    free(last_seen);
    contacts_db_free_list(contacts);
}

/* ============================================================================
 * PRESENCE HEARTBEAT (batch query every 60 seconds)
 * ============================================================================ */

#define PRESENCE_HEARTBEAT_INTERVAL_SECONDS 60  /* 60 seconds */
#define RETRY_INTERVAL_TICKS 3  /* Retry pending messages every 3 heartbeats (180s) */
#define BG_POLL_INTERVAL_TICKS 5  /* Background: TCP poll every 5 ticks (5×60s = 300s) */
#define DAY_ROTATION_TICKS 10    /* Day rotation every 10 heartbeats (10×60s = 600s) */

static void* presence_heartbeat_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;
    int retry_tick = 0;
    int day_rotation_tick = 0;
    int bg_poll_tick = 0;

    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat thread started");

    /* v0.9.1: Immediate first batch query so UI doesn't show "Syncing..." for 60s */
    if (atomic_load(&engine->presence_active) && engine->messenger) {
        dna_presence_batch_query(engine);
    }

    while (!atomic_load(&engine->shutdown_requested)) {
        bool active = atomic_load(&engine->presence_active);

        /* Sleep interval: 1s when active (responsive shutdown), 60s when background
         * (battery saving — fewer CPU wakes). */
        int sleep_seconds = active ? PRESENCE_HEARTBEAT_INTERVAL_SECONDS : 60;
        for (int i = 0; i < sleep_seconds; i++) {
            if (atomic_load(&engine->shutdown_requested)) {
                break;
            }
            qgp_platform_sleep(1);
        }

        if (atomic_load(&engine->shutdown_requested)) {
            break;
        }

        /* Re-read after sleep (may have changed during sleep) */
        active = atomic_load(&engine->presence_active);

        if (active) {
            /* FOREGROUND: Poll Nodus TCP every heartbeat (60s).
             * Detects disconnect, processes listener notifications,
             * keeps connection alive. */
            nodus_messenger_poll(100);

            /* Nodus-native presence: batch query all contacts */
            if (engine->messenger) {
                QGP_LOG_DEBUG(LOG_TAG, "Heartbeat: batch presence query");
                dna_presence_batch_query(engine);
            }

            /* Retry pending messages every 180s (3 heartbeats) */
            if (++retry_tick >= RETRY_INTERVAL_TICKS) {
                retry_tick = 0;
                dna_engine_retry_pending_messages(engine);
            }

            /* Day rotation every 600s (10 heartbeats) — only matters at midnight */
            if (++day_rotation_tick >= DAY_ROTATION_TICKS) {
                day_rotation_tick = 0;
                dna_engine_check_group_day_rotation(engine);
                dna_engine_check_outbox_day_rotation(engine);
                dna_engine_check_channel_day_rotation(engine);
            }
        } else {
            /* BACKGROUND: Minimal activity for battery saving.
             * Only poll TCP every 300s to keep connection alive. */
            if (++bg_poll_tick >= BG_POLL_INTERVAL_TICKS) {
                bg_poll_tick = 0;
                nodus_messenger_poll(100);
                QGP_LOG_DEBUG(LOG_TAG, "Background: TCP keepalive poll");
            }
            /* Reset foreground counters so they start fresh on resume */
            retry_tick = 0;
            day_rotation_tick = 0;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat thread stopped");
    return NULL;
}

int dna_start_presence_heartbeat(dna_engine_t *engine) {
    int rc = pthread_create(&engine->presence_heartbeat_thread, NULL,
                           presence_heartbeat_thread, engine);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start presence heartbeat thread");
        return -1;
    }
    engine->presence_heartbeat_started = true;
    return 0;
}

void dna_stop_presence_heartbeat(dna_engine_t *engine) {
    /* v0.6.0+: Only join if thread was started (prevents crash on early failure) */
    if (!engine->presence_heartbeat_started) {
        return;
    }
    /* Thread will exit when shutdown_requested is true */
    pthread_join(engine->presence_heartbeat_thread, NULL);
    engine->presence_heartbeat_started = false;
}

int dna_engine_network_changed(dna_engine_t *engine) {
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "network_changed: NULL engine");
        return -1;
    }

    QGP_LOG_WARN(LOG_TAG, "Network change detected - reinitializing DHT connection");

    /* CRITICAL: Cancel engine-level listeners BEFORE DHT reinit.
     * The listener tokens were issued by the OLD DHT context. We must cancel
     * them while that context still exists, otherwise dht_cancel_listen()
     * silently fails (token not found in new context's map). */
    if (engine->identity_loaded) {
        QGP_LOG_INFO(LOG_TAG, "Cancelling listeners before DHT reinit");
        dna_engine_cancel_all_outbox_listeners(engine);
        /* v0.9.0: Presence listeners removed — batch query via Nodus server */
        dna_engine_cancel_contact_request_listener(engine);
    }

    /* Reinitialize nodus singleton (handles reconnection internally) */
    if (nodus_messenger_reinit() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to reinitialize nodus connection");
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "Nodus reinitialized - status callback will restart listeners");
    return 0;
}

/* ============================================================================
 * PRESENCE TASK HANDLERS
 * ============================================================================ */

void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    /* Don't query presence if app is in background (defense in depth) */
    if (!atomic_load(&engine->presence_active)) {
        QGP_LOG_DEBUG(LOG_TAG, "Skipping presence refresh - app in background");
        if (task->callback.completion) {
            task->callback.completion(task->request_id, DNA_OK, task->user_data);
        }
        return;
    }

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        /* v0.9.0: Nodus-native batch query instead of DHT PUT */
        dna_presence_batch_query(engine);
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_lookup_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    uint64_t last_seen = 0;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        /* v0.9.0: Read from presence cache (populated by batch query) */
        const char *fp = task->params.lookup_presence.fingerprint;
        time_t ts = presence_cache_last_seen(fp);
        if (ts > 0) {
            last_seen = (uint64_t)ts;
        }
        /* Not found is not an error - just return 0 timestamp */
    }

    if (task->callback.presence) {
        task->callback.presence(task->request_id, error, last_seen, task->user_data);
    }
}

/* DHT sync handlers moved to src/api/engine/dna_engine_backup.c */

void dna_handle_get_registered_name(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    char *name = NULL;

    if (!engine->messenger || !engine->identity_loaded) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        char *registered_name = NULL;
        int ret = dht_keyserver_reverse_lookup(engine->fingerprint, &registered_name);
        if (ret == 0 && registered_name) {
            name = registered_name; /* Transfer ownership */
        }
        /* Not found is not an error - just returns NULL name */
    }

    if (task->callback.display_name) {
        /* Caller frees via dna_free_string - don't free here due to async callback */
        task->callback.display_name(task->request_id, error, name, task->user_data);
    }
}

/* ============================================================================
 * P2P & PRESENCE PUBLIC API WRAPPERS
 * ============================================================================ */

dna_request_id_t dna_engine_refresh_presence(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_REFRESH_PRESENCE, NULL, cb, user_data);
}

bool dna_engine_is_peer_online(dna_engine_t *engine, const char *fingerprint) {
    if (!engine || !fingerprint || !engine->messenger) {
        return false;
    }

    return messenger_transport_peer_online(engine->messenger, fingerprint);
}

dna_request_id_t dna_engine_lookup_presence(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_presence_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.lookup_presence.fingerprint, sizeof(params.lookup_presence.fingerprint),
             "%s", fingerprint);

    dna_task_callback_t cb = { .presence = callback };
    return dna_submit_task(engine, TASK_LOOKUP_PRESENCE, &params, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_TO_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_contacts_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_CONTACTS_FROM_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_groups(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUPS, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_groups_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUPS_TO_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_restore_groups_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_RESTORE_GROUPS_FROM_DHT, NULL, cb, user_data);
}

dna_request_id_t dna_engine_sync_group_by_uuid(
    dna_engine_t *engine,
    const char *group_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !group_uuid || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }
    if (strlen(group_uuid) != 36) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_params_t params;
    memset(&params, 0, sizeof(params));
    snprintf(params.sync_group_by_uuid.group_uuid,
             sizeof(params.sync_group_by_uuid.group_uuid),
             "%s", group_uuid);

    dna_task_callback_t cb = { .completion = callback };
    return dna_submit_task(engine, TASK_SYNC_GROUP_BY_UUID, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_registered_name(
    dna_engine_t *engine,
    dna_display_name_cb callback,
    void *user_data
) {
    if (!engine || !callback) {
        return DNA_REQUEST_ID_INVALID;
    }

    dna_task_callback_t cb = { .display_name = callback };
    return dna_submit_task(engine, TASK_GET_REGISTERED_NAME, NULL, cb, user_data);
}
