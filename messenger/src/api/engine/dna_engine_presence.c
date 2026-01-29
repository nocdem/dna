/*
 * DNA Engine - Presence Module
 *
 * Presence management: heartbeat, refresh, lookup, network changes.
 *
 * Functions:
 *   - presence_heartbeat_thread()        // Background presence announcer (4 min)
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
 * PRESENCE HEARTBEAT (announces our presence every 4 minutes)
 * ============================================================================ */

#define PRESENCE_HEARTBEAT_INTERVAL_SECONDS 240  /* 4 minutes */

static void* presence_heartbeat_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t*)arg;

    QGP_LOG_INFO(LOG_TAG, "Presence heartbeat thread started");

    while (!atomic_load(&engine->shutdown_requested)) {
        /* Sleep in short intervals to respond quickly to shutdown */
        for (int i = 0; i < PRESENCE_HEARTBEAT_INTERVAL_SECONDS; i++) {
            if (atomic_load(&engine->shutdown_requested)) {
                break;
            }
            qgp_platform_sleep(1);
        }

        if (atomic_load(&engine->shutdown_requested)) {
            break;
        }

        /* Only announce presence if active (foreground) */
        if (atomic_load(&engine->presence_active) && engine->messenger) {
            QGP_LOG_DEBUG(LOG_TAG, "Heartbeat: refreshing presence");
            messenger_transport_refresh_presence(engine->messenger);
        }

        /* Check for day rotation on group listeners (runs every 4 min, actual
         * rotation only happens at midnight UTC when day bucket changes) */
        dna_engine_check_group_day_rotation(engine);

        /* Check for day rotation on 1-1 DM outbox listeners (v0.4.81+) */
        dna_engine_check_outbox_day_rotation(engine);
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
        dna_engine_cancel_all_presence_listeners(engine);
        dna_engine_cancel_contact_request_listener(engine);
    }

    /* v0.6.8+: Recreate DHT context from scratch instead of using dht_singleton_reinit().
     * This works for both owned and borrowed contexts. The identity is loaded fresh
     * from the cached dht_identity.bin file. */

    /* Free old context */
    if (engine->dht_ctx) {
        QGP_LOG_INFO(LOG_TAG, "Freeing old DHT context");
        dht_singleton_set_borrowed_context(NULL);  /* Clear singleton reference first */
        dht_context_free(engine->dht_ctx);
        engine->dht_ctx = NULL;
    }

    /* Recreate DHT context from identity */
    if (messenger_load_dht_identity_for_engine(engine->fingerprint, &engine->dht_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to recreate DHT context");
        return -1;
    }

    /* Lend to singleton for backwards compatibility */
    dht_singleton_set_borrowed_context(engine->dht_ctx);
    QGP_LOG_INFO(LOG_TAG, "DHT context recreated - status callback will restart listeners");
    return 0;
}

/* ============================================================================
 * PRESENCE TASK HANDLERS
 * ============================================================================ */

void dna_handle_refresh_presence(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    /* Don't announce presence if app is in background (defense in depth) */
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
        if (messenger_transport_refresh_presence(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
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
        if (messenger_transport_lookup_presence(engine->messenger,
                task->params.lookup_presence.fingerprint,
                &last_seen) == 0 && last_seen > 0) {
            /* Update presence cache with DHT result */
            time_t now = time(NULL);
            bool is_online = (now - (time_t)last_seen) < 300; /* 5 min TTL */
            presence_cache_update(task->params.lookup_presence.fingerprint,
                                  is_online, (time_t)last_seen);
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
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            char *registered_name = NULL;
            int ret = dht_keyserver_reverse_lookup(dht_ctx, engine->fingerprint, &registered_name);
            if (ret == 0 && registered_name) {
                name = registered_name; /* Transfer ownership */
            }
            /* Not found is not an error - just returns NULL name */
        }
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
