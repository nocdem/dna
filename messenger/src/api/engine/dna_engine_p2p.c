/*
 * DNA Engine - P2P/Presence Module
 *
 * P2P and presence handling extracted from dna_engine.c.
 * Contains presence refresh, DHT sync, and P2P coordination handlers.
 *
 * Functions:
 *   - dna_handle_refresh_presence()
 *   - dna_handle_lookup_presence()
 *   - dna_handle_sync_contacts_to_dht()
 *   - dna_handle_sync_contacts_from_dht()
 *   - dna_handle_sync_groups()
 *   - dna_handle_sync_groups_to_dht()
 *   - dna_handle_restore_groups_from_dht()
 *   - dna_handle_sync_group_by_uuid()
 *   - dna_handle_get_registered_name()
 *
 * Note: Listener management functions (outbox, presence, ACK listeners)
 * remain in dna_engine_unified.c as they are tightly coupled with
 * engine lifecycle management.
 */

#define DNA_ENGINE_P2P_IMPL
#include "engine_includes.h"

/* ============================================================================
 * P2P & PRESENCE TASK HANDLERS
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

void dna_handle_sync_contacts_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] sync_contacts_to_dht handler: calling sync");
        if (messenger_sync_contacts_to_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_contacts_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_contacts_from_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_groups(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        if (messenger_sync_groups(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_groups_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        QGP_LOG_INFO(LOG_TAG, "[GROUPLIST_PUBLISH] sync_groups_to_dht handler: calling sync");
        if (messenger_sync_groups_to_dht(engine->messenger) != 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_restore_groups_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else {
        QGP_LOG_INFO(LOG_TAG, "restore_groups_from_dht handler: calling restore");
        int restored = messenger_restore_groups_from_dht(engine->messenger);
        if (restored < 0) {
            error = DNA_ENGINE_ERROR_NETWORK;
        } else {
            QGP_LOG_INFO(LOG_TAG, "Restored %d groups from DHT", restored);
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

void dna_handle_sync_group_by_uuid(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    int error = DNA_OK;
    const char *group_uuid = task->params.sync_group_by_uuid.group_uuid;

    if (!engine->messenger) {
        error = DNA_ENGINE_ERROR_NO_IDENTITY;
    } else if (!group_uuid || strlen(group_uuid) != 36) {
        error = DNA_ENGINE_ERROR_INVALID_PARAM;
    } else {
        dht_context_t *dht_ctx = dht_singleton_get();
        if (dht_ctx) {
            int ret = dht_groups_sync_from_dht(dht_ctx, group_uuid);
            if (ret != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to sync group %s from DHT: %d", group_uuid, ret);
                error = DNA_ENGINE_ERROR_NETWORK;
            } else {
                QGP_LOG_INFO(LOG_TAG, "Successfully synced group %s from DHT", group_uuid);
                // Also sync GEK for this group
                int gek_ret = messenger_sync_group_gek(group_uuid);
                if (gek_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync GEK for group %s (non-fatal)", group_uuid);
                } else {
                    QGP_LOG_INFO(LOG_TAG, "Successfully synced GEK for group %s", group_uuid);
                }

                // Sync messages from DHT to local DB
                size_t msg_count = 0;
                int msg_ret = dna_group_outbox_sync(dht_ctx, group_uuid, &msg_count);
                if (msg_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync messages for group %s (non-fatal)", group_uuid);
                } else if (msg_count > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Synced %zu new messages for group %s", msg_count, group_uuid);
                }
            }
        } else {
            error = DNA_ENGINE_ERROR_NETWORK;
        }
    }

    if (task->callback.completion) {
        task->callback.completion(task->request_id, error, task->user_data);
    }
}

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
