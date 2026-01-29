/*
 * DNA Engine - Backup & Sync Module
 *
 * All DHT synchronization operations consolidated here:
 *   - Message backup/restore (DHT cloud backup)
 *   - Contacts sync to/from DHT
 *   - Groups sync to/from DHT
 *   - Address book sync to/from DHT
 *
 * Functions:
 *   - dna_engine_backup_messages()
 *   - dna_engine_restore_messages()
 *   - dna_engine_check_backup_exists()
 *   - dna_handle_sync_contacts_to_dht()
 *   - dna_handle_sync_contacts_from_dht()
 *   - dna_handle_sync_groups()
 *   - dna_handle_sync_groups_to_dht()
 *   - dna_handle_restore_groups_from_dht()
 *   - dna_handle_sync_group_by_uuid()
 *   - dna_engine_sync_addressbook_to_dht()
 *   - dna_engine_sync_addressbook_from_dht()
 */

#define DNA_ENGINE_BACKUP_IMPL
#include "engine_includes.h"

/* ============================================================================
 * MESSAGE BACKUP/RESTORE (DHT Cloud Backup)
 * ============================================================================ */

/* Context for async backup thread */
typedef struct {
    dna_engine_t *engine;
    dna_request_id_t request_id;
    dna_backup_result_cb callback;
    void *user_data;
    qgp_key_t *kyber_key;
    qgp_key_t *dilithium_key;
} backup_thread_ctx_t;

/* Context for async restore thread */
typedef struct {
    dna_engine_t *engine;
    dna_request_id_t request_id;
    dna_backup_result_cb callback;
    void *user_data;
    qgp_key_t *kyber_key;
    qgp_key_t *dilithium_key;
} restore_thread_ctx_t;

/* Background thread for message backup (never blocks UI) */
static void *backup_thread_func(void *arg) {
    backup_thread_ctx_t *ctx = (backup_thread_ctx_t *)arg;
    if (!ctx) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[BACKUP-THREAD] Starting async backup...");

    dna_engine_t *engine = ctx->engine;
    if (!engine || !engine->messenger || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[BACKUP-THREAD] Engine not ready, aborting");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] DHT not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get message backup context */
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] Backup context not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Perform backup (slow DHT operation) */
    int message_count = 0;
    int result = dht_message_backup_publish(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        ctx->kyber_key->public_key,
        ctx->kyber_key->private_key,
        ctx->dilithium_key->public_key,
        ctx->dilithium_key->private_key,
        &message_count
    );

    /* Cleanup keys */
    qgp_key_free(ctx->kyber_key);
    qgp_key_free(ctx->dilithium_key);

    /* Invoke callback with results */
    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "[BACKUP-THREAD] Backup completed: %d messages", message_count);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, 0, message_count, 0, ctx->user_data);
        }
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[BACKUP-THREAD] Backup failed: %d", result);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, result, 0, 0, ctx->user_data);
        }
    }

    free(ctx);
    return NULL;
}

/* Background thread for message restore (never blocks UI) */
static void *restore_thread_func(void *arg) {
    restore_thread_ctx_t *ctx = (restore_thread_ctx_t *)arg;
    if (!ctx) return NULL;

    QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] Starting async restore...");

    dna_engine_t *engine = ctx->engine;
    if (!engine || !engine->messenger || !engine->identity_loaded) {
        QGP_LOG_WARN(LOG_TAG, "[RESTORE-THREAD] Engine not ready, aborting");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] DHT not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Get message backup context */
    message_backup_context_t *msg_ctx = engine->messenger->backup_ctx;
    if (!msg_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] Backup context not available");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -1, 0, 0, ctx->user_data);
        }
        qgp_key_free(ctx->kyber_key);
        qgp_key_free(ctx->dilithium_key);
        free(ctx);
        return NULL;
    }

    /* Perform restore (slow DHT operation) */
    int restored_count = 0;
    int skipped_count = 0;
    int result = dht_message_backup_restore(
        dht_ctx,
        msg_ctx,
        engine->fingerprint,
        ctx->kyber_key->private_key,
        ctx->dilithium_key->public_key,
        &restored_count,
        &skipped_count
    );

    /* Cleanup keys */
    qgp_key_free(ctx->kyber_key);
    qgp_key_free(ctx->dilithium_key);

    /* Invoke callback with results */
    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] Restore completed: %d restored, %d skipped",
                     restored_count, skipped_count);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, 0, restored_count, skipped_count, ctx->user_data);
        }
    } else if (result == -2) {
        QGP_LOG_INFO(LOG_TAG, "[RESTORE-THREAD] No backup found in DHT");
        if (ctx->callback) {
            ctx->callback(ctx->request_id, -2, 0, 0, ctx->user_data);
        }
    } else {
        QGP_LOG_ERROR(LOG_TAG, "[RESTORE-THREAD] Restore failed: %d", result);
        if (ctx->callback) {
            ctx->callback(ctx->request_id, result, 0, 0, ctx->user_data);
        }
    }

    free(ctx);
    return NULL;
}

dna_request_id_t dna_engine_backup_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data)
{
    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for backup_messages");
        return 0;
    }

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded for backup");
        callback(0, -1, 0, 0, user_data);
        return 0;
    }

    dna_request_id_t request_id = dna_next_request_id(engine);

    /* Load keys on main thread for fast-fail validation */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    /* Load Kyber keypair (v0.3.0: flat structure - keys/identity.kem) */
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(kyber_path, engine->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    /* Load Dilithium keypair (v0.3.0: flat structure) */
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, engine->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    /* Allocate thread context - keys ownership transferred to thread */
    backup_thread_ctx_t *ctx = (backup_thread_ctx_t *)malloc(sizeof(backup_thread_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate backup thread context");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    ctx->engine = engine;
    ctx->request_id = request_id;
    ctx->callback = callback;
    ctx->user_data = user_data;
    ctx->kyber_key = kyber_key;
    ctx->dilithium_key = dilithium_key;

    /* Spawn detached thread for async backup (never blocks UI) */
    pthread_t backup_thread;
    if (pthread_create(&backup_thread, NULL, backup_thread_func, ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to spawn backup thread");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        free(ctx);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }
    pthread_detach(backup_thread);

    QGP_LOG_INFO(LOG_TAG, "Backup thread spawned (request_id=%llu)", (unsigned long long)request_id);
    return request_id;
}

dna_request_id_t dna_engine_restore_messages(
    dna_engine_t *engine,
    dna_backup_result_cb callback,
    void *user_data)
{
    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for restore_messages");
        return 0;
    }

    if (!engine->identity_loaded || !engine->messenger) {
        QGP_LOG_ERROR(LOG_TAG, "No identity loaded for restore");
        callback(0, -1, 0, 0, user_data);
        return 0;
    }

    dna_request_id_t request_id = dna_next_request_id(engine);

    /* Load keys on main thread for fast-fail validation */
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    /* Load Kyber keypair (v0.3.0: flat structure - keys/identity.kem) */
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    qgp_key_t *kyber_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(kyber_path, engine->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key");
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    /* Load Dilithium keypair (v0.3.0: flat structure) */
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *dilithium_key = NULL;
    if (engine->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, engine->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key");
            qgp_key_free(kyber_key);
            callback(request_id, -1, 0, 0, user_data);
            return request_id;
        }
    }

    /* Allocate thread context - keys ownership transferred to thread */
    restore_thread_ctx_t *ctx = (restore_thread_ctx_t *)malloc(sizeof(restore_thread_ctx_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate restore thread context");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }

    ctx->engine = engine;
    ctx->request_id = request_id;
    ctx->callback = callback;
    ctx->user_data = user_data;
    ctx->kyber_key = kyber_key;
    ctx->dilithium_key = dilithium_key;

    /* Spawn detached thread for async restore (never blocks UI) */
    pthread_t restore_thread;
    if (pthread_create(&restore_thread, NULL, restore_thread_func, ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to spawn restore thread");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        free(ctx);
        callback(request_id, -1, 0, 0, user_data);
        return request_id;
    }
    pthread_detach(restore_thread);

    QGP_LOG_INFO(LOG_TAG, "Restore thread spawned (request_id=%llu)", (unsigned long long)request_id);
    return request_id;
}

/* ============================================================================
 * CONTACTS SYNC (from p2p module)
 * ============================================================================ */

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

/* ============================================================================
 * GROUPS SYNC (from p2p module)
 * ============================================================================ */

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
                /* Also sync GEK for this group */
                int gek_ret = messenger_sync_group_gek(group_uuid);
                if (gek_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync GEK for group %s (non-fatal)", group_uuid);
                } else {
                    QGP_LOG_INFO(LOG_TAG, "Successfully synced GEK for group %s", group_uuid);
                }

                /* Sync messages from DHT to local DB */
                size_t msg_count = 0;
                int msg_ret = dna_group_outbox_sync(dht_ctx, group_uuid, &msg_count);
                if (msg_ret != 0) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to sync messages for group %s (non-fatal)", group_uuid);
                } else if (msg_count > 0) {
                    QGP_LOG_INFO(LOG_TAG, "Synced %zu messages for group %s", msg_count, group_uuid);
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

/* ============================================================================
 * ADDRESS BOOK SYNC (from addressbook module)
 * ============================================================================ */

/* DHT Sync task data */
typedef struct {
    dna_engine_t *engine;
    dna_completion_cb callback;
    void *user_data;
} addressbook_sync_task_t;

/* Task: Sync address book to DHT */
static void task_sync_addressbook_to_dht(void *data) {
    addressbook_sync_task_t *task = (addressbook_sync_task_t*)data;
    if (!task) return;

    int error = 0;

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(task->engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "No DHT context for address book sync");
        error = -1;
        goto done;
    }

    /* Load keys */
    qgp_key_t *sign_key = dna_load_private_key(task->engine);
    qgp_key_t *enc_key = dna_load_encryption_key(task->engine);
    if (!sign_key || !enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load keys for address book sync");
        error = -1;
        if (sign_key) qgp_key_free(sign_key);
        if (enc_key) qgp_key_free(enc_key);
        goto done;
    }

    /* Get address book from database */
    addressbook_list_t *list = NULL;
    if (addressbook_db_list(&list) != 0 || !list) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get address book for sync");
        error = -1;
        qgp_key_free(sign_key);
        qgp_key_free(enc_key);
        goto done;
    }

    /* Convert to DHT entries */
    dht_addressbook_entry_t *dht_entries = NULL;
    if (list->count > 0) {
        dht_entries = dht_addressbook_from_db_entries(list->entries, list->count);
    }

    /* Publish to DHT */
    int result = dht_addressbook_publish(
        dht_ctx,
        task->engine->fingerprint,
        dht_entries,
        list->count,
        enc_key->public_key,
        enc_key->private_key,
        sign_key->public_key,
        sign_key->private_key,
        0  /* Use default TTL */
    );

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish address book to DHT");
        error = -1;
    } else {
        QGP_LOG_INFO(LOG_TAG, "Published %zu addresses to DHT", list->count);
    }

    if (dht_entries) {
        dht_addressbook_free_entries(dht_entries, list->count);
    }
    addressbook_db_free_list(list);
    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

done:
    if (task->callback) {
        task->callback(0, error, task->user_data);
    }
    free(task);
}

/* Task: Sync address book from DHT */
static void task_sync_addressbook_from_dht(void *data) {
    addressbook_sync_task_t *task = (addressbook_sync_task_t*)data;
    if (!task) return;

    int error = 0;

    /* Get DHT context */
    dht_context_t *dht_ctx = dna_get_dht_ctx(task->engine);
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "No DHT context for address book sync");
        error = -1;
        goto done;
    }

    /* Load keys */
    qgp_key_t *sign_key = dna_load_private_key(task->engine);
    qgp_key_t *enc_key = dna_load_encryption_key(task->engine);
    if (!sign_key || !enc_key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load keys for address book sync");
        error = -1;
        if (sign_key) qgp_key_free(sign_key);
        if (enc_key) qgp_key_free(enc_key);
        goto done;
    }

    /* Fetch from DHT */
    dht_addressbook_entry_t *dht_entries = NULL;
    size_t entry_count = 0;

    int result = dht_addressbook_fetch(
        dht_ctx,
        task->engine->fingerprint,
        &dht_entries,
        &entry_count,
        enc_key->private_key,
        sign_key->public_key
    );

    qgp_key_free(sign_key);
    qgp_key_free(enc_key);

    if (result == -2) {
        /* Not found in DHT - not an error, just no data */
        QGP_LOG_INFO(LOG_TAG, "No address book found in DHT");
        goto done;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch address book from DHT");
        error = -1;
        goto done;
    }

    /* Replace local database with DHT data */
    addressbook_db_clear_all();

    for (size_t i = 0; i < entry_count; i++) {
        addressbook_db_add(
            dht_entries[i].address,
            dht_entries[i].label,
            dht_entries[i].network,
            dht_entries[i].notes
        );
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %zu addresses from DHT", entry_count);

    if (dht_entries) {
        dht_addressbook_free_entries(dht_entries, entry_count);
    }

done:
    if (task->callback) {
        task->callback(0, error, task->user_data);
    }
    free(task);
}

/* Async: Sync address book to DHT */
dna_request_id_t dna_engine_sync_addressbook_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    addressbook_sync_task_t *task = calloc(1, sizeof(addressbook_sync_task_t));
    if (!task) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    task_sync_addressbook_to_dht(task);
    return 1;
}

/* Async: Sync address book from DHT */
dna_request_id_t dna_engine_sync_addressbook_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !engine->identity_loaded) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    addressbook_sync_task_t *task = calloc(1, sizeof(addressbook_sync_task_t));
    if (!task) {
        if (callback) {
            callback(0, -1, user_data);
        }
        return 0;
    }

    task->engine = engine;
    task->callback = callback;
    task->user_data = user_data;

    task_sync_addressbook_from_dht(task);
    return 1;
}

/* ============================================================================
 * BACKUP CHECK API
 * ============================================================================ */

dna_request_id_t dna_engine_check_backup_exists(
    dna_engine_t *engine,
    dna_backup_info_cb callback,
    void *user_data)
{
    dna_request_id_t request_id = dna_next_request_id(engine);

    if (!engine || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: invalid parameters");
        if (callback) {
            dna_backup_info_t info = {0};
            callback(request_id, -1, &info, user_data);
        }
        return request_id;
    }

    if (engine->fingerprint[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: no identity loaded");
        dna_backup_info_t info = {0};
        callback(request_id, -1, &info, user_data);
        return request_id;
    }

    /* Get DHT context */
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "check_backup_exists: DHT not initialized");
        dna_backup_info_t info = {0};
        callback(request_id, -1, &info, user_data);
        return request_id;
    }

    QGP_LOG_INFO(LOG_TAG, "Checking if backup exists for fingerprint %.20s...",
                 engine->fingerprint);

    /* Use dht_message_backup_get_info to check without full download */
    uint64_t timestamp = 0;
    int message_count = -1;
    int result = dht_message_backup_get_info(dht_ctx, engine->fingerprint,
                                              &timestamp, &message_count);

    dna_backup_info_t info = {0};
    if (result == 0) {
        info.exists = true;
        info.timestamp = timestamp;
        info.message_count = message_count;
        QGP_LOG_INFO(LOG_TAG, "Backup found: timestamp=%llu, messages=%d",
                     (unsigned long long)timestamp, message_count);
        callback(request_id, 0, &info, user_data);
    } else if (result == -2) {
        info.exists = false;
        info.timestamp = 0;
        info.message_count = 0;
        QGP_LOG_INFO(LOG_TAG, "No backup found in DHT");
        callback(request_id, 0, &info, user_data);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to check backup: %d", result);
        callback(request_id, result, &info, user_data);
    }

    return request_id;
}
