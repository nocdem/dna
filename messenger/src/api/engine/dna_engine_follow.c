/*
 * DNA Engine - Follow Module
 *
 * One-directional follow system. No approval needed, private to owner.
 * Follow list stored locally (SQLite) and synced to DHT (encrypted).
 *
 * Contains handlers and public API:
 *   - dna_handle_follow()
 *   - dna_handle_unfollow()
 *   - dna_handle_get_following()
 *   - dna_handle_sync_following_to_dht()
 *   - dna_handle_sync_following_from_dht()
 *   - dna_engine_follow()
 *   - dna_engine_unfollow()
 *   - dna_engine_get_following()
 *   - dna_free_following()
 *   - dna_engine_sync_following_to_dht()
 *   - dna_engine_sync_following_from_dht()
 *
 * STATUS: v0.9.126+ - Follow system
 */

#define DNA_ENGINE_FOLLOW_IMPL

#include "engine_includes.h"

/* Override LOG_TAG for this module */
#undef LOG_TAG
#define LOG_TAG "ENGINE_FOLLOW"

/* ============================================================================
 * KEY LOADING HELPER
 * ============================================================================ */

/**
 * Load Kyber and Dilithium keypairs for DHT encryption.
 * Caller must free keys with qgp_key_free().
 */
static int load_crypto_keys(dna_engine_t *engine,
                             qgp_key_t **kyber_out,
                             qgp_key_t **dilithium_out) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory");
        return -1;
    }

    const char *password = engine->messenger ? engine->messenger->session_password : NULL;

    /* Load Kyber keypair */
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

    if (password) {
        if (qgp_key_load_encrypted(kyber_path, password, kyber_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key");
            return -1;
        }
    } else {
        if (qgp_key_load(kyber_path, kyber_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key");
            return -1;
        }
    }

    /* Load Dilithium keypair */
    char dil_path[1024];
    snprintf(dil_path, sizeof(dil_path), "%s/keys/identity.dsa", data_dir);

    if (password) {
        if (qgp_key_load_encrypted(dil_path, password, dilithium_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key");
            qgp_key_free(*kyber_out);
            *kyber_out = NULL;
            return -1;
        }
    } else {
        if (qgp_key_load(dil_path, dilithium_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key");
            qgp_key_free(*kyber_out);
            *kyber_out = NULL;
            return -1;
        }
    }

    return 0;
}

/* ============================================================================
 * TASK HANDLERS
 * ============================================================================ */

void dna_handle_follow(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    if (!engine->identity_loaded) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    const char *fp = task->params.follow.fingerprint;
    if (!fp || strlen(fp) != 128) {
        QGP_LOG_ERROR(LOG_TAG, "Follow: invalid fingerprint");
        task->callback.completion(task->request_id, DNA_ERROR_INVALID_ARG, task->user_data);
        return;
    }

    /* Cannot follow yourself */
    if (strcmp(fp, engine->fingerprint) == 0) {
        QGP_LOG_WARN(LOG_TAG, "Cannot follow yourself");
        task->callback.completion(task->request_id, DNA_ERROR_INVALID_ARG, task->user_data);
        return;
    }

    following_db_init(engine->fingerprint);

    int ret = following_db_add(fp);
    if (ret == -2) {
        QGP_LOG_INFO(LOG_TAG, "Already following %.16s...", fp);
        /* Not an error — still success */
    } else if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to follow %.16s...", fp);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Now following %.16s...", fp);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_unfollow(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    if (!engine->identity_loaded) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    const char *fp = task->params.follow.fingerprint;
    if (!fp || strlen(fp) != 128) {
        task->callback.completion(task->request_id, DNA_ERROR_INVALID_ARG, task->user_data);
        return;
    }

    following_db_init(engine->fingerprint);

    int ret = following_db_remove(fp);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to unfollow %.16s...", fp);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Unfollowed %.16s...", fp);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_get_following(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    if (!engine->identity_loaded) {
        task->callback.following(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, 0, task->user_data);
        return;
    }

    following_db_init(engine->fingerprint);

    following_list_t *list = NULL;
    int ret = following_db_list(&list);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get following list");
        task->callback.following(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, 0, task->user_data);
        return;
    }

    if (!list || list->count == 0) {
        if (list) following_db_free_list(list);
        task->callback.following(task->request_id, DNA_OK, NULL, 0, task->user_data);
        return;
    }

    /* Convert to public API format */
    dna_following_t *result = calloc(list->count, sizeof(dna_following_t));
    if (!result) {
        following_db_free_list(list);
        task->callback.following(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < list->count; i++) {
        strncpy(result[i].fingerprint, list->entries[i].fingerprint, 128);
        result[i].fingerprint[128] = '\0';
        result[i].followed_at = list->entries[i].followed_at;
    }

    int count = (int)list->count;
    following_db_free_list(list);

    QGP_LOG_INFO(LOG_TAG, "Returning %d followed users", count);
    task->callback.following(task->request_id, DNA_OK, result, count, task->user_data);
}

void dna_handle_sync_following_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    if (!engine->identity_loaded || !engine->messenger) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    following_db_init(engine->fingerprint);

    /* Load follow list from local DB */
    following_list_t *list = NULL;
    int ret = following_db_list(&list);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Sync to DHT: failed to load follow list");
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    size_t count = list ? list->count : 0;

    /* Build fingerprint array for DHT publish */
    const char **fps = NULL;
    if (count > 0) {
        fps = calloc(count, sizeof(const char *));
        if (!fps) {
            following_db_free_list(list);
            task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
            return;
        }
        for (size_t i = 0; i < count; i++) {
            fps[i] = list->entries[i].fingerprint;
        }
    }

    /* Load crypto keys */
    qgp_key_t *kyber_key = NULL;
    qgp_key_t *dilithium_key = NULL;
    if (load_crypto_keys(engine, &kyber_key, &dilithium_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Sync to DHT: failed to load crypto keys");
        free(fps);
        if (list) following_db_free_list(list);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Publish to DHT */
    ret = dht_followlist_publish(
        engine->fingerprint,
        fps, count,
        kyber_key->public_key, kyber_key->private_key,
        dilithium_key->public_key, dilithium_key->private_key,
        0  /* default TTL */
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);
    free(fps);
    if (list) following_db_free_list(list);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Sync to DHT: publish failed");
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NETWORK, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %zu followed users to DHT", count);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_sync_following_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (task->cancelled) return;

    if (!engine->identity_loaded || !engine->messenger) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    /* Load crypto keys */
    qgp_key_t *kyber_key = NULL;
    qgp_key_t *dilithium_key = NULL;
    if (load_crypto_keys(engine, &kyber_key, &dilithium_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Sync from DHT: failed to load crypto keys");
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Fetch from DHT */
    char **fps = NULL;
    size_t count = 0;

    int ret = dht_followlist_fetch(
        engine->fingerprint,
        &fps, &count,
        kyber_key->private_key,
        dilithium_key->public_key
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (ret == -2) {
        /* Not found in DHT — not an error for first-time users */
        QGP_LOG_INFO(LOG_TAG, "No follow list found in DHT (first time user or not published)");

        /* If we have local entries, publish them */
        following_db_init(engine->fingerprint);
        int local_count = following_db_count();
        if (local_count > 0) {
            QGP_LOG_INFO(LOG_TAG, "Publishing %d local follows to DHT", local_count);
            /* Re-trigger sync to DHT (will be done in a separate task) */
        }

        task->callback.completion(task->request_id, DNA_OK, task->user_data);
        return;
    }

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Sync from DHT: fetch failed");
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NETWORK, task->user_data);
        return;
    }

    /* REPLACE mode: DHT is source of truth */
    following_db_init(engine->fingerprint);

    int local_count = following_db_count();

    /* Invariant guard: don't wipe local data with empty DHT response */
    if (count == 0 && local_count > 0) {
        QGP_LOG_WARN(LOG_TAG, "DHT returned 0 follows but local has %d — keeping local", local_count);
        dht_followlist_free(fps, count);
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
        return;
    }

    /* Clear and replace */
    following_db_clear_all();

    size_t imported = 0;
    for (size_t i = 0; i < count; i++) {
        if (fps[i] && strlen(fps[i]) == 128) {
            if (following_db_add(fps[i]) == 0) {
                imported++;
            }
        }
    }

    dht_followlist_free(fps, count);

    QGP_LOG_INFO(LOG_TAG, "Synced %zu/%zu follows from DHT (local had %d)", imported, count, local_count);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_follow(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.follow.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_FOLLOW, &params, cb, user_data);
}

dna_request_id_t dna_engine_unfollow(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.follow.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_UNFOLLOW, &params, cb, user_data);
}

dna_request_id_t dna_engine_get_following(
    dna_engine_t *engine,
    dna_following_cb callback,
    void *user_data)
{
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.following = callback;
    return dna_submit_task(engine, TASK_GET_FOLLOWING, &params, cb, user_data);
}

void dna_free_following(dna_following_t *following, int count) {
    (void)count;
    free(following);
}

dna_request_id_t dna_engine_sync_following_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_SYNC_FOLLOWING_TO_DHT, &params, cb, user_data);
}

dna_request_id_t dna_engine_sync_following_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data)
{
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_SYNC_FOLLOWING_FROM_DHT, &params, cb, user_data);
}
