/*
 * DNA Engine - Channels Module
 *
 * RSS-like channel system. Named channels with flat text post streams.
 * Replaces the forum-style feed system (topics + threaded comments).
 *
 * Contains handlers and public API for:
 *   - Channel CRUD (create, get, delete)
 *   - Posts (create, list)
 *   - Subscriptions (subscribe, unsubscribe, sync)
 *   - Discovery (browse public index)
 */

#define DNA_ENGINE_CHANNELS_IMPL

#include "engine_includes.h"
#include "dht/client/dna_channels.h"
#include "database/channel_cache.h"
#include "database/channel_subscriptions_db.h"
#include "dht/shared/dht_channel_subscriptions.h"
#include <json-c/json.h>

#undef LOG_TAG
#define LOG_TAG "ENGINE_CHANNELS"

/* ============================================================================
 * DEFAULT CHANNEL CONSTANTS
 *
 * Deterministic UUIDs generated from SHA256("dna:default:<name>")
 * First 16 bytes formatted as UUID v4 (version nibble=4, variant=10xx)
 * ============================================================================ */

const char *DNA_DEFAULT_CHANNEL_UUIDS[DNA_DEFAULT_CHANNEL_COUNT] = {
    "94e8ed2b-92fe-46f5-bf44-65af1483e55e",  /* dna:default:general */
    "5b17b54a-43ed-475e-ad3b-d5fa46907210",  /* dna:default:technology */
    "11191eee-4173-4f30-a35d-de8fefbef7d8",  /* dna:default:help */
    "23a703c5-6f0d-4c35-bc8b-be44aea7697c",  /* dna:default:announcements */
    "ab187d8c-412d-4d1f-97f1-c9538fbda325",  /* dna:default:trading */
    "d1c51ab2-8e7c-4295-986f-fe214933403c",  /* dna:default:offtopic */
    "41c8b8fb-958a-4501-b76a-9e7e70cf3acc"   /* dna:default:cpunk */
};

const char *DNA_DEFAULT_CHANNEL_NAMES[DNA_DEFAULT_CHANNEL_COUNT] = {
    "General",
    "Technology",
    "Help",
    "Announcements",
    "Trading",
    "Off Topic",
    "Cpunk"
};

const char *DNA_DEFAULT_CHANNEL_DESCRIPTIONS[DNA_DEFAULT_CHANNEL_COUNT] = {
    "General discussion",
    "Technology and development",
    "Help and support",
    "Official announcements",
    "Trading and marketplace",
    "Off-topic conversation",
    "Cypherpunk culture and privacy"
};

/* ============================================================================
 * JSON SERIALIZATION HELPERS (static)
 * ============================================================================ */

/**
 * Serialize dna_channel_info_t to JSON string
 * @param info      Channel info struct
 * @param json_out  Output: heap-allocated JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
static int channel_info_to_json(const dna_channel_info_t *info, char **json_out) {
    if (!info || !json_out) return -1;
    *json_out = NULL;

    struct json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "channel_uuid", json_object_new_string(info->channel_uuid));
    json_object_object_add(root, "name", json_object_new_string(info->name));
    if (info->description) {
        json_object_object_add(root, "description", json_object_new_string(info->description));
    }
    json_object_object_add(root, "creator", json_object_new_string(info->creator_fingerprint));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)info->created_at));
    json_object_object_add(root, "is_public", json_object_new_boolean(info->is_public));
    json_object_object_add(root, "deleted", json_object_new_boolean(info->deleted));
    json_object_object_add(root, "deleted_at", json_object_new_int64((int64_t)info->deleted_at));
    json_object_object_add(root, "verified", json_object_new_boolean(info->verified));

    const char *str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if (str) {
        *json_out = strdup(str);
    }
    json_object_put(root);

    return (*json_out) ? 0 : -1;
}

/**
 * Deserialize JSON string to dna_channel_info_t
 * Caller must provide a pre-zeroed struct. description is heap-allocated.
 * @param json_str  JSON string
 * @param info_out  Output: pre-zeroed channel info struct
 * @return 0 on success, -1 on error
 */
static int channel_info_from_json(const char *json_str, dna_channel_info_t *info_out) {
    if (!json_str || !info_out) return -1;

    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    struct json_object *val = NULL;

    if (json_object_object_get_ex(root, "channel_uuid", &val))
        strncpy(info_out->channel_uuid, json_object_get_string(val), 36);

    if (json_object_object_get_ex(root, "name", &val))
        strncpy(info_out->name, json_object_get_string(val), 100);

    if (json_object_object_get_ex(root, "description", &val)) {
        info_out->description = strdup(json_object_get_string(val));
        if (!info_out->description) {
            json_object_put(root);
            return -1;
        }
    }

    if (json_object_object_get_ex(root, "creator", &val))
        strncpy(info_out->creator_fingerprint, json_object_get_string(val), 128);

    if (json_object_object_get_ex(root, "created_at", &val))
        info_out->created_at = (uint64_t)json_object_get_int64(val);

    if (json_object_object_get_ex(root, "is_public", &val))
        info_out->is_public = json_object_get_boolean(val);

    if (json_object_object_get_ex(root, "deleted", &val))
        info_out->deleted = json_object_get_boolean(val);

    if (json_object_object_get_ex(root, "deleted_at", &val))
        info_out->deleted_at = (uint64_t)json_object_get_int64(val);

    if (json_object_object_get_ex(root, "verified", &val))
        info_out->verified = json_object_get_boolean(val);

    json_object_put(root);
    return 0;
}

/**
 * Serialize dna_channel_post_info_t to JSON string
 */
static int post_info_to_json(const dna_channel_post_info_t *info, char **json_out) {
    if (!info || !json_out) return -1;
    *json_out = NULL;

    struct json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "post_uuid", json_object_new_string(info->post_uuid));
    json_object_object_add(root, "channel_uuid", json_object_new_string(info->channel_uuid));
    json_object_object_add(root, "author", json_object_new_string(info->author_fingerprint));
    if (info->body) {
        json_object_object_add(root, "body", json_object_new_string(info->body));
    }
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)info->created_at));
    json_object_object_add(root, "verified", json_object_new_boolean(info->verified));

    const char *str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if (str) {
        *json_out = strdup(str);
    }
    json_object_put(root);

    return (*json_out) ? 0 : -1;
}

/**
 * Deserialize JSON string to dna_channel_post_info_t
 * Caller must provide a pre-zeroed struct. body is heap-allocated.
 */
static int post_info_from_json(const char *json_str, dna_channel_post_info_t *info_out) {
    if (!json_str || !info_out) return -1;

    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    struct json_object *val = NULL;

    if (json_object_object_get_ex(root, "post_uuid", &val))
        strncpy(info_out->post_uuid, json_object_get_string(val), 36);

    if (json_object_object_get_ex(root, "channel_uuid", &val))
        strncpy(info_out->channel_uuid, json_object_get_string(val), 36);

    if (json_object_object_get_ex(root, "author", &val))
        strncpy(info_out->author_fingerprint, json_object_get_string(val), 128);

    if (json_object_object_get_ex(root, "body", &val)) {
        info_out->body = strdup(json_object_get_string(val));
        if (!info_out->body) {
            json_object_put(root);
            return -1;
        }
    }

    if (json_object_object_get_ex(root, "created_at", &val))
        info_out->created_at = (uint64_t)json_object_get_int64(val);

    if (json_object_object_get_ex(root, "verified", &val))
        info_out->verified = json_object_get_boolean(val);

    json_object_put(root);
    return 0;
}

/**
 * Serialize array of dna_channel_post_info_t to JSON array string
 */
static int post_infos_to_json(const dna_channel_post_info_t *infos, int count, char **json_out) {
    if (!json_out) return -1;
    *json_out = NULL;
    if (!infos || count <= 0) {
        *json_out = strdup("[]");
        return (*json_out) ? 0 : -1;
    }

    struct json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (int i = 0; i < count; i++) {
        struct json_object *obj = json_object_new_object();
        if (!obj) {
            json_object_put(arr);
            return -1;
        }
        json_object_object_add(obj, "post_uuid", json_object_new_string(infos[i].post_uuid));
        json_object_object_add(obj, "channel_uuid", json_object_new_string(infos[i].channel_uuid));
        json_object_object_add(obj, "author", json_object_new_string(infos[i].author_fingerprint));
        if (infos[i].body) {
            json_object_object_add(obj, "body", json_object_new_string(infos[i].body));
        }
        json_object_object_add(obj, "created_at", json_object_new_int64((int64_t)infos[i].created_at));
        json_object_object_add(obj, "verified", json_object_new_boolean(infos[i].verified));
        json_object_array_add(arr, obj);
    }

    const char *str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    if (str) {
        *json_out = strdup(str);
    }
    json_object_put(arr);

    return (*json_out) ? 0 : -1;
}

/**
 * Deserialize JSON array string to array of dna_channel_post_info_t
 * Caller must free returned array and body fields.
 */
static int post_infos_from_json(const char *json_str, dna_channel_post_info_t **infos_out, int *count_out) {
    if (!json_str || !infos_out || !count_out) return -1;
    *infos_out = NULL;
    *count_out = 0;

    struct json_object *root = json_tokener_parse(json_str);
    if (!root || !json_object_is_type(root, json_type_array)) {
        if (root) json_object_put(root);
        return -1;
    }

    int len = json_object_array_length(root);
    if (len == 0) {
        json_object_put(root);
        return 0;
    }

    dna_channel_post_info_t *infos = calloc(len, sizeof(dna_channel_post_info_t));
    if (!infos) {
        json_object_put(root);
        return -1;
    }

    int valid = 0;
    for (int i = 0; i < len; i++) {
        struct json_object *obj = json_object_array_get_idx(root, i);
        if (!obj) continue;

        struct json_object *val = NULL;

        if (json_object_object_get_ex(obj, "post_uuid", &val))
            strncpy(infos[valid].post_uuid, json_object_get_string(val), 36);

        if (json_object_object_get_ex(obj, "channel_uuid", &val))
            strncpy(infos[valid].channel_uuid, json_object_get_string(val), 36);

        if (json_object_object_get_ex(obj, "author", &val))
            strncpy(infos[valid].author_fingerprint, json_object_get_string(val), 128);

        if (json_object_object_get_ex(obj, "body", &val)) {
            infos[valid].body = strdup(json_object_get_string(val));
            if (!infos[valid].body) {
                /* Cleanup on failure */
                for (int k = 0; k < valid; k++) free(infos[k].body);
                free(infos);
                json_object_put(root);
                return -1;
            }
        }

        if (json_object_object_get_ex(obj, "created_at", &val))
            infos[valid].created_at = (uint64_t)json_object_get_int64(val);

        if (json_object_object_get_ex(obj, "verified", &val))
            infos[valid].verified = json_object_get_boolean(val);

        valid++;
    }

    json_object_put(root);
    *infos_out = infos;
    *count_out = valid;
    return 0;
}

/* ============================================================================
 * CHANNEL TASK HANDLERS
 * ============================================================================ */

void dna_handle_channel_create(dna_engine_t *engine, dna_task_t *task) {
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.channel(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                               NULL, task->user_data);
        return;
    }

    /* Create channel */
    char uuid_out[37] = {0};
    int ret = dna_channel_create(
        task->params.channel_create.name,
        task->params.channel_create.description,
        task->params.channel_create.is_public,
        engine->fingerprint,
        key->private_key,
        uuid_out
    );

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create channel: %d", ret);
        qgp_key_free(key);
        task->callback.channel(task->request_id, DNA_ERROR_INTERNAL,
                               NULL, task->user_data);
        return;
    }

    /* If public, register in the discovery index */
    if (task->params.channel_create.is_public) {
        int idx_ret = dna_channel_index_register(
            uuid_out,
            task->params.channel_create.name,
            task->params.channel_create.description,
            engine->fingerprint,
            key->private_key
        );
        if (idx_ret != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to register channel in index: %d", idx_ret);
        }
    }

    qgp_key_free(key);

    /* Auto-subscribe the creator */
    channel_subscriptions_db_subscribe(uuid_out);

    /* Fetch the created channel to return full info */
    dna_channel_t *channel = NULL;
    ret = dna_channel_get(uuid_out, &channel);

    if (ret != 0 || !channel) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch created channel: %d", ret);
        task->callback.channel(task->request_id, DNA_ERROR_INTERNAL,
                               NULL, task->user_data);
        return;
    }

    /* Convert dna_channel_t -> dna_channel_info_t */
    dna_channel_info_t *info = calloc(1, sizeof(dna_channel_info_t));
    if (!info) {
        dna_channel_free(channel);
        task->callback.channel(task->request_id, DNA_ERROR_INTERNAL,
                               NULL, task->user_data);
        return;
    }

    strncpy(info->channel_uuid, channel->uuid, 36);
    strncpy(info->name, channel->name, 100);
    if (channel->description) {
        info->description = strdup(channel->description);
    }
    strncpy(info->creator_fingerprint, channel->creator_fingerprint, 128);
    info->created_at = channel->created_at;
    info->is_public = channel->is_public;
    info->deleted = channel->deleted;
    info->deleted_at = channel->deleted_at;
    info->verified = (channel->signature_len > 0);

    dna_channel_free(channel);

    /* Cache the result */
    {
        char *json = NULL;
        if (channel_info_to_json(info, &json) == 0) {
            channel_cache_put_channel_json(info->channel_uuid, json,
                                            info->created_at, info->deleted ? 1 : 0);
            free(json);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Created channel: %s (%s)", uuid_out, info->name);
    task->callback.channel(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_channel_get(dna_engine_t *engine, dna_task_t *task) {
    const char *uuid = task->params.channel_by_uuid.uuid;

    /* Cache check — keep cached_json alive for stale fallback */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "channel:%s", uuid);

    char *cached_json = NULL;
    int cache_ret = channel_cache_get_channel_json(uuid, &cached_json);
    if (cache_ret == 0 && cached_json && !channel_cache_is_stale(cache_key)) {
        /* Fresh cache hit */
        dna_channel_info_t *info = calloc(1, sizeof(dna_channel_info_t));
        if (info && channel_info_from_json(cached_json, info) == 0) {
            free(cached_json);
            task->callback.channel(task->request_id, DNA_OK, info, task->user_data);
            return;
        }
        /* Parse failed - fall through to DHT fetch */
        free(info);
    }

    /* Fetch from DHT */
    dna_channel_t *channel = NULL;
    int ret = dna_channel_get(uuid, &channel);

    if (ret != 0 || !channel) {
        /* DHT failed — fallback to stale cache if available */
        if (cached_json) {
            dna_channel_info_t *info = calloc(1, sizeof(dna_channel_info_t));
            if (info && channel_info_from_json(cached_json, info) == 0) {
                free(cached_json);
                QGP_LOG_INFO(LOG_TAG, "Channel %.8s...: DHT unavailable, using cached metadata", uuid);
                task->callback.channel(task->request_id, DNA_OK, info, task->user_data);
                return;
            }
            free(info);
        }
        free(cached_json);
        int err = (ret == -2) ? DNA_ENGINE_ERROR_NOT_FOUND : DNA_ERROR_INTERNAL;
        task->callback.channel(task->request_id, err, NULL, task->user_data);
        if (channel) dna_channel_free(channel);
        return;
    }

    free(cached_json);  /* No longer need stale cache */

    /* Convert to public API format */
    dna_channel_info_t *info = calloc(1, sizeof(dna_channel_info_t));
    if (!info) {
        dna_channel_free(channel);
        task->callback.channel(task->request_id, DNA_ERROR_INTERNAL,
                               NULL, task->user_data);
        return;
    }

    strncpy(info->channel_uuid, channel->uuid, 36);
    strncpy(info->name, channel->name, 100);
    if (channel->description) {
        info->description = strdup(channel->description);
    }
    strncpy(info->creator_fingerprint, channel->creator_fingerprint, 128);
    info->created_at = channel->created_at;
    info->is_public = channel->is_public;
    info->deleted = channel->deleted;
    info->deleted_at = channel->deleted_at;
    info->verified = (channel->signature_len > 0);

    dna_channel_free(channel);

    /* Cache the fetched result */
    {
        char *json = NULL;
        if (channel_info_to_json(info, &json) == 0) {
            channel_cache_put_channel_json(info->channel_uuid, json,
                                            info->created_at, info->deleted ? 1 : 0);
            free(json);
        }
        channel_cache_mark_fresh(cache_key);
    }

    task->callback.channel(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_channel_delete(dna_engine_t *engine, dna_task_t *task) {
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  task->user_data);
        return;
    }

    int ret = dna_channel_delete(
        task->params.channel_by_uuid.uuid,
        engine->fingerprint,
        key->private_key
    );
    qgp_key_free(key);

    if (ret == -2) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NOT_FOUND,
                                  task->user_data);
        return;
    }

    if (ret == -3) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_PERMISSION,
                                  task->user_data);
        return;
    }

    if (ret != 0) {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted channel: %s", task->params.channel_by_uuid.uuid);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_channel_discover(dna_engine_t *engine, dna_task_t *task) {
    int days = task->params.channel_discover.days_back;
    if (days < 1) days = 1;
    if (days > DNA_CHANNEL_INDEX_DAYS_MAX) days = DNA_CHANNEL_INDEX_DAYS_MAX;

    dna_channel_t *channels = NULL;
    size_t count = 0;
    int ret = dna_channel_index_browse(days, &channels, &count);

    if (ret != 0 && ret != -2) {
        task->callback.channels(task->request_id, DNA_ERROR_INTERNAL,
                                NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        task->callback.channels(task->request_id, DNA_OK,
                                NULL, 0, task->user_data);
        if (channels) dna_channels_free(channels, count);
        return;
    }

    /* Convert array of dna_channel_t -> array of dna_channel_info_t */
    dna_channel_info_t *info = calloc(count, sizeof(dna_channel_info_t));
    if (!info) {
        dna_channels_free(channels, count);
        task->callback.channels(task->request_id, DNA_ERROR_INTERNAL,
                                NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].channel_uuid, channels[i].uuid, 36);
        strncpy(info[i].name, channels[i].name, 100);
        if (channels[i].description) {
            info[i].description = strdup(channels[i].description);
        }
        strncpy(info[i].creator_fingerprint, channels[i].creator_fingerprint, 128);
        info[i].created_at = channels[i].created_at;
        info[i].is_public = channels[i].is_public;
        info[i].deleted = channels[i].deleted;
        info[i].deleted_at = channels[i].deleted_at;
        info[i].verified = (channels[i].signature_len > 0);
    }

    dna_channels_free(channels, count);

    QGP_LOG_INFO(LOG_TAG, "Discovered %d channels (days_back=%d)",
                 (int)count, days);
    task->callback.channels(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_channel_post(dna_engine_t *engine, dna_task_t *task) {
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.channel_post_cb(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                       NULL, task->user_data);
        return;
    }

    char post_uuid_out[37] = {0};
    int ret = dna_channel_post_create(
        task->params.channel_post.channel_uuid,
        task->params.channel_post.body,
        engine->fingerprint,
        key->private_key,
        post_uuid_out
    );
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create post: %d", ret);
        task->callback.channel_post_cb(task->request_id, DNA_ERROR_INTERNAL,
                                       NULL, task->user_data);
        return;
    }

    /* Build response post info */
    dna_channel_post_info_t *info = calloc(1, sizeof(dna_channel_post_info_t));
    if (!info) {
        task->callback.channel_post_cb(task->request_id, DNA_ERROR_INTERNAL,
                                       NULL, task->user_data);
        return;
    }

    strncpy(info->post_uuid, post_uuid_out, 36);
    strncpy(info->channel_uuid, task->params.channel_post.channel_uuid, 36);
    strncpy(info->author_fingerprint, engine->fingerprint, 128);
    info->body = strdup(task->params.channel_post.body);
    info->created_at = (uint64_t)time(NULL);
    info->verified = true;  /* We just signed it */

    if (!info->body) {
        free(info);
        task->callback.channel_post_cb(task->request_id, DNA_ERROR_INTERNAL,
                                       NULL, task->user_data);
        return;
    }

    /* Invalidate posts cache for this channel so next fetch goes to DHT */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "posts:%s",
             task->params.channel_post.channel_uuid);
    channel_cache_invalidate(cache_key);

    QGP_LOG_INFO(LOG_TAG, "Created post %s in channel %.8s...",
                 post_uuid_out, task->params.channel_post.channel_uuid);
    task->callback.channel_post_cb(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_channel_get_posts(dna_engine_t *engine, dna_task_t *task) {
    const char *channel_uuid = task->params.channel_get_posts.uuid;
    int days_back = task->params.channel_get_posts.days_back;

    /* Cache check */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "posts:%s", channel_uuid);

    char *cached_json = NULL;
    int cached_count = 0;
    int cache_ret = channel_cache_get_posts(channel_uuid, &cached_json, &cached_count);
    if (cache_ret == 0 && cached_json) {
        if (!channel_cache_is_stale(cache_key)) {
            /* Fresh cache hit */
            dna_channel_post_info_t *infos = NULL;
            int parsed_count = 0;
            if (post_infos_from_json(cached_json, &infos, &parsed_count) == 0) {
                free(cached_json);
                task->callback.channel_posts(task->request_id, DNA_OK,
                                             infos, parsed_count, task->user_data);
                return;
            }
            /* Parse failed - fall through to DHT fetch */
        }
        free(cached_json);
    }

    /* Fetch from DHT */
    dna_channel_post_internal_t *posts = NULL;
    size_t count = 0;
    int ret = dna_channel_posts_get(channel_uuid, days_back, &posts, &count);

    if (ret != 0 && ret != -2) {
        task->callback.channel_posts(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        task->callback.channel_posts(task->request_id, DNA_OK,
                                     NULL, 0, task->user_data);
        if (posts) dna_channel_posts_free(posts, count);
        return;
    }

    /* Convert to public API format */
    dna_channel_post_info_t *info = calloc(count, sizeof(dna_channel_post_info_t));
    if (!info) {
        dna_channel_posts_free(posts, count);
        task->callback.channel_posts(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].post_uuid, posts[i].post_uuid, 36);
        strncpy(info[i].channel_uuid, posts[i].channel_uuid, 36);
        strncpy(info[i].author_fingerprint, posts[i].author_fingerprint, 128);
        if (posts[i].body) {
            info[i].body = strdup(posts[i].body);
        }
        info[i].created_at = posts[i].created_at;
        info[i].verified = (posts[i].signature_len > 0);

        if (posts[i].body && !info[i].body) {
            /* Cleanup on strdup failure */
            for (size_t k = 0; k < i; k++) {
                free(info[k].body);
            }
            free(info);
            dna_channel_posts_free(posts, count);
            task->callback.channel_posts(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
            return;
        }
    }

    dna_channel_posts_free(posts, count);

    /* Cache the fetched result */
    {
        char *json = NULL;
        if (post_infos_to_json(info, (int)count, &json) == 0) {
            channel_cache_put_posts(channel_uuid, json, (int)count);
            free(json);
        }
        channel_cache_mark_fresh(cache_key);
    }

    task->callback.channel_posts(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

/* ============================================================================
 * SUBSCRIPTION TASK HANDLERS
 * ============================================================================ */

void dna_handle_channel_get_subscriptions(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    channel_subscription_t *subs = NULL;
    int count = 0;

    int ret = channel_subscriptions_db_get_all(&subs, &count);
    if (ret != 0) {
        task->callback.channel_subscriptions(task->request_id, DNA_ERROR_INTERNAL,
                                             NULL, 0, task->user_data);
        return;
    }

    if (count == 0) {
        task->callback.channel_subscriptions(task->request_id, DNA_OK,
                                             NULL, 0, task->user_data);
        return;
    }

    /* Convert to public API format */
    dna_channel_subscription_info_t *info = calloc(count, sizeof(dna_channel_subscription_info_t));
    if (!info) {
        channel_subscriptions_db_free(subs, count);
        task->callback.channel_subscriptions(task->request_id, DNA_ERROR_INTERNAL,
                                             NULL, 0, task->user_data);
        return;
    }

    for (int i = 0; i < count; i++) {
        strncpy(info[i].channel_uuid, subs[i].channel_uuid, 36);
        info[i].subscribed_at = subs[i].subscribed_at;
        info[i].last_synced = subs[i].last_synced;
        info[i].last_read_at = subs[i].last_read_at;
    }

    channel_subscriptions_db_free(subs, count);
    task->callback.channel_subscriptions(task->request_id, DNA_OK, info, count, task->user_data);
}

void dna_handle_channel_sync_subs_to_dht(dna_engine_t *engine, dna_task_t *task) {
    if (!engine->fingerprint[0]) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    /* Get local subscriptions */
    channel_subscription_t *subs = NULL;
    int count = 0;
    int ret = channel_subscriptions_db_get_all(&subs, &count);
    if (ret != 0) {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Convert to DHT format */
    dht_channel_subscription_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(dht_channel_subscription_entry_t));
        if (!entries) {
            channel_subscriptions_db_free(subs, count);
            task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
            return;
        }
        for (int i = 0; i < count; i++) {
            strncpy(entries[i].channel_uuid, subs[i].channel_uuid, 36);
            entries[i].subscribed_at = subs[i].subscribed_at;
            entries[i].last_synced = subs[i].last_synced;
            entries[i].last_read_at = subs[i].last_read_at;
        }
    }
    channel_subscriptions_db_free(subs, count);

    /* Sync to DHT */
    ret = dht_channel_subscriptions_sync_to_dht(engine->fingerprint, entries, (size_t)count);
    if (entries) free(entries);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync channel subscriptions to DHT: %d", ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %d channel subscriptions to DHT", count);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_channel_sync_subs_from_dht(dna_engine_t *engine, dna_task_t *task) {
    if (!engine->fingerprint[0]) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    /* Fetch from DHT */
    dht_channel_subscription_entry_t *entries = NULL;
    size_t count = 0;
    int ret = dht_channel_subscriptions_sync_from_dht(engine->fingerprint, &entries, &count);

    if (ret == -2) {
        /* Not found - no subscriptions in DHT yet */
        QGP_LOG_INFO(LOG_TAG, "No channel subscriptions in DHT");
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
        return;
    }
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync channel subscriptions from DHT: %d", ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Merge with local: for each remote sub, if not local, add it */
    int added = 0;
    for (size_t i = 0; i < count; i++) {
        if (!channel_subscriptions_db_is_subscribed(entries[i].channel_uuid)) {
            int add_ret = channel_subscriptions_db_subscribe(entries[i].channel_uuid);
            if (add_ret == 0) {
                added++;
            }
        }
    }

    dht_channel_subscriptions_free(entries, count);

    QGP_LOG_INFO(LOG_TAG, "Synced channel subs from DHT: %zu total, %d new",
                 (size_t)count, added);

    /* Fire sync event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_CHANNEL_SUBS_SYNCED;
    event.data.channel_subs_synced.subscriptions_synced = added;
    dna_dispatch_event(engine, &event);

    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

/* ============================================================================
 * CHANNEL PUBLIC API - Async wrappers
 * ============================================================================ */

dna_request_id_t dna_engine_channel_create(
    dna_engine_t *engine,
    const char *name,
    const char *description,
    bool is_public,
    dna_channel_cb callback,
    void *user_data
) {
    if (!engine || !name || !name[0]) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.channel_create.name, name, sizeof(params.channel_create.name) - 1);
    if (description) {
        params.channel_create.description = strdup(description);
        if (!params.channel_create.description) return DNA_REQUEST_ID_INVALID;
    }
    params.channel_create.is_public = is_public;

    dna_task_callback_t cb = {0};
    cb.channel = callback;
    return dna_submit_task(engine, TASK_CHANNEL_CREATE, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_get(
    dna_engine_t *engine,
    const char *uuid,
    dna_channel_cb callback,
    void *user_data
) {
    if (!engine || !uuid) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.channel_by_uuid.uuid, uuid, 36);

    dna_task_callback_t cb = {0};
    cb.channel = callback;
    return dna_submit_task(engine, TASK_CHANNEL_GET, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_delete(
    dna_engine_t *engine,
    const char *uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !uuid) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.channel_by_uuid.uuid, uuid, 36);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CHANNEL_DELETE, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_discover(
    dna_engine_t *engine,
    int days_back,
    dna_channels_cb callback,
    void *user_data
) {
    if (!engine) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.channel_discover.days_back = days_back;

    dna_task_callback_t cb = {0};
    cb.channels = callback;
    return dna_submit_task(engine, TASK_CHANNEL_DISCOVER, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_post(
    dna_engine_t *engine,
    const char *channel_uuid,
    const char *body,
    dna_channel_post_cb callback,
    void *user_data
) {
    if (!engine || !channel_uuid || !body || !body[0]) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.channel_post.channel_uuid, channel_uuid, 36);
    params.channel_post.body = strdup(body);
    if (!params.channel_post.body) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.channel_post_cb = callback;
    return dna_submit_task(engine, TASK_CHANNEL_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_get_posts(
    dna_engine_t *engine,
    const char *channel_uuid,
    int days_back,
    dna_channel_posts_cb callback,
    void *user_data
) {
    if (!engine || !channel_uuid) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.channel_get_posts.uuid, channel_uuid, 36);
    params.channel_get_posts.days_back = days_back;

    dna_task_callback_t cb = {0};
    cb.channel_posts = callback;
    return dna_submit_task(engine, TASK_CHANNEL_GET_POSTS, &params, cb, user_data);
}

/* ============================================================================
 * CHANNEL PUBLIC API - Synchronous (database-direct)
 * ============================================================================ */

int dna_engine_channel_subscribe(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return -1;
    return channel_subscriptions_db_subscribe(channel_uuid);
}

int dna_engine_channel_unsubscribe(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return -1;
    return channel_subscriptions_db_unsubscribe(channel_uuid);
}

bool dna_engine_channel_is_subscribed(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return false;
    return channel_subscriptions_db_is_subscribed(channel_uuid);
}

int dna_engine_channel_mark_read(dna_engine_t *engine, const char *channel_uuid) {
    if (!engine || !channel_uuid) return -1;
    return channel_subscriptions_db_mark_read(channel_uuid, (uint64_t)time(NULL));
}

/* ============================================================================
 * CHANNEL PUBLIC API - Async subscription management
 * ============================================================================ */

dna_request_id_t dna_engine_channel_get_subscriptions(
    dna_engine_t *engine,
    dna_channel_subscriptions_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.channel_subscriptions = callback;
    return dna_submit_task(engine, TASK_CHANNEL_GET_SUBSCRIPTIONS, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_sync_subs_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CHANNEL_SYNC_SUBS_TO_DHT, &params, cb, user_data);
}

dna_request_id_t dna_engine_channel_sync_subs_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_CHANNEL_SYNC_SUBS_FROM_DHT, &params, cb, user_data);
}

/* ============================================================================
 * MEMORY CLEANUP
 * ============================================================================ */

void dna_free_channel_info(dna_channel_info_t *channel) {
    if (!channel) return;
    free(channel->description);
    free(channel);
}

void dna_free_channel_infos(dna_channel_info_t *channels, int count) {
    if (!channels) return;
    for (int i = 0; i < count; i++) {
        free(channels[i].description);
    }
    free(channels);
}

void dna_free_channel_post(dna_channel_post_info_t *post) {
    if (!post) return;
    free(post->body);
    free(post);
}

void dna_free_channel_posts(dna_channel_post_info_t *posts, int count) {
    if (!posts) return;
    for (int i = 0; i < count; i++) {
        free(posts[i].body);
    }
    free(posts);
}

void dna_free_channel_subscriptions(dna_channel_subscription_info_t *subs, int count) {
    (void)count;
    if (!subs) return;
    free(subs);
}
