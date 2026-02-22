/*
 * DNA Engine - Feed Module v2
 *
 * Topic-based public feeds with categories and tags.
 * Replaces v1 channel/post/vote system entirely.
 *
 * Contains handlers and public API:
 *   - dna_handle_feed_create_topic()
 *   - dna_handle_feed_get_topic()
 *   - dna_handle_feed_delete_topic()
 *   - dna_handle_feed_add_comment()
 *   - dna_handle_feed_get_comments()
 *   - dna_handle_feed_get_category()
 *   - dna_handle_feed_get_all()
 *   - dna_engine_feed_create_topic()
 *   - dna_engine_feed_get_topic()
 *   - dna_engine_feed_delete_topic()
 *   - dna_engine_feed_add_comment()
 *   - dna_engine_feed_get_comments()
 *   - dna_engine_feed_get_category()
 *   - dna_engine_feed_get_all()
 *   - dna_free_feed_topic()
 *   - dna_free_feed_topics()
 *   - dna_free_feed_comment()
 *   - dna_free_feed_comments()
 *
 * STATUS: v2 - Topic-based, no voting (voting deferred)
 */

#define DNA_ENGINE_FEED_IMPL

#include "engine_includes.h"
#include "dht/client/dna_feed.h"
#include "database/feed_cache.h"
#include <json-c/json.h>

/* Override LOG_TAG for this module (engine_includes.h defines DNA_ENGINE) */
#undef LOG_TAG
#define LOG_TAG "ENGINE_FEED"

/* ============================================================================
 * HELPER FUNCTIONS - JSON Parsing
 * ============================================================================ */

/**
 * Parse JSON array of strings into C array
 * @param json_str  JSON array string, e.g., "[\"tag1\", \"tag2\"]"
 * @param out       Output array of strings (caller owns)
 * @param count     Output count
 * @return 0 on success, -1 on error
 */
static int parse_json_string_array(const char *json_str, char ***out, int *count) {
    if (!out || !count) return -1;
    *out = NULL;
    *count = 0;

    if (!json_str || json_str[0] == '\0') return 0;

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

    *out = calloc(len, sizeof(char*));
    if (!*out) {
        json_object_put(root);
        return -1;
    }

    for (int i = 0; i < len; i++) {
        struct json_object *item = json_object_array_get_idx(root, i);
        if (json_object_is_type(item, json_type_string)) {
            (*out)[i] = strdup(json_object_get_string(item));
            if (!(*out)[i]) {
                /* Cleanup on strdup failure */
                for (int j = 0; j < i; j++) free((*out)[j]);
                free(*out);
                *out = NULL;
                json_object_put(root);
                return -1;
            }
            (*count)++;
        }
    }

    json_object_put(root);
    return 0;
}

/**
 * Free parsed string array
 */
static void free_string_array(char **arr, int count) {
    if (!arr) return;
    for (int i = 0; i < count; i++) {
        free(arr[i]);
    }
    free(arr);
}

/* ============================================================================
 * HELPER FUNCTIONS - Feed Cache JSON Serialization
 * ============================================================================ */

/**
 * Serialize a dna_feed_topic_info_t to a JSON string.
 * @param info      Topic info struct
 * @param json_out  Output: heap-allocated JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
static int topic_info_to_json(const dna_feed_topic_info_t *info, char **json_out) {
    if (!info || !json_out) return -1;
    *json_out = NULL;

    struct json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "topic_uuid", json_object_new_string(info->topic_uuid));
    json_object_object_add(root, "author", json_object_new_string(info->author_fingerprint));
    json_object_object_add(root, "title", json_object_new_string(info->title ? info->title : ""));
    if (info->body) {
        json_object_object_add(root, "body", json_object_new_string(info->body));
    }
    json_object_object_add(root, "category_id", json_object_new_string(info->category_id));

    /* Tags array */
    struct json_object *tags_arr = json_object_new_array();
    for (int i = 0; i < info->tag_count && i < DNA_FEED_MAX_TAGS; i++) {
        json_object_array_add(tags_arr, json_object_new_string(info->tags[i]));
    }
    json_object_object_add(root, "tags", tags_arr);
    json_object_object_add(root, "tag_count", json_object_new_int(info->tag_count));

    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)info->created_at));
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
 * Deserialize a JSON string to a dna_feed_topic_info_t.
 * Caller must provide a pre-zeroed struct. title and body are heap-allocated.
 * @param json_str  JSON string
 * @param info_out  Output: pre-zeroed topic info struct
 * @return 0 on success, -1 on error
 */
static int topic_info_from_json(const char *json_str, dna_feed_topic_info_t *info_out) {
    if (!json_str || !info_out) return -1;

    struct json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    struct json_object *val = NULL;

    if (json_object_object_get_ex(root, "topic_uuid", &val))
        strncpy(info_out->topic_uuid, json_object_get_string(val), 36);

    if (json_object_object_get_ex(root, "author", &val))
        strncpy(info_out->author_fingerprint, json_object_get_string(val), 128);

    if (json_object_object_get_ex(root, "title", &val)) {
        info_out->title = strdup(json_object_get_string(val));
        if (!info_out->title) {
            json_object_put(root);
            return -1;
        }
    }

    if (json_object_object_get_ex(root, "body", &val)) {
        info_out->body = strdup(json_object_get_string(val));
        if (!info_out->body) {
            free(info_out->title);
            info_out->title = NULL;
            json_object_put(root);
            return -1;
        }
    }

    if (json_object_object_get_ex(root, "category_id", &val))
        strncpy(info_out->category_id, json_object_get_string(val), 64);

    if (json_object_object_get_ex(root, "tags", &val) && json_object_is_type(val, json_type_array)) {
        int len = json_object_array_length(val);
        info_out->tag_count = (len > DNA_FEED_MAX_TAGS) ? DNA_FEED_MAX_TAGS : len;
        for (int i = 0; i < info_out->tag_count; i++) {
            struct json_object *tag = json_object_array_get_idx(val, i);
            if (tag) strncpy(info_out->tags[i], json_object_get_string(tag), 32);
        }
    } else if (json_object_object_get_ex(root, "tag_count", &val)) {
        info_out->tag_count = json_object_get_int(val);
    }

    if (json_object_object_get_ex(root, "created_at", &val))
        info_out->created_at = (uint64_t)json_object_get_int64(val);

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
 * Serialize an array of dna_feed_comment_info_t to a JSON array string.
 * @param infos     Array of comment info structs
 * @param count     Number of comments
 * @param json_out  Output: heap-allocated JSON string (caller must free)
 * @return 0 on success, -1 on error
 */
static int comment_infos_to_json(const dna_feed_comment_info_t *infos, int count, char **json_out) {
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

        json_object_object_add(obj, "comment_uuid", json_object_new_string(infos[i].comment_uuid));
        json_object_object_add(obj, "topic_uuid", json_object_new_string(infos[i].topic_uuid));
        json_object_object_add(obj, "parent_comment_uuid", json_object_new_string(infos[i].parent_comment_uuid));
        json_object_object_add(obj, "author", json_object_new_string(infos[i].author_fingerprint));
        json_object_object_add(obj, "body", json_object_new_string(infos[i].body ? infos[i].body : ""));
        json_object_object_add(obj, "created_at", json_object_new_int64((int64_t)infos[i].created_at));
        json_object_object_add(obj, "verified", json_object_new_boolean(infos[i].verified));

        /* Mentions array */
        struct json_object *mentions_arr = json_object_new_array();
        for (int j = 0; j < infos[i].mention_count && j < DNA_FEED_MAX_MENTIONS; j++) {
            json_object_array_add(mentions_arr, json_object_new_string(infos[i].mentions[j]));
        }
        json_object_object_add(obj, "mentions", mentions_arr);
        json_object_object_add(obj, "mention_count", json_object_new_int(infos[i].mention_count));

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
 * Deserialize a JSON array string to an array of dna_feed_comment_info_t.
 * body fields are heap-allocated (caller must free).
 * @param json_str   JSON array string
 * @param infos_out  Output: heap-allocated array (caller must free)
 * @param count_out  Output: number of comments
 * @return 0 on success, -1 on error
 */
static int comment_infos_from_json(const char *json_str, dna_feed_comment_info_t **infos_out, int *count_out) {
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

    dna_feed_comment_info_t *infos = calloc(len, sizeof(dna_feed_comment_info_t));
    if (!infos) {
        json_object_put(root);
        return -1;
    }

    int valid = 0;
    for (int i = 0; i < len; i++) {
        struct json_object *obj = json_object_array_get_idx(root, i);
        if (!obj) continue;

        struct json_object *val = NULL;

        if (json_object_object_get_ex(obj, "comment_uuid", &val))
            strncpy(infos[valid].comment_uuid, json_object_get_string(val), 36);

        if (json_object_object_get_ex(obj, "topic_uuid", &val))
            strncpy(infos[valid].topic_uuid, json_object_get_string(val), 36);

        if (json_object_object_get_ex(obj, "parent_comment_uuid", &val))
            strncpy(infos[valid].parent_comment_uuid, json_object_get_string(val), 36);

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

        if (json_object_object_get_ex(obj, "mentions", &val) && json_object_is_type(val, json_type_array)) {
            int mlen = json_object_array_length(val);
            infos[valid].mention_count = (mlen > DNA_FEED_MAX_MENTIONS) ? DNA_FEED_MAX_MENTIONS : mlen;
            for (int j = 0; j < infos[valid].mention_count; j++) {
                struct json_object *m = json_object_array_get_idx(val, j);
                if (m) strncpy(infos[valid].mentions[j], json_object_get_string(m), 128);
            }
        } else if (json_object_object_get_ex(obj, "mention_count", &val)) {
            infos[valid].mention_count = json_object_get_int(val);
        }

        valid++;
    }

    json_object_put(root);
    *infos_out = infos;
    *count_out = valid;
    return 0;
}

/* ============================================================================
 * FEED v2 INTERNAL HANDLERS
 * ============================================================================ */

void dna_handle_feed_create_topic(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_topic(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  NULL, task->user_data);
        return;
    }

    /* Parse tags JSON */
    char **tags = NULL;
    int tag_count = 0;
    if (task->params.feed_create_topic.tags_json) {
        if (parse_json_string_array(task->params.feed_create_topic.tags_json,
                                    &tags, &tag_count) != 0) {
            qgp_key_free(key);
            task->callback.feed_topic(task->request_id, DNA_ERROR_INVALID_ARG,
                                      NULL, task->user_data);
            return;
        }
    }

    /* Create topic */
    char uuid_out[37] = {0};
    int ret = dna_feed_topic_create(
        dht,
        task->params.feed_create_topic.title,
        task->params.feed_create_topic.body,
        task->params.feed_create_topic.category,
        (const char **)tags,
        tag_count,
        engine->fingerprint,
        key->private_key,
        uuid_out
    );

    free_string_array(tags, tag_count);
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create topic: %d", ret);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    /* Fetch the created topic to return full info */
    dna_feed_topic_t *topic = NULL;
    ret = dna_feed_topic_get(dht, uuid_out, &topic);

    if (ret != 0 || !topic) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch created topic: %d", ret);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    /* Convert to public API format */
    dna_feed_topic_info_t *info = calloc(1, sizeof(dna_feed_topic_info_t));
    if (!info) {
        dna_feed_topic_free(topic);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    strncpy(info->topic_uuid, topic->topic_uuid, 36);
    strncpy(info->author_fingerprint, topic->author_fingerprint, 128);
    info->title = strdup(topic->title);
    info->body = strdup(topic->body);
    strncpy(info->category_id, topic->category_id, 64);
    info->tag_count = topic->tag_count;
    for (int i = 0; i < topic->tag_count && i < DNA_FEED_MAX_TAGS; i++) {
        strncpy(info->tags[i], topic->tags[i], 32);
    }
    info->created_at = topic->created_at;
    info->deleted = topic->deleted;
    info->deleted_at = topic->deleted_at;
    info->verified = (topic->signature_len > 0);

    if (!info->title || !info->body) {
        free(info->title);
        free(info->body);
        free(info);
        dna_feed_topic_free(topic);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    dna_feed_topic_free(topic);

    /* Cache: store new topic */
    {
        char *json = NULL;
        if (topic_info_to_json(info, &json) == 0) {
            feed_cache_put_topic_json(info->topic_uuid, json, info->category_id,
                                      info->created_at, info->deleted ? 1 : 0);
            free(json);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Created topic: %s", uuid_out);
    task->callback.feed_topic(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_feed_get_topic(dna_engine_t *engine, dna_task_t *task) {
    const char *uuid = task->params.feed_get_topic.uuid;

    /* Cache check */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "topic:%s", uuid);

    char *cached_json = NULL;
    int cache_ret = feed_cache_get_topic_json(uuid, &cached_json);
    if (cache_ret == 0 && cached_json) {
        dna_feed_topic_info_t *info = calloc(1, sizeof(dna_feed_topic_info_t));
        if (info && topic_info_from_json(cached_json, info) == 0) {
            free(cached_json);
            task->callback.feed_topic(task->request_id, DNA_OK, info, task->user_data);

            /* Background revalidation if stale */
            if (feed_cache_is_stale(cache_key)) {
                dna_task_params_t rp = {0};
                strncpy(rp.feed_revalidate_topic.uuid, uuid, 36);
                dna_submit_task(engine, TASK_FEED_REVALIDATE_TOPIC, &rp,
                                (dna_task_callback_t){0}, NULL);
            }
            return;
        }
        /* Parse failed - fall through to DHT fetch */
        free(info);
        free(cached_json);
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topic(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, task->user_data);
        return;
    }

    dna_feed_topic_t *topic = NULL;
    int ret = dna_feed_topic_get(dht, uuid, &topic);

    if (ret == -2) {
        /* Not found */
        task->callback.feed_topic(task->request_id, DNA_ENGINE_ERROR_NOT_FOUND,
                                  NULL, task->user_data);
        return;
    }

    if (ret != 0 || !topic) {
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    /* Verify signature - for now just check if signature present
     * Full verification would require keyserver lookup for author's public key */
    bool verified = (topic->signature_len > 0);

    /* Convert to public API format */
    dna_feed_topic_info_t *info = calloc(1, sizeof(dna_feed_topic_info_t));
    if (!info) {
        dna_feed_topic_free(topic);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    strncpy(info->topic_uuid, topic->topic_uuid, 36);
    strncpy(info->author_fingerprint, topic->author_fingerprint, 128);
    info->title = strdup(topic->title);
    info->body = strdup(topic->body);
    strncpy(info->category_id, topic->category_id, 64);
    info->tag_count = topic->tag_count;
    for (int i = 0; i < topic->tag_count && i < DNA_FEED_MAX_TAGS; i++) {
        strncpy(info->tags[i], topic->tags[i], 32);
    }
    info->created_at = topic->created_at;
    info->deleted = topic->deleted;
    info->deleted_at = topic->deleted_at;
    info->verified = verified;

    if (!info->title || !info->body) {
        free(info->title);
        free(info->body);
        free(info);
        dna_feed_topic_free(topic);
        task->callback.feed_topic(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    dna_feed_topic_free(topic);

    /* Cache the fetched result */
    {
        char *json = NULL;
        if (topic_info_to_json(info, &json) == 0) {
            feed_cache_put_topic_json(info->topic_uuid, json, info->category_id,
                                      info->created_at, info->deleted ? 1 : 0);
            free(json);
        }
        feed_cache_update_meta(cache_key);
    }

    task->callback.feed_topic(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_feed_delete_topic(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  task->user_data);
        return;
    }

    int ret = dna_feed_topic_delete(
        dht,
        task->params.feed_delete_topic.uuid,
        engine->fingerprint,
        key->private_key
    );
    qgp_key_free(key);

    if (ret == -2) {
        /* Not found */
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NOT_FOUND,
                                  task->user_data);
        return;
    }

    if (ret == -3) {
        /* Not authorized (not author) */
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_PERMISSION,
                                  task->user_data);
        return;
    }

    if (ret != 0) {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    /* Cache: remove deleted topic */
    feed_cache_delete_topic(task->params.feed_delete_topic.uuid);

    QGP_LOG_INFO(LOG_TAG, "Deleted topic: %s", task->params.feed_delete_topic.uuid);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_feed_add_comment(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.feed_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                    NULL, task->user_data);
        return;
    }

    /* Parse mentions JSON */
    char **mentions = NULL;
    int mention_count = 0;
    if (task->params.feed_add_comment.mentions_json) {
        if (parse_json_string_array(task->params.feed_add_comment.mentions_json,
                                    &mentions, &mention_count) != 0) {
            qgp_key_free(key);
            task->callback.feed_comment(task->request_id, DNA_ERROR_INVALID_ARG,
                                        NULL, task->user_data);
            return;
        }
    }

    /* Add comment (optionally as reply) */
    char uuid_out[37] = {0};
    const char *parent_uuid = task->params.feed_add_comment.parent_comment_uuid[0]
        ? task->params.feed_add_comment.parent_comment_uuid : NULL;
    int ret = dna_feed_comment_add(
        dht,
        task->params.feed_add_comment.topic_uuid,
        parent_uuid,
        task->params.feed_add_comment.body,
        (const char **)mentions,
        mention_count,
        engine->fingerprint,
        key->private_key,
        uuid_out
    );

    free_string_array(mentions, mention_count);
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add comment: %d", ret);
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
        return;
    }

    /* Return success response with comment info */
    dna_feed_comment_info_t *info = calloc(1, sizeof(dna_feed_comment_info_t));
    if (!info) {
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
        return;
    }

    strncpy(info->comment_uuid, uuid_out, 36);
    strncpy(info->topic_uuid, task->params.feed_add_comment.topic_uuid, 36);
    if (task->params.feed_add_comment.parent_comment_uuid[0]) {
        strncpy(info->parent_comment_uuid,
                task->params.feed_add_comment.parent_comment_uuid, 36);
    }
    strncpy(info->author_fingerprint, engine->fingerprint, 128);
    info->body = strdup(task->params.feed_add_comment.body);
    info->created_at = (uint64_t)time(NULL);
    info->verified = true;  /* We just signed it */

    if (!info->body) {
        free(info);
        task->callback.feed_comment(task->request_id, DNA_ERROR_INTERNAL,
                                    NULL, task->user_data);
        return;
    }

    /* Cache: invalidate comments for this topic */
    feed_cache_invalidate_comments(task->params.feed_add_comment.topic_uuid);

    QGP_LOG_INFO(LOG_TAG, "Added comment to topic: %s",
                 task->params.feed_add_comment.topic_uuid);
    task->callback.feed_comment(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_feed_get_comments(dna_engine_t *engine, dna_task_t *task) {
    const char *topic_uuid = task->params.feed_get_comments.topic_uuid;

    /* Cache check */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "comments:%s", topic_uuid);

    char *cached_json = NULL;
    int cached_count = 0;
    int cache_ret = feed_cache_get_comments(topic_uuid, &cached_json, &cached_count);
    if (cache_ret == 0 && cached_json) {
        dna_feed_comment_info_t *infos = NULL;
        int parsed_count = 0;
        if (comment_infos_from_json(cached_json, &infos, &parsed_count) == 0) {
            free(cached_json);
            task->callback.feed_comments(task->request_id, DNA_OK,
                                         infos, parsed_count, task->user_data);

            /* Background revalidation if stale */
            if (feed_cache_is_stale(cache_key)) {
                dna_task_params_t rp = {0};
                strncpy(rp.feed_revalidate_comments.topic_uuid, topic_uuid, 36);
                dna_submit_task(engine, TASK_FEED_REVALIDATE_COMMENTS, &rp,
                                (dna_task_callback_t){0}, NULL);
            }
            return;
        }
        /* Parse failed - fall through to DHT fetch */
        free(cached_json);
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, topic_uuid, &comments, &count);

    if (ret != 0 && ret != -2) {
        task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        /* No comments */
        task->callback.feed_comments(task->request_id, DNA_OK,
                                     NULL, 0, task->user_data);
        if (comments) dna_feed_comments_free(comments, count);
        return;
    }

    /* Convert to public API format */
    dna_feed_comment_info_t *info = calloc(count, sizeof(dna_feed_comment_info_t));
    if (!info) {
        dna_feed_comments_free(comments, count);
        task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].comment_uuid, comments[i].comment_uuid, 36);
        strncpy(info[i].topic_uuid, comments[i].topic_uuid, 36);
        if (comments[i].parent_comment_uuid[0]) {
            strncpy(info[i].parent_comment_uuid, comments[i].parent_comment_uuid, 36);
        }
        strncpy(info[i].author_fingerprint, comments[i].author_fingerprint, 128);
        info[i].body = strdup(comments[i].body);
        info[i].mention_count = comments[i].mention_count;
        for (int j = 0; j < comments[i].mention_count && j < DNA_FEED_MAX_MENTIONS; j++) {
            strncpy(info[i].mentions[j], comments[i].mentions[j], 128);
        }
        info[i].created_at = comments[i].created_at;
        /* Verify signature - for now just check if signature present */
        info[i].verified = (comments[i].signature_len > 0);

        if (!info[i].body) {
            /* Cleanup on strdup failure */
            for (size_t k = 0; k < i; k++) {
                free(info[k].body);
            }
            free(info);
            dna_feed_comments_free(comments, count);
            task->callback.feed_comments(task->request_id, DNA_ERROR_INTERNAL,
                                         NULL, 0, task->user_data);
            return;
        }
    }

    dna_feed_comments_free(comments, count);

    /* Cache the fetched result */
    {
        char *json = NULL;
        if (comment_infos_to_json(info, (int)count, &json) == 0) {
            feed_cache_put_comments(topic_uuid, json, (int)count);
            free(json);
        }
        feed_cache_update_meta(cache_key);
    }

    task->callback.feed_comments(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_feed_get_category(dna_engine_t *engine, dna_task_t *task) {
    const char *category = task->params.feed_get_category.category;
    int days = task->params.feed_get_category.days_back;
    if (days < 1) days = 1;
    if (days > 30) days = 30;

    /* Cache check */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "index:%.48s:%d", category, days);

    char **cached_jsons = NULL;
    int cached_count = 0;
    int cache_ret = feed_cache_get_topics_by_category(category, days,
                                                       &cached_jsons, &cached_count);
    if (cache_ret == 0 && cached_count > 0) {
        dna_feed_topic_info_t *info = calloc(cached_count, sizeof(dna_feed_topic_info_t));
        if (info) {
            int valid_count = 0;
            for (int i = 0; i < cached_count; i++) {
                if (topic_info_from_json(cached_jsons[i], &info[valid_count]) == 0) {
                    valid_count++;
                }
            }
            feed_cache_free_json_list(cached_jsons, cached_count);
            task->callback.feed_topics(task->request_id, DNA_OK, info,
                                       valid_count, task->user_data);

            /* Background revalidation if stale */
            if (feed_cache_is_stale(cache_key)) {
                dna_task_params_t rp = {0};
                strncpy(rp.feed_revalidate_index.category, category, 64);
                rp.feed_revalidate_index.days_back = days;
                strncpy(rp.feed_revalidate_index.cache_key, cache_key, 63);
                dna_submit_task(engine, TASK_FEED_REVALIDATE_INDEX, &rp,
                                (dna_task_callback_t){0}, NULL);
            }
            return;
        }
        feed_cache_free_json_list(cached_jsons, cached_count);
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topics(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                   NULL, 0, task->user_data);
        return;
    }

    dna_feed_index_entry_t *entries = NULL;
    size_t count = 0;
    int ret = dna_feed_index_get_category(dht, category, days, &entries, &count);

    if (ret != 0 && ret != -2) {
        task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        /* No topics */
        task->callback.feed_topics(task->request_id, DNA_OK,
                                   NULL, 0, task->user_data);
        if (entries) dna_feed_index_entries_free(entries, count);
        return;
    }

    /* Convert to public API format */
    dna_feed_topic_info_t *info = calloc(count, sizeof(dna_feed_topic_info_t));
    if (!info) {
        dna_feed_index_entries_free(entries, count);
        task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].topic_uuid, entries[i].topic_uuid, 36);
        strncpy(info[i].author_fingerprint, entries[i].author_fingerprint, 128);
        info[i].title = strdup(entries[i].title);
        info[i].body = NULL;  /* Index only has title preview */
        strncpy(info[i].category_id, entries[i].category_id, 64);
        info[i].created_at = entries[i].created_at;
        info[i].deleted = entries[i].deleted;
        info[i].verified = false;  /* Index entries not individually verified */

        if (!info[i].title) {
            /* Cleanup on strdup failure */
            for (size_t k = 0; k < i; k++) {
                free(info[k].title);
            }
            free(info);
            dna_feed_index_entries_free(entries, count);
            task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                       NULL, 0, task->user_data);
            return;
        }
    }

    dna_feed_index_entries_free(entries, count);

    /* Cache the fetched results */
    for (int i = 0; i < (int)count; i++) {
        char *json = NULL;
        if (topic_info_to_json(&info[i], &json) == 0) {
            feed_cache_put_topic_json(info[i].topic_uuid, json, info[i].category_id,
                                      info[i].created_at, info[i].deleted ? 1 : 0);
            free(json);
        }
    }
    feed_cache_update_meta(cache_key);

    task->callback.feed_topics(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_feed_get_all(dna_engine_t *engine, dna_task_t *task) {
    int days = task->params.feed_get_all.days_back;
    if (days < 1) days = 1;
    if (days > 30) days = 30;

    /* Cache check */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "index:all:%d", days);

    char **cached_jsons = NULL;
    int cached_count = 0;
    int cache_ret = feed_cache_get_topics_all(days, &cached_jsons, &cached_count);
    if (cache_ret == 0 && cached_count > 0) {
        dna_feed_topic_info_t *info = calloc(cached_count, sizeof(dna_feed_topic_info_t));
        if (info) {
            int valid_count = 0;
            for (int i = 0; i < cached_count; i++) {
                if (topic_info_from_json(cached_jsons[i], &info[valid_count]) == 0) {
                    valid_count++;
                }
            }
            feed_cache_free_json_list(cached_jsons, cached_count);
            task->callback.feed_topics(task->request_id, DNA_OK, info,
                                       valid_count, task->user_data);

            /* Background revalidation if stale */
            if (feed_cache_is_stale(cache_key)) {
                dna_task_params_t rp = {0};
                rp.feed_revalidate_index.days_back = days;
                strncpy(rp.feed_revalidate_index.cache_key, cache_key, 63);
                dna_submit_task(engine, TASK_FEED_REVALIDATE_INDEX, &rp,
                                (dna_task_callback_t){0}, NULL);
            }
            return;
        }
        feed_cache_free_json_list(cached_jsons, cached_count);
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topics(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                   NULL, 0, task->user_data);
        return;
    }

    dna_feed_index_entry_t *entries = NULL;
    size_t count = 0;
    int ret = dna_feed_index_get_all(dht, days, &entries, &count);

    if (ret != 0 && ret != -2) {
        task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        /* No topics */
        task->callback.feed_topics(task->request_id, DNA_OK,
                                   NULL, 0, task->user_data);
        if (entries) dna_feed_index_entries_free(entries, count);
        return;
    }

    /* Convert to public API format */
    dna_feed_topic_info_t *info = calloc(count, sizeof(dna_feed_topic_info_t));
    if (!info) {
        dna_feed_index_entries_free(entries, count);
        task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].topic_uuid, entries[i].topic_uuid, 36);
        strncpy(info[i].author_fingerprint, entries[i].author_fingerprint, 128);
        info[i].title = strdup(entries[i].title);
        info[i].body = NULL;  /* Index only has title preview */
        strncpy(info[i].category_id, entries[i].category_id, 64);
        info[i].created_at = entries[i].created_at;
        info[i].deleted = entries[i].deleted;
        info[i].verified = false;  /* Index entries not individually verified */

        if (!info[i].title) {
            /* Cleanup on strdup failure */
            for (size_t k = 0; k < i; k++) {
                free(info[k].title);
            }
            free(info);
            dna_feed_index_entries_free(entries, count);
            task->callback.feed_topics(task->request_id, DNA_ERROR_INTERNAL,
                                       NULL, 0, task->user_data);
            return;
        }
    }

    dna_feed_index_entries_free(entries, count);

    /* Cache the fetched results */
    for (int i = 0; i < (int)count; i++) {
        char *json = NULL;
        if (topic_info_to_json(&info[i], &json) == 0) {
            feed_cache_put_topic_json(info[i].topic_uuid, json, info[i].category_id,
                                      info[i].created_at, info[i].deleted ? 1 : 0);
            free(json);
        }
    }
    feed_cache_update_meta(cache_key);

    task->callback.feed_topics(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_feed_reindex_topic(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  task->user_data);
        return;
    }

    const char *uuid = task->params.feed_reindex_topic.uuid;
    QGP_LOG_INFO(LOG_TAG, "Reindexing topic: %s", uuid);

    /* Fetch the topic */
    dna_feed_topic_t *topic = NULL;
    int ret = dna_feed_topic_get(dht, uuid, &topic);

    if (ret == -2 || !topic) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NOT_FOUND,
                                  task->user_data);
        return;
    }

    if (ret != 0) {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    /* Create index entry from topic */
    dna_feed_index_entry_t entry = {0};
    strncpy(entry.topic_uuid, topic->topic_uuid, DNA_FEED_UUID_LEN - 1);
    strncpy(entry.author_fingerprint, topic->author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);
    strncpy(entry.title, topic->title, DNA_FEED_MAX_TITLE_LEN);
    strncpy(entry.category_id, topic->category_id, DNA_FEED_CATEGORY_ID_LEN - 1);
    entry.created_at = topic->created_at;
    entry.deleted = topic->deleted;

    dna_feed_topic_free(topic);

    /* Add to index */
    ret = dna_feed_index_add(dht, &entry);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add topic to index: %d", ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Topic reindexed: %s", uuid);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

/* ============================================================================
 * FEED v2 PUBLIC API
 * ============================================================================ */

dna_request_id_t dna_engine_feed_create_topic(
    dna_engine_t *engine,
    const char *title,
    const char *body,
    const char *category,
    const char *tags_json,
    dna_feed_topic_cb callback,
    void *user_data
) {
    if (!engine || !title || !body || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_create_topic.title, title, 200);
    params.feed_create_topic.body = strdup(body);
    if (!params.feed_create_topic.body) return DNA_REQUEST_ID_INVALID;

    if (category) {
        strncpy(params.feed_create_topic.category, category, 64);
    } else {
        strncpy(params.feed_create_topic.category, "general", 64);
    }

    if (tags_json) {
        params.feed_create_topic.tags_json = strdup(tags_json);
        if (!params.feed_create_topic.tags_json) {
            free(params.feed_create_topic.body);
            return DNA_REQUEST_ID_INVALID;
        }
    }

    dna_task_callback_t cb = {0};
    cb.feed_topic = callback;
    return dna_submit_task(engine, TASK_FEED_CREATE_TOPIC, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_get_topic(
    dna_engine_t *engine,
    const char *uuid,
    dna_feed_topic_cb callback,
    void *user_data
) {
    if (!engine || !uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_get_topic.uuid, uuid, 36);

    dna_task_callback_t cb = {0};
    cb.feed_topic = callback;
    return dna_submit_task(engine, TASK_FEED_GET_TOPIC, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_delete_topic(
    dna_engine_t *engine,
    const char *uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_delete_topic.uuid, uuid, 36);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_FEED_DELETE_TOPIC, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_reindex_topic(
    dna_engine_t *engine,
    const char *uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_reindex_topic.uuid, uuid, 36);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_FEED_REINDEX_TOPIC, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_add_comment(
    dna_engine_t *engine,
    const char *topic_uuid,
    const char *parent_comment_uuid,
    const char *body,
    const char *mentions_json,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !topic_uuid || !body || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_add_comment.topic_uuid, topic_uuid, 36);
    if (parent_comment_uuid && parent_comment_uuid[0]) {
        strncpy(params.feed_add_comment.parent_comment_uuid, parent_comment_uuid, 36);
    }
    params.feed_add_comment.body = strdup(body);
    if (!params.feed_add_comment.body) return DNA_REQUEST_ID_INVALID;

    if (mentions_json) {
        params.feed_add_comment.mentions_json = strdup(mentions_json);
        if (!params.feed_add_comment.mentions_json) {
            free(params.feed_add_comment.body);
            return DNA_REQUEST_ID_INVALID;
        }
    }

    dna_task_callback_t cb = {0};
    cb.feed_comment = callback;
    return dna_submit_task(engine, TASK_FEED_ADD_COMMENT, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_get_comments(
    dna_engine_t *engine,
    const char *topic_uuid,
    dna_feed_comments_cb callback,
    void *user_data
) {
    if (!engine || !topic_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_get_comments.topic_uuid, topic_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.feed_comments = callback;
    return dna_submit_task(engine, TASK_FEED_GET_COMMENTS, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_get_category(
    dna_engine_t *engine,
    const char *category,
    int days_back,
    dna_feed_topics_cb callback,
    void *user_data
) {
    if (!engine || !category || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_get_category.category, category, 64);
    params.feed_get_category.days_back = days_back;

    dna_task_callback_t cb = {0};
    cb.feed_topics = callback;
    return dna_submit_task(engine, TASK_FEED_GET_CATEGORY, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_get_all(
    dna_engine_t *engine,
    int days_back,
    dna_feed_topics_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.feed_get_all.days_back = days_back;

    dna_task_callback_t cb = {0};
    cb.feed_topics = callback;
    return dna_submit_task(engine, TASK_FEED_GET_ALL, &params, cb, user_data);
}

/* ============================================================================
 * MEMORY CLEANUP
 * ============================================================================ */

void dna_free_feed_topic(dna_feed_topic_info_t *topic) {
    if (!topic) return;
    free(topic->title);
    free(topic->body);
    free(topic);
}

void dna_free_feed_topics(dna_feed_topic_info_t *topics, int count) {
    if (!topics) return;
    for (int i = 0; i < count; i++) {
        free(topics[i].title);
        free(topics[i].body);
    }
    free(topics);
}

void dna_free_feed_comment(dna_feed_comment_info_t *comment) {
    if (!comment) return;
    free(comment->body);
    free(comment);
}

void dna_free_feed_comments(dna_feed_comment_info_t *comments, int count) {
    if (!comments) return;
    for (int i = 0; i < count; i++) {
        free(comments[i].body);
    }
    free(comments);
}

/* ============================================================================
 * FEED v2 SUBSCRIPTIONS - v0.6.91+
 *
 * Local SQLite storage + DHT sync for multi-device support.
 * ============================================================================ */

#include "database/feed_subscriptions_db.h"
#include "dht/shared/dht_feed_subscriptions.h"
#include "dht/core/dht_listen.h"

/* ============================================================================
 * SUBSCRIPTION TASK HANDLERS
 * ============================================================================ */

void dna_handle_feed_get_subscriptions(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;

    feed_subscription_t *subs = NULL;
    int count = 0;

    int ret = feed_subscriptions_db_get_all(&subs, &count);
    if (ret != 0) {
        task->callback.feed_subscriptions(task->request_id, DNA_ERROR_INTERNAL,
                                          NULL, 0, task->user_data);
        return;
    }

    if (count == 0) {
        task->callback.feed_subscriptions(task->request_id, DNA_OK,
                                          NULL, 0, task->user_data);
        return;
    }

    /* Convert to public API format */
    dna_feed_subscription_info_t *info = calloc(count, sizeof(dna_feed_subscription_info_t));
    if (!info) {
        feed_subscriptions_db_free(subs, count);
        task->callback.feed_subscriptions(task->request_id, DNA_ERROR_INTERNAL,
                                          NULL, 0, task->user_data);
        return;
    }

    for (int i = 0; i < count; i++) {
        strncpy(info[i].topic_uuid, subs[i].topic_uuid, 36);
        info[i].subscribed_at = subs[i].subscribed_at;
        info[i].last_synced = subs[i].last_synced;
    }

    feed_subscriptions_db_free(subs, count);
    task->callback.feed_subscriptions(task->request_id, DNA_OK, info, count, task->user_data);
}

void dna_handle_feed_sync_subscriptions_to_dht(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NETWORK, task->user_data);
        return;
    }

    if (!engine->fingerprint[0]) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    /* Get local subscriptions */
    feed_subscription_t *subs = NULL;
    int count = 0;
    int ret = feed_subscriptions_db_get_all(&subs, &count);
    if (ret != 0) {
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Convert to DHT format */
    dht_feed_subscription_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(dht_feed_subscription_entry_t));
        if (!entries) {
            feed_subscriptions_db_free(subs, count);
            task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
            return;
        }
        for (int i = 0; i < count; i++) {
            strncpy(entries[i].topic_uuid, subs[i].topic_uuid, 36);
            entries[i].subscribed_at = subs[i].subscribed_at;
            entries[i].last_synced = subs[i].last_synced;
        }
    }
    feed_subscriptions_db_free(subs, count);

    /* Sync to DHT */
    ret = dht_feed_subscriptions_sync_to_dht(dht, engine->fingerprint, entries, (size_t)count);
    if (entries) free(entries);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync subscriptions to DHT: %d", ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Synced %d subscriptions to DHT", count);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_feed_sync_subscriptions_from_dht(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NETWORK, task->user_data);
        return;
    }

    if (!engine->fingerprint[0]) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY, task->user_data);
        return;
    }

    /* Fetch from DHT */
    dht_feed_subscription_entry_t *entries = NULL;
    size_t count = 0;
    int ret = dht_feed_subscriptions_sync_from_dht(dht, engine->fingerprint, &entries, &count);

    if (ret == -2) {
        /* Not found - no subscriptions in DHT yet */
        QGP_LOG_INFO(LOG_TAG, "No subscriptions in DHT");
        task->callback.completion(task->request_id, DNA_OK, task->user_data);
        return;
    }
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync subscriptions from DHT: %d", ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL, task->user_data);
        return;
    }

    /* Merge with local (add any missing) */
    int added = 0;
    for (size_t i = 0; i < count; i++) {
        if (!feed_subscriptions_db_is_subscribed(entries[i].topic_uuid)) {
            /* Add to local DB with original timestamp */
            /* Note: feed_subscriptions_db_subscribe sets current time, so we may want
               a different internal function. For now, just subscribe. */
            int add_ret = feed_subscriptions_db_subscribe(entries[i].topic_uuid);
            if (add_ret == 0) {
                added++;
            }
        }
    }

    dht_feed_subscriptions_free(entries, count);

    QGP_LOG_INFO(LOG_TAG, "Synced from DHT: %zu total, %d new", count, added);

    /* Fire sync event */
    dna_event_t event = {0};
    event.type = DNA_EVENT_FEED_SUBSCRIPTIONS_SYNCED;
    event.data.feed_subscriptions_synced.subscriptions_synced = added;
    dna_dispatch_event(engine, &event);

    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

/* ============================================================================
 * SUBSCRIPTION PUBLIC API
 * ============================================================================ */

int dna_engine_feed_subscribe(dna_engine_t *engine, const char *topic_uuid) {
    if (!engine || !topic_uuid) return -1;
    if (strlen(topic_uuid) < 36) return -1;

    return feed_subscriptions_db_subscribe(topic_uuid);
}

int dna_engine_feed_unsubscribe(dna_engine_t *engine, const char *topic_uuid) {
    if (!engine || !topic_uuid) return -1;
    if (strlen(topic_uuid) < 36) return -1;

    return feed_subscriptions_db_unsubscribe(topic_uuid);
}

int dna_engine_feed_is_subscribed(dna_engine_t *engine, const char *topic_uuid) {
    if (!engine || !topic_uuid) return 0;
    if (strlen(topic_uuid) < 36) return 0;

    return feed_subscriptions_db_is_subscribed(topic_uuid) ? 1 : 0;
}

dna_request_id_t dna_engine_feed_get_subscriptions(
    dna_engine_t *engine,
    dna_feed_subscriptions_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.feed_subscriptions = callback;
    return dna_submit_task(engine, TASK_FEED_GET_SUBSCRIPTIONS, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_sync_subscriptions_to_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_FEED_SYNC_SUBSCRIPTIONS_TO_DHT, &params, cb, user_data);
}

dna_request_id_t dna_engine_feed_sync_subscriptions_from_dht(
    dna_engine_t *engine,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_FEED_SYNC_SUBSCRIPTIONS_FROM_DHT, &params, cb, user_data);
}

/* ============================================================================
 * SUBSCRIPTION LISTENERS (Real-time comment updates)
 * ============================================================================ */

/* Listener context for topic comments */
typedef struct {
    dna_engine_t *engine;
    char topic_uuid[37];
} feed_topic_listener_ctx_t;

/**
 * DHT listen callback - fires DNA_EVENT_FEED_TOPIC_COMMENT when new comments
 */
static bool feed_topic_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data)
{
    feed_topic_listener_ctx_t *ctx = (feed_topic_listener_ctx_t *)user_data;
    if (!ctx || !ctx->engine) {
        return false;  /* Stop listening */
    }

    /* Only fire event for new values, not expirations */
    if (!expired && value && value_len > 0) {
        QGP_LOG_INFO(LOG_TAG, "New comment on topic %.8s...", ctx->topic_uuid);

        /* Fire event - we don't parse the comment here, just notify UI to refresh */
        dna_event_t event = {0};
        event.type = DNA_EVENT_FEED_TOPIC_COMMENT;
        strncpy(event.data.feed_topic_comment.topic_uuid, ctx->topic_uuid, 36);
        /* comment_uuid and author_fingerprint would require parsing - leave empty for now */

        dna_dispatch_event(ctx->engine, &event);
    }

    return true;  /* Continue listening */
}

size_t dna_engine_feed_listen_topic_comments(dna_engine_t *engine, const char *topic_uuid) {
    if (!engine || !topic_uuid || strlen(topic_uuid) < 36) {
        return 0;
    }

    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        return 0;
    }

    /* Generate comments key */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "dna:feeds:topic:%s:comments", topic_uuid);

    /* Allocate listener context */
    feed_topic_listener_ctx_t *ctx = calloc(1, sizeof(feed_topic_listener_ctx_t));
    if (!ctx) {
        return 0;
    }
    ctx->engine = engine;
    strncpy(ctx->topic_uuid, topic_uuid, 36);

    /* Start DHT listener */
    size_t token = dht_listen(dht, (const uint8_t *)comments_key, strlen(comments_key),
                              feed_topic_listen_callback, ctx);

    if (token == 0) {
        free(ctx);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Started comment listener for topic %.8s... (token=%zu)",
                 topic_uuid, token);
    return token;
}

void dna_engine_feed_cancel_topic_listener(dna_engine_t *engine, const char *topic_uuid) {
    if (!engine || !topic_uuid) return;

    /* Note: We don't track listener tokens by topic_uuid currently.
       For a full implementation, we'd need a hash map of topic_uuid -> token.
       For now, this is a placeholder. */
    QGP_LOG_WARN(LOG_TAG, "feed_cancel_topic_listener not fully implemented yet");
    (void)topic_uuid;
}

int dna_engine_feed_listen_all_subscriptions(dna_engine_t *engine) {
    if (!engine) return -1;

    feed_subscription_t *subs = NULL;
    int count = 0;

    int ret = feed_subscriptions_db_get_all(&subs, &count);
    if (ret != 0 || count == 0) {
        return 0;
    }

    int started = 0;
    for (int i = 0; i < count; i++) {
        size_t token = dna_engine_feed_listen_topic_comments(engine, subs[i].topic_uuid);
        if (token > 0) {
            started++;
        }
    }

    feed_subscriptions_db_free(subs, count);

    QGP_LOG_INFO(LOG_TAG, "Started %d topic comment listeners", started);
    return started;
}

void dna_engine_feed_cancel_all_topic_listeners(dna_engine_t *engine) {
    if (!engine) return;

    /* Note: We'd need to track all active listener tokens to cancel them.
       For a full implementation, we'd iterate through stored tokens and cancel.
       For now, this is a placeholder. */
    QGP_LOG_WARN(LOG_TAG, "feed_cancel_all_topic_listeners not fully implemented yet");
}

/* ============================================================================
 * SUBSCRIPTION MEMORY CLEANUP
 * ============================================================================ */

void dna_free_feed_subscriptions(dna_feed_subscription_info_t *subscriptions, int count) {
    (void)count;  /* No dynamically allocated members */
    if (subscriptions) {
        free(subscriptions);
    }
}

/* ============================================================================
 * FEED CACHE REVALIDATION HANDLERS (v0.6.121+)
 *
 * Background fire-and-forget tasks. No callback - use events to notify UI.
 * ============================================================================ */

void dna_handle_feed_revalidate_index(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        QGP_LOG_WARN(LOG_TAG, "revalidate_index: no DHT context");
        return;
    }

    const char *category = task->params.feed_revalidate_index.category;
    int days = task->params.feed_revalidate_index.days_back;
    const char *cache_key = task->params.feed_revalidate_index.cache_key;

    if (days < 1) days = 1;
    if (days > 30) days = 30;

    dna_feed_index_entry_t *entries = NULL;
    size_t count = 0;
    int ret;

    if (category[0] == '\0') {
        ret = dna_feed_index_get_all(dht, days, &entries, &count);
    } else {
        ret = dna_feed_index_get_category(dht, category, days, &entries, &count);
    }

    if (ret != 0 || count == 0) {
        if (ret != 0 && ret != -2) {
            QGP_LOG_WARN(LOG_TAG, "revalidate_index: DHT fetch failed: %d", ret);
        }
        if (entries) dna_feed_index_entries_free(entries, count);
        return;
    }

    /* Cache each index entry */
    for (size_t i = 0; i < count; i++) {
        dna_feed_topic_info_t tmp = {0};
        strncpy(tmp.topic_uuid, entries[i].topic_uuid, 36);
        strncpy(tmp.author_fingerprint, entries[i].author_fingerprint, 128);
        tmp.title = entries[i].title;   /* Borrow pointer - not freed */
        tmp.body = NULL;                /* Index entries have no body */
        strncpy(tmp.category_id, entries[i].category_id, 64);
        tmp.created_at = entries[i].created_at;
        tmp.deleted = entries[i].deleted;
        tmp.verified = false;

        char *json = NULL;
        if (topic_info_to_json(&tmp, &json) == 0) {
            feed_cache_put_topic_json(tmp.topic_uuid, json, tmp.category_id,
                                      tmp.created_at, tmp.deleted ? 1 : 0);
            free(json);
        }
    }

    dna_feed_index_entries_free(entries, count);
    feed_cache_update_meta(cache_key);

    /* Fire event to notify UI */
    dna_event_t event = {0};
    event.type = DNA_EVENT_FEED_CACHE_UPDATED;
    strncpy(event.data.feed_cache_updated.cache_key, cache_key, 63);
    dna_dispatch_event(engine, &event);

    QGP_LOG_INFO(LOG_TAG, "Revalidated index cache '%s': %zu entries", cache_key, count);
}

void dna_handle_feed_revalidate_topic(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        QGP_LOG_WARN(LOG_TAG, "revalidate_topic: no DHT context");
        return;
    }

    const char *uuid = task->params.feed_revalidate_topic.uuid;

    dna_feed_topic_t *topic = NULL;
    int ret = dna_feed_topic_get(dht, uuid, &topic);

    if (ret != 0 || !topic) {
        if (ret != -2) {
            QGP_LOG_WARN(LOG_TAG, "revalidate_topic: DHT fetch failed for %s: %d", uuid, ret);
        }
        return;
    }

    /* Convert to public API format */
    dna_feed_topic_info_t info = {0};
    strncpy(info.topic_uuid, topic->topic_uuid, 36);
    strncpy(info.author_fingerprint, topic->author_fingerprint, 128);
    info.title = strdup(topic->title);
    info.body = strdup(topic->body);
    strncpy(info.category_id, topic->category_id, 64);
    info.tag_count = topic->tag_count;
    for (int i = 0; i < topic->tag_count && i < DNA_FEED_MAX_TAGS; i++) {
        strncpy(info.tags[i], topic->tags[i], 32);
    }
    info.created_at = topic->created_at;
    info.deleted = topic->deleted;
    info.deleted_at = topic->deleted_at;
    info.verified = (topic->signature_len > 0);

    dna_feed_topic_free(topic);

    if (!info.title || !info.body) {
        free(info.title);
        free(info.body);
        QGP_LOG_WARN(LOG_TAG, "revalidate_topic: strdup failed for %s", uuid);
        return;
    }

    /* Serialize and cache */
    char *json = NULL;
    if (topic_info_to_json(&info, &json) == 0) {
        feed_cache_put_topic_json(info.topic_uuid, json, info.category_id,
                                  info.created_at, info.deleted ? 1 : 0);
        free(json);
    }

    free(info.title);
    free(info.body);

    /* Update meta and fire event */
    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "topic:%s", uuid);
    feed_cache_update_meta(cache_key);

    dna_event_t event = {0};
    event.type = DNA_EVENT_FEED_CACHE_UPDATED;
    strncpy(event.data.feed_cache_updated.cache_key, cache_key, 63);
    dna_dispatch_event(engine, &event);

    QGP_LOG_INFO(LOG_TAG, "Revalidated topic cache: %s", uuid);
}

void dna_handle_feed_revalidate_comments(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        QGP_LOG_WARN(LOG_TAG, "revalidate_comments: no DHT context");
        return;
    }

    const char *topic_uuid = task->params.feed_revalidate_comments.topic_uuid;

    char cache_key[64];
    snprintf(cache_key, sizeof(cache_key), "comments:%s", topic_uuid);

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, topic_uuid, &comments, &count);

    if (ret != 0 && ret != -2) {
        QGP_LOG_WARN(LOG_TAG, "revalidate_comments: DHT fetch failed for %s: %d", topic_uuid, ret);
        /* Still update meta + fire event for "no comments" */
        feed_cache_update_meta(cache_key);
        dna_event_t event = {0};
        event.type = DNA_EVENT_FEED_CACHE_UPDATED;
        strncpy(event.data.feed_cache_updated.cache_key, cache_key, 63);
        dna_dispatch_event(engine, &event);
        return;
    }

    if (ret == -2 || count == 0) {
        /* No comments - cache empty and update meta */
        feed_cache_put_comments(topic_uuid, "[]", 0);
        feed_cache_update_meta(cache_key);
        if (comments) dna_feed_comments_free(comments, count);

        dna_event_t event = {0};
        event.type = DNA_EVENT_FEED_CACHE_UPDATED;
        strncpy(event.data.feed_cache_updated.cache_key, cache_key, 63);
        dna_dispatch_event(engine, &event);

        QGP_LOG_INFO(LOG_TAG, "Revalidated comments cache (empty): %s", topic_uuid);
        return;
    }

    /* Convert to public API format */
    dna_feed_comment_info_t *infos = calloc(count, sizeof(dna_feed_comment_info_t));
    if (!infos) {
        dna_feed_comments_free(comments, count);
        return;
    }

    int valid = 0;
    for (size_t i = 0; i < count; i++) {
        strncpy(infos[valid].comment_uuid, comments[i].comment_uuid, 36);
        strncpy(infos[valid].topic_uuid, comments[i].topic_uuid, 36);
        if (comments[i].parent_comment_uuid[0]) {
            strncpy(infos[valid].parent_comment_uuid, comments[i].parent_comment_uuid, 36);
        }
        strncpy(infos[valid].author_fingerprint, comments[i].author_fingerprint, 128);
        infos[valid].body = strdup(comments[i].body);
        infos[valid].mention_count = comments[i].mention_count;
        for (int j = 0; j < comments[i].mention_count && j < DNA_FEED_MAX_MENTIONS; j++) {
            strncpy(infos[valid].mentions[j], comments[i].mentions[j], 128);
        }
        infos[valid].created_at = comments[i].created_at;
        infos[valid].verified = (comments[i].signature_len > 0);

        if (!infos[valid].body) {
            /* Cleanup on strdup failure */
            for (int k = 0; k < valid; k++) free(infos[k].body);
            free(infos);
            dna_feed_comments_free(comments, count);
            return;
        }
        valid++;
    }

    dna_feed_comments_free(comments, count);

    /* Serialize and cache */
    char *json = NULL;
    if (comment_infos_to_json(infos, valid, &json) == 0) {
        feed_cache_put_comments(topic_uuid, json, valid);
        free(json);
    }

    /* Free info bodies */
    for (int i = 0; i < valid; i++) free(infos[i].body);
    free(infos);

    feed_cache_update_meta(cache_key);

    dna_event_t event = {0};
    event.type = DNA_EVENT_FEED_CACHE_UPDATED;
    strncpy(event.data.feed_cache_updated.cache_key, cache_key, 63);
    dna_dispatch_event(engine, &event);

    QGP_LOG_INFO(LOG_TAG, "Revalidated comments cache: %s (%d comments)", topic_uuid, valid);
}
