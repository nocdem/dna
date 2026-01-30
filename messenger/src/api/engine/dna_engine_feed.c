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

    QGP_LOG_INFO(LOG_TAG, "Created topic: %s", uuid_out);
    task->callback.feed_topic(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_feed_get_topic(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topic(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, task->user_data);
        return;
    }

    dna_feed_topic_t *topic = NULL;
    int ret = dna_feed_topic_get(dht, task->params.feed_get_topic.uuid, &topic);

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

    /* Add comment */
    char uuid_out[37] = {0};
    int ret = dna_feed_comment_add(
        dht,
        task->params.feed_add_comment.topic_uuid,
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

    QGP_LOG_INFO(LOG_TAG, "Added comment to topic: %s",
                 task->params.feed_add_comment.topic_uuid);
    task->callback.feed_comment(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_feed_get_comments(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                     NULL, 0, task->user_data);
        return;
    }

    dna_feed_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_feed_comments_get(dht, task->params.feed_get_comments.topic_uuid,
                                    &comments, &count);

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
    task->callback.feed_comments(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_feed_get_category(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topics(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                   NULL, 0, task->user_data);
        return;
    }

    int days = task->params.feed_get_category.days_back;
    if (days < 1) days = 1;
    if (days > 30) days = 30;

    dna_feed_index_entry_t *entries = NULL;
    size_t count = 0;
    int ret = dna_feed_index_get_category(dht, task->params.feed_get_category.category,
                                          days, &entries, &count);

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
    task->callback.feed_topics(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

void dna_handle_feed_get_all(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.feed_topics(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                   NULL, 0, task->user_data);
        return;
    }

    int days = task->params.feed_get_all.days_back;
    if (days < 1) days = 1;
    if (days > 30) days = 30;

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
    task->callback.feed_topics(task->request_id, DNA_OK, info, (int)count, task->user_data);
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

dna_request_id_t dna_engine_feed_add_comment(
    dna_engine_t *engine,
    const char *topic_uuid,
    const char *body,
    const char *mentions_json,
    dna_feed_comment_cb callback,
    void *user_data
) {
    if (!engine || !topic_uuid || !body || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.feed_add_comment.topic_uuid, topic_uuid, 36);
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
