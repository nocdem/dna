/*
 * DNA Engine - Wall Module
 *
 * Personal wall posts with DHT storage and local cache.
 *
 * Contains handlers and public API:
 *   - dna_handle_wall_post()
 *   - dna_handle_wall_delete()
 *   - dna_handle_wall_load()
 *   - dna_handle_wall_timeline()
 *   - dna_engine_wall_post()
 *   - dna_engine_wall_delete()
 *   - dna_engine_wall_load()
 *   - dna_engine_wall_timeline()
 *   - dna_free_wall_posts()
 *
 * STATUS: v0.6.135+ - MVP text-only wall posts
 */

#define DNA_ENGINE_WALL_IMPL

#include "engine_includes.h"
#include "dht/client/dna_wall.h"
#include "database/wall_cache.h"

/* Override LOG_TAG for this module (engine_includes.h defines DNA_ENGINE) */
#undef LOG_TAG
#define LOG_TAG "ENGINE_WALL"

/* ============================================================================
 * HELPER FUNCTIONS - Name Resolution
 * ============================================================================ */

/**
 * Resolve display name for a fingerprint.
 * Tries: 1) DHT profile (registered_name), 2) Keyserver cache, 3) fingerprint prefix.
 *
 * @param fingerprint  128-char hex fingerprint
 * @param name_out     Output buffer (min 65 chars)
 * @param name_out_size Size of output buffer
 */
static void resolve_author_name(const char *fingerprint, char *name_out, size_t name_out_size) {
    if (!fingerprint || !name_out || name_out_size == 0) return;
    name_out[0] = '\0';

    /* Try 1: DHT profile (registered_name) */
    dna_unified_identity_t *identity = NULL;
    if (profile_manager_get_profile(fingerprint, &identity) == 0 && identity) {
        if (identity->registered_name[0] != '\0') {
            strncpy(name_out, identity->registered_name, name_out_size - 1);
            name_out[name_out_size - 1] = '\0';
            dna_identity_free(identity);
            return;
        }
        dna_identity_free(identity);
    }

    /* Try 2: Keyserver cache */
    char cached_name[64] = {0};
    if (keyserver_cache_get_name(fingerprint, cached_name, sizeof(cached_name)) == 0 &&
        cached_name[0] != '\0') {
        strncpy(name_out, cached_name, name_out_size - 1);
        name_out[name_out_size - 1] = '\0';
        return;
    }

    /* Fallback: fingerprint prefix (first 12 chars) */
    size_t prefix_len = 12;
    if (prefix_len >= name_out_size) prefix_len = name_out_size - 1;
    strncpy(name_out, fingerprint, prefix_len);
    name_out[prefix_len] = '\0';
}

/**
 * Convert a dna_wall_post_t (DHT/cache struct) to dna_wall_post_info_t (public API struct).
 *
 * @param post      Source DHT post
 * @param info      Output public API info (must be zeroed by caller)
 */
static void wall_post_to_info(const dna_wall_post_t *post, dna_wall_post_info_t *info) {
    strncpy(info->uuid, post->uuid, 36);
    info->uuid[36] = '\0';
    strncpy(info->author_fingerprint, post->author_fingerprint, 128);
    info->author_fingerprint[128] = '\0';
    strncpy(info->text, post->text, sizeof(info->text) - 1);
    info->text[sizeof(info->text) - 1] = '\0';
    info->image_json = post->image_json ? strdup(post->image_json) : NULL;
    info->timestamp = post->timestamp;
    info->verified = post->verified;

    /* Resolve author display name */
    resolve_author_name(post->author_fingerprint, info->author_name, sizeof(info->author_name));
}

/* ============================================================================
 * TASK HANDLERS
 * ============================================================================ */

void dna_handle_wall_post(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.wall_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, task->user_data);
        return;
    }

    dna_wall_post_t out_post = {0};
    int ret;
    if (task->params.wall_post.image_json) {
        ret = dna_wall_post_with_image(dht, engine->fingerprint, key->private_key,
                                        task->params.wall_post.text,
                                        task->params.wall_post.image_json, &out_post);
    } else {
        ret = dna_wall_post(dht, engine->fingerprint, key->private_key,
                            task->params.wall_post.text, &out_post);
    }
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to post to wall: %d", ret);
        task->callback.wall_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
        return;
    }

    /* Invalidate cache so next load refreshes from DHT */
    wall_cache_delete_by_author(engine->fingerprint);

    /* Convert to public API format */
    dna_wall_post_info_t *info = calloc(1, sizeof(dna_wall_post_info_t));
    if (!info) {
        free(out_post.image_json);
        task->callback.wall_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
        return;
    }

    wall_post_to_info(&out_post, info);
    free(out_post.image_json); /* wall_post_to_info already strdup'd for info */

    QGP_LOG_INFO(LOG_TAG, "Wall post created: %s", info->uuid);
    task->callback.wall_post(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_wall_delete(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  task->user_data);
        return;
    }

    int ret = dna_wall_delete(dht, engine->fingerprint, key->private_key,
                              task->params.wall_delete.uuid);
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete wall post %s: %d",
                      task->params.wall_delete.uuid, ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    /* Remove from local cache */
    wall_cache_delete_post(task->params.wall_delete.uuid);

    QGP_LOG_INFO(LOG_TAG, "Wall post deleted: %s", task->params.wall_delete.uuid);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_wall_load(dna_engine_t *engine, dna_task_t *task) {
    const char *fp = task->params.wall_load.fingerprint;

    /* Check cache first */
    if (!wall_cache_is_stale(fp)) {
        dna_wall_post_t *cached_posts = NULL;
        size_t cached_count = 0;
        int cache_ret = wall_cache_load(fp, &cached_posts, &cached_count);

        if (cache_ret == 0 && cached_posts && cached_count > 0) {
            /* Cache hit and fresh - convert and return */
            dna_wall_post_info_t *info = calloc(cached_count, sizeof(dna_wall_post_info_t));
            if (!info) {
                wall_cache_free_posts(cached_posts, cached_count);
                task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                          NULL, 0, task->user_data);
                return;
            }

            for (size_t i = 0; i < cached_count; i++) {
                wall_post_to_info(&cached_posts[i], &info[i]);
            }

            wall_cache_free_posts(cached_posts, cached_count);
            QGP_LOG_INFO(LOG_TAG, "Wall load (cache hit): %s, %zu posts", fp, cached_count);
            task->callback.wall_posts(task->request_id, DNA_OK,
                                      info, (int)cached_count, task->user_data);
            return;
        }

        if (cached_posts) wall_cache_free_posts(cached_posts, cached_count);
    }

    /* Cache miss or stale - fetch from DHT */
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.wall_posts(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, 0, task->user_data);
        return;
    }

    dna_wall_t wall = {0};
    int ret = dna_wall_load(dht, fp, &wall);

    if (ret == -2) {
        /* Not found - return empty list (not an error) */
        QGP_LOG_INFO(LOG_TAG, "Wall load: %s - no posts found", fp);
        task->callback.wall_posts(task->request_id, DNA_OK,
                                  NULL, 0, task->user_data);
        return;
    }

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load wall for %s: %d", fp, ret);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Store in cache */
    wall_cache_store(fp, wall.posts, wall.post_count);
    wall_cache_update_meta(fp);

    /* Convert to public API format */
    int count = (int)wall.post_count;
    dna_wall_post_info_t *info = NULL;

    if (count > 0) {
        info = calloc(count, sizeof(dna_wall_post_info_t));
        if (!info) {
            dna_wall_free(&wall);
            task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
            return;
        }

        for (int i = 0; i < count; i++) {
            wall_post_to_info(&wall.posts[i], &info[i]);
        }
    }

    dna_wall_free(&wall);

    QGP_LOG_INFO(LOG_TAG, "Wall load (DHT): %s, %d posts", fp, count);
    task->callback.wall_posts(task->request_id, DNA_OK, info, count, task->user_data);
}

void dna_handle_wall_timeline(dna_engine_t *engine, dna_task_t *task) {
    if (!engine->identity_loaded) {
        task->callback.wall_posts(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Build fingerprint list: own + all contacts */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Timeline: contacts_db_init failed, using own wall only");
    }

    contact_list_t *list = NULL;
    contacts_db_list(&list);

    /* Count: own fingerprint + contacts */
    size_t fp_count = 1 + (list ? list->count : 0);
    const char **fingerprints = calloc(fp_count, sizeof(const char *));
    if (!fingerprints) {
        if (list) contacts_db_free_list(list);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Own fingerprint first */
    fingerprints[0] = engine->fingerprint;

    /* Add contacts */
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            fingerprints[1 + i] = list->contacts[i].identity;
        }
    }

    /* Try cache first */
    dna_wall_post_t *cached_posts = NULL;
    size_t cached_count = 0;
    int cache_ret = wall_cache_load_timeline(fingerprints, fp_count,
                                             &cached_posts, &cached_count);

    if (cache_ret == 0 && cached_posts && cached_count > 0) {
        /* Cache has data - return it */
        dna_wall_post_info_t *info = calloc(cached_count, sizeof(dna_wall_post_info_t));
        if (!info) {
            wall_cache_free_posts(cached_posts, cached_count);
            free(fingerprints);
            if (list) contacts_db_free_list(list);
            task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
            return;
        }

        for (size_t i = 0; i < cached_count; i++) {
            wall_post_to_info(&cached_posts[i], &info[i]);
        }

        wall_cache_free_posts(cached_posts, cached_count);
        free(fingerprints);
        if (list) contacts_db_free_list(list);

        QGP_LOG_INFO(LOG_TAG, "Timeline (cache): %zu posts", cached_count);
        task->callback.wall_posts(task->request_id, DNA_OK,
                                  info, (int)cached_count, task->user_data);
        return;
    }

    if (cached_posts) wall_cache_free_posts(cached_posts, cached_count);

    /* Cache empty - fetch each contact's wall from DHT */
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        free(fingerprints);
        if (list) contacts_db_free_list(list);
        task->callback.wall_posts(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Collect all posts from all contacts */
    dna_wall_post_info_t *all_posts = NULL;
    int total_count = 0;
    int all_capacity = 0;

    for (size_t fi = 0; fi < fp_count; fi++) {
        const char *fp = fingerprints[fi];

        dna_wall_t wall = {0};
        int ret = dna_wall_load(dht, fp, &wall);

        if (ret != 0 || wall.post_count == 0) {
            dna_wall_free(&wall);
            continue;
        }

        /* Cache the fetched wall */
        wall_cache_store(fp, wall.posts, wall.post_count);
        wall_cache_update_meta(fp);

        /* Grow output array */
        int new_total = total_count + (int)wall.post_count;
        if (new_total > all_capacity) {
            int new_cap = (new_total > all_capacity * 2) ? new_total : all_capacity * 2;
            if (new_cap < 32) new_cap = 32;
            dna_wall_post_info_t *tmp = realloc(all_posts,
                                                 (size_t)new_cap * sizeof(dna_wall_post_info_t));
            if (!tmp) {
                dna_wall_free(&wall);
                break;
            }
            all_posts = tmp;
            all_capacity = new_cap;
        }

        for (size_t i = 0; i < wall.post_count; i++) {
            memset(&all_posts[total_count], 0, sizeof(dna_wall_post_info_t));
            wall_post_to_info(&wall.posts[i], &all_posts[total_count]);
            total_count++;
        }

        dna_wall_free(&wall);
    }

    free(fingerprints);
    if (list) contacts_db_free_list(list);

    /* Sort by timestamp descending (newest first) */
    if (all_posts && total_count > 1) {
        for (int i = 0; i < total_count - 1; i++) {
            for (int j = i + 1; j < total_count; j++) {
                if (all_posts[j].timestamp > all_posts[i].timestamp) {
                    dna_wall_post_info_t tmp = all_posts[i];
                    all_posts[i] = all_posts[j];
                    all_posts[j] = tmp;
                }
            }
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Timeline (DHT): %d posts from %zu contacts",
                 total_count, fp_count);
    task->callback.wall_posts(task->request_id, DNA_OK,
                              all_posts, total_count, task->user_data);
}

/* ============================================================================
 * WALL COMMENTS - JSON Helpers for Cache
 * ============================================================================ */

#include <json-c/json.h>

/**
 * Serialize wall comment info array to JSON for caching
 */
static int wall_comment_infos_to_json(const dna_wall_comment_info_t *infos, int count, char **json_out) {
    json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (int i = 0; i < count; i++) {
        json_object *obj = json_object_new_object();
        if (!obj) continue;

        json_object_object_add(obj, "uuid", json_object_new_string(infos[i].comment_uuid));
        json_object_object_add(obj, "post_uuid", json_object_new_string(infos[i].post_uuid));
        if (infos[i].parent_comment_uuid[0]) {
            json_object_object_add(obj, "parent_uuid",
                                   json_object_new_string(infos[i].parent_comment_uuid));
        }
        json_object_object_add(obj, "author_fp", json_object_new_string(infos[i].author_fingerprint));
        json_object_object_add(obj, "author_name", json_object_new_string(infos[i].author_name));
        json_object_object_add(obj, "body", json_object_new_string(infos[i].body));
        json_object_object_add(obj, "created_at", json_object_new_int64(infos[i].created_at));
        json_object_object_add(obj, "verified", json_object_new_boolean(infos[i].verified));

        json_object_array_add(arr, obj);
    }

    const char *str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    *json_out = str ? strdup(str) : NULL;
    json_object_put(arr);
    return *json_out ? 0 : -1;
}

/**
 * Deserialize wall comment info array from cached JSON
 */
static int wall_comment_infos_from_json(const char *json, dna_wall_comment_info_t **infos_out, int *count_out) {
    *infos_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }

    int len = json_object_array_length(arr);
    if (len == 0) {
        json_object_put(arr);
        return 0;
    }

    dna_wall_comment_info_t *infos = calloc(len, sizeof(dna_wall_comment_info_t));
    if (!infos) {
        json_object_put(arr);
        return -1;
    }

    for (int i = 0; i < len; i++) {
        json_object *obj = json_object_array_get_idx(arr, i);
        json_object *j_val;

        if (json_object_object_get_ex(obj, "uuid", &j_val))
            strncpy(infos[i].comment_uuid, json_object_get_string(j_val), 36);
        if (json_object_object_get_ex(obj, "post_uuid", &j_val))
            strncpy(infos[i].post_uuid, json_object_get_string(j_val), 36);
        if (json_object_object_get_ex(obj, "parent_uuid", &j_val))
            strncpy(infos[i].parent_comment_uuid, json_object_get_string(j_val), 36);
        if (json_object_object_get_ex(obj, "author_fp", &j_val))
            strncpy(infos[i].author_fingerprint, json_object_get_string(j_val), 128);
        if (json_object_object_get_ex(obj, "author_name", &j_val))
            strncpy(infos[i].author_name, json_object_get_string(j_val), 64);
        if (json_object_object_get_ex(obj, "body", &j_val))
            strncpy(infos[i].body, json_object_get_string(j_val), 2000);
        if (json_object_object_get_ex(obj, "created_at", &j_val))
            infos[i].created_at = json_object_get_int64(j_val);
        if (json_object_object_get_ex(obj, "verified", &j_val))
            infos[i].verified = json_object_get_boolean(j_val);
    }

    json_object_put(arr);
    *infos_out = infos;
    *count_out = len;
    return 0;
}

/* ============================================================================
 * WALL COMMENTS - Task Handlers
 * ============================================================================ */

void dna_handle_wall_add_comment(dna_engine_t *engine, dna_task_t *task) {
    dht_context_t *dht = dna_get_dht_ctx(engine);
    qgp_key_t *key = dna_load_private_key(engine);

    if (!dht || !key) {
        if (key) qgp_key_free(key);
        task->callback.wall_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                     NULL, task->user_data);
        return;
    }

    char uuid_out[37] = {0};
    const char *parent_uuid = task->params.wall_add_comment.parent_comment_uuid[0]
        ? task->params.wall_add_comment.parent_comment_uuid : NULL;

    int ret = dna_wall_comment_add(
        dht,
        task->params.wall_add_comment.post_uuid,
        parent_uuid,
        task->params.wall_add_comment.body,
        engine->fingerprint,
        key->private_key,
        uuid_out
    );
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add wall comment: %d", ret);
        task->callback.wall_comment(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, task->user_data);
        return;
    }

    /* Build response */
    dna_wall_comment_info_t *info = calloc(1, sizeof(dna_wall_comment_info_t));
    if (!info) {
        task->callback.wall_comment(task->request_id, DNA_ERROR_INTERNAL,
                                     NULL, task->user_data);
        return;
    }

    strncpy(info->comment_uuid, uuid_out, 36);
    strncpy(info->post_uuid, task->params.wall_add_comment.post_uuid, 36);
    if (parent_uuid) {
        strncpy(info->parent_comment_uuid, parent_uuid, 36);
    }
    strncpy(info->author_fingerprint, engine->fingerprint, 128);
    strncpy(info->body, task->params.wall_add_comment.body, 2000);
    info->created_at = (uint64_t)time(NULL);
    info->verified = true;

    /* Resolve own name */
    resolve_author_name(engine->fingerprint, info->author_name, sizeof(info->author_name));

    /* Invalidate comment cache for this post */
    wall_cache_invalidate_comments(task->params.wall_add_comment.post_uuid);

    QGP_LOG_INFO(LOG_TAG, "Added wall comment %s to post %s",
                 uuid_out, task->params.wall_add_comment.post_uuid);
    task->callback.wall_comment(task->request_id, DNA_OK, info, task->user_data);
}

void dna_handle_wall_get_comments(dna_engine_t *engine, dna_task_t *task) {
    const char *post_uuid = task->params.wall_get_comments.post_uuid;

    /* Check cache first */
    if (!wall_cache_is_stale_comments(post_uuid)) {
        char *cached_json = NULL;
        int cached_count = 0;
        int cache_ret = wall_cache_load_comments(post_uuid, &cached_json, &cached_count);
        if (cache_ret == 0 && cached_json) {
            dna_wall_comment_info_t *infos = NULL;
            int parsed_count = 0;
            if (wall_comment_infos_from_json(cached_json, &infos, &parsed_count) == 0) {
                free(cached_json);
                QGP_LOG_INFO(LOG_TAG, "Wall comments (cache): post %s, %d comments",
                             post_uuid, parsed_count);
                task->callback.wall_comments(task->request_id, DNA_OK,
                                              infos, parsed_count, task->user_data);
                return;
            }
            free(cached_json);
        }
    }

    /* Cache miss - fetch from DHT */
    dht_context_t *dht = dna_get_dht_ctx(engine);
    if (!dht) {
        task->callback.wall_comments(task->request_id, DNA_ENGINE_ERROR_NETWORK,
                                      NULL, 0, task->user_data);
        return;
    }

    dna_wall_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_wall_comments_get(dht, post_uuid, &comments, &count);

    if (ret != 0 && ret != -2) {
        task->callback.wall_comments(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        return;
    }

    if (ret == -2 || count == 0) {
        /* No comments */
        task->callback.wall_comments(task->request_id, DNA_OK,
                                      NULL, 0, task->user_data);
        if (comments) dna_wall_comments_free(comments, count);
        return;
    }

    /* Convert to public API format */
    dna_wall_comment_info_t *info = calloc(count, sizeof(dna_wall_comment_info_t));
    if (!info) {
        dna_wall_comments_free(comments, count);
        task->callback.wall_comments(task->request_id, DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].comment_uuid, comments[i].uuid, 36);
        strncpy(info[i].post_uuid, comments[i].post_uuid, 36);
        if (comments[i].parent_comment_uuid[0]) {
            strncpy(info[i].parent_comment_uuid, comments[i].parent_comment_uuid, 36);
        }
        strncpy(info[i].author_fingerprint, comments[i].author_fingerprint, 128);
        strncpy(info[i].body, comments[i].body, 2000);
        info[i].created_at = comments[i].created_at;
        info[i].verified = (comments[i].signature_len > 0);

        /* Resolve author name */
        resolve_author_name(comments[i].author_fingerprint,
                           info[i].author_name, sizeof(info[i].author_name));
    }

    dna_wall_comments_free(comments, count);

    /* Cache the result */
    {
        char *json = NULL;
        if (wall_comment_infos_to_json(info, (int)count, &json) == 0) {
            wall_cache_store_comments(post_uuid, json, (int)count);
            free(json);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Wall comments (DHT): post %s, %zu comments",
                 post_uuid, count);
    task->callback.wall_comments(task->request_id, DNA_OK, info, (int)count, task->user_data);
}

/* ============================================================================
 * PUBLIC API WRAPPERS
 * ============================================================================ */

dna_request_id_t dna_engine_wall_post(
    dna_engine_t *engine,
    const char *text,
    dna_wall_post_cb callback,
    void *user_data
) {
    if (!engine || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.wall_post.text = strdup(text);
    if (!params.wall_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.wall_post = callback;
    return dna_submit_task(engine, TASK_WALL_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_post_with_image(
    dna_engine_t *engine,
    const char *text,
    const char *image_json,
    dna_wall_post_cb callback,
    void *user_data
) {
    if (!engine || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.wall_post.text = strdup(text);
    if (!params.wall_post.text) return DNA_REQUEST_ID_INVALID;

    if (image_json) {
        params.wall_post.image_json = strdup(image_json);
        if (!params.wall_post.image_json) {
            free(params.wall_post.text);
            return DNA_REQUEST_ID_INVALID;
        }
    }

    dna_task_callback_t cb = {0};
    cb.wall_post = callback;
    return dna_submit_task(engine, TASK_WALL_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_delete(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_completion_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_delete.uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.completion = callback;
    return dna_submit_task(engine, TASK_WALL_DELETE, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_load(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_wall_posts_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_load.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_LOAD, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_TIMELINE, &params, cb, user_data);
}

/* ============================================================================
 * MEMORY CLEANUP
 * ============================================================================ */

void dna_free_wall_posts(dna_wall_post_info_t *posts, int count) {
    if (posts) {
        for (int i = 0; i < count; i++) {
            free(posts[i].image_json); /* NULL-safe */
        }
        free(posts);
    }
}

/* ── Wall Comments API ── */

dna_request_id_t dna_engine_wall_add_comment(
    dna_engine_t *engine,
    const char *post_uuid,
    const char *parent_comment_uuid,
    const char *body,
    dna_wall_comment_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !body || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_add_comment.post_uuid, post_uuid, 36);
    if (parent_comment_uuid && parent_comment_uuid[0] != '\0') {
        strncpy(params.wall_add_comment.parent_comment_uuid, parent_comment_uuid, 36);
    }
    params.wall_add_comment.body = strdup(body);
    if (!params.wall_add_comment.body) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.wall_comment = callback;
    return dna_submit_task(engine, TASK_WALL_ADD_COMMENT, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_get_comments(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_comments_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_get_comments.post_uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.wall_comments = callback;
    return dna_submit_task(engine, TASK_WALL_GET_COMMENTS, &params, cb, user_data);
}

void dna_free_wall_comments(dna_wall_comment_info_t *comments, int count) {
    (void)count;  /* dna_wall_comment_info_t has no heap members */
    if (comments) free(comments);
}
