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
 *   - dna_handle_wall_like()
 *   - dna_handle_wall_get_likes()
 *   - dna_engine_wall_like()
 *   - dna_engine_wall_get_likes()
 *   - dna_free_wall_likes()
 *
 * STATUS: v0.6.135+ - MVP text-only wall posts
 */

#define DNA_ENGINE_WALL_IMPL

#include "engine_includes.h"
#include "dht/client/dna_wall.h"
#include "dht/shared/nodus_ops.h"
#include "database/wall_cache.h"
#include "nodus/nodus_types.h"
#include <json-c/json.h>

/* Override LOG_TAG for this module (engine_includes.h defines DNA_ENGINE) */
#undef LOG_TAG
#define LOG_TAG "ENGINE_WALL"

/* ============================================================================
 * HELPER FUNCTIONS - Date
 * ============================================================================ */

/** Get today's date as "YYYY-MM-DD" (UTC) */
static void engine_today_str(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);
    snprintf(buf, buf_size, "%04d-%02d-%02d",
             utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday);
}

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
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.wall_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                 NULL, task->user_data);
        return;
    }

    dna_wall_post_t out_post = {0};
    int ret;
    if (task->params.wall_post.image_json) {
        ret = dna_wall_post_with_image(engine->fingerprint, key->private_key,
                                        task->params.wall_post.text,
                                        task->params.wall_post.image_json, &out_post);
    } else {
        ret = dna_wall_post(engine->fingerprint, key->private_key,
                            task->params.wall_post.text, &out_post);
    }
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to post to wall: %d", ret);
        task->callback.wall_post(task->request_id, DNA_ERROR_INTERNAL,
                                 NULL, task->user_data);
        return;
    }

    /* Insert new post into cache (avoids cache miss on next timeline load) */
    wall_cache_insert_post(&out_post);
    wall_cache_update_meta(engine->fingerprint);

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
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.completion(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  task->user_data);
        return;
    }

    /* Look up post timestamp from cache for daily bucket routing */
    uint64_t post_ts = wall_cache_get_post_timestamp(task->params.wall_delete.uuid);
    int ret = dna_wall_delete(engine->fingerprint, key->private_key,
                              task->params.wall_delete.uuid, post_ts);
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete wall post %s: %d",
                      task->params.wall_delete.uuid, ret);
        task->callback.completion(task->request_id, DNA_ERROR_INTERNAL,
                                  task->user_data);
        return;
    }

    /* Remove from local cache and invalidate meta so next load re-fetches */
    wall_cache_delete_post(task->params.wall_delete.uuid);
    wall_cache_delete_meta(engine->fingerprint);

    QGP_LOG_INFO(LOG_TAG, "Wall post deleted: %s", task->params.wall_delete.uuid);
    task->callback.completion(task->request_id, DNA_OK, task->user_data);
}

void dna_handle_wall_load(dna_engine_t *engine, dna_task_t *task) {
    const char *fp = task->params.wall_load.fingerprint;

    /* Check cache first (use wall meta staleness for daily buckets) */
    if (!wall_cache_is_stale_wall_meta(fp)) {
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
    dna_wall_t wall = {0};
    int ret = dna_wall_load(fp, &wall);

    if (ret == -2) {
        /* Not found - return empty list (not an error).
         * Mark meta fresh so we don't re-fetch every call. */
        wall_cache_update_meta(fp);
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

    /* Build fingerprint list: own + contacts + following */
    if (contacts_db_init(engine->fingerprint) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Timeline: contacts_db_init failed, using own wall only");
    }
    following_db_init(engine->fingerprint);

    contact_list_t *list = NULL;
    contacts_db_list(&list);

    following_list_t *follow_list = NULL;
    following_db_list(&follow_list);

    size_t contact_count = list ? list->count : 0;
    size_t follow_count = follow_list ? follow_list->count : 0;
    size_t fp_count = 1 + contact_count + follow_count;
    const char **fingerprints = calloc(fp_count, sizeof(const char *));
    if (!fingerprints) {
        if (list) contacts_db_free_list(list);
        if (follow_list) following_db_free_list(follow_list);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    fingerprints[0] = engine->fingerprint;
    size_t idx = 1;
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            fingerprints[idx++] = list->contacts[i].identity;
        }
    }

    /* Add followed users (skip duplicates with contacts) */
    if (follow_list) {
        for (size_t i = 0; i < follow_list->count; i++) {
            const char *fp = follow_list->entries[i].fingerprint;
            bool dup = false;
            for (size_t j = 0; j < idx; j++) {
                if (fingerprints[j] && strcmp(fingerprints[j], fp) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                fingerprints[idx++] = fp;
            }
        }
        fp_count = idx;  /* Adjust for skipped duplicates */
    }

    /* Debug: log fingerprint list for timeline query */
    for (size_t i = 0; i < fp_count; i++) {
        QGP_LOG_INFO(LOG_TAG, "Timeline query fp[%zu]=%.32s... (len=%zu)",
                     i, fingerprints[i] ? fingerprints[i] : "(null)",
                     fingerprints[i] ? strlen(fingerprints[i]) : 0);
    }

    /* Return from cache (wall poll timer handles DHT refresh in background) */
    dna_wall_post_t *cached_posts = NULL;
    size_t cached_count = 0;
    int cache_ret = wall_cache_load_timeline(fingerprints, fp_count,
                                             &cached_posts, &cached_count);

    free(fingerprints);
    if (list) contacts_db_free_list(list);
    if (follow_list) following_db_free_list(follow_list);

    if (cache_ret != 0 || !cached_posts || cached_count == 0) {
        /* Empty timeline */
        if (cached_posts) wall_cache_free_posts(cached_posts, cached_count);
        QGP_LOG_INFO(LOG_TAG, "Timeline: empty (cache_ret=%d)", cache_ret);
        task->callback.wall_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
        return;
    }

    /* Convert to public API format */
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

    /* Merge cached boost pointers (same logic as cached path) */
    size_t final_count = cached_count;
    {
        dna_wall_boost_ptr_t *boost_ptrs = NULL;
        size_t boost_count = 0;
        if (wall_cache_load_boosts(&boost_ptrs, &boost_count) == 0 && boost_ptrs && boost_count > 0) {
            size_t new_cap = cached_count + boost_count;
            dna_wall_post_info_t *merged = realloc(info, new_cap * sizeof(dna_wall_post_info_t));
            if (merged) {
                info = merged;
                for (size_t b = 0; b < boost_count; b++) {
                    bool found = false;
                    for (size_t e = 0; e < final_count; e++) {
                        if (strncmp(info[e].uuid, boost_ptrs[b].uuid, 36) == 0) {
                            info[e].is_boosted = true;
                            found = true;
                            break;
                        }
                    }
                    if (found) continue;

                    /* Resolve from wall cache, fallback to DHT if connected */
                    dna_wall_post_t *bp = NULL;
                    size_t bp_count = 0;
                    bool resolved = false;

                    if (wall_cache_load(boost_ptrs[b].author_fingerprint, &bp, &bp_count) == 0 && bp) {
                        for (size_t p = 0; p < bp_count; p++) {
                            if (strncmp(bp[p].uuid, boost_ptrs[b].uuid, 36) == 0) {
                                if (final_count < new_cap) {
                                    wall_post_to_info(&bp[p], &info[final_count]);
                                    info[final_count].is_boosted = true;
                                    final_count++;
                                    resolved = true;
                                }
                                break;
                            }
                        }
                        wall_cache_free_posts(bp, bp_count);
                    }

                    /* Cache miss — try DHT if connected (non-follow authors) */
                    if (!resolved && nodus_ops_is_ready()) {
                        dna_wall_t wall = {0};
                        if (dna_wall_load(boost_ptrs[b].author_fingerprint, &wall) == 0) {
                            wall_cache_store(boost_ptrs[b].author_fingerprint,
                                             wall.posts, wall.post_count);
                            for (size_t p = 0; p < wall.post_count; p++) {
                                if (strncmp(wall.posts[p].uuid, boost_ptrs[b].uuid, 36) == 0) {
                                    if (final_count < new_cap) {
                                        wall_post_to_info(&wall.posts[p], &info[final_count]);
                                        info[final_count].is_boosted = true;
                                        final_count++;
                                    }
                                    break;
                                }
                            }
                            dna_wall_free(&wall);
                        }
                    }
                }
                QGP_LOG_INFO(LOG_TAG, "Timeline: merged %zu boost pointers", boost_count);
            }
            free(boost_ptrs);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Timeline: %zu posts (cache-first)", final_count);
    task->callback.wall_posts(task->request_id, DNA_OK, info, (int)final_count, task->user_data);
}

/* ============================================================================
 * WALL TIMELINE CACHED - Cache-only, no identity/DHT required
 * ============================================================================ */

/**
 * Return wall timeline from local cache only.
 * Does NOT require identity_loaded — just needs fingerprint to look up contacts.
 * No DHT access, no background refresh. Pure SQLite read.
 */
void dna_handle_wall_timeline_cached(dna_engine_t *engine, dna_task_t *task) {
    const char *fingerprint = task->params.wall_timeline_cached.fingerprint;
    if (!fingerprint || strlen(fingerprint) != 128) {
        QGP_LOG_WARN(LOG_TAG, "Timeline cached: invalid fingerprint");
        task->callback.wall_posts(task->request_id, DNA_ERROR_INVALID_ARG,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Open contacts DB for this fingerprint (idempotent if already open) */
    if (contacts_db_init(fingerprint) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Timeline cached: contacts_db_init failed, using own wall only");
    }
    following_db_init(fingerprint);

    contact_list_t *list = NULL;
    contacts_db_list(&list);

    following_list_t *follow_list = NULL;
    following_db_list(&follow_list);

    size_t contact_count = list ? list->count : 0;
    size_t follow_count = follow_list ? follow_list->count : 0;
    size_t fp_count = 1 + contact_count + follow_count;
    const char **fingerprints = calloc(fp_count, sizeof(const char *));
    if (!fingerprints) {
        if (list) contacts_db_free_list(list);
        if (follow_list) following_db_free_list(follow_list);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    fingerprints[0] = fingerprint;
    size_t idx = 1;
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            fingerprints[idx++] = list->contacts[i].identity;
        }
    }

    /* Add followed users (skip duplicates with contacts) */
    if (follow_list) {
        for (size_t i = 0; i < follow_list->count; i++) {
            const char *fp = follow_list->entries[i].fingerprint;
            bool dup = false;
            for (size_t j = 0; j < idx; j++) {
                if (fingerprints[j] && strcmp(fingerprints[j], fp) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                fingerprints[idx++] = fp;
            }
        }
        fp_count = idx;
    }

    /* Read from cache only — no staleness check, no DHT refresh */
    dna_wall_post_t *cached_posts = NULL;
    size_t cached_count = 0;
    int cache_ret = wall_cache_load_timeline(fingerprints, fp_count,
                                             &cached_posts, &cached_count);

    free(fingerprints);
    if (list) contacts_db_free_list(list);
    if (follow_list) following_db_free_list(follow_list);

    if (cache_ret != 0 || !cached_posts || cached_count == 0) {
        if (cached_posts) wall_cache_free_posts(cached_posts, cached_count);
        QGP_LOG_INFO(LOG_TAG, "Timeline cached: empty (cache_ret=%d)", cache_ret);
        task->callback.wall_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
        return;
    }

    /* Convert to public API format */
    dna_wall_post_info_t *info = calloc(cached_count, sizeof(dna_wall_post_info_t));
    if (!info) {
        wall_cache_free_posts(cached_posts, cached_count);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < cached_count; i++) {
        wall_post_to_info(&cached_posts[i], &info[i]);
        QGP_LOG_DEBUG(LOG_TAG, "Timeline cached [%zu]: uuid=%.8s... author=%.16s... img=%s",
                      i, info[i].uuid, info[i].author_name,
                      info[i].image_json ? "yes" : "no");
    }

    wall_cache_free_posts(cached_posts, cached_count);

    /* Merge cached boost pointers — resolve against wall cache */
    dna_wall_boost_ptr_t *boost_ptrs = NULL;
    size_t boost_count = 0;
    if (wall_cache_load_boosts(&boost_ptrs, &boost_count) == 0 && boost_ptrs) {
        /* Mark existing posts as boosted + add new boost posts */
        size_t new_total = cached_count;
        size_t new_cap = cached_count + boost_count;
        dna_wall_post_info_t *merged = realloc(info, new_cap * sizeof(dna_wall_post_info_t));
        if (merged) {
            info = merged;
            for (size_t b = 0; b < boost_count; b++) {
                /* Check if already in timeline */
                bool found = false;
                for (size_t e = 0; e < new_total; e++) {
                    if (strncmp(info[e].uuid, boost_ptrs[b].uuid, 36) == 0) {
                        info[e].is_boosted = true;
                        found = true;
                        break;
                    }
                }
                if (found) continue;

                /* Resolve from wall cache */
                dna_wall_post_t *bp = NULL;
                size_t bp_count = 0;
                if (wall_cache_load(boost_ptrs[b].author_fingerprint, &bp, &bp_count) == 0 && bp) {
                    for (size_t j = 0; j < bp_count; j++) {
                        if (strncmp(bp[j].uuid, boost_ptrs[b].uuid, 36) == 0) {
                            if (new_total < new_cap) {
                                wall_post_to_info(&bp[j], &info[new_total]);
                                info[new_total].is_boosted = true;
                                new_total++;
                            }
                            break;
                        }
                    }
                    wall_cache_free_posts(bp, bp_count);
                }
            }
            cached_count = new_total;
        }
        free(boost_ptrs);

        QGP_LOG_INFO(LOG_TAG, "Timeline cached: merged %zu boost pointers", boost_count);
    }

    QGP_LOG_INFO(LOG_TAG, "Timeline cached: %zu posts (cache-only, no DHT)", cached_count);
    task->callback.wall_posts(task->request_id, DNA_OK, info, (int)cached_count, task->user_data);
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
        if (infos[i].comment_type > 0) {
            json_object_object_add(obj, "comment_type", json_object_new_int(infos[i].comment_type));
        }

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
        if (json_object_object_get_ex(obj, "comment_type", &j_val))
            infos[i].comment_type = json_object_get_int(j_val);
        /* else: defaults to 0 (text) from calloc */
    }

    json_object_put(arr);
    *infos_out = infos;
    *count_out = len;
    return 0;
}

/* ============================================================================
 * WALL LIKES - JSON Helpers for Cache (v0.9.53+)
 * ============================================================================ */

/**
 * Serialize wall like info array to JSON for caching
 */
static int wall_like_infos_to_json(const dna_wall_like_info_t *infos, int count, char **json_out) {
    json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (int i = 0; i < count; i++) {
        json_object *obj = json_object_new_object();
        if (!obj) continue;

        json_object_object_add(obj, "author_fp", json_object_new_string(infos[i].author_fingerprint));
        json_object_object_add(obj, "author_name", json_object_new_string(infos[i].author_name));
        json_object_object_add(obj, "timestamp", json_object_new_int64((int64_t)infos[i].timestamp));
        json_object_object_add(obj, "verified", json_object_new_boolean(infos[i].verified));

        json_object_array_add(arr, obj);
    }

    const char *str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    *json_out = str ? strdup(str) : NULL;
    json_object_put(arr);
    return *json_out ? 0 : -1;
}

/**
 * Deserialize wall like info array from cached JSON
 */
static int wall_like_infos_from_json(const char *json, dna_wall_like_info_t **infos_out, int *count_out) {
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

    dna_wall_like_info_t *infos = calloc(len, sizeof(dna_wall_like_info_t));
    if (!infos) {
        json_object_put(arr);
        return -1;
    }

    for (int i = 0; i < len; i++) {
        json_object *obj = json_object_array_get_idx(arr, i);
        json_object *j_val;

        if (json_object_object_get_ex(obj, "author_fp", &j_val))
            strncpy(infos[i].author_fingerprint, json_object_get_string(j_val), 128);
        if (json_object_object_get_ex(obj, "author_name", &j_val))
            strncpy(infos[i].author_name, json_object_get_string(j_val), 64);
        if (json_object_object_get_ex(obj, "timestamp", &j_val))
            infos[i].timestamp = (uint64_t)json_object_get_int64(j_val);
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
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.wall_comment(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                     NULL, task->user_data);
        return;
    }

    char uuid_out[37] = {0};
    const char *parent_uuid = task->params.wall_add_comment.parent_comment_uuid[0]
        ? task->params.wall_add_comment.parent_comment_uuid : NULL;

    int ret = dna_wall_comment_add(
        task->params.wall_add_comment.post_uuid,
        parent_uuid,
        task->params.wall_add_comment.body,
        engine->fingerprint,
        key->private_key,
        task->params.wall_add_comment.comment_type,
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
    info->comment_type = task->params.wall_add_comment.comment_type;

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
    dna_wall_comment_t *comments = NULL;
    size_t count = 0;
    int ret = dna_wall_comments_get(post_uuid, &comments, &count);

    if (ret != 0) {
        /* DHT error (not connected, timeout, etc.) — do NOT cache,
         * return empty without poisoning cache with false negatives */
        task->callback.wall_comments(task->request_id,
                                      ret == -2 ? DNA_OK : DNA_ERROR_INTERNAL,
                                      NULL, 0, task->user_data);
        if (comments) dna_wall_comments_free(comments, count);
        return;
    }

    if (count == 0) {
        /* DHT returned successfully but no comments exist — safe to cache */
        wall_cache_store_comments(post_uuid, "[]", 0);
        task->callback.wall_comments(task->request_id, DNA_OK,
                                      NULL, 0, task->user_data);
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
        info[i].comment_type = comments[i].comment_type;

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

dna_request_id_t dna_engine_wall_timeline_cached(
    dna_engine_t *engine,
    const char *fingerprint,
    dna_wall_posts_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_timeline_cached.fingerprint, fingerprint, 128);

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_TIMELINE_CACHED, &params, cb, user_data);
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

dna_request_id_t dna_engine_wall_add_tip_comment(
    dna_engine_t *engine,
    const char *post_uuid,
    const char *body,
    dna_wall_comment_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !body || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_add_comment.post_uuid, post_uuid, 36);
    /* Tips are always top-level comments (no parent) */
    params.wall_add_comment.body = strdup(body);
    if (!params.wall_add_comment.body) return DNA_REQUEST_ID_INVALID;
    params.wall_add_comment.comment_type = 1;  /* tip */

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

/* ============================================================================
 * WALL LIKES - Task Handlers (v0.9.52+)
 * ============================================================================ */

void dna_handle_wall_like(dna_engine_t *engine, dna_task_t *task) {
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.wall_likes(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                   NULL, 0, task->user_data);
        return;
    }

    int ret = dna_wall_like_add(
        task->params.wall_like.post_uuid,
        engine->fingerprint,
        key->private_key
    );
    qgp_key_free(key);

    if (ret != 0 && ret != -3) {
        int error = DNA_ERROR_INTERNAL;
        if (ret == -4) error = DNA_ENGINE_ERROR_LIMIT_REACHED;
        QGP_LOG_ERROR(LOG_TAG, "Failed to like post %s: %d",
                      task->params.wall_like.post_uuid, ret);
        task->callback.wall_likes(task->request_id, error,
                                   NULL, 0, task->user_data);
        return;
    }

    if (ret == -3) {
        QGP_LOG_INFO(LOG_TAG, "Already liked post %s, fetching current likes",
                     task->params.wall_like.post_uuid);
    }

    /* Fetch updated likes to return */
    dna_wall_like_t *likes = NULL;
    size_t count = 0;
    ret = dna_wall_likes_get(task->params.wall_like.post_uuid, &likes, &count);

    if (ret != 0 || count == 0) {
        /* Like succeeded but couldn't fetch - return success with empty list */
        QGP_LOG_INFO(LOG_TAG, "Like added for post %s (fetch failed: %d)",
                     task->params.wall_like.post_uuid, ret);
        task->callback.wall_likes(task->request_id, DNA_OK,
                                   NULL, 0, task->user_data);
        if (likes) dna_wall_likes_free(likes, count);
        return;
    }

    /* Convert to public API format */
    dna_wall_like_info_t *info = calloc(count, sizeof(dna_wall_like_info_t));
    if (!info) {
        dna_wall_likes_free(likes, count);
        task->callback.wall_likes(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].author_fingerprint, likes[i].author_fingerprint, 128);
        info[i].timestamp = likes[i].timestamp;
        info[i].verified = (likes[i].signature_len > 0);
        resolve_author_name(likes[i].author_fingerprint,
                           info[i].author_name, sizeof(info[i].author_name));
    }

    dna_wall_likes_free(likes, count);

    /* Update likes cache with fresh data */
    char *likes_json = NULL;
    if (wall_like_infos_to_json(info, (int)count, &likes_json) == 0 && likes_json) {
        wall_cache_store_likes(task->params.wall_like.post_uuid, likes_json, (int)count);
        free(likes_json);
    }

    QGP_LOG_INFO(LOG_TAG, "Like added for post %s, total: %zu",
                 task->params.wall_like.post_uuid, count);
    task->callback.wall_likes(task->request_id, DNA_OK,
                               info, (int)count, task->user_data);
}

void dna_handle_wall_get_likes(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    const char *post_uuid = task->params.wall_get_likes.post_uuid;

    /* ── Cache-first: return cached likes if fresh ── */
    if (!wall_cache_is_stale_likes(post_uuid)) {
        char *json = NULL;
        int cached_count = 0;
        if (wall_cache_load_likes(post_uuid, &json, &cached_count) == 0 && json) {
            dna_wall_like_info_t *infos = NULL;
            int info_count = 0;
            if (wall_like_infos_from_json(json, &infos, &info_count) == 0) {
                free(json);
                QGP_LOG_DEBUG(LOG_TAG, "Likes cache hit for %s (%d)", post_uuid, info_count);
                task->callback.wall_likes(task->request_id, DNA_OK,
                                           infos, info_count, task->user_data);
                return;
            }
            free(json);
        }
        /* Cache parse failed — fall through to DHT */
    }

    /* ── Cache miss or stale: fetch from DHT ── */
    dna_wall_like_t *likes = NULL;
    size_t count = 0;
    int ret = dna_wall_likes_get(post_uuid, &likes, &count);

    if (ret != 0) {
        /* DHT error (not connected, timeout, etc.) — do NOT cache,
         * return empty without poisoning cache with false negatives */
        task->callback.wall_likes(task->request_id,
                                   ret == -2 ? DNA_OK : DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        if (likes) dna_wall_likes_free(likes, count);
        return;
    }

    if (count == 0) {
        /* DHT returned successfully but no likes exist — safe to cache */
        wall_cache_store_likes(post_uuid, "[]", 0);
        task->callback.wall_likes(task->request_id, DNA_OK,
                                   NULL, 0, task->user_data);
        if (likes) dna_wall_likes_free(likes, count);
        return;
    }

    /* Convert to public API format */
    dna_wall_like_info_t *info = calloc(count, sizeof(dna_wall_like_info_t));
    if (!info) {
        dna_wall_likes_free(likes, count);
        task->callback.wall_likes(task->request_id, DNA_ERROR_INTERNAL,
                                   NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        strncpy(info[i].author_fingerprint, likes[i].author_fingerprint, 128);
        info[i].timestamp = likes[i].timestamp;
        info[i].verified = (likes[i].signature_len > 0);
        resolve_author_name(likes[i].author_fingerprint,
                           info[i].author_name, sizeof(info[i].author_name));
    }

    dna_wall_likes_free(likes, count);

    /* Store in cache for next time */
    char *likes_json = NULL;
    if (wall_like_infos_to_json(info, (int)count, &likes_json) == 0 && likes_json) {
        wall_cache_store_likes(post_uuid, likes_json, (int)count);
        free(likes_json);
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu likes for post %s (from DHT)",
                 count, post_uuid);
    task->callback.wall_likes(task->request_id, DNA_OK,
                               info, (int)count, task->user_data);
}

/* ── Wall Engagement Batch (v0.9.123+) ── */

void dna_handle_wall_get_engagement(dna_engine_t *engine, dna_task_t *task) {
    char **post_uuids = task->params.wall_get_engagement.post_uuids;
    int post_count = task->params.wall_get_engagement.post_count;

    if (!post_uuids || post_count < 1) {
        task->callback.wall_engagement(task->request_id, DNA_ERROR_INTERNAL,
                                        NULL, 0, task->user_data);
        return;
    }

    /* Allocate result array */
    dna_wall_engagement_t *engagements = calloc((size_t)post_count,
                                                 sizeof(dna_wall_engagement_t));
    if (!engagements) {
        task->callback.wall_engagement(task->request_id, DNA_ERROR_INTERNAL,
                                        NULL, 0, task->user_data);
        return;
    }

    /* ── Phase 1: Serve from cache where fresh ── */
    bool *need_dht_comments = calloc((size_t)post_count, sizeof(bool));
    bool *need_dht_likes = calloc((size_t)post_count, sizeof(bool));
    int stale_comment_count = 0;
    int stale_like_count = 0;

    if (!need_dht_comments || !need_dht_likes) {
        free(need_dht_comments); free(need_dht_likes); free(engagements);
        task->callback.wall_engagement(task->request_id, DNA_ERROR_INTERNAL,
                                        NULL, 0, task->user_data);
        return;
    }

    for (int i = 0; i < post_count; i++) {
        strncpy(engagements[i].post_uuid, post_uuids[i], 36);
        engagements[i].post_uuid[36] = '\0';

        /* Try comments cache (serve even if stale — better than 0) */
        {
            bool comments_stale = wall_cache_is_stale_comments(post_uuids[i]);
            char *cached_json = NULL;
            int cached_count = 0;
            if (wall_cache_load_comments(post_uuids[i], &cached_json, &cached_count) == 0
                && cached_json) {
                dna_wall_comment_info_t *infos = NULL;
                int parsed = 0;
                if (wall_comment_infos_from_json(cached_json, &infos, &parsed) == 0) {
                    engagements[i].comments = infos;
                    engagements[i].comment_count = parsed;
                }
                free(cached_json);
            }
            if (comments_stale) {
                need_dht_comments[i] = true;
                stale_comment_count++;
            }
        }

        /* Try likes cache (serve even if stale — better than 0) */
        {
            bool likes_stale = wall_cache_is_stale_likes(post_uuids[i]);
            char *cached_json = NULL;
            int cached_count = 0;
            if (wall_cache_load_likes(post_uuids[i], &cached_json, &cached_count) == 0
                && cached_json) {
                /* Use cached_count from SQLite like_count column (reliable).
                 * JSON may be "[]" (from count_batch which only stores count). */
                engagements[i].like_count = cached_count;

                /* Try to resolve is_liked_by_me from JSON if it has real data */
                if (cached_count > 0 && engine->identity_loaded) {
                    dna_wall_like_info_t *infos = NULL;
                    int parsed = 0;
                    if (wall_like_infos_from_json(cached_json, &infos, &parsed) == 0
                        && parsed > 0) {
                        for (int k = 0; k < parsed; k++) {
                            if (strcmp(infos[k].author_fingerprint,
                                       engine->fingerprint) == 0) {
                                engagements[i].is_liked_by_me = true;
                                break;
                            }
                        }
                        free(infos);
                    }
                }
                free(cached_json);
            }
            if (likes_stale) {
                need_dht_likes[i] = true;
                stale_like_count++;
            }
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Engagement batch: %d posts, %d stale comments, %d stale likes",
                 post_count, stale_comment_count, stale_like_count);

    /* ── Phase 2: Batch fetch stale entries from DHT ── */
    if (stale_comment_count > 0) {
        /* Build keys only for stale comment posts */
        const char **comment_keys = calloc((size_t)post_count, sizeof(char *));
        char *ck_buf = calloc((size_t)post_count, 256);
        if (comment_keys && ck_buf) {
            for (int i = 0; i < post_count; i++) {
                char *ck = ck_buf + (size_t)i * 256;
                snprintf(ck, 256, "%s%s",
                         DNA_WALL_COMMENT_KEY_PREFIX, post_uuids[i]);
                comment_keys[i] = ck;
            }

            nodus_ops_batch_result_t *results = NULL;
            int result_count = 0;
            int rc = nodus_ops_get_batch_str(comment_keys, post_count,
                                              &results, &result_count);

            if (rc == 0 && results) {
                for (int i = 0; i < post_count && i < result_count; i++) {
                    if (!need_dht_comments[i]) continue;  /* Already served from cache */

                    int total_comments = 0;
                    dna_wall_comment_info_t *all_infos = NULL;
                    size_t alloc_cap = 0;

                    for (size_t v = 0; v < results[i].count; v++) {
                        if (!results[i].values[v] || results[i].lens[v] == 0)
                            continue;

                        json_tokener *tok = json_tokener_new();
                        json_object *arr = json_tokener_parse_ex(
                            tok, (const char *)results[i].values[v],
                            (int)results[i].lens[v]);
                        json_tokener_free(tok);
                        if (!arr) continue;

                        if (json_object_get_type(arr) != json_type_array) {
                            json_object_put(arr);
                            continue;
                        }

                        int arr_len = (int)json_object_array_length(arr);
                        for (int j = 0; j < arr_len; j++) {
                            json_object *obj = json_object_array_get_idx(arr, (size_t)j);
                            if (!obj) continue;

                            if ((size_t)total_comments >= alloc_cap) {
                                alloc_cap = alloc_cap == 0 ? 16 : alloc_cap * 2;
                                dna_wall_comment_info_t *tmp = realloc(all_infos,
                                    alloc_cap * sizeof(dna_wall_comment_info_t));
                                if (!tmp) break;
                                all_infos = tmp;
                            }

                            dna_wall_comment_info_t *ci = &all_infos[total_comments];
                            memset(ci, 0, sizeof(*ci));

                            json_object *jv;
                            if (json_object_object_get_ex(obj, "uuid", &jv))
                                strncpy(ci->comment_uuid, json_object_get_string(jv), 36);
                            if (json_object_object_get_ex(obj, "post_uuid", &jv))
                                strncpy(ci->post_uuid, json_object_get_string(jv), 36);
                            if (json_object_object_get_ex(obj, "parent_uuid", &jv))
                                strncpy(ci->parent_comment_uuid, json_object_get_string(jv), 36);
                            if (json_object_object_get_ex(obj, "author", &jv))
                                strncpy(ci->author_fingerprint, json_object_get_string(jv), 128);
                            if (json_object_object_get_ex(obj, "body", &jv))
                                strncpy(ci->body, json_object_get_string(jv), 2000);
                            if (json_object_object_get_ex(obj, "created_at", &jv))
                                ci->created_at = (uint64_t)json_object_get_int64(jv);
                            if (json_object_object_get_ex(obj, "comment_type", &jv))
                                ci->comment_type = (uint32_t)json_object_get_int(jv);

                            ci->verified = true;
                            resolve_author_name(ci->author_fingerprint,
                                               ci->author_name, sizeof(ci->author_name));
                            total_comments++;
                        }
                        json_object_put(arr);
                    }

                    /* Free old cache data if any, replace with DHT data */
                    free(engagements[i].comments);
                    engagements[i].comments = all_infos;
                    engagements[i].comment_count = total_comments;

                    /* Update cache with fresh DHT data */
                    if (total_comments > 0 && all_infos) {
                        char *json = NULL;
                        if (wall_comment_infos_to_json(all_infos, total_comments, &json) == 0) {
                            wall_cache_store_comments(post_uuids[i], json, total_comments);
                            free(json);
                        }
                    } else {
                        wall_cache_store_comments(post_uuids[i], "[]", 0);
                    }
                }
                nodus_ops_free_batch_result(results, result_count);
            }
        }
        free(comment_keys);
        free(ck_buf);
    }

    if (stale_like_count > 0) {
        const char **like_keys = calloc((size_t)post_count, sizeof(char *));
        char *lk_buf = calloc((size_t)post_count, 256);
        if (like_keys && lk_buf) {
            for (int i = 0; i < post_count; i++) {
                char *lk = lk_buf + (size_t)i * 256;
                snprintf(lk, 256, "%s%s",
                         DNA_WALL_LIKE_KEY_PREFIX, post_uuids[i]);
                like_keys[i] = lk;
            }

            nodus_ops_count_result_t *results = NULL;
            int result_count = 0;
            int rc = nodus_ops_count_batch_str(like_keys, post_count,
                                                &results, &result_count);

            if (rc == 0 && results) {
                for (int i = 0; i < post_count && i < result_count; i++) {
                    if (!need_dht_likes[i]) continue;
                    engagements[i].like_count = (int)results[i].count;
                    engagements[i].is_liked_by_me = results[i].has_mine;

                    /* Cache the count so next call skips DHT */
                    char count_json[32];
                    snprintf(count_json, sizeof(count_json), "[]");
                    wall_cache_store_likes(post_uuids[i], count_json,
                                           (int)results[i].count);
                }
                nodus_ops_free_count_result(results, result_count);
            }
        }
        free(like_keys);
        free(lk_buf);
    }

    free(need_dht_comments);
    free(need_dht_likes);

    /* Free the post_uuids array (task owns it) */
    for (int i = 0; i < post_count; i++)
        free(post_uuids[i]);
    free(post_uuids);
    task->params.wall_get_engagement.post_uuids = NULL;

    QGP_LOG_INFO(LOG_TAG, "Batch engagement: %d posts (cache-first)", post_count);
    task->callback.wall_engagement(task->request_id, DNA_OK,
                                    engagements, post_count, task->user_data);
}

/* ── Wall Likes Public API ── */

dna_request_id_t dna_engine_wall_like(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_likes_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_like.post_uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.wall_likes = callback;
    return dna_submit_task(engine, TASK_WALL_LIKE, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_get_likes(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_likes_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_get_likes.post_uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.wall_likes = callback;
    return dna_submit_task(engine, TASK_WALL_GET_LIKES, &params, cb, user_data);
}

void dna_free_wall_likes(dna_wall_like_info_t *likes, int count) {
    (void)count;  /* dna_wall_like_info_t has no heap members */
    if (likes) free(likes);
}

/* ── Wall Engagement Batch Public API (v0.9.123+) ── */

dna_request_id_t dna_engine_wall_get_engagement(
    dna_engine_t *engine,
    const char **post_uuids,
    int post_count,
    dna_wall_engagement_cb callback,
    void *user_data
) {
    if (!engine || !post_uuids || post_count < 1 || !callback)
        return DNA_REQUEST_ID_INVALID;
    if (post_count > NODUS_MAX_BATCH_KEYS) post_count = NODUS_MAX_BATCH_KEYS;

    /* Deep-copy UUIDs (task takes ownership) */
    char **uuids_copy = calloc((size_t)post_count, sizeof(char *));
    if (!uuids_copy) return DNA_REQUEST_ID_INVALID;
    for (int i = 0; i < post_count; i++) {
        uuids_copy[i] = strdup(post_uuids[i]);
        if (!uuids_copy[i]) {
            for (int j = 0; j < i; j++) free(uuids_copy[j]);
            free(uuids_copy);
            return DNA_REQUEST_ID_INVALID;
        }
    }

    dna_task_params_t params = {0};
    params.wall_get_engagement.post_uuids = uuids_copy;
    params.wall_get_engagement.post_count = post_count;

    dna_task_callback_t cb = {0};
    cb.wall_engagement = callback;

    return dna_submit_task(engine, TASK_WALL_GET_ENGAGEMENT, &params, cb, user_data);
}

void dna_free_wall_engagement(dna_wall_engagement_t *engagements, int count) {
    if (!engagements) return;
    for (int i = 0; i < count; i++) {
        free(engagements[i].comments);
    }
    free(engagements);
}

/* ============================================================================
 * WALL BOOST - Task Handlers (v0.9.71+)
 * ============================================================================ */

void dna_handle_wall_boost_post(dna_engine_t *engine, dna_task_t *task) {
    qgp_key_t *key = dna_load_private_key(engine);

    if (!key) {
        task->callback.wall_post(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  NULL, task->user_data);
        return;
    }

    /* Step 1: Create normal wall post */
    dna_wall_post_t out_post = {0};
    int ret;
    if (task->params.wall_boost_post.image_json) {
        ret = dna_wall_post_with_image(engine->fingerprint, key->private_key,
                                        task->params.wall_boost_post.text,
                                        task->params.wall_boost_post.image_json, &out_post);
    } else {
        ret = dna_wall_post(engine->fingerprint, key->private_key,
                            task->params.wall_boost_post.text, &out_post);
    }
    qgp_key_free(key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to post to wall for boost: %d", ret);
        task->callback.wall_post(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    /* Insert into cache */
    wall_cache_insert_post(&out_post);
    wall_cache_update_meta(engine->fingerprint);

    /* Step 2: Write boost pointer to daily key */
    ret = dna_wall_boost_post(out_post.uuid, engine->fingerprint, out_post.timestamp);
    if (ret != 0 && ret != -3) {
        /* Boost pointer failed but wall post succeeded — log but don't fail */
        QGP_LOG_WARN(LOG_TAG, "Wall post created but boost pointer failed (ret=%d)", ret);
    } else {
        QGP_LOG_INFO(LOG_TAG, "Boost post created: %s", out_post.uuid);
    }

    /* Convert to public API format */
    dna_wall_post_info_t *info = calloc(1, sizeof(dna_wall_post_info_t));
    if (!info) {
        free(out_post.image_json);
        task->callback.wall_post(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, task->user_data);
        return;
    }

    wall_post_to_info(&out_post, info);
    free(out_post.image_json);

    task->callback.wall_post(task->request_id, DNA_OK, info, task->user_data);
}

/* ── Load single day bucket (v0.9.141+) ── */

void dna_handle_wall_load_day(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    const char *fp = task->params.wall_load_day.fingerprint;
    const char *date = task->params.wall_load_day.date_str;

    /* ── Cache-first: past days are immutable, serve from cache ── */
    char today[16];
    engine_today_str(today, sizeof(today));
    bool is_today = (strcmp(date, today) == 0);

    if (!is_today) {
        int expected_count = wall_day_complete_get(fp, date);

        if (expected_count >= 0) {
            /* Day was fully fetched before */
            if (expected_count == 0) {
                QGP_LOG_DEBUG(LOG_TAG, "Load day %.16s... %s: complete (0 posts)",
                             fp, date);
                task->callback.wall_posts(task->request_id, DNA_OK,
                                          NULL, 0, task->user_data);
                return;
            }

            /* Load from cache */
            dna_wall_post_t *cached = NULL;
            size_t cached_count = 0;
            if (wall_cache_load_by_date(fp, date, &cached, &cached_count) == 0
                && cached) {
                if ((int)cached_count == expected_count) {
                    dna_wall_post_info_t *info = calloc(cached_count,
                                                         sizeof(dna_wall_post_info_t));
                    if (info) {
                        for (size_t i = 0; i < cached_count; i++) {
                            wall_post_to_info(&cached[i], &info[i]);
                        }
                        wall_cache_free_posts(cached, cached_count);
                        QGP_LOG_DEBUG(LOG_TAG,
                            "Load day %.16s... %s: cache hit (%zu posts)",
                            fp, date, cached_count);
                        task->callback.wall_posts(task->request_id, DNA_OK,
                                                  info, (int)cached_count,
                                                  task->user_data);
                        return;
                    }
                }
                /* Count mismatch — cache inconsistent, re-fetch from DHT */
                QGP_LOG_WARN(LOG_TAG,
                    "Load day %.16s... %s: count mismatch (expected=%d got=%zu)",
                    fp, date, expected_count, cached_count);
                wall_cache_free_posts(cached, cached_count);
            }
            /* Cache read failed — fall through to DHT */
        }
        /* Not fetched yet — fall through to DHT */
    }

    /* ── DHT fetch ── */
    dna_wall_t wall = {0};
    int ret = dna_wall_load_day(fp, date, &wall);

    if (ret != 0 || wall.post_count == 0) {
        if (!is_today) {
            wall_day_complete_set(fp, date, 0);
        }
        dna_wall_free(&wall);
        task->callback.wall_posts(task->request_id,
                                  ret == -2 ? DNA_OK
                                            : (ret != 0 ? DNA_ERROR_INTERNAL : DNA_OK),
                                  NULL, 0, task->user_data);
        return;
    }

    /* Store in cache */
    wall_cache_store(fp, wall.posts, wall.post_count);
    wall_cache_update_meta_day(fp, date);

    if (!is_today) {
        wall_day_complete_set(fp, date, (int)wall.post_count);
    }

    /* Convert to public API format */
    dna_wall_post_info_t *info = calloc(wall.post_count, sizeof(dna_wall_post_info_t));
    if (!info) {
        dna_wall_free(&wall);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    for (size_t i = 0; i < wall.post_count; i++) {
        wall_post_to_info(&wall.posts[i], &info[i]);
    }

    QGP_LOG_INFO(LOG_TAG, "Load day %.16s... %s: %zu posts (DHT)",
                 fp, date, wall.post_count);
    task->callback.wall_posts(task->request_id, DNA_OK,
                              info, (int)wall.post_count, task->user_data);
    dna_wall_free(&wall);
}

void dna_handle_wall_boost_timeline(dna_engine_t *engine, dna_task_t *task) {
    if (!engine->identity_loaded) {
        task->callback.wall_posts(task->request_id, DNA_ENGINE_ERROR_NO_IDENTITY,
                                  NULL, 0, task->user_data);
        return;
    }

    /* Fetch boost pointers from last 7 days */
    dna_wall_boost_ptr_t *ptrs = NULL;
    size_t ptr_count = 0;
    int ret = dna_wall_boost_load_recent(7, &ptrs, &ptr_count);

    if (ret != 0 || ptr_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "Boost timeline: no boosted posts found");
        task->callback.wall_posts(task->request_id, DNA_OK, NULL, 0, task->user_data);
        if (ptrs) dna_wall_boost_free(ptrs, ptr_count);
        return;
    }

    /* For each pointer, try to resolve the actual post.
     * First check wall cache, then fetch from DHT if needed. */
    dna_wall_post_info_t *results = calloc(ptr_count, sizeof(dna_wall_post_info_t));
    if (!results) {
        dna_wall_boost_free(ptrs, ptr_count);
        task->callback.wall_posts(task->request_id, DNA_ERROR_INTERNAL,
                                  NULL, 0, task->user_data);
        return;
    }

    int result_count = 0;

    for (size_t i = 0; i < ptr_count; i++) {
        const char *fp = ptrs[i].author_fingerprint;
        const char *target_uuid = ptrs[i].uuid;

        /* Try cache first */
        dna_wall_post_t *cached_posts = NULL;
        size_t cached_count = 0;
        bool found = false;

        if (wall_cache_load(fp, &cached_posts, &cached_count) == 0 && cached_posts) {
            for (size_t j = 0; j < cached_count; j++) {
                if (strncmp(cached_posts[j].uuid, target_uuid, 36) == 0) {
                    wall_post_to_info(&cached_posts[j], &results[result_count++]);
                    found = true;
                    break;
                }
            }
            wall_cache_free_posts(cached_posts, cached_count);
        }

        if (found) continue;

        /* Cache miss — fetch wall from DHT */
        dna_wall_t wall = {0};
        if (dna_wall_load(fp, &wall) == 0) {
            wall_cache_store(fp, wall.posts, wall.post_count);
            wall_cache_update_meta(fp);

            for (size_t j = 0; j < wall.post_count; j++) {
                if (strncmp(wall.posts[j].uuid, target_uuid, 36) == 0) {
                    wall_post_to_info(&wall.posts[j], &results[result_count++]);
                    found = true;
                    break;
                }
            }
            dna_wall_free(&wall);
        }

        if (!found) {
            QGP_LOG_DEBUG(LOG_TAG, "Boost: could not resolve post %s from %s (orphan)",
                          target_uuid, fp);
            /* Skip orphan pointers — don't store in cache */
            continue;
        }
    }

    /* Cache only resolved boost pointers (skip orphans) */
    if (result_count > 0) {
        /* Build clean pointer array from resolved results */
        dna_wall_boost_ptr_t *clean_ptrs = calloc((size_t)result_count,
                                                    sizeof(dna_wall_boost_ptr_t));
        if (clean_ptrs) {
            for (int r = 0; r < result_count; r++) {
                strncpy(clean_ptrs[r].uuid, results[r].uuid, 36);
                strncpy(clean_ptrs[r].author_fingerprint,
                        results[r].author_fingerprint, 128);
                clean_ptrs[r].timestamp = results[r].timestamp;
            }
            wall_cache_store_boosts(clean_ptrs, (size_t)result_count);
            free(clean_ptrs);
        }
    }

    dna_wall_boost_free(ptrs, ptr_count);

    QGP_LOG_INFO(LOG_TAG, "Boost timeline: resolved %d/%zu posts", result_count, ptr_count);
    task->callback.wall_posts(task->request_id, DNA_OK, results, result_count, task->user_data);
}

/* ── Wall Boost Public API ── */

dna_request_id_t dna_engine_wall_boost_post(
    dna_engine_t *engine,
    const char *text,
    dna_wall_post_cb callback,
    void *user_data
) {
    if (!engine || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.wall_boost_post.text = strdup(text);
    if (!params.wall_boost_post.text) return DNA_REQUEST_ID_INVALID;

    dna_task_callback_t cb = {0};
    cb.wall_post = callback;
    return dna_submit_task(engine, TASK_WALL_BOOST_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_boost_post_with_image(
    dna_engine_t *engine,
    const char *text,
    const char *image_json,
    dna_wall_post_cb callback,
    void *user_data
) {
    if (!engine || !text || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    params.wall_boost_post.text = strdup(text);
    if (!params.wall_boost_post.text) return DNA_REQUEST_ID_INVALID;

    if (image_json) {
        params.wall_boost_post.image_json = strdup(image_json);
        if (!params.wall_boost_post.image_json) {
            free(params.wall_boost_post.text);
            return DNA_REQUEST_ID_INVALID;
        }
    }

    dna_task_callback_t cb = {0};
    cb.wall_post = callback;
    return dna_submit_task(engine, TASK_WALL_BOOST_POST, &params, cb, user_data);
}

dna_request_id_t dna_engine_wall_boost_timeline(
    dna_engine_t *engine,
    dna_wall_posts_cb callback,
    void *user_data
) {
    if (!engine || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_BOOST_TIMELINE, &params, cb, user_data);
}

/* ── Wall Load Day (v0.9.141+) ── */

dna_request_id_t dna_engine_wall_load_day(
    dna_engine_t *engine,
    const char *fingerprint,
    const char *date_str,
    dna_wall_posts_cb callback,
    void *user_data
) {
    if (!engine || !fingerprint || !date_str || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_load_day.fingerprint, fingerprint, 128);
    params.wall_load_day.fingerprint[128] = '\0';
    strncpy(params.wall_load_day.date_str, date_str, 10);
    params.wall_load_day.date_str[10] = '\0';

    dna_task_callback_t cb = {0};
    cb.wall_posts = callback;
    return dna_submit_task(engine, TASK_WALL_LOAD_DAY, &params, cb, user_data);
}

/* ── Wall Get Image (v0.9.142+) ── */

void dna_handle_wall_get_image(dna_engine_t *engine, dna_task_t *task) {
    (void)engine;
    const char *uuid = task->params.wall_get_image.post_uuid;

    char *image_json = NULL;
    int ret = wall_cache_load_image(uuid, &image_json);

    if (ret == 0 && image_json) {
        task->callback.wall_image(task->request_id, DNA_OK,
                                   image_json, task->user_data);
        free(image_json);
    } else {
        task->callback.wall_image(task->request_id, DNA_OK,
                                   NULL, task->user_data);
    }
}

dna_request_id_t dna_engine_wall_get_image(
    dna_engine_t *engine,
    const char *post_uuid,
    dna_wall_image_cb callback,
    void *user_data
) {
    if (!engine || !post_uuid || !callback) return DNA_REQUEST_ID_INVALID;

    dna_task_params_t params = {0};
    strncpy(params.wall_get_image.post_uuid, post_uuid, 36);

    dna_task_callback_t cb = {0};
    cb.wall_image = callback;
    return dna_submit_task(engine, TASK_WALL_GET_IMAGE, &params, cb, user_data);
}
