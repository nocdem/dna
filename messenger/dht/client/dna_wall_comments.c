/*
 * DNA Wall Comments - Comment operations for wall posts
 *
 * Implements single-level threaded comment system for wall posts.
 * Comments can optionally reply to other comments via parent_comment_uuid.
 * Comments are stored as multi-owner chunked values under post key.
 *
 * Storage Model (same as feed comments):
 * - Comments: "dna:wall:comments:<post_uuid>" (multi-owner)
 * - Each author stores their comments in their own value_id slot
 * - Uses nodus_ops_* functions (Nodus native)
 *
 * v0.7.0: Initial implementation
 */

#include "dna_wall.h"
#include "../shared/nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <json-c/json.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define LOG_TAG "DNA_WALL_COMMENTS"

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* UUID v4 generation (local) */
static void wall_comment_generate_uuid(char *uuid_out) {
    uint8_t bytes[16];
    qgp_randombytes(bytes, 16);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  /* Version 4 */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  /* Variant 1 */
    snprintf(uuid_out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/* ============================================================================
 * Comparison Functions for qsort
 * ========================================================================== */

static int compare_comment_by_time_desc(const void *a, const void *b) {
    const dna_wall_comment_t *ca = (const dna_wall_comment_t *)a;
    const dna_wall_comment_t *cb = (const dna_wall_comment_t *)b;
    if (cb->created_at > ca->created_at) return 1;
    if (cb->created_at < ca->created_at) return -1;
    return 0;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int comment_to_json(const dna_wall_comment_t *comment, bool include_signature, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(comment->version));
    json_object_object_add(root, "uuid", json_object_new_string(comment->uuid));
    json_object_object_add(root, "post_uuid", json_object_new_string(comment->post_uuid));

    if (comment->parent_comment_uuid[0] != '\0') {
        json_object_object_add(root, "parent_uuid",
                               json_object_new_string(comment->parent_comment_uuid));
    }

    json_object_object_add(root, "author", json_object_new_string(comment->author_fingerprint));
    json_object_object_add(root, "body", json_object_new_string(comment->body));
    json_object_object_add(root, "created_at", json_object_new_int64(comment->created_at));

    if (comment->comment_type > 0) {
        json_object_object_add(root, "comment_type", json_object_new_int(comment->comment_type));
    }

    if (include_signature && comment->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(comment->signature, comment->signature_len, NULL);
        if (sig_b64) {
            json_object_object_add(root, "signature", json_object_new_string(sig_b64));
            free(sig_b64);
        }
    }

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int comment_from_json(const char *json_str, dna_wall_comment_t *comment_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(comment_out, 0, sizeof(dna_wall_comment_t));

    json_object *j_val;

    if (json_object_object_get_ex(root, "version", &j_val))
        comment_out->version = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "uuid", &j_val))
        strncpy(comment_out->uuid, json_object_get_string(j_val), 36);
    if (json_object_object_get_ex(root, "post_uuid", &j_val))
        strncpy(comment_out->post_uuid, json_object_get_string(j_val), 36);
    if (json_object_object_get_ex(root, "parent_uuid", &j_val))
        strncpy(comment_out->parent_comment_uuid, json_object_get_string(j_val), 36);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(comment_out->author_fingerprint, json_object_get_string(j_val), 128);
    if (json_object_object_get_ex(root, "body", &j_val))
        strncpy(comment_out->body, json_object_get_string(j_val), DNA_WALL_COMMENT_MAX_BODY);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        comment_out->created_at = json_object_get_int64(j_val);

    if (json_object_object_get_ex(root, "comment_type", &j_val))
        comment_out->comment_type = json_object_get_int(j_val);
    /* else: defaults to 0 (text) from memset */

    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= sizeof(comment_out->signature)) {
                memcpy(comment_out->signature, sig_bytes, sig_len);
                comment_out->signature_len = sig_len;
            }
            free(sig_bytes);
        }
    }

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * Bucket Serialization (multi-owner pattern)
 * ========================================================================== */

static int comments_bucket_to_json(const dna_wall_comment_t *comments, size_t count, char **json_out) {
    json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (size_t i = 0; i < count; i++) {
        char *c_json = NULL;
        if (comment_to_json(&comments[i], true, &c_json) == 0) {
            json_object *c_obj = json_tokener_parse(c_json);
            if (c_obj) {
                json_object_array_add(arr, c_obj);
            }
            free(c_json);
        }
    }

    const char *json_str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(arr);

    return *json_out ? 0 : -1;
}

static int comments_bucket_from_json(const char *json_str, dna_wall_comment_t **comments_out, size_t *count_out) {
    *comments_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json_str);
    if (!arr) return -1;

    if (!json_object_is_type(arr, json_type_array)) {
        /* Try single comment */
        dna_wall_comment_t *single = calloc(1, sizeof(dna_wall_comment_t));
        if (single && comment_from_json(json_str, single) == 0) {
            *comments_out = single;
            *count_out = 1;
            json_object_put(arr);
            return 0;
        }
        free(single);
        json_object_put(arr);
        return -1;
    }

    int arr_len = json_object_array_length(arr);
    if (arr_len == 0) {
        json_object_put(arr);
        return 0;
    }

    dna_wall_comment_t *comments = calloc(arr_len, sizeof(dna_wall_comment_t));
    if (!comments) {
        json_object_put(arr);
        return -1;
    }

    size_t parsed = 0;
    for (int i = 0; i < arr_len; i++) {
        json_object *c = json_object_array_get_idx(arr, i);
        const char *c_str = json_object_to_json_string(c);
        if (c_str && comment_from_json(c_str, &comments[parsed]) == 0) {
            parsed++;
        }
    }

    json_object_put(arr);

    if (parsed == 0) {
        free(comments);
        return -1;
    }

    *comments_out = comments;
    *count_out = parsed;
    return 0;
}

/* ============================================================================
 * Comment Operations
 * ========================================================================== */

void dna_wall_comments_free(dna_wall_comment_t *comments, size_t count) {
    (void)count;
    free(comments);
}

int dna_wall_comment_verify(const dna_wall_comment_t *comment, const uint8_t *public_key) {
    if (!comment || !public_key || comment->signature_len == 0) return -1;

    /* Build JSON without signature for verification */
    dna_wall_comment_t temp = *comment;
    temp.signature_len = 0;
    memset(temp.signature, 0, sizeof(temp.signature));

    char *json_data = NULL;
    if (comment_to_json(&temp, false, &json_data) != 0) {
        return -1;
    }

    int ret = pqcrystals_dilithium5_ref_verify(
        comment->signature, comment->signature_len,
        (const uint8_t *)json_data, strlen(json_data),
        NULL, 0, public_key);

    free(json_data);
    return (ret == 0) ? 0 : -1;
}

int dna_wall_comment_add(const char *post_uuid,
                          const char *parent_comment_uuid,
                          const char *body,
                          const char *author_fingerprint,
                          const uint8_t *private_key,
                          uint32_t comment_type,
                          char *uuid_out) {
    if (!post_uuid || !body || !author_fingerprint || !private_key) {
        return -1;
    }

    size_t body_len = strlen(body);
    if (body_len == 0 || body_len > DNA_WALL_COMMENT_MAX_BODY) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid comment body length: %zu", body_len);
        return -1;
    }

    /* Create comment structure */
    dna_wall_comment_t new_comment = {0};

    wall_comment_generate_uuid(new_comment.uuid);
    strncpy(new_comment.post_uuid, post_uuid, 36);
    if (parent_comment_uuid && parent_comment_uuid[0] != '\0') {
        strncpy(new_comment.parent_comment_uuid, parent_comment_uuid, 36);
    }
    strncpy(new_comment.author_fingerprint, author_fingerprint, 128);
    strncpy(new_comment.body, body, DNA_WALL_COMMENT_MAX_BODY);
    new_comment.created_at = (uint64_t)time(NULL);
    new_comment.version = DNA_WALL_COMMENT_VERSION;
    new_comment.comment_type = comment_type;

    /* Sign comment: JSON without signature */
    char *json_to_sign = NULL;
    if (comment_to_json(&new_comment, false, &json_to_sign) != 0) {
        return -1;
    }

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(
        new_comment.signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign wall comment");
        return -1;
    }
    new_comment.signature_len = sig_len;

    /* Get DHT key for comments on this post */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "%s%s",
             DNA_WALL_COMMENT_KEY_PREFIX, post_uuid);

    /* Fetch MY existing comments from the multi-owner key.
     * Uses get_all_with_ids and filters by our value_id. */
    dna_wall_comment_t *existing_comments = NULL;
    size_t existing_count = 0;

    uint8_t **all_values = NULL;
    size_t *all_lens = NULL;
    uint64_t *all_vids = NULL;
    size_t all_count = 0;
    uint64_t my_vid = nodus_ops_value_id();

    ret = nodus_ops_get_all_str_with_ids(comments_key, &all_values, &all_lens,
                                          &all_vids, &all_count);

    if (ret == 0 && all_count > 0) {
        for (size_t i = 0; i < all_count; i++) {
            if (all_vids[i] == my_vid && all_values[i] && all_lens[i] > 0) {
                char *json_str = malloc(all_lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, all_values[i], all_lens[i]);
                    json_str[all_lens[i]] = '\0';
                    comments_bucket_from_json(json_str, &existing_comments, &existing_count);
                    free(json_str);
                }
                break;
            }
        }
        for (size_t i = 0; i < all_count; i++)
            free(all_values[i]);
        free(all_values);
        free(all_lens);
        free(all_vids);
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu existing comments from this author on post %s",
                 existing_count, post_uuid);

    /* Build new array with existing + new comment */
    size_t new_count = existing_count + 1;
    dna_wall_comment_t *all_comments = calloc(new_count, sizeof(dna_wall_comment_t));
    if (!all_comments) {
        free(existing_comments);
        return -1;
    }

    for (size_t i = 0; i < existing_count; i++) {
        all_comments[i] = existing_comments[i];
    }
    free(existing_comments);

    all_comments[existing_count] = new_comment;

    /* Serialize and publish using nodus_ops_put_str() */
    char *bucket_json = NULL;
    if (comments_bucket_to_json(all_comments, new_count, &bucket_json) != 0) {
        free(all_comments);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu comments to key %s", new_count, comments_key);

    ret = nodus_ops_put_str(comments_key,
                             (const uint8_t *)bucket_json, strlen(bucket_json),
                             DNA_WALL_COMMENT_TTL_SECONDS, nodus_ops_value_id());

    free(bucket_json);
    free(all_comments);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT publish failed for wall comment");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created wall comment %s", new_comment.uuid);

    if (uuid_out) {
        strncpy(uuid_out, new_comment.uuid, 37);
    }

    return 0;
}

int dna_wall_comments_get(const char *post_uuid,
                           dna_wall_comment_t **comments_out,
                           size_t *count_out) {
    if (!post_uuid || !comments_out || !count_out) return -1;

    *comments_out = NULL;
    *count_out = 0;

    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "%s%s",
             DNA_WALL_COMMENT_KEY_PREFIX, post_uuid);

    QGP_LOG_INFO(LOG_TAG, "Fetching comments for post %s", post_uuid);

    /* Fetch all authors' comments using nodus_ops_get_all_str() */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = nodus_ops_get_all_str(comments_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No comments found for post %s", post_uuid);
        return -2;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Got %zu author buckets for post %s", value_count, post_uuid);

    /* Merge all comments from all authors */
    dna_wall_comment_t *all_comments = NULL;
    size_t total_count = 0;
    size_t allocated = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || lens[i] == 0) continue;

        char *json_str = malloc(lens[i] + 1);
        if (!json_str) {
            free(values[i]);
            continue;
        }

        memcpy(json_str, values[i], lens[i]);
        json_str[lens[i]] = '\0';
        free(values[i]);

        dna_wall_comment_t *bucket_comments = NULL;
        size_t bucket_count = 0;

        if (comments_bucket_from_json(json_str, &bucket_comments, &bucket_count) == 0 && bucket_comments) {
            if (total_count + bucket_count > allocated) {
                size_t new_alloc = allocated == 0 ? 64 : allocated * 2;
                while (new_alloc < total_count + bucket_count) new_alloc *= 2;

                dna_wall_comment_t *new_arr = realloc(all_comments, new_alloc * sizeof(dna_wall_comment_t));
                if (!new_arr) {
                    free(bucket_comments);
                    free(json_str);
                    continue;
                }
                all_comments = new_arr;
                allocated = new_alloc;
            }

            for (size_t j = 0; j < bucket_count; j++) {
                /* Deduplicate by UUID — skip if already merged */
                bool duplicate = false;
                for (size_t k = 0; k < total_count; k++) {
                    if (strncmp(all_comments[k].uuid, bucket_comments[j].uuid, 36) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    all_comments[total_count++] = bucket_comments[j];
                } else {
                    QGP_LOG_DEBUG(LOG_TAG, "Skipping duplicate comment %s",
                                  bucket_comments[j].uuid);
                }
            }
            free(bucket_comments);
        }
        free(json_str);
    }

    free(values);
    free(lens);

    if (total_count == 0) {
        free(all_comments);
        return -2;
    }

    /* Sort by created_at descending (newest first) */
    qsort(all_comments, total_count, sizeof(dna_wall_comment_t), compare_comment_by_time_desc);

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu comments from %zu authors for post %s",
                 total_count, value_count, post_uuid);

    *comments_out = all_comments;
    *count_out = total_count;
    return 0;
}
