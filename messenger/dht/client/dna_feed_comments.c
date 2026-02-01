/*
 * DNA Feeds v2 - Comment Operations
 *
 * Implements single-level threaded comment system for topics.
 * Comments can optionally reply to other comments via parent_comment_uuid.
 * Comments are stored as multi-owner chunked values under topic key.
 *
 * Storage Model (v3 - Same as Groups):
 * - Comments: "dna:feeds:topic:{uuid}:comments" (chunked, multi-owner)
 * - Each author stores their comments in their own value_id slot
 * - Uses dht_chunked_* functions like dna_group_outbox.c
 *
 * v3 Changes (v0.6.104):
 * - Uses dht_chunked_fetch_mine() for reading my comments
 * - Uses dht_chunked_publish() for writing my comments
 * - Uses dht_chunked_fetch_all() for reading all comments
 * - Same pattern as dna_group_outbox.c
 */

#include "dna_feed.h"
#include "../shared/dht_chunked.h"
#include "../core/dht_context.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define LOG_TAG "DNA_COMMENTS"

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* ============================================================================
 * Comparison Functions for qsort
 * ========================================================================== */

/* Compare comments by created_at descending (newest first) */
static int compare_comment_by_time_desc(const void *a, const void *b) {
    const dna_feed_comment_t *ca = (const dna_feed_comment_t *)a;
    const dna_feed_comment_t *cb = (const dna_feed_comment_t *)b;
    /* Descending: b - a */
    if (cb->created_at > ca->created_at) return 1;
    if (cb->created_at < ca->created_at) return -1;
    return 0;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int comment_to_json(const dna_feed_comment_t *comment, bool include_signature, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(comment->version));
    json_object_object_add(root, "comment_uuid", json_object_new_string(comment->comment_uuid));
    json_object_object_add(root, "topic_uuid", json_object_new_string(comment->topic_uuid));

    /* Parent comment UUID for replies (omit if empty for backward compat) */
    if (comment->parent_comment_uuid[0] != '\0') {
        json_object_object_add(root, "parent_comment_uuid",
                               json_object_new_string(comment->parent_comment_uuid));
    }

    json_object_object_add(root, "author", json_object_new_string(comment->author_fingerprint));
    json_object_object_add(root, "body", json_object_new_string(comment->body));
    json_object_object_add(root, "created_at", json_object_new_int64(comment->created_at));

    /* Mentions array */
    json_object *mentions = json_object_new_array();
    for (int i = 0; i < comment->mention_count; i++) {
        json_object_array_add(mentions, json_object_new_string(comment->mentions[i]));
    }
    json_object_object_add(root, "mentions", mentions);

    /* Signature (base64) - only if requested */
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

static int comment_from_json(const char *json_str, dna_feed_comment_t *comment_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(comment_out, 0, sizeof(dna_feed_comment_t));

    json_object *j_val;

    if (json_object_object_get_ex(root, "version", &j_val))
        comment_out->version = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "comment_uuid", &j_val))
        strncpy(comment_out->comment_uuid, json_object_get_string(j_val), DNA_FEED_UUID_LEN - 1);
    if (json_object_object_get_ex(root, "topic_uuid", &j_val))
        strncpy(comment_out->topic_uuid, json_object_get_string(j_val), DNA_FEED_UUID_LEN - 1);
    if (json_object_object_get_ex(root, "parent_comment_uuid", &j_val))
        strncpy(comment_out->parent_comment_uuid, json_object_get_string(j_val), DNA_FEED_UUID_LEN - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(comment_out->author_fingerprint, json_object_get_string(j_val), DNA_FEED_FINGERPRINT_LEN - 1);
    if (json_object_object_get_ex(root, "body", &j_val))
        strncpy(comment_out->body, json_object_get_string(j_val), DNA_FEED_MAX_COMMENT_LEN);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        comment_out->created_at = json_object_get_int64(j_val);

    /* Mentions array */
    json_object *j_mentions;
    if (json_object_object_get_ex(root, "mentions", &j_mentions)) {
        int count = json_object_array_length(j_mentions);
        if (count > DNA_FEED_MAX_MENTIONS) count = DNA_FEED_MAX_MENTIONS;
        comment_out->mention_count = count;
        for (int i = 0; i < count; i++) {
            json_object *j_mention = json_object_array_get_idx(j_mentions, i);
            if (j_mention) {
                strncpy(comment_out->mentions[i], json_object_get_string(j_mention), DNA_FEED_FINGERPRINT_LEN - 1);
            }
        }
    }

    /* Signature (base64) */
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
 * Bucket Serialization (like groups)
 * ========================================================================== */

/**
 * Serialize comment array to JSON for DHT storage
 */
static int comments_bucket_to_json(const dna_feed_comment_t *comments, size_t count, char **json_out) {
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

/**
 * Deserialize JSON to comment array
 */
static int comments_bucket_from_json(const char *json_str, dna_feed_comment_t **comments_out, size_t *count_out) {
    *comments_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json_str);
    if (!arr) return -1;

    if (!json_object_is_type(arr, json_type_array)) {
        /* Try single comment */
        dna_feed_comment_t *single = calloc(1, sizeof(dna_feed_comment_t));
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

    dna_feed_comment_t *comments = calloc(arr_len, sizeof(dna_feed_comment_t));
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

void dna_feed_comment_free(dna_feed_comment_t *comment) {
    free(comment);
}

void dna_feed_comments_free(dna_feed_comment_t *comments, size_t count) {
    (void)count;  /* Comments are in a single allocation */
    free(comments);
}

int dna_feed_comment_verify(const dna_feed_comment_t *comment, const uint8_t *public_key) {
    if (!comment || !public_key || comment->signature_len == 0) return -1;

    /* Build JSON without signature for verification */
    dna_feed_comment_t temp = *comment;
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

int dna_feed_comment_add(dht_context_t *dht_ctx,
                         const char *topic_uuid,
                         const char *parent_comment_uuid,
                         const char *body,
                         const char **mentions,
                         int mention_count,
                         const char *author_fingerprint,
                         const uint8_t *private_key,
                         char *uuid_out) {
    if (!dht_ctx || !topic_uuid || !body || !author_fingerprint || !private_key) {
        return -1;
    }

    /* Validate body length */
    size_t body_len = strlen(body);
    if (body_len == 0 || body_len > DNA_FEED_MAX_COMMENT_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid comment body length: %zu\n", body_len);
        return -1;
    }

    /* Validate mention count */
    if (mention_count < 0 || mention_count > DNA_FEED_MAX_MENTIONS) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid mention count: %d\n", mention_count);
        return -1;
    }

    /* Create comment structure */
    dna_feed_comment_t new_comment = {0};

    /* Generate UUID */
    dna_feed_generate_uuid(new_comment.comment_uuid);

    /* Copy fields */
    strncpy(new_comment.topic_uuid, topic_uuid, DNA_FEED_UUID_LEN - 1);
    if (parent_comment_uuid && parent_comment_uuid[0] != '\0') {
        strncpy(new_comment.parent_comment_uuid, parent_comment_uuid, DNA_FEED_UUID_LEN - 1);
    }
    strncpy(new_comment.author_fingerprint, author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);
    strncpy(new_comment.body, body, DNA_FEED_MAX_COMMENT_LEN);
    new_comment.created_at = (uint64_t)time(NULL);
    new_comment.version = DNA_FEED_VERSION;

    /* Copy mentions */
    for (int i = 0; i < mention_count && mentions && mentions[i]; i++) {
        strncpy(new_comment.mentions[i], mentions[i], DNA_FEED_FINGERPRINT_LEN - 1);
        new_comment.mention_count++;
    }

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
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign comment\n");
        return -1;
    }
    new_comment.signature_len = sig_len;

    /* Get DHT key for comments */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "dna:feeds:topic:%s:comments", topic_uuid);

    /* Step 1: Fetch MY existing comments using dht_chunked_fetch_mine() */
    dna_feed_comment_t *existing_comments = NULL;
    size_t existing_count = 0;

    uint8_t *existing_data = NULL;
    size_t existing_len = 0;
    ret = dht_chunked_fetch_mine(dht_ctx, comments_key, &existing_data, &existing_len);

    if (ret == 0 && existing_data && existing_len > 0) {
        char *json_str = malloc(existing_len + 1);
        if (json_str) {
            memcpy(json_str, existing_data, existing_len);
            json_str[existing_len] = '\0';
            comments_bucket_from_json(json_str, &existing_comments, &existing_count);
            free(json_str);
        }
        free(existing_data);
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu existing comments from this author\n", existing_count);

    /* Step 2: Build new array with existing + new comment */
    size_t new_count = existing_count + 1;
    dna_feed_comment_t *all_comments = calloc(new_count, sizeof(dna_feed_comment_t));
    if (!all_comments) {
        free(existing_comments);
        return -1;
    }

    /* Copy existing comments */
    for (size_t i = 0; i < existing_count; i++) {
        all_comments[i] = existing_comments[i];
    }
    free(existing_comments);

    /* Add new comment */
    all_comments[existing_count] = new_comment;

    /* Step 3: Serialize and publish using dht_chunked_publish() */
    char *bucket_json = NULL;
    if (comments_bucket_to_json(all_comments, new_count, &bucket_json) != 0) {
        free(all_comments);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu comments to key %s\n", new_count, comments_key);

    ret = dht_chunked_publish(dht_ctx, comments_key,
                               (const uint8_t *)bucket_json, strlen(bucket_json),
                               DNA_FEED_TTL_SECONDS);

    free(bucket_json);
    free(all_comments);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT chunked publish failed: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created comment %s\n", new_comment.comment_uuid);

    /* Return UUID */
    if (uuid_out) {
        strncpy(uuid_out, new_comment.comment_uuid, DNA_FEED_UUID_LEN);
    }

    return 0;
}

int dna_feed_comments_get(dht_context_t *dht_ctx,
                          const char *topic_uuid,
                          dna_feed_comment_t **comments_out,
                          size_t *count_out) {
    if (!dht_ctx || !topic_uuid || !comments_out || !count_out) return -1;

    *comments_out = NULL;
    *count_out = 0;

    /* Get DHT key for comments */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "dna:feeds:topic:%s:comments", topic_uuid);

    QGP_LOG_INFO(LOG_TAG, "Fetching comments for topic %s from key %s\n", topic_uuid, comments_key);

    /* Fetch all authors' comments using dht_chunked_fetch_all() */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = dht_chunked_fetch_all(dht_ctx, comments_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No comment buckets found at key %s\n", comments_key);
        return -2; /* No comments */
    }

    QGP_LOG_DEBUG(LOG_TAG, "Got %zu author buckets from key %s\n", value_count, comments_key);

    /* Merge all comments from all authors */
    dna_feed_comment_t *all_comments = NULL;
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

        dna_feed_comment_t *bucket_comments = NULL;
        size_t bucket_count = 0;

        if (comments_bucket_from_json(json_str, &bucket_comments, &bucket_count) == 0 && bucket_comments) {
            /* Expand array if needed */
            if (total_count + bucket_count > allocated) {
                size_t new_alloc = allocated == 0 ? 64 : allocated * 2;
                while (new_alloc < total_count + bucket_count) new_alloc *= 2;

                dna_feed_comment_t *new_arr = realloc(all_comments, new_alloc * sizeof(dna_feed_comment_t));
                if (!new_arr) {
                    free(bucket_comments);
                    free(json_str);
                    continue;
                }
                all_comments = new_arr;
                allocated = new_alloc;
            }

            /* Copy comments */
            for (size_t j = 0; j < bucket_count; j++) {
                all_comments[total_count++] = bucket_comments[j];
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
    qsort(all_comments, total_count, sizeof(dna_feed_comment_t), compare_comment_by_time_desc);

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu comments from %zu authors\n", total_count, value_count);

    *comments_out = all_comments;
    *count_out = total_count;
    return 0;
}
