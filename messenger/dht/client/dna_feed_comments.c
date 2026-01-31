/*
 * DNA Feeds v2 - Comment Operations
 *
 * Implements single-level threaded comment system for topics.
 * Comments can optionally reply to other comments via parent_comment_uuid.
 * Comments are stored as multi-owner values under topic key.
 *
 * Storage Model:
 * - Comments: SHA256("dna:feeds:topic:{uuid}:comments") (multi-owner)
 *
 * v2 Changes:
 * - Uses topic_uuid instead of post_id
 * - Supports @mentions (up to 10 fingerprints per comment)
 * - Uses UUID for comment identifiers
 * - Single-level threading via parent_comment_uuid (v0.6.96+)
 * - No voting system (deferred)
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
    dna_feed_comment_t comment = {0};

    /* Generate UUID */
    dna_feed_generate_uuid(comment.comment_uuid);

    /* Copy fields */
    strncpy(comment.topic_uuid, topic_uuid, DNA_FEED_UUID_LEN - 1);
    if (parent_comment_uuid && parent_comment_uuid[0] != '\0') {
        strncpy(comment.parent_comment_uuid, parent_comment_uuid, DNA_FEED_UUID_LEN - 1);
    }
    strncpy(comment.author_fingerprint, author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);
    strncpy(comment.body, body, DNA_FEED_MAX_COMMENT_LEN);
    comment.created_at = (uint64_t)time(NULL);
    comment.version = DNA_FEED_VERSION;

    /* Copy mentions */
    for (int i = 0; i < mention_count && mentions && mentions[i]; i++) {
        strncpy(comment.mentions[i], mentions[i], DNA_FEED_FINGERPRINT_LEN - 1);
        comment.mention_count++;
    }

    /* Sign comment: JSON without signature */
    char *json_to_sign = NULL;
    if (comment_to_json(&comment, false, &json_to_sign) != 0) {
        return -1;
    }

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(
        comment.signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign comment\n");
        return -1;
    }
    comment.signature_len = sig_len;

    /* Get DHT key for comments */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "dna:feeds:topic:%s:comments", topic_uuid);

    /* Get my value_id (unique per DHT identity) */
    uint64_t my_value_id = 1;
    dht_get_owner_value_id(dht_ctx, &my_value_id);

    /* Read-modify-write: fetch my existing comments, append new one */
    dna_feed_comment_t *my_comments = NULL;
    size_t my_count = 0;

    uint8_t **values = NULL;
    size_t *lens = NULL;
    uint64_t *value_ids = NULL;
    size_t value_count = 0;

    ret = dht_get_all_with_ids(dht_ctx, (const uint8_t *)comments_key, strlen(comments_key),
                                &values, &lens, &value_ids, &value_count);

    if (ret == 0 && value_count > 0) {
        /* Find my existing comments by author fingerprint */
        for (size_t i = 0; i < value_count; i++) {
            if (values[i] && lens[i] > 0) {
                char *json_str = malloc(lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, values[i], lens[i]);
                    json_str[lens[i]] = '\0';

                    /* Try to parse as array first */
                    json_object *arr = json_tokener_parse(json_str);
                    if (arr && json_object_is_type(arr, json_type_array)) {
                        int arr_len = json_object_array_length(arr);
                        if (arr_len > 0) {
                            json_object *first = json_object_array_get_idx(arr, 0);
                            json_object *author_obj;
                            if (json_object_object_get_ex(first, "author", &author_obj)) {
                                const char *arr_author = json_object_get_string(author_obj);
                                if (arr_author && strcmp(arr_author, author_fingerprint) == 0) {
                                    /* These are my comments - free any previous and reset count */
                                    free(my_comments);
                                    my_comments = calloc(arr_len, sizeof(dna_feed_comment_t));
                                    my_count = 0;  /* Reset count for new array */
                                    if (my_comments) {
                                        for (int j = 0; j < arr_len; j++) {
                                            json_object *c = json_object_array_get_idx(arr, j);
                                            const char *c_str = json_object_to_json_string(c);
                                            if (c_str) {
                                                if (comment_from_json(c_str, &my_comments[my_count]) == 0) {
                                                    my_count++;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        json_object_put(arr);
                    } else if (arr) {
                        /* Try single comment */
                        dna_feed_comment_t tmp;
                        if (comment_from_json(json_str, &tmp) == 0) {
                            if (strcmp(tmp.author_fingerprint, author_fingerprint) == 0) {
                                /* Free any previous and reset */
                                free(my_comments);
                                my_comments = calloc(1, sizeof(dna_feed_comment_t));
                                my_count = 0;  /* Reset before setting */
                                if (my_comments) {
                                    my_comments[0] = tmp;
                                    my_count = 1;
                                }
                            }
                        }
                        json_object_put(arr);
                    }
                    free(json_str);
                }
            }
            free(values[i]);
        }
        free(values);
        free(lens);
        free(value_ids);
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu existing comments from this author\n", my_count);

    /* Build array with existing + new comment */
    json_object *arr = json_object_new_array();

    /* Add existing comments */
    for (size_t i = 0; i < my_count; i++) {
        char *c_json = NULL;
        if (comment_to_json(&my_comments[i], true, &c_json) == 0) {
            json_object *c_obj = json_tokener_parse(c_json);
            if (c_obj) {
                json_object_array_add(arr, c_obj);
            }
            free(c_json);
        }
    }
    free(my_comments);

    /* Add new comment */
    char *new_json = NULL;
    if (comment_to_json(&comment, true, &new_json) != 0) {
        json_object_put(arr);
        return -1;
    }
    json_object *new_obj = json_tokener_parse(new_json);
    free(new_json);
    if (new_obj) {
        json_object_array_add(arr, new_obj);
    }

    const char *json_data = json_object_to_json_string(arr);
    QGP_LOG_INFO(LOG_TAG, "Publishing %zu comments to DHT (value_id=%llu)...\n",
                 my_count + 1, (unsigned long long)my_value_id);

    /* Publish as multi-owner signed value */
    ret = dht_put_signed(dht_ctx, (const uint8_t *)comments_key, strlen(comments_key),
                         (const uint8_t *)json_data, strlen(json_data),
                         my_value_id, DNA_FEED_TTL_SECONDS, "feed_comment");
    json_object_put(arr);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish comment\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created comment %s\n", comment.comment_uuid);

    /* Return UUID */
    if (uuid_out) {
        strncpy(uuid_out, comment.comment_uuid, DNA_FEED_UUID_LEN);
    }

    return 0;
}

int dna_feed_comments_get(dht_context_t *dht_ctx,
                          const char *topic_uuid,
                          dna_feed_comment_t **comments_out,
                          size_t *count_out) {
    if (!dht_ctx || !topic_uuid || !comments_out || !count_out) return -1;

    /* Get DHT key for comments */
    char comments_key[256];
    snprintf(comments_key, sizeof(comments_key), "dna:feeds:topic:%s:comments", topic_uuid);

    QGP_LOG_INFO(LOG_TAG, "Fetching comments for topic %s...\n", topic_uuid);

    /* Fetch all multi-owner values with value_ids for deduplication */
    uint8_t **values = NULL;
    size_t *value_lens = NULL;
    uint64_t *value_ids = NULL;
    size_t value_count = 0;

    int ret = dht_get_all_with_ids(dht_ctx, (const uint8_t *)comments_key, strlen(comments_key),
                                    &values, &value_lens, &value_ids, &value_count);

    if (ret != 0 || value_count == 0) {
        *comments_out = NULL;
        *count_out = 0;
        /* dht_get_all returns:
         *   0  = success (but we have count=0 here, so no values)
         *  -1 = no values found (empty DHT key)
         *  -2 = timeout (real error)
         * Treat -2 as error (-1), everything else as "not found" (-2)
         */
        return (ret == -2) ? -1 : -2;
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu comment values\n", value_count);

    /* Parse comments - values can be arrays or single objects */
    dna_feed_comment_t *comments = NULL;
    size_t capacity = 0;
    size_t parsed = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (values[i] && value_lens[i] > 0) {
            char *json_str = malloc(value_lens[i] + 1);
            if (json_str) {
                memcpy(json_str, values[i], value_lens[i]);
                json_str[value_lens[i]] = '\0';

                json_object *obj = json_tokener_parse(json_str);
                if (obj) {
                    if (json_object_is_type(obj, json_type_array)) {
                        /* Array of comments from one author */
                        int arr_len = json_object_array_length(obj);
                        for (int j = 0; j < arr_len; j++) {
                            json_object *c = json_object_array_get_idx(obj, j);
                            const char *c_str = json_object_to_json_string(c);

                            /* Expand array if needed */
                            if (parsed >= capacity) {
                                capacity = capacity ? capacity * 2 : 16;
                                dna_feed_comment_t *tmp = realloc(comments, capacity * sizeof(dna_feed_comment_t));
                                if (!tmp) break;
                                comments = tmp;
                            }

                            if (comment_from_json(c_str, &comments[parsed]) == 0) {
                                parsed++;
                            }
                        }
                    } else {
                        /* Single comment */
                        if (parsed >= capacity) {
                            capacity = capacity ? capacity * 2 : 16;
                            dna_feed_comment_t *tmp = realloc(comments, capacity * sizeof(dna_feed_comment_t));
                            if (!tmp) {
                                json_object_put(obj);
                                free(json_str);
                                continue;
                            }
                            comments = tmp;
                        }

                        if (comment_from_json(json_str, &comments[parsed]) == 0) {
                            parsed++;
                        }
                    }
                    json_object_put(obj);
                }
                free(json_str);
            }
        }
        free(values[i]);
    }
    free(values);
    free(value_lens);
    free(value_ids);

    if (parsed == 0) {
        free(comments);
        *comments_out = NULL;
        *count_out = 0;
        return -2;
    }

    /* Sort by created_at descending (newest first) */
    qsort(comments, parsed, sizeof(dna_feed_comment_t), compare_comment_by_time_desc);

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu comments\n", parsed);

    *comments_out = comments;
    *count_out = parsed;
    return 0;
}
