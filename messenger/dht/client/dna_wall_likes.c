/*
 * DNA Wall Likes - Like operations for wall posts
 *
 * Implements like system for wall posts using multi-owner DHT pattern.
 * Each liker stores their like under their own value_id.
 *
 * Storage Model:
 * - Likes: "dna:wall:likes:<post_uuid>" (multi-owner)
 * - Each liker stores one JSON value with their fingerprint + signature
 * - Client-side max 100 likes per post
 *
 * v0.9.52: Initial implementation
 */

#include "dna_wall.h"
#include "../shared/nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"

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

#define LOG_TAG "DNA_WALL_LIKES"

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
 * JSON Serialization
 * ========================================================================== */

static int like_to_json(const dna_wall_like_t *like, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "fp", json_object_new_string(like->author_fingerprint));
    json_object_object_add(root, "ts", json_object_new_int64((int64_t)like->timestamp));

    if (like->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(like->signature, like->signature_len, NULL);
        if (sig_b64) {
            json_object_object_add(root, "sig", json_object_new_string(sig_b64));
            free(sig_b64);
        }
    }

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int like_from_json(const char *json_str, dna_wall_like_t *like_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(like_out, 0, sizeof(dna_wall_like_t));

    json_object *j_val;

    if (json_object_object_get_ex(root, "fp", &j_val))
        strncpy(like_out->author_fingerprint, json_object_get_string(j_val), 128);
    if (json_object_object_get_ex(root, "ts", &j_val))
        like_out->timestamp = (uint64_t)json_object_get_int64(j_val);

    if (json_object_object_get_ex(root, "sig", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= sizeof(like_out->signature)) {
                memcpy(like_out->signature, sig_bytes, sig_len);
                like_out->signature_len = sig_len;
            }
            free(sig_bytes);
        }
    }

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * Like Operations
 * ========================================================================== */

void dna_wall_likes_free(dna_wall_like_t *likes, size_t count) {
    (void)count;
    free(likes);
}

int dna_wall_like_verify(const dna_wall_like_t *like,
                          const char *post_uuid,
                          const uint8_t *public_key) {
    if (!like || !post_uuid || !public_key || like->signature_len == 0) return -1;

    int ret = pqcrystals_dilithium5_ref_verify(
        like->signature, like->signature_len,
        (const uint8_t *)post_uuid, strlen(post_uuid),
        NULL, 0, public_key);

    return (ret == 0) ? 0 : -1;
}

int dna_wall_like_add(const char *post_uuid,
                       const char *author_fingerprint,
                       const uint8_t *private_key) {
    if (!post_uuid || !author_fingerprint || !private_key) {
        return -1;
    }

    /* Build DHT key */
    char likes_key[256];
    snprintf(likes_key, sizeof(likes_key), "%s%s",
             DNA_WALL_LIKE_KEY_PREFIX, post_uuid);

    /* Check existing likes: total count + already liked */
    uint8_t **all_values = NULL;
    size_t *all_lens = NULL;
    size_t all_count = 0;
    size_t total_likes = 0;

    int ret = nodus_ops_get_all_str(likes_key, &all_values, &all_lens, &all_count);

    if (ret == 0 && all_count > 0) {
        for (size_t i = 0; i < all_count; i++) {
            if (!all_values[i] || all_lens[i] == 0) continue;

            /* Parse like to check fingerprint */
            char *json_str = malloc(all_lens[i] + 1);
            if (!json_str) {
                free(all_values[i]);
                continue;
            }
            memcpy(json_str, all_values[i], all_lens[i]);
            json_str[all_lens[i]] = '\0';
            free(all_values[i]);

            dna_wall_like_t existing_like = {0};
            if (like_from_json(json_str, &existing_like) == 0) {
                total_likes++;

                /* Check if already liked by this user */
                if (strncmp(existing_like.author_fingerprint, author_fingerprint, 128) == 0) {
                    QGP_LOG_WARN(LOG_TAG, "Already liked post %s", post_uuid);
                    free(json_str);
                    /* Free remaining values */
                    for (size_t j = i + 1; j < all_count; j++)
                        free(all_values[j]);
                    free(all_values);
                    free(all_lens);
                    return -3; /* Already liked */
                }
            }
            free(json_str);
        }
        free(all_values);
        free(all_lens);
    }

    /* Check max likes */
    if (total_likes >= DNA_WALL_LIKE_MAX) {
        QGP_LOG_WARN(LOG_TAG, "Max likes (%d) reached for post %s",
                     DNA_WALL_LIKE_MAX, post_uuid);
        return -4;
    }

    /* Create like */
    dna_wall_like_t new_like = {0};
    strncpy(new_like.author_fingerprint, author_fingerprint, 128);
    new_like.timestamp = (uint64_t)time(NULL);

    /* Sign the post_uuid */
    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(
        new_like.signature, &sig_len,
        (const uint8_t *)post_uuid, strlen(post_uuid),
        NULL, 0, private_key);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign like for post %s", post_uuid);
        return -1;
    }
    new_like.signature_len = sig_len;

    /* Serialize to JSON */
    char *like_json = NULL;
    if (like_to_json(&new_like, &like_json) != 0) {
        return -1;
    }

    /* PUT to DHT with our value_id */
    QGP_LOG_INFO(LOG_TAG, "Publishing like for post %s", post_uuid);
    ret = nodus_ops_put_str(likes_key,
                             (const uint8_t *)like_json, strlen(like_json),
                             DNA_WALL_LIKE_TTL_SECONDS, nodus_ops_value_id());
    free(like_json);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT publish failed for like on post %s", post_uuid);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Like added for post %s (total: %zu)", post_uuid, total_likes + 1);
    return 0;
}

int dna_wall_likes_get(const char *post_uuid,
                        dna_wall_like_t **likes_out,
                        size_t *count_out) {
    if (!post_uuid || !likes_out || !count_out) return -1;

    *likes_out = NULL;
    *count_out = 0;

    char likes_key[256];
    snprintf(likes_key, sizeof(likes_key), "%s%s",
             DNA_WALL_LIKE_KEY_PREFIX, post_uuid);

    /* Fetch all likes from DHT (multi-owner) */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = nodus_ops_get_all_str(likes_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No likes found for post %s", post_uuid);
        return -2;
    }

    /* Parse all likes, dedup by fingerprint */
    dna_wall_like_t *all_likes = calloc(value_count, sizeof(dna_wall_like_t));
    if (!all_likes) {
        for (size_t i = 0; i < value_count; i++)
            free(values[i]);
        free(values);
        free(lens);
        return -1;
    }

    size_t total = 0;
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

        dna_wall_like_t like = {0};
        if (like_from_json(json_str, &like) == 0 && like.author_fingerprint[0] != '\0') {
            /* Dedup by fingerprint */
            bool duplicate = false;
            for (size_t j = 0; j < total; j++) {
                if (strncmp(all_likes[j].author_fingerprint,
                            like.author_fingerprint, 128) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                all_likes[total++] = like;
            }
        }
        free(json_str);
    }

    free(values);
    free(lens);

    if (total == 0) {
        free(all_likes);
        return -2;
    }

    *likes_out = all_likes;
    *count_out = total;

    QGP_LOG_DEBUG(LOG_TAG, "Fetched %zu likes for post %s", total, post_uuid);
    return 0;
}
