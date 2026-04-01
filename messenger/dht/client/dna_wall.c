/*
 * DNA Wall - Personal wall posts stored on DHT
 *
 * Each user's wall posts are stored under a per-user DHT key:
 *   SHA3-512("dna:wall:<fingerprint>")
 *
 * Posts are signed with Dilithium5 for authenticity.
 * Max 50 posts per user, 30-day TTL, text-only (MVP).
 */

#include "dna_wall.h"
#include "../shared/nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <json-c/json.h>

/* Cross-platform big-endian conversion */
#ifdef _WIN32
#include <winsock2.h>
#define htobe64(x) ( \
    ((uint64_t)(htonl((uint32_t)((x) & 0xFFFFFFFF))) << 32) | \
    ((uint64_t)(htonl((uint32_t)((x) >> 32)))) \
)
#else
#include <endian.h>
#endif

#define LOG_TAG "DNA_WALL"

/* ============================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * Generate a UUID v4 string
 */
static void wall_generate_uuid(char *uuid_out) {
    uint8_t bytes[16];
    qgp_randombytes(bytes, 16);

    /* Set version 4 (random) and variant bits */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  /* Version 4 */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  /* Variant 1 */

    snprintf(uuid_out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/**
 * Build signing payload for a wall post:
 *   uuid + text + timestamp_be (8 bytes) [+ SHA3-512(image_json) if present]
 *
 * When image_json is present, its SHA3-512 hash (64 bytes) is appended.
 * This ensures image data integrity without bloating the signing payload.
 * Old clients without image support produce the same payload for text-only posts.
 *
 * Caller must free the returned buffer.
 */
static uint8_t *wall_build_sign_payload(const dna_wall_post_t *post, size_t *payload_len_out) {
    if (!post || !payload_len_out) return NULL;

    size_t uuid_len = strlen(post->uuid);
    size_t text_len = strlen(post->text);
    bool has_image = (post->image_json != NULL && post->image_json[0] != '\0');
    size_t payload_len = uuid_len + text_len + 8 + (has_image ? 64 : 0);

    uint8_t *payload = malloc(payload_len);
    if (!payload) return NULL;

    memcpy(payload, post->uuid, uuid_len);
    memcpy(payload + uuid_len, post->text, text_len);

    uint64_t ts_be = htobe64(post->timestamp);
    memcpy(payload + uuid_len + text_len, &ts_be, 8);

    /* Append SHA3-512 hash of image_json if present */
    if (has_image) {
        qgp_sha3_512((const uint8_t *)post->image_json, strlen(post->image_json),
                      payload + uuid_len + text_len + 8);
    }

    *payload_len_out = payload_len;
    return payload;
}

/**
 * Build the DHT base key string for a user's wall
 */
static void wall_base_key(const char *fingerprint, char *base_key, size_t base_key_size) {
    snprintf(base_key, base_key_size, "%s%s", DNA_WALL_KEY_PREFIX, fingerprint);
}

/**
 * Build DHT key for a daily wall bucket: "dna:wall:<fp>:<YYYY-MM-DD>"
 */
static void wall_bucket_key(const char *fingerprint, const char *date_str,
                             char *base_key, size_t base_key_size) {
    snprintf(base_key, base_key_size, "%s%s:%s", DNA_WALL_KEY_PREFIX, fingerprint, date_str);
}

/**
 * Build DHT key for wall metadata: "dna:wall:meta:<fp>"
 */
static void wall_meta_key(const char *fingerprint, char *base_key, size_t base_key_size) {
    snprintf(base_key, base_key_size, "%s%s", DNA_WALL_META_KEY_PREFIX, fingerprint);
}

/**
 * Get today's date as "YYYY-MM-DD" (UTC).
 */
static void wall_today_str(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm tm_now;
#ifdef _WIN32
    gmtime_s(&tm_now, &now);
#else
    gmtime_r(&now, &tm_now);
#endif
    strftime(buf, buf_size, "%Y-%m-%d", &tm_now);
}

/**
 * Convert Unix timestamp to "YYYY-MM-DD" (UTC).
 */
static void wall_date_from_timestamp(uint64_t ts, char *buf, size_t buf_size) {
    time_t t = (time_t)ts;
    struct tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    strftime(buf, buf_size, "%Y-%m-%d", &tm_val);
}

/* ============================================================================
 * DHT Key Derivation
 * ========================================================================== */

void dna_wall_make_key(const char *fingerprint, uint8_t *out_key) {
    if (!fingerprint || !out_key) return;

    char input[256];
    snprintf(input, sizeof(input), "%s%s", DNA_WALL_KEY_PREFIX, fingerprint);

    qgp_sha3_512((const uint8_t *)input, strlen(input), out_key);
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

char *dna_wall_to_json(const dna_wall_t *wall) {
    if (!wall) return NULL;

    json_object *arr = json_object_new_array();
    if (!arr) return NULL;

    for (size_t i = 0; i < wall->post_count; i++) {
        const dna_wall_post_t *post = &wall->posts[i];

        json_object *obj = json_object_new_object();
        if (!obj) {
            json_object_put(arr);
            return NULL;
        }

        json_object_object_add(obj, "uuid", json_object_new_string(post->uuid));
        json_object_object_add(obj, "author", json_object_new_string(post->author_fingerprint));
        json_object_object_add(obj, "text", json_object_new_string(post->text));
        json_object_object_add(obj, "ts", json_object_new_int64((int64_t)post->timestamp));

        /* Image JSON (v0.7.0+) - omit if not present for backward compat */
        if (post->image_json && post->image_json[0] != '\0') {
            json_object *img_obj = json_tokener_parse(post->image_json);
            if (img_obj) {
                json_object_object_add(obj, "img", img_obj);
            }
        }

        /* Signature as base64 */
        if (post->signature_len > 0) {
            char *sig_b64 = qgp_base64_encode(post->signature, post->signature_len, NULL);
            if (sig_b64) {
                json_object_object_add(obj, "sig", json_object_new_string(sig_b64));
                free(sig_b64);
            }
        }

        json_object_array_add(arr, obj);
    }

    const char *json_str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    char *result = json_str ? strdup(json_str) : NULL;
    json_object_put(arr);

    return result;
}

int dna_wall_from_json(const char *json, dna_wall_t *wall) {
    if (!json || !wall) return -1;

    json_object *arr = json_tokener_parse(json);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }

    size_t count = (size_t)json_object_array_length(arr);
    if (count == 0) {
        wall->posts = NULL;
        wall->post_count = 0;
        json_object_put(arr);
        return 0;
    }

    wall->posts = calloc(count, sizeof(dna_wall_post_t));
    if (!wall->posts) {
        json_object_put(arr);
        return -1;
    }
    wall->post_count = count;

    for (size_t i = 0; i < count; i++) {
        json_object *obj = json_object_array_get_idx(arr, (int)i);
        if (!obj) {
            QGP_LOG_WARN(LOG_TAG, "Malformed wall JSON: missing post at index %zu", i);
            free(wall->posts);
            wall->posts = NULL;
            wall->post_count = 0;
            json_object_put(arr);
            return -1;
        }

        dna_wall_post_t *post = &wall->posts[i];
        json_object *j_val;

        if (json_object_object_get_ex(obj, "uuid", &j_val)) {
            const char *str = json_object_get_string(j_val);
            if (str) strncpy(post->uuid, str, 36);
        }
        post->uuid[36] = '\0';

        if (json_object_object_get_ex(obj, "author", &j_val)) {
            const char *str = json_object_get_string(j_val);
            if (str) strncpy(post->author_fingerprint, str, 128);
        }
        post->author_fingerprint[128] = '\0';

        if (json_object_object_get_ex(obj, "text", &j_val)) {
            const char *str = json_object_get_string(j_val);
            if (str) strncpy(post->text, str, DNA_WALL_MAX_TEXT_LEN - 1);
        }
        post->text[DNA_WALL_MAX_TEXT_LEN - 1] = '\0';

        if (json_object_object_get_ex(obj, "ts", &j_val))
            post->timestamp = (uint64_t)json_object_get_int64(j_val);

        /* Image JSON (v0.7.0+) - old posts won't have this field */
        if (json_object_object_get_ex(obj, "img", &j_val) && j_val) {
            const char *img_str = json_object_to_json_string_ext(j_val, JSON_C_TO_STRING_PLAIN);
            if (img_str) {
                post->image_json = strdup(img_str);
            }
        }

        if (json_object_object_get_ex(obj, "sig", &j_val)) {
            const char *sig_b64 = json_object_get_string(j_val);
            if (sig_b64) {
                size_t sig_len = 0;
                uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
                if (!sig_bytes) {
                    QGP_LOG_WARN(LOG_TAG, "Failed to decode signature base64 for post %zu", i);
                } else if (sig_len > 0 && sig_len <= sizeof(post->signature)) {
                    memcpy(post->signature, sig_bytes, sig_len);
                    post->signature_len = sig_len;
                } else {
                    QGP_LOG_WARN(LOG_TAG, "Invalid signature length %zu for post %zu", sig_len, i);
                }
                free(sig_bytes);
            }
        }

        post->verified = false;
    }

    json_object_put(arr);
    return 0;
}

/* ============================================================================
 * Content dedup — prevent duplicate posts within a time window
 * ========================================================================== */

#define WALL_DEDUP_WINDOW_SEC 300  /* 5 minutes */

/**
 * Check if a post with the same text (and optionally image) already exists
 * in the wall within the dedup window. Returns the matching post index or -1.
 */
static int wall_find_duplicate(const dna_wall_t *wall, const char *text,
                                const char *image_json) {
    if (!wall || !wall->posts || wall->post_count == 0 || !text) return -1;

    uint64_t now = (uint64_t)time(NULL);

    for (size_t i = 0; i < wall->post_count; i++) {
        const dna_wall_post_t *p = &wall->posts[i];

        /* Only check recent posts */
        if (now - p->timestamp > WALL_DEDUP_WINDOW_SEC) continue;

        /* Text must match */
        if (strcmp(p->text, text) != 0) continue;

        /* Image presence must match */
        bool existing_has_image = (p->image_json != NULL && p->image_json[0] != '\0');
        bool new_has_image = (image_json != NULL && image_json[0] != '\0');

        if (existing_has_image != new_has_image) continue;

        /* If both have images, compare image_json */
        if (existing_has_image && new_has_image) {
            if (strcmp(p->image_json, image_json) != 0) continue;
        }

        QGP_LOG_WARN(LOG_TAG, "Duplicate post detected: existing=%s (age=%llu s)",
                     p->uuid, (unsigned long long)(now - p->timestamp));
        return (int)i;
    }

    return -1;
}

/* ============================================================================
 * Wall Operations
 * ========================================================================== */

int dna_wall_post(const char *fingerprint,
                  const uint8_t *private_key,
                  const char *text,
                  dna_wall_post_t *out_post) {
    if (!fingerprint || !private_key || !text) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for wall post");
        return -1;
    }

    /* Validate text */
    size_t text_len = strlen(text);
    if (text_len == 0 || text_len >= DNA_WALL_MAX_TEXT_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid text length: %zu", text_len);
        return -1;
    }

    /* Create new post */
    dna_wall_post_t new_post;
    memset(&new_post, 0, sizeof(new_post));

    wall_generate_uuid(new_post.uuid);
    strncpy(new_post.author_fingerprint, fingerprint, 128);
    new_post.author_fingerprint[128] = '\0';
    strncpy(new_post.text, text, DNA_WALL_MAX_TEXT_LEN - 1);
    new_post.text[DNA_WALL_MAX_TEXT_LEN - 1] = '\0';
    new_post.timestamp = (uint64_t)time(NULL);

    /* Build signing payload and sign */
    size_t payload_len = 0;
    uint8_t *payload = wall_build_sign_payload(&new_post, &payload_len);
    if (!payload) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build signing payload");
        return -1;
    }

    size_t sig_len = 0;
    int ret = qgp_dsa87_sign(new_post.signature, &sig_len,
                              payload, payload_len, private_key);
    free(payload);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign wall post");
        return -1;
    }
    new_post.signature_len = sig_len;
    new_post.verified = true;

    /* Load today's bucket from DHT (daily bucket storage v0.9.141+) */
    char today[16];
    wall_today_str(today, sizeof(today));

    dna_wall_t bucket;
    memset(&bucket, 0, sizeof(bucket));
    strncpy(bucket.owner_fingerprint, fingerprint, 128);
    bucket.owner_fingerprint[128] = '\0';

    int load_ret = dna_wall_load_day(fingerprint, today, &bucket);
    if (load_ret != 0 && load_ret != -2 && load_ret != NODUS_ERR_NOT_FOUND) {
        QGP_LOG_WARN(LOG_TAG, "Failed to load today's bucket, starting fresh");
        bucket.posts = NULL;
        bucket.post_count = 0;
    }

    /* Content dedup within today's bucket */
    int dup_idx = wall_find_duplicate(&bucket, text, NULL);
    if (dup_idx >= 0) {
        QGP_LOG_WARN(LOG_TAG, "Dedup: returning existing post %s instead of creating duplicate",
                     bucket.posts[dup_idx].uuid);
        if (out_post) {
            *out_post = bucket.posts[dup_idx];
            out_post->image_json = bucket.posts[dup_idx].image_json
                ? strdup(bucket.posts[dup_idx].image_json) : NULL;
        }
        dna_wall_free(&bucket);
        return 0;
    }

    /* Max posts check via meta total */
    dna_wall_meta_t meta = {0};
    int meta_ret = dna_wall_load_meta(fingerprint, &meta);
    if (meta_ret == 0 && meta.total_posts >= DNA_WALL_MAX_POSTS) {
        QGP_LOG_WARN(LOG_TAG, "Max posts reached (%zu), rejecting new post",
                     meta.total_posts);
        dna_wall_meta_free(&meta);
        dna_wall_free(&bucket);
        return -5;
    }
    dna_wall_meta_free(&meta);

    /* Append new post to today's bucket */
    dna_wall_post_t *new_posts = realloc(bucket.posts,
                                          (bucket.post_count + 1) * sizeof(dna_wall_post_t));
    if (!new_posts) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for new post");
        dna_wall_free(&bucket);
        return -1;
    }
    bucket.posts = new_posts;
    bucket.posts[bucket.post_count] = new_post;
    bucket.post_count++;

    /* Serialize and publish today's bucket to DHT */
    char *json_str = dna_wall_to_json(&bucket);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize bucket to JSON");
        dna_wall_free(&bucket);
        return -1;
    }

    char bkey[512];
    wall_bucket_key(fingerprint, today, bkey, sizeof(bkey));

    QGP_LOG_INFO(LOG_TAG, "Publishing wall post %s to bucket %s", new_post.uuid, today);
    ret = nodus_ops_put_str_exclusive(bkey,
                                      (const uint8_t *)json_str, strlen(json_str),
                                      nodus_ops_value_id());
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish bucket (ret=%d)", ret);
        dna_wall_free(&bucket);
        return -1;
    }

    /* Update meta key */
    dna_wall_update_meta(fingerprint, today, 1);

    /* Fill out_post if requested */
    if (out_post) {
        *out_post = new_post;
    }

    QGP_LOG_INFO(LOG_TAG, "Wall post %s published to bucket %s", new_post.uuid, today);
    dna_wall_free(&bucket);
    return 0;
}

int dna_wall_post_with_image(const char *fingerprint,
                              const uint8_t *private_key,
                              const char *text,
                              const char *image_json,
                              dna_wall_post_t *out_post) {
    if (!image_json) {
        /* No image — delegate to text-only variant */
        return dna_wall_post(fingerprint, private_key, text, out_post);
    }

    if (!fingerprint || !private_key || !text) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for wall post with image");
        return -1;
    }

    size_t text_len = strlen(text);
    if (text_len == 0 || text_len >= DNA_WALL_MAX_TEXT_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid text length: %zu", text_len);
        return -1;
    }

    /* Create new post with image */
    dna_wall_post_t new_post;
    memset(&new_post, 0, sizeof(new_post));

    wall_generate_uuid(new_post.uuid);
    strncpy(new_post.author_fingerprint, fingerprint, 128);
    new_post.author_fingerprint[128] = '\0';
    strncpy(new_post.text, text, DNA_WALL_MAX_TEXT_LEN - 1);
    new_post.text[DNA_WALL_MAX_TEXT_LEN - 1] = '\0';
    new_post.image_json = strdup(image_json);
    new_post.timestamp = (uint64_t)time(NULL);

    /* Build signing payload (includes image hash) and sign */
    size_t payload_len = 0;
    uint8_t *payload = wall_build_sign_payload(&new_post, &payload_len);
    if (!payload) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build signing payload");
        free(new_post.image_json);
        return -1;
    }

    size_t sig_len = 0;
    int ret = qgp_dsa87_sign(new_post.signature, &sig_len,
                              payload, payload_len, private_key);
    free(payload);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign wall post");
        free(new_post.image_json);
        return -1;
    }
    new_post.signature_len = sig_len;
    new_post.verified = true;

    /* Load today's bucket from DHT (daily bucket storage v0.9.141+) */
    char today[16];
    wall_today_str(today, sizeof(today));

    dna_wall_t bucket;
    memset(&bucket, 0, sizeof(bucket));
    strncpy(bucket.owner_fingerprint, fingerprint, 128);
    bucket.owner_fingerprint[128] = '\0';

    int load_ret = dna_wall_load_day(fingerprint, today, &bucket);
    if (load_ret != 0 && load_ret != -2 && load_ret != NODUS_ERR_NOT_FOUND) {
        QGP_LOG_WARN(LOG_TAG, "Failed to load today's bucket, starting fresh");
        bucket.posts = NULL;
        bucket.post_count = 0;
    }

    /* Content dedup within today's bucket */
    int dup_idx = wall_find_duplicate(&bucket, text, image_json);
    if (dup_idx >= 0) {
        QGP_LOG_WARN(LOG_TAG, "Dedup: returning existing post %s instead of creating duplicate",
                     bucket.posts[dup_idx].uuid);
        if (out_post) {
            *out_post = bucket.posts[dup_idx];
            out_post->image_json = bucket.posts[dup_idx].image_json
                ? strdup(bucket.posts[dup_idx].image_json) : NULL;
        }
        free(new_post.image_json);
        dna_wall_free(&bucket);
        return 0;
    }

    /* Max posts check via meta total */
    dna_wall_meta_t meta = {0};
    int meta_ret = dna_wall_load_meta(fingerprint, &meta);
    if (meta_ret == 0 && meta.total_posts >= DNA_WALL_MAX_POSTS) {
        QGP_LOG_WARN(LOG_TAG, "Max posts reached (%zu), rejecting new post",
                     meta.total_posts);
        dna_wall_meta_free(&meta);
        free(new_post.image_json);
        dna_wall_free(&bucket);
        return -5;
    }
    dna_wall_meta_free(&meta);

    /* Append new post to today's bucket */
    dna_wall_post_t *new_posts = realloc(bucket.posts,
                                          (bucket.post_count + 1) * sizeof(dna_wall_post_t));
    if (!new_posts) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for new post");
        free(new_post.image_json);
        dna_wall_free(&bucket);
        return -1;
    }
    bucket.posts = new_posts;
    bucket.posts[bucket.post_count] = new_post;
    bucket.post_count++;

    /* Serialize and publish today's bucket to DHT */
    char *json_str = dna_wall_to_json(&bucket);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize bucket to JSON");
        dna_wall_free(&bucket);
        return -1;
    }

    char bkey[512];
    wall_bucket_key(fingerprint, today, bkey, sizeof(bkey));

    QGP_LOG_INFO(LOG_TAG, "Publishing wall post %s (with image) to bucket %s", new_post.uuid, today);
    ret = nodus_ops_put_str_exclusive(bkey,
                                      (const uint8_t *)json_str, strlen(json_str),
                                      nodus_ops_value_id());
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish bucket (ret=%d)", ret);
        dna_wall_free(&bucket);
        return -1;
    }

    /* Update meta key */
    dna_wall_update_meta(fingerprint, today, 1);

    /* Fill out_post with a separate copy of image_json (bucket_free will free the array's copy) */
    if (out_post) {
        *out_post = new_post;
        out_post->image_json = new_post.image_json ? strdup(new_post.image_json) : NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Wall post %s (with image) published to bucket %s", new_post.uuid, today);
    dna_wall_free(&bucket);
    return 0;
}

int dna_wall_delete(const char *fingerprint,
                    const uint8_t *private_key,
                    const char *post_uuid,
                    uint64_t post_timestamp) {
    if (!fingerprint || !private_key || !post_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for wall delete");
        return -1;
    }

    /* Derive bucket day from post timestamp */
    char date_str[16];
    if (post_timestamp > 0) {
        wall_date_from_timestamp(post_timestamp, date_str, sizeof(date_str));
    } else {
        /* Fallback: use today (caller should provide timestamp) */
        wall_today_str(date_str, sizeof(date_str));
        QGP_LOG_WARN(LOG_TAG, "Delete without timestamp, assuming today: %s", date_str);
    }

    /* Load the day's bucket */
    dna_wall_t bucket;
    memset(&bucket, 0, sizeof(bucket));
    int ret = dna_wall_load_day(fingerprint, date_str, &bucket);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load bucket %s for delete (rc=%d)", date_str, ret);
        return ret;
    }

    /* Find and remove the post */
    bool found = false;
    for (size_t i = 0; i < bucket.post_count; i++) {
        if (strcmp(bucket.posts[i].uuid, post_uuid) == 0) {
            free(bucket.posts[i].image_json);
            if (i < bucket.post_count - 1) {
                memmove(&bucket.posts[i], &bucket.posts[i + 1],
                        (bucket.post_count - i - 1) * sizeof(dna_wall_post_t));
            }
            bucket.post_count--;
            found = true;
            break;
        }
    }

    if (!found) {
        QGP_LOG_WARN(LOG_TAG, "Post %s not found in bucket %s", post_uuid, date_str);
        dna_wall_free(&bucket);
        return -1;
    }

    /* Re-serialize and republish the bucket */
    char bkey[512];
    wall_bucket_key(fingerprint, date_str, bkey, sizeof(bkey));

    if (bucket.post_count > 0) {
        char *json_str = dna_wall_to_json(&bucket);
        if (!json_str) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to serialize bucket after delete");
            dna_wall_free(&bucket);
            return -1;
        }
        ret = nodus_ops_put_str_exclusive(bkey, (const uint8_t *)json_str, strlen(json_str),
                                          nodus_ops_value_id());
        free(json_str);
    } else {
        /* Empty bucket — publish empty array so DHT overwrites */
        ret = nodus_ops_put_str_exclusive(bkey, (const uint8_t *)"[]", 2,
                                          nodus_ops_value_id());
    }
    dna_wall_free(&bucket);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to republish bucket %s (ret=%d)", date_str, ret);
        return -1;
    }

    /* Update meta */
    dna_wall_update_meta(fingerprint, date_str, -1);

    QGP_LOG_INFO(LOG_TAG, "Post %s deleted from bucket %s", post_uuid, date_str);
    return 0;
}

int dna_wall_load(const char *fingerprint,
                  dna_wall_t *wall) {
    if (!fingerprint || !wall) {
        return -1;
    }
    memset(wall, 0, sizeof(*wall));
    strncpy(wall->owner_fingerprint, fingerprint, 128);
    wall->owner_fingerprint[128] = '\0';

    /* Try daily bucket format first (v0.9.141+) */
    dna_wall_meta_t meta = {0};
    int meta_ret = dna_wall_load_meta(fingerprint, &meta);

    if (meta_ret == 0 && meta.day_count > 0) {
        /* Aggregate posts from all day buckets */
        for (size_t d = 0; d < meta.day_count; d++) {
            dna_wall_t day_wall = {0};
            int day_ret = dna_wall_load_day(fingerprint, meta.days[d], &day_wall);
            if (day_ret != 0 || day_wall.post_count == 0) {
                dna_wall_free(&day_wall);
                continue;
            }

            /* Grow posts array */
            dna_wall_post_t *grown = realloc(wall->posts,
                (wall->post_count + day_wall.post_count) * sizeof(dna_wall_post_t));
            if (!grown) {
                dna_wall_free(&day_wall);
                continue;
            }
            wall->posts = grown;

            /* Copy posts (transfer ownership of image_json pointers) */
            for (size_t i = 0; i < day_wall.post_count; i++) {
                wall->posts[wall->post_count] = day_wall.posts[i];
                wall->posts[wall->post_count].image_json =
                    day_wall.posts[i].image_json ? strdup(day_wall.posts[i].image_json) : NULL;
                wall->post_count++;
            }
            dna_wall_free(&day_wall);
        }
        dna_wall_meta_free(&meta);

        /* Sort by timestamp DESC */
        for (size_t i = 1; i < wall->post_count; i++) {
            dna_wall_post_t tmp = wall->posts[i];
            size_t j = i;
            while (j > 0 && wall->posts[j - 1].timestamp < tmp.timestamp) {
                wall->posts[j] = wall->posts[j - 1];
                j--;
            }
            wall->posts[j] = tmp;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Loaded wall for %.16s...: %zu posts from %zu buckets",
                      fingerprint, wall->post_count, meta.day_count);
        return wall->post_count > 0 ? 0 : -2;
    }
    dna_wall_meta_free(&meta);

    /* No meta found — no wall posts for this user */
    QGP_LOG_DEBUG(LOG_TAG, "No meta for %.16s..., no wall", fingerprint);
    return meta_ret;
}

/* ============================================================================
 * Memory Management
 * ========================================================================== */

void dna_wall_free(dna_wall_t *wall) {
    if (!wall) return;
    if (wall->posts) {
        for (size_t i = 0; i < wall->post_count; i++) {
            free(wall->posts[i].image_json);
        }
        free(wall->posts);
    }
    wall->posts = NULL;
    wall->post_count = 0;
}

/* ============================================================================
 * Wall Meta — Daily Bucket Metadata (v0.9.141+)
 * ========================================================================== */

char *dna_wall_meta_to_json(const dna_wall_meta_t *meta) {
    if (!meta) return NULL;

    json_object *obj = json_object_new_object();
    if (!obj) return NULL;

    json_object *days_arr = json_object_new_array();
    if (!days_arr) { json_object_put(obj); return NULL; }

    for (size_t i = 0; i < meta->day_count; i++) {
        json_object_array_add(days_arr, json_object_new_string(meta->days[i]));
    }
    json_object_object_add(obj, "days", days_arr);

    /* Per-day counts (v0.9.142+) */
    if (meta->day_post_counts) {
        json_object *counts_arr = json_object_new_array();
        if (counts_arr) {
            for (size_t i = 0; i < meta->day_count; i++) {
                json_object_array_add(counts_arr,
                    json_object_new_int(meta->day_post_counts[i]));
            }
            json_object_object_add(obj, "counts", counts_arr);
        }
    }

    json_object_object_add(obj, "total", json_object_new_int64((int64_t)meta->total_posts));
    json_object_object_add(obj, "updated", json_object_new_int64((int64_t)meta->updated));

    const char *str = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    char *result = str ? strdup(str) : NULL;
    json_object_put(obj);
    return result;
}

int dna_wall_meta_from_json(const char *json, dna_wall_meta_t *meta) {
    if (!json || !meta) return -1;
    memset(meta, 0, sizeof(*meta));

    json_object *obj = json_tokener_parse(json);
    if (!obj) return -1;

    json_object *jv;

    /* Parse days array */
    if (json_object_object_get_ex(obj, "days", &jv) &&
        json_object_is_type(jv, json_type_array)) {
        int arr_len = json_object_array_length(jv);
        if (arr_len > 0) {
            meta->days = calloc((size_t)arr_len, sizeof(char *));
            if (meta->days) {
                meta->day_count = 0;
                for (int i = 0; i < arr_len; i++) {
                    json_object *elem = json_object_array_get_idx(jv, (size_t)i);
                    const char *s = json_object_get_string(elem);
                    if (s && strlen(s) == 10) {  /* "YYYY-MM-DD" */
                        meta->days[meta->day_count++] = strdup(s);
                    }
                }
            }
        }
    }

    /* Parse per-day counts (v0.9.142+, optional for backward compat) */
    if (json_object_object_get_ex(obj, "counts", &jv) &&
        json_object_is_type(jv, json_type_array)) {
        int counts_len = json_object_array_length(jv);
        if (counts_len > 0 && (size_t)counts_len == meta->day_count) {
            meta->day_post_counts = calloc((size_t)counts_len, sizeof(int));
            if (meta->day_post_counts) {
                for (int i = 0; i < counts_len; i++) {
                    json_object *elem = json_object_array_get_idx(jv, (size_t)i);
                    meta->day_post_counts[i] = json_object_get_int(elem);
                }
            }
        }
    }
    /* If "counts" not present (old format), day_post_counts stays NULL */

    if (json_object_object_get_ex(obj, "total", &jv))
        meta->total_posts = (size_t)json_object_get_int64(jv);
    if (json_object_object_get_ex(obj, "updated", &jv))
        meta->updated = (uint64_t)json_object_get_int64(jv);

    json_object_put(obj);
    return 0;
}

void dna_wall_meta_free(dna_wall_meta_t *meta) {
    if (!meta) return;
    if (meta->days) {
        for (size_t i = 0; i < meta->day_count; i++) {
            free(meta->days[i]);
        }
        free(meta->days);
    }
    free(meta->day_post_counts);  /* NULL-safe */
    memset(meta, 0, sizeof(*meta));
}

int dna_wall_load_day(const char *fingerprint, const char *date_str,
                      dna_wall_t *wall) {
    if (!fingerprint || !date_str || !wall) return -1;
    memset(wall, 0, sizeof(*wall));

    char key[512];
    wall_bucket_key(fingerprint, date_str, key, sizeof(key));

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = nodus_ops_get_str(key, &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No bucket found for %.16s... day=%s (rc=%d)",
                      fingerprint, date_str, ret);
        free(value);
        return ret == 0 ? -2 : ret;
    }

    char *json_str = malloc(value_len + 1);
    if (!json_str) { free(value); return -1; }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = dna_wall_from_json(json_str, wall);
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse bucket JSON for %.16s... day=%s",
                      fingerprint, date_str);
        return -1;
    }

    strncpy(wall->owner_fingerprint, fingerprint, 128);
    wall->owner_fingerprint[128] = '\0';

    QGP_LOG_DEBUG(LOG_TAG, "Loaded bucket %.16s... day=%s: %zu posts",
                  fingerprint, date_str, wall->post_count);
    return 0;
}

int dna_wall_load_meta(const char *fingerprint, dna_wall_meta_t *meta) {
    if (!fingerprint || !meta) return -1;
    memset(meta, 0, sizeof(*meta));

    char key[512];
    wall_meta_key(fingerprint, key, sizeof(key));

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = nodus_ops_get_str(key, &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No meta found for %.16s... (rc=%d)",
                      fingerprint, ret);
        free(value);
        return ret == 0 ? -2 : ret;
    }

    char *json_str = malloc(value_len + 1);
    if (!json_str) { free(value); return -1; }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = dna_wall_meta_from_json(json_str, meta);
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse meta JSON for %.16s...", fingerprint);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Loaded meta %.16s...: %zu days, %zu total posts",
                  fingerprint, meta->day_count, meta->total_posts);
    return 0;
}

int dna_wall_update_meta(const char *fingerprint, const char *date_str, int delta) {
    if (!fingerprint || !date_str) return -1;

    /* Load existing meta (or start fresh) */
    dna_wall_meta_t meta = {0};
    int load_ret = dna_wall_load_meta(fingerprint, &meta);
    if (load_ret != 0 && load_ret != -2 && load_ret != NODUS_ERR_NOT_FOUND) {
        /* -2 or NODUS_ERR_NOT_FOUND(2) = not found (ok, start fresh) */
        dna_wall_meta_free(&meta);
        return load_ret;
    }

    /* Find if date_str already in days[] */
    int found_idx = -1;
    for (size_t i = 0; i < meta.day_count; i++) {
        if (meta.days[i] && strcmp(meta.days[i], date_str) == 0) {
            found_idx = (int)i;
            break;
        }
    }

    if (delta > 0 && found_idx < 0) {
        /* Add new day — insert sorted (newest first) */
        char **new_days = realloc(meta.days, (meta.day_count + 1) * sizeof(char *));
        if (!new_days) { dna_wall_meta_free(&meta); return -1; }
        meta.days = new_days;

        /* Grow day_post_counts (or allocate if NULL — old format upgrade) */
        int *new_counts = realloc(meta.day_post_counts,
                                   (meta.day_count + 1) * sizeof(int));
        if (!new_counts) {
            /* Allocate fresh if was NULL */
            new_counts = calloc(meta.day_count + 1, sizeof(int));
        }
        if (new_counts) {
            meta.day_post_counts = new_counts;
        }

        /* Find insertion point (days sorted descending) */
        size_t insert_at = 0;
        for (size_t i = 0; i < meta.day_count; i++) {
            if (strcmp(date_str, meta.days[i]) > 0) {
                insert_at = i;
                break;
            }
            insert_at = i + 1;
        }

        /* Shift right — both days and counts */
        for (size_t i = meta.day_count; i > insert_at; i--) {
            meta.days[i] = meta.days[i - 1];
            if (meta.day_post_counts) {
                meta.day_post_counts[i] = meta.day_post_counts[i - 1];
            }
        }
        meta.days[insert_at] = strdup(date_str);
        if (meta.day_post_counts) {
            meta.day_post_counts[insert_at] = (delta > 0) ? delta : 0;
        }
        meta.day_count++;
    } else if (found_idx >= 0 && meta.day_post_counts) {
        /* Existing day — update count */
        meta.day_post_counts[found_idx] += delta;
        if (meta.day_post_counts[found_idx] < 0) {
            meta.day_post_counts[found_idx] = 0;
        }
    }

    /* Update total */
    if (delta > 0) {
        meta.total_posts += (size_t)delta;
    } else if (delta < 0 && meta.total_posts > 0) {
        size_t abs_delta = (size_t)(-delta);
        meta.total_posts = meta.total_posts > abs_delta ? meta.total_posts - abs_delta : 0;
    }

    /* If delta < 0 and the day's bucket might be empty, caller should check
     * and remove the day. For now, keep the day in meta — bg-refresh will
     * reconcile if bucket is truly empty. */

    meta.updated = (uint64_t)time(NULL);

    /* Serialize and publish */
    char *json_str = dna_wall_meta_to_json(&meta);
    dna_wall_meta_free(&meta);
    if (!json_str) return -1;

    char key[512];
    wall_meta_key(fingerprint, key, sizeof(key));

    int ret = nodus_ops_put_str_exclusive(key, (const uint8_t *)json_str, strlen(json_str),
                                          nodus_ops_value_id());
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish meta for %.16s... (ret=%d)",
                      fingerprint, ret);
        return ret;
    }

    QGP_LOG_INFO(LOG_TAG, "Meta updated for %.16s...: day=%s delta=%d",
                 fingerprint, date_str, delta);
    return 0;
}

/* ============================================================================
 * Verification
 * ========================================================================== */

int dna_wall_post_verify(const dna_wall_post_t *post,
                         const uint8_t *public_key) {
    if (!post || !public_key || post->signature_len == 0) return -1;

    /* Build same signing payload */
    size_t payload_len = 0;
    uint8_t *payload = wall_build_sign_payload(post, &payload_len);
    if (!payload) return -1;

    int ret = qgp_dsa87_verify(post->signature, post->signature_len,
                                payload, payload_len, public_key);
    free(payload);

    return (ret == 0) ? 0 : -1;
}

/* ============================================================================
 * Boost Operations (v0.9.71+)
 * ========================================================================== */

/**
 * Build the DHT base key string for a daily boost feed.
 */
static void boost_base_key(const char *date_str, char *base_key, size_t base_key_size) {
    snprintf(base_key, base_key_size, "%s%s", DNA_WALL_BOOST_KEY_PREFIX, date_str);
}

/**
 * Get today's date as "YYYY-MM-DD".
 */
static void boost_today_str(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm tm_now;
#ifdef _WIN32
    gmtime_s(&tm_now, &now);
#else
    gmtime_r(&now, &tm_now);
#endif
    strftime(buf, buf_size, "%Y-%m-%d", &tm_now);
}

/**
 * Serialize boost pointer array to JSON string.
 */
static char *boost_ptrs_to_json(const dna_wall_boost_ptr_t *ptrs, size_t count) {
    json_object *arr = json_object_new_array();
    if (!arr) return NULL;

    for (size_t i = 0; i < count; i++) {
        json_object *obj = json_object_new_object();
        if (!obj) continue;
        json_object_object_add(obj, "uuid", json_object_new_string(ptrs[i].uuid));
        json_object_object_add(obj, "author", json_object_new_string(ptrs[i].author_fingerprint));
        json_object_object_add(obj, "ts", json_object_new_int64((int64_t)ptrs[i].timestamp));
        json_object_array_add(arr, obj);
    }

    const char *str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    char *result = str ? strdup(str) : NULL;
    json_object_put(arr);
    return result;
}

/**
 * Deserialize boost pointers from JSON string.
 * Caller must free *ptrs_out.
 */
static int boost_ptrs_from_json(const char *json_str,
                                 dna_wall_boost_ptr_t **ptrs_out,
                                 size_t *count_out) {
    *ptrs_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json_str);
    if (!arr) return -1;

    if (!json_object_is_type(arr, json_type_array)) {
        json_object_put(arr);
        return -1;
    }

    int arr_len = json_object_array_length(arr);
    if (arr_len == 0) {
        json_object_put(arr);
        return 0;
    }

    dna_wall_boost_ptr_t *ptrs = calloc((size_t)arr_len, sizeof(dna_wall_boost_ptr_t));
    if (!ptrs) {
        json_object_put(arr);
        return -1;
    }

    size_t parsed = 0;
    for (int i = 0; i < arr_len; i++) {
        json_object *obj = json_object_array_get_idx(arr, i);
        if (!obj) continue;

        json_object *j_val;
        dna_wall_boost_ptr_t *p = &ptrs[parsed];

        if (json_object_object_get_ex(obj, "uuid", &j_val)) {
            const char *s = json_object_get_string(j_val);
            if (s) strncpy(p->uuid, s, 36);
        }
        p->uuid[36] = '\0';

        if (json_object_object_get_ex(obj, "author", &j_val)) {
            const char *s = json_object_get_string(j_val);
            if (s) strncpy(p->author_fingerprint, s, 128);
        }
        p->author_fingerprint[128] = '\0';

        if (json_object_object_get_ex(obj, "ts", &j_val))
            p->timestamp = (uint64_t)json_object_get_int64(j_val);

        if (p->uuid[0] != '\0' && p->author_fingerprint[0] != '\0')
            parsed++;
    }

    json_object_put(arr);

    if (parsed == 0) {
        free(ptrs);
        return -1;
    }

    *ptrs_out = ptrs;
    *count_out = parsed;
    return 0;
}

int dna_wall_boost_post(const char *post_uuid,
                         const char *author_fingerprint,
                         uint64_t post_timestamp) {
    if (!post_uuid || !author_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for boost post");
        return -1;
    }

    /* Build today's boost key */
    char today[16];
    boost_today_str(today, sizeof(today));

    char base_key[256];
    boost_base_key(today, base_key, sizeof(base_key));

    uint64_t my_vid = nodus_ops_value_id();

    /* Fetch my existing boost pointers for today (multi-owner: filter by my vid) */
    dna_wall_boost_ptr_t *existing = NULL;
    size_t existing_count = 0;

    uint8_t **all_values = NULL;
    size_t *all_lens = NULL;
    uint64_t *all_vids = NULL;
    size_t all_count = 0;

    int ret = nodus_ops_get_all_str_with_ids(base_key, &all_values, &all_lens,
                                              &all_vids, &all_count);

    if (ret == 0 && all_count > 0) {
        for (size_t i = 0; i < all_count; i++) {
            if (all_vids[i] == my_vid && all_values[i] && all_lens[i] > 0) {
                char *json_str = malloc(all_lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, all_values[i], all_lens[i]);
                    json_str[all_lens[i]] = '\0';
                    boost_ptrs_from_json(json_str, &existing, &existing_count);
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

    /* Check daily limit */
    if (existing_count >= DNA_WALL_BOOST_MAX_PER_DAY) {
        QGP_LOG_WARN(LOG_TAG, "Daily boost limit reached (%d)", DNA_WALL_BOOST_MAX_PER_DAY);
        free(existing);
        return -4;
    }

    /* Check for duplicate (same UUID already boosted) */
    for (size_t i = 0; i < existing_count; i++) {
        if (strncmp(existing[i].uuid, post_uuid, 36) == 0) {
            QGP_LOG_INFO(LOG_TAG, "Post %s already boosted today", post_uuid);
            free(existing);
            return -3;
        }
    }

    /* Build new pointer array: existing + new */
    size_t new_count = existing_count + 1;
    dna_wall_boost_ptr_t *all_ptrs = calloc(new_count, sizeof(dna_wall_boost_ptr_t));
    if (!all_ptrs) {
        free(existing);
        return -1;
    }

    for (size_t i = 0; i < existing_count; i++) {
        all_ptrs[i] = existing[i];
    }
    free(existing);

    /* Add new pointer */
    strncpy(all_ptrs[existing_count].uuid, post_uuid, 36);
    all_ptrs[existing_count].uuid[36] = '\0';
    strncpy(all_ptrs[existing_count].author_fingerprint, author_fingerprint, 128);
    all_ptrs[existing_count].author_fingerprint[128] = '\0';
    all_ptrs[existing_count].timestamp = post_timestamp;

    /* Serialize and PUT */
    char *json = boost_ptrs_to_json(all_ptrs, new_count);
    free(all_ptrs);

    if (!json) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize boost pointers");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing boost pointer for post %s to key %s (%zu total)",
                 post_uuid, base_key, new_count);

    ret = nodus_ops_put_str(base_key,
                             (const uint8_t *)json, strlen(json),
                             DNA_WALL_BOOST_TTL_SECONDS, my_vid);
    free(json);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish boost pointer (ret=%d)", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Boost pointer for post %s published successfully", post_uuid);
    return 0;
}

int dna_wall_boost_load(const char *date_str,
                         dna_wall_boost_ptr_t **ptrs_out,
                         size_t *count_out) {
    if (!date_str || !ptrs_out || !count_out) return -1;

    *ptrs_out = NULL;
    *count_out = 0;

    char base_key[256];
    boost_base_key(date_str, base_key, sizeof(base_key));

    /* Fetch all authors' boost pointers using get_all */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = nodus_ops_get_all_str(base_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No boost pointers found for %s", date_str);
        return -2;
    }

    /* Merge all pointers from all authors, deduplicate by UUID */
    dna_wall_boost_ptr_t *all_ptrs = NULL;
    size_t total = 0;
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

        dna_wall_boost_ptr_t *bucket = NULL;
        size_t bucket_count = 0;

        if (boost_ptrs_from_json(json_str, &bucket, &bucket_count) == 0 && bucket) {
            if (total + bucket_count > allocated) {
                size_t new_alloc = allocated == 0 ? 64 : allocated * 2;
                while (new_alloc < total + bucket_count) new_alloc *= 2;

                dna_wall_boost_ptr_t *new_arr = realloc(all_ptrs,
                    new_alloc * sizeof(dna_wall_boost_ptr_t));
                if (!new_arr) {
                    free(bucket);
                    free(json_str);
                    continue;
                }
                all_ptrs = new_arr;
                allocated = new_alloc;
            }

            for (size_t j = 0; j < bucket_count; j++) {
                /* Deduplicate by UUID */
                bool dup = false;
                for (size_t k = 0; k < total; k++) {
                    if (strncmp(all_ptrs[k].uuid, bucket[j].uuid, 36) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    all_ptrs[total++] = bucket[j];
                }
            }
            free(bucket);
        }
        free(json_str);
    }

    free(values);
    free(lens);

    if (total == 0) {
        free(all_ptrs);
        return -2;
    }

    QGP_LOG_INFO(LOG_TAG, "Loaded %zu boost pointers for %s from %zu authors",
                 total, date_str, value_count);

    *ptrs_out = all_ptrs;
    *count_out = total;
    return 0;
}

int dna_wall_boost_load_recent(int days,
                                dna_wall_boost_ptr_t **ptrs_out,
                                size_t *count_out) {
    if (!ptrs_out || !count_out) return -1;
    if (days <= 0) days = 7;
    if (days > 7) days = 7;

    *ptrs_out = NULL;
    *count_out = 0;

    dna_wall_boost_ptr_t *all_ptrs = NULL;
    size_t total = 0;
    size_t allocated = 0;

    time_t now = time(NULL);

    for (int d = 0; d < days; d++) {
        time_t day = now - (d * 86400);
        struct tm tm_day;
#ifdef _WIN32
        gmtime_s(&tm_day, &day);
#else
        gmtime_r(&day, &tm_day);
#endif
        char date_str[16];
        strftime(date_str, sizeof(date_str), "%Y-%m-%d", &tm_day);

        dna_wall_boost_ptr_t *day_ptrs = NULL;
        size_t day_count = 0;

        if (dna_wall_boost_load(date_str, &day_ptrs, &day_count) == 0 && day_ptrs) {
            if (total + day_count > allocated) {
                size_t new_alloc = allocated == 0 ? 64 : allocated * 2;
                while (new_alloc < total + day_count) new_alloc *= 2;

                dna_wall_boost_ptr_t *new_arr = realloc(all_ptrs,
                    new_alloc * sizeof(dna_wall_boost_ptr_t));
                if (!new_arr) {
                    free(day_ptrs);
                    continue;
                }
                all_ptrs = new_arr;
                allocated = new_alloc;
            }

            /* Deduplicate across days (same post boosted on different days) */
            for (size_t j = 0; j < day_count; j++) {
                bool dup = false;
                for (size_t k = 0; k < total; k++) {
                    if (strncmp(all_ptrs[k].uuid, day_ptrs[j].uuid, 36) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    all_ptrs[total++] = day_ptrs[j];
                }
            }
            free(day_ptrs);
        }
    }

    if (total == 0) {
        free(all_ptrs);
        return -2;
    }

    QGP_LOG_INFO(LOG_TAG, "Loaded %zu boost pointers from last %d days", total, days);

    *ptrs_out = all_ptrs;
    *count_out = total;
    return 0;
}

void dna_wall_boost_free(dna_wall_boost_ptr_t *ptrs, size_t count) {
    (void)count;
    free(ptrs);
}
