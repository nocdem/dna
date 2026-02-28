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
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_dilithium.h"
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

    /* Load existing wall from DHT */
    dna_wall_t wall;
    memset(&wall, 0, sizeof(wall));
    strncpy(wall.owner_fingerprint, fingerprint, 128);
    wall.owner_fingerprint[128] = '\0';

    int load_ret = dna_wall_load(fingerprint, &wall);
    /* load_ret == -2 means no existing wall, which is fine */
    if (load_ret != 0 && load_ret != -2) {
        QGP_LOG_WARN(LOG_TAG, "Failed to load existing wall, starting fresh");
        wall.posts = NULL;
        wall.post_count = 0;
    }

    /* If at max capacity, remove one oldest post by timestamp */
    if (wall.post_count >= DNA_WALL_MAX_POSTS) {
        size_t oldest_idx = 0;
        uint64_t oldest_ts = wall.posts[0].timestamp;
        for (size_t i = 1; i < wall.post_count; i++) {
            if (wall.posts[i].timestamp < oldest_ts) {
                oldest_ts = wall.posts[i].timestamp;
                oldest_idx = i;
            }
        }
        /* Free heap members before overwriting */
        free(wall.posts[oldest_idx].image_json);
        if (oldest_idx < wall.post_count - 1) {
            memmove(&wall.posts[oldest_idx], &wall.posts[oldest_idx + 1],
                    (wall.post_count - oldest_idx - 1) * sizeof(dna_wall_post_t));
        }
        wall.post_count--;
    }

    /* Append new post */
    dna_wall_post_t *new_posts = realloc(wall.posts,
                                          (wall.post_count + 1) * sizeof(dna_wall_post_t));
    if (!new_posts) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for new post");
        dna_wall_free(&wall);
        return -1;
    }
    wall.posts = new_posts;
    wall.posts[wall.post_count] = new_post;
    wall.post_count++;

    /* Serialize and publish to DHT */
    char *json_str = dna_wall_to_json(&wall);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize wall to JSON");
        dna_wall_free(&wall);
        return -1;
    }

    char base_key[256];
    wall_base_key(fingerprint, base_key, sizeof(base_key));

    QGP_LOG_INFO(LOG_TAG, "Publishing wall post %s to DHT", new_post.uuid);
    ret = nodus_ops_put_str(base_key,
                             (const uint8_t *)json_str, strlen(json_str),
                             (30*24*3600), nodus_ops_value_id());
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish wall (ret=%d)", ret);
        dna_wall_free(&wall);
        return -1;
    }

    /* Fill out_post if requested */
    if (out_post) {
        *out_post = new_post;
    }

    QGP_LOG_INFO(LOG_TAG, "Wall post %s published successfully", new_post.uuid);
    dna_wall_free(&wall);
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

    /* Load existing wall from DHT */
    dna_wall_t wall;
    memset(&wall, 0, sizeof(wall));
    strncpy(wall.owner_fingerprint, fingerprint, 128);
    wall.owner_fingerprint[128] = '\0';

    int load_ret = dna_wall_load(fingerprint, &wall);
    if (load_ret != 0 && load_ret != -2) {
        QGP_LOG_WARN(LOG_TAG, "Failed to load existing wall, starting fresh");
        wall.posts = NULL;
        wall.post_count = 0;
    }

    /* If at max capacity, remove oldest post */
    if (wall.post_count >= DNA_WALL_MAX_POSTS) {
        size_t oldest_idx = 0;
        uint64_t oldest_ts = wall.posts[0].timestamp;
        for (size_t i = 1; i < wall.post_count; i++) {
            if (wall.posts[i].timestamp < oldest_ts) {
                oldest_ts = wall.posts[i].timestamp;
                oldest_idx = i;
            }
        }
        free(wall.posts[oldest_idx].image_json);
        if (oldest_idx < wall.post_count - 1) {
            memmove(&wall.posts[oldest_idx], &wall.posts[oldest_idx + 1],
                    (wall.post_count - oldest_idx - 1) * sizeof(dna_wall_post_t));
        }
        wall.post_count--;
    }

    /* Append new post */
    dna_wall_post_t *new_posts = realloc(wall.posts,
                                          (wall.post_count + 1) * sizeof(dna_wall_post_t));
    if (!new_posts) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for new post");
        free(new_post.image_json);
        dna_wall_free(&wall);
        return -1;
    }
    wall.posts = new_posts;
    wall.posts[wall.post_count] = new_post;
    wall.post_count++;

    /* Serialize and publish to DHT */
    char *json_str = dna_wall_to_json(&wall);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize wall to JSON");
        dna_wall_free(&wall);
        return -1;
    }

    char base_key[256];
    wall_base_key(fingerprint, base_key, sizeof(base_key));

    QGP_LOG_INFO(LOG_TAG, "Publishing wall post %s (with image) to DHT", new_post.uuid);
    ret = nodus_ops_put_str(base_key,
                             (const uint8_t *)json_str, strlen(json_str),
                             (30*24*3600), nodus_ops_value_id());
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish wall (ret=%d)", ret);
        dna_wall_free(&wall);
        return -1;
    }

    /* Fill out_post with a separate copy of image_json (wall_free will free the array's copy) */
    if (out_post) {
        *out_post = new_post;
        out_post->image_json = new_post.image_json ? strdup(new_post.image_json) : NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Wall post %s (with image) published successfully", new_post.uuid);
    dna_wall_free(&wall);
    return 0;
}

int dna_wall_delete(const char *fingerprint,
                    const uint8_t *private_key,
                    const char *post_uuid) {
    if (!fingerprint || !private_key || !post_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for wall delete");
        return -1;
    }

    /* Load existing wall */
    dna_wall_t wall;
    memset(&wall, 0, sizeof(wall));
    int ret = dna_wall_load(fingerprint, &wall);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load wall for delete");
        return ret;
    }

    /* Find and remove the post */
    bool found = false;
    for (size_t i = 0; i < wall.post_count; i++) {
        if (strcmp(wall.posts[i].uuid, post_uuid) == 0) {
            /* Free heap members before overwriting */
            free(wall.posts[i].image_json);
            /* Shift remaining posts */
            if (i < wall.post_count - 1) {
                memmove(&wall.posts[i], &wall.posts[i + 1],
                        (wall.post_count - i - 1) * sizeof(dna_wall_post_t));
            }
            wall.post_count--;
            found = true;
            break;
        }
    }

    if (!found) {
        QGP_LOG_WARN(LOG_TAG, "Post %s not found on wall", post_uuid);
        dna_wall_free(&wall);
        return -1;
    }

    /* Re-serialize and republish */
    char *json_str = dna_wall_to_json(&wall);
    if (!json_str) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize wall after delete");
        dna_wall_free(&wall);
        return -1;
    }

    char base_key[256];
    wall_base_key(fingerprint, base_key, sizeof(base_key));

    QGP_LOG_INFO(LOG_TAG, "Republishing wall after deleting post %s", post_uuid);
    ret = nodus_ops_put_str(base_key,
                             (const uint8_t *)json_str, strlen(json_str),
                             (30*24*3600), nodus_ops_value_id());
    free(json_str);
    dna_wall_free(&wall);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to republish wall (ret=%d)", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Post %s deleted from wall", post_uuid);
    return 0;
}

int dna_wall_load(const char *fingerprint,
                  dna_wall_t *wall) {
    if (!fingerprint || !wall) {
        return -1;
    }

    char base_key[256];
    wall_base_key(fingerprint, base_key, sizeof(base_key));

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = nodus_ops_get_str(base_key, &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No wall found for %s (ret=%d)", fingerprint, ret);
        return -2;
    }

    /* Convert to null-terminated string */
    char *json_str = malloc(value_len + 1);
    if (!json_str) {
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    /* Parse JSON */
    ret = dna_wall_from_json(json_str, wall);
    free(json_str);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to parse wall JSON for %s", fingerprint);
        return -1;
    }

    /* Set owner fingerprint */
    strncpy(wall->owner_fingerprint, fingerprint, 128);
    wall->owner_fingerprint[128] = '\0';

    QGP_LOG_DEBUG(LOG_TAG, "Loaded wall for %s: %zu posts", fingerprint, wall->post_count);
    return 0;
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
