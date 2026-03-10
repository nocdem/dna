/*
 * DNA Channels - DHT Channel Operations Layer
 *
 * Implements channel metadata CRUD, post operations, and public index browsing.
 *
 * Storage Model:
 * - Channel metadata: "dna:channels:meta:" + uuid (single-owner, chunked)
 * - Channel posts: "dna:channels:posts:" + uuid (multi-owner, chunked)
 * - Public index: "dna:channels:idx:" + YYYYMMDD (multi-owner day buckets)
 *
 * Follows the same patterns as dna_feed_topic.c, dna_feed_comments.c,
 * and dna_feed_index.c.
 *
 * Part of DNA Messenger
 */

#include "dna_channels.h"
#include "../shared/nodus_ops.h"
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

#define LOG_TAG "DNA_CHANNELS"

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* Dilithium5 max signature size */
#define DNA_CHANNEL_SIG_MAX 4627

/* ============================================================================
 * UUID Generation (reuses same pattern as dna_feed_topic.c)
 * ========================================================================== */

static void channel_generate_uuid(char *uuid_out) {
    uint8_t bytes[16];
    if (RAND_bytes(bytes, 16) != 1) {
        /* Fallback: use time-based pseudo-random */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        for (int i = 0; i < 16; i++) {
            bytes[i] = (uint8_t)(ts.tv_nsec ^ ts.tv_sec ^ i);
        }
    }

    /* Set version 4 (random) and variant bits */
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  /* Version 4 */
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  /* Variant 1 */

    snprintf(uuid_out, DNA_CHANNEL_UUID_LEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/* ============================================================================
 * Date Helpers
 * ========================================================================== */

void channel_get_today_date(char *date_out) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(date_out, 12, "%Y%m%d", tm_info);
}

void channel_get_date_offset(int days_ago, char *date_out) {
    time_t now = time(NULL);
    now -= days_ago * 86400;
    struct tm *tm_info = gmtime(&now);
    strftime(date_out, 12, "%Y%m%d", tm_info);
}

/* ============================================================================
 * DHT Key Derivation
 * ========================================================================== */

int dna_channel_make_meta_key(const char *uuid, uint8_t *key_out, size_t *key_len_out) {
    if (!uuid || !key_out || !key_len_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "%s%s", DNA_CHANNEL_NS_META, uuid);

    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    memcpy(key_out, hash, 32);
    *key_len_out = 32;
    return 0;
}

int dna_channel_make_posts_key(const char *uuid, const char *date,
                                uint8_t *key_out, size_t *key_len_out) {
    if (!uuid || !key_out || !key_len_out) return -1;

    char input[256];
    if (date) {
        snprintf(input, sizeof(input), "%s%s:%s", DNA_CHANNEL_NS_POSTS, uuid, date);
    } else {
        snprintf(input, sizeof(input), "%s%s", DNA_CHANNEL_NS_POSTS, uuid);
    }

    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    memcpy(key_out, hash, 32);
    *key_len_out = 32;
    return 0;
}

int dna_channel_make_index_key(const char *date_str, uint8_t *key_out, size_t *key_len_out) {
    if (!date_str || !key_out || !key_len_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "%s%s", DNA_CHANNEL_NS_INDEX, date_str);

    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    memcpy(key_out, hash, 32);
    *key_len_out = 32;
    return 0;
}

/* ============================================================================
 * JSON Serialization - Channel Metadata
 * ========================================================================== */

/**
 * Serialize channel to JSON (without signature for signing, or with signature
 * for DHT storage).
 */
static int channel_to_json(const dna_channel_t *channel, bool include_signature, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "uuid", json_object_new_string(channel->uuid));
    json_object_object_add(root, "name", json_object_new_string(channel->name));
    json_object_object_add(root, "description",
                           json_object_new_string(channel->description ? channel->description : ""));
    json_object_object_add(root, "creator", json_object_new_string(channel->creator_fingerprint));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)channel->created_at));
    json_object_object_add(root, "is_public", json_object_new_boolean(channel->is_public));
    json_object_object_add(root, "deleted", json_object_new_boolean(channel->deleted));
    json_object_object_add(root, "deleted_at", json_object_new_int64((int64_t)channel->deleted_at));

    if (include_signature && channel->signature && channel->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(channel->signature, channel->signature_len, NULL);
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

/**
 * Deserialize channel from JSON.
 */
static int channel_from_json(const char *json_str, dna_channel_t **channel_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_channel_t *channel = calloc(1, sizeof(dna_channel_t));
    if (!channel) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;

    if (json_object_object_get_ex(root, "uuid", &j_val))
        strncpy(channel->uuid, json_object_get_string(j_val), sizeof(channel->uuid) - 1);
    if (json_object_object_get_ex(root, "name", &j_val))
        strncpy(channel->name, json_object_get_string(j_val), DNA_CHANNEL_NAME_MAX);
    if (json_object_object_get_ex(root, "description", &j_val)) {
        const char *desc = json_object_get_string(j_val);
        channel->description = desc ? strdup(desc) : NULL;
    }
    if (json_object_object_get_ex(root, "creator", &j_val))
        strncpy(channel->creator_fingerprint, json_object_get_string(j_val),
                sizeof(channel->creator_fingerprint) - 1);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        channel->created_at = (uint64_t)json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "is_public", &j_val))
        channel->is_public = json_object_get_boolean(j_val);
    if (json_object_object_get_ex(root, "deleted", &j_val))
        channel->deleted = json_object_get_boolean(j_val);
    if (json_object_object_get_ex(root, "deleted_at", &j_val))
        channel->deleted_at = (uint64_t)json_object_get_int64(j_val);

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= DNA_CHANNEL_SIG_MAX) {
                channel->signature = sig_bytes;
                channel->signature_len = sig_len;
            } else {
                free(sig_bytes);
            }
        }
    }

    json_object_put(root);
    *channel_out = channel;
    return 0;
}

/* ============================================================================
 * JSON Serialization - Posts
 * ========================================================================== */

/**
 * Serialize a single post to JSON.
 */
static int post_to_json(const dna_channel_post_internal_t *post, bool include_signature, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "post_uuid", json_object_new_string(post->post_uuid));
    json_object_object_add(root, "channel_uuid", json_object_new_string(post->channel_uuid));
    json_object_object_add(root, "author", json_object_new_string(post->author_fingerprint));
    json_object_object_add(root, "body",
                           json_object_new_string(post->body ? post->body : ""));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)post->created_at));

    if (include_signature && post->signature && post->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(post->signature, post->signature_len, NULL);
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

/**
 * Deserialize a single post from JSON into an existing struct.
 */
static int post_from_json(const char *json_str, dna_channel_post_internal_t *post_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(post_out, 0, sizeof(dna_channel_post_internal_t));

    json_object *j_val;

    if (json_object_object_get_ex(root, "post_uuid", &j_val))
        strncpy(post_out->post_uuid, json_object_get_string(j_val), sizeof(post_out->post_uuid) - 1);
    if (json_object_object_get_ex(root, "channel_uuid", &j_val))
        strncpy(post_out->channel_uuid, json_object_get_string(j_val), sizeof(post_out->channel_uuid) - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(post_out->author_fingerprint, json_object_get_string(j_val),
                sizeof(post_out->author_fingerprint) - 1);
    if (json_object_object_get_ex(root, "body", &j_val)) {
        const char *body = json_object_get_string(j_val);
        post_out->body = body ? strdup(body) : NULL;
    }
    if (json_object_object_get_ex(root, "created_at", &j_val))
        post_out->created_at = (uint64_t)json_object_get_int64(j_val);

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= DNA_CHANNEL_SIG_MAX) {
                post_out->signature = sig_bytes;
                post_out->signature_len = sig_len;
            } else {
                free(sig_bytes);
            }
        }
    }

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * JSON Serialization - Index Entries
 * ========================================================================== */

static int index_entry_to_json(const dna_channel_index_entry_t *entry, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "channel_uuid", json_object_new_string(entry->channel_uuid));
    json_object_object_add(root, "name", json_object_new_string(entry->name));
    json_object_object_add(root, "description_preview",
                           json_object_new_string(entry->description_preview));
    json_object_object_add(root, "creator", json_object_new_string(entry->creator_fingerprint));
    json_object_object_add(root, "created_at", json_object_new_int64((int64_t)entry->created_at));
    json_object_object_add(root, "deleted", json_object_new_boolean(entry->deleted));

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int index_entry_from_json(const char *json_str, dna_channel_index_entry_t *entry_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(entry_out, 0, sizeof(dna_channel_index_entry_t));

    json_object *j_val;
    if (json_object_object_get_ex(root, "channel_uuid", &j_val))
        strncpy(entry_out->channel_uuid, json_object_get_string(j_val),
                sizeof(entry_out->channel_uuid) - 1);
    if (json_object_object_get_ex(root, "name", &j_val))
        strncpy(entry_out->name, json_object_get_string(j_val), DNA_CHANNEL_NAME_MAX);
    if (json_object_object_get_ex(root, "description_preview", &j_val))
        strncpy(entry_out->description_preview, json_object_get_string(j_val),
                sizeof(entry_out->description_preview) - 1);
    if (json_object_object_get_ex(root, "creator", &j_val))
        strncpy(entry_out->creator_fingerprint, json_object_get_string(j_val),
                sizeof(entry_out->creator_fingerprint) - 1);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        entry_out->created_at = (uint64_t)json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "deleted", &j_val))
        entry_out->deleted = json_object_get_boolean(j_val);

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * Post Bucket Serialization (multi-owner pattern, like dna_feed_comments.c)
 * ========================================================================== */

/**
 * Serialize post array to JSON for DHT storage.
 */
static int posts_bucket_to_json(const dna_channel_post_internal_t *posts, size_t count, char **json_out) {
    json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (size_t i = 0; i < count; i++) {
        char *p_json = NULL;
        if (post_to_json(&posts[i], true, &p_json) == 0) {
            json_object *p_obj = json_tokener_parse(p_json);
            if (p_obj) {
                json_object_array_add(arr, p_obj);
            }
            free(p_json);
        }
    }

    const char *json_str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(arr);

    return *json_out ? 0 : -1;
}

/**
 * Deserialize JSON to post array.
 */
static int posts_bucket_from_json(const char *json_str,
                                   dna_channel_post_internal_t **posts_out,
                                   size_t *count_out) {
    *posts_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json_str);
    if (!arr) return -1;

    if (!json_object_is_type(arr, json_type_array)) {
        /* Try single post */
        dna_channel_post_internal_t *single = calloc(1, sizeof(dna_channel_post_internal_t));
        if (single && post_from_json(json_str, single) == 0) {
            *posts_out = single;
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

    dna_channel_post_internal_t *posts = calloc(arr_len, sizeof(dna_channel_post_internal_t));
    if (!posts) {
        json_object_put(arr);
        return -1;
    }

    size_t parsed = 0;
    for (int i = 0; i < arr_len; i++) {
        json_object *p = json_object_array_get_idx(arr, i);
        const char *p_str = json_object_to_json_string(p);
        if (p_str && post_from_json(p_str, &posts[parsed]) == 0) {
            parsed++;
        }
    }

    json_object_put(arr);

    if (parsed == 0) {
        free(posts);
        return -1;
    }

    *posts_out = posts;
    *count_out = parsed;
    return 0;
}

/* ============================================================================
 * Index Bucket Serialization (multi-owner day-bucket pattern)
 * ========================================================================== */

static int index_bucket_to_json(const dna_channel_index_entry_t *entries, size_t count, char **json_out) {
    if (!entries || count == 0 || !json_out) return -1;

    json_object *arr = json_object_new_array();
    if (!arr) return -1;

    for (size_t i = 0; i < count; i++) {
        char *entry_json = NULL;
        if (index_entry_to_json(&entries[i], &entry_json) == 0 && entry_json) {
            json_object *entry_obj = json_tokener_parse(entry_json);
            if (entry_obj) {
                json_object_array_add(arr, entry_obj);
            }
            free(entry_json);
        }
    }

    const char *json_str = json_object_to_json_string_ext(arr, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(arr);

    return *json_out ? 0 : -1;
}

static int index_bucket_from_json(const char *json_str,
                                    dna_channel_index_entry_t **entries_out,
                                    size_t *count_out) {
    if (!json_str || !entries_out || !count_out) return -1;

    *entries_out = NULL;
    *count_out = 0;

    json_object *arr = json_tokener_parse(json_str);
    if (!arr || !json_object_is_type(arr, json_type_array)) {
        if (arr) json_object_put(arr);
        return -1;
    }

    int len = json_object_array_length(arr);
    if (len == 0) {
        json_object_put(arr);
        return 0;
    }

    dna_channel_index_entry_t *entries = calloc(len, sizeof(dna_channel_index_entry_t));
    if (!entries) {
        json_object_put(arr);
        return -1;
    }

    size_t count = 0;
    for (int i = 0; i < len; i++) {
        json_object *entry_obj = json_object_array_get_idx(arr, i);
        const char *entry_str = json_object_to_json_string(entry_obj);
        if (entry_str && index_entry_from_json(entry_str, &entries[count]) == 0) {
            count++;
        }
    }

    json_object_put(arr);

    if (count == 0) {
        free(entries);
        return 0;
    }

    *entries_out = entries;
    *count_out = count;
    return 0;
}

/* ============================================================================
 * Comparison Functions for qsort
 * ========================================================================== */

/* Compare posts by created_at descending (newest first) */
static int compare_post_by_time_desc(const void *a, const void *b) {
    const dna_channel_post_internal_t *pa = (const dna_channel_post_internal_t *)a;
    const dna_channel_post_internal_t *pb = (const dna_channel_post_internal_t *)b;
    if (pb->created_at > pa->created_at) return 1;
    if (pb->created_at < pa->created_at) return -1;
    return 0;
}

/* Compare index entries by created_at descending */
static int compare_index_entry_desc(const void *a, const void *b) {
    const dna_channel_index_entry_t *ea = (const dna_channel_index_entry_t *)a;
    const dna_channel_index_entry_t *eb = (const dna_channel_index_entry_t *)b;
    if (eb->created_at > ea->created_at) return 1;
    if (eb->created_at < ea->created_at) return -1;
    return 0;
}

/* ============================================================================
 * Memory Management
 * ========================================================================== */

void dna_channel_free(dna_channel_t *channel) {
    if (!channel) return;
    free(channel->description);
    free(channel->signature);
    free(channel);
}

void dna_channels_free(dna_channel_t *channels, size_t count) {
    if (!channels) return;
    for (size_t i = 0; i < count; i++) {
        free(channels[i].description);
        free(channels[i].signature);
    }
    free(channels);
}

void dna_channel_post_free(dna_channel_post_internal_t *post) {
    if (!post) return;
    free(post->body);
    free(post->signature);
    free(post);
}

void dna_channel_posts_free(dna_channel_post_internal_t *posts, size_t count) {
    if (!posts) return;
    for (size_t i = 0; i < count; i++) {
        free(posts[i].body);
        free(posts[i].signature);
    }
    free(posts);
}

/* ============================================================================
 * Channel CRUD Operations
 * ========================================================================== */

int dna_channel_create(const char *name,
                        const char *description, bool is_public,
                        const char *creator_fingerprint, const uint8_t *private_key,
                        char *uuid_out) {
    if (!name || !creator_fingerprint || !private_key) {
        return -1;
    }

    /* Validate lengths */
    if (strlen(name) == 0 || strlen(name) > DNA_CHANNEL_NAME_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid channel name length\n");
        return -1;
    }
    if (description && strlen(description) > DNA_CHANNEL_DESC_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "Channel description too long\n");
        return -1;
    }

    /* Create channel structure */
    dna_channel_t *channel = calloc(1, sizeof(dna_channel_t));
    if (!channel) return -1;

    /* Generate UUID */
    channel_generate_uuid(channel->uuid);

    /* Copy fields */
    strncpy(channel->name, name, DNA_CHANNEL_NAME_MAX);
    channel->description = description ? strdup(description) : strdup("");
    strncpy(channel->creator_fingerprint, creator_fingerprint,
            sizeof(channel->creator_fingerprint) - 1);
    channel->created_at = (uint64_t)time(NULL);
    channel->is_public = is_public;
    channel->deleted = false;
    channel->deleted_at = 0;

    /* Sign channel: JSON without signature */
    char *json_to_sign = NULL;
    if (channel_to_json(channel, false, &json_to_sign) != 0) {
        dna_channel_free(channel);
        return -1;
    }

    /* Allocate signature buffer */
    channel->signature = malloc(DNA_CHANNEL_SIG_MAX);
    if (!channel->signature) {
        free(json_to_sign);
        dna_channel_free(channel);
        return -1;
    }

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(
        channel->signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign channel\n");
        dna_channel_free(channel);
        return -1;
    }
    channel->signature_len = sig_len;

    /* Serialize with signature */
    char *json_data = NULL;
    if (channel_to_json(channel, true, &json_data) != 0) {
        dna_channel_free(channel);
        return -1;
    }

    /* Publish channel metadata using chunked layer (single-owner) */
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s%s", DNA_CHANNEL_NS_META, channel->uuid);

    QGP_LOG_INFO(LOG_TAG, "Publishing channel %s (%s) to DHT...\n", channel->uuid, channel->name);
    ret = nodus_ops_put_str(base_key,
                            (const uint8_t *)json_data, strlen(json_data),
                            DNA_CHANNEL_TTL_SECONDS, nodus_ops_value_id());
    free(json_data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish channel: %d\n", ret);
        dna_channel_free(channel);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created channel %s\n", channel->uuid);

    /* Return UUID */
    if (uuid_out) {
        strncpy(uuid_out, channel->uuid, DNA_CHANNEL_UUID_LEN);
    }

    dna_channel_free(channel);
    return 0;
}

int dna_channel_get(const char *uuid,
                     dna_channel_t **channel_out) {
    if (!uuid || !channel_out) return -1;

    /* Derive base key for channel metadata */
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s%s", DNA_CHANNEL_NS_META, uuid);

    QGP_LOG_INFO(LOG_TAG, "Fetching channel %s...\n", uuid);

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = nodus_ops_get_str(base_key, &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
        return -2;  /* Not found */
    }

    char *json_str = malloc(value_len + 1);
    if (!json_str) {
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = channel_from_json(json_str, channel_out);
    free(json_str);

    return ret;
}

int dna_channel_delete(const char *uuid,
                        const char *creator_fingerprint, const uint8_t *private_key) {
    if (!uuid || !creator_fingerprint || !private_key) return -1;

    /* Fetch existing channel */
    dna_channel_t *channel = NULL;
    int ret = dna_channel_get(uuid, &channel);
    if (ret != 0 || !channel) {
        return -2;  /* Not found */
    }

    /* Verify ownership */
    if (strcmp(channel->creator_fingerprint, creator_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Not the owner of channel %s\n", uuid);
        dna_channel_free(channel);
        return -3;  /* Not owner */
    }

    /* Already deleted? */
    if (channel->deleted) {
        dna_channel_free(channel);
        return 0;
    }

    /* Mark as deleted */
    channel->deleted = true;
    channel->deleted_at = (uint64_t)time(NULL);

    /* Re-sign with new data */
    char *json_to_sign = NULL;
    if (channel_to_json(channel, false, &json_to_sign) != 0) {
        dna_channel_free(channel);
        return -1;
    }

    /* Re-allocate signature buffer if needed */
    free(channel->signature);
    channel->signature = malloc(DNA_CHANNEL_SIG_MAX);
    if (!channel->signature) {
        free(json_to_sign);
        channel->signature_len = 0;
        dna_channel_free(channel);
        return -1;
    }

    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(
        channel->signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign deleted channel\n");
        dna_channel_free(channel);
        return -1;
    }
    channel->signature_len = sig_len;

    /* Serialize and republish */
    char *json_data = NULL;
    if (channel_to_json(channel, true, &json_data) != 0) {
        dna_channel_free(channel);
        return -1;
    }

    char base_key[256];
    snprintf(base_key, sizeof(base_key), "%s%s", DNA_CHANNEL_NS_META, uuid);

    QGP_LOG_INFO(LOG_TAG, "Publishing deleted channel %s...\n", uuid);
    ret = nodus_ops_put_str(base_key,
                            (const uint8_t *)json_data, strlen(json_data),
                            DNA_CHANNEL_TTL_SECONDS, nodus_ops_value_id());
    free(json_data);
    dna_channel_free(channel);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish deleted channel: %d\n", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully deleted channel %s\n", uuid);
    return 0;
}

/* ============================================================================
 * Post Operations (multi-owner pattern, like dna_feed_comments.c)
 * ========================================================================== */

int dna_channel_post_create(const char *channel_uuid,
                             const char *body, const char *author_fingerprint,
                             const uint8_t *private_key, char *post_uuid_out) {
    if (!channel_uuid || !body || !author_fingerprint || !private_key) {
        return -1;
    }

    /* Validate body length */
    size_t body_len = strlen(body);
    if (body_len == 0 || body_len > DNA_CHANNEL_POST_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid post body length: %zu\n", body_len);
        return -1;
    }

    /* Create post structure */
    dna_channel_post_internal_t new_post;
    memset(&new_post, 0, sizeof(new_post));

    /* Generate UUID */
    channel_generate_uuid(new_post.post_uuid);

    /* Copy fields */
    strncpy(new_post.channel_uuid, channel_uuid, sizeof(new_post.channel_uuid) - 1);
    strncpy(new_post.author_fingerprint, author_fingerprint,
            sizeof(new_post.author_fingerprint) - 1);
    new_post.body = strdup(body);
    if (!new_post.body) return -1;
    new_post.created_at = (uint64_t)time(NULL);

    /* Sign post: JSON without signature */
    char *json_to_sign = NULL;
    if (post_to_json(&new_post, false, &json_to_sign) != 0) {
        free(new_post.body);
        return -1;
    }

    new_post.signature = malloc(DNA_CHANNEL_SIG_MAX);
    if (!new_post.signature) {
        free(json_to_sign);
        free(new_post.body);
        return -1;
    }

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(
        new_post.signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign post\n");
        free(new_post.body);
        free(new_post.signature);
        return -1;
    }
    new_post.signature_len = sig_len;

    /* Get DHT key for posts (daily bucket) */
    char today[12];
    channel_get_today_date(today);
    char posts_key[256];
    snprintf(posts_key, sizeof(posts_key), "%s%s:%s", DNA_CHANNEL_NS_POSTS, channel_uuid, today);

    /* Step 1: Fetch MY existing posts from the multi-owner key.
     * Uses get_all_with_ids to retrieve all owner buckets, then filters
     * by our own value_id so we only modify our own data. */
    dna_channel_post_internal_t *existing_posts = NULL;
    size_t existing_count = 0;

    uint8_t **all_values = NULL;
    size_t *all_lens = NULL;
    uint64_t *all_vids = NULL;
    size_t all_count = 0;
    uint64_t my_vid = nodus_ops_value_id();

    ret = nodus_ops_get_all_str_with_ids(posts_key, &all_values, &all_lens,
                                          &all_vids, &all_count);

    if (ret == 0 && all_count > 0) {
        /* Find our own bucket by value_id */
        for (size_t i = 0; i < all_count; i++) {
            if (all_vids[i] == my_vid && all_values[i] && all_lens[i] > 0) {
                char *json_str = malloc(all_lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, all_values[i], all_lens[i]);
                    json_str[all_lens[i]] = '\0';
                    posts_bucket_from_json(json_str, &existing_posts, &existing_count);
                    free(json_str);
                }
                break;
            }
        }
        /* Free all returned values */
        for (size_t i = 0; i < all_count; i++)
            free(all_values[i]);
        free(all_values);
        free(all_lens);
        free(all_vids);
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu existing posts from this author\n", existing_count);

    /* Step 2: Build new array with existing + new post */
    size_t new_count = existing_count + 1;
    dna_channel_post_internal_t *all_posts = calloc(new_count, sizeof(dna_channel_post_internal_t));
    if (!all_posts) {
        dna_channel_posts_free(existing_posts, existing_count);
        free(new_post.body);
        free(new_post.signature);
        return -1;
    }

    /* Copy existing posts (transfer ownership of heap fields) */
    for (size_t i = 0; i < existing_count; i++) {
        all_posts[i] = existing_posts[i];
    }
    /* Free the array container only, not the individual heap fields */
    free(existing_posts);

    /* Add new post (transfer ownership) */
    all_posts[existing_count] = new_post;

    /* Step 3: Serialize and publish using nodus_ops_put_str() */
    char *bucket_json = NULL;
    if (posts_bucket_to_json(all_posts, new_count, &bucket_json) != 0) {
        dna_channel_posts_free(all_posts, new_count);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu posts to key %s\n", new_count, posts_key);

    ret = nodus_ops_put_str(posts_key,
                            (const uint8_t *)bucket_json, strlen(bucket_json),
                            DNA_CHANNEL_TTL_SECONDS, nodus_ops_value_id());

    free(bucket_json);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT put failed: %d\n", ret);
        dna_channel_posts_free(all_posts, new_count);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created post %s in channel %s\n",
                 new_post.post_uuid, channel_uuid);

    /* Return UUID */
    if (post_uuid_out) {
        strncpy(post_uuid_out, all_posts[existing_count].post_uuid, DNA_CHANNEL_UUID_LEN);
    }

    dna_channel_posts_free(all_posts, new_count);
    return 0;
}

/**
 * Helper: Merge posts from a single DHT key into the accumulator arrays.
 * Fetches all authors' buckets from the given key and appends non-duplicate posts.
 */
static void merge_posts_from_key(const char *key,
                                  dna_channel_post_internal_t **all_posts,
                                  size_t *total_count, size_t *allocated,
                                  const dna_channel_post_internal_t *existing,
                                  size_t existing_count) {
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = nodus_ops_get_all_str(key, &values, &lens, &value_count);
    if (ret != 0 || value_count == 0) return;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || lens[i] == 0) {
            free(values[i]);
            continue;
        }

        char *json_str = malloc(lens[i] + 1);
        if (!json_str) {
            free(values[i]);
            continue;
        }

        memcpy(json_str, values[i], lens[i]);
        json_str[lens[i]] = '\0';
        free(values[i]);

        dna_channel_post_internal_t *bucket_posts = NULL;
        size_t bucket_count = 0;

        if (posts_bucket_from_json(json_str, &bucket_posts, &bucket_count) == 0 && bucket_posts) {
            for (size_t j = 0; j < bucket_count; j++) {
                /* Dedup by post_uuid against already-collected posts */
                bool duplicate = false;
                for (size_t k = 0; k < *total_count; k++) {
                    if (strcmp((*all_posts)[k].post_uuid, bucket_posts[j].post_uuid) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                /* Also check against existing posts passed in (for legacy dedup) */
                if (!duplicate && existing) {
                    for (size_t k = 0; k < existing_count; k++) {
                        if (strcmp(existing[k].post_uuid, bucket_posts[j].post_uuid) == 0) {
                            duplicate = true;
                            break;
                        }
                    }
                }
                if (duplicate) {
                    /* Free heap fields of duplicate post */
                    free(bucket_posts[j].body);
                    free(bucket_posts[j].signature);
                    continue;
                }

                /* Expand array if needed */
                if (*total_count >= *allocated) {
                    size_t new_alloc = *allocated == 0 ? 64 : *allocated * 2;
                    dna_channel_post_internal_t *new_arr = realloc(*all_posts,
                        new_alloc * sizeof(dna_channel_post_internal_t));
                    if (!new_arr) {
                        free(bucket_posts[j].body);
                        free(bucket_posts[j].signature);
                        continue;
                    }
                    *all_posts = new_arr;
                    *allocated = new_alloc;
                }

                (*all_posts)[(*total_count)++] = bucket_posts[j];
            }
            free(bucket_posts);
        }
        free(json_str);
    }

    free(values);
    free(lens);
}

int dna_channel_posts_get(const char *channel_uuid,
                           int days_back,
                           dna_channel_post_internal_t **posts_out, size_t *count_out) {
    if (!channel_uuid || !posts_out || !count_out) return -1;

    *posts_out = NULL;
    *count_out = 0;

    /* Validate days_back */
    if (days_back <= 0) days_back = DNA_CHANNEL_POSTS_DAYS_DEFAULT;
    if (days_back > DNA_CHANNEL_POSTS_DAYS_MAX) days_back = DNA_CHANNEL_POSTS_DAYS_MAX;

    QGP_LOG_INFO(LOG_TAG, "Fetching posts for channel %s (%d days)\n", channel_uuid, days_back);

    /* Iterate day buckets (newest first) */
    dna_channel_post_internal_t *all_posts = NULL;
    size_t total_count = 0;
    size_t allocated = 0;

    for (int d = 0; d < days_back; d++) {
        char date[12];
        channel_get_date_offset(d, date);

        char posts_key[256];
        snprintf(posts_key, sizeof(posts_key), "%s%s:%s", DNA_CHANNEL_NS_POSTS, channel_uuid, date);

        merge_posts_from_key(posts_key, &all_posts, &total_count, &allocated, NULL, 0);
    }

    /* Legacy fallback: fetch from old undated key (migration period) */
    char legacy_key[256];
    snprintf(legacy_key, sizeof(legacy_key), "%s%s", DNA_CHANNEL_NS_POSTS, channel_uuid);
    merge_posts_from_key(legacy_key, &all_posts, &total_count, &allocated,
                         all_posts, total_count);

    if (total_count == 0) {
        free(all_posts);
        return -2;
    }

    /* Sort by created_at descending (newest first) */
    qsort(all_posts, total_count, sizeof(dna_channel_post_internal_t), compare_post_by_time_desc);

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu posts across %d day buckets + legacy\n", total_count, days_back);

    *posts_out = all_posts;
    *count_out = total_count;
    return 0;
}

/* ============================================================================
 * Public Index Operations (multi-owner day-bucket pattern)
 * ========================================================================== */

/**
 * Helper: Publish index entries to a multi-owner index bucket.
 * Uses nodus_ops_get_all_str_with_ids() to fetch own bucket,
 * then nodus_ops_put_str() to publish merged entries.
 */
static int publish_channel_index_entries(const char *index_key,
                                          const dna_channel_index_entry_t *entries,
                                          size_t count) {
    if (!index_key || !entries || count == 0) return -1;

    int ret;

    /* Step 1: Fetch MY existing entries from the multi-owner index key.
     * Uses get_all_with_ids and filters by our value_id. */
    dna_channel_index_entry_t *my_entries = NULL;
    size_t my_count = 0;

    uint8_t **all_values = NULL;
    size_t *all_lens = NULL;
    uint64_t *all_vids = NULL;
    size_t all_count = 0;
    uint64_t my_vid = nodus_ops_value_id();

    ret = nodus_ops_get_all_str_with_ids(index_key, &all_values, &all_lens,
                                          &all_vids, &all_count);

    if (ret == 0 && all_count > 0) {
        /* Find our own bucket by value_id */
        for (size_t i = 0; i < all_count; i++) {
            if (all_vids[i] == my_vid && all_values[i] && all_lens[i] > 0) {
                char *json_str = malloc(all_lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, all_values[i], all_lens[i]);
                    json_str[all_lens[i]] = '\0';
                    index_bucket_from_json(json_str, &my_entries, &my_count);
                    free(json_str);
                }
                break;
            }
        }
        /* Free all returned values */
        for (size_t i = 0; i < all_count; i++)
            free(all_values[i]);
        free(all_values);
        free(all_lens);
        free(all_vids);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Found %zu existing entries in my bucket at %s\n",
                  my_count, index_key);

    /* Step 2: Build merged array (existing + new, deduped by channel_uuid) */
    size_t new_capacity = my_count + count;
    dna_channel_index_entry_t *merged = calloc(new_capacity, sizeof(dna_channel_index_entry_t));
    if (!merged) {
        free(my_entries);
        return -1;
    }

    size_t merged_count = 0;

    /* Add existing entries (skip if channel_uuid is in new entries) */
    for (size_t i = 0; i < my_count; i++) {
        bool skip = false;
        for (size_t j = 0; j < count; j++) {
            if (strcmp(my_entries[i].channel_uuid, entries[j].channel_uuid) == 0) {
                skip = true;
                break;
            }
        }
        if (!skip) {
            merged[merged_count++] = my_entries[i];
        }
    }
    free(my_entries);

    /* Add new entries */
    for (size_t i = 0; i < count; i++) {
        merged[merged_count++] = entries[i];
    }

    /* Step 3: Serialize and publish using nodus_ops_put_str() */
    char *bucket_json = NULL;
    if (index_bucket_to_json(merged, merged_count, &bucket_json) != 0) {
        free(merged);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu index entries to DHT key %s\n",
                 merged_count, index_key);

    ret = nodus_ops_put_str(index_key,
                            (const uint8_t *)bucket_json, strlen(bucket_json),
                            DNA_CHANNEL_TTL_SECONDS, nodus_ops_value_id());

    free(bucket_json);
    free(merged);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT put failed: %d\n", ret);
        return -1;
    }

    return 0;
}

/**
 * Helper: Fetch all entries from a day bucket (all senders).
 * Uses nodus_ops_get_all_str() like dna_feed_index.c:fetch_day_bucket().
 */
static int fetch_channel_day_bucket(const char *index_key,
                                      dna_channel_index_entry_t **entries_out,
                                      size_t *count_out) {
    if (!index_key || !entries_out || !count_out) return -1;

    *entries_out = NULL;
    *count_out = 0;

    /* Fetch all senders' buckets using nodus_ops_get_all_str() */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = nodus_ops_get_all_str(index_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No buckets found at key %s\n", index_key);
        return (ret == 0) ? -2 : -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Got %zu sender buckets from key %s\n", value_count, index_key);

    /* Merge all entries from all senders */
    dna_channel_index_entry_t *all_entries = NULL;
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

        /* Parse this sender's bucket */
        dna_channel_index_entry_t *sender_entries = NULL;
        size_t sender_count = 0;

        if (index_bucket_from_json(json_str, &sender_entries, &sender_count) == 0 && sender_count > 0) {
            /* Merge entries, deduping by channel_uuid */
            for (size_t j = 0; j < sender_count; j++) {
                bool duplicate = false;
                for (size_t k = 0; k < total_count; k++) {
                    if (strcmp(all_entries[k].channel_uuid, sender_entries[j].channel_uuid) == 0) {
                        duplicate = true;
                        break;
                    }
                }

                if (!duplicate) {
                    if (total_count >= allocated) {
                        allocated = allocated ? allocated * 2 : 64;
                        dna_channel_index_entry_t *tmp = realloc(
                            all_entries, allocated * sizeof(dna_channel_index_entry_t));
                        if (!tmp) break;
                        all_entries = tmp;
                    }
                    all_entries[total_count++] = sender_entries[j];
                }
            }
            free(sender_entries);
        }
        free(json_str);
    }

    free(values);
    free(lens);

    if (total_count == 0) {
        free(all_entries);
        return -2;
    }

    *entries_out = all_entries;
    *count_out = total_count;
    return 0;
}

int dna_channel_index_register(const char *channel_uuid,
                                const char *name, const char *description,
                                const char *creator_fingerprint,
                                const uint8_t *private_key) {
    if (!channel_uuid || !name || !creator_fingerprint) return -1;
    (void)private_key;  /* Reserved for future use (signed index entries) */

    /* Get today's date */
    char today[12];
    channel_get_today_date(today);

    /* Build index entry */
    dna_channel_index_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.channel_uuid, channel_uuid, sizeof(entry.channel_uuid) - 1);
    strncpy(entry.name, name, DNA_CHANNEL_NAME_MAX);
    if (description) {
        strncpy(entry.description_preview, description, sizeof(entry.description_preview) - 1);
    }
    strncpy(entry.creator_fingerprint, creator_fingerprint,
            sizeof(entry.creator_fingerprint) - 1);
    entry.created_at = (uint64_t)time(NULL);
    entry.deleted = false;

    /* Publish to today's index bucket */
    char index_key[256];
    snprintf(index_key, sizeof(index_key), "%s%s", DNA_CHANNEL_NS_INDEX, today);

    int ret = publish_channel_index_entries(index_key, &entry, 1);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to register channel %s in index\n", channel_uuid);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Registered channel %s in index (date=%s)\n", channel_uuid, today);
    return 0;
}

int dna_channel_index_browse(int days_back,
                              dna_channel_t **channels_out, size_t *count_out) {
    if (!channels_out || !count_out) return -1;

    *channels_out = NULL;
    *count_out = 0;

    /* Validate days_back */
    if (days_back <= 0) days_back = DNA_CHANNEL_INDEX_DAYS_DEFAULT;
    if (days_back > DNA_CHANNEL_INDEX_DAYS_MAX) days_back = DNA_CHANNEL_INDEX_DAYS_MAX;

    QGP_LOG_INFO(LOG_TAG, "Browsing channel index (%d days)...\n", days_back);

    /* Fetch from each day bucket and merge */
    dna_channel_index_entry_t *all_entries = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;

    for (int d = 0; d < days_back; d++) {
        char date[12];
        channel_get_date_offset(d, date);

        char index_key[256];
        snprintf(index_key, sizeof(index_key), "%s%s", DNA_CHANNEL_NS_INDEX, date);

        dna_channel_index_entry_t *day_entries = NULL;
        size_t day_count = 0;

        int ret = fetch_channel_day_bucket(index_key, &day_entries, &day_count);
        if (ret == 0 && day_entries && day_count > 0) {
            /* Merge, deduping by channel_uuid */
            for (size_t i = 0; i < day_count; i++) {
                bool duplicate = false;
                for (size_t j = 0; j < all_count; j++) {
                    if (strcmp(all_entries[j].channel_uuid, day_entries[i].channel_uuid) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;

                if (all_count >= all_capacity) {
                    all_capacity = all_capacity ? all_capacity * 2 : 64;
                    dna_channel_index_entry_t *tmp = realloc(
                        all_entries, all_capacity * sizeof(dna_channel_index_entry_t));
                    if (!tmp) break;
                    all_entries = tmp;
                }

                all_entries[all_count++] = day_entries[i];
            }
            free(day_entries);
        }
    }

    if (all_count == 0) {
        free(all_entries);
        return -2;  /* No channels found */
    }

    /* Sort by created_at descending (newest first) */
    qsort(all_entries, all_count, sizeof(dna_channel_index_entry_t), compare_index_entry_desc);

    /* Filter out deleted entries */
    size_t filtered = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (!all_entries[i].deleted) {
            if (filtered != i) {
                all_entries[filtered] = all_entries[i];
            }
            filtered++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Browsed %zu channels (%zu after filtering deleted)\n", all_count, filtered);

    if (filtered == 0) {
        free(all_entries);
        return -2;
    }

    /* Convert index entries to channel structs for the caller */
    dna_channel_t *channels = calloc(filtered, sizeof(dna_channel_t));
    if (!channels) {
        free(all_entries);
        return -1;
    }

    for (size_t i = 0; i < filtered; i++) {
        strncpy(channels[i].uuid, all_entries[i].channel_uuid, sizeof(channels[i].uuid) - 1);
        strncpy(channels[i].name, all_entries[i].name, DNA_CHANNEL_NAME_MAX);
        channels[i].description = strdup(all_entries[i].description_preview);
        strncpy(channels[i].creator_fingerprint, all_entries[i].creator_fingerprint,
                sizeof(channels[i].creator_fingerprint) - 1);
        channels[i].created_at = all_entries[i].created_at;
        channels[i].is_public = true;  /* Only public channels appear in index */
        channels[i].deleted = false;
        channels[i].deleted_at = 0;
        channels[i].signature = NULL;
        channels[i].signature_len = 0;
    }

    free(all_entries);

    *channels_out = channels;
    *count_out = filtered;
    return 0;
}
