/*
 * DNA Feeds v2 - Topic Operations
 *
 * Implements topic creation, retrieval, deletion, and indexing.
 *
 * Storage Model:
 * - Topic: SHA256("dna:feeds:topic:" + uuid) -> chunked JSON
 * - Category Index: SHA256("dna:feeds:idx:cat:" + cat_id + ":" + date) -> multi-owner
 * - Global Index: SHA256("dna:feeds:idx:all:" + date) -> multi-owner
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

#define LOG_TAG "DNA_FEED"

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
 * UUID Generation
 * ========================================================================== */

void dna_feed_generate_uuid(char *uuid_out) {
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

    /* Format: xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx */
    snprintf(uuid_out, DNA_FEED_UUID_LEN,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5],
             bytes[6], bytes[7],
             bytes[8], bytes[9],
             bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/* ============================================================================
 * Category ID Generation
 * ========================================================================== */

int dna_feed_make_category_id(const char *name, char *category_id_out) {
    if (!name || !category_id_out) return -1;

    /* Convert to lowercase */
    char lower[64];
    size_t len = strlen(name);
    if (len >= sizeof(lower)) len = sizeof(lower) - 1;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') {
            lower[i] = c + ('a' - 'A');
        } else {
            lower[i] = c;
        }
    }
    lower[len] = '\0';

    /* SHA256 of lowercase name */
    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, lower, len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Hex encode */
    for (int i = 0; i < 32; i++) {
        sprintf(category_id_out + (i * 2), "%02x", hash[i]);
    }
    category_id_out[64] = '\0';

    return 0;
}

/* ============================================================================
 * Date Helpers
 * ========================================================================== */

void dna_feed_get_today_date(char *date_out) {
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    strftime(date_out, 12, "%Y%m%d", tm_info);
}

void dna_feed_get_date_offset(int days_ago, char *date_out) {
    time_t now = time(NULL);
    now -= days_ago * 86400;  /* Subtract days in seconds */
    struct tm *tm_info = gmtime(&now);
    strftime(date_out, 12, "%Y%m%d", tm_info);
}

/* ============================================================================
 * DHT Key Generation
 * ========================================================================== */

int dna_feed_get_topic_key(const char *uuid, char *key_out) {
    if (!uuid || !key_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "dna:feeds:topic:%s", uuid);

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

    for (int i = 0; i < 32; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

int dna_feed_get_comments_key(const char *uuid, char *key_out) {
    if (!uuid || !key_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "dna:feeds:topic:%s:comments", uuid);

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

    for (int i = 0; i < 32; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

int dna_feed_get_category_index_key(const char *category_id, const char *date, char *key_out) {
    if (!category_id || !date || !key_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "dna:feeds:idx:cat:%s:%s", category_id, date);

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

    for (int i = 0; i < 32; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

int dna_feed_get_global_index_key(const char *date, char *key_out) {
    if (!date || !key_out) return -1;

    char input[256];
    snprintf(input, sizeof(input), "dna:feeds:idx:all:%s", date);

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

    for (int i = 0; i < 32; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int topic_to_json(const dna_feed_topic_t *topic, bool include_signature, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(topic->version));
    json_object_object_add(root, "topic_uuid", json_object_new_string(topic->topic_uuid));
    json_object_object_add(root, "author", json_object_new_string(topic->author_fingerprint));
    json_object_object_add(root, "title", json_object_new_string(topic->title));
    json_object_object_add(root, "body", json_object_new_string(topic->body));
    json_object_object_add(root, "category_id", json_object_new_string(topic->category_id));

    /* Tags array */
    json_object *tags = json_object_new_array();
    for (int i = 0; i < topic->tag_count; i++) {
        json_object_array_add(tags, json_object_new_string(topic->tags[i]));
    }
    json_object_object_add(root, "tags", tags);

    json_object_object_add(root, "created_at", json_object_new_int64(topic->created_at));
    json_object_object_add(root, "deleted", json_object_new_boolean(topic->deleted));
    json_object_object_add(root, "deleted_at", json_object_new_int64(topic->deleted_at));

    /* Signature (base64) - only if requested */
    if (include_signature && topic->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(topic->signature, topic->signature_len, NULL);
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

static int topic_from_json(const char *json_str, dna_feed_topic_t **topic_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_topic_t *topic = calloc(1, sizeof(dna_feed_topic_t));
    if (!topic) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;

    if (json_object_object_get_ex(root, "version", &j_val))
        topic->version = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "topic_uuid", &j_val))
        strncpy(topic->topic_uuid, json_object_get_string(j_val), DNA_FEED_UUID_LEN - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(topic->author_fingerprint, json_object_get_string(j_val), DNA_FEED_FINGERPRINT_LEN - 1);
    if (json_object_object_get_ex(root, "title", &j_val))
        strncpy(topic->title, json_object_get_string(j_val), DNA_FEED_MAX_TITLE_LEN);
    if (json_object_object_get_ex(root, "body", &j_val))
        strncpy(topic->body, json_object_get_string(j_val), DNA_FEED_MAX_BODY_LEN);
    if (json_object_object_get_ex(root, "category_id", &j_val))
        strncpy(topic->category_id, json_object_get_string(j_val), DNA_FEED_CATEGORY_ID_LEN - 1);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        topic->created_at = json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "deleted", &j_val))
        topic->deleted = json_object_get_boolean(j_val);
    if (json_object_object_get_ex(root, "deleted_at", &j_val))
        topic->deleted_at = json_object_get_int64(j_val);

    /* Tags array */
    json_object *j_tags;
    if (json_object_object_get_ex(root, "tags", &j_tags)) {
        int count = json_object_array_length(j_tags);
        if (count > DNA_FEED_MAX_TAGS) count = DNA_FEED_MAX_TAGS;
        topic->tag_count = count;
        for (int i = 0; i < count; i++) {
            json_object *j_tag = json_object_array_get_idx(j_tags, i);
            if (j_tag) {
                strncpy(topic->tags[i], json_object_get_string(j_tag), DNA_FEED_MAX_TAG_LEN);
            }
        }
    }

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= sizeof(topic->signature)) {
                memcpy(topic->signature, sig_bytes, sig_len);
                topic->signature_len = sig_len;
            }
            free(sig_bytes);
        }
    }

    json_object_put(root);
    *topic_out = topic;
    return 0;
}

/* ============================================================================
 * Topic Operations
 * ========================================================================== */

void dna_feed_topic_free(dna_feed_topic_t *topic) {
    free(topic);
}

void dna_feed_topics_free(dna_feed_topic_t *topics, size_t count) {
    /* Topics is an array, not array of pointers */
    free(topics);
}

int dna_feed_topic_verify(const dna_feed_topic_t *topic, const uint8_t *public_key) {
    if (!topic || !public_key || topic->signature_len == 0) return -1;

    /* Build JSON without signature for verification */
    dna_feed_topic_t temp = *topic;
    temp.signature_len = 0;
    memset(temp.signature, 0, sizeof(temp.signature));

    char *json_data = NULL;
    if (topic_to_json(&temp, false, &json_data) != 0) {
        return -1;
    }

    int ret = pqcrystals_dilithium5_ref_verify(
        topic->signature, topic->signature_len,
        (const uint8_t *)json_data, strlen(json_data),
        NULL, 0, public_key);

    free(json_data);
    return (ret == 0) ? 0 : -1;
}

int dna_feed_topic_get(dht_context_t *dht_ctx, const char *uuid, dna_feed_topic_t **topic_out) {
    if (!dht_ctx || !uuid || !topic_out) return -1;

    /* Generate base key for topic */
    char base_key[128];
    snprintf(base_key, sizeof(base_key), "dna:feeds:topic:%s", uuid);

    QGP_LOG_INFO(LOG_TAG, "Fetching topic %s...\n", uuid);

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);

    if (ret != DHT_CHUNK_OK || !value || value_len == 0) {
        return -2;
    }

    char *json_str = malloc(value_len + 1);
    if (!json_str) {
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = topic_from_json(json_str, topic_out);
    free(json_str);

    return ret;
}

int dna_feed_topic_create(dht_context_t *dht_ctx,
                          const char *title,
                          const char *body,
                          const char *category,
                          const char **tags,
                          int tag_count,
                          const char *author_fingerprint,
                          const uint8_t *private_key,
                          char *uuid_out) {
    if (!dht_ctx || !title || !body || !category || !author_fingerprint || !private_key) {
        return -1;
    }

    /* Validate lengths */
    if (strlen(title) == 0 || strlen(title) > DNA_FEED_MAX_TITLE_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid title length\n");
        return -1;
    }
    if (strlen(body) > DNA_FEED_MAX_BODY_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Body too long\n");
        return -1;
    }
    if (tag_count < 0 || tag_count > DNA_FEED_MAX_TAGS) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid tag count\n");
        return -1;
    }

    /* Create topic structure */
    dna_feed_topic_t *topic = calloc(1, sizeof(dna_feed_topic_t));
    if (!topic) return -1;

    /* Generate UUID */
    dna_feed_generate_uuid(topic->topic_uuid);

    /* Copy fields */
    strncpy(topic->title, title, DNA_FEED_MAX_TITLE_LEN);
    strncpy(topic->body, body, DNA_FEED_MAX_BODY_LEN);
    strncpy(topic->author_fingerprint, author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);

    /* Generate category_id */
    if (dna_feed_make_category_id(category, topic->category_id) != 0) {
        free(topic);
        return -1;
    }

    /* Copy tags */
    for (int i = 0; i < tag_count && tags && tags[i]; i++) {
        strncpy(topic->tags[i], tags[i], DNA_FEED_MAX_TAG_LEN);
        topic->tag_count++;
    }

    /* Set timestamps */
    topic->created_at = (uint64_t)time(NULL);
    topic->deleted = false;
    topic->deleted_at = 0;
    topic->version = DNA_FEED_VERSION;

    /* Sign topic: JSON without signature */
    char *json_to_sign = NULL;
    if (topic_to_json(topic, false, &json_to_sign) != 0) {
        free(topic);
        return -1;
    }

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(
        topic->signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign topic\n");
        free(topic);
        return -1;
    }
    topic->signature_len = sig_len;

    /* Serialize with signature */
    char *json_data = NULL;
    if (topic_to_json(topic, true, &json_data) != 0) {
        free(topic);
        return -1;
    }

    /* Publish topic using chunked layer */
    char base_key[128];
    snprintf(base_key, sizeof(base_key), "dna:feeds:topic:%s", topic->topic_uuid);

    QGP_LOG_INFO(LOG_TAG, "Publishing topic %s to DHT...\n", topic->topic_uuid);
    ret = dht_chunked_publish(dht_ctx, base_key,
                              (const uint8_t *)json_data, strlen(json_data),
                              DNA_FEED_TTL_SECONDS);
    free(json_data);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish topic: %s\n", dht_chunked_strerror(ret));
        free(topic);
        return -1;
    }

    /* Add to indexes */
    dna_feed_index_entry_t entry = {0};
    strncpy(entry.topic_uuid, topic->topic_uuid, DNA_FEED_UUID_LEN - 1);
    strncpy(entry.author_fingerprint, author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);
    strncpy(entry.title, topic->title, DNA_FEED_MAX_TITLE_LEN);
    strncpy(entry.category_id, topic->category_id, DNA_FEED_CATEGORY_ID_LEN - 1);
    entry.created_at = topic->created_at;
    entry.deleted = false;

    if (dna_feed_index_add(dht_ctx, &entry) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to add to indexes\n");
        /* Continue anyway - topic itself was published successfully */
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created topic %s\n", topic->topic_uuid);

    /* Return UUID */
    if (uuid_out) {
        strncpy(uuid_out, topic->topic_uuid, DNA_FEED_UUID_LEN);
    }

    free(topic);
    return 0;
}

int dna_feed_topic_delete(dht_context_t *dht_ctx,
                          const char *uuid,
                          const char *author_fingerprint,
                          const uint8_t *private_key) {
    if (!dht_ctx || !uuid || !author_fingerprint || !private_key) return -1;

    /* Fetch existing topic */
    dna_feed_topic_t *topic = NULL;
    int ret = dna_feed_topic_get(dht_ctx, uuid, &topic);
    if (ret != 0 || !topic) {
        return -2;  /* Not found */
    }

    /* Verify ownership */
    if (strcmp(topic->author_fingerprint, author_fingerprint) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Not the owner of topic %s\n", uuid);
        dna_feed_topic_free(topic);
        return -3;  /* Not owner */
    }

    /* Already deleted? */
    if (topic->deleted) {
        dna_feed_topic_free(topic);
        return 0;  /* Already deleted, success */
    }

    /* Mark as deleted */
    topic->deleted = true;
    topic->deleted_at = (uint64_t)time(NULL);

    /* Re-sign with new data */
    char *json_to_sign = NULL;
    if (topic_to_json(topic, false, &json_to_sign) != 0) {
        dna_feed_topic_free(topic);
        return -1;
    }

    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(
        topic->signature, &sig_len,
        (const uint8_t *)json_to_sign, strlen(json_to_sign),
        NULL, 0, private_key);
    free(json_to_sign);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign deleted topic\n");
        dna_feed_topic_free(topic);
        return -1;
    }
    topic->signature_len = sig_len;

    /* Serialize and republish */
    char *json_data = NULL;
    if (topic_to_json(topic, true, &json_data) != 0) {
        dna_feed_topic_free(topic);
        return -1;
    }

    char base_key[128];
    snprintf(base_key, sizeof(base_key), "dna:feeds:topic:%s", uuid);

    QGP_LOG_INFO(LOG_TAG, "Publishing deleted topic %s...\n", uuid);
    ret = dht_chunked_publish(dht_ctx, base_key,
                              (const uint8_t *)json_data, strlen(json_data),
                              DNA_FEED_TTL_SECONDS);
    free(json_data);
    dna_feed_topic_free(topic);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish deleted topic: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully deleted topic %s\n", uuid);
    return 0;
}

/* ============================================================================
 * Default Categories
 * ========================================================================== */

static const char *DEFAULT_CATEGORIES[] = {
    DNA_FEED_CATEGORY_GENERAL,
    DNA_FEED_CATEGORY_TECHNOLOGY,
    DNA_FEED_CATEGORY_HELP,
    DNA_FEED_CATEGORY_ANNOUNCEMENTS,
    DNA_FEED_CATEGORY_TRADING,
    DNA_FEED_CATEGORY_OFFTOPIC
};

static const int DEFAULT_CATEGORY_COUNT = sizeof(DEFAULT_CATEGORIES) / sizeof(DEFAULT_CATEGORIES[0]);

int dna_feed_get_default_categories(dna_feed_category_t **categories_out, size_t *count_out) {
    if (!categories_out || !count_out) return -1;

    dna_feed_category_t *cats = calloc(DEFAULT_CATEGORY_COUNT, sizeof(dna_feed_category_t));
    if (!cats) return -1;

    for (int i = 0; i < DEFAULT_CATEGORY_COUNT; i++) {
        dna_feed_make_category_id(DEFAULT_CATEGORIES[i], cats[i].category_id);
        strncpy(cats[i].name, DEFAULT_CATEGORIES[i], sizeof(cats[i].name) - 1);
        cats[i].topic_count = 0;  /* Would need DHT query to get actual count */
    }

    *categories_out = cats;
    *count_out = DEFAULT_CATEGORY_COUNT;
    return 0;
}
