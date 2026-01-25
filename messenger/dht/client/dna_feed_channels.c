/*
 * DNA Feed - Channel Operations
 *
 * Implements channel CRUD operations for the public feed system.
 * Uses dht_chunked layer for automatic chunking, compression, and parallel fetch.
 */

#include "dna_feed.h"
#include "../shared/dht_chunked.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DNA_CHANNELS"

/* v0.6.47: Thread-safe gmtime wrapper (security fix) */
static inline struct tm *safe_gmtime(const time_t *timer, struct tm *result) {
#ifdef _WIN32
    return (gmtime_s(result, timer) == 0) ? result : NULL;
#else
    return gmtime_r(timer, result);
#endif
}

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* ============================================================================
 * DHT Key Generation
 * ========================================================================== */

static int sha256_hex(const char *input, char *hex_out) {
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
        sprintf(hex_out + (i * 2), "%02x", hash[i]);
    }
    hex_out[64] = '\0';
    return 0;
}

int dna_feed_get_registry_key(char *key_out) {
    if (!key_out) return -1;
    return sha256_hex("dna:feed:registry", key_out);
}

int dna_feed_get_channel_key(const char *channel_id, char *key_out) {
    if (!channel_id || !key_out) return -1;
    char input[256];
    snprintf(input, sizeof(input), "dna:feed:%s:meta", channel_id);
    return sha256_hex(input, key_out);
}

int dna_feed_get_bucket_key(const char *channel_id, const char *date, char *key_out) {
    if (!channel_id || !date || !key_out) return -1;
    char input[256];
    snprintf(input, sizeof(input), "dna:feed:%s:posts:%s", channel_id, date);
    return sha256_hex(input, key_out);
}

int dna_feed_get_post_key(const char *post_id, char *key_out) {
    if (!post_id || !key_out) return -1;
    char input[512];
    snprintf(input, sizeof(input), "dna:feed:post:%s", post_id);
    return sha256_hex(input, key_out);
}

int dna_feed_get_votes_key(const char *post_id, char *key_out) {
    if (!post_id || !key_out) return -1;
    char input[512];
    snprintf(input, sizeof(input), "dna:feed:post:%s:votes", post_id);
    return sha256_hex(input, key_out);
}

void dna_feed_get_today_date(char *date_out) {
    time_t now = time(NULL);
    struct tm tm_buf;
    if (safe_gmtime(&now, &tm_buf)) {
        strftime(date_out, 12, "%Y%m%d", &tm_buf);
    } else {
        strncpy(date_out, "00000000", 12);
    }
}

int dna_feed_make_channel_id(const char *name, char *channel_id_out) {
    if (!name || !channel_id_out) return -1;

    /* Lowercase the name for consistent hashing */
    char lowercase[DNA_FEED_MAX_CHANNEL_NAME];
    size_t i;
    for (i = 0; name[i] && i < DNA_FEED_MAX_CHANNEL_NAME - 1; i++) {
        lowercase[i] = tolower((unsigned char)name[i]);
    }
    lowercase[i] = '\0';

    return sha256_hex(lowercase, channel_id_out);
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int channel_to_json(const dna_feed_channel_t *channel, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "channel_id", json_object_new_string(channel->channel_id));
    json_object_object_add(root, "name", json_object_new_string(channel->name));
    json_object_object_add(root, "description", json_object_new_string(channel->description));
    json_object_object_add(root, "creator", json_object_new_string(channel->creator_fingerprint));
    json_object_object_add(root, "created_at", json_object_new_int64(channel->created_at));
    json_object_object_add(root, "post_count", json_object_new_int(channel->post_count));
    json_object_object_add(root, "subscriber_count", json_object_new_int(channel->subscriber_count));
    json_object_object_add(root, "last_activity", json_object_new_int64(channel->last_activity));

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int channel_from_json(const char *json_str, dna_feed_channel_t **channel_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_channel_t *channel = calloc(1, sizeof(dna_feed_channel_t));
    if (!channel) {
        json_object_put(root);
        return -1;
    }

    /* v0.6.47: Add NULL checks - json_object_get_string() returns NULL on type mismatch (security fix) */
    json_object *j_val;
    const char *str_val;
    if (json_object_object_get_ex(root, "channel_id", &j_val)) {
        str_val = json_object_get_string(j_val);
        if (str_val) strncpy(channel->channel_id, str_val, sizeof(channel->channel_id) - 1);
    }
    if (json_object_object_get_ex(root, "name", &j_val)) {
        str_val = json_object_get_string(j_val);
        if (str_val) strncpy(channel->name, str_val, sizeof(channel->name) - 1);
    }
    if (json_object_object_get_ex(root, "description", &j_val)) {
        str_val = json_object_get_string(j_val);
        if (str_val) strncpy(channel->description, str_val, sizeof(channel->description) - 1);
    }
    if (json_object_object_get_ex(root, "creator", &j_val)) {
        str_val = json_object_get_string(j_val);
        if (str_val) strncpy(channel->creator_fingerprint, str_val, sizeof(channel->creator_fingerprint) - 1);
    }
    if (json_object_object_get_ex(root, "created_at", &j_val))
        channel->created_at = json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "post_count", &j_val))
        channel->post_count = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "subscriber_count", &j_val))
        channel->subscriber_count = json_object_get_int(j_val);
    if (json_object_object_get_ex(root, "last_activity", &j_val))
        channel->last_activity = json_object_get_int64(j_val);

    json_object_put(root);
    *channel_out = channel;
    return 0;
}

static int registry_to_json(const dna_feed_registry_t *registry, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "updated_at", json_object_new_int64(registry->updated_at));

    json_object *channels_arr = json_object_new_array();
    for (size_t i = 0; i < registry->channel_count; i++) {
        json_object *ch_obj = json_object_new_object();
        json_object_object_add(ch_obj, "channel_id",
            json_object_new_string(registry->channels[i].channel_id));
        json_object_object_add(ch_obj, "name",
            json_object_new_string(registry->channels[i].name));
        json_object_object_add(ch_obj, "description",
            json_object_new_string(registry->channels[i].description));
        json_object_object_add(ch_obj, "creator",
            json_object_new_string(registry->channels[i].creator_fingerprint));
        json_object_object_add(ch_obj, "created_at",
            json_object_new_int64(registry->channels[i].created_at));
        json_object_object_add(ch_obj, "post_count",
            json_object_new_int(registry->channels[i].post_count));
        json_object_object_add(ch_obj, "subscriber_count",
            json_object_new_int(registry->channels[i].subscriber_count));
        json_object_object_add(ch_obj, "last_activity",
            json_object_new_int64(registry->channels[i].last_activity));
        json_object_array_add(channels_arr, ch_obj);
    }
    json_object_object_add(root, "channels", channels_arr);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int registry_from_json(const char *json_str, dna_feed_registry_t **registry_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_registry_t *registry = calloc(1, sizeof(dna_feed_registry_t));
    if (!registry) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;
    if (json_object_object_get_ex(root, "updated_at", &j_val))
        registry->updated_at = json_object_get_int64(j_val);

    json_object *j_channels;
    if (json_object_object_get_ex(root, "channels", &j_channels)) {
        size_t count = json_object_array_length(j_channels);
        if (count > 0) {
            registry->channels = calloc(count, sizeof(dna_feed_channel_t));
            registry->allocated_count = count;

            for (size_t i = 0; i < count; i++) {
                json_object *ch_obj = json_object_array_get_idx(j_channels, i);
                if (!ch_obj) continue;

                if (json_object_object_get_ex(ch_obj, "channel_id", &j_val))
                    strncpy(registry->channels[i].channel_id, json_object_get_string(j_val),
                            sizeof(registry->channels[i].channel_id) - 1);
                if (json_object_object_get_ex(ch_obj, "name", &j_val))
                    strncpy(registry->channels[i].name, json_object_get_string(j_val),
                            sizeof(registry->channels[i].name) - 1);
                if (json_object_object_get_ex(ch_obj, "description", &j_val))
                    strncpy(registry->channels[i].description, json_object_get_string(j_val),
                            sizeof(registry->channels[i].description) - 1);
                if (json_object_object_get_ex(ch_obj, "creator", &j_val))
                    strncpy(registry->channels[i].creator_fingerprint, json_object_get_string(j_val),
                            sizeof(registry->channels[i].creator_fingerprint) - 1);
                if (json_object_object_get_ex(ch_obj, "created_at", &j_val))
                    registry->channels[i].created_at = json_object_get_int64(j_val);
                if (json_object_object_get_ex(ch_obj, "post_count", &j_val))
                    registry->channels[i].post_count = json_object_get_int(j_val);
                if (json_object_object_get_ex(ch_obj, "subscriber_count", &j_val))
                    registry->channels[i].subscriber_count = json_object_get_int(j_val);
                if (json_object_object_get_ex(ch_obj, "last_activity", &j_val))
                    registry->channels[i].last_activity = json_object_get_int64(j_val);

                registry->channel_count++;
            }
        }
    }

    json_object_put(root);
    *registry_out = registry;
    return 0;
}

/* ============================================================================
 * Channel Operations
 * ========================================================================== */

void dna_feed_channel_free(dna_feed_channel_t *channel) {
    free(channel);
}

void dna_feed_registry_free(dna_feed_registry_t *registry) {
    if (!registry) return;
    free(registry->channels);
    free(registry);
}

int dna_feed_registry_get(dht_context_t *dht_ctx, dna_feed_registry_t **registry_out) {
    if (!dht_ctx || !registry_out) return -1;

    /* Use base key string directly for chunked layer */
    const char *base_key = "dna:feed:registry";

    QGP_LOG_INFO(LOG_TAG, "Fetching channel registry from DHT...\n");

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);

    if (ret != DHT_CHUNK_OK || !value || value_len == 0) {
        QGP_LOG_INFO(LOG_TAG, "Registry not found in DHT\n");
        return -2;
    }

    /* Parse JSON */
    char *json_str = malloc(value_len + 1);
    if (!json_str) {
        free(value);
        return -1;
    }
    memcpy(json_str, value, value_len);
    json_str[value_len] = '\0';
    free(value);

    ret = registry_from_json(json_str, registry_out);
    free(json_str);

    if (ret == 0) {
        QGP_LOG_INFO(LOG_TAG, "Loaded registry with %zu channels\n", (*registry_out)->channel_count);
    }

    return ret;
}

int dna_feed_channel_get(dht_context_t *dht_ctx, const char *channel_id,
                         dna_feed_channel_t **channel_out) {
    if (!dht_ctx || !channel_id || !channel_out) return -1;

    /* Generate base key for channel metadata */
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "dna:feed:%s:meta", channel_id);

    QGP_LOG_INFO(LOG_TAG, "Fetching channel %s from DHT...\n", channel_id);

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_chunked_fetch(dht_ctx, base_key, &value, &value_len);

    if (ret != DHT_CHUNK_OK || !value || value_len == 0) {
        QGP_LOG_INFO(LOG_TAG, "Channel not found\n");
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

    ret = channel_from_json(json_str, channel_out);
    free(json_str);

    return ret;
}

int dna_feed_channel_create(dht_context_t *dht_ctx,
                            const char *name,
                            const char *description,
                            const char *creator_fingerprint,
                            const uint8_t *private_key,
                            dna_feed_channel_t **channel_out) {
    if (!dht_ctx || !name || !creator_fingerprint || !private_key) return -1;

    /* Validate name length */
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len >= DNA_FEED_MAX_CHANNEL_NAME) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid channel name length\n");
        return -1;
    }

    /* Generate channel_id */
    char channel_id[65];
    if (dna_feed_make_channel_id(name, channel_id) != 0) return -1;

    /* Check if channel already exists */
    dna_feed_channel_t *existing = NULL;
    if (dna_feed_channel_get(dht_ctx, channel_id, &existing) == 0) {
        QGP_LOG_INFO(LOG_TAG, "Channel '%s' already exists\n", name);
        dna_feed_channel_free(existing);
        return -2;
    }

    /* Create channel structure */
    dna_feed_channel_t *channel = calloc(1, sizeof(dna_feed_channel_t));
    if (!channel) return -1;

    strncpy(channel->channel_id, channel_id, sizeof(channel->channel_id) - 1);
    strncpy(channel->name, name, sizeof(channel->name) - 1);
    if (description) {
        strncpy(channel->description, description, sizeof(channel->description) - 1);
    }
    strncpy(channel->creator_fingerprint, creator_fingerprint, sizeof(channel->creator_fingerprint) - 1);
    channel->created_at = (uint64_t)time(NULL);
    channel->post_count = 0;
    channel->subscriber_count = 1;  /* Creator is first subscriber */
    channel->last_activity = channel->created_at;

    /* Serialize to JSON */
    char *json_data = NULL;
    if (channel_to_json(channel, &json_data) != 0) {
        free(channel);
        return -1;
    }

    /* Publish channel metadata to DHT using chunked layer */
    char base_key[256];
    snprintf(base_key, sizeof(base_key), "dna:feed:%s:meta", channel_id);

    QGP_LOG_INFO(LOG_TAG, "Publishing channel '%s' to DHT...\n", name);
    int ret = dht_chunked_publish(dht_ctx, base_key,
                                   (const uint8_t *)json_data, strlen(json_data),
                                   DNA_FEED_TTL_SECONDS);
    free(json_data);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish channel to DHT: %s\n", dht_chunked_strerror(ret));
        free(channel);
        return -1;
    }

    /* Add to registry */
    dna_feed_registry_t *registry = NULL;
    if (dna_feed_registry_get(dht_ctx, &registry) != 0) {
        /* Create new registry */
        registry = calloc(1, sizeof(dna_feed_registry_t));
        if (!registry) {
            free(channel);
            return -1;
        }
    }

    /* Expand registry */
    size_t new_count = registry->channel_count + 1;
    dna_feed_channel_t *new_channels = realloc(registry->channels,
                                                new_count * sizeof(dna_feed_channel_t));
    if (!new_channels) {
        dna_feed_registry_free(registry);
        free(channel);
        return -1;
    }

    registry->channels = new_channels;
    registry->channels[registry->channel_count] = *channel;
    registry->channel_count = new_count;
    registry->allocated_count = new_count;
    registry->updated_at = (uint64_t)time(NULL);

    /* Publish updated registry using chunked layer */
    char *registry_json = NULL;
    if (registry_to_json(registry, &registry_json) != 0) {
        dna_feed_registry_free(registry);
        free(channel);
        return -1;
    }

    ret = dht_chunked_publish(dht_ctx, "dna:feed:registry",
                              (const uint8_t *)registry_json, strlen(registry_json),
                              DNA_FEED_TTL_SECONDS);
    free(registry_json);
    dna_feed_registry_free(registry);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update registry: %s\n", dht_chunked_strerror(ret));
        /* Channel was created, just registry update failed */
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully created channel '%s'\n", name);

    if (channel_out) {
        *channel_out = channel;
    } else {
        free(channel);
    }

    return 0;
}

int dna_feed_init_default_channels(dht_context_t *dht_ctx,
                                   const char *creator_fingerprint,
                                   const uint8_t *private_key) {
    if (!dht_ctx || !creator_fingerprint || !private_key) return -1;

    const struct {
        const char *name;
        const char *description;
    } defaults[] = {
        { "general", "General discussion for everyone" },
        { "announcements", "Official announcements and updates" },
        { "help", "Get help and support from the community" },
        { "random", "Off-topic chat and random discussions" }
    };

    int created = 0;
    for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++) {
        int ret = dna_feed_channel_create(dht_ctx, defaults[i].name, defaults[i].description,
                                          creator_fingerprint, private_key, NULL);
        if (ret == 0) {
            QGP_LOG_INFO(LOG_TAG, "Created default channel: #%s\n", defaults[i].name);
            created++;
        } else if (ret == -2) {
            QGP_LOG_INFO(LOG_TAG, "Default channel #%s already exists\n", defaults[i].name);
        }
    }

    return created;
}
