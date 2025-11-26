/*
 * DNA Feed - Post Operations
 *
 * Implements post creation, retrieval, and threading for the public feed system.
 */

#include "dna_feed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/* Dilithium5 functions */
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

/* Network byte order helpers */
static inline uint64_t htonll_feed(uint64_t value) {
    static const int num = 1;
    if (*(char *)&num == 1) {
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

/* Base64 helpers (same as in dna_feed_channels.c) */
static char *base64_encode(const uint8_t *data, size_t len) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = base64_chars[(triple >> 6) & 0x3F];
        out[j++] = base64_chars[triple & 0x3F];
    }

    size_t padding = len % 3;
    if (padding == 1) { out[j - 2] = '='; out[j - 1] = '='; }
    else if (padding == 2) { out[j - 1] = '='; }
    out[j] = '\0';
    return out;
}

static uint8_t *base64_decode(const char *str, size_t *out_len) {
    static const uint8_t base64_table[256] = {
        ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
        ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
        ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
        ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
        ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
        ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
        ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
        ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63
    };

    size_t len = strlen(str);
    size_t padding = 0;
    if (len >= 2 && str[len - 1] == '=') {
        padding++;
        if (str[len - 2] == '=') padding++;
    }

    *out_len = (len / 4) * 3 - padding;
    uint8_t *out = malloc(*out_len);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t sextet_a = str[i] == '=' ? 0 : base64_table[(uint8_t)str[i]]; i++;
        uint32_t sextet_b = str[i] == '=' ? 0 : base64_table[(uint8_t)str[i]]; i++;
        uint32_t sextet_c = str[i] == '=' ? 0 : base64_table[(uint8_t)str[i]]; i++;
        uint32_t sextet_d = str[i] == '=' ? 0 : base64_table[(uint8_t)str[i]]; i++;

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len) out[j++] = (triple >> 8) & 0xFF;
        if (j < *out_len) out[j++] = triple & 0xFF;
    }
    return out;
}

/* ============================================================================
 * Post ID Generation
 * ========================================================================== */

int dna_feed_make_post_id(const char *fingerprint, char *post_id_out) {
    if (!fingerprint || !post_id_out) return -1;

    /* Get current timestamp in milliseconds */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    /* Generate 4 random bytes for uniqueness */
    uint8_t random_bytes[4];
    if (RAND_bytes(random_bytes, 4) != 1) {
        /* Fallback: use nanoseconds */
        uint32_t fallback = (uint32_t)(ts.tv_nsec ^ ts.tv_sec);
        memcpy(random_bytes, &fallback, 4);
    }

    /* Format: fingerprint_timestamp_random */
    snprintf(post_id_out, 200, "%s_%lu_%02x%02x%02x%02x",
             fingerprint, timestamp_ms,
             random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]);

    return 0;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int post_to_json(const dna_feed_post_t *post, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "post_id", json_object_new_string(post->post_id));
    json_object_object_add(root, "channel_id", json_object_new_string(post->channel_id));
    json_object_object_add(root, "author", json_object_new_string(post->author_fingerprint));
    json_object_object_add(root, "text", json_object_new_string(post->text));
    json_object_object_add(root, "timestamp", json_object_new_int64(post->timestamp));
    json_object_object_add(root, "reply_to", json_object_new_string(post->reply_to));
    json_object_object_add(root, "reply_depth", json_object_new_int(post->reply_depth));

    /* Signature (base64) */
    if (post->signature_len > 0) {
        char *sig_b64 = base64_encode(post->signature, post->signature_len);
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

static int post_from_json(const char *json_str, dna_feed_post_t **post_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_post_t *post = calloc(1, sizeof(dna_feed_post_t));
    if (!post) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;
    if (json_object_object_get_ex(root, "post_id", &j_val))
        strncpy(post->post_id, json_object_get_string(j_val), sizeof(post->post_id) - 1);
    if (json_object_object_get_ex(root, "channel_id", &j_val))
        strncpy(post->channel_id, json_object_get_string(j_val), sizeof(post->channel_id) - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(post->author_fingerprint, json_object_get_string(j_val), sizeof(post->author_fingerprint) - 1);
    if (json_object_object_get_ex(root, "text", &j_val))
        strncpy(post->text, json_object_get_string(j_val), sizeof(post->text) - 1);
    if (json_object_object_get_ex(root, "timestamp", &j_val))
        post->timestamp = json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "reply_to", &j_val))
        strncpy(post->reply_to, json_object_get_string(j_val), sizeof(post->reply_to) - 1);
    if (json_object_object_get_ex(root, "reply_depth", &j_val))
        post->reply_depth = json_object_get_int(j_val);

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = base64_decode(sig_b64, &sig_len);
            if (sig_bytes && sig_len <= sizeof(post->signature)) {
                memcpy(post->signature, sig_bytes, sig_len);
                post->signature_len = sig_len;
            }
            free(sig_bytes);
        }
    }

    json_object_put(root);
    *post_out = post;
    return 0;
}

static int bucket_to_json(const dna_feed_bucket_t *bucket, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "channel_id", json_object_new_string(bucket->channel_id));
    json_object_object_add(root, "bucket_date", json_object_new_string(bucket->bucket_date));

    json_object *post_ids = json_object_new_array();
    for (size_t i = 0; i < bucket->post_count; i++) {
        json_object_array_add(post_ids, json_object_new_string(bucket->post_ids[i]));
    }
    json_object_object_add(root, "post_ids", post_ids);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int bucket_from_json(const char *json_str, dna_feed_bucket_t **bucket_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    dna_feed_bucket_t *bucket = calloc(1, sizeof(dna_feed_bucket_t));
    if (!bucket) {
        json_object_put(root);
        return -1;
    }

    json_object *j_val;
    if (json_object_object_get_ex(root, "channel_id", &j_val))
        strncpy(bucket->channel_id, json_object_get_string(j_val), sizeof(bucket->channel_id) - 1);
    if (json_object_object_get_ex(root, "bucket_date", &j_val))
        strncpy(bucket->bucket_date, json_object_get_string(j_val), sizeof(bucket->bucket_date) - 1);

    json_object *j_post_ids;
    if (json_object_object_get_ex(root, "post_ids", &j_post_ids)) {
        size_t count = json_object_array_length(j_post_ids);
        if (count > 0) {
            bucket->post_ids = calloc(count, sizeof(char *));
            bucket->allocated_count = count;

            for (size_t i = 0; i < count; i++) {
                json_object *j_id = json_object_array_get_idx(j_post_ids, i);
                if (j_id) {
                    bucket->post_ids[i] = strdup(json_object_get_string(j_id));
                    bucket->post_count++;
                }
            }
        }
    }

    json_object_put(root);
    *bucket_out = bucket;
    return 0;
}

/* ============================================================================
 * Post Operations
 * ========================================================================== */

void dna_feed_post_free(dna_feed_post_t *post) {
    free(post);
}

void dna_feed_bucket_free(dna_feed_bucket_t *bucket) {
    if (!bucket) return;
    if (bucket->post_ids) {
        for (size_t i = 0; i < bucket->post_count; i++) {
            free(bucket->post_ids[i]);
        }
        free(bucket->post_ids);
    }
    free(bucket);
}

int dna_feed_verify_post_signature(const dna_feed_post_t *post, const uint8_t *public_key) {
    if (!post || !public_key || post->signature_len == 0) return -1;

    /* Build signed data: text || timestamp (network byte order) */
    size_t text_len = strlen(post->text);
    size_t data_len = text_len + sizeof(uint64_t);
    uint8_t *data = malloc(data_len);
    if (!data) return -1;

    memcpy(data, post->text, text_len);
    uint64_t ts_net = htonll_feed(post->timestamp);
    memcpy(data + text_len, &ts_net, sizeof(uint64_t));

    int ret = pqcrystals_dilithium5_ref_verify(post->signature, post->signature_len,
                                                data, data_len, NULL, 0, public_key);
    free(data);
    return (ret == 0) ? 0 : -1;
}

int dna_feed_post_get(dht_context_t *dht_ctx, const char *post_id, dna_feed_post_t **post_out) {
    if (!dht_ctx || !post_id || !post_out) return -1;

    char dht_key[65];
    if (dna_feed_get_post_key(post_id, dht_key) != 0) return -1;

    printf("[DNA_FEED] Fetching post %s...\n", post_id);

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_get(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key), &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
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

    ret = post_from_json(json_str, post_out);
    free(json_str);

    return ret;
}

/* Get bucket for a channel/date */
static int get_bucket(dht_context_t *dht_ctx, const char *channel_id, const char *date,
                      dna_feed_bucket_t **bucket_out) {
    char dht_key[65];
    if (dna_feed_get_bucket_key(channel_id, date, dht_key) != 0) return -1;

    uint8_t *value = NULL;
    size_t value_len = 0;
    int ret = dht_get(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key), &value, &value_len);

    if (ret != 0 || !value || value_len == 0) {
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

    ret = bucket_from_json(json_str, bucket_out);
    free(json_str);

    return ret;
}

/* Save bucket to DHT */
static int save_bucket(dht_context_t *dht_ctx, const dna_feed_bucket_t *bucket) {
    char *json_data = NULL;
    if (bucket_to_json(bucket, &json_data) != 0) return -1;

    char dht_key[65];
    if (dna_feed_get_bucket_key(bucket->channel_id, bucket->bucket_date, dht_key) != 0) {
        free(json_data);
        return -1;
    }

    int ret = dht_put_signed(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                             (const uint8_t *)json_data, strlen(json_data),
                             1, DNA_FEED_TTL_SECONDS);
    free(json_data);

    return ret;
}

int dna_feed_post_create(dht_context_t *dht_ctx,
                         const char *channel_id,
                         const char *author_fingerprint,
                         const char *text,
                         const uint8_t *private_key,
                         const char *reply_to,
                         dna_feed_post_t **post_out) {
    if (!dht_ctx || !channel_id || !author_fingerprint || !text || !private_key) return -1;

    /* Validate text length */
    size_t text_len = strlen(text);
    if (text_len == 0 || text_len >= DNA_FEED_MAX_POST_TEXT) {
        fprintf(stderr, "[DNA_FEED] Invalid post text length\n");
        return -1;
    }

    /* Create post structure */
    dna_feed_post_t *post = calloc(1, sizeof(dna_feed_post_t));
    if (!post) return -1;

    /* Generate unique post_id */
    if (dna_feed_make_post_id(author_fingerprint, post->post_id) != 0) {
        free(post);
        return -1;
    }

    strncpy(post->channel_id, channel_id, sizeof(post->channel_id) - 1);
    strncpy(post->author_fingerprint, author_fingerprint, sizeof(post->author_fingerprint) - 1);
    strncpy(post->text, text, sizeof(post->text) - 1);

    /* Use millisecond timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    post->timestamp = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    /* Handle threading */
    post->reply_depth = 0;
    if (reply_to && reply_to[0] != '\0') {
        strncpy(post->reply_to, reply_to, sizeof(post->reply_to) - 1);

        /* Fetch parent to get depth */
        dna_feed_post_t *parent = NULL;
        if (dna_feed_post_get(dht_ctx, reply_to, &parent) == 0) {
            post->reply_depth = parent->reply_depth + 1;
            dna_feed_post_free(parent);

            if (post->reply_depth > DNA_FEED_MAX_THREAD_DEPTH) {
                fprintf(stderr, "[DNA_FEED] Max thread depth exceeded\n");
                free(post);
                return -2;
            }
        }
    }

    /* Sign post: text || timestamp */
    uint8_t *sign_data = malloc(text_len + sizeof(uint64_t));
    if (!sign_data) {
        free(post);
        return -1;
    }

    memcpy(sign_data, text, text_len);
    uint64_t ts_net = htonll_feed(post->timestamp);
    memcpy(sign_data + text_len, &ts_net, sizeof(uint64_t));

    size_t sig_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(post->signature, &sig_len,
                                                   sign_data, text_len + sizeof(uint64_t),
                                                   NULL, 0, private_key);
    free(sign_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_FEED] Failed to sign post\n");
        free(post);
        return -1;
    }
    post->signature_len = sig_len;

    /* Serialize and publish post */
    char *json_data = NULL;
    if (post_to_json(post, &json_data) != 0) {
        free(post);
        return -1;
    }

    char post_key[65];
    if (dna_feed_get_post_key(post->post_id, post_key) != 0) {
        free(json_data);
        free(post);
        return -1;
    }

    printf("[DNA_FEED] Publishing post to DHT...\n");
    ret = dht_put_signed(dht_ctx, (const uint8_t *)post_key, strlen(post_key),
                         (const uint8_t *)json_data, strlen(json_data),
                         1, DNA_FEED_TTL_SECONDS);
    free(json_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_FEED] Failed to publish post\n");
        free(post);
        return -1;
    }

    /* Add to daily bucket index */
    char today[12];
    dna_feed_get_today_date(today);

    dna_feed_bucket_t *bucket = NULL;
    if (get_bucket(dht_ctx, channel_id, today, &bucket) != 0) {
        /* Create new bucket */
        bucket = calloc(1, sizeof(dna_feed_bucket_t));
        if (!bucket) {
            free(post);
            return -1;
        }
        strncpy(bucket->channel_id, channel_id, sizeof(bucket->channel_id) - 1);
        strncpy(bucket->bucket_date, today, sizeof(bucket->bucket_date) - 1);
    }

    /* Check bucket size limit */
    if (bucket->post_count >= DNA_FEED_MAX_POSTS_PER_BUCKET) {
        fprintf(stderr, "[DNA_FEED] Bucket full for today\n");
        /* Continue anyway, just don't add to index */
    } else {
        /* Add post_id to bucket */
        size_t new_count = bucket->post_count + 1;
        char **new_ids = realloc(bucket->post_ids, new_count * sizeof(char *));
        if (new_ids) {
            bucket->post_ids = new_ids;
            bucket->post_ids[bucket->post_count] = strdup(post->post_id);
            bucket->post_count = new_count;

            /* Save updated bucket */
            save_bucket(dht_ctx, bucket);
        }
    }

    dna_feed_bucket_free(bucket);

    printf("[DNA_FEED] Successfully created post %s\n", post->post_id);

    if (post_out) {
        *post_out = post;
    } else {
        free(post);
    }

    return 0;
}

int dna_feed_posts_get_by_channel(dht_context_t *dht_ctx,
                                  const char *channel_id,
                                  const char *date,
                                  dna_feed_post_t **posts_out,
                                  size_t *count_out) {
    if (!dht_ctx || !channel_id || !posts_out || !count_out) return -1;

    /* Use today if no date specified */
    char date_buf[12];
    if (!date) {
        dna_feed_get_today_date(date_buf);
        date = date_buf;
    }

    printf("[DNA_FEED] Fetching posts for channel %s, date %s...\n", channel_id, date);

    /* Get bucket */
    dna_feed_bucket_t *bucket = NULL;
    int ret = get_bucket(dht_ctx, channel_id, date, &bucket);
    if (ret != 0 || !bucket || bucket->post_count == 0) {
        *posts_out = NULL;
        *count_out = 0;
        if (bucket) dna_feed_bucket_free(bucket);
        return (ret == -2) ? -2 : -1;
    }

    /* Fetch each post */
    dna_feed_post_t *posts = calloc(bucket->post_count, sizeof(dna_feed_post_t));
    if (!posts) {
        dna_feed_bucket_free(bucket);
        return -1;
    }

    size_t fetched = 0;
    for (size_t i = 0; i < bucket->post_count; i++) {
        dna_feed_post_t *post = NULL;
        if (dna_feed_post_get(dht_ctx, bucket->post_ids[i], &post) == 0) {
            posts[fetched++] = *post;
            free(post);
        }
    }

    dna_feed_bucket_free(bucket);

    if (fetched == 0) {
        free(posts);
        *posts_out = NULL;
        *count_out = 0;
        return -2;
    }

    /* Resize to actual count */
    if (fetched < bucket->post_count) {
        dna_feed_post_t *resized = realloc(posts, fetched * sizeof(dna_feed_post_t));
        if (resized) posts = resized;
    }

    printf("[DNA_FEED] Fetched %zu posts\n", fetched);

    *posts_out = posts;
    *count_out = fetched;
    return 0;
}

int dna_feed_post_get_replies(dht_context_t *dht_ctx,
                              const char *post_id,
                              dna_feed_post_t **replies_out,
                              size_t *count_out) {
    /* For now, this requires fetching all posts and filtering by reply_to.
     * A more efficient approach would store reply indexes separately. */
    if (!dht_ctx || !post_id || !replies_out || !count_out) return -1;

    /* Get parent post to know channel */
    dna_feed_post_t *parent = NULL;
    if (dna_feed_post_get(dht_ctx, post_id, &parent) != 0) {
        return -1;
    }

    /* Get today's posts and filter */
    dna_feed_post_t *all_posts = NULL;
    size_t all_count = 0;
    if (dna_feed_posts_get_by_channel(dht_ctx, parent->channel_id, NULL, &all_posts, &all_count) != 0) {
        dna_feed_post_free(parent);
        *replies_out = NULL;
        *count_out = 0;
        return 0;
    }

    /* Count replies */
    size_t reply_count = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (strcmp(all_posts[i].reply_to, post_id) == 0) {
            reply_count++;
        }
    }

    if (reply_count == 0) {
        free(all_posts);
        dna_feed_post_free(parent);
        *replies_out = NULL;
        *count_out = 0;
        return 0;
    }

    /* Collect replies */
    dna_feed_post_t *replies = calloc(reply_count, sizeof(dna_feed_post_t));
    if (!replies) {
        free(all_posts);
        dna_feed_post_free(parent);
        return -1;
    }

    size_t idx = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (strcmp(all_posts[i].reply_to, post_id) == 0) {
            replies[idx++] = all_posts[i];
        }
    }

    free(all_posts);
    dna_feed_post_free(parent);

    *replies_out = replies;
    *count_out = reply_count;
    return 0;
}
