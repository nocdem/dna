/*
 * DNA Feed - Comment Operations
 *
 * Implements flat comment system for posts (no nesting).
 * Comments are stored as multi-owner values under post key.
 *
 * Storage Model:
 * - Comments: dna:feed:post:{post_id}:comments (multi-owner)
 * - Comment Votes: dna:feed:comment:{comment_id}:votes (multi-owner)
 */

#include "dna_feed.h"
#include "../shared/dht_chunked.h"
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
static inline uint64_t htonll_comment(uint64_t value) {
    static const int num = 1;
    if (*(char *)&num == 1) {
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

/* Base64 helpers */
static char *base64_encode_comment(const uint8_t *data, size_t len) {
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

static uint8_t *base64_decode_comment(const char *str, size_t *out_len) {
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
 * Comment ID Generation
 * ========================================================================== */

int dna_feed_make_comment_id(const char *fingerprint, char *comment_id_out) {
    if (!fingerprint || !comment_id_out) return -1;

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
    snprintf(comment_id_out, 200, "%s_%lu_%02x%02x%02x%02x",
             fingerprint, timestamp_ms,
             random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]);

    return 0;
}

/* ============================================================================
 * DHT Key Generation for Comments
 * ========================================================================== */

int dna_feed_get_comments_key(const char *post_id, char *key_out) {
    if (!post_id || !key_out) return -1;

    /* Build key string */
    char key_str[512];
    snprintf(key_str, sizeof(key_str), "dna:feed:post:%s:comments", post_id);

    /* SHA256 hash */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    uint8_t hash[32];
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key_str, strlen(key_str)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex */
    for (int i = 0; i < 32; i++) {
        sprintf(key_out + i * 2, "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

int dna_feed_get_comment_votes_key(const char *comment_id, char *key_out) {
    if (!comment_id || !key_out) return -1;

    /* Build key string */
    char key_str[512];
    snprintf(key_str, sizeof(key_str), "dna:feed:comment:%s:votes", comment_id);

    /* SHA256 hash */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    uint8_t hash[32];
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, key_str, strlen(key_str)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* Convert to hex */
    for (int i = 0; i < 32; i++) {
        sprintf(key_out + i * 2, "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
}

/* ============================================================================
 * JSON Serialization
 * ========================================================================== */

static int comment_to_json(const dna_feed_comment_t *comment, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(DNA_FEED_POST_VERSION));
    json_object_object_add(root, "comment_id", json_object_new_string(comment->comment_id));
    json_object_object_add(root, "post_id", json_object_new_string(comment->post_id));
    json_object_object_add(root, "author", json_object_new_string(comment->author_fingerprint));
    json_object_object_add(root, "text", json_object_new_string(comment->text));
    json_object_object_add(root, "timestamp", json_object_new_int64(comment->timestamp));

    /* Signature (base64) */
    if (comment->signature_len > 0) {
        char *sig_b64 = base64_encode_comment(comment->signature, comment->signature_len);
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
    if (json_object_object_get_ex(root, "comment_id", &j_val))
        strncpy(comment_out->comment_id, json_object_get_string(j_val), sizeof(comment_out->comment_id) - 1);
    if (json_object_object_get_ex(root, "post_id", &j_val))
        strncpy(comment_out->post_id, json_object_get_string(j_val), sizeof(comment_out->post_id) - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(comment_out->author_fingerprint, json_object_get_string(j_val), sizeof(comment_out->author_fingerprint) - 1);
    if (json_object_object_get_ex(root, "text", &j_val))
        strncpy(comment_out->text, json_object_get_string(j_val), sizeof(comment_out->text) - 1);
    if (json_object_object_get_ex(root, "timestamp", &j_val))
        comment_out->timestamp = json_object_get_int64(j_val);

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        const char *sig_b64 = json_object_get_string(j_val);
        if (sig_b64) {
            size_t sig_len = 0;
            uint8_t *sig_bytes = base64_decode_comment(sig_b64, &sig_len);
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

int dna_feed_verify_comment_signature(const dna_feed_comment_t *comment, const uint8_t *public_key) {
    if (!comment || !public_key || comment->signature_len == 0) return -1;

    /* Build signed data: text || timestamp || post_id (network byte order for timestamp) */
    size_t text_len = strlen(comment->text);
    size_t post_id_len = strlen(comment->post_id);
    size_t data_len = text_len + sizeof(uint64_t) + post_id_len;
    uint8_t *data = malloc(data_len);
    if (!data) return -1;

    memcpy(data, comment->text, text_len);
    uint64_t ts_net = htonll_comment(comment->timestamp);
    memcpy(data + text_len, &ts_net, sizeof(uint64_t));
    memcpy(data + text_len + sizeof(uint64_t), comment->post_id, post_id_len);

    int ret = pqcrystals_dilithium5_ref_verify(comment->signature, comment->signature_len,
                                                data, data_len, NULL, 0, public_key);
    free(data);
    return (ret == 0) ? 0 : -1;
}

int dna_feed_comment_add(dht_context_t *dht_ctx,
                         const char *post_id,
                         const char *author_fingerprint,
                         const char *text,
                         const uint8_t *private_key,
                         dna_feed_comment_t **comment_out) {
    if (!dht_ctx || !post_id || !author_fingerprint || !text || !private_key) return -1;

    /* Validate text length */
    size_t text_len = strlen(text);
    if (text_len == 0 || text_len >= DNA_FEED_MAX_COMMENT_TEXT) {
        fprintf(stderr, "[DNA_FEED] Invalid comment text length\n");
        return -1;
    }

    /* Verify parent post exists */
    dna_feed_post_t *parent = NULL;
    int ret = dna_feed_post_get(dht_ctx, post_id, &parent);
    if (ret != 0) {
        fprintf(stderr, "[DNA_FEED] Parent post not found: %s\n", post_id);
        return -2;
    }
    char parent_channel[65];
    strncpy(parent_channel, parent->channel_id, sizeof(parent_channel) - 1);
    parent_channel[64] = '\0';
    dna_feed_post_free(parent);

    /* Create comment structure */
    dna_feed_comment_t *comment = calloc(1, sizeof(dna_feed_comment_t));
    if (!comment) return -1;

    /* Generate unique comment_id */
    if (dna_feed_make_comment_id(author_fingerprint, comment->comment_id) != 0) {
        free(comment);
        return -1;
    }

    strncpy(comment->post_id, post_id, sizeof(comment->post_id) - 1);
    strncpy(comment->author_fingerprint, author_fingerprint, sizeof(comment->author_fingerprint) - 1);
    strncpy(comment->text, text, sizeof(comment->text) - 1);

    /* Use millisecond timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    comment->timestamp = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    /* Sign comment: text || timestamp || post_id */
    size_t post_id_len = strlen(post_id);
    size_t sign_data_len = text_len + sizeof(uint64_t) + post_id_len;
    uint8_t *sign_data = malloc(sign_data_len);
    if (!sign_data) {
        free(comment);
        return -1;
    }

    memcpy(sign_data, text, text_len);
    uint64_t ts_net = htonll_comment(comment->timestamp);
    memcpy(sign_data + text_len, &ts_net, sizeof(uint64_t));
    memcpy(sign_data + text_len + sizeof(uint64_t), post_id, post_id_len);

    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(comment->signature, &sig_len,
                                               sign_data, sign_data_len,
                                               NULL, 0, private_key);
    free(sign_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_FEED] Failed to sign comment\n");
        free(comment);
        return -1;
    }
    comment->signature_len = sig_len;

    /* Serialize comment */
    char *json_data = NULL;
    if (comment_to_json(comment, &json_data) != 0) {
        free(comment);
        return -1;
    }

    /* Get DHT key for comments: dna:feed:post:{post_id}:comments */
    char comments_key[512];
    snprintf(comments_key, sizeof(comments_key), "dna:feed:post:%s:comments", post_id);

    /* Get unique value_id for this author */
    uint64_t value_id = 1;
    dht_get_owner_value_id(dht_ctx, &value_id);

    printf("[DNA_FEED] Publishing comment to DHT (value_id=%lu)...\n", value_id);

    /* Publish as multi-owner signed value */
    ret = dht_put_signed(dht_ctx, (const uint8_t *)comments_key, strlen(comments_key),
                         (const uint8_t *)json_data, strlen(json_data),
                         value_id, DNA_FEED_TTL_SECONDS);
    free(json_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_FEED] Failed to publish comment\n");
        free(comment);
        return -1;
    }

    /* Engagement-TTL: Republish parent post to refresh its TTL
     * This keeps active posts alive longer */
    printf("[DNA_FEED] Refreshing parent post TTL (engagement-TTL)...\n");

    /* Fetch and republish the parent post */
    dna_feed_post_t *parent_post = NULL;
    if (dna_feed_post_get(dht_ctx, post_id, &parent_post) == 0) {
        /* Note: We don't modify the post content, just republish it to refresh TTL */
        char post_key[512];
        snprintf(post_key, sizeof(post_key), "dna:feed:post:%s", post_id);

        /* The post is already in DHT, just touch it to refresh */
        /* For now, we rely on the post author to republish their own content
         * In a full implementation, we could store the raw bytes and republish */
        dna_feed_post_free(parent_post);
    }

    /* Also ensure post is in today's bucket (for activity sorting) */
    char today[12];
    dna_feed_get_today_date(today);

    /* Note: save_poster_bucket would need to be made non-static or we'd need
     * to add the post to today's index here. For now, this is handled by the
     * channel index already containing the post_id */

    printf("[DNA_FEED] Successfully created comment %s\n", comment->comment_id);

    if (comment_out) {
        *comment_out = comment;
    } else {
        free(comment);
    }

    return 0;
}

int dna_feed_comments_get(dht_context_t *dht_ctx,
                          const char *post_id,
                          dna_feed_comment_t **comments_out,
                          size_t *count_out) {
    if (!dht_ctx || !post_id || !comments_out || !count_out) return -1;

    /* Get DHT key for comments */
    char comments_key[512];
    snprintf(comments_key, sizeof(comments_key), "dna:feed:post:%s:comments", post_id);

    printf("[DNA_FEED] Fetching comments for post %s...\n", post_id);

    /* Fetch all multi-owner values */
    uint8_t **values = NULL;
    size_t *value_lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)comments_key, strlen(comments_key),
                          &values, &value_lens, &value_count);

    if (ret != 0 || value_count == 0) {
        *comments_out = NULL;
        *count_out = 0;
        return (ret == 0) ? -2 : -1;
    }

    printf("[DNA_FEED] Found %zu comment values\n", value_count);

    /* Parse comments */
    dna_feed_comment_t *comments = calloc(value_count, sizeof(dna_feed_comment_t));
    if (!comments) {
        for (size_t i = 0; i < value_count; i++) free(values[i]);
        free(values);
        free(value_lens);
        return -1;
    }

    size_t parsed = 0;
    for (size_t i = 0; i < value_count; i++) {
        if (values[i] && value_lens[i] > 0) {
            char *json_str = malloc(value_lens[i] + 1);
            if (json_str) {
                memcpy(json_str, values[i], value_lens[i]);
                json_str[value_lens[i]] = '\0';

                if (comment_from_json(json_str, &comments[parsed]) == 0) {
                    parsed++;
                }
                free(json_str);
            }
        }
        free(values[i]);
    }
    free(values);
    free(value_lens);

    if (parsed == 0) {
        free(comments);
        *comments_out = NULL;
        *count_out = 0;
        return -2;
    }

    /* Resize if needed */
    if (parsed < value_count) {
        dna_feed_comment_t *resized = realloc(comments, parsed * sizeof(dna_feed_comment_t));
        if (resized) comments = resized;
    }

    printf("[DNA_FEED] Parsed %zu comments\n", parsed);

    *comments_out = comments;
    *count_out = parsed;
    return 0;
}

/* ============================================================================
 * Full Post with Comments
 * ========================================================================== */

int dna_feed_post_get_full(dht_context_t *dht_ctx,
                           const char *post_id,
                           dna_feed_post_with_comments_t **result_out) {
    if (!dht_ctx || !post_id || !result_out) return -1;

    /* Fetch the post */
    dna_feed_post_t *post = NULL;
    int ret = dna_feed_post_get(dht_ctx, post_id, &post);
    if (ret != 0) {
        return ret;
    }

    /* Create result structure */
    dna_feed_post_with_comments_t *result = calloc(1, sizeof(dna_feed_post_with_comments_t));
    if (!result) {
        dna_feed_post_free(post);
        return -1;
    }

    /* Copy post */
    result->post = *post;
    free(post);

    /* Fetch comments */
    ret = dna_feed_comments_get(dht_ctx, post_id, &result->comments, &result->comment_count);
    if (ret == -2) {
        /* No comments is OK */
        result->comments = NULL;
        result->comment_count = 0;
    } else if (ret != 0) {
        /* Error fetching comments - still return post */
        result->comments = NULL;
        result->comment_count = 0;
    }
    result->allocated_count = result->comment_count;

    *result_out = result;
    return 0;
}

/* ============================================================================
 * Comment Voting
 * ========================================================================== */

int dna_feed_comment_vote_cast(dht_context_t *dht_ctx,
                               const char *comment_id,
                               const char *voter_fingerprint,
                               int8_t vote_value,
                               const uint8_t *private_key) {
    if (!dht_ctx || !comment_id || !voter_fingerprint || !private_key) return -1;
    if (vote_value != 1 && vote_value != -1) return -1;

    /* Check if already voted - reuse post vote check logic */
    char votes_key[512];
    snprintf(votes_key, sizeof(votes_key), "dna:feed:comment:%s:votes", comment_id);

    /* Fetch existing votes */
    uint8_t **values = NULL;
    size_t *value_lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)votes_key, strlen(votes_key),
                          &values, &value_lens, &value_count);

    if (ret == 0 && value_count > 0) {
        /* Check if user already voted */
        for (size_t i = 0; i < value_count; i++) {
            if (values[i] && value_lens[i] > 0) {
                char *json_str = malloc(value_lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, values[i], value_lens[i]);
                    json_str[value_lens[i]] = '\0';

                    json_object *root = json_tokener_parse(json_str);
                    if (root) {
                        json_object *j_voter;
                        if (json_object_object_get_ex(root, "voter", &j_voter)) {
                            const char *voter = json_object_get_string(j_voter);
                            if (voter && strcmp(voter, voter_fingerprint) == 0) {
                                json_object_put(root);
                                free(json_str);
                                for (size_t j = 0; j < value_count; j++) free(values[j]);
                                free(values);
                                free(value_lens);
                                return -2;  /* Already voted */
                            }
                        }
                        json_object_put(root);
                    }
                    free(json_str);
                }
            }
            free(values[i]);
        }
        free(values);
        free(value_lens);
    }

    /* Create vote JSON */
    json_object *vote_obj = json_object_new_object();
    if (!vote_obj) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    json_object_object_add(vote_obj, "voter", json_object_new_string(voter_fingerprint));
    json_object_object_add(vote_obj, "value", json_object_new_int(vote_value));
    json_object_object_add(vote_obj, "timestamp", json_object_new_int64(timestamp));

    /* Sign vote: comment_id || vote_value || timestamp */
    size_t comment_id_len = strlen(comment_id);
    size_t sign_data_len = comment_id_len + sizeof(int8_t) + sizeof(uint64_t);
    uint8_t *sign_data = malloc(sign_data_len);
    if (!sign_data) {
        json_object_put(vote_obj);
        return -1;
    }

    memcpy(sign_data, comment_id, comment_id_len);
    sign_data[comment_id_len] = (uint8_t)vote_value;
    uint64_t ts_net = htonll_comment(timestamp);
    memcpy(sign_data + comment_id_len + 1, &ts_net, sizeof(uint64_t));

    uint8_t signature[4627];
    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(signature, &sig_len,
                                               sign_data, sign_data_len,
                                               NULL, 0, private_key);
    free(sign_data);

    if (ret != 0) {
        json_object_put(vote_obj);
        return -1;
    }

    /* Add signature to vote */
    char *sig_b64 = base64_encode_comment(signature, sig_len);
    if (sig_b64) {
        json_object_object_add(vote_obj, "signature", json_object_new_string(sig_b64));
        free(sig_b64);
    }

    const char *vote_json = json_object_to_json_string_ext(vote_obj, JSON_C_TO_STRING_PLAIN);
    char *vote_str = strdup(vote_json);
    json_object_put(vote_obj);

    if (!vote_str) return -1;

    /* Get unique value_id */
    uint64_t value_id = 1;
    dht_get_owner_value_id(dht_ctx, &value_id);

    /* Publish vote */
    ret = dht_put_signed(dht_ctx, (const uint8_t *)votes_key, strlen(votes_key),
                         (const uint8_t *)vote_str, strlen(vote_str),
                         value_id, DNA_FEED_TTL_SECONDS);
    free(vote_str);

    return (ret == 0) ? 0 : -1;
}

int dna_feed_comment_votes_get(dht_context_t *dht_ctx,
                               const char *comment_id,
                               dna_feed_votes_t **votes_out) {
    if (!dht_ctx || !comment_id || !votes_out) return -1;

    char votes_key[512];
    snprintf(votes_key, sizeof(votes_key), "dna:feed:comment:%s:votes", comment_id);

    /* Fetch all vote values */
    uint8_t **values = NULL;
    size_t *value_lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)votes_key, strlen(votes_key),
                          &values, &value_lens, &value_count);

    if (ret != 0 || value_count == 0) {
        *votes_out = NULL;
        return (ret == 0) ? -2 : -1;
    }

    /* Create votes structure */
    dna_feed_votes_t *votes = calloc(1, sizeof(dna_feed_votes_t));
    if (!votes) {
        for (size_t i = 0; i < value_count; i++) free(values[i]);
        free(values);
        free(value_lens);
        return -1;
    }

    strncpy(votes->post_id, comment_id, sizeof(votes->post_id) - 1);  /* Reusing post_id field */
    votes->votes = calloc(value_count, sizeof(dna_feed_vote_t));
    if (!votes->votes) {
        free(votes);
        for (size_t i = 0; i < value_count; i++) free(values[i]);
        free(values);
        free(value_lens);
        return -1;
    }

    /* Parse votes */
    for (size_t i = 0; i < value_count; i++) {
        if (values[i] && value_lens[i] > 0) {
            char *json_str = malloc(value_lens[i] + 1);
            if (json_str) {
                memcpy(json_str, values[i], value_lens[i]);
                json_str[value_lens[i]] = '\0';

                json_object *root = json_tokener_parse(json_str);
                if (root) {
                    dna_feed_vote_t *vote = &votes->votes[votes->vote_count];
                    json_object *j_val;

                    if (json_object_object_get_ex(root, "voter", &j_val))
                        strncpy(vote->voter_fingerprint, json_object_get_string(j_val),
                                sizeof(vote->voter_fingerprint) - 1);
                    if (json_object_object_get_ex(root, "value", &j_val))
                        vote->vote_value = json_object_get_int(j_val);
                    if (json_object_object_get_ex(root, "timestamp", &j_val))
                        vote->timestamp = json_object_get_int64(j_val);

                    if (vote->vote_value == 1) votes->upvote_count++;
                    else if (vote->vote_value == -1) votes->downvote_count++;

                    votes->vote_count++;
                    json_object_put(root);
                }
                free(json_str);
            }
        }
        free(values[i]);
    }
    free(values);
    free(value_lens);

    votes->allocated_count = value_count;
    *votes_out = votes;
    return 0;
}
