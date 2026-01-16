/*
 * DNA Message Wall - Public Message Board via DHT
 *
 * Storage Model (Option 2 - Owner-Namespaced):
 * - Each poster stores their messages under: wall_owner:wall:poster_fingerprint (chunked)
 * - Contributor index at: wall_owner:wall:contributors (multi-owner, small)
 * - Fetch aggregates all contributors' messages
 */

#include "dna_message_wall.h"
#include "../shared/dht_chunked.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#define LOG_TAG "DNA_WALL"

// Dilithium5 functions (actual exported symbols from dsa library)
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);

// Network byte order helpers (must be declared before use)
static inline uint64_t htonll(uint64_t value) {
    static const int num = 1;
    if (*(char *)&num == 1) {
        // Little-endian
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

static inline uint64_t ntohll(uint64_t value) {
    return htonll(value);
}

/**
 * Make base key for a poster's messages on a wall
 * Format: wall_owner:wall:poster_fingerprint
 */
static void make_poster_base_key(const char *wall_owner, const char *poster,
                                  char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:wall:%s", wall_owner, poster);
}

/**
 * Make key for contributors index (small, multi-owner)
 * Format: wall_owner:wall:contributors
 */
static void make_contributors_key(const char *wall_owner, char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:wall:contributors", wall_owner);
}

/**
 * Free message wall structure
 */
void dna_message_wall_free(dna_message_wall_t *wall) {
    if (!wall) {
        return;
    }

    if (wall->messages) {
        free(wall->messages);
    }

    free(wall);
}

/**
 * Serialize wall to JSON string
 */
int dna_message_wall_to_json(const dna_message_wall_t *wall, char **json_out) {
    if (!wall || !json_out) {
        return -1;
    }

    json_object *root = json_object_new_object();
    if (!root) {
        return -1;
    }

    // Version
    json_object_object_add(root, "version", json_object_new_int(1));

    // Fingerprint
    json_object_object_add(root, "fingerprint",
                           json_object_new_string(wall->fingerprint));

    // Messages array
    json_object *messages_arr = json_object_new_array();
    if (!messages_arr) {
        json_object_put(root);
        return -1;
    }

    for (size_t i = 0; i < wall->message_count; i++) {
        json_object *msg_obj = json_object_new_object();
        if (!msg_obj) {
            continue;
        }

        // Post ID
        json_object_object_add(msg_obj, "post_id",
                               json_object_new_string(wall->messages[i].post_id));

        // Text
        json_object_object_add(msg_obj, "text",
                               json_object_new_string(wall->messages[i].text));

        // Timestamp
        json_object_object_add(msg_obj, "timestamp",
                               json_object_new_int64(wall->messages[i].timestamp));

        // Signature (base64)
        char *sig_b64 = qgp_base64_encode(wall->messages[i].signature,
                                        wall->messages[i].signature_len, NULL);
        if (sig_b64) {
            json_object_object_add(msg_obj, "signature",
                                   json_object_new_string(sig_b64));
            free(sig_b64);
        }

        // Threading fields
        json_object_object_add(msg_obj, "reply_to",
                               json_object_new_string(wall->messages[i].reply_to));
        json_object_object_add(msg_obj, "reply_depth",
                               json_object_new_int(wall->messages[i].reply_depth));
        json_object_object_add(msg_obj, "reply_count",
                               json_object_new_int(wall->messages[i].reply_count));

        json_object_array_add(messages_arr, msg_obj);
    }

    json_object_object_add(root, "messages", messages_arr);

    // Serialize
    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if (!json_str) {
        json_object_put(root);
        return -1;
    }

    *json_out = strdup(json_str);
    json_object_put(root);

    return *json_out ? 0 : -1;
}

/**
 * Parse wall from JSON string
 */
int dna_message_wall_from_json(const char *json_str, dna_message_wall_t **wall_out) {
    if (!json_str || !wall_out) {
        return -1;
    }

    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        return -1;
    }

    // Allocate wall structure
    dna_message_wall_t *wall = calloc(1, sizeof(dna_message_wall_t));
    if (!wall) {
        json_object_put(root);
        return -1;
    }

    // Parse fingerprint
    json_object *j_fingerprint = NULL;
    if (json_object_object_get_ex(root, "fingerprint", &j_fingerprint)) {
        const char *fp = json_object_get_string(j_fingerprint);
        if (fp) {
            strncpy(wall->fingerprint, fp, sizeof(wall->fingerprint) - 1);
        }
    }

    // Parse messages array
    json_object *j_messages = NULL;
    if (!json_object_object_get_ex(root, "messages", &j_messages)) {
        json_object_put(root);
        free(wall);
        return -1;
    }

    size_t msg_count = json_object_array_length(j_messages);
    if (msg_count == 0) {
        wall->messages = NULL;
        wall->message_count = 0;
        wall->allocated_count = 0;
        *wall_out = wall;
        json_object_put(root);
        return 0;
    }

    // Allocate messages array
    wall->messages = calloc(msg_count, sizeof(dna_wall_message_t));
    if (!wall->messages) {
        json_object_put(root);
        free(wall);
        return -1;
    }
    wall->allocated_count = msg_count;

    // Parse each message
    for (size_t i = 0; i < msg_count; i++) {
        json_object *msg_obj = json_object_array_get_idx(j_messages, i);
        if (!msg_obj) {
            continue;
        }

        // Text
        json_object *j_text = NULL;
        if (json_object_object_get_ex(msg_obj, "text", &j_text)) {
            const char *text = json_object_get_string(j_text);
            if (text) {
                strncpy(wall->messages[i].text, text,
                        DNA_MESSAGE_WALL_MAX_TEXT_LEN - 1);
            }
        }

        // Timestamp
        json_object *j_timestamp = NULL;
        if (json_object_object_get_ex(msg_obj, "timestamp", &j_timestamp)) {
            wall->messages[i].timestamp = json_object_get_int64(j_timestamp);
        }

        // Signature (base64)
        json_object *j_signature = NULL;
        if (json_object_object_get_ex(msg_obj, "signature", &j_signature)) {
            const char *sig_b64 = json_object_get_string(j_signature);
            if (sig_b64) {
                size_t sig_len = 0;
                uint8_t *sig_bytes = qgp_base64_decode(sig_b64, &sig_len);
                if (sig_bytes && sig_len <= sizeof(wall->messages[i].signature)) {
                    memcpy(wall->messages[i].signature, sig_bytes, sig_len);
                    wall->messages[i].signature_len = sig_len;
                }
                free(sig_bytes);
            }
        }

        // Threading fields (backward compatible: use defaults if missing)
        json_object *j_post_id = NULL;
        if (json_object_object_get_ex(msg_obj, "post_id", &j_post_id)) {
            const char *post_id = json_object_get_string(j_post_id);
            if (post_id) {
                strncpy(wall->messages[i].post_id, post_id, sizeof(wall->messages[i].post_id) - 1);
            }
        } else {
            // Backward compatibility: generate post_id from fingerprint + timestamp
            dna_wall_make_post_id(wall->fingerprint, wall->messages[i].timestamp, wall->messages[i].post_id);
        }

        json_object *j_reply_to = NULL;
        if (json_object_object_get_ex(msg_obj, "reply_to", &j_reply_to)) {
            const char *reply_to = json_object_get_string(j_reply_to);
            if (reply_to) {
                strncpy(wall->messages[i].reply_to, reply_to, sizeof(wall->messages[i].reply_to) - 1);
            }
        }

        json_object *j_reply_depth = NULL;
        if (json_object_object_get_ex(msg_obj, "reply_depth", &j_reply_depth)) {
            wall->messages[i].reply_depth = json_object_get_int(j_reply_depth);
        }

        json_object *j_reply_count = NULL;
        if (json_object_object_get_ex(msg_obj, "reply_count", &j_reply_count)) {
            wall->messages[i].reply_count = json_object_get_int(j_reply_count);
        }

        wall->message_count++;
    }

    json_object_put(root);
    *wall_out = wall;
    return 0;
}

/**
 * Verify message signature
 */
int dna_message_wall_verify_signature(const dna_wall_message_t *message,
                                       const uint8_t *public_key) {
    if (!message || !public_key || message->signature_len == 0) {
        return -1;
    }

    // Build signed data: message_text || timestamp (network byte order)
    size_t text_len = strlen(message->text);
    size_t data_len = text_len + sizeof(uint64_t);
    uint8_t *data = malloc(data_len);
    if (!data) {
        return -1;
    }

    memcpy(data, message->text, text_len);
    uint64_t ts_net = htonll(message->timestamp);
    memcpy(data + text_len, &ts_net, sizeof(uint64_t));

    // Verify signature (no context)
    int ret = pqcrystals_dilithium5_ref_verify(message->signature, message->signature_len,
                                                data, data_len, NULL, 0, public_key);

    free(data);
    return (ret == 0) ? 0 : -1;
}

/**
 * Load user's public message wall from DHT (Owner-Namespaced)
 *
 * Storage model:
 * - Each poster's messages stored at: wall_owner:wall:poster_fingerprint (chunked)
 * - Contributors index at: wall_owner:wall:contributors (multi-owner, small)
 */
int dna_load_wall(dht_context_t *dht_ctx,
                  const char *fingerprint,
                  dna_message_wall_t **wall_out) {
    if (!dht_ctx || !fingerprint || !wall_out) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Loading wall for %.16s... (owner-namespaced)\n", fingerprint);

    // Step 1: Get contributors index (multi-owner, small fingerprint list)
    char contrib_key[512];
    make_contributors_key(fingerprint, contrib_key, sizeof(contrib_key));

    uint8_t **contrib_values = NULL;
    size_t *contrib_lens = NULL;
    size_t contrib_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)contrib_key, strlen(contrib_key),
                          &contrib_values, &contrib_lens, &contrib_count);

    // Collect unique contributor fingerprints
    char **contributors = NULL;
    size_t num_contributors = 0;

    if (ret == 0 && contrib_count > 0) {
        // Parse each contributor entry (simple fingerprint string)
        contributors = calloc(contrib_count, sizeof(char *));
        if (contributors) {
            for (size_t i = 0; i < contrib_count; i++) {
                if (contrib_values[i] && contrib_lens[i] > 0 && contrib_lens[i] < 256) {
                    // Check if this fingerprint is already in list (dedup)
                    char *fp = malloc(contrib_lens[i] + 1);
                    if (fp) {
                        memcpy(fp, contrib_values[i], contrib_lens[i]);
                        fp[contrib_lens[i]] = '\0';

                        bool duplicate = false;
                        for (size_t j = 0; j < num_contributors; j++) {
                            if (strcmp(contributors[j], fp) == 0) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            contributors[num_contributors++] = fp;
                        } else {
                            free(fp);
                        }
                    }
                }
                free(contrib_values[i]);
            }
        }
        free(contrib_values);
        free(contrib_lens);
    }

    QGP_LOG_INFO(LOG_TAG, "Found %zu unique contributors\n", num_contributors);

    // Step 2: Create merged wall
    dna_message_wall_t *merged_wall = calloc(1, sizeof(dna_message_wall_t));
    if (!merged_wall) {
        for (size_t i = 0; i < num_contributors; i++) free(contributors[i]);
        free(contributors);
        return -1;
    }
    strncpy(merged_wall->fingerprint, fingerprint, sizeof(merged_wall->fingerprint) - 1);

    // Pre-allocate messages array
    size_t msg_capacity = 64;
    merged_wall->messages = calloc(msg_capacity, sizeof(dna_wall_message_t));
    if (!merged_wall->messages) {
        free(merged_wall);
        for (size_t i = 0; i < num_contributors; i++) free(contributors[i]);
        free(contributors);
        return -1;
    }
    merged_wall->allocated_count = msg_capacity;

    // Step 3: Fetch each contributor's messages via chunked
    for (size_t c = 0; c < num_contributors; c++) {
        char poster_key[512];
        make_poster_base_key(fingerprint, contributors[c], poster_key, sizeof(poster_key));

        uint8_t *data = NULL;
        size_t data_len = 0;

        ret = dht_chunked_fetch(dht_ctx, poster_key, &data, &data_len);
        if (ret != DHT_CHUNK_OK || !data) {
            QGP_LOG_INFO(LOG_TAG, "Contributor %.16s...: no data\n", contributors[c]);
            continue;
        }

        // Parse contributor's wall
        char *json_str = malloc(data_len + 1);
        if (!json_str) {
            free(data);
            continue;
        }
        memcpy(json_str, data, data_len);
        json_str[data_len] = '\0';
        free(data);

        dna_message_wall_t *contrib_wall = NULL;
        if (dna_message_wall_from_json(json_str, &contrib_wall) != 0) {
            QGP_LOG_INFO(LOG_TAG, "Contributor %.16s...: parse failed\n", contributors[c]);
            free(json_str);
            continue;
        }
        free(json_str);

        QGP_LOG_INFO(LOG_TAG, "Contributor %.16s...: %zu messages\n",
               contributors[c], contrib_wall->message_count);

        // Merge messages into main wall
        for (size_t m = 0; m < contrib_wall->message_count; m++) {
            // Grow array if needed
            if (merged_wall->message_count >= merged_wall->allocated_count) {
                size_t new_cap = merged_wall->allocated_count * 2;
                dna_wall_message_t *new_msgs = realloc(merged_wall->messages,
                                                        new_cap * sizeof(dna_wall_message_t));
                if (!new_msgs) break;
                merged_wall->messages = new_msgs;
                merged_wall->allocated_count = new_cap;
            }

            merged_wall->messages[merged_wall->message_count++] = contrib_wall->messages[m];
        }

        dna_message_wall_free(contrib_wall);
    }

    // Free contributors list
    for (size_t i = 0; i < num_contributors; i++) free(contributors[i]);
    free(contributors);

    // Step 4: Sort messages by timestamp (newest first)
    if (merged_wall->message_count > 1) {
        for (size_t i = 0; i < merged_wall->message_count - 1; i++) {
            for (size_t j = i + 1; j < merged_wall->message_count; j++) {
                if (merged_wall->messages[j].timestamp > merged_wall->messages[i].timestamp) {
                    dna_wall_message_t tmp = merged_wall->messages[i];
                    merged_wall->messages[i] = merged_wall->messages[j];
                    merged_wall->messages[j] = tmp;
                }
            }
        }
    }

    // Update reply counts
    dna_wall_update_reply_counts(merged_wall);

    if (merged_wall->message_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "Wall is empty\n");
        dna_message_wall_free(merged_wall);
        return -2;  // Not found
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Loaded wall: %zu messages from %zu contributors\n",
           merged_wall->message_count, num_contributors);

    *wall_out = merged_wall;
    return 0;
}

/**
 * Post a message to user's public message wall (Owner-Namespaced)
 *
 * Storage model:
 * - Poster's messages stored at: wall_owner:wall:poster_fingerprint (chunked)
 * - Contributors index at: wall_owner:wall:contributors (multi-owner, small)
 */
int dna_post_to_wall(dht_context_t *dht_ctx,
                     const char *wall_owner_fingerprint,
                     const char *poster_fingerprint,
                     const char *message_text,
                     const uint8_t *private_key,
                     const char *reply_to) {
    if (!dht_ctx || !wall_owner_fingerprint || !poster_fingerprint || !message_text || !private_key) {
        return -1;
    }

    // Validate message length
    size_t text_len = strlen(message_text);
    if (text_len == 0 || text_len >= DNA_MESSAGE_WALL_MAX_TEXT_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "Message text invalid (len=%zu)\n", text_len);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Posting to wall %.16s... as poster %.16s...\n",
           wall_owner_fingerprint, poster_fingerprint);

    // Step 1: Load poster's OWN existing messages for this wall (not entire wall)
    char poster_key[512];
    make_poster_base_key(wall_owner_fingerprint, poster_fingerprint, poster_key, sizeof(poster_key));

    dna_message_wall_t *poster_wall = NULL;
    uint8_t *existing_data = NULL;
    size_t existing_len = 0;

    int ret = dht_chunked_fetch(dht_ctx, poster_key, &existing_data, &existing_len);
    if (ret == DHT_CHUNK_OK && existing_data) {
        // Parse existing messages
        char *json_str = malloc(existing_len + 1);
        if (json_str) {
            memcpy(json_str, existing_data, existing_len);
            json_str[existing_len] = '\0';
            dna_message_wall_from_json(json_str, &poster_wall);
            free(json_str);
        }
        free(existing_data);
    }

    // Create poster wall if doesn't exist
    if (!poster_wall) {
        poster_wall = calloc(1, sizeof(dna_message_wall_t));
        if (!poster_wall) {
            return -1;
        }
        strncpy(poster_wall->fingerprint, wall_owner_fingerprint, sizeof(poster_wall->fingerprint) - 1);
    }

    QGP_LOG_INFO(LOG_TAG, "Poster has %zu existing messages on this wall\n", poster_wall->message_count);

    // Step 2: Handle reply depth (need to load full wall to find parent)
    int reply_depth = 0;
    if (reply_to && reply_to[0] != '\0') {
        // Load full wall to find parent message depth
        dna_message_wall_t *full_wall = NULL;
        if (dna_load_wall(dht_ctx, wall_owner_fingerprint, &full_wall) == 0 && full_wall) {
            for (size_t i = 0; i < full_wall->message_count; i++) {
                if (strcmp(full_wall->messages[i].post_id, reply_to) == 0) {
                    reply_depth = full_wall->messages[i].reply_depth + 1;
                    break;
                }
            }
            dna_message_wall_free(full_wall);
        }
        if (reply_depth > 2) {
            QGP_LOG_ERROR(LOG_TAG, "Max thread depth exceeded (max 3 levels)\n");
            dna_message_wall_free(poster_wall);
            return -2;
        }
    }

    // Step 3: Create new message
    dna_wall_message_t new_msg = {0};
    strncpy(new_msg.text, message_text, DNA_MESSAGE_WALL_MAX_TEXT_LEN - 1);
    new_msg.timestamp = (uint64_t)time(NULL);
    dna_wall_make_post_id(poster_fingerprint, new_msg.timestamp, new_msg.post_id);
    new_msg.reply_depth = reply_depth;
    new_msg.reply_count = 0;
    if (reply_to && reply_to[0] != '\0') {
        strncpy(new_msg.reply_to, reply_to, sizeof(new_msg.reply_to) - 1);
    }

    // Sign message (text + timestamp)
    uint8_t *sign_data = malloc(text_len + sizeof(uint64_t));
    if (!sign_data) {
        dna_message_wall_free(poster_wall);
        return -1;
    }

    memcpy(sign_data, message_text, text_len);
    uint64_t ts_net = htonll(new_msg.timestamp);
    memcpy(sign_data + text_len, &ts_net, sizeof(uint64_t));

    size_t sig_len = 0;
    ret = pqcrystals_dilithium5_ref_signature(new_msg.signature, &sig_len,
                                               sign_data, text_len + sizeof(uint64_t),
                                               NULL, 0, private_key);
    free(sign_data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign message\n");
        dna_message_wall_free(poster_wall);
        return -1;
    }
    new_msg.signature_len = sig_len;

    // Step 4: Add message to poster's wall (prepend, newest first)
    size_t new_count = poster_wall->message_count + 1;
    if (new_count > DNA_MESSAGE_WALL_MAX_MESSAGES) {
        new_count = DNA_MESSAGE_WALL_MAX_MESSAGES;
    }

    dna_wall_message_t *new_messages = calloc(new_count, sizeof(dna_wall_message_t));
    if (!new_messages) {
        dna_message_wall_free(poster_wall);
        return -1;
    }

    new_messages[0] = new_msg;
    size_t copy_count = (poster_wall->message_count < new_count - 1) ?
                        poster_wall->message_count : (new_count - 1);
    for (size_t i = 0; i < copy_count; i++) {
        new_messages[i + 1] = poster_wall->messages[i];
    }

    free(poster_wall->messages);
    poster_wall->messages = new_messages;
    poster_wall->message_count = new_count;
    poster_wall->allocated_count = new_count;

    // Step 5: Serialize and publish poster's messages via chunked
    char *json_data = NULL;
    ret = dna_message_wall_to_json(poster_wall, &json_data);
    if (ret != 0 || !json_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize wall\n");
        dna_message_wall_free(poster_wall);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing poster's %zu messages via chunked\n", poster_wall->message_count);
    ret = dht_chunked_publish(dht_ctx, poster_key,
                               (uint8_t*)json_data, strlen(json_data),
                               DHT_CHUNK_TTL_30DAY);
    free(json_data);
    dna_message_wall_free(poster_wall);

    if (ret != DHT_CHUNK_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish poster data: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    // Step 6: Register poster in contributors index (multi-owner, small)
    char contrib_key[512];
    make_contributors_key(wall_owner_fingerprint, contrib_key, sizeof(contrib_key));

    QGP_LOG_INFO(LOG_TAG, "Registering contributor in index\n");
    ret = dht_put_signed(dht_ctx, (const uint8_t *)contrib_key, strlen(contrib_key),
                         (const uint8_t *)poster_fingerprint, strlen(poster_fingerprint),
                         1, DHT_CHUNK_TTL_30DAY, "wall_contributor");

    if (ret != 0) {
        // Non-fatal - poster data is already stored
        QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to register in contributors index\n");
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Posted message (wall=%.16s..., poster=%.16s...)\n",
           wall_owner_fingerprint, poster_fingerprint);
    return 0;
}

/**
 * Generate post_id from fingerprint and timestamp
 */
int dna_wall_make_post_id(const char *fingerprint, uint64_t timestamp, char *post_id_out) {
    if (!fingerprint || !post_id_out) {
        return -1;
    }

    snprintf(post_id_out, 160, "%s_%lu", fingerprint, (unsigned long)timestamp);
    return 0;
}

/**
 * Update reply counts for all messages
 */
int dna_wall_update_reply_counts(dna_message_wall_t *wall) {
    if (!wall || !wall->messages) {
        return -1;
    }

    // Reset all reply counts
    for (size_t i = 0; i < wall->message_count; i++) {
        wall->messages[i].reply_count = 0;
    }

    // Count direct replies for each message
    for (size_t i = 0; i < wall->message_count; i++) {
        if (wall->messages[i].reply_to[0] != '\0') {
            // This message is a reply - find parent and increment its count
            for (size_t j = 0; j < wall->message_count; j++) {
                if (strcmp(wall->messages[j].post_id, wall->messages[i].reply_to) == 0) {
                    wall->messages[j].reply_count++;
                    break;
                }
            }
        }
    }

    return 0;
}

/**
 * Get all direct replies to a post
 */
int dna_wall_get_replies(const dna_message_wall_t *wall,
                         const char *post_id,
                         dna_wall_message_t ***replies_out,
                         size_t *count_out) {
    if (!wall || !post_id || !replies_out || !count_out) {
        return -1;
    }

    // First pass: count replies
    size_t reply_count = 0;
    for (size_t i = 0; i < wall->message_count; i++) {
        if (strcmp(wall->messages[i].reply_to, post_id) == 0) {
            reply_count++;
        }
    }

    if (reply_count == 0) {
        *replies_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array of pointers
    dna_wall_message_t **replies = malloc(reply_count * sizeof(dna_wall_message_t *));
    if (!replies) {
        return -1;
    }

    // Second pass: collect replies
    size_t idx = 0;
    for (size_t i = 0; i < wall->message_count; i++) {
        if (strcmp(wall->messages[i].reply_to, post_id) == 0) {
            replies[idx++] = &wall->messages[i];
        }
    }

    *replies_out = replies;
    *count_out = reply_count;
    return 0;
}

/**
 * Get full conversation thread for a post (recursive helper)
 */
static void collect_thread_recursive(const dna_message_wall_t *wall,
                                      const char *post_id,
                                      dna_wall_message_t ***thread,
                                      size_t *count,
                                      size_t *capacity) {
    // Find message with this post_id
    for (size_t i = 0; i < wall->message_count; i++) {
        if (strcmp(wall->messages[i].post_id, post_id) == 0) {
            // Add this message to thread
            if (*count >= *capacity) {
                *capacity = (*capacity == 0) ? 10 : (*capacity * 2);
                *thread = realloc(*thread, *capacity * sizeof(dna_wall_message_t *));
            }
            (*thread)[(*count)++] = &wall->messages[i];

            // Recursively collect replies
            dna_wall_message_t **replies = NULL;
            size_t reply_count = 0;
            if (dna_wall_get_replies(wall, post_id, &replies, &reply_count) == 0 && replies) {
                for (size_t j = 0; j < reply_count; j++) {
                    collect_thread_recursive(wall, replies[j]->post_id, thread, count, capacity);
                }
                free(replies);
            }
            break;
        }
    }
}

/**
 * Get full conversation thread for a post
 */
int dna_wall_get_thread(const dna_message_wall_t *wall,
                        const char *post_id,
                        dna_wall_message_t ***thread_out,
                        size_t *count_out) {
    if (!wall || !post_id || !thread_out || !count_out) {
        return -1;
    }

    dna_wall_message_t **thread = NULL;
    size_t count = 0;
    size_t capacity = 0;

    collect_thread_recursive(wall, post_id, &thread, &count, &capacity);

    *thread_out = thread;
    *count_out = count;
    return 0;
}
