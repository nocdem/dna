/*
 * DNA Message Wall - Public Message Board via DHT
 */

#include "dna_message_wall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

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

// Base64 encoding/decoding helpers
static char *base64_encode(const uint8_t *data, size_t len);
static uint8_t *base64_decode(const char *str, size_t *out_len);

/**
 * Get DHT key for user's message wall
 * Key format: SHA256(fingerprint + ":message_wall")
 */
int dna_message_wall_get_dht_key(const char *fingerprint, char *key_out) {
    if (!fingerprint || !key_out) {
        return -1;
    }

    // Construct string: fingerprint + ":message_wall"
    char input[256] = {0};
    snprintf(input, sizeof(input), "%s:message_wall", fingerprint);

    // SHA256 hash
    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, strlen(input)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[64] = '\0';

    return 0;
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
 * Base64 encode helper
 */
static char *base64_encode(const uint8_t *data, size_t len) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) {
        return NULL;
    }

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

    // Padding
    size_t padding = len % 3;
    if (padding == 1) {
        out[j - 2] = '=';
        out[j - 1] = '=';
    } else if (padding == 2) {
        out[j - 1] = '=';
    }

    out[j] = '\0';
    return out;
}

/**
 * Base64 decode helper
 */
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
        if (str[len - 2] == '=') {
            padding++;
        }
    }

    *out_len = (len / 4) * 3 - padding;
    uint8_t *out = malloc(*out_len);
    if (!out) {
        return NULL;
    }

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

        // Text
        json_object_object_add(msg_obj, "text",
                               json_object_new_string(wall->messages[i].text));

        // Timestamp
        json_object_object_add(msg_obj, "timestamp",
                               json_object_new_int64(wall->messages[i].timestamp));

        // Signature (base64)
        char *sig_b64 = base64_encode(wall->messages[i].signature,
                                      wall->messages[i].signature_len);
        if (sig_b64) {
            json_object_object_add(msg_obj, "signature",
                                   json_object_new_string(sig_b64));
            free(sig_b64);
        }

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
                uint8_t *sig_bytes = base64_decode(sig_b64, &sig_len);
                if (sig_bytes && sig_len <= sizeof(wall->messages[i].signature)) {
                    memcpy(wall->messages[i].signature, sig_bytes, sig_len);
                    wall->messages[i].signature_len = sig_len;
                }
                free(sig_bytes);
            }
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
 * Load user's public message wall from DHT
 */
int dna_load_wall(dht_context_t *dht_ctx,
                  const char *fingerprint,
                  dna_message_wall_t **wall_out) {
    if (!dht_ctx || !fingerprint || !wall_out) {
        return -1;
    }

    // Get DHT key
    char dht_key[65] = {0};
    if (dna_message_wall_get_dht_key(fingerprint, dht_key) != 0) {
        return -1;
    }

    // Query DHT - fetch ALL versions (DHT is append-only)
    printf("[DNA_WALL] → DHT GET: Loading message wall for user\n");
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                          &values, &values_len, &value_count);
    if (ret != 0 || value_count == 0) {
        return -2;  // Not found
    }

    printf("[DNA_WALL] Found %zu wall version(s) in DHT\n", value_count);

    // Parse all versions and find the one with newest message
    dna_message_wall_t *best_wall = NULL;
    uint64_t best_timestamp = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || values_len[i] == 0) {
            continue;
        }

        // Parse JSON
        dna_message_wall_t *wall = NULL;
        if (dna_message_wall_from_json((const char *)values[i], &wall) != 0) {
            printf("[DNA_WALL] ⚠ Version %zu/%zu: JSON parse failed\n", i+1, value_count);
            continue;
        }

        // Get timestamp of newest message (messages[0] is newest)
        uint64_t wall_timestamp = 0;
        if (wall->message_count > 0) {
            wall_timestamp = wall->messages[0].timestamp;
        }

        printf("[DNA_WALL] Version %zu/%zu: %zu messages, newest=%lu\n",
               i+1, value_count, wall->message_count, wall_timestamp);

        // Keep the wall with the newest message
        if (wall_timestamp > best_timestamp) {
            if (best_wall) {
                dna_message_wall_free(best_wall);
            }
            best_wall = wall;
            best_timestamp = wall_timestamp;
        } else {
            dna_message_wall_free(wall);
        }
    }

    // Free DHT data
    for (size_t i = 0; i < value_count; i++) {
        free(values[i]);
    }
    free(values);
    free(values_len);

    if (!best_wall) {
        fprintf(stderr, "[DNA_WALL] No valid wall found\n");
        return -2;
    }

    printf("[DNA_WALL] ✓ Loaded newest wall version (%zu messages, timestamp=%lu)\n",
           best_wall->message_count, best_timestamp);

    *wall_out = best_wall;
    return 0;
}

/**
 * Post a message to user's public message wall
 */
int dna_post_to_wall(dht_context_t *dht_ctx,
                     const char *fingerprint,
                     const char *message_text,
                     const uint8_t *private_key) {
    if (!dht_ctx || !fingerprint || !message_text || !private_key) {
        return -1;
    }

    // Validate message length
    size_t text_len = strlen(message_text);
    if (text_len == 0 || text_len >= DNA_MESSAGE_WALL_MAX_TEXT_LEN) {
        fprintf(stderr, "[DNA_WALL] Message text invalid (len=%zu)\n", text_len);
        return -1;
    }

    // Load existing wall (or create new)
    dna_message_wall_t *wall = NULL;
    int ret = dna_load_wall(dht_ctx, fingerprint, &wall);
    if (ret == -2) {
        // Wall doesn't exist, create new
        wall = calloc(1, sizeof(dna_message_wall_t));
        if (!wall) {
            return -1;
        }
        strncpy(wall->fingerprint, fingerprint, sizeof(wall->fingerprint) - 1);
        wall->messages = NULL;
        wall->message_count = 0;
        wall->allocated_count = 0;
    } else if (ret != 0) {
        // Error loading
        return -1;
    }

    // Create new message
    dna_wall_message_t new_msg = {0};
    strncpy(new_msg.text, message_text, DNA_MESSAGE_WALL_MAX_TEXT_LEN - 1);
    new_msg.timestamp = (uint64_t)time(NULL);

    // Sign message (text + timestamp)
    uint8_t *sign_data = malloc(text_len + sizeof(uint64_t));
    if (!sign_data) {
        dna_message_wall_free(wall);
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
        fprintf(stderr, "[DNA_WALL] Failed to sign message\n");
        dna_message_wall_free(wall);
        return -1;
    }
    new_msg.signature_len = sig_len;

    // Add message to wall (prepend, newest first)
    printf("[DNA_WALL] Adding message to wall (current: %zu messages)\n", wall->message_count);
    size_t new_count = wall->message_count + 1;
    if (new_count > DNA_MESSAGE_WALL_MAX_MESSAGES) {
        new_count = DNA_MESSAGE_WALL_MAX_MESSAGES;
    }

    dna_wall_message_t *new_messages = calloc(new_count, sizeof(dna_wall_message_t));
    if (!new_messages) {
        dna_message_wall_free(wall);
        return -1;
    }

    // First message is the new one
    new_messages[0] = new_msg;
    printf("[DNA_WALL] New message at index 0: timestamp=%lu, text='%s'\n",
           new_msg.timestamp, new_msg.text);

    // Copy old messages (up to limit - 1)
    size_t copy_count = (wall->message_count < new_count - 1) ?
                        wall->message_count : (new_count - 1);
    printf("[DNA_WALL] Copying %zu old messages\n", copy_count);
    for (size_t i = 0; i < copy_count; i++) {
        new_messages[i + 1] = wall->messages[i];
        printf("[DNA_WALL]   Old message %zu at index %zu: timestamp=%lu, text='%s'\n",
               i, i+1, wall->messages[i].timestamp, wall->messages[i].text);
    }

    // Replace messages array
    free(wall->messages);
    wall->messages = new_messages;
    wall->message_count = new_count;
    wall->allocated_count = new_count;
    printf("[DNA_WALL] Wall now has %zu messages\n", new_count);

    // Serialize to JSON
    char *json_data = NULL;
    ret = dna_message_wall_to_json(wall, &json_data);
    if (ret != 0 || !json_data) {
        fprintf(stderr, "[DNA_WALL] Failed to serialize wall\n");
        dna_message_wall_free(wall);
        return -1;
    }

    // Publish to DHT
    char dht_key[65] = {0};
    if (dna_message_wall_get_dht_key(fingerprint, dht_key) != 0) {
        free(json_data);
        dna_message_wall_free(wall);
        return -1;
    }

    printf("[DNA_WALL] → DHT PUT: Publishing message wall (%zu messages)\n", wall->message_count);
    ret = dht_put(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                  (const uint8_t *)json_data, strlen(json_data));
    free(json_data);

    if (ret != 0) {
        fprintf(stderr, "[DNA_WALL] Failed to publish to DHT\n");
        dna_message_wall_free(wall);
        return -1;
    }

    printf("[DNA_WALL] Successfully posted message to wall (fingerprint=%s)\n",
           fingerprint);

    dna_message_wall_free(wall);
    return 0;
}
