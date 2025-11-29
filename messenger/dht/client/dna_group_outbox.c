/**
 * @file dna_group_outbox.c
 * @brief Group Message Outbox Implementation
 *
 * Feed-pattern group messaging with owner-namespaced storage.
 *
 * Part of DNA Messenger
 *
 * @date 2025-11-29
 */

#include "dna_group_outbox.h"
#include "../../messenger/gsk.h"
#include "../../message_backup.h"
#include "../../crypto/utils/qgp_aes.h"
#include "../../crypto/utils/qgp_dilithium.h"
#include "../core/dht_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <sqlite3.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/* External DHT functions */
extern int dht_put_signed(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                          const uint8_t *value, size_t value_len,
                          uint64_t value_id, uint32_t ttl);
extern int dht_get_all(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                       uint8_t ***values_out, size_t **lens_out, size_t *count_out);
extern int dht_get_owner_value_id(dht_context_t *ctx, uint64_t *value_id_out);

/* Dilithium5 signing functions */
extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
                                                const uint8_t *m, size_t mlen,
                                                const uint8_t *ctx, size_t ctxlen,
                                                const uint8_t *sk);
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *ctx, size_t ctxlen,
                                             const uint8_t *pk);

/* Database handle (set during init) */
static sqlite3 *group_outbox_db = NULL;

/* Network byte order helper for 64-bit */
static inline uint64_t htonll_outbox(uint64_t value) {
    static const int num = 1;
    if (*(char *)&num == 1) {
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

/*============================================================================
 * Base64 Encoding/Decoding
 *============================================================================*/

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

/*============================================================================
 * Utility Functions
 *============================================================================*/

uint64_t dna_group_outbox_get_hour_bucket(void) {
    return (uint64_t)time(NULL) / 3600;
}

int dna_group_outbox_make_key(
    const char *group_uuid,
    uint64_t hour_bucket,
    char *key_out,
    size_t key_out_size
) {
    if (!group_uuid || !key_out || key_out_size < 64) {
        return -1;
    }

    snprintf(key_out, key_out_size, "dna:group:%s:out:%lu", group_uuid, (unsigned long)hour_bucket);
    return 0;
}

int dna_group_outbox_make_message_id(
    const char *sender_fingerprint,
    const char *group_uuid,
    uint64_t timestamp_ms,
    char *message_id_out
) {
    if (!sender_fingerprint || !group_uuid || !message_id_out) {
        return -1;
    }

    snprintf(message_id_out, DNA_GROUP_MSG_ID_SIZE, "%s_%s_%lu",
             sender_fingerprint, group_uuid, (unsigned long)timestamp_ms);
    return 0;
}

const char *dna_group_outbox_strerror(int error) {
    switch (error) {
        case DNA_GROUP_OUTBOX_OK: return "Success";
        case DNA_GROUP_OUTBOX_ERR_NULL_PARAM: return "NULL parameter";
        case DNA_GROUP_OUTBOX_ERR_NO_GSK: return "No active GSK found";
        case DNA_GROUP_OUTBOX_ERR_ENCRYPT: return "Encryption failed";
        case DNA_GROUP_OUTBOX_ERR_DECRYPT: return "Decryption failed";
        case DNA_GROUP_OUTBOX_ERR_SIGN: return "Signing failed";
        case DNA_GROUP_OUTBOX_ERR_VERIFY: return "Signature verification failed";
        case DNA_GROUP_OUTBOX_ERR_DHT_PUT: return "DHT put failed";
        case DNA_GROUP_OUTBOX_ERR_DHT_GET: return "DHT get failed";
        case DNA_GROUP_OUTBOX_ERR_SERIALIZE: return "Serialization failed";
        case DNA_GROUP_OUTBOX_ERR_DESERIALIZE: return "Deserialization failed";
        case DNA_GROUP_OUTBOX_ERR_ALLOC: return "Memory allocation failed";
        case DNA_GROUP_OUTBOX_ERR_DB: return "Database error";
        case DNA_GROUP_OUTBOX_ERR_DUPLICATE: return "Message already exists";
        default: return "Unknown error";
    }
}

/*============================================================================
 * JSON Serialization
 *============================================================================*/

/**
 * Serialize a single message to JSON
 */
static int message_to_json(const dna_group_message_t *msg, json_object **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "message_id", json_object_new_string(msg->message_id));
    json_object_object_add(root, "sender", json_object_new_string(msg->sender_fingerprint));
    json_object_object_add(root, "group", json_object_new_string(msg->group_uuid));
    json_object_object_add(root, "timestamp_ms", json_object_new_int64(msg->timestamp_ms));
    json_object_object_add(root, "gsk_version", json_object_new_int(msg->gsk_version));

    /* Nonce (base64) */
    char *nonce_b64 = base64_encode(msg->nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);
    if (nonce_b64) {
        json_object_object_add(root, "nonce", json_object_new_string(nonce_b64));
        free(nonce_b64);
    }

    /* Ciphertext (base64) */
    if (msg->ciphertext && msg->ciphertext_len > 0) {
        char *ct_b64 = base64_encode(msg->ciphertext, msg->ciphertext_len);
        if (ct_b64) {
            json_object_object_add(root, "ciphertext", json_object_new_string(ct_b64));
            free(ct_b64);
        }
    }

    /* Tag (base64) */
    char *tag_b64 = base64_encode(msg->tag, DNA_GROUP_OUTBOX_TAG_SIZE);
    if (tag_b64) {
        json_object_object_add(root, "tag", json_object_new_string(tag_b64));
        free(tag_b64);
    }

    /* Signature (base64) */
    if (msg->signature_len > 0) {
        char *sig_b64 = base64_encode(msg->signature, msg->signature_len);
        if (sig_b64) {
            json_object_object_add(root, "signature", json_object_new_string(sig_b64));
            free(sig_b64);
        }
    }

    *json_out = root;
    return 0;
}

/**
 * Deserialize a single message from JSON
 */
static int message_from_json(json_object *root, dna_group_message_t *msg) {
    if (!root || !msg) return -1;

    memset(msg, 0, sizeof(dna_group_message_t));

    json_object *j_val;
    if (json_object_object_get_ex(root, "message_id", &j_val))
        strncpy(msg->message_id, json_object_get_string(j_val), sizeof(msg->message_id) - 1);
    if (json_object_object_get_ex(root, "sender", &j_val))
        strncpy(msg->sender_fingerprint, json_object_get_string(j_val), sizeof(msg->sender_fingerprint) - 1);
    if (json_object_object_get_ex(root, "group", &j_val))
        strncpy(msg->group_uuid, json_object_get_string(j_val), sizeof(msg->group_uuid) - 1);
    if (json_object_object_get_ex(root, "timestamp_ms", &j_val))
        msg->timestamp_ms = json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "gsk_version", &j_val))
        msg->gsk_version = (uint32_t)json_object_get_int(j_val);

    /* Nonce (base64) */
    if (json_object_object_get_ex(root, "nonce", &j_val)) {
        size_t nonce_len = 0;
        uint8_t *nonce = base64_decode(json_object_get_string(j_val), &nonce_len);
        if (nonce && nonce_len == DNA_GROUP_OUTBOX_NONCE_SIZE) {
            memcpy(msg->nonce, nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);
        }
        free(nonce);
    }

    /* Ciphertext (base64) */
    if (json_object_object_get_ex(root, "ciphertext", &j_val)) {
        size_t ct_len = 0;
        uint8_t *ct = base64_decode(json_object_get_string(j_val), &ct_len);
        if (ct && ct_len > 0) {
            msg->ciphertext = ct;
            msg->ciphertext_len = ct_len;
        }
    }

    /* Tag (base64) */
    if (json_object_object_get_ex(root, "tag", &j_val)) {
        size_t tag_len = 0;
        uint8_t *tag = base64_decode(json_object_get_string(j_val), &tag_len);
        if (tag && tag_len == DNA_GROUP_OUTBOX_TAG_SIZE) {
            memcpy(msg->tag, tag, DNA_GROUP_OUTBOX_TAG_SIZE);
        }
        free(tag);
    }

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        size_t sig_len = 0;
        uint8_t *sig = base64_decode(json_object_get_string(j_val), &sig_len);
        if (sig && sig_len <= DNA_GROUP_OUTBOX_SIG_SIZE) {
            memcpy(msg->signature, sig, sig_len);
            msg->signature_len = sig_len;
        }
        free(sig);
    }

    return 0;
}

/**
 * Serialize a bucket (array of messages) to JSON string
 */
static int bucket_to_json(const dna_group_message_t *messages, size_t count, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(1));

    json_object *msg_array = json_object_new_array();
    for (size_t i = 0; i < count; i++) {
        json_object *msg_json = NULL;
        if (message_to_json(&messages[i], &msg_json) == 0 && msg_json) {
            json_object_array_add(msg_array, msg_json);
        }
    }
    json_object_object_add(root, "messages", msg_array);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

/**
 * Deserialize a bucket from JSON string
 */
static int bucket_from_json(const char *json_str, dna_group_message_t **messages_out, size_t *count_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    json_object *j_messages;
    if (!json_object_object_get_ex(root, "messages", &j_messages)) {
        json_object_put(root);
        return -1;
    }

    size_t count = json_object_array_length(j_messages);
    if (count == 0) {
        json_object_put(root);
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    dna_group_message_t *messages = calloc(count, sizeof(dna_group_message_t));
    if (!messages) {
        json_object_put(root);
        return -1;
    }

    size_t valid = 0;
    for (size_t i = 0; i < count; i++) {
        json_object *j_msg = json_object_array_get_idx(j_messages, i);
        if (j_msg && message_from_json(j_msg, &messages[valid]) == 0) {
            valid++;
        }
    }

    json_object_put(root);

    *messages_out = messages;
    *count_out = valid;
    return 0;
}

/*============================================================================
 * Send API
 *============================================================================*/

int dna_group_outbox_send(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    const char *sender_fingerprint,
    const char *plaintext,
    const uint8_t *dilithium_privkey,
    char *message_id_out
) {
    if (!dht_ctx || !group_uuid || !sender_fingerprint || !plaintext || !dilithium_privkey) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    printf("[GROUP_OUTBOX] Sending message to group %s\n", group_uuid);

    /* Step 1: Load active GSK */
    uint8_t gsk[GSK_KEY_SIZE];
    uint32_t gsk_version = 0;
    if (gsk_load_active(group_uuid, gsk, &gsk_version) != 0) {
        fprintf(stderr, "[GROUP_OUTBOX] No active GSK for group %s\n", group_uuid);
        return DNA_GROUP_OUTBOX_ERR_NO_GSK;
    }

    /* Step 2: Get current hour bucket */
    uint64_t hour_bucket = dna_group_outbox_get_hour_bucket();

    /* Step 3: Generate message ID */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    char message_id[DNA_GROUP_MSG_ID_SIZE];
    dna_group_outbox_make_message_id(sender_fingerprint, group_uuid, timestamp_ms, message_id);

    if (message_id_out) {
        strncpy(message_id_out, message_id, DNA_GROUP_MSG_ID_SIZE - 1);
    }

    /* Step 4: Encrypt plaintext with GSK (AES-256-GCM) */
    size_t plaintext_len = strlen(plaintext);
    size_t ciphertext_size = qgp_aes256_encrypt_size(plaintext_len);
    uint8_t *ciphertext = malloc(ciphertext_size);
    if (!ciphertext) {
        return DNA_GROUP_OUTBOX_ERR_ALLOC;
    }

    uint8_t nonce[DNA_GROUP_OUTBOX_NONCE_SIZE];
    uint8_t tag[DNA_GROUP_OUTBOX_TAG_SIZE];
    size_t ciphertext_len = 0;

    /* AAD = message_id (for authentication binding) */
    if (qgp_aes256_encrypt(gsk, (const uint8_t *)plaintext, plaintext_len,
                           (const uint8_t *)message_id, strlen(message_id),
                           ciphertext, &ciphertext_len, nonce, tag) != 0) {
        fprintf(stderr, "[GROUP_OUTBOX] AES encryption failed\n");
        free(ciphertext);
        return DNA_GROUP_OUTBOX_ERR_ENCRYPT;
    }

    /* Step 5: Build signed data and sign with Dilithium5 */
    /* Sign: message_id || timestamp_ms || ciphertext */
    size_t sign_data_len = strlen(message_id) + sizeof(uint64_t) + ciphertext_len;
    uint8_t *sign_data = malloc(sign_data_len);
    if (!sign_data) {
        free(ciphertext);
        return DNA_GROUP_OUTBOX_ERR_ALLOC;
    }

    size_t offset = 0;
    memcpy(sign_data + offset, message_id, strlen(message_id));
    offset += strlen(message_id);
    uint64_t ts_net = htonll_outbox(timestamp_ms);
    memcpy(sign_data + offset, &ts_net, sizeof(uint64_t));
    offset += sizeof(uint64_t);
    memcpy(sign_data + offset, ciphertext, ciphertext_len);

    uint8_t signature[DNA_GROUP_OUTBOX_SIG_SIZE];
    size_t signature_len = 0;
    int ret = pqcrystals_dilithium5_ref_signature(signature, &signature_len,
                                                   sign_data, sign_data_len,
                                                   NULL, 0, dilithium_privkey);
    free(sign_data);

    if (ret != 0) {
        fprintf(stderr, "[GROUP_OUTBOX] Dilithium signing failed\n");
        free(ciphertext);
        return DNA_GROUP_OUTBOX_ERR_SIGN;
    }

    /* Step 6: Build message structure */
    dna_group_message_t new_msg;
    memset(&new_msg, 0, sizeof(new_msg));
    strncpy(new_msg.message_id, message_id, sizeof(new_msg.message_id) - 1);
    strncpy(new_msg.sender_fingerprint, sender_fingerprint, sizeof(new_msg.sender_fingerprint) - 1);
    strncpy(new_msg.group_uuid, group_uuid, sizeof(new_msg.group_uuid) - 1);
    new_msg.timestamp_ms = timestamp_ms;
    new_msg.gsk_version = gsk_version;
    memcpy(new_msg.nonce, nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);
    new_msg.ciphertext = ciphertext;
    new_msg.ciphertext_len = ciphertext_len;
    memcpy(new_msg.tag, tag, DNA_GROUP_OUTBOX_TAG_SIZE);
    memcpy(new_msg.signature, signature, signature_len);
    new_msg.signature_len = signature_len;

    /* Step 7: Get my unique value_id */
    uint64_t my_value_id = 1;
    dht_get_owner_value_id(dht_ctx, &my_value_id);

    /* Step 8: Generate DHT key for this bucket */
    char dht_key[128];
    dna_group_outbox_make_key(group_uuid, hour_bucket, dht_key, sizeof(dht_key));

    /* Step 9: Read my existing messages at this key (read-modify-write pattern) */
    dna_group_message_t *existing_msgs = NULL;
    size_t existing_count = 0;

    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    /* Use dht_get with my value_id to get only my data */
    ret = dht_get_all(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                      &values, &lens, &value_count);

    if (ret == 0 && value_count > 0) {
        /* Find my entry (match by sender fingerprint in deserialized messages) */
        for (size_t i = 0; i < value_count; i++) {
            if (values[i] && lens[i] > 0) {
                char *json_str = malloc(lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, values[i], lens[i]);
                    json_str[lens[i]] = '\0';

                    dna_group_message_t *msgs = NULL;
                    size_t msg_count = 0;
                    if (bucket_from_json(json_str, &msgs, &msg_count) == 0 && msgs) {
                        /* Check if these are my messages */
                        if (msg_count > 0 && strcmp(msgs[0].sender_fingerprint, sender_fingerprint) == 0) {
                            existing_msgs = msgs;
                            existing_count = msg_count;
                        } else {
                            dna_group_outbox_free_messages(msgs, msg_count);
                        }
                    }
                    free(json_str);
                }
            }
            free(values[i]);
        }
        free(values);
        free(lens);
    }

    printf("[GROUP_OUTBOX] Found %zu existing messages in my bucket\n", existing_count);

    /* Step 10: Append new message to my array */
    size_t new_count = existing_count + 1;
    dna_group_message_t *all_msgs = calloc(new_count, sizeof(dna_group_message_t));
    if (!all_msgs) {
        free(ciphertext);
        dna_group_outbox_free_messages(existing_msgs, existing_count);
        return DNA_GROUP_OUTBOX_ERR_ALLOC;
    }

    /* Copy existing messages */
    for (size_t i = 0; i < existing_count; i++) {
        all_msgs[i] = existing_msgs[i];
        /* Transfer ownership of ciphertext pointer */
        existing_msgs[i].ciphertext = NULL;
    }
    free(existing_msgs);

    /* Add new message */
    all_msgs[existing_count] = new_msg;
    /* Duplicate ciphertext for the array since we'll free individually */
    all_msgs[existing_count].ciphertext = malloc(ciphertext_len);
    if (all_msgs[existing_count].ciphertext) {
        memcpy(all_msgs[existing_count].ciphertext, ciphertext, ciphertext_len);
    }
    free(ciphertext);

    /* Step 11: Serialize and publish to DHT */
    char *bucket_json = NULL;
    if (bucket_to_json(all_msgs, new_count, &bucket_json) != 0) {
        dna_group_outbox_free_messages(all_msgs, new_count);
        return DNA_GROUP_OUTBOX_ERR_SERIALIZE;
    }

    printf("[GROUP_OUTBOX] Publishing %zu messages to DHT key %s (value_id=%lu)\n",
           new_count, dht_key, (unsigned long)my_value_id);

    ret = dht_put_signed(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                         (const uint8_t *)bucket_json, strlen(bucket_json),
                         my_value_id, DNA_GROUP_OUTBOX_TTL);

    free(bucket_json);
    dna_group_outbox_free_messages(all_msgs, new_count);

    if (ret != 0) {
        fprintf(stderr, "[GROUP_OUTBOX] DHT put failed\n");
        return DNA_GROUP_OUTBOX_ERR_DHT_PUT;
    }

    /* Step 12: Store locally */
    new_msg.ciphertext = NULL; /* Already freed in all_msgs */
    new_msg.plaintext = strdup(plaintext);
    dna_group_outbox_db_store_message(&new_msg);
    free(new_msg.plaintext);

    printf("[GROUP_OUTBOX] Message sent: %s\n", message_id);
    return DNA_GROUP_OUTBOX_OK;
}

/*============================================================================
 * Receive API
 *============================================================================*/

int dna_group_outbox_fetch(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    uint64_t hour_bucket,
    dna_group_message_t **messages_out,
    size_t *count_out
) {
    if (!dht_ctx || !group_uuid || !messages_out || !count_out) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    /* Use current hour if 0 */
    if (hour_bucket == 0) {
        hour_bucket = dna_group_outbox_get_hour_bucket();
    }

    /* Generate DHT key */
    char dht_key[128];
    dna_group_outbox_make_key(group_uuid, hour_bucket, dht_key, sizeof(dht_key));

    printf("[GROUP_OUTBOX] Fetching bucket %s\n", dht_key);

    /* Fetch all senders' messages with dht_get_all() */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)dht_key, strlen(dht_key),
                          &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        *messages_out = NULL;
        *count_out = 0;
        return DNA_GROUP_OUTBOX_OK; /* No messages is OK */
    }

    printf("[GROUP_OUTBOX] Got %zu sender buckets\n", value_count);

    /* Merge all messages from all senders */
    dna_group_message_t *all_messages = NULL;
    size_t total_count = 0;
    size_t allocated = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (!values[i] || lens[i] == 0) continue;

        char *json_str = malloc(lens[i] + 1);
        if (!json_str) continue;

        memcpy(json_str, values[i], lens[i]);
        json_str[lens[i]] = '\0';

        dna_group_message_t *bucket_msgs = NULL;
        size_t bucket_count = 0;

        if (bucket_from_json(json_str, &bucket_msgs, &bucket_count) == 0 && bucket_msgs) {
            /* Expand array if needed */
            if (total_count + bucket_count > allocated) {
                size_t new_alloc = allocated == 0 ? 64 : allocated * 2;
                while (new_alloc < total_count + bucket_count) new_alloc *= 2;

                dna_group_message_t *new_arr = realloc(all_messages, new_alloc * sizeof(dna_group_message_t));
                if (!new_arr) {
                    dna_group_outbox_free_messages(bucket_msgs, bucket_count);
                    free(json_str);
                    continue;
                }
                all_messages = new_arr;
                allocated = new_alloc;
            }

            /* Copy messages */
            for (size_t j = 0; j < bucket_count; j++) {
                all_messages[total_count++] = bucket_msgs[j];
                bucket_msgs[j].ciphertext = NULL; /* Transfer ownership */
            }
            free(bucket_msgs);
        }

        free(json_str);
        free(values[i]);
    }
    free(values);
    free(lens);

    *messages_out = all_messages;
    *count_out = total_count;

    printf("[GROUP_OUTBOX] Merged %zu messages from bucket\n", total_count);
    return DNA_GROUP_OUTBOX_OK;
}

int dna_group_outbox_sync(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    size_t *new_message_count_out
) {
    if (!dht_ctx || !group_uuid) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    printf("[GROUP_OUTBOX] Syncing group %s\n", group_uuid);

    /* Get last sync hour */
    uint64_t last_sync_hour = 0;
    dna_group_outbox_db_get_last_sync_hour(group_uuid, &last_sync_hour);

    uint64_t current_hour = dna_group_outbox_get_hour_bucket();
    size_t new_count = 0;

    /* Load GSK for decryption */
    uint8_t gsk[GSK_KEY_SIZE];
    if (gsk_load_active(group_uuid, gsk, NULL) != 0) {
        fprintf(stderr, "[GROUP_OUTBOX] No active GSK for group %s (skipping sync)\n", group_uuid);
        return DNA_GROUP_OUTBOX_ERR_NO_GSK;
    }

    /* Sync past buckets (sealed, fetch once) */
    uint64_t start_hour = last_sync_hour > 0 ? last_sync_hour + 1 : current_hour - DNA_GROUP_OUTBOX_MAX_CATCHUP_BUCKETS;
    if (start_hour > current_hour) start_hour = current_hour;

    for (uint64_t hour = start_hour; hour <= current_hour; hour++) {
        dna_group_message_t *messages = NULL;
        size_t count = 0;

        int ret = dna_group_outbox_fetch(dht_ctx, group_uuid, hour, &messages, &count);
        if (ret != DNA_GROUP_OUTBOX_OK || !messages || count == 0) {
            continue;
        }

        printf("[GROUP_OUTBOX] Processing %zu messages from hour %lu\n", count, (unsigned long)hour);

        for (size_t i = 0; i < count; i++) {
            /* Check if already stored */
            if (dna_group_outbox_db_message_exists(messages[i].message_id) == 1) {
                continue; /* Already have it */
            }

            /* Decrypt message */
            if (messages[i].ciphertext && messages[i].ciphertext_len > 0) {
                uint8_t *plaintext = malloc(messages[i].ciphertext_len);
                if (plaintext) {
                    size_t plaintext_len = 0;
                    /* AAD = message_id */
                    if (qgp_aes256_decrypt(gsk, messages[i].ciphertext, messages[i].ciphertext_len,
                                           (const uint8_t *)messages[i].message_id, strlen(messages[i].message_id),
                                           messages[i].nonce, messages[i].tag,
                                           plaintext, &plaintext_len) == 0) {
                        messages[i].plaintext = malloc(plaintext_len + 1);
                        if (messages[i].plaintext) {
                            memcpy(messages[i].plaintext, plaintext, plaintext_len);
                            messages[i].plaintext[plaintext_len] = '\0';
                        }
                    }
                    free(plaintext);
                }
            }

            /* Store in database */
            if (dna_group_outbox_db_store_message(&messages[i]) == 0) {
                new_count++;
            }
        }

        dna_group_outbox_free_messages(messages, count);

        /* Update sync hour for past buckets only */
        if (hour < current_hour) {
            dna_group_outbox_db_set_last_sync_hour(group_uuid, hour);
        }
    }

    if (new_message_count_out) {
        *new_message_count_out = new_count;
    }

    printf("[GROUP_OUTBOX] Sync complete: %zu new messages\n", new_count);
    return DNA_GROUP_OUTBOX_OK;
}

int dna_group_outbox_sync_all(
    dht_context_t *dht_ctx,
    const char *my_fingerprint,
    size_t *total_new_messages_out
) {
    if (!dht_ctx || !my_fingerprint || !group_outbox_db) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    printf("[GROUP_OUTBOX] Syncing all groups for %s\n", my_fingerprint);

    /* Query all groups the user is a member of */
    const char *sql = "SELECT DISTINCT group_uuid FROM dht_group_members WHERE member_fingerprint = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[GROUP_OUTBOX] Failed to query groups: %s\n", sqlite3_errmsg(group_outbox_db));
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

    sqlite3_bind_text(stmt, 1, my_fingerprint, -1, SQLITE_TRANSIENT);

    size_t total_new = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *group_uuid = (const char *)sqlite3_column_text(stmt, 0);
        if (!group_uuid) continue;

        size_t new_count = 0;
        int ret = dna_group_outbox_sync(dht_ctx, group_uuid, &new_count);
        if (ret == DNA_GROUP_OUTBOX_OK) {
            total_new += new_count;
        }
    }

    sqlite3_finalize(stmt);

    if (total_new_messages_out) {
        *total_new_messages_out = total_new;
    }

    printf("[GROUP_OUTBOX] Total: %zu new messages across all groups\n", total_new);
    return DNA_GROUP_OUTBOX_OK;
}

/*============================================================================
 * Database Functions
 *============================================================================*/

int dna_group_outbox_db_init(void) {
    /* Get database from message backup context (will be set by caller) */
    /* For now, we assume msg_db is already set */
    if (!group_outbox_db) {
        fprintf(stderr, "[GROUP_OUTBOX] Database not set - call with backup context first\n");
        return -1;
    }

    /* Create group_messages table */
    const char *create_messages =
        "CREATE TABLE IF NOT EXISTS group_messages ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  message_id TEXT UNIQUE NOT NULL,"
        "  group_uuid TEXT NOT NULL,"
        "  sender_fingerprint TEXT NOT NULL,"
        "  gsk_version INTEGER NOT NULL,"
        "  nonce BLOB NOT NULL,"
        "  ciphertext BLOB NOT NULL,"
        "  ciphertext_len INTEGER NOT NULL,"
        "  tag BLOB NOT NULL,"
        "  signature BLOB NOT NULL,"
        "  signature_len INTEGER NOT NULL,"
        "  timestamp_ms INTEGER NOT NULL,"
        "  received_at INTEGER NOT NULL,"
        "  decrypted_text TEXT"
        ")";

    char *err_msg = NULL;
    int rc = sqlite3_exec(group_outbox_db, create_messages, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[GROUP_OUTBOX] Failed to create group_messages table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    /* Create indexes */
    const char *create_idx1 = "CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_uuid)";
    const char *create_idx2 = "CREATE INDEX IF NOT EXISTS idx_group_messages_timestamp ON group_messages(timestamp_ms)";
    const char *create_idx3 = "CREATE INDEX IF NOT EXISTS idx_group_messages_id ON group_messages(message_id)";

    sqlite3_exec(group_outbox_db, create_idx1, NULL, NULL, NULL);
    sqlite3_exec(group_outbox_db, create_idx2, NULL, NULL, NULL);
    sqlite3_exec(group_outbox_db, create_idx3, NULL, NULL, NULL);

    /* Create group_sync_state table */
    const char *create_sync =
        "CREATE TABLE IF NOT EXISTS group_sync_state ("
        "  group_uuid TEXT PRIMARY KEY,"
        "  last_sync_hour INTEGER NOT NULL,"
        "  last_sync_time INTEGER NOT NULL"
        ")";

    rc = sqlite3_exec(group_outbox_db, create_sync, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[GROUP_OUTBOX] Failed to create group_sync_state table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    printf("[GROUP_OUTBOX] Database tables initialized\n");
    return 0;
}

/**
 * Set database handle (called during messenger init)
 */
void dna_group_outbox_set_db(void *db) {
    group_outbox_db = (sqlite3 *)db;
}

int dna_group_outbox_db_store_message(const dna_group_message_t *msg) {
    if (!msg || !group_outbox_db) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    const char *sql =
        "INSERT OR IGNORE INTO group_messages "
        "(message_id, group_uuid, sender_fingerprint, gsk_version, nonce, ciphertext, ciphertext_len, "
        "tag, signature, signature_len, timestamp_ms, received_at, decrypted_text) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

    sqlite3_bind_text(stmt, 1, msg->message_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, msg->group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, msg->sender_fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)msg->gsk_version);
    sqlite3_bind_blob(stmt, 5, msg->nonce, DNA_GROUP_OUTBOX_NONCE_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 6, msg->ciphertext, (int)msg->ciphertext_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, (int)msg->ciphertext_len);
    sqlite3_bind_blob(stmt, 8, msg->tag, DNA_GROUP_OUTBOX_TAG_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 9, msg->signature, (int)msg->signature_len, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 10, (int)msg->signature_len);
    sqlite3_bind_int64(stmt, 11, (sqlite3_int64)msg->timestamp_ms);
    sqlite3_bind_int64(stmt, 12, (sqlite3_int64)time(NULL));
    if (msg->plaintext) {
        sqlite3_bind_text(stmt, 13, msg->plaintext, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_null(stmt, 13);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (sqlite3_errcode(group_outbox_db) == SQLITE_CONSTRAINT) {
            return DNA_GROUP_OUTBOX_ERR_DUPLICATE;
        }
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

    return sqlite3_changes(group_outbox_db) > 0 ? DNA_GROUP_OUTBOX_OK : DNA_GROUP_OUTBOX_ERR_DUPLICATE;
}

int dna_group_outbox_db_message_exists(const char *message_id) {
    if (!message_id || !group_outbox_db) {
        return -1;
    }

    const char *sql = "SELECT 1 FROM group_messages WHERE message_id = ? LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, message_id, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_ROW) ? 1 : 0;
}

int dna_group_outbox_db_get_messages(
    const char *group_uuid,
    size_t limit,
    size_t offset,
    dna_group_message_t **messages_out,
    size_t *count_out
) {
    if (!group_uuid || !messages_out || !count_out || !group_outbox_db) {
        return -1;
    }

    char sql[512];
    if (limit > 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT message_id, group_uuid, sender_fingerprint, gsk_version, nonce, ciphertext, "
                 "ciphertext_len, tag, signature, signature_len, timestamp_ms, decrypted_text "
                 "FROM group_messages WHERE group_uuid = ? ORDER BY timestamp_ms DESC LIMIT %zu OFFSET %zu",
                 limit, offset);
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT message_id, group_uuid, sender_fingerprint, gsk_version, nonce, ciphertext, "
                 "ciphertext_len, tag, signature, signature_len, timestamp_ms, decrypted_text "
                 "FROM group_messages WHERE group_uuid = ? ORDER BY timestamp_ms DESC");
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    /* Count rows first */
    dna_group_message_t *messages = NULL;
    size_t count = 0;
    size_t allocated = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= allocated) {
            size_t new_alloc = allocated == 0 ? 32 : allocated * 2;
            dna_group_message_t *new_arr = realloc(messages, new_alloc * sizeof(dna_group_message_t));
            if (!new_arr) break;
            messages = new_arr;
            allocated = new_alloc;
        }

        dna_group_message_t *msg = &messages[count];
        memset(msg, 0, sizeof(dna_group_message_t));

        strncpy(msg->message_id, (const char *)sqlite3_column_text(stmt, 0), sizeof(msg->message_id) - 1);
        strncpy(msg->group_uuid, (const char *)sqlite3_column_text(stmt, 1), sizeof(msg->group_uuid) - 1);
        strncpy(msg->sender_fingerprint, (const char *)sqlite3_column_text(stmt, 2), sizeof(msg->sender_fingerprint) - 1);
        msg->gsk_version = (uint32_t)sqlite3_column_int(stmt, 3);

        const void *nonce = sqlite3_column_blob(stmt, 4);
        if (nonce) memcpy(msg->nonce, nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);

        const void *ct = sqlite3_column_blob(stmt, 5);
        int ct_len = sqlite3_column_int(stmt, 6);
        if (ct && ct_len > 0) {
            msg->ciphertext = malloc(ct_len);
            if (msg->ciphertext) {
                memcpy(msg->ciphertext, ct, ct_len);
                msg->ciphertext_len = ct_len;
            }
        }

        const void *tag = sqlite3_column_blob(stmt, 7);
        if (tag) memcpy(msg->tag, tag, DNA_GROUP_OUTBOX_TAG_SIZE);

        const void *sig = sqlite3_column_blob(stmt, 8);
        int sig_len = sqlite3_column_int(stmt, 9);
        if (sig && sig_len <= DNA_GROUP_OUTBOX_SIG_SIZE) {
            memcpy(msg->signature, sig, sig_len);
            msg->signature_len = sig_len;
        }

        msg->timestamp_ms = (uint64_t)sqlite3_column_int64(stmt, 10);

        const char *text = (const char *)sqlite3_column_text(stmt, 11);
        if (text) msg->plaintext = strdup(text);

        count++;
    }

    sqlite3_finalize(stmt);

    *messages_out = messages;
    *count_out = count;
    return 0;
}

int dna_group_outbox_db_get_last_sync_hour(
    const char *group_uuid,
    uint64_t *last_sync_hour_out
) {
    if (!group_uuid || !last_sync_hour_out || !group_outbox_db) {
        return -1;
    }

    const char *sql = "SELECT last_sync_hour FROM group_sync_state WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        *last_sync_hour_out = 0;
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *last_sync_hour_out = (uint64_t)sqlite3_column_int64(stmt, 0);
    } else {
        *last_sync_hour_out = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int dna_group_outbox_db_set_last_sync_hour(
    const char *group_uuid,
    uint64_t last_sync_hour
) {
    if (!group_uuid || !group_outbox_db) {
        return -1;
    }

    const char *sql =
        "INSERT OR REPLACE INTO group_sync_state (group_uuid, last_sync_hour, last_sync_time) "
        "VALUES (?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)last_sync_hour);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

/*============================================================================
 * Memory Management
 *============================================================================*/

void dna_group_outbox_free_message(dna_group_message_t *msg) {
    if (!msg) return;
    free(msg->ciphertext);
    free(msg->plaintext);
    msg->ciphertext = NULL;
    msg->plaintext = NULL;
}

void dna_group_outbox_free_messages(dna_group_message_t *messages, size_t count) {
    if (!messages) return;
    for (size_t i = 0; i < count; i++) {
        dna_group_outbox_free_message(&messages[i]);
    }
    free(messages);
}

void dna_group_outbox_free_bucket(dna_group_outbox_bucket_t *bucket) {
    if (!bucket) return;
    if (bucket->messages) {
        dna_group_outbox_free_messages(bucket->messages, bucket->message_count);
    }
    free(bucket);
}
