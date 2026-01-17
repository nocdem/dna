/**
 * @file dna_group_outbox.c
 * @brief Group Message Outbox Implementation
 *
 * Single-key group messaging with multi-writer DHT storage.
 * All group members write to the same key with different value_id.
 * dht_get_all() fetches all senders' buckets in one query.
 *
 * Part of DNA Messenger
 *
 * @date 2025-11-29
 * @updated 2026-01-15 - Single-key architecture
 */

#include "dna_group_outbox.h"
#include "../shared/dht_chunked.h"
#include "../core/dht_listen.h"
#include "dht_singleton.h"
#include "../../messenger/gek.h"
#include "../../messenger.h"  // For messenger_sync_group_gek
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

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"
#define LOG_TAG "DNA_OUTBOX"

/* External DHT functions - declared in dht_chunked.h */
/* dht_chunked_fetch_all() - fetch all values from all senders at a key */
/* dht_chunked_fetch_mine() - fetch only my value at a key */

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
 * Utility Functions
 *============================================================================*/

uint64_t dna_group_outbox_get_day_bucket(void) {
    return (uint64_t)time(NULL) / DNA_GROUP_OUTBOX_SECONDS_PER_DAY;
}

int dna_group_outbox_make_key(
    const char *group_uuid,
    uint64_t day_bucket,
    char *key_out,
    size_t key_out_size
) {
    if (!group_uuid || !key_out || key_out_size < 128) {
        return -1;
    }

    snprintf(key_out, key_out_size, DNA_GROUP_OUTBOX_KEY_FMT,
             group_uuid, (unsigned long)day_bucket);
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
        case DNA_GROUP_OUTBOX_ERR_NO_GEK: return "No active GEK found";
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
    char *nonce_b64 = qgp_base64_encode(msg->nonce, DNA_GROUP_OUTBOX_NONCE_SIZE, NULL);
    if (nonce_b64) {
        json_object_object_add(root, "nonce", json_object_new_string(nonce_b64));
        free(nonce_b64);
    }

    /* Ciphertext (base64) */
    if (msg->ciphertext && msg->ciphertext_len > 0) {
        char *ct_b64 = qgp_base64_encode(msg->ciphertext, msg->ciphertext_len, NULL);
        if (ct_b64) {
            json_object_object_add(root, "ciphertext", json_object_new_string(ct_b64));
            free(ct_b64);
        }
    }

    /* Tag (base64) */
    char *tag_b64 = qgp_base64_encode(msg->tag, DNA_GROUP_OUTBOX_TAG_SIZE, NULL);
    if (tag_b64) {
        json_object_object_add(root, "tag", json_object_new_string(tag_b64));
        free(tag_b64);
    }

    /* Signature (base64) */
    if (msg->signature_len > 0) {
        char *sig_b64 = qgp_base64_encode(msg->signature, msg->signature_len, NULL);
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
        uint8_t *nonce = qgp_base64_decode(json_object_get_string(j_val), &nonce_len);
        if (nonce && nonce_len == DNA_GROUP_OUTBOX_NONCE_SIZE) {
            memcpy(msg->nonce, nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);
        }
        free(nonce);
    }

    /* Ciphertext (base64) */
    if (json_object_object_get_ex(root, "ciphertext", &j_val)) {
        size_t ct_len = 0;
        uint8_t *ct = qgp_base64_decode(json_object_get_string(j_val), &ct_len);
        if (ct && ct_len > 0) {
            msg->ciphertext = ct;
            msg->ciphertext_len = ct_len;
        }
    }

    /* Tag (base64) */
    if (json_object_object_get_ex(root, "tag", &j_val)) {
        size_t tag_len = 0;
        uint8_t *tag = qgp_base64_decode(json_object_get_string(j_val), &tag_len);
        if (tag && tag_len == DNA_GROUP_OUTBOX_TAG_SIZE) {
            memcpy(msg->tag, tag, DNA_GROUP_OUTBOX_TAG_SIZE);
        }
        free(tag);
    }

    /* Signature (base64) */
    if (json_object_object_get_ex(root, "signature", &j_val)) {
        size_t sig_len = 0;
        uint8_t *sig = qgp_base64_decode(json_object_get_string(j_val), &sig_len);
        if (sig && sig_len <= DNA_GROUP_OUTBOX_SIG_SIZE) {
            memcpy(msg->signature, sig, sig_len);
            msg->signature_len = sig_len;
        }
        free(sig);
    }

    return 0;
}

/**
 * Serialize a bucket (array of messages from one sender) to JSON string
 * Version 2: includes sender_fingerprint at bucket level
 */
static int bucket_to_json(const char *sender_fingerprint, const dna_group_message_t *messages,
                          size_t count, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "version", json_object_new_int(2));
    json_object_object_add(root, "sender_fingerprint", json_object_new_string(sender_fingerprint));

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

    QGP_LOG_INFO(LOG_TAG, "Sending message to group %s\n", group_uuid);

    /* Step 1: Load active GEK */
    uint8_t gek[GEK_KEY_SIZE];
    uint32_t gek_version = 0;
    if (gek_load_active(group_uuid, gek, &gek_version) != 0) {
        /* GEK not found locally - try auto-sync from DHT */
        QGP_LOG_WARN(LOG_TAG, "No local GEK for group %s, attempting auto-sync from DHT...\n", group_uuid);
        if (messenger_sync_group_gek(group_uuid) == 0) {
            /* Sync succeeded, retry load */
            if (gek_load_active(group_uuid, gek, &gek_version) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "GEK load failed after sync for group %s\n", group_uuid);
                return DNA_GROUP_OUTBOX_ERR_NO_GEK;
            }
            QGP_LOG_INFO(LOG_TAG, "Auto-synced GEK v%u for group %s\n", gek_version, group_uuid);
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Auto-sync failed, no active GEK for group %s\n", group_uuid);
            return DNA_GROUP_OUTBOX_ERR_NO_GEK;
        }
    }

    /* Step 2: Get current day bucket */
    uint64_t day_bucket = dna_group_outbox_get_day_bucket();

    /* Step 3: Generate message ID */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t timestamp_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    char message_id[DNA_GROUP_MSG_ID_SIZE];
    dna_group_outbox_make_message_id(sender_fingerprint, group_uuid, timestamp_ms, message_id);

    if (message_id_out) {
        strncpy(message_id_out, message_id, DNA_GROUP_MSG_ID_SIZE - 1);
    }

    /* Step 4: Encrypt plaintext with GEK (AES-256-GCM) */
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
    if (qgp_aes256_encrypt(gek, (const uint8_t *)plaintext, plaintext_len,
                           (const uint8_t *)message_id, strlen(message_id),
                           ciphertext, &ciphertext_len, nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES encryption failed\n");
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
        QGP_LOG_ERROR(LOG_TAG, "Dilithium signing failed\n");
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
    new_msg.gsk_version = gek_version;
    memcpy(new_msg.nonce, nonce, DNA_GROUP_OUTBOX_NONCE_SIZE);
    new_msg.ciphertext = ciphertext;
    new_msg.ciphertext_len = ciphertext_len;
    memcpy(new_msg.tag, tag, DNA_GROUP_OUTBOX_TAG_SIZE);
    memcpy(new_msg.signature, signature, signature_len);
    new_msg.signature_len = signature_len;

    /* Step 7: Generate shared group DHT key */
    char group_key[256];
    dna_group_outbox_make_key(group_uuid, day_bucket, group_key, sizeof(group_key));

    /* Step 8: Read my existing messages using chunked fetch with my value_id */
    dna_group_message_t *existing_msgs = NULL;
    size_t existing_count = 0;

    uint8_t *existing_data = NULL;
    size_t existing_len = 0;
    /* Fetch my own bucket from the shared key using dht_chunked_fetch_mine() */
    ret = dht_chunked_fetch_mine(dht_ctx, group_key, &existing_data, &existing_len);

    if (ret == 0 && existing_data && existing_len > 0) {
        char *json_str = malloc(existing_len + 1);
        if (json_str) {
            memcpy(json_str, existing_data, existing_len);
            json_str[existing_len] = '\0';
            bucket_from_json(json_str, &existing_msgs, &existing_count);
            free(json_str);
        }
        free(existing_data);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Found %zu existing messages in my bucket at %s\n",
                  existing_count, group_key);

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

    /* Step 11: Serialize and publish to DHT using chunked storage */
    char *bucket_json = NULL;
    if (bucket_to_json(sender_fingerprint, all_msgs, new_count, &bucket_json) != 0) {
        dna_group_outbox_free_messages(all_msgs, new_count);
        return DNA_GROUP_OUTBOX_ERR_SERIALIZE;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu messages to shared key %s\n",
           new_count, group_key);

    ret = dht_chunked_publish(dht_ctx, group_key,
                               (const uint8_t *)bucket_json, strlen(bucket_json),
                               DNA_GROUP_OUTBOX_TTL);

    free(bucket_json);
    dna_group_outbox_free_messages(all_msgs, new_count);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "DHT chunked publish failed: %s\n", dht_chunked_strerror(ret));
        return DNA_GROUP_OUTBOX_ERR_DHT_PUT;
    }

    /* Step 12: Store locally */
    new_msg.ciphertext = NULL; /* Already freed in all_msgs */
    new_msg.plaintext = strdup(plaintext);
    dna_group_outbox_db_store_message(&new_msg);
    free(new_msg.plaintext);

    QGP_LOG_INFO(LOG_TAG, "Message sent: %s\n", message_id);
    return DNA_GROUP_OUTBOX_OK;
}

/*============================================================================
 * Receive API
 *============================================================================*/

int dna_group_outbox_fetch(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    uint64_t day_bucket,
    dna_group_message_t **messages_out,
    size_t *count_out
) {
    if (!dht_ctx || !group_uuid || !messages_out || !count_out) {
        return DNA_GROUP_OUTBOX_ERR_NULL_PARAM;
    }

    *messages_out = NULL;
    *count_out = 0;

    /* Use current day if 0 */
    if (day_bucket == 0) {
        day_bucket = dna_group_outbox_get_day_bucket();
    }

    /* Generate shared group DHT key */
    char group_key[256];
    dna_group_outbox_make_key(group_uuid, day_bucket, group_key, sizeof(group_key));

    QGP_LOG_DEBUG(LOG_TAG, "Fetching group %s day %lu from key %s\n",
                  group_uuid, (unsigned long)day_bucket, group_key);

    /* Fetch all senders' buckets using dht_chunked_fetch_all() */
    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = dht_chunked_fetch_all(dht_ctx, group_key, &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No buckets found at key %s\n", group_key);
        return DNA_GROUP_OUTBOX_OK; /* No messages is OK */
    }

    QGP_LOG_DEBUG(LOG_TAG, "Got %zu sender buckets from key %s\n", value_count, group_key);

    /* Merge all messages from all senders */
    dna_group_message_t *all_messages = NULL;
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

            /* Copy messages (transfer ownership) */
            for (size_t j = 0; j < bucket_count; j++) {
                all_messages[total_count++] = bucket_msgs[j];
                bucket_msgs[j].ciphertext = NULL;
                bucket_msgs[j].plaintext = NULL;
            }
            free(bucket_msgs);
        }

        free(json_str);
    }
    free(values);
    free(lens);

    *messages_out = all_messages;
    *count_out = total_count;

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu total messages from group %s day %lu\n",
                 total_count, group_uuid, (unsigned long)day_bucket);
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

    QGP_LOG_INFO(LOG_TAG, "Syncing group %s\n", group_uuid);

    /* Get last sync day */
    uint64_t last_sync_day = 0;
    dna_group_outbox_db_get_last_sync_day(group_uuid, &last_sync_day);

    uint64_t current_day = dna_group_outbox_get_day_bucket();
    size_t new_count = 0;

    /* Determine start day */
    uint64_t start_day = last_sync_day > 0
        ? last_sync_day + 1
        : current_day - DNA_GROUP_OUTBOX_MAX_CATCHUP_DAYS;
    if (start_day > current_day) start_day = current_day;

    QGP_LOG_INFO(LOG_TAG, "Syncing days %lu to %lu\n", (unsigned long)start_day, (unsigned long)current_day);

    /* Sync each day */
    for (uint64_t day = start_day; day <= current_day; day++) {
        dna_group_message_t *messages = NULL;
        size_t count = 0;

        /* Fetch all messages from shared key for this day */
        int ret = dna_group_outbox_fetch(dht_ctx, group_uuid, day,
                                          &messages, &count);

        if (ret != DNA_GROUP_OUTBOX_OK || !messages || count == 0) {
            /* Update sync day for past days even if empty */
            if (day < current_day) {
                dna_group_outbox_db_set_last_sync_day(group_uuid, day);
            }
            continue;
        }

        QGP_LOG_INFO(LOG_TAG, "Processing %zu messages from day %lu\n", count, (unsigned long)day);

        for (size_t i = 0; i < count; i++) {
            /* Check if already stored */
            if (dna_group_outbox_db_message_exists(messages[i].message_id) == 1) {
                continue; /* Already have it */
            }

            /* Decrypt message - load GEK by message's version */
            if (messages[i].ciphertext && messages[i].ciphertext_len > 0) {
                uint8_t gek[GEK_KEY_SIZE];
                int gek_loaded = gek_load(group_uuid, messages[i].gsk_version, gek);
                if (gek_loaded != 0) {
                    /* Try auto-sync from DHT */
                    if (messenger_sync_group_gek(group_uuid) == 0) {
                        gek_loaded = gek_load(group_uuid, messages[i].gsk_version, gek);
                    }
                }
                if (gek_loaded == 0) {
                    uint8_t *plaintext = malloc(messages[i].ciphertext_len);
                    if (plaintext) {
                        size_t plaintext_len = 0;
                        /* AAD = message_id */
                        if (qgp_aes256_decrypt(gek, messages[i].ciphertext, messages[i].ciphertext_len,
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
                    qgp_secure_memzero(gek, GEK_KEY_SIZE);
                } else {
                    QGP_LOG_WARN(LOG_TAG, "No GEK v%u for group %s, cannot decrypt\n",
                                 messages[i].gsk_version, group_uuid);
                }
            }

            /* Store in database */
            if (dna_group_outbox_db_store_message(&messages[i]) == 0) {
                new_count++;
            }
        }

        dna_group_outbox_free_messages(messages, count);

        /* Update sync day for past days only */
        if (day < current_day) {
            dna_group_outbox_db_set_last_sync_day(group_uuid, day);
        }
    }

    if (new_message_count_out) {
        *new_message_count_out = new_count;
    }

    QGP_LOG_INFO(LOG_TAG, "Sync complete: %zu new messages\n", new_count);
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

    QGP_LOG_INFO(LOG_TAG, "Syncing all groups for %s\n", my_fingerprint);
    (void)my_fingerprint;  /* Groups table only contains joined groups, no filter needed */

    /* Query all groups the user has joined (from message backup database) */
    const char *sql = "SELECT uuid FROM groups";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to query groups: %s\n", sqlite3_errmsg(group_outbox_db));
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

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

    QGP_LOG_INFO(LOG_TAG, "Total: %zu new messages across all groups\n", total_new);
    return DNA_GROUP_OUTBOX_OK;
}

/*============================================================================
 * Database Functions
 *============================================================================*/

int dna_group_outbox_db_init(void) {
    /* Get database from message backup context (will be set by caller) */
    /* For now, we assume msg_db is already set */
    if (!group_outbox_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not set - call with backup context first\n");
        return -1;
    }

    /* group_messages table is created by group_database.c - don't recreate */
    char *err_msg = NULL;
    int rc;

    /* Create group_sync_state table */
    const char *create_sync =
        "CREATE TABLE IF NOT EXISTS group_sync_state ("
        "  group_uuid TEXT PRIMARY KEY,"
        "  last_sync_hour INTEGER NOT NULL,"
        "  last_sync_time INTEGER NOT NULL"
        ")";

    rc = sqlite3_exec(group_outbox_db, create_sync, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create group_sync_state table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Database tables initialized\n");
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

    /* Schema 1: group_uuid, message_id (INTEGER), sender_fp, timestamp_ms, gek_version, plaintext, received_at */
    const char *sql =
        "INSERT OR IGNORE INTO group_messages "
        "(group_uuid, message_id, sender_fp, timestamp_ms, gek_version, plaintext, received_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare store SQL: %s\n", sqlite3_errmsg(group_outbox_db));
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

    /* Convert full message_id string to integer hash
     * message_id format: <128char_fingerprint>_<uuid>_<timestamp>
     * Must hash ENTIRE string - first 16 chars are always same (fingerprint start) */
    int64_t msg_id_int = 0;
    for (size_t i = 0; msg->message_id[i]; i++) {
        msg_id_int = (msg_id_int * 31) + (unsigned char)msg->message_id[i];
    }

    sqlite3_bind_text(stmt, 1, msg->group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, msg_id_int);
    sqlite3_bind_text(stmt, 3, msg->sender_fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)msg->timestamp_ms);
    sqlite3_bind_int(stmt, 5, (int)msg->gsk_version);
    if (msg->plaintext) {
        sqlite3_bind_text(stmt, 6, msg->plaintext, -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 6, "", -1, SQLITE_STATIC);
    }
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (sqlite3_errcode(group_outbox_db) == SQLITE_CONSTRAINT) {
            return DNA_GROUP_OUTBOX_ERR_DUPLICATE;
        }
        QGP_LOG_ERROR(LOG_TAG, "Failed to store message: %s\n", sqlite3_errmsg(group_outbox_db));
        return DNA_GROUP_OUTBOX_ERR_DB;
    }

    return sqlite3_changes(group_outbox_db) > 0 ? DNA_GROUP_OUTBOX_OK : DNA_GROUP_OUTBOX_ERR_DUPLICATE;
}

int dna_group_outbox_db_message_exists(const char *message_id) {
    if (!message_id || !group_outbox_db) {
        return -1;
    }

    /* Convert full message_id string to integer hash (same as store)
     * message_id format: <128char_fingerprint>_<uuid>_<timestamp>
     * Must hash ENTIRE string - first 16 chars are always same (fingerprint start) */
    int64_t msg_id_int = 0;
    for (size_t i = 0; message_id[i]; i++) {
        msg_id_int = (msg_id_int * 31) + (unsigned char)message_id[i];
    }

    const char *sql = "SELECT 1 FROM group_messages WHERE message_id = ? LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, msg_id_int);

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

    /* Schema 1: group_uuid, message_id, sender_fp, timestamp_ms, gek_version, plaintext, received_at */
    const char *sql_with_limit =
        "SELECT group_uuid, message_id, sender_fp, timestamp_ms, gek_version, plaintext "
        "FROM group_messages WHERE group_uuid = ? ORDER BY timestamp_ms DESC LIMIT ? OFFSET ?";

    const char *sql_no_limit =
        "SELECT group_uuid, message_id, sender_fp, timestamp_ms, gek_version, plaintext "
        "FROM group_messages WHERE group_uuid = ? ORDER BY timestamp_ms DESC";

    const char *sql = (limit > 0) ? sql_with_limit : sql_no_limit;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(group_outbox_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare get SQL: %s\n", sqlite3_errmsg(group_outbox_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    if (limit > 0) {
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)limit);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)offset);
    }

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

        /* Column 0: group_uuid */
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        if (uuid) strncpy(msg->group_uuid, uuid, sizeof(msg->group_uuid) - 1);

        /* Column 1: message_id (INTEGER) - convert to string */
        int64_t msg_id_int = sqlite3_column_int64(stmt, 1);
        snprintf(msg->message_id, sizeof(msg->message_id), "%lld", (long long)msg_id_int);

        /* Column 2: sender_fp */
        const char *sender = (const char *)sqlite3_column_text(stmt, 2);
        if (sender) strncpy(msg->sender_fingerprint, sender, sizeof(msg->sender_fingerprint) - 1);

        /* Column 3: timestamp_ms */
        msg->timestamp_ms = (uint64_t)sqlite3_column_int64(stmt, 3);

        /* Column 4: gek_version */
        msg->gsk_version = (uint32_t)sqlite3_column_int(stmt, 4);

        /* Column 5: plaintext */
        const char *text = (const char *)sqlite3_column_text(stmt, 5);
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

/* Day-based sync functions - use same column as hour (it's just a bucket number) */
int dna_group_outbox_db_get_last_sync_day(
    const char *group_uuid,
    uint64_t *last_sync_day_out
) {
    /* Reuse hour column for day bucket */
    return dna_group_outbox_db_get_last_sync_hour(group_uuid, last_sync_day_out);
}

int dna_group_outbox_db_set_last_sync_day(
    const char *group_uuid,
    uint64_t last_sync_day
) {
    /* Reuse hour column for day bucket */
    return dna_group_outbox_db_set_last_sync_hour(group_uuid, last_sync_day);
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

/*============================================================================
 * Listen API (Real-time notifications - Single Listener per Group)
 *============================================================================*/

/**
 * Internal: DHT listen callback for group messages
 *
 * Called when ANY sender publishes to the shared group key.
 * Fetches all messages and dedupes against local DB.
 */
static bool group_message_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
) {
    (void)value;
    (void)value_len;

    if (expired || !user_data) {
        return true;  /* Continue listening */
    }

    dna_group_listen_ctx_t *ctx = (dna_group_listen_ctx_t *)user_data;

    QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] >>> CALLBACK FIRED for group %s", ctx->group_uuid);

    /* Fetch ALL messages from the shared key (all senders) */
    dna_group_message_t *messages = NULL;
    size_t count = 0;

    dht_context_t *dht_ctx = ctx->dht_ctx;
    if (!dht_ctx) {
        dht_ctx = dht_singleton_get();
    }
    if (!dht_ctx) {
        return true;
    }

    int ret = dna_group_outbox_fetch(dht_ctx, ctx->group_uuid, ctx->current_day,
                                      &messages, &count);

    QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] Fetch result: ret=%d messages=%p count=%zu", ret, (void*)messages, count);

    if (ret != 0 || !messages || count == 0) {
        QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] No messages from fetch, returning");
        return true;
    }

    /* Process and store new messages */
    size_t new_count = 0;
    for (size_t i = 0; i < count; i++) {
        /* Check if already stored */
        if (dna_group_outbox_db_message_exists(messages[i].message_id) == 1) {
            continue;
        }

        /* Decrypt message - load GEK by message's version */
        if (messages[i].ciphertext && messages[i].ciphertext_len > 0) {
            uint8_t gek[GEK_KEY_SIZE];
            int gek_loaded = gek_load(ctx->group_uuid, messages[i].gsk_version, gek);
            if (gek_loaded != 0) {
                /* Try auto-sync from DHT */
                if (messenger_sync_group_gek(ctx->group_uuid) == 0) {
                    gek_loaded = gek_load(ctx->group_uuid, messages[i].gsk_version, gek);
                }
            }
            if (gek_loaded == 0) {
                uint8_t *plaintext = malloc(messages[i].ciphertext_len);
                if (plaintext) {
                    size_t plaintext_len = 0;
                    if (qgp_aes256_decrypt(gek, messages[i].ciphertext, messages[i].ciphertext_len,
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
                qgp_secure_memzero(gek, GEK_KEY_SIZE);
            } else {
                QGP_LOG_WARN(LOG_TAG, "No GEK v%u for group %s in listen callback\n",
                             messages[i].gsk_version, ctx->group_uuid);
            }
        }

        /* Store in database */
        if (dna_group_outbox_db_store_message(&messages[i]) == 0) {
            new_count++;
        }
    }

    dna_group_outbox_free_messages(messages, count);

    QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] Processed: total=%zu new=%zu callback=%p", count, new_count, (void*)ctx->on_new_message);

    /* Fire user callback if new messages */
    if (new_count > 0 && ctx->on_new_message) {
        QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] >>> FIRING EVENT: group=%s new_count=%zu", ctx->group_uuid, new_count);
        ctx->on_new_message(ctx->group_uuid, new_count, ctx->user_data);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[GROUP-LISTEN] NOT firing event: new_count=%zu", new_count);
    }

    return true;  /* Continue listening */
}

/**
 * Internal: Cleanup callback for listen context
 */
static void group_listen_cleanup(void *user_data) {
    /* Context is freed by unsubscribe, not here */
    (void)user_data;
}

/**
 * Internal: Subscribe to the shared group key for current day
 */
static int subscribe_to_group_key(dna_group_listen_ctx_t *ctx) {
    if (!ctx || !ctx->dht_ctx) {
        return -1;
    }

    /* Generate shared group key for current day */
    char group_key[256];
    dna_group_outbox_make_key(ctx->group_uuid, ctx->current_day, group_key, sizeof(group_key));

    /* Generate chunk:0 key (binary) for listening */
    uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];
    dht_chunked_make_key(group_key, 0, chunk0_key);

    /* Subscribe to the shared key */
    size_t token = dht_listen_ex(ctx->dht_ctx, chunk0_key, DHT_CHUNK_KEY_SIZE,
                                  group_message_listen_callback,
                                  ctx,  /* Pass context directly */
                                  group_listen_cleanup);

    ctx->listen_token = token;

    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to subscribe to group %s key %s\n",
                      ctx->group_uuid, group_key);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Subscribed to group %s day %lu token=%zu\n",
                 ctx->group_uuid, (unsigned long)ctx->current_day, token);
    return 0;
}

int dna_group_outbox_subscribe(
    dht_context_t *dht_ctx,
    const char *group_uuid,
    void (*on_new_message)(const char *group_uuid, size_t new_count, void *user_data),
    void *user_data,
    dna_group_listen_ctx_t **ctx_out
) {
    if (!dht_ctx || !group_uuid || !ctx_out) {
        return -1;
    }

    /* Allocate context */
    dna_group_listen_ctx_t *ctx = calloc(1, sizeof(dna_group_listen_ctx_t));
    if (!ctx) {
        return -1;
    }

    strncpy(ctx->group_uuid, group_uuid, sizeof(ctx->group_uuid) - 1);
    ctx->current_day = dna_group_outbox_get_day_bucket();
    ctx->on_new_message = on_new_message;
    ctx->user_data = user_data;
    ctx->dht_ctx = dht_ctx;
    ctx->listen_token = 0;

    QGP_LOG_INFO(LOG_TAG, "Subscribing to group %s day %lu (single key)\n",
                 group_uuid, (unsigned long)ctx->current_day);

    /* Subscribe to the shared group key */
    if (subscribe_to_group_key(ctx) != 0) {
        free(ctx);
        return -1;
    }

    *ctx_out = ctx;
    return 0;
}

void dna_group_outbox_unsubscribe(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx
) {
    if (!ctx) return;

    QGP_LOG_INFO(LOG_TAG, "Unsubscribing from group %s\n", ctx->group_uuid);

    /* Cancel the single listener */
    if (dht_ctx && ctx->listen_token != 0) {
        dht_cancel_listen(dht_ctx, ctx->listen_token);
        ctx->listen_token = 0;
    }

    /* Free context */
    free(ctx);
}

int dna_group_outbox_check_day_rotation(
    dht_context_t *dht_ctx,
    dna_group_listen_ctx_t *ctx
) {
    if (!dht_ctx || !ctx) {
        return -1;
    }

    uint64_t new_day = dna_group_outbox_get_day_bucket();

    if (new_day == ctx->current_day) {
        return 0;  /* No change */
    }

    QGP_LOG_INFO(LOG_TAG, "Day rotation: %lu -> %lu for group %s\n",
                 (unsigned long)ctx->current_day, (unsigned long)new_day,
                 ctx->group_uuid);

    /* Cancel old listener */
    if (ctx->listen_token != 0) {
        dht_cancel_listen(dht_ctx, ctx->listen_token);
        ctx->listen_token = 0;
    }

    /* Update day and context */
    ctx->current_day = new_day;
    ctx->dht_ctx = dht_ctx;

    /* Resubscribe for new day */
    if (subscribe_to_group_key(ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to resubscribe group %s for day %lu\n",
                      ctx->group_uuid, (unsigned long)new_day);
        return -1;
    }

    return 1;  /* Rotated */
}
