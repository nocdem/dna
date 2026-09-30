/**
 * @file offline_queue_codec.c
 * @brief Offline-message blob codec + ACK key derivation — codec unit
 *
 * NC-1 (Web Connect design rev 5 §1.3, operator decision 2026-09-30 Q2 = a):
 * moved verbatim out of dht/shared/dht_offline_queue.c (which also does the
 * DHT puts/gets and ACK listeners) so the native library and the web thin
 * core compile the same code. Declarations stay in dht_offline_queue.h.
 * No network I/O, no database.
 */

#include "dht/shared/dht_offline_queue.h"
#include "crypto/hash/qgp_sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "crypto/utils/qgp_log.h"
#include "messenger/messages.h"  /* DNA_MESSAGE_MAX_CIPHERTEXT_SIZE */

#define LOG_TAG "DHT_OFFLINE"

/* M6: Maximum messages per outbox (DoS prevention) */
#define DHT_OFFLINE_MAX_MESSAGES_PER_OUTBOX 1000

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Linux
#endif

/**
 * Free a single offline message
 */
void dht_offline_message_free(dht_offline_message_t *msg) {
    if (!msg) return;

    if (msg->sender) {
        free(msg->sender);
        msg->sender = NULL;
    }
    if (msg->recipient) {
        free(msg->recipient);
        msg->recipient = NULL;
    }
    if (msg->ciphertext) {
        free(msg->ciphertext);
        msg->ciphertext = NULL;
    }
}

/**
 * Free array of offline messages
 */
void dht_offline_messages_free(dht_offline_message_t *messages, size_t count) {
    if (!messages) return;

    for (size_t i = 0; i < count; i++) {
        dht_offline_message_free(&messages[i]);
    }
    free(messages);
}

/**
 * Serialize message array to binary format (v2)
 *
 * Format:
 * [4-byte count (network order)]
 * For each message:
 *   [4-byte magic (network order)]
 *   [1-byte version]
 *   [8-byte seq_num (network order)] - NEW in v2
 *   [8-byte timestamp (network order)]
 *   [8-byte expiry (network order)]
 *   [2-byte sender_len (network order)]
 *   [2-byte recipient_len (network order)]
 *   [4-byte ciphertext_len (network order)]
 *   [sender string (variable length)]
 *   [recipient string (variable length)]
 *   [ciphertext bytes (variable length)]
 */
int dht_serialize_messages(
    const dht_offline_message_t *messages,
    size_t count,
    uint8_t **serialized_out,
    size_t *len_out)
{
    if (!messages && count > 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for serialization\n");
        return -1;
    }

    // Calculate total size
    size_t total_size = sizeof(uint32_t);  // Message count

    for (size_t i = 0; i < count; i++) {
        total_size += sizeof(uint32_t);  // magic
        total_size += 1;                  // version
        total_size += sizeof(uint64_t);  // seq_num (v2)
        total_size += sizeof(uint64_t);  // timestamp
        total_size += sizeof(uint64_t);  // expiry
        total_size += sizeof(uint16_t);  // sender_len
        total_size += sizeof(uint16_t);  // recipient_len
        total_size += sizeof(uint32_t);  // ciphertext_len
        total_size += strlen(messages[i].sender);
        total_size += strlen(messages[i].recipient);
        total_size += messages[i].ciphertext_len;
    }

    // Allocate buffer
    uint8_t *buffer = (uint8_t*)malloc(total_size);
    if (!buffer) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate %zu bytes for serialization\n", total_size);
        return -1;
    }

    uint8_t *ptr = buffer;

    // Write message count
    uint32_t count_network = htonl((uint32_t)count);
    memcpy(ptr, &count_network, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    // Write each message
    for (size_t i = 0; i < count; i++) {
        const dht_offline_message_t *msg = &messages[i];

        // Magic
        uint32_t magic_network = htonl(DHT_OFFLINE_QUEUE_MAGIC);
        memcpy(ptr, &magic_network, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Version
        *ptr++ = DHT_OFFLINE_QUEUE_VERSION;

        // Seq_num (8 bytes, split into 2x4 bytes for network order) - v2
        uint32_t seq_high = htonl((uint32_t)(msg->seq_num >> 32));
        uint32_t seq_low = htonl((uint32_t)(msg->seq_num & 0xFFFFFFFF));
        memcpy(ptr, &seq_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &seq_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Timestamp (8 bytes, split into 2x4 bytes for network order)
        uint32_t ts_high = htonl((uint32_t)(msg->timestamp >> 32));
        uint32_t ts_low = htonl((uint32_t)(msg->timestamp & 0xFFFFFFFF));
        memcpy(ptr, &ts_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &ts_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Expiry (8 bytes, split into 2x4 bytes for network order)
        uint32_t exp_high = htonl((uint32_t)(msg->expiry >> 32));
        uint32_t exp_low = htonl((uint32_t)(msg->expiry & 0xFFFFFFFF));
        memcpy(ptr, &exp_high, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &exp_low, sizeof(uint32_t));
        ptr += sizeof(uint32_t);

        // Sender length and string
        uint16_t sender_len = (uint16_t)strlen(msg->sender);
        uint16_t sender_len_network = htons(sender_len);
        memcpy(ptr, &sender_len_network, sizeof(uint16_t));
        ptr += sizeof(uint16_t);
        memcpy(ptr, msg->sender, sender_len);
        ptr += sender_len;

        // Recipient length and string
        uint16_t recipient_len = (uint16_t)strlen(msg->recipient);
        uint16_t recipient_len_network = htons(recipient_len);
        memcpy(ptr, &recipient_len_network, sizeof(uint16_t));
        ptr += sizeof(uint16_t);
        memcpy(ptr, msg->recipient, recipient_len);
        ptr += recipient_len;

        // Ciphertext length and data
        uint32_t ciphertext_len_network = htonl((uint32_t)msg->ciphertext_len);
        memcpy(ptr, &ciphertext_len_network, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, msg->ciphertext, msg->ciphertext_len);
        ptr += msg->ciphertext_len;
    }

    *serialized_out = buffer;
    *len_out = total_size;

    return 0;
}

/**
 * Deserialize message array from binary format
 */
int dht_deserialize_messages(
    const uint8_t *data,
    size_t len,
    dht_offline_message_t **messages_out,
    size_t *count_out)
{
    if (!data || len < sizeof(uint32_t)) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid data for deserialization\n");
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    // Read message count
    if (ptr + sizeof(uint32_t) > end) {
        QGP_LOG_ERROR(LOG_TAG, "Truncated data (count)\n");
        return -1;
    }
    uint32_t count_network;
    memcpy(&count_network, ptr, sizeof(uint32_t));
    uint32_t count = ntohl(count_network);
    ptr += sizeof(uint32_t);

    if (count == 0) {
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // M6: Sanity check message count (DoS prevention)
    if (count > DHT_OFFLINE_MAX_MESSAGES_PER_OUTBOX) {
        QGP_LOG_ERROR(LOG_TAG, "Too many messages in outbox: %u (max %d)\n",
                      count, DHT_OFFLINE_MAX_MESSAGES_PER_OUTBOX);
        return -1;
    }

    // Allocate message array
    dht_offline_message_t *messages = (dht_offline_message_t*)calloc(count, sizeof(dht_offline_message_t));
    if (!messages) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate message array\n");
        return -1;
    }

    // Read each message
    for (uint32_t i = 0; i < count; i++) {
        dht_offline_message_t *msg = &messages[i];

        // Magic
        if (ptr + sizeof(uint32_t) > end) goto truncated;
        uint32_t magic_network;
        memcpy(&magic_network, ptr, sizeof(uint32_t));
        uint32_t magic = ntohl(magic_network);
        if (magic != DHT_OFFLINE_QUEUE_MAGIC) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid magic bytes: 0x%08X\n", magic);
            goto error;
        }
        ptr += sizeof(uint32_t);

        // Version (support v1 and v2)
        if (ptr + 1 > end) goto truncated;
        uint8_t version = *ptr++;
        if (version != 1 && version != 2) {
            QGP_LOG_ERROR(LOG_TAG, "Unsupported version: %u (expected 1 or 2)\n", version);
            goto error;
        }

        // Seq_num (8 bytes) - v2 only, v1 gets seq_num=0
        if (version >= 2) {
            if (ptr + 2 * sizeof(uint32_t) > end) goto truncated;
            uint32_t seq_high, seq_low;
            memcpy(&seq_high, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(&seq_low, ptr, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            msg->seq_num = ((uint64_t)ntohl(seq_high) << 32) | ntohl(seq_low);
        } else {
            // v1: no seq_num field, treat as oldest (will be pruned first)
            msg->seq_num = 0;
            QGP_LOG_INFO(LOG_TAG, "Reading v1 message (seq_num=0, legacy compat)\n");
        }

        // Timestamp (8 bytes from 2x4 bytes)
        if (ptr + 2 * sizeof(uint32_t) > end) goto truncated;
        uint32_t ts_high, ts_low;
        memcpy(&ts_high, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(&ts_low, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        msg->timestamp = ((uint64_t)ntohl(ts_high) << 32) | ntohl(ts_low);

        // Expiry (8 bytes from 2x4 bytes)
        if (ptr + 2 * sizeof(uint32_t) > end) goto truncated;
        uint32_t exp_high, exp_low;
        memcpy(&exp_high, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(&exp_low, ptr, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        msg->expiry = ((uint64_t)ntohl(exp_high) << 32) | ntohl(exp_low);

        // Sender length and string
        if (ptr + sizeof(uint16_t) > end) goto truncated;
        uint16_t sender_len_network;
        memcpy(&sender_len_network, ptr, sizeof(uint16_t));
        uint16_t sender_len = ntohs(sender_len_network);
        ptr += sizeof(uint16_t);

        if (ptr + sender_len > end) goto truncated;
        msg->sender = (char*)malloc(sender_len + 1);
        if (!msg->sender) goto error;
        memcpy(msg->sender, ptr, sender_len);
        msg->sender[sender_len] = '\0';
        ptr += sender_len;

        // Recipient length and string
        if (ptr + sizeof(uint16_t) > end) goto truncated;
        uint16_t recipient_len_network;
        memcpy(&recipient_len_network, ptr, sizeof(uint16_t));
        uint16_t recipient_len = ntohs(recipient_len_network);
        ptr += sizeof(uint16_t);

        if (ptr + recipient_len > end) goto truncated;
        msg->recipient = (char*)malloc(recipient_len + 1);
        if (!msg->recipient) goto error;
        memcpy(msg->recipient, ptr, recipient_len);
        msg->recipient[recipient_len] = '\0';
        ptr += recipient_len;

        // Ciphertext length and data
        if (ptr + sizeof(uint32_t) > end) goto truncated;
        uint32_t ciphertext_len_network;
        memcpy(&ciphertext_len_network, ptr, sizeof(uint32_t));
        msg->ciphertext_len = (size_t)ntohl(ciphertext_len_network);
        ptr += sizeof(uint32_t);

        // M6: Sanity check ciphertext size (DoS prevention)
        if (msg->ciphertext_len > DNA_MESSAGE_MAX_CIPHERTEXT_SIZE) {
            QGP_LOG_ERROR(LOG_TAG, "Ciphertext too large: %zu bytes (max %d)\n",
                          msg->ciphertext_len, DNA_MESSAGE_MAX_CIPHERTEXT_SIZE);
            goto error;
        }

        if (ptr + msg->ciphertext_len > end) goto truncated;
        msg->ciphertext = (uint8_t*)malloc(msg->ciphertext_len);
        if (!msg->ciphertext) goto error;
        memcpy(msg->ciphertext, ptr, msg->ciphertext_len);
        ptr += msg->ciphertext_len;
    }

    *messages_out = messages;
    *count_out = count;
    return 0;

truncated:
    QGP_LOG_ERROR(LOG_TAG, "Truncated message data\n");
error:
    dht_offline_messages_free(messages, count);
    return -1;
}

/**
 * Generate base key for ACK storage
 * Key format: recipient + ":ack:" + sender + ":" + SALT_HEX
 *
 * CORE-04 (phase 6, plan 05): salt is REQUIRED. The legacy unsalted fallback
 * was removed to prevent deterministic ACK keys from leaking sender/recipient
 * communication metadata. Returns -1 if salt is NULL.
 */
static int make_ack_base_key(const char *recipient, const char *sender,
                              const uint8_t *salt,
                              char *key_out, size_t key_out_size) {
    if (!recipient || !sender || !key_out || key_out_size == 0) {
        return -1;
    }
    if (!salt) {
        QGP_LOG_ERROR(LOG_TAG,
            "make_ack_base_key: salt is required (NULL passed) "
            "- refusing to produce unsalted ACK key");
        return -1;
    }
    char salt_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(salt_hex + (i * 2), 3, "%02x", salt[i]);
    }
    salt_hex[64] = '\0';
    int written = snprintf(key_out, key_out_size, "%s:ack:%s:%s",
                           recipient, sender, salt_hex);
    if (written < 0 || (size_t)written >= key_out_size) {
        return -1;
    }
    return 0;
}

/**
 * Generate DHT key for ACK storage (SHA3-512 hash of base key).
 *
 * CORE-04: returns -1 if salt is NULL (no unsalted fallback).
 */
int dht_generate_ack_key(const char *recipient, const char *sender,
                          const uint8_t *salt, uint8_t *key_out) {
    if (!key_out) {
        return -1;
    }
    char base_key[512];
    if (make_ack_base_key(recipient, sender, salt, base_key, sizeof(base_key)) != 0) {
        return -1;
    }
    qgp_sha3_512((const uint8_t*)base_key, strlen(base_key), key_out);
    return 0;
}
