#include "dht_offline_queue.h"
#include "dht_dm_outbox.h"  /* Daily bucket messaging (v0.4.81+) */
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"  /* qgp_platform_sleep_ms */
#include "messenger/messages.h"  /* DNA_MESSAGE_MAX_CIPHERTEXT_SIZE */

#define LOG_TAG "DHT_OFFLINE"

/* M6: Maximum messages per outbox (DoS prevention) */
#define DHT_OFFLINE_MAX_MESSAGES_PER_OUTBOX 1000

// Mutex to serialize DHT queue read-modify-write operations
// Prevents race conditions when sending multiple messages quickly
static pthread_mutex_t g_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// LOCAL OUTBOX CACHE
// ============================================================================
// Caches outbox messages in memory to avoid network fetch on every send.
// Protected by g_queue_mutex. Entries expire after 60 seconds.

#define OUTBOX_CACHE_MAX_ENTRIES 32
#define OUTBOX_CACHE_TTL_SECONDS 60

typedef struct {
    char base_key[512];                  // Outbox key (sender:outbox:recipient)
    dht_offline_message_t *messages;     // Cached messages (owned)
    size_t count;                        // Number of messages
    time_t last_update;                  // When cache was last updated
    bool valid;                          // True if entry is in use
    bool needs_dht_sync;                 // True if failed to publish, needs retry
} outbox_cache_entry_t;

/* g_outbox_cache is zero-initialized at load time (static storage). All live
 * access happens inside dht_offline_queue_sync_pending which holds
 * g_queue_mutex (see CONCURRENCY.md L4). Phase 02-04 deleted four dead
 * helper functions (outbox_cache_init / outbox_cache_find / outbox_cache_store
 * / outbox_cache_store_ex) per CLAUDE.md No Dead Code rule — they had zero
 * callers anywhere in the codebase. */
static outbox_cache_entry_t g_outbox_cache[OUTBOX_CACHE_MAX_ENTRIES];

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Linux
#endif

/*
 * CORE-04 (phase 6, plan 06): Removed legacy unsalted outbox-key helpers
 * (make_outbox_base_key, dht_generate_outbox_key) along with the unsalted
 * retrieval paths (dht_retrieve_queued_messages_from_contacts[_parallel]).
 * Per CLAUDE.md "No Dead Code" rule, these had zero non-doc callers and
 * represented a re-introduction risk for deterministic outbox keys that
 * leak sender×recipient communication metadata. The salted DM outbox
 * (dht_dm_outbox.c) is the sole remaining producer/consumer of outbox keys.
 */

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
 * Store encrypted message in DHT for offline recipient
 *
 * v0.4.81+: Redirects to daily bucket API (dht_dm_queue_message).
 * No watermark pruning - TTL handles cleanup automatically.
 */
int dht_queue_message(
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds,
    const uint8_t *salt)
{
    /* v0.4.81: Redirect to daily bucket API */
    QGP_LOG_DEBUG(LOG_TAG, "Redirecting to daily bucket API (v0.4.81+)");
    return dht_dm_queue_message(sender, recipient, ciphertext,
                                 ciphertext_len, seq_num, ttl_seconds, salt);
}

/*
 * CORE-04 (phase 6, plan 06): Removed dead functions
 * dht_retrieve_queued_messages_from_contacts and
 * dht_retrieve_queued_messages_from_contacts_parallel. Both produced
 * deterministic unsalted outbox keys (sender:outbox:recipient) and had zero
 * callers anywhere in messenger/, dnac/, or nodus/ (only docstring mentions).
 * The live DM retrieval path is dht_dm_outbox.c with per-contact salts.
 *
 * REMOVED: dht_clear_queue() - No longer needed in Spillway Protocol.
 * In sender-based outbox model, recipients don't control sender outboxes;
 * senders manage their own outboxes and recipients are read-only.
 */

/**
 * ============================================================================
 * SIMPLE ACK API IMPLEMENTATION (v15: Replaced Watermarks)
 * ============================================================================
 * Simple per-contact ACK tracking. Recipients publish a timestamp when they
 * fetch messages. Senders mark ALL messages to that contact as RECEIVED.
 * Much simpler than watermarks: no per-message sequence number tracking!
 */

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

/**
 * Publish ACK after fetching messages (blocking)
 *
 * Called by recipient after fetching messages from a sender's outbox.
 * Publishes current timestamp to notify sender of delivery.
 *
 * @param ctx DHT context
 * @param my_fp My fingerprint (ACK owner - the recipient)
 * @param sender_fp Sender fingerprint (whose messages I fetched)
 * @return 0 on success, -1 on failure
 */
int dht_publish_ack(const char *my_fp,
                    const char *sender_fp,
                    const uint8_t *salt) {
    if (!my_fp || !sender_fp) {
        return -1;
    }

    // Generate ACK key (CORE-04: salt is required, returns -1 if NULL)
    uint8_t key[64];
    if (dht_generate_ack_key(my_fp, sender_fp, salt, key) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "[ACK-PUT] Refusing to publish ACK without per-contact salt "
            "(%.20s... -> %.20s...)", my_fp, sender_fp);
        return -1;
    }

    // Get current timestamp
    uint64_t timestamp = (uint64_t)time(NULL);

    // Serialize timestamp to 8 bytes big-endian
    uint8_t value[8];
    value[0] = (uint8_t)(timestamp >> 56);
    value[1] = (uint8_t)(timestamp >> 48);
    value[2] = (uint8_t)(timestamp >> 40);
    value[3] = (uint8_t)(timestamp >> 32);
    value[4] = (uint8_t)(timestamp >> 24);
    value[5] = (uint8_t)(timestamp >> 16);
    value[6] = (uint8_t)(timestamp >> 8);
    value[7] = (uint8_t)(timestamp);

    // Publish ACK via nodus (synchronous - blocks until server responds)
    int result = nodus_ops_put(key, 64,
                                value, sizeof(value),
                                DHT_ACK_TTL,
                                1);  // value_id=1 for replacement

    if (result == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "[ACK-PUT] Published: %.20s... -> %.20s... ts=%lu\n",
               my_fp, sender_fp, (unsigned long)timestamp);
    } else {
        QGP_LOG_WARN(LOG_TAG, "[ACK-PUT] FAILED: %.20s... -> %.20s... (result=%d)\n",
               my_fp, sender_fp, result);
    }
    return result;
}

/**
 * ============================================================================
 * ACK LISTENER IMPLEMENTATION (Delivery Confirmation)
 * ============================================================================
 */

/**
 * Internal context for ACK listener callback
 */
typedef struct {
    char sender[129];                 // My fingerprint (I sent messages)
    char recipient[129];              // Contact fingerprint (they received)
    dht_ack_callback_t user_cb;       // User's callback
    void *user_data;                  // User's context
} ack_listener_ctx_t;

/**
 * Internal DHT listen callback for ACK updates
 * Parses the 8-byte big-endian timestamp and invokes user callback
 */
static bool ack_listen_callback(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
) {
    ack_listener_ctx_t *ctx = (ack_listener_ctx_t *)user_data;
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK-LISTEN] NULL context received!\n");
        return false;  // Stop listening
    }

    // Validate context integrity
    if (ctx->sender[0] == '\0' ||
        !((ctx->sender[0] >= '0' && ctx->sender[0] <= '9') ||
          (ctx->sender[0] >= 'a' && ctx->sender[0] <= 'f') ||
          (ctx->sender[0] >= 'A' && ctx->sender[0] <= 'F'))) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK-LISTEN] CORRUPTED CONTEXT! ctx=%p sender[0]=0x%02x\n",
                      (void*)ctx, (unsigned char)ctx->sender[0]);
        return true;  // Keep listening but skip processing
    }

    // Ignore expiration notifications
    if (expired || !value) {
        QGP_LOG_DEBUG(LOG_TAG, "[ACK] Expired: %.20s... -> %.20s...\n",
               ctx->recipient, ctx->sender);
        return true;  // Keep listening
    }

    // Parse 8-byte big-endian timestamp
    if (value_len != 8) {
        QGP_LOG_WARN(LOG_TAG, "[ACK] Invalid value size: %zu (expected 8)\n", value_len);
        return true;  // Keep listening
    }

    uint64_t ack_ts = ((uint64_t)value[0] << 56) |
                      ((uint64_t)value[1] << 48) |
                      ((uint64_t)value[2] << 40) |
                      ((uint64_t)value[3] << 32) |
                      ((uint64_t)value[4] << 24) |
                      ((uint64_t)value[5] << 16) |
                      ((uint64_t)value[6] << 8) |
                      ((uint64_t)value[7]);

    QGP_LOG_INFO(LOG_TAG, "[ACK-LISTEN] Received: %.20s... -> %.20s... ts=%lu\n",
           ctx->recipient, ctx->sender, (unsigned long)ack_ts);

    // Invoke user callback (triggers RECEIVED status update)
    if (ctx->user_cb) {
        ctx->user_cb(ctx->sender, ctx->recipient, ack_ts, ctx->user_data);
    }

    return true;  // Keep listening
}

/**
 * Cleanup callback for ACK listener
 */
static void ack_listener_cleanup(void *user_data) {
    ack_listener_ctx_t *actx = (ack_listener_ctx_t *)user_data;
    if (actx) {
        QGP_LOG_DEBUG(LOG_TAG, "[ACK] Cleanup: freeing context for %.20s... -> %.20s...\n",
                      actx->recipient, actx->sender);
        free(actx);
    }
}

/**
 * Listen for ACK updates from a recipient
 */
size_t dht_listen_ack(
    const char *my_fp,
    const char *recipient_fp,
    const uint8_t *salt,
    dht_ack_callback_t callback,
    void *user_data
) {
    if (!my_fp || !recipient_fp || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Invalid parameters for listener\n");
        return 0;
    }

    // Validate fingerprint lengths
    size_t my_len = strlen(my_fp);
    size_t recip_len = strlen(recipient_fp);
    if (my_len != 128 || recip_len != 128) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Invalid fingerprint length: my=%zu recipient=%zu (expected 128)\n",
                      my_len, recip_len);
        return 0;
    }

    // Allocate listener context
    ack_listener_ctx_t *actx = (ack_listener_ctx_t *)calloc(1, sizeof(ack_listener_ctx_t));
    if (!actx) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Failed to allocate listener context\n");
        return 0;
    }

    strncpy(actx->sender, my_fp, sizeof(actx->sender) - 1);
    actx->sender[sizeof(actx->sender) - 1] = '\0';
    strncpy(actx->recipient, recipient_fp, sizeof(actx->recipient) - 1);
    actx->recipient[sizeof(actx->recipient) - 1] = '\0';
    actx->user_cb = callback;
    actx->user_data = user_data;

    // Generate ACK key: SHA3-512(recipient + ":ack:" + sender + ":" + SALT_HEX)
    // CORE-04: salt is required — refuse to start an unsalted listener.
    uint8_t key[64];
    if (dht_generate_ack_key(recipient_fp, my_fp, salt, key) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "[ACK] Refusing to start listener without per-contact salt "
            "(%.20s... -> %.20s...)", recipient_fp, my_fp);
        free(actx);
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "[ACK] Starting listener: %.20s... -> %.20s...\n",
           recipient_fp, my_fp);

    // Start listening via nodus
    size_t token = nodus_ops_listen(key, 64, ack_listen_callback, actx, ack_listener_cleanup);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Failed to start nodus listener\n");
        free(actx);  // Clean up allocated context on failure
        return 0;
    }

    /* v0.9.1: Initial pull — fetch existing ACK value from DHT.
     * The listener only catches NEW puts after registration. */
    {
        uint8_t *ack_data = NULL;
        size_t ack_len = 0;
        if (nodus_ops_get(key, 64, &ack_data, &ack_len) == 0 && ack_data && ack_len == 8) {
            QGP_LOG_INFO(LOG_TAG, "[ACK] Initial pull: found existing ACK for %.20s...\n", recipient_fp);
            ack_listen_callback(ack_data, ack_len, false, actx);
        }
        if (ack_data) free(ack_data);
    }

    return token;
}

/**
 * Cancel ACK listener
 */
void dht_cancel_ack_listener(
    size_t token
) {
    if (token == 0) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "[ACK] Cancelling listener (token=%zu)\n", token);
    nodus_ops_cancel_listen(token);
}

/**
 * Sync pending outbox caches to DHT
 *
 * Iterates all cached outboxes that failed to publish (needs_dht_sync=true)
 * and attempts to republish them. Call this when DHT becomes ready.
 *
 * @param ctx DHT context
 * @return Number of entries successfully synced
 */
int dht_offline_queue_sync_pending(void) {

    /* CONCURRENCY.md L4: g_queue_mutex protects g_outbox_cache[]. After the
     * Phase 02-04 dead-code removal, this is the only live access path to
     * the cache array. g_outbox_cache is zero-initialized at load time, so
     * no explicit init is required. */
    pthread_mutex_lock(&g_queue_mutex);

    int synced = 0;
    int pending = 0;

    for (int i = 0; i < OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (!g_outbox_cache[i].valid || !g_outbox_cache[i].needs_dht_sync) {
            continue;
        }

        pending++;
        outbox_cache_entry_t *entry = &g_outbox_cache[i];

        QGP_LOG_INFO(LOG_TAG, "Syncing pending outbox: %s (%zu messages)\n",
                     entry->base_key, entry->count);

        // Serialize messages
        uint8_t *serialized = NULL;
        size_t serialized_len = 0;
        if (dht_serialize_messages(entry->messages, entry->count, &serialized, &serialized_len) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to serialize pending outbox\n");
            continue;
        }

        // Try to publish via nodus
        int result = nodus_ops_put_str(entry->base_key, serialized, serialized_len,
                                        7 * 24 * 3600, nodus_ops_value_id());
        free(serialized);

        if (result == 0) {
            entry->needs_dht_sync = false;
            synced++;
            QGP_LOG_INFO(LOG_TAG, "Successfully synced pending outbox\n");
        } else {
            QGP_LOG_WARN(LOG_TAG, "Still failed to sync outbox (result=%d)\n", result);
        }
    }

    pthread_mutex_unlock(&g_queue_mutex);

    if (pending > 0) {
        QGP_LOG_INFO(LOG_TAG, "Synced %d/%d pending outboxes\n", synced, pending);
    }

    return synced;
}
