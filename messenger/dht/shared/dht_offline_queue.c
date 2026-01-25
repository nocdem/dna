#include "dht_offline_queue.h"
#include "dht_dm_outbox.h"  /* Daily bucket messaging (v0.4.81+) */
#include "dht_chunked.h"
#include "../core/dht_listen.h"
#include "../crypto/utils/qgp_sha3.h"
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

static outbox_cache_entry_t g_outbox_cache[OUTBOX_CACHE_MAX_ENTRIES];
static bool g_cache_initialized = false;

static void outbox_cache_init(void) {
    if (g_cache_initialized) return;
    memset(g_outbox_cache, 0, sizeof(g_outbox_cache));
    g_cache_initialized = true;
}

// Find cache entry for key (returns NULL if not found or expired)
static outbox_cache_entry_t *outbox_cache_find(const char *base_key) {
    outbox_cache_init();
    time_t now = time(NULL);

    for (int i = 0; i < OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_outbox_cache[i].valid &&
            strcmp(g_outbox_cache[i].base_key, base_key) == 0) {
            // Check if expired
            if (now - g_outbox_cache[i].last_update > OUTBOX_CACHE_TTL_SECONDS) {
                // Expired - invalidate and return NULL
                if (g_outbox_cache[i].messages) {
                    dht_offline_messages_free(g_outbox_cache[i].messages, g_outbox_cache[i].count);
                }
                g_outbox_cache[i].valid = false;
                return NULL;
            }
            return &g_outbox_cache[i];
        }
    }
    return NULL;
}

// Store messages in cache (takes ownership of messages array)
// needs_sync: true if DHT publish failed, entry needs retry
static void outbox_cache_store_ex(const char *base_key, dht_offline_message_t *messages, size_t count, bool needs_sync) {
    outbox_cache_init();

    // Find existing entry or empty slot
    outbox_cache_entry_t *entry = NULL;
    int oldest_idx = 0;
    time_t oldest_time = time(NULL);

    for (int i = 0; i < OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_outbox_cache[i].valid && strcmp(g_outbox_cache[i].base_key, base_key) == 0) {
            // Found existing - free old data
            if (g_outbox_cache[i].messages) {
                dht_offline_messages_free(g_outbox_cache[i].messages, g_outbox_cache[i].count);
            }
            entry = &g_outbox_cache[i];
            break;
        }
        if (!g_outbox_cache[i].valid) {
            entry = &g_outbox_cache[i];
            break;
        }
        if (g_outbox_cache[i].last_update < oldest_time) {
            oldest_time = g_outbox_cache[i].last_update;
            oldest_idx = i;
        }
    }

    // If no slot found, evict oldest
    if (!entry) {
        entry = &g_outbox_cache[oldest_idx];
        if (entry->messages) {
            dht_offline_messages_free(entry->messages, entry->count);
        }
    }

    strncpy(entry->base_key, base_key, sizeof(entry->base_key) - 1);
    entry->base_key[sizeof(entry->base_key) - 1] = '\0';
    entry->messages = messages;
    entry->count = count;
    entry->last_update = time(NULL);
    entry->valid = true;
    entry->needs_dht_sync = needs_sync;
}

// Wrapper for backward compatibility
static void outbox_cache_store(const char *base_key, dht_offline_message_t *messages, size_t count) {
    outbox_cache_store_ex(base_key, messages, count, false);
}

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Linux
#endif

/**
 * Generate base key for sender's outbox to recipient (Spillway)
 * Chunked layer handles hashing internally
 *
 * Key format: sender + ":outbox:" + recipient
 * Example: "alice_fp:outbox:bob_fp"
 */
static void make_outbox_base_key(const char *sender, const char *recipient, char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:outbox:%s", sender, recipient);
}

/**
 * Legacy function - kept for API compatibility but now just creates base key
 * @deprecated Use make_outbox_base_key instead
 */
void dht_generate_outbox_key(const char *sender, const char *recipient, uint8_t *key_out) {
    // For backward compatibility, fill with SHA3-512 hash of base key
    char base_key[512];
    make_outbox_base_key(sender, recipient, base_key, sizeof(base_key));
    qgp_sha3_512((const uint8_t*)base_key, strlen(base_key), key_out);
}

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
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds)
{
    /*
     * v0.4.81: Redirect to daily bucket API
     *
     * Old behavior (removed):
     * - Watermark fetch + pruning (lines 515-617)
     * - Static key: sender:outbox:recipient
     *
     * New behavior:
     * - Daily bucket key: sender:outbox:recipient:DAY
     * - No watermark pruning (TTL auto-expire)
     * - Watermark still used for delivery reports (separate API)
     */
    QGP_LOG_DEBUG(LOG_TAG, "Redirecting to daily bucket API (v0.4.81+)");
    return dht_dm_queue_message(ctx, sender, recipient, ciphertext,
                                 ciphertext_len, seq_num, ttl_seconds);
}

/**
 * Retrieve all queued messages for recipient from all contacts' outboxes (Spillway)
 *
 * Queries each sender's outbox (SHA3-512(sender + ":outbox:" + recipient))
 * and accumulates all messages from all senders.
 */
int dht_retrieve_queued_messages_from_contacts(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out)
{
    if (!ctx || !recipient || !sender_list || sender_count == 0 || !messages_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for retrieval\n");
        return -1;
    }

    struct timespec function_start;
    clock_gettime(CLOCK_MONOTONIC, &function_start);

    QGP_LOG_INFO(LOG_TAG, "Retrieving queued messages for %s from %zu contacts\n", recipient, sender_count);

    // Allocate temporary array to accumulate messages from all senders
    dht_offline_message_t *all_messages = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;

    uint64_t now = (uint64_t)time(NULL);

    // Iterate through all senders (contacts)
    for (size_t contact_idx = 0; contact_idx < sender_count; contact_idx++) {
        struct timespec loop_start, dht_get_start, deserialize_start;
        clock_gettime(CLOCK_MONOTONIC, &loop_start);

        const char *sender = sender_list[contact_idx];

        // Generate sender's outbox base key to us
        char outbox_base_key[512];
        make_outbox_base_key(sender, recipient, outbox_base_key, sizeof(outbox_base_key));

        QGP_LOG_INFO(LOG_TAG, "[%zu/%zu] Checking sender %.20s... outbox\n",
               contact_idx + 1, sender_count, sender);

        // Query DHT for this sender's outbox via chunked layer
        uint8_t *outbox_data = NULL;
        size_t outbox_len = 0;

        clock_gettime(CLOCK_MONOTONIC, &dht_get_start);
        int get_result = dht_chunked_fetch(ctx, outbox_base_key, &outbox_data, &outbox_len);
        struct timespec dht_get_end;
        clock_gettime(CLOCK_MONOTONIC, &dht_get_end);
        long dht_get_ms = (dht_get_end.tv_sec - dht_get_start.tv_sec) * 1000 +
                          (dht_get_end.tv_nsec - dht_get_start.tv_nsec) / 1000000;

        if (get_result != DHT_CHUNK_OK || !outbox_data || outbox_len == 0) {
            // No messages from this sender (outbox empty or doesn't exist)
            QGP_LOG_INFO(LOG_TAG, "✗ No messages (chunked_fetch took %ld ms)\n", dht_get_ms);
            continue;
        }

        QGP_LOG_INFO(LOG_TAG, "✓ Found outbox (%zu bytes, chunked_fetch took %ld ms)\n", outbox_len, dht_get_ms);

        // Deserialize messages from this sender's outbox
        dht_offline_message_t *sender_messages = NULL;
        size_t sender_count_msgs = 0;

        clock_gettime(CLOCK_MONOTONIC, &deserialize_start);
        if (dht_deserialize_messages(outbox_data, outbox_len, &sender_messages, &sender_count_msgs) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "✗ Failed to deserialize sender's outbox\n");
            free(outbox_data);
            continue;
        }

        free(outbox_data);
        struct timespec deserialize_end;
        clock_gettime(CLOCK_MONOTONIC, &deserialize_end);
        long deserialize_ms = (deserialize_end.tv_sec - deserialize_start.tv_sec) * 1000 +
                              (deserialize_end.tv_nsec - deserialize_start.tv_nsec) / 1000000;

        QGP_LOG_INFO(LOG_TAG, "Deserialized %zu message(s) from this sender (took %ld ms)\n",
               sender_count_msgs, deserialize_ms);

        // Filter out expired messages and append valid ones to all_messages
        for (size_t i = 0; i < sender_count_msgs; i++) {
            if (sender_messages[i].expiry >= now) {
                // Valid message - add to combined array
                if (all_count >= all_capacity) {
                    // Grow array (double capacity, min 16)
                    size_t new_capacity = (all_capacity == 0) ? 16 : (all_capacity * 2);
                    dht_offline_message_t *new_array = (dht_offline_message_t*)realloc(
                        all_messages, new_capacity * sizeof(dht_offline_message_t));
                    if (!new_array) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to grow message array\n");
                        dht_offline_messages_free(all_messages, all_count);
                        dht_offline_messages_free(sender_messages, sender_count_msgs);
                        return -1;
                    }
                    all_messages = new_array;
                    all_capacity = new_capacity;
                }

                // Copy message to combined array (transfer ownership)
                all_messages[all_count++] = sender_messages[i];
            } else {
                // Expired message - free it
                QGP_LOG_INFO(LOG_TAG, "Message %zu expired (expiry=%llu, now=%llu)\n",
                       i, (unsigned long long)sender_messages[i].expiry, (unsigned long long)now);
                dht_offline_message_free(&sender_messages[i]);
            }
        }

        // Free sender_messages array (contents transferred or freed)
        free(sender_messages);
    }

    struct timespec function_end;
    clock_gettime(CLOCK_MONOTONIC, &function_end);
    long total_ms = (function_end.tv_sec - function_start.tv_sec) * 1000 +
                    (function_end.tv_nsec - function_start.tv_nsec) / 1000000;
    long avg_ms_per_contact = sender_count > 0 ? total_ms / sender_count : 0;

    QGP_LOG_INFO(LOG_TAG, "✓ Retrieved %zu valid messages from %zu contacts (total: %ld ms, avg per contact: %ld ms)\n",
           all_count, sender_count, total_ms, avg_ms_per_contact);

    *messages_out = all_messages;
    *count_out = all_count;
    return 0;
}

/**
 * REMOVED: dht_clear_queue() - No longer needed in Spillway Protocol
 *
 * In sender-based outbox model:
 * - Recipients don't control sender outboxes (can't clear them)
 * - Senders manage their own outboxes
 * - Recipients only retrieve messages (read-only operation)
 * - No need for recipient-side clearing
 */

/**
 * ============================================================================
 * PARALLEL MESSAGE RETRIEVAL (BATCH API)
 * ============================================================================
 * Uses dht_chunked_fetch_batch() to fetch all contacts' outboxes in parallel.
 * This provides 10-100x speedup compared to sequential fetching.
 *
 * Performance: 50 contacts sequential = ~12.5s, parallel = ~0.3s
 */

/**
 * Retrieve queued messages from all contacts using parallel batch fetch
 *
 * Uses the new batch API to fetch all chunk0 keys simultaneously, providing
 * massive speedup for checking offline messages from many contacts.
 */
int dht_retrieve_queued_messages_from_contacts_parallel(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out)
{
    if (!ctx || !recipient || !sender_list || sender_count == 0 || !messages_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for parallel retrieval\n");
        return -1;
    }

    struct timespec function_start;
    clock_gettime(CLOCK_MONOTONIC, &function_start);

    QGP_LOG_INFO(LOG_TAG, "PARALLEL: Retrieving queued messages for %s from %zu contacts\n",
                 recipient, sender_count);

    // Step 1: Build all outbox base keys
    char **outbox_keys = (char **)malloc(sender_count * sizeof(char *));
    if (!outbox_keys) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate outbox keys array\n");
        return -1;
    }

    for (size_t i = 0; i < sender_count; i++) {
        outbox_keys[i] = (char *)malloc(512);
        if (!outbox_keys[i]) {
            for (size_t j = 0; j < i; j++) free(outbox_keys[j]);
            free(outbox_keys);
            return -1;
        }
        make_outbox_base_key(sender_list[i], recipient, outbox_keys[i], 512);
    }

    // Step 2: Batch fetch all outboxes in parallel
    dht_chunked_batch_result_t *batch_results = NULL;
    int fetch_count = dht_chunked_fetch_batch(ctx,
                                               (const char **)outbox_keys,
                                               sender_count,
                                               &batch_results);

    // Free outbox keys (no longer needed after batch fetch)
    for (size_t i = 0; i < sender_count; i++) {
        free(outbox_keys[i]);
    }
    free(outbox_keys);

    if (fetch_count < 0 || !batch_results) {
        QGP_LOG_ERROR(LOG_TAG, "PARALLEL: Batch fetch failed\n");
        return -1;
    }

    // Step 3: Process results and accumulate messages
    dht_offline_message_t *all_messages = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;
    uint64_t now = (uint64_t)time(NULL);

    for (size_t i = 0; i < sender_count; i++) {
        if (batch_results[i].error != DHT_CHUNK_OK ||
            !batch_results[i].data || batch_results[i].data_len == 0) {
            // No messages from this sender
            continue;
        }

        QGP_LOG_INFO(LOG_TAG, "PARALLEL: [%zu/%zu] Found outbox from %.20s... (%zu bytes)\n",
                     i + 1, sender_count, sender_list[i], batch_results[i].data_len);

        // Deserialize messages from this sender's outbox
        dht_offline_message_t *sender_messages = NULL;
        size_t sender_msg_count = 0;

        if (dht_deserialize_messages(batch_results[i].data, batch_results[i].data_len,
                                     &sender_messages, &sender_msg_count) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "PARALLEL: Failed to deserialize sender's outbox\n");
            continue;
        }

        QGP_LOG_INFO(LOG_TAG, "PARALLEL: Deserialized %zu message(s) from sender\n", sender_msg_count);

        // Filter and accumulate valid messages
        for (size_t j = 0; j < sender_msg_count; j++) {
            if (sender_messages[j].expiry >= now) {
                // Valid message - add to combined array
                if (all_count >= all_capacity) {
                    size_t new_capacity = (all_capacity == 0) ? 16 : (all_capacity * 2);
                    dht_offline_message_t *new_array = (dht_offline_message_t *)realloc(
                        all_messages, new_capacity * sizeof(dht_offline_message_t));
                    if (!new_array) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to grow message array\n");
                        dht_offline_messages_free(all_messages, all_count);
                        dht_offline_messages_free(sender_messages, sender_msg_count);
                        dht_chunked_batch_results_free(batch_results, sender_count);
                        return -1;
                    }
                    all_messages = new_array;
                    all_capacity = new_capacity;
                }

                // Transfer ownership
                all_messages[all_count++] = sender_messages[j];
            } else {
                // Expired - free it
                dht_offline_message_free(&sender_messages[j]);
            }
        }

        // Free sender_messages array (contents transferred or freed)
        free(sender_messages);
    }

    // Free batch results
    dht_chunked_batch_results_free(batch_results, sender_count);

    struct timespec function_end;
    clock_gettime(CLOCK_MONOTONIC, &function_end);
    long total_ms = (function_end.tv_sec - function_start.tv_sec) * 1000 +
                    (function_end.tv_nsec - function_start.tv_nsec) / 1000000;
    long avg_ms = sender_count > 0 ? total_ms / sender_count : 0;

    QGP_LOG_INFO(LOG_TAG, "PARALLEL: Retrieved %zu messages from %zu contacts in %ld ms (avg %ld ms/contact)\n",
                 all_count, sender_count, total_ms, avg_ms);

    *messages_out = all_messages;
    *count_out = all_count;
    return 0;
}

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
 * Key format: recipient + ":ack:" + sender
 */
static void make_ack_base_key(const char *recipient, const char *sender,
                               char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "%s:ack:%s", recipient, sender);
}

/**
 * Generate DHT key for ACK storage (SHA3-512 hash of base key)
 */
void dht_generate_ack_key(const char *recipient, const char *sender,
                           uint8_t *key_out) {
    char base_key[512];
    make_ack_base_key(recipient, sender, base_key, sizeof(base_key));
    qgp_sha3_512((const uint8_t*)base_key, strlen(base_key), key_out);
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
int dht_publish_ack(dht_context_t *ctx,
                    const char *my_fp,
                    const char *sender_fp) {
    if (!ctx || !my_fp || !sender_fp) {
        return -1;
    }

    // Generate ACK key
    uint8_t key[64];
    dht_generate_ack_key(my_fp, sender_fp, key);

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

    // Retry with exponential backoff
    int max_retries = 3;
    int delay_ms = 500;
    int result = -1;

    for (int attempt = 1; attempt <= max_retries; attempt++) {
        result = dht_put_signed(ctx,
                                key, 64,
                                value, sizeof(value),
                                1,  // value_id=1 for replacement
                                DHT_ACK_TTL,
                                "ack");

        if (result == 0) {
            QGP_LOG_DEBUG(LOG_TAG, "[ACK-PUT] Published: %.20s... -> %.20s... ts=%lu (attempt %d)\n",
                   my_fp, sender_fp, (unsigned long)timestamp, attempt);
            return 0;
        }

        if (attempt < max_retries) {
            QGP_LOG_WARN(LOG_TAG, "[ACK-PUT] Failed attempt %d/%d, retrying in %dms...\n",
                   attempt, max_retries, delay_ms);
            qgp_platform_sleep_ms(delay_ms);
            delay_ms *= 2;
        }
    }

    QGP_LOG_WARN(LOG_TAG, "[ACK-PUT] FAILED after %d attempts: %.20s... -> %.20s...\n",
           max_retries, my_fp, sender_fp);
    return -1;
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
    dht_context_t *ctx,
    const char *my_fp,
    const char *recipient_fp,
    dht_ack_callback_t callback,
    void *user_data
) {
    if (!ctx || !my_fp || !recipient_fp || !callback) {
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

    // Generate ACK key: SHA3-512(recipient + ":ack:" + sender)
    uint8_t key[64];
    dht_generate_ack_key(recipient_fp, my_fp, key);

    QGP_LOG_INFO(LOG_TAG, "[ACK] Starting listener: %.20s... -> %.20s...\n",
           recipient_fp, my_fp);

    // Start DHT listen
    size_t token = dht_listen_ex(ctx, key, 64, ack_listen_callback, actx, ack_listener_cleanup);
    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "[ACK] Failed to start DHT listener\n");
        free(actx);  // Clean up allocated context on failure
        return 0;
    }

    return token;
}

/**
 * Cancel ACK listener
 */
void dht_cancel_ack_listener(
    dht_context_t *ctx,
    size_t token
) {
    if (!ctx || token == 0) {
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "[ACK] Cancelling listener (token=%zu)\n", token);
    dht_cancel_listen(ctx, token);
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
int dht_offline_queue_sync_pending(dht_context_t *ctx) {
    if (!ctx) return 0;

    pthread_mutex_lock(&g_queue_mutex);
    outbox_cache_init();

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

        // Try to publish
        int result = dht_chunked_publish(ctx, entry->base_key, serialized, serialized_len, DHT_CHUNK_TTL_7DAY);
        free(serialized);

        if (result == DHT_CHUNK_OK) {
            entry->needs_dht_sync = false;
            synced++;
            QGP_LOG_INFO(LOG_TAG, "Successfully synced pending outbox\n");
        } else {
            QGP_LOG_WARN(LOG_TAG, "Still failed to sync outbox: %s\n", dht_chunked_strerror(result));
        }
    }

    pthread_mutex_unlock(&g_queue_mutex);

    if (pending > 0) {
        QGP_LOG_INFO(LOG_TAG, "Synced %d/%d pending outboxes\n", synced, pending);
    }

    return synced;
}
