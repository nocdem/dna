#include "dht_offline_queue.h"
#include "../crypto/utils/qgp_sha3.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Linux
#endif

/**
 * SHA3-512 hash helper (Category 5 security)
 * Uses qgp_sha3.h wrapper for consistent hashing
 */
static void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    qgp_sha3_512(data, len, hash_out);
}

/**
 * Generate DHT storage key for sender's outbox to recipient (Model E)
 * Uses SHA3-512 for 256-bit quantum security
 *
 * Key format: SHA3-512(sender + ":outbox:" + recipient)
 * Example: SHA3-512("alice_fp:outbox:bob_fp")
 */
void dht_generate_outbox_key(const char *sender, const char *recipient, uint8_t *key_out) {
    char key_input[2048];  // sender(128) + ":outbox:" + recipient(128) + margin
    snprintf(key_input, sizeof(key_input), "%s:outbox:%s", sender, recipient);
    sha3_512_hash((const uint8_t*)key_input, strlen(key_input), key_out);
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
 * Serialize message array to binary format
 *
 * Format:
 * [4-byte count (network order)]
 * For each message:
 *   [4-byte magic (network order)]
 *   [1-byte version]
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
        fprintf(stderr, "[DHT Queue] Invalid parameters for serialization\n");
        return -1;
    }

    // Calculate total size
    size_t total_size = sizeof(uint32_t);  // Message count

    for (size_t i = 0; i < count; i++) {
        total_size += sizeof(uint32_t);  // magic
        total_size += 1;                  // version
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
        fprintf(stderr, "[DHT Queue] Failed to allocate %zu bytes for serialization\n", total_size);
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
        fprintf(stderr, "[DHT Queue] Invalid data for deserialization\n");
        return -1;
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + len;

    // Read message count
    if (ptr + sizeof(uint32_t) > end) {
        fprintf(stderr, "[DHT Queue] Truncated data (count)\n");
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

    // Allocate message array
    dht_offline_message_t *messages = (dht_offline_message_t*)calloc(count, sizeof(dht_offline_message_t));
    if (!messages) {
        fprintf(stderr, "[DHT Queue] Failed to allocate message array\n");
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
            fprintf(stderr, "[DHT Queue] Invalid magic bytes: 0x%08X\n", magic);
            goto error;
        }
        ptr += sizeof(uint32_t);

        // Version
        if (ptr + 1 > end) goto truncated;
        uint8_t version = *ptr++;
        if (version != DHT_OFFLINE_QUEUE_VERSION) {
            fprintf(stderr, "[DHT Queue] Unsupported version: %u\n", version);
            goto error;
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
    fprintf(stderr, "[DHT Queue] Truncated message data\n");
error:
    dht_offline_messages_free(messages, count);
    return -1;
}

/**
 * Store encrypted message in DHT for offline recipient
 */
int dht_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_seconds)
{
    if (!ctx || !sender || !recipient || !ciphertext || ciphertext_len == 0) {
        fprintf(stderr, "[DHT Queue] Invalid parameters for queueing message\n");
        return -1;
    }

    if (ttl_seconds == 0) {
        ttl_seconds = DHT_OFFLINE_QUEUE_DEFAULT_TTL;
    }

    printf("[DHT Queue] Queueing message from %s to %s (%zu bytes, TTL=%u)\n",
           sender, recipient, ciphertext_len, ttl_seconds);

    // Generate sender's outbox key (Model E): SHA3-512(sender + ":outbox:" + recipient) = 64 bytes
    uint8_t queue_key[64];
    dht_generate_outbox_key(sender, recipient, queue_key);

    printf("[DHT Queue] Outbox key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           queue_key[0], queue_key[1], queue_key[2], queue_key[3],
           queue_key[4], queue_key[5], queue_key[6], queue_key[7]);

    // 1. Try to retrieve existing queue (use dht_get_all to get latest version)
    uint8_t *existing_data = NULL;
    size_t existing_len = 0;
    dht_offline_message_t *existing_messages = NULL;
    size_t existing_count = 0;

    printf("[DHT Queue] → DHT GET_ALL: Checking existing offline queue\n");
    uint8_t **all_values = NULL;
    size_t *all_lengths = NULL;
    size_t value_count = 0;

    int get_result = dht_get_all(ctx, queue_key, 64, &all_values, &all_lengths, &value_count);
    if (get_result == 0 && value_count > 0) {
        // Multiple values found - pick the largest one (most recent with most messages)
        printf("[DHT Queue] Found %zu queue version(s), selecting largest\n", value_count);
        size_t largest_idx = 0;
        size_t largest_size = all_lengths[0];
        for (size_t i = 1; i < value_count; i++) {
            if (all_lengths[i] > largest_size) {
                largest_size = all_lengths[i];
                largest_idx = i;
            }
        }

        existing_data = all_values[largest_idx];
        existing_len = all_lengths[largest_idx];

        printf("[DHT Queue] Selected version %zu/%zu (%zu bytes)\n", largest_idx + 1, value_count, existing_len);

        if (dht_deserialize_messages(existing_data, existing_len, &existing_messages, &existing_count) == 0) {
            printf("[DHT Queue] Existing queue has %zu messages\n", existing_count);
        }

        // Free all values except the one we're using
        for (size_t i = 0; i < value_count; i++) {
            if (i != largest_idx) {
                free(all_values[i]);
            }
        }
        free(all_values);
        free(all_lengths);
        free(existing_data);  // Free after deserialize
    } else {
        printf("[DHT Queue] No existing queue found, creating new\n");
    }

    // 2. Create new message
    dht_offline_message_t new_msg = {
        .timestamp = (uint64_t)time(NULL),
        .expiry = (uint64_t)time(NULL) + ttl_seconds,
        .sender = strdup(sender),
        .recipient = strdup(recipient),
        .ciphertext = (uint8_t*)malloc(ciphertext_len),
        .ciphertext_len = ciphertext_len
    };

    if (!new_msg.sender || !new_msg.recipient || !new_msg.ciphertext) {
        fprintf(stderr, "[DHT Queue] Failed to allocate memory for new message\n");
        dht_offline_message_free(&new_msg);
        dht_offline_messages_free(existing_messages, existing_count);
        return -1;
    }

    memcpy(new_msg.ciphertext, ciphertext, ciphertext_len);

    // 3. APPEND new message to existing queue (Model E: accumulate offline messages)
    // Important: When recipient is offline, ALL messages must be queued
    // Duplicate prevention happens at recipient side (message_backup_exists_ciphertext)
    size_t new_count = existing_count + 1;
    dht_offline_message_t *all_messages = (dht_offline_message_t*)calloc(new_count, sizeof(dht_offline_message_t));
    if (!all_messages) {
        fprintf(stderr, "[DHT Queue] Failed to allocate combined message array\n");
        dht_offline_message_free(&new_msg);
        dht_offline_messages_free(existing_messages, existing_count);
        return -1;
    }

    // Copy existing messages
    for (size_t i = 0; i < existing_count; i++) {
        all_messages[i] = existing_messages[i];
    }

    // Add new message at end
    all_messages[existing_count] = new_msg;

    // Free old array (but not the message contents, they're now in all_messages)
    if (existing_messages) {
        free(existing_messages);
    }

    printf("[DHT Queue] Appended new message to outbox (%zu total messages)\n", new_count);

    // 4. Serialize combined queue
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (dht_serialize_messages(all_messages, new_count, &serialized, &serialized_len) != 0) {
        fprintf(stderr, "[DHT Queue] Failed to serialize message queue\n");
        dht_offline_messages_free(all_messages, new_count);
        return -1;
    }

    printf("[DHT Queue] Serialized queue: %zu messages, %zu bytes\n", new_count, serialized_len);

    // 5. Store in DHT using SIGNED put with fixed value ID
    // Using value_id=1 ensures old queue versions are REPLACED (not accumulated)
    printf("[DHT Queue] → DHT PUT_SIGNED: Queueing offline message (%zu total in queue)\n", new_count);
    int put_result = dht_put_signed(ctx, queue_key, 64, serialized, serialized_len, 1, 0);

    free(serialized);
    dht_offline_messages_free(all_messages, new_count);

    if (put_result != 0) {
        fprintf(stderr, "[DHT Queue] Failed to store queue in DHT\n");
        return -1;
    }

    printf("[DHT Queue] ✓ Message queued successfully\n");
    return 0;
}

/**
 * Retrieve all queued messages for recipient from all contacts' outboxes (Model E)
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
        fprintf(stderr, "[DHT Queue] Invalid parameters for retrieval\n");
        return -1;
    }

    printf("[DHT Queue] Retrieving queued messages for %s from %zu contacts\n", recipient, sender_count);

    // Allocate temporary array to accumulate messages from all senders
    dht_offline_message_t *all_messages = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;

    uint64_t now = (uint64_t)time(NULL);

    // Iterate through all senders (contacts)
    for (size_t contact_idx = 0; contact_idx < sender_count; contact_idx++) {
        const char *sender = sender_list[contact_idx];

        // Generate sender's outbox key to us: SHA3-512(sender + ":outbox:" + recipient)
        uint8_t outbox_key[64];
        dht_generate_outbox_key(sender, recipient, outbox_key);

        printf("[DHT Queue] [%zu/%zu] Checking sender %.20s... outbox\n",
               contact_idx + 1, sender_count, sender);

        // Query DHT for this sender's outbox (use dht_get to get single value)
        uint8_t *outbox_data = NULL;
        size_t outbox_len = 0;

        int get_result = dht_get(ctx, outbox_key, 64, &outbox_data, &outbox_len);
        if (get_result != 0 || !outbox_data || outbox_len == 0) {
            // No messages from this sender (outbox empty or doesn't exist)
            continue;
        }

        printf("[DHT Queue]   ✓ Found outbox (%zu bytes)\n", outbox_len);

        // Deserialize messages from this sender's outbox
        dht_offline_message_t *sender_messages = NULL;
        size_t sender_count_msgs = 0;

        if (dht_deserialize_messages(outbox_data, outbox_len, &sender_messages, &sender_count_msgs) != 0) {
            fprintf(stderr, "[DHT Queue]   ✗ Failed to deserialize sender's outbox\n");
            free(outbox_data);
            continue;
        }

        free(outbox_data);

        printf("[DHT Queue]   Deserialized %zu message(s) from this sender\n", sender_count_msgs);

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
                        fprintf(stderr, "[DHT Queue] Failed to grow message array\n");
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
                printf("[DHT Queue]   Message %zu expired (expiry=%lu, now=%lu)\n",
                       i, sender_messages[i].expiry, now);
                dht_offline_message_free(&sender_messages[i]);
            }
        }

        // Free sender_messages array (contents transferred or freed)
        free(sender_messages);
    }

    printf("[DHT Queue] ✓ Retrieved %zu valid messages from %zu contacts\n", all_count, sender_count);

    *messages_out = all_messages;
    *count_out = all_count;
    return 0;
}

/**
 * REMOVED: dht_clear_queue() - No longer needed in Model E
 *
 * In sender-based outbox model:
 * - Recipients don't control sender outboxes (can't clear them)
 * - Senders manage their own outboxes
 * - Recipients only retrieve messages (read-only operation)
 * - No need for recipient-side clearing
 */
