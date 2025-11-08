#include "dht_offline_queue.h"
#include "../qgp_sha3.h"
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
 * Generate DHT storage key for recipient's offline queue
 * Uses SHA3-512 for 256-bit quantum security
 */
void dht_generate_queue_key(const char *recipient, uint8_t *key_out) {
    char key_input[512];
    snprintf(key_input, sizeof(key_input), "%s:offline_queue", recipient);
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

    // Generate queue key
    uint8_t queue_key[32];
    dht_generate_queue_key(recipient, queue_key);

    printf("[DHT Queue] Queue key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           queue_key[0], queue_key[1], queue_key[2], queue_key[3],
           queue_key[4], queue_key[5], queue_key[6], queue_key[7]);

    // 1. Try to retrieve existing queue
    uint8_t *existing_data = NULL;
    size_t existing_len = 0;
    dht_offline_message_t *existing_messages = NULL;
    size_t existing_count = 0;

    printf("[DHT Queue] → DHT GET: Checking existing offline queue\n");
    int get_result = dht_get(ctx, queue_key, 32, &existing_data, &existing_len);
    if (get_result == 0 && existing_data && existing_len > 1) {
        // Queue exists, deserialize
        printf("[DHT Queue] Found existing queue (%zu bytes)\n", existing_len);
        if (dht_deserialize_messages(existing_data, existing_len, &existing_messages, &existing_count) == 0) {
            printf("[DHT Queue] Existing queue has %zu messages\n", existing_count);
        }
        free(existing_data);
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

    // 3. Combine existing + new message
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

    // 4. Serialize combined queue
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (dht_serialize_messages(all_messages, new_count, &serialized, &serialized_len) != 0) {
        fprintf(stderr, "[DHT Queue] Failed to serialize message queue\n");
        dht_offline_messages_free(all_messages, new_count);
        return -1;
    }

    printf("[DHT Queue] Serialized queue: %zu messages, %zu bytes\n", new_count, serialized_len);

    // 5. Store in DHT
    printf("[DHT Queue] → DHT PUT: Queueing offline message (%zu total in queue)\n", new_count);
    int put_result = dht_put(ctx, queue_key, 32, serialized, serialized_len);

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
 * Retrieve all queued messages for recipient
 */
int dht_retrieve_queued_messages(
    dht_context_t *ctx,
    const char *recipient,
    dht_offline_message_t **messages_out,
    size_t *count_out)
{
    if (!ctx || !recipient || !messages_out || !count_out) {
        fprintf(stderr, "[DHT Queue] Invalid parameters for retrieval\n");
        return -1;
    }

    printf("[DHT Queue] Retrieving queued messages for %s\n", recipient);

    // Generate queue key
    uint8_t queue_key[32];
    dht_generate_queue_key(recipient, queue_key);

    printf("[DHT Queue] Queue key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           queue_key[0], queue_key[1], queue_key[2], queue_key[3],
           queue_key[4], queue_key[5], queue_key[6], queue_key[7]);

    // Query DHT
    uint8_t *queue_data = NULL;
    size_t queue_len = 0;

    printf("[DHT Queue] → DHT GET: Retrieving offline messages\n");
    int get_result = dht_get(ctx, queue_key, 32, &queue_data, &queue_len);
    if (get_result != 0 || !queue_data || queue_len <= 1) {
        printf("[DHT Queue] No queued messages found\n");
        *messages_out = NULL;
        *count_out = 0;
        if (queue_data) free(queue_data);
        return 0;  // Not an error, just empty queue
    }

    printf("[DHT Queue] Retrieved queue data: %zu bytes\n", queue_len);

    // Deserialize messages
    dht_offline_message_t *all_messages = NULL;
    size_t all_count = 0;

    if (dht_deserialize_messages(queue_data, queue_len, &all_messages, &all_count) != 0) {
        fprintf(stderr, "[DHT Queue] Failed to deserialize queue\n");
        free(queue_data);
        return -1;
    }

    free(queue_data);

    printf("[DHT Queue] Deserialized %zu messages\n", all_count);

    // Filter out expired messages
    uint64_t now = (uint64_t)time(NULL);
    size_t valid_count = 0;

    for (size_t i = 0; i < all_count; i++) {
        if (all_messages[i].expiry >= now) {
            valid_count++;
        } else {
            printf("[DHT Queue] Message %zu expired (expiry=%lu, now=%lu)\n",
                   i, all_messages[i].expiry, now);
        }
    }

    if (valid_count == 0) {
        printf("[DHT Queue] All messages expired\n");
        dht_offline_messages_free(all_messages, all_count);
        *messages_out = NULL;
        *count_out = 0;
        return 0;
    }

    // Allocate array for valid messages only
    dht_offline_message_t *valid_messages = (dht_offline_message_t*)calloc(valid_count, sizeof(dht_offline_message_t));
    if (!valid_messages) {
        fprintf(stderr, "[DHT Queue] Failed to allocate valid message array\n");
        dht_offline_messages_free(all_messages, all_count);
        return -1;
    }

    // Copy valid messages
    size_t j = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (all_messages[i].expiry >= now) {
            valid_messages[j++] = all_messages[i];
        } else {
            // Free expired message
            dht_offline_message_free(&all_messages[i]);
        }
    }

    // Free old array (contents moved to valid_messages)
    free(all_messages);

    printf("[DHT Queue] ✓ Retrieved %zu valid messages\n", valid_count);

    *messages_out = valid_messages;
    *count_out = valid_count;
    return 0;
}

/**
 * Clear offline message queue for recipient
 */
int dht_clear_queue(
    dht_context_t *ctx,
    const char *recipient)
{
    if (!ctx || !recipient) {
        fprintf(stderr, "[DHT Queue] Invalid parameters for clearing queue\n");
        return -1;
    }

    printf("[DHT Queue] Clearing queue for %s\n", recipient);

    // Generate queue key
    uint8_t queue_key[32];
    dht_generate_queue_key(recipient, queue_key);

    // Store empty queue (since dht_delete doesn't work in OpenDHT)
    uint8_t empty_queue[5];  // Just the count=0
    uint32_t zero = htonl(0);
    memcpy(empty_queue, &zero, sizeof(uint32_t));

    printf("[DHT Queue] → DHT PUT: Clearing offline queue\n");
    int result = dht_put(ctx, queue_key, 32, empty_queue, sizeof(uint32_t));
    if (result != 0) {
        fprintf(stderr, "[DHT Queue] Failed to clear queue\n");
        return -1;
    }

    printf("[DHT Queue] ✓ Queue cleared\n");
    return 0;
}
