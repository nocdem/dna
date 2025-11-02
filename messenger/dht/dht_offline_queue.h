#ifndef DHT_OFFLINE_QUEUE_H
#define DHT_OFFLINE_QUEUE_H

#include "dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DHT Offline Message Queue for DNA Messenger (Phase 9.2)
 *
 * Stores encrypted messages in DHT when recipients are offline.
 * Messages are retrieved when recipient comes online and auto-deleted.
 *
 * Architecture:
 * - Storage Key: SHA256(recipient_identity + ":offline_queue")
 * - Value: Serialized array of messages (binary format)
 * - TTL: 7 days default (604,800 seconds)
 * - Approach: Single queue per recipient (append-only)
 *
 * Message Format:
 * [4-byte magic "DNA "][1-byte version][8-byte timestamp][8-byte expiry]
 * [2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
 * [sender string][recipient string][ciphertext bytes]
 *
 * Note: Signatures deferred to Phase 9.2b (production hardening)
 */

// Magic bytes for message format validation
#define DHT_OFFLINE_QUEUE_MAGIC 0x444E4120  // "DNA "
#define DHT_OFFLINE_QUEUE_VERSION 1

// Default TTL: 7 days
#define DHT_OFFLINE_QUEUE_DEFAULT_TTL 604800

/**
 * Offline message structure
 */
typedef struct {
    uint64_t timestamp;           // Unix timestamp (when queued)
    uint64_t expiry;              // Unix timestamp (when expires)
    char *sender;                 // Sender identity (dynamically allocated)
    char *recipient;              // Recipient identity (dynamically allocated)
    uint8_t *ciphertext;          // Encrypted DNA message (dynamically allocated)
    size_t ciphertext_len;        // Length of ciphertext
} dht_offline_message_t;

/**
 * Store encrypted message in DHT for offline recipient
 *
 * Workflow:
 * 1. Query existing queue at SHA256(recipient + ":offline_queue")
 * 2. Deserialize existing messages (if any)
 * 3. Append new message to array
 * 4. Serialize updated array
 * 5. Store back in DHT with TTL
 *
 * @param ctx DHT context
 * @param sender Sender identity string (e.g., "alice")
 * @param recipient Recipient identity string (e.g., "bob")
 * @param ciphertext Encrypted message blob (already encrypted)
 * @param ciphertext_len Length of ciphertext
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on failure
 */
int dht_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_seconds
);

/**
 * Retrieve all queued messages for recipient
 *
 * Workflow:
 * 1. Query DHT at SHA256(recipient + ":offline_queue")
 * 2. Deserialize message array
 * 3. Filter out expired messages
 * 4. Return valid messages
 * 5. Caller is responsible for clearing queue (via dht_clear_queue)
 *
 * @param ctx DHT context
 * @param recipient Recipient identity string
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count of messages
 * @return 0 on success, -1 on failure
 */
int dht_retrieve_queued_messages(
    dht_context_t *ctx,
    const char *recipient,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * Clear offline message queue for recipient
 *
 * Stores empty queue in DHT to effectively delete all messages.
 * (OpenDHT delete() doesn't work, so we overwrite with empty value)
 *
 * @param ctx DHT context
 * @param recipient Recipient identity string
 * @return 0 on success, -1 on failure
 */
int dht_clear_queue(
    dht_context_t *ctx,
    const char *recipient
);

/**
 * Free a single offline message (internal use)
 *
 * @param msg Message to free
 */
void dht_offline_message_free(dht_offline_message_t *msg);

/**
 * Free array of offline messages
 *
 * @param messages Array to free
 * @param count Number of messages in array
 */
void dht_offline_messages_free(dht_offline_message_t *messages, size_t count);

/**
 * Serialize message array to binary format
 *
 * Format:
 * [4-byte count][message1][message2]...[messageN]
 *
 * Each message:
 * [4-byte magic][1-byte version][8-byte timestamp][8-byte expiry]
 * [2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
 * [sender string][recipient string][ciphertext bytes]
 *
 * @param messages Array of messages
 * @param count Number of messages
 * @param serialized_out Output buffer (caller must free)
 * @param len_out Output length
 * @return 0 on success, -1 on failure
 */
int dht_serialize_messages(
    const dht_offline_message_t *messages,
    size_t count,
    uint8_t **serialized_out,
    size_t *len_out
);

/**
 * Deserialize message array from binary format
 *
 * @param data Serialized data
 * @param len Length of data
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dht_deserialize_messages(
    const uint8_t *data,
    size_t len,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * Generate DHT storage key for recipient's offline queue
 *
 * Key format: SHA256(recipient + ":offline_queue")
 *
 * @param recipient Recipient identity
 * @param key_out Output buffer (32 bytes for SHA256)
 */
void dht_generate_queue_key(
    const char *recipient,
    uint8_t *key_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_OFFLINE_QUEUE_H
