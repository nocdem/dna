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
 * DHT Offline Message Queue for DNA Messenger (Phase 9.2 + Model E)
 *
 * Stores encrypted messages in DHT when recipients are offline.
 * Messages are retrieved when recipient comes online.
 *
 * Architecture (Model E - Sender-Based Outbox):
 * - Storage Key: SHA3-512(sender_identity + ":outbox:" + recipient_identity) - 64 bytes
 * - Value: Serialized array of messages (binary format)
 * - TTL: 7 days default (604,800 seconds)
 * - Put Type: Signed putSigned() with value_id=1 (enables replacement, prevents accumulation)
 * - Approach: Each sender controls their own outbox to each recipient
 *
 * Key Benefits:
 * - No accumulation: Signed puts with value_id=1 replace old values (not append)
 * - Spam prevention: Recipients only query known contacts' outboxes
 * - Sender control: Senders can edit/unsend messages (within 7-day TTL)
 *
 * Message Format:
 * [4-byte magic "DNA "][1-byte version][8-byte timestamp][8-byte expiry]
 * [2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
 * [sender string][recipient string][ciphertext bytes]
 *
 * Note: Uses Dilithium5 signatures (signed puts) for authentication
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
 * Store encrypted message in sender's outbox to recipient
 *
 * Workflow (Model E - Sender Outbox):
 * 1. Generate sender's outbox key: SHA3-512(sender + ":outbox:" + recipient)
 * 2. Query existing outbox (sender's messages to this recipient)
 * 3. Deserialize existing messages (if any)
 * 4. Append new message to array
 * 5. Serialize updated array
 * 6. Store with dht_put_signed(value_id=1) - replaces old outbox version
 *
 * Note: Uses signed put with fixed value_id=1 to prevent accumulation.
 *       Each update to sender's outbox REPLACES the old version (not appends).
 *
 * @param ctx DHT context
 * @param sender Sender identity (fingerprint - 128 hex chars)
 * @param recipient Recipient identity (fingerprint - 128 hex chars)
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
 * Retrieve all queued messages for recipient from all contacts' outboxes
 *
 * Workflow (Model E - Multi-Outbox Retrieval):
 * 1. For each sender in sender_list (contacts):
 *    a. Generate outbox key: SHA3-512(sender + ":outbox:" + recipient)
 *    b. Query DHT for this sender's outbox
 *    c. Deserialize messages from this outbox
 *    d. Filter out expired messages
 *    e. Append to combined message array
 * 2. Return all messages from all contacts
 *
 * Note: Only queries contacts in sender_list (spam prevention).
 *       Messages from unknown senders are ignored (not queried).
 *
 * @param ctx DHT context
 * @param recipient Recipient identity (fingerprint - 128 hex chars)
 * @param sender_list Array of sender identities (contacts' fingerprints)
 * @param sender_count Number of senders in list
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count of messages
 * @return 0 on success, -1 on failure
 */
int dht_retrieve_queued_messages_from_contacts(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * REMOVED: dht_clear_queue() - No longer needed in Model E
 *
 * In sender-based outbox model, recipients don't control sender outboxes.
 * Senders manage their own outboxes and can clear/edit at will.
 * Recipients simply retrieve messages from senders' outboxes (read-only).
 */

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
 * Generate DHT storage key for sender's outbox to recipient
 *
 * Key format (Model E): SHA3-512(sender + ":outbox:" + recipient)
 *
 * Example:
 *   sender = "a3f9e2d1c5b8a7f6..."  (128-char fingerprint)
 *   recipient = "b4a7f89012e3c6d5..."  (128-char fingerprint)
 *   input = "a3f9e2d1c5b8a7f6...:outbox:b4a7f89012e3c6d5..."
 *   output = SHA3-512(input) = 64-byte hash
 *
 * @param sender Sender identity (fingerprint - 128 hex chars)
 * @param recipient Recipient identity (fingerprint - 128 hex chars)
 * @param key_out Output buffer (64 bytes for SHA3-512)
 */
void dht_generate_outbox_key(
    const char *sender,
    const char *recipient,
    uint8_t *key_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_OFFLINE_QUEUE_H
