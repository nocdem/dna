#ifndef DHT_OFFLINE_QUEUE_H
#define DHT_OFFLINE_QUEUE_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DHT Offline Message Queue for DNA Messenger (Phase 9.2 + Spillway Protocol)
 *
 * Stores encrypted messages in DHT when recipients are offline.
 * Messages are retrieved when recipient comes online.
 *
 * Architecture (Spillway Protocol - Sender-Based Outbox):
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
 * Message Format (v2):
 * [4-byte magic "DNA "][1-byte version][8-byte seq_num][8-byte timestamp][8-byte expiry]
 * [2-byte sender_len][2-byte recipient_len][4-byte ciphertext_len]
 * [sender string][recipient string][ciphertext bytes]
 *
 * Note: Uses Dilithium5 signatures (signed puts) for authentication
 */

// Magic bytes for message format validation
#define DHT_OFFLINE_QUEUE_MAGIC 0x444E4120  // "DNA "
#define DHT_OFFLINE_QUEUE_VERSION 2  // v2: Added seq_num for watermark pruning

// Default TTL: 7 days
#define DHT_OFFLINE_QUEUE_DEFAULT_TTL 604800

// Watermark TTL: 30 days (longer than message TTL)
#define DHT_WATERMARK_TTL (30 * 24 * 3600)

/**
 * Offline message structure
 */
typedef struct {
    uint64_t seq_num;             // Monotonic sequence number per sender-recipient pair (for watermark pruning)
    uint64_t timestamp;           // Unix timestamp (when queued, for display)
    uint64_t expiry;              // Unix timestamp (when expires)
    char *sender;                 // Sender identity (dynamically allocated)
    char *recipient;              // Recipient identity (dynamically allocated)
    uint8_t *ciphertext;          // Encrypted DNA message (dynamically allocated)
    size_t ciphertext_len;        // Length of ciphertext
} dht_offline_message_t;

/**
 * Store encrypted message in sender's outbox to recipient
 *
 * Workflow (Spillway - Sender Outbox with Watermark Pruning):
 * 1. Generate sender's outbox key: SHA3-512(sender + ":outbox:" + recipient)
 * 2. Fetch recipient's watermark (highest seq_num they've received)
 * 3. Query existing outbox (sender's messages to this recipient)
 * 4. Deserialize existing messages (if any)
 * 5. Prune messages where seq_num <= watermark (already delivered)
 * 6. Create new message with provided seq_num
 * 7. Append new message to pruned array
 * 8. Serialize updated array
 * 9. Store with dht_put_signed(value_id=1) - replaces old outbox version
 *
 * Note: Uses signed put with fixed value_id=1 to prevent accumulation.
 *       Each update to sender's outbox REPLACES the old version (not appends).
 *       Caller should use message_backup_get_next_seq() to get seq_num.
 *
 * @param ctx DHT context
 * @param sender Sender identity (fingerprint - 128 hex chars)
 * @param recipient Recipient identity (fingerprint - 128 hex chars)
 * @param ciphertext Encrypted message blob (already encrypted)
 * @param ciphertext_len Length of ciphertext
 * @param seq_num Monotonic sequence number for this message (from message_backup_get_next_seq)
 * @param ttl_seconds Time-to-live in seconds (0 = use default 7 days)
 * @return 0 on success, -1 on failure
 */
int dht_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds
);

/**
 * Retrieve all queued messages for recipient from all contacts' outboxes
 *
 * Workflow (Spillway - Multi-Outbox Retrieval):
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
 * Retrieve all queued messages for recipient from all contacts' outboxes (PARALLEL VERSION)
 *
 * Same as dht_retrieve_queued_messages_from_contacts(), but queries all contacts
 * concurrently using async DHT operations for 10-100× speedup.
 *
 * Performance comparison:
 * - Sequential: N contacts × 300ms/contact = 30 seconds for 100 contacts
 * - Parallel:   ~300ms total (all queries concurrent)
 *
 * @param ctx DHT context
 * @param recipient Recipient identity (fingerprint - 128 hex chars)
 * @param sender_list Array of sender identities (contacts' fingerprints)
 * @param sender_count Number of senders in list
 * @param messages_out Output array (caller must free with dht_offline_messages_free)
 * @param count_out Output count of messages
 * @return 0 on success, -1 on failure
 */
int dht_retrieve_queued_messages_from_contacts_parallel(
    dht_context_t *ctx,
    const char *recipient,
    const char **sender_list,
    size_t sender_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
);

/**
 * REMOVED: dht_clear_queue() - No longer needed in Spillway Protocol
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
 * Each message (v2):
 * [4-byte magic][1-byte version][8-byte seq_num][8-byte timestamp][8-byte expiry]
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
 * Key format (Spillway): SHA3-512(sender + ":outbox:" + recipient)
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

/**
 * ============================================================================
 * Watermark API (Delivery Acknowledgment for Outbox Pruning)
 * ============================================================================
 *
 * Watermarks allow recipients to acknowledge received messages so senders
 * can prune their outboxes. Uses sequence numbers (clock-skew immune).
 *
 * Key format: SHA3-512(recipient + ":watermark:" + sender)
 * Value: 8-byte big-endian seq_num (latest received from this sender)
 *
 * Flow:
 * 1. Alice sends msg to Bob with seq_num=3
 * 2. Bob receives, publishes watermark(seq=3) asynchronously
 * 3. Alice sends new msg (seq=4), fetches Bob's watermark
 * 4. Alice prunes outbox: remove msgs where seq <= 3
 */

/**
 * Generate DHT key for watermark storage
 *
 * Key format: SHA3-512(recipient + ":watermark:" + sender)
 *
 * @param recipient Recipient fingerprint (watermark owner)
 * @param sender Sender fingerprint (whose messages were received)
 * @param key_out Output buffer (64 bytes for SHA3-512)
 */
void dht_generate_watermark_key(
    const char *recipient,
    const char *sender,
    uint8_t *key_out
);

/**
 * Publish watermark asynchronously (fire-and-forget)
 *
 * Used by recipient after receiving messages from a sender.
 * Publishes the highest seq_num received from that sender.
 * Async: does not block, failure is tolerable (retry on next receive).
 *
 * @param ctx DHT context
 * @param recipient My fingerprint (watermark owner)
 * @param sender Contact fingerprint (whose messages I received)
 * @param seq_num Latest seq_num received from this sender
 */
void dht_publish_watermark_async(
    dht_context_t *ctx,
    const char *recipient,
    const char *sender,
    uint64_t seq_num
);

/**
 * Get watermark synchronously (blocking)
 *
 * Used by sender before queueing a message to check what the recipient
 * has already received. Returns highest seq_num acknowledged by recipient.
 *
 * @param ctx DHT context
 * @param recipient Recipient fingerprint (watermark owner)
 * @param sender My fingerprint
 * @param seq_num_out Output: latest seq_num recipient has received (0 if none)
 * @return 0 on success (including no watermark found), -1 on error
 */
int dht_get_watermark(
    dht_context_t *ctx,
    const char *recipient,
    const char *sender,
    uint64_t *seq_num_out
);

/**
 * NOTE: For seq_num, callers should use message_backup_get_next_seq() from message_backup.h
 * to get the next sequence number before calling dht_queue_message().
 */

/**
 * ============================================================================
 * Watermark Listener API (Delivery Confirmation)
 * ============================================================================
 *
 * Listen for watermark updates from recipients. When a recipient retrieves
 * messages, they publish a watermark. Senders can listen for these updates
 * to confirm delivery and update message status to DELIVERED.
 *
 * Flow:
 * 1. Sender calls dht_listen_watermark() after sending offline message
 * 2. Recipient retrieves messages, publishes watermark asynchronously
 * 3. Sender's callback is invoked with new seq_num
 * 4. Sender updates message status to DELIVERED for all seq <= watermark
 */

/**
 * Watermark update callback
 *
 * @param sender My fingerprint (I sent messages to recipient)
 * @param recipient Contact fingerprint (they received my messages)
 * @param seq_num Latest seq_num recipient has received from me
 * @param user_data User-provided context pointer
 */
typedef void (*dht_watermark_callback_t)(
    const char *sender,
    const char *recipient,
    uint64_t seq_num,
    void *user_data
);

/**
 * Listen for watermark updates from a recipient
 *
 * Subscribes to real-time notifications when recipient publishes watermark
 * updates. Callback fires when recipient acknowledges receiving messages.
 *
 * Key: SHA3-512(recipient + ":watermark:" + sender)
 *
 * @param ctx DHT context
 * @param sender My fingerprint (I'm the sender)
 * @param recipient Contact fingerprint (they're the recipient)
 * @param callback Function to invoke when watermark updates
 * @param user_data Context pointer passed to callback
 *
 * @return Listen token (> 0 on success, 0 on failure)
 */
size_t dht_listen_watermark(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    dht_watermark_callback_t callback,
    void *user_data
);

/**
 * Cancel watermark listener
 *
 * Stops receiving notifications for the watermark subscription.
 *
 * @param ctx DHT context
 * @param token Listen token returned by dht_listen_watermark()
 */
void dht_cancel_watermark_listener(
    dht_context_t *ctx,
    size_t token
);

#ifdef __cplusplus
}
#endif

#endif // DHT_OFFLINE_QUEUE_H
