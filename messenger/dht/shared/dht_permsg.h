/**
 * DHT Per-Message Storage for DNA Messenger
 *
 * Replaces the GET-MODIFY-PUT offline queue model with direct per-message PUTs.
 * Each message gets a unique DHT key - no blocking GET required.
 *
 * Architecture:
 * - Message Key: SHA3-512(sender_fp + recipient_fp + timestamp + nonce)[0:32]
 * - Notification Key: SHA3-512(recipient_fp + ":msg_notifications")[0:32]
 * - Each message is a single PUT (instant, no GET)
 * - Notifications accumulate at recipient's notification key (OpenDHT handles this)
 *
 * Message Format:
 * [4-byte magic "PMG "][1-byte version][8-byte timestamp]
 * [128-byte sender_fp][128-byte recipient_fp]
 * [4-byte ciphertext_len][ciphertext bytes]
 *
 * Notification Format:
 * [4-byte magic "NTF "][1-byte version][8-byte timestamp]
 * [128-byte sender_fp][32-byte message_key]
 *
 * @file dht_permsg.h
 * @date 2025-11-26
 */

#ifndef DHT_PERMSG_H
#define DHT_PERMSG_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Magic bytes for format validation
#define DHT_PERMSG_MAGIC     0x504D4720  // "PMG "
#define DHT_PERMSG_NTF_MAGIC 0x4E544620  // "NTF "
#define DHT_PERMSG_VERSION   1

// Key sizes
#define DHT_PERMSG_KEY_SIZE       32   // Truncated SHA3-512 for DHT key
#define DHT_PERMSG_FINGERPRINT_SIZE 128 // Hex fingerprint

// Default TTL: 7 days
#define DHT_PERMSG_DEFAULT_TTL 604800

/**
 * Per-message structure (for sending/receiving)
 */
typedef struct {
    uint64_t timestamp;                              // Unix timestamp
    char sender_fp[DHT_PERMSG_FINGERPRINT_SIZE + 1]; // Sender fingerprint (128 hex + null)
    char recipient_fp[DHT_PERMSG_FINGERPRINT_SIZE + 1]; // Recipient fingerprint
    uint8_t *ciphertext;                             // Encrypted message
    size_t ciphertext_len;                           // Ciphertext length
    uint8_t message_key[DHT_PERMSG_KEY_SIZE];        // DHT key where message is stored
} dht_permsg_t;

/**
 * Notification structure (lightweight pointer to message)
 */
typedef struct {
    uint64_t timestamp;                              // When message was sent
    char sender_fp[DHT_PERMSG_FINGERPRINT_SIZE + 1]; // Who sent it
    uint8_t message_key[DHT_PERMSG_KEY_SIZE];        // Where to fetch the message
} dht_permsg_notification_t;

/**
 * Store a single message in DHT (no GET required - instant PUT)
 *
 * Workflow:
 * 1. Generate unique message key: SHA3-512(sender + recipient + timestamp + random)
 * 2. Serialize message with header
 * 3. PUT to DHT at message key (async, instant return)
 * 4. PUT notification to recipient's notification key
 *
 * @param ctx DHT context
 * @param sender_fp Sender fingerprint (128 hex chars)
 * @param recipient_fp Recipient fingerprint (128 hex chars)
 * @param ciphertext Encrypted message blob
 * @param ciphertext_len Length of ciphertext
 * @param ttl_seconds Time-to-live (0 = default 7 days)
 * @param message_key_out Output: the generated message key (32 bytes, optional)
 * @return 0 on success, -1 on failure
 */
int dht_permsg_put(
    dht_context_t *ctx,
    const char *sender_fp,
    const char *recipient_fp,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint32_t ttl_seconds,
    uint8_t *message_key_out
);

/**
 * Fetch a single message from DHT by its key
 *
 * @param ctx DHT context
 * @param message_key The 32-byte message key
 * @param msg_out Output message structure (caller must free with dht_permsg_free)
 * @return 0 on success, -1 on failure, -2 if not found
 */
int dht_permsg_get(
    dht_context_t *ctx,
    const uint8_t *message_key,
    dht_permsg_t *msg_out
);

/**
 * Fetch all notifications for a recipient
 *
 * Returns list of message notifications (sender + message_key pairs).
 * Recipient can then fetch individual messages using dht_permsg_get().
 *
 * @param ctx DHT context
 * @param recipient_fp Recipient fingerprint
 * @param notifications_out Output array (caller must free with dht_permsg_free_notifications)
 * @param count_out Number of notifications
 * @return 0 on success, -1 on failure
 */
int dht_permsg_get_notifications(
    dht_context_t *ctx,
    const char *recipient_fp,
    dht_permsg_notification_t **notifications_out,
    size_t *count_out
);

/**
 * Fetch all messages for recipient from specific senders (contacts)
 *
 * Convenience function that:
 * 1. Gets all notifications for recipient
 * 2. Filters by sender_list (only messages from contacts)
 * 3. Fetches each message in parallel
 * 4. Returns combined message array
 *
 * @param ctx DHT context
 * @param recipient_fp Recipient fingerprint
 * @param sender_list Array of contact fingerprints (NULL = all senders)
 * @param sender_count Number of senders (0 = all senders)
 * @param messages_out Output message array
 * @param count_out Number of messages
 * @return 0 on success, -1 on failure
 */
int dht_permsg_fetch_from_contacts(
    dht_context_t *ctx,
    const char *recipient_fp,
    const char **sender_list,
    size_t sender_count,
    dht_permsg_t **messages_out,
    size_t *count_out
);

/**
 * Generate notification key for a recipient
 *
 * Key format: SHA3-512(recipient_fp + ":msg_notifications")[0:32]
 *
 * @param recipient_fp Recipient fingerprint
 * @param key_out Output buffer (32 bytes)
 */
void dht_permsg_make_notification_key(
    const char *recipient_fp,
    uint8_t *key_out
);

/**
 * Generate unique message key
 *
 * Key format: SHA3-512(sender_fp + recipient_fp + timestamp_hex + random_nonce)[0:32]
 *
 * @param sender_fp Sender fingerprint
 * @param recipient_fp Recipient fingerprint
 * @param timestamp Unix timestamp
 * @param key_out Output buffer (32 bytes)
 */
void dht_permsg_make_message_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t timestamp,
    uint8_t *key_out
);

/**
 * Free a single message structure
 */
void dht_permsg_free(dht_permsg_t *msg);

/**
 * Free message array
 */
void dht_permsg_free_messages(dht_permsg_t *messages, size_t count);

/**
 * Free notification array
 */
void dht_permsg_free_notifications(dht_permsg_notification_t *notifications, size_t count);

/**
 * Serialize message to binary format
 */
int dht_permsg_serialize(
    const dht_permsg_t *msg,
    uint8_t **data_out,
    size_t *len_out
);

/**
 * Deserialize message from binary format
 */
int dht_permsg_deserialize(
    const uint8_t *data,
    size_t len,
    dht_permsg_t *msg_out
);

/**
 * Serialize notification to binary format
 */
int dht_permsg_serialize_notification(
    const dht_permsg_notification_t *ntf,
    uint8_t **data_out,
    size_t *len_out
);

/**
 * Deserialize notification from binary format
 */
int dht_permsg_deserialize_notification(
    const uint8_t *data,
    size_t len,
    dht_permsg_notification_t *ntf_out
);

#ifdef __cplusplus
}
#endif

#endif // DHT_PERMSG_H
