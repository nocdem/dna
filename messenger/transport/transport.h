#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Transport Layer for DNA Messenger
 *
 * Architecture:
 * - DHT-only messaging (privacy-preserving, no IP leaks)
 * - Timestamp-only presence (online status without IP disclosure)
 * - Post-quantum encryption: Kyber1024 (ML-KEM-1024) + Dilithium5 (ML-DSA-87) + AES-256-GCM
 * - NIST Category 5 security (256-bit quantum)
 * - Offline message queuing in DHT (7-day TTL)
 *
 * Port Usage:
 * - UDP 4000: DHT network
 */

// Forward declare opaque type
typedef struct transport transport_t;

/**
 * Transport Configuration
 */
typedef struct {
    uint16_t dht_port;              // DHT port (default: 4000)

    char bootstrap_nodes[5][256];   // DHT bootstrap node addresses
    size_t bootstrap_count;

    char identity[256];             // Node identity (fingerprint for logging)

    bool enable_offline_queue;      // Store offline messages in DHT
    uint32_t offline_ttl_seconds;   // TTL for offline messages (default: 7 days)
} transport_config_t;

/**
 * Message Callback
 * Called when a message is received from DHT
 *
 * @param peer_pubkey Sender's Dilithium5 public key (2592 bytes), NULL for offline messages
 * @param sender_fingerprint Sender's fingerprint (128 hex chars)
 * @param message Decrypted message data
 * @param message_len Length of decrypted message
 * @param user_data User-provided callback data
 */
typedef void (*transport_message_callback_t)(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data
);

// ============================================================================
// Core API
// ============================================================================

/**
 * Initialize transport layer
 *
 * @param config Configuration (will be copied)
 * @param my_privkey_dilithium Dilithium5 private key (ML-DSA-87, 4896 bytes)
 * @param my_pubkey_dilithium Dilithium5 public key (ML-DSA-87, 2592 bytes)
 * @param my_kyber_key Kyber1024 private key (ML-KEM-1024, 3168 bytes) for encryption
 * @param message_callback Called when message received (can be NULL)
 * @param callback_user_data User data for callbacks
 * @return Transport context, or NULL on failure
 */
transport_t* transport_init(
    const transport_config_t *config,
    const uint8_t *my_privkey_dilithium,
    const uint8_t *my_pubkey_dilithium,
    const uint8_t *my_kyber_key,
    transport_message_callback_t message_callback,
    void *callback_user_data
);

/**
 * Start transport (DHT bootstrap)
 * This is non-blocking
 *
 * @param ctx Transport context
 * @return 0 on success, -1 on failure
 */
int transport_start(transport_t *ctx);

/**
 * Stop transport
 *
 * @param ctx Transport context
 */
void transport_stop(transport_t *ctx);

/**
 * Free transport context (calls stop if needed)
 *
 * @param ctx Transport context
 */
void transport_free(transport_t *ctx);

/**
 * Deliver message via transport callback
 * Thread-safe helper function for invoking the message callback
 *
 * @param ctx Transport context
 * @param peer_pubkey Peer's public key (NULL if unknown)
 * @param data Message data
 * @param len Message length
 * @return 0 on success, -1 if no callback registered
 */
int transport_deliver_message(
    transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *data,
    size_t len
);

// ============================================================================
// Presence (DHT-based)
// ============================================================================

/**
 * Register my presence in DHT (timestamp only - privacy preserving)
 * Publishes: hash(my_pubkey) -> { timestamp }
 * No IP address is published to protect user privacy.
 *
 * This should be called periodically (every 5-10 minutes) to refresh presence
 *
 * @param ctx Transport context
 * @return 0 on success, -1 on failure
 */
int transport_register_presence(transport_t *ctx);

// ============================================================================
// DHT Offline Queue (Primary messaging path)
// ============================================================================

/**
 * Check for offline messages in DHT
 *
 * Queries contacts' outboxes for messages addressed to this user
 * Decrypts and delivers messages via callback
 *
 * This should be called periodically (every 1-5 minutes)
 *
 * @param ctx Transport context
 * @param sender_fp If non-NULL, fetch only from this contact's outbox. If NULL, fetch from all contacts.
 * @param publish_watermarks If true, publish watermarks to tell senders we received messages.
 *                           Set false for background caching (user hasn't read them yet).
 * @param messages_received Output - number of messages retrieved (can be NULL)
 * @return 0 on success, -1 on failure
 */
int transport_check_offline_messages(
    transport_t *ctx,
    const char *sender_fp,
    bool publish_watermarks,
    size_t *messages_received
);

/**
 * Queue message in DHT for offline recipient (Spillway protocol)
 *
 * Stores encrypted message in sender's outbox for recipient to retrieve.
 * Message expires after TTL (default 7 days).
 *
 * @param ctx Transport context
 * @param sender Sender fingerprint (outbox owner)
 * @param recipient Recipient fingerprint
 * @param message Encrypted message data
 * @param message_len Length of message
 * @param seq_num Monotonic sequence number for watermark pruning
 * @return 0 on success, -1 on failure
 */
int transport_queue_offline_message(
    transport_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *message,
    size_t message_len,
    uint64_t seq_num
);

#ifdef __cplusplus
}
#endif

#endif // TRANSPORT_H
