#ifndef P2P_TRANSPORT_H
#define P2P_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * P2P Transport Layer for DNA Messenger
 *
 * Architecture:
 * - DHT-based peer discovery (OpenDHT via dht_context.h)
 * - TCP socket connections for peer-to-peer messaging
 * - Post-quantum encryption: Kyber1024 (ML-KEM-1024) + Dilithium5 (ML-DSA-87) + AES-256-GCM
 * - NIST Category 5 security (256-bit quantum)
 * - Offline message queuing in DHT
 *
 * Port Usage:
 * - UDP 4000: DHT network
 * - TCP 4001: P2P messaging
 */

// Forward declare opaque types
typedef struct p2p_transport p2p_transport_t;
typedef struct p2p_connection p2p_connection_t;

/**
 * P2P Configuration
 */
typedef struct {
    uint16_t listen_port;           // TCP listen port (default: 4001)
    uint16_t dht_port;              // DHT port (default: 4000)

    char bootstrap_nodes[5][256];   // DHT bootstrap node addresses
    size_t bootstrap_count;

    char identity[256];             // Node identity (for logging)

    bool enable_offline_queue;      // Store offline messages in DHT
    uint32_t offline_ttl_seconds;   // TTL for offline messages (default: 7 days)
} p2p_config_t;

/**
 * Peer Information
 */
typedef struct {
    char ip[64];                    // IPv4 or IPv6 address
    uint16_t port;                  // TCP port
    uint64_t last_seen;             // Unix timestamp
    uint8_t public_key[2592];       // Dilithium5 public key
    bool is_online;                 // Currently reachable
} peer_info_t;

/**
 * Message Callback
 * Called when a P2P message is received
 *
 * @param peer_pubkey Sender's Dilithium5 public key (2592 bytes), NULL for offline messages
 * @param sender_fingerprint Sender's fingerprint (128 hex chars), NULL for direct P2P
 * @param message Decrypted message data
 * @param message_len Length of decrypted message
 * @param user_data User-provided callback data
 */
typedef void (*p2p_message_callback_t)(
    const uint8_t *peer_pubkey,
    const char *sender_fingerprint,
    const uint8_t *message,
    size_t message_len,
    void *user_data
);

/**
 * Connection State Callback
 * Called when a peer connects or disconnects
 *
 * @param peer_pubkey Peer's Dilithium5 public key (2592 bytes)
 * @param is_connected true if connected, false if disconnected
 * @param user_data User-provided callback data
 */
typedef void (*p2p_connection_callback_t)(
    const uint8_t *peer_pubkey,
    bool is_connected,
    void *user_data
);

// ============================================================================
// Core API
// ============================================================================

/**
 * Initialize P2P transport layer
 *
 * @param config Configuration (will be copied)
 * @param my_privkey_dilithium Dilithium5 private key (ML-DSA-87, 4896 bytes)
 * @param my_pubkey_dilithium Dilithium5 public key (ML-DSA-87, 2592 bytes)
 * @param my_kyber_key Kyber1024 private key (ML-KEM-1024, 3168 bytes) for encryption
 * @param message_callback Called when message received (can be NULL)
 * @param connection_callback Called on peer connect/disconnect (can be NULL)
 * @param callback_user_data User data for callbacks
 * @return P2P transport context, or NULL on failure
 */
p2p_transport_t* p2p_transport_init(
    const p2p_config_t *config,
    const uint8_t *my_privkey_dilithium,
    const uint8_t *my_pubkey_dilithium,
    const uint8_t *my_kyber_key,
    p2p_message_callback_t message_callback,
    p2p_connection_callback_t connection_callback,
    void *callback_user_data
);

/**
 * Start P2P transport (DHT bootstrap + TCP listener)
 * This is non-blocking - starts listener thread
 *
 * @param ctx P2P transport context
 * @return 0 on success, -1 on failure
 */
int p2p_transport_start(p2p_transport_t *ctx);

/**
 * Stop P2P transport (stop listening, close connections)
 *
 * @param ctx P2P transport context
 */
void p2p_transport_stop(p2p_transport_t *ctx);

/**
 * Free P2P transport context (calls stop if needed)
 *
 * @param ctx P2P transport context
 */
void p2p_transport_free(p2p_transport_t *ctx);

/**
 * Get DHT context from P2P transport
 * Used for accessing DHT directly (e.g., for group management)
 *
 * @param ctx P2P transport context
 * @return DHT context pointer (do not free)
 */
struct dht_context* p2p_transport_get_dht_context(p2p_transport_t *ctx);

/**
 * Deliver message via P2P transport callback
 * Thread-safe helper function for invoking the message callback
 *
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's public key (NULL if unknown)
 * @param data: Message data
 * @param len: Message length
 * @return: 0 on success, -1 if no callback registered
 */
int p2p_transport_deliver_message(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *data,
    size_t len
);

// ============================================================================
// Peer Discovery (DHT-based)
// ============================================================================

/**
 * Register my presence in DHT
 * Publishes: hash(my_pubkey) -> { ip, port, timestamp }
 *
 * This should be called periodically (every 5-10 minutes) to refresh presence
 *
 * @param ctx P2P transport context
 * @return 0 on success, -1 on failure
 */
int p2p_register_presence(p2p_transport_t *ctx);

/**
 * Look up a peer in DHT
 * Queries: hash(peer_pubkey) -> { ip, port, timestamp }
 *
 * @param ctx P2P transport context
 * @param peer_pubkey Peer's Dilithium5 public key (2592 bytes)
 * @param peer_info Output - peer information (caller-allocated)
 * @return 0 on success (peer found), -1 if not found
 */
int p2p_lookup_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    peer_info_t *peer_info
);

// ============================================================================
// Direct Messaging
// ============================================================================

/**
 * Send encrypted message to a peer
 *
 * Steps:
 * 1. Look up peer in DHT (if not already connected)
 * 2. Establish TCP connection (if not already connected)
 * 3. Encrypt message with Kyber1024 (ML-KEM-1024) + AES-256-GCM
 * 4. Sign with Dilithium5 (ML-DSA-87)
 * 5. Send over TCP connection
 *
 * If peer is offline and offline_queue is enabled, stores in DHT
 *
 * @param ctx P2P transport context
 * @param peer_pubkey Recipient's Dilithium5 public key (2592 bytes)
 * @param message Plaintext message
 * @param message_len Length of message
 * @return 0 on success, -1 on failure
 */
int p2p_send_message(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *message,
    size_t message_len
);

/**
 * Check for offline messages in DHT
 *
 * Queries: hash(my_pubkey) -> offline_message_queue
 * Decrypts and delivers messages via callback
 * Deletes retrieved messages from DHT
 *
 * This should be called periodically (every 1-5 minutes)
 *
 * @param ctx P2P transport context
 * @param messages_received Output - number of messages retrieved (can be NULL)
 * @return 0 on success, -1 on failure
 */
int p2p_check_offline_messages(
    p2p_transport_t *ctx,
    size_t *messages_received
);

/**
 * Queue message in DHT for offline recipient (Phase 9.2)
 *
 * Stores encrypted message in DHT for later retrieval.
 * Message expires after TTL (default 7 days).
 *
 * @param ctx P2P transport context
 * @param sender Sender identity string
 * @param recipient Recipient identity string
 * @param message Encrypted message data
 * @param message_len Length of message
 * @return 0 on success, -1 on failure
 */
int p2p_queue_offline_message(
    p2p_transport_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *message,
    size_t message_len
);

// ============================================================================
// Connection Management
// ============================================================================

/**
 * Get list of currently connected peers
 *
 * @param ctx P2P transport context
 * @param pubkeys Output array (caller must allocate for max_peers)
 * @param max_peers Maximum number of peers to return
 * @param count Output - actual number of connected peers
 * @return 0 on success, -1 on failure
 */
int p2p_get_connected_peers(
    p2p_transport_t *ctx,
    uint8_t (*pubkeys)[2592],  // Dilithium5 public keys
    size_t max_peers,
    size_t *count
);

/**
 * Disconnect from a specific peer
 *
 * @param ctx P2P transport context
 * @param peer_pubkey Peer's Dilithium5 public key (2592 bytes)
 * @return 0 on success, -1 if peer not connected
 */
int p2p_disconnect_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey
);

// ============================================================================
// Statistics
// ============================================================================

/**
 * Get P2P transport statistics
 *
 * @param ctx P2P transport context
 * @param connections_active Output - number of active TCP connections
 * @param messages_sent Output - total messages sent
 * @param messages_received Output - total messages received
 * @param offline_queued Output - messages queued in DHT
 * @return 0 on success, -1 on failure
 */
int p2p_get_stats(
    p2p_transport_t *ctx,
    size_t *connections_active,
    size_t *messages_sent,
    size_t *messages_received,
    size_t *offline_queued
);

#ifdef __cplusplus
}
#endif

#endif // P2P_TRANSPORT_H
