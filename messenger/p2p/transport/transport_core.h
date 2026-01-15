/**
 * P2P Transport Core - Shared types and internal APIs
 * Used by all transport modules
 */

#ifndef P2P_TRANSPORT_CORE_H
#define P2P_TRANSPORT_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
    #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #endif

    #define close closesocket
    typedef int socklen_t;
    #define sleep(x) Sleep((x)*1000)

    // llvm-mingw provides proper pthread support - use it
    #include <pthread.h>
#else
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <ifaddrs.h>
#endif

// External dependencies
#include "p2p_transport.h"
#include "dht_context.h"
#include "dht_offline_queue.h"
#include "dht_singleton.h"
#include "../database/contacts_db.h"
#include "../crypto/utils/qgp_sha3.h"
// ICE/STUN/TURN removed in v0.4.61 for privacy (IP address leakage)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Connection Type
 * Identifies transport mechanism for this connection
 * Note: ICE removed in v0.4.61 for privacy - only TCP for LAN connections
 */
typedef enum {
    CONNECTION_TYPE_TCP = 0    // Direct TCP connection (LAN only, no external IP published)
} connection_type_t;

/**
 * P2P Connection Structure (internal)
 * Represents a TCP connection to a peer
 *
 * Note: ICE removed in v0.4.61 for privacy - TCP only for LAN connections
 */
struct p2p_connection {
    connection_type_t type;             // Connection type (TCP only)

    // Common fields
    uint8_t peer_pubkey[2592];          // Peer's Dilithium5 public key
    char peer_fingerprint[129];         // Peer fingerprint (SHA3-512 hex)
    time_t connected_at;                // Connection timestamp
    pthread_t recv_thread;              // Receive thread
    bool active;                        // Connection active

    // Back-pointer to transport (for callback invocation in recv thread)
    struct p2p_transport *transport;    // Parent transport context

    // TCP-specific fields
    int sockfd;                         // TCP socket
    char peer_ip[64];                   // Peer IP address (LAN only)
    uint16_t peer_port;                 // Peer port
};

/**
 * P2P Transport Context (internal)
 * Main structure for P2P transport layer
 *
 * Note: ICE/STUN/TURN removed in v0.4.61 for privacy
 * DHT-only messaging, TCP kept for potential LAN connections
 */
struct p2p_transport {
    // Configuration
    p2p_config_t config;

    // NOTE: DHT access via dht_singleton_get() - P2P transport is for TCP only
    // DHT field removed in Phase 14 refactoring (v0.3.122)

    // My cryptographic keys (NIST Category 5: ML-DSA-87 + ML-KEM-1024)
    uint8_t my_private_key[4896];       // Dilithium5 private key (ML-DSA-87)
    uint8_t my_public_key[2592];        // Dilithium5 public key (ML-DSA-87)
    uint8_t my_kyber_key[3168];         // Kyber1024 private key (ML-KEM-1024)
    char my_fingerprint[129];           // My fingerprint (SHA3-512 hex)

    // TCP listener (kept for potential LAN connections)
    int listen_sockfd;                  // Listening socket
    pthread_t listen_thread;            // Listener thread
    bool running;                       // Transport is running

    // Connections (TCP only)
    p2p_connection_t *connections[256]; // Max 256 concurrent connections
    size_t connection_count;
    pthread_mutex_t connections_mutex;

    // Callbacks (protected by callback_mutex to prevent TOCTOU race conditions)
    pthread_mutex_t callback_mutex;
    p2p_message_callback_t message_callback;
    p2p_connection_callback_t connection_callback;
    void *callback_user_data;

    // Statistics
    size_t messages_sent;
    size_t messages_received;
    size_t offline_queued;
};

// ===== HELPER FUNCTIONS (internal use by transport modules) =====

/**
 * Compute SHA3-512 hash
 * @param data: Input data
 * @param len: Length of data
 * @param hash_out: Output hash (64 bytes)
 */
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t *hash_out);

// Note: get_external_ip() and stun_get_public_ip() removed in v0.4.61
// Presence now only publishes timestamp, no IP address (privacy)

/**
 * Create presence JSON for DHT registration (timestamp only - privacy)
 * @param json_out: Output JSON string buffer
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int create_presence_json(char *json_out, size_t len);

/**
 * Parse presence JSON from DHT (timestamp only)
 * @param json_str: JSON string
 * @param last_seen_out: Output timestamp
 * @return: 0 on success, -1 on failure
 */
int parse_presence_json(const char *json_str, uint64_t *last_seen_out);

/**
 * TCP connection receive thread (internal)
 * @param arg: p2p_connection_t pointer
 * @return: NULL
 */
void* connection_recv_thread(void *arg);

/**
 * TCP listener thread (internal)
 * @param arg: p2p_transport_t pointer
 * @return: NULL
 */
void* listener_thread(void *arg);

/**
 * Create and bind TCP listening socket (internal)
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int tcp_create_listener(p2p_transport_t *ctx);

/**
 * Start TCP listener thread (internal)
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int tcp_start_listener_thread(p2p_transport_t *ctx);

/**
 * Stop TCP listener and close all connections (internal)
 * @param ctx: P2P transport context
 */
void tcp_stop_listener(p2p_transport_t *ctx);

// ICE functions removed in v0.4.61 for privacy
// (ice_init_persistent, ice_shutdown_persistent, ice_listener_thread,
//  ice_get_or_create_connection, ice_connection_recv_thread)

#ifdef __cplusplus
}
#endif

#endif // P2P_TRANSPORT_CORE_H
