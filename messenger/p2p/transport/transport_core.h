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
#include "transport_ice.h"  // Phase 11 FIX: ICE support

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Connection Type
 * Identifies transport mechanism for this connection
 */
typedef enum {
    CONNECTION_TYPE_TCP = 0,   // Direct TCP connection (LAN or public IP)
    CONNECTION_TYPE_ICE = 1    // ICE NAT traversal connection
} connection_type_t;

/**
 * P2P Connection Structure (internal)
 * Represents a connection to a peer (TCP or ICE)
 *
 * Phase 11 FIX: Added ICE support with connection type discrimination
 */
struct p2p_connection {
    connection_type_t type;             // Connection type (TCP or ICE)

    // Common fields
    uint8_t peer_pubkey[2592];          // Peer's Dilithium5 public key
    char peer_fingerprint[129];         // Peer fingerprint (SHA3-512 hex)
    time_t connected_at;                // Connection timestamp
    pthread_t recv_thread;              // Receive thread
    bool active;                        // Connection active

    // Back-pointer to transport (for callback invocation in recv thread)
    struct p2p_transport *transport;    // Parent transport context

    // TCP-specific fields (used when type == TCP)
    int sockfd;                         // TCP socket
    char peer_ip[64];                   // Peer IP address
    uint16_t peer_port;                 // Peer port

    // ICE-specific fields (used when type == ICE)
    ice_context_t *ice_ctx;             // ICE context (NULL if TCP)
};

/**
 * P2P Transport Context (internal)
 * Main structure for P2P transport layer
 *
 * Phase 11 FIX: Added persistent ICE support
 */
struct p2p_transport {
    // Configuration
    p2p_config_t config;

    // DHT layer
    dht_context_t *dht;

    // My cryptographic keys (NIST Category 5: ML-DSA-87 + ML-KEM-1024)
    uint8_t my_private_key[4896];       // Dilithium5 private key (ML-DSA-87)
    uint8_t my_public_key[2592];        // Dilithium5 public key (ML-DSA-87)
    uint8_t my_kyber_key[3168];         // Kyber1024 private key (ML-KEM-1024)
    char my_fingerprint[129];           // My fingerprint (SHA3-512 hex)

    // TCP listener
    int listen_sockfd;                  // Listening socket
    pthread_t listen_thread;            // Listener thread
    bool running;                       // Transport is running

    // ICE support (Phase 11 FIX: persistent ICE context)
    ice_context_t *ice_context;         // Persistent ICE agent (one per app instance)
    bool ice_ready;                     // ICE initialized and candidates published
    pthread_t ice_listen_thread;        // ICE listener thread for incoming connections
    pthread_mutex_t ice_mutex;          // Protect ICE context access

    // Connections (both TCP and ICE)
    p2p_connection_t *connections[256]; // Max 256 concurrent connections (TCP + ICE)
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

/**
 * Get external IP address (for presence registration)
 * @param ip_out: Output buffer for IP string
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int get_external_ip(char *ip_out, size_t len);

/**
 * Get public IP address via STUN query
 * Queries STUN server to discover NAT-mapped public IP
 * @param ip_out: Output buffer for public IP string
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int stun_get_public_ip(char *ip_out, size_t len);

/**
 * Create presence JSON for DHT registration
 * @param ip: IP address
 * @param port: TCP port
 * @param json_out: Output JSON string buffer
 * @param len: Buffer length
 * @return: 0 on success, -1 on failure
 */
int create_presence_json(const char *ip, uint16_t port, char *json_out, size_t len);

/**
 * Parse presence JSON from DHT
 * @param json_str: JSON string
 * @param peer_info: Output peer info structure
 * @return: 0 on success, -1 on failure
 */
int parse_presence_json(const char *json_str, peer_info_t *peer_info);

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

/**
 * Initialize persistent ICE context (Phase 11 FIX)
 * Creates ICE agent, gathers candidates, publishes to DHT
 * Called once at startup
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int ice_init_persistent(p2p_transport_t *ctx);

/**
 * Shutdown persistent ICE context (Phase 11 FIX)
 * Stops ICE listener thread, closes all ICE connections
 * @param ctx: P2P transport context
 */
void ice_shutdown_persistent(p2p_transport_t *ctx);

/**
 * ICE listener thread (Phase 11 FIX)
 * Monitors for incoming ICE connections (not used in current design)
 * @param arg: p2p_transport_t pointer
 * @return: NULL
 */
void* ice_listener_thread(void *arg);

/**
 * Find or create ICE connection to peer (Phase 11 FIX)
 * Reuses existing ICE connection if available, creates new one otherwise
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key
 * @param peer_fingerprint: Peer's fingerprint (SHA3-512 hex)
 * @return: p2p_connection_t on success, NULL on error
 */
p2p_connection_t* ice_get_or_create_connection(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const char *peer_fingerprint);

/**
 * ICE connection receive thread (Phase 11 FIX)
 * Reads messages from ICE connection and invokes callback
 * @param arg: p2p_connection_t pointer
 * @return: NULL
 */
void* ice_connection_recv_thread(void *arg);

#ifdef __cplusplus
}
#endif

#endif // P2P_TRANSPORT_CORE_H
