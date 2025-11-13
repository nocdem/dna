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
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")

    #define close closesocket
    typedef int socklen_t;
    #define sleep(x) Sleep((x)*1000)

    // Windows threading (use CRITICAL_SECTION instead of mutex)
    typedef HANDLE pthread_t;
    typedef CRITICAL_SECTION pthread_mutex_t;
    typedef void* (*pthread_func_t)(void*);

    #define pthread_create(thread, attr, func, arg) (*(thread) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func), (arg), 0, NULL), 0)
    #define pthread_join(thread, retval) (WaitForSingleObject((thread), INFINITE), 0)
    #define pthread_mutex_init(mutex, attr) (InitializeCriticalSection(mutex), 0)
    #define pthread_mutex_lock(mutex) (EnterCriticalSection(mutex), 0)
    #define pthread_mutex_unlock(mutex) (LeaveCriticalSection(mutex), 0)
    #define pthread_mutex_destroy(mutex) (DeleteCriticalSection(mutex), 0)
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * P2P Connection Structure (internal)
 * Represents a TCP connection to a peer
 */
struct p2p_connection {
    int sockfd;                         // TCP socket
    uint8_t peer_pubkey[2592];          // Peer's Dilithium5 public key
    char peer_ip[64];                   // Peer IP address
    uint16_t peer_port;                 // Peer port
    time_t connected_at;                // Connection timestamp
    pthread_t recv_thread;              // Receive thread
    bool active;                        // Connection active
};

/**
 * P2P Transport Context (internal)
 * Main structure for P2P transport layer
 */
struct p2p_transport {
    // Configuration
    p2p_config_t config;

    // DHT layer
    dht_context_t *dht;

    // My cryptographic keys
    uint8_t my_private_key[4016];       // Dilithium3 private key
    uint8_t my_public_key[2592];        // Dilithium5 public key
    uint8_t my_kyber_key[2400];         // Kyber512 private key

    // TCP listener
    int listen_sockfd;                  // Listening socket
    pthread_t listen_thread;            // Listener thread
    bool running;                       // Transport is running

    // Connections
    p2p_connection_t *connections[256]; // Max 256 concurrent connections
    size_t connection_count;
    pthread_mutex_t connections_mutex;

    // Callbacks
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

#ifdef __cplusplus
}
#endif

#endif // P2P_TRANSPORT_CORE_H
