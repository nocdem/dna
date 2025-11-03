#include "p2p_transport.h"
#include "dht_context.h"
#include "dht_offline_queue.h"
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

/**
 * P2P Connection Structure
 * Represents a TCP connection to a peer
 */
struct p2p_connection {
    int sockfd;                         // TCP socket
    uint8_t peer_pubkey[1952];          // Peer's Dilithium3 public key
    char peer_ip[64];                   // Peer IP address
    uint16_t peer_port;                 // Peer port
    time_t connected_at;                // Connection timestamp
    pthread_t recv_thread;              // Receive thread
    bool active;                        // Connection active
};

/**
 * P2P Transport Context
 * Main structure for P2P transport layer
 */
struct p2p_transport {
    // Configuration
    p2p_config_t config;

    // DHT layer
    dht_context_t *dht;

    // My cryptographic keys
    uint8_t my_private_key[4016];       // Dilithium3 private key
    uint8_t my_public_key[1952];        // Dilithium3 public key
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

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get external IP address
 * TODO: Implement proper external IP detection (STUN, HTTP API, etc.)
 * For now, returns "0.0.0.0" as placeholder
 */
static int get_external_ip(char *ip_out, size_t len) {
#ifdef _WIN32
    // Windows implementation using GetAdaptersAddresses
    IP_ADAPTER_ADDRESSES *addresses = NULL;
    IP_ADAPTER_ADDRESSES *adapter = NULL;
    ULONG size = 0;
    ULONG result;
    int found = 0;

    // Get required buffer size
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &size);
    if (result != ERROR_BUFFER_OVERFLOW) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    addresses = (IP_ADAPTER_ADDRESSES *)malloc(size);
    if (!addresses) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, addresses, &size);
    if (result != NO_ERROR) {
        free(addresses);
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    // Look for first non-loopback IPv4 address
    for (adapter = addresses; adapter != NULL; adapter = adapter->Next) {
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;

        IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
        if (unicast && unicast->Address.lpSockaddr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1)
            if (strncmp(ip, "127.", 4) != 0) {
                snprintf(ip_out, len, "%s", ip);
                found = 1;
                break;
            }
        }
    }

    free(addresses);

    if (!found) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    return 0;
#else
    // Linux implementation using getifaddrs
    struct ifaddrs *ifaddr, *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) == -1) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    // Look for first non-loopback IPv4 address
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {  // IPv4
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            const char *ip = inet_ntoa(addr->sin_addr);

            // Skip loopback (127.0.0.1)
            if (strncmp(ip, "127.", 4) != 0) {
                snprintf(ip_out, len, "%s", ip);
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    if (!found) {
        snprintf(ip_out, len, "0.0.0.0");
        return -1;
    }

    return 0;
#endif
}

/**
 * Compute SHA256 hash
 * Used for DHT keys: key = SHA256(public_key)
 * Updated to use OpenSSL 3.0 EVP API
 */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash_out, NULL);
    EVP_MD_CTX_free(ctx);
}

/**
 * Create JSON string for peer presence
 * Format: {"ip":"x.x.x.x","port":4001,"timestamp":1234567890}
 */
static int create_presence_json(const char *ip, uint16_t port, char *json_out, size_t len) {
    int written = snprintf(json_out, len,
                          "{\"ip\":\"%s\",\"port\":%d,\"timestamp\":%ld}",
                          ip, port, time(NULL));
    return (written < len) ? 0 : -1;
}

/**
 * Parse JSON presence data
 * Simple manual parsing (no json-c dependency for minimal build)
 */
static int parse_presence_json(const char *json_str, peer_info_t *peer_info) {
    // Extract IP
    const char *ip_start = strstr(json_str, "\"ip\":\"");
    if (ip_start) {
        ip_start += 6;
        const char *ip_end = strchr(ip_start, '"');
        if (ip_end) {
            size_t ip_len = ip_end - ip_start;
            if (ip_len < sizeof(peer_info->ip)) {
                memcpy(peer_info->ip, ip_start, ip_len);
                peer_info->ip[ip_len] = '\0';
            }
        }
    }

    // Extract port
    const char *port_start = strstr(json_str, "\"port\":");
    if (port_start) {
        peer_info->port = (uint16_t)atoi(port_start + 7);
    }

    // Extract timestamp
    const char *ts_start = strstr(json_str, "\"timestamp\":");
    if (ts_start) {
        peer_info->last_seen = (uint64_t)atoll(ts_start + 12);
    }

    return 0;
}

// ============================================================================
// TCP Connection Handler
// ============================================================================

/**
 * Connection receive thread
 * Handles incoming messages from a peer
 */
static void* connection_recv_thread(void *arg) {
    p2p_connection_t *conn = (p2p_connection_t*)arg;

    printf("[P2P] Receive thread started for peer\n");

    uint8_t buffer[65536];
    while (conn->active) {
        ssize_t received = recv(conn->sockfd, buffer, sizeof(buffer), 0);
        if (received <= 0) {
            printf("[P2P] Connection closed by peer\n");
            conn->active = false;
            break;
        }

        // TODO: Decrypt and verify message
        // TODO: Call message callback
        printf("[P2P] Received %zd bytes from peer\n", received);
    }

    return NULL;
}

/**
 * Accept incoming connections (listener thread)
 */
static void* listener_thread(void *arg) {
    p2p_transport_t *ctx = (p2p_transport_t*)arg;

    printf("[P2P] Listener thread started on port %d\n", ctx->config.listen_port);

    while (ctx->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_sock = accept(ctx->listen_sockfd,
                                 (struct sockaddr*)&client_addr,
                                 &client_len);

        if (client_sock < 0) {
            if (ctx->running) {
                printf("[P2P] Accept error: %s\n", strerror(errno));
            }
            continue;
        }

        printf("[P2P] New connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        // Receive incoming message
        // Format: [4-byte length][message data]
        uint32_t msg_len_network;
        ssize_t received = recv(client_sock, (char*)&msg_len_network, sizeof(msg_len_network), 0);

        if (received != sizeof(msg_len_network)) {
            printf("[P2P] Failed to receive message length header\n");
            close(client_sock);
            continue;
        }

        uint32_t msg_len = ntohl(msg_len_network);

        // Sanity check: max 10MB message
        if (msg_len == 0 || msg_len > 10 * 1024 * 1024) {
            printf("[P2P] Invalid message length: %u bytes\n", msg_len);
            close(client_sock);
            continue;
        }

        // Allocate buffer and receive message
        uint8_t *message = (uint8_t*)malloc(msg_len);
        if (!message) {
            printf("[P2P] Failed to allocate %u bytes for message\n", msg_len);
            close(client_sock);
            continue;
        }

        size_t total_received = 0;
        while (total_received < msg_len) {
            received = recv(client_sock, (char*)message + total_received,
                          msg_len - total_received, 0);
            if (received <= 0) {
                printf("[P2P] Connection closed while receiving message\n");
                free(message);
                close(client_sock);
                goto next_connection;
            }
            total_received += received;
        }

        printf("[P2P] ✓ Received %u bytes from peer\n", msg_len);

        // Call message callback if registered (stores message in PostgreSQL)
        if (ctx->message_callback) {
            // Note: We don't have the peer's public key here (would need handshake)
            // For now, pass NULL - the callback can try to identify sender from message content
            ctx->message_callback(NULL, message, msg_len, ctx->callback_user_data);
        }

        // Send ACK (1 byte = 0x01) to confirm receipt
        uint8_t ack = 0x01;
        ssize_t ack_sent = send(client_sock, (char*)&ack, 1, 0);
        if (ack_sent == 1) {
            printf("[P2P] ✓ Sent ACK to peer\n");
        } else {
            printf("[P2P] Failed to send ACK (peer may assume failure)\n");
        }

        free(message);
        close(client_sock);

next_connection:
        continue;
    }

    return NULL;
}

// ============================================================================
// Core API Implementation
// ============================================================================

p2p_transport_t* p2p_transport_init(
    const p2p_config_t *config,
    const uint8_t *my_privkey_dilithium,
    const uint8_t *my_pubkey_dilithium,
    const uint8_t *my_kyber_key,
    p2p_message_callback_t message_callback,
    p2p_connection_callback_t connection_callback,
    void *callback_user_data)
{
    if (!config || !my_privkey_dilithium || !my_pubkey_dilithium || !my_kyber_key) {
        return NULL;
    }

    p2p_transport_t *ctx = (p2p_transport_t*)calloc(1, sizeof(p2p_transport_t));
    if (!ctx) {
        return NULL;
    }

    // Copy configuration
    memcpy(&ctx->config, config, sizeof(p2p_config_t));

    // Copy keys
    memcpy(ctx->my_private_key, my_privkey_dilithium, 4016);
    memcpy(ctx->my_public_key, my_pubkey_dilithium, 1952);
    memcpy(ctx->my_kyber_key, my_kyber_key, 2400);

    // Callbacks
    ctx->message_callback = message_callback;
    ctx->connection_callback = connection_callback;
    ctx->callback_user_data = callback_user_data;

    // Initialize mutex
    pthread_mutex_init(&ctx->connections_mutex, NULL);

    // Initialize DHT
    dht_config_t dht_config = {0};
    dht_config.port = config->dht_port;
    dht_config.is_bootstrap = false;
    snprintf(dht_config.identity, sizeof(dht_config.identity), "%s", config->identity);

    for (size_t i = 0; i < config->bootstrap_count && i < 5; i++) {
        snprintf(dht_config.bootstrap_nodes[i], 256, "%s", config->bootstrap_nodes[i]);
    }
    dht_config.bootstrap_count = config->bootstrap_count;

    ctx->dht = dht_context_new(&dht_config);
    if (!ctx->dht) {
        printf("[P2P] Failed to create DHT context\n");
        free(ctx);
        return NULL;
    }

    ctx->listen_sockfd = -1;
    ctx->running = false;

    printf("[P2P] Transport initialized (DHT port: %d, TCP port: %d)\n",
           config->dht_port, config->listen_port);

    return ctx;
}

int p2p_transport_start(p2p_transport_t *ctx) {
    if (!ctx || ctx->running) {
        return -1;
    }

    // Start DHT
    if (dht_context_start(ctx->dht) != 0) {
        printf("[P2P] Failed to start DHT\n");
        return -1;
    }

    printf("[P2P] DHT started on port %d\n", ctx->config.dht_port);

    // Create TCP listening socket
    ctx->listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_sockfd < 0) {
        printf("[P2P] Failed to create listening socket: %s\n", strerror(errno));
        dht_context_stop(ctx->dht);
        return -1;
    }

    // Set socket options
    int opt = 1;
#ifdef _WIN32
    setsockopt(ctx->listen_sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(ctx->listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    // Bind to port
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(ctx->config.listen_port);

    if (bind(ctx->listen_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("[P2P] Failed to bind to port %d: %s\n",
               ctx->config.listen_port, strerror(errno));
        close(ctx->listen_sockfd);
        dht_context_stop(ctx->dht);
        return -1;
    }

    // Start listening
    if (listen(ctx->listen_sockfd, 32) < 0) {
        printf("[P2P] Failed to listen: %s\n", strerror(errno));
        close(ctx->listen_sockfd);
        dht_context_stop(ctx->dht);
        return -1;
    }

    printf("[P2P] TCP listener started on port %d\n", ctx->config.listen_port);

    // Start listener thread
    ctx->running = true;
    if (pthread_create(&ctx->listen_thread, NULL, listener_thread, ctx) != 0) {
        printf("[P2P] Failed to create listener thread\n");
        close(ctx->listen_sockfd);
        dht_context_stop(ctx->dht);
        ctx->running = false;
        return -1;
    }

    printf("[P2P] Listener thread started\n");

    return 0;
}

void p2p_transport_stop(p2p_transport_t *ctx) {
    if (!ctx || !ctx->running) {
        return;
    }

    printf("[P2P] Stopping transport...\n");

    ctx->running = false;

    // Close listening socket (will unblock accept())
    if (ctx->listen_sockfd >= 0) {
        close(ctx->listen_sockfd);
        ctx->listen_sockfd = -1;
    }

    // Wait for listener thread
    pthread_join(ctx->listen_thread, NULL);

    // Close all connections
    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i]) {
            ctx->connections[i]->active = false;
            close(ctx->connections[i]->sockfd);
            pthread_join(ctx->connections[i]->recv_thread, NULL);
            free(ctx->connections[i]);
            ctx->connections[i] = NULL;
        }
    }
    ctx->connection_count = 0;
    pthread_mutex_unlock(&ctx->connections_mutex);

    // Stop DHT
    dht_context_stop(ctx->dht);

    printf("[P2P] Transport stopped\n");
}

void p2p_transport_free(p2p_transport_t *ctx) {
    if (!ctx) {
        return;
    }

    p2p_transport_stop(ctx);

    if (ctx->dht) {
        dht_context_free(ctx->dht);
    }

    pthread_mutex_destroy(&ctx->connections_mutex);

    // Clear sensitive keys
    memset(ctx->my_private_key, 0, sizeof(ctx->my_private_key));
    memset(ctx->my_kyber_key, 0, sizeof(ctx->my_kyber_key));

    free(ctx);
}

// ============================================================================
// Peer Discovery (DHT-based)
// ============================================================================

int p2p_register_presence(p2p_transport_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Get external IP
    char my_ip[64];
    if (get_external_ip(my_ip, sizeof(my_ip)) != 0) {
        printf("[P2P] Failed to get external IP\n");
        return -1;
    }

    // Create presence JSON
    char presence_data[512];
    if (create_presence_json(my_ip, ctx->config.listen_port,
                            presence_data, sizeof(presence_data)) != 0) {
        printf("[P2P] Failed to create presence JSON\n");
        return -1;
    }

    // Compute DHT key: SHA256(public_key)
    uint8_t dht_key[32];
    sha256_hash(ctx->my_public_key, 1952, dht_key);

    printf("[P2P] Registering presence in DHT\n");
    printf("[P2P] DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);
    printf("[P2P] Presence data: %s\n", presence_data);

    // Store in DHT
    int result = dht_put(ctx->dht, dht_key, sizeof(dht_key),
                        (const uint8_t*)presence_data, strlen(presence_data));

    if (result == 0) {
        printf("[P2P] Presence registered successfully\n");
    } else {
        printf("[P2P] Failed to register presence in DHT\n");
    }

    return result;
}

int p2p_lookup_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    peer_info_t *peer_info)
{
    if (!ctx || !peer_pubkey || !peer_info) {
        return -1;
    }

    // Compute DHT key: SHA256(peer_pubkey)
    uint8_t dht_key[32];
    sha256_hash(peer_pubkey, 1952, dht_key);

    printf("[P2P] Looking up peer in DHT\n");
    printf("[P2P] DHT key (first 8 bytes): %02x%02x%02x%02x%02x%02x%02x%02x\n",
           dht_key[0], dht_key[1], dht_key[2], dht_key[3],
           dht_key[4], dht_key[5], dht_key[6], dht_key[7]);

    // Query DHT
    uint8_t *value = NULL;
    size_t value_len = 0;

    if (dht_get(ctx->dht, dht_key, sizeof(dht_key), &value, &value_len) != 0 || !value) {
        printf("[P2P] Peer not found in DHT\n");
        return -1;
    }

    printf("[P2P] Found peer data: %.*s\n", (int)value_len, value);

    // Parse JSON
    if (parse_presence_json((const char*)value, peer_info) != 0) {
        printf("[P2P] Failed to parse peer presence JSON\n");
        free(value);
        return -1;
    }

    // Copy public key
    memcpy(peer_info->public_key, peer_pubkey, 1952);

    // Check if peer is online (last seen < 10 minutes)
    time_t now = time(NULL);
    peer_info->is_online = (now - (time_t)peer_info->last_seen) < 600;

    free(value);

    printf("[P2P] Peer lookup successful: %s:%d (online: %s)\n",
           peer_info->ip, peer_info->port,
           peer_info->is_online ? "yes" : "no");

    return 0;
}

// ============================================================================
// Direct Messaging (Stub - TODO)
// ============================================================================

int p2p_send_message(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const uint8_t *message,
    size_t message_len)
{
    if (!ctx || !peer_pubkey || !message || message_len == 0) {
        fprintf(stderr, "[P2P] Invalid parameters\n");
        return -1;
    }

    // Step 1: Look up peer in DHT
    peer_info_t peer_info;
    if (p2p_lookup_peer(ctx, peer_pubkey, &peer_info) != 0) {
        printf("[P2P] Peer not found in DHT - may be offline\n");
        return -1;  // Peer not online, use PostgreSQL fallback
    }

    if (!peer_info.is_online) {
        printf("[P2P] Peer last seen too long ago - may be offline\n");
        return -1;  // Peer appears offline, use PostgreSQL fallback
    }

    printf("[P2P] Connecting to peer at %s:%d...\n", peer_info.ip, peer_info.port);

    // Step 2: Establish TCP connection
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[P2P] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    // Set connection timeout (3 seconds)
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_info.port);

    if (inet_pton(AF_INET, peer_info.ip, &peer_addr.sin_addr) <= 0) {
        fprintf(stderr, "[P2P] Invalid peer IP address: %s\n", peer_info.ip);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        fprintf(stderr, "[P2P] Failed to connect to %s:%d: %s\n",
                peer_info.ip, peer_info.port, strerror(errno));
        close(sockfd);
        return -1;
    }

    printf("[P2P] ✓ Connected to peer at %s:%d\n", peer_info.ip, peer_info.port);

    // Step 3: Send message
    // Format: [4-byte length][message data]
    uint32_t msg_len_network = htonl((uint32_t)message_len);

    // Send length header
    ssize_t sent = send(sockfd, (char*)&msg_len_network, sizeof(msg_len_network), 0);
    if (sent != sizeof(msg_len_network)) {
        fprintf(stderr, "[P2P] Failed to send message length header\n");
        close(sockfd);
        return -1;
    }

    // Send message data
    size_t total_sent = 0;
    while (total_sent < message_len) {
        sent = send(sockfd, (char*)message + total_sent, message_len - total_sent, 0);
        if (sent <= 0) {
            fprintf(stderr, "[P2P] Failed to send message data: %s\n", strerror(errno));
            close(sockfd);
            return -1;
        }
        total_sent += sent;
    }

    printf("[P2P] ✓ Sent %zu bytes to peer\n", message_len);

    // Step 4: Wait for ACK (1 byte acknowledgment)
    // This confirms the peer received AND stored the message
    uint8_t ack;
    ssize_t ack_received = recv(sockfd, (char*)&ack, 1, 0);

    if (ack_received == 1 && ack == 0x01) {
        printf("[P2P] ✓ Received ACK from peer (message confirmed)\n");
        close(sockfd);
        return 0;  // Success - peer confirmed receipt
    } else {
        printf("[P2P] ⚠ No ACK received from peer (may not have processed message)\n");
        close(sockfd);
        return -1;  // Consider failed - fallback to PostgreSQL reliability
    }
}

int p2p_check_offline_messages(
    p2p_transport_t *ctx,
    size_t *messages_received)
{
    if (!ctx) {
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        printf("[P2P] Offline queue disabled, skipping check\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    printf("[P2P] Checking DHT for offline messages...\n");

    // 1. Retrieve queued messages from DHT
    // Key: SHA256(my_identity + ":offline_queue")
    dht_offline_message_t *messages = NULL;
    size_t count = 0;

    int result = dht_retrieve_queued_messages(
        ctx->dht,
        ctx->config.identity,
        &messages,
        &count
    );

    if (result != 0) {
        fprintf(stderr, "[P2P] Failed to retrieve offline messages from DHT\n");
        if (messages_received) *messages_received = 0;
        return -1;
    }

    if (count == 0) {
        printf("[P2P] No offline messages in DHT\n");
        if (messages_received) *messages_received = 0;
        return 0;
    }

    printf("[P2P] Found %zu offline messages in DHT\n", count);

    // 2. Deliver each message via callback
    size_t delivered_count = 0;
    for (size_t i = 0; i < count; i++) {
        dht_offline_message_t *msg = &messages[i];

        printf("[P2P] Delivering offline message %zu/%zu from %s (%zu bytes)\n",
               i + 1, count, msg->sender, msg->ciphertext_len);

        // Deliver to application layer (messenger_p2p.c)
        // Note: Sender pubkey is unknown for offline messages (would need reverse lookup)
        // Callback will try to identify sender from message content
        if (ctx->message_callback) {
            ctx->message_callback(
                NULL,  // peer_pubkey (unknown for offline messages)
                msg->ciphertext,
                msg->ciphertext_len,
                ctx->callback_user_data
            );
            delivered_count++;
        } else {
            printf("[P2P] Warning: No message callback registered, skipping message\n");
        }
    }

    printf("[P2P] ✓ Delivered %zu/%zu offline messages\n", delivered_count, count);

    // 3. Clear queue in DHT
    if (delivered_count > 0) {
        printf("[P2P] Clearing offline message queue in DHT\n");
        int clear_result = dht_clear_queue(ctx->dht, ctx->config.identity);
        if (clear_result != 0) {
            fprintf(stderr, "[P2P] Warning: Failed to clear offline queue (messages may be delivered again)\n");
        } else {
            printf("[P2P] ✓ Offline queue cleared\n");
        }
    }

    if (messages_received) {
        *messages_received = delivered_count;
    }

    dht_offline_messages_free(messages, count);
    return 0;
}

int p2p_queue_offline_message(
    p2p_transport_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *message,
    size_t message_len)
{
    if (!ctx || !sender || !recipient || !message || message_len == 0) {
        fprintf(stderr, "[P2P] Invalid parameters for queuing offline message\n");
        return -1;
    }

    if (!ctx->config.enable_offline_queue) {
        printf("[P2P] Offline queue disabled\n");
        return -1;
    }

    printf("[P2P] Queueing offline message for %s (%zu bytes)\n", recipient, message_len);

    int result = dht_queue_message(
        ctx->dht,
        sender,
        recipient,
        message,
        message_len,
        ctx->config.offline_ttl_seconds
    );

    if (result == 0) {
        printf("[P2P] ✓ Message queued successfully\n");
    } else {
        fprintf(stderr, "[P2P] Failed to queue message in DHT\n");
    }

    return result;
}

// ============================================================================
// Connection Management (Stub - TODO)
// ============================================================================

int p2p_get_connected_peers(
    p2p_transport_t *ctx,
    uint8_t (*pubkeys)[1952],
    size_t max_peers,
    size_t *count)
{
    if (!ctx || !pubkeys || !count) {
        return -1;
    }

    pthread_mutex_lock(&ctx->connections_mutex);
    *count = ctx->connection_count < max_peers ? ctx->connection_count : max_peers;

    size_t idx = 0;
    for (size_t i = 0; i < 256 && idx < *count; i++) {
        if (ctx->connections[i] && ctx->connections[i]->active) {
            memcpy(pubkeys[idx], ctx->connections[i]->peer_pubkey, 1952);
            idx++;
        }
    }
    pthread_mutex_unlock(&ctx->connections_mutex);

    return 0;
}

int p2p_disconnect_peer(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey)
{
    if (!ctx || !peer_pubkey) {
        return -1;
    }

    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i] &&
            memcmp(ctx->connections[i]->peer_pubkey, peer_pubkey, 1952) == 0) {

            ctx->connections[i]->active = false;
            close(ctx->connections[i]->sockfd);
            pthread_join(ctx->connections[i]->recv_thread, NULL);
            free(ctx->connections[i]);
            ctx->connections[i] = NULL;
            ctx->connection_count--;
            pthread_mutex_unlock(&ctx->connections_mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&ctx->connections_mutex);

    return -1; // Not found
}

// ============================================================================
// Statistics
// ============================================================================

int p2p_get_stats(
    p2p_transport_t *ctx,
    size_t *connections_active,
    size_t *messages_sent,
    size_t *messages_received,
    size_t *offline_queued)
{
    if (!ctx) {
        return -1;
    }

    if (connections_active) {
        pthread_mutex_lock(&ctx->connections_mutex);
        *connections_active = ctx->connection_count;
        pthread_mutex_unlock(&ctx->connections_mutex);
    }

    if (messages_sent) *messages_sent = ctx->messages_sent;
    if (messages_received) *messages_received = ctx->messages_received;
    if (offline_queued) *offline_queued = ctx->offline_queued;

    return 0;
}
