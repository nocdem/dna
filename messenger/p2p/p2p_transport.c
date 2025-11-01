#include "p2p_transport.h"
#include "dht_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <openssl/sha.h>
#include <errno.h>

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
    // Get primary network interface IP (not loopback)
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
}

/**
 * Compute SHA256 hash
 * Used for DHT keys: key = SHA256(public_key)
 */
static void sha256_hash(const uint8_t *data, size_t len, uint8_t *hash_out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash_out, &ctx);
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

        // TODO: Handshake to exchange public keys
        // TODO: Create connection structure and receive thread
        // For now, just close the connection
        close(client_sock);
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
    setsockopt(ctx->listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

    // Check if peer is online (last seen < 5 minutes)
    time_t now = time(NULL);
    peer_info->is_online = (now - (time_t)peer_info->last_seen) < 300;

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
    if (!ctx || !peer_pubkey || !message) {
        return -1;
    }

    printf("[P2P] TODO: Implement p2p_send_message\n");

    // TODO:
    // 1. Look up peer in DHT
    // 2. Establish TCP connection if not connected
    // 3. Encrypt message (Kyber512 + AES-256-GCM)
    // 4. Sign with Dilithium3
    // 5. Send over TCP
    // 6. If offline, queue in DHT

    return -1;
}

int p2p_check_offline_messages(
    p2p_transport_t *ctx,
    size_t *messages_received)
{
    if (!ctx) {
        return -1;
    }

    printf("[P2P] TODO: Implement p2p_check_offline_messages\n");

    // TODO:
    // 1. Query DHT for offline messages: hash(my_pubkey) -> message_queue
    // 2. Decrypt and verify each message
    // 3. Deliver via callback
    // 4. Delete from DHT

    if (messages_received) {
        *messages_received = 0;
    }

    return 0;
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
