/**
 * P2P Transport TCP Module
 * TCP listener, connections, socket management
 */

#include "transport_core.h"

/**
 * NOTE: This function is for future persistent bidirectional P2P connections (not currently used).
 * Active implementation uses short-lived connections in listener_thread() below.
 * See listener_thread() for active message callback and messenger_p2p.c for decryption.
 */

/**
 * Accept incoming connections (listener thread)
 * @param arg: p2p_transport_t pointer
 * @return: NULL
 */
void* listener_thread(void *arg) {
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

        // Call message callback if registered (stores message in SQLite)
        // Protected by callback_mutex to prevent TOCTOU race condition
        pthread_mutex_lock(&ctx->callback_mutex);
        if (ctx->message_callback) {
            // Note: We don't have the peer's public key here (would need handshake)
            // For now, pass NULL - the callback can try to identify sender from message content
            ctx->message_callback(NULL, NULL, message, msg_len, ctx->callback_user_data);
        }
        pthread_mutex_unlock(&ctx->callback_mutex);

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

/**
 * Create and bind TCP listening socket
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int tcp_create_listener(p2p_transport_t *ctx) {
    if (!ctx) {
        return -1;
    }

    // Create TCP listening socket
    ctx->listen_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_sockfd < 0) {
        printf("[P2P] Failed to create listening socket: %s\n", strerror(errno));
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
        return -1;
    }

    // Start listening
    if (listen(ctx->listen_sockfd, 32) < 0) {
        printf("[P2P] Failed to listen: %s\n", strerror(errno));
        close(ctx->listen_sockfd);
        return -1;
    }

    printf("[P2P] TCP listener started on port %d\n", ctx->config.listen_port);

    return 0;
}

/**
 * Start TCP listener thread
 * @param ctx: P2P transport context
 * @return: 0 on success, -1 on error
 */
int tcp_start_listener_thread(p2p_transport_t *ctx) {
    if (!ctx) {
        return -1;
    }

    ctx->running = true;
    if (pthread_create(&ctx->listen_thread, NULL, listener_thread, ctx) != 0) {
        printf("[P2P] Failed to create listener thread\n");
        ctx->running = false;
        return -1;
    }

    printf("[P2P] Listener thread started\n");

    return 0;
}

/**
 * Stop TCP listener and close all connections
 * @param ctx: P2P transport context
 */
void tcp_stop_listener(p2p_transport_t *ctx) {
    if (!ctx) {
        return;
    }

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
}
