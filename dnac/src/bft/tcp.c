/**
 * @file tcp.c
 * @brief TCP Networking for BFT Witness Mesh
 *
 * Implements TCP server and client for witness-to-witness communication.
 * Uses epoll for efficient I/O multiplexing on Linux.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "dnac/tcp.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "BFT_TCP"

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

uint64_t dnac_tcp_get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_keepalive(int fd) {
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

    /* TCP keepalive settings */
    optval = 60;  /* Start probing after 60 seconds of idle */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, sizeof(optval));

    optval = 10;  /* Probe interval 10 seconds */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, sizeof(optval));

    optval = 3;   /* Max 3 probes */
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, sizeof(optval));

    return 0;
}

int dnac_tcp_parse_address(const char *address, char *host_out, uint16_t *port_out) {
    if (!address || !host_out || !port_out) {
        return -1;
    }

    /* Find the last colon (for IPv6 support) */
    const char *colon = strrchr(address, ':');
    if (!colon) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid address format (no port): %s", address);
        return -1;
    }

    size_t host_len = colon - address;
    if (host_len >= 256) {
        return -1;
    }

    /* Handle [IPv6]:port format */
    if (address[0] == '[') {
        const char *bracket = strchr(address, ']');
        if (bracket && bracket < colon) {
            host_len = bracket - address - 1;
            memcpy(host_out, address + 1, host_len);
            host_out[host_len] = '\0';
        } else {
            return -1;
        }
    } else {
        memcpy(host_out, address, host_len);
        host_out[host_len] = '\0';
    }

    *port_out = (uint16_t)atoi(colon + 1);
    if (*port_out == 0) {
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Frame Header Functions
 * ========================================================================== */

/**
 * v0.10.0: Frame header layout (41 bytes):
 *   magic(4) + payload_len(4) + msg_type(1) + chain_id(32)
 */
void dnac_tcp_write_frame_header(uint8_t *buffer, uint8_t msg_type, uint32_t payload_len) {
    /* Magic */
    uint32_t magic = htonl(DNAC_TCP_FRAME_MAGIC);
    memcpy(buffer, &magic, 4);

    /* Length */
    uint32_t len = htonl(payload_len);
    memcpy(buffer + 4, &len, 4);

    /* Type */
    buffer[8] = msg_type;

    /* Chain ID — default to all-zeros */
    memset(buffer + 9, 0, 32);
}

void dnac_tcp_write_frame_header_with_chain(uint8_t *buffer, uint8_t msg_type,
                                             uint32_t payload_len, const uint8_t *chain_id) {
    /* Magic */
    uint32_t magic = htonl(DNAC_TCP_FRAME_MAGIC);
    memcpy(buffer, &magic, 4);

    /* Length */
    uint32_t len = htonl(payload_len);
    memcpy(buffer + 4, &len, 4);

    /* Type */
    buffer[8] = msg_type;

    /* Chain ID */
    if (chain_id) {
        memcpy(buffer + 9, chain_id, 32);
    } else {
        memset(buffer + 9, 0, 32);
    }
}

int dnac_tcp_parse_frame_header(const uint8_t *buffer, size_t buffer_len,
                                uint8_t *msg_type_out, uint32_t *payload_len_out) {
    return dnac_tcp_parse_frame_header_with_chain(buffer, buffer_len,
                                                   msg_type_out, payload_len_out, NULL);
}

int dnac_tcp_parse_frame_header_with_chain(const uint8_t *buffer, size_t buffer_len,
                                            uint8_t *msg_type_out, uint32_t *payload_len_out,
                                            uint8_t *chain_id_out) {
    if (buffer_len < DNAC_TCP_FRAME_HEADER_SIZE) {
        return -1;
    }

    /* Check magic */
    uint32_t magic;
    memcpy(&magic, buffer, 4);
    if (ntohl(magic) != DNAC_TCP_FRAME_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid frame magic: 0x%08X", ntohl(magic));
        return -1;
    }

    /* Get length */
    uint32_t len;
    memcpy(&len, buffer + 4, 4);
    *payload_len_out = ntohl(len);

    /* Check max size */
    if (*payload_len_out > DNAC_TCP_MAX_MESSAGE_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Message too large: %u", *payload_len_out);
        return -1;
    }

    /* Get type */
    *msg_type_out = buffer[8];

    /* Get chain_id */
    if (chain_id_out) {
        memcpy(chain_id_out, buffer + 9, 32);
    }

    return 0;
}

/* ============================================================================
 * TCP Server Implementation
 * ========================================================================== */

static void* server_worker_thread(void *arg);
static void server_accept_connection(dnac_tcp_server_t *server);
static void server_handle_peer_data(dnac_tcp_server_t *server, int peer_index);

dnac_tcp_server_t* dnac_tcp_server_create(uint16_t port) {
    dnac_tcp_server_t *server = calloc(1, sizeof(dnac_tcp_server_t));
    if (!server) {
        return NULL;
    }

    server->port = port;
    server->listen_fd = -1;
    server->epoll_fd = -1;
    server->wakeup_pipe[0] = -1;
    server->wakeup_pipe[1] = -1;
    pthread_mutex_init(&server->peer_mutex, NULL);

    /* Initialize peer array */
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        server->peers[i].fd = -1;
        server->peers[i].state = DNAC_PEER_DISCONNECTED;
    }

    return server;
}

void dnac_tcp_server_destroy(dnac_tcp_server_t *server) {
    if (!server) return;

    dnac_tcp_server_stop(server);

    pthread_mutex_destroy(&server->peer_mutex);
    free(server);
}

int dnac_tcp_server_start(dnac_tcp_server_t *server) {
    if (!server || server->running) {
        return -1;
    }

    /* Create listening socket */
    server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listen_fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Set socket options */
    int optval = 1;
    setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    set_nonblocking(server->listen_fd);

    /* Bind */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(server->port);

    if (bind(server->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "bind() failed: %s", strerror(errno));
        close(server->listen_fd);
        server->listen_fd = -1;
        return -1;
    }

    /* Listen */
    if (listen(server->listen_fd, DNAC_TCP_BACKLOG) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "listen() failed: %s", strerror(errno));
        close(server->listen_fd);
        server->listen_fd = -1;
        return -1;
    }

    /* Create epoll instance */
    server->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (server->epoll_fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "epoll_create1() failed: %s", strerror(errno));
        close(server->listen_fd);
        server->listen_fd = -1;
        return -1;
    }

    /* Create wakeup pipe */
    if (pipe(server->wakeup_pipe) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "pipe() failed: %s", strerror(errno));
        close(server->epoll_fd);
        close(server->listen_fd);
        server->epoll_fd = -1;
        server->listen_fd = -1;
        return -1;
    }
    set_nonblocking(server->wakeup_pipe[0]);

    /* Add listen fd to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server->listen_fd;
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->listen_fd, &ev);

    /* Add wakeup pipe to epoll */
    ev.events = EPOLLIN;
    ev.data.fd = server->wakeup_pipe[0];
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->wakeup_pipe[0], &ev);

    /* Start worker thread */
    server->running = true;
    if (pthread_create(&server->worker_thread, NULL, server_worker_thread, server) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "pthread_create() failed");
        server->running = false;
        close(server->epoll_fd);
        close(server->listen_fd);
        close(server->wakeup_pipe[0]);
        close(server->wakeup_pipe[1]);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TCP server started on port %u", server->port);
    return 0;
}

void dnac_tcp_server_stop(dnac_tcp_server_t *server) {
    if (!server || !server->running) return;

    server->running = false;

    /* Wake up worker thread */
    if (server->wakeup_pipe[1] >= 0) {
        write(server->wakeup_pipe[1], "X", 1);
    }

    /* Wait for worker thread */
    pthread_join(server->worker_thread, NULL);

    /* Close all peer connections */
    pthread_mutex_lock(&server->peer_mutex);
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        if (server->peers[i].fd >= 0) {
            close(server->peers[i].fd);
            server->peers[i].fd = -1;
            server->peers[i].state = DNAC_PEER_DISCONNECTED;
        }
    }
    server->peer_count = 0;
    pthread_mutex_unlock(&server->peer_mutex);

    /* Close server sockets */
    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }
    if (server->epoll_fd >= 0) {
        close(server->epoll_fd);
        server->epoll_fd = -1;
    }
    if (server->wakeup_pipe[0] >= 0) {
        close(server->wakeup_pipe[0]);
        server->wakeup_pipe[0] = -1;
    }
    if (server->wakeup_pipe[1] >= 0) {
        close(server->wakeup_pipe[1]);
        server->wakeup_pipe[1] = -1;
    }

    QGP_LOG_INFO(LOG_TAG, "TCP server stopped");
}

void dnac_tcp_server_set_callbacks(dnac_tcp_server_t *server,
                                   dnac_tcp_recv_cb_t on_recv,
                                   dnac_tcp_connect_cb_t on_connect,
                                   dnac_tcp_disconnect_cb_t on_disconnect,
                                   void *user_data) {
    if (!server) return;
    server->on_recv = on_recv;
    server->on_connect = on_connect;
    server->on_disconnect = on_disconnect;
    server->user_data = user_data;
}

static void* server_worker_thread(void *arg) {
    dnac_tcp_server_t *server = (dnac_tcp_server_t*)arg;
    struct epoll_event events[DNAC_TCP_MAX_PEERS + 2];

    QGP_LOG_DEBUG(LOG_TAG, "Worker thread started");

    while (server->running) {
        int nfds = epoll_wait(server->epoll_fd, events, DNAC_TCP_MAX_PEERS + 2, 1000);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            QGP_LOG_ERROR(LOG_TAG, "epoll_wait() failed: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;

            if (fd == server->listen_fd) {
                /* New connection */
                server_accept_connection(server);
            } else if (fd == server->wakeup_pipe[0]) {
                /* Wakeup signal */
                char buf[16];
                read(server->wakeup_pipe[0], buf, sizeof(buf));
            } else {
                /* Peer data */
                pthread_mutex_lock(&server->peer_mutex);
                for (int j = 0; j < DNAC_TCP_MAX_PEERS; j++) {
                    if (server->peers[j].fd == fd) {
                        if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                            /* Peer disconnected */
                            QGP_LOG_DEBUG(LOG_TAG, "Peer %d disconnected (event)", j);
                            epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                            close(fd);
                            server->peers[j].fd = -1;
                            server->peers[j].state = DNAC_PEER_DISCONNECTED;
                            server->peer_count--;

                            if (server->on_disconnect) {
                                pthread_mutex_unlock(&server->peer_mutex);
                                server->on_disconnect(j, server->user_data);
                                pthread_mutex_lock(&server->peer_mutex);
                            }
                        } else if (events[i].events & EPOLLIN) {
                            pthread_mutex_unlock(&server->peer_mutex);
                            server_handle_peer_data(server, j);
                            pthread_mutex_lock(&server->peer_mutex);
                        }
                        break;
                    }
                }
                pthread_mutex_unlock(&server->peer_mutex);
            }
        }
    }

    QGP_LOG_DEBUG(LOG_TAG, "Worker thread exiting");
    return NULL;
}

static void server_accept_connection(dnac_tcp_server_t *server) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd = accept(server->listen_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            QGP_LOG_ERROR(LOG_TAG, "accept() failed: %s", strerror(errno));
        }
        return;
    }

    set_nonblocking(client_fd);
    set_keepalive(client_fd);

    /* Find free peer slot */
    pthread_mutex_lock(&server->peer_mutex);

    int peer_index = -1;
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        if (server->peers[i].fd < 0) {
            peer_index = i;
            break;
        }
    }

    if (peer_index < 0) {
        QGP_LOG_WARN(LOG_TAG, "Max peers reached, rejecting connection");
        close(client_fd);
        pthread_mutex_unlock(&server->peer_mutex);
        return;
    }

    /* Initialize peer */
    dnac_tcp_peer_t *peer = &server->peers[peer_index];
    memset(peer, 0, sizeof(*peer));
    peer->fd = client_fd;
    peer->state = DNAC_PEER_CONNECTED;
    peer->is_outbound = false;
    peer->connected_at = dnac_tcp_get_time_ms();
    peer->last_recv = peer->connected_at;

    /* Format address */
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
    snprintf(peer->address, sizeof(peer->address), "%s:%u", ip_str, ntohs(client_addr.sin_port));

    server->peer_count++;

    /* Add to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

    pthread_mutex_unlock(&server->peer_mutex);

    QGP_LOG_INFO(LOG_TAG, "Accepted connection from %s (peer %d)", peer->address, peer_index);

    if (server->on_connect) {
        server->on_connect(peer_index, peer->address, server->user_data);
    }
}

static void server_handle_peer_data(dnac_tcp_server_t *server, int peer_index) {
    pthread_mutex_lock(&server->peer_mutex);
    dnac_tcp_peer_t *peer = &server->peers[peer_index];

    if (peer->fd < 0) {
        pthread_mutex_unlock(&server->peer_mutex);
        return;
    }

    int fd = peer->fd;
    pthread_mutex_unlock(&server->peer_mutex);

    /*
     * With edge-triggered epoll (EPOLLET), we MUST read ALL available data
     * until we get EAGAIN, otherwise we won't get notified again.
     */
    uint8_t temp_buf[4096];
    bool connection_closed = false;

    while (1) {
        ssize_t n = recv(fd, temp_buf, sizeof(temp_buf), 0);

        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                /* No more data available - this is normal for edge-triggered */
                break;
            }

            /* Connection closed or error */
            connection_closed = true;
            break;
        }

        /* Append to receive buffer */
        pthread_mutex_lock(&server->peer_mutex);

        if (peer->recv_len + n > DNAC_TCP_BUFFER_SIZE) {
            QGP_LOG_WARN(LOG_TAG, "Peer %d receive buffer overflow", peer_index);
            pthread_mutex_unlock(&server->peer_mutex);
            continue;  /* Try to drain remaining data */
        }

        memcpy(peer->recv_buffer + peer->recv_len, temp_buf, n);
        peer->recv_len += n;
        peer->last_recv = dnac_tcp_get_time_ms();
        pthread_mutex_unlock(&server->peer_mutex);
    }

    if (connection_closed) {
        QGP_LOG_DEBUG(LOG_TAG, "Peer %d connection closed", peer_index);

        pthread_mutex_lock(&server->peer_mutex);
        epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
        peer->fd = -1;
        peer->state = DNAC_PEER_DISCONNECTED;
        server->peer_count--;
        pthread_mutex_unlock(&server->peer_mutex);

        if (server->on_disconnect) {
            server->on_disconnect(peer_index, server->user_data);
        }
        return;
    }

    /* Process complete messages from receive buffer */
    pthread_mutex_lock(&server->peer_mutex);

    while (peer->recv_len >= DNAC_TCP_FRAME_HEADER_SIZE) {
        uint8_t msg_type;
        uint32_t payload_len;

        if (dnac_tcp_parse_frame_header(peer->recv_buffer, peer->recv_len,
                                        &msg_type, &payload_len) < 0) {
            /* Invalid frame - reset buffer */
            QGP_LOG_ERROR(LOG_TAG, "Invalid frame from peer %d, resetting buffer", peer_index);
            peer->recv_len = 0;
            break;
        }

        size_t total_len = DNAC_TCP_FRAME_HEADER_SIZE + payload_len;
        if (peer->recv_len < total_len) {
            /* Need more data */
            break;
        }

        /* Complete message - copy payload and shift buffer */
        uint8_t *payload = peer->recv_buffer + DNAC_TCP_FRAME_HEADER_SIZE;

        pthread_mutex_unlock(&server->peer_mutex);

        /* Invoke callback */
        if (server->on_recv) {
            server->on_recv(peer_index, msg_type, payload, payload_len, server->user_data);
        }

        pthread_mutex_lock(&server->peer_mutex);

        /* Shift remaining data */
        if (peer->recv_len > total_len) {
            memmove(peer->recv_buffer, peer->recv_buffer + total_len,
                    peer->recv_len - total_len);
        }
        peer->recv_len -= total_len;
    }

    pthread_mutex_unlock(&server->peer_mutex);
}

int dnac_tcp_server_connect(dnac_tcp_server_t *server,
                            const char *address,
                            const uint8_t *peer_id) {
    if (!server || !address) return -1;

    char host[256];
    uint16_t port;

    if (dnac_tcp_parse_address(address, host, &port) < 0) {
        return -1;
    }

    /* Create socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Resolve host */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        QGP_LOG_ERROR(LOG_TAG, "gethostbyname(%s) failed", host);
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    /* Set timeout */
    struct timeval tv;
    tv.tv_sec = DNAC_TCP_CONNECT_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect */
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "connect(%s) failed: %s", address, strerror(errno));
        close(fd);
        return -1;
    }

    set_nonblocking(fd);
    set_keepalive(fd);

    /* Find free peer slot */
    pthread_mutex_lock(&server->peer_mutex);

    int peer_index = -1;
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        if (server->peers[i].fd < 0) {
            peer_index = i;
            break;
        }
    }

    if (peer_index < 0) {
        QGP_LOG_WARN(LOG_TAG, "Max peers reached");
        close(fd);
        pthread_mutex_unlock(&server->peer_mutex);
        return -1;
    }

    /* Initialize peer */
    dnac_tcp_peer_t *peer = &server->peers[peer_index];
    memset(peer, 0, sizeof(*peer));
    peer->fd = fd;
    peer->state = DNAC_PEER_CONNECTED;
    peer->is_outbound = true;
    peer->is_witness = true;
    peer->connected_at = dnac_tcp_get_time_ms();
    peer->last_recv = peer->connected_at;
    strncpy(peer->address, address, sizeof(peer->address) - 1);

    if (peer_id) {
        memcpy(peer->peer_id, peer_id, 32);
        peer->state = DNAC_PEER_AUTHENTICATED;
    }

    server->peer_count++;

    /* Add to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    pthread_mutex_unlock(&server->peer_mutex);

    QGP_LOG_INFO(LOG_TAG, "Connected to %s (peer %d)", address, peer_index);

    if (server->on_connect) {
        server->on_connect(peer_index, address, server->user_data);
    }

    return peer_index;
}

void dnac_tcp_server_disconnect(dnac_tcp_server_t *server, int peer_index) {
    if (!server || peer_index < 0 || peer_index >= DNAC_TCP_MAX_PEERS) return;

    pthread_mutex_lock(&server->peer_mutex);
    dnac_tcp_peer_t *peer = &server->peers[peer_index];

    if (peer->fd >= 0) {
        epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, peer->fd, NULL);
        close(peer->fd);
        peer->fd = -1;
        peer->state = DNAC_PEER_DISCONNECTED;
        server->peer_count--;
    }

    pthread_mutex_unlock(&server->peer_mutex);
}

int dnac_tcp_server_send(dnac_tcp_server_t *server,
                         int peer_index,
                         const uint8_t *data,
                         size_t len) {
    if (!server || !data || peer_index < 0 || peer_index >= DNAC_TCP_MAX_PEERS) {
        return -1;
    }

    pthread_mutex_lock(&server->peer_mutex);
    dnac_tcp_peer_t *peer = &server->peers[peer_index];

    if (peer->fd < 0) {
        pthread_mutex_unlock(&server->peer_mutex);
        return -1;
    }

    int fd = peer->fd;
    pthread_mutex_unlock(&server->peer_mutex);

    /* Send with timeout */
    struct timeval tv;
    tv.tv_sec = DNAC_TCP_IO_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssize_t sent = send(fd, data, len, MSG_NOSIGNAL);
    if (sent != (ssize_t)len) {
        QGP_LOG_ERROR(LOG_TAG, "send() to peer %d failed: %s", peer_index, strerror(errno));
        return -1;
    }

    pthread_mutex_lock(&server->peer_mutex);
    peer->last_send = dnac_tcp_get_time_ms();
    pthread_mutex_unlock(&server->peer_mutex);

    return 0;
}

int dnac_tcp_server_broadcast(dnac_tcp_server_t *server,
                              const uint8_t *data,
                              size_t len,
                              int exclude_index) {
    if (!server || !data) return 0;

    int count = 0;

    pthread_mutex_lock(&server->peer_mutex);
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        if (i == exclude_index) continue;
        if (server->peers[i].fd >= 0 && server->peers[i].is_witness) {
            pthread_mutex_unlock(&server->peer_mutex);

            if (dnac_tcp_server_send(server, i, data, len) == 0) {
                count++;
            }

            pthread_mutex_lock(&server->peer_mutex);
        }
    }
    pthread_mutex_unlock(&server->peer_mutex);

    return count;
}

int dnac_tcp_server_find_peer(dnac_tcp_server_t *server, const uint8_t *peer_id) {
    if (!server || !peer_id) return -1;

    pthread_mutex_lock(&server->peer_mutex);
    for (int i = 0; i < DNAC_TCP_MAX_PEERS; i++) {
        if (server->peers[i].fd >= 0 &&
            memcmp(server->peers[i].peer_id, peer_id, 32) == 0) {
            pthread_mutex_unlock(&server->peer_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&server->peer_mutex);
    return -1;
}

void dnac_tcp_server_set_peer_id(dnac_tcp_server_t *server,
                                 int peer_index,
                                 const uint8_t *peer_id) {
    if (!server || !peer_id || peer_index < 0 || peer_index >= DNAC_TCP_MAX_PEERS) return;

    pthread_mutex_lock(&server->peer_mutex);
    memcpy(server->peers[peer_index].peer_id, peer_id, 32);
    server->peers[peer_index].state = DNAC_PEER_AUTHENTICATED;
    pthread_mutex_unlock(&server->peer_mutex);
}

int dnac_tcp_server_peer_count(dnac_tcp_server_t *server) {
    if (!server) return 0;
    return server->peer_count;
}

/* ============================================================================
 * TCP Client Implementation
 * ========================================================================== */

dnac_tcp_client_t* dnac_tcp_client_create(void) {
    dnac_tcp_client_t *client = calloc(1, sizeof(dnac_tcp_client_t));
    if (!client) return NULL;

    client->fd = -1;
    return client;
}

void dnac_tcp_client_destroy(dnac_tcp_client_t *client) {
    if (!client) return;
    dnac_tcp_client_disconnect(client);
    free(client);
}

int dnac_tcp_client_connect(dnac_tcp_client_t *client, const char *address) {
    if (!client || !address) return -1;

    if (client->connected) {
        dnac_tcp_client_disconnect(client);
    }

    char host[256];
    uint16_t port;

    if (dnac_tcp_parse_address(address, host, &port) < 0) {
        return -1;
    }

    /* Create socket */
    client->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client->fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Resolve host */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        QGP_LOG_ERROR(LOG_TAG, "gethostbyname(%s) failed", host);
        close(client->fd);
        client->fd = -1;
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    /* Set connect timeout */
    struct timeval tv;
    tv.tv_sec = DNAC_TCP_CONNECT_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(client->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Connect */
    if (connect(client->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "connect(%s) failed: %s", address, strerror(errno));
        close(client->fd);
        client->fd = -1;
        return -1;
    }

    strncpy(client->address, address, sizeof(client->address) - 1);
    client->connected = true;

    QGP_LOG_DEBUG(LOG_TAG, "Connected to %s", address);
    return 0;
}

void dnac_tcp_client_disconnect(dnac_tcp_client_t *client) {
    if (!client) return;

    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }
    client->connected = false;
    client->recv_len = 0;
}

int dnac_tcp_client_send(dnac_tcp_client_t *client,
                         const uint8_t *data,
                         size_t len) {
    if (!client || !data || !client->connected) return -1;

    struct timeval tv;
    tv.tv_sec = DNAC_TCP_IO_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(client->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssize_t sent = send(client->fd, data, len, MSG_NOSIGNAL);
    if (sent != (ssize_t)len) {
        QGP_LOG_ERROR(LOG_TAG, "send() failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int dnac_tcp_client_recv(dnac_tcp_client_t *client,
                         uint8_t *buffer,
                         size_t buffer_len,
                         size_t *received_out,
                         int timeout_ms) {
    if (!client || !buffer || !client->connected) return -1;

    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Read until we have a complete frame */
    while (1) {
        /* Check if we have a complete message */
        if (client->recv_len >= DNAC_TCP_FRAME_HEADER_SIZE) {
            uint8_t msg_type;
            uint32_t payload_len;

            if (dnac_tcp_parse_frame_header(client->recv_buffer, client->recv_len,
                                            &msg_type, &payload_len) == 0) {
                size_t total_len = DNAC_TCP_FRAME_HEADER_SIZE + payload_len;

                if (client->recv_len >= total_len) {
                    /* Complete message */
                    if (buffer_len < total_len) {
                        return -1;  /* Buffer too small */
                    }

                    memcpy(buffer, client->recv_buffer, total_len);
                    if (received_out) *received_out = total_len;

                    /* Shift remaining data */
                    if (client->recv_len > total_len) {
                        memmove(client->recv_buffer, client->recv_buffer + total_len,
                                client->recv_len - total_len);
                    }
                    client->recv_len -= total_len;

                    return 0;
                }
            }
        }

        /* Read more data */
        ssize_t n = recv(client->fd, client->recv_buffer + client->recv_len,
                         DNAC_TCP_BUFFER_SIZE - client->recv_len, 0);

        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return -1;  /* Timeout */
            }
            return -1;  /* Error or connection closed */
        }

        client->recv_len += n;
    }
}
