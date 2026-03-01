/**
 * @file tcp.h
 * @brief DNAC TCP Networking for BFT Witness Mesh
 *
 * Provides TCP server/client for witness-to-witness communication
 * and client-to-witness connections for spend requests.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_TCP_H
#define DNAC_TCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Maximum pending connections */
#define DNAC_TCP_BACKLOG            16

/** Maximum peers */
#define DNAC_TCP_MAX_PEERS          32

/** Read buffer size */
#define DNAC_TCP_BUFFER_SIZE        65536

/** Connection timeout (seconds) */
#define DNAC_TCP_CONNECT_TIMEOUT    5

/** Read/write timeout (seconds) */
#define DNAC_TCP_IO_TIMEOUT         10

/** Reconnect interval (seconds) */
#define DNAC_TCP_RECONNECT_INTERVAL 5

/** Heartbeat interval (seconds) */
#define DNAC_TCP_HEARTBEAT_INTERVAL 30

/** Maximum message size */
#define DNAC_TCP_MAX_MESSAGE_SIZE   131072

/* ============================================================================
 * Peer State
 * ========================================================================== */

typedef enum {
    DNAC_PEER_DISCONNECTED  = 0,
    DNAC_PEER_CONNECTING    = 1,
    DNAC_PEER_CONNECTED     = 2,
    DNAC_PEER_AUTHENTICATED = 3,
} dnac_peer_state_t;

/**
 * @brief Peer connection info
 */
typedef struct {
    int fd;                             /**< Socket file descriptor */
    dnac_peer_state_t state;            /**< Connection state */
    uint8_t peer_id[32];                /**< Peer's witness ID */
    char address[256];                  /**< IP:port */
    uint64_t connected_at;              /**< Connection timestamp */
    uint64_t last_recv;                 /**< Last message received */
    uint64_t last_send;                 /**< Last message sent */
    bool is_outbound;                   /**< We initiated connection */
    bool is_witness;                    /**< Is a witness peer (vs client) */

    /* Receive buffer */
    uint8_t recv_buffer[DNAC_TCP_BUFFER_SIZE];
    size_t recv_len;
} dnac_tcp_peer_t;

/* ============================================================================
 * TCP Server
 * ========================================================================== */

/**
 * @brief Message received callback
 *
 * @param peer_index Peer index in array
 * @param msg_type Message type (from BFT)
 * @param data Message data
 * @param len Message length
 * @param user_data User data
 */
typedef void (*dnac_tcp_recv_cb_t)(int peer_index,
                                   uint8_t msg_type,
                                   const uint8_t *data,
                                   size_t len,
                                   void *user_data);

/**
 * @brief Peer connected callback
 *
 * @param peer_index Peer index
 * @param address Peer address
 * @param user_data User data
 */
typedef void (*dnac_tcp_connect_cb_t)(int peer_index,
                                      const char *address,
                                      void *user_data);

/**
 * @brief Peer disconnected callback
 *
 * @param peer_index Peer index
 * @param user_data User data
 */
typedef void (*dnac_tcp_disconnect_cb_t)(int peer_index, void *user_data);

/**
 * @brief TCP server context
 */
typedef struct dnac_tcp_server {
    int listen_fd;                      /**< Listening socket */
    uint16_t port;                      /**< Listen port */
    bool running;                       /**< Server running */

    /* Peers */
    dnac_tcp_peer_t peers[DNAC_TCP_MAX_PEERS];
    int peer_count;
    pthread_mutex_t peer_mutex;

    /* Callbacks */
    dnac_tcp_recv_cb_t on_recv;
    dnac_tcp_connect_cb_t on_connect;
    dnac_tcp_disconnect_cb_t on_disconnect;
    void *user_data;

    /* Worker thread */
    pthread_t worker_thread;
    int epoll_fd;                       /**< epoll instance */

    /* Pipe for wakeup */
    int wakeup_pipe[2];
} dnac_tcp_server_t;

/* ============================================================================
 * Server Functions
 * ========================================================================== */

/**
 * @brief Create TCP server
 *
 * @param port Listen port
 * @return Server pointer or NULL on failure
 */
dnac_tcp_server_t* dnac_tcp_server_create(uint16_t port);

/**
 * @brief Destroy TCP server
 */
void dnac_tcp_server_destroy(dnac_tcp_server_t *server);

/**
 * @brief Start server (begins listening and accepting)
 *
 * @param server Server context
 * @return 0 on success
 */
int dnac_tcp_server_start(dnac_tcp_server_t *server);

/**
 * @brief Stop server
 *
 * @param server Server context
 */
void dnac_tcp_server_stop(dnac_tcp_server_t *server);

/**
 * @brief Set callbacks
 *
 * @param server Server context
 * @param on_recv Message received callback
 * @param on_connect Peer connected callback
 * @param on_disconnect Peer disconnected callback
 * @param user_data User data for callbacks
 */
void dnac_tcp_server_set_callbacks(dnac_tcp_server_t *server,
                                   dnac_tcp_recv_cb_t on_recv,
                                   dnac_tcp_connect_cb_t on_connect,
                                   dnac_tcp_disconnect_cb_t on_disconnect,
                                   void *user_data);

/**
 * @brief Connect to peer
 *
 * @param server Server context
 * @param address IP:port to connect to
 * @param peer_id Expected peer ID (32 bytes, can be NULL)
 * @return Peer index on success, -1 on failure
 */
int dnac_tcp_server_connect(dnac_tcp_server_t *server,
                            const char *address,
                            const uint8_t *peer_id);

/**
 * @brief Disconnect peer
 *
 * @param server Server context
 * @param peer_index Peer index
 */
void dnac_tcp_server_disconnect(dnac_tcp_server_t *server, int peer_index);

/**
 * @brief Send message to peer
 *
 * @param server Server context
 * @param peer_index Peer index
 * @param data Message data
 * @param len Message length
 * @return 0 on success
 */
int dnac_tcp_server_send(dnac_tcp_server_t *server,
                         int peer_index,
                         const uint8_t *data,
                         size_t len);

/**
 * @brief Broadcast message to all connected peers
 *
 * @param server Server context
 * @param data Message data
 * @param len Message length
 * @param exclude_index Peer to exclude (-1 for none)
 * @return Number of peers sent to
 */
int dnac_tcp_server_broadcast(dnac_tcp_server_t *server,
                              const uint8_t *data,
                              size_t len,
                              int exclude_index);

/**
 * @brief Get peer by ID
 *
 * @param server Server context
 * @param peer_id Peer ID to find
 * @return Peer index or -1 if not found
 */
int dnac_tcp_server_find_peer(dnac_tcp_server_t *server,
                              const uint8_t *peer_id);

/**
 * @brief Set peer ID (after authentication)
 *
 * @param server Server context
 * @param peer_index Peer index
 * @param peer_id Peer ID
 */
void dnac_tcp_server_set_peer_id(dnac_tcp_server_t *server,
                                 int peer_index,
                                 const uint8_t *peer_id);

/**
 * @brief Get connected peer count
 *
 * @param server Server context
 * @return Number of connected peers
 */
int dnac_tcp_server_peer_count(dnac_tcp_server_t *server);

/* TCP Client removed — all client operations now use Nodus SDK
 * (nodus_client_dnac_*) via the authenticated Nodus TCP connection. */

/* ============================================================================
 * Message Framing
 * ========================================================================== */

/**
 * @brief Message frame header (v0.10.0)
 *
 * All TCP messages are prefixed with:
 * - 4 bytes: magic (0x444E4143 = "DNAC")
 * - 4 bytes: length (network byte order)
 * - 1 byte: message type
 * - 32 bytes: chain_id (identifies which zone this message belongs to)
 *
 * BREAKING CHANGE in v0.10.0: header grew from 9 to 41 bytes.
 */
#define DNAC_TCP_FRAME_MAGIC        0x444E4143
#define DNAC_TCP_FRAME_HEADER_SIZE  41  /* v0.10.0: was 9, now includes chain_id(32) */

/**
 * @brief Write frame header with chain_id
 *
 * @param buffer Output buffer (must be at least DNAC_TCP_FRAME_HEADER_SIZE)
 * @param msg_type Message type
 * @param payload_len Payload length
 *
 * Note: chain_id defaults to all-zeros. Use dnac_tcp_write_frame_header_with_chain
 * to specify a chain_id.
 */
void dnac_tcp_write_frame_header(uint8_t *buffer, uint8_t msg_type, uint32_t payload_len);

/**
 * @brief Write frame header with explicit chain_id
 *
 * @param buffer Output buffer (must be at least DNAC_TCP_FRAME_HEADER_SIZE)
 * @param msg_type Message type
 * @param payload_len Payload length
 * @param chain_id Chain ID (DNAC_CHAIN_ID_SIZE bytes, or NULL for all-zeros)
 */
void dnac_tcp_write_frame_header_with_chain(uint8_t *buffer, uint8_t msg_type,
                                             uint32_t payload_len, const uint8_t *chain_id);

/**
 * @brief Parse frame header
 *
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param msg_type_out Output message type
 * @param payload_len_out Output payload length
 * @return 0 on success, -1 on invalid header
 */
int dnac_tcp_parse_frame_header(const uint8_t *buffer, size_t buffer_len,
                                uint8_t *msg_type_out, uint32_t *payload_len_out);

/**
 * @brief Parse frame header with chain_id extraction
 *
 * @param buffer Input buffer
 * @param buffer_len Buffer length
 * @param msg_type_out Output message type
 * @param payload_len_out Output payload length
 * @param chain_id_out Output chain_id (32 bytes, can be NULL to ignore)
 * @return 0 on success, -1 on invalid header
 */
int dnac_tcp_parse_frame_header_with_chain(const uint8_t *buffer, size_t buffer_len,
                                            uint8_t *msg_type_out, uint32_t *payload_len_out,
                                            uint8_t *chain_id_out);

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * @brief Parse address string into host and port
 *
 * @param address "host:port" string
 * @param host_out Output host buffer (256 bytes)
 * @param port_out Output port
 * @return 0 on success
 */
int dnac_tcp_parse_address(const char *address, char *host_out, uint16_t *port_out);

/**
 * @brief Get current time in milliseconds
 *
 * @return Milliseconds since epoch
 */
uint64_t dnac_tcp_get_time_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_TCP_H */
