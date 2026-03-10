/**
 * Nodus — UDP Transport
 *
 * Non-blocking UDP for Kademlia routing messages (PING, FIND_NODE).
 * Single socket, datagram-per-frame.
 *
 * @file nodus_udp.h
 */

#ifndef NODUS_UDP_H
#define NODUS_UDP_H

#include "nodus/nodus_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Called when a valid frame payload is received via UDP */
typedef void (*nodus_udp_recv_fn)(const uint8_t *payload, size_t len,
                                   const char *from_ip, uint16_t from_port,
                                   void *ctx);

typedef struct {
    int                 fd;
    int                 epoll_fd;
    bool                owns_epoll;
    nodus_udp_recv_fn   on_recv;
    void               *cb_ctx;
    uint16_t            port;
} nodus_udp_t;

/**
 * Initialize UDP transport.
 * @param shared_epoll_fd  If >= 0, use this epoll fd. Otherwise creates own.
 */
int nodus_udp_init(nodus_udp_t *udp, int shared_epoll_fd);

/** Bind to address and port. */
int nodus_udp_bind(nodus_udp_t *udp, const char *bind_ip, uint16_t port);

/**
 * Send a framed payload as a single UDP datagram.
 * Prepends the 7-byte Nodus frame header.
 */
int nodus_udp_send(nodus_udp_t *udp, const uint8_t *payload, size_t len,
                    const char *ip, uint16_t port);

/** Process pending datagrams. Returns number processed. */
int nodus_udp_poll(nodus_udp_t *udp);

/** Close socket and free resources. */
void nodus_udp_close(nodus_udp_t *udp);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_UDP_H */
