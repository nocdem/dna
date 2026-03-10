/**
 * Nodus — UDP Transport Implementation
 *
 * Non-blocking UDP for Kademlia routing signals.
 * Single socket, datagram-per-frame, integrated with epoll.
 */

#include "transport/nodus_udp.h"
#include "protocol/nodus_wire.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

/* Max datagram size (header + max UDP payload) */
#define UDP_BUFSIZE (NODUS_FRAME_HEADER_SIZE + NODUS_MAX_FRAME_UDP)

/* ── Helpers ─────────────────────────────────────────────────────── */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ── Public API ──────────────────────────────────────────────────── */

int nodus_udp_init(nodus_udp_t *udp, int shared_epoll_fd) {
    if (!udp) return -1;
    memset(udp, 0, sizeof(*udp));
    udp->fd = -1;

    if (shared_epoll_fd >= 0) {
        udp->epoll_fd = shared_epoll_fd;
        udp->owns_epoll = false;
    } else {
        udp->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (udp->epoll_fd < 0) return -1;
        udp->owns_epoll = true;
    }
    return 0;
}

int nodus_udp_bind(nodus_udp_t *udp, const char *bind_ip, uint16_t port) {
    if (!udp) return -1;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    set_nonblocking(fd);

    /* Allow address reuse */
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (bind_ip && bind_ip[0])
        inet_pton(AF_INET, bind_ip, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Get actual port */
    socklen_t slen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &slen);
    udp->port = ntohs(addr.sin_port);
    udp->fd = fd;

    /* Add to epoll */
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
    epoll_ctl(udp->epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    return 0;
}

int nodus_udp_send(nodus_udp_t *udp, const uint8_t *payload, size_t len,
                    const char *ip, uint16_t port) {
    if (!udp || !payload || !ip || udp->fd < 0) return -1;
    if (len > NODUS_MAX_FRAME_UDP) return -1;

    /* Build framed datagram */
    uint8_t dgram[UDP_BUFSIZE];
    size_t frame_len = nodus_frame_encode(dgram, sizeof(dgram),
                                           payload, (uint32_t)len);
    if (frame_len == 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
        return -1;

    ssize_t sent = sendto(udp->fd, dgram, frame_len, 0,
                           (struct sockaddr *)&addr, sizeof(addr));
    return (sent == (ssize_t)frame_len) ? 0 : -1;
}

int nodus_udp_poll(nodus_udp_t *udp) {
    if (!udp || udp->fd < 0) return -1;

    int processed = 0;
    uint8_t buf[UDP_BUFSIZE];

    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t n = recvfrom(udp->fd, buf, sizeof(buf), 0,
                              (struct sockaddr *)&from, &from_len);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            break;
        }

        /* Parse frame header */
        nodus_frame_t frame;
        int rc = nodus_frame_decode(buf, (size_t)n, &frame);
        if (rc <= 0) continue;  /* Bad or incomplete frame — skip */
        if (!nodus_frame_validate(&frame, true)) continue;  /* Too large for UDP */

        if (udp->on_recv) {
            char from_ip[64];
            inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
            uint16_t from_port = ntohs(from.sin_port);
            udp->on_recv(frame.payload, frame.payload_len,
                          from_ip, from_port, udp->cb_ctx);
        }

        processed++;
    }

    return processed;
}

void nodus_udp_close(nodus_udp_t *udp) {
    if (!udp) return;

    if (udp->fd >= 0) {
        epoll_ctl(udp->epoll_fd, EPOLL_CTL_DEL, udp->fd, NULL);
        close(udp->fd);
        udp->fd = -1;
    }

    if (udp->owns_epoll && udp->epoll_fd >= 0) {
        close(udp->epoll_fd);
        udp->epoll_fd = -1;
    }
}
