/**
 * @file nodus/src/witness/nodus_witness_p2p.c
 * @brief The nodus host of the ported cometbft @709fd12b p2p layer on the
 *        witness port 4004. Contract, governing records and the
 *        deviations: nodus_witness_p2p.h.
 *
 * Reference call sites each block mirrors are named per block
 * (node/node.go and node/setup.go: how a node builds and starts its p2p
 * half; p2p/transport.go / switch.go: what a host must do for them).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_p2p.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_join.h"
#include "witness/nodus_witness_v2_sync2.h"
#include "protocol/nodus_tier3.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_p2p_pex.h"
#include "dnac/cmt_p2p_addrbook.h"
#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_block.h"         /* CMT_BLOCK_PROTOCOL            */
#include "dnac/cmt_part_set.h"      /* CMT_BLOCK_PART_SIZE_BYTES     */
#include "dnac/cmt_mem.h"           /* CMT_MEM_CHANNEL, mempool cfg  */
#include "dnac/validator.h"         /* DNAC_VALIDATOR_ACTIVE / ELIGIBLE */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "W_P2P"

/* The consensus seam's index space IS the reactors' peer tables. */
_Static_assert((int)CMT_CONR_MAX_PEERS == (int)CMT_MEM_MAX_PEERS,
               "cmt_conr and cmt_memr must share one peer index space");

/* ══ config ═══════════════════════════════════════════════════════════ */

void nodus_p2p_config_default(nodus_p2p_config_t *c)
{
    if (c == NULL) {
        return;
    }
    memset(c, 0, sizeof(*c));
    c->pex = true;                                          /* config.go:625 */
    c->addr_book_strict = true;                             /* config.go:621 */
    c->allow_duplicate_ip = false;                          /* config.go:630 */
    c->max_num_inbound_peers = CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS;   /* :622 */
    c->max_num_outbound_peers = CMT_P2P_DEFAULT_MAX_NUM_OUTBOUND_PEERS; /* :623 */
    c->flush_throttle_timeout_ms =
        CMT_P2P_CONFIG_DEFAULT_FLUSH_THROTTLE_NS / CMT_P2P_MCONN_NS_PER_MS;
    c->max_packet_msg_payload_size = CMT_P2P_CONFIG_DEFAULT_MAX_PACKET_MSG_PAYLOAD_SIZE;
    c->send_rate = CMT_P2P_CONFIG_DEFAULT_SEND_RATE;
    c->recv_rate = CMT_P2P_CONFIG_DEFAULT_RECV_RATE;
    c->handshake_timeout_ms = 0;        /* transport.go:22's 3 s */
    c->dial_timeout_ms = 0;             /* transport.go:20's 1 s */
}

static int copy_bounded(char *dst, size_t cap, const char *s)
{
    size_t n;

    if (s == NULL) {
        return -1;
    }
    n = strlen(s);
    if (n == 0 || n >= cap) {
        return -1;
    }
    memcpy(dst, s, n + 1);
    return 0;
}

int nodus_p2p_config_add_persistent(nodus_p2p_config_t *c, const char *s)
{
    if (c == NULL || c->n_persistent_peers >= NODUS_P2P_MAX_PEER_LIST ||
        copy_bounded(c->persistent_peers[c->n_persistent_peers],
                     sizeof(c->persistent_peers[0]), s) != 0) {
        return -1;
    }
    c->n_persistent_peers++;
    return 0;
}

int nodus_p2p_config_add_unconditional(nodus_p2p_config_t *c, const char *id)
{
    if (c == NULL || c->n_unconditional_peer_ids >= NODUS_P2P_MAX_PEER_LIST ||
        copy_bounded(c->unconditional_peer_ids[c->n_unconditional_peer_ids],
                     sizeof(c->unconditional_peer_ids[0]), id) != 0) {
        return -1;
    }
    c->n_unconditional_peer_ids++;
    return 0;
}

int nodus_p2p_config_add_private(nodus_p2p_config_t *c, const char *id)
{
    if (c == NULL || c->n_private_peer_ids >= NODUS_P2P_MAX_PEER_LIST ||
        copy_bounded(c->private_peer_ids[c->n_private_peer_ids],
                     sizeof(c->private_peer_ids[0]), id) != 0) {
        return -1;
    }
    c->n_private_peer_ids++;
    return 0;
}

/* ══ clocks, randomness, the 0x0A sign / verify ══════════════════════ */

int64_t nodus_p2p_mono_ns(void *ctx)
{
    struct timespec ts;

    (void)ctx;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

int64_t nodus_p2p_wall_ns(void *ctx)
{
    struct timespec ts;

    (void)ctx;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

int64_t nodus_p2p_rand_int63n(void *ctx, int64_t n)
{
    uint64_t v = 0;

    (void)ctx;
    if (n <= 1) {
        return 0;
    }
    if (nodus_random((uint8_t *)&v, sizeof(v)) != 0) {
        /* D4: transport-local only — a failed draw picks the first
         * choice; it never reaches consensus data. */
        QGP_LOG_ERROR(LOG_TAG, "OS randomness failed; transport choice 0");
        return 0;
    }
    return (int64_t)((v >> 1) % (uint64_t)n);
}

int nodus_p2p_sc_sign(void *ctx, const uint8_t *msg, size_t msg_len,
                      uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    const nodus_identity_t *id = (const nodus_identity_t *)ctx;
    nodus_sig_t sig;
    int rc;

    if (id == NULL) {
        return -1;
    }
    rc = nodus_sign_session_auth(&sig, msg, msg_len, &id->sk);
    memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    memset(&sig, 0, sizeof(sig));
    return rc;
}

int nodus_p2p_sc_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_session_auth(&sig, msg, msg_len, &pk);
}

/* ══ the socket host ══════════════════════════════════════════════════ */

#define IO_TAG_LISTEN ((uint64_t)UINT64_MAX - 1)
#define IO_TAG_WAKE   ((uint64_t)UINT64_MAX - 2)

static int ip_to_sockaddr(const cmt_p2p_ip_t *ip, uint16_t port,
                          struct sockaddr_storage *ss, socklen_t *sl)
{
    uint8_t v4[4];

    memset(ss, 0, sizeof(*ss));
    if (cmt_p2p_ip_to4(ip, v4)) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;

        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        memcpy(&sin->sin_addr, v4, 4);
        *sl = (socklen_t)sizeof(*sin);
        return 0;
    }
    if (ip->len == CMT_P2P_IPV6_LEN) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        memcpy(&sin6->sin6_addr, ip->b, 16);
        *sl = (socklen_t)sizeof(*sin6);
        return 0;
    }
    return -1;
}

static int sockaddr_to_ip(const struct sockaddr_storage *ss, cmt_p2p_ip_t *ip,
                          uint16_t *port)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        const uint8_t *b = (const uint8_t *)&sin->sin_addr;

        *ip = cmt_p2p_ip_v4(b[0], b[1], b[2], b[3]);
        *port = ntohs(sin->sin_port);
        return 0;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;

        memset(ip, 0, sizeof(*ip));
        memcpy(ip->b, &sin6->sin6_addr, 16);
        ip->len = CMT_P2P_IPV6_LEN;
        *port = ntohs(sin6->sin6_port);
        return 0;
    }
    return -1;
}

static nodus_p2p_sock_t *io_slot(nodus_p2p_io_t *io, int slot, bool grow)
{
    if (slot < 0) {
        return NULL;
    }
    if (slot >= io->n_socks) {
        int n = io->n_socks > 0 ? io->n_socks : 16, i;
        nodus_p2p_sock_t *ns;

        if (!grow) {
            return NULL;
        }
        while (n <= slot) {
            n *= 2;
        }
        ns = (nodus_p2p_sock_t *)realloc(io->socks, (size_t)n * sizeof(*ns));
        if (ns == NULL) {
            return NULL;
        }
        for (i = io->n_socks; i < n; i++) {
            memset(&ns[i], 0, sizeof(ns[i]));
            ns[i].fd = -1;
        }
        io->socks = ns;
        io->n_socks = n;
    }
    return &io->socks[slot];
}

static void io_set_events(nodus_p2p_io_t *io, int slot, uint32_t events)
{
    nodus_p2p_sock_t *s = &io->socks[slot];
    struct epoll_event ev;

    if (s->fd < 0 || s->events == events) {
        return;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = (uint64_t)slot;
    if (epoll_ctl(io->epfd, EPOLL_CTL_MOD, s->fd, &ev) == 0) {
        s->events = events;
    }
}

static int io_register(nodus_p2p_io_t *io, int slot, int fd, uint64_t gen,
                       bool connecting)
{
    nodus_p2p_sock_t *s = io_slot(io, slot, true);
    struct epoll_event ev;

    if (s == NULL) {
        return -1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = connecting ? (EPOLLOUT | EPOLLIN) : EPOLLIN;
    ev.data.u64 = (uint64_t)slot;
    if (epoll_ctl(io->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        return -1;
    }
    s->fd = fd;
    s->gen = gen;
    s->connecting = connecting;
    s->failed = false;
    s->events = ev.events;
    s->ready = 0;
    return 0;
}

int nodus_p2p_io_init(nodus_p2p_io_t *io, bool with_wake)
{
    if (io == NULL) {
        return -1;
    }
    memset(io, 0, sizeof(*io));
    io->listen_fd = -1;
    io->wake_fd = -1;
    io->last_served = -1;
    io->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (io->epfd < 0) {
        return -1;
    }
    if (with_wake) {
        struct epoll_event ev;

        io->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (io->wake_fd < 0) {
            close(io->epfd);
            io->epfd = -1;
            return -1;
        }
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.u64 = IO_TAG_WAKE;
        if (epoll_ctl(io->epfd, EPOLL_CTL_ADD, io->wake_fd, &ev) != 0) {
            close(io->wake_fd);
            close(io->epfd);
            io->wake_fd = -1;
            io->epfd = -1;
            return -1;
        }
    }
    return 0;
}

void nodus_p2p_io_free(nodus_p2p_io_t *io)
{
    int i;

    if (io == NULL) {
        return;
    }
    for (i = 0; i < io->n_socks; i++) {
        if (io->socks[i].fd >= 0) {
            close(io->socks[i].fd);
        }
    }
    free(io->socks);
    if (io->listen_fd >= 0) {
        close(io->listen_fd);
    }
    if (io->wake_fd >= 0) {
        close(io->wake_fd);
    }
    if (io->epfd >= 0) {
        close(io->epfd);
    }
    memset(io, 0, sizeof(*io));
    io->epfd = -1;
    io->listen_fd = -1;
    io->wake_fd = -1;
}

int nodus_p2p_io_listen(nodus_p2p_io_t *io, const char *ip, uint16_t port)
{
    cmt_p2p_ip_t a;
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    struct epoll_event ev;
    int fd, one = 1;

    if (io == NULL || ip == NULL || !cmt_p2p_ip_parse(ip, strlen(ip), &a) ||
        ip_to_sockaddr(&a, port, &ss, &sl) != 0) {
        errno = EINVAL;
        return -1;
    }
    fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 || listen(fd, 128) != 0) {
        int e = errno;

        close(fd);
        errno = e;
        return -1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = IO_TAG_LISTEN;
    if (epoll_ctl(io->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        int e = errno;

        close(fd);
        errno = e;
        return -1;
    }
    io->listen_fd = fd;
    io->listen_armed = true;
    return 0;
}

/* transport.go:212-241 Dial — the host half: a non-blocking connect. */
int nodus_p2p_io_dial(nodus_p2p_io_t *io, int slot, uint64_t gen,
                      const cmt_p2p_netaddr_t *addr)
{
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    int fd, one = 1;

    if (io == NULL || addr == NULL ||
        ip_to_sockaddr(&addr->ip, addr->port, &ss, &sl) != 0) {
        return -1;
    }
    fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (io_register(io, slot, fd, gen, true) != 0) {
        close(fd);
        return -1;
    }
    return 0;
}

void nodus_p2p_io_close(nodus_p2p_io_t *io, int slot, uint64_t gen)
{
    nodus_p2p_sock_t *s;

    if (io == NULL || (s = io_slot(io, slot, false)) == NULL || s->fd < 0 ||
        s->gen != gen) {
        return;
    }
    (void)epoll_ctl(io->epfd, EPOLL_CTL_DEL, s->fd, NULL);
    close(s->fd);
    s->fd = -1;
    s->connecting = false;
    s->failed = false;
    s->events = 0;
    s->ready = 0;
}

void nodus_p2p_io_wait(nodus_p2p_io_t *io, int timeout_ms)
{
    struct epoll_event evs[64];
    int n, i;

    if (io == NULL || io->epfd < 0) {
        return;
    }
    /* Re-arm EPOLLIN on every socket whose read_buf has room again: io_read
     * cleared it at true backpressure, and the transport may have consumed
     * since (the switch's tick, a returned handshake job). Without this a
     * socket holding unread bytes would sleep through the whole wait. */
    if (io->t != NULL) {
        for (i = 0; i < io->n_socks; i++) {
            nodus_p2p_sock_t *s = &io->socks[i];
            size_t room = 0;

            if (s->fd < 0 || s->failed || s->connecting ||
                (s->events & (uint32_t)EPOLLIN) != 0) {
                continue;
            }
            if (cmt_p2p_transport_read_buf(io->t, i, s->gen, &room) != NULL &&
                room > 0) {
                io_set_events(io, i, s->events | EPOLLIN);
            }
        }
    }
    n = epoll_wait(io->epfd, evs, 64, timeout_ms < 0 ? 0 : timeout_ms);
    for (i = 0; i < n; i++) {
        if (evs[i].data.u64 == IO_TAG_WAKE) {
            uint64_t v;

            while (read(io->wake_fd, &v, sizeof(v)) == (ssize_t)sizeof(v)) {
                /* drained */
            }
        } else if (evs[i].data.u64 != IO_TAG_LISTEN &&
                   evs[i].data.u64 < (uint64_t)io->n_socks) {
            io->socks[evs[i].data.u64].ready |= evs[i].events;
        }
    }
}

/* The socket of (slot, gen) is still the one this call started on and may
 * still move bytes. Re-evaluated after every transport call: a consumer
 * step can close the connection (host close → fd -1), a reactor callback
 * can dial and so reuse the slot under a new generation, or grow
 * io->socks (io_slot's realloc) — the caller re-takes &io->socks[slot]. */
static bool io_sock_live(const nodus_p2p_io_t *io, int slot, uint64_t gen)
{
    const nodus_p2p_sock_t *s = &io->socks[slot];

    return s->fd >= 0 && s->gen == gen && !s->failed && !s->connecting;
}

/*
 * One socket's writes — the sendRoutine's continuous conn.Write
 * (connection.go:429-507, R-P2P-17): write what write_buf holds; when it
 * is empty, run the connection's SEND step once
 * (cmt_p2p_transport_pump_conn with_recv false: the MConnection's next
 * flushed bytes are sealed into wbuf; nothing is delivered — the write
 * path never hands out consensus-queue room outside the read path's and
 * the tick's rotation, RT2 A-F3 / decision 2026-09-27-p2p-fix-2.md (4))
 * and write again. Ends when send(2) would block (EPOLLOUT armed), when a step
 * produced nothing (EPOLLOUT cleared — nothing to write: the MConnection
 * is idle or parked in its send Monitor, :515), or when the socket /
 * connection is gone. Every trip either sends >= 1 byte or is the single
 * step between two sends; the bytes a step can produce are what the
 * reactors have queued (bounded send queues) and the send Monitor lets
 * through.
 */
static void io_write(nodus_p2p_io_t *io, int slot)
{
    uint64_t gen = io->socks[slot].gen;
    bool stepped = false;               /* a step ran since the last send */

    for (;;) {
        nodus_p2p_sock_t *s;
        size_t len = 0;
        const uint8_t *b;
        ssize_t n;

        if (!io_sock_live(io, slot, gen)) {
            return;
        }
        s = &io->socks[slot];
        b = cmt_p2p_transport_write_buf(io->t, slot, gen, &len);
        if (b == NULL || len == 0) {
            if (!stepped) {
                cmt_p2p_transport_pump_conn(io->t, slot, gen, false);
                stepped = true;
                continue;               /* re-check: the step may close it */
            }
            io_set_events(io, slot, s->events & ~(uint32_t)EPOLLOUT);
            return;
        }
        n = send(s->fd, b, len, MSG_NOSIGNAL);
        if (n > 0) {
            cmt_p2p_transport_write_done(io->t, slot, gen, (size_t)n);
            stepped = false;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            io_set_events(io, slot, s->events | EPOLLOUT);
            return;
        }
        s->failed = true;
        cmt_p2p_transport_conn_failed(io->t, slot, gen);
        return;
    }
}

/*
 * The most socket bytes ONE io_read call takes: about one sample of the
 * recv Monitor at the configured rate — recv_rate × the Monitor's 100 ms
 * sample (flowrate.go:51; 512 000 B at the default 5 120 000 B/s,
 * config.go:584), never less than one rbuf. "About": this counts sealed
 * wire bytes (1044 per 1024 plaintext), the Monitor counts packet bytes,
 * so the cap sits ~2 % below one sample's plaintext quota.
 * ⚠ NOT GROUNDED — the reference has no such cap: its recvRoutine is its
 * own goroutine, and the recv Monitor (connection.go:598) alone bounds
 * it. Here every connection shares one loop and the Monitor reads the
 * live monotonic clock: if consuming one sample's bytes takes longer than
 * the sample, a new sample opens INSIDE the call, and a peer that keeps
 * its socket full would hold the loop — every other connection and the
 * consensus lane — without end. The cap makes one call yield after at
 * most one sample's quota; EPOLLIN stays armed, so a socket with bytes
 * left is served again at the next wait (level-triggered) — no stranding.
 */
static size_t io_read_budget(const nodus_p2p_io_t *io)
{
    int64_t rate = io->t->cfg.mconn.recv_rate;
    int64_t q;

    if (rate <= 0) {
        return (size_t)CMT_P2P_CONN_RBUF_ALLOC;
    }
    q = rate / (CMT_P2P_NS_PER_SEC / CMT_FLOWRATE_DEFAULT_SAMPLE_NS);
    return q > (int64_t)CMT_P2P_CONN_RBUF_ALLOC ? (size_t)q
                                                : (size_t)CMT_P2P_CONN_RBUF_ALLOC;
}

/*
 * One socket's reads — the recvRoutine's continuous read (connection.go:
 * 590-694, through bufio :186; R-P2P-17): read into read_buf; when it is
 * full, run the connection's step once (cmt_p2p_transport_pump_conn: open
 * the sealed frames, hand the plaintext to the MConnection → the
 * reactors) and read again. Ends:
 *   · recv(2) would block — everything the kernel held is taken;
 *   · a step freed no room — TRUE backpressure (the recv Monitor refused,
 *     :598; the MConnection or an upgrade step takes nothing more; an
 *     upgraded connection not yet wrapped): EPOLLIN is cleared, and
 *     nodus_p2p_io_wait re-arms it as soon as read_buf has room again;
 *   · io_read_budget bytes taken (EPOLLIN stays armed);
 *   · the transport's `may_receive` answers false for this PEER
 *     connection — the consensus reactor's Receive is "blocked": the
 *     state machine's queue has no room for ONE more message
 *     (h_may_receive): nothing read, EPOLLIN left as it is. The step
 *     itself asks the same row before every message it delivers, and
 *     while the queue is contended delivers ONE queue-entering message
 *     per step (h_recv_near_full, h_queue_mark; cmt_p2p_peer.h "THE
 *     RECEIVE GATE");
 *   · the queue is contended after a step (h_recv_near_full): one
 *     step per call, then the next socket (EPOLLIN stays armed);
 *   · EOF / error, or the step closed the connection.
 * Every trip either reads >= 1 byte or is the single step between two
 * reads, so the loop is bounded by the budget.
 * @return true when >= 1 socket byte was read (the slot was served).
 */
static bool io_read(nodus_p2p_io_t *io, int slot)
{
    uint64_t gen = io->socks[slot].gen;
    size_t budget = io_read_budget(io), taken = 0;
    bool stepped = false;               /* a step ran since the last recv */

    for (;;) {
        nodus_p2p_sock_t *s;
        size_t room = 0;
        uint8_t *b;
        ssize_t n;

        if (!io_sock_live(io, slot, gen)) {
            return taken > 0;
        }
        /* The blocked Receive (transport host row `may_receive`; PEER
         * connections only, handshakes never): asked before every recv
         * and every step. No read, no step, EPOLLIN left as it is — the
         * wait is level-triggered, so the loop comes straight back after
         * the consensus lane has drained its queue in between. */
        if (!cmt_p2p_transport_may_receive(io->t, slot, gen)) {
            return taken > 0;
        }
        s = &io->socks[slot];
        b = cmt_p2p_transport_read_buf(io->t, slot, gen, &room);
        if (b == NULL || room == 0) {
            if (!stepped) {
                cmt_p2p_transport_pump_conn(io->t, slot, gen, true);
                stepped = true;
                /* Contended: that step delivered at most ONE
                 * queue-entering message; the next socket gets its turn
                 * before this one steps again (the FIFO hand-out,
                 * h_recv_near_full). EPOLLIN stays armed —
                 * level-triggered, the bytes wait. */
                if (cmt_p2p_transport_recv_near_full(io->t, slot, gen)) {
                    return taken > 0;
                }
                continue;               /* re-check: the step may close it */
            }
            /* Backpressure (a full rbuf is a blocked Read): stop watching
             * for input until the transport has consumed some. */
            io_set_events(io, slot, s->events & ~(uint32_t)EPOLLIN);
            return taken > 0;
        }
        io_set_events(io, slot, s->events | EPOLLIN);
        if (taken >= budget) {
            return true;
        }
        if (room > budget - taken) {
            room = budget - taken;
        }
        n = recv(s->fd, b, room, 0);
        if (n > 0) {
            cmt_p2p_transport_read_done(io->t, slot, gen, (size_t)n);
            taken += (size_t)n;
            stepped = false;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return taken > 0;
        }
        s->failed = true;                                  /* EOF or error */
        cmt_p2p_transport_conn_failed(io->t, slot, gen);
        return taken > 0;
    }
}

/* A non-blocking connect(2) has finished (or failed). */
static void io_connect_done(nodus_p2p_io_t *io, int slot)
{
    nodus_p2p_sock_t *s = &io->socks[slot];
    struct pollfd pfd;
    int err = 0;
    socklen_t el = (socklen_t)sizeof(err);
    struct sockaddr_storage ss;
    socklen_t sl = (socklen_t)sizeof(ss);
    cmt_p2p_ip_t ip;
    uint16_t port = 0;
    uint64_t gen = s->gen;

    pfd.fd = s->fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    if (poll(&pfd, 1, 0) <= 0) {
        return;                                            /* still connecting */
    }
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0 ||
        getpeername(s->fd, (struct sockaddr *)&ss, &sl) != 0 ||
        sockaddr_to_ip(&ss, &ip, &port) != 0) {
        s->connecting = false;
        s->failed = true;
        cmt_p2p_transport_conn_failed(io->t, slot, gen);
        return;
    }
    s->connecting = false;
    io_set_events(io, slot, EPOLLIN);
    cmt_p2p_transport_dial_connected(io->t, slot, gen, &ip, port);
}

/* transport.go:286-353 acceptPeers — the host half (LimitListener
 * :261-263: never accept(2) while the limit is reached), at most
 * NODUS_P2P_ACCEPT_BUDGET accept(2) calls per pass (header). */
static void io_accept(nodus_p2p_io_t *io)
{
    struct epoll_event ev;
    int calls = 0;

    if (io->listen_fd < 0) {
        return;
    }
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        cmt_p2p_ip_t ip;
        uint16_t port = 0;
        int fd, slot = -1, rc;
        uint64_t gen = 0;

        if (!cmt_p2p_transport_can_accept(io->t) ||
            calls >= NODUS_P2P_ACCEPT_BUDGET) {
            break;
        }
        calls++;
        fd = accept(io->listen_fd, (struct sockaddr *)&ss, &sl);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) {
                continue;
            }
            break;                                         /* EAGAIN / error */
        }
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) != 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            close(fd);
            continue;
        }
        if (sockaddr_to_ip(&ss, &ip, &port) != 0) {
            close(fd);
            continue;
        }
        rc = cmt_p2p_transport_accept(io->t, &ip, port, 0, &slot, &gen);
        if (rc != CMT_P2P_ERR_NONE) {
            char ipb[CMT_P2P_IP_STR_MAX];

            (void)cmt_p2p_ip_string(&ip, ipb, sizeof(ipb));
            QGP_LOG_DEBUG(LOG_TAG, "inbound %s:%u refused: %s", ipb,
                          (unsigned)port, cmt_p2p_err_str(rc));
            close(fd);
            continue;
        }
        if (io_register(io, slot, fd, gen, false) != 0) {
            close(fd);
            cmt_p2p_transport_conn_failed(io->t, slot, gen);
        }
    }
    /* Watch the listener only while the limit has room (a full limit
     * leaves connections in the kernel's backlog, as LimitListener's
     * blocked Accept does). */
    {
        bool want = cmt_p2p_transport_can_accept(io->t);

        if (want != io->listen_armed) {
            memset(&ev, 0, sizeof(ev));
            ev.events = want ? EPOLLIN : 0;
            ev.data.u64 = IO_TAG_LISTEN;
            if (epoll_ctl(io->epfd, EPOLL_CTL_MOD, io->listen_fd, &ev) == 0) {
                io->listen_armed = want;
            }
        }
    }
}

/*
 * One pass over every socket. The walk STARTS just past the slot this
 * pump last served (read >= 1 byte) and wraps — the served-goes-to-the-
 * back round-robin of the APPROVED fairness rule atlas-dec-efa4d29c. The
 * reference has no walk: each connection's recvRoutine is its own
 * goroutine (connection.go:590-694). A walk that always began at slot 0
 * gave a low slot that keeps the consensus queue full the first read of
 * every pass (red-team H3); the transport tick walks the same way
 * (cmt_p2p_transport_tick). A socket added inside the pass (a dial from
 * a reactor callback) waits for the next one.
 */
void nodus_p2p_io_pump(nodus_p2p_io_t *io)
{
    int k, n, start;

    if (io == NULL || io->t == NULL) {
        return;
    }
    io_accept(io);
    n = io->n_socks;
    start = (io->last_served >= 0 && io->last_served < n) ? io->last_served + 1 : 0;
    for (k = 0; k < n; k++) {
        int slot = (start + k) % n;
        nodus_p2p_sock_t *s = &io->socks[slot];

        if (s->fd < 0) {
            continue;
        }
        s->ready = 0;
        if (s->connecting) {
            io_connect_done(io, slot);
            continue;
        }
        if (io_read(io, slot)) {
            io->last_served = slot;
        }
        io_write(io, slot);
    }
}

void nodus_p2p_io_flush(nodus_p2p_io_t *io)
{
    int slot;

    if (io == NULL || io->t == NULL) {
        return;
    }
    for (slot = 0; slot < io->n_socks; slot++) {
        if (io->socks[slot].fd >= 0) {
            io_write(io, slot);
        }
    }
}

/* ══ the witness host ═════════════════════════════════════════════════ */

/* The worker's three bounded queues (file header; §2R4 P3). */
enum { WQ_OUTBOUND = 0, WQ_INBOUND = 1, WQ_ADDR = 2, WQ_N = 3 };
/** Depth of each queue. ⚠ NOT GROUNDED — a size (the reference runs one
 *  goroutine per connection, transport.go:304-309, with no queue).
 *  Rationale: a full reconnect of the default inbound limit (40, config.go
 *  :622) queues at once; past the depth a handshake is closed (§2R4 P3),
 *  never blocked. The INBOUND queue is never shallower than the live
 *  listener limit (inbound_depth — bonded peers raise the limit at run
 *  time, red-team R6 F4). */
#define NODUS_P2P_JOBQ_DEPTH   64
/* The static half of the inbound queue's bound (inbound_depth): the
 * default inbound limit alone must fit. */
_Static_assert(NODUS_P2P_JOBQ_DEPTH >= CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS,
               "the job queue must hold one handshake job per default "
               "inbound connection");
#define NODUS_P2P_WORKERS_DEFAULT 2
#define NODUS_P2P_WORKERS_MAX     8

typedef struct wjob {
    struct wjob       *next;
    int                q;
    cmt_p2p_hs_job_t  *hs;                        /* WQ_OUTBOUND / INBOUND */
    uint64_t           ticket;                    /* WQ_ADDR               */
    uint8_t            payload[CMT_P2P_ADDR_REC_PAYLOAD_SIZE];
    uint8_t            sig[CMT_P2P_ADDR_REC_SIG_SIZE];
    uint8_t            pk[QGP_DSA87_PUBLICKEYBYTES];
    int                rc;
} wjob_t;

typedef struct {
    char    id[CMT_P2P_ID_CAP];
    uint8_t pk[NODUS_PK_BYTES];
} p2p_bonded_t;

/** The largest StatusResponse `bs_receive` keeps before the lane is live:
 *  its canonical form is at most tag + len + two (tag + 10-byte varint)
 *  fields = 24 bytes (cmt_bsync_msgs.c, types.pb.go:565-581, :704-718). */
#define NODUS_P2P_BS_STATUS_MAX 32

/** One index of the consensus seam (file header). */
typedef struct {
    cmt_p2p_peer_t *peer;          /* NULL = free                          */
    bool conr_init, memr_init;     /* the reactor's InitPeer ran           */
    bool conr_added, memr_added;   /* the reactor's AddPeer ran            */
    bool cons_removed, mem_removed;/* the shim's RemovePeer ran            */
    int  pending_stop;             /* deferred StopPeerForError reason     */
    /* DEVIATION (bs_receive): the latest 0x40 StatusResponse this peer
     * sent before the lane was live, re-marshalled; replayed into the
     * block sync reactor at nodus_witness_p2p_lane_live. */
    bool    bs_status_held;
    char    bs_status_id[CMT_P2P_ID_CAP];
    uint8_t bs_status[NODUS_P2P_BS_STATUS_MAX];
    size_t  bs_status_len;
} p2p_lane_slot_t;

/* The 0x70 serving side's per-requester gate (red-team H2 / R6 F5): one
 * entry per requesting peer ID, the last time it was served. Sized by
 * the host's peer index space (CMT_CONR_MAX_PEERS, the consensus seam's
 * slot count): no more peers than that can be connected and indexed at
 * once. ⚠ NOT GROUNDED — channel 0x70 has no reference counterpart
 * (R-P2P-5). */
#define NODUS_P2P_GB_SERVE_SLOTS  CMT_CONR_MAX_PEERS
/** The minimum gap between two chunks served to ONE requester — the
 *  former node-wide V2SYNC_SERVE_MIN_GAP_MS (nodus_witness_v2_sync2.c),
 *  now per requester. ⚠ NOT GROUNDED (local policy, as it was). */
#define NODUS_P2P_GB_SERVE_GAP_MS 100u

typedef struct {
    char     id[CMT_P2P_ID_CAP];   /* "" = free                          */
    uint64_t last_ms;              /* monotonic                          */
} p2p_gb_serve_t;

/* StopPeerForError reasons this host passes (logged by the switch). */
#define NODUS_P2P_STOP_CONR_BASE    400   /* + cmt_conr_stop_reason_t      */
#define NODUS_P2P_STOP_MEMR         410   /* mempool/reactor.go:172        */
#define NODUS_P2P_STOP_DECODE_0X70  420   /* peer.go:410-421               */
#define NODUS_P2P_STOP_DECODE_0X71  421
#define NODUS_P2P_STOP_BSYNC_BASE   430   /* + cmt_bsync_stop_reason_t     */

struct nodus_witness_p2p {
    nodus_witness_t            *w;
    const nodus_identity_t     *identity;
    nodus_p2p_config_t          cfg;
    uint8_t                     chain_id[32];
    char                        self_id[CMT_P2P_ID_CAP];
    char                        data_path[256];
    char                        seq_dir[256];
    char                        listen_ip[64];
    uint16_t                    listen_port;
    char                        external_ip[64];

    nodus_p2p_io_t              io;
    cmt_p2p_node_info_t        *ni;
    cmt_p2p_transport_t         t;
    bool                        t_init;
    cmt_p2p_switch_t            sw;
    bool                        sw_init;
    cmt_p2p_addrbook_t         *book;
    cmt_p2p_addr_book_t         seam;
    cmt_p2p_pex_t              *pex;

    cmt_p2p_ch_desc_t           cons_desc[CMT_CONR_NUM_CHANNELS];
    cmt_p2p_ch_desc_t           mem_desc[1];
    cmt_p2p_ch_desc_t           bs_desc[1];
    cmt_p2p_ch_desc_t           gb_desc[1];
    cmt_p2p_ch_desc_t           cc_desc[1];

    /* the worker */
    pthread_mutex_t             mu;
    pthread_cond_t              cv;
    bool                        mu_init;
    wjob_t                     *qh[WQ_N], *qt[WQ_N];
    int                         qdepth[WQ_N];
    wjob_t                     *dh, *dt;
    bool                        stop;
    pthread_t                   th[NODUS_P2P_WORKERS_MAX];
    int                         n_th;

    /* the bonded set (K2 / N5), sorted by ID */
    p2p_bonded_t               *bonded;
    int                         n_bonded, cap_bonded;
    bool                        bonded_valid;
    uint64_t                    bonded_tip;
    bool                        self_bonded;
    /* IDs that JOINED the set, summed over every refresh (the purge's
     * input, bonded_purge_new) — nodus_witness_p2p_bonded_joined_total */
    uint64_t                    bonded_joined_total;

    /* 0x70 — the joiner's ONE outstanding genesis-bundle request
     * (nodus_witness_p2p_gb_request / _gb_take) and the serving side's
     * per-requester gate (nodus_witness_p2p_gb_serve_allow). Kept here,
     * with the channel, not in nodus_witness_t (red-team H2). */
    bool                        gb_out_valid;
    char                        gb_out_peer[CMT_P2P_ID_CAP];
    uint64_t                    gb_out_offset;
    p2p_gb_serve_t              gb_serve[NODUS_P2P_GB_SERVE_SLOTS];
    /* The serving side's in-memory copy of the chain's genesis bundle
     * (RT2 B-F2; nodus_witness_p2p_gb_bundle), and the chain id it
     * belongs to. NULL = not loaded yet. */
    uint8_t                    *gb_bundle;
    size_t                      gb_bundle_len;
    uint8_t                     gb_bundle_chain[32];

    /* our own ADDR record (N7) */
    bool                        have_own_addr;
    cmt_p2p_ip_t                own_ip;
    uint16_t                    own_port;
    uint64_t                    own_seq;
    bool                        own_seq_exhausted;   /* UINT64_MAX logged */

    /* M4 — the last "no persistent peers" ERROR (monotonic ms; 0 = none) */
    int64_t                     no_peer_logged_ms;
    bool                        have_own_rec;
    uint8_t                     own_rec[CMT_P2P_ADDR_REC_SIZE];

    /* the consensus lane */
    cmt_conr_host_t             conr_host;
    cmt_memr_host_t             memr_host;
    bool                        lane_prepared;
    nodus_cmt_store_t          *store;
    cmt_now_fn                  lane_now;       /* the wall clock       */
    void                       *lane_now_ctx;
    cmt_mono_fn                 lane_mono;      /* the wait clock       */
    void                       *lane_mono_ctx;
    cmt_pb_arena_t              recv_arena;
    cmt_commit_sig_t           *commit_sigs;
    cmt_extended_commit_sig_t  *ext_sigs;
    cmt_pb_arena_t              ext_load_arena;
    cmt_pb_arena_t              part_arena;
    cmt_conr_t                 *conr;
    cmt_memr_t                 *memr;
    cmt_bsync_reactor_t        *bsync;       /* 0x40, borrowed (header)  */
    bool                        lane_live;
    p2p_lane_slot_t             slots[CMT_CONR_MAX_PEERS];
    bool                        any_pending_stop;
    /* A reactor call made from a p2p callback (receive, InitPeer,
     * AddPeer, RemovePeer) returned CMT_FAULT — node-local (W1.7). The
     * callback has no caller to hand it to, so it is kept here and
     * nodus_witness_p2p_lane_tick / _lane_live return CMT_FAULT from then
     * on; the witness stops consensus participation on that
     * (nodus_witness.c witness_cmt_tick). Never cleared: a node that
     * faulted does not resume (lane_fault_note). */
    bool                        lane_fault;
};

/* ── the worker (R-P2P-8, R-P2P-43) ─────────────────────────────────── */

static void wake(nodus_witness_p2p_t *p)
{
    uint64_t one = 1;

    if (p->io.wake_fd >= 0) {
        (void)!write(p->io.wake_fd, &one, sizeof(one));
    }
}

static void *worker_main(void *arg)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)arg;

    for (;;) {
        wjob_t *j = NULL;
        int q;

        pthread_mutex_lock(&p->mu);
        while (!p->stop && p->qh[0] == NULL && p->qh[1] == NULL &&
               p->qh[2] == NULL) {
            pthread_cond_wait(&p->cv, &p->mu);
        }
        if (p->stop) {
            pthread_mutex_unlock(&p->mu);
            return NULL;
        }
        for (q = 0; q < WQ_N; q++) {          /* outbound never waits (P3) */
            if (p->qh[q] != NULL) {
                j = p->qh[q];
                p->qh[q] = j->next;
                if (p->qh[q] == NULL) {
                    p->qt[q] = NULL;
                }
                p->qdepth[q]--;
                break;
            }
        }
        pthread_mutex_unlock(&p->mu);
        if (j == NULL) {
            continue;
        }
        j->next = NULL;
        if (j->hs != NULL) {
            (void)cmt_p2p_hs_job_run(j->hs);   /* stores its rc in the job */
        } else {
            nodus_sig_t sig;
            nodus_pubkey_t pk;

            memcpy(sig.bytes, j->sig, sizeof(j->sig));
            memcpy(pk.bytes, j->pk, sizeof(j->pk));
            j->rc = nodus_verify_witness_addr(&sig, j->payload,
                                              sizeof(j->payload), &pk);
        }
        pthread_mutex_lock(&p->mu);
        if (p->dt != NULL) {
            p->dt->next = j;
        } else {
            p->dh = j;
        }
        p->dt = j;
        pthread_mutex_unlock(&p->mu);
        wake(p);
    }
}

static int worker_push(nodus_witness_p2p_t *p, wjob_t *j, int depth)
{
    pthread_mutex_lock(&p->mu);
    if (p->stop || p->qdepth[j->q] >= depth) {
        pthread_mutex_unlock(&p->mu);
        return -1;
    }
    j->next = NULL;
    if (p->qt[j->q] != NULL) {
        p->qt[j->q]->next = j;
    } else {
        p->qh[j->q] = j;
    }
    p->qt[j->q] = j;
    p->qdepth[j->q]++;
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->mu);
    return 0;
}

/* Results, applied on the loop thread by (slot, generation) / ticket. */
static void worker_drain(nodus_witness_p2p_t *p)
{
    wjob_t *j;

    if (!p->mu_init) {
        return;
    }
    pthread_mutex_lock(&p->mu);
    j = p->dh;
    p->dh = p->dt = NULL;
    pthread_mutex_unlock(&p->mu);
    while (j != NULL) {
        wjob_t *next = j->next;

        if (j->hs != NULL) {
            (void)cmt_p2p_transport_job_done(&p->t, j->hs);
        } else if (p->book != NULL) {
            (void)cmt_p2p_addrbook_verify_done(p->book, j->ticket, j->rc);
        }
        free(j);
        j = next;
    }
}

/* Stop the threads; every job still queued is completed as "failed"
 * (the transport discards it — its connection is gone — and frees it),
 * every finished job is applied. */
static void worker_stop(nodus_witness_p2p_t *p)
{
    int i, q;

    if (!p->mu_init) {
        return;
    }
    pthread_mutex_lock(&p->mu);
    p->stop = true;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    for (i = 0; i < p->n_th; i++) {
        pthread_join(p->th[i], NULL);
    }
    p->n_th = 0;
    worker_drain(p);
    for (q = 0; q < WQ_N; q++) {
        wjob_t *j = p->qh[q];

        while (j != NULL) {
            wjob_t *next = j->next;

            if (j->hs != NULL) {
                j->hs->rc = -1;
                (void)cmt_p2p_transport_job_done(&p->t, j->hs);
            }
            free(j);
            j = next;
        }
        p->qh[q] = p->qt[q] = NULL;
        p->qdepth[q] = 0;
    }
}

/*
 * The inbound queue's depth, derived from the listener limit (red-team
 * R6 F4: a fixed 64 was below the limit — 40 + 32 bonded = 72 — so a full
 * reconnect of an accepted set could see handshakes closed for queue
 * space). Every accepted connection has at most ONE job outstanding
 * (cmt_p2p_transport.c submit_job: `c->job != NULL` returns), and the
 * listener admits at most cmt_p2p_transport_max_incoming connections
 * (LimitListener, transport.go:261); `n_inbound` covers a limit that
 * shrank (the bonded set got smaller) while those connections live. So
 * an inbound job never finds the queue full. The limit's bonded part is
 * known only at run time; its static part is the _Static_assert above.
 */
static int inbound_depth(const nodus_witness_p2p_t *p)
{
    int d = NODUS_P2P_JOBQ_DEPTH;
    int lim = p->t_init ? cmt_p2p_transport_max_incoming(&p->t) : 0;

    if (lim > d) {
        d = lim;
    }
    if (p->t_init && p->t.n_inbound > d) {
        d = p->t.n_inbound;
    }
    return d;
}

/* transport host `submit_job` (R-P2P-8; §2R4 P3). */
static int h_submit(void *ctx, cmt_p2p_hs_job_t *job)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    wjob_t *j = (wjob_t *)calloc(1, sizeof(*j));

    if (j == NULL) {
        return -1;
    }
    j->q = job->job_class == CMT_P2P_JOB_CLASS_OUTBOUND ? WQ_OUTBOUND : WQ_INBOUND;
    j->hs = job;
    if (worker_push(p, j, j->q == WQ_INBOUND ? inbound_depth(p)
                                             : NODUS_P2P_JOBQ_DEPTH) != 0) {
        free(j);
        return -1;
    }
    return 0;
}

/* address-book host `verify_addr_submit` (R-P2P-43). */
static int h_verify_submit(void *ctx, uint64_t ticket, const uint8_t *payload,
                           size_t len, const uint8_t sig[CMT_P2P_ADDR_REC_SIG_SIZE],
                           const uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    wjob_t *j;

    if (len != CMT_P2P_ADDR_REC_PAYLOAD_SIZE) {
        return -1;
    }
    j = (wjob_t *)calloc(1, sizeof(*j));
    if (j == NULL) {
        return -1;
    }
    j->q = WQ_ADDR;
    j->ticket = ticket;
    memcpy(j->payload, payload, sizeof(j->payload));
    memcpy(j->sig, sig, sizeof(j->sig));
    memcpy(j->pk, pk, sizeof(j->pk));
    if (worker_push(p, j, NODUS_P2P_JOBQ_DEPTH) != 0) {
        free(j);
        return -1;
    }
    return 0;
}

/* ── transport host rows ────────────────────────────────────────────── */

static int h_dial(void *ctx, int slot, uint64_t gen, const cmt_p2p_netaddr_t *addr,
                  uint64_t *host_handle)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    *host_handle = (uint64_t)slot;
    return nodus_p2p_io_dial(&p->io, slot, gen, addr);
}

static void h_close(void *ctx, int slot, uint64_t gen, uint64_t host_handle)
{
    (void)host_handle;
    nodus_p2p_io_close(&((nodus_witness_p2p_t *)ctx)->io, slot, gen);
}

/* ── the bonded set (K2 / N5) ───────────────────────────────────────── */

static int bonded_cmp(const void *a, const void *b)
{
    return strcmp(((const p2p_bonded_t *)a)->id, ((const p2p_bonded_t *)b)->id);
}

/* bsearch's comparator with the KEY first (C11 7.22.5.1): the key is the
 * ID string itself, so a lookup builds no 2.6 KB p2p_bonded_t key (RT2
 * D-F1 — the former memset of the whole entry, pubkey included, on every
 * is_bonded / bonded_pubkey). */
static int bonded_id_cmp(const void *key, const void *elem)
{
    return strcmp((const char *)key, ((const p2p_bonded_t *)elem)->id);
}

static const p2p_bonded_t *bonded_find_in(const p2p_bonded_t *set, int n,
                                          const char *id)
{
    if (id == NULL || n <= 0 || strlen(id) >= CMT_P2P_ID_CAP) {
        return NULL;
    }
    return (const p2p_bonded_t *)bsearch(id, set, (size_t)n, sizeof(*set),
                                         bonded_id_cmp);
}

static const p2p_bonded_t *bonded_find(const nodus_witness_p2p_t *p,
                                       const char *id)
{
    return bonded_find_in(p->bonded, p->n_bonded, id);
}

/* One pubkey into the scratch set being built (unsorted while filling;
 * duplicates skipped). */
static void bonded_add(p2p_bonded_t **set, int *n, int *cap,
                       const uint8_t pk[NODUS_PK_BYTES])
{
    char id[CMT_P2P_ID_CAP];
    int i;

    if (cmt_p2p_pubkey_to_id(pk, id) != CMT_OK) {
        return;
    }
    for (i = 0; i < *n; i++) {
        if (strcmp((*set)[i].id, id) == 0) {
            return;
        }
    }
    if (*n == *cap) {
        int ncap = *cap > 0 ? *cap * 2 : 64;
        p2p_bonded_t *nb = (p2p_bonded_t *)realloc(*set, (size_t)ncap * sizeof(*nb));

        if (nb == NULL) {
            return;
        }
        *set = nb;
        *cap = ncap;
    }
    memcpy((*set)[*n].id, id, sizeof(id));
    memcpy((*set)[*n].pk, pk, NODUS_PK_BYTES);
    (*n)++;
}

/* N5: the committee a height resolves to (the deleted B1 gate's reads,
 * nodus_witness_peer.c:696-720 before F5). */
static void bonded_add_committee(nodus_witness_p2p_t *p, p2p_bonded_t **set,
                                 int *n, int *cap, uint64_t height)
{
    nodus_committee_member_t *cm = NULL;
    int k = 0, i;

    if (nodus_committee_get_for_block_alloc(p->w, height, &cm, &k) == 0) {
        for (i = 0; i < k; i++) {
            bonded_add(set, n, cap, cm[i].pubkey);
        }
    }
    free(cm);
}

/*
 * Z2-F11 — the IDs that are in the new bonded set `nb` and were not in
 * the old one keep only a signed record and no ban from their unbonded
 * days (cmt_p2p_addrbook_purge_bonded_ids); otherwise a stale unsigned
 * entry → failed dials → MarkBad would refuse its signed record for 24 h
 * (design K2/K3: a new candidate is never held back). Only a NEWLY bonded
 * ID can need it (RT2 D-F1 — the purge used to walk the whole book and
 * every ban on every tip change): mark_bad never bans a bonded ID and the
 * book refuses an unsigned address for one (cmt_p2p_addrbook.c
 * add_address, and the file load's §2R4 P4 check), so an ID that stays
 * bonded acquires nothing to purge. Both sets are sorted by ID: one
 * merge walk. An old set that was never valid counts as empty — every
 * member is new.
 */
static void bonded_purge_new(nodus_witness_p2p_t *p, const p2p_bonded_t *nb,
                             int n_new)
{
    const char (*ids)[CMT_P2P_ID_CAP];
    char (*fresh)[CMT_P2P_ID_CAP];
    int i, j = 0, n_fresh = 0, n_old = p->bonded_valid ? p->n_bonded : 0;

    if (n_new == 0) {
        return;
    }
    fresh = (char (*)[CMT_P2P_ID_CAP])malloc((size_t)n_new * sizeof(*fresh));
    if (fresh == NULL) {
        return;
    }
    for (i = 0; i < n_new; i++) {
        int c = 1;

        while (j < n_old && (c = strcmp(p->bonded[j].id, nb[i].id)) < 0) {
            j++;
        }
        if (j < n_old && c == 0) {
            continue;                           /* bonded before: nothing */
        }
        memcpy(fresh[n_fresh++], nb[i].id, CMT_P2P_ID_CAP);
    }
    ids = (const char (*)[CMT_P2P_ID_CAP])fresh;
    p->bonded_joined_total += (uint64_t)n_fresh;
    if (n_fresh > 0 && p->book != NULL) {
        (void)cmt_p2p_addrbook_purge_bonded_ids(p->book, ids, n_fresh);
    }
    free(fresh);
}

uint64_t nodus_witness_p2p_bonded_joined_total(const nodus_witness_p2p_t *p)
{
    return p != NULL ? p->bonded_joined_total : 0;
}

void nodus_witness_p2p_refresh_bonded(nodus_witness_p2p_t *p)
{
    uint64_t tip = 0;
    sqlite3_stmt *st = NULL;
    bool was_self;
    p2p_bonded_t *nb = NULL;
    int n_new = 0, cap_new = 0;

    if (p == NULL) {
        return;
    }
    was_self = p->self_bonded;
    if (p->w == NULL || p->w->db == NULL) {
        p->n_bonded = 0;
        p->bonded_valid = true;
        p->bonded_tip = 0;
        p->self_bonded = false;
        return;
    }
    if (nodus_witness_block_height_checked(p->w, &tip) != 0) {
        return;                                /* keep the last good set */
    }
    /* The new set is built beside the old one, so the two can be
     * compared (bonded_purge_new) before the old one is replaced. */
    if (sqlite3_prepare_v2(p->w->db,
                           "SELECT pubkey FROM validators WHERE status IN (?, ?) "
                           "ORDER BY pubkey_hash", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int(st, 2, (int)DNAC_VALIDATOR_ELIGIBLE);
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_bytes(st, 0) == NODUS_PK_BYTES) {
                bonded_add(&nb, &n_new, &cap_new,
                           (const uint8_t *)sqlite3_column_blob(st, 0));
            }
        }
        sqlite3_finalize(st);
    } else {
        QGP_LOG_WARN(LOG_TAG, "validators table unreadable: %s",
                     sqlite3_errmsg(p->w->db));
    }
    bonded_add_committee(p, &nb, &n_new, &cap_new, tip + 1);
    if (tip >= 1) {
        bonded_add_committee(p, &nb, &n_new, &cap_new, tip - 1);
    }
    if (n_new > 1) {
        qsort(nb, (size_t)n_new, sizeof(*nb), bonded_cmp);
    }
    bonded_purge_new(p, nb, n_new);
    free(p->bonded);
    p->bonded = nb;
    p->n_bonded = n_new;
    p->cap_bonded = cap_new;
    p->bonded_valid = true;
    p->bonded_tip = tip;
    p->self_bonded = bonded_find(p, p->self_id) != NULL;
    if (p->self_bonded && !was_self && p->pex != NULL) {
        cmt_p2p_pex_own_record_changed(p->pex);          /* R-P2P-41 */
    }
}

static void bonded_maybe_refresh(nodus_witness_p2p_t *p)
{
    uint64_t tip = 0;

    if (p->w == NULL || p->w->db == NULL) {
        if (p->n_bonded != 0 || !p->bonded_valid) {
            nodus_witness_p2p_refresh_bonded(p);
        }
        return;
    }
    if (!p->bonded_valid ||
        (nodus_witness_block_height_checked(p->w, &tip) == 0 && tip != p->bonded_tip)) {
        nodus_witness_p2p_refresh_bonded(p);
    }
}

bool nodus_witness_p2p_is_bonded(nodus_witness_p2p_t *p, const char *id)
{
    return p != NULL && bonded_find(p, id) != NULL;
}

int nodus_witness_p2p_bonded_count(nodus_witness_p2p_t *p)
{
    return p != NULL ? p->n_bonded : 0;
}

bool nodus_witness_p2p_bonded_at(nodus_witness_p2p_t *p, int i,
                                 char id[CMT_P2P_ID_CAP],
                                 uint8_t pk[NODUS_PK_BYTES])
{
    if (p == NULL || i < 0 || i >= p->n_bonded) {
        return false;
    }
    if (id != NULL) {
        memcpy(id, p->bonded[i].id, CMT_P2P_ID_CAP);
    }
    if (pk != NULL) {
        memcpy(pk, p->bonded[i].pk, NODUS_PK_BYTES);
    }
    return true;
}

static bool h_is_bonded(void *ctx, const char *id)
{
    return nodus_witness_p2p_is_bonded((nodus_witness_p2p_t *)ctx, id);
}

static int h_bonded_count(void *ctx)
{
    return nodus_witness_p2p_bonded_count((nodus_witness_p2p_t *)ctx);
}

/* Free entries of the state machine's peer queue (cmt_cs_t.peer_q,
 * CMT_CS_MSG_QUEUE_SIZE = 1000 = consensus/state.go:168's msgQueueSize).
 * No lane bound, or no state machine behind it: unbounded — PEX, the
 * 0x70 / 0x71 channels and a pre-genesis joiner never wait (and a reactor
 * that is not running enqueues nothing, cmt_conr.c:739-741). */
static size_t peer_q_room(const nodus_witness_p2p_t *p)
{
    size_t len;

    if (p->conr == NULL || p->conr->cs == NULL) {
        return SIZE_MAX;
    }
    len = p->conr->cs->peer_q_len;
    return len < (size_t)CMT_CS_MSG_QUEUE_SIZE
               ? (size_t)CMT_CS_MSG_QUEUE_SIZE - len : 0;
}

/*
 * The transport's `may_receive` row — the consensus reactor's blocking
 * `peerMsgQueue <-` (consensus/reactor.go:324, :330, :350) in the
 * single-loop form: ROOM FOR ONE MESSAGE. The reference blocks each
 * message on its own slot; here the question is asked before EVERY
 * message a peer connection delivers (cmt_p2p_peer_pump →
 * cmt_p2p_mconn_recv_n with max 1) and before every socket read
 * (io_read). The lane tick (nodus_witness.c witness_cmt_tick) drains the
 * queue between two polls.
 *
 * WHY NOTHING READ IS EVER DROPPED (the invariant the deleted 483-message
 * step margin, register R-P2P-57, used to protect): a message reaches
 * cons_receive only if this row answered true right before the packets
 * that completed it were consumed, i.e. with >= 1 free entry; one
 * delivered message enqueues at most ONE entry (Proposal
 * cmt_conr.c:950-953, BlockPart :975-978, Vote :1014-1016 — the only
 * three enqueue sites, each a single cs_q_push, cmt_cs.c:761), and the
 * push happens synchronously inside that delivery, so the next question
 * sees it. No step size and no byte arithmetic remain. The bytes of a
 * message that may not be delivered stay in the connection's buffers
 * (pbuf / rbuf / the socket) until the queue has room — TCP
 * backpressure, as in the reference.
 */
static bool h_may_receive(void *ctx)
{
    return peer_q_room((const nodus_witness_p2p_t *)ctx) >= 1;
}

/*
 * The per-peer share of the state machine's peer queue behind the
 * contended threshold (h_recv_near_full): the queue divided evenly over
 * every index the consensus seam has — CMT_CS_MSG_QUEUE_SIZE (1000,
 * consensus/state.go:168) / CMT_CONR_MAX_PEERS (128) = 7 entries. So the
 * threshold, connected peers × share, never exceeds the queue itself
 * (128 × 7 = 896 < 1000), and with every index in use the queue is
 * contended below nearly its whole size.
 * ⚠ NOT GROUNDED — the reference has no share (its blocked goroutines
 * need no decision; decision 2026-09-27-p2p-fix-2.md (4) names "a
 * per-pass share" and leaves the number to the port).
 */
#define NODUS_P2P_RECV_SHARE ((size_t)CMT_CS_MSG_QUEUE_SIZE / (size_t)CMT_CONR_MAX_PEERS)
_Static_assert((size_t)CMT_CS_MSG_QUEUE_SIZE / (size_t)CMT_CONR_MAX_PEERS >= 1,
               "every consensus index must have a share of at least one entry");

/*
 * The transport's `recv_near_full` row — the queue is CONTENDED: fewer
 * free entries than connected peers × NODUS_P2P_RECV_SHARE, i.e. it can
 * no longer give every peer its share (decision 2026-09-27-p2p-fix-2.md
 * (4); RT2 A-F1 — the former "room < peers" rule let one peer take all
 * but n − 1 entries first). From here on each peer delivers ONE
 * queue-entering message per pump and the walks move on, sweep after
 * sweep while room remains (cmt_p2p_peer.h "THE RECEIVE GATE",
 * cmt_p2p_transport_tick), which is the order the Go runtime gives
 * blocked senders on a full channel (FIFO sendq): every waiting
 * recvRoutine gets one freed slot in turn. Above the threshold a peer
 * delivers until the queue becomes contended — every other peer's share
 * is still there.
 * ⚠ NOT GROUNDED as a threshold — the reference has none (register
 * R-P2P-58, replaced by this rule).
 */
static bool h_recv_near_full(void *ctx)
{
    const nodus_witness_p2p_t *p = (const nodus_witness_p2p_t *)ctx;
    size_t room = peer_q_room(p);
    int n = p->sw_init ? cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&p->sw)) : 0;

    if (room == SIZE_MAX) {
        return false;
    }
    return room < (size_t)(n > 1 ? n : 1) * NODUS_P2P_RECV_SHARE;
}

/*
 * The transport's `queue_mark` row: the peer queue's LENGTH. A delivered
 * message entered the queue exactly when the length moved across its
 * delivery — the pump compares the value right before and right after
 * the one recv_n call that delivered it (cmt_p2p_peer_pump). Exact
 * because nothing POPS the queue inside a delivery: the only pop is
 * cmt_cs_step's (cmt_cs.c:1623), which runs from the lane tick
 * (nodus_witness.c), never from a reactor Receive; and a delivery pushes
 * at most one entry (Proposal cmt_conr.c:950-953, BlockPart :975-978,
 * Vote :1014-1016 — each one cs_q_push, cmt_cs.c:761). Chosen over "the
 * channel id decides" because channel 0x21 also carries ProposalPOL and
 * 0x23 VoteSetBits, which enter no queue. No lane (a joiner, before
 * genesis): 0 — nothing enters a queue, and the queue is never contended.
 */
static uint64_t h_queue_mark(void *ctx)
{
    const nodus_witness_p2p_t *p = (const nodus_witness_p2p_t *)ctx;

    if (p->conr == NULL || p->conr->cs == NULL) {
        return 0;
    }
    return (uint64_t)p->conr->cs->peer_q_len;
}

static bool h_bonded_pubkey(void *ctx, const char *id,
                            uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    const p2p_bonded_t *b = bonded_find((const nodus_witness_p2p_t *)ctx, id);

    if (b == NULL) {
        return false;
    }
    memcpy(pk, b->pk, QGP_DSA87_PUBLICKEYBYTES);
    return true;
}

static int h_verify_addr(void *ctx, const uint8_t *payload, size_t len,
                         const uint8_t sig_in[CMT_P2P_ADDR_REC_SIG_SIZE],
                         const uint8_t pk_in[QGP_DSA87_PUBLICKEYBYTES])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_ADDR_REC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, QGP_DSA87_PUBLICKEYBYTES);
    return nodus_verify_witness_addr(&sig, payload, len, &pk);
}

static int h_rand_bytes(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    return n == 0 ? 0 : nodus_random(out, n);
}

/* ── files: atomic replace (tempfile.WriteFileAtomic, file.go:38) ──── */

static int write_file_atomic(const char *path, const uint8_t *bytes, size_t len)
{
    char tmp[600];
    char dir[600];
    char *slash;
    int fd, n;
    size_t off = 0;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }
    while (off < len) {
        ssize_t w = write(fd, bytes + off, len - off);

        if (w < 0 && errno == EINTR) {
            continue;
        }
        if (w <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t)w;
    }
    /* close(2) runs whatever fsync(2) answered: `fsync || close` left the
     * descriptor open on every fsync failure (Codex 12). */
    {
        int frc = fsync(fd);
        int crc = close(fd);

        if (frc != 0 || crc != 0) {
            unlink(tmp);
            return -1;
        }
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    snprintf(dir, sizeof(dir), "%s", path);
    slash = strrchr(dir, '/');
    if (slash != NULL) {
        *slash = '\0';
        fd = open(dir[0] ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            (void)fsync(fd);
            close(fd);
        }
    }
    return 0;
}

/* @return 1 no file; 0 read (`*bytes` malloc'd); -1 error. */
static int read_file(const char *path, uint8_t **bytes, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    uint8_t *b;

    *bytes = NULL;
    *len = 0;
    if (f == NULL) {
        return errno == ENOENT ? 1 : -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    b = (uint8_t *)malloc(sz > 0 ? (size_t)sz : 1);
    if (b == NULL) {
        fclose(f);
        return -1;
    }
    if (sz > 0 && fread(b, 1, (size_t)sz, f) != (size_t)sz) {
        free(b);
        fclose(f);
        return -1;
    }
    fclose(f);
    *bytes = b;
    *len = (size_t)sz;
    return 0;
}

#define NODUS_P2P_ADDRBOOK_FILE "p2p_addrbook.pb"
#define NODUS_P2P_ADDR_SEQ_FILE "nodus.addr_seq"

static void book_path(const nodus_witness_p2p_t *p, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", p->data_path[0] ? p->data_path : ".",
             NODUS_P2P_ADDRBOOK_FILE);
}

static int h_book_save(void *ctx, const uint8_t *bytes, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    char path[600];

    book_path(p, path, sizeof(path));
    if (write_file_atomic(path, bytes, len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "address book not saved to %s: %s", path,
                      strerror(errno));
        return -1;
    }
    return 0;
}

static int h_book_load(void *ctx, uint8_t **bytes, size_t *len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    char path[600];

    book_path(p, path, sizeof(path));
    return read_file(path, bytes, len);
}

/* ── our own signed ADDR record (N7; §2R4 P5: seq persisted first) ─── */

static int seq_read(const nodus_witness_p2p_t *p, uint64_t *out)
{
    char path[600];
    uint8_t *b = NULL;
    size_t len = 0;
    char buf[32];
    char *end = NULL;
    int rc;

    *out = 0;
    snprintf(path, sizeof(path), "%s/%s", p->seq_dir, NODUS_P2P_ADDR_SEQ_FILE);
    rc = read_file(path, &b, &len);
    if (rc == 1) {
        return 0;
    }
    if (rc != 0 || len == 0 || len >= sizeof(buf)) {
        free(b);
        return -1;
    }
    memcpy(buf, b, len);
    buf[len] = '\0';
    free(b);
    errno = 0;
    *out = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf) {
        return -1;
    }
    return 0;
}

static int seq_write(const nodus_witness_p2p_t *p, uint64_t seq)
{
    char path[600];
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)seq);

    snprintf(path, sizeof(path), "%s/%s", p->seq_dir, NODUS_P2P_ADDR_SEQ_FILE);
    return write_file_atomic(path, (const uint8_t *)buf, (size_t)n);
}

/* Persist `seq`, THEN sign the record naming it. */
static int own_sign(nodus_witness_p2p_t *p, uint64_t seq)
{
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];
    uint8_t payload[CMT_P2P_ADDR_REC_PAYLOAD_SIZE];
    nodus_sig_t sig;

    if (!p->have_own_addr) {
        return -1;
    }
    if (seq_write(p, seq) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "own ADDR seq %llu not persisted (%s) — not "
                      "signing", (unsigned long long)seq, strerror(errno));
        return -1;
    }
    if (qgp_sha3_512(p->identity->pk.bytes, NODUS_PK_BYTES, fp) != 0 ||
        cmt_p2p_addr_rec_payload(p->chain_id, fp, &p->own_ip, p->own_port, seq,
                                 payload) != CMT_OK ||
        nodus_sign_witness_addr(&sig, payload, sizeof(payload),
                                &p->identity->sk) != 0) {
        return -1;
    }
    memcpy(p->own_rec, payload, sizeof(payload));
    memcpy(p->own_rec + sizeof(payload), sig.bytes, CMT_P2P_ADDR_REC_SIG_SIZE);
    p->own_seq = seq;
    p->have_own_rec = true;
    return 0;
}

/* N7: seq = max(stored, the highest own seq peers have shown us) + 1. */
static void own_record_start(nodus_witness_p2p_t *p)
{
    uint64_t stored = 0, seen = 0, seq;

    if (!p->have_own_addr) {
        QGP_LOG_WARN(LOG_TAG, "no routable own address (set external_ip): "
                     "this node publishes no signed ADDR record");
        return;
    }
    if (seq_read(p, &stored) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "own ADDR seq file unreadable in %s — not "
                      "signing a record", p->seq_dir);
        return;
    }
    if (p->book != NULL) {
        (void)cmt_p2p_addrbook_own_seq_seen(p->book, &seen);
    }
    seq = stored > seen ? stored : seen;
    if (seq == UINT64_MAX) {                 /* checked +1 (own_record_check) */
        p->own_seq_exhausted = true;
        QGP_LOG_ERROR(LOG_TAG, "own ADDR seq is at its maximum — this node "
                      "publishes no signed ADDR record");
        return;
    }
    (void)own_sign(p, seq + 1);
}

/*
 * N7 — overtake a record of ours that someone ELSE signed (a reinstalled
 * key, a second instance): re-sign at seen + 1 only when a peer holds
 *   · a HIGHER seq than ours, or
 *   · the SAME seq with different bytes (cmt_p2p_addrbook_own_seq_differs).
 * Our own record echoed back by peers (same seq, same bytes) is NOT a
 * reason: re-signing on `seen == own_seq` made every echo bump the seq,
 * and it climbed forever (red-team M1). The +1 is checked: at UINT64_MAX
 * there is no newer seq to sign, and a wrapped 0 would be refused by
 * every book as not newer (P5) — refuse loudly instead. No reference
 * counterpart: signed ADDR records are nodus's own (R-P2P-4).
 */
static void own_record_check(nodus_witness_p2p_t *p)
{
    uint64_t seen = 0;

    if (p->book == NULL || !p->have_own_rec ||
        !cmt_p2p_addrbook_own_seq_seen(p->book, &seen) || seen < p->own_seq) {
        return;
    }
    if (seen == p->own_seq &&
        !cmt_p2p_addrbook_own_seq_differs(p->book, p->own_rec)) {
        return;                                  /* our own record, echoed */
    }
    if (seen == UINT64_MAX) {
        if (!p->own_seq_exhausted) {            /* once, not every poll */
            p->own_seq_exhausted = true;
            QGP_LOG_ERROR(LOG_TAG, "a record of ours at seq %llu (the "
                          "maximum) is held by peers — cannot sign a newer "
                          "one", (unsigned long long)seen);
        }
        return;
    }
    if (own_sign(p, seen + 1) == 0 && p->pex != NULL) {
        cmt_p2p_pex_own_record_changed(p->pex);
    }
}

static bool h_own_record(void *ctx, uint8_t rec[CMT_P2P_ADDR_REC_SIZE])
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (!p->have_own_rec || !p->self_bonded) {
        return false;                    /* pex.h: none unless bonded */
    }
    memcpy(rec, p->own_rec, CMT_P2P_ADDR_REC_SIZE);
    return true;
}

bool nodus_witness_p2p_signed_addr(nodus_witness_p2p_t *p,
                                   const uint8_t pk[NODUS_PK_BYTES],
                                   char *out, size_t cap)
{
    char id[CMT_P2P_ID_CAP];
    const uint8_t *rec = NULL;
    cmt_p2p_addr_rec_t r;
    cmt_p2p_netaddr_t na;

    if (p == NULL || pk == NULL || out == NULL || cap == 0 ||
        cmt_p2p_pubkey_to_id(pk, id) != CMT_OK) {
        return false;
    }
    if (strcmp(id, p->self_id) == 0) {
        rec = p->have_own_rec ? p->own_rec : NULL;
    } else if (p->book != NULL) {
        rec = cmt_p2p_addrbook_record(p->book, id, NULL);
    }
    if (rec == NULL ||
        cmt_p2p_addr_rec_parse(rec, CMT_P2P_ADDR_REC_SIZE, &r) != CMT_OK) {
        return false;
    }
    na = cmt_p2p_netaddr_new_ip_port(&r.ip, r.port);
    return cmt_p2p_netaddr_dial_string(&na, out, cap) > 0;
}

/* ── the consensus seam (file header) ───────────────────────────────── */

/* A reactor call made from inside a p2p callback returned `rc`. CMT_FAULT
 * is node-local (W1.7: a store, allocation or wiring failure of THIS
 * node, never a peer's input) and must stop consensus participation; the
 * callback returns void, so the fault is logged and made sticky here and
 * nodus_witness_p2p_lane_tick returns it (the reference panics at the
 * same places, e.g. mempool/clist_mempool.go:272-274). CMT_REJECT and
 * CMT_OK are not faults and are left to the caller. */
static void lane_fault_note(nodus_witness_p2p_t *p, int rc, const char *what,
                            const char *peer_id, int index)
{
    if (rc != CMT_FAULT) {
        return;
    }
    QGP_LOG_ERROR(LOG_TAG, "%s: CMT_FAULT (peer %s, index %d) — consensus "
                  "participation stops at the next lane tick", what,
                  peer_id != NULL ? peer_id : "-", index);
    p->lane_fault = true;
}

static int lane_find(const nodus_witness_p2p_t *p, const cmt_p2p_peer_t *peer)
{
    int i;

    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer == peer) {
            return i;
        }
    }
    return -1;
}

static int lane_slot_for(nodus_witness_p2p_t *p, cmt_p2p_peer_t *peer)
{
    int i = lane_find(p, peer);

    if (i >= 0 || peer == NULL) {
        return i;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {         /* the lowest free index */
        if (p->slots[i].peer == NULL) {
            memset(&p->slots[i], 0, sizeof(p->slots[i]));
            p->slots[i].peer = peer;
            return i;
        }
    }
    QGP_LOG_WARN(LOG_TAG, "peer %s gets no consensus index (all %d in use)",
                 cmt_p2p_peer_id(peer), (int)CMT_CONR_MAX_PEERS);
    return -1;
}

static void lane_slot_release(nodus_witness_p2p_t *p, int i)
{
    if (p->slots[i].cons_removed && p->slots[i].mem_removed) {
        memset(&p->slots[i], 0, sizeof(p->slots[i]));
    }
}

/* Take index `i` out of both reactors and free it — a peer the switch
 * dropped without a RemovePeer (switch.go:811-865: an addPeer that fails
 * after InitPeer calls no RemovePeer, in the reference too). */
static void lane_slot_clear(nodus_witness_p2p_t *p, int i)
{
    if (p->slots[i].conr_init && p->conr != NULL) {
        lane_fault_note(p, cmt_conr_remove_peer(p->conr, i),
                        "conr RemovePeer", NULL, i);
    }
    if (p->slots[i].memr_init && p->memr != NULL) {
        lane_fault_note(p, cmt_memr_remove_peer(p->memr, i),
                        "memr RemovePeer", NULL, i);
    }
    memset(&p->slots[i], 0, sizeof(p->slots[i]));
}

/* After the switch's tick every indexed peer must be in the peer set;
 * one that is not was dropped by a failed addPeer (above). Pointers are
 * compared, never dereferenced — the switch may already have freed it. */
static void lane_gc(nodus_witness_p2p_t *p)
{
    const cmt_p2p_peer_set_t *ps = cmt_p2p_switch_peers(&p->sw);
    int i, k;

    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        bool in_set = false;

        if (p->slots[i].peer == NULL) {
            continue;
        }
        for (k = 0; k < ps->n; k++) {
            if (ps->list[k] == p->slots[i].peer) {
                in_set = true;
                break;
            }
        }
        if (!in_set) {
            lane_slot_clear(p, i);
        }
    }
}

/* SHA3-512(the authenticated ML-DSA-87 key)[0..31] (file header). */
static bool peer_wid(const cmt_p2p_peer_t *peer, uint8_t out[32])
{
    const uint8_t *pk;
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];

    if (peer == NULL || peer->conn == NULL || peer->conn->sc == NULL ||
        !cmt_p2p_sc_is_authenticated(peer->conn->sc) ||
        (pk = cmt_p2p_sc_remote_pubkey(peer->conn->sc)) == NULL ||
        qgp_sha3_512(pk, CMT_P2P_SC_DSA_PK_SIZE, fp) != 0) {
        return false;
    }
    memcpy(out, fp, 32);
    return true;
}

static void lane_conr_init(nodus_witness_p2p_t *p, int i)
{
    uint8_t id[32];
    int     rc;

    if (p->conr == NULL || p->slots[i].conr_init || !peer_wid(p->slots[i].peer, id)) {
        return;
    }
    rc = cmt_conr_init_peer(p->conr, i, id);              /* switch.go:829-831 */
    if (rc == CMT_OK) {
        p->slots[i].conr_init = true;
    }
    lane_fault_note(p, rc, "conr InitPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_memr_init(nodus_witness_p2p_t *p, int i)
{
    int rc;

    if (p->memr == NULL || p->slots[i].memr_init) {
        return;
    }
    rc = cmt_memr_init_peer(p->memr, i);
    if (rc == CMT_OK) {
        p->slots[i].memr_init = true;
    }
    lane_fault_note(p, rc, "memr InitPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_conr_add(nodus_witness_p2p_t *p, int i)
{
    int rc;

    if (p->conr == NULL || !p->slots[i].conr_init || p->slots[i].conr_added) {
        return;
    }
    rc = cmt_conr_add_peer(p->conr, i);                   /* switch.go:858-860 */
    if (rc == CMT_OK) {
        p->slots[i].conr_added = true;
    }
    lane_fault_note(p, rc, "conr AddPeer", cmt_p2p_peer_id(p->slots[i].peer), i);
}

static void lane_memr_add(nodus_witness_p2p_t *p, int i)
{
    const cmt_p2p_peer_t *peer = p->slots[i].peer;
    int                   rc;

    if (p->memr == NULL || !p->slots[i].memr_init || p->slots[i].memr_added) {
        return;
    }
    rc = cmt_memr_add_peer(p->memr, i, cmt_p2p_peer_is_persistent(peer),
                           cmt_p2p_switch_is_peer_unconditional(
                               &p->sw, cmt_p2p_peer_id(peer)));
    if (rc == CMT_OK) {
        p->slots[i].memr_added = true;
    }
    lane_fault_note(p, rc, "memr AddPeer", cmt_p2p_peer_id(peer), i);
}

static void process_pending_stops(nodus_witness_p2p_t *p)
{
    int i;

    if (!p->any_pending_stop) {
        return;
    }
    p->any_pending_stop = false;
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        int reason = p->slots[i].pending_stop;
        cmt_p2p_peer_t *peer = p->slots[i].peer;

        if (reason == 0) {
            continue;
        }
        p->slots[i].pending_stop = 0;
        if (peer != NULL) {
            cmt_p2p_switch_stop_peer_for_error(&p->sw, peer, reason);
        }
    }
}

/* CONSENSUS shim reactor (channels 0x20-0x23, cmt_conr_get_channels). */
static const cmt_p2p_ch_desc_t *cons_channels(void *ctx, int *n)
{
    *n = CMT_CONR_NUM_CHANNELS;
    return ((nodus_witness_p2p_t *)ctx)->cons_desc;
}

static void cons_init_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    /* InitPeer runs once per peer object, and CONSENSUS is registered
     * before MEMPOOL: an index already naming this pointer belongs to a
     * freed peer whose memory was reused — clear it. */
    if (i >= 0) {
        lane_slot_clear(p, i);
    }
    i = lane_slot_for(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_conr_init(p, i);
    }
}

static void cons_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_conr_add(p, i);
    }
}

static void cons_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i < 0) {
        return;
    }
    if (p->slots[i].conr_init && p->conr != NULL) {
        lane_fault_note(p, cmt_conr_remove_peer(p->conr, i),   /* reactor.go:213-223 */
                        "conr RemovePeer", cmt_p2p_peer_id(peer), i);
    }
    p->slots[i].conr_init = false;
    p->slots[i].conr_added = false;
    p->slots[i].cons_removed = true;
    p->slots[i].pending_stop = 0;
    lane_slot_release(p, i);
}

static void cons_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                         const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, src), rc;

    if (i < 0 || p->conr == NULL || !p->slots[i].conr_added) {
        QGP_LOG_DEBUG(LOG_TAG, "consensus message from %s before the reactor "
                      "knows it — dropped (R-P2P-47)", cmt_p2p_peer_id(src));
        return;
    }
    rc = cmt_conr_receive(p->conr, i, ch_id, msg, len);
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "conr receive: CMT_FAULT (index %d channel "
                      "0x%02x)", i, ch_id);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    } else if (rc == CMT_REJECT) {
        /* The state machine's peer queue was full (R3-A-2) and the
         * message is DROPPED after its PeerState effects — the reference
         * blocks instead (consensus/reactor.go:324, :330, :350). Should be
         * unreachable: every message is delivered only after h_may_receive
         * found room for ONE, and one message enqueues at most one entry
         * (h_may_receive's invariant). A line here means that invariant
         * is broken. recv_msg is the message this call decoded
         * (cmt_conr.h, valid until the next receive). */
        int kind = p->conr->recv_msg != NULL ? (int)p->conr->recv_msg->kind : -1;

        QGP_LOG_WARN(LOG_TAG, "conr receive: REJECT (peer queue full) — "
                     "%s DROPPED from index %d channel 0x%02x",
                     kind == (int)CMT_PB_CONS_MSG_PROPOSAL   ? "Proposal" :
                     kind == (int)CMT_PB_CONS_MSG_BLOCK_PART ? "BlockPart" :
                     kind == (int)CMT_PB_CONS_MSG_VOTE       ? "Vote" :
                                                               "message",
                     i, ch_id);
    }
    process_pending_stops(p);
}

/* MEMPOOL shim reactor (channel 0x30, cmt_memr_get_channels). */
static const cmt_p2p_ch_desc_t *mem_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->mem_desc;
}

static void mem_init_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);                 /* CONSENSUS's InitPeer assigned it */

    if (i >= 0 && p->lane_live) {
        lane_memr_init(p, i);
    }
}

static void mem_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    if (i >= 0 && p->lane_live) {
        lane_memr_add(p, i);
    }
}

static void mem_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i < 0) {
        return;
    }
    if (p->slots[i].memr_init && p->memr != NULL) {
        lane_fault_note(p, cmt_memr_remove_peer(p->memr, i),   /* mempool/reactor.go:133-136 */
                        "memr RemovePeer", cmt_p2p_peer_id(peer), i);
    }
    p->slots[i].memr_init = false;
    p->slots[i].memr_added = false;
    p->slots[i].mem_removed = true;
    lane_slot_release(p, i);
}

static void mem_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                        const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, src), rc;
    uint8_t id[32];

    (void)ch_id;
    if (i < 0 || p->memr == NULL || !p->slots[i].memr_added) {
        QGP_LOG_DEBUG(LOG_TAG, "mempool message from %s before the reactor "
                      "knows it — dropped (R-P2P-47)", cmt_p2p_peer_id(src));
        return;
    }
    if (!peer_wid(src, id)) {
        return;
    }
    rc = cmt_memr_receive(p->memr, i, msg, len, id, sizeof(id));
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "memr receive: CMT_FAULT (index %d)", i);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    } else if (rc == CMT_REJECT) {
        QGP_LOG_WARN(LOG_TAG, "memr receive: REJECT from index %d", i);
    }
    process_pending_stops(p);
}

/* BLOCKSYNC shim reactor (channel 0x40, cmt_bsync_reactor_get_channels;
 * header "THE BLOCK SYNC SEAM"). No InitPeer: blocksync/reactor.go
 * embeds BaseReactor's no-op InitPeer. */
static const cmt_p2p_ch_desc_t *bs_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->bs_desc;
}

/* reactor.go:190-203 AddPeer — only once the lane is live (R-P2P-47);
 * lane_live runs it for the peers connected before. */
static void bs_add_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_live && p->bsync != NULL) {
        /* cmt_bsync_reactor_add_peer answers CMT_OK or CMT_FAULT only. */
        lane_fault_note(p, cmt_bsync_reactor_add_peer(p->bsync,
                                                      cmt_p2p_peer_id(peer)),
                        "blocksync AddPeer", cmt_p2p_peer_id(peer), -1);
    }
}

/* reactor.go:205-208 RemovePeer — the pool forgets the ID. */
static void bs_remove_peer(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int i = lane_find(p, peer);

    (void)reason;
    if (i >= 0) {
        p->slots[i].bs_status_held = false;     /* a held status dies here */
    }
    if (p->bsync != NULL) {
        cmt_bsync_reactor_remove_peer(p->bsync, cmt_p2p_peer_id(peer));
    }
}

/* ⚠ DEVIATION (no reference counterpart — the reference has no pre-live
 * window: p2p/switch.go:234-246 starts every reactor BEFORE it accepts a
 * peer, so a peer's AddPeer StatusResponse, reactor.go:190-203, always
 * reaches a running reactor). Here R-P2P-47 keeps the reactors away
 * from peers until nodus_witness_p2p_lane_live, and dropping that one
 * message made the pool learn the peer's height only at its 10 s status
 * broadcast (reactor.go:325, :371-373) — every node's switch to
 * consensus late by up to one interval. So while the lane is not live a
 * 0x40 StatusResponse is KEPT — only the LATEST one per peer (its lane
 * slot, keyed by the peer's p2p ID), canonical re-marshal, at most
 * NODUS_P2P_BS_STATUS_MAX bytes — and replayed into the reactor right
 * after it runs (lane_live). It is discarded when the peer is removed or
 * the lane unbound. Every other 0x40 message is still DROPPED before the
 * lane is live, undecodable bytes included, and the sender is never
 * stopped for anything received then (a pre-genesis joiner has no chain
 * to answer from). A peer holding no lane index keeps nothing. */
static void bs_hold_status(nodus_witness_p2p_t *p, cmt_p2p_peer_t *src,
                           const uint8_t *msg, size_t len)
{
    cmt_bsync_msg_t m;
    int i = lane_find(p, src);
    size_t n = 0;

    if (i < 0) {
        return;
    }
    cmt_bsync_msg_init(&m);
    if (cmt_bsync_msg_unmarshal(msg, len, &m) != CMT_OK ||
        m.kind != CMT_BSYNC_MSG_STATUS_RESPONSE) {
        cmt_bsync_msg_release(&m);
        return;
    }
    if (cmt_bsync_msg_marshal(&m, p->slots[i].bs_status,
                              sizeof(p->slots[i].bs_status), &n) == CMT_OK) {
        p->slots[i].bs_status_len = n;
        snprintf(p->slots[i].bs_status_id, CMT_P2P_ID_CAP, "%s",
                 cmt_p2p_peer_id(src));
        p->slots[i].bs_status_held = true;       /* the latest replaces */
    }
    cmt_bsync_msg_release(&m);
}

/* Replay the held StatusResponse of index `i` into the running block sync
 * reactor (the DEVIATION above), once; the entry is discarded either way. */
static void bs_replay_status(nodus_witness_p2p_t *p, int i)
{
    const char *id;

    if (!p->slots[i].bs_status_held) {
        return;
    }
    p->slots[i].bs_status_held = false;
    id = cmt_p2p_peer_id(p->slots[i].peer);
    if (p->bsync == NULL || strcmp(id, p->slots[i].bs_status_id) != 0) {
        return;
    }
    if (cmt_bsync_reactor_receive(p->bsync, id, p->slots[i].bs_status,
                                  p->slots[i].bs_status_len) == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "blocksync receive (held status): CMT_FAULT "
                      "(peer %s)", id);
        p->lane_fault = true;          /* sticky — lane_fault_note */
    }
}

bool nodus_witness_p2p_bsync_status_held(const nodus_witness_p2p_t *p,
                                         const char *peer_id,
                                         int64_t *out_height)
{
    int i;

    if (p == NULL || peer_id == NULL) {
        return false;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer != NULL && p->slots[i].bs_status_held &&
            strcmp(p->slots[i].bs_status_id, peer_id) == 0) {
            if (out_height != NULL) {
                cmt_bsync_msg_t m;

                cmt_bsync_msg_init(&m);
                *out_height = cmt_bsync_msg_unmarshal(p->slots[i].bs_status,
                                                      p->slots[i].bs_status_len,
                                                      &m) == CMT_OK ? m.height : -1;
                cmt_bsync_msg_release(&m);
            }
            return true;
        }
    }
    return false;
}

/* reactor.go:251-305 Receive. Before the lane is live — a pinned-genesis
 * joiner has no chain, a node before genesis time has no running
 * reactors — the message is DROPPED and the sender is NOT stopped
 * (R-P2P-47): an honest peer asks every node it meets. The one exception
 * is a StatusResponse, held for the replay (DEVIATION, bs_hold_status). */
static void bs_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    int rc;

    (void)ch_id;
    if (!p->lane_live) {
        bs_hold_status(p, src, msg, len);
        QGP_LOG_DEBUG(LOG_TAG, "blocksync message from %s before the reactor "
                      "runs — dropped, a StatusResponse held (R-P2P-47)",
                      cmt_p2p_peer_id(src));
        return;
    }
    if (p->bsync == NULL) {
        QGP_LOG_DEBUG(LOG_TAG, "blocksync message from %s with no block sync "
                      "reactor — dropped", cmt_p2p_peer_id(src));
        return;
    }
    rc = cmt_bsync_reactor_receive(p->bsync, cmt_p2p_peer_id(src), msg, len);
    if (rc == CMT_FAULT) {
        QGP_LOG_ERROR(LOG_TAG, "blocksync receive: CMT_FAULT (peer %s)",
                      cmt_p2p_peer_id(src));
        p->lane_fault = true;          /* sticky — lane_fault_note */
    }
    process_pending_stops(p);
}

/* 0x70 — the genesis bundle (the former verbs 24/25). */
static const cmt_p2p_ch_desc_t *gb_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->gb_desc;
}

static void noop_peer(void *ctx, cmt_p2p_peer_t *peer)
{
    (void)ctx;
    (void)peer;
}

static void noop_remove(void *ctx, cmt_p2p_peer_t *peer, int reason)
{
    (void)ctx;
    (void)peer;
    (void)reason;
}

static void gb_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_t3_msg_t m;

    (void)ch_id;
    if (nodus_t3_gbundle_decode(msg, len, &m) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x70 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->sw, src, NODUS_P2P_STOP_DECODE_0X70);
        return;
    }
    if (p->w == NULL) {
        return;
    }
    if (m.type == NODUS_T3_V2_GBUNDLE_REQ) {
        nodus_witness_v2_sync_handle_gbundle_q(p->w, cmt_p2p_peer_id(src),
                                               &m.w_v2_gbundle_q);
    } else {
        /* The sender travels with the response: the joiner takes a chunk
         * only from the peer it asked (red-team H2). */
        nodus_witness_v2_join_handle_gbundle_r(p->w, cmt_p2p_peer_id(src),
                                               &m.w_v2_gbundle_r);
    }
}

bool nodus_witness_p2p_gb_request(nodus_witness_p2p_t *p, const char *peer_id,
                                  uint64_t offset, const uint8_t *msg,
                                  size_t len)
{
    if (p == NULL || peer_id == NULL || strlen(peer_id) >= sizeof(p->gb_out_peer)) {
        return false;
    }
    /* A new request replaces the outstanding one: a late answer to the
     * old one is dropped by gb_take (the joiner asks again from its
     * accumulated offset anyway). */
    p->gb_out_valid = false;
    if (!nodus_witness_p2p_send(p, peer_id, NODUS_P2P_CH_GBUNDLE, msg, len)) {
        return false;
    }
    snprintf(p->gb_out_peer, sizeof(p->gb_out_peer), "%s", peer_id);
    p->gb_out_offset = offset;
    p->gb_out_valid = true;
    return true;
}

bool nodus_witness_p2p_gb_take(nodus_witness_p2p_t *p, const char *peer_id,
                               uint64_t offset)
{
    if (p == NULL || peer_id == NULL || !p->gb_out_valid ||
        strcmp(p->gb_out_peer, peer_id) != 0 || p->gb_out_offset != offset) {
        return false;
    }
    p->gb_out_valid = false;                 /* one answer per request */
    return true;
}

bool nodus_witness_p2p_gb_serve_allow(nodus_witness_p2p_t *p, const char *peer_id,
                                      uint64_t now_ms)
{
    int i, free_i = -1, stale_i = -1, target;

    if (p == NULL || peer_id == NULL || peer_id[0] == '\0' ||
        strlen(peer_id) >= sizeof(p->gb_serve[0].id)) {
        return false;
    }
    for (i = 0; i < NODUS_P2P_GB_SERVE_SLOTS; i++) {
        p2p_gb_serve_t *e = &p->gb_serve[i];
        /* A clock that went back reads as "just served" (the
         * rate-limit table's skew rule, nodus_cc_rate_limit_check). */
        uint64_t elapsed = now_ms >= e->last_ms ? now_ms - e->last_ms : 0;

        if (e->id[0] == '\0') {
            if (free_i < 0) {
                free_i = i;
            }
            continue;
        }
        if (strcmp(e->id, peer_id) == 0) {
            if (elapsed < NODUS_P2P_GB_SERVE_GAP_MS) {
                return false;
            }
            e->last_ms = now_ms;
            return true;
        }
        if (elapsed >= NODUS_P2P_GB_SERVE_GAP_MS && stale_i < 0) {
            stale_i = i;       /* past its gap: holds nobody back any more */
        }
    }
    target = free_i >= 0 ? free_i : stale_i;
    if (target < 0) {
        /* Every entry was served inside the gap: more requesters than
         * the host can index, all at once — refuse this one. */
        QGP_LOG_DEBUG(LOG_TAG, "0x70 request from %s not served: every "
                      "serve slot busy", peer_id);
        return false;
    }
    snprintf(p->gb_serve[target].id, sizeof(p->gb_serve[target].id), "%s", peer_id);
    p->gb_serve[target].last_ms = now_ms;
    return true;
}

/*
 * The serving side's bundle copy (RT2 B-F2): the bytes are read from the
 * chain database ONCE and served from memory after that — the former
 * SELECT + malloc + free per chunk request made every requester's 100 ms
 * gap a full bundle read. The bundle is immutable once the genesis
 * committed (nodus_witness_v2_bundle_persist refuses a row that differs,
 * nodus_witness_v2_bundle.h "WHY IT IS PERSISTED AT DERIVATION TIME"), so
 * the copy can never go stale for its chain; it is keyed by the chain id
 * anyway, so a host that finds itself on another chain reloads. No
 * reference counterpart (R-P2P-5).
 */
bool nodus_witness_p2p_gb_bundle(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                 const uint8_t **out, size_t *len)
{
    if (p == NULL || chain == NULL || out == NULL || len == NULL ||
        p->gb_bundle == NULL || memcmp(p->gb_bundle_chain, chain, 32) != 0) {
        return false;
    }
    *out = p->gb_bundle;
    *len = p->gb_bundle_len;
    return true;
}

bool nodus_witness_p2p_gb_bundle_keep(nodus_witness_p2p_t *p, const uint8_t chain[32],
                                      uint8_t *bytes, size_t len)
{
    if (p == NULL || chain == NULL || bytes == NULL || len == 0) {
        free(bytes);
        return false;
    }
    free(p->gb_bundle);
    p->gb_bundle = bytes;
    p->gb_bundle_len = len;
    memcpy(p->gb_bundle_chain, chain, 32);
    return true;
}

/* 0x71 — the governance approval (the former verbs 40/41). */
static const cmt_p2p_ch_desc_t *cc_channels(void *ctx, int *n)
{
    *n = 1;
    return ((nodus_witness_p2p_t *)ctx)->cc_desc;
}

static void cc_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_t3_msg_t m;
    uint8_t wid[32];

    (void)ch_id;
    if (nodus_t3_cc_appr_decode(msg, len, &m) != 0) {
        QGP_LOG_WARN(LOG_TAG, "undecodable 0x71 message from %s",
                     cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(&p->sw, src, NODUS_P2P_STOP_DECODE_0X71);
        return;
    }
    if (m.type != NODUS_T3_CC_APPR_REQ) {
        /* A response is taken only by this node's own pending approval
         * collection, only when it names that collection's request (its
         * `rq`, decision 2026-09-27-p2p-fix-2.md (2)) and only from a seat
         * it asked and has not heard from (decision
         * 2026-09-26-cc-approval-via-own-node.md (3)); every other
         * response is dropped, as verb 41 was at the tier-3 dispatcher's
         * `default:`. DEBUG, not WARN (RT2 B-F3 / Codex 11): a late honest
         * answer after the collection's deadline looks exactly like an
         * unsolicited one, and any connected peer could otherwise write
         * WARN lines at will. The sender is not stopped, for the same
         * reason. */
        if (p->w == NULL ||
            !nodus_witness_cc_collect_on_rsp(p->w, cmt_p2p_peer_id(src),
                                             &m.cc_appr_rsp)) {
            QGP_LOG_DEBUG(LOG_TAG, "unsolicited 0x71 response from %s dropped",
                          cmt_p2p_peer_id(src));
        }
        return;
    }
    if (p->w == NULL || !peer_wid(src, wid)) {
        return;
    }
    (void)nodus_witness_handle_cc_appr_req(p->w, cmt_p2p_peer_id(src), wid,
                                           &m.cc_appr_req);
}

/* ── the lane's host rows (cmt_conr_host_t, cmt_memr_host_t) ────────── */

/* peer.go:258-268 Send / TrySend (R-P2P-19: Send ≡ TrySend). */
static bool lane_send(void *ctx, int idx, uint8_t ch, const uint8_t *bytes,
                      size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return false;
    }
    return cmt_p2p_peer_send(p->slots[idx].peer, ch, bytes, len);
}

/* switch.go:335-358 StopPeerForError — DEFERRED until the reactor call
 * that raised it returns (file header). */
static void lane_conr_stop(void *ctx, int idx, int reason_code)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return;
    }
    p->slots[idx].pending_stop = NODUS_P2P_STOP_CONR_BASE + reason_code;
    p->any_pending_stop = true;
}

static void lane_memr_stop(void *ctx, int idx)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (idx < 0 || idx >= CMT_CONR_MAX_PEERS || p->slots[idx].peer == NULL) {
        return;
    }
    p->slots[idx].pending_stop = NODUS_P2P_STOP_MEMR;
    p->any_pending_stop = true;
}

static int lane_now(void *ctx, cmt_time_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_now == NULL || out == NULL) {
        return CMT_FAULT;
    }
    return p->lane_now(p->lane_now_ctx, out);
}

/* The reactors' `mono` row (ctx = this host): the lane's WAIT clock,
 * CLOCK_MONOTONIC (decision 2026-09-30-monotonic-waits.md). */
static int lane_mono(void *ctx, int64_t *out_ns)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->lane_mono == NULL || out_ns == NULL) {
        return CMT_FAULT;
    }
    return p->lane_mono(p->lane_mono_ctx, out_ns);
}

static int lane_bs_base(void *ctx, int64_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || p->store == NULL) return CMT_FAULT;
    *out = nodus_cmt_bs_base(p->store);
    return CMT_OK;
}

static int lane_bs_height(void *ctx, int64_t *out)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || p->store == NULL) return CMT_FAULT;
    *out = nodus_cmt_bs_height(p->store);
    return CMT_OK;
}

/* reactor.go:581-587 / :651-663 — the BlockID projection of LoadBlockMeta. */
static int lane_bs_meta_block_id(void *ctx, int64_t height, cmt_block_id_t *out,
                                 bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    nodus_cmt_block_meta_t *meta;
    int rc;

    if (out == NULL || out_found == NULL || p->store == NULL) return CMT_FAULT;
    meta = (nodus_cmt_block_meta_t *)malloc(sizeof(*meta));
    if (meta == NULL) return CMT_FAULT;
    rc = nodus_cmt_bs_load_block_meta(p->store, height, meta, out_found);
    if (rc == CMT_OK && *out_found) {
        *out = meta->block_id;
    }
    free(meta);
    return rc;
}

/* reactor.go:664 LoadBlockPart — `bytes` points into part_arena, valid
 * until the next call of this row (cmt_conr.h:462-469). */
static int lane_bs_part(void *ctx, int64_t height, int index, cmt_part_t *out,
                        bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (out == NULL || out_found == NULL || p->store == NULL) return CMT_FAULT;
    p->part_arena.used = 0;
    return nodus_cmt_bs_load_block_part(p->store, height, index, &p->part_arena,
                                        out, out_found);
}

/* reactor.go:756 LoadBlockCommit. */
static int lane_bs_commit(void *ctx, int64_t height, cmt_commit_t *out,
                          bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->store == NULL) return CMT_FAULT;
    return nodus_cmt_bs_load_block_commit(p->store, height, p->commit_sigs,
                                          (size_t)CMT_VALSET_MAX, out, out_found);
}

/* reactor.go:754 LoadBlockExtendedCommit. */
static int lane_bs_ext_commit(void *ctx, int64_t height, cmt_extended_commit_t *out,
                              bool *out_found)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->store == NULL) return CMT_FAULT;
    p->ext_load_arena.used = 0;
    return nodus_cmt_bs_load_block_extended_commit(p->store, height, p->ext_sigs,
                                                   (size_t)CMT_VALSET_MAX,
                                                   &p->ext_load_arena, out,
                                                   out_found);
}

/* ── the block sync reactor's p2p rows (cmt_bsync_host_t, `ctx`) ───── */

/* reactor.go:216, :242, :289, :358 — `Switch.Peers().Get(id)` then
 * `TrySend` on 0x40; a peer not connected is `false`. */
static bool bs_try_send(void *ctx, const char *peer_id, const uint8_t *msg,
                        size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw),
                                                peer_id);

    return peer != NULL &&
           cmt_p2p_peer_try_send(peer, CMT_BSYNC_CHANNEL, msg, len);
}

/* reactor.go:192-198 — `peer.Send` (≡ TrySend, R-P2P-19). */
static bool bs_send(void *ctx, const char *peer_id, const uint8_t *msg,
                    size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw),
                                                peer_id);

    return peer != NULL && cmt_p2p_peer_send(peer, CMT_BSYNC_CHANNEL, msg, len);
}

/* reactor.go:576-579 — `Switch.Broadcast` on 0x40. */
static void bs_broadcast(void *ctx, const uint8_t *msg, size_t len)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    (void)cmt_p2p_switch_broadcast(&p->sw, CMT_BSYNC_CHANNEL, msg, len);
}

/* switch.go:335-358 StopPeerForError, DEFERRED like the other lane rows:
 * the peer by ID (a peer no longer connected is skipped — reactor.go:
 * 366-367, :518-519, :525-526), then its index. A connected peer with no
 * index cannot be deferred — logged (header). */
static void bs_stop_peer(void *ctx, const char *peer_id, int reason)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;
    cmt_p2p_peer_t *peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw),
                                                peer_id);
    int i;

    if (peer == NULL) {
        return;
    }
    i = lane_find(p, peer);
    if (i < 0) {
        QGP_LOG_WARN(LOG_TAG, "blocksync asked to stop %s (reason %d) but the "
                     "peer holds no index — not stopped", peer_id, reason);
        return;
    }
    p->slots[i].pending_stop = NODUS_P2P_STOP_BSYNC_BASE + reason;
    p->any_pending_stop = true;
}

int nodus_witness_p2p_bsync_host_fill(nodus_witness_p2p_t *p,
                                      cmt_bsync_host_t *out)
{
    if (p == NULL || out == NULL || !p->lane_prepared) {
        return CMT_FAULT;
    }
    out->ctx                 = p;
    out->try_send            = bs_try_send;
    out->send                = bs_send;
    out->broadcast           = bs_broadcast;
    out->stop_peer_for_error = bs_stop_peer;
    out->now                 = p->lane_now;       /* wall: bans, rate    */
    out->now_ctx             = p->lane_now_ctx;
    out->mono                = p->lane_mono;      /* every wait          */
    out->mono_ctx            = p->lane_mono_ctx;
    return CMT_OK;
}

void nodus_witness_p2p_bsync_bind(nodus_witness_p2p_t *p,
                                  cmt_bsync_reactor_t *bsync)
{
    if (p != NULL) {
        p->bsync = bsync;
    }
}

cmt_bsync_reactor_t *nodus_witness_p2p_bsync(const nodus_witness_p2p_t *p)
{
    return p != NULL ? p->bsync : NULL;
}

/* mempool/reactor.go:180-182, :212-230 — the consensus reactor's
 * PeerState is the peer's one PeerStateKey value. */
static int64_t lane_peer_height(void *ctx, int idx, bool *out_known)
{
    nodus_witness_p2p_t *p = (nodus_witness_p2p_t *)ctx;

    if (p->conr == NULL || idx < 0 || idx >= CMT_CONR_MAX_PEERS ||
        !p->conr->peers[idx].in_set) {
        if (out_known != NULL) *out_known = false;
        return 0;
    }
    if (out_known != NULL) *out_known = true;
    return cmt_ps_get_height(&p->conr->peers[idx].ps);
}

int nodus_witness_p2p_lane_prepare(nodus_witness_p2p_t *p,
                                   nodus_cmt_store_t *store,
                                   cmt_now_fn now, void *now_ctx,
                                   cmt_mono_fn mono, void *mono_ctx)
{
    if (p == NULL || store == NULL || now == NULL || mono == NULL ||
        p->lane_prepared) {
        return CMT_FAULT;
    }
    p->store = store;
    p->lane_now = now;
    p->lane_now_ctx = now_ctx;
    p->lane_mono = mono;
    p->lane_mono_ctx = mono_ctx;

    memset(&p->conr_host, 0, sizeof(p->conr_host));
    p->conr_host.send = lane_send;
    p->conr_host.try_send = lane_send;                     /* R-P2P-19 */
    p->conr_host.stop_peer_for_error = lane_conr_stop;
    p->conr_host.bs_base = lane_bs_base;
    p->conr_host.bs_height = lane_bs_height;
    p->conr_host.bs_load_block_meta_block_id = lane_bs_meta_block_id;
    p->conr_host.bs_load_block_part = lane_bs_part;
    p->conr_host.bs_load_block_commit = lane_bs_commit;
    p->conr_host.bs_load_block_extended_commit = lane_bs_ext_commit;
    p->conr_host.now = lane_now;
    p->conr_host.mono = lane_mono;

    memset(&p->memr_host, 0, sizeof(p->memr_host));
    p->memr_host.ctx = p;
    p->memr_host.send = lane_send;
    p->memr_host.stop_peer_for_error = lane_memr_stop;
    p->memr_host.peer_height = lane_peer_height;
    p->memr_host.mono = lane_mono;

    /* cmt_conr.h "THE RECEIVE ARENA": exactly one message's bound,
     * reset by cmt_conr_receive at the top of every call. */
    p->recv_arena.cap = (size_t)CMT_CONR_MAX_MSG_SIZE;
    p->recv_arena.buf = (uint8_t *)malloc(p->recv_arena.cap);
    p->recv_arena.used = 0;
    p->commit_sigs = (cmt_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                sizeof(*p->commit_sigs));
    p->ext_sigs = (cmt_extended_commit_sig_t *)calloc((size_t)CMT_VALSET_MAX,
                                                      sizeof(*p->ext_sigs));
    p->ext_load_arena.cap = (size_t)CMT_VALSET_MAX * 4096u;
    p->ext_load_arena.buf = (uint8_t *)malloc(p->ext_load_arena.cap);
    p->ext_load_arena.used = 0;
    p->part_arena.cap = (size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u;
    p->part_arena.buf = (uint8_t *)malloc(p->part_arena.cap);
    p->part_arena.used = 0;
    if (p->recv_arena.buf == NULL || p->commit_sigs == NULL ||
        p->ext_sigs == NULL || p->ext_load_arena.buf == NULL ||
        p->part_arena.buf == NULL) {
        free(p->recv_arena.buf);
        free(p->commit_sigs);
        free(p->ext_sigs);
        free(p->ext_load_arena.buf);
        free(p->part_arena.buf);
        memset(&p->recv_arena, 0, sizeof(p->recv_arena));
        memset(&p->ext_load_arena, 0, sizeof(p->ext_load_arena));
        memset(&p->part_arena, 0, sizeof(p->part_arena));
        p->commit_sigs = NULL;
        p->ext_sigs = NULL;
        p->store = NULL;
        return CMT_FAULT;
    }
    p->lane_prepared = true;
    return CMT_OK;
}

const cmt_conr_host_t *nodus_witness_p2p_conr_host(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->conr_host : NULL;
}

const cmt_memr_host_t *nodus_witness_p2p_memr_host(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->memr_host : NULL;
}

cmt_pb_arena_t *nodus_witness_p2p_recv_arena(nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_prepared ? &p->recv_arena : NULL;
}

void nodus_witness_p2p_lane_bind(nodus_witness_p2p_t *p, cmt_conr_t *conr,
                                 cmt_memr_t *memr)
{
    if (p != NULL) {
        p->conr = conr;
        p->memr = memr;
    }
}

int nodus_witness_p2p_lane_live(nodus_witness_p2p_t *p)
{
    int i;

    if (p == NULL || p->conr == NULL || p->memr == NULL) {
        return CMT_FAULT;
    }
    p->lane_live = true;
    /* R-P2P-47: every connected peer, index order, the reference's
     * addPeer order (switch.go:829-831 then :858-860). The block sync
     * reactor has no InitPeer; its AddPeer (our StatusResponse,
     * reactor.go:190-203) comes after the other two's. */
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].peer == NULL) {
            continue;
        }
        lane_conr_init(p, i);
        lane_memr_init(p, i);
        lane_conr_add(p, i);
        lane_memr_add(p, i);
        if (p->bsync != NULL) {
            /* CMT_OK or CMT_FAULT only (cmt_bsync_reactor_add_peer). */
            lane_fault_note(p, cmt_bsync_reactor_add_peer(
                                   p->bsync, cmt_p2p_peer_id(p->slots[i].peer)),
                            "blocksync AddPeer",
                            cmt_p2p_peer_id(p->slots[i].peer), i);
        }
        /* The StatusResponse this peer sent before the lane was live
         * (DEVIATION, bs_hold_status) — after AddPeer, as the reference's
         * running reactor would have received it. The caller has STARTED
         * the block sync reactor before this call (nodus_witness.c). */
        bs_replay_status(p, i);
    }
    process_pending_stops(p);   /* a replayed status may be invalid (:253-257) */
    /* A reactor fault during the admission above (lane_fault_note). */
    return p->lane_fault ? CMT_FAULT : CMT_OK;
}

int nodus_witness_p2p_lane_tick(nodus_witness_p2p_t *p, int64_t *next_deadline_ns)
{
    int64_t d_conr = INT64_MAX, d_memr = INT64_MAX, d_bsync = INT64_MAX;
    bool memr_has = false;

    if (next_deadline_ns != NULL) {
        *next_deadline_ns = INT64_MAX;
    }
    if (p == NULL || p->conr == NULL || p->memr == NULL) {
        return CMT_FAULT;
    }
    /* A reactor call made from a p2p callback since the last tick (or
     * any earlier one) returned CMT_FAULT — sticky, lane_fault_note. */
    if (p->lane_fault) {
        return CMT_FAULT;
    }
    if (cmt_conr_tick(p->conr, &d_conr) == CMT_FAULT) {
        return CMT_FAULT;
    }
    if (cmt_memr_tick(p->memr, &d_memr, &memr_has) == CMT_FAULT) {
        return CMT_FAULT;
    }
    /* The block sync reactor's poolRoutine (cmt_bsync_reactor.h); after
     * the switch to consensus it returns at once with no deadline. */
    if (p->bsync != NULL &&
        cmt_bsync_reactor_tick(p->bsync, &d_bsync) == CMT_FAULT) {
        return CMT_FAULT;
    }
    process_pending_stops(p);
    if (next_deadline_ns != NULL) {
        int64_t d = (memr_has && d_memr < d_conr) ? d_memr : d_conr;

        *next_deadline_ns = d_bsync < d ? d_bsync : d;
    }
    return CMT_OK;
}

bool nodus_witness_p2p_lane_faulted(const nodus_witness_p2p_t *p)
{
    return p != NULL && p->lane_fault;
}

void nodus_witness_p2p_lane_unbind(nodus_witness_p2p_t *p)
{
    int i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < CMT_CONR_MAX_PEERS; i++) {
        if (p->slots[i].conr_init && p->conr != NULL) {
            (void)cmt_conr_remove_peer(p->conr, i);
        }
        if (p->slots[i].memr_init && p->memr != NULL) {
            (void)cmt_memr_remove_peer(p->memr, i);
        }
        p->slots[i].conr_init = p->slots[i].conr_added = false;
        p->slots[i].memr_init = p->slots[i].memr_added = false;
        p->slots[i].pending_stop = 0;
        p->slots[i].bs_status_held = false;      /* bs_hold_status */
    }
    p->any_pending_stop = false;
    p->lane_live = false;
    p->conr = NULL;
    p->memr = NULL;
    p->bsync = NULL;      /* its owner frees it (nodus_witness_close) */
}

/* ── construction (node.go:285-422 / setup.go:349-491, the p2p half) ── */

static void fill_descs(nodus_witness_p2p_t *p)
{
    size_t n = 0, i;
    const cmt_conr_channel_desc_t *cd = cmt_conr_get_channels(&n);
    cmt_mempool_config_t mc;
    cmt_memr_t *probe;
    cmt_memr_channel_descriptor_t md;

    for (i = 0; i < n && i < CMT_CONR_NUM_CHANNELS; i++) {
        p->cons_desc[i].id = cd[i].id;
        p->cons_desc[i].priority = cd[i].priority;
        p->cons_desc[i].send_queue_capacity = cd[i].send_queue_capacity;
        p->cons_desc[i].recv_buffer_capacity = cd[i].recv_buffer_capacity;
        p->cons_desc[i].recv_message_capacity = cd[i].recv_message_capacity;
    }
    /* mempool/reactor.go:71-89 GetChannels over the node's mempool config
     * — cometbft's defaults, the one nodus_cmt_node_init builds the
     * mempool with (nodus_witness_cmt_node.c, cmt_mempool_config_default).
     * Only `config` is read (cmt_memr.c GetChannels). */
    memset(&md, 0, sizeof(md));
    md.id = CMT_MEM_CHANNEL;
    md.priority = 5;
    md.recv_message_capacity = (size_t)CMT_CONR_MAX_MSG_SIZE;
    probe = (cmt_memr_t *)calloc(1, sizeof(*probe));
    if (probe != NULL && cmt_mempool_config_default(&mc) == CMT_OK) {
        probe->config = &mc;
        (void)cmt_memr_get_channels(probe, &md);
    }
    free(probe);
    p->mem_desc[0].id = md.id;
    p->mem_desc[0].priority = md.priority;
    p->mem_desc[0].send_queue_capacity = 0;       /* FillDefaults (:762-774) */
    p->mem_desc[0].recv_buffer_capacity = 0;
    p->mem_desc[0].recv_message_capacity = (int)md.recv_message_capacity;
    /* blocksync/reactor.go:177-188 GetChannels — 0x40, priority 5, send
     * queue 1000, receive buffer 50 × 4096, MaxMsgSize (msgs.go:16-18,
     * the operator's "follow the reference" answer). */
    {
        cmt_bsync_channel_desc_t bd;

        cmt_bsync_reactor_get_channels(&bd);
        p->bs_desc[0].id = bd.id;
        p->bs_desc[0].priority = bd.priority;
        p->bs_desc[0].send_queue_capacity = bd.send_queue_capacity;
        p->bs_desc[0].recv_buffer_capacity = bd.recv_buffer_capacity;
        p->bs_desc[0].recv_message_capacity = (int)bd.recv_message_capacity;
    }
    /* R-P2P-5: the two nodus channels (constants and their rationale:
     * nodus_witness_p2p.h). ⚠ NOT GROUNDED — no reference channel. */
    p->gb_desc[0].id = NODUS_P2P_CH_GBUNDLE;
    p->gb_desc[0].priority = NODUS_P2P_GBUNDLE_PRIORITY;
    p->gb_desc[0].send_queue_capacity = NODUS_P2P_GBUNDLE_SEND_QUEUE;
    p->gb_desc[0].recv_buffer_capacity = 0;
    p->gb_desc[0].recv_message_capacity = (int)NODUS_T3_GBUNDLE_MSG_MAX;
    p->cc_desc[0].id = NODUS_P2P_CH_CC_APPR;
    p->cc_desc[0].priority = NODUS_P2P_CCAPPR_PRIORITY;
    p->cc_desc[0].send_queue_capacity = NODUS_P2P_CCAPPR_SEND_QUEUE;
    p->cc_desc[0].recv_buffer_capacity = 0;
    p->cc_desc[0].recv_message_capacity = (int)NODUS_T3_CC_APPR_MSG_MAX;
}

static int add_reactor(nodus_witness_p2p_t *p, const char *name,
                       const cmt_p2p_ch_desc_t *(*chans)(void *, int *),
                       void (*init_peer)(void *, cmt_p2p_peer_t *),
                       void (*add_peer)(void *, cmt_p2p_peer_t *),
                       void (*remove_peer)(void *, cmt_p2p_peer_t *, int),
                       void (*receive)(void *, cmt_p2p_peer_t *, uint8_t,
                                       const uint8_t *, size_t))
{
    cmt_p2p_reactor_t r;

    memset(&r, 0, sizeof(r));
    r.name = name;
    r.ctx = p;
    r.get_channels = chans;
    r.init_peer = init_peer;
    r.add_peer = add_peer;
    r.remove_peer = remove_peer;
    r.receive = receive;
    return cmt_p2p_switch_add_reactor(&p->sw, &r);
}

static void no_peer_check(nodus_witness_p2p_t *p, bool at_start);   /* M4 */

nodus_witness_p2p_t *nodus_witness_p2p_new(struct nodus_witness *w,
                                           const nodus_witness_p2p_params_t *prm)
{
    nodus_witness_p2p_t *p;
    cmt_p2p_transport_host_t th;
    cmt_p2p_transport_config_t tc;
    cmt_p2p_switch_host_t sh;
    cmt_p2p_switch_config_t sc;
    cmt_p2p_node_info_params_t nip;
    cmt_p2p_netaddr_t laddr;
    cmt_p2p_ip_t lip;
    char listen_str[CMT_P2P_NETADDR_STR_MAX];
    char moniker[64];
    uint8_t chans[CMT_P2P_MAX_NUM_CHANNELS];
    size_t n_chans = 0;
    int i;

    if (prm == NULL || prm->identity == NULL || prm->chain_id == NULL ||
        prm->cfg == NULL || prm->listen_ip == NULL || prm->data_path == NULL ||
        prm->seq_dir == NULL) {
        return NULL;
    }
    if (!prm->identity->has_mlkem) {
        QGP_LOG_ERROR(LOG_TAG, "this node has no ML-KEM-1024 key "
                      "(nodus.mlkem_pk / nodus.mlkem_sk): port 4004 cannot run");
        return NULL;
    }
    if (!cmt_p2p_ip_parse(prm->listen_ip, strlen(prm->listen_ip), &lip)) {
        QGP_LOG_ERROR(LOG_TAG, "listen address %s is not an IP literal "
                      "(R-P2P-24)", prm->listen_ip);
        return NULL;
    }
    p = (nodus_witness_p2p_t *)calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->w = w;
    p->identity = prm->identity;
    p->cfg = *prm->cfg;
    memcpy(p->chain_id, prm->chain_id, 32);
    snprintf(p->data_path, sizeof(p->data_path), "%s", prm->data_path);
    snprintf(p->seq_dir, sizeof(p->seq_dir), "%s", prm->seq_dir);
    snprintf(p->listen_ip, sizeof(p->listen_ip), "%s", prm->listen_ip);
    snprintf(p->external_ip, sizeof(p->external_ip), "%s",
             prm->external_ip != NULL ? prm->external_ip : "");
    p->listen_port = prm->listen_port;
    if (cmt_p2p_pubkey_to_id(p->identity->pk.bytes, p->self_id) != CMT_OK ||
        nodus_p2p_io_init(&p->io, true) != 0) {
        free(p);
        return NULL;
    }
    if (pthread_mutex_init(&p->mu, NULL) != 0) {
        nodus_p2p_io_free(&p->io);
        free(p);
        return NULL;
    }
    if (pthread_cond_init(&p->cv, NULL) != 0) {
        pthread_mutex_destroy(&p->mu);
        nodus_p2p_io_free(&p->io);
        free(p);
        return NULL;
    }
    p->mu_init = true;

    /* The listener (transport.go:255-271 Listen: the host owns it). */
    if (prm->open_listener) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        cmt_p2p_ip_t bound;
        uint16_t bport = 0;

        if (nodus_p2p_io_listen(&p->io, p->listen_ip, p->listen_port) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "cannot listen on %s:%u: %s", p->listen_ip,
                          (unsigned)p->listen_port, strerror(errno));
            goto fail;
        }
        if (getsockname(p->io.listen_fd, (struct sockaddr *)&ss, &sl) == 0 &&
            sockaddr_to_ip(&ss, &bound, &bport) == 0) {
            p->listen_port = bport;
        }
    }

    /* Our address (setup.go:449-459): the external address when set,
     * otherwise the listen address. */
    {
        const char *adv = p->external_ip[0] ? p->external_ip : p->listen_ip;
        cmt_p2p_ip_t aip;

        if (!cmt_p2p_ip_parse(adv, strlen(adv), &aip)) {
            QGP_LOG_ERROR(LOG_TAG, "external address %s is not an IP literal "
                          "(R-P2P-24)", adv);
            goto fail;
        }
        laddr = cmt_p2p_netaddr_new_ip_port(&aip, p->listen_port);
        memcpy(laddr.id, p->self_id, sizeof(laddr.id));
        if (!cmt_p2p_ip_is_unspecified(&aip)) {
            p->have_own_addr = true;
            p->own_ip = aip;
            p->own_port = p->listen_port;
        }
        if (cmt_p2p_netaddr_dial_string(&laddr, listen_str, sizeof(listen_str)) == 0) {
            goto fail;
        }
    }

    /* node.go:928-975 makeNodeInfo. Channels in the reference's list order
     * (blocksync, consensus, mempool, :949-955; PEX last) with the two
     * nodus channels before PEX. */
    fill_descs(p);
    chans[n_chans++] = p->bs_desc[0].id;
    for (i = 0; i < CMT_CONR_NUM_CHANNELS; i++) {
        chans[n_chans++] = p->cons_desc[i].id;
    }
    chans[n_chans++] = p->mem_desc[0].id;
    chans[n_chans++] = NODUS_P2P_CH_GBUNDLE;
    chans[n_chans++] = NODUS_P2P_CH_CC_APPR;
    if (p->cfg.pex) {
        chans[n_chans++] = CMT_P2P_PEX_CHANNEL;
    }
    if (p->cfg.moniker[0] != '\0') {
        snprintf(moniker, sizeof(moniker), "%s", p->cfg.moniker);
    } else {
        snprintf(moniker, sizeof(moniker), "nodus-%.16s", p->self_id);
    }
    p->ni = (cmt_p2p_node_info_t *)calloc(1, sizeof(*p->ni));
    if (p->ni == NULL) {
        goto fail;
    }
    memset(&nip, 0, sizeof(nip));
    nip.block_version = CMT_BLOCK_PROTOCOL;
    nip.app_version = 0;
    nip.node_id = p->self_id;
    nip.chain_id = p->chain_id;
    nip.version = NODUS_VERSION_STRING;
    nip.channels = chans;
    nip.n_channels = n_chans;
    nip.moniker = moniker;
    nip.tx_index = "off";
    nip.rpc_address = "";
    nip.listen_addr = listen_str;
    if (cmt_p2p_node_info_make(p->ni, &nip) != CMT_P2P_ERR_NONE) {
        QGP_LOG_ERROR(LOG_TAG, "our NodeInfo does not validate");
        goto fail;
    }

    /* setup.go:352-409 createTransport */
    memset(&th, 0, sizeof(th));
    th.ctx = p;
    th.now_ns = nodus_p2p_mono_ns;
    th.dial = h_dial;
    th.close = h_close;
    th.submit_job = h_submit;
    th.bonded_count = h_bonded_count;
    th.may_receive = h_may_receive;
    th.recv_near_full = h_recv_near_full;
    th.queue_mark = h_queue_mark;
    memset(&tc, 0, sizeof(tc));
    tc.dsa_pk = p->identity->pk.bytes;
    tc.kem_pk = p->identity->mlkem_pk;
    tc.kem_sk = p->identity->mlkem_sk;
    tc.sc_host.ctx = (void *)p->identity;
    tc.sc_host.sign = nodus_p2p_sc_sign;
    tc.sc_host.verify = nodus_p2p_sc_verify;
    tc.chain_id = p->chain_id;
    tc.node_info = p->ni;
    cmt_p2p_mconn_p2p_default_config(&tc.mconn);           /* switch.go:36 */
    tc.mconn.flush_throttle_ns = p->cfg.flush_throttle_timeout_ms * CMT_P2P_MCONN_NS_PER_MS;
    tc.mconn.max_packet_msg_payload_size = p->cfg.max_packet_msg_payload_size;
    tc.mconn.send_rate = p->cfg.send_rate;
    tc.mconn.recv_rate = p->cfg.recv_rate;
    tc.max_num_inbound_peers = p->cfg.max_num_inbound_peers;
    tc.n_unconditional_ids = p->cfg.n_unconditional_peer_ids;
    tc.allow_duplicate_ip = p->cfg.allow_duplicate_ip;
    tc.handshake_timeout_ns = p->cfg.handshake_timeout_ms * CMT_P2P_MCONN_NS_PER_MS;
    tc.dial_timeout_ns = p->cfg.dial_timeout_ms * CMT_P2P_MCONN_NS_PER_MS;
    if (cmt_p2p_transport_init(&p->t, &th, &tc) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "transport init failed");
        goto fail;
    }
    p->t_init = true;
    p->io.t = &p->t;
    {
        cmt_p2p_netaddr_t la = cmt_p2p_netaddr_new_ip_port(&lip, p->listen_port);

        memcpy(la.id, p->self_id, sizeof(la.id));
        cmt_p2p_transport_listen(&p->t, &la);
    }

    /* setup.go:411-445 createSwitch */
    memset(&sh, 0, sizeof(sh));
    sh.ctx = p;
    sh.rand_int63n = nodus_p2p_rand_int63n;
    sh.is_bonded = h_is_bonded;
    cmt_p2p_switch_default_config(&sc);
    sc.max_num_inbound_peers = p->cfg.max_num_inbound_peers;
    sc.max_num_outbound_peers = p->cfg.max_num_outbound_peers;
    sc.allow_duplicate_ip = p->cfg.allow_duplicate_ip;
    if (cmt_p2p_switch_init(&p->sw, &sc, &p->t, &sh) != CMT_OK) {
        goto fail;
    }
    p->sw_init = true;
    if (add_reactor(p, "CONSENSUS", cons_channels, cons_init_peer, cons_add_peer,
                    cons_remove_peer, cons_receive) != CMT_OK ||
        add_reactor(p, "MEMPOOL", mem_channels, mem_init_peer, mem_add_peer,
                    mem_remove_peer, mem_receive) != CMT_OK ||
        add_reactor(p, "BLOCKSYNC", bs_channels, noop_peer, bs_add_peer,
                    bs_remove_peer, bs_receive) != CMT_OK ||
        add_reactor(p, "GBUNDLE", gb_channels, noop_peer, noop_peer, noop_remove,
                    gb_receive) != CMT_OK ||
        add_reactor(p, "CCAPPR", cc_channels, noop_peer, noop_peer, noop_remove,
                    cc_receive) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "reactor registration failed");
        goto fail;
    }

    /* setup.go:447-470 createAddrBookAndSetOnSwitch + :473-491
     * createPEXReactorAndAddToSwitch (only with `pex`). */
    if (p->cfg.pex) {
        cmt_p2p_ab_config_t bc;
        cmt_p2p_ab_host_t bh;
        cmt_p2p_pex_config_t pc;
        cmt_p2p_pex_host_t ph;
        cmt_p2p_reactor_t pr;

        memset(&bc, 0, sizeof(bc));
        bc.routability_strict = p->cfg.addr_book_strict;
        memcpy(bc.chain_id, p->chain_id, 32);
        memcpy(bc.self_id, p->self_id, sizeof(bc.self_id));
        memset(&bh, 0, sizeof(bh));
        bh.ctx = p;
        bh.now_ns = nodus_p2p_wall_ns;                     /* R-P2P-35 */
        bh.rand_bytes = h_rand_bytes;
        bh.rand_int63n = nodus_p2p_rand_int63n;
        bh.bonded_pubkey = h_bonded_pubkey;
        bh.verify_addr = h_verify_addr;
        bh.verify_addr_submit = h_verify_submit;           /* R-P2P-43 */
        bh.save = h_book_save;
        bh.load = h_book_load;
        p->book = cmt_p2p_addrbook_new(&bc, &bh);
        if (p->book == NULL) {
            goto fail;
        }
        if (p->have_own_addr) {
            cmt_p2p_addrbook_add_our_address(p->book, &laddr);   /* :452-459 */
        }
        cmt_p2p_addrbook_switch_seam(p->book, &p->seam);
        cmt_p2p_switch_set_addr_book(&p->sw, &p->seam);
        memset(&pc, 0, sizeof(pc));
        memset(&ph, 0, sizeof(ph));
        ph.ctx = p;
        ph.now_ns = nodus_p2p_mono_ns;
        ph.rand_int63n = nodus_p2p_rand_int63n;
        ph.own_record = h_own_record;
        p->pex = cmt_p2p_pex_new(&pc, &ph, p->book, &p->sw);
        if (p->pex == NULL) {
            goto fail;
        }
        cmt_p2p_pex_reactor(p->pex, &pr);
        if (cmt_p2p_switch_add_reactor(&p->sw, &pr) != CMT_OK) {
            goto fail;
        }
    }

    /* setup.go:432-440 — the configured peer lists. */
    {
        const char *list[NODUS_P2P_MAX_PEER_LIST];
        int rc;

        for (i = 0; i < p->cfg.n_unconditional_peer_ids; i++) {
            list[i] = p->cfg.unconditional_peer_ids[i];
        }
        rc = cmt_p2p_switch_add_unconditional_peer_ids(&p->sw, list,
                                                       p->cfg.n_unconditional_peer_ids);
        if (rc != CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "unconditional_peer_ids: %s", cmt_p2p_err_str(rc));
            goto fail;
        }
        for (i = 0; i < p->cfg.n_private_peer_ids; i++) {
            list[i] = p->cfg.private_peer_ids[i];
        }
        rc = cmt_p2p_switch_add_private_peer_ids(&p->sw, list,
                                                 p->cfg.n_private_peer_ids);
        if (rc != CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "private_peer_ids: %s", cmt_p2p_err_str(rc));
            goto fail;
        }
        for (i = 0; i < p->cfg.n_persistent_peers; i++) {
            list[i] = p->cfg.persistent_peers[i];
        }
        rc = cmt_p2p_switch_add_persistent_peers(&p->sw, list,
                                                 p->cfg.n_persistent_peers);
        if (rc != CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "persistent_peers: %s", cmt_p2p_err_str(rc));
            goto fail;
        }
    }

    /* The bonded set before the first connection is admitted. */
    nodus_witness_p2p_refresh_bonded(p);

    /* The worker (R-P2P-8). */
    {
        int n = prm->n_workers > 0 ? prm->n_workers : NODUS_P2P_WORKERS_DEFAULT;

        if (n > NODUS_P2P_WORKERS_MAX) {
            n = NODUS_P2P_WORKERS_MAX;
        }
        for (i = 0; i < n; i++) {
            if (pthread_create(&p->th[i], NULL, worker_main, p) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "worker thread %d not started", i);
                goto fail;
            }
            p->n_th++;
        }
    }

    /* node.go:548-580 OnStart: the switch (and with it PEX, which starts
     * the book — loadFromFile, R-P2P-38), then our record (the book's
     * own-seq is known now), then the persistent peers (:563-564). */
    if (cmt_p2p_switch_start(&p->sw) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "switch start failed (address book file "
                      "unreadable?)");
        goto fail;
    }
    own_record_start(p);
    if (p->cfg.n_persistent_peers > 0) {
        const char *list[NODUS_P2P_MAX_PEER_LIST];
        int rc;

        for (i = 0; i < p->cfg.n_persistent_peers; i++) {
            list[i] = p->cfg.persistent_peers[i];
        }
        rc = cmt_p2p_switch_dial_peers_async(&p->sw, list, p->cfg.n_persistent_peers);
        if (rc != CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "could not dial persistent peers: %s",
                          cmt_p2p_err_str(rc));
        }
    }
    QGP_LOG_INFO(LOG_TAG, "p2p on %s:%u — id %s, %d persistent peer(s), pex %s",
                 p->listen_ip, (unsigned)p->listen_port, p->self_id,
                 p->cfg.n_persistent_peers, p->cfg.pex ? "on" : "off");
    no_peer_check(p, true);
    return p;

fail:
    nodus_witness_p2p_free(p);
    return NULL;
}

void nodus_witness_p2p_free(nodus_witness_p2p_t *p)
{
    if (p == NULL) {
        return;
    }
    nodus_witness_p2p_lane_unbind(p);
    /* A pending approval collection waits on THIS host's peers: it ends
     * here, with no reply (the CLI's own request times out). */
    if (p->w != NULL && p->w->p2p == p) {
        nodus_witness_cc_collect_abort(p->w);
    }
    if (p->sw_init) {
        cmt_p2p_switch_stop(&p->sw);          /* peers, reactors (book saved) */
    }
    worker_stop(p);                            /* every job back to the transport */
    if (p->pex != NULL) {
        cmt_p2p_pex_free(p->pex);
        p->pex = NULL;
    }
    if (p->sw_init) {
        cmt_p2p_switch_free(&p->sw);
        p->sw_init = false;
    }
    if (p->t_init) {
        cmt_p2p_transport_close(&p->t);
        cmt_p2p_transport_free(&p->t);
        p->t_init = false;
    }
    if (p->book != NULL) {
        cmt_p2p_addrbook_free(p->book);
        p->book = NULL;
    }
    nodus_p2p_io_free(&p->io);
    if (p->mu_init) {
        pthread_cond_destroy(&p->cv);
        pthread_mutex_destroy(&p->mu);
    }
    free(p->ni);
    free(p->bonded);
    free(p->gb_bundle);
    free(p->recv_arena.buf);
    free(p->commit_sigs);
    free(p->ext_sigs);
    free(p->ext_load_arena.buf);
    free(p->part_arena.buf);
    memset(p->own_rec, 0, sizeof(p->own_rec));
    free(p);
}

/* How often the M4 ERROR repeats while it holds. Operator choice
 * (fix proposals 2026-09-27 "REVISED" M4: "every 60 s"). */
#define NODUS_P2P_NO_PEER_LOG_MS 60000

/*
 * M4 — a node that HOLDS A CHAIN but was given no persistent peers (no
 * network file, or one without peers) has nobody to dial: it learns
 * peers only if one dials in, and a validator cut off like that stalls
 * silently. ERROR at start when none is configured, and every
 * NODUS_P2P_NO_PEER_LOG_MS while NO peer is connected — configured or not
 * (a listed but unreachable set is the same stall); the node is never
 * refused (operator: log,
 * do not refuse). A joiner (no chain yet) has its own diagnosis
 * (nodus_witness_v2_join.c join_diag). The reference dials whatever
 * persistent_peers holds (node.go:563-567) and says nothing when it is
 * empty; no counterpart for this warning — an operator aid, not
 * consensus (monotonic clock, D3).
 */
static void no_peer_check(nodus_witness_p2p_t *p, bool at_start)
{
    int64_t now_ms;

    if (p->w == NULL || p->w->db == NULL) {
        return;
    }
    now_ms = nodus_p2p_mono_ns(NULL) / 1000000;
    if (at_start && p->cfg.n_persistent_peers > 0) {
        /* peers are configured: nothing to say yet, but arm the 60 s
         * clock so an unreachable set is reported one period in
         * (ORCHESTRATOR repair — verifier: the periodic ERROR must cover
         * "0 CONNECTED", not only "0 configured") */
        p->no_peer_logged_ms = now_ms != 0 ? now_ms : 1;
        return;
    }
    if (!at_start && nodus_witness_p2p_peer_count(p) > 0) {
        return;
    }
    if (!at_start && p->no_peer_logged_ms != 0 &&
        now_ms - p->no_peer_logged_ms < NODUS_P2P_NO_PEER_LOG_MS) {
        return;
    }
    p->no_peer_logged_ms = now_ms != 0 ? now_ms : 1;
    QGP_LOG_ERROR(LOG_TAG, "this node holds a chain but has %d persistent "
                  "peer(s) configured and %d connected — it cannot reach "
                  "the validators; check the network file and the peers' "
                  "reachability", p->cfg.n_persistent_peers,
                  nodus_witness_p2p_peer_count(p));
}

void nodus_witness_p2p_poll(nodus_witness_p2p_t *p, int timeout_ms)
{
    if (p == NULL) {
        return;
    }
    worker_drain(p);
    nodus_p2p_io_wait(&p->io, timeout_ms);
    worker_drain(p);
    nodus_p2p_io_pump(&p->io);
    cmt_p2p_switch_tick(&p->sw);
    lane_gc(p);
    if (p->pex != NULL) {
        cmt_p2p_pex_tick(p->pex);
    }
    process_pending_stops(p);
    bonded_maybe_refresh(p);
    own_record_check(p);
    no_peer_check(p, false);
    /* The node-side approval collection's deadline (tooling, not
     * consensus — the monotonic clock, nodus_witness.h
     * NODUS_CC_COLLECT_DEADLINE_MS). */
    if (p->w != NULL && p->w->p2p == p) {
        nodus_witness_cc_collect_tick(p->w, nodus_p2p_mono_ns(NULL) / 1000000);
    }
    nodus_p2p_io_flush(&p->io);
}

uint16_t nodus_witness_p2p_listen_port(const nodus_witness_p2p_t *p)
{
    return p != NULL && p->io.listen_fd >= 0 ? p->listen_port : 0;
}

const char *nodus_witness_p2p_id(const nodus_witness_p2p_t *p)
{
    return p != NULL ? p->self_id : "";
}

cmt_p2p_switch_t *nodus_witness_p2p_switch(nodus_witness_p2p_t *p)
{
    return p != NULL ? &p->sw : NULL;
}

int nodus_witness_p2p_peer_count(const nodus_witness_p2p_t *p)
{
    return p != NULL ? cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&p->sw)) : 0;
}

bool nodus_witness_p2p_peer_id_at(const nodus_witness_p2p_t *p, int i,
                                  char out[CMT_P2P_ID_CAP])
{
    const cmt_p2p_peer_set_t *ps;

    if (p == NULL || out == NULL) {
        return false;
    }
    ps = cmt_p2p_switch_peers(&p->sw);
    if (i < 0 || i >= ps->n) {
        return false;
    }
    snprintf(out, CMT_P2P_ID_CAP, "%s", cmt_p2p_peer_id(ps->list[i]));
    return true;
}

bool nodus_witness_p2p_has_peer(const nodus_witness_p2p_t *p, const char *peer_id)
{
    return p != NULL && peer_id != NULL &&
           cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw), peer_id) != NULL;
}

bool nodus_witness_p2p_send(nodus_witness_p2p_t *p, const char *peer_id,
                            uint8_t ch, const uint8_t *msg, size_t len)
{
    cmt_p2p_peer_t *peer;

    if (p == NULL || peer_id == NULL) {
        return false;
    }
    peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw), peer_id);
    return peer != NULL && cmt_p2p_peer_send(peer, ch, msg, len);
}
