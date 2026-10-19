/**
 * @file nodus/src/net/nodus_p2p_host.c
 * @brief The witness-free host of the ported cometbft @v0.38.26 p2p layer
 *        on port 4004. Contract, governing records and the lifecycle:
 *        nodus_p2p_host.h.
 *
 * Moved from nodus/src/witness/nodus_witness_p2p.c (net-layer design
 * 2026-10-19 §11, package N3) with the logic unchanged: every moved body
 * keeps its statements; what changed is the struct it reads (the host,
 * not the witness), the embedder's rows behind the policy trampolines
 * (pol_*), and — Windows only — the socket / file headers and the atomic
 * file replace's Windows arm. LOG_TAG stays "W_P2P": the moved log lines
 * are byte-identical to the ones the witness host printed.
 *
 * Reference call sites each block mirrors are named per block
 * (node/node.go and node/setup.go: how a node builds and starts its p2p
 * half; p2p/transport.go / switch.go: what a host must do for them).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#if defined(_WIN32) && !defined(_WIN32_WINNT)
  #define _WIN32_WINNT 0x0600
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <io.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include "net/nodus_p2p_host.h"

#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_block.h"         /* CMT_BLOCK_PROTOCOL            */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* The witness host's tag: the moved log lines stay byte-identical. */
#define LOG_TAG "W_P2P"

/* ══ config ═══════════════════════════════════════════════════════════ */

void nodus_p2p_config_default(nodus_p2p_config_t *c)
{
    if (c == NULL) {
        return;
    }
    memset(c, 0, sizeof(*c));
    c->pex = true;                                          /* config.go:633 */
    c->addr_book_strict = true;                             /* config.go:629 */
    c->allow_duplicate_ip = false;                          /* config.go:638 */
    c->max_num_inbound_peers = CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS;   /* :630 */
    c->max_num_outbound_peers = CMT_P2P_DEFAULT_MAX_NUM_OUTBOUND_PEERS; /* :631 */
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

/* The listener's tag in the readiness set. The wake's is the backend's
 * own (NODUS_NET_TAG_WAKE, UINT64_MAX - 2); slots are 0..n_socks-1. */
#define IO_TAG_LISTEN ((uint64_t)UINT64_MAX - 1)

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
            ns[i].fd = NODUS_SOCK_INVALID;
        }
        io->socks = ns;
        io->n_socks = n;
    }
    return &io->socks[slot];
}

static void io_set_events(nodus_p2p_io_t *io, int slot, uint32_t events)
{
    nodus_p2p_sock_t *s = &io->socks[slot];

    if (s->fd == NODUS_SOCK_INVALID || s->events == events) {
        return;
    }
    if (nodus_net_poll_mod(&io->poll, s->fd, (uint64_t)slot, events) == 0) {
        s->events = events;
    }
}

static int io_register(nodus_p2p_io_t *io, int slot, nodus_sock_t fd,
                       uint64_t gen, bool connecting)
{
    nodus_p2p_sock_t *s = io_slot(io, slot, true);
    /* A connecting socket also carries NODUS_NET_CONNECT (Windows: watch
     * the except set for a refused connect); the Linux backend removes it,
     * so epoll_ctl sees EPOLLOUT|EPOLLIN as before. */
    uint32_t events = connecting ? (NODUS_NET_OUT | NODUS_NET_IN |
                                    NODUS_NET_CONNECT)
                                 : NODUS_NET_IN;

    if (s == NULL) {
        return -1;
    }
    if (nodus_net_poll_add(&io->poll, fd, (uint64_t)slot, events) != 0) {
        return -1;
    }
    s->fd = fd;
    s->gen = gen;
    s->connecting = connecting;
    s->failed = false;
    s->events = events;
    s->ready = 0;
    return 0;
}

int nodus_p2p_io_init(nodus_p2p_io_t *io, bool with_wake)
{
    if (io == NULL) {
        return -1;
    }
    memset(io, 0, sizeof(*io));
    io->listen_fd = NODUS_SOCK_INVALID;
    io->last_served = -1;
    return nodus_net_poll_init(&io->poll, with_wake);
}

void nodus_p2p_io_free(nodus_p2p_io_t *io)
{
    int i;

    if (io == NULL) {
        return;
    }
    for (i = 0; i < io->n_socks; i++) {
        if (io->socks[i].fd != NODUS_SOCK_INVALID) {
            (void)nodus_net_close(io->socks[i].fd);
        }
    }
    free(io->socks);
    if (io->listen_fd != NODUS_SOCK_INVALID) {
        (void)nodus_net_close(io->listen_fd);
    }
    nodus_net_poll_free(&io->poll);         /* the wake, then the set */
    {
        nodus_net_poll_t closed = io->poll; /* _free left it "not open" */

        memset(io, 0, sizeof(*io));
        io->poll = closed;
    }
    io->listen_fd = NODUS_SOCK_INVALID;
}

int nodus_p2p_io_listen(nodus_p2p_io_t *io, const char *ip, uint16_t port)
{
    cmt_p2p_ip_t a;
    struct sockaddr_storage ss;
    socklen_t sl = 0;
    nodus_sock_t fd;
    int one = 1;

    if (io == NULL || ip == NULL || !cmt_p2p_ip_parse(ip, strlen(ip), &a) ||
        ip_to_sockaddr(&a, port, &ss, &sl) != 0) {
        errno = EINVAL;
        return -1;
    }
    fd = nodus_net_socket(ss.ss_family, SOCK_STREAM);
    if (fd == NODUS_SOCK_INVALID) {
        return -1;
    }
    /* (const void *): Winsock's optval is const char *; POSIX's const
     * void * — the same pointer either way. */
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&one, sizeof(one));
    /* nodus_net_close keeps errno: the caller reports the failure hit. */
    if (bind(fd, (struct sockaddr *)&ss, sl) != 0 || listen(fd, 128) != 0) {
        (void)nodus_net_close(fd);
        return -1;
    }
    if (nodus_net_poll_add(&io->poll, fd, IO_TAG_LISTEN, NODUS_NET_IN) != 0) {
        (void)nodus_net_close(fd);
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
    nodus_sock_t fd;
    int one = 1;

    if (io == NULL || addr == NULL ||
        ip_to_sockaddr(&addr->ip, addr->port, &ss, &sl) != 0) {
        return -1;
    }
    fd = nodus_net_socket(ss.ss_family, SOCK_STREAM);
    if (fd == NODUS_SOCK_INVALID) {
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0 &&
        !NODUS_NET_IS_EINPROGRESS(nodus_net_errno())) {
        (void)nodus_net_close(fd);
        return -1;
    }
    if (io_register(io, slot, fd, gen, true) != 0) {
        (void)nodus_net_close(fd);
        return -1;
    }
    return 0;
}

void nodus_p2p_io_close(nodus_p2p_io_t *io, int slot, uint64_t gen)
{
    nodus_p2p_sock_t *s;

    if (io == NULL || (s = io_slot(io, slot, false)) == NULL ||
        s->fd == NODUS_SOCK_INVALID || s->gen != gen) {
        return;
    }
    (void)nodus_net_poll_del(&io->poll, s->fd);
    (void)nodus_net_close(s->fd);
    s->fd = NODUS_SOCK_INVALID;
    s->connecting = false;
    s->failed = false;
    s->events = 0;
    s->ready = 0;
}

void nodus_p2p_io_wait(nodus_p2p_io_t *io, int timeout_ms)
{
    nodus_net_event_t evs[64];
    int n, i;

    if (io == NULL || !nodus_net_poll_is_open(&io->poll)) {
        return;
    }
    /* Re-arm IN on every socket whose read_buf has room again: io_read
     * cleared it at true backpressure, and the transport may have consumed
     * since (the switch's tick, a returned handshake job). Without this a
     * socket holding unread bytes would sleep through the whole wait. */
    if (io->t != NULL) {
        for (i = 0; i < io->n_socks; i++) {
            nodus_p2p_sock_t *s = &io->socks[i];
            size_t room = 0;

            if (s->fd == NODUS_SOCK_INVALID || s->failed || s->connecting ||
                (s->events & NODUS_NET_IN) != 0) {
                continue;
            }
            if (cmt_p2p_transport_read_buf(io->t, i, s->gen, &room) != NULL &&
                room > 0) {
                io_set_events(io, i, s->events | NODUS_NET_IN);
            }
        }
    }
    /* The wake, when it fired, is drained inside the wait (the backend's
     * read-until-it-stops loop) and not returned. */
    n = nodus_net_poll_wait(&io->poll, timeout_ms < 0 ? 0 : timeout_ms, evs, 64);
    for (i = 0; i < n; i++) {
        if (evs[i].tag != IO_TAG_LISTEN && evs[i].tag < (uint64_t)io->n_socks) {
            io->socks[evs[i].tag].ready |= evs[i].ready;
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

    return s->fd != NODUS_SOCK_INVALID && s->gen == gen && !s->failed &&
           !s->connecting;
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
        long n;
        int e;

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
            io_set_events(io, slot, s->events & ~NODUS_NET_OUT);
            return;
        }
        n = nodus_net_send(s->fd, b, len);     /* Linux: MSG_NOSIGNAL */
        if (n > 0) {
            cmt_p2p_transport_write_done(io->t, slot, gen, (size_t)n);
            stepped = false;
            continue;
        }
        e = n < 0 ? nodus_net_errno() : 0;
        if (n < 0 && NODUS_NET_IS_EINTR_IO(e)) {
            continue;
        }
        if (n < 0 && NODUS_NET_IS_EAGAIN(e)) {
            io_set_events(io, slot, s->events | NODUS_NET_OUT);
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
 * config.go:592), never less than one rbuf. "About": this counts sealed
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
 *     (the witness's h_may_receive, behind the policy row): nothing read,
 *     EPOLLIN left as it is. The step
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
        long n;
        int e;

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
            io_set_events(io, slot, s->events & ~NODUS_NET_IN);
            return taken > 0;
        }
        io_set_events(io, slot, s->events | NODUS_NET_IN);
        if (taken >= budget) {
            return true;
        }
        if (room > budget - taken) {
            room = budget - taken;
        }
        n = nodus_net_recv(s->fd, b, room);
        if (n > 0) {
            cmt_p2p_transport_read_done(io->t, slot, gen, (size_t)n);
            taken += (size_t)n;
            stepped = false;
            continue;
        }
        e = n < 0 ? nodus_net_errno() : 0;
        if (n < 0 && NODUS_NET_IS_EINTR_IO(e)) {
            continue;
        }
        if (n < 0 && NODUS_NET_IS_EAGAIN(e)) {
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
    int err = 0;
    socklen_t el = (socklen_t)sizeof(err);
    struct sockaddr_storage ss;
    socklen_t sl = (socklen_t)sizeof(ss);
    cmt_p2p_ip_t ip;
    uint16_t port = 0;
    uint64_t gen = s->gen;

    /* R4: Linux = poll({fd, POLLOUT}, 1, 0); the outcome is read below. */
    if (nodus_net_probe_connect(s->fd) <= 0) {
        return;                                            /* still connecting */
    }
    /* (void *): Winsock's optval is char *; POSIX's void *. */
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &el) != 0 || err != 0 ||
        getpeername(s->fd, (struct sockaddr *)&ss, &sl) != 0 ||
        sockaddr_to_ip(&ss, &ip, &port) != 0) {
        s->connecting = false;
        s->failed = true;
        cmt_p2p_transport_conn_failed(io->t, slot, gen);
        return;
    }
    s->connecting = false;
    io_set_events(io, slot, NODUS_NET_IN);
    cmt_p2p_transport_dial_connected(io->t, slot, gen, &ip, port);
}

/* transport.go:286-353 acceptPeers — the host half (LimitListener
 * :261-263: never accept(2) while the limit is reached), at most
 * NODUS_P2P_ACCEPT_BUDGET accept(2) calls per pass (header). */
static void io_accept(nodus_p2p_io_t *io)
{
    int calls = 0;

    if (io->listen_fd == NODUS_SOCK_INVALID) {
        return;
    }
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        cmt_p2p_ip_t ip;
        uint16_t port = 0;
        nodus_sock_t fd;
        int slot = -1, rc;
        uint64_t gen = 0;

        if (!cmt_p2p_transport_can_accept(io->t) ||
            calls >= NODUS_P2P_ACCEPT_BUDGET) {
            break;
        }
        calls++;
        fd = nodus_net_accept(io->listen_fd, (struct sockaddr *)&ss, &sl);
        if (fd == NODUS_SOCK_INVALID) {
            int e = nodus_net_errno();

            if (NODUS_NET_IS_EINTR_IO(e) || NODUS_NET_IS_CONNABORTED(e)) {
                continue;
            }
            break;                                         /* EAGAIN / error */
        }
        if (nodus_net_set_nonblocking(fd) != 0 ||
            nodus_net_set_cloexec(fd) != 0) {
            (void)nodus_net_close(fd);
            continue;
        }
        if (sockaddr_to_ip(&ss, &ip, &port) != 0) {
            (void)nodus_net_close(fd);
            continue;
        }
        rc = cmt_p2p_transport_accept(io->t, &ip, port, 0, &slot, &gen);
        if (rc != CMT_P2P_ERR_NONE) {
            char ipb[CMT_P2P_IP_STR_MAX];

            (void)cmt_p2p_ip_string(&ip, ipb, sizeof(ipb));
            QGP_LOG_DEBUG(LOG_TAG, "inbound %s:%u refused: %s", ipb,
                          (unsigned)port, cmt_p2p_err_str(rc));
            (void)nodus_net_close(fd);
            continue;
        }
        if (io_register(io, slot, fd, gen, false) != 0) {
            (void)nodus_net_close(fd);
            cmt_p2p_transport_conn_failed(io->t, slot, gen);
        }
    }
    /* Watch the listener only while the limit has room (a full limit
     * leaves connections in the kernel's backlog, as LimitListener's
     * blocked Accept does). */
    {
        bool want = cmt_p2p_transport_can_accept(io->t);

        if (want != io->listen_armed &&
            nodus_net_poll_mod(&io->poll, io->listen_fd, IO_TAG_LISTEN,
                               want ? NODUS_NET_IN : 0) == 0) {
            io->listen_armed = want;
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

        if (s->fd == NODUS_SOCK_INVALID) {
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
        if (io->socks[slot].fd != NODUS_SOCK_INVALID) {
            io_write(io, slot);
        }
    }
}

/* ══ the host ═════════════════════════════════════════════════════════ */

/* The worker's three bounded queues (file header; §2R4 P3). */
enum { WQ_OUTBOUND = 0, WQ_INBOUND = 1, WQ_ADDR = 2, WQ_N = 3 };
_Static_assert(WQ_N == NODUS_P2P_WQ_N, "the host header sizes the queues");
/** Depth of each queue. ⚠ NOT GROUNDED — a size (the reference runs one
 *  goroutine per connection, transport.go:304-309, with no queue).
 *  Rationale: a full reconnect of the default inbound limit (40, config.go
 *  :630) queues at once; past the depth a handshake is closed (§2R4 P3),
 *  never blocked. The INBOUND queue is never shallower than the live
 *  listener limit (inbound_depth — bonded peers raise the limit at run
 *  time, red-team R6 F4). */
#define NODUS_P2P_JOBQ_DEPTH   64
/* The static half of the inbound queue's bound (inbound_depth): the
 * default inbound limit alone must fit. */
_Static_assert(NODUS_P2P_JOBQ_DEPTH >= CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS,
               "the job queue must hold one handshake job per default "
               "inbound connection");

typedef struct nodus_p2p_wjob {
    struct nodus_p2p_wjob *next;
    int                q;
    cmt_p2p_hs_job_t  *hs;                        /* WQ_OUTBOUND / INBOUND */
    uint64_t           ticket;                    /* WQ_ADDR               */
    uint8_t            payload[CMT_P2P_ADDR_REC_PAYLOAD_SIZE];
    uint8_t            sig[CMT_P2P_ADDR_REC_SIG_SIZE];
    uint8_t            pk[QGP_DSA87_PUBLICKEYBYTES];
    int                rc;
} wjob_t;

/* ── the worker (R-P2P-8, R-P2P-43) ─────────────────────────────────── */

static void wake(nodus_p2p_host_t *p)
{
    /* Linux: write(eventfd, 1, 8); a no-op without the wake. */
    nodus_net_poll_wake(&p->io.poll);
}

static void *worker_main(void *arg)
{
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)arg;

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

static int worker_push(nodus_p2p_host_t *p, wjob_t *j, int depth)
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
static void worker_drain(nodus_p2p_host_t *p)
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
static void worker_stop(nodus_p2p_host_t *p)
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
static int inbound_depth(const nodus_p2p_host_t *p)
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
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;
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
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;
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
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;

    *host_handle = (uint64_t)slot;
    return nodus_p2p_io_dial(&p->io, slot, gen, addr);
}

static void h_close(void *ctx, int slot, uint64_t gen, uint64_t host_handle)
{
    (void)host_handle;
    nodus_p2p_io_close(&((nodus_p2p_host_t *)ctx)->io, slot, gen);
}

/* ── the embedder's policy rows (header; NULL = the neutral answer) ─── */

static bool pol_is_bonded(void *ctx, const char *id)
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.is_bonded != NULL && p->policy.is_bonded(p->policy.ctx, id);
}

static int pol_bonded_count(void *ctx)
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.bonded_count != NULL ? p->policy.bonded_count(p->policy.ctx) : 0;
}

static bool pol_bonded_pubkey(void *ctx, const char *id,
                              uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.bonded_pubkey != NULL &&
           p->policy.bonded_pubkey(p->policy.ctx, id, pk);
}

static bool pol_may_receive(void *ctx)
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.may_receive == NULL || p->policy.may_receive(p->policy.ctx);
}

static bool pol_recv_near_full(void *ctx)
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.recv_near_full != NULL &&
           p->policy.recv_near_full(p->policy.ctx);
}

static uint64_t pol_queue_mark(void *ctx)
{
    const nodus_p2p_host_t *p = (const nodus_p2p_host_t *)ctx;

    return p->policy.queue_mark != NULL ? p->policy.queue_mark(p->policy.ctx) : 0;
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

#ifndef _WIN32
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
#else
/* The Windows arm (net-layer design §11 "portable"): the same steps with
 * the Windows calls — a temporary file written in full, _commit (the
 * fsync of the CRT: FlushFileBuffers), closed, then MoveFileExW with
 * MOVEFILE_REPLACE_EXISTING (replace the old file in one step) and
 * MOVEFILE_WRITE_THROUGH (return only once the move is on disk — the
 * directory fsync's job on POSIX). Paths are UTF-8, converted to UTF-16
 * for the wide calls. On a failure the temporary file is removed and -1
 * returned with errno set (EIO for a Win32 step), as the POSIX arm does. */
static int win_widen(const char *s, wchar_t *out, int cap)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, cap);

    return n > 0 ? 0 : -1;
}

static int write_file_atomic(const char *path, const uint8_t *bytes, size_t len)
{
    char tmp[600];
    wchar_t wtmp[600];
    wchar_t wpath[600];
    int fd, n;
    size_t off = 0;

    n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return -1;
    }
    if (win_widen(tmp, wtmp, (int)(sizeof(wtmp) / sizeof(wtmp[0]))) != 0 ||
        win_widen(path, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) != 0) {
        errno = EINVAL;
        return -1;
    }
    fd = _wopen(wtmp, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY | _O_NOINHERIT,
                _S_IREAD | _S_IWRITE);
    if (fd < 0) {
        return -1;
    }
    while (off < len) {
        size_t want = len - off;
        int w;

        if (want > (size_t)INT_MAX) {
            want = (size_t)INT_MAX;
        }
        w = _write(fd, bytes + off, (unsigned int)want);
        if (w <= 0) {
            _close(fd);
            _wunlink(wtmp);
            return -1;
        }
        off += (size_t)w;
    }
    {
        int frc = _commit(fd);
        int crc = _close(fd);

        if (frc != 0 || crc != 0) {
            _wunlink(wtmp);
            return -1;
        }
    }
    if (!MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        _wunlink(wtmp);
        errno = EIO;
        return -1;
    }
    return 0;
}
#endif

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

static void book_path(const nodus_p2p_host_t *p, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", p->data_path[0] ? p->data_path : ".",
             NODUS_P2P_ADDRBOOK_FILE);
}

static int h_book_save(void *ctx, const uint8_t *bytes, size_t len)
{
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;
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
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;
    char path[600];

    book_path(p, path, sizeof(path));
    return read_file(path, bytes, len);
}

/* ── our own signed ADDR record (N7; §2R4 P5: seq persisted first) ─── */

static int seq_read(const nodus_p2p_host_t *p, uint64_t *out)
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

static int seq_write(const nodus_p2p_host_t *p, uint64_t seq)
{
    char path[600];
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)seq);

    snprintf(path, sizeof(path), "%s/%s", p->seq_dir, NODUS_P2P_ADDR_SEQ_FILE);
    return write_file_atomic(path, (const uint8_t *)buf, (size_t)n);
}

/* Persist `seq`, THEN sign the record naming it. */
static int own_sign(nodus_p2p_host_t *p, uint64_t seq)
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
static void own_record_start(nodus_p2p_host_t *p)
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
static void own_record_check(nodus_p2p_host_t *p)
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
    nodus_p2p_host_t *p = (nodus_p2p_host_t *)ctx;

    if (!p->have_own_rec || !p->self_bonded) {
        return false;                    /* pex.h: none unless bonded */
    }
    memcpy(rec, p->own_rec, CMT_P2P_ADDR_REC_SIZE);
    return true;
}

bool nodus_p2p_host_signed_addr(nodus_p2p_host_t *p,
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

/* ── construction (node.go:283-421 / setup.go:349-491, the p2p half) ── */

int nodus_p2p_host_init(nodus_p2p_host_t *h, const nodus_p2p_host_params_t *prm)
{
    nodus_p2p_host_t *p = h;
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

    if (p == NULL) {
        return -1;
    }
    memset(p, 0, sizeof(*p));
    if (prm == NULL || prm->identity == NULL || prm->chain_id == NULL ||
        prm->cfg == NULL || prm->listen_ip == NULL || prm->data_path == NULL ||
        prm->seq_dir == NULL ||
        (prm->n_channels > 0 && prm->channels == NULL) ||
        prm->n_channels > (size_t)CMT_P2P_MAX_NUM_CHANNELS - 1 ||
        prm->n_reactors < 0 || (prm->n_reactors > 0 && prm->reactors == NULL)) {
        return -1;
    }
    if (!prm->identity->has_mlkem) {
        QGP_LOG_ERROR(LOG_TAG, "this node has no ML-KEM-1024 key "
                      "(nodus.mlkem_pk / nodus.mlkem_sk): port 4004 cannot run");
        return -1;
    }
    if (!cmt_p2p_ip_parse(prm->listen_ip, strlen(prm->listen_ip), &lip)) {
        QGP_LOG_ERROR(LOG_TAG, "listen address %s is not an IP literal "
                      "(R-P2P-24)", prm->listen_ip);
        return -1;
    }
    p->identity = prm->identity;
    p->cfg = *prm->cfg;
    memcpy(p->chain_id, prm->chain_id, 32);
    snprintf(p->data_path, sizeof(p->data_path), "%s", prm->data_path);
    snprintf(p->seq_dir, sizeof(p->seq_dir), "%s", prm->seq_dir);
    snprintf(p->listen_ip, sizeof(p->listen_ip), "%s", prm->listen_ip);
    snprintf(p->external_ip, sizeof(p->external_ip), "%s",
             prm->external_ip != NULL ? prm->external_ip : "");
    p->listen_port = prm->listen_port;
    p->n_workers = prm->n_workers;
    p->policy = prm->policy;
    if (cmt_p2p_pubkey_to_id(p->identity->pk.bytes, p->self_id) != CMT_OK ||
        nodus_p2p_io_init(&p->io, true) != 0) {
        return -1;
    }
    p->io_init = true;
    if (pthread_mutex_init(&p->mu, NULL) != 0) {
        return -1;                       /* nodus_p2p_host_free closes io */
    }
    if (pthread_cond_init(&p->cv, NULL) != 0) {
        pthread_mutex_destroy(&p->mu);
        return -1;                       /* nodus_p2p_host_free closes io */
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

    /* node.go:927-974 makeNodeInfo. The caller's channels in the order it
     * gives them; PEX last (node.go:955-957). */
    for (i = 0; i < (int)prm->n_channels; i++) {
        chans[n_chans++] = prm->channels[i];
    }
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
    th.bonded_count = pol_bonded_count;
    th.may_receive = pol_may_receive;
    th.recv_near_full = pol_recv_near_full;
    th.queue_mark = pol_queue_mark;
    memset(&tc, 0, sizeof(tc));
    tc.dsa_pk = p->identity->pk.bytes;
    tc.kem_pk = p->identity->mlkem_pk;
    tc.kem_sk = p->identity->mlkem_sk;
    tc.sc_host.ctx = (void *)p->identity;
    tc.sc_host.sign = nodus_p2p_sc_sign;
    tc.sc_host.verify = nodus_p2p_sc_verify;
    tc.chain_id = p->chain_id;
    tc.node_info = p->ni;
    cmt_p2p_mconn_p2p_default_config(&tc.mconn);           /* switch.go:37 */
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
    sh.is_bonded = pol_is_bonded;
    cmt_p2p_switch_default_config(&sc);
    sc.max_num_inbound_peers = p->cfg.max_num_inbound_peers;
    sc.max_num_outbound_peers = p->cfg.max_num_outbound_peers;
    sc.allow_duplicate_ip = p->cfg.allow_duplicate_ip;
    if (cmt_p2p_switch_init(&p->sw, &sc, &p->t, &sh) != CMT_OK) {
        goto fail;
    }
    p->sw_init = true;
    /* The caller's reactors, in its order (the witness: CONSENSUS first —
     * its InitPeer assigns the consensus index, nodus_witness_p2p.h). */
    for (i = 0; i < prm->n_reactors; i++) {
        if (cmt_p2p_switch_add_reactor(&p->sw, &prm->reactors[i]) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "reactor registration failed");
            goto fail;
        }
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
        bh.bonded_pubkey = pol_bonded_pubkey;
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
    return 0;

fail:
    return -1;                           /* the caller runs nodus_p2p_host_free */
}

int nodus_p2p_host_start(nodus_p2p_host_t *h)
{
    nodus_p2p_host_t *p = h;
    int i;

    if (p == NULL || !p->sw_init) {
        return -1;
    }
    /* The worker (R-P2P-8). */
    {
        int n = p->n_workers > 0 ? p->n_workers : NODUS_P2P_WORKERS_DEFAULT;

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

    /* node.go:547-579 OnStart: the switch (and with it PEX, which starts
     * the book — loadFromFile, R-P2P-38), then our record (the book's
     * own-seq is known now), then the persistent peers (:562-563). */
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
    return 0;

fail:
    return -1;                           /* the caller runs nodus_p2p_host_free */
}

void nodus_p2p_host_free(nodus_p2p_host_t *h)
{
    nodus_p2p_host_t *p = h;

    if (p == NULL) {
        return;
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
    if (p->io_init) {
        nodus_p2p_io_free(&p->io);
        p->io_init = false;
    }
    if (p->mu_init) {
        pthread_cond_destroy(&p->cv);
        pthread_mutex_destroy(&p->mu);
        p->mu_init = false;
    }
    free(p->ni);
    p->ni = NULL;
    memset(p->own_rec, 0, sizeof(p->own_rec));
    p->have_own_rec = false;
}

/* ── one pass (the witness calls the steps with its own in between) ── */

void nodus_p2p_host_poll_io(nodus_p2p_host_t *h, int timeout_ms)
{
    nodus_p2p_host_t *p = h;

    if (p == NULL) {
        return;
    }
    worker_drain(p);
    nodus_p2p_io_wait(&p->io, timeout_ms);
    worker_drain(p);
    nodus_p2p_io_pump(&p->io);
    cmt_p2p_switch_tick(&p->sw);
}

void nodus_p2p_host_pex_tick(nodus_p2p_host_t *h)
{
    if (h != NULL && h->pex != NULL) {
        cmt_p2p_pex_tick(h->pex);
    }
}

void nodus_p2p_host_own_record_check(nodus_p2p_host_t *h)
{
    if (h != NULL) {
        own_record_check(h);
    }
}

void nodus_p2p_host_flush(nodus_p2p_host_t *h)
{
    if (h != NULL) {
        nodus_p2p_io_flush(&h->io);
    }
}

void nodus_p2p_host_poll(nodus_p2p_host_t *h, int timeout_ms)
{
    if (h == NULL) {
        return;
    }
    nodus_p2p_host_poll_io(h, timeout_ms);
    nodus_p2p_host_pex_tick(h);
    nodus_p2p_host_own_record_check(h);
    nodus_p2p_host_flush(h);
}

/* ── accessors ─────────────────────────────────────────────────────── */

uint16_t nodus_p2p_host_listen_port(const nodus_p2p_host_t *p)
{
    return p != NULL && p->io.listen_fd != NODUS_SOCK_INVALID ? p->listen_port : 0;
}

const char *nodus_p2p_host_id(const nodus_p2p_host_t *p)
{
    return p != NULL ? p->self_id : "";
}

cmt_p2p_switch_t *nodus_p2p_host_switch(nodus_p2p_host_t *p)
{
    return p != NULL ? &p->sw : NULL;
}

int nodus_p2p_host_peer_count(const nodus_p2p_host_t *p)
{
    return p != NULL ? cmt_p2p_peer_set_size(cmt_p2p_switch_peers(&p->sw)) : 0;
}

bool nodus_p2p_host_peer_id_at(const nodus_p2p_host_t *p, int i,
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

bool nodus_p2p_host_has_peer(const nodus_p2p_host_t *p, const char *peer_id)
{
    return p != NULL && peer_id != NULL &&
           cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw), peer_id) != NULL;
}

bool nodus_p2p_host_send(nodus_p2p_host_t *p, const char *peer_id,
                         uint8_t ch, const uint8_t *msg, size_t len)
{
    cmt_p2p_peer_t *peer;

    if (p == NULL || peer_id == NULL) {
        return false;
    }
    peer = cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&p->sw), peer_id);
    return peer != NULL && cmt_p2p_peer_send(peer, ch, msg, len);
}
