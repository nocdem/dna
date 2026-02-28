/**
 * Nodus v5 — TCP Transport Implementation
 *
 * Non-blocking TCP with epoll, buffered frame I/O, connection pool.
 */

#include "transport/nodus_tcp.h"
#include "protocol/nodus_wire.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MAX_EVENTS 64

/* ── Socket helpers ──────────────────────────────────────────────── */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_keepalive(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    int idle = NODUS_TCP_KEEPIDLE;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    int intvl = NODUS_TCP_KEEPINTVL;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    int cnt = NODUS_TCP_KEEPCNT;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
}

static void set_nodelay(int fd) {
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
}

static void set_reuseaddr(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

/* ── Connection management ───────────────────────────────────────── */

static nodus_tcp_conn_t *conn_alloc(nodus_tcp_t *tcp) {
    int slot = -1;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        if (tcp->pool[i] == NULL) { slot = i; break; }
    }
    if (slot < 0) return NULL;

    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->fd = -1;
    conn->rbuf = malloc(NODUS_TCP_BUF_INIT);
    conn->rcap = NODUS_TCP_BUF_INIT;
    conn->wbuf = malloc(NODUS_TCP_BUF_INIT);
    conn->wcap = NODUS_TCP_BUF_INIT;

    if (!conn->rbuf || !conn->wbuf) {
        free(conn->rbuf);
        free(conn->wbuf);
        free(conn);
        return NULL;
    }

    conn->slot = slot;
    tcp->pool[slot] = conn;
    tcp->count++;
    return conn;
}

static void conn_free(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (!conn) return;

    if (conn->fd >= 0) {
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
        close(conn->fd);
    }

    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS)
        tcp->pool[conn->slot] = NULL;

    tcp->count--;
    free(conn->rbuf);
    free(conn->wbuf);
    free(conn);
}

static int buf_ensure(uint8_t **buf, size_t *cap, size_t needed) {
    if (needed <= *cap) return 0;
    size_t new_cap = *cap;
    while (new_cap < needed) new_cap *= 2;
    if (new_cap > NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096)
        return -1;
    uint8_t *nb = realloc(*buf, new_cap);
    if (!nb) return -1;
    *buf = nb;
    *cap = new_cap;
    return 0;
}

static void epoll_add(int epoll_fd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static void epoll_mod(int epoll_fd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

/* ── Frame parsing ───────────────────────────────────────────────── */

static void try_parse_frames(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    while (conn->rlen >= NODUS_FRAME_HEADER_SIZE) {
        nodus_frame_t frame;
        int rc = nodus_frame_decode(conn->rbuf, conn->rlen, &frame);

        if (rc == 0) break;     /* Incomplete — need more data */
        if (rc < 0) {
            /* Bad frame — disconnect */
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return;
        }

        /* Valid frame */
        size_t consumed = (size_t)rc;
        if (tcp->on_frame)
            tcp->on_frame(conn, frame.payload, frame.payload_len, tcp->cb_ctx);

        /* Shift remaining data */
        size_t remaining = conn->rlen - consumed;
        if (remaining > 0)
            memmove(conn->rbuf, conn->rbuf + consumed, remaining);
        conn->rlen = remaining;
    }
}

/* ── Event handlers ──────────────────────────────────────────────── */

static void handle_accept(nodus_tcp_t *tcp) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = accept(tcp->listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) return;

    if (tcp->count >= NODUS_TCP_MAX_CONNS) {
        close(fd);
        return;
    }

    set_nonblocking(fd);
    set_keepalive(fd);
    set_nodelay(fd);

    nodus_tcp_conn_t *conn = conn_alloc(tcp);
    if (!conn) { close(fd); return; }

    conn->fd = fd;
    conn->state = NODUS_CONN_CONNECTED;
    conn->port = ntohs(addr.sin_port);
    inet_ntop(AF_INET, &addr.sin_addr, conn->ip, sizeof(conn->ip));
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;

    epoll_add(tcp->epoll_fd, fd, EPOLLIN | EPOLLET, conn);

    if (tcp->on_accept)
        tcp->on_accept(conn, tcp->cb_ctx);
}

static void handle_read(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    for (;;) {
        if (buf_ensure(&conn->rbuf, &conn->rcap, conn->rlen + 4096) != 0) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return;
        }

        ssize_t n = read(conn->fd, conn->rbuf + conn->rlen,
                          conn->rcap - conn->rlen);
        if (n > 0) {
            conn->rlen += (size_t)n;
            conn->last_activity = nodus_time_now();
            continue;
        }
        if (n == 0) {
            /* Peer closed */
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return;
        }
        /* n < 0 */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        /* Real error */
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return;
    }

    try_parse_frames(tcp, conn);
}

static void handle_write(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    while (conn->wpos < conn->wlen) {
        ssize_t n = write(conn->fd, conn->wbuf + conn->wpos,
                           conn->wlen - conn->wpos);
        if (n > 0) {
            conn->wpos += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        /* Error */
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return;
    }

    if (conn->wpos >= conn->wlen) {
        /* All data sent — compact and disable EPOLLOUT */
        conn->wpos = 0;
        conn->wlen = 0;
        epoll_mod(tcp->epoll_fd, conn->fd, EPOLLIN | EPOLLET, conn);
    }
}

static void handle_connect_complete(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len);

    if (err != 0) {
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return;
    }

    conn->state = NODUS_CONN_CONNECTED;
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;
    set_keepalive(conn->fd);
    set_nodelay(conn->fd);

    /* Switch to read mode */
    uint32_t events = EPOLLIN | EPOLLET;
    if (conn->wlen > conn->wpos) events |= EPOLLOUT;
    epoll_mod(tcp->epoll_fd, conn->fd, events, conn);

    if (tcp->on_connect)
        tcp->on_connect(conn, tcp->cb_ctx);
}

/* ── Public API ──────────────────────────────────────────────────── */

uint64_t nodus_time_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

int nodus_tcp_init(nodus_tcp_t *tcp, int shared_epoll_fd) {
    if (!tcp) return -1;
    memset(tcp, 0, sizeof(*tcp));
    tcp->listen_fd = -1;

    if (shared_epoll_fd >= 0) {
        tcp->epoll_fd = shared_epoll_fd;
        tcp->owns_epoll = false;
    } else {
        tcp->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (tcp->epoll_fd < 0) return -1;
        tcp->owns_epoll = true;
    }
    return 0;
}

int nodus_tcp_listen(nodus_tcp_t *tcp, const char *bind_ip, uint16_t port) {
    if (!tcp) return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    set_reuseaddr(fd);
    set_nonblocking(fd);

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

    if (listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }

    /* Get actual port (useful if port was 0) */
    socklen_t slen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &slen);
    tcp->port = ntohs(addr.sin_port);

    tcp->listen_fd = fd;

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = NULL  /* NULL data.ptr = listen socket marker */
    };
    epoll_ctl(tcp->epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    return 0;
}

nodus_tcp_conn_t *nodus_tcp_connect(nodus_tcp_t *tcp,
                                     const char *ip, uint16_t port) {
    if (!tcp || !ip) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    set_nonblocking(fd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return NULL;
    }

    nodus_tcp_conn_t *conn = conn_alloc(tcp);
    if (!conn) { close(fd); return NULL; }

    conn->fd = fd;
    conn->state = NODUS_CONN_CONNECTING;
    conn->port = port;
    strncpy(conn->ip, ip, sizeof(conn->ip) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        /* Immediate connect (localhost) */
        conn->state = NODUS_CONN_CONNECTED;
        conn->connected_at = nodus_time_now();
        conn->last_activity = conn->connected_at;
        set_keepalive(fd);
        set_nodelay(fd);
        epoll_add(tcp->epoll_fd, fd, EPOLLIN | EPOLLET, conn);
        if (tcp->on_connect)
            tcp->on_connect(conn, tcp->cb_ctx);
    } else if (errno == EINPROGRESS) {
        /* Connecting — wait for EPOLLOUT */
        epoll_add(tcp->epoll_fd, fd, EPOLLOUT | EPOLLET, conn);
    } else {
        conn_free(tcp, conn);
        return NULL;
    }

    return conn;
}

int nodus_tcp_send(nodus_tcp_conn_t *conn,
                    const uint8_t *payload, size_t len) {
    if (!conn || !payload || conn->state == NODUS_CONN_CLOSED) return -1;

    size_t frame_size = NODUS_FRAME_HEADER_SIZE + len;
    size_t needed = conn->wlen + frame_size;

    if (buf_ensure(&conn->wbuf, &conn->wcap, needed) != 0)
        return -1;

    /* Write frame directly into write buffer */
    size_t written = nodus_frame_encode(conn->wbuf + conn->wlen,
                                         conn->wcap - conn->wlen,
                                         payload, (uint32_t)len);
    if (written == 0) return -1;
    conn->wlen += written;

    /* Enable EPOLLOUT to flush */
    /* Note: caller must have access to the tcp transport for epoll_mod.
     * We store the data; the next poll() will attempt to write. We need
     * to re-register EPOLLOUT. To do this without passing tcp, we
     * always try a direct write first. */
    while (conn->wpos < conn->wlen) {
        ssize_t n = write(conn->fd, conn->wbuf + conn->wpos,
                           conn->wlen - conn->wpos);
        if (n > 0) {
            conn->wpos += (size_t)n;
            continue;
        }
        break;  /* Would block or error — let poll handle it */
    }

    if (conn->wpos >= conn->wlen) {
        conn->wpos = 0;
        conn->wlen = 0;
    }

    return 0;
}

int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms) {
    if (!tcp) return -1;

    /* Re-enable EPOLLOUT for connections with pending writes */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->state == NODUS_CONN_CONNECTED && c->wlen > c->wpos)
            epoll_mod(tcp->epoll_fd, c->fd, EPOLLIN | EPOLLOUT | EPOLLET, c);
    }

    struct epoll_event events[MAX_EVENTS];
    int n = epoll_wait(tcp->epoll_fd, events, MAX_EVENTS, timeout_ms);
    if (n < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }

    for (int i = 0; i < n; i++) {
        nodus_tcp_conn_t *conn = events[i].data.ptr;

        if (conn == NULL) {
            /* Listen socket */
            handle_accept(tcp);
            continue;
        }

        if (conn->state == NODUS_CONN_CONNECTING) {
            handle_connect_complete(tcp, conn);
            continue;
        }

        if (events[i].events & (EPOLLERR | EPOLLHUP)) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            continue;
        }

        if (events[i].events & EPOLLOUT)
            handle_write(tcp, conn);

        if (events[i].events & EPOLLIN)
            handle_read(tcp, conn);
    }

    return n;
}

void nodus_tcp_disconnect(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (!tcp || !conn) return;
    if (tcp->on_disconnect)
        tcp->on_disconnect(conn, tcp->cb_ctx);
    conn_free(tcp, conn);
}

nodus_tcp_conn_t *nodus_tcp_find_by_id(nodus_tcp_t *tcp,
                                        const nodus_key_t *peer_id) {
    if (!tcp || !peer_id) return NULL;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->peer_id_set && nodus_key_cmp(&c->peer_id, peer_id) == 0)
            return c;
    }
    return NULL;
}

nodus_tcp_conn_t *nodus_tcp_find_by_addr(nodus_tcp_t *tcp,
                                          const char *ip, uint16_t port) {
    if (!tcp || !ip) return NULL;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->port == port && strcmp(c->ip, ip) == 0)
            return c;
    }
    return NULL;
}

int nodus_tcp_epoll_fd(const nodus_tcp_t *tcp) {
    return tcp ? tcp->epoll_fd : -1;
}

void nodus_tcp_close(nodus_tcp_t *tcp) {
    if (!tcp) return;

    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        if (tcp->pool[i])
            conn_free(tcp, tcp->pool[i]);
    }

    if (tcp->listen_fd >= 0) {
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, tcp->listen_fd, NULL);
        close(tcp->listen_fd);
        tcp->listen_fd = -1;
    }

    if (tcp->owns_epoll && tcp->epoll_fd >= 0) {
        close(tcp->epoll_fd);
        tcp->epoll_fd = -1;
    }
}
