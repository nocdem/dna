/**
 * Nodus — TCP Transport Implementation
 *
 * Cross-platform non-blocking TCP with buffered frame I/O, connection pool.
 * Linux/Android: epoll (high-perf server + client)
 * Windows: select() (client SDK only)
 */

#include "transport/nodus_tcp.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_channel_crypto.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG_TCP "NODUS_TCP"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #ifdef _MSC_VER
    #pragma comment(lib, "ws2_32.lib")
    #include <basetsd.h>
    typedef SSIZE_T ssize_t;
  #endif
  #define SHUT_RDWR SD_BOTH
  #define close(fd) closesocket(fd)
  #define poll_read(fd, buf, len)  recv(fd, (char*)(buf), (int)(len), 0)
  #define poll_write(fd, buf, len) send(fd, (const char*)(buf), (int)(len), 0)
  static int set_nonblocking(int fd) {
      u_long mode = 1;
      return ioctlsocket(fd, FIONBIO, &mode);
  }
  static int get_socket_error(void) { return WSAGetLastError(); }
  #define IS_EAGAIN(e) ((e) == WSAEWOULDBLOCK)
  #define IS_EINPROGRESS(e) ((e) == WSAEWOULDBLOCK)
#else
  #include <sys/epoll.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
  #define poll_read(fd, buf, len)  read(fd, buf, len)
  #define poll_write(fd, buf, len) write(fd, buf, len)
  static int set_nonblocking(int fd) {
      int flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0) return -1;
      return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
  static int get_socket_error(void) { return errno; }
  #define IS_EAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
  #define IS_EINPROGRESS(e) ((e) == EINPROGRESS)
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define MAX_EVENTS 64

/* ── Socket helpers ──────────────────────────────────────────────── */

static void set_keepalive(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&yes, sizeof(yes));
#ifndef _WIN32
    int idle = NODUS_TCP_KEEPIDLE;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    int intvl = NODUS_TCP_KEEPINTVL;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    int cnt = NODUS_TCP_KEEPCNT;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
}

static void set_nodelay(int fd) {
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&yes, sizeof(yes));
}

static void set_reuseaddr(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
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
#ifndef _WIN32
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
#endif
        close(conn->fd);
    }

    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS)
        tcp->pool[conn->slot] = NULL;

    tcp->count--;
    free(conn->pending_buf);
    free(conn->rbuf);
    free(conn->wbuf);
    free(conn);
}

static int buf_ensure(uint8_t **buf, size_t *cap, size_t needed) {
    if (needed <= *cap) return 0;
    const size_t max_cap = NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096;
    if (needed > max_cap) return -1;
    size_t new_cap = *cap;
    while (new_cap < needed) new_cap *= 2;
    /* Clamp to max instead of rejecting overshoot from doubling */
    if (new_cap > max_cap) new_cap = max_cap;
    uint8_t *nb = realloc(*buf, new_cap);
    if (!nb) return -1;
    *buf = nb;
    *cap = new_cap;
    return 0;
}

#ifndef _WIN32
static void epoll_add(int epoll_fd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static void epoll_mod(int epoll_fd, int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}
#endif

/* ── Frame parsing ───────────────────────────────────────────────── */

/**
 * Parse complete frames from the read buffer and dispatch them.
 * Returns true if the connection was freed (bad frame → disconnect),
 * in which case the caller must NOT touch conn again.
 */
static bool try_parse_frames(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    while (conn->rlen >= NODUS_FRAME_HEADER_SIZE) {
        nodus_frame_t frame;
        int rc = nodus_frame_decode(conn->rbuf, conn->rlen, &frame);

        if (rc == 0) break;     /* Incomplete — need more data */
        if (rc < 0) {
            /* Bad frame — disconnect */
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return true;
        }

        /* Validate frame size (HIGH-1: TCP path was missing this check) */
        if (!nodus_frame_validate(&frame, false)) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return true;
        }

        /* Valid frame — decrypt if channel crypto active */
        size_t consumed = (size_t)rc;
        const uint8_t *dispatch_payload = frame.payload;
        size_t dispatch_len = frame.payload_len;
        uint8_t *dec_buf = NULL;

        if (conn->crypto) {
            nodus_channel_crypto_t *cc = (nodus_channel_crypto_t *)conn->crypto;
            if (cc->established && frame.payload_len > NODUS_CHANNEL_OVERHEAD) {
                size_t pt_max = frame.payload_len - NODUS_CHANNEL_OVERHEAD;
                dec_buf = malloc(pt_max > 0 ? pt_max : 1);
                if (dec_buf) {
                    size_t pt_len = 0;
                    if (nodus_channel_decrypt(cc, frame.payload, frame.payload_len,
                                              dec_buf, pt_max, &pt_len) == 0) {
                        dispatch_payload = dec_buf;
                        dispatch_len = pt_len;
                    } else {
                        /* Decrypt failed — log details and disconnect */
                        QGP_LOG_ERROR(LOG_TAG_TCP, "decrypt failed: conn=%s:%d slot=%d frame_len=%zu is_nodus=%d",
                                      conn->ip, conn->port, conn->slot,
                                      frame.payload_len, conn->is_nodus);
                        /* Hex dump first 16 bytes of frame payload for diagnosis */
                        if (frame.payload_len >= 16) {
                            QGP_LOG_ERROR(LOG_TAG_TCP, "  frame_head: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                                frame.payload[0], frame.payload[1], frame.payload[2], frame.payload[3],
                                frame.payload[4], frame.payload[5], frame.payload[6], frame.payload[7],
                                frame.payload[8], frame.payload[9], frame.payload[10], frame.payload[11],
                                frame.payload[12], frame.payload[13], frame.payload[14], frame.payload[15]);
                        }
                        free(dec_buf);
                        if (tcp->on_disconnect)
                            tcp->on_disconnect(conn, tcp->cb_ctx);
                        conn_free(tcp, conn);
                        return true;
                    }
                }
            }
        }

        if (tcp->on_frame)
            tcp->on_frame(conn, dispatch_payload, dispatch_len, tcp->cb_ctx);
        free(dec_buf);

        /* Shift remaining data */
        size_t remaining = conn->rlen - consumed;
        if (remaining > 0)
            memmove(conn->rbuf, conn->rbuf + consumed, remaining);
        conn->rlen = remaining;
    }
    return false;
}

/* ── Event handlers ──────────────────────────────────────────────── */

static void handle_read(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    for (;;) {
        if (buf_ensure(&conn->rbuf, &conn->rcap, conn->rlen + 4096) != 0) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return;
        }

        ssize_t n = poll_read(conn->fd, conn->rbuf + conn->rlen,
                              conn->rcap - conn->rlen);
        if (n > 0) {
            conn->rlen += (size_t)n;
            conn->last_activity = nodus_time_now();
            continue;
        }
        if (n == 0) {
            /* Peer closed — process any buffered data before disconnect */
            bool freed = try_parse_frames(tcp, conn);
            if (!freed) {
                if (tcp->on_disconnect)
                    tcp->on_disconnect(conn, tcp->cb_ctx);
                conn_free(tcp, conn);
            }
            return;
        }
        /* n < 0 */
        if (IS_EAGAIN(get_socket_error()))
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
        ssize_t n = poll_write(conn->fd, conn->wbuf + conn->wpos,
                               conn->wlen - conn->wpos);
        if (n > 0) {
            conn->wpos += (size_t)n;
            continue;
        }
        if (n < 0 && IS_EAGAIN(get_socket_error()))
            break;
        /* Error */
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return;
    }

    if (conn->wpos >= conn->wlen) {
        conn->wpos = 0;
        conn->wlen = 0;
#ifndef _WIN32
        uint32_t ev = EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET);
        epoll_mod(tcp->epoll_fd, conn->fd, ev, conn);
#endif
    }
}

#ifndef _WIN32
static void handle_read_fwd(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn);
#endif

static void handle_connect_complete(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);

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

#ifndef _WIN32
    /* Switch to read mode */
    uint32_t et = tcp->level_triggered ? 0 : EPOLLET;
    uint32_t events = EPOLLIN | EPOLLRDHUP | et;
    if (conn->wlen > conn->wpos) events |= EPOLLOUT;
    epoll_mod(tcp->epoll_fd, conn->fd, events, conn);
#endif

    if (tcp->on_connect)
        tcp->on_connect(conn, tcp->cb_ctx);

#ifndef _WIN32
    /* on_connect callback may have queued data (e.g. hello for auth).
     * Re-check wbuf and ensure EPOLLOUT is set so it gets flushed. */
    if (conn->wlen > conn->wpos) {
        uint32_t ev2 = EPOLLIN | EPOLLOUT | EPOLLRDHUP | et;
        epoll_mod(tcp->epoll_fd, conn->fd, ev2, conn);
    }

    /* Edge-triggered: on_connect callback may have sent data (e.g. node_hello)
     * and the peer may have already responded before we return to epoll_wait.
     * Do an immediate read to avoid missing the initial EPOLLIN edge —
     * same pattern as handle_accept(). */
    handle_read_fwd(tcp, conn);
#endif
}

#ifndef _WIN32

#define NODUS_MAX_CONNS_PER_IP  20   /* CRIT-5: Per-IP connection limit */

static void handle_accept(nodus_tcp_t *tcp) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = accept(tcp->listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) return;

    if (tcp->count >= NODUS_TCP_MAX_CONNS) {
        close(fd);
        return;
    }

    /* CRIT-5: Per-IP connection limit */
    char new_ip[64];
    inet_ntop(AF_INET, &addr.sin_addr, new_ip, sizeof(new_ip));
    int ip_count = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        if (tcp->pool[i] && strcmp(tcp->pool[i]->ip, new_ip) == 0)
            ip_count++;
    }
    if (ip_count >= NODUS_MAX_CONNS_PER_IP) {
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
    snprintf(conn->ip, sizeof(conn->ip), "%s", new_ip);
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;

    epoll_add(tcp->epoll_fd, fd, EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);

    if (tcp->on_accept)
        tcp->on_accept(conn, tcp->cb_ctx);

    /* Edge-triggered: data may already be in buffer before epoll_add.
     * Do an immediate read to avoid missing the initial EPOLLIN edge. */
    handle_read_fwd(tcp, conn);
}

/* Forward-declared wrapper to call handle_read from handle_accept */
static void handle_read_fwd(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    handle_read(tcp, conn);
}
#endif /* !_WIN32 */

/* ── Public API ──────────────────────────────────────────────────── */

uint64_t nodus_time_now(void) {
#ifdef _WIN32
    return (uint64_t)time(NULL);
#else
    struct timespec ts;
    /* Must use CLOCK_REALTIME — nodus_time_now is used for absolute timestamps
     * (created_at, expires_at, seq, TTL expiry). CLOCK_MONOTONIC returns uptime
     * which breaks all DHT value timing and inter-node sync.
     * M-25 note: for relative timing (rate limit windows), callers compare
     * two nodus_time_now() values, so wall clock jumps cancel out. */
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
#endif
}

uint64_t nodus_time_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)time(NULL) * 1000ULL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

int nodus_tcp_init(nodus_tcp_t *tcp, int shared_epoll_fd) {
    if (!tcp) return -1;
    memset(tcp, 0, sizeof(*tcp));
    tcp->listen_fd = -1;

#ifdef _WIN32
    /* Initialize Winsock */
    static int wsa_init = 0;
    if (!wsa_init) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_init = 1;
    }
    tcp->poll_fd = -1;
    tcp->owns_epoll = false;
    (void)shared_epoll_fd;
#else
    if (shared_epoll_fd >= 0) {
        tcp->epoll_fd = shared_epoll_fd;
        tcp->owns_epoll = false;
    } else {
        tcp->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (tcp->epoll_fd < 0) return -1;
        tcp->owns_epoll = true;
    }
#endif
    return 0;
}

int nodus_tcp_listen(nodus_tcp_t *tcp, const char *bind_ip, uint16_t port) {
#ifdef _WIN32
    (void)tcp; (void)bind_ip; (void)port;
    return -1;  /* Server is Linux-only */
#else
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
#endif
}

nodus_tcp_conn_t *nodus_tcp_connect(nodus_tcp_t *tcp,
                                     const char *ip, uint16_t port) {
    if (!tcp || !ip) return NULL;

    int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
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

    /* Inherit auth requirement from transport IMMEDIATELY so gated send
     * queues frames even before TCP handshake completes. Without this,
     * callers would bypass the gate (auth_required=false default) and
     * write data to wbuf before hello, causing peer to reject. */
    conn->auth_required = tcp->auth_required;
    if (tcp->auth_required)
        conn->auth_state = NODUS_CONN_AUTH_NONE;  /* Will transition to HELLO_SENT in on_connect */
    strncpy(conn->ip, ip, sizeof(conn->ip) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        /* Immediate connect (localhost) */
        conn->state = NODUS_CONN_CONNECTED;
        conn->connected_at = nodus_time_now();
        conn->last_activity = conn->connected_at;
        set_keepalive(fd);
        set_nodelay(fd);
#ifndef _WIN32
        epoll_add(tcp->epoll_fd, fd, EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);
#endif
        if (tcp->on_connect)
            tcp->on_connect(conn, tcp->cb_ctx);
    } else if (IS_EINPROGRESS(get_socket_error())) {
        /* Connecting — wait for writable */
#ifndef _WIN32
        epoll_add(tcp->epoll_fd, fd, EPOLLOUT | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);
#endif
    } else {
        conn_free(tcp, conn);
        return NULL;
    }

    return conn;
}

/* ── Auth pending queue ─────────────────────────────────────────── */

static int pending_queue_append(nodus_tcp_conn_t *conn,
                                 const uint8_t *payload, size_t len) {
    size_t frame_size = NODUS_FRAME_HEADER_SIZE + len;

    /* Lazy init */
    if (!conn->pending_buf) {
        conn->pending_cap = NODUS_TCP_BUF_INIT;
        conn->pending_buf = malloc(conn->pending_cap);
        if (!conn->pending_buf) return -1;
        conn->pending_len = 0;
    }

    /* Cap check */
    if (conn->pending_len + frame_size > NODUS_TCP_PENDING_MAX) {
        QGP_LOG_WARN(LOG_TAG_TCP, "pending queue full (%zu + %zu > %d), dropping frame",
                     conn->pending_len, frame_size, NODUS_TCP_PENDING_MAX);
        return -1;
    }

    /* Grow if needed */
    if (conn->pending_len + frame_size > conn->pending_cap) {
        size_t new_cap = conn->pending_cap;
        while (new_cap < conn->pending_len + frame_size) new_cap *= 2;
        if (new_cap > NODUS_TCP_PENDING_MAX) new_cap = NODUS_TCP_PENDING_MAX;
        uint8_t *nb = realloc(conn->pending_buf, new_cap);
        if (!nb) return -1;
        conn->pending_buf = nb;
        conn->pending_cap = new_cap;
    }

    /* Encode frame into pending buffer */
    size_t written = nodus_frame_encode(conn->pending_buf + conn->pending_len,
                                         conn->pending_cap - conn->pending_len,
                                         payload, (uint32_t)len);
    if (written == 0) return -1;
    conn->pending_len += written;
    return 0;
}

int nodus_tcp_pending_flush(nodus_tcp_conn_t *conn) {
    if (!conn->pending_buf || conn->pending_len == 0) return 0;

    if (conn->wpos > 0) {
        size_t remaining = conn->wlen - conn->wpos;
        if (remaining > 0)
            memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
        conn->wlen = remaining;
        conn->wpos = 0;
    }

    size_t needed = conn->wlen + conn->pending_len;
    if (buf_ensure(&conn->wbuf, &conn->wcap, needed) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "pending flush: buf_ensure failed (needed=%zu)", needed);
        return -1;
    }

    memcpy(conn->wbuf + conn->wlen, conn->pending_buf, conn->pending_len);
    conn->wlen += conn->pending_len;

    QGP_LOG_INFO(LOG_TAG_TCP, "pending queue flushed: %zu bytes", conn->pending_len);

    free(conn->pending_buf);
    conn->pending_buf = NULL;
    conn->pending_len = 0;
    conn->pending_cap = 0;

    return 0;
}

int nodus_tcp_send(nodus_tcp_conn_t *conn,
                    const uint8_t *payload, size_t len) {
    /* Auth gate: queue frames while auth in progress */
    if (conn && conn->auth_required) {
        if (conn->auth_state == NODUS_CONN_AUTH_FAILED)
            return -1;
        if (conn->auth_state != NODUS_CONN_AUTH_OK)
            return pending_queue_append(conn, payload, len);
    }
    return nodus_tcp_send_progress(conn, payload, len, NULL, NULL);
}

int nodus_tcp_send_raw(nodus_tcp_conn_t *conn,
                        const uint8_t *payload, size_t len) {
    return nodus_tcp_send_progress(conn, payload, len, NULL, NULL);
}

int nodus_tcp_send_progress(nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len,
                             nodus_tcp_progress_cb progress_cb,
                             void *user_data) {
    if (!conn || !payload) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: NULL conn=%p payload=%p", (void*)conn, (void*)payload);
        return -1;
    }
    if (conn->state == NODUS_CONN_CLOSED) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: connection closed (fd=%d)", conn->fd);
        return -1;
    }
    if (len > NODUS_MAX_FRAME_TCP) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: payload too large (%zu > %d)", len, NODUS_MAX_FRAME_TCP);
        return -1;
    }

    /* Encrypt payload if channel crypto is established */
    uint8_t *enc_buf = NULL;
    const uint8_t *send_payload = payload;
    size_t send_len = len;

    if (conn->crypto) {
        nodus_channel_crypto_t *cc = (nodus_channel_crypto_t *)conn->crypto;
        if (cc->established) {
            size_t enc_needed = len + NODUS_CHANNEL_OVERHEAD;
            enc_buf = malloc(enc_needed);
            if (!enc_buf) return -1;
            size_t enc_out = 0;
            if (nodus_channel_encrypt(cc, payload, len, enc_buf, enc_needed, &enc_out) != 0) {
                free(enc_buf);
                return -1;
            }
            send_payload = enc_buf;
            send_len = enc_out;
        }
    }

    size_t frame_size = NODUS_FRAME_HEADER_SIZE + send_len;

    /* Compact: reclaim space from already-sent bytes before growing */
    if (conn->wpos > 0) {
        size_t remaining = conn->wlen - conn->wpos;
        if (remaining > 0)
            memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
        conn->wlen = remaining;
        conn->wpos = 0;
    }

    size_t needed = conn->wlen + frame_size;

    if (buf_ensure(&conn->wbuf, &conn->wcap, needed) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: buf_ensure failed (needed=%zu, wcap=%zu, wlen=%zu, wpos=%zu)",
                      needed, conn->wcap, conn->wlen, conn->wpos);
        return -1;
    }

    /* Write frame directly into write buffer */
    size_t written = nodus_frame_encode(conn->wbuf + conn->wlen,
                                         conn->wcap - conn->wlen,
                                         send_payload, (uint32_t)send_len);
    if (written == 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: frame_encode failed (len=%zu)", send_len);
        free(enc_buf);
        return -1;
    }
    conn->wlen += written;
    free(enc_buf);  /* NULL-safe */

    /* Try immediate send */
    while (conn->wpos < conn->wlen) {
        ssize_t n = poll_write(conn->fd, conn->wbuf + conn->wpos,
                               conn->wlen - conn->wpos);
        if (n > 0) {
            conn->wpos += (size_t)n;
            if (progress_cb)
                progress_cb(conn->wpos, conn->wlen, user_data);
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

/* ── Poll: platform-specific ─────────────────────────────────────── */

#ifdef _WIN32

int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms) {
    if (!tcp) return -1;

    fd_set rfds, wfds, efds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    int max_fd = -1;

    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c || c->fd < 0) continue;

        if (c->state == NODUS_CONN_CONNECTING) {
            FD_SET((SOCKET)c->fd, &wfds);
            FD_SET((SOCKET)c->fd, &efds);
        } else {
            FD_SET((SOCKET)c->fd, &rfds);
            if (c->wlen > c->wpos)
                FD_SET((SOCKET)c->fd, &wfds);
        }
        if (c->fd > max_fd) max_fd = c->fd;
    }

    if (max_fd < 0) {
        /* No connections — just sleep */
        if (timeout_ms > 0) Sleep(timeout_ms);
        return 0;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int n = select(max_fd + 1, &rfds, &wfds, &efds,
                   timeout_ms >= 0 ? &tv : NULL);
    if (n <= 0) return n;

    int events = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c || c->fd < 0) continue;

        if (c->state == NODUS_CONN_CONNECTING) {
            if (FD_ISSET((SOCKET)c->fd, &wfds) || FD_ISSET((SOCKET)c->fd, &efds)) {
                handle_connect_complete(tcp, c);
                events++;
            }
            continue;
        }

        if (FD_ISSET((SOCKET)c->fd, &wfds)) {
            handle_write(tcp, c);
            events++;
            /* conn may have been freed */
            if (tcp->pool[i] == NULL) continue;
        }

        if (FD_ISSET((SOCKET)c->fd, &rfds)) {
            handle_read(tcp, c);
            events++;
        }
    }

    return events;
}

#else /* Linux/Android: epoll */

int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms) {
    if (!tcp) return -1;

    /* Re-enable EPOLLOUT for connections with pending writes */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->state == NODUS_CONN_CONNECTED && c->wlen > c->wpos) {
            uint32_t ev = EPOLLIN | EPOLLOUT | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET);
            epoll_mod(tcp->epoll_fd, c->fd, ev, c);
        }
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

        if (events[i].events & EPOLLERR) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            continue;
        }

        int slot = conn->slot;  /* Save before handle_write may free conn */

        if (events[i].events & EPOLLOUT)
            handle_write(tcp, conn);

        /* handle_write() may have freed conn on write error.
         * Check the pool slot before touching conn again. */
        if (tcp->pool[slot] == NULL)
            continue;

        /* Read data before handling HUP — sender may close immediately
         * after sending, producing EPOLLIN|EPOLLHUP in the same event.
         * EPOLLRDHUP detects peer FIN even when EPOLLET edge is missed
         * by epoll_mod race — prevents CLOSE_WAIT socket accumulation. */
        if (events[i].events & (EPOLLIN | EPOLLRDHUP))
            handle_read(tcp, conn);
        else if (events[i].events & EPOLLHUP) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
        }
    }

    return n;
}

#endif /* _WIN32 */

/* ── Shared public API ───────────────────────────────────────────── */

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
#ifdef _WIN32
    (void)tcp;
    return -1;
#else
    return tcp ? tcp->epoll_fd : -1;
#endif
}

void nodus_tcp_close(nodus_tcp_t *tcp) {
    if (!tcp) return;

    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        if (tcp->pool[i])
            conn_free(tcp, tcp->pool[i]);
    }

    if (tcp->listen_fd >= 0) {
#ifndef _WIN32
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, tcp->listen_fd, NULL);
#endif
        close(tcp->listen_fd);
        tcp->listen_fd = -1;
    }

#ifndef _WIN32
    if (tcp->owns_epoll && tcp->epoll_fd >= 0) {
        close(tcp->epoll_fd);
        tcp->epoll_fd = -1;
    }
#endif
}
