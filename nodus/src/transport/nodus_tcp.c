/**
 * Nodus — TCP Transport Implementation
 *
 * Cross-platform non-blocking TCP with buffered frame I/O, connection pool.
 * Linux/Android: epoll (high-perf server + client)
 * Windows: select() (client SDK only)
 */

/* struct ucred (SO_PEERCRED, the Unix socket entry's peer check) is exposed
 * by glibc only under _GNU_SOURCE; -std=gnu11 gives _DEFAULT_SOURCE only.
 * Must precede the first include (features.h is fixed by the first system
 * header). Linux/Android only: Windows and Emscripten builds of this file
 * compile no Unix socket code. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
  #define _GNU_SOURCE 1
#endif

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
  /* O15B §8 — Winsock has no EINTR for socket I/O (WSAEINTR exists but is
   * only raised by a cancelled blocking call, which we never make since the
   * sockets are non-blocking). Peer-gone is the reset/abort family. */
  #define IS_EINTR_IO(e) (0 && (e))
  #define IS_PEER_GONE(e) ((e) == WSAECONNRESET || (e) == WSAECONNABORTED || \
                           (e) == WSAESHUTDOWN  || (e) == WSAENOTCONN)
#else
  #ifndef __EMSCRIPTEN__
    #include <sys/epoll.h>
  #else
    #include <poll.h>     /* browser build: poll() over the pool, no epoll */
  #endif
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <errno.h>
  #define poll_read(fd, buf, len)  read(fd, buf, len)
  /* O15B §8 — writes MUST NOT be able to kill the process.
   *
   * This was a raw write(2). Writing to a socket whose peer has already
   * closed raises SIGPIPE, whose default disposition is TERMINATE. Two of
   * the three processes that link this transport install
   * `signal(SIGPIPE, SIG_IGN)` in main() (nodus-server.c:269,
   * nodus-cli.c:1557) — but the transport is a LIBRARY, and every other
   * consumer (test_cc_client, the Messenger CLI `dna-connect-cli`, the
   * Flutter FFI host, any embedder) inherits the default and dies on an
   * ordinary peer disconnect. That is the pre-existing intermittent
   * `test_cc_client` SIGPIPE recorded in BUGS.md.
   *
   * MSG_NOSIGNAL is the NARROWEST correct policy: it suppresses the signal
   * for THIS call only and yields EPIPE instead, which the write sites below
   * handle. A process-wide `signal(SIGPIPE, SIG_IGN)` installed from library
   * code would silently change the disposition for the whole host program,
   * including for file and pipe descriptors this library never touches — a
   * library has no business making that decision for its embedder.
   * Linux and Android/bionic both provide MSG_NOSIGNAL; the Windows arm
   * above already uses send() and Windows raises no such signal.
   */
  #define poll_write(fd, buf, len) send(fd, buf, len, MSG_NOSIGNAL)
  static int set_nonblocking(int fd) {
      int flags = fcntl(fd, F_GETFL, 0);
      if (flags < 0) return -1;
      return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
  static int get_socket_error(void) { return errno; }
  #define IS_EAGAIN(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
  #define IS_EINPROGRESS(e) ((e) == EINPROGRESS)
  /* O15B §8 — EINTR means the call was interrupted before transferring
   * anything; nothing was lost and the operation is safe to repeat. Before
   * this season every write site treated EINTR as a hard error and tore the
   * connection down, so a signal delivered at the wrong instant destroyed a
   * healthy connection (and, on the submit path, an in-flight transaction). */
  #define IS_EINTR_IO(e) ((e) == EINTR)
  /* The peer is definitively gone. EPIPE is what MSG_NOSIGNAL turns the old
   * SIGPIPE into, so it MUST be handled here or the fix is only half done. */
  #define IS_PEER_GONE(e) ((e) == EPIPE || (e) == ECONNRESET || \
                           (e) == ENOTCONN || (e) == ESHUTDOWN)
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Three event-loop builds of this file:
 *   Linux/Android  epoll, server + client (listen, accept, WebSocket entry)
 *   _WIN32         select() over the pool, client only
 *   __EMSCRIPTEN__ poll() over the pool, client only (browser wallet,
 *                  sockets are Emscripten SOCKFS over a WebSocket). No
 *                  listen / accept / WebSocket-server code is compiled.
 * NODUS_TCP_EPOLL marks everything that exists only in the first build. */
#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
  #define NODUS_TCP_EPOLL 1
  #include <sys/un.h>     /* Unix socket entry (server side, like listen) */
  #include <sys/stat.h>
#endif

#define MAX_EVENTS 64

/* ── O15B §8: one classification of every socket I/O outcome ─────────
 *
 * Before this season each of the four I/O loops in this file re-derived its
 * own partial policy, and all four agreed only on "n > 0 is progress" and
 * "EAGAIN means stop". Everything else — EINTR, EPIPE, ECONNRESET, a
 * zero-byte return — fell into a single "Real error" arm that tore the
 * connection down (or, in nodus_tcp_send, into a bare `break` that reported
 * SUCCESS to the caller). Naming the outcomes once means a reviewer can see
 * the policy instead of reconstructing it four times.
 *
 * NTCP_IO_STALLED is deliberately distinct from NTCP_IO_WOULDBLOCK: a
 * send()/read() that returns 0 for a NON-zero length is not a documented
 * outcome for a stream socket in either direction (read()==0 is EOF and is
 * handled before classification). Treating it as "would block" would spin;
 * treating it as progress would advance wpos past bytes never written.
 */
typedef enum {
    NTCP_IO_PROGRESS = 0,  /* n > 0 — n bytes transferred                  */
    NTCP_IO_RETRY,         /* EINTR — nothing transferred, repeat the call  */
    NTCP_IO_WOULDBLOCK,    /* EAGAIN/EWOULDBLOCK — socket buffer full       */
    NTCP_IO_PEER_GONE,     /* EPIPE/ECONNRESET/... — peer is definitively gone */
    NTCP_IO_STALLED,       /* 0 bytes for a non-zero request                */
    NTCP_IO_FATAL          /* anything else                                 */
} ntcp_io_t;

static ntcp_io_t ntcp_classify(ssize_t n) {
    if (n > 0) return NTCP_IO_PROGRESS;
    if (n == 0) return NTCP_IO_STALLED;
    int e = get_socket_error();
    if (IS_EINTR_IO(e))  return NTCP_IO_RETRY;
    if (IS_EAGAIN(e))    return NTCP_IO_WOULDBLOCK;
    if (IS_PEER_GONE(e)) return NTCP_IO_PEER_GONE;
    return NTCP_IO_FATAL;
}

/* An EINTR storm must not become an unbounded spin. Each loop below repeats
 * only this many times on NTCP_IO_RETRY before giving up and letting the
 * ordinary error path run; a real signal flood is then reported rather than
 * silently absorbed. */
#define NTCP_MAX_EINTR_RETRY 64

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

#ifdef NODUS_TCP_EPOLL   /* only the listeners use it */
static void set_reuseaddr(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
}
#endif

/* ── Connection management ───────────────────────────────────────── */

/* Phase 3: forward declarations so conn_free can release pending frames. */
static void pending_free_all(nodus_tcp_conn_t *conn);

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
    conn->tcp_parent = tcp;   /* Phase 3: back-pointer for pending-full callback */
    tcp->pool[slot] = conn;
    tcp->count++;

    /* Phase 3.2d: log every conn alloc with its (slot, ptr, tcp pool ptr).
     * Reader correlates tcp ptr to inter/client/witness pool. Captures slot
     * reuse + memory address recycling so we can detect cached stale conn
     * pointers being aliased to fresh allocations. */
    fprintf(stderr, "TCP_CONN: ALLOC slot=%d tcp=%p conn=%p\n",
            slot, (void *)tcp, (void *)conn);
    return conn;
}

/* True if `conn` is a live member of this transport's pool. Compares the
 * pointer only — never dereferences it — so it is safe on any pointer an
 * event batch still carries. Linear in NODUS_TCP_MAX_CONNS; called once per
 * connection event. (The Windows select loop walks the pool itself.) */
#ifndef _WIN32   /* epoll and the browser poll() loop */
static bool conn_in_pool(const nodus_tcp_t *tcp, const nodus_tcp_conn_t *conn) {
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (tcp->pool[i] == conn) return true;
    return false;
}
#endif

/* Release the memory of a connection that conn_free already detached. */
static void conn_release(nodus_tcp_conn_t *conn) {
    free(conn->pending_buf);
    free(conn->rbuf);
    free(conn->wbuf);
    free(conn);
}

/* Release every connection parked by conn_free during a poll batch. Only
 * called when no poll is running on this transport (poll_depth == 0). */
static void conn_release_deferred(nodus_tcp_t *tcp) {
    while (tcp->close_list) {
        nodus_tcp_conn_t *c = tcp->close_list;
        tcp->close_list = c->close_next;
        conn_release(c);
    }
}

/* ── Read budget: the pending-read FIFO ──────────────────────────────
 *
 * A connection whose read handler stopped on NODUS_TCP_READ_BUDGET_* (or
 * that still has complete frames in rbuf) sits on tcp->read_head until a
 * later nodus_tcp_poll call services it. Under EPOLLET the kernel reports
 * no new edge for bytes that were already there, so this list — not epoll —
 * is what guarantees the rest is processed. A closing connection is never
 * on it: read_pending_add refuses one and conn_free unlinks. */

static void read_pending_add(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (conn->read_pending || conn->close_pending) return;
    conn->read_pending = true;
    conn->read_next = NULL;
    if (tcp->read_tail)
        tcp->read_tail->read_next = conn;
    else
        tcp->read_head = conn;
    tcp->read_tail = conn;
    tcp->read_count++;
}

/* Unlink wherever it is. Linear in the list (at most NODUS_TCP_MAX_CONNS). */
static void read_pending_del(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (!conn->read_pending) return;
    nodus_tcp_conn_t *prev = NULL;
    for (nodus_tcp_conn_t *c = tcp->read_head; c; prev = c, c = c->read_next) {
        if (c != conn) continue;
        if (prev) prev->read_next = c->read_next;
        else      tcp->read_head  = c->read_next;
        if (tcp->read_tail == c) tcp->read_tail = prev;
        tcp->read_count--;
        break;
    }
    conn->read_pending = false;
    conn->read_next = NULL;
}

static nodus_tcp_conn_t *read_pending_pop(nodus_tcp_t *tcp) {
    nodus_tcp_conn_t *c = tcp->read_head;
    if (!c) return NULL;
    tcp->read_head = c->read_next;
    if (!tcp->read_head) tcp->read_tail = NULL;
    tcp->read_count--;
    c->read_pending = false;
    c->read_next = NULL;
    return c;
}

/* Write-side lock (nodus_tcp_t.write_lock). No-ops when none is installed,
 * which is every server transport. Held only around wbuf / wpos / wlen /
 * pending-queue work and released before any callback. */
static void wl_enter(nodus_tcp_t *tcp) {
    if (tcp && tcp->write_lock) tcp->write_lock(tcp->write_lock_ctx, true);
}

static void wl_leave(nodus_tcp_t *tcp) {
    if (tcp && tcp->write_lock) tcp->write_lock(tcp->write_lock_ctx, false);
}

/* "Does conn hold unsent bytes?" — the poll side asks it to arm a write
 * event; read under the lock like every other wbuf access. */
static bool conn_has_unsent(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    wl_enter(tcp);
    bool unsent = conn->wlen > conn->wpos;
    wl_leave(tcp);
    return unsent;
}

void nodus_tcp_set_write_lock(nodus_tcp_t *tcp,
                              void (*fn)(void *ctx, bool lock), void *ctx) {
    if (!tcp) return;
    tcp->write_lock = fn;
    tcp->write_lock_ctx = fn ? ctx : NULL;
}

/* Tear a connection down. The caller has already run on_disconnect.
 *
 * Detaching is always immediate: the socket leaves epoll and is closed, the
 * pool slot is emptied, the per-conn counters are folded, queued frames and
 * key material are dropped, and the connection is marked close_pending /
 * CLOSED so any later send on it fails instead of writing to a stale fd.
 *
 * Releasing the memory is immediate only when no nodus_tcp_poll is running
 * on this transport. Inside one — which is every frame, accept, connect and
 * disconnect callback — the struct is parked on close_list and freed when
 * the outermost poll returns. That is the ONE safe point: the event batch
 * still holds this pointer in events[].data.ptr, try_parse_frames still
 * holds it after on_frame returns, and a later accept in the same batch
 * must not be handed the same address while a stale event for it is
 * pending. Freeing any earlier would reintroduce exactly that aliasing. */
static void conn_free(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (!conn || conn->close_pending) return;

    /* Under the write lock: a sender on another thread must see either the
     * live fd, buffers and key, or CLOSED — never a closed fd, a freed
     * pending queue or a cleared key mid-send. */
    wl_enter(tcp);

    if (conn->fd >= 0) {
#ifdef NODUS_TCP_EPOLL
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
#endif
        close(conn->fd);
        conn->fd = -1;
    }

    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS &&
        tcp->pool[conn->slot] == conn)
        tcp->pool[conn->slot] = NULL;

    /* D2.4: preserve this conn's decrypt-failure count before the struct dies,
     * so the harness gate can still see it after a teardown. */
    tcp->decrypt_fail_total += conn->decrypt_skip_count;

    tcp->count--;
    read_pending_del(tcp, conn);   /* read budget: never service a closed conn */
    pending_free_all(conn);   /* Phase 3: drop any queued frames */

    /* Phase 3.2b-inv: conn lifecycle visibility at TCP layer.
     * B3 fix — read crypto state from inline channel_crypto field. */
    int had_crypto = conn->channel_crypto.established ? 1 : 0;
    fprintf(stderr,
            "TCP_CONN: FREE slot=%d peer=%s:%u had_crypto=%d "
            "send_ok=%llu send_full=%llu pending=%zu\n",
            conn->slot, conn->ip, (unsigned)conn->port, had_crypto,
            (unsigned long long)conn->send_ok_count,
            (unsigned long long)conn->send_full_count,
            conn->pending_count);

    /* B3 fix — secure-zero the per-conn AES-GCM key + counters before the
     * struct is freed. Defensive even though the entire struct is about to
     * disappear; key material should never linger on the freelist. */
    nodus_channel_crypto_clear(&conn->channel_crypto);

    conn->state = NODUS_CONN_CLOSED;
    conn->close_pending = true;
    conn->rlen = 0;
    conn->wlen = 0;
    conn->wpos = 0;

    wl_leave(tcp);

    if (tcp->poll_depth > 0) {
        conn->close_next = tcp->close_list;
        tcp->close_list = conn;
        return;
    }
    conn_release(conn);
}

/* ── Phase 3: Pending queue ──────────────────────────────────────── */

/* Forward decl so pending_drain_to_wbuf() can grow the buffer. */
static int buf_ensure(uint8_t **buf, size_t *cap, size_t needed);

/** Push an already-encoded frame onto the tail of the pending FIFO.
 *  Takes ownership of `encoded` (caller must not free on success). */
static int pending_push_tail(nodus_tcp_conn_t *conn,
                              uint8_t *encoded, size_t frame_size) {
    nodus_pending_frame_t *node = malloc(sizeof(*node));
    if (!node) return -1;
    node->next = NULL;
    node->encoded = encoded;
    node->frame_size = frame_size;
    node->enqueued_at = nodus_time_now_ms();

    if (conn->pending_tail) {
        conn->pending_tail->next = node;
        conn->pending_tail = node;
    } else {
        conn->pending_head = conn->pending_tail = node;
    }
    conn->pending_count++;
    conn->pending_bytes += frame_size;
    conn->pending_enqueued_count++;
    return 0;
}

/** Pop the head of the pending FIFO. Caller owns returned node and must free
 *  both node->encoded and node itself. Returns NULL if queue empty. */
static nodus_pending_frame_t *pending_pop_head(nodus_tcp_conn_t *conn) {
    nodus_pending_frame_t *node = conn->pending_head;
    if (!node) return NULL;
    conn->pending_head = node->next;
    if (!conn->pending_head) conn->pending_tail = NULL;
    if (conn->pending_count > 0) conn->pending_count--;
    if (conn->pending_bytes >= node->frame_size)
        conn->pending_bytes -= node->frame_size;
    else
        conn->pending_bytes = 0;
    node->next = NULL;
    return node;
}

/** Free the entire pending list (called on conn_free). */
static void pending_free_all(nodus_tcp_conn_t *conn) {
    nodus_pending_frame_t *node = conn->pending_head;
    while (node) {
        nodus_pending_frame_t *next = node->next;
        free(node->encoded);
        free(node);
        node = next;
    }
    conn->pending_head = conn->pending_tail = NULL;
    conn->pending_count = 0;
    conn->pending_bytes = 0;
}

/** Drain pending head frames into wbuf as long as they fit.
 *  Bounded by NODUS_DRAIN_PER_CALL to avoid monopolizing the event loop. */
static void pending_drain_to_wbuf(nodus_tcp_conn_t *conn) {
    /* Phase 3.2b-inv2: first-drain visibility */
    if (!conn->drain_logged && conn->pending_head) {
        conn->drain_logged = true;
        fprintf(stderr,
                "PENDING_DRAIN slot=%d peer=%s:%u count=%zu bytes=%zu\n",
                conn->slot, conn->ip, (unsigned)conn->port,
                conn->pending_count, conn->pending_bytes);
    }
    int drained = 0;
    const size_t max_cap = NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096;
    while (drained < NODUS_DRAIN_PER_CALL && conn->pending_head) {
        nodus_pending_frame_t *head = conn->pending_head;
        if (conn->wlen + head->frame_size > max_cap) break;
        if (buf_ensure(&conn->wbuf, &conn->wcap, conn->wlen + head->frame_size) != 0)
            break;
        head = pending_pop_head(conn);
        memcpy(conn->wbuf + conn->wlen, head->encoded, head->frame_size);
        conn->wlen += head->frame_size;
        conn->pending_drained_count++;
        free(head->encoded);
        free(head);
        drained++;
    }
}

static int buf_ensure(uint8_t **buf, size_t *cap, size_t needed) {
    if (needed <= *cap) return 0;
    const size_t max_cap = NODUS_MAX_FRAME_TCP + NODUS_FRAME_HEADER_SIZE + 4096;
    if (needed > max_cap) return -1;
    size_t new_cap = *cap;
    /* A zero cap makes the doubling loop below spin forever — 0 * 2 == 0,
     * and `needed` is > 0 by the guard above, so the loop can never exit.
     * Every production connection is constructed with rcap/wcap =
     * NODUS_TCP_BUF_INIT (conn_alloc), but the invariant belongs HERE,
     * next to the loop that depends on it: a caller holding a zeroed conn
     * must get a buffer, not an unkillable spin. */
    if (new_cap == 0) new_cap = NODUS_TCP_BUF_INIT;
    while (new_cap < needed) new_cap *= 2;
    /* Clamp to max instead of rejecting overshoot from doubling */
    if (new_cap > max_cap) new_cap = max_cap;
    uint8_t *nb = realloc(*buf, new_cap);
    if (!nb) return -1;
    *buf = nb;
    *cap = new_cap;
    return 0;
}

/* ── Outgoing wire layout: the ONE place a nodus frame is laid out ──
 *
 * Every byte a connection sends as a nodus frame is produced here: the
 * direct wbuf write and the Phase-3 pending FIFO in nodus_tcp_send_progress,
 * and the auth pending_buf in pending_queue_append. The two remaining wbuf
 * writers — pending_drain_to_wbuf and nodus_tcp_pending_flush — only copy
 * bytes these produced. On a WebSocket connection each nodus frame becomes
 * the payload of one FIN=1 binary WS frame (server→client frames are never
 * masked, RFC 6455 §5.1); on a plain connection the layout is unchanged. */
static size_t conn_wire_size(const nodus_tcp_conn_t *conn, size_t send_len) {
    size_t n = NODUS_FRAME_HEADER_SIZE + send_len;
#ifdef NODUS_TCP_EPOLL
    if (conn->is_ws)
        n += nodus_ws_frame_header_len(n);
#else
    (void)conn;
#endif
    return n;
}

static size_t conn_wire_encode(const nodus_tcp_conn_t *conn,
                               uint8_t *dst, size_t cap,
                               const uint8_t *payload, size_t send_len) {
    size_t hdr = 0;
#ifdef NODUS_TCP_EPOLL
    if (conn->is_ws) {
        hdr = nodus_ws_frame_header(NODUS_WS_OP_BINARY,
                                    NODUS_FRAME_HEADER_SIZE + send_len, dst, cap);
        if (hdr == 0) return 0;
    }
#else
    (void)conn;
#endif
    size_t w = nodus_frame_encode(dst + hdr, cap - hdr, payload, (uint32_t)send_len);
    if (w == 0) return 0;
    return hdr + w;
}

/* A WebSocket connection whose Upgrade has not completed carries no nodus
 * frame in either direction. */
static bool conn_ws_not_open(const nodus_tcp_conn_t *conn) {
    return conn->is_ws && !conn->ws_open;
}

#ifdef NODUS_TCP_EPOLL
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

/* Outcome of try_parse_frames. */
typedef enum {
    PARSE_NEED_DATA = 0,  /* no complete frame left in rbuf                  */
    PARSE_MORE,           /* complete frames may remain: the frame budget ran
                           * out, or the channel crypto state flipped        */
    PARSE_CLOSED          /* conn is closed — do no further work on it       */
} parse_rc_t;

/**
 * Parse complete frames from the read buffer and dispatch them.
 * Returns PARSE_CLOSED if the connection is closed — torn down here (bad
 * frame), or closed by the on_frame callback itself (nodus_tcp_disconnect on
 * its own connection) — in which case the caller must do no further work on
 * conn.
 * budgeted: stop (PARSE_MORE) before a complete frame once
 * conn->read_frames_left is used up. Every frame taken off rbuf — dispatched
 * or dropped — spends one. Unbudgeted only on a terminal path (EOF, WS
 * close), where there is no later call to finish the job.
 */
static parse_rc_t try_parse_frames(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                                   bool budgeted) {
    if (conn->close_pending) return PARSE_CLOSED;
    while (conn->rlen >= NODUS_FRAME_HEADER_SIZE) {
        /* Snapshot crypto state before dispatching — if it changes mid-loop
         * (e.g., key_init handler activates crypto), remaining buffered frames
         * are plaintext but crypto would try to decrypt them. Break and let
         * the next poll iteration handle them correctly.
         * B3 fix — no pointer alias to snapshot; track the established flag
         * which is the actual gate (false → true on init). */
        bool established_before = conn->channel_crypto.established;

        nodus_frame_t frame;
        int rc = nodus_frame_decode(conn->rbuf, conn->rlen, &frame);

        if (rc == 0) break;     /* Incomplete — need more data */
        if (rc < 0) {
            /* Bad frame — disconnect */
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return PARSE_CLOSED;
        }

        /* Validate frame size (HIGH-1: TCP path was missing this check) */
        if (!nodus_frame_validate(&frame, false)) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return PARSE_CLOSED;
        }

        /* Read budget: a complete, valid frame is waiting but this call
         * may take no more. It stays in rbuf for the next call. */
        if (budgeted && conn->read_frames_left <= 0)
            return PARSE_MORE;
        conn->read_frames_left--;

        /* Valid frame — decrypt if channel crypto active.
         * B3 fix — read inline channel_crypto directly; no pointer alias. */
        size_t consumed = (size_t)rc;
        const uint8_t *dispatch_payload = frame.payload;
        size_t dispatch_len = frame.payload_len;
        uint8_t *dec_buf = NULL;

        nodus_channel_crypto_t *cc = &conn->channel_crypto;
        if (cc->established) {
            /* CRIT-3 — AEAD completeness. Once the channel is established,
             * EVERY frame must be authenticated. Previously this gated on
             * 'payload_len > NODUS_CHANNEL_OVERHEAD', so a <=28-byte payload
             * skipped the decrypt block entirely and fell through to the raw
             * on_frame() dispatch below — unauthenticated, with rx_counter
             * untouched (indefinitely replayable). On the inter-node channel
             * that reached the post-auth method dispatcher, letting an on-path
             * attacker inject authenticated-peer messages with no key at all.
             * A short frame or an allocation failure must now DROP the frame,
             * never dispatch it raw.
             *
             * Boundary is '>= NODUS_CHANNEL_OVERHEAD': a 28-byte frame is a
             * valid EMPTY-plaintext AEAD frame (nonce12+tag16) which the module
             * explicitly supports, so dropping it would break legitimate empty
             * frames. Only '< OVERHEAD' is impossible-to-authenticate.
             * See tests/test_channel_crypto_aead_complete.c. */
            bool drop_frame = false;

            if (frame.payload_len < NODUS_CHANNEL_OVERHEAD) {
                conn->decrypt_skip_count++;
                QGP_LOG_WARN(LOG_TAG_TCP,
                             "short frame dropped: conn=%s:%d slot=%d frame_len=%u < overhead=%u (unauthenticatable)",
                             conn->ip, conn->port, conn->slot,
                             (unsigned)frame.payload_len,
                             (unsigned)NODUS_CHANNEL_OVERHEAD);
                drop_frame = true;
            } else {
                /* Safe: payload_len >= NODUS_CHANNEL_OVERHEAD checked above,
                 * so the subtraction cannot underflow. */
                size_t pt_max = frame.payload_len - NODUS_CHANNEL_OVERHEAD;
                dec_buf = malloc(pt_max > 0 ? pt_max : 1);
                if (!dec_buf) {
                    QGP_LOG_ERROR(LOG_TAG_TCP,
                                  "decrypt alloc failed, frame dropped: conn=%s:%d slot=%d frame_len=%u",
                                  conn->ip, conn->port, conn->slot,
                                  (unsigned)frame.payload_len);
                    drop_frame = true;   /* fail closed — never dispatch ciphertext raw */
                } else {
                    size_t pt_len = 0;
                    if (nodus_channel_decrypt(cc, frame.payload, frame.payload_len,
                                              dec_buf, pt_max, &pt_len) == 0) {
                        dispatch_payload = dec_buf;
                        dispatch_len = pt_len;
                    } else {
                        /* Decrypt failed — drop the frame, do NOT reset
                         * rx_counter. A reset opens a silent replay window:
                         * later legitimate out-of-order frames would be
                         * (mis)accepted or (mis)rejected against a stale
                         * baseline. If this is truly an in-flight plaintext
                         * leftover it is rare and self-heals; if it is a
                         * real replay/attack we want rx_counter to stay
                         * strictly monotonic. */
                        /* D2.3: this is an AEAD FAILURE, not a benign event. On
                         * an ordered TCP stream there is no legitimate
                         * post-established plaintext frame (the established flip
                         * re-processes buffered bytes as encrypted), so any hit
                         * here means tampering, a key/role mismatch, or a real
                         * bug. The old "(in-flight plaintext)" text asserted a
                         * benign cause and would have masked exactly that. */
                        conn->decrypt_skip_count++;
                        QGP_LOG_WARN(LOG_TAG_TCP,
                                     "AEAD DECRYPT FAILED: conn=%s:%d slot=%d cc=%p frame_len=%u fail_count=%u "
                                     "(frame dropped; tamper/key-mismatch — NOT expected on an ordered stream)",
                                     conn->ip, conn->port, conn->slot,
                                     (void *)cc,
                                     (unsigned)frame.payload_len,
                                     (unsigned)conn->decrypt_skip_count);
                        free(dec_buf);
                        dec_buf = NULL;
                        drop_frame = true;
                    }
                }
            }

            if (drop_frame) {
                /* Skip this frame, continue processing */
                size_t remaining = conn->rlen - consumed;
                if (remaining > 0)
                    memmove(conn->rbuf, conn->rbuf + consumed, remaining);
                conn->rlen = remaining;
                continue;
            }
        }

        if (tcp->on_frame)
            tcp->on_frame(conn, dispatch_payload, dispatch_len, tcp->cb_ctx);
        free(dec_buf);

        /* The callback closed this connection (nodus_tcp_disconnect from
         * inside on_frame). on_frame always runs inside nodus_tcp_poll, so
         * the memory is still ours (deferred until the poll returns), but
         * no further frame of it may be dispatched. */
        if (conn->close_pending)
            return PARSE_CLOSED;

        /* If crypto state changed during dispatch (Kyber handshake completed),
         * stop processing — remaining frames in rbuf need different handling.
         * B3 fix — compare established flag (false → true on init).
         * PARSE_MORE puts the connection on the pending-read list, so the
         * "next poll iteration" really does handle them; before, under
         * EPOLLET, that happened only when more bytes arrived. */
        if (conn->channel_crypto.established != established_before) {
            size_t remaining = conn->rlen - consumed;
            if (remaining > 0)
                memmove(conn->rbuf, conn->rbuf + consumed, remaining);
            conn->rlen = remaining;
            return remaining >= NODUS_FRAME_HEADER_SIZE ? PARSE_MORE
                                                        : PARSE_NEED_DATA;
        }

        /* Shift remaining data */
        size_t remaining = conn->rlen - consumed;
        if (remaining > 0)
            memmove(conn->rbuf, conn->rbuf + consumed, remaining);
        conn->rlen = remaining;
    }
    return PARSE_NEED_DATA;
}

/* ── Event handlers ──────────────────────────────────────────────── */

/* Outcome of one budgeted read of a connection. */
typedef enum {
    READ_DRAINED = 0,  /* socket at EAGAIN and no complete frame left in rbuf */
    READ_MORE,         /* budget spent (or frames left in rbuf): continue in
                        * a later nodus_tcp_poll call                        */
    READ_CLOSED        /* conn is closed — do no further work on it          */
} read_rc_t;

#ifdef NODUS_TCP_EPOLL
static read_rc_t read_ws(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn);
#endif

/* The plain reader. Invariant: the socket is read only while rbuf holds no
 * complete frame — frames left over from an earlier call are dispatched
 * first, and each chunk read is parsed before the next one. So rbuf never
 * holds more than one incomplete frame plus one chunk, however far the
 * frame budget lags the byte budget. */
static read_rc_t read_plain(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    parse_rc_t pr = try_parse_frames(tcp, conn, true);
    if (pr == PARSE_CLOSED) return READ_CLOSED;
    if (pr == PARSE_MORE)   return READ_MORE;

    int eintr_left = NTCP_MAX_EINTR_RETRY;
    for (;;) {
        if (conn->read_bytes_left == 0)
            return READ_MORE;

        if (buf_ensure(&conn->rbuf, &conn->rcap, conn->rlen + 4096) != 0) {
            if (tcp->on_disconnect)
                tcp->on_disconnect(conn, tcp->cb_ctx);
            conn_free(tcp, conn);
            return READ_CLOSED;
        }

        size_t want = conn->rcap - conn->rlen;
        if (want > conn->read_bytes_left)
            want = conn->read_bytes_left;
        ssize_t n = poll_read(conn->fd, conn->rbuf + conn->rlen, want);
        if (n > 0) {
            conn->rlen += (size_t)n;
            conn->read_bytes_left -= (size_t)n;
            conn->last_activity = nodus_time_now();
            eintr_left = NTCP_MAX_EINTR_RETRY;   /* progress resets the budget */
            pr = try_parse_frames(tcp, conn, true);
            if (pr == PARSE_CLOSED) return READ_CLOSED;
            if (pr == PARSE_MORE)   return READ_MORE;
            continue;
        }
        if (n == 0) {
            /* Orderly EOF: the peer closed its write side. Process any
             * buffered data before disconnecting — a frame that arrived in
             * the same segment as the FIN is still a valid frame. (This is
             * read()'s EOF, NOT the NTCP_IO_STALLED case, which is why it is
             * handled before ntcp_classify.) Unbudgeted: there is no later
             * call for this connection. */
            if (try_parse_frames(tcp, conn, false) != PARSE_CLOSED) {
                if (tcp->on_disconnect)
                    tcp->on_disconnect(conn, tcp->cb_ctx);
                conn_free(tcp, conn);
            }
            return READ_CLOSED;
        }
        /* n < 0 */
        ntcp_io_t io = ntcp_classify(n);
        if (io == NTCP_IO_RETRY && eintr_left-- > 0)
            continue;                    /* interrupted, nothing lost */
        if (io == NTCP_IO_WOULDBLOCK)
            return READ_DRAINED;         /* drained for now */
        /* NTCP_IO_PEER_GONE / NTCP_IO_FATAL / EINTR budget exhausted. A
         * receive-side reset is still a disconnect, so the handling is the
         * same — but it is now reached deliberately rather than by falling
         * through from EINTR. */
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return READ_CLOSED;
    }
}

/* Read a connection within its per-call budget (NODUS_TCP_READ_BUDGET_*).
 * Every read of a connection — poll event, pending-read list, the immediate
 * read after accept / connect-complete — comes through here, so the budget,
 * the list and the WebSocket routing are decided in one place. Always runs
 * inside nodus_tcp_poll (poll_depth > 0), so conn's memory outlives a close
 * made below and read_active can be cleared after it. */
static void handle_read(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (conn->close_pending) return;   /* closed by a callback in this batch */

    /* Already serviced by this poll call, or its read is running further up
     * the stack (a callback polled again): queue it, never skip it — under
     * EPOLLET a skipped event would not be reported again. */
    if (conn->read_active || conn->read_gen == tcp->poll_gen) {
        read_pending_add(tcp, conn);
        return;
    }
    conn->read_active      = true;
    conn->read_gen         = tcp->poll_gen;
    conn->read_bytes_left  = NODUS_TCP_READ_BUDGET_BYTES;
    conn->read_frames_left = NODUS_TCP_READ_BUDGET_FRAMES;

    read_rc_t rc;
#ifdef NODUS_TCP_EPOLL
    if (conn->is_ws)
        rc = read_ws(tcp, conn);
    else
#endif
        rc = read_plain(tcp, conn);

    conn->read_active = false;
    if (rc == READ_CLOSED)
        return;                          /* conn_free already unlinked it */
    if (rc == READ_MORE)
        read_pending_add(tcp, conn);
    else
        read_pending_del(tcp, conn);
}

/* Service the pending-read list once: each connection that was on it when
 * the pass began gets one handle_read. A connection this call already
 * serviced (its epoll event came first) is re-queued by handle_read, and so
 * is one that uses its budget again — both go to the tail and wait for the
 * next call. Bounded by the count at the start, so it always ends. Returns
 * the number of connections taken off the list. */
static int read_pending_service(nodus_tcp_t *tcp) {
    int todo = tcp->read_count;
    int served = 0;
    while (todo-- > 0) {
        nodus_tcp_conn_t *c = read_pending_pop(tcp);
        if (!c) break;
        handle_read(tcp, c);
        served++;
    }
    return served;
}

/* Enter / leave one nodus_tcp_poll call: a fresh generation for the budget
 * (a nested call gets its own and hands the caller's back on return). */
static uint64_t poll_gen_enter(nodus_tcp_t *tcp) {
    uint64_t saved = tcp->poll_gen;
    tcp->poll_gen = ++tcp->poll_gen_last;
    return saved;
}

static void poll_gen_leave(nodus_tcp_t *tcp, uint64_t saved) {
    tcp->poll_gen = saved;
}

/* O15B §8 — the ONE write-drain loop.
 *
 * Pushes as much of [wpos, wlen) as the socket will take. Partial writes are
 * the normal case on a non-blocking socket and are accounted by advancing
 * wpos ONLY by the bytes the kernel accepted — never by the bytes offered.
 *
 * Returns the terminal classification:
 *   NTCP_IO_PROGRESS   the buffer is fully drained
 *   NTCP_IO_WOULDBLOCK partially drained; wpos is exact, retry on EPOLLOUT
 *   NTCP_IO_PEER_GONE / NTCP_IO_STALLED / NTCP_IO_FATAL   unrecoverable
 *
 * It never frees the connection: teardown belongs to the caller, because two
 * of the three call sites hold `conn` across the call and one of them is
 * reached from a public API whose caller also holds it.
 */
static ntcp_io_t conn_flush_wbuf(nodus_tcp_conn_t *conn,
                                 nodus_tcp_progress_cb progress_cb,
                                 void *user_data) {
    int eintr_left = NTCP_MAX_EINTR_RETRY;
    while (conn->wpos < conn->wlen) {
        ssize_t n = poll_write(conn->fd, conn->wbuf + conn->wpos,
                               conn->wlen - conn->wpos);
        ntcp_io_t io = ntcp_classify(n);
        if (io == NTCP_IO_PROGRESS) {
            conn->wpos += (size_t)n;
            eintr_left = NTCP_MAX_EINTR_RETRY;
            if (progress_cb) progress_cb(conn->wpos, conn->wlen, user_data);
            continue;
        }
        if (io == NTCP_IO_RETRY && eintr_left-- > 0)
            continue;
        return io;                       /* WOULDBLOCK, PEER_GONE, STALLED, FATAL */
    }
    return NTCP_IO_PROGRESS;
}

/* The write drain, under the write lock. Returns false when the socket is
 * dead; the caller then tears the connection down after releasing the lock
 * (on_disconnect may send, and conn_free takes the lock itself). */
static bool handle_write_locked(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    ntcp_io_t io = conn_flush_wbuf(conn, NULL, NULL);
    if (io != NTCP_IO_PROGRESS && io != NTCP_IO_WOULDBLOCK)
        return false;

    if (conn->wpos >= conn->wlen) {
        conn->wpos = 0;
        conn->wlen = 0;
    }

    /* Phase 3: wbuf made space — promote queued frames if any. We compact
     * first so `wlen` reflects only still-pending bytes, then pull from the
     * pending FIFO as long as they fit. */
    if (conn->pending_head) {
        if (conn->wpos > 0) {
            size_t remaining = conn->wlen - conn->wpos;
            if (remaining > 0)
                memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
            conn->wlen = remaining;
            conn->wpos = 0;
        }
        pending_drain_to_wbuf(conn);
        /* If we queued more data into wbuf, try to push it out right now
         * so drain and send stay in lock-step. */
        io = conn_flush_wbuf(conn, NULL, NULL);
        if (io != NTCP_IO_PROGRESS && io != NTCP_IO_WOULDBLOCK)
            return false;
        if (conn->wpos >= conn->wlen) {
            conn->wpos = 0;
            conn->wlen = 0;
        }
    }

#ifdef NODUS_TCP_EPOLL
    if (conn->wlen == 0 && conn->pending_head == NULL) {
        uint32_t ev = EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET);
        epoll_mod(tcp->epoll_fd, conn->fd, ev, conn);
    }
#else
    (void)tcp;
#endif
    return true;
}

static void handle_write(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    wl_enter(tcp);
    bool alive = handle_write_locked(tcp, conn);
    wl_leave(tcp);
    if (!alive) {
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
    }
}

#ifdef NODUS_TCP_EPOLL
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
    if (!conn->is_unix) {   /* TCP options; an AF_UNIX conn never connects async anyway */
        set_keepalive(conn->fd);
        set_nodelay(conn->fd);
    }

#ifdef NODUS_TCP_EPOLL
    /* Switch to read mode */
    uint32_t et = tcp->level_triggered ? 0 : EPOLLET;
    uint32_t events = EPOLLIN | EPOLLRDHUP | et;
    if (conn_has_unsent(tcp, conn)) events |= EPOLLOUT;
    epoll_mod(tcp->epoll_fd, conn->fd, events, conn);
#endif

    if (tcp->on_connect)
        tcp->on_connect(conn, tcp->cb_ctx);

    /* on_connect may have closed the connection (nodus_tcp_disconnect);
     * the memory is deferred, but its fd is gone — touch nothing more. */
    if (conn->close_pending)
        return;

#ifdef NODUS_TCP_EPOLL
    /* on_connect callback may have queued data (e.g. hello for auth).
     * Re-check wbuf and ensure EPOLLOUT is set so it gets flushed. */
    if (conn_has_unsent(tcp, conn)) {
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

#ifdef NODUS_TCP_EPOLL

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

    /* CRIT-5: Per-IP connection limit. WebSocket connections share this
     * pool but are counted separately (after their real IP is known, in
     * ws_try_upgrade) — decision 2026-09-25-web-wallet-nodus-send-transport
     * "IP sayacı": 20 plain + 20 WS per IP. */
    char new_ip[64];
    inet_ntop(AF_INET, &addr.sin_addr, new_ip, sizeof(new_ip));
    int ip_count = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        if (tcp->pool[i] && !tcp->pool[i]->is_ws && !tcp->pool[i]->is_unix &&
            strcmp(tcp->pool[i]->ip, new_ip) == 0)
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

    /* Phase 3.2d: bind fd to slot, log it. Match this fd against
     * INTER_FRAME_FIRST and TCP_SEND_FIRST to detect any fd alias. */
    fprintf(stderr, "TCP_CONN: FD_SET slot=%d fd=%d direction=accept "
            "peer=%s:%u conn=%p\n",
            conn->slot, fd, new_ip, (unsigned)conn->port, (void *)conn);

    epoll_add(tcp->epoll_fd, fd, EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);

    if (tcp->on_accept)
        tcp->on_accept(conn, tcp->cb_ctx);

    /* on_accept may have closed the connection — nothing left to read. */
    if (conn->close_pending)
        return;

    /* Edge-triggered: data may already be in buffer before epoll_add.
     * Do an immediate read to avoid missing the initial EPOLLIN edge. */
    handle_read_fwd(tcp, conn);
}

/* Forward-declared wrapper to call handle_read from handle_accept */
static void handle_read_fwd(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    handle_read(tcp, conn);
}

/* ── WebSocket entry glue (RFC 6455; codec in nodus_ws.c) ────────────
 *
 * Teardown follows the transport's one protocol: on_disconnect, then
 * conn_free, and the function that did it returns "closed" so its caller
 * does no further work on the connection (RT1 F7). All of this runs inside
 * nodus_tcp_poll, so conn_free only detaches and the memory is released
 * when the poll returns — the same deferred-close rule as the plain path.
 * No new free path. */

/* Append bytes that are NOT a nodus frame — the 101 / refusal response,
 * a pong, a close frame — to wbuf as they are. wbuf only ever holds whole
 * frames, so appending at wlen keeps it frame-aligned. */
static int ws_wbuf_append_raw(nodus_tcp_conn_t *conn,
                              const uint8_t *bytes, size_t n) {
    if (conn->wpos > 0) {
        size_t remaining = conn->wlen - conn->wpos;
        if (remaining > 0)
            memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
        conn->wlen = remaining;
        conn->wpos = 0;
    }
    if (buf_ensure(&conn->wbuf, &conn->wcap, conn->wlen + n) != 0)
        return -1;
    memcpy(conn->wbuf + conn->wlen, bytes, n);
    conn->wlen += n;
    return 0;
}

/* Queue `bytes` (may be NULL), push what the socket takes right now, then
 * tear the connection down. The caller must not touch conn afterwards. */
static void ws_close_now(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                         const uint8_t *bytes, size_t n) {
    if (conn->close_pending) return;   /* already closed: on_disconnect ran */
    wl_enter(tcp);
    if (bytes && n > 0 && ws_wbuf_append_raw(conn, bytes, n) == 0)
        (void)conn_flush_wbuf(conn, NULL, NULL);
    wl_leave(tcp);
    if (tcp->on_disconnect)
        tcp->on_disconnect(conn, tcp->cb_ctx);
    conn_free(tcp, conn);
}

/* Parser sink: unmasked payload goes onto the read buffer, where the
 * ordinary nodus frame decoder (try_parse_frames) finds it (RT1 F4). */
static int ws_sink_data(void *ctx, const uint8_t *data, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)ctx;
    if (buf_ensure(&conn->rbuf, &conn->rcap, conn->rlen + len) != 0)
        return -1;
    memcpy(conn->rbuf + conn->rlen, data, len);
    conn->rlen += len;
    return 0;
}

/* Parser sink: answer a ping with a pong carrying the same payload. */
static int ws_sink_ping(void *ctx, const uint8_t *payload, size_t len) {
    nodus_tcp_conn_t *conn = (nodus_tcp_conn_t *)ctx;
    uint8_t fr[NODUS_WS_SERVER_HDR_MAX + NODUS_WS_CTRL_MAX];
    if (len > NODUS_WS_CTRL_MAX) return -1;
    conn->read_frames_left--;   /* read budget: a ping is per-frame work */
    size_t h = nodus_ws_frame_header(NODUS_WS_OP_PONG, len, fr, sizeof(fr));
    if (h == 0) return -1;
    memcpy(fr + h, payload, len);
    nodus_tcp_t *tcp = conn->tcp_parent;
    wl_enter(tcp);
    int rc = ws_wbuf_append_raw(conn, fr, h + len);
    if (rc == 0)
        (void)conn_flush_wbuf(conn, NULL, NULL);   /* never frees; errors surface on the next write */
    wl_leave(tcp);
    return rc == 0 ? 0 : -1;
}

/* Feed raw bytes of an open WS connection. Returns true if conn was closed. */
static bool ws_feed_frames(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                           uint8_t *data, size_t n) {
    nodus_ws_sink_t sink = { ws_sink_data, ws_sink_ping, conn };
    uint16_t code = 0;
    int rc = nodus_ws_feed(&conn->ws, data, n, &sink, &code);
    if (rc == NODUS_WS_FEED_OK)
        return false;

    uint8_t cf[4];
    size_t cl = nodus_ws_close_frame(code, cf, sizeof(cf));
    if (rc == NODUS_WS_FEED_PEER_CLOSE) {
        QGP_LOG_INFO(LOG_TAG_TCP, "ws: peer closed slot=%d ip=%s",
                     conn->slot, conn->ip);
        /* Frames that arrived before the close are still frames — the
         * same rule as the plain reader's EOF path, and unbudgeted like it:
         * the connection closes right below, there is no later call. */
        if (try_parse_frames(tcp, conn, false) == PARSE_CLOSED)
            return true;
    } else {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: closing slot=%d ip=%s code=%u: %s",
                     conn->slot, conn->ip, (unsigned)code,
                     conn->ws.reason ? conn->ws.reason : "protocol error");
    }
    ws_close_now(tcp, conn, cf, cl);
    return true;
}

/* Try to complete the HTTP Upgrade from the bytes gathered in rbuf.
 * Returns true if conn was closed. */
static bool ws_try_upgrade(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    nodus_ws_hs_result_t res;
    int rc = nodus_ws_handshake_parse(conn->rbuf, conn->rlen, conn->ip,
                                      tcp->ws_origins, &res);
    if (rc == NODUS_WS_HS_NEED_MORE)
        return false;

    if (rc != NODUS_WS_HS_OK) {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: upgrade refused slot=%d status=%d: %s",
                     conn->slot, res.status,
                     res.reason ? res.reason : "invalid request");
        char resp[256];
        size_t rl = nodus_ws_reject_response(res.status, resp, sizeof(resp));
        ws_close_now(tcp, conn, (const uint8_t *)resp, rl);
        return true;
    }

    /* Per real-IP limit among OPEN WebSocket connections only — a separate
     * counter from the plain listener's (handle_accept). IPv6 counts by
     * /64 prefix (nodus_ws_ip_bucket). real_ip came out of inet_ntop, so it
     * always parses; a failure is refused rather than left uncounted. */
    nodus_ws_ip_bucket_t bucket;
    if (nodus_ws_ip_bucket(res.real_ip, &bucket) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "ws: client address does not parse, slot=%d closed",
                      conn->slot);
        ws_close_now(tcp, conn, NULL, 0);
        return true;
    }
    int same_ip = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c != conn && c->is_ws && c->ws_open &&
            memcmp(&c->ws_bucket, &bucket, sizeof(bucket)) == 0)
            same_ip++;
    }
    if (same_ip >= NODUS_WS_MAX_CONNS_PER_IP) {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: per-IP limit %d reached for %s, slot=%d closed",
                     NODUS_WS_MAX_CONNS_PER_IP, res.real_ip, conn->slot);
        ws_close_now(tcp, conn, NULL, 0);
        return true;
    }

    char resp[256];
    size_t rl = nodus_ws_handshake_response(&res, resp, sizeof(resp));
    int queued = -1;
    if (rl > 0) {
        wl_enter(tcp);
        queued = ws_wbuf_append_raw(conn, (const uint8_t *)resp, rl);
        wl_leave(tcp);
    }
    if (queued != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "ws: could not queue 101 response, slot=%d",
                      conn->slot);
        ws_close_now(tcp, conn, NULL, 0);
        return true;
    }

    /* Bytes after the request head are already WS frames. Copy them out:
     * the parser unmasks in place and its sink appends to rbuf, which
     * buf_ensure may move. */
    size_t leftover = conn->rlen - res.consumed;
    uint8_t *rest = NULL;
    if (leftover > 0) {
        rest = malloc(leftover);
        if (!rest) {
            QGP_LOG_ERROR(LOG_TAG_TCP, "ws: alloc failed after upgrade, slot=%d",
                          conn->slot);
            ws_close_now(tcp, conn, NULL, 0);
            return true;
        }
        memcpy(rest, conn->rbuf + res.consumed, leftover);
    }
    conn->rlen = 0;   /* the request head must never reach nodus_frame_decode */

    snprintf(conn->ip, sizeof(conn->ip), "%s", res.real_ip);
    conn->ws_bucket = bucket;
    nodus_ws_parser_init(&conn->ws);
    conn->ws_open = true;
    QGP_LOG_INFO(LOG_TAG_TCP, "ws: upgrade ok slot=%d ip=%s%s",
                 conn->slot, conn->ip, res.proto_binary ? " proto=binary" : "");

    wl_enter(tcp);
    (void)conn_flush_wbuf(conn, NULL, NULL);   /* never frees; see ws_sink_ping */
    wl_leave(tcp);

    if (rest) {
        bool freed = ws_feed_frames(tcp, conn, rest, leftover);
        free(rest);
        return freed;
    }
    return false;
}

/* Take one chunk of socket bytes. Returns true if conn was closed. */
static bool ws_ingest(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                      uint8_t *data, size_t n) {
    if (conn->ws_open)
        return ws_feed_frames(tcp, conn, data, n);

    /* Upgrade not done: gather the request head in rbuf (unused until the
     * upgrade). nodus_ws_handshake_parse refuses once 8 KiB pass without
     * the head's end, so this stays bounded by 8 KiB + one chunk. */
    if (buf_ensure(&conn->rbuf, &conn->rcap, conn->rlen + n) != 0) {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: request buffer full, slot=%d", conn->slot);
        ws_close_now(tcp, conn, NULL, 0);
        return true;
    }
    memcpy(conn->rbuf + conn->rlen, data, n);
    conn->rlen += n;
    return ws_try_upgrade(tcp, conn);
}

/* The WS reader: reads the socket until EAGAIN or the read budget
 * (edge-triggered; the pending-read list covers a stop on the budget),
 * passes each chunk through the handshake / frame parser, then — exactly
 * like the plain reader — decodes the nodus frames accumulated in rbuf,
 * after every chunk. Same invariant as read_plain: the socket is read only
 * while rbuf holds no complete nodus frame. nodus_ws_feed takes a whole
 * chunk, so the frame budget can overrun by the pings of one chunk; empty
 * data frames and pongs reach no callback and are bounded by the bytes. */
static read_rc_t read_ws(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    uint8_t chunk[16384];
    parse_rc_t pr;

    if (conn->ws_open) {
        pr = try_parse_frames(tcp, conn, true);
        if (pr == PARSE_CLOSED) return READ_CLOSED;
        if (pr == PARSE_MORE)   return READ_MORE;
    }

    int eintr_left = NTCP_MAX_EINTR_RETRY;
    for (;;) {
        if (conn->read_bytes_left == 0 || conn->read_frames_left <= 0)
            return READ_MORE;

        size_t want = sizeof(chunk);
        if (want > conn->read_bytes_left)
            want = conn->read_bytes_left;
        ssize_t n = poll_read(conn->fd, chunk, want);
        if (n > 0) {
            conn->read_bytes_left -= (size_t)n;
            conn->last_activity = nodus_time_now();
            eintr_left = NTCP_MAX_EINTR_RETRY;
            if (ws_ingest(tcp, conn, chunk, (size_t)n))
                return READ_CLOSED;      /* closed — no further work on conn */
            if (conn->ws_open) {
                pr = try_parse_frames(tcp, conn, true);
                if (pr == PARSE_CLOSED) return READ_CLOSED;
                if (pr == PARSE_MORE)   return READ_MORE;
            }
            continue;
        }
        if (n == 0) {
            /* EOF — unbudgeted, as in read_plain. */
            bool freed = conn->ws_open &&
                         try_parse_frames(tcp, conn, false) == PARSE_CLOSED;
            if (!freed) {
                if (tcp->on_disconnect)
                    tcp->on_disconnect(conn, tcp->cb_ctx);
                conn_free(tcp, conn);
            }
            return READ_CLOSED;
        }
        ntcp_io_t io = ntcp_classify(n);
        if (io == NTCP_IO_RETRY && eintr_left-- > 0)
            continue;
        if (io == NTCP_IO_WOULDBLOCK)
            return READ_DRAINED;
        if (tcp->on_disconnect)
            tcp->on_disconnect(conn, tcp->cb_ctx);
        conn_free(tcp, conn);
        return READ_CLOSED;
    }
}

static void handle_accept_ws(nodus_tcp_t *tcp) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd = accept(tcp->ws_listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0) return;

    if (tcp->count >= NODUS_TCP_MAX_CONNS) {
        close(fd);
        return;
    }

    /* No per-IP check here: every peer of this socket is the local proxy
     * (127.0.0.1). The per-IP limit applies to the real IP after the
     * Upgrade. What is bounded here is how many WS connections exist in
     * total (NODUS_WS_MAX_CONNS, so the shared pool keeps room for plain
     * 4001 clients) and how many Upgrades may be pending. */
    int ws_total = 0, handshaking = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c || !c->is_ws) continue;
        ws_total++;
        if (!c->ws_open)
            handshaking++;
    }
    if (ws_total >= NODUS_WS_MAX_CONNS) {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: %d WebSocket connections open, new connection refused",
                     ws_total);
        close(fd);
        return;
    }
    if (handshaking >= NODUS_WS_MAX_HANDSHAKING) {
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: %d upgrades pending, new connection refused",
                     handshaking);
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
    if (!inet_ntop(AF_INET, &addr.sin_addr, conn->ip, sizeof(conn->ip)))
        conn->ip[0] = '\0';
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;
    conn->is_ws = true;
    conn->ws_open = false;
    nodus_ws_parser_init(&conn->ws);

    epoll_add(tcp->epoll_fd, fd,
              EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);

    /* Same lifecycle as a plain accept: the session for this slot is
     * reset now, so every teardown path below runs the usual callbacks. */
    if (tcp->on_accept)
        tcp->on_accept(conn, tcp->cb_ctx);

    if (conn->close_pending)   /* closed by on_accept */
        return;

    handle_read_fwd(tcp, conn);
}

/* ── Unix domain socket entry ────────────────────────────────────────
 *
 * Local IPC between the split nodus services (decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md item 7). Peers
 * are admitted by the socket file's mode (0600, nodus_tcp_unix_listen) and
 * by their SO_PEERCRED uid (below). The per-IP limit of handle_accept does
 * not apply: every peer is a local process, there is no address, and the
 * pool cap NODUS_TCP_MAX_CONNS still bounds the total.
 *
 * One listener event accepts every queued peer (up to
 * NODUS_TCP_UNIX_ACCEPT_BURST), so a burst of local services connecting at
 * once is not served one per poll. The bound keeps one event from starving
 * the rest of the loop; the listener is level-triggered, so peers left in
 * the backlog fire it again on the next poll. */

#define NODUS_TCP_UNIX_ACCEPT_BURST  64

/* Accept and admit one queued peer. Returns false when the backlog is
 * empty (EAGAIN/EWOULDBLOCK) or accept failed in a way retrying in this
 * event cannot fix; true when the caller may try the next one. */
static bool accept_one_unix(nodus_tcp_t *tcp) {
    /* No peer address is requested: an AF_UNIX peer has none worth reading
     * (an unbound client's is empty) and nothing here may treat a
     * sockaddr_un as a sockaddr_in. */
    int fd = accept4(tcp->unix_listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (fd < 0) {
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK)
            return false;
        if (err == EINTR || err == ECONNABORTED)
            return true;   /* this peer is gone; the next may be queued */
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: accept failed (errno=%d)", err);
        return false;
    }

    if (tcp->count >= NODUS_TCP_MAX_CONNS) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: connection pool full (%d), local peer dropped",
                     NODUS_TCP_MAX_CONNS);
        close(fd);
        return true;
    }

    /* SO_PEERCRED: the peer process's credentials as of its connect().
     * Fail closed — credentials that cannot be read are a refusal. Checked
     * BEFORE a connection is allocated, so on_accept never runs for a
     * refused peer. */
    struct ucred cr;
    socklen_t cr_len = sizeof(cr);
    memset(&cr, 0, sizeof(cr));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) != 0 ||
        cr_len != sizeof(cr)) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: peer credentials unreadable (errno=%d), "
                     "connection refused", errno);
        close(fd);
        return true;
    }
    if (!nodus_tcp_unix_peercred_ok((uint32_t)cr.uid, tcp->unix_allowed_uid)) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: peer uid=%u pid=%d is not the allowed uid=%u, "
                     "connection refused",
                     (unsigned)cr.uid, (int)cr.pid, (unsigned)tcp->unix_allowed_uid);
        close(fd);
        return true;
    }

    /* A blocking socket in the event loop would stall every connection. */
    if (set_nonblocking(fd) != 0) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: cannot make accepted socket non-blocking "
                     "(errno=%d), connection refused", errno);
        close(fd);
        return true;
    }
    /* No set_keepalive / set_nodelay: both are TCP options. */

    nodus_tcp_conn_t *conn = conn_alloc(tcp);
    if (!conn) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: no free connection slot, local peer dropped");
        close(fd);
        return true;
    }

    conn->fd = fd;
    conn->state = NODUS_CONN_CONNECTED;
    conn->is_unix = true;
    conn->peer_cred_set = true;
    conn->peer_uid = (uint32_t)cr.uid;
    conn->peer_pid = (int32_t)cr.pid;
    conn->port = 0;
    snprintf(conn->ip, sizeof(conn->ip), "%s", NODUS_TCP_UNIX_PEER_IP);
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;

    QGP_LOG_DEBUG(LOG_TAG_TCP, "unix: accepted slot=%d fd=%d peer uid=%u pid=%d",
                  conn->slot, fd, (unsigned)conn->peer_uid, (int)conn->peer_pid);

    epoll_add(tcp->epoll_fd, fd,
              EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);

    /* Same lifecycle as a plain accept. */
    if (tcp->on_accept)
        tcp->on_accept(conn, tcp->cb_ctx);

    if (conn->close_pending)   /* closed by on_accept */
        return true;

    handle_read_fwd(tcp, conn);
    return true;
}

static void handle_accept_unix(nodus_tcp_t *tcp) {
    for (int i = 0; i < NODUS_TCP_UNIX_ACCEPT_BURST; i++) {
        /* A callback may have closed the transport's Unix entry. */
        if (tcp->unix_listen_fd < 0 || !accept_one_unix(tcp))
            break;
    }
}

/* Is a listener alive at the socket file `path`? A non-blocking connect:
 * 0 or EAGAIN (backlog full) = alive → 1; ECONNREFUSED = nobody listens
 * (a stale file left by a process that died) → 0; anything else → -1
 * (undecidable, e.g. EACCES — the caller must not unlink). */
static int unix_path_probe(const struct sockaddr_un *sa) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int rc = connect(fd, (const struct sockaddr *)sa, sizeof(*sa));
    int err = errno;
    close(fd);
    if (rc == 0) return 1;
    if (err == EAGAIN || err == EWOULDBLOCK) return 1;
    if (err == ECONNREFUSED) return 0;
    return -1;
}

/* Fill an AF_UNIX address. Returns -1 if path does not fit in sun_path
 * (with its terminating NUL). */
static int unix_addr_fill(struct sockaddr_un *sa, const char *path) {
    size_t plen = strlen(path);
    memset(sa, 0, sizeof(*sa));
    if (plen == 0 || plen >= sizeof(sa->sun_path)) return -1;
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, path, plen + 1);
    return 0;
}

/* The socket file is only as safe as the directory holding it: whoever can
 * write there can remove or replace the file, and the service runs as root.
 * The parent of `path` (path already fits NODUS_TCP_UNIX_PATH_MAX) must be,
 * by lstat — a symlink in its place is refused, not followed — a directory
 * owned by this process's euid or by root, with no group/other write bit.
 * Returns 0 if so; otherwise logs an ERROR naming the directory, -1. */
static int unix_parent_dir_ok(const char *path) {
    char dir[NODUS_TCP_UNIX_PATH_MAX];
    size_t plen = strlen(path);
    if (plen >= sizeof(dir)) return -1;
    memcpy(dir, path, plen + 1);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        dir[0] = '.'; dir[1] = '\0';          /* relative name: current dir */
    } else if (slash == dir) {
        dir[1] = '\0';                        /* "/name": the root directory */
    } else {
        *slash = '\0';
    }

    struct stat st;
    if (lstat(dir, &st) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket directory %s cannot be checked (errno=%d), "
                      "refusing", dir, errno);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket directory %s is not a directory "
                      "(or is a symlink), refusing", dir);
        return -1;
    }
    if (st.st_uid != geteuid() && st.st_uid != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket directory %s is owned by uid=%u, "
                      "neither this process (uid=%u) nor root, refusing",
                      dir, (unsigned)st.st_uid, (unsigned)geteuid());
        return -1;
    }
    if ((st.st_mode & 022) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket directory %s is group/other-writable "
                      "(mode %04o), refusing", dir, (unsigned)(st.st_mode & 07777));
        return -1;
    }
    return 0;
}

/* Remove the socket file at `path` only if it is still the one this
 * transport bound (a socket with that dev/ino): never a file someone else
 * put there after our bind. */
static void unix_unlink_if_ours(const char *path, uint64_t dev, uint64_t ino) {
    struct stat st;
    if (lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
        (uint64_t)st.st_dev == dev && (uint64_t)st.st_ino == ino)
        unlink(path);
}

_Static_assert(sizeof(((struct sockaddr_un *)0)->sun_path) == NODUS_TCP_UNIX_PATH_MAX,
               "NODUS_TCP_UNIX_PATH_MAX must equal sizeof(sockaddr_un.sun_path)");
#endif /* NODUS_TCP_EPOLL */

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

uint64_t nodus_time_mono_ms(void) {
#ifdef _WIN32
    /* Milliseconds since boot; never goes back, not moved by clock changes. */
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    /* CLOCK_MONOTONIC: an interval measured with it is not moved by a
     * wall-clock step (NTP correction, manual change). Its zero point is
     * arbitrary, so it is only ever compared with another value of itself —
     * never with a nodus_time_now()/nodus_time_now_ms() timestamp. */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

int nodus_tcp_init(nodus_tcp_t *tcp, int shared_epoll_fd) {
    if (!tcp) return -1;
    memset(tcp, 0, sizeof(*tcp));
    tcp->listen_fd = -1;
    tcp->ws_listen_fd = -1;
    tcp->unix_listen_fd = -1;

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
#elif defined(__EMSCRIPTEN__)
    /* No epoll: nodus_tcp_poll walks the pool with poll(). */
    tcp->epoll_fd = -1;
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
#ifndef NODUS_TCP_EPOLL
    (void)tcp; (void)bind_ip; (void)port;
    return -1;  /* Server is Linux-only (not Windows, not the browser) */
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

int nodus_tcp_ws_listen(nodus_tcp_t *tcp, uint16_t port,
                        const nodus_ws_origins_t *origins) {
#ifndef NODUS_TCP_EPOLL
    (void)tcp; (void)port; (void)origins;
    return -1;  /* Server is Linux-only (not Windows, not the browser) */
#else
    if (!tcp || !origins || origins->count <= 0 || tcp->ws_listen_fd >= 0)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    set_reuseaddr(fd);
    set_nonblocking(fd);

    /* Loopback ONLY — deliberately not configurable. The public side and
     * TLS belong to the local proxy; X-Forwarded-For is believed only
     * because nothing but that proxy can reach this socket. */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 128) < 0) {
        close(fd);
        return -1;
    }

    socklen_t slen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &slen) != 0) {
        close(fd);
        return -1;
    }

    /* Level-triggered like the plain listener; the marker is the address
     * of ws_listen_fd, which no connection pointer can equal. */
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &tcp->ws_listen_fd };
    if (epoll_ctl(tcp->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        close(fd);
        return -1;
    }

    tcp->ws_listen_fd = fd;
    tcp->ws_port = ntohs(addr.sin_port);
    tcp->ws_origins = origins;
    return 0;
#endif
}

bool nodus_tcp_unix_peercred_ok(uint32_t peer_uid, uint32_t allowed_uid) {
    /* The unresolved sentinel is no uid: it admits nobody, so a caller that
     * forgot to resolve it fails closed. */
    if (allowed_uid == NODUS_TCP_UNIX_UID_SELF)
        return false;
    return peer_uid == allowed_uid;
}

int nodus_tcp_unix_listen(nodus_tcp_t *tcp, const char *path,
                          uint32_t allowed_uid) {
#ifndef NODUS_TCP_EPOLL
    (void)tcp; (void)path; (void)allowed_uid;
    return -1;  /* Server is Linux-only (not Windows, not the browser) */
#else
    /* unix_path is set only by a successful call: one entry per transport. */
    if (!tcp || !path || tcp->unix_path[0] != '\0')
        return -1;

    struct sockaddr_un sa;
    if (unix_addr_fill(&sa, path) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket path empty or longer than %d bytes",
                      NODUS_TCP_UNIX_PATH_MAX - 1);
        return -1;
    }

    /* The directory first: nothing at the path is looked at, removed or
     * created unless only this uid (or root) can change that directory. */
    if (unix_parent_dir_ok(path) != 0)
        return -1;

    /* Something already at the path. Only a STALE socket file is removed:
     * never a regular file or directory (a mistyped path must not delete
     * data), and never a socket a live listener still serves (that would
     * orphan it — its clients could no longer reach it). */
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (!S_ISSOCK(st.st_mode)) {
            QGP_LOG_ERROR(LOG_TAG_TCP, "unix: %s exists and is not a socket, refusing",
                          path);
            return -1;
        }
        int live = unix_path_probe(&sa);
        if (live != 0) {
            QGP_LOG_ERROR(LOG_TAG_TCP, "unix: %s %s, refusing to replace it", path,
                          live > 0 ? "has a live listener"
                                   : "cannot be probed (errno other than ECONNREFUSED)");
            return -1;
        }
        if (unlink(path) != 0) {
            QGP_LOG_ERROR(LOG_TAG_TCP, "unix: cannot remove stale socket %s (errno=%d)",
                          path, errno);
            return -1;
        }
        QGP_LOG_INFO(LOG_TAG_TCP, "unix: removed stale socket %s", path);
    } else if (errno != ENOENT) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: lstat %s failed (errno=%d)", path, errno);
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    /* 0600 from the moment the file exists: bind() creates the socket file
     * with mode 0777 & ~umask, so umask 0177 yields exactly 0600 — there is
     * no window in which another uid could connect. umask is process-wide:
     * a file another thread creates during these two calls gets the
     * stricter mask too (never a looser one). The result is verified with
     * lstat below; anything other than exactly 0600 is a refusal. There is
     * deliberately no chmod repair: chmod follows a symlink, so a path
     * swapped after bind could make it change some other file's mode. */
    mode_t old_mask = umask(0177);
    int brc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
    int berr = errno;
    umask(old_mask);
    if (brc != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: bind %s failed (errno=%d)", path, berr);
        close(fd);
        return -1;
    }

    /* What is at the path now must be the socket we just bound. If it is
     * not a socket, nothing proves it is ours, so it is left in place. */
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode)) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: %s is not a socket after bind", path);
        close(fd);
        return -1;
    }
    /* From here on every failure removes the file — but only while it is
     * still the socket with the dev/ino recorded right after bind. */
    uint64_t bound_dev = (uint64_t)st.st_dev;
    uint64_t bound_ino = (uint64_t)st.st_ino;
    if ((st.st_mode & 07777) != 0600) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: %s has mode %04o after bind, not 0600, "
                      "refusing", path, (unsigned)(st.st_mode & 07777));
        close(fd);
        unix_unlink_if_ours(path, bound_dev, bound_ino);
        return -1;
    }

    if (listen(fd, 128) != 0 || set_nonblocking(fd) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: listen %s failed (errno=%d)", path, errno);
        close(fd);
        unix_unlink_if_ours(path, bound_dev, bound_ino);
        return -1;
    }

    /* Level-triggered like the other listeners; the marker is the address
     * of unix_listen_fd, which no connection pointer can equal. */
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &tcp->unix_listen_fd };
    if (epoll_ctl(tcp->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: epoll add %s failed (errno=%d)", path, errno);
        close(fd);
        unix_unlink_if_ours(path, bound_dev, bound_ino);
        return -1;
    }

    tcp->unix_listen_fd = fd;
    tcp->unix_allowed_uid = (allowed_uid == NODUS_TCP_UNIX_UID_SELF)
                                ? (uint32_t)geteuid() : allowed_uid;
    snprintf(tcp->unix_path, sizeof(tcp->unix_path), "%s", path);
    tcp->unix_dev = bound_dev;
    tcp->unix_ino = bound_ino;
    QGP_LOG_INFO(LOG_TAG_TCP, "unix: listening on %s (mode 0600, allowed uid=%u)",
                 path, (unsigned)tcp->unix_allowed_uid);
    return 0;
#endif
}

int nodus_tcp_ws_sweep(nodus_tcp_t *tcp, uint64_t now) {
    if (!tcp) return 0;
    int closed = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c || !c->is_ws || c->ws_open) continue;
        /* Unsigned: a clock that stepped backwards reads as expired, the
         * same way the idle sweep treats it — closing an unfinished
         * Upgrade is always safe. */
        if (now - c->connected_at < NODUS_WS_HANDSHAKE_TIMEOUT_S) continue;
        QGP_LOG_WARN(LOG_TAG_TCP, "ws: upgrade not completed within %ds, slot=%d closed",
                     NODUS_WS_HANDSHAKE_TIMEOUT_S, c->slot);
        nodus_tcp_disconnect(tcp, c);
        closed++;
    }
    return closed;
}

/* connect() returned 0 for conn->fd: mark the connection CONNECTED,
 * register it for reading and run on_connect. Returns false if on_connect
 * closed it — the caller then returns NULL. Shared by nodus_tcp_connect
 * (an immediate localhost TCP connect) and nodus_tcp_unix_connect (an
 * AF_UNIX connect always completes at once). */
static bool conn_connected_now(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    conn->state = NODUS_CONN_CONNECTED;
    conn->connected_at = nodus_time_now();
    conn->last_activity = conn->connected_at;
    if (!conn->is_unix) {   /* TCP options; meaningless on AF_UNIX */
        set_keepalive(conn->fd);
        set_nodelay(conn->fd);
    }
#ifdef NODUS_TCP_EPOLL
    epoll_add(tcp->epoll_fd, conn->fd, EPOLLIN | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET), conn);
#endif
    if (tcp->on_connect) {
        /* The callback runs under the deferred-close rule like every
         * other one: if it disconnects this connection, the memory
         * must outlive the check below, and the caller gets NULL
         * instead of a pointer to a closed connection. */
        tcp->poll_depth++;
        tcp->on_connect(conn, tcp->cb_ctx);
        tcp->poll_depth--;
        bool closed = conn->close_pending;
        if (tcp->poll_depth == 0)
            conn_release_deferred(tcp);
        if (closed)
            return false;
    }
    return true;
}

nodus_tcp_conn_t *nodus_tcp_unix_connect(nodus_tcp_t *tcp, const char *path,
                                         uint32_t expected_uid) {
#ifndef NODUS_TCP_EPOLL
    (void)tcp; (void)path; (void)expected_uid;
    return NULL;  /* Unix socket entry is Linux-only */
#else
    if (!tcp || !path) return NULL;

    struct sockaddr_un sa;
    if (unix_addr_fill(&sa, path) != 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "unix: socket path empty or longer than %d bytes",
                      NODUS_TCP_UNIX_PATH_MAX - 1);
        return NULL;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return NULL;
    }

    /* AF_UNIX connect never reports EINPROGRESS: it is done (0) or failed
     * (ENOENT, ECONNREFUSED, EACCES, EAGAIN = backlog full). So it is made
     * before a connection is allocated, and a UDS connection is never in
     * the CONNECTING state. */
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: connect %s failed (errno=%d)", path, errno);
        close(fd);
        return NULL;
    }

    /* The listener checks us; we check the listener. SO_PEERCRED on the
     * dialing fd is the credentials of the process that called listen()
     * on that socket — whoever bound the path, not whoever we meant. Fail
     * closed, before a connection is allocated (on_connect never runs). */
    uint32_t want_uid = (expected_uid == NODUS_TCP_UNIX_UID_SELF)
                            ? (uint32_t)geteuid() : expected_uid;
    struct ucred cr;
    socklen_t cr_len = sizeof(cr);
    memset(&cr, 0, sizeof(cr));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) != 0 ||
        cr_len != sizeof(cr)) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: server credentials at %s unreadable (errno=%d), "
                     "connection refused", path, errno);
        close(fd);
        return NULL;
    }
    if (!nodus_tcp_unix_peercred_ok((uint32_t)cr.uid, want_uid)) {
        QGP_LOG_WARN(LOG_TAG_TCP, "unix: server at %s is uid=%u pid=%d, expected uid=%u, "
                     "connection refused",
                     path, (unsigned)cr.uid, (int)cr.pid, (unsigned)want_uid);
        close(fd);
        return NULL;
    }

    nodus_tcp_conn_t *conn = conn_alloc(tcp);
    if (!conn) { close(fd); return NULL; }

    conn->fd = fd;
    conn->is_unix = true;
    conn->port = 0;
    snprintf(conn->ip, sizeof(conn->ip), "%s", NODUS_TCP_UNIX_PEER_IP);
    /* Same as nodus_tcp_connect: an outbound conn we opened, inheriting the
     * transport's auth requirement before any frame can be queued. */
    conn->auth_initiated_by_us = true;
    conn->auth_required = tcp->auth_required;
    if (tcp->auth_required)
        conn->auth_state = NODUS_CONN_AUTH_NONE;

    QGP_LOG_DEBUG(LOG_TAG_TCP, "unix: connected slot=%d fd=%d path=%s",
                  conn->slot, fd, path);

    if (!conn_connected_now(tcp, conn))
        return NULL;
    return conn;
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
    /* C2 fix: this is an outbound conn — we opened it. Challenge handler will
     * only sign auth responses when this flag is true (closes signing oracle). */
    conn->auth_initiated_by_us = true;

    /* Phase 3.2d: bind fd to slot, log it. */
    fprintf(stderr, "TCP_CONN: FD_SET slot=%d fd=%d direction=connect "
            "peer=%s:%u conn=%p\n",
            conn->slot, fd, ip, (unsigned)port, (void *)conn);

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
        if (!conn_connected_now(tcp, conn))
            return NULL;
    } else if (IS_EINPROGRESS(get_socket_error())) {
        /* Connecting — wait for writable */
#ifdef NODUS_TCP_EPOLL
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
    if (conn_ws_not_open(conn)) return -1;
    size_t frame_size = conn_wire_size(conn, len);

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
    size_t written = conn_wire_encode(conn, conn->pending_buf + conn->pending_len,
                                      conn->pending_cap - conn->pending_len,
                                      payload, len);
    if (written == 0) return -1;
    conn->pending_len += written;
    return 0;
}

static int pending_flush_locked(nodus_tcp_conn_t *conn) {
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

int nodus_tcp_pending_flush(nodus_tcp_conn_t *conn) {
    if (!conn) return -1;
    nodus_tcp_t *tcp = conn->tcp_parent;
    wl_enter(tcp);
    int rc = pending_flush_locked(conn);
    wl_leave(tcp);
    return rc;
}

static int send_progress_locked(nodus_tcp_conn_t *conn,
                                const uint8_t *payload, size_t len,
                                nodus_tcp_progress_cb progress_cb,
                                void *user_data);

int nodus_tcp_send(nodus_tcp_conn_t *conn,
                    const uint8_t *payload, size_t len) {
    if (!conn) return send_progress_locked(conn, payload, len, NULL, NULL);
    nodus_tcp_t *tcp = conn->tcp_parent;
    int rc;
    /* One critical section for the gate and the write, so an auth result
     * cannot land between "still pending" and the append. */
    wl_enter(tcp);
    if (conn->auth_required && conn->auth_state == NODUS_CONN_AUTH_FAILED)
        rc = -1;
    else if (conn->auth_required && conn->auth_state != NODUS_CONN_AUTH_OK)
        rc = pending_queue_append(conn, payload, len);  /* auth in progress */
    else
        rc = send_progress_locked(conn, payload, len, NULL, NULL);
    wl_leave(tcp);
    return rc;
}

int nodus_tcp_send_raw(nodus_tcp_conn_t *conn,
                        const uint8_t *payload, size_t len) {
    return nodus_tcp_send_progress(conn, payload, len, NULL, NULL);
}

int nodus_tcp_send_progress(nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len,
                             nodus_tcp_progress_cb progress_cb,
                             void *user_data) {
    nodus_tcp_t *tcp = conn ? conn->tcp_parent : NULL;
    wl_enter(tcp);
    int rc = send_progress_locked(conn, payload, len, progress_cb, user_data);
    wl_leave(tcp);
    return rc;
}

/* The send path proper; the caller holds the write lock. */
static int send_progress_locked(nodus_tcp_conn_t *conn,
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
    if (conn_ws_not_open(conn)) {
        QGP_LOG_WARN(LOG_TAG_TCP, "send: ws upgrade not complete, slot=%d", conn->slot);
        return -1;
    }

    /* Phase 3.2d: log first send per conn — captures (slot, fd, conn ptr,
     * peer, has_crypto) at the moment data is first written. Compare with
     * INTER_FRAME_FIRST to detect any cross-conn fd alias. */
    if (!conn->first_send_logged) {
        conn->first_send_logged = true;
        /* B3 fix — read inline channel_crypto state. */
        int established = conn->channel_crypto.established ? 1 : 0;
        int has_crypto = established;
        fprintf(stderr,
                "TCP_SEND_FIRST: slot=%d fd=%d peer=%s:%u len=%zu "
                "has_crypto=%d est=%d state=%d auth_state=%d "
                "tcp=%p conn=%p\n",
                conn->slot, conn->fd, conn->ip, (unsigned)conn->port, len,
                has_crypto, established, (int)conn->state,
                (int)conn->auth_state,
                (void *)conn->tcp_parent, (void *)conn);
    }

    /* Encrypt payload if channel crypto is established.
     * B3 fix — read inline channel_crypto, no pointer alias. */
    uint8_t *enc_buf = NULL;
    const uint8_t *send_payload = payload;
    size_t send_len = len;

    {
        nodus_channel_crypto_t *cc = &conn->channel_crypto;
        if (cc->established) {
            /* Phase 3.2b-inv: log the first encrypted send on this conn
             * so we can correlate "sender established crypto" with the
             * matching receiver's conn state at the same moment. */
            if (!conn->tx_encrypt_logged) {
                conn->tx_encrypt_logged = true;
                fprintf(stderr,
                        "TX_ENCRYPT_FIRST slot=%d peer=%s:%u tx_counter=%llu len=%zu\n",
                        conn->slot, conn->ip, (unsigned)conn->port,
                        (unsigned long long)cc->tx_counter, len);
            }
            /* Phase 3.2b-inv2+inv3: milestone encrypt log. First 3 catch
             * fresh handshake; 100/500/1000/2000k milestones catch long-lived
             * conns so we can correlate high tx_counter T1 fails with the
             * actual sender state. */
            if (cc->tx_counter < 3 ||
                cc->tx_counter == 100 || cc->tx_counter == 500 ||
                cc->tx_counter == 1000 || (cc->tx_counter % 2000) == 0) {
                fprintf(stderr,
                        "ENCRYPT_CALL slot=%d peer=%s:%u tx_counter=%llu "
                        "cc=%p conn_crypto=%p len=%zu\n",
                        conn->slot, conn->ip, (unsigned)conn->port,
                        (unsigned long long)cc->tx_counter,
                        (void *)cc, (void *)cc, len);
            }
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

    size_t frame_size = conn_wire_size(conn, send_len);

    /* Compact: reclaim space from already-sent bytes before growing */
    if (conn->wpos > 0) {
        size_t remaining = conn->wlen - conn->wpos;
        if (remaining > 0)
            memmove(conn->wbuf, conn->wbuf + conn->wpos, remaining);
        conn->wlen = remaining;
        conn->wpos = 0;
    }

    size_t needed = conn->wlen + frame_size;

    /* FIFO order preservation: if the pending queue already has frames
     * waiting, this new frame MUST go to the pending tail — not jump
     * ahead via wbuf. Otherwise the receiver sees higher-counter frames
     * before lower-counter ones on the wire and rejects the later
     * arrivals as CH_CRYPTO replays, silently dropping them. This
     * manifests as bursts of "Replay detected: counter=X < expected=Y"
     * with large gaps during media-repl storms. */
    bool force_pending = (conn->pending_count > 0);

    if (force_pending || buf_ensure(&conn->wbuf, &conn->wcap, needed) != 0) {
        /* Phase 3: wbuf can't absorb this frame right now (or pending
         * already has queued frames we must not reorder). Route to the
         * per-conn pending queue instead of dropping. handle_write will
         * drain it later when the socket makes room.
         *
         * If the pending queue is also at its cap, fall back to the
         * tcp-level on_pending_full callback (typically writes to the
         * hint table for persistent off-box queueing). If no callback
         * is installed we preserve legacy behavior: log + drop. */
        bool queue_ok = (conn->pending_count < NODUS_PENDING_MAX_FRAMES) &&
                        (conn->pending_bytes + frame_size <= NODUS_PENDING_MAX_BYTES);
        if (queue_ok) {
            uint8_t *encoded = malloc(frame_size);
            if (encoded) {
                size_t written = conn_wire_encode(conn, encoded, frame_size,
                                                  send_payload, send_len);
                if (written == frame_size &&
                    pending_push_tail(conn, encoded, frame_size) == 0) {
                    conn->send_ok_count++;
                    conn->send_bytes_total += send_len;
#ifdef NODUS_TCP_EPOLL
                    /* Make sure EPOLLOUT is armed so drain kicks in. */
                    nodus_tcp_t *tcp = conn->tcp_parent;
                    if (tcp && tcp->epoll_fd >= 0 && conn->fd >= 0) {
                        uint32_t et = tcp->level_triggered ? 0 : EPOLLET;
                        uint32_t ev = EPOLLIN | EPOLLOUT | EPOLLRDHUP | et;
                        epoll_mod(tcp->epoll_fd, conn->fd, ev, conn);
                    }
#endif
                    free(enc_buf);
                    return 0;
                }
                free(encoded);
            }
            /* malloc / encode / push failure — fall through to callback path */
        }

        /* Queue is full (or allocation failed) — last resort fallback. */
        nodus_tcp_t *tcp = conn->tcp_parent;
        if (tcp && tcp->on_pending_full) {
            tcp->on_pending_full(conn, payload, len, tcp->pending_full_ctx);
            conn->pending_hint_fallback_count++;
            free(enc_buf);
            return 0;
        }

        /* No callback — legacy drop with diagnostic log. */
        char head[33] = {0};
        size_t hlen = len < 16 ? len : 16;
        for (size_t i = 0; i < hlen; i++)
            snprintf(head + i * 2, 3, "%02x", payload[i]);
        QGP_LOG_ERROR(LOG_TAG_TCP,
                      "send: buf_ensure failed (needed=%zu wcap=%zu wlen=%zu wpos=%zu) "
                      "peer=%s:%u slot=%d payload_len=%zu head=%s pending=%zu/%zu",
                      needed, conn->wcap, conn->wlen, conn->wpos,
                      conn->ip, (unsigned)conn->port, conn->slot, len, head,
                      conn->pending_count, conn->pending_bytes);
        conn->send_full_count++;
        free(enc_buf);
        return -1;
    }

    /* Write frame directly into write buffer */
    size_t written = conn_wire_encode(conn, conn->wbuf + conn->wlen,
                                      conn->wcap - conn->wlen,
                                      send_payload, send_len);
    if (written == 0) {
        QGP_LOG_ERROR(LOG_TAG_TCP, "send: frame_encode failed (len=%zu)", send_len);
        free(enc_buf);
        return -1;
    }
    conn->wlen += written;
    conn->send_ok_count++;
    conn->send_bytes_total += send_len;
    free(enc_buf);  /* NULL-safe */

    /* Try immediate send.
     *
     * O15B §8 — this loop used to `break` on EVERY non-positive result and
     * then `return 0`. A peer that had already closed therefore produced
     * "send succeeded" at this API, and the caller went on to wait for a
     * response that could never arrive: on the submit path that is a 60 s
     * NODUS_ERR_TIMEOUT reported for a write that demonstrably failed.
     * EAGAIN genuinely IS success-so-far (the bytes are buffered and the
     * poll loop will flush them); a peer-gone or fatal error is not.
     *
     * The connection is NOT freed here. This function is public API and its
     * callers hold `conn` across the call — nodus_client.c's send_request
     * keeps `client->conn` — so freeing it here would hand every caller a
     * dangling pointer. Teardown stays with the poll loop, which will reach
     * the same error and run on_disconnect exactly once.
     */
    ntcp_io_t io = conn_flush_wbuf(conn, progress_cb, user_data);

    if (conn->wpos >= conn->wlen) {
        conn->wpos = 0;
        conn->wlen = 0;
    }

    if (io == NTCP_IO_PROGRESS || io == NTCP_IO_WOULDBLOCK)
        return 0;

    conn->send_error_count++;
    QGP_LOG_WARN(LOG_TAG_TCP,
                 "send: write failed peer=%s:%u slot=%d class=%d "
                 "(%zu of %zu bytes accepted)",
                 conn->ip, (unsigned)conn->port, conn->slot, (int)io,
                 conn->wpos, conn->wlen);
    return -1;
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
            if (conn_has_unsent(tcp, c))
                FD_SET((SOCKET)c->fd, &wfds);
        }
        if (c->fd > max_fd) max_fd = c->fd;
    }

    if (max_fd < 0) {
        /* No connections — just sleep. (The pending-read list holds only
         * pool members, so it is empty here.) */
        if (timeout_ms > 0) Sleep(timeout_ms);
        return 0;
    }

    /* Read budget: leftover input from an earlier call — do not sleep
     * (see the epoll variant below). */
    if (tcp->read_head)
        timeout_ms = 0;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int n = select(max_fd + 1, &rfds, &wfds, &efds,
                   timeout_ms >= 0 ? &tv : NULL);
    if (n < 0) return n;
    if (n == 0 && !tcp->read_head) return 0;

    /* Deferred close: nothing closed during this batch is freed before it
     * ends (see the epoll variant below). */
    tcp->poll_depth++;
    uint64_t saved_gen = poll_gen_enter(tcp);

    int events = 0;
    for (int i = 0; n > 0 && i < NODUS_TCP_MAX_CONNS; i++) {
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
            /* conn may have been closed (and the slot refilled) */
            if (tcp->pool[i] != c) continue;
        }

        if (FD_ISSET((SOCKET)c->fd, &rfds)) {
            handle_read(tcp, c);
            events++;
        }
    }

    events += read_pending_service(tcp);
    poll_gen_leave(tcp, saved_gen);

    tcp->poll_depth--;
    if (tcp->poll_depth == 0)
        conn_release_deferred(tcp);

    return events;
}

#elif defined(__EMSCRIPTEN__)

/* Browser build (web wallet, design 2026-09-25 rev 2 §0a.3 (c1)): poll()
 * over the pool, level-triggered, client connections only (no listen
 * socket exists in this build). Same per-connection work as the select()
 * loop above: a CONNECTING socket completes on POLLOUT/POLLERR/POLLHUP via
 * handle_connect_complete (SO_ERROR), a connected one flushes wbuf on
 * POLLOUT and reads on POLLIN/POLLHUP/POLLERR (the read reports EOF or the
 * error and tears the connection down exactly once).
 *
 * poll() is always called with timeout 0 and timeout_ms is not slept here:
 * the browser has one thread, a blocking wait would freeze the page, and
 * Emscripten's poll() does not wait anyway (spike 2026-09-25 S0). The WAIT
 * belongs to the caller, which yields to the browser event loop between
 * calls (emscripten_sleep in nodus_client.c) — without that yield SOCKFS
 * never delivers bytes. */
int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms) {
    if (!tcp) return -1;
    (void)timeout_ms;

    int live = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (tcp->pool[i] && tcp->pool[i]->fd >= 0) live++;
    if (live == 0)
        return 0;   /* the pending-read list holds only pool members */

    /* Heap, not stack: the Asyncify stack is small, and a callback may
     * call nodus_tcp_poll again (nested), so no static buffer either. */
    struct pollfd *pfd = calloc((size_t)live, sizeof(*pfd));
    nodus_tcp_conn_t **pconn = calloc((size_t)live, sizeof(*pconn));
    if (!pfd || !pconn) {
        free(pfd);
        free(pconn);
        return -1;
    }

    int k = 0;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS && k < live; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (!c || c->fd < 0) continue;
        pfd[k].fd = c->fd;
        if (c->state == NODUS_CONN_CONNECTING)
            pfd[k].events = POLLOUT;
        else
            pfd[k].events = (short)(POLLIN | (conn_has_unsent(tcp, c) ? POLLOUT : 0));
        pconn[k] = c;
        k++;
    }

    int n = poll(pfd, (nfds_t)k, 0);
    if (n < 0) {
        if (errno != EINTR) {
            free(pfd);
            free(pconn);
            return -1;
        }
        /* interrupted: no socket events, still service the pending reads */
        for (int j = 0; j < k; j++) pfd[j].revents = 0;
        n = 0;
    }
    if (n == 0 && !tcp->read_head) {
        free(pfd);
        free(pconn);
        return 0;
    }

    /* Deferred close: nothing closed during this batch is freed before it
     * ends, so a pconn[] pointer can be compared against the pool safely. */
    tcp->poll_depth++;
    uint64_t saved_gen = poll_gen_enter(tcp);

    int events = 0;
    for (int j = 0; j < k; j++) {
        short re = pfd[j].revents;
        nodus_tcp_conn_t *c = pconn[j];
        if (re == 0) continue;
        if (!conn_in_pool(tcp, c)) continue;   /* closed earlier in this batch */

        if (c->state == NODUS_CONN_CONNECTING) {
            if (re & (POLLOUT | POLLERR | POLLHUP)) {
                handle_connect_complete(tcp, c);
                events++;
            }
            continue;
        }

        if (re & POLLOUT) {
            handle_write(tcp, c);
            events++;
            if (!conn_in_pool(tcp, c)) continue;   /* closed on write error */
        }

        if (re & (POLLIN | POLLHUP | POLLERR)) {
            handle_read(tcp, c);
            events++;
        }
    }

    events += read_pending_service(tcp);
    poll_gen_leave(tcp, saved_gen);

    tcp->poll_depth--;
    if (tcp->poll_depth == 0)
        conn_release_deferred(tcp);

    free(pfd);
    free(pconn);
    return events;
}

#else /* Linux/Android: epoll */

int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms) {
    if (!tcp) return -1;

    /* Re-enable EPOLLOUT for connections with pending writes */
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        if (c && c->state == NODUS_CONN_CONNECTED && conn_has_unsent(tcp, c)) {
            uint32_t ev = EPOLLIN | EPOLLOUT | EPOLLRDHUP | (tcp->level_triggered ? 0 : EPOLLET);
            epoll_mod(tcp->epoll_fd, c->fd, ev, c);
        }
    }

    /* Read budget: input left over from an earlier call is waiting in user
     * space or in a socket whose edge was already consumed — do not sleep. */
    if (tcp->read_head)
        timeout_ms = 0;

    struct epoll_event events[MAX_EVENTS];
    int n = epoll_wait(tcp->epoll_fd, events, MAX_EVENTS, timeout_ms);
    if (n < 0) {
        if (errno != EINTR) return -1;
        if (!tcp->read_head) return 0;
        n = 0;                 /* interrupted: still service the pending reads */
    }

    /* Deferred close: from here until the depth drops back, no connection
     * memory is released (conn_free parks it on close_list). */
    tcp->poll_depth++;
    uint64_t saved_gen = poll_gen_enter(tcp);

    for (int i = 0; i < n; i++) {
        nodus_tcp_conn_t *conn = events[i].data.ptr;

        if (conn == NULL) {
            /* Listen socket */
            handle_accept(tcp);
            continue;
        }
        if ((void *)conn == (void *)&tcp->ws_listen_fd) {
            /* WebSocket listen socket (marker set in nodus_tcp_ws_listen);
             * not a connection — must not be dereferenced as one. */
            handle_accept_ws(tcp);
            continue;
        }
        if ((void *)conn == (void *)&tcp->unix_listen_fd) {
            /* Unix socket listener (marker set in nodus_tcp_unix_listen);
             * not a connection — must not be dereferenced as one. */
            handle_accept_unix(tcp);
            continue;
        }

        /* Skip a connection an earlier event of this batch closed (a
         * callback's nodus_tcp_disconnect, or a transport teardown). The
         * pointer is compared against the pool without dereferencing it;
         * it cannot have been handed to a new connection meanwhile, because
         * nothing closed during the batch is freed before it ends. */
        if (!conn_in_pool(tcp, conn))
            continue;

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

        int slot = conn->slot;

        if (events[i].events & EPOLLOUT)
            handle_write(tcp, conn);

        /* handle_write() may have closed conn on write error (and its
         * on_disconnect may have opened a new connection in the same slot),
         * so test identity, not emptiness, before any further work. */
        if (tcp->pool[slot] != conn)
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

    /* Read budget: connections left over from earlier calls, after this
     * call's own events. Inside the depth window, so a close made here is
     * deferred like any other. */
    int served = read_pending_service(tcp);

    poll_gen_leave(tcp, saved_gen);

    /* End of the batch: the safe point for everything closed during it. */
    tcp->poll_depth--;
    if (tcp->poll_depth == 0)
        conn_release_deferred(tcp);

    return n + served;
}

#endif /* _WIN32 / __EMSCRIPTEN__ / epoll */

/* ── Shared public API ───────────────────────────────────────────── */

void nodus_tcp_disconnect(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn) {
    if (!tcp || !conn) return;
    /* Already closed earlier in this poll batch: on_disconnect has run once
     * and must not run again. (Outside a batch a closed conn is freed, so
     * a caller cannot legitimately hold one there.) */
    if (conn->close_pending) return;
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

bool nodus_tcp_read_pending(const nodus_tcp_t *tcp) {
    return tcp && tcp->read_head != NULL;
}

uint64_t nodus_tcp_decrypt_fail_total(const nodus_tcp_t *tcp) {
    if (!tcp) return 0;
    /* Freed conns already folded their count into decrypt_fail_total (conn_free);
     * add what the still-live conns are carrying. */
    uint64_t total = tcp->decrypt_fail_total;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        if (tcp->pool[i]) total += tcp->pool[i]->decrypt_skip_count;
    return total;
}

nodus_tcp_conn_t *nodus_tcp_find_by_addr(nodus_tcp_t *tcp,
                                          const char *ip, uint16_t port) {
    if (!tcp || !ip) return NULL;
    /* Phase 3.2b-inv3: duplicate conn detector. If pool holds more than
     * one conn with the same (ip, port) pair we return the first match
     * (legacy behavior) but also emit a warning. Hypothesis under test:
     * T1 decode fail on receiver is caused by sender picking a stale
     * conn while a fresh handshake already exists on a different slot. */
    nodus_tcp_conn_t *first = NULL;
    int match_count = 0;
    int second_slot = -1;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = tcp->pool[i];
        /* An AF_UNIX conn carries the placeholder NODUS_TCP_UNIX_PEER_IP /
         * port 0 — it is never a network peer, whatever the caller asks. */
        if (c && !c->is_unix && c->port == port && strcmp(c->ip, ip) == 0) {
            if (!first) first = c;
            else if (second_slot < 0) second_slot = c->slot;
            match_count++;
        }
    }
    if (match_count > 1) {
        fprintf(stderr,
                "FIND_DUP: %s:%u matches=%d first_slot=%d second_slot=%d\n",
                ip, (unsigned)port, match_count,
                first ? first->slot : -1, second_slot);
    }
    return first;
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
    /* Called outside a poll, this releases everything at once. Called from
     * inside a callback, the parked connections are released when the
     * outermost poll returns, so the transport struct must outlive it. */
    if (tcp->poll_depth == 0)
        conn_release_deferred(tcp);

    if (tcp->listen_fd >= 0) {
#ifdef NODUS_TCP_EPOLL
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, tcp->listen_fd, NULL);
#endif
        close(tcp->listen_fd);
        tcp->listen_fd = -1;
    }

    if (tcp->ws_listen_fd >= 0) {
#ifdef NODUS_TCP_EPOLL
        epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, tcp->ws_listen_fd, NULL);
#endif
        close(tcp->ws_listen_fd);
        tcp->ws_listen_fd = -1;
    }

#ifdef NODUS_TCP_EPOLL
    /* unix_path is set only by a successful nodus_tcp_unix_listen, so a
     * transport that never opened the Unix entry closes nothing here. */
    if (tcp->unix_path[0] != '\0') {
        if (tcp->unix_listen_fd >= 0) {
            epoll_ctl(tcp->epoll_fd, EPOLL_CTL_DEL, tcp->unix_listen_fd, NULL);
            close(tcp->unix_listen_fd);
        }
        tcp->unix_listen_fd = -1;
        /* Remove the socket file only if it is still the one we bound: a
         * later process may have replaced a file it found stale. */
        unix_unlink_if_ours(tcp->unix_path, tcp->unix_dev, tcp->unix_ino);
        tcp->unix_path[0] = '\0';
    }
#endif

#ifdef NODUS_TCP_EPOLL
    if (tcp->owns_epoll && tcp->epoll_fd >= 0) {
        close(tcp->epoll_fd);
        tcp->epoll_fd = -1;
    }
#endif
}
