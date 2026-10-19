/**
 * @file nodus/src/net/nodus_net_poll.c
 * @brief Socket readiness backends (epoll / select) and socket shims.
 *        Contract: nodus_net_poll.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

/* Windows: the select set holds up to NODUS_NET_POLL_WIN_CAPACITY sockets.
 * Winsock's fd_set is { fd_count; SOCKET fd_array[FD_SETSIZE] } with a
 * default FD_SETSIZE of 64, so it must be grown BEFORE <winsock2.h> — the
 * documented Winsock way, as nodus_tcp.c:9-23 does. fd_set never leaves
 * this file (the header carries none), so no other TU is affected. The
 * capacity is checked below once both constants are visible. */
#if defined(_WIN32) && !defined(FD_SETSIZE)
  #define FD_SETSIZE 1026
#endif

/* Windows: SRWLOCK (the Winsock startup lock below) needs Vista (0x0600)
 * or later from the SDK headers; set before any windows / winsock include.
 * A build that already sets a higher _WIN32_WINNT keeps its own value. */
#if defined(_WIN32) && !defined(_WIN32_WINNT)
  #define _WIN32_WINNT 0x0600
#endif

#ifdef __EMSCRIPTEN__
  #error "nodus_net_poll: the browser arm is package N2 (nodus_tcp keeps its own poll loop until then)"
#endif

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#else
  #include <errno.h>
  #include <fcntl.h>
  #include <poll.h>
  #include <sys/epoll.h>
  #include <sys/eventfd.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include "net/nodus_net_poll.h"

#include "crypto/utils/qgp_log.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NODUS_NET"

#ifndef _WIN32
/* ══ Linux / Android: epoll ═══════════════════════════════════════════ */

/* The NODUS_NET_* bits ARE the EPOLL* bits: a caller's mask reaches
 * epoll_ctl unchanged and a result reaches the caller unchanged. */
_Static_assert(NODUS_NET_IN    == (uint32_t)EPOLLIN,    "NODUS_NET_IN != EPOLLIN");
_Static_assert(NODUS_NET_OUT   == (uint32_t)EPOLLOUT,   "NODUS_NET_OUT != EPOLLOUT");
_Static_assert(NODUS_NET_ERR   == (uint32_t)EPOLLERR,   "NODUS_NET_ERR != EPOLLERR");
_Static_assert(NODUS_NET_HUP   == (uint32_t)EPOLLHUP,   "NODUS_NET_HUP != EPOLLHUP");
_Static_assert(NODUS_NET_RDHUP == (uint32_t)EPOLLRDHUP, "NODUS_NET_RDHUP != EPOLLRDHUP");
_Static_assert(NODUS_NET_EDGE  == (uint32_t)EPOLLET,    "NODUS_NET_EDGE != EPOLLET");
/* NODUS_NET_CONNECT is no epoll bit (it is removed before epoll_ctl). */
_Static_assert((NODUS_NET_CONNECT & ((uint32_t)EPOLLIN | (uint32_t)EPOLLPRI |
                (uint32_t)EPOLLOUT | (uint32_t)EPOLLERR | (uint32_t)EPOLLHUP |
                (uint32_t)EPOLLRDNORM | (uint32_t)EPOLLRDBAND |
                (uint32_t)EPOLLWRNORM | (uint32_t)EPOLLWRBAND |
                (uint32_t)EPOLLMSG | (uint32_t)EPOLLRDHUP |
                (uint32_t)EPOLLEXCLUSIVE | (uint32_t)EPOLLWAKEUP |
                (uint32_t)EPOLLONESHOT | (uint32_t)EPOLLET)) == 0,
               "NODUS_NET_CONNECT collides with an epoll bit");

#define NET_RESULT_BITS (NODUS_NET_IN | NODUS_NET_OUT | NODUS_NET_ERR | \
                         NODUS_NET_HUP | NODUS_NET_RDHUP)

int nodus_net_poll_init(nodus_net_poll_t *p, bool with_wake)
{
    if (p == NULL) {
        return -1;
    }
    p->wake_fd = -1;
    p->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (p->epfd < 0) {
        return -1;
    }
    if (with_wake) {
        struct epoll_event ev;

        p->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (p->wake_fd < 0) {
            close(p->epfd);
            p->epfd = -1;
            return -1;
        }
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.u64 = NODUS_NET_TAG_WAKE;
        if (epoll_ctl(p->epfd, EPOLL_CTL_ADD, p->wake_fd, &ev) != 0) {
            close(p->wake_fd);
            close(p->epfd);
            p->wake_fd = -1;
            p->epfd = -1;
            return -1;
        }
    }
    return 0;
}

void nodus_net_poll_free(nodus_net_poll_t *p)
{
    if (p == NULL) {
        return;
    }
    if (p->wake_fd >= 0) {
        close(p->wake_fd);
    }
    if (p->epfd >= 0) {
        close(p->epfd);
    }
    p->wake_fd = -1;
    p->epfd = -1;
}

bool nodus_net_poll_is_open(const nodus_net_poll_t *p)
{
    return p != NULL && p->epfd >= 0;
}

static int net_ctl(nodus_net_poll_t *p, int op, nodus_sock_t s, uint64_t tag,
                   uint32_t mask)
{
    struct epoll_event ev;

    if (p == NULL || tag == NODUS_NET_TAG_WAKE) {
        errno = EINVAL;
        return -1;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = mask & ~NODUS_NET_CONNECT;
    ev.data.u64 = tag;
    return epoll_ctl(p->epfd, op, s, &ev);
}

int nodus_net_poll_add(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                       uint32_t mask)
{
    return net_ctl(p, EPOLL_CTL_ADD, s, tag, mask);
}

int nodus_net_poll_mod(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                       uint32_t mask)
{
    return net_ctl(p, EPOLL_CTL_MOD, s, tag, mask);
}

int nodus_net_poll_del(nodus_net_poll_t *p, nodus_sock_t s)
{
    if (p == NULL) {
        errno = EINVAL;
        return -1;
    }
    return epoll_ctl(p->epfd, EPOLL_CTL_DEL, s, NULL);
}

int nodus_net_poll_wait(nodus_net_poll_t *p, int timeout_ms,
                        nodus_net_event_t *out, int cap)
{
    struct epoll_event evs[NODUS_NET_POLL_MAX_BATCH];
    int n, i, k = 0;

    if (p == NULL || out == NULL || cap <= 0 || cap > NODUS_NET_POLL_MAX_BATCH) {
        errno = EINVAL;
        return -1;
    }
    n = epoll_wait(p->epfd, evs, cap, timeout_ms);
    for (i = 0; i < n; i++) {
        if (evs[i].data.u64 == NODUS_NET_TAG_WAKE) {
            uint64_t v;

            while (read(p->wake_fd, &v, sizeof(v)) == (ssize_t)sizeof(v)) {
                /* drained */
            }
            continue;
        }
        out[k].tag = evs[i].data.u64;
        out[k].ready = evs[i].events & NET_RESULT_BITS;
        k++;
    }
    return n < 0 ? -1 : k;
}

void nodus_net_poll_wake(nodus_net_poll_t *p)
{
    uint64_t one = 1;

    if (p != NULL && p->wake_fd >= 0) {
        (void)!write(p->wake_fd, &one, sizeof(one));
    }
}

int nodus_net_probe_connect(nodus_sock_t s)
{
    struct pollfd pfd;

    pfd.fd = s;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    return poll(&pfd, 1, 0);
}

/* ── socket shims ──────────────────────────────────────────────────── */

int nodus_net_startup(void)
{
    return 0;
}

void nodus_net_cleanup(void)
{
}

nodus_sock_t nodus_net_socket(int family, int type)
{
    return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

nodus_sock_t nodus_net_accept(nodus_sock_t l, struct sockaddr *sa,
                              nodus_socklen_t *sl)
{
    return accept(l, sa, sl);
}

int nodus_net_set_nonblocking(nodus_sock_t s)
{
    int flags = fcntl(s, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(s, F_SETFL, flags | O_NONBLOCK);
}

int nodus_net_set_cloexec(nodus_sock_t s)
{
    return fcntl(s, F_SETFD, FD_CLOEXEC);
}

long nodus_net_send(nodus_sock_t s, const void *b, size_t len)
{
    return (long)send(s, b, len, MSG_NOSIGNAL);
}

long nodus_net_recv(nodus_sock_t s, void *b, size_t len)
{
    return (long)recv(s, b, len, 0);
}

int nodus_net_close(nodus_sock_t s)
{
    int e = errno, rc = close(s);

    errno = e;
    return rc;
}

int nodus_net_errno(void)
{
    return errno;
}

#else
/* ══ Windows: select ══════════════════════════════════════════════════ */

_Static_assert(FD_SETSIZE >= NODUS_NET_POLL_WIN_CAPACITY,
               "FD_SETSIZE smaller than the select set's capacity");
_Static_assert(NODUS_NET_POLL_WIN_CAPACITY >= 1026,
               "capacity below the nodus_tcp pool (1024) + listener + wake");
_Static_assert(sizeof(nodus_sock_t) == sizeof(SOCKET),
               "nodus_sock_t is not Winsock's SOCKET");
_Static_assert(NODUS_SOCK_INVALID == INVALID_SOCKET,
               "NODUS_SOCK_INVALID != INVALID_SOCKET");
_Static_assert(sizeof(nodus_socklen_t) == sizeof(socklen_t),
               "nodus_socklen_t is not Winsock's socklen_t");

typedef struct {
    SOCKET   s;
    uint64_t tag;
    uint32_t mask;
} net_entry_t;

struct nodus_net_poll_win {
    net_entry_t e[NODUS_NET_POLL_WIN_CAPACITY];
    int         n;                       /* registration order, no holes */
    int         next;                    /* where the next _wait's scan
                                          * starts: just past the entry the
                                          * last _wait reported last; always
                                          * 0 <= next < n, or 0 when n == 0 */
    SOCKET      wake_rd;                 /* in the read set, or INVALID   */
    SOCKET      wake_wr;                 /* written by _wake              */
};

/* ── Winsock startup (R7) ──────────────────────────────────────────── */

static SRWLOCK  g_wsa_lock = SRWLOCK_INIT;
static unsigned g_wsa_refs;

int nodus_net_startup(void)
{
    int rc = 0;

    AcquireSRWLockExclusive(&g_wsa_lock);
    if (g_wsa_refs == 0) {
        WSADATA d;
        int w = WSAStartup(MAKEWORD(2, 2), &d);

        /* WSAStartup returns its error instead of setting the thread's
         * last error; it is stored with WSASetLastError so that
         * nodus_net_errno() carries it. Whether WSASetLastError is honoured
         * before a successful WSAStartup is NOT verified against the
         * Microsoft documentation either way. */
        if (w != 0) {
            QGP_LOG_ERROR(LOG_TAG, "WSAStartup failed: %d", w);
            rc = w;
        } else if (LOBYTE(d.wVersion) != 2 || HIBYTE(d.wVersion) != 2) {
            QGP_LOG_ERROR(LOG_TAG, "Winsock 2.2 not available (got %u.%u)",
                          (unsigned)LOBYTE(d.wVersion),
                          (unsigned)HIBYTE(d.wVersion));
            WSACleanup();
            rc = WSAVERNOTSUPPORTED;
        }
    }
    if (rc == 0) {
        g_wsa_refs++;
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);
    if (rc != 0) {
        WSASetLastError(rc);
        return -1;
    }
    return 0;
}

void nodus_net_cleanup(void)
{
    AcquireSRWLockExclusive(&g_wsa_lock);
    if (g_wsa_refs > 0) {
        g_wsa_refs--;
        if (g_wsa_refs == 0) {
            WSACleanup();
        }
    }
    ReleaseSRWLockExclusive(&g_wsa_lock);
}

/* ── socket shims ──────────────────────────────────────────────────── */

int nodus_net_set_nonblocking(nodus_sock_t s)
{
    u_long mode = 1;

    return ioctlsocket((SOCKET)s, FIONBIO, &mode) == 0 ? 0 : -1;
}

int nodus_net_set_cloexec(nodus_sock_t s)
{
    return SetHandleInformation((HANDLE)(uintptr_t)s, HANDLE_FLAG_INHERIT, 0)
               ? 0 : -1;
}

/* Clear HANDLE_FLAG_INHERIT on a socket this file creates. A failure is
 * logged and the socket is kept: whether SetHandleInformation can fail on
 * a fresh Winsock handle (e.g. under a layered service provider), and
 * whether such a socket is then inherited, is NOT verified against the
 * Microsoft documentation either way — so it is neither a hard failure
 * nor silent. The thread's last error is kept as it was. */
static void net_no_inherit(SOCKET s, const char *what)
{
    int e = WSAGetLastError();

    if (nodus_net_set_cloexec((nodus_sock_t)s) != 0) {
        QGP_LOG_WARN(LOG_TAG, "%s: cannot clear HANDLE_FLAG_INHERIT (%lu); "
                     "kept", what, (unsigned long)GetLastError());
    }
    WSASetLastError(e);
}

nodus_sock_t nodus_net_socket(int family, int type)
{
    SOCKET s = socket(family, type, 0);

    if (s == INVALID_SOCKET) {
        return NODUS_SOCK_INVALID;
    }
    if (nodus_net_set_nonblocking((nodus_sock_t)s) != 0) {
        int e = WSAGetLastError();

        closesocket(s);
        WSASetLastError(e);
        return NODUS_SOCK_INVALID;
    }
    net_no_inherit(s, "socket");
    return (nodus_sock_t)s;
}

nodus_sock_t nodus_net_accept(nodus_sock_t l, struct sockaddr *sa,
                              nodus_socklen_t *sl)
{
    return (nodus_sock_t)accept((SOCKET)l, sa, sl);
}

long nodus_net_send(nodus_sock_t s, const void *b, size_t len)
{
    int n = len > (size_t)INT_MAX ? INT_MAX : (int)len;
    int r = send((SOCKET)s, (const char *)b, n, 0);

    return r == SOCKET_ERROR ? -1 : (long)r;
}

long nodus_net_recv(nodus_sock_t s, void *b, size_t len)
{
    int n = len > (size_t)INT_MAX ? INT_MAX : (int)len;
    int r = recv((SOCKET)s, (char *)b, n, 0);

    return r == SOCKET_ERROR ? -1 : (long)r;
}

int nodus_net_close(nodus_sock_t s)
{
    int e = WSAGetLastError();
    int rc = closesocket((SOCKET)s) == 0 ? 0 : -1;

    WSASetLastError(e);
    return rc;
}

int nodus_net_errno(void)
{
    return WSAGetLastError();
}

/* ── the wake: a loopback TCP pair ─────────────────────────────────── */

/* listen(127.0.0.1:0) → connect → accept → close the listener.
 *  · The listener is bound SO_EXCLUSIVEADDRUSE, so no other socket can
 *    bind the same address and port while it exists.
 *  · The connect is blocking: when it returns 0 the handshake is complete
 *    and the connection is queued on the listener. The accept then runs
 *    with the listener NON-blocking — it either takes the queued
 *    connection at once or fails; any failure, WOULDBLOCK included, fails
 *    closed (no wait, no timeout).
 *  · The accepted end must be OUR connector (another local process could
 *    reach the ephemeral listener first): its peer address is compared
 *    with the connector's own address, and a mismatch fails closed.
 *  · Every socket here is made non-inheritable (net_no_inherit).
 * On failure the thread's last error holds the cause, logged once. */
static int wake_pair(SOCKET *rd, SOCKET *wr)
{
    struct sockaddr_in a, mine, peer;
    int al = (int)sizeof(a), ml = (int)sizeof(mine), pl = (int)sizeof(peer);
    SOCKET l = INVALID_SOCKET, c = INVALID_SOCKET, r = INVALID_SOCKET;
    BOOL one = TRUE, excl = TRUE;
    u_long nb = 1;
    const char *why;
    int err;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    why = "listener socket";
    l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET) {
        goto fail_wsa;
    }
    net_no_inherit(l, "wake listener");
    why = "listener SO_EXCLUSIVEADDRUSE";
    if (setsockopt(l, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&excl,
                   (int)sizeof(excl)) != 0) {
        goto fail_wsa;
    }
    why = "listener bind / listen / getsockname";
    if (bind(l, (struct sockaddr *)&a, (int)sizeof(a)) != 0 ||
        listen(l, 1) != 0 ||
        getsockname(l, (struct sockaddr *)&a, &al) != 0) {
        goto fail_wsa;
    }
    why = "loopback connect";
    c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c == INVALID_SOCKET) {
        goto fail_wsa;
    }
    net_no_inherit(c, "wake writer");
    if (connect(c, (struct sockaddr *)&a, (int)sizeof(a)) != 0) {
        goto fail_wsa;
    }
    why = "non-blocking accept of the queued connection";
    if (ioctlsocket(l, FIONBIO, &nb) != 0) {
        goto fail_wsa;
    }
    r = accept(l, (struct sockaddr *)&peer, &pl);
    if (r == INVALID_SOCKET) {
        goto fail_wsa;
    }
    net_no_inherit(r, "wake reader");
    why = "connector getsockname";
    if (getsockname(c, (struct sockaddr *)&mine, &ml) != 0) {
        goto fail_wsa;
    }
    if (peer.sin_family != AF_INET || mine.sin_family != AF_INET ||
        peer.sin_port != mine.sin_port ||
        peer.sin_addr.s_addr != mine.sin_addr.s_addr) {
        why = "the accepted end is not ours";
        /* No Winsock call failed here: WSAEACCES is CHOSEN as the closest
         * "not permitted" code, so that nodus_net_errno() is not stale. */
        err = WSAEACCES;
        goto fail;
    }
    closesocket(l);
    l = INVALID_SOCKET;
    (void)setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one,
                     (int)sizeof(one));
    why = "FIONBIO on the pair";
    if (nodus_net_set_nonblocking((nodus_sock_t)r) != 0 ||
        nodus_net_set_nonblocking((nodus_sock_t)c) != 0) {
        goto fail_wsa;
    }
    *rd = r;
    *wr = c;
    return 0;

fail_wsa:
    err = WSAGetLastError();
fail:
    QGP_LOG_ERROR(LOG_TAG, "wake pair cannot be built: %s (%d)", why, err);
    if (r != INVALID_SOCKET) {
        closesocket(r);
    }
    if (c != INVALID_SOCKET) {
        closesocket(c);
    }
    if (l != INVALID_SOCKET) {
        closesocket(l);
    }
    WSASetLastError(err);
    return -1;
}

/* ── the set ───────────────────────────────────────────────────────── */

int nodus_net_poll_init(nodus_net_poll_t *p, bool with_wake)
{
    struct nodus_net_poll_win *w;

    int e;

    if (p == NULL) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    p->w = NULL;
    if (nodus_net_startup() != 0) {
        return -1;                       /* last error set by startup */
    }
    w = (struct nodus_net_poll_win *)calloc(1, sizeof(*w));
    if (w == NULL) {
        nodus_net_cleanup();
        WSASetLastError(WSAENOBUFS);
        return -1;
    }
    w->wake_rd = INVALID_SOCKET;
    w->wake_wr = INVALID_SOCKET;
    if (with_wake && wake_pair(&w->wake_rd, &w->wake_wr) != 0) {
        e = WSAGetLastError();           /* WSACleanup may overwrite it */
        free(w);
        nodus_net_cleanup();
        WSASetLastError(e);
        return -1;
    }
    p->w = w;
    return 0;
}

void nodus_net_poll_free(nodus_net_poll_t *p)
{
    if (p == NULL || p->w == NULL) {
        return;
    }
    if (p->w->wake_rd != INVALID_SOCKET) {
        closesocket(p->w->wake_rd);
    }
    if (p->w->wake_wr != INVALID_SOCKET) {
        closesocket(p->w->wake_wr);
    }
    free(p->w);
    p->w = NULL;
    nodus_net_cleanup();
}

bool nodus_net_poll_is_open(const nodus_net_poll_t *p)
{
    return p != NULL && p->w != NULL;
}

static int net_find(const struct nodus_net_poll_win *w, SOCKET s)
{
    int i;

    for (i = 0; i < w->n; i++) {
        if (w->e[i].s == s) {
            return i;
        }
    }
    return -1;
}

/* Remove entry i, keeping registration order. The scan cursor keeps
 * pointing at the same next entry: an entry removed before it shifts it
 * down by one; a cursor left at or past the end wraps to 0. Both _del and
 * the WSAENOTSOCK eviction go through here. */
static void net_remove(struct nodus_net_poll_win *w, int i)
{
    memmove(&w->e[i], &w->e[i + 1], (size_t)(w->n - i - 1) * sizeof(w->e[0]));
    w->n--;
    if (i < w->next) {
        w->next--;
    }
    if (w->next >= w->n) {
        w->next = 0;
    }
}

int nodus_net_poll_add(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                       uint32_t mask)
{
    struct nodus_net_poll_win *w;
    int room;

    if (p == NULL || (w = p->w) == NULL || s == NODUS_SOCK_INVALID ||
        tag == NODUS_NET_TAG_WAKE || net_find(w, (SOCKET)s) >= 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    room = NODUS_NET_POLL_WIN_CAPACITY - (w->wake_rd != INVALID_SOCKET ? 1 : 0);
    if (w->n >= room) {
        QGP_LOG_WARN(LOG_TAG, "select set full (%d sockets)", w->n);
        WSASetLastError(WSAENOBUFS);
        return -1;
    }
    w->e[w->n].s = (SOCKET)s;
    w->e[w->n].tag = tag;
    w->e[w->n].mask = mask;
    w->n++;
    return 0;
}

int nodus_net_poll_mod(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                       uint32_t mask)
{
    int i;

    if (p == NULL || p->w == NULL || tag == NODUS_NET_TAG_WAKE ||
        (i = net_find(p->w, (SOCKET)s)) < 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    p->w->e[i].tag = tag;
    p->w->e[i].mask = mask;
    return 0;
}

int nodus_net_poll_del(nodus_net_poll_t *p, nodus_sock_t s)
{
    int i;

    if (p == NULL || p->w == NULL || (i = net_find(p->w, (SOCKET)s)) < 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    net_remove(p->w, i);
    return 0;
}

/* select failed with WSAENOTSOCK: a registered handle was closed without
 * _del (nodus_client_force_disconnect, BUGS.md C-06; R5). Evict up to
 * `cap` handles Winsock no longer knows and report each evicted entry's
 * tag once in `out` as ERR|HUP, so its owner learns the socket is gone;
 * the rest stay registered (a further stale one fails the next select
 * again and is evicted then). ⚠ A handle VALUE that Windows has already
 * reused for a new socket passes the SO_TYPE check and is not evicted —
 * the C-06 fix is the gate for that (design §10).
 * @return the number of entries evicted and written (0 = none found). */
static int net_evict_invalid(struct nodus_net_poll_win *w,
                             nodus_net_event_t *out, int cap)
{
    int i = 0, k = 0;

    while (i < w->n && k < cap) {
        int t = 0, tl = (int)sizeof(t);

        if (getsockopt(w->e[i].s, SOL_SOCKET, SO_TYPE, (char *)&t, &tl) != 0 &&
            WSAGetLastError() == WSAENOTSOCK) {
            QGP_LOG_WARN(LOG_TAG, "evicted a closed socket still registered "
                         "(tag %llu)", (unsigned long long)w->e[i].tag);
            out[k].tag = w->e[i].tag;
            out[k].ready = NODUS_NET_ERR | NODUS_NET_HUP;
            k++;
            net_remove(w, i);
            continue;
        }
        i++;
    }
    return k;
}

int nodus_net_poll_wait(nodus_net_poll_t *p, int timeout_ms,
                        nodus_net_event_t *out, int cap)
{
    struct nodus_net_poll_win *w;
    fd_set rs, ws, xs;
    struct timeval tv, *tvp = NULL;
    int i, t, k = 0, last = -1, watched = 0, rc;

    if (p == NULL || (w = p->w) == NULL || out == NULL || cap <= 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&xs);
    if (w->wake_rd != INVALID_SOCKET) {
        FD_SET(w->wake_rd, &rs);
        watched++;
    }
    for (i = 0; i < w->n; i++) {
        uint32_t m = w->e[i].mask;

        if (m & NODUS_NET_IN) {
            FD_SET(w->e[i].s, &rs);
        }
        if (m & NODUS_NET_OUT) {
            FD_SET(w->e[i].s, &ws);
        }
        if (m & NODUS_NET_CONNECT) {
            FD_SET(w->e[i].s, &xs);
        }
        if (m & (NODUS_NET_IN | NODUS_NET_OUT | NODUS_NET_CONNECT)) {
            watched++;
        }
    }
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }
    if (watched == 0) {
        /* select with three empty sets fails (WSAEINVAL): sleep instead. */
        if (timeout_ms < 0) {
            QGP_LOG_WARN(LOG_TAG, "wait without limit on an empty set");
            WSASetLastError(WSAEINVAL);
            return -1;
        }
        Sleep((DWORD)timeout_ms);
        return 0;
    }
    rc = select(0, &rs, &ws, &xs, tvp);
    if (rc == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAENOTSOCK) {
            k = net_evict_invalid(w, out, cap);
            if (k == 0) {
                /* select named a non-socket, yet every registered handle
                 * still answers SO_TYPE (the wake pair, or a reused handle
                 * value): nothing to evict — report the failure. */
                QGP_LOG_ERROR(LOG_TAG, "select: WSAENOTSOCK, but no "
                              "registered socket is stale");
                WSASetLastError(WSAENOTSOCK);
                return -1;
            }
            QGP_LOG_WARN(LOG_TAG, "select: WSAENOTSOCK, %d stale socket(s) "
                         "evicted and reported as ERR|HUP", k);
            return k;
        }
        return -1;
    }
    if (w->wake_rd != INVALID_SOCKET && FD_ISSET(w->wake_rd, &rs)) {
        char b[64];

        while (recv(w->wake_rd, b, (int)sizeof(b), 0) > 0) {
            /* drained (until WOULDBLOCK) */
        }
    }
    /* Fair rotation (design §10, R7 amended): the scan starts at w->next —
     * just past the entry the previous call reported last — and wraps, so
     * a ready entry that did not fit in `cap` this time is ahead of the
     * scan next time: every entry that stays ready is reported within
     * ceil(n / cap) consecutive waits. */
    for (t = 0; t < w->n && k < cap; t++) {
        uint32_t r = 0;

        i = (w->next + t) % w->n;
        if (FD_ISSET(w->e[i].s, &rs)) {
            r |= NODUS_NET_IN;
        }
        if (FD_ISSET(w->e[i].s, &ws)) {
            r |= NODUS_NET_OUT;
        }
        /* Except set: a failed non-blocking connect (or OOB data). Only
         * ERR is reported — the caller reads SO_ERROR; nothing is closed
         * here (R7). */
        if (FD_ISSET(w->e[i].s, &xs)) {
            r |= NODUS_NET_ERR;
        }
        if (r != 0) {
            out[k].tag = w->e[i].tag;
            out[k].ready = r;
            k++;
            last = i;
        }
    }
    if (last >= 0) {
        w->next = (last + 1) % w->n;
    }
    return k;
}

void nodus_net_poll_wake(nodus_net_poll_t *p)
{
    char one = 1;

    if (p != NULL && p->w != NULL && p->w->wake_wr != INVALID_SOCKET) {
        /* WOULDBLOCK = a wake is already pending; nothing is lost. */
        (void)send(p->w->wake_wr, &one, 1, 0);
    }
}

int nodus_net_probe_connect(nodus_sock_t s)
{
    fd_set ws, xs;
    struct timeval tv;
    int rc;

    FD_ZERO(&ws);
    FD_ZERO(&xs);
    FD_SET((SOCKET)s, &ws);
    FD_SET((SOCKET)s, &xs);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    rc = select(0, NULL, &ws, &xs, &tv);
    return rc == SOCKET_ERROR ? -1 : rc;
}

#endif /* _WIN32 */
