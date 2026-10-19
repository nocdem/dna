/**
 * @file nodus/src/net/nodus_net_poll.h
 * @brief Socket readiness for the nodus ports 4000-4004 — one backend, no
 *        policy (net-layer design 2026-10-19 §2 + rev 1 §9, package N1).
 *
 * What this module is: "which registered sockets are ready for what", plus
 * the few socket shims every caller needs on every platform. It knows
 * nothing about frames, peers, budgets, admission or crypto — every such
 * rule stays in the caller (design §6 G1), and so does each caller's
 * DISPATCH rule (what it does with ERR / HUP / RDHUP, R2).
 *
 * Backends:
 *   · Linux / Android — epoll. The registration mask is handed to
 *     epoll_ctl unchanged (the NODUS_NET_* bits below ARE the EPOLL*
 *     values, checked at compile time in the .c), the caller's `cap` is
 *     epoll_wait's maxevents, the wake is an eventfd. A caller that moves
 *     onto this layer issues the same syscalls with the same arguments in
 *     the same order as before (K25-5 "Linux behaviour unchanged",
 *     decisions/2026-10-16-kurultay-25-summary.md).
 *   · Windows — select over a per-instance registry. LEVEL-triggered only:
 *     NODUS_NET_EDGE is ignored (design §2 rev 1). The wake is a loopback
 *     TCP socket pair. Capacity NODUS_NET_POLL_WIN_CAPACITY sockets per set,
 *     wake included; _add beyond it fails, never truncates (G2).
 *   · Browser (Emscripten) — NOT in N1. nodus_tcp keeps its own poll()
 *     loop until package N2; this file refuses to compile there.
 *
 * Threads (R5, G3): one thread owns a set — the loop owner. Only
 * nodus_net_poll_wake may be called from any other thread.
 *
 * One set per transport instance (R1): nothing is shared between two
 * nodus_net_poll_t, and _init takes no foreign descriptor.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_NET_POLL_H
#define NODUS_NET_POLL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* No Winsock header here: a header that pulls <winsock2.h> breaks every
 * Windows TU that included <windows.h> first, and would fix FD_SETSIZE for
 * TUs that size their own fd_set (nodus_tcp.c:21-23). The Windows types
 * below are the integer types Winsock defines them as; nodus_net_poll.c
 * asserts that. The NODUS_NET_IS_* classes name WSAE* constants and are
 * usable only in a TU that includes <winsock2.h> itself. */
#ifndef _WIN32
  #include <errno.h>
  #include <sys/types.h>
  #include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ── the socket handle ─────────────────────────────────────────────── */

/** One socket: `int` on POSIX, Winsock's `SOCKET` (UINT_PTR) on Windows;
 *  `nodus_socklen_t` is what accept(2) takes as its length. */
#ifdef _WIN32
typedef uintptr_t nodus_sock_t;
#define NODUS_SOCK_INVALID (~(nodus_sock_t)0)    /* INVALID_SOCKET */
typedef int nodus_socklen_t;
#else
typedef int nodus_sock_t;
#define NODUS_SOCK_INVALID (-1)
typedef socklen_t nodus_socklen_t;
#endif

struct sockaddr;

/* ── readiness bits ────────────────────────────────────────────────── */

/* Interest (passed to _add / _mod) and result (nodus_net_event_t.ready).
 * The values are Linux's EPOLL* bits, so the Linux arm passes a mask
 * through byte for byte (nodus_net_poll.c asserts the equality). */
#define NODUS_NET_IN     0x001u          /* EPOLLIN     — readable          */
#define NODUS_NET_OUT    0x004u          /* EPOLLOUT    — writable          */
#define NODUS_NET_ERR    0x008u          /* EPOLLERR    — result only       */
#define NODUS_NET_HUP    0x010u          /* EPOLLHUP    — result only       */
#define NODUS_NET_RDHUP  0x2000u         /* EPOLLRDHUP  — peer shut its write half */
#define NODUS_NET_EDGE   (1u << 31)      /* EPOLLET     — Linux only; ignored on Windows */
/** A non-blocking connect is in progress on this socket. Windows: the
 *  socket is then also watched in the except set, where Winsock reports a
 *  refused connect (nodus_tcp.c:17-20); a hit there is reported as
 *  NODUS_NET_ERR and the caller reads SO_ERROR. Linux: removed from the
 *  mask before epoll_ctl (epoll reports a failed connect as ERR|HUP by
 *  itself), so the epoll arguments are what they would be without it. Not
 *  an epoll bit (1u << 27 is unused by epoll). */
#define NODUS_NET_CONNECT (1u << 27)

/** The tag the backend's own wake registration carries (Linux: the
 *  epoll_event.data.u64 of the eventfd — the value nodus_witness_p2p.c
 *  used before N1). Reserved: never pass it to _add / _mod. */
#define NODUS_NET_TAG_WAKE ((uint64_t)UINT64_MAX - 2)

/** One ready socket. `ready` holds IN / OUT / ERR / HUP / RDHUP, each
 *  kept separate (R2): what the caller does with each is the caller's. */
typedef struct {
    uint64_t tag;
    uint32_t ready;
} nodus_net_event_t;

/** Windows: the most sockets one set holds, the wake pair's read end
 *  included — the nodus_tcp pool (1024) + a listener + the wake (R7). */
#define NODUS_NET_POLL_WIN_CAPACITY 1026

struct nodus_net_poll_win;               /* Windows registry, private */

/** One readiness set. Embedded by value in its owner; opened by _init. */
typedef struct {
#ifdef _WIN32
    struct nodus_net_poll_win *w;        /* NULL = not open                */
#else
    int epfd;                            /* epoll fd, -1 = not open        */
    int wake_fd;                         /* eventfd, -1 = no wake          */
#endif
} nodus_net_poll_t;

/* ── the set ───────────────────────────────────────────────────────── */

/**
 * Open a set; with `with_wake` also the wake (Linux: eventfd
 * EFD_NONBLOCK|EFD_CLOEXEC registered IN under NODUS_NET_TAG_WAKE;
 * Windows: a loopback TCP pair — _init fails closed when it cannot be
 * built). Windows: takes one nodus_net_startup reference, released by
 * _free. @return 0, or -1 with nothing left open.
 */
int  nodus_net_poll_init(nodus_net_poll_t *p, bool with_wake);
/** Close the wake and the set. Sockets still registered are NOT closed
 *  (they are the caller's). Safe on a set that is not open. */
void nodus_net_poll_free(nodus_net_poll_t *p);
/** True between a successful _init and _free. */
bool nodus_net_poll_is_open(const nodus_net_poll_t *p);

/** Register `s` under `tag` watching `mask` (NODUS_NET_IN / OUT, plus
 *  EDGE / RDHUP / CONNECT flags; 0 = registered, watching nothing).
 *  @return 0 or -1 (Linux: errno from epoll_ctl; Windows: full set). */
int  nodus_net_poll_add(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                        uint32_t mask);
/** Replace the tag and mask of a registered socket. @return 0 or -1. */
int  nodus_net_poll_mod(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                        uint32_t mask);
/** Unregister `s` (call before closing it). @return 0 or -1. */
int  nodus_net_poll_del(nodus_net_poll_t *p, nodus_sock_t s);

/**
 * Wait up to `timeout_ms` (< 0 = without limit; 0 = do not block) and
 * write at most `cap` ready sockets to `out`. The wake, when it fired, is
 * drained here (read until it would block) and NOT reported.
 * Linux: one epoll_wait(epfd, …, cap, timeout_ms); entries in the order
 * epoll returns them; cap ≤ NODUS_NET_POLL_MAX_BATCH.
 * Windows: one select; entries in registration-array order. More ready
 * sockets than `cap`: the rest stay ready (level) and are reported by the
 * next wait — nothing is carried between calls.
 * @return the number written (0 on timeout or a wake alone), or -1
 *         (Linux: epoll_wait's errno, e.g. EINTR).
 */
#define NODUS_NET_POLL_MAX_BATCH 64
int  nodus_net_poll_wait(nodus_net_poll_t *p, int timeout_ms,
                         nodus_net_event_t *out, int cap);

/** Make a blocked or the next _wait return. Thread-safe; the ONLY call
 *  allowed off the loop thread. No-op on a set opened without wake. */
void nodus_net_poll_wake(nodus_net_poll_t *p);

/**
 * Has the non-blocking connect on `s` finished (either way)? Does not
 * block. Linux: poll({s, POLLOUT}, 1, 0) — the probe nodus_witness_p2p.c
 * ran before N1. Windows: a one-socket select on the write and except
 * sets (R4). Whether it SUCCEEDED (SO_ERROR, getpeername) is the
 * caller's check. @return > 0 finished, 0 still connecting, < 0 error.
 */
int  nodus_net_probe_connect(nodus_sock_t s);

/* ── socket shims (R3) ─────────────────────────────────────────────── */

/** Winsock owner: checked, reference-counted, synchronized WSAStartup /
 *  WSACleanup (R7). No-op elsewhere. @return 0 or -1. */
int  nodus_net_startup(void);
void nodus_net_cleanup(void);

/** A non-blocking, close-on-exec socket. Linux:
 *  socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0). Windows:
 *  socket + FIONBIO, not inheritable. @return the socket or
 *  NODUS_SOCK_INVALID (error in nodus_net_errno()). */
nodus_sock_t nodus_net_socket(int family, int type);
/** accept(2), nothing added: the caller makes the result non-blocking
 *  (nodus_net_set_nonblocking) and close-on-exec (nodus_net_set_cloexec). */
nodus_sock_t nodus_net_accept(nodus_sock_t l, struct sockaddr *sa,
                              nodus_socklen_t *sl);
/** Linux: fcntl(F_GETFL) then fcntl(F_SETFL, flags | O_NONBLOCK) — the
 *  nodus_tcp.c set_nonblocking. Windows: FIONBIO. @return 0 or -1. */
int  nodus_net_set_nonblocking(nodus_sock_t s);
/** Linux: fcntl(F_SETFD, FD_CLOEXEC). Windows: clears HANDLE_FLAG_INHERIT.
 *  @return 0 or -1. */
int  nodus_net_set_cloexec(nodus_sock_t s);
/** send without a signal: Linux send(s, b, len, MSG_NOSIGNAL) (EPIPE
 *  instead of SIGPIPE); Windows send(…, 0). @return bytes or -1. */
long nodus_net_send(nodus_sock_t s, const void *b, size_t len);
/** recv(s, b, len, 0). @return bytes, 0 at EOF, or -1. */
long nodus_net_recv(nodus_sock_t s, void *b, size_t len);
/** close(2) / closesocket. Keeps nodus_net_errno() as it was before the
 *  call, so a caller can close and still report the failure it hit.
 *  @return 0 or -1. */
int  nodus_net_close(nodus_sock_t s);
/** The last socket error of this thread: errno / WSAGetLastError(). */
int  nodus_net_errno(void);

/* ── error classes (the nodus_tcp.c:58-65 / :108-119 set) ──────────── */

#ifdef _WIN32
#define NODUS_NET_IS_EAGAIN(e)      ((e) == WSAEWOULDBLOCK)
#define NODUS_NET_IS_EINPROGRESS(e) ((e) == WSAEWOULDBLOCK)
/* Winsock raises WSAEINTR only for a cancelled blocking call; these
 * sockets are non-blocking (nodus_tcp.c:59-61). */
#define NODUS_NET_IS_EINTR_IO(e)    (0 && (e))
#define NODUS_NET_IS_PEER_GONE(e)   ((e) == WSAECONNRESET || (e) == WSAECONNABORTED || \
                                     (e) == WSAESHUTDOWN  || (e) == WSAENOTCONN)
/** accept(2) returned a connection the peer already aborted: retry.
 *  ⚠ NOT GROUNDED in this tree (no Windows accept path exists yet): the
 *  reset/abort pair Winsock documents for a connection dropped before
 *  accept. Not used by any Windows build in N1; re-read before N3. */
#define NODUS_NET_IS_CONNABORTED(e) ((e) == WSAECONNRESET || (e) == WSAECONNABORTED)
#else
#define NODUS_NET_IS_EAGAIN(e)      ((e) == EAGAIN || (e) == EWOULDBLOCK)
#define NODUS_NET_IS_EINPROGRESS(e) ((e) == EINPROGRESS)
#define NODUS_NET_IS_EINTR_IO(e)    ((e) == EINTR)
#define NODUS_NET_IS_PEER_GONE(e)   ((e) == EPIPE || (e) == ECONNRESET || \
                                     (e) == ENOTCONN || (e) == ESHUTDOWN)
/** accept(2) returned a connection the peer already aborted: retry. */
#define NODUS_NET_IS_CONNABORTED(e) ((e) == ECONNABORTED)
#endif

#ifdef __cplusplus
}
#endif

#endif /* NODUS_NET_POLL_H */
