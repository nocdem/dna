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
 *     onto this layer issues, on every SUCCESS path, the same syscalls
 *     with the same arguments in the same order as before (K25-5 "Linux
 *     behaviour unchanged", decisions/2026-10-16-kurultay-25-summary.md).
 *     One stated deviation, on an error path only (design §10):
 *     nodus_net_set_nonblocking returns -1 WITHOUT calling F_SETFL when
 *     F_GETFL fails (before N1, F_SETFL ran with -1 | O_NONBLOCK); p2p's
 *     accept then closes the fd.
 *   · Windows — select over a per-instance registry. LEVEL-triggered only:
 *     NODUS_NET_EDGE is ignored (design §2 rev 1). The wake is a loopback
 *     TCP socket pair. Capacity NODUS_NET_POLL_WIN_CAPACITY sockets per set,
 *     wake included; _add beyond it fails, never truncates (G2). HUP and
 *     RDHUP are never produced by readiness here: a peer close shows as IN
 *     and then recv() returning 0; the one place HUP appears is an entry
 *     evicted after WSAENOTSOCK (see _wait), reported ERR|HUP.
 *   · Browser (Emscripten) — NOT in N1. nodus_tcp keeps its own poll()
 *     loop until package N2. The `#error` that refuses it sits in
 *     nodus_net_poll.c; this header itself compiles under Emscripten
 *     (POSIX arm), so including it there is not an error by itself.
 *
 * Threads (R5, G3): one thread owns a set — the loop owner. Only
 * nodus_net_poll_wake may be called from any other thread. _wake is safe
 * concurrently with _wait, but must NOT overlap _free: join every thread
 * that may call _wake before _free (design R5 free order: quiesce senders
 * → stop → wake → join → del → close → free).
 *
 * Windows startup: a set holds one nodus_net_startup reference from _init
 * to _free. WSACleanup at the LAST reference resets every socket still
 * open in the process — close sockets before the last _free / _cleanup.
 * nodus_net_socket takes NO startup reference of its own.
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
 *  epoll_event.data.u64 of the eventfd — the value the 4004 host, then in
 *  nodus_witness_p2p.c and now net/nodus_p2p_host.c, used before N1).
 *  Reserved: never pass it to _add / _mod. */
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
 * _free. @return 0, or -1 with nothing left open (error in
 * nodus_net_errno(); Windows: WSAEINVAL for p == NULL, WSAENOBUFS when the
 * registry cannot be allocated, else the Winsock error of the step that
 * failed).
 */
int  nodus_net_poll_init(nodus_net_poll_t *p, bool with_wake);
/** Close the wake and the set. Sockets still registered are NOT closed
 *  (they are the caller's). Safe after a failed _init and after _free
 *  (twice is a no-op). NOT safe on a struct _init has never seen: on
 *  Linux a zeroed struct holds epfd 0, which _free would close — callers
 *  must _init first. Must not overlap a _wake (see Threads above). */
void nodus_net_poll_free(nodus_net_poll_t *p);
/** True between a successful _init and _free. */
bool nodus_net_poll_is_open(const nodus_net_poll_t *p);

/** Register `s` under `tag` watching `mask` (NODUS_NET_IN / OUT, plus
 *  EDGE / RDHUP / CONNECT flags; 0 = registered, watching nothing).
 *  @return 0 or -1, error in nodus_net_errno() (Linux: EINVAL for p ==
 *  NULL or the reserved tag, else epoll_ctl's errno; Windows: WSAEINVAL
 *  for a bad argument, the reserved tag or a socket already registered,
 *  WSAENOBUFS for a full set). */
int  nodus_net_poll_add(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                        uint32_t mask);
/** Replace the tag and mask of a registered socket. @return 0 or -1
 *  (Linux: as _add; Windows: WSAEINVAL for a bad argument, the reserved
 *  tag or a socket not registered). */
int  nodus_net_poll_mod(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag,
                        uint32_t mask);
/** Unregister `s` (call before closing it). @return 0 or -1 (Linux:
 *  EINVAL for p == NULL, else epoll_ctl's errno; Windows: WSAEINVAL for a
 *  bad argument or a socket not registered). */
int  nodus_net_poll_del(nodus_net_poll_t *p, nodus_sock_t s);

/**
 * Wait up to `timeout_ms` (< 0 = without limit; 0 = do not block) and
 * write at most `cap` ready sockets to `out`. The wake, when it fired, is
 * drained here (read until it would block) and NOT reported.
 * Linux: one epoll_wait(epfd, …, cap, timeout_ms); entries in the order
 * epoll returns them; cap ≤ NODUS_NET_POLL_MAX_BATCH. The wake's eventfd
 * is one of epoll's `cap` entries (as in p2p before N1): a call in which
 * the wake fired returns at most cap - 1 sockets, and with a small cap it
 * may return fewer sockets than are ready because the wake took a slot —
 * the rest are reported by the next call (level) as before.
 * Windows: one select over the whole set (the wake is not one of the
 * `cap` entries there). Fair rotation (design §10, R7 amended): the scan
 * of the registry starts just past the entry the previous call reported
 * last and wraps around, so with more ready sockets than `cap` every
 * socket that stays ready is reported within ceil(n / cap) consecutive
 * calls (n = registered sockets); _del keeps the rotation position.
 * Windows, WSAENOTSOCK from select (a registered socket was closed
 * without _del): up to `cap` stale entries are evicted and each evicted
 * tag is reported ONCE as NODUS_NET_ERR | NODUS_NET_HUP (no readiness is
 * reported in that call); if none is stale, -1 with WSAENOTSOCK. ⚠ A
 * handle value Windows already reused for a new socket is not detected.
 * @return the number written (0 on timeout, on a wake alone, or — Linux,
 *         cap 1 — when the wake took the only slot), or -1,
 *         error in nodus_net_errno() (Linux: EINVAL for a bad argument,
 *         else epoll_wait's errno, e.g. EINTR; Windows: WSAEINVAL for a
 *         bad argument or a wait without limit on an empty set, else
 *         select's error).
 */
#define NODUS_NET_POLL_MAX_BATCH 64
int  nodus_net_poll_wait(nodus_net_poll_t *p, int timeout_ms,
                         nodus_net_event_t *out, int cap);

/** Make a blocked or the next _wait return. Thread-safe against _wait;
 *  the ONLY call allowed off the loop thread; must NOT overlap _free
 *  (join every waker first). No-op on a set opened without wake. */
void nodus_net_poll_wake(nodus_net_poll_t *p);

/**
 * Has the non-blocking connect on `s` finished (either way)? Does not
 * block. Linux: poll({s, POLLOUT}, 1, 0) — the probe the 4004 host (then
 * nodus_witness_p2p.c, now net/nodus_p2p_host.c) ran before N1. Windows: a one-socket select on the write and except
 * sets (R4). Whether it SUCCEEDED (SO_ERROR, getpeername) is the
 * caller's check. @return > 0 finished, 0 still connecting, < 0 error
 * (Linux: poll's -1; Windows: select's SOCKET_ERROR). A caller must NOT
 * read < 0 as "still connecting". p2p's caller (nodus_p2p_host.c
 * io_connect_done), since N3-FIX2: the Windows build reads < 0 as a
 * FAILED connect (the SO_ERROR != 0 branch: conn_failed) and 0 as still
 * connecting; the Linux build keeps its `<= 0` = still-connecting test,
 * unchanged (design §10).
 */
int  nodus_net_probe_connect(nodus_sock_t s);

/* ── socket shims (R3) ─────────────────────────────────────────────── */

/** Winsock owner: checked, reference-counted, synchronized WSAStartup /
 *  WSACleanup (R7). No-op elsewhere. The last _cleanup resets every
 *  socket still open in the process (see "Windows startup" above).
 *  @return 0 or -1 (Windows: WSAStartup's code in nodus_net_errno()). */
int  nodus_net_startup(void);
void nodus_net_cleanup(void);

/** A non-blocking, close-on-exec socket. Linux:
 *  socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0). Windows:
 *  socket + FIONBIO, then HANDLE_FLAG_INHERIT cleared — a failure of that
 *  last step is logged (QGP_LOG_WARN) and the socket is still returned.
 *  Takes no nodus_net_startup reference. @return the socket or
 *  NODUS_SOCK_INVALID (error in nodus_net_errno()). */
nodus_sock_t nodus_net_socket(int family, int type);
/** accept(2), nothing added: the caller makes the result non-blocking
 *  (nodus_net_set_nonblocking) and close-on-exec (nodus_net_set_cloexec). */
nodus_sock_t nodus_net_accept(nodus_sock_t l, struct sockaddr *sa,
                              nodus_socklen_t *sl);
/** Linux: fcntl(F_GETFL) then fcntl(F_SETFL, flags | O_NONBLOCK) — the
 *  nodus_tcp.c set_nonblocking; when F_GETFL fails, -1 WITHOUT calling
 *  F_SETFL (the one stated Linux deviation, see Backends above).
 *  Windows: FIONBIO. @return 0 or -1. */
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
 *  Used by the Windows build since N3: nodus_p2p_host.c io_accept reads
 *  it as "retry this accept" (continue; the pass still stops at
 *  NODUS_P2P_ACCEPT_BUDGET calls). ⚠ NOT VERIFIED against Microsoft's
 *  documentation: WSAECONNRESET || WSAECONNABORTED is assumed to be what
 *  Winsock's accept returns for a connection reset before it was
 *  accepted. If wrong: an error this pair misses ends io_accept's loop
 *  for this pass (break, as EAGAIN does) and the next pass accepts the
 *  rest of the backlog; an error it wrongly includes is retried, at most
 *  until the pass's accept budget is spent. */
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
