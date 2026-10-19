# Transport Layer Functions

**Directory:** `transport/`

Transport layer providing offline message queue. Presence is handled natively by Nodus server (v0.9.0+).

> **Phase 14 (v0.3.154):** Direct P2P messaging removed - all messaging now uses DHT-only path.
> **v0.4.61:** ICE/STUN/TURN removed for privacy. Future voice/video will use alternative transport.
> **v0.4.61:** Renamed from `p2p_*` to `transport_*` for clarity (no P2P, only DHT).

---

## Transport Core (`transport/transport.h`)

### Lifecycle

| Function | Description |
|----------|-------------|
| `transport_t* transport_init(const transport_config_t*, ...)` | Initialize transport layer |
| `int transport_start(transport_t*)` | Start DHT bootstrap |
| `void transport_stop(transport_t*)` | Stop transport layer |
| `void transport_free(transport_t*)` | Free transport context |
| `int transport_deliver_message(transport_t*, const uint8_t*, size_t)` | Deliver message via registered callback |

### Presence System

Presence is handled natively by Nodus server (v0.9.0+). The legacy `transport_register_presence()` stub was removed; there is no transport-level presence API to call. Query presence via `messenger_transport_peer_online()` / `messenger_transport_lookup_presence()` below (they read the locally-cached last-seen populated by Nodus batch query).

### DHT Offline Queue

| Function | Description |
|----------|-------------|
| `int transport_check_offline_messages(transport_t*, const char* sender_fp, bool publish_watermarks, bool force_full_sync, size_t*)` | Check for offline messages in DHT (sender_fp=NULL for all contacts, force_full_sync=true bypasses smart sync for startup) |
| `int transport_queue_offline_message(transport_t*, const char*, const char*, const uint8_t*, size_t, uint64_t)` | Queue message for offline recipient |

---

## Messenger Transport Integration (`messenger_transport.h`)

### Lifecycle

| Function | Description |
|----------|-------------|
| `int messenger_transport_init(messenger_context_t*)` | Initialize transport for messenger (DHT bootstrap + presence registration) |
| `void messenger_transport_shutdown(messenger_context_t*)` | Shutdown transport and release resources |

### Messaging

| Function | Description |
|----------|-------------|
| `int messenger_queue_to_dht(messenger_context_t*, const char*, const uint8_t*, size_t, uint64_t)` | Queue encrypted message to DHT (Spillway) |
| `void messenger_transport_message_callback(const char*, const uint8_t*, size_t, void*)` | Callback when message arrives via DHT |

### Presence & Discovery

| Function | Description |
|----------|-------------|
| `bool messenger_transport_peer_online(messenger_context_t*, const char*)` | Check if peer is online (reads from presence cache) |
| `int messenger_transport_list_online_peers(messenger_context_t*, char***, int*)` | Get list of online peers |
| `int messenger_transport_lookup_presence(messenger_context_t*, const char*, uint64_t*)` | Lookup peer's last-seen timestamp from local presence cache (populated by Nodus batch TCP query) |

### Offline Messages

| Function | Description |
|----------|-------------|
| `int messenger_transport_check_offline_messages(messenger_context_t*, const char*, bool publish_watermarks, bool force_full_sync, size_t*)` | Poll DHT for offline messages (force_full_sync=true for startup sync, false for periodic polling) |

---

## Nodus network readiness layer (`nodus/src/net/nodus_net_poll.h`, nodus 0.26.14)

Net-layer package N1 (decision `docs/plans/decisions/2026-10-19-kurultay-26b-summary.md`, local). One readiness backend for the nodus ports 4000-4004 plus socket shims; no framing, no crypto, no policy — each caller keeps its own dispatch rule. Backends: Linux / Android epoll; Windows `select` (run under Wine only — `nodus/tests/test_net_poll_win.c`; never on native Windows); Emscripten refused by `#error` in `nodus_net_poll.c:27-29`. Only user today: the 4004 host's io seam (`nodus_witness_p2p.c`). Mechanism: `nodus/docs/ARCHITECTURE.md` "Network readiness layer (`nodus_net_poll`)". Other nodus transport entries (`nodus_tcp_*`) are in [dht.md](dht.md) §12.6-12.10.

**Threads:** one thread (the loop owner) owns a set; only `nodus_net_poll_wake` may be called from another thread, and it must not overlap `nodus_net_poll_free` (join every waker first).

### Types and constants

| Declaration | Description |
|-------------|-------------|
| `typedef int nodus_sock_t;` (POSIX) / `typedef uintptr_t nodus_sock_t;` (`_WIN32`) | **NEW.** One socket handle: `int` on POSIX, Winsock's `SOCKET` on Windows (size asserted in the `.c`). |
| `#define NODUS_SOCK_INVALID (-1)` (POSIX) / `(~(nodus_sock_t)0)` (`_WIN32`, = `INVALID_SOCKET`) | **NEW.** "No socket". |
| `typedef socklen_t nodus_socklen_t;` (POSIX) / `typedef int nodus_socklen_t;` (`_WIN32`) | **NEW.** What `accept(2)` takes as its length. |
| `#define NODUS_NET_IN 0x001u` / `NODUS_NET_OUT 0x004u` / `NODUS_NET_ERR 0x008u` / `NODUS_NET_HUP 0x010u` / `NODUS_NET_RDHUP 0x2000u` / `NODUS_NET_EDGE (1u << 31)` | **NEW.** Interest / result bits, equal to `EPOLLIN` / `EPOLLOUT` / `EPOLLERR` / `EPOLLHUP` / `EPOLLRDHUP` / `EPOLLET` (compile-time asserted). `ERR` / `HUP` are result-only. `EDGE` is ignored on Windows. Windows never produces `HUP` / `RDHUP` from readiness (only for an evicted entry, see `nodus_net_poll_wait`). |
| `#define NODUS_NET_CONNECT (1u << 27)` | **NEW.** A non-blocking connect is in progress: Windows also watches the except set (a hit is reported as `NODUS_NET_ERR`; the caller reads `SO_ERROR`); Linux strips it before `epoll_ctl`. Not an epoll bit. |
| `#define NODUS_NET_TAG_WAKE ((uint64_t)UINT64_MAX - 2)` | **NEW.** The backend's own wake registration tag. Reserved: `_add` / `_mod` refuse it. |
| `typedef struct { uint64_t tag; uint32_t ready; } nodus_net_event_t;` | **NEW.** One ready socket; `ready` holds IN / OUT / ERR / HUP / RDHUP kept separate. |
| `#define NODUS_NET_POLL_WIN_CAPACITY 1026` | **NEW.** Windows: the most sockets one set holds, the wake's read end included (pool 1024 + listener + wake). |
| `#define NODUS_NET_POLL_MAX_BATCH 64` | **NEW.** Linux: the largest `cap` `nodus_net_poll_wait` accepts. |
| `typedef struct { int epfd; int wake_fd; } nodus_net_poll_t;` (POSIX) / `typedef struct { struct nodus_net_poll_win *w; } nodus_net_poll_t;` (`_WIN32`) | **NEW.** One readiness set, embedded by value in its owner. POSIX: `epfd` -1 = not open, `wake_fd` -1 = no wake; Windows: `w` NULL = not open (private registry). |

### The set

| Function | Description |
|----------|-------------|
| `int nodus_net_poll_init(nodus_net_poll_t *p, bool with_wake)` | **NEW.** Open a set; with `with_wake` also the wake (Linux: `eventfd(0, EFD_NONBLOCK\|EFD_CLOEXEC)` registered IN under `NODUS_NET_TAG_WAKE`; Windows: a loopback TCP pair, `_init` fails closed when it cannot be built). Windows takes one `nodus_net_startup` reference, released by `_free`. Returns 0, or -1 with nothing left open (error in `nodus_net_errno()`; Windows: `WSAEINVAL` for `p == NULL`, `WSAENOBUFS` when the registry cannot be allocated, else the failing step's Winsock error). |
| `void nodus_net_poll_free(nodus_net_poll_t *p)` | **NEW.** Close the wake and the set; registered sockets are NOT closed. Safe after a failed `_init` and twice; NOT safe on a struct `_init` never saw (a zeroed Linux struct holds `epfd` 0). Must not overlap `_wake`. |
| `bool nodus_net_poll_is_open(const nodus_net_poll_t *p)` | **NEW.** True between a successful `_init` and `_free`. |
| `int nodus_net_poll_add(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag, uint32_t mask)` | **NEW.** Register `s` under `tag` watching `mask` (IN / OUT plus EDGE / RDHUP / CONNECT; 0 = registered, watching nothing). Returns 0 or -1 (Linux: `EINVAL` for `p == NULL` or the reserved tag, else `epoll_ctl`'s errno; Windows: `WSAEINVAL` for a bad argument, the reserved tag or a socket already registered, `WSAENOBUFS` for a full set). |
| `int nodus_net_poll_mod(nodus_net_poll_t *p, nodus_sock_t s, uint64_t tag, uint32_t mask)` | **NEW.** Replace tag and mask of a registered socket. Returns 0 or -1 (Linux: as `_add`; Windows: `WSAEINVAL` for a bad argument, the reserved tag or a socket not registered). |
| `int nodus_net_poll_del(nodus_net_poll_t *p, nodus_sock_t s)` | **NEW.** Unregister `s` (call before closing it). Returns 0 or -1 (Linux: `EINVAL` for `p == NULL`, else `epoll_ctl`'s errno; Windows: `WSAEINVAL` for a bad argument or a socket not registered). |
| `int nodus_net_poll_wait(nodus_net_poll_t *p, int timeout_ms, nodus_net_event_t *out, int cap)` | **NEW.** Wait up to `timeout_ms` (< 0 without limit, 0 no block); write at most `cap` ready sockets to `out`; a fired wake is drained here and NOT reported. Linux: one `epoll_wait(epfd, …, cap, timeout_ms)`, `cap ≤ NODUS_NET_POLL_MAX_BATCH`, the wake occupies one of the `cap` slots. Windows: one `select` over the whole set (wake not counted in `cap`); fair rotation — every socket that stays ready is reported within ⌈n / cap⌉ consecutive calls; on `WSAENOTSOCK` up to `cap` stale entries are evicted and reported once as `ERR\|HUP` (if none is stale: -1 with `WSAENOTSOCK`); a reused handle value is not detected. Returns the number written (0 on timeout, on a wake alone, or — Linux, cap 1 — when the wake took the only slot), or -1 (Linux: `EINVAL` for a bad argument, else `epoll_wait`'s errno, e.g. `EINTR`; Windows: `WSAEINVAL` for a bad argument or a wait without limit on an empty set, else `select`'s error). |
| `void nodus_net_poll_wake(nodus_net_poll_t *p)` | **NEW.** Make a blocked or the next `_wait` return. Thread-safe against `_wait`; the ONLY call allowed off the loop thread; must NOT overlap `_free`. No-op on a set opened without wake. |
| `int nodus_net_probe_connect(nodus_sock_t s)` | **NEW.** Has the non-blocking connect on `s` finished (either way)? Does not block. Linux: `poll({s, POLLOUT}, 1, 0)`; Windows: a one-socket `select` on the write and except sets. Returns > 0 finished, 0 still connecting, < 0 error (Linux `poll`'s -1, Windows `select`'s `SOCKET_ERROR`) — a caller must NOT read < 0 as "still connecting". Success (`SO_ERROR`, `getpeername`) is the caller's check. p2p's caller tests `<= 0` (Linux-only; revisited in package N3). |

### Socket shims

| Function | Description |
|----------|-------------|
| `int nodus_net_startup(void)` | **NEW.** Windows: checked, reference-counted, synchronized `WSAStartup(2.2)` (returns -1 with `WSAStartup`'s code, or `WSAVERNOTSUPPORTED`, in `nodus_net_errno()`). No-op returning 0 elsewhere. |
| `void nodus_net_cleanup(void)` | **NEW.** Windows: drops one reference; the LAST one calls `WSACleanup`, which resets every socket still open in the process. No-op elsewhere. |
| `nodus_sock_t nodus_net_socket(int family, int type)` | **NEW.** A non-blocking, close-on-exec socket. Linux: `socket(family, type \| SOCK_NONBLOCK \| SOCK_CLOEXEC, 0)`. Windows: `socket` + `FIONBIO`, then `HANDLE_FLAG_INHERIT` cleared (failure of that step logged, socket still returned). Takes no startup reference. Returns the socket or `NODUS_SOCK_INVALID` (error in `nodus_net_errno()`). |
| `nodus_sock_t nodus_net_accept(nodus_sock_t l, struct sockaddr *sa, nodus_socklen_t *sl)` | **NEW.** `accept(2)`, nothing added: the caller makes the result non-blocking and close-on-exec. |
| `int nodus_net_set_nonblocking(nodus_sock_t s)` | **NEW.** Linux: `fcntl(F_GETFL)` then `fcntl(F_SETFL, flags \| O_NONBLOCK)`; when `F_GETFL` fails, -1 WITHOUT calling `F_SETFL` (the one stated Linux deviation). Windows: `FIONBIO`. Returns 0 or -1. |
| `int nodus_net_set_cloexec(nodus_sock_t s)` | **NEW.** Linux: `fcntl(F_SETFD, FD_CLOEXEC)`. Windows: clears `HANDLE_FLAG_INHERIT`. Returns 0 or -1. |
| `long nodus_net_send(nodus_sock_t s, const void *b, size_t len)` | **NEW.** Linux: `send(s, b, len, MSG_NOSIGNAL)` (`EPIPE` instead of `SIGPIPE`); Windows: `send(…, 0)` with `len` clamped to `INT_MAX`. Returns bytes or -1. |
| `long nodus_net_recv(nodus_sock_t s, void *b, size_t len)` | **NEW.** `recv(s, b, len, 0)` (Windows: `len` clamped to `INT_MAX`). Returns bytes, 0 at EOF, or -1. |
| `int nodus_net_close(nodus_sock_t s)` | **NEW.** `close(2)` / `closesocket`; keeps `nodus_net_errno()` as it was before the call. Returns 0 or -1. |
| `int nodus_net_errno(void)` | **NEW.** The last socket error of this thread: `errno` / `WSAGetLastError()`. |

### Error classes (macros)

| Macro | POSIX | `_WIN32` (usable only in a TU that includes `<winsock2.h>`) |
|-------|-------|-------|
| `NODUS_NET_IS_EAGAIN(e)` | `EAGAIN` or `EWOULDBLOCK` | `WSAEWOULDBLOCK` |
| `NODUS_NET_IS_EINPROGRESS(e)` | `EINPROGRESS` | `WSAEWOULDBLOCK` |
| `NODUS_NET_IS_EINTR_IO(e)` | `EINTR` | never (`0 && (e)`; the sockets are non-blocking) |
| `NODUS_NET_IS_PEER_GONE(e)` | `EPIPE`, `ECONNRESET`, `ENOTCONN`, `ESHUTDOWN` | `WSAECONNRESET`, `WSAECONNABORTED`, `WSAESHUTDOWN`, `WSAENOTCONN` |
| `NODUS_NET_IS_CONNABORTED(e)` | `ECONNABORTED` (accept: retry) | `WSAECONNRESET` or `WSAECONNABORTED` — ⚠ NOT GROUNDED in this tree (no Windows accept path exists yet); not used by any Windows build in N1; re-read before N3 (`nodus_net_poll.h:280-284`) |

### Changed fields of the 4004 host's io seam (`nodus/src/witness/nodus_witness_p2p.h`)

No `nodus_p2p_io_*` function signature changed; the structs it works on did.

| Field | Description |
|-------|-------------|
| `nodus_sock_t fd;` (`nodus_p2p_sock_t`) | **CHANGED** from `int fd` (-1 = none) to `nodus_sock_t` (`NODUS_SOCK_INVALID` = none). `events` / `ready` now hold `NODUS_NET_*` bits (same values as the `EPOLL*` bits they held). |
| `nodus_net_poll_t poll;` (`nodus_p2p_io_t`) | **NEW.** The readiness set + the wake when asked; replaces the removed `int epfd` and `int wake_fd` fields. |
| `nodus_sock_t listen_fd;` (`nodus_p2p_io_t`) | **CHANGED** from `int` (-1 = none) to `nodus_sock_t` (`NODUS_SOCK_INVALID` = none). |

---

## Removed Functions

The following functions were removed during the p2p → transport refactoring:

| Removed Function | Removal Version | Reason |
|-----------------|-----------------|--------|
| `p2p_transport_start()` TCP listener | v0.4.61 | TCP listener not used (DHT-only) |
| `p2p_lookup_peer()` | v0.4.61 | Dead code - direct P2P removed |
| `p2p_lookup_presence_by_fingerprint()` | v0.4.61 | Dead code - replaced by `messenger_transport_lookup_presence()` |
| `p2p_get_connected_peers()` | v0.4.61 | Dead code - no direct connections |
| `p2p_disconnect_peer()` | v0.4.61 | Dead code - no direct connections |
| `p2p_get_stats()` | v0.4.61 | Dead code - simplified API |
| `p2p_send_message()` | v0.3.154 | Dead code - Phase 14 DHT-only |
