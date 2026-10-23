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

Net-layer package N1 (decision `docs/plans/decisions/2026-10-19-kurultay-26b-summary.md`, local). One readiness backend for the nodus ports 4000-4004 plus socket shims; no framing, no crypto, no policy — each caller keeps its own dispatch rule. Backends: Linux / Android epoll; Windows `select` (run under Wine only — `nodus/tests/test_net_poll_win.c`; never on native Windows); Emscripten refused by `#error` in `nodus_net_poll.c:27-29`. Only user today: the 4004 host's io seam (`nodus/src/net/nodus_p2p_host.c` since nodus 0.26.15 / N3; `nodus_witness_p2p.c` before). Mechanism: `nodus/docs/ARCHITECTURE.md` "Network readiness layer (`nodus_net_poll`)". Other nodus transport entries (`nodus_tcp_*`) are in [dht.md](dht.md) §12.6-12.10.

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
| `int nodus_net_probe_connect(nodus_sock_t s)` | **NEW.** Has the non-blocking connect on `s` finished (either way)? Does not block. Linux: `poll({s, POLLOUT}, 1, 0)`; Windows: a one-socket `select` on the write and except sets. Returns > 0 finished, 0 still connecting, < 0 error (Linux `poll`'s -1, Windows `select`'s `SOCKET_ERROR`) — a caller must NOT read < 0 as "still connecting". Success (`SO_ERROR`, `getpeername`) is the caller's check. p2p's caller (`io_connect_done`, `nodus_p2p_host.c:707-738`): Linux keeps `<= 0` (the pre-N1 probe, unchanged); Windows since N3-FIX2 (nodus 0.26.15) reads 0 as still connecting and < 0 as a failed connect (`nodus_net_poll.h:225-230`). |

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
| `NODUS_NET_IS_CONNABORTED(e)` | `ECONNABORTED` (accept: retry) | `WSAECONNRESET` or `WSAECONNABORTED` — ⚠ NOT GROUNDED in this tree (no Windows accept path exists yet); not used by any Windows build in N1; since N3 (0.26.15) the 4004 host's accept path uses it (`nodus_p2p_host.c:753`) and that file compiles for Windows, while the header still says "re-read before N3" (`nodus_net_poll.h:281-285`) — no Windows program runs the host |

### Changed fields of the 4004 host's io seam (N1, 0.26.14; declared in `nodus/src/net/nodus_p2p_host.h` since N3, 0.26.15 — `nodus_witness_p2p.h` before)

No `nodus_p2p_io_*` function signature changed in N1; the structs it works on did. The full current declarations are in "Nodus witness-free 4004 host" below.

| Field | Description |
|-------|-------------|
| `nodus_sock_t fd;` (`nodus_p2p_sock_t`) | **CHANGED** from `int fd` (-1 = none) to `nodus_sock_t` (`NODUS_SOCK_INVALID` = none). `events` / `ready` now hold `NODUS_NET_*` bits (same values as the `EPOLL*` bits they held). |
| `nodus_net_poll_t poll;` (`nodus_p2p_io_t`) | **NEW.** The readiness set + the wake when asked; replaces the removed `int epfd` and `int wake_fd` fields. |
| `nodus_sock_t listen_fd;` (`nodus_p2p_io_t`) | **CHANGED** from `int` (-1 = none) to `nodus_sock_t` (`NODUS_SOCK_INVALID` = none). |

---

## Nodus witness-free 4004 host (`nodus/src/net/nodus_p2p_host.h`, nodus 0.26.15)

Net-layer package N3 (decision `docs/plans/decisions/2026-10-19-kurultay-26b-summary.md`, local; design `docs/plans/2026-10-19-net-layer-design.md` §11, local). The part of the 4004 cometbft p2p host that needs no witness — sockets, handshake / ADDR-verify worker, clocks, identity, own ADDR record, address-book file, NodeInfo, transport, switch, PEX — moved out of `nodus/src/witness/nodus_witness_p2p.c` with its logic unchanged; the witness embeds it by value and supplies the policy rows. In the common source list (compiles for Windows; never run there). Callers today (`git grep nodus_p2p_host_init` at 88284e668): the witness (`nodus_witness_p2p.c:2200`, `:2209`) and the test `nodus/tests/test_p2p_host.c:258`, `:261`; no witness-free program calls it yet. Mechanism, caller obligations, lifecycle and Windows arms: `nodus/docs/ARCHITECTURE.md` "The witness-free 4004 host (`nodus_p2p_host`)".

**`nodus_witness_p2p_*` public API: unchanged.** Every `nodus_witness_p2p_*` function in `nodus/src/witness/nodus_witness_p2p.h` keeps its signature; `nodus_witness_p2p_new` / `_poll` / `_free` now call the host's `_init` / `_start`, the poll steps and `_free`, and `nodus_witness_p2p_listen_port` / `_id` / `_switch` / `_peer_count` / `_peer_id_at` / `_has_peer` / `_send` forward to the `nodus_p2p_host_*` accessor of the same name (`nodus_witness_p2p.c:2317-2363`). The config type, the socket host, the clocks and the 0x0A sign / verify below were declared in `nodus_witness_p2p.h` before N3; that header now includes `net/nodus_p2p_host.h` (`nodus_witness_p2p.h:213`), and `nodus_server.h`, `nodus_witness_host.h` and `nodus_witness_network_file.h` include it directly.

**Threads:** every host call from ONE thread; never `nodus_p2p_host_free` or `nodus_p2p_host_start` from inside a reactor or policy callback. The worker threads touch only handshake and ADDR-verification jobs.

### Config (moved from `nodus_witness_p2p.h`, unchanged)

| Declaration | Description |
|-------------|-------------|
| `#define NODUS_P2P_MAX_PEER_LIST 64` | **MOVED.** The capacity of each of the three peer lists. |
| `typedef struct { … } nodus_p2p_config_t;` | **MOVED.** The P2P section of the node's config, reference `config.go` key names: `persistent_peers[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_NETADDR_STR_MAX]` + `n_persistent_peers`, `unconditional_peer_ids[…][CMT_P2P_ID_CAP]` + `n_unconditional_peer_ids`, `private_peer_ids[…][CMT_P2P_ID_CAP]` + `n_private_peer_ids`, `bool pex`, `bool addr_book_strict`, `bool allow_duplicate_ip`, `int max_num_inbound_peers`, `int max_num_outbound_peers`, `int64_t flush_throttle_timeout_ms`, `int max_packet_msg_payload_size`, `int64_t send_rate`, `int64_t recv_rate`, `int64_t handshake_timeout_ms`, `int64_t dial_timeout_ms` (0 = the transport's own 3 s / 1 s constants), `char moniker[64]` (empty = `"nodus-"` + the first 16 characters of the node ID). |
| `void nodus_p2p_config_default(nodus_p2p_config_t *c)` | **MOVED.** The reference defaults. |
| `int nodus_p2p_config_add_persistent(nodus_p2p_config_t *c, const char *s)` | **MOVED.** Append one `"id@ip:port"` entry. Returns 0; -1 when the list is full or the entry does not fit. |
| `int nodus_p2p_config_add_unconditional(nodus_p2p_config_t *c, const char *id)` | **MOVED.** Append one ID. Returns 0 or -1 (as above). |
| `int nodus_p2p_config_add_private(nodus_p2p_config_t *c, const char *id)` | **MOVED.** Append one ID (never gossiped). Returns 0 or -1 (as above). |

### Socket host (moved from `nodus_witness_p2p.c`, unchanged except the Windows arms)

| Declaration | Description |
|-------------|-------------|
| `#define NODUS_P2P_ACCEPT_BUDGET CMT_P2P_DEFAULT_MAX_NUM_INBOUND_PEERS` | **MOVED.** The most `accept(2)` calls one pass makes, refused and interrupted ones included; ⚠ NOT GROUNDED as a number (no reference counterpart — the reference's accept goroutine has no bound). A backlog left over wakes the next wait (level-triggered `NODUS_NET_IN`); nothing is refused because of the budget. |
| `typedef struct { nodus_sock_t fd; uint64_t gen; bool connecting; bool failed; uint32_t events; uint32_t ready; } nodus_p2p_sock_t;` | **MOVED.** One transport slot's socket (`fd` `NODUS_SOCK_INVALID` = none; `events` / `ready` are `NODUS_NET_*` bits). |
| `typedef struct { cmt_p2p_transport_t *t; nodus_net_poll_t poll; nodus_sock_t listen_fd; bool listen_armed; nodus_p2p_sock_t *socks; int n_socks; int last_served; } nodus_p2p_io_t;` | **MOVED.** Non-blocking sockets for one transport, indexed by its slot, on their own readiness set. `last_served` -1 = none yet (the next pump starts just past it). |
| `int nodus_p2p_io_init(nodus_p2p_io_t *io, bool with_wake)` | **MOVED.** Zero `io`, open its readiness set (with the worker's wake when asked). Returns 0 or -1. |
| `void nodus_p2p_io_free(nodus_p2p_io_t *io)` | **MOVED.** Close every slot socket and the listener, then the set (wake first); `io` is zeroed with the set left "not open". |
| `int nodus_p2p_io_listen(nodus_p2p_io_t *io, const char *ip, uint16_t port)` | **MOVED; CHANGED (Windows only).** Bind + listen on an IP literal: Linux `SO_REUSEADDR`, Windows `SO_EXCLUSIVEADDRUSE` (N3-FIX). Returns 0 or -1 with the failure's code kept (Linux `errno`; Windows `nodus_net_errno()`; a bad address sets `EINVAL` and, on Windows, `WSAEINVAL`). |
| `int nodus_p2p_io_dial(nodus_p2p_io_t *io, int slot, uint64_t gen, const cmt_p2p_netaddr_t *addr)` | **MOVED.** The transport's `dial` row body: a non-blocking `connect(2)` to `addr`'s IP literal. Returns 0 connecting; -1 failed at once. |
| `void nodus_p2p_io_close(nodus_p2p_io_t *io, int slot, uint64_t gen)` | **MOVED.** The transport's `close` row body; ignores a stale (slot, gen). |
| `void nodus_p2p_io_wait(nodus_p2p_io_t *io, int timeout_ms)` | **MOVED.** Re-arm `NODUS_NET_IN` on every socket whose `read_buf` has room again, then one `nodus_net_poll_wait` (batch 64) up to `timeout_ms`. |
| `void nodus_p2p_io_pump(nodus_p2p_io_t *io)` | **MOVED.** One I/O pass: accept while `can_accept` (at most `NODUS_P2P_ACCEPT_BUDGET`), finish the connects, then per socket the continuous read and the continuous write. Reactor callbacks run inside this call. |
| `void nodus_p2p_io_flush(nodus_p2p_io_t *io)` | **MOVED.** The continuous write of every socket (the pass's last step); delivers no message. |
| `int64_t nodus_p2p_mono_ns(void *ctx)` | **MOVED.** Monotonic clock, ns (every p2p deadline). |
| `int64_t nodus_p2p_wall_ns(void *ctx)` | **MOVED.** Wall clock, ns (address-book timestamps only). |
| `int64_t nodus_p2p_rand_int63n(void *ctx, int64_t n)` | **MOVED.** [0, n) from OS randomness. |
| `int nodus_p2p_sc_sign(void *ctx, const uint8_t *msg, size_t msg_len, uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])` | **MOVED.** The secret connection's sign under purpose 0x0A, `ctx` = the `nodus_identity_t *`; safe on a worker thread. |
| `int nodus_p2p_sc_verify(void *ctx, const uint8_t sig[CMT_P2P_SC_SIG_SIZE], const uint8_t *msg, size_t msg_len, const uint8_t pk[CMT_P2P_SC_DSA_PK_SIZE])` | **MOVED.** The matching verify under purpose 0x0A. |

### The host (NEW in N3)

| Declaration | Description |
|-------------|-------------|
| `#define NODUS_P2P_WQ_N 3` | **NEW.** Worker queues: outbound handshakes, inbound handshakes, ADDR verifications. |
| `#define NODUS_P2P_WORKERS_DEFAULT 2` | **NEW.** Worker threads when `n_workers` is 0. |
| `#define NODUS_P2P_WORKERS_MAX 8` | **NEW.** Cap on worker threads (a larger `n_workers` is clamped). |
| `typedef struct { void *ctx; bool (*is_bonded)(void *ctx, const char *id); int (*bonded_count)(void *ctx); bool (*bonded_pubkey)(void *ctx, const char *id, uint8_t pk[QGP_DSA87_PUBLICKEYBYTES]); bool (*may_receive)(void *ctx); bool (*recv_near_full)(void *ctx); uint64_t (*queue_mark)(void *ctx); } nodus_p2p_host_policy_t;` | **NEW.** The embedder's answers. NULL row meanings: `is_bonded` → false; `bonded_count` → 0; `bonded_pubkey` → no key for any ID (no signed ADDR record verifies), and `nodus_p2p_host_init` REFUSES `cfg->pex` on with this row NULL; `may_receive` → true; `recv_near_full` → false; `queue_mark` → the transport gets NO `queue_mark` row (every delivered message counts as a peer's turn), not a constant 0. |
| `typedef struct { const nodus_identity_t *identity; const uint8_t *chain_id; const nodus_p2p_config_t *cfg; const char *listen_ip; uint16_t listen_port; const char *external_ip; const char *data_path; const char *seq_dir; bool open_listener; int n_workers; const uint8_t *channels; size_t n_channels; const cmt_p2p_reactor_t *reactors; int n_reactors; nodus_p2p_host_policy_t policy; } nodus_p2p_host_params_t;` | **NEW.** What the host is built from; every pointer borrowed. `identity` needs `has_mlkem`; `chain_id` 32 bytes; `external_ip` `""`/NULL = none; `open_listener` false = no accept (tests); `n_workers` 0 = 2; `channels` in NodeInfo order, at most `CMT_P2P_MAX_NUM_CHANNELS − 1` (PEX 0x00 appended by the host when `cfg->pex`); `reactors` registered in this order (copied), before PEX — each `get_channels` array must outlive the host. |
| `typedef struct { … } nodus_p2p_host_t;` | **NEW.** The host, a complete type so it can be embedded by value. Must NOT be moved or copied after `_init` (it points into itself). An embedder reads its fields and writes only `bool self_bonded` (PEX pushes the own record only while true; a witness-free host leaves it false). Lifecycle fields `bool init_ok` (end of a successful `_init`) and `bool started` (set on entry to `_start`); `char data_path[256]`, `char seq_dir[256]` bound the path lengths. |
| `int nodus_p2p_host_init(nodus_p2p_host_t *h, const nodus_p2p_host_params_t *prm)` | **NEW.** Zero `h`, then build: listener, own address, NodeInfo, transport, switch, the caller's reactors, address book + PEX (when `cfg->pex`), the configured peer lists. Returns 0 (`init_ok` set), or -1 (logged) — then call `nodus_p2p_host_free(h)`. Refused before anything is built: a NULL required parameter; `n_channels` over `CMT_P2P_MAX_NUM_CHANNELS − 1` or a count without a list; `n_reactors < 0` or a count without a list; a peer-list count outside [0, `NODUS_P2P_MAX_PEER_LIST`]; a `data_path` / `seq_dir` that does not fit 256 bytes with its NUL; PEX on without `policy.bonded_pubkey`; no ML-KEM key; a listen address that is not an IP literal. Refused after the reactors are registered: a NodeInfo channel set (`channels` + PEX) that is not exactly the union of the registered reactors' channels. Only on a fresh (zeroed) or freed host. |
| `int nodus_p2p_host_start(nodus_p2p_host_t *h)` | **NEW.** Worker threads, switch start (PEX loads the address book), own ADDR record, persistent-peer dial, the `p2p on …` INFO line. Returns 0, or -1 (logged) — then call `nodus_p2p_host_free(h)`. -1 with no side effect when the host is not `init_ok` or was already started (`started` is set on entry, so a failed `_start` is not retried — only `_free` recovers). |
| `int nodus_p2p_host_poll(nodus_p2p_host_t *h, int timeout_ms)` | **NEW.** One whole pass for a witness-free caller: `_poll_io`, `_pex_tick`, `_own_record_check`, `_flush`. Returns 0; -1 with nothing done when the host is not running (not `init_ok`, not started, or freed). |
| `void nodus_p2p_host_poll_io(nodus_p2p_host_t *h, int timeout_ms)` | **NEW.** Worker results, the socket wait (≤ `timeout_ms`), worker results, the I/O pass, the switch tick. No-op unless `init_ok`. |
| `void nodus_p2p_host_pex_tick(nodus_p2p_host_t *h)` | **NEW.** PEX's tick (no-op without PEX or unless `init_ok`). |
| `void nodus_p2p_host_own_record_check(nodus_p2p_host_t *h)` | **NEW.** When the address book has seen a record of ours at a seq above ours, or at our seq with different bytes, sign a new one at that seq + 1 and tell PEX (an `UINT64_MAX` seq is logged once and not exceeded). No-op without an address book, without an own record, or unless `init_ok`. |
| `void nodus_p2p_host_flush(nodus_p2p_host_t *h)` | **NEW.** Final write of everything the pass produced (`nodus_p2p_io_flush`). No-op unless `init_ok`. |
| `void nodus_p2p_host_free(nodus_p2p_host_t *h)` | **NEW.** Switch stop (the book is saved; reactors' `remove_peer` rows run), worker stop, PEX, switch, transport, book, sockets, mutex, NodeInfo; clears `init_ok` / `started` last. NULL-safe; must be called after a failed `_init` / `_start` (releases exactly what was built, nothing twice — header); does not free `h`. A second call finds every build flag cleared and every pointer NULL (`nodus_p2p_host.c:2019-2064`; `worker_stop` returns at once without `mu_init`, `:996-998`); `test_p2p_host` (6) exercises a second call only after a FAILED init — the header does not state a second free after a successful start. |
| `uint16_t nodus_p2p_host_listen_port(const nodus_p2p_host_t *h)` | **NEW.** The port actually listened on (0 = none or not `init_ok`). |
| `const char *nodus_p2p_host_id(const nodus_p2p_host_t *h)` | **NEW.** This node's p2p ID (`""` unless `init_ok`). |
| `cmt_p2p_switch_t *nodus_p2p_host_switch(nodus_p2p_host_t *h)` | **NEW.** The switch (NULL unless `init_ok`). |
| `int nodus_p2p_host_peer_count(const nodus_p2p_host_t *h)` | **NEW.** Connected peers, in the switch's peer-set order (0 unless `init_ok`). |
| `bool nodus_p2p_host_peer_id_at(const nodus_p2p_host_t *h, int i, char out[CMT_P2P_ID_CAP])` | **NEW.** The i-th connected peer's ID. Returns false outside the set or unless `init_ok`. |
| `bool nodus_p2p_host_has_peer(const nodus_p2p_host_t *h, const char *peer_id)` | **NEW.** Whether `peer_id` is in the switch's peer set now. |
| `bool nodus_p2p_host_send(nodus_p2p_host_t *h, const char *peer_id, uint8_t ch, const uint8_t *msg, size_t len)` | **NEW.** Send `msg` to the connected peer on channel `ch` (Send ≡ TrySend, R-P2P-19). Returns true when the channel's queue took it; false unless `init_ok`. |
| `bool nodus_p2p_host_signed_addr(nodus_p2p_host_t *h, const uint8_t pk[NODUS_PK_BYTES], char *out, size_t cap)` | **NEW.** The `"ip:port"` named by the verified signed ADDR record of the identity with chain key `pk` (our own identity answers from our own record). Returns true and `out`, or false (no record held). The witness's signed-address lookup forwards here. |

---

## 4004 SecretConnection session profiles (`shared/dnac/cmt_p2p_secret.h`) and session-auth signing (`nodus/src/crypto/nodus_sign.h`) — DHT v2 sub-package 3a

The secret connection runs under one of three const **session profiles**; the DHT v2 client / node sessions sign their challenge under two new strict purposes. Only the 4004 transport calls the profile API today, with WITNESS (`shared/dnac/cmt_p2p_transport.c:766-769`, `:863-865`); 4001 / 4002 use none of it until sub-package 3b. This section covers the 3a additions and their direct siblings (`cmt_p2p_sc_init`, the 0x0A pair) only — the rest of the `cmt_p2p_secret` API and of `nodus_sign.h` has no entry in this reference yet. Architecture and governing decisions: `nodus/docs/ARCHITECTURE.md` "DHT v2 sub-package 3a".

### Profile type and constants (`cmt_p2p_secret.h`)

| Signature | Description |
|-----------|-------------|
| `#define CMT_P2P_SC_PROFILE_STR_MAX 64` (`:237`) | **NEW.** Longest transcript tag / HKDF info string a profile may carry, in bytes. |
| `typedef struct { const char *transcript_tag; const char *info_aead; const char *info_challenge; } cmt_p2p_sc_profile_t;` (`:251-255`) | **NEW.** The three domain strings of one secret-connection family: row-4 transcript tag, row-5 HKDF info for the AEAD key, rows 5-6 HKDF info for the challenge. Message bytes, key schedule, frame and nonce are the same for every profile; different profiles derive different keys, so a mixed pair never authenticates. The signing purpose is NOT in the profile — it stays the host's `cmt_p2p_sc_host_t.sign / .verify`, and nothing in the module checks the pairing. |
| `extern const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_WITNESS;` (`:258`; defined `cmt_p2p_secret.c:41-43`) | **NEW.** 4004: `CMT_P2P_SC_TAG_T` `"nodus.wsess.transcript.v1"`, `CMT_P2P_SC_INFO_AEAD` `"nodus.wsess.keys.v1/aead"`, `CMT_P2P_SC_INFO_CHALLENGE` `"nodus.wsess.keys.v1/challenge"` (`:227-231`, unchanged). Host purpose 0x0A. |
| `extern const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_CLIENT;` (`:265`; defined `cmt_p2p_secret.c:44-47`) | **NEW.** DHT v2 client session: `"nodus.csess.transcript.v1"`, `"nodus.csess.keys.v1/aead"`, `"nodus.csess.keys.v1/challenge"`. Host purpose 0x0C. |
| `extern const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_NODE;` (`:268`; defined `cmt_p2p_secret.c:48-51`) | **NEW.** DHT v2 node-to-node session: `"nodus.nsess.transcript.v1"`, `"nodus.nsess.keys.v1/aead"`, `"nodus.nsess.keys.v1/challenge"`. Host purpose 0x0D. |
| `const cmt_p2p_sc_profile_t *profile;` field of `cmt_p2p_sc_t` (`:397`) | **NEW.** The connection's profile, set once at init, immutable; the pointed-to struct and strings must outlive the machine (the three consts do). |

### Init (`cmt_p2p_secret.h`)

| Signature | Description |
|-----------|-------------|
| `int cmt_p2p_sc_init_profile(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role, const cmt_p2p_sc_host_t *host, const cmt_p2p_sc_profile_t *profile, const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE], const uint8_t *local_kem_pk, const uint8_t *local_kem_sk, uint32_t proto_ver, const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])` (`:490-498`; `cmt_p2p_secret.c:463`) | **NEW.** `cmt_p2p_sc_init` with an explicit profile. `profile` must be one of the three consts BY POINTER (`sc_profile_ok`, `cmt_p2p_secret.c:68-76`): NULL, a copy of a const profile or any custom struct is refused, and each string must be 1 … `CMT_P2P_SC_PROFILE_STR_MAX` bytes (`sc_profile_str_ok`, `:54-63`). A refused profile returns `CMT_FAULT` with the machine DEAD (zeroed), before anything is generated. Other parameters and returns as `cmt_p2p_sc_init`. The transcript preimage is `tag ‖ fixed fields`, sized from the tag (`sc_derive`, `:364-408`). |
| `int cmt_p2p_sc_init(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role, const cmt_p2p_sc_host_t *host, const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE], const uint8_t *local_kem_pk, const uint8_t *local_kem_sk, uint32_t proto_ver, const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])` (`:473-479`; `cmt_p2p_secret.c:450-460`) | **CHANGED (body only, signature unchanged).** Now exactly `cmt_p2p_sc_init_profile(…, &CMT_P2P_SC_PROFILE_WITNESS, …)`. Starts a handshake: the INITIATOR queues its HELLO, the RESPONDER waits for one. `local_dsa_pk` copied; `local_kem_pk` / `local_kem_sk` RESPONDER only (the secret key is NOT copied — caller keeps it alive), NULL for the INITIATOR; `proto_ver` / `chain_id` (32 bytes) ride in the transcript. Returns `CMT_OK`; `CMT_FAULT` on a NULL / inconsistent argument or an RNG failure. |

### Session-auth signing purposes (`nodus/src/crypto/nodus_sign.h`)

All four are strict: `nodus_sign_purpose_is_strict` (`nodus_sign.h:146`; `nodus_sign.c:116-126`) is true for exactly {0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}, so sign and verify always use the NDS1 tagged preimage `"NDS1" ‖ purpose(1) ‖ u32 BE len ‖ challenge` (`NODUS_SIGN_HEADER_LEN` 9), no raw fallback either direction. Each returns 0 on success / valid, -1 otherwise (the `nodus_sign_tagged` / `nodus_verify_tagged` contract they forward to).

| Signature | Description |
|-----------|-------------|
| `#define NODUS_PURPOSE_CLIENT_SESSION_AUTH 0x0C` (`:84`) | **NEW.** DHT v2 client session authentication (profile `nodus.csess.*`). Strict. |
| `#define NODUS_PURPOSE_NODE_SESSION_AUTH 0x0D` (`:87`) | **NEW.** DHT v2 node-to-node session authentication (profile `nodus.nsess.*`). Strict. |
| `int nodus_sign_client_session_auth(nodus_sig_t *sig_out, const uint8_t *challenge, size_t challenge_len, const nodus_seckey_t *sk)` (`:214-216`; `nodus_sign.c:310`) | **NEW.** ML-DSA-87 signature over the session's 32-byte challenge under 0x0C. |
| `int nodus_verify_client_session_auth(const nodus_sig_t *sig, const uint8_t *challenge, size_t challenge_len, const nodus_pubkey_t *pk)` (`:217-219`; `nodus_sign.c:317`) | **NEW.** Verify under 0x0C only — a 0x0A or 0x0D signature over the same bytes does not verify. |
| `int nodus_sign_node_session_auth(nodus_sig_t *sig_out, const uint8_t *challenge, size_t challenge_len, const nodus_seckey_t *sk)` (`:220-222`; `nodus_sign.c:324`) | **NEW.** Same under 0x0D. |
| `int nodus_verify_node_session_auth(const nodus_sig_t *sig, const uint8_t *challenge, size_t challenge_len, const nodus_pubkey_t *pk)` (`:223-225`; `nodus_sign.c:331`) | **NEW.** Verify under 0x0D only. |
| `int nodus_sign_session_auth(nodus_sig_t *sig_out, const uint8_t *challenge, size_t challenge_len, const nodus_seckey_t *sk)` / `int nodus_verify_session_auth(const nodus_sig_t *sig, const uint8_t *challenge, size_t challenge_len, const nodus_pubkey_t *pk)` (`:203-208`; `nodus_sign.c:296`, `:303`) | Existing 4004 pair, purpose `NODUS_PURPOSE_SESSION_AUTH` 0x0A (`:73`), unchanged; listed as the sibling the new pairs mirror. |

Tests: `test_p2p_secret_kat` (4004 bytes pinned literally, passed on the unchanged base), `test_p2p_secret_profiles` (profiles, mixed pairs, purpose separation, refused profiles), `test_sign_domain_separation` §A (strict set {0x07-0x0D}, 0x0E not strict).

---

## SecretConnection layer of the TCP / WebSocket transport (`nodus/src/transport/nodus_tcp_sc.h`) — DHT v2 sub-package 3b-1

An OPTIONAL per-connection `cmt_p2p_sc_t` (the 4004 secret connection, CLIENT or NODE profile) between a `nodus_tcp` connection's socket — or its WebSocket payload — and the nodus frame parser; nodus frames travel unchanged inside the sealed stream. **NOT enabled on any port:** `git grep nodus_tcp_sc_enable` at `e0df99bcd` finds calls only in `nodus/tests/test_tcp_sc.c`; 3b-2 wires the 4001 / 4002 server, 3c the clients (`nodus_tcp_sc.h:7-11`). Compiled into libnodus only (`nodus_tcp_sc.c` in `NODUS_SOURCES`, `NODUS_TCP_SC=1` PRIVATE on the `nodus` target, `nodus/CMakeLists.txt:139`, `:1198`); a build that compiles `nodus_tcp.c` without the define (the web-wallet lists) has none of the behaviour, though the new struct fields below exist in every build. Mechanism, bounds, governing decisions and the record-vs-code note on incremental sealing: `nodus/docs/ARCHITECTURE.md` §15 "DHT v2 sub-package 3b-1". The other `nodus_tcp.h` entries remain in [dht.md](dht.md) §12.6-12.10.

**Locking:** the public queries take the transport's write lock (`nodus_tcp_set_write_lock`) and return copies; the transport-internal functions run with the lock held by the caller unless marked poll-thread-only. A callback that runs under the write lock (the `nodus_tcp_send_progress` progress callback, `tcp->on_pending_full`) must not call any `nodus_tcp_sc_*` query — non-recursive lock, self-deadlock (`nodus_tcp_sc.h:159-163`, `nodus_tcp.h:560-566`).

### Constants (`nodus_tcp_sc.h`; sizes are the implementation's — "NOT in the records", `:185`)

| Declaration | Description |
|-------------|-------------|
| `#define NODUS_SC_INLINE 1` (`:181-183`, defined when `__EMSCRIPTEN__`) | **NEW.** Inline (threadless) jobs: every handshake job runs on the loop and is applied at once; no worker, no queue. May also be defined by any single-thread build. |
| `#define NODUS_TCP_SC_WORKERS 2` (`:188`) | **NEW.** Worker threads of a transport's handshake worker (mirrors `NODUS_P2P_WORKERS_DEFAULT`). |
| `#define NODUS_TCP_SC_JOBQ_OUT 64` / `#define NODUS_TCP_SC_JOBQ_IN 64` (`:193-194`) | **NEW.** Outstanding jobs per class (queued + running + completed-not-applied): OUTBOUND (we dialed) / INBOUND (we accepted). Mirrors `NODUS_P2P_JOBQ_DEPTH`. One job per live connection at most, so also the number of handshakes a class advances at once. |
| `#define NODUS_TCP_SC_POLL_MS 5` (`:196`) | **NEW.** Longest `nodus_tcp_poll` wait (ms) while a job is outstanding or a loop-owned teardown is due. |
| `#define NODUS_TCP_SC_RAW_CHUNK 16384` (`:200`) | **NEW.** Socket bytes read per step of the layer's read path; also the hold-buffer capacity. |
| `#define NODUS_TCP_SC_WS_GROUP_FRAMES 32` (`:204`) | **NEW.** Sealed frames per WebSocket binary frame (32 × 1,044 = 33,408 bytes, 4-byte WS header; asserted at `:232-234`). |
| `NODUS_TCP_SC_PLAIN_MAX` / `_FRAMES_MAX` / `_SEALED_MAX` / `_WS_GROUPS_MAX` (`:207-214`) | **NEW.** Derived: header 7 + `NODUS_MAX_FRAME_TCP` = 5,242,887; ⌈÷ `CMT_P2P_SC_DATA_MAX_SIZE` (1024)⌉ = 5,121 (asserted `:228`); × `CMT_P2P_SC_SEALED_FRAME_SIZE` (1044) = 5,346,324 (asserted `:230`); ⌈5,121 ÷ 32⌉ = 161 groups. |
| `#define NODUS_TCP_SC_WS_HDR 4` / `#define NODUS_TCP_SC_WBUF_SLACK 4096` (`:215-216`) | **NEW.** Header of a 126..65,535-byte WS payload; the plain bound's slack. |
| `NODUS_TCP_SC_WBUF_MAX` (`:217-219`) | **NEW.** Write-buffer bound of a layer connection: sealed max + groups × 4 + 4,096 = 5,351,064 (asserted `nodus_tcp_sc.c:34`). |
| `NODUS_TCP_SC_RBUF_MAX` (`:225-226`) | **NEW.** Read-buffer (plaintext) bound of a layer connection: `NODUS_MAX_FRAME_TCP` + 7 + 4,096 + 16,384 = 5,263,367. |

### Enable and public queries

| Signature | Description |
|-----------|-------------|
| `typedef struct { cmt_p2p_sc_role_t role; const cmt_p2p_sc_profile_t *profile; const nodus_identity_t *id; uint32_t proto_ver; uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE]; const nodus_key_t *expected_peer; } nodus_tcp_sc_cfg_t;` (`:238-249`) | **NEW.** `role` INITIATOR / RESPONDER; `profile` `&CMT_P2P_SC_PROFILE_CLIENT` or `&CMT_P2P_SC_PROFILE_NODE` only (by pointer); `id` the signing key and, for a RESPONDER, the ML-KEM-1024 pair (`has_mlkem` required) — must outlive `nodus_tcp_close` (a queued or running job holds a pointer to it; the responder's KEM secret key is not copied); `proto_ver` a per-PORT symbol, never 4004's; `chain_id` 32 bytes; `expected_peer` INITIATOR: the node id (SHA3-512 of the public key) the caller meant to dial, required, copied; RESPONDER: ignored. |
| `int nodus_tcp_sc_enable(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn, const nodus_tcp_sc_cfg_t *cfg)` (`:265-266`; `nodus_tcp_sc.c:584`) | **NEW.** Turn the layer on, exactly once per connection. The profile picks the host's signing purpose: CLIENT → 0x0C (`nodus_{sign,verify}_client_session_auth`), NODE → 0x0D (`nodus_{sign,verify}_node_session_auth`); any other profile (WITNESS included) is refused. The connection must never have carried a byte (`io_started` false), have empty `rbuf` / `wbuf`, no auth pending buffer, no pending queue, `auth_state == NODUS_CONN_AUTH_NONE`, no peer id, not authenticated, no auth nonce pending, an all-zero session token, no channel crypto, not AF_UNIX, not closing — checked under the write lock before the machine init and again at publication. Responder: from `on_accept` (plain or WS; on WS the machine starts after the Upgrade). Initiator: right after `nodus_tcp_connect` or from `on_connect`; its HELLO goes into the write buffer here, and before its ENCAPS job the responder's claimed key must fingerprint to `expected_peer` (else the machine is aborted and the connection fails). The first enable on a transport starts its worker. Returns 0; -1 on a bad argument (NULL `tcp` / `conn` / `cfg` / `cfg->id`), a refused profile / pin / role, a connection that is not clean, a responder without ML-KEM, a machine-init failure, or an allocation / worker / HELLO-buffering failure — the connection left as it was. |
| `bool nodus_tcp_sc_authenticated(const nodus_tcp_conn_t *conn)` (`:269`; `nodus_tcp_sc.c:686`) | **NEW.** Layer enabled AND the machine AUTHENTICATED. Takes the write lock. False for NULL. |
| `int nodus_tcp_sc_peer_pubkey(const nodus_tcp_conn_t *conn, uint8_t out[CMT_P2P_SC_DSA_PK_SIZE])` (`:275-276`; `nodus_tcp_sc.c:699`) | **NEW.** Copy the peer's ML-DSA-87 public key once AUTHENTICATED. Returns 0; -1 before that, without the layer, or on a NULL argument (`out` untouched). A copy — `conn_free` wipes the machine. Takes the write lock. |
| `uint64_t nodus_tcp_sc_send_counter(const nodus_tcp_conn_t *conn)` (`:280`; `nodus_tcp_sc.c:720`) | **NEW.** The machine's send counter (tests: a refused send must not move it); 0 without the layer. Takes the write lock. |
| `uint64_t nodus_tcp_sc_generation(const nodus_tcp_conn_t *conn)` (`:285`; `nodus_tcp_sc.c:734`) | **NEW.** The generation given to this connection's layer at enable (from `++tcp->sc_gen_last`; never reused within a transport); 0 without the layer. Takes the write lock. |
| `int nodus_tcp_sc_outstanding(const nodus_tcp_t *tcp)` (`:289`; `nodus_tcp_sc.c:278`) | **NEW.** Jobs outstanding (queued + running + completed-not-applied), both classes; 0 without a worker, and always 0 in an inline build. |

### Transport-internal (`nodus_tcp_sc.h:291-420`; used by `nodus_tcp.c`, tests may call the job entry points)

| Signature | Description |
|-----------|-------------|
| `typedef struct nodus_sc_job { struct nodus_sc_job *next; int slot; uint64_t gen; int cls; cmt_p2p_sc_job_kind_t kind; int rc; bool charged; cmt_p2p_sc_host_t host; cmt_p2p_sc_job_t job; uint8_t kem_pk[CMT_P2P_SC_KEM_PK_SIZE]; uint8_t kem_ct[CMT_P2P_SC_KEM_CT_SIZE]; const uint8_t *kem_sk; uint8_t msg[CMT_P2P_SC_CHALLENGE_SIZE]; size_t msg_len; uint8_t dsa_pk[CMT_P2P_SC_DSA_PK_SIZE]; uint8_t sig[CMT_P2P_SC_SIG_SIZE]; uint8_t kem_ct_out[CMT_P2P_SC_KEM_CT_SIZE]; uint8_t kem_ss_out[CMT_P2P_SC_KEM_SS_SIZE]; uint8_t sig_out[CMT_P2P_SC_SIG_SIZE]; } nodus_sc_job_t;` (`:295-315`) | **NEW.** One handshake job: a self-contained copy of the machine's job (`cls` 0 OUTBOUND, 1 INBOUND; `rc` = `cmt_p2p_sc_job_run`'s result; `charged` = counted in the worker's bound until applied; `host` by value; `kem_sk` the responder's caller-owned key). Zeroed on free. |
| `typedef enum { NODUS_SC_APPLY_DISCARDED = 0, NODUS_SC_APPLY_OK, NODUS_SC_APPLY_FAIL } nodus_sc_apply_t;` (`:317-321`) | **NEW.** Stale (slot, generation): job freed, nothing done / applied, `*conn_out` to resume / applied and `*conn_out` must close. |
| `nodus_sc_job_t *nodus_tcp_sc_take_done(nodus_tcp_t *tcp)` (`:325`; `nodus_tcp_sc.c:257`) | **NEW.** Take the finished jobs off the worker, oldest first; each stays charged until applied. NULL when none (always NULL inline). |
| `nodus_sc_apply_t nodus_tcp_sc_job_apply(nodus_tcp_t *tcp, nodus_sc_job_t *job, nodus_tcp_conn_t **conn_out)` (`:336-337`; `nodus_tcp_sc.c:494`) | **NEW.** Apply one finished job by (slot, generation) and FREE it in every case (releasing its charge). DISCARDED when an argument is NULL, or `tcp->pool[job->slot]` is empty, closing, claimed for teardown, has no layer, another generation, is not waiting for a job, or waits for another kind. FAIL when the machine's job does not match, `cmt_p2p_sc_job_done` fails, or the next step fails (e.g. the dial pin). OK: the machine advanced, the next job (if any) already submitted. Caller holds the write lock. Tests may pass a fabricated stale job (must be `malloc`'d). |
| `int nodus_tcp_sc_poll_timeout(const nodus_tcp_t *tcp, int timeout_ms)` (`:340`; `nodus_tcp_sc.c:310`) | **NEW.** `NODUS_TCP_SC_POLL_MS` when `nodus_tcp_sc_busy` and `timeout_ms` is < 0 or > 5; else `timeout_ms`. |
| `bool nodus_tcp_sc_busy(const nodus_tcp_t *tcp)` (`:347`; `nodus_tcp_sc.c:296`) | **NEW.** True while jobs are outstanding or a loop-owned teardown is due (`tcp->sc_close_requests > 0`). `nodus_tcp_poll` must not return early then; an owner polling several transports in one loop must include this predicate of EVERY transport in its wait (a 3b-2 obligation). Takes the write lock. |
| `void nodus_tcp_sc_worker_stop(nodus_tcp_t *tcp)` (`:350`; `nodus_tcp_sc.c:318`) | **NEW.** Called by `nodus_tcp_close` after the pool is freed: stop and join the threads, free every queued / finished job, free the worker, `tcp->sc_worker = NULL`. |
| `void nodus_tcp_sc_free(nodus_tcp_conn_t *conn)` (`:353`; `nodus_tcp_sc.c:753`) | **NEW.** Called by `conn_free`: zero and release the machine and the hold buffer; `conn->sc = NULL`. |
| `int nodus_tcp_sc_flush_hs(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn)` (`:362`; IMPLEMENTED BY `nodus_tcp.c:1076`) | **NEW.** Move the machine's pending output (handshake messages, not nodus frames) into the write buffer — one WS binary frame on a WS connection — then push what the socket takes if connected. Takes the write lock itself. Returns 0; -1 only if the bytes could not be buffered. |
| `typedef int (*nodus_tcp_sc_plain_fn)(void *ctx, const uint8_t *data, size_t len);` (`:365`) | **NEW.** Receives plaintext the machine opened; return 0, or -1 to fail the feed. |
| `int nodus_tcp_sc_feed(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn, const uint8_t *raw, size_t n, nodus_tcp_sc_plain_fn plain, void *plain_ctx)` (`:378-380`; `nodus_tcp_sc.c:889`) | **NEW.** Hand `n` raw bytes (socket bytes or one WS payload; `n` may be 0 = resume held input and drain plaintext the machine already holds) to the layer; drives the machine as far as the input allows, plaintext to `plain`, jobs submitted here; bytes it cannot take while a job is outstanding are held (≤ `NODUS_TCP_SC_RAW_CHUNK`). Caller holds the write lock. Returns 0; -1 = fail the connection (no layer, NULL `plain`, NULL `raw` with `n > 0`, handshake rejected, bad frame, pin mismatch, queue full, hold overflow, `plain` refused, input left over with no job outstanding). |
| `bool nodus_tcp_sc_blocked(const nodus_tcp_conn_t *conn)` (`:386`; `nodus_tcp_sc.c:769`) | **NEW.** A job is outstanding or bytes are held: do not read the socket. POLL-THREAD-ONLY, no lock. |
| `const uint8_t *nodus_tcp_sc_out(const nodus_tcp_conn_t *conn, size_t *len)` / `void nodus_tcp_sc_out_consume(nodus_tcp_conn_t *conn, size_t n)` (`:390-391`; `nodus_tcp_sc.c:776`, `:785`) | **NEW.** The bytes the machine wants written (`*len` 0 and NULL without the layer); consume what was copied out. |
| `bool nodus_tcp_sc_take_ready(nodus_tcp_conn_t *conn)` (`:395`; `nodus_tcp_sc.c:791`) | **NEW.** True ONCE after the machine became AUTHENTICATED: the cue to fire `tcp->on_session` (invoked by the caller after the lock is released). Takes the write lock. |
| `size_t nodus_tcp_sc_sealed_size(size_t plain_len)` (`:399`; `nodus_tcp_sc.c:937`) | **NEW.** ⌈`plain_len` / 1024⌉ × 1044, without WS framing. |
| `bool nodus_tcp_sc_can_seal(const nodus_tcp_conn_t *conn, size_t nframes)` (`:403`; `nodus_tcp_sc.c:943`) | **NEW.** Authenticated AND the send counter can take `nframes` more. Write lock held by the caller. |
| `bool nodus_tcp_sc_dead(const nodus_tcp_conn_t *conn)` (`:408`; `nodus_tcp_sc.c:748`) | **NEW.** The machine is DEAD (cipher failure, reject) — sealing failed for good, as opposed to a refusal that leaves the session intact. Write lock held by the caller. |
| `int nodus_tcp_sc_seal(nodus_tcp_conn_t *conn, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, size_t first, size_t nframes, uint8_t *out)` (`:417-420`; `nodus_tcp_sc.c:952`) | **NEW.** Seal frames [`first`, `first + nframes`) of the logical stream `a ‖ b` into `out` (`nframes` × 1044 bytes, caller-reserved), one `cmt_p2p_sc_write` per frame; the caller checked `nodus_tcp_sc_can_seal` for the whole unit first. Returns 0; -1 on a cipher failure (the machine is dead — the connection is marked for a loop-owned close). |

### New fields and changed comments in `nodus/src/transport/nodus_tcp.h`

| Declaration | Description |
|-------------|-------------|
| `#include <stdatomic.h>` (`:18`) | **NEW.** For `io_started`. |
| `struct nodus_tcp_sc *sc;` (`nodus_tcp_conn_t`, `:277`) | **NEW.** The layer; NULL = not enabled (every path is the plaintext / channel-crypto path). Set by `nodus_tcp_sc_enable`, released by `conn_free`. Opaque so the header stays free of the secret-connection headers. |
| `atomic_bool io_started;` (`nodus_tcp_conn_t`, `:283`) | **NEW.** Sticky: the first byte read from or written to the socket sets it (relaxed; set by the reader and, under the write lock, the sender); nothing clears it. Enable requires it false. Set on every connection, layer or not. |
| `bool sc_close_req;` (`:289`) / `bool sc_closing;` (`:294`) (`nodus_tcp_conn_t`) | **NEW.** Loop-owned teardown: a fatal sealing failure marks `sc_close_req` (counted in `tcp->sc_close_requests`); the next `nodus_tcp_poll` claims the connection under the write lock (`sc_close_req` cleared, `sc_closing` set) and runs `on_disconnect` + `conn_free` unlocked. A claimed connection is skipped by a nested poll, and `nodus_tcp_disconnect` on it is a no-op. |
| `bool ws_close_wait; uint8_t ws_close_len; uint8_t ws_close_frame[4];` (`nodus_tcp_conn_t`, `:300-302`) | **NEW.** A WebSocket Close that arrived while a handshake job held the input before it: the close frame to send is kept; the connection closes once that input has been opened and dispatched, in order, after `on_session`. |
| `nodus_tcp_event_fn on_session;` (`nodus_tcp_t`, `:438`) | **NEW.** `void (*)(nodus_tcp_conn_t *conn, void *ctx)` (`nodus_tcp_event_fn`, `:313`), called with `tcp->cb_ctx`: a layer connection has just become AUTHENTICATED — the first moment a nodus frame may be sent on it. Runs inside `nodus_tcp_poll`, never inside a socket-read callback, without the write lock; may be NULL. |
| `struct nodus_sc_worker *sc_worker;` (`nodus_tcp_t`, `:439`) | **NEW.** The bounded handshake-job worker of this transport: started by the first `nodus_tcp_sc_enable`, stopped by `nodus_tcp_close`; NULL until then (always NULL inline). |
| `uint64_t sc_gen_last;` (`nodus_tcp_t`, `:440`) | **NEW.** Last generation handed out; a job's result is applied only if its pool slot still holds the connection that generation was given to. |
| `int sc_close_requests;` (`nodus_tcp_t`, `:441`) | **NEW.** Connections with `sc_close_req` set. |
| `int nodus_tcp_send_progress(nodus_tcp_conn_t *conn, const uint8_t *payload, size_t len, nodus_tcp_progress_cb progress_cb, void *user_data)` (comment `:560-566`) | **CHANGED (contract note, signature unchanged).** `progress_cb` and `tcp->on_pending_full` run with the write lock held when one is installed: besides not sending on this transport they must not call the `nodus_tcp_sc_*` queries (self-deadlock). With the layer on, `nodus_tcp_send` / `_send_progress` return -1 before AUTHENTICATED or when the counter cannot take the whole frame (nothing sealed or queued), and -1 on a sealing failure (connection marked, `on_pending_full` NOT called). |

Test: `test_tcp_sc` (`nodus/CMakeLists.txt:1569-1571`, default build).

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
