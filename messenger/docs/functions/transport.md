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
| `int nodus_net_probe_connect(nodus_sock_t s)` | **NEW.** Has the non-blocking connect on `s` finished (either way)? Does not block. Linux: `poll({s, POLLOUT}, 1, 0)`; Windows: a one-socket `select` on the write and except sets. Returns > 0 finished, 0 still connecting, < 0 error (Linux `poll`'s -1, Windows `select`'s `SOCKET_ERROR`) — a caller must NOT read < 0 as "still connecting". Success (`SO_ERROR`, `getpeername`) is the caller's check. p2p's caller (`io_connect_done`, `nodus_p2p_host.c:708`) still tests `<= 0` at nodus 0.26.15 — correct on Linux only; the header's "revisited in package N3" (`nodus_net_poll.h:225-226`) did not happen in N3. |

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
