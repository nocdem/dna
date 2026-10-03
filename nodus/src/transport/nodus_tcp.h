/**
 * Nodus — TCP Transport
 *
 * Cross-platform non-blocking TCP with connection pool and frame-based I/O.
 * Linux/Android: uses epoll for server (high-perf multi-connection).
 * Windows: uses select() (client SDK only — server is Linux-only).
 *
 * @file nodus_tcp.h
 */

#ifndef NODUS_TCP_H
#define NODUS_TCP_H

#include "nodus/nodus_types.h"
#include "crypto/nodus_channel_crypto.h"
#include "transport/nodus_ws.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_TCP_MAX_CONNS   1024
#define NODUS_TCP_BUF_INIT    (64 * 1024)    /* Initial read/write buffer */
#define NODUS_TCP_PENDING_MAX  (5 * 1024 * 1024)   /* 5MB auth pending queue cap */

/* Read budget: the most one connection may consume in ONE nodus_tcp_poll
 * call (see "Read budget" in nodus/docs/ARCHITECTURE.md). A connection that
 * reaches either limit before its socket returns EAGAIN stops for this call
 * and is put on nodus_tcp_t.read_head; the next call services it after its
 * own socket events (and waits 0 ms in epoll_wait/select while that list is
 * non-empty), so the
 * edge-triggered event it will not get again is never needed.
 *   FRAMES: nodus frames taken off rbuf (dispatched or dropped) plus
 *           WebSocket pings answered — the per-frame work a peer can force.
 *   BYTES:  socket bytes read. Bounds what the frame count cannot see:
 *           empty WS data frames and pongs, which reach no callback. At
 *           256 KiB a 5 MiB NODUS_MAX_FRAME_TCP frame needs 20 calls. */
#define NODUS_TCP_READ_BUDGET_FRAMES  256
#define NODUS_TCP_READ_BUDGET_BYTES   (256 * 1024)

/* Local IPC over a Unix domain socket (component split, decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md item 7: socket
 * file under /var/lib/nodus, mode 0600, the connecting process checked with
 * SO_PEERCRED). Same transport, pool, framing and callbacks as TCP.
 *
 * NODUS_TCP_UNIX_PEER_IP: the text put in conn->ip of every AF_UNIX
 * connection (conn->port = 0). It is not an IP address — inet_pton fails on
 * it, so no code can dial it, and it can never equal an inet_ntop result,
 * so it never matches a TCP peer in an ip comparison.
 * NODUS_TCP_UNIX_UID_SELF: allowed_uid value meaning "this process's
 * effective uid", resolved when nodus_tcp_unix_listen (allowed_uid) or
 * nodus_tcp_unix_connect (expected_uid) runs. (uid_t)-1 is
 * not a valid uid on Linux, so it cannot collide with a real one. */
#define NODUS_TCP_UNIX_PEER_IP    "unix"
#define NODUS_TCP_UNIX_UID_SELF   UINT32_MAX
#define NODUS_TCP_UNIX_PATH_MAX   108   /* sizeof(sockaddr_un.sun_path) on Linux */

/* ── Connection ──────────────────────────────────────────────────── */

typedef enum {
    NODUS_CONN_CLOSED = 0,
    NODUS_CONN_CONNECTING,
    NODUS_CONN_CONNECTED
} nodus_conn_state_t;

typedef enum {
    NODUS_CONN_AUTH_NONE = 0,
    NODUS_CONN_AUTH_HELLO_SENT,
    NODUS_CONN_AUTH_OK,
    NODUS_CONN_AUTH_FAILED
} nodus_conn_auth_state_t;

/* Phase 3: Pending frame queued while wbuf is over the send cap.
 * The frame is already encoded (header + encrypted payload) and ready to
 * blast into wbuf as soon as space becomes available. Stored FIFO. */
typedef struct nodus_pending_frame {
    struct nodus_pending_frame *next;
    uint8_t                    *encoded;      /* malloc'd, owned */
    size_t                      frame_size;   /* encoded bytes including 7-byte header */
    uint64_t                    enqueued_at;  /* monotonic ms for diagnostics */
} nodus_pending_frame_t;

typedef struct nodus_tcp_conn {
    int                 fd;
    nodus_conn_state_t  state;
    char                ip[64];
    uint16_t            port;

    /* Read buffer (accumulates until full frame) */
    uint8_t            *rbuf;
    size_t              rlen;
    size_t              rcap;

    /* Write buffer (outgoing frames queued) */
    uint8_t            *wbuf;
    size_t              wlen;     /* total buffered bytes */
    size_t              wcap;
    size_t              wpos;     /* bytes already sent */

    /* Peer identity (set after authentication) */
    nodus_key_t         peer_id;
    nodus_pubkey_t      peer_pk;
    uint8_t             session_token[NODUS_SESSION_TOKEN_LEN];
    bool                peer_id_set;
    bool                is_nodus;    /* true = Nodus peer, false = client */

    /* CRIT-1: EXPECTED peer identity, set by the DIALER at connect time from
     * the routing/roster entry it dialed — i.e. "who we believe we are calling".
     * Deliberately distinct from `peer_id` above, which is the VERIFIED identity
     * written only after authentication: conflating the two would let a reader
     * mistake an unverified expectation for a proven identity, which is exactly
     * the confusion the kyber_pk pin exists to prevent. The dialer pins
     * fingerprint(server_pk) against this before Kyber-encapsulating, so an
     * on-path attacker cannot substitute its own self-consistent
     * (server_pk, kyber_pk, kpk_sig) triple. */
    nodus_key_t         expected_peer_id;
    bool                expected_peer_id_set;

    /* C-01/C-02: Auth state for inter-node and witness ports */
    uint8_t             auth_nonce[NODUS_NONCE_LEN];
    bool                auth_nonce_pending;
    bool                authenticated;   /* Dilithium5 challenge-response completed */

    /* C2 fix: set true when WE opened this outbound conn (via nodus_tcp_connect).
     * Challenge handlers only sign auth responses on outbound conns to close the
     * Dilithium5 signing oracle. Default false (calloc zero init) so inbound
     * accepted conns correctly reject challenge frames. */
    bool                auth_initiated_by_us;

    /* Auth state machine (inter-node / witness connections) */
    nodus_conn_auth_state_t auth_state;
    bool                    auth_required;

    /* Pending frame queue (buffered while auth in progress) */
    uint8_t                *pending_buf;
    size_t                  pending_len;
    size_t                  pending_cap;

    void               *user_data;
    uint64_t            connected_at;
    uint64_t            last_activity;
    int                 slot;        /* Index in pool */

    /* Channel encryption — owned per-conn (B3 fix). Inline storage
     * eliminates the pointer-aliasing race that caused production
     * "Replay detected: counter=N < expected=M" loops when multiple
     * conns recycled through the same slot shared a session-level cc
     * struct. Encrypt/decrypt sites read &conn->channel_crypto directly;
     * established=false (zero-init) until handshake completes. */
    nodus_channel_crypto_t channel_crypto;

    /* Send diagnostics (Phase 1 visibility — no behavior change) */
    uint64_t            send_ok_count;      /* frames accepted into wbuf */
    uint64_t            send_full_count;    /* buf_ensure failed (wbuf cap exceeded) */
    uint64_t            send_bytes_total;   /* cumulative plaintext bytes offered to wbuf */
    /* O15B §8: writes that failed unrecoverably (peer gone / fatal / stalled)
     * in the immediate-send path, as opposed to send_full_count, which counts
     * buffer-capacity refusals BEFORE anything reached the socket. Kept
     * separate because "the peer hung up" and "we ran out of local buffer"
     * call for opposite operator responses. */
    uint64_t            send_error_count;

    /* Phase 3: parent transport back-pointer so send path can invoke the
     * pending-full callback without global state. Set in conn_alloc. */
    struct nodus_tcp *tcp_parent;

    /* Phase 3: Pending queue (FIFO) for frames that can't fit into wbuf right now.
     * Drained by handle_write whenever wbuf gets space. */
    nodus_pending_frame_t *pending_head;
    nodus_pending_frame_t *pending_tail;
    size_t              pending_count;
    size_t              pending_bytes;
    uint64_t            pending_enqueued_count;      /* lifetime frames queued */
    uint64_t            pending_drained_count;       /* lifetime frames promoted from queue to wbuf */
    uint64_t            pending_hint_fallback_count; /* lifetime frames that spilled to hint table */

    /* Phase 3.2a: crypto-path visibility — decrypt failures are currently
     * silently logged once and the frame skipped. Counter lets us correlate
     * these with upstream "T1 decode failed" asymmetry. */
    uint64_t            decrypt_skip_count;

    /* Phase 3.2b-inv: one-shot flag so we log TX_ENCRYPT_FIRST only once
     * per conn lifetime (per-frame would flood the journal). */
    bool                tx_encrypt_logged;

    /* Phase 3.2b-inv2: one-shot flag for PENDING_DRAIN log. */
    bool                drain_logged;

    /* Phase 3.2c: one-shot flag for INTER_FRAME_FIRST log + tag bitmap so
     * dispatch_inter only logs each handshake message once per conn. Bits:
     * 0=hello 1=challenge 2=auth 3=auth_ok 4=key_init 5=key_ack */
    bool                first_frame_logged;
    uint8_t             dispatch_logged_mask;

    /* Phase 3.2d: one-shot flag for first SEND log per conn. */
    bool                first_send_logged;

    /* WebSocket entry (nodus_ws.h). is_ws: accepted on the transport's
     * ws_listen_fd; lives in the SAME pool / slot space as the plain
     * connections, so session indexing, same-identity eviction and the
     * idle sweep cover it unchanged. ws_open: the HTTP Upgrade completed —
     * until then no nodus frame is read from or written to it. After it,
     * inbound WS payload is unmasked into rbuf and every outbound nodus
     * frame is wrapped in one binary WS frame (conn_wire_encode). */
    bool                is_ws;
    bool                ws_open;
    nodus_ws_parser_t   ws;
    /* Per-IP limit key of the real client address (IPv6 by /64), set when
     * the Upgrade completes — compared instead of the text in `ip`. */
    nodus_ws_ip_bucket_t ws_bucket;

    /* Unix domain socket entry (nodus_tcp_unix_listen / _unix_connect).
     * is_unix: this connection is AF_UNIX — ip is NODUS_TCP_UNIX_PEER_IP,
     *   port is 0; the per-IP limit, TCP keepalive and TCP_NODELAY do not
     *   apply to it.
     *   It stays PLAINTEXT: the transport encrypts/decrypts only when
     *   channel_crypto.established is true (try_parse_frames, send path),
     *   which is zero in conn_alloc and is never set by this file — only the
     *   host's key_init handshake handlers set it. A host must not run that
     *   handshake on an is_unix connection; local-only traffic is protected
     *   by the 0600 socket file and the SO_PEERCRED uid check instead.
     * peer_uid / peer_pid: SO_PEERCRED of the peer process, recorded on
     *   accept (valid only when is_unix && peer_cred_set). */
    bool                is_unix;
    bool                peer_cred_set;
    uint32_t            peer_uid;
    int32_t             peer_pid;

    /* Deferred close (see "Connection close" in nodus/docs/ARCHITECTURE.md).
     * close_pending: the connection has been torn down — on_disconnect has
     * run, the socket is closed (fd = -1, state = CLOSED) and it has left
     * the pool — but its memory is still owned by the transport because a
     * poll batch was in progress. The transport never processes it again;
     * it is released when the outermost nodus_tcp_poll returns.
     * close_next: link in nodus_tcp_t.close_list. */
    bool                   close_pending;
    struct nodus_tcp_conn *close_next;

    /* Read budget (NODUS_TCP_READ_BUDGET_*).
     * read_pending: on nodus_tcp_t.read_head — its read stopped on the budget,
     *   or complete frames are still in rbuf; read_next links that FIFO.
     *   conn_free unlinks it, so the list never holds a closing connection.
     * read_active: its read handler is running (a callback may poll again;
     *   the nested call re-queues it instead of re-entering it).
     * read_gen: the nodus_tcp_t.poll_gen of the call that last serviced it,
     *   so one call never services it twice (epoll event + list).
     * read_bytes_left / read_frames_left: what is left of the budget of the
     *   service in progress (frames may go below 0 by the pings of one chunk). */
    bool                   read_pending;
    bool                   read_active;
    struct nodus_tcp_conn *read_next;
    uint64_t               read_gen;
    size_t                 read_bytes_left;
    int                    read_frames_left;
} nodus_tcp_conn_t;

/* ── Callbacks ───────────────────────────────────────────────────── */

/** Called when a complete frame payload is received */
typedef void (*nodus_tcp_frame_fn)(nodus_tcp_conn_t *conn,
                                    const uint8_t *payload, size_t len,
                                    void *ctx);

/** Called on connection events (accept, connect, disconnect) */
typedef void (*nodus_tcp_event_fn)(nodus_tcp_conn_t *conn, void *ctx);

/**
 * Phase 3: Called when a send cannot fit into wbuf AND the pending queue
 * is also full (frames or bytes cap exhausted). The handler is expected
 * to persist the frame elsewhere (e.g. hint table) so it is not lost.
 * If the handler is NULL, the frame is dropped with an error log
 * (legacy behavior).
 */
typedef void (*nodus_tcp_pending_full_fn)(nodus_tcp_conn_t *conn,
                                           const uint8_t *payload, size_t len,
                                           void *ctx);

/* ── TCP Transport ───────────────────────────────────────────────── */

typedef struct nodus_tcp {
    int                 listen_fd;
#ifdef _WIN32
    int                 poll_fd;     /* unused on Windows, kept for compat */
#else
    int                 epoll_fd;
#endif
    bool                owns_epoll;

    nodus_tcp_conn_t   *pool[NODUS_TCP_MAX_CONNS];
    int                 count;

    /* D2.4: cumulative post-established AEAD decrypt failures across ALL conns
     * on this transport, INCLUDING conns that have since been freed. The
     * per-conn decrypt_skip_count dies with the conn (conn_free), so a gate that
     * sums the live pool reads 0 precisely when a failure caused a teardown —
     * i.e. it is blind to the regression it exists to catch. conn_free folds the
     * per-conn count in here before freeing. On a healthy cluster this MUST stay
     * 0: on an ordered TCP stream there is no legitimate post-established
     * decrypt failure. */
    uint64_t            decrypt_fail_total;

    /* Callbacks */
    nodus_tcp_frame_fn  on_frame;
    nodus_tcp_event_fn  on_accept;
    nodus_tcp_event_fn  on_connect;
    nodus_tcp_event_fn  on_disconnect;
    void               *cb_ctx;

    uint16_t            port;
    bool                level_triggered; /* disable EPOLLET when true */

    bool                auth_required;     /* New conns inherit this */
    void               *auth_ctx;          /* nodus_identity_t* for hello/sign */

    /* Phase 3: pending-full fallback hook. May be NULL (legacy drop). */
    nodus_tcp_pending_full_fn on_pending_full;
    void                    *pending_full_ctx;

    /* WebSocket entry: a SECOND listening socket of this same transport,
     * bound to 127.0.0.1 only (nodus_tcp_ws_listen). -1 = off. Its epoll
     * data.ptr is &ws_listen_fd (the plain listener uses NULL). */
    int                       ws_listen_fd;
    uint16_t                  ws_port;
    const nodus_ws_origins_t *ws_origins;   /* owned by the caller; outlives tcp */

    /* Unix domain socket entry: a THIRD listening socket of this transport
     * (nodus_tcp_unix_listen). -1 = off. Its epoll data.ptr is
     * &unix_listen_fd. unix_allowed_uid: the only uid accepted (SO_PEERCRED).
     * unix_dev / unix_ino: the socket file this transport created, so
     * nodus_tcp_close unlinks only that file and never one a later process
     * bound at the same path. */
    int                       unix_listen_fd;
    uint32_t                  unix_allowed_uid;
    char                      unix_path[NODUS_TCP_UNIX_PATH_MAX];
    uint64_t                  unix_dev;
    uint64_t                  unix_ino;

    /* Deferred close. poll_depth > 0 while nodus_tcp_poll is running on
     * this transport, and around the on_connect that nodus_tcp_connect
     * runs itself on an immediate connect (a depth, not a flag: a callback
     * may poll again).
     * Every connection torn down while it is > 0 is detached at once and
     * parked on close_list; its memory is released only when the depth
     * returns to 0, so no pointer still held by the event batch, by
     * try_parse_frames or by a callback's caller can dangle. Not atomic:
     * callers that poll from one thread and disconnect from another must
     * serialise the two themselves (nodus_client.c does, poll_mutex). */
    int                       poll_depth;
    nodus_tcp_conn_t         *close_list;

    /* Read budget: FIFO of connections with input left over from an earlier
     * call (conn->read_pending). Serviced at the end of every nodus_tcp_poll
     * call, after that call's socket events; epoll_wait / select wait 0 ms
     * while it is non-empty. poll_gen: generation of the call in progress
     * (a nested call gets its own and restores this one on return);
     * poll_gen_last: the last generation handed out. */
    nodus_tcp_conn_t         *read_head;
    nodus_tcp_conn_t         *read_tail;
    int                       read_count;
    uint64_t                  poll_gen;
    uint64_t                  poll_gen_last;

    /* Write-side lock hook (nodus_tcp_set_write_lock). NULL = no lock: the
     * server does all of its I/O on one thread. A user that sends on one
     * thread while another runs nodus_tcp_poll — nodus_client.c: callers
     * send, the read thread polls and drains — installs it, and the
     * transport then holds it around every read or write of a connection's
     * wbuf / wpos / wlen / pending queue, on the send path and on the poll
     * side alike, and never across a callback. Without it both threads
     * flushed the same wbuf range: the same frame went out twice, and a
     * realloc under the other thread's write crashed the process. */
    void                    (*write_lock)(void *ctx, bool lock);
    void                     *write_lock_ctx;
} nodus_tcp_t;

/**
 * Initialize TCP transport.
 * @param shared_epoll_fd  If >= 0, use this epoll fd (Linux only). Otherwise creates own.
 *                         Ignored on Windows.
 */
int nodus_tcp_init(nodus_tcp_t *tcp, int shared_epoll_fd);

/** Start listening for incoming connections (server only, Linux). */
int nodus_tcp_listen(nodus_tcp_t *tcp, const char *bind_ip, uint16_t port);

/**
 * Open the WebSocket entry: a second listening socket on this transport,
 * bound to 127.0.0.1:port (never any other address — TLS and the public
 * side belong to the local proxy). Accepted connections share the pool,
 * callbacks and slot space with the plain listener and carry is_ws.
 * @param origins  allowed Origin list; must outlive the transport.
 * Linux only (returns -1 on Windows).
 */
int nodus_tcp_ws_listen(nodus_tcp_t *tcp, uint16_t port,
                        const nodus_ws_origins_t *origins);

/**
 * Close WebSocket connections whose Upgrade has not completed within
 * NODUS_WS_HANDSHAKE_TIMEOUT_S of connected_at, as of `now` (seconds,
 * nodus_time_now() scale). Schedules only this node's own connection
 * housekeeping. Returns the number closed.
 */
int nodus_tcp_ws_sweep(nodus_tcp_t *tcp, uint64_t now);

/** Connect to a remote peer (non-blocking). Returns connection or NULL. */
nodus_tcp_conn_t *nodus_tcp_connect(nodus_tcp_t *tcp,
                                     const char *ip, uint16_t port);

/**
 * Open the Unix domain socket entry: a listening AF_UNIX stream socket at
 * `path`, sharing this transport's pool, callbacks and slot space.
 *
 * - path must be shorter than NODUS_TCP_UNIX_PATH_MAX.
 * - An existing file at path: a regular file / directory / anything that is
 *   not a socket → -1, left untouched. A socket that accepts a connection
 *   (a live listener) → -1, left untouched. A socket that refuses
 *   (ECONNREFUSED: stale, its listener is gone) → unlinked, then bound.
 * - Checked FIRST, before anything at path is touched: the parent
 *   directory of path, by lstat (a symlink there is refused, not
 *   followed), must be a directory owned by this process's euid or by
 *   root, with no group/other write bit (mode & 022 == 0). Otherwise an
 *   ERROR names the directory and -1 is returned; no file is created.
 * - The socket file is created with mode 0600 (bind under umask 0177) and
 *   verified with lstat; anything other than exactly 0600 → the listener
 *   is closed and -1 returned (no chmod repair: chmod follows symlinks).
 * - On every failure after bind the file is removed only if lstat still
 *   shows the socket with the dev/ino this call bound.
 * - Every accepted peer is checked with SO_PEERCRED: a peer whose uid is
 *   not allowed_uid (NODUS_TCP_UNIX_UID_SELF = this process's euid), or
 *   whose credentials cannot be read, is closed before a connection is
 *   allocated — on_accept never runs for it.
 * - One listener event accepts every queued peer, up to 64 per event (the
 *   rest on the next poll); a peer dropped because the pool is full is
 *   logged with a WARN.
 * nodus_tcp_close closes the listener and unlinks the file if it is still
 * the one this call created.
 * One per transport (a second call returns -1). Linux only (-1 elsewhere).
 */
int nodus_tcp_unix_listen(nodus_tcp_t *tcp, const char *path,
                          uint32_t allowed_uid);

/**
 * Connect to a Unix domain socket at `path`. AF_UNIX connect completes
 * immediately or fails (it never reports EINPROGRESS), so the returned
 * connection is already CONNECTED and on_connect has run; NULL on any
 * failure (no listener, backlog full, permission, path too long) or if
 * on_connect closed it. Inherits tcp->auth_required like nodus_tcp_connect.
 * The connection is is_unix and plaintext (see nodus_tcp_conn_t.is_unix).
 * The server is checked too: after connect, SO_PEERCRED on the dialing fd
 * (the credentials of the process that listens on the socket) must show
 * uid == expected_uid (NODUS_TCP_UNIX_UID_SELF = this process's euid,
 * decided by nodus_tcp_unix_peercred_ok). Unreadable credentials or a
 * different uid → WARN, socket closed, NULL; no connection is allocated
 * and on_connect does not run.
 * Linux only (NULL elsewhere).
 */
nodus_tcp_conn_t *nodus_tcp_unix_connect(nodus_tcp_t *tcp, const char *path,
                                         uint32_t expected_uid);

/**
 * The SO_PEERCRED admission decision of the Unix listener, exposed so it
 * can be tested with injected credentials. True iff peer_uid ==
 * allowed_uid. allowed_uid must already be resolved (never
 * NODUS_TCP_UNIX_UID_SELF): that value, being no valid uid, admits nobody.
 */
bool nodus_tcp_unix_peercred_ok(uint32_t peer_uid, uint32_t allowed_uid);

/**
 * Progress callback for send operations.
 * @param bytes_sent  cumulative bytes sent so far
 * @param total_bytes total bytes to send (frame header + payload)
 * @param user_data   opaque pointer passed through
 */
typedef void (*nodus_tcp_progress_cb)(size_t bytes_sent, size_t total_bytes,
                                       void *user_data);

/**
 * Send a framed payload (7-byte header prepended automatically).
 * Data is buffered and flushed on next poll.
 */
int nodus_tcp_send(nodus_tcp_conn_t *conn,
                    const uint8_t *payload, size_t len);

/**
 * Send a framed payload with progress reporting.
 * Same as nodus_tcp_send but calls progress_cb after each partial write.
 * progress_cb (and tcp->on_pending_full) run with the write lock held when
 * one is installed: they must not send on this transport.
 */
int nodus_tcp_send_progress(nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len,
                             nodus_tcp_progress_cb progress_cb,
                             void *user_data);

/** Internal: send bypassing auth gate. For hello/auth frames only. */
int nodus_tcp_send_raw(nodus_tcp_conn_t *conn,
                        const uint8_t *payload, size_t len);

/** Flush pending auth queue to write buffer. Called when auth completes. */
int nodus_tcp_pending_flush(nodus_tcp_conn_t *conn);

/**
 * Install the write-side lock (see nodus_tcp_t.write_lock). fn(ctx, true)
 * must acquire and fn(ctx, false) release one non-recursive lock that no
 * other code path takes while calling into this transport — the transport
 * takes it inside nodus_tcp_send / _send_progress / _send_raw /
 * _pending_flush and inside nodus_tcp_poll's write drain, so a caller that
 * already holds it when calling them deadlocks. Install before the first
 * connection is made; NULL fn removes it.
 */
void nodus_tcp_set_write_lock(nodus_tcp_t *tcp,
                              void (*fn)(void *ctx, bool lock), void *ctx);

/**
 * Poll for events. Returns number of events processed (socket events plus
 * connections serviced from the pending-read list), or -1 on error.
 * Each connection is read at most once per call and within
 * NODUS_TCP_READ_BUDGET_*; what is left is serviced by the next call.
 * @param timeout_ms  wait timeout (-1 = block forever); treated as 0 while
 *                    the pending-read list is non-empty
 */
int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms);

/**
 * True while connections of this transport wait on the pending-read list
 * (their read stopped on NODUS_TCP_READ_BUDGET_*). nodus_tcp_poll already
 * waits 0 ms for its OWN list; a loop that polls several transports in turn
 * uses this to poll the OTHER ones with timeout 0 too, so leftover input is
 * not delayed by a sibling's blocking wait.
 */
bool nodus_tcp_read_pending(const nodus_tcp_t *tcp);

/**
 * Disconnect a connection: on_disconnect runs (exactly once — a second call
 * on a connection already closing is a no-op), the socket is closed and the
 * connection leaves the pool immediately. Outside nodus_tcp_poll the memory
 * is freed before this returns. Inside nodus_tcp_poll (any callback) the
 * memory is kept until the outermost poll returns, so the caller's pointer
 * and the transport's own references stay valid; the transport does no
 * further work on it.
 */
void nodus_tcp_disconnect(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn);

/** D2.4 gate: cumulative post-established AEAD decrypt failures on this
 *  transport, surviving conn teardown (live conns + all freed ones). MUST be 0
 *  on a healthy cluster — there is no legitimate post-established decrypt
 *  failure on an ordered TCP stream. */
uint64_t nodus_tcp_decrypt_fail_total(const nodus_tcp_t *tcp);

/** Find connection by peer ID. */
nodus_tcp_conn_t *nodus_tcp_find_by_id(nodus_tcp_t *tcp,
                                        const nodus_key_t *peer_id);

/** Find connection by IP:port. Never returns an is_unix connection (its
 *  NODUS_TCP_UNIX_PEER_IP / port 0 is a placeholder, not a network peer). */
nodus_tcp_conn_t *nodus_tcp_find_by_addr(nodus_tcp_t *tcp,
                                          const char *ip, uint16_t port);

/** Get epoll fd (for sharing with UDP transport). Linux only. */
int nodus_tcp_epoll_fd(const nodus_tcp_t *tcp);

/** Current unix timestamp (seconds). */
uint64_t nodus_time_now(void);

/** Current unix timestamp (milliseconds). */
uint64_t nodus_time_now_ms(void);

/**
 * Monotonic milliseconds (CLOCK_MONOTONIC; Windows GetTickCount64).
 * For measuring intervals and deadlines only — the zero point is arbitrary,
 * so a value is compared only with another nodus_time_mono_ms() value,
 * never with a unix timestamp. A wall-clock step does not move it.
 * Used by the client SDK's own waits and timeouts (nodus_client.c); it
 * never enters consensus, a block, a vote or stored data.
 */
uint64_t nodus_time_mono_ms(void);

/** Close all connections and free resources. */
void nodus_tcp_close(nodus_tcp_t *tcp);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TCP_H */
