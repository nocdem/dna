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

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_TCP_MAX_CONNS   1024
#define NODUS_TCP_BUF_INIT    (64 * 1024)    /* Initial read/write buffer */
#define NODUS_TCP_PENDING_MAX  (5 * 1024 * 1024)   /* 5MB auth pending queue cap */

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

    /* C-01/C-02: Auth state for inter-node and witness ports */
    uint8_t             auth_nonce[NODUS_NONCE_LEN];
    bool                auth_nonce_pending;
    bool                authenticated;   /* Dilithium5 challenge-response completed */

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

    /* Channel encryption (set after Kyber handshake, NULL = plaintext) */
    void               *crypto;     /* nodus_channel_crypto_t*, opaque to avoid circular include */

    /* Send diagnostics (Phase 1 visibility — no behavior change) */
    uint64_t            send_ok_count;      /* frames accepted into wbuf */
    uint64_t            send_full_count;    /* buf_ensure failed (wbuf cap exceeded) */
    uint64_t            send_bytes_total;   /* cumulative plaintext bytes offered to wbuf */
} nodus_tcp_conn_t;

/* ── Callbacks ───────────────────────────────────────────────────── */

/** Called when a complete frame payload is received */
typedef void (*nodus_tcp_frame_fn)(nodus_tcp_conn_t *conn,
                                    const uint8_t *payload, size_t len,
                                    void *ctx);

/** Called on connection events (accept, connect, disconnect) */
typedef void (*nodus_tcp_event_fn)(nodus_tcp_conn_t *conn, void *ctx);

/* ── TCP Transport ───────────────────────────────────────────────── */

typedef struct {
    int                 listen_fd;
#ifdef _WIN32
    int                 poll_fd;     /* unused on Windows, kept for compat */
#else
    int                 epoll_fd;
#endif
    bool                owns_epoll;

    nodus_tcp_conn_t   *pool[NODUS_TCP_MAX_CONNS];
    int                 count;

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
} nodus_tcp_t;

/**
 * Initialize TCP transport.
 * @param shared_epoll_fd  If >= 0, use this epoll fd (Linux only). Otherwise creates own.
 *                         Ignored on Windows.
 */
int nodus_tcp_init(nodus_tcp_t *tcp, int shared_epoll_fd);

/** Start listening for incoming connections (server only, Linux). */
int nodus_tcp_listen(nodus_tcp_t *tcp, const char *bind_ip, uint16_t port);

/** Connect to a remote peer (non-blocking). Returns connection or NULL. */
nodus_tcp_conn_t *nodus_tcp_connect(nodus_tcp_t *tcp,
                                     const char *ip, uint16_t port);

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
 * Poll for events. Returns number of events processed.
 * @param timeout_ms  wait timeout (-1 = block forever)
 */
int nodus_tcp_poll(nodus_tcp_t *tcp, int timeout_ms);

/** Disconnect and free a connection. */
void nodus_tcp_disconnect(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn);

/** Find connection by peer ID. */
nodus_tcp_conn_t *nodus_tcp_find_by_id(nodus_tcp_t *tcp,
                                        const nodus_key_t *peer_id);

/** Find connection by IP:port. */
nodus_tcp_conn_t *nodus_tcp_find_by_addr(nodus_tcp_t *tcp,
                                          const char *ip, uint16_t port);

/** Get epoll fd (for sharing with UDP transport). Linux only. */
int nodus_tcp_epoll_fd(const nodus_tcp_t *tcp);

/** Current unix timestamp (seconds). */
uint64_t nodus_time_now(void);

/** Current unix timestamp (milliseconds). */
uint64_t nodus_time_now_ms(void);

/** Close all connections and free resources. */
void nodus_tcp_close(nodus_tcp_t *tcp);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TCP_H */
