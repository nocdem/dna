/**
 * Nodus — Client SDK
 *
 * Public API for applications connecting to Nodus servers.
 * Supports DHT operations, channel messaging, multi-server failover,
 * and auto-reconnect with exponential backoff.
 *
 * Usage:
 *   nodus_client_t client;
 *   nodus_client_config_t cfg = { .servers = {{"1.2.3.4", 4001}}, .server_count = 1 };
 *   nodus_client_init(&client, &cfg, &identity);
 *   nodus_client_connect(&client);
 *   nodus_client_put(&client, &key, data, len, type, ttl, vid, seq, &sig);
 *   nodus_client_close(&client);
 *
 * @file nodus.h
 */

#ifndef NODUS_H
#define NODUS_H

#include "nodus/nodus_types.h"
#include "core/nodus_media_storage.h"
#include "channel/nodus_channel_store.h"
#include "crypto/nodus_channel_crypto.h"
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CLIENT_MAX_SERVERS   8
#define NODUS_CLIENT_MAX_LISTENS  128
#define NODUS_CLIENT_MAX_CH_SUBS   32
/** Size of the chain id a client session is bound to (equals
 *  CMT_P2P_SC_CHAIN_ID_SIZE; asserted in nodus_client.c — this header stays
 *  free of the secret-connection headers, the browser builds include it). */
#define NODUS_CLIENT_CHAIN_ID_SIZE 32

/* ── Connection state ───────────────────────────────────────────── */

typedef enum {
    NODUS_CLIENT_DISCONNECTED = 0,
    NODUS_CLIENT_CONNECTING,
    NODUS_CLIENT_AUTHENTICATING,
    NODUS_CLIENT_READY,
    NODUS_CLIENT_RECONNECTING
} nodus_client_state_t;

/* ── Server endpoint ────────────────────────────────────────────── */

typedef struct {
    char        ip[64];
    uint16_t    port;
} nodus_server_endpoint_t;

/* ── Callbacks ──────────────────────────────────────────────────── */

/** Called when a LISTEN key's value changes. */
typedef void (*nodus_on_value_changed_fn)(const nodus_key_t *key,
                                           const nodus_value_t *val,
                                           void *user_data);

/** Called when a channel post notification arrives. */
typedef void (*nodus_on_ch_post_fn)(const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                     const nodus_channel_post_t *post,
                                     void *user_data);

/** Called when server sends ch_ring_changed (client should disconnect + reconnect) */
typedef void (*nodus_on_ch_ring_changed_fn)(const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                              uint32_t new_version, void *user_data);

/** Called when connection state changes. */
typedef void (*nodus_on_state_change_fn)(nodus_client_state_t old_state,
                                          nodus_client_state_t new_state,
                                          void *user_data);

/** Progress callback for media upload/download operations. */
typedef void (*nodus_media_progress_cb)(size_t bytes_sent, size_t total_bytes,
                                         void *user_data);

/* ── Configuration ──────────────────────────────────────────────── */

typedef struct {
    nodus_server_endpoint_t  servers[NODUS_CLIENT_MAX_SERVERS];
    int                      server_count;

    /* Timeouts (ms). 0 = use defaults. */
    int     connect_timeout_ms;     /* Default: 5000 */
    int     request_timeout_ms;     /* Default: 10000 */

    /* Auto-reconnect (enabled by default) */
    bool    auto_reconnect;         /* Default: true */
    int     reconnect_min_ms;       /* Default: 1000 */
    int     reconnect_max_ms;       /* Default: 30000 */

    /* Callbacks */
    nodus_on_value_changed_fn   on_value_changed;
    nodus_on_ch_post_fn         on_ch_post;
    nodus_on_state_change_fn    on_state_change;
    void                       *callback_data;

    /* Server key pin (MANDATORY since the client session moved onto the
     * SecretConnection layer, DHT v2 package 3 — decisions/2026-10-23-
     * kurultay-43-summary.md, mandatory fixes). Fingerprints (SHA3-512 of
     * the server's ML-DSA-87 public key — nodus_fingerprint(), the same
     * 64-byte value as a node id) of the servers this client accepts.
     *
     * nodus_client_init() REFUSES a config with no pin: pinned_server_fps
     * NULL or pinned_server_fp_count <= 0 (what a zeroed config gives) —
     * there is no unpinned client, no round-3 / cached-key / unencrypted
     * session.
     *
     * Each connect checks the server's CLAIMED public key against this list
     * BEFORE it encapsulates to it (nodus_tcp_sc.h "PROFILES, PURPOSES, THE
     * PIN"); a key whose fingerprint is not in the list aborts the handshake.
     *
     * The array is owned by the caller and must outlive the client (it is
     * not copied; same rule as nodus_tcp_t.ws_origins). count > 0 with a
     * NULL pointer, or count < 0, also makes nodus_client_init() fail. */
    const nodus_key_t          *pinned_server_fps;
    int                         pinned_server_fp_count;

    /* The chain id the session is bound to (MANDATORY, same rule): the
     * 32-byte id of the chain this client means to talk to. It travels in
     * the SecretConnection HELLO of both ends and the handshake fails when
     * the two differ (a per-network binding: a client of one network cannot
     * complete a session with a node of another). Set has_expected_chain_id
     * together with expected_chain_id; nodus_client_init() REFUSES a config
     * with has_expected_chain_id false (or an all-zero id). The id is copied
     * into the client. */
    uint8_t                     expected_chain_id[NODUS_CLIENT_CHAIN_ID_SIZE];
    bool                        has_expected_chain_id;
} nodus_client_config_t;

/* ── Concurrent request slot ────────────────────────────────────── */

#define NODUS_MAX_PENDING  64

typedef struct {
    uint32_t    txn;
    void       *response;       /* nodus_tier2_msg_t* */
    uint8_t    *raw_response;
    size_t      raw_response_len;
    _Atomic bool ready;
    bool        in_use;
} nodus_pending_t;

/* ── Circuit (VPN mesh Faz 1) ───────────────────────────────────── */

struct nodus_client;

typedef struct nodus_circuit_handle nodus_circuit_handle_t;

typedef void (*nodus_circuit_data_cb)(nodus_circuit_handle_t *h,
                                       const uint8_t *data, size_t len,
                                       void *user);

typedef void (*nodus_circuit_close_cb)(nodus_circuit_handle_t *h,
                                        int reason, void *user);

typedef void (*nodus_circuit_inbound_cb)(struct nodus_client *client,
                                          const nodus_key_t *peer_fp,
                                          nodus_circuit_handle_t *h,
                                          void *user);

struct nodus_circuit_handle {
    struct nodus_client       *client;
    uint64_t                   cid;             /* Locally-known cid */
    bool                       in_use;
    bool                       closed;
    nodus_circuit_data_cb      on_data;
    nodus_circuit_close_cb     on_close;
    void                      *user;
    /* E2E encryption (onion layer — relay-blind) */
    nodus_channel_crypto_t     e2e_crypto;
    bool                       e2e_active;
};

#define NODUS_CLIENT_MAX_CIRCUITS  16

/* ── Client ─────────────────────────────────────────────────────── */

/* Forward declarations for internal types */
struct nodus_tcp;
struct nodus_tcp_conn;

typedef struct nodus_client {
    nodus_client_config_t  config;
    nodus_identity_t       identity;
    nodus_client_state_t   state;

    /* TCP transport (opaque — managed internally) */
    void                  *tcp;        /* nodus_tcp_t* */
    void                  *conn;       /* nodus_tcp_conn_t* */

    /* Session */
    uint8_t                token[NODUS_SESSION_TOKEN_LEN];
    /* The SecretConnection of the current connection became AUTHENTICATED
     * (set by the transport's on_session, cleared at each connect). The
     * session is READY once this AND the server's token message are in. */
    _Atomic bool           session_ready;
    _Atomic uint32_t       next_txn;

    /* Current server index for failover */
    int                    server_idx;

    /* Reconnect backoff state */
    int                    backoff_ms;
    uint64_t               reconnect_at; /* Monotonic ms (nodus_time_mono_ms) when to reconnect */

    /* Keepalive ping (prevents server idle sweep) */
    uint64_t               last_ping_ms; /* Monotonic ms (nodus_time_mono_ms) of last ping sent */

    /* Active subscriptions (for re-subscribe on reconnect) */
    nodus_key_t            listen_keys[NODUS_CLIENT_MAX_LISTENS];
    int                    listen_count;
    uint8_t                ch_subs[NODUS_CLIENT_MAX_CH_SUBS][NODUS_UUID_BYTES];
    int                    ch_sub_count;

    /* Concurrent request handling */
    nodus_pending_t        pending[NODUS_MAX_PENDING];
    pthread_mutex_t        pending_mutex;  /* protects pending[] slots */
    pthread_mutex_t        send_mutex;     /* serializes TCP send */
    pthread_mutex_t        poll_mutex;     /* serializes TCP poll */
    pthread_mutex_t        wbuf_mutex;     /* transport write lock (nodus_tcp_set_write_lock):
                                            * callers send while the read thread polls */

    /* Internal read thread — continuously reads TCP for push notifications */
    pthread_t              read_thread;
    _Atomic bool           read_thread_running;
    _Atomic bool           read_thread_stop;

    /* App lifecycle — suspend prevents auto-reconnect while in background */
    _Atomic bool           suspended;

    /* Circuit handles (VPN mesh Faz 1) */
    nodus_circuit_handle_t    circuits[NODUS_CLIENT_MAX_CIRCUITS];
    nodus_circuit_inbound_cb  on_circuit_inbound;
    void                     *circuit_inbound_user;
    _Atomic uint32_t          next_client_cid;
    pthread_mutex_t           circuits_mutex;

    /* Channel encryption (Kyber handshake result).
     * B3 fix — channel_crypto storage moved to nodus_tcp_conn_t.
     * Read via client->conn->channel_crypto. Eliminates the pointer
     * aliasing race that caused "Replay detected" loops on
     * disconnect+reconnect. */

    /* Cached server Kyber pubkey (survives reconnect, prep for anonymous hello) */
    uint8_t                   cached_server_kyber_pk[1568];
    bool                      has_cached_server_kyber;

    /* Cached server ML-KEM-1024 pubkey (Faz 1 KEM migration — same role as
     * cached_server_kyber_pk above, docs/plans/decisions/2026-09-23-kem-
     * mlkem-migration.md) */
    uint8_t                   cached_server_mlkem_pk[1568];
    bool                      has_cached_server_mlkem;

    /* Cached server Dilithium5 pubkey (TOFU — set on every auth_ok whose
     * kpk_sig verified; not cleared by an unsigned one). With a server-key
     * pin set, a connection only succeeds through that path, so after a
     * successful pinned connect it is the current server's key. */
    nodus_pubkey_t             server_dil_pk;
    bool                       has_server_dil_pk;

} nodus_client_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

/**
 * Initialize client with config and identity.
 * Does NOT connect — call nodus_client_connect() after.
 */
int nodus_client_init(nodus_client_t *client,
                       const nodus_client_config_t *config,
                       const nodus_identity_t *identity);

/**
 * Connect to the first available server and authenticate.
 * Tries servers in order until one succeeds.
 *
 * @return 0 on success, -1 on failure (all servers unreachable)
 */
int nodus_client_connect(nodus_client_t *client);

/**
 * Poll for incoming data and process callbacks.
 * Call this regularly from your event loop.
 * Handles auto-reconnect if enabled.
 *
 * @param timeout_ms  Poll timeout (-1 = block until event)
 * @return Number of events processed, or -1 on error
 */
int nodus_client_poll(nodus_client_t *client, int timeout_ms);

/**
 * Periodic housekeeping for a client WITHOUT a read thread (the browser
 * build, where nodus_client_connect starts none): sends the 60 s keepalive
 * ping when due, then nodus_client_poll(client, 0) — which delivers pending
 * input and, when the connection dropped with auto_reconnect set, runs the
 * reconnect. Call it at least every few seconds (the server closes an
 * authenticated connection idle for 180 s). With a read thread running it
 * does nothing (the thread already does both).
 * In the browser build a reconnect waits for its handshake by yielding to
 * the event loop, so this must be called as an async (Asyncify/JSPI) export.
 *
 * @return nodus_client_poll's result, 0 with a read thread, -1 on bad args
 */
int nodus_client_tick(nodus_client_t *client);

/**
 * Check if client is connected and authenticated.
 */
bool nodus_client_is_ready(const nodus_client_t *client);

/** O15C-D — the request/result correlation rule: the pending entry that
 * is in_use AND holds exactly `txn`, or NULL. A response therefore can
 * never reach a different request, and a reply arriving after the caller
 * released its slot matches nothing. Caller holds pending_mutex.
 * Exposed for the request-lifecycle regression. */
nodus_pending_t *nodus_client_pending_find(nodus_client_t *client,
                                             uint32_t txn);

/**
 * Suspend client — close TCP and prevent auto-reconnect.
 * Call when app goes to background to avoid dead sockets.
 * Read thread stays alive but idle.
 */
void nodus_client_suspend(nodus_client_t *client);

/**
 * Resume client — allow auto-reconnect and trigger immediate reconnect.
 * Call when app comes to foreground.
 */
void nodus_client_resume(nodus_client_t *client);

/**
 * Get current connection state.
 */
nodus_client_state_t nodus_client_state(const nodus_client_t *client);

/**
 * Disconnect and clean up. Does NOT free client struct.
 */
void nodus_client_close(nodus_client_t *client);

/**
 * Force-disconnect the TCP socket to interrupt blocking operations.
 * Closes the socket fd but does NOT free any memory.
 * Use before joining threads that may be blocked on nodus ops.
 */
void nodus_client_force_disconnect(nodus_client_t *client);

/* ── DHT Operations ─────────────────────────────────────────────── */

/**
 * Store a signed value on the DHT.
 * The value must already be signed (sig parameter).
 *
 * @return 0 on success, error code on failure
 */
int nodus_client_put(nodus_client_t *client,
                      const nodus_key_t *key,
                      const uint8_t *data, size_t data_len,
                      nodus_value_type_t type, uint32_t ttl,
                      uint64_t vid, uint64_t seq,
                      const nodus_sig_t *sig);

/**
 * Same as nodus_client_put(), but waits up to timeout_ms milliseconds for
 * the server response instead of config.request_timeout_ms. Use for large
 * payloads or mobile links where the default 10s is too tight.
 *
 * Passing timeout_ms <= 0 falls back to config.request_timeout_ms.
 *
 * @return 0 on success, error code on failure
 */
int nodus_client_put_ex(nodus_client_t *client,
                         const nodus_key_t *key,
                         const uint8_t *data, size_t data_len,
                         nodus_value_type_t type, uint32_t ttl,
                         uint64_t vid, uint64_t seq,
                         const nodus_sig_t *sig,
                         int timeout_ms);

/**
 * Retrieve a single value by key (latest version).
 * Caller must free *val_out with nodus_value_free().
 *
 * @return 0 on success, NODUS_ERR_NOT_FOUND if missing
 */
int nodus_client_get(nodus_client_t *client,
                      const nodus_key_t *key,
                      nodus_value_t **val_out);

/**
 * Retrieve all values for a key (all writers).
 * Caller must free each value with nodus_value_free().
 *
 * @return 0 on success (count may be 0)
 */
int nodus_client_get_all(nodus_client_t *client,
                          const nodus_key_t *key,
                          nodus_value_t ***vals_out,
                          size_t *count_out);

/* ── Owner-filtered get + paged get_all (DHT Package A) ─────────── */

/**
 * One position in a key's rows: the storage primary key (owner_fp,
 * value_id). Pages run in PK order — owner_fp ascending bytewise, then
 * value_id ascending compared as SIGNED int64.
 */
typedef struct {
    nodus_key_t owner_fp;
    uint64_t    value_id;
} nodus_dht_page_cursor_t;

/**
 * Retrieve one owner's newest value for a key (request "own").
 * Same request, timeout and ownership rules as nodus_client_get();
 * caller frees *val_out with nodus_value_free(). The value is NOT
 * signature-verified here (as with nodus_client_get).
 *
 * @return 0 on success,
 *         NODUS_ERR_NOT_FOUND     the node has no row of that owner,
 *         NODUS_ERR_UNAVAILABLE   the node could not look (no forward slot /
 *                                 no forward answered), OR it returned a row
 *                                 of another owner (a node that predates the
 *                                 owner filter) — never reported as absent,
 *         NODUS_ERR_PROTOCOL_ERROR the row is of another key, or an error
 *                                 reply without a valid code,
 *         NODUS_ERR_TIMEOUT, another node error code, or -1 (bad args /
 *         not connected / local allocation).
 */
int nodus_client_get_owner(nodus_client_t *client,
                            const nodus_key_t *key,
                            const nodus_key_t *owner_fp,
                            nodus_value_t **val_out);

/**
 * Retrieve one page of a key's values (request "pg", plus "after" when
 * `after` is given and "own" when `owner_fp` is given).
 *
 * Start with after = NULL; while *more_out is true, call again with
 * after = the returned *cursor_out. Every returned row carries the asked
 * key, is past `after` and (with owner_fp) belongs to that owner; the
 * client drops anything else.
 *
 * A node that predates paging ignores "pg" / "after" / "own" and answers
 * with a plain get_all reply (no "more"). Its completeness is UNKNOWN: the
 * old node may have capped the reply, or answered empty because it could
 * not look. Such a reply sets *legacy_out = true and *more_out = false —
 * it is NOT a statement that no rows remain. A legacy reply with no row
 * left after the filtering above is NODUS_ERR_UNAVAILABLE, never an empty
 * success. The values are NOT signature-verified here.
 * Caller frees each value with nodus_value_free() and the array with free().
 *
 * @param owner_fp    NULL = every owner
 * @param after       NULL = first page
 * @param vals_out    page rows (NULL when the page is empty)
 * @param more_out    true = rows remain after this page
 * @param cursor_out  the next page's `after` (zeroed when !*more_out)
 * @param legacy_out  true = the node predates paging; the rows returned are
 *                    what it sent, completeness unknown (false on error)
 * @return 0 on success (a paging node's page may be empty),
 *         NODUS_ERR_UNAVAILABLE   the node could not look, or a legacy
 *                                 reply had no row of the asked page —
 *                                 not "empty",
 *         NODUS_ERR_PROTOCOL_ERROR more without a cursor, a cursor that
 *                                 does not advance past `after`, a cursor
 *                                 without more = true, or an error reply
 *                                 without a valid code,
 *         NODUS_ERR_TIMEOUT, another node error code, or -1.
 */
int nodus_client_get_all_page(nodus_client_t *client,
                               const nodus_key_t *key,
                               const nodus_key_t *owner_fp,
                               const nodus_dht_page_cursor_t *after,
                               nodus_value_t ***vals_out,
                               size_t *count_out,
                               bool *more_out,
                               nodus_dht_page_cursor_t *cursor_out,
                               bool *legacy_out);

/**
 * nodus_client_get_all_page, STRICT (the strict-read family of
 * src/client/nodus_client_strict.h): the same request ("pg", plus "after" /
 * "own") and the same protocol checks on "more" / "next" / the cursor, but
 * the caller classifies the rows itself:
 *   - rows of another key, and (with owner_fp) of another owner, are
 *     RETURNED, not dropped — a reader that counts them (Nodus Connect,
 *     web-wallet/connect/nc_read.c) needs to see them;
 *   - rows outside the page bounds (at or before `after`, or past "next"
 *     when more = true) are dropped AND counted into *undecodable_out: a
 *     paging node never sends them, so they are a protocol anomaly;
 *   - *undecodable_out also counts the "vals" items that did not decode (a
 *     non-byte-string item, a value nodus_value_deserialize refused, an
 *     item past NODUS_MAX_WIRE_VALUES), read from the raw reply as
 *     nodus_client_get_all_strict does; when the raw reply could not be
 *     kept the call is NODUS_ERR_PROTOCOL_ERROR;
 *   - a legacy reply (no "more") keeps its meaning (*legacy_out = true,
 *     *more_out = false, completeness unknown) but is NOT turned into
 *     NODUS_ERR_UNAVAILABLE when it carries no row: it returns 0 with
 *     count 0 and *legacy_out = true, and the caller decides (Connect reads
 *     it as unreadable, never as empty).
 * Error replies map as in nodus_client_get_all_page. The values are NOT
 * signature-verified here. Caller frees each value with nodus_value_free()
 * and the array with free().
 *
 * @param undecodable_out  required (NULL = -1)
 * @return 0 on success (the page may be empty; see legacy above),
 *         NODUS_ERR_UNAVAILABLE   the node could not look,
 *         NODUS_ERR_PROTOCOL_ERROR more without a cursor, a cursor that does
 *                                 not advance past `after`, a cursor without
 *                                 more = true, an error reply without a
 *                                 valid code, or the raw reply not kept,
 *         NODUS_ERR_TIMEOUT, another node error code, or -1.
 */
int nodus_client_get_all_page_strict(nodus_client_t *client,
                                     const nodus_key_t *key,
                                     const nodus_key_t *owner_fp,
                                     const nodus_dht_page_cursor_t *after,
                                     nodus_value_t ***vals_out,
                                     size_t *count_out,
                                     bool *more_out,
                                     nodus_dht_page_cursor_t *cursor_out,
                                     bool *legacy_out,
                                     size_t *undecodable_out);

/** Most requests one nodus_client_get_all_page_strict_many call carries. */
#define NODUS_CLIENT_PAGE_PIPELINE_MAX 8

/** One request of nodus_client_get_all_page_strict_many: the arguments of
 *  nodus_client_get_all_page_strict (in) and its answer (out). The pointers
 *  in the request half must stay valid for the whole call. */
typedef struct {
    /* in */
    const nodus_key_t             *key;          /**< required              */
    const nodus_key_t             *owner_fp;     /**< NULL = every owner    */
    const nodus_dht_page_cursor_t *after;        /**< NULL = first page     */
    /* out — exactly what nodus_client_get_all_page_strict returns */
    int                            rc;
    nodus_value_t                **vals;         /**< caller frees          */
    size_t                         count;
    bool                           more;
    nodus_dht_page_cursor_t        cursor;
    bool                           legacy;
    size_t                         undecodable;
} nodus_page_req_t;

/**
 * nodus_client_get_all_page_strict for up to NODUS_CLIENT_PAGE_PIPELINE_MAX
 * keys at once, PIPELINED on the one session: every request is sent before
 * the first reply is awaited. NOT a batch request — each key gets its own
 * strict paged GET_ALL frame (the same frame, the same reply checks, the
 * same undecodable count), so each node-side read keeps its own forwarded
 * lookup (the node's get_batch does not: it forwards only keys with no
 * local row, to one peer).
 *
 * Per item, reqs[i].rc and the answer fields are what
 * nodus_client_get_all_page_strict(key, owner_fp, after, ...) would have
 * returned: 0, NODUS_ERR_UNAVAILABLE, NODUS_ERR_PROTOCOL_ERROR,
 * NODUS_ERR_TIMEOUT (that request's own reply did not come within the
 * client's request timeout, measured from its own send), another node
 * error code, or -1 (not connected / no pending slot / local allocation /
 * send failure). An item's failure does not affect the others. Replies are
 * matched by transaction id, never by position.
 *
 * Caller frees each reqs[i].vals[j] with nodus_value_free() and each
 * reqs[i].vals with free(), on every rc.
 *
 * @return 0 (every reqs[i].rc set, -1 for all when the client is not
 *         ready), or -1 with nothing sent: reqs NULL, n == 0,
 *         n > NODUS_CLIENT_PAGE_PIPELINE_MAX, or a key NULL.
 */
int nodus_client_get_all_page_strict_many(nodus_client_t *client,
                                          nodus_page_req_t *reqs, size_t n);

/* ── Batch DHT Operations ───────────────────────────────────────── */

/** Result for one key in a get_batch response */
typedef struct {
    nodus_key_t     key;
    nodus_value_t **vals;
    size_t          count;
} nodus_batch_result_t;

/** Result for one key in a count_batch response */
typedef struct {
    nodus_key_t     key;
    size_t          count;
    bool            has_mine;
} nodus_count_result_t;

/**
 * Batch get_all: retrieve all values for multiple keys in one request.
 * Caller must free results with nodus_client_free_batch_result().
 *
 * @param keys           Array of keys to query
 * @param key_count      Number of keys (1..32)
 * @param results_out    Output: heap-allocated array of per-key results
 * @param result_count_out  Number of results (== key_count on success)
 * @return 0 on success, error code on failure
 */
int nodus_client_get_batch(nodus_client_t *client,
                            const nodus_key_t *keys, int key_count,
                            nodus_batch_result_t **results_out,
                            int *result_count_out);

/**
 * nodus_client_get_batch() plus the per-key "could not look" marker
 * (DHT Package A). Same request frame, same results and ownership
 * (free with nodus_client_free_batch_result()).
 *
 * unavail_out[i] is true when the node marked result i ("u": true) as not
 * looked up (no forward slot / no forward answered): an empty result i is
 * then NOT "no values". A node that predates the marker never sets it, so
 * false only means "not marked". All key_count entries are zeroed first.
 * On success *result_count_out == key_count and results[i].key == keys[i]
 * (a node answers every asked key in the asked order).
 *
 * @param unavail_out  caller array of key_count bools (required)
 * @return 0 on success,
 *         NODUS_ERR_PROTOCOL_ERROR the reply does not carry exactly
 *                                 key_count entries, an entry's key is not
 *                                 keys[i] at its position, or an error
 *                                 reply without a valid code,
 *         NODUS_ERR_UNAVAILABLE, NODUS_ERR_TIMEOUT, another node error
 *         code, or -1 (bad args / not connected / local allocation).
 *         On any non-zero return *results_out is NULL.
 */
int nodus_client_get_batch_ex(nodus_client_t *client,
                               const nodus_key_t *keys, int key_count,
                               nodus_batch_result_t **results_out,
                               int *result_count_out,
                               bool *unavail_out);

/**
 * Batch count: get value counts + has_mine for multiple keys in one request.
 * Caller must free results with nodus_client_free_count_result().
 *
 * @param keys           Array of keys to query
 * @param key_count      Number of keys (1..32)
 * @param my_fp          Caller fingerprint for has_mine check (NULL to skip)
 * @param results_out    Output: heap-allocated array of per-key results
 * @param result_count_out  Number of results
 * @return 0 on success, error code on failure
 */
int nodus_client_count_batch(nodus_client_t *client,
                              const nodus_key_t *keys, int key_count,
                              const nodus_key_t *my_fp,
                              nodus_count_result_t **results_out,
                              int *result_count_out);

/** Free results from nodus_client_get_batch(). */
void nodus_client_free_batch_result(nodus_batch_result_t *results, int count);

/** Free results from nodus_client_count_batch(). */
void nodus_client_free_count_result(nodus_count_result_t *results, int count);

/**
 * Subscribe to changes on a DHT key.
 * Notifications delivered via on_value_changed callback.
 *
 * @return 0 on success
 */
int nodus_client_listen(nodus_client_t *client,
                         const nodus_key_t *key);

/**
 * Unsubscribe from a DHT key.
 */
int nodus_client_unlisten(nodus_client_t *client,
                           const nodus_key_t *key);

/**
 * Request list of cluster servers from the connected server.
 * Returns endpoints of all alive cluster peers + self.
 *
 * @param endpoints_out  Output array (caller provides, up to max_count)
 * @param max_count      Max entries in endpoints_out
 * @param count_out      Actual count written
 * @return 0 on success, error code on failure
 */
int nodus_client_get_servers(nodus_client_t *client,
                              nodus_server_endpoint_t *endpoints_out,
                              int max_count, int *count_out);

/* ── Channel Operations ─────────────────────────────────────────── */

/**
 * Create a new channel.
 * The UUID should be generated by the caller (UUID v4).
 *
 * @return 0 on success
 */
int nodus_client_ch_create(nodus_client_t *client,
                            const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * List public channels from server (paginated).
 *
 * @param offset     Skip first N results (0 = start)
 * @param limit      Maximum results to return (default 50, max 200)
 * @param metas_out  Output: heap-allocated array. Caller frees with free().
 * @param count_out  Number of results
 * @return 0 on success
 */
/**
 * Get a single channel's metadata from server by UUID.
 *
 * @param uuid       16-byte channel UUID
 * @param meta_out   Output: channel metadata (caller-owned, stack or heap)
 * @return 0 on success, NODUS_ERR_NOT_FOUND if channel doesn't exist
 */
int nodus_client_ch_get(nodus_client_t *client,
                         const uint8_t uuid[NODUS_UUID_BYTES],
                         nodus_channel_meta_t *meta_out);

int nodus_client_ch_list(nodus_client_t *client,
                          int offset, int limit,
                          nodus_channel_meta_t **metas_out,
                          size_t *count_out);

/**
 * Search public channels by name/description (paginated).
 *
 * @param query      Search string (server does LIKE %query%)
 * @param offset     Skip first N results
 * @param limit      Maximum results to return
 * @param metas_out  Output: heap-allocated array. Caller frees with free().
 * @param count_out  Number of results
 * @return 0 on success
 */
int nodus_client_ch_search(nodus_client_t *client,
                            const char *query,
                            int offset, int limit,
                            nodus_channel_meta_t **metas_out,
                            size_t *count_out);

/**
 * Post a message to a channel.
 * The post must be signed by the caller.
 *
 * @param received_at_out  If non-NULL, receives the assigned received_at (ms)
 * @return 0 on success
 */
int nodus_client_ch_post(nodus_client_t *client,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const uint8_t post_uuid[NODUS_UUID_BYTES],
                          const uint8_t *body, size_t body_len,
                          uint64_t timestamp, const nodus_sig_t *sig,
                          uint64_t *received_at_out);

/**
 * Get posts from a channel.
 * Caller must free each post's body and the array.
 *
 * @param since_received_at  Get posts after this received_at (0 = from start)
 * @param max_count  Maximum posts to return (0 = server default)
 * @return 0 on success
 */
int nodus_client_ch_get_posts(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES],
                               uint64_t since_received_at, int max_count,
                               nodus_channel_post_t **posts_out,
                               size_t *count_out);

/**
 * Subscribe to channel post notifications.
 * Notifications delivered via on_ch_post callback.
 *
 * @return 0 on success
 */
int nodus_client_ch_subscribe(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Unsubscribe from a channel.
 */
int nodus_client_ch_unsubscribe(nodus_client_t *client,
                                 const uint8_t uuid[NODUS_UUID_BYTES]);

/* ── Channel Connection (TCP 4003) ─────────────────────────────── */

#define NODUS_CH_CONN_MAX_SUBS  32
#define NODUS_CH_MAX_PENDING    32

/** Channel connection state */
typedef enum {
    NODUS_CH_DISCONNECTED = 0,
    NODUS_CH_CONNECTING,
    NODUS_CH_AUTHENTICATING,
    NODUS_CH_READY,
    NODUS_CH_RECONNECTING
} nodus_ch_state_t;

/** Pending request slot for channel connection */
typedef struct {
    uint32_t    txn;
    void       *response;       /* nodus_tier2_msg_t* */
    _Atomic bool ready;
    bool        in_use;
} nodus_ch_pending_t;

/** Dedicated channel connection to a node's TCP 4003 port */
typedef struct {
    char                    host[64];
    uint16_t                port;
    nodus_ch_state_t        state;
    nodus_identity_t        identity;

    /* TCP transport */
    void                   *tcp;        /* nodus_tcp_t* */
    void                   *conn;       /* nodus_tcp_conn_t* */

    /* Session */
    uint8_t                 token[NODUS_SESSION_TOKEN_LEN];
    _Atomic uint32_t        next_txn;

    /* Subscriptions tracked for push notifications */
    uint8_t                 ch_subs[NODUS_CH_CONN_MAX_SUBS][NODUS_UUID_BYTES];
    int                     ch_sub_count;

    /* Callback for push post notifications */
    nodus_on_ch_post_fn     on_ch_post;
    void                   *cb_data;

    /* Callback for ring change notifications */
    nodus_on_ch_ring_changed_fn on_ring_changed;
    void                       *ring_changed_data;

    /* Concurrent request handling */
    nodus_ch_pending_t      pending[NODUS_CH_MAX_PENDING];
    pthread_mutex_t         pending_mutex;
    pthread_mutex_t         send_mutex;
    pthread_mutex_t         wbuf_mutex;   /* transport write lock, as nodus_client_t */

    /* Reconnect state */
    uint64_t                reconnect_at;     /* Monotonic ms (nodus_time_mono_ms) of next reconnect attempt */
    uint32_t                backoff_ms;       /* Current backoff interval */

    /* Internal read thread */
    pthread_t               read_thread;
    _Atomic bool            read_thread_running;
    _Atomic bool            read_thread_stop;
} nodus_ch_conn_t;

/**
 * Initialize a channel connection.
 * Does NOT connect — call nodus_channel_connect() after.
 */
int nodus_channel_init(nodus_ch_conn_t *ch,
                       const char *host, uint16_t port,
                       const nodus_identity_t *identity,
                       nodus_on_ch_post_fn on_post, void *cb_data);

/**
 * Connect to the node's TCP 4003 port and authenticate.
 * @return 0 on success, -1 on failure
 */
int nodus_channel_connect(nodus_ch_conn_t *ch);

/**
 * Check if channel connection is ready.
 */
bool nodus_channel_is_ready(const nodus_ch_conn_t *ch);

/**
 * Disconnect and clean up. Does NOT free the struct.
 */
void nodus_channel_close(nodus_ch_conn_t *ch);

/**
 * Create a channel via TCP 4003.
 */
int nodus_ch_conn_create(nodus_ch_conn_t *ch,
                         const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Post to a channel via TCP 4003.
 */
int nodus_ch_conn_post(nodus_ch_conn_t *ch,
                       const uint8_t ch_uuid[NODUS_UUID_BYTES],
                       const uint8_t post_uuid[NODUS_UUID_BYTES],
                       const uint8_t *body, size_t body_len,
                       uint64_t timestamp, const nodus_sig_t *sig,
                       uint64_t *received_at_out);

/**
 * Get posts from a channel via TCP 4003.
 */
int nodus_ch_conn_get_posts(nodus_ch_conn_t *ch,
                            const uint8_t uuid[NODUS_UUID_BYTES],
                            uint64_t since_received_at, int max_count,
                            nodus_channel_post_t **posts_out,
                            size_t *count_out);

/**
 * Subscribe to channel post notifications via TCP 4003.
 */
int nodus_ch_conn_subscribe(nodus_ch_conn_t *ch,
                            const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Unsubscribe from channel notifications via TCP 4003.
 */
int nodus_ch_conn_unsubscribe(nodus_ch_conn_t *ch,
                              const uint8_t uuid[NODUS_UUID_BYTES]);

/* ── Presence Operations ─────────────────────────────────────────── */

#define NODUS_PRESENCE_MAX_QUERY  128

typedef struct {
    nodus_key_t fp;
    bool        online;
    uint8_t     peer_index;
    uint64_t    last_seen;
} nodus_presence_entry_result_t;

typedef struct {
    int total_queried;
    int online_count;
    nodus_presence_entry_result_t *entries;       /* heap, online entries */
    int offline_seen_count;
    nodus_presence_entry_result_t *offline_seen;  /* heap, recently disconnected */
} nodus_presence_result_t;

/**
 * Batch presence query: check online status for up to 128 fingerprints.
 * Result contains only online entries (sparse).
 * Caller must free result with nodus_client_free_presence_result().
 *
 * @return 0 on success, error code on failure
 */
int nodus_client_presence_query(nodus_client_t *client,
                                  const nodus_key_t *fps, int count,
                                  nodus_presence_result_t *result);

/**
 * Free a presence result.
 */
void nodus_client_free_presence_result(nodus_presence_result_t *result);

/* ── DNAC Operations ─────────────────────────────────────────────── */

/**
 * Submit spend transaction for BFT consensus.
 * This is asynchronous on the server — blocks until COMMIT or error (up to 30s).
 *
 * @param tx_hash     SHA3-512 hash of tx_data (64 bytes)
 * @param tx_data     Serialized DNAC transaction
 * @param tx_len      Length of tx_data
 * @param sender_pk   Sender's Dilithium5 public key
 * @param sender_sig  Sender's signature over tx_hash
 * @param fee         Fee amount
 * @param result_out  Witness attestation result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_spend(nodus_client_t *client,
                              const uint8_t *tx_hash,
                              const uint8_t *tx_data, uint32_t tx_len,
                              const nodus_pubkey_t *sender_pk,
                              const nodus_sig_t *sender_sig,
                              uint64_t fee,
                              nodus_dnac_spend_result_t *result_out);

/**
 * nodus_client_dnac_spend, plus the node's refusal text.
 *
 * Identical request, wait and return value. When the node answers with
 * an error frame, its message (the tier-2 "msg" field, at most 127 bytes
 * — nodus_tier2_msg_t.error_msg) is copied NUL-terminated into err_msg,
 * truncated to err_cap - 1 bytes; on a CheckTx refusal it reads
 * "CheckTx code N". err_msg is set to "" on entry and stays "" for every
 * other outcome (success, timeout, local failure). err_msg NULL or
 * err_cap 0 = the text is not wanted (nodus_client_dnac_spend's form).
 *
 * @param err_msg  Out: the node's error text, or "" (may be NULL)
 * @param err_cap  Size of err_msg in bytes
 * @return 0 on success, error code on failure (as nodus_client_dnac_spend)
 */
int nodus_client_dnac_spend_ex(nodus_client_t *client,
                                 const uint8_t *tx_hash,
                                 const uint8_t *tx_data, uint32_t tx_len,
                                 const nodus_pubkey_t *sender_pk,
                                 const nodus_sig_t *sender_sig,
                                 uint64_t fee,
                                 nodus_dnac_spend_result_t *result_out,
                                 char *err_msg, size_t err_cap);

/* nodus_client_dnac_nullifier / _ledger / _ledger_range / _history / _tx /
 * _spend_replay / _block / _block_range / _genesis and their result
 * types are deleted with the dnac_* RPCs of the same names (2026-10-15):
 * those RPCs read legacy tables no version-3 chain writes. */

/**
 * Query supply state.
 *
 * @param result_out  Supply state result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_supply(nodus_client_t *client,
                               nodus_dnac_supply_result_t *result_out);

/**
 * Read this node's own 32-byte derived chain id via the dnac_supply RPC
 * (D-16 rev 7, W4-CC — operator ruling "kendisi alsın", 2026-09-18).
 *
 * A THIN accessor over the SAME dnac_supply request nodus_client_dnac_supply
 * sends: it does its own short round trip and reads only the ADDITIVE
 * "chain_id32" key (nodus_witness_handlers.c handle_dnac_supply), rather
 * than growing nodus_dnac_supply_result_t (defined in nodus_types.h,
 * outside this package's whitelist) — every existing caller of
 * nodus_client_dnac_supply is therefore untouched. A legacy (pre-version-3)
 * node's reply carries no such key; `*has_out` distinguishes that case
 * from a transport/RPC failure.
 *
 * @param has_out         [out] true iff the additive key was present
 *                        (the node is on a version-3 chain).
 * @param chain_id32_out  [out] the 32-byte derived chain id when
 *                        *has_out is true; untouched otherwise.
 * @return 0 on success (*has_out is still meaningful either way),
 *         error code on transport/RPC failure.
 */
int nodus_client_dnac_chain_id32(nodus_client_t *client,
                                 bool *has_out,
                                 uint8_t chain_id32_out[32]);

/**
 * @brief Query current dynamic fee info from witness
 * @param client Connected nodus client
 * @param result_out Output fee info
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_fee_info(nodus_client_t *client,
                                nodus_dnac_fee_info_t *result_out);

/**
 * @brief The dnac_fee_info raw-reply decoder nodus_client_dnac_fee_info
 *        uses, exported for tests (no network). Zeroes *result_out, then
 *        fills each known key whose value is an unsigned integer
 *        (base_fee, mempool, min_fee, gas_price, token_create_fee and —
 *        HF-6 slice 8a — stake_min, storage_bond, power_cap_bps); unknown
 *        keys are skipped, an absent key leaves its field 0.
 * @return 0; -1 on NULL arguments or a reply the CBOR decoder cannot walk.
 */
int nodus_dnac_fee_info_decode(const uint8_t *raw, size_t raw_len,
                               nodus_dnac_fee_info_t *result_out);

/**
 * @brief nodus_dnac_fee_info_decode that also reports whether the reply
 *        CARRIED "gas_price" as an unsigned integer exactly once.
 *        nodus_dnac_fee_info_t.gas_price reads 0 both for a present 0 ("the
 *        price rule is off") and for an absent / wrongly typed / repeated
 *        key (an older server, a malformed reply); a caller that must not
 *        act on an UNKNOWN price (nodus-faucet) reads the flag. The struct
 *        itself is unchanged (it lives in nodus_types.h, appended-field
 *        compatibility with every other caller).
 * @param has_gas_price_out Set true only for one uint "gas_price" key (a
 *        present 0 included); false on every other outcome and on error.
 *        May be NULL (then identical to nodus_dnac_fee_info_decode).
 * @return Same as nodus_dnac_fee_info_decode.
 */
int nodus_dnac_fee_info_decode_ex(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_fee_info_t *result_out,
                                  bool *has_gas_price_out);

/**
 * @brief nodus_client_dnac_fee_info plus the gas-price presence flag of
 *        nodus_dnac_fee_info_decode_ex. nodus_client_dnac_fee_info is this
 *        with has_gas_price_out == NULL — behaviour unchanged.
 * @return 0 on success, error code on failure (the flag is false then).
 */
int nodus_client_dnac_fee_info_ex(nodus_client_t *client,
                                  nodus_dnac_fee_info_t *result_out,
                                  bool *has_gas_price_out);

/**
 * Query UTXOs by owner fingerprint.
 * Caller must free result_out->entries when done.
 *
 * @param owner        Owner fingerprint string
 * @param max_results  Maximum entries to return (capped at 100)
 * @param result_out   UTXO query result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_utxo(nodus_client_t *client,
                             const char *owner,
                             int max_results,
                             nodus_dnac_utxo_result_t *result_out);

/**
 * nodus_client_dnac_utxo for ONE token (operator 2026-10-22, decision
 * 2026-10-22-testnet-test-tokens-faucet-dex.md answer 3): sends "tok"
 * (bstr 64) and the node lists only coins of that token, same order and
 * 100-coin cap. token_id is exactly 64 bytes; all-zero = native.
 *
 * A node that predates "tok" skips the unknown key and answers every
 * token; the reply is then REFUSED (freed, result empty) with
 * NODUS_CLIENT_ERR_TOKEN_FILTER_IGNORED if it holds a coin of another
 * token. (A reply of only the requested token's coins is accepted — from
 * an old node it is the same set a new one would send, up to the cap.)
 * Every coin entry must carry exactly one "tid" (a 64-byte bstr) and no
 * repeated key, else NODUS_ERR_PROTOCOL_ERROR (freed): a missing or
 * mistyped tid would otherwise read as the all-zero native id.
 *
 * @return 0 / the node's error code (a malformed tok is PROTOCOL_ERROR) /
 *         NODUS_CLIENT_ERR_TOKEN_FILTER_IGNORED / NODUS_ERR_PROTOCOL_ERROR
 *         malformed reply / NODUS_ERR_TIMEOUT / -1 (bad arguments, transport)
 */
#define NODUS_CLIENT_ERR_TOKEN_FILTER_IGNORED  (-3)
int nodus_client_dnac_utxo_token(nodus_client_t *client,
                                 const char *owner,
                                 const uint8_t token_id[64],
                                 int max_results,
                                 nodus_dnac_utxo_result_t *result_out);
/* A vault member reading a multisig address's coins:
 * nodus_client_dnac_msig_utxo (beside dnac_addr_history below). */

/**
 * Query witness roster.
 *
 * @param result_out  Roster result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_roster(nodus_client_t *client,
                               nodus_dnac_roster_result_t *result_out);

/**
 * List all registered tokens.
 * Caller must free result_out with nodus_client_free_token_list_result().
 *
 * @param result_out  Token list result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_token_list(nodus_client_t *client,
                                   nodus_dnac_token_list_result_t *result_out);

/**
 * Query single token by token_id.
 *
 * The reply is decoded strictly: tid / name / sym / dec / supply / creator
 * must each be present exactly once with its own type, name <= 32 and sym
 * <= 8 bytes without an embedded NUL (judged on the wire length), dec <= 18
 * (judged before the narrowing to uint8_t), the returned tid equal to
 * `token_id`, and nothing truncated. Anything else is
 * NODUS_ERR_PROTOCOL_ERROR and `result_out` is zeroed.
 *
 * @param token_id    64-byte token identifier
 * @param result_out  Token info result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_token_info(nodus_client_t *client,
                                   const uint8_t *token_id,
                                   nodus_dnac_token_info_t *result_out);

/**
 * Free token list from nodus_client_dnac_token_list().
 */
void nodus_client_free_token_list_result(nodus_dnac_token_list_result_t *result);

/**
 * Free UTXO entries from nodus_client_dnac_utxo().
 */
void nodus_client_free_utxo_result(nodus_dnac_utxo_result_t *result);

/* ── Phase 14 / stake-delegation v1 RPCs ───────────────────────────── */

/* v0.16: nodus_client_dnac_pending_rewards +
 * nodus_client_free_pending_rewards_result removed. Rewards are pushed
 * out as UTXOs at each epoch boundary, so there is no pending balance
 * to query. */

/**
 * Query the witness for the current epoch's committee (chain-authoritative).
 *
 * @param result_out   Committee result (fixed-size internal array)
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_committee(nodus_client_t *client,
                                  nodus_dnac_committee_result_t *result_out);

/** Its raw-reply decoder, exported for tests (no network). Lenient as
 *  before (a key of the wrong type is ignored, unknown keys skipped,
 *  entries past the struct's capacity dropped); a repeated top-level key
 *  is refused. Each entry's "power" sets power + has_power = 1; an entry
 *  without it (an older node) decodes with has_power = 0, power = 0.
 *  @return 0 / -1 malformed (result zeroed). */
int nodus_dnac_committee_decode(const uint8_t *raw, size_t raw_len,
                                nodus_dnac_committee_result_t *result_out);

/* ── Governance approvals collected by the proposer's OWN node ────────
 * (decision docs/plans/decisions/2026-09-26-cc-approval-via-own-node.md)
 *
 * Method `dnac_cc_collect`, args {"e": bstr — the pre-auth SYSTEM-
 * governance envelope}. Served ONLY to a session authenticated with the
 * node's OWN identity key. The node asks every OTHER seat of the committee
 * it resolves at its tip, on channel 0x71 over its existing 4004
 * connections, and answers once every asked seat answered or its
 * collection deadline passed (nodus_witness.h NODUS_CC_COLLECT_DEADLINE_MS,
 * 5000 ms):
 *   "r": {"res": [ {"i": seat, "st": status, "ok": bool,
 *                   ["rs": the responder's own seat, "s": signature,
 *                    "sh": set hash (64), "ep": epoch]   when ok,
 *                   ["r": reason]                         when refused} ]}
 * One entry per seat except the node's own, ascending seat order. A
 * busy node (one collection at a time) or a refused request answers an
 * error instead. */

/** Status of one seat in a `dnac_cc_collect` reply (the wire's "st"). */
#define NODUS_CC_COLLECT_ST_ANSWERED       0  /* the seat replied: "ok" / "r"  */
#define NODUS_CC_COLLECT_ST_NOT_CONNECTED  1  /* no 4004 connection to it now  */
#define NODUS_CC_COLLECT_ST_NO_ANSWER      2  /* asked; no reply by deadline   */
#define NODUS_CC_COLLECT_ST_SEND_FAILED    3  /* connected; request not queued */

/** How long `nodus_client_dnac_cc_collect` waits for the node's answer:
 *  the node's own 5000 ms collection deadline plus 10 s for the committee
 *  resolution, the 4001 round trip and a loaded node's loop. Pinned above
 *  the node's deadline by a _Static_assert in
 *  nodus_witness_chain_config.c. */
#define NODUS_DNAC_CC_COLLECT_TIMEOUT_MS   15000

/** One seat's result in a `dnac_cc_collect` reply. */
typedef struct {
    uint16_t seat;                    /* "i": the seat the node asked     */
    uint8_t  status;                  /* "st": NODUS_CC_COLLECT_ST_*      */
    bool     ok;                      /* "ok": an approval came back      */
    uint16_t rsp_seat;                /* "rs": the seat the reply names   */
    uint8_t  sig[NODUS_SIG_BYTES];    /* "s"  (ok only)                   */
    uint8_t  set_hash[64];            /* "sh" (ok only)                   */
    uint64_t epoch;                   /* "ep" (ok only)                   */
    char     reason[129];             /* "r"  (refused only), NUL-ended   */
} nodus_dnac_cc_collect_entry_t;

/** A `dnac_cc_collect` reply. ⚠ SIZE: ~620 KB — heap-allocate it, never
 *  a stack variable (the nodus_dnac_committee_result_t rule). */
typedef struct {
    int count;
    nodus_dnac_cc_collect_entry_t entries[NODUS_T3_MAX_WITNESSES];
} nodus_dnac_cc_collect_result_t;

/**
 * Ask the connected node to collect governance approvals for the pre-auth
 * envelope `env_bytes` (dnac_cc_collect, above). The client must be
 * authenticated with the node's own identity. Waits up to
 * NODUS_DNAC_CC_COLLECT_TIMEOUT_MS.
 *
 * @return 0 and `result_out` filled; a NODUS_ERR_* code the node answered
 *         (busy, not its own identity, …) or NODUS_ERR_TIMEOUT; -1 on
 *         invalid arguments / encode / transport failure.
 */
int nodus_client_dnac_cc_collect(nodus_client_t *client,
                                 const uint8_t *env_bytes, size_t env_len,
                                 nodus_dnac_cc_collect_result_t *result_out);

/**
 * Decode a raw `dnac_cc_collect` response message (the T2 map the node
 * sends) into `result_out` — the decoder nodus_client_dnac_cc_collect
 * uses, exported for tests that read the node's reply off a socket.
 * Entries beyond NODUS_T3_MAX_WITNESSES are refused, not truncated.
 * @return 0; -1 malformed.
 */
int nodus_dnac_cc_collect_decode(const uint8_t *raw, size_t raw_len,
                                 nodus_dnac_cc_collect_result_t *result_out);

/* ── dnac_v3_block — one committed version-3 block, paged (scan-v3) ────
 * (decision docs/plans/decisions/2026-09-28-scan-v3-query.md; design
 * docs/plans/2026-09-28-scan-v3-design.md item 1)
 *
 * Request  "a": {"h": u64 height >= 1,
 *                "i": u32 first item index (absent = 0),
 *                "b": u32 item-byte budget (absent/0 = BUDGET_MAX;
 *                     clamped to [BUDGET_MIN, BUDGET_MAX])}
 * Response "r" — the header keys, then "it" LAST:
 *   "h"   u64     the height
 *   "bid" bstr64  block id — the cometbft header hash (v2_blocks.block_id)
 *   "pb"  bstr64  previous block id (v2_blocks.prev_block_id)
 *   "tm"  u64     header time, ms since the Unix epoch (BlockMeta header)
 *   "pa"  bstr    proposer address (header; 32 bytes on this chain)
 *   "gr"  bstr64  global root after the block (v2_blocks.global_root)
 *   "ac"  u64     applied envelopes (v2_blocks.tx_count — claims excluded)
 *   "n"   u32     items the block carries (applied AND refused)
 *   "tip" u64     the node's committed tip (MAX(v2_blocks.global_height))
 *   "nx"  u32     the next item index — PRESENT ONLY when the page ended
 *                 early (budget or item-count bound); ask again with i=nx
 *   "it"  array   one map per item, index-ascending from "i":
 *     "i"  u32     item index in the block
 *     "k"  u8      NODUS_DNAC_V3_KIND_* (1 envelope, 2 claim, 0 empty)
 *     "c"  u32     result code, the stored FinalizeBlock response's
 *                  tx_results[i].code — 0 = APPLIED, anything else =
 *                  refused (the ledger's nodus_v2_tx_code_t)
 *     "w"  bstr64  wire id — an APPLIED envelope: the id v2_tx_index
 *                  stores; a claim that decodes: SHA3-512(claim bytes)
 *                  (v2_claim_bytes.claim_hash). ABSENT on a refused
 *                  envelope: its wire id binds the block-start ruleset
 *                  context, which a historic height does not keep.
 *     "in" bstr64  intent id (an APPLIED envelope only)
 *     "f"  u64     declared fee (an envelope that decodes)
 *     "op" tstr    "spend" "burn" "token_create" "sysfund" "stake"
 *                  "delegate" "unstake" "undelegate" "validator_update"
 *                  "chain_config" "claim" "name_register" (HF-4)
 *                  "evm_call" "evm_create" "evm_deposit" "evm_withdraw"
 *                  "evm_redeem" (Nodus EVM — named by the EVM leg's runtime op
 *                  1..5 of an [CORE EVMFUND] + [EVM op] envelope; an
 *                  older client shows them as unknown names) —
 *                  absent when unnamed
 *     EFFECTS — present on APPLIED items only (a refused item has none):
 *     "sp" array   consumed coin ids (bstr64), call order
 *     "cr" array   created coins, call order, each
 *                  {"id" bstr64 coin id (the utxo_set key),
 *                   "o"  tstr  owner fp, 128 lowercase hex (dnac_utxo's
 *                              "owner" format),
 *                   "a"  u64   amount, "t" bstr64 token id (zero = native),
 *                   "u"  u64   unlock block (0 = unlocked)}
 *     "bu" u64     burned amount (BURN only)
 *     "nm" tstr    HF-4 NAME_REGISTER only (OPTIONAL — an older decoder
 *                  skips it): the registered name, 3..36 of a-z0-9
 *     "pr" u64     HF-4 NAME_REGISTER only (OPTIONAL): the price paid
 *                  into the reward pool — NOT a burn, never in "bu"
 *     Nodus EVM (OPTIONAL keys — an older decoder skips them; design
 *     docs/plans/2026-10-04-nodus-evm-chain-integration-design.md §2, §5, §7).
 *     An EVM envelope's "sp"/"cr" are its CORE EVMFUND leg's: the funding
 *     coins consumed, the change created and — WITHDRAW / REDEEM — the
 *     release coin LAST (owner = the recipient, unlocked). The CORE EVM
 *     reserve move, raw units, present only when non-zero:
 *     "ri" u64     DEPOSIT: raw units locked INTO the reserve
 *     "ro" u64     WITHDRAW / REDEEM: raw units paid OUT of the reserve
 *                  (the release coin's amount)
 *     "ev" map     an APPLIED EVM item's facts — every field read from the
 *                  STORED receipt (evm_receipts, the §7 bytes, decoded by
 *                  dna_evm_rcpt_decode; its SHA3-512 checked against the
 *                  stored row's digest AND the block's committed
 *                  ExecTxResult.Data) and from the decoded call
 *                  (dna_evm_call_decode); nothing is executed. A refused
 *                  item carries no "ev" (it has no receipt).
 *        "s"   u8      status (1 success, 0 failed — a paid failure)
 *        "gu"  u64     EVM gas used (not the ledger units)
 *        "fr"  bstr32  EVM sender = the EVM leg's signer fingerprint
 *                      [0..32] (nodus_rt_native_committed_signer_fp)
 *        "to"  bstr32  CALL: the target address
 *        "ca"  bstr32  CREATE, status 1 only: the created address
 *        "v"   bstr32  CALL / CREATE: value in wei (big-endian)
 *        "dst" bstr64  WITHDRAW / REDEEM: the recipient fingerprint (the
 *                      design's 64-byte dest_fp — the "withdraw target")
 *        "nl"  u32     number of logs the receipt holds
 *        "tk"  array   ticket ids (bstr64) the item OPENED, receipt order,
 *                      at most NODUS_DNAC_V3_EVM_MAX_TICKETS; absent when
 *                      none
 *        "tkm" bool    true = the receipt holds MORE tickets than "tk"
 *                      carries (cut short); absent otherwise
 *        "wd"  bstr32  wei destroyed (big-endian)
 *        "dg"  bstr64  the receipt digest = the item's ExecTxResult.Data
 *     "rc" map     the SYSTEM record written:
 *                  {"k" u8 NODUS_DNAC_V3_REC_*,
 *                   "v" tstr128 validator fp, "d" tstr128 delegator fp,
 *                   "ds" tstr128 unstake destination fp, "a" u64 amount,
 *                   "cm" u16 commission bps, "p" u8 param id,
 *                   "nv" u64 new value, "ef" u64 effective height}
 *                  HF-6 generation 4 (sub-slice 3e, OPTIONAL — present
 *                  exactly for a generation-4 STAKE-family record; this
 *                  SDK's decoder skips them): "vid" tstr128 validator_id
 *                  (the value "v" also carries under generation 4 — "v"
 *                  names the validator's id there, not an address),
 *                  "ow" tstr128 the validator's owner_fp (its address)
 * An error reply (NODUS_ERR_NOT_FOUND: not committed / not held;
 * NODUS_ERR_INTERNAL_ERROR: a store/decode fault on the node) is never a
 * partial page. */

/* ── HF-4 queries (design docs/plans/2026-10-02-onchain-names-design.md
 *    rev 4 §1.6, §2 "Queries") ─────────────────────────────────────────
 *
 * dnac_ruleset_info — Request: no args. Response "r":
 *   "tip" u64  the node's committed tip
 *   "gen" u32  the rule-set generation governing tip + 1 (from the
 *              registry — the switch rewrites it at the end of H-1)
 *   "sv" u32, "sh" bstr64   SYSTEM ruleset_version / ruleset_hash
 *   "cv" u32, "ch" bstr64   DNA_CORE ruleset_version / ruleset_hash
 *   "pd" bstr64  the SYSTEM meter-policy digest of that generation
 *   "H"  u64   the earliest committed RULESET_GEN2 effective height,
 *              0 = no vote committed
 *   "d2" u64   the node build's DNAC_CFG_RULESET_GEN2_D2
 *   "ng" u32   OPTIONAL (update-required warning, design 2026-10-20 §1 A):
 *              the generation a committed generation-switch row that is
 *              NOT yet effective (effective_block > tip) moves the chain
 *              to — the node's own param → generation table (9 → 2,
 *              14 → 3, 18 → 4, 22 → 5); the row with the smallest
 *              effective_block (ties: the smaller param id). 0 = none.
 *   "nh" u64   OPTIONAL: that row's effective height, 0 = none.
 *              A node older than these keys sends neither: the decoder
 *              reads them as 0 (no pending switch known).
 * A client builds an envelope for the compiled generation whose tuple
 * EQUALS (sv, sh, cv, ch) — never by height; no match = this client is
 * out of date. An older node answers "unknown DNAC method": fail closed.
 * ng / nh are for a WARNING only (nodus_ruleset_compat); they never
 * choose what is built.
 *
 * dnac_name_lookup — "a": {"name": tstr, 3..36 of a-z0-9, LOWERCASE}.
 * dnac_name_of     — "a": {"owner": tstr, 128 lowercase hex}.
 * Response "r": {"found" bool, "ch" u64 the committed height the answer
 *   is from, and when found: "owner" tstr128 + "rh" u64 (lookup) /
 *   "name" tstr + "rh" u64 (name_of)}. One node is trusted for the answer
 *   (decision 2026-10-02-onchain-names.md item 9 — accepted risk).
 *
 * dnac_fee_info gains (HF-4) "np" — the COMPUTED NAME_REGISTER prices at
 * tip + 1 for names of 3 / 4 / 5 / 6+ characters — and "ns", the
 * committed NAME_PRICE rows effective above tip + 1 (at most
 * NODUS_DNAC_NAME_SCHED_MAX, ascending (effective, param)). */

/** Scheduled name-price rows one dnac_fee_info answer carries at most. */
#define NODUS_DNAC_NAME_SCHED_MAX  16u

typedef struct {
    uint64_t tip;
    uint32_t generation;
    uint32_t sys_version;
    uint8_t  sys_hash[64];
    uint32_t core_version;
    uint8_t  core_hash[64];
    uint8_t  policy_digest[64];
    uint64_t gen2_height;              /* "H": 0 = no vote committed     */
    uint64_t d2;
    uint32_t next_generation;          /* "ng": 0 = no pending switch    */
    uint64_t next_height;              /* "nh": 0 = no pending switch    */
} nodus_dnac_ruleset_info_t;

typedef struct {
    bool     found;
    char     owner[129];               /* lookup: 128 hex + NUL          */
    char     name[37];                 /* name_of: NUL-terminated        */
    uint64_t registered_height;
    uint64_t committed_height;
} nodus_dnac_name_result_t;

typedef struct {
    uint64_t price[4];                 /* 3, 4, 5, 6+ characters         */
    size_t   n_sched;
    struct {
        uint8_t  param_id;             /* DNAC_CFG_NAME_PRICE_3P..6P     */
        uint64_t value;
        uint64_t effective;
    } sched[NODUS_DNAC_NAME_SCHED_MAX];
} nodus_dnac_name_prices_t;

/** dnac_ruleset_info. @return 0; a NODUS_ERR_* the node answered (an
 *  older node: "unknown DNAC method" — the caller must fail closed);
 *  NODUS_ERR_TIMEOUT; -1 on invalid args / transport failure. */
int nodus_client_dnac_ruleset_info(nodus_client_t *client,
                                   nodus_dnac_ruleset_info_t *out);
/** dnac_name_lookup (`name` must already be lowercase). Same returns. */
int nodus_client_dnac_name_lookup(nodus_client_t *client, const char *name,
                                  nodus_dnac_name_result_t *out);
/** dnac_name_of (`owner_hex` = 128 lowercase hex). Same returns. */
int nodus_client_dnac_name_of(nodus_client_t *client, const char *owner_hex,
                              nodus_dnac_name_result_t *out);
/** dnac_fee_info's HF-4 keys ("np", "ns"). An older node sends neither:
 *  NODUS_ERR_PROTOCOL_ERROR (fail closed — no price is ever guessed). */
int nodus_client_dnac_name_prices(nodus_client_t *client,
                                  nodus_dnac_name_prices_t *out);

/** HF-8 (decision docs/plans/decisions/2026-10-21-hf8-activation.md):
 *  dnac_fee_info's "delegate_name_required" key — chain_config param 17
 *  (DELEGATE_NAME_REQUIRED) as the node judges it at tip + 1, the height
 *  CheckTx judges the next envelope at. A thin reader over the same
 *  request nodus_client_dnac_fee_info sends, kept out of
 *  nodus_dnac_fee_info_t (nodus_types.h) because that struct's uint64_t
 *  fields read an absent key as 0, and 0 here means "off": an older node
 *  that predates the key must read as UNKNOWN. Who is exempt is not
 *  reported — the chain decides per DELEGATE (generation 4: the
 *  validator row's owner, decision D3). */
#define NODUS_DLG_NAME_RULE_UNKNOWN  (-1)  /**< key absent: an older node */
#define NODUS_DLG_NAME_RULE_OFF        0
#define NODUS_DLG_NAME_RULE_ON         1

/** dnac_fee_info → *state_out = NODUS_DLG_NAME_RULE_*. Same returns as
 *  nodus_client_dnac_name_prices (0; a NODUS_ERR_* the node answered;
 *  NODUS_ERR_TIMEOUT; NODUS_ERR_PROTOCOL_ERROR on a malformed reply; -1
 *  on invalid args / transport failure). *state_out is meaningful only
 *  on 0. */
int nodus_client_dnac_delegate_name_rule(nodus_client_t *client,
                                         int *state_out);

/** The raw-reply decoder nodus_client_dnac_delegate_name_rule uses,
 *  exported for tests (no network). The v3d_* discipline: a duplicate
 *  key, truncation, or a "delegate_name_required" value that is not the
 *  unsigned integer 0 or 1 refuses; every other key is skipped. Key
 *  absent → NODUS_DLG_NAME_RULE_UNKNOWN.
 *  @return 0 / -1 (NULL argument or malformed reply). */
int nodus_dnac_delegate_name_rule_decode(const uint8_t *raw, size_t raw_len,
                                         int *state_out);

/** The raw-reply decoders the four functions above use, exported for
 *  tests (no network). @return 0 / -1 malformed. */
int nodus_dnac_ruleset_info_decode(const uint8_t *raw, size_t raw_len,
                                   nodus_dnac_ruleset_info_t *out);
int nodus_dnac_name_result_decode(const uint8_t *raw, size_t raw_len,
                                  int is_name_of,
                                  nodus_dnac_name_result_t *out);
int nodus_dnac_name_prices_decode(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_name_prices_t *out);

/** Rule-set compatibility of THIS build with a node's dnac_ruleset_info
 *  answer (update-required warning, design docs/plans/2026-10-20-update-
 *  required-warning-design.md §1 B). Pure: no network, no clock.
 *  `max_generation_supported` = the newest rule-set generation the
 *  caller can build for.
 *  @return 2 UPDATE REQUIRED — ri->generation > max (checked first);
 *          1 UPDATE BEFORE  — ri->next_generation > max and
 *                             ri->next_height > ri->tip;
 *          0 OK;
 *         -1 ri == NULL.
 *  For 1 and 2 a one-line English message is written to `msg` (when msg
 *  != NULL and msg_len > 0; truncated to fit, always NUL-terminated; ""
 *  for 0). The distance is given in blocks (next_height − tip), never as
 *  a time. The text says "Install the current release" — what that means
 *  is the caller's to say. A warning only: it never decides what is
 *  built. */
int nodus_ruleset_compat(const nodus_dnac_ruleset_info_t *ri,
                         uint32_t max_generation_supported,
                         char *msg, size_t msg_len);

/* ── Storage reward v1 — dnac_storage_status (package B2b-CLI; decision
 *    docs/plans/decisions/2026-10-05-storage-reward-is-for-archive.md) ──
 *
 * READ-ONLY, committed tables only. Request "a": {"fp": tstr, exactly 128
 * lowercase hex = SHA3-512(node_pk)}. Response "r":
 *   "ch"    u64   the node's committed tip
 *   "es"    u64   H = ch − (ch mod E): the boundary whose frozen
 *                 storage_set(H) governs epoch (H, H+E]; 0 = none yet
 *   "found" bool  the storage registry row exists; when (and only when)
 *                 true also:
 *     "st"    u8   1 ACTIVE / 2 EXITING / 3 RELEASED
 *     "bond"  u64  raw
 *     "fs"    u32  fail_streak (live registry value)
 *     "gu"    u64  grace_until (live registry value; K9 — epoch (H, H+E]
 *                  is in grace while H < gu: not probed, earns nothing)
 *     "rh"    u64  registered_height (>= 1)
 *     "xh"    u64  exit_height (0 = no exit)
 *     "payee" tstr 128 lowercase hex
 *   "set"   bool  storage_set(H) exists
 *   "sc"    u32   its member count (0..NODUS_DNAC_STORAGE_SET_MAX)
 *   "mem"   bool  the node is a member of storage_set(H)
 *   "ns"    u64   segments ELIGIBLE for the node in (H, H+E] (assigned or
 *                 in the handoff overlap, 0 while in grace; K1 weight =
 *                 ns × 17280 blocks)
 *   "segs"  array of u64: the first min(ns, NODUS_DNAC_STORAGE_SEG_MAX)
 *                 of them, k strictly ascending
 * Rules the decoder enforces: every key above present exactly once (the
 * row keys iff found; a duplicate refuses, an unknown key is skipped as in
 * every v3d_* decoder); es <= ch; !set ⇒ sc 0 ∧ !mem;
 * mem ⇒ found ∧ set; !mem ⇒ ns 0; |segs| = min(ns, SEG_MAX); k >= 1.
 * The last SETTLED outcome is NOT in the reply — the chain records no
 * per-member verdict (fail_streak is its only committed trace). An older
 * node answers "unknown DNAC method". One node is trusted for the answer
 * (as every dnac_* query). */

/** Members of one frozen storage set at most (DNA_V2_STORAGE_SET_MAX). */
#define NODUS_DNAC_STORAGE_SET_MAX  256u
/** Eligible segment numbers one dnac_storage_status reply lists. */
#define NODUS_DNAC_STORAGE_SEG_MAX  64u

typedef struct {
    uint64_t committed_height;         /* "ch"                           */
    uint64_t epoch_start;              /* "es"                           */
    bool     found;
    uint8_t  status;                   /* "st": 1..3 when found          */
    uint64_t bond;
    uint32_t fail_streak;
    uint64_t grace_until;              /* "gu" (K9)                      */
    uint64_t registered_height;
    uint64_t exit_height;
    char     payee[129];               /* 128 hex + NUL                  */
    bool     set_exists;               /* "set"                          */
    uint32_t set_count;                /* "sc"                           */
    bool     member;                   /* "mem"                          */
    uint64_t n_segments;               /* "ns"                           */
    size_t   n_listed;                 /* entries of segments[]          */
    uint64_t segments[NODUS_DNAC_STORAGE_SEG_MAX];
} nodus_dnac_storage_status_t;

/** dnac_storage_status for `node_fp_hex` (128 lowercase hex). @return 0;
 *  a NODUS_ERR_* the node answered (an older node: "unknown DNAC
 *  method"); NODUS_ERR_PROTOCOL_ERROR for a reply the decoder refuses;
 *  NODUS_ERR_TIMEOUT; -1 on invalid args / transport failure. */
int nodus_client_dnac_storage_status(nodus_client_t *client,
                                     const char *node_fp_hex,
                                     nodus_dnac_storage_status_t *out);
/** Its raw-reply decoder, exported for tests (no network).
 *  @return 0 / -1 malformed (the rules above). */
int nodus_dnac_storage_status_decode(const uint8_t *raw, size_t raw_len,
                                     nodus_dnac_storage_status_t *out);

/* ── HF-6 slice 7a — dnac_storage_by_owner (design docs/plans/2026-10-03-
 *    hf5-validator-owner-stake-design.md rev 6 §9 / §11) ──
 *
 * READ-ONLY, committed tables only: the storage registry rows an OWNER
 * registered (v2_storage_nodes.payee_fp = owner_fp since HF-6 6b).
 * Request "a": {"owner": tstr, exactly 128 lowercase hex}. Response "r":
 *   "ch"    u64   the node's committed tip
 *   "total" u64   the owner's rows, every status (ACTIVE / EXITING /
 *                 RELEASED)
 *   "nodes" array of the first min(total, NODUS_DNAC_STORAGE_SET_MAX)
 *                 rows, node_fp strictly ASCENDING; each a map of "fp"
 *                 tstr128 (the node_fp) plus exactly the keys
 *                 dnac_storage_status answers for that node (above), all
 *                 against ONE storage_set(H).
 * The live rows are capped at NODUS_DNAC_STORAGE_SET_MAX on chain;
 * RELEASED rows never vanish, so total may exceed the list — total >
 * count means the list stops at the cap (no paging). An owner without
 * rows answers total 0 and an empty list (not an error).
 * Rules the decoder enforces, besides every per-node rule of
 * nodus_dnac_storage_status_decode: "ch", "total", "nodes" each exactly
 * once; |nodes| = min(total, SET_MAX); every entry carries "fp" (128
 * lowercase hex), found = true, the reply's "ch", and the same "es" /
 * "set" / "sc" as the first entry; fp strictly ascending; when the caller
 * names the owner, every entry's "payee" equals it. An older node answers
 * "unknown DNAC method". One node is trusted for the answer. */

/** One node of a dnac_storage_by_owner answer. */
typedef struct {
    char                         node_fp[129];   /* "fp": 128 hex + NUL  */
    nodus_dnac_storage_status_t  st;             /* its status answer    */
} nodus_dnac_storage_node_t;

/** A dnac_storage_by_owner answer. nodes is heap (count entries, NULL
 *  when count is 0); free with nodus_dnac_storage_by_owner_free(). */
typedef struct {
    uint64_t                   committed_height; /* "ch"                 */
    uint64_t                   total;            /* "total"              */
    size_t                     count;            /* entries of nodes[]   */
    nodus_dnac_storage_node_t *nodes;
} nodus_dnac_storage_by_owner_t;

/** dnac_storage_by_owner for `owner_hex` (128 lowercase hex). @return 0;
 *  a NODUS_ERR_* the node answered (an older node: "unknown DNAC
 *  method"); NODUS_ERR_PROTOCOL_ERROR for a reply the decoder refuses
 *  (incl. an entry whose owner is not `owner_hex`); NODUS_ERR_TIMEOUT;
 *  -1 on invalid args / transport failure. On success the caller frees
 *  `out` with nodus_dnac_storage_by_owner_free(). */
int nodus_client_dnac_storage_by_owner(nodus_client_t *client,
                                       const char *owner_hex,
                                       nodus_dnac_storage_by_owner_t *out);
/** Its raw-reply decoder, exported for tests (no network). `owner_hex`
 *  NULL skips the per-entry owner check. On -1 `out` is freed and zeroed.
 *  @return 0 / -1 malformed (the rules above). */
int nodus_dnac_storage_by_owner_decode(const uint8_t *raw, size_t raw_len,
                                       const char *owner_hex,
                                       nodus_dnac_storage_by_owner_t *out);
/** Free a dnac_storage_by_owner answer (nodes) and zero it. NULL-safe. */
void nodus_dnac_storage_by_owner_free(nodus_dnac_storage_by_owner_t *r);

/* ── dnac_node_duties — "may this node switch its witness package off?"
 *    (design docs/plans/2026-10-22-nodus-packages-design.md §3; decisions
 *    2026-10-22-nodus-packages-add-remove.md, 2026-10-22-kurultay-36-
 *    summary.md) ──
 *
 * READ-ONLY, node-local, committed tables only. NO ARGUMENTS: it always
 * answers for the node that is asked. SERVED ONLY to a session
 * authenticated with THIS node's own identity key — any other session
 * gets NODUS_ERR_NOT_AUTHENTICATED. An older node answers "unknown DNAC
 * method"; a node without a chain, NODUS_ERR_NOT_FOUND; a core without a
 * witness, NODUS_CHAIN_NO_WITNESS_MSG.
 *
 * Response "r" (every key exactly once, except "why"):
 *   "ch"    u64     the committed tip T (read at the start; read again at
 *                   the end — a different value turns the answer UNKNOWN)
 *   "cid"   bstr32  the chain id; all zero when it could not be read
 *   "bh"    bstr64  the block id at T; all zero when it could not be read
 *   "fresh" bool    the node is caught up with its peers. True exactly
 *                   when ALL hold (the decoder re-checks it):
 *                     "ws" is false  (the consensus reactor is not
 *                                     waiting for block sync),
 *                     "cs" is true   (the consensus state machine has
 *                                     started),
 *                     "np" >= 1      (consensus peers that are in the
 *                                     reactor's set, started, and whose
 *                                     round-state height is known, > 0),
 *                     "ch" + 1 >= "mph"  (T >= maxPeerHeight - 1: a peer
 *                                     at height h has committed h - 1).
 *   "ws"    bool    the reactor's wait-sync flag
 *   "cs"    bool    the state machine started
 *   "np"    u32     peers with a known height (<= 65535)
 *   "mph"   u64     the highest such peer height (0 when "np" is 0)
 *   "state" u8      NODUS_DNAC_DUTIES_CLEAR / _BLOCKED / _UNKNOWN. It is
 *                   decided from the committed rows alone; "fresh" is a
 *                   separate fact and is NOT folded into it — a caller
 *                   must require BOTH fresh and CLEAR.
 *                   CLEAR    no duty found. Never sent when any read
 *                            failed, returned -1, found a row that must
 *                            exist missing, or met an unsupported state.
 *                   BLOCKED  at least one blocker, below.
 *                   UNKNOWN  something could not be established; "bl" and
 *                            "own" are empty and "why" says what.
 *   "bl"    array of <= NODUS_DNAC_DUTIES_BL_MAX maps {"c" u8 code,
 *                   "eh" u64 end}, "c" STRICTLY ASCENDING (one entry per
 *                   code), "c" in 1..NODUS_DNAC_DUTY_MAX. "eh" is the
 *                   committed tip at which the blocker no longer applies
 *                   (the node may be asked again once ch >= eh); 0 means
 *                   "until the owner leaves" and occurs only for codes
 *                   WITNESS_REGISTERED and STORAGE_REGISTERED. Otherwise
 *                   eh > ch.
 *   "own"   array of <= NODUS_DNAC_DUTIES_OWNERS_MAX tstr128 (lowercase
 *                   hex), strictly ascending: the owner fingerprints of
 *                   the rows behind codes 1, 2, 6 and 7.
 *   "why"   tstr    (<= NODUS_DNAC_DUTIES_WHY_MAX chars) only when
 *                   state is UNKNOWN.
 * Rules the decoder enforces: the 11 keys above present exactly once (a
 * duplicate, a missing key, a wrong type or a length that is not exact
 * refuses; an unknown key is skipped as in every v3d_* decoder); "fresh"
 * consistent with its inputs; "np" 0 <=> "mph" 0; CLEAR => "bl" and "own"
 * empty; BLOCKED => "bl" non-empty; UNKNOWN => "bl" and "own" empty and
 * "why" present; non-UNKNOWN => "why" absent; "ch" < UINT64_MAX.
 *
 * The blockers (design §3.3; B = the epoch start of block ch + 1, E =
 * DNAC_EPOCH_LENGTH; the choices the code makes where the design leaves
 * one open are in nodus_witness_handlers.c, handle_dnac_node_duties):
 *   1 WITNESS_REGISTERED  a validators row with this node's key is ACTIVE
 *                         or ELIGIBLE (several rows with one key are all
 *                         read); eh 0.
 *   2 WITNESS_LEAVING     such a row is RETIRING or AUTO_RETIRED; it
 *                         graduates by itself: eh = B + 2E when the key
 *                         is an entry of snapshot(B + E), else B + E.
 *   3 SEATED_NOW          the key is an entry of the snapshot governing
 *                         block ch + 1; eh = B + E.
 *   4 SEATED_NEXT         the key is an entry of the already frozen
 *                         snapshot(B + E); eh = B + 2E.
 *   5 CMT_TRANSITION      ch + 1 is B or B + 1 and the key is an entry of
 *                         snapshot(B - E) (cometbft applies validator
 *                         updates two blocks late); eh = B + 1.
 *   6 STORAGE_REGISTERED  the storage registry row of this node is ACTIVE;
 *                         eh 0.
 *   7 STORAGE_LEAVING     that row is EXITING; eh = the first multiple of
 *                         E that is >= ch + 1 (the release boundary).
 *   8 ARCHIVE_OVERLAP     this node still must hold archive segments at
 *                         H = ch - ch mod E (nodus_witness_sthold_must_hold);
 *                         eh = H + 2E when it is a member of storage_set(H),
 *                         else H + E.
 *   9 STORAGE_REPORT      this node held seat s of the committee of the
 *                         probing epoch P = B - E, the report window
 *                         (P + E, P + E + E/2] is open at ch and no
 *                         STORAGE_REPORT (P, s) is committed; eh = P + E +
 *                         E/2.
 * One node is trusted for the answer: the CLI pins the session to the
 * node's own id on 127.0.0.1. */

/** "state" values. */
#define NODUS_DNAC_DUTIES_CLEAR    0u
#define NODUS_DNAC_DUTIES_BLOCKED  1u
#define NODUS_DNAC_DUTIES_UNKNOWN  2u

/** Blocker codes ("bl" entry "c"). */
#define NODUS_DNAC_DUTY_WITNESS_REGISTERED  1u
#define NODUS_DNAC_DUTY_WITNESS_LEAVING     2u
#define NODUS_DNAC_DUTY_SEATED_NOW          3u
#define NODUS_DNAC_DUTY_SEATED_NEXT         4u
#define NODUS_DNAC_DUTY_CMT_TRANSITION      5u
#define NODUS_DNAC_DUTY_STORAGE_REGISTERED  6u
#define NODUS_DNAC_DUTY_STORAGE_LEAVING     7u
#define NODUS_DNAC_DUTY_ARCHIVE_OVERLAP     8u
#define NODUS_DNAC_DUTY_STORAGE_REPORT      9u
#define NODUS_DNAC_DUTY_MAX                 9u

/** Bounds of the lists (one blocker per code; owners of the rows). */
#define NODUS_DNAC_DUTIES_BL_MAX      NODUS_DNAC_DUTY_MAX
#define NODUS_DNAC_DUTIES_OWNERS_MAX  16u
/** Longest "why" text. */
#define NODUS_DNAC_DUTIES_WHY_MAX     96u

typedef struct {
    uint8_t  code;                     /* NODUS_DNAC_DUTY_*              */
    uint64_t end_height;               /* "eh"; 0 = until the owner leaves */
} nodus_dnac_duty_blocker_t;

typedef struct {
    uint64_t committed_height;         /* "ch"                           */
    uint8_t  chain_id[32];             /* "cid"                          */
    uint8_t  block_hash[64];           /* "bh"                           */
    bool     fresh;                    /* "fresh"                        */
    bool     wait_sync;                /* "ws"                           */
    bool     cs_started;               /* "cs"                           */
    uint32_t n_peers;                  /* "np"                           */
    uint64_t max_peer_height;          /* "mph"                          */
    uint8_t  state;                    /* NODUS_DNAC_DUTIES_*            */
    size_t   n_blockers;               /* entries of blockers[]          */
    nodus_dnac_duty_blocker_t blockers[NODUS_DNAC_DUTIES_BL_MAX];
    size_t   n_owners;                 /* entries of owners[]            */
    char     owners[NODUS_DNAC_DUTIES_OWNERS_MAX][129];  /* 128 hex + NUL */
    char     why[NODUS_DNAC_DUTIES_WHY_MAX + 1];         /* UNKNOWN only  */
} nodus_dnac_node_duties_t;

/** dnac_node_duties of the connected node (no arguments). @return 0; a
 *  NODUS_ERR_* the node answered (NODUS_ERR_NOT_AUTHENTICATED for a
 *  session that is not the node's own identity; an older node: "unknown
 *  DNAC method"); NODUS_ERR_PROTOCOL_ERROR for a reply the decoder
 *  refuses; NODUS_ERR_TIMEOUT; -1 on invalid args / transport failure. */
int nodus_client_dnac_node_duties(nodus_client_t *client,
                                  nodus_dnac_node_duties_t *out);
/** Its raw-reply decoder, exported for tests (no network). `out` is zeroed
 *  on -1. @return 0 / -1 malformed (the rules above). */
int nodus_dnac_node_duties_decode(const uint8_t *raw, size_t raw_len,
                                  nodus_dnac_node_duties_t *out);

#define NODUS_DNAC_V3_BLOCK_BUDGET_MIN      1024u
#define NODUS_DNAC_V3_BLOCK_BUDGET_MAX      (1024u * 1024u)
/** Items one page may carry — bounds the client's allocation. */
#define NODUS_DNAC_V3_BLOCK_PAGE_MAX_ITEMS  256u
/** Consumed / created coins per item (the node's native CORE bounds:
 *  15 inputs; 16 wire outputs + the UNDELEGATE release coin). */
#define NODUS_DNAC_V3_ITEM_MAX_IN           15u
#define NODUS_DNAC_V3_ITEM_MAX_OUT          17u
#define NODUS_DNAC_V3_OP_MAX                24u
/** Nodus EVM: ticket ids one item's "ev" carries at most ("tkm" = more). */
#define NODUS_DNAC_V3_EVM_MAX_TICKETS       32u

#define NODUS_DNAC_V3_KIND_EMPTY            0
#define NODUS_DNAC_V3_KIND_ENVELOPE         1
#define NODUS_DNAC_V3_KIND_CLAIM            2

#define NODUS_DNAC_V3_REC_NONE              0
#define NODUS_DNAC_V3_REC_STAKE             1
#define NODUS_DNAC_V3_REC_DELEGATE          2
#define NODUS_DNAC_V3_REC_UNSTAKE           3
#define NODUS_DNAC_V3_REC_UNDELEGATE        4
#define NODUS_DNAC_V3_REC_VALIDATOR_UPDATE  5
#define NODUS_DNAC_V3_REC_CHAIN_CONFIG      6

/** One created coin ("cr" entry). */
typedef struct {
    uint8_t  id[64];
    char     owner[129];              /* 128 lowercase hex + NUL          */
    uint64_t amount;
    uint8_t  token_id[64];
    uint64_t unlock_block;
} nodus_dnac_v3_coin_t;

/** One item of a `dnac_v3_block` page (~8.5 KB). */
typedef struct {
    uint32_t index;
    uint8_t  kind;                    /* NODUS_DNAC_V3_KIND_*             */
    uint32_t code;                    /* 0 = applied                      */
    bool     has_wire_id;
    uint8_t  wire_id[64];
    bool     has_intent_id;
    uint8_t  intent_id[64];
    bool     has_fee;
    uint64_t fee;
    char     op[NODUS_DNAC_V3_OP_MAX + 1];   /* "" when absent            */
    bool     has_effects;             /* "sp"/"cr" present (applied)      */
    uint8_t  n_consumed;
    uint8_t  consumed[NODUS_DNAC_V3_ITEM_MAX_IN][64];
    uint8_t  n_created;
    nodus_dnac_v3_coin_t created[NODUS_DNAC_V3_ITEM_MAX_OUT];
    uint64_t burned;
    uint8_t  rec_kind;                /* NODUS_DNAC_V3_REC_*              */
    char     rec_validator_fp[129];   /* "" when absent                   */
    char     rec_delegator_fp[129];
    char     rec_dest_fp[129];
    uint64_t rec_amount;
    uint16_t rec_commission_bps;
    uint8_t  cc_param_id;
    uint64_t cc_new_value;
    uint64_t cc_effective;
    /* HF-4 NAME_REGISTER (optional keys "nm" / "pr", applied items only):
     * the registered name (3..36 of a-z0-9, NUL-terminated; "" = not a
     * registration) and the price paid into the reward pool — never a
     * burn, so it is not `burned`. */
    char     name[37];
    uint64_t name_price;
    /* Nodus EVM (optional keys "ri" / "ro" / "ev", applied items only):
     * the CORE EVM reserve move in raw units (0 = absent) and the EVM
     * facts of the stored receipt (has_evm false = no "ev"). */
    uint64_t reserve_in;
    uint64_t reserve_out;
    bool     has_evm;
    uint8_t  evm_status;
    uint64_t evm_gas_used;
    uint8_t  evm_from[32];
    bool     evm_has_to;
    uint8_t  evm_to[32];
    bool     evm_has_created;
    uint8_t  evm_created[32];
    bool     evm_has_value;
    uint8_t  evm_value[32];
    bool     evm_has_dest;
    uint8_t  evm_dest[64];
    uint32_t evm_n_logs;
    uint8_t  evm_n_tickets;           /* entries in evm_tickets           */
    bool     evm_tickets_more;        /* "tkm": the receipt holds more    */
    uint8_t  evm_tickets[NODUS_DNAC_V3_EVM_MAX_TICKETS][64];
    uint8_t  evm_wei_destroyed[32];
    uint8_t  evm_digest[64];
} nodus_dnac_v3_item_t;

/** One `dnac_v3_block` page. `items` is heap (count entries) — free with
 *  nodus_client_free_v3_block_result. */
typedef struct {
    uint64_t height;
    uint8_t  block_id[64];
    uint8_t  prev_block_id[64];
    uint64_t time_ms;
    uint8_t  proposer[64];
    size_t   proposer_len;
    uint8_t  global_root[64];
    uint64_t applied_count;
    uint32_t total_items;
    uint64_t tip;
    bool     has_next;
    uint32_t next_index;
    size_t   count;
    nodus_dnac_v3_item_t *items;
} nodus_dnac_v3_block_result_t;

/**
 * Fetch one page of a committed version-3 block (dnac_v3_block, above).
 * Walk a block with from_index = 0, then result.next_index while
 * result.has_next.
 *
 * @param budget  item-byte budget (0 = the node's maximum)
 * @return 0 and `result_out` filled (free it with
 *         nodus_client_free_v3_block_result); the NODUS_ERR_* code the
 *         node answered; NODUS_ERR_PROTOCOL_ERROR for a reply the decoder
 *         refuses; -1 on invalid arguments / encode / transport failure.
 */
int nodus_client_dnac_v3_block(nodus_client_t *client, uint64_t height,
                               uint32_t from_index, uint32_t budget,
                               nodus_dnac_v3_block_result_t *result_out);

/**
 * Decode a raw `dnac_v3_block` response message (the T2 map the node
 * sends) — the decoder nodus_client_dnac_v3_block uses, exported for
 * tests. STRICT (the reply is a server's, possibly hostile): every
 * header key required and type-checked, a duplicate key refused, every
 * array bounded BEFORE it is walked (items <= PAGE_MAX_ITEMS, consumed
 * <= ITEM_MAX_IN, created <= ITEM_MAX_OUT), item indices strictly
 * ascending and below "n", "nx" consistent with the last item, a
 * truncated message refused. Unknown keys are skipped. On any refusal
 * `result_out` is left empty (nothing to free).
 * @return 0; -1 malformed.
 */
int nodus_dnac_v3_block_decode(const uint8_t *raw, size_t raw_len,
                               nodus_dnac_v3_block_result_t *result_out);

/** Free a `dnac_v3_block` result's items (NULL-safe; the struct is
 *  zeroed). */
void nodus_client_free_v3_block_result(nodus_dnac_v3_block_result_t *result);

/* ── dnac_light_block — one LightBlock for the light client ────────────
 * (decision docs/plans/decisions/2026-10-16-dnac-light-block-rpc.md,
 * APPROVED B1-B4; Kurultay #25 item 8: served over a PINNED 4001 session
 * only on the client side — nodus_light_provider.h refuses an unpinned
 * client)
 *
 * Request  "a": {"h": u64 — the height; 0 = the node's latest stored
 *                block (cometbft rpc/core/env.go:173-191, the nil
 *                height)}
 * Response "r": {"h":  u64  the resolved height (never 0),
 *                "lb": bstr the `tendermint.types.LightBlock` proto
 *                      (types.proto:161-164) — cmt_light_block_encode of
 *                      {SignedHeader{BlockMeta.Header, commit},
 *                       LoadValidators(h)}; the commit is the SEEN commit
 *                      at the node's latest height and the canonical one
 *                      (from block h+1) below it (rpc/core/blocks.go:
 *                      166-174); at most NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES}
 * Errors:  NODUS_ERR_HEIGHT_TOO_HIGH  h above the latest stored block
 *          NODUS_ERR_NOT_FOUND        pruned / not held (below the base,
 *                                     no meta, no commit, no validator
 *                                     set) or no version-3 chain served
 *          NODUS_ERR_INTERNAL_ERROR   a read or encode fault
 *          NODUS_ERR_PROTOCOL_ERROR   a malformed request
 * The answer is a peer's word: nothing here verifies it beyond the wire
 * shape; the light client does (ValidateBasic + verification).
 */

/** Ceiling of "lb": 1 MiB. The LightBlock of a full set (CMT_VALSET_MAX
 *  = 128 validators and as many commit signatures) is at most
 *  cmt_pb_light_block_upper_bound(128, 128) = 949 929 bytes
 *  (shared/dnac/cmt_light_block.c); the node checks that bound against
 *  this one before it answers, and test_light_block_rpc.c pins it. A
 *  constant here, not that call, so this client file does not link the
 *  cmt codec (the web wallet's WASM build compiles nodus_client.c
 *  without it). */
#define NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES  (1024u * 1024u)

/**
 * Encode the `dnac_light_block` request frame (the T2 query map with the
 * session token) into `buf` — the encoder nodus_client_dnac_light_block
 * uses, exported for tests.
 * @return 0 and `*len_out` set; -1 on NULL arguments or a buffer too
 *         small.
 */
int nodus_dnac_light_block_request_encode(uint32_t txn,
                                          const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                          uint64_t height,
                                          uint8_t *buf, size_t cap,
                                          size_t *len_out);

/**
 * Decode a raw `dnac_light_block` response message (the T2 map the node
 * sends) — the decoder nodus_client_dnac_light_block uses, exported for
 * tests. STRICT: "h" (u64, non-zero) and "lb" (bstr, 1 ..
 * NODUS_DNAC_LIGHT_BLOCK_MAX_BYTES bytes) are both required, a duplicate
 * key or a truncated message is refused, unknown keys are skipped.
 * `*lb_out` points INTO `raw` (valid while `raw` is).
 * @return 0; -1 malformed (outputs zeroed).
 */
int nodus_dnac_light_block_decode(const uint8_t *raw, size_t raw_len,
                                  uint64_t *height_out,
                                  const uint8_t **lb_out, size_t *lb_len_out);

/**
 * Fetch one LightBlock (dnac_light_block, above). Bounded by the
 * client's request_timeout_ms.
 *
 * @param height      0 = the node's latest; otherwise the node must
 *                    answer exactly this height (anything else is
 *                    refused NODUS_ERR_PROTOCOL_ERROR — the reference
 *                    provider's check, light/provider/http/http.go:70-74)
 * @param height_out  the resolved height
 * @param lb_out      malloc'd copy of the "lb" bytes; the caller frees it
 *                    with free(). NULL on every non-zero return.
 * @param server_err_out  the NODUS_ERR_* code of the node's ERROR reply,
 *                    0 when the node did not answer with one (success,
 *                    timeout, transport failure, a reply refused here).
 *                    May be NULL.
 * @return 0; the node's NODUS_ERR_* code (also in *server_err_out);
 *         NODUS_ERR_TIMEOUT when no reply came in time;
 *         NODUS_ERR_PROTOCOL_ERROR for a reply refused here; -1 on
 *         invalid arguments, a client that is not ready, or an encode /
 *         send / allocation failure.
 */
int nodus_client_dnac_light_block(nodus_client_t *client, uint64_t height,
                                  uint64_t *height_out,
                                  uint8_t **lb_out, size_t *lb_len_out,
                                  int *server_err_out);

/**
 * Read the node's committed version-3 tip through the dnac_supply RPC
 * (scan-v3 — the ADDITIVE "tip" key; the nodus_client_dnac_chain_id32
 * pattern: nodus_dnac_supply_result_t is not grown). A legacy node's
 * reply carries no such key; `*has_out` tells that case apart.
 * @return 0 (*has_out meaningful either way); error code on
 *         transport/RPC failure.
 */
int nodus_client_dnac_supply_tip(nodus_client_t *client, bool *has_out,
                                 uint64_t *tip_out);

/* ── dnac_supply buckets (decision
 * docs/plans/decisions/2026-09-30-scan-supply-buckets.md) ─────────────
 *
 * The version-3 dnac_supply reply carries three ADDITIVE keys beside
 * "chain_id32" / "tip" (nodus_witness_handlers.c handle_dnac_supply):
 *   "reward_pool": uint             supply_tracking.reward_pool — the
 *                                   validator reward reserve left
 *   "treasury":    [uint × 9]       v2_treasury.balance, pool 1..9 in
 *                                   order (NODUS_DNAC_TREASURY_POOLS)
 *   "unclaimed":   uint             Σ v2_dist_state.remaining of the
 *                                   distributions targeting the native
 *                                   coin — genesis allocation not yet
 *                                   claimed
 * The node reads them and "current" at ONE reading moment
 * (nodus_witness_supply_view_get), so
 *   circulating = current − reward_pool − Σ treasury − unclaimed
 * is computed from one reply. A legacy node, and a successor node with
 * no supply row yet, sends none of the three. */

#define NODUS_DNAC_TREASURY_POOLS 9

typedef struct {
    bool     has;             /* false: the reply carried none of the three
                               * bucket keys (an older node) — every
                               * field below is 0 and means nothing */
    uint64_t current_supply;  /* "current" of the SAME reply */
    uint64_t reward_pool;
    uint64_t treasury[NODUS_DNAC_TREASURY_POOLS];   /* [0] = pool 1 */
    uint64_t unclaimed;
} nodus_dnac_supply_buckets_t;

/**
 * Decode a dnac_supply reply's buckets — the decoder
 * nodus_client_dnac_supply_buckets uses, exported for tests. STRICT (the
 * reply is a server's, possibly hostile): a duplicate key, a truncated
 * message, a non-uint value, a "treasury" array that is not exactly
 * NODUS_DNAC_TREASURY_POOLS uints, "current" missing, or SOME but not
 * all of the three bucket keys are refused. None of the three = a valid
 * older reply (`has` false). Unknown keys are skipped.
 * @return 0; -1 malformed (`out` zeroed).
 */
int nodus_dnac_supply_buckets_decode(const uint8_t *raw, size_t raw_len,
                                     nodus_dnac_supply_buckets_t *out);

/**
 * Read the supply buckets through the dnac_supply RPC (the
 * nodus_client_dnac_supply_tip pattern: the same request, additive keys,
 * nodus_dnac_supply_result_t is not grown). `out->has` false = an older
 * node that sends no buckets.
 * @return 0 (`out->has` meaningful either way); NODUS_ERR_PROTOCOL_ERROR
 *         on a malformed reply; an error code on transport/RPC failure
 *         (the node answers an error, never zeros, when it cannot read
 *         its own state).
 */
int nodus_client_dnac_supply_buckets(nodus_client_t *client,
                                     nodus_dnac_supply_buckets_t *out);

/* ── dnac_balance — one owner's TRANSPARENT balance, per token (scan-v3) ─
 * (decision docs/plans/decisions/2026-09-28-scan-v3-query.md item 3a)
 *
 * PUBLIC: any session may ask about any owner (no session-owner gate —
 * unlike dnac_utxo, which keeps its own, C11). It answers
 * totals only: no coin ids, no history. TRANSPARENT coins only — the
 * CORE-domain rows of utxo_set; never a shielded pool's notes (never to
 * be extended there).
 *
 * Request  "a": {"owner": tstr — exactly 128 lowercase hex characters}
 * Response "r":
 *   "tip" u64    the node's committed tip (MAX(v2_blocks.global_height))
 *   "tk"  array  one map per token the owner holds, token id strictly
 *                ascending (bytewise), at most NODUS_DNAC_BALANCE_MAX_TOKENS:
 *     "t" bstr64  token id (all zero = native)
 *     "a" u64     total: Σ amount of the owner's unspent coins of the token
 *     "s" u64     spendable: Σ amount of those with unlock_block < tip + 1
 *                 (the native exec's lock gate judged for the next block;
 *                 s <= a)
 *     "c" u64     number of those coins (>= 1)
 *   An owner holding nothing answers an EMPTY "tk" — a real zero.
 * Errors (never a partial or zeroed answer):
 *   NODUS_ERR_PROTOCOL_ERROR  owner missing / duplicated / not 128
 *                             lowercase hex
 *   NODUS_ERR_NOT_FOUND       the node serves no version-3 chain
 *   NODUS_ERR_TOO_LARGE       the owner holds more than
 *                             NODUS_DNAC_BALANCE_MAX_TOKENS tokens
 *   NODUS_ERR_INTERNAL_ERROR  a store fault, an overflow, a malformed row
 */

/** Tokens one dnac_balance answer carries at most (~26 KB of reply). */
#define NODUS_DNAC_BALANCE_MAX_TOKENS  256u

typedef struct {
    uint8_t  token_id[64];
    uint64_t total;
    uint64_t spendable;
    uint64_t coins;
} nodus_dnac_balance_token_t;

/** One `dnac_balance` answer. `tokens` is heap (count entries; NULL when
 *  count is 0) — free with nodus_client_free_balance_result. */
typedef struct {
    uint64_t tip;
    size_t   count;
    nodus_dnac_balance_token_t *tokens;
} nodus_dnac_balance_result_t;

/**
 * Query one owner's transparent balance (dnac_balance, above).
 * @param owner_hex  exactly 128 lowercase hex characters (checked here
 *                   before anything is sent)
 * @return 0 and `result_out` filled (free with
 *         nodus_client_free_balance_result); the NODUS_ERR_* code the node
 *         answered; NODUS_ERR_PROTOCOL_ERROR for a reply the decoder
 *         refuses; -1 on invalid arguments / encode / transport failure.
 */
int nodus_client_dnac_balance(nodus_client_t *client, const char *owner_hex,
                              nodus_dnac_balance_result_t *result_out);

/**
 * Decode a raw `dnac_balance` response message — the decoder
 * nodus_client_dnac_balance uses, exported for tests. STRICT: "tip" and
 * "tk" required, a duplicate key refused (top level and per token), every
 * read checked for END/ERROR, "tk" bounded by
 * NODUS_DNAC_BALANCE_MAX_TOKENS before it is walked, every token map
 * carries all four of its keys typed, token ids strictly ascending,
 * s <= a, c >= 1, dec.error checked at the end. Unknown keys (top level
 * or per token) are skipped by a walker that refuses truncation. On any
 * refusal
 * `result_out` is left empty (nothing to free).
 * @return 0; -1 malformed.
 */
int nodus_dnac_balance_decode(const uint8_t *raw, size_t raw_len,
                              nodus_dnac_balance_result_t *result_out);

/** Free a `dnac_balance` result's tokens (NULL-safe; the struct is
 *  zeroed). */
void nodus_client_free_balance_result(nodus_dnac_balance_result_t *result);

/* ── dnac_addr_history — the session owner's history from the node's
 * LOCAL address index (decision docs/plans/decisions/2026-10-01-node-
 * address-history-index.md rev 2; tables and per-op rows:
 * nodus/src/witness/nodus_witness_addr_index.h).
 *
 * NODE-LOCAL, NOT CONSENSUS: a node indexes only while it runs with
 * `addr_history_index: true`, and only from the first block it indexed
 * ("from_height"); rows below it are simply not there. Another node may
 * answer differently for heights one of them did not index.
 *
 * C11: the owner MUST be the authenticated session's own fingerprint
 * (the C11 session-owner rule) — nobody reads another owner's history.
 *
 * Request  "a": {"owner": tstr — exactly 128 lowercase hex,
 *                "limit": uint 1..NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT,
 *                "before": uint (optional) — cursor height,
 *                "bi": uint, "bq": uint (optional, only with "before") —
 *                cursor item / sequence; the page holds rows strictly
 *                older than (before, bi, bq); "before" alone = (before,
 *                0, 0) = every row below that height}
 *   A page cut inside one height is continued with the LAST entry's
 *   (h, i, q) as the cursor — a height-only cursor would skip the rest of
 *   that height.
 * Response "r":
 *   "count"       u64   entries in this page
 *   "enabled"     bool  this node is indexing now
 *   "from_height" u64   first height of the node's current gap-free
 *                       indexed run; 0 = it never indexed
 *   "entries"     array newest first — (h, i, q) strictly descending:
 *     "h" u64       global height
 *     "i" u64       engine item position (envelopes in block order, then
 *                   claims) — NOT the dnac_v3_block tx index; 4294967295
 *                   = a block-boundary row (payout, release)
 *     "q" u64       sequence within (h, i)
 *     "kind" tstr   spend_out | spend_in | burn | token_create | claim |
 *                   stake | delegate | undelegate | unstake |
 *                   validator_update | payout | release | fee |
 *                   name (HF-4: a NAME_REGISTER on its owner, amount =
 *                   the price; an older CLI refuses this kind — it fails
 *                   closed on the whole page) |
 *                   evm_deposit (Nodus EVM: an EVM DEPOSIT, on the payer,
 *                   amount = the amount locked into the EVM reserve; an
 *                   older CLI or wallet refuses this kind the same way)
 *     "amount" u64
 *     "token" bstr64  all zero = native
 *     "fee" u64     the envelope fee, on the payer's first row only
 *     "peer" tstr   counterparty fingerprint (128 hex) or "" (none —
 *                   claims, payouts and releases have no sender)
 *     "wire" bstr   the item's 64-byte wire id, or empty (boundary rows)
 *     "ts" u64      block time, unix seconds (the Comet header time)
 * Errors (never a partial answer):
 *   NODUS_ERR_PROTOCOL_ERROR   owner / limit / cursor missing, duplicated
 *                              or malformed
 *   NODUS_ERR_NOT_AUTHENTICATED  no session, or owner != session
 *   NODUS_ERR_NOT_FOUND        the node serves no version-3 chain
 *   NODUS_ERR_INTERNAL_ERROR   a store fault or a malformed stored row
 */

/** Entries one dnac_addr_history page carries at most. */
#define NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT  100u

typedef struct {
    uint64_t h;
    uint32_t i;
    uint32_t q;
    char     kind[24];           /* NUL-terminated                       */
    uint64_t amount;
    uint8_t  token_id[64];
    uint64_t fee;
    char     peer[129];          /* 128 hex + NUL, or "" = none          */
    bool     has_wire;
    uint8_t  wire_id[64];
    uint64_t ts;
} nodus_dnac_addr_history_entry_t;

/** One `dnac_addr_history` page. `entries` is heap (count entries; NULL
 *  when count is 0) — free with nodus_client_free_addr_history_result. */
typedef struct {
    size_t   count;
    bool     enabled;
    uint64_t from_height;
    nodus_dnac_addr_history_entry_t *entries;
} nodus_dnac_addr_history_result_t;

/** A page cursor: rows strictly older than (h, i, q). {H, 0, 0} = every
 *  row below height H. */
typedef struct {
    uint64_t h;
    uint32_t i;
    uint32_t q;
} nodus_dnac_addr_history_cursor_t;

/**
 * Query the session owner's address history (dnac_addr_history, above).
 * @param owner_hex  exactly 128 lowercase hex characters — the client's
 *                   own fingerprint (checked here before anything is sent)
 * @param before     NULL = the newest page
 * @param limit      1..NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT
 * @return 0 and `result_out` filled (free with
 *         nodus_client_free_addr_history_result); the NODUS_ERR_* code the
 *         node answered; NODUS_ERR_PROTOCOL_ERROR for a reply the decoder
 *         refuses; -1 on invalid arguments / encode / transport failure.
 */
int nodus_client_dnac_addr_history(nodus_client_t *client,
                                   const char *owner_hex,
                                   const nodus_dnac_addr_history_cursor_t *before,
                                   uint32_t limit,
                                   nodus_dnac_addr_history_result_t *result_out);

/**
 * Decode a raw `dnac_addr_history` response message — the decoder
 * nodus_client_dnac_addr_history uses, exported for tests. STRICT: all
 * four top-level keys required, "count" equal to the array length, the
 * array bounded by NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT before it is walked,
 * every entry carries all ten keys typed, a known kind, "peer" empty or
 * 128 lowercase hex, "wire" empty or 64 bytes, (h, i, q) strictly
 * descending; a duplicate key anywhere is refused; unknown keys are
 * skipped by a walker that refuses truncation. On any refusal
 * `result_out` is left empty (nothing to free).
 * @return 0; -1 malformed.
 */
int nodus_dnac_addr_history_decode(const uint8_t *raw, size_t raw_len,
                                   nodus_dnac_addr_history_result_t *result_out);

/** Free a `dnac_addr_history` result's entries (NULL-safe; zeroed). */
void nodus_client_free_addr_history_result(nodus_dnac_addr_history_result_t *result);

/* ── dnac_msig_utxo / dnac_msig_addr_history — a multisig VAULT MEMBER
 * reads the vault address's coins and history (design docs/plans/2026-
 * 09-29-general-multisig-design.md §8 + §8.6 rev 2; Kurultay #15,
 * approved by the operator 2026-10-08). The node: nodus_witness_
 * handlers.c "dnac_msig_utxo / dnac_msig_addr_history".
 *
 * dnac_utxo and dnac_addr_history keep C11 (owner == session) unchanged;
 * these two are SEPARATE methods. A member is a session whose
 * authenticated public key is one of the descriptor's N keys.
 *
 * Request  "a" (both methods):
 *   "owner" tstr  exactly 128 lowercase hex — the multisig address
 *   "msig"  bstr  the address's descriptor bytes, 1..NODUS_DNAC_MSIG_
 *                 MAX_DESC_LEN (shared/dnac/msig_wire.h layout:
 *                 tag ‖ M ‖ N ‖ N × pubkey, address = SHA3-512(it))
 *   dnac_msig_utxo:          "max" uint 1..NODUS_DNAC_MAX_UTXO_RESULTS
 *                            (optional; absent = 100)
 *                            "nul" array of 1..NODUS_DNAC_MSIG_MAX_NULS
 *                            bstr, each exactly 64 bytes, STRICTLY
 *                            ascending (optional; the input check of
 *                            nodus-cli `msig sign`, design §2 "ÖDEYİCİ
 *                            BAĞLAMA" 2026-10-13). Given: the answer
 *                            lists exactly those of the named coins that
 *                            are unspent CORE coins whose owner is
 *                            "owner" (any token), in "nul" order — a
 *                            coin that is missing, spent or another
 *                            owner's is simply absent — and "max" must be
 *                            absent (both → PROTOCOL_ERROR). Not given:
 *                            the page below, exactly as before (the web
 *                            wallet's request).
 *   dnac_msig_addr_history:  "limit", "before", "bi", "bq" exactly as
 *                            dnac_addr_history above
 *   Each key at most once; a known key of the wrong type or out of
 *   bounds is refused (a bad "msig" is never read as "absent"); unknown
 *   keys are skipped.
 * Node order: session not authenticated → NOT_AUTHENTICATED (before any
 *   argument is read); arguments → PROTOCOL_ERROR; then ONCE: the
 *   descriptor parses, its address == owner, and the session key is one
 *   of its keys — else NOT_AUTHENTICATED "not authorized for this owner"
 *   (the same text whichever step failed); then the store.
 * Response "r":
 *   dnac_msig_utxo — EXACTLY dnac_utxo's "count", "block_height",
 *     "utxos" (same per-entry keys and encoding, CORE-domain coins,
 *     ordered amount DESC then nullifier ASC), then one more key LAST:
 *     "trunc" bool  true = the owner holds more coins than were returned
 *                   (no paging yet: the page is the first "max");
 *                   always false for a "nul" request
 *     and, ONLY for a "nul" request, one more key LAST:
 *     "nul"   uint  the number of nullifiers the request named — the
 *                   marker a client requires to know the list was honoured
 *                   (a node without it skips the unknown "nul" argument and
 *                   answers the page, which proves nothing about the named
 *                   coins)
 *     "q" = "dnac_msig_utxo".
 *   dnac_msig_addr_history — EXACTLY dnac_addr_history's answer (same
 *     four keys, same entries, same node-local caveats: "enabled",
 *     "from_height"), "q" = "dnac_msig_addr_history".
 * Errors (never a partial or an empty-on-fault answer):
 *   NODUS_ERR_NOT_AUTHENTICATED  no session, or not a member of `owner`
 *   NODUS_ERR_PROTOCOL_ERROR     an argument missing, repeated or bad
 *   NODUS_ERR_NOT_FOUND          (history) no version-3 chain
 *   NODUS_ERR_INTERNAL_ERROR     a store fault (coin list or history)
 *   A node WITHOUT these methods answers NODUS_ERR_PROTOCOL_ERROR with
 *   the text NODUS_DNAC_UNKNOWN_METHOD_MSG; the two client calls below
 *   turn exactly that into NODUS_CLIENT_ERR_METHOD_UNSUPPORTED ("this node
 *   is not updated yet"). */

/** The longest descriptor a dnac_msig_* request carries: 18 + 7 × 2592
 *  (DNA_MSIG_MAX_DESC_LEN, shared/dnac/msig_wire.h; the node
 *  _Static_asserts the equality). */
#define NODUS_DNAC_MSIG_MAX_DESC_LEN  18162u

/** The most nullifiers one dnac_msig_utxo "nul" request names: the chain's
 *  per-leg input ceiling (15 — RTN_SPEND_MAX_IN, restated by the client
 *  builders as NODUS_V2_SPEND_MAX_IN; the node _Static_asserts the
 *  equality). Every funding leg a co-signer is asked to sign has at most
 *  this many inputs, so one request always covers it, and the node's work
 *  per request is bounded by it (one indexed lookup per nullifier). */
#define NODUS_DNAC_MSIG_MAX_NULS  15u

/** The error text a node answers (with NODUS_ERR_PROTOCOL_ERROR) for a
 *  `dnac_*` method it does not have (nodus_witness_handlers.c dispatch).
 *  THE CONTRACT the client relies on to tell "node too old" apart. */
#define NODUS_DNAC_UNKNOWN_METHOD_MSG  "unknown DNAC method"

/** Client-side return code: the node does not serve the method (it
 *  answered PROTOCOL_ERROR NODUS_DNAC_UNKNOWN_METHOD_MSG) — a node not
 *  updated yet, NOT a refusal of this session. Negative, so it never
 *  collides with a NODUS_ERR_* code a node sends. */
#define NODUS_CLIENT_ERR_METHOD_UNSUPPORTED  (-2)

/**
 * A vault member's coin list of the multisig address `owner_hex`
 * (dnac_msig_utxo, above). Caller frees with nodus_client_free_utxo_result.
 * @param owner_hex    exactly 128 lowercase hex (checked before sending)
 * @param msig         the address's descriptor, 1..NODUS_DNAC_MSIG_MAX_
 *                     DESC_LEN bytes
 * @param max_results  page size; <= 0 or > 100 → 100 (as dnac_utxo)
 * @param trunc_out    receives "trunc" (may be NULL)
 * @return 0 and `result_out` filled; the NODUS_ERR_* code the node
 *         answered; NODUS_CLIENT_ERR_METHOD_UNSUPPORTED for a node
 *         without the method; NODUS_ERR_PROTOCOL_ERROR for a reply the
 *         decoder refuses (incl. a missing / non-bool "trunc", and an
 *         entry without a 64-byte "tid" — the node always sends one, and
 *         a missing id would read as a native coin);
 *         NODUS_ERR_TIMEOUT; -1 on invalid arguments / encode / transport
 *         failure.
 */
int nodus_client_dnac_msig_utxo(nodus_client_t *client,
                                const char *owner_hex,
                                const uint8_t *msig, size_t msig_len,
                                int max_results,
                                nodus_dnac_utxo_result_t *result_out,
                                bool *trunc_out);

/**
 * A vault member's view of NAMED coins of the multisig address
 * `owner_hex` (dnac_msig_utxo with "nul", above): the answer lists exactly
 * those of `nuls` that are unspent CORE coins owned by `owner_hex`.
 * The reply is refused (NODUS_ERR_PROTOCOL_ERROR, `result_out` empty)
 * unless it carries the "nul" marker equal to `n_nuls` (a node that does
 * not know the argument answers the page instead — not a verification),
 * "trunc" is false, it has at most `n_nuls` entries, every entry's
 * nullifier is one of `nuls` and no nullifier repeats.
 * @param nuls    n_nuls nullifiers, STRICTLY ascending (checked before
 *                sending)
 * @param n_nuls  1..NODUS_DNAC_MSIG_MAX_NULS
 * @return as nodus_client_dnac_msig_utxo; free the result with
 *         nodus_client_free_utxo_result.
 */
int nodus_client_dnac_msig_utxo_nuls(nodus_client_t *client,
                                     const char *owner_hex,
                                     const uint8_t *msig, size_t msig_len,
                                     const uint8_t (*nuls)[64],
                                     uint32_t n_nuls,
                                     nodus_dnac_utxo_result_t *result_out);

/**
 * A vault member's history of the multisig address `owner_hex`
 * (dnac_msig_addr_history, above). The reply is decoded by
 * nodus_dnac_addr_history_decode (it reads only "r", never "q").
 * @param before  NULL = the newest page
 * @param limit   1..NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT
 * @return as nodus_client_dnac_msig_utxo; free the result with
 *         nodus_client_free_addr_history_result.
 */
int nodus_client_dnac_msig_addr_history(nodus_client_t *client,
                                        const char *owner_hex,
                                        const uint8_t *msig, size_t msig_len,
                                        const nodus_dnac_addr_history_cursor_t *before,
                                        uint32_t limit,
                                        nodus_dnac_addr_history_result_t *result_out);

/* ── Nodus EVM §18 — the EVM read RPC (design docs/plans/2026-10-04-nodus-evm-
 *    chain-integration-design.md rev 3 §18; the node side and its exact
 *    key list: nodus_witness_handlers.c "Nodus EVM §18") ─────────────────────
 *
 * Every answer is ONE node's COMMITTED tip state, read-only. "h" is the
 * committed tip, except a receipt's and a log's, which carry their
 * INCLUSION height. A node whose EVM domain is not active answers
 * NODUS_ERR_NOT_FOUND; a node too old to know the method answers
 * NODUS_ERR_PROTOCOL_ERROR ("unknown DNAC method") — fail closed.
 *
 * Every typed reader below is STRICT (the v3d discipline of this file):
 * every documented key required and typed, a duplicate key refused, an
 * unknown key skipped by a walker that refuses truncation. */

#define NODUS_EVM_LOGS_MAX_LIMIT  1000u    /* evm_logs lim                */
#define NODUS_EVM_LOGS_MAX_SPAN   10000u   /* th - fh < this              */

/**
 * The GENERIC §18 call: `method` (any evm_* name) with `n_args` key/value
 * pairs already CBOR-encoded in `args` (`args_len` bytes: the map's
 * ENTRIES, without the map header). On 0, *reply_out is a heap copy of
 * the reply's "r" value — one complete CBOR map (free()); the caller
 * decodes it. The web wallet's evmQuery uses this.
 * @return 0; the NODUS_ERR_* the node answered; NODUS_ERR_TIMEOUT;
 *         NODUS_ERR_PROTOCOL_ERROR for a reply without an "r" map; -1 on
 *         invalid arguments / encode / transport failure.
 */
int nodus_client_dnac_query_raw(nodus_client_t *client, const char *method,
                                const uint8_t *args, size_t args_len,
                                size_t n_args, uint8_t **reply_out,
                                size_t *reply_len_out);

typedef struct {
    uint64_t nonce;
    uint8_t  balance_wei[32];          /* big-endian                      */
    uint8_t  code_hash[32];            /* keccak256(code)                 */
    uint32_t code_size;
    uint64_t height;                   /* the committed tip               */
} nodus_evm_account_t;

/** evm_account. Same returns as nodus_client_dnac_query_raw. */
int nodus_client_evm_account(nodus_client_t *client, const uint8_t addr[32],
                             nodus_evm_account_t *out);

/** evm_code: *code_out heap (NULL when the account has no code; free()). */
int nodus_client_evm_code(nodus_client_t *client, const uint8_t addr[32],
                          uint8_t **code_out, size_t *code_len_out,
                          uint64_t *height_out);

/** evm_storage: the 32-byte slot value (zero = no row). */
int nodus_client_evm_storage(nodus_client_t *client, const uint8_t addr[32],
                             const uint8_t key[32], uint8_t value_out[32],
                             uint64_t *height_out);

typedef struct {
    const uint8_t *from;               /* 32: the EVM sender              */
    const uint8_t *to;                 /* 32, NULL = CREATE               */
    const uint8_t *value;              /* 32 BE wei, NULL = none          */
    const uint8_t *data;               /* call data / initcode            */
    size_t         data_len;
    uint64_t       gas;                /* 0 = the node's per-tx gas cap   */
} nodus_evm_call_req_t;

typedef struct {
    int      success;                  /* "s"                             */
    uint8_t *output;                   /* "o", heap (return / revert data)*/
    size_t   output_len;
    uint64_t gas_used;                 /* "gu"                            */
    uint64_t height;                   /* "h"                             */
    /* evm_estimate only */
    uint64_t gas_limit;                /* "ge" suggested gas_limit        */
    uint64_t units;                    /* "ue" suggested res_max_total_
                                        * units (the REFERENCE shape —
                                        * client/nodus_v2_evm.h "UNITS")  */
    uint64_t fee;                      /* "fe" suggested fee, raw units   */
} nodus_evm_call_res_t;

/** evm_call / evm_estimate. Free with nodus_evm_call_res_free. A call the
 *  node refuses before execution comes back as NODUS_ERR_PROTOCOL_ERROR
 *  (never as success = 0). */
int nodus_client_evm_call(nodus_client_t *client,
                          const nodus_evm_call_req_t *req,
                          nodus_evm_call_res_t *out);
int nodus_client_evm_estimate(nodus_client_t *client,
                              const nodus_evm_call_req_t *req,
                              nodus_evm_call_res_t *out);
void nodus_evm_call_res_free(nodus_evm_call_res_t *r);

typedef struct {
    uint8_t  addr[32];
    uint8_t  n_topics;
    uint8_t  topics[4][32];
    uint8_t *data;                     /* heap                            */
    size_t   data_len;
    /* evm_logs only (zero inside a receipt) */
    uint64_t height;                   /* "h" inclusion height            */
    uint32_t item;                     /* "x" item index in that block    */
    uint32_t log_index;                /* "li"                            */
    uint8_t  intent_id[64];            /* "i"                             */
} nodus_evm_log_t;

typedef struct {
    bool     found;                    /* false: the node answered {}     */
    uint64_t height;                   /* "h" inclusion height            */
    uint32_t item;                     /* "x"                             */
    uint8_t  status;                   /* 1 success / 0 applied failure   */
    uint8_t  op;                       /* EVM op 1..5                     */
    uint64_t gas_used;                 /* "gu" EVM gas                    */
    bool     has_created;
    uint8_t  created[32];              /* "cr" (successful CREATE)        */
    uint8_t *output;                   /* heap                            */
    size_t   output_len;
    nodus_evm_log_t *logs;             /* heap                            */
    size_t   n_logs;
    uint8_t  wei_destroyed[32];
    uint8_t (*tickets)[64];            /* heap                            */
    size_t   n_tickets;
    uint8_t  digest[64];               /* "dg" = SHA3-512(§7 bytes) — the
                                        * decoder re-encodes the §7 bytes
                                        * from the fields and REFUSES a
                                        * reply whose digest differs      */
} nodus_evm_receipt_t;

/** evm_receipt. Free with nodus_evm_receipt_free. */
int nodus_client_evm_receipt(nodus_client_t *client,
                             const uint8_t intent_id[64],
                             nodus_evm_receipt_t *out);
void nodus_evm_receipt_free(nodus_evm_receipt_t *r);

/* An evm_logs CURSOR "c": the first (height, item index, log index) the
 * node has not examined yet. x / li may be one past the u32 range. */
typedef struct {
    uint64_t height;
    uint64_t item;
    uint64_t log_index;
} nodus_evm_logs_cursor_t;

#define NODUS_EVM_LOGS_CURSOR_POS_MAX  ((uint64_t)UINT32_MAX + 1u)

typedef struct {
    uint64_t       from_height, to_height;   /* to - from < 10 000      */
    const uint8_t *addr;                     /* 32 or NULL              */
    const uint8_t *topic[4];                 /* 32 each or NULL         */
    uint32_t       limit;                    /* 1..1000                 */
    /* NULL = start at (from_height, 0, 0); else resume where a previous
     * reply's cursor points (from_height <= cursor->height <= to_height;
     * send the SAME from/to/addr/topics as that request) */
    const nodus_evm_logs_cursor_t *cursor;
} nodus_evm_logs_req_t;

typedef struct {
    nodus_evm_log_t *logs;             /* heap                            */
    size_t           n;
    /* more = the node stopped before to_height (the limit, its examined-
     * row bound, its reply byte bound or its per-block work budget);
     * then — and only then — `cursor` is where to resume. A page with
     * more = true may hold no log at all: ask again from the cursor. */
    bool             more;
    bool             has_cursor;
    nodus_evm_logs_cursor_t cursor;
} nodus_evm_logs_res_t;

/** evm_logs. Free with nodus_evm_logs_free. STRICT beyond the reader
 *  discipline above: "c" present exactly when more is true; every log
 *  inside [from_height, to_height], at or after the request's start
 *  position, strictly increasing in (h, x, li), and before the returned
 *  cursor; the cursor itself inside the range and strictly after the
 *  request's start when the page holds a log, never before it — a reply
 *  breaking any of these is refused (NODUS_ERR_PROTOCOL_ERROR), so a
 *  paging loop cannot be walked backwards or skipped forward past a
 *  returned log. */
int nodus_client_evm_logs(nodus_client_t *client,
                          const nodus_evm_logs_req_t *req,
                          nodus_evm_logs_res_t *out);
void nodus_evm_logs_free(nodus_evm_logs_res_t *r);

typedef struct {
    bool     pending;                  /* "p"                             */
    uint64_t amount_raw;               /* "amt"                           */
    uint8_t  dest_fp[64];              /* "dst"                           */
} nodus_evm_ticket_t;

/** evm_ticket. */
int nodus_client_evm_ticket(nodus_client_t *client, const uint8_t id[64],
                            nodus_evm_ticket_t *out);

/**
 * Page through the full validator table on the witness (all statuses).
 *
 * Caller MUST free result_out with nodus_client_free_validator_list_result().
 *
 * Each entry's delegator_count (filled delegation slots of
 * NODUS_MAX_DELEGATORS_PER_VALIDATOR) is valid only when
 * has_delegator_count is 1; a node that predates the reply's "dlg" key
 * leaves it 0 = unknown (not "0 delegators"). A malformed or repeated
 * "dlg" refuses the whole reply (NODUS_ERR_PROTOCOL_ERROR).
 * HF-6 generation 4 (sub-slice 3e): each entry also carries OPTIONAL
 * "vid" / "owner" bstr(64) (validator_id / owner_fp); "pk" is the
 * consensus key. Since slice 7a this decoder fills the entry's
 * validator_id / owner_fp with has_v2 = 1 when both are present; an older
 * node (neither) leaves has_v2 0 and both zero. A non-64-byte value, a
 * repeated key or one key without the other refuses the whole reply
 * (NODUS_ERR_PROTOCOL_ERROR).
 *
 * @param filter_status  -1 = all statuses, 0..3 = filter by status
 * @param offset         Page offset (0-based)
 * @param limit          Max entries to return (server-side cap applies)
 * @param result_out     Query result (entries heap-allocated)
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_validator_list(nodus_client_t *client,
                                       int filter_status,
                                       int offset,
                                       int limit,
                                       nodus_dnac_validator_list_result_t *result_out);

/** Free heap allocation inside a validator-list result. */
void nodus_client_free_validator_list_result(nodus_dnac_validator_list_result_t *result);

/**
 * Query the caller's own active delegations.
 *
 * Sends the raw 2592-byte Dilithium5 pubkey on the wire. The witness
 * C11-authenticates by computing SHA3-512(pubkey) and comparing against
 * the authenticated session fingerprint — mismatch yields
 * NODUS_ERR_NOT_AUTHENTICATED. Response entries carry validator_fp
 * rendered server-side so the client never sees raw validator pubkeys.
 * HF-6 generation 4 (sub-slice 3e): validator_fp then holds the
 * validator_id (the identifier a generation-4 DELEGATE names), and the
 * reply carries OPTIONAL "vid" / "owner" (hex) keys this decoder skips.
 *
 * Caller must free result_out with nodus_client_free_delegations_result().
 *
 * @param client         Active nodus client (authenticated session)
 * @param delegator_pubkey  Raw pubkey — must match the session identity
 * @param pubkey_len     Must equal NODUS_PK_BYTES (2592); otherwise
 *                        returns -1
 * @param max_results    Upper bound (capped at NODUS_DNAC_MAX_DELEGATIONS_RESULTS)
 * @param result_out     Query result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_delegations(nodus_client_t *client,
                                    const uint8_t *delegator_pubkey,
                                    size_t pubkey_len,
                                    int max_results,
                                    nodus_dnac_delegations_result_t *result_out);

/**
 * Free heap allocation inside a delegations result.
 */
void nodus_client_free_delegations_result(nodus_dnac_delegations_result_t *result);

/* ── Media Operations ──────────────────────────────────────────────── */

/**
 * Upload a media chunk to the DHT.
 * For chunk_index=0, provides metadata (chunk_count, total_size, media_type, ttl, encrypted).
 * Server responds with put_ok; complete_out is set true when all chunks received.
 *
 * @return 0 on success, error code on failure
 */
int nodus_client_media_put(nodus_client_t *client,
                           const uint8_t content_hash[64],
                           uint32_t chunk_index, uint32_t chunk_count,
                           uint64_t total_size, uint8_t media_type,
                           bool encrypted, uint32_t ttl,
                           const uint8_t *data, size_t data_len,
                           const nodus_sig_t *sig,
                           bool *complete_out,
                           nodus_media_progress_cb progress_cb,
                           void *progress_user_data);

/**
 * Get media metadata (chunk count, size, type, completion status).
 * Caller provides pre-allocated meta_out.
 *
 * @return 0 on success, NODUS_ERR_NOT_FOUND if missing
 */
int nodus_client_media_get_meta(nodus_client_t *client,
                                const uint8_t content_hash[64],
                                nodus_media_meta_t *meta_out);

/**
 * Download a single media chunk by index.
 * Caller must free(*data_out).
 *
 * @return 0 on success, NODUS_ERR_NOT_FOUND if missing
 */
int nodus_client_media_get_chunk(nodus_client_t *client,
                                 const uint8_t content_hash[64],
                                 uint32_t chunk_index,
                                 uint8_t **data_out, size_t *data_len_out);

/**
 * Check if media exists and is complete on the DHT.
 *
 * @return 0 on success (exists_out set), error code on failure
 */
int nodus_client_media_exists(nodus_client_t *client,
                              const uint8_t content_hash[64],
                              bool *exists_out);

/* ── Utility ────────────────────────────────────────────────────── */

/**
 * Get the client's fingerprint string.
 */
const char *nodus_client_fingerprint(const nodus_client_t *client);

/**
 * Free a posts array returned by nodus_client_ch_get_posts().
 */
void nodus_client_free_posts(nodus_channel_post_t *posts, size_t count);

/* ── Circuit operations (Faz 1) ─────────────────────────────────── */

/**
 * Open outbound circuit to a peer by fingerprint. Blocks until ack or error.
 * Returns 0 on success (out handle populated), or a NODUS_ERR_* code.
 */
int nodus_circuit_open(nodus_client_t *client, const nodus_key_t *peer_fp,
                        nodus_circuit_data_cb on_data,
                        nodus_circuit_close_cb on_close,
                        void *user,
                        nodus_circuit_handle_t **out);

/**
 * Open outbound circuit with E2E encryption (onion layer).
 * peer_kyber_pk: target's Kyber1024 pubkey (1568 bytes, from DHT keyserver).
 * Circuit payload is encrypted with per-circuit AES key — relay nodes blind.
 */
int nodus_circuit_open_e2e(nodus_client_t *client, const nodus_key_t *peer_fp,
                            const uint8_t *peer_kyber_pk,
                            nodus_circuit_data_cb on_data,
                            nodus_circuit_close_cb on_close,
                            void *user,
                            nodus_circuit_handle_t **out);

/**
 * Open outbound circuit with E2E encryption (onion layer), algorithm-aware
 * (Faz 1 KEM migration, docs/plans/decisions/2026-09-23-kem-mlkem-
 * migration.md). peer_pk: target's KEM pubkey (1568 bytes, from DHT
 * keyserver) — Kyber round-3 when peer_alg == 0, ML-KEM-1024 when
 * peer_alg == 1; the caller decides based on what the target published
 * there. nodus_circuit_open_e2e() above is unchanged and always uses
 * peer_alg == 0 (its existing callers are untouched by this dispatch).
 *
 * peer_alg=1 must not be used until every relay on the path runs a build
 * that forwards `alg` — an old relay drops the key and the far end
 * decapsulates with the wrong algorithm (silent dead circuit). The
 * messenger switches circuits to alg=1 in Faz 2, not Faz 1.
 */
int nodus_circuit_open_e2e_alg(nodus_client_t *client, const nodus_key_t *peer_fp,
                                const uint8_t *peer_pk, uint8_t peer_alg,
                                nodus_circuit_data_cb on_data,
                                nodus_circuit_close_cb on_close,
                                void *user,
                                nodus_circuit_handle_t **out);

/**
 * Open a circuit keyed by an EXTERNALLY-agreed 32-byte secret (K_call from call
 * signaling, PQ VoIP Faz A). No in-circuit Kyber handshake: a plain circ_open is
 * sent and every circ_data payload is AES-256-GCM under a key derived from
 * k_call + (caller_fp, callee_fp). The peer answers with nodus_circuit_attach_keyed
 * using the same k_call. Use this for media once K_call is agreed out-of-band.
 */
int nodus_circuit_open_keyed(nodus_client_t *client, const nodus_key_t *peer_fp,
                             const uint8_t k_call[32],
                             nodus_circuit_data_cb on_data,
                             nodus_circuit_close_cb on_close,
                             void *user,
                             nodus_circuit_handle_t **out);

/** Register global callback for inbound circuits from peers. */
void nodus_circuit_set_inbound_cb(nodus_client_t *client,
                                    nodus_circuit_inbound_cb cb, void *user);

/** Attach data/close callbacks to an inbound circuit handle. */
int nodus_circuit_attach(nodus_circuit_handle_t *h,
                          nodus_circuit_data_cb on_data,
                          nodus_circuit_close_cb on_close,
                          void *user);

/**
 * Attach to an inbound circuit and key it with an externally-agreed K_call
 * (call-signaling secret, Faz A) — the callee counterpart of
 * nodus_circuit_open_keyed. caller_fp is the originator from the inbound
 * callback. Both ends derive the identical channel key from k_call +
 * (caller_fp, callee_fp), so subsequent circ_data is E2E AES-256-GCM.
 */
int nodus_circuit_attach_keyed(nodus_circuit_handle_t *h,
                               const nodus_key_t *caller_fp,
                               const uint8_t k_call[32],
                               nodus_circuit_data_cb on_data,
                               nodus_circuit_close_cb on_close,
                               void *user);

/** Send data through circuit. Returns 0 on success. */
int nodus_circuit_send(nodus_circuit_handle_t *h,
                        const uint8_t *data, size_t len);

/** Close circuit. Notifies peer and releases handle. */
int nodus_circuit_close(nodus_circuit_handle_t *h);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_H */
