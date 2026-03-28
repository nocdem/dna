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
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_CLIENT_MAX_SERVERS   8
#define NODUS_CLIENT_MAX_LISTENS  128
#define NODUS_CLIENT_MAX_CH_SUBS   32

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

/* ── Client ─────────────────────────────────────────────────────── */

/* Forward declarations for internal types */
struct nodus_tcp;
struct nodus_tcp_conn;

typedef struct {
    nodus_client_config_t  config;
    nodus_identity_t       identity;
    nodus_client_state_t   state;

    /* TCP transport (opaque — managed internally) */
    void                  *tcp;        /* nodus_tcp_t* */
    void                  *conn;       /* nodus_tcp_conn_t* */

    /* Session */
    uint8_t                token[NODUS_SESSION_TOKEN_LEN];
    _Atomic uint32_t       next_txn;

    /* Current server index for failover */
    int                    server_idx;

    /* Reconnect backoff state */
    int                    backoff_ms;
    uint64_t               reconnect_at; /* Unix ms when to reconnect */

    /* Keepalive ping (prevents server idle sweep) */
    uint64_t               last_ping_ms; /* Unix ms of last ping sent */

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

    /* Internal read thread — continuously reads TCP for push notifications */
    pthread_t              read_thread;
    _Atomic bool           read_thread_running;
    _Atomic bool           read_thread_stop;

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
 * Check if client is connected and authenticated.
 */
bool nodus_client_is_ready(const nodus_client_t *client);

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

    /* Reconnect state */
    uint64_t                reconnect_at;     /* Timestamp (ms) for next reconnect attempt */
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
 * Check if a nullifier has been spent.
 *
 * @param nullifier  64-byte nullifier to check
 * @param result_out  Nullifier check result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_nullifier(nodus_client_t *client,
                                  const uint8_t *nullifier,
                                  nodus_dnac_nullifier_result_t *result_out);

/**
 * Query ledger entry by transaction hash.
 *
 * @param tx_hash     64-byte transaction hash
 * @param result_out  Ledger entry result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_ledger(nodus_client_t *client,
                               const uint8_t *tx_hash,
                               nodus_dnac_ledger_result_t *result_out);

/**
 * Query supply state.
 *
 * @param result_out  Supply state result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_supply(nodus_client_t *client,
                               nodus_dnac_supply_result_t *result_out);

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
 * Query ledger entries in a sequence range.
 * Caller must free result_out->entries when done.
 *
 * @param from_seq    Start sequence (inclusive)
 * @param to_seq      End sequence (inclusive)
 * @param result_out  Ledger range result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_ledger_range(nodus_client_t *client,
                                     uint64_t from_seq, uint64_t to_seq,
                                     nodus_dnac_range_result_t *result_out);

/**
 * Query witness roster.
 *
 * @param result_out  Roster result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_roster(nodus_client_t *client,
                               nodus_dnac_roster_result_t *result_out);

/**
 * Query full transaction data by hash.
 * Caller must free result_out->tx_data when done.
 *
 * @param tx_hash     64-byte transaction hash
 * @param result_out  Transaction data result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_tx(nodus_client_t *client,
                           const uint8_t *tx_hash,
                           nodus_dnac_tx_result_t *result_out);

/**
 * Query block by height.
 *
 * @param height      Block height
 * @param result_out  Block result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_block(nodus_client_t *client,
                              uint64_t height,
                              nodus_dnac_block_result_t *result_out);

/**
 * Query blocks in a height range.
 * Caller must free result_out->blocks when done.
 *
 * @param from_height Start height (inclusive)
 * @param to_height   End height (inclusive)
 * @param result_out  Block range result
 * @return 0 on success, error code on failure
 */
int nodus_client_dnac_block_range(nodus_client_t *client,
                                    uint64_t from_height, uint64_t to_height,
                                    nodus_dnac_block_range_result_t *result_out);

/**
 * Free UTXO entries from nodus_client_dnac_utxo().
 */
void nodus_client_free_utxo_result(nodus_dnac_utxo_result_t *result);

/**
 * Free range entries from nodus_client_dnac_ledger_range().
 */
void nodus_client_free_range_result(nodus_dnac_range_result_t *result);

/**
 * Free TX data from nodus_client_dnac_tx().
 */
void nodus_client_free_tx_result(nodus_dnac_tx_result_t *result);

/**
 * Free block range from nodus_client_dnac_block_range().
 */
void nodus_client_free_block_range_result(nodus_dnac_block_range_result_t *result);

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
                           bool *complete_out);

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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_H */
