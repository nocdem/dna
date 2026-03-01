/**
 * Nodus v5 — Client SDK
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
    uint32_t               next_txn;

    /* Current server index for failover */
    int                    server_idx;

    /* Reconnect backoff state */
    int                    backoff_ms;
    uint64_t               reconnect_at; /* Unix ms when to reconnect */

    /* Active subscriptions (for re-subscribe on reconnect) */
    nodus_key_t            listen_keys[NODUS_CLIENT_MAX_LISTENS];
    int                    listen_count;
    uint8_t                ch_subs[NODUS_CLIENT_MAX_CH_SUBS][NODUS_UUID_BYTES];
    int                    ch_sub_count;

    /* Synchronous response handling */
    void                  *pending_response;  /* nodus_tier2_msg_t* */
    bool                   response_ready;

    /* Raw response payload (for DNAC-specific CBOR decoding) */
    uint8_t               *raw_response;
    size_t                 raw_response_len;
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
 * Returns endpoints of all alive PBFT peers + self.
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
 * Post a message to a channel.
 * The post must be signed by the caller.
 *
 * @param seq_out  If non-NULL, receives the assigned sequence ID
 * @return 0 on success
 */
int nodus_client_ch_post(nodus_client_t *client,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const uint8_t post_uuid[NODUS_UUID_BYTES],
                          const uint8_t *body, size_t body_len,
                          uint64_t timestamp, const nodus_sig_t *sig,
                          uint32_t *seq_out);

/**
 * Get posts from a channel.
 * Caller must free each post's body and the array.
 *
 * @param since_seq  Get posts after this seq_id (0 = from start)
 * @param max_count  Maximum posts to return (0 = server default)
 * @return 0 on success
 */
int nodus_client_ch_get_posts(nodus_client_t *client,
                               const uint8_t uuid[NODUS_UUID_BYTES],
                               uint32_t since_seq, int max_count,
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
 * Free UTXO entries from nodus_client_dnac_utxo().
 */
void nodus_client_free_utxo_result(nodus_dnac_utxo_result_t *result);

/**
 * Free range entries from nodus_client_dnac_ledger_range().
 */
void nodus_client_free_range_result(nodus_dnac_range_result_t *result);

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
