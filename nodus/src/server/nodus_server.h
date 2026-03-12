/**
 * Nodus — Server Core
 *
 * Dual-transport event loop (UDP Kademlia + TCP data/clients).
 * Session management, authentication, message dispatch.
 *
 * @file nodus_server.h
 */

#ifndef NODUS_SERVER_H
#define NODUS_SERVER_H

#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_udp.h"
#include "core/nodus_routing.h"
#include "core/nodus_storage.h"
#include "channel/nodus_hashring.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_replication.h"
#include "consensus/nodus_pbft.h"
#include "crypto/nodus_identity.h"
#include "witness/nodus_witness.h"
#include "server/nodus_presence.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MAX_SESSIONS     NODUS_TCP_MAX_CONNS
#define NODUS_MAX_LISTEN_KEYS  128    /* Per session */
#define NODUS_MAX_CH_SUBS      32     /* Per session channel subscriptions */
#define NODUS_MAX_SEED_NODES   16

/* ── Configuration ───────────────────────────────────────────────── */

typedef struct {
    char        bind_ip[64];
    uint16_t    udp_port;
    uint16_t    tcp_port;
    char        identity_path[256];
    char        data_path[256];
    char        seed_nodes[NODUS_MAX_SEED_NODES][64];
    uint16_t    seed_ports[NODUS_MAX_SEED_NODES];
    int         seed_count;

    /* Witness module (optional DNAC BFT consensus) */
    nodus_witness_config_t  witness;
} nodus_server_config_t;

/* ── Client session ──────────────────────────────────────────────── */

typedef struct {
    nodus_tcp_conn_t   *conn;
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    uint8_t             token[NODUS_SESSION_TOKEN_LEN];
    bool                authenticated;
    bool                is_nodus;

    /* Pending auth challenge */
    uint8_t             nonce[NODUS_NONCE_LEN];
    bool                nonce_pending;

    /* LISTEN subscriptions (DHT keys) */
    nodus_key_t         listen_keys[NODUS_MAX_LISTEN_KEYS];
    int                 listen_count;

    /* Channel subscriptions */
    uint8_t             ch_subs[NODUS_MAX_CH_SUBS][NODUS_UUID_BYTES];
    int                 ch_sub_count;

    /* Rate limiting */
    uint64_t            rate_window_start;
    int                 puts_in_window;
} nodus_session_t;

/* ── FIND_VALUE async state machine ──────────────────────────────── */

/** Query states for outgoing FIND_VALUE TCP connections */
typedef enum {
    FV_QUERY_CONNECTING,    /**< Non-blocking connect in progress (EPOLLOUT) */
    FV_QUERY_SENDING,       /**< Connected, sending request (EPOLLOUT) */
    FV_QUERY_RECEIVING,     /**< Request sent, waiting for response (EPOLLIN) */
    FV_QUERY_DONE,          /**< Response received or failed */
} dht_fv_query_state_t;

/** One outgoing TCP query to a peer */
typedef struct {
    int                     fd;           /**< Socket fd (-1 if unused) */
    dht_fv_query_state_t    state;
    nodus_key_t             node_id;      /**< Peer being queried */
    char                    ip[64];
    uint16_t                tcp_port;
    uint64_t                started_at;   /**< For per-query timeout (ms) */
    uint8_t                *send_buf;     /**< Encoded fv request frame */
    size_t                  send_len;
    size_t                  send_pos;     /**< Bytes sent so far */
    uint8_t                *recv_buf;     /**< Dynamic: malloc on start, free on done */
    size_t                  recv_cap;
    size_t                  recv_len;
} dht_fv_query_t;

/** One FIND_VALUE lookup (may issue multiple queries across rounds) */
typedef struct {
    bool                    active;
    nodus_key_t             key_hash;          /**< Key being looked up */
    uint32_t                txn_id;            /**< Client's transaction ID */
    int                     session_slot;      /**< Client session index */
    uint64_t                started_at;        /**< For overall timeout (ms) */

    /* Kademlia iterative state */
    nodus_peer_t            candidates[NODUS_K * 4];
    int                     candidate_count;
    nodus_key_t             visited[NODUS_K * 4];
    int                     visited_count;
    int                     round;

    /* Active outgoing queries for this lookup */
    dht_fv_query_t          queries[NODUS_ALPHA];
    int                     queries_pending;

    /* Result */
    bool                    found;
    uint8_t                *result_buf;
    size_t                  result_len;
} dht_fv_lookup_t;

/** All in-flight FIND_VALUE lookups */
typedef struct {
    dht_fv_lookup_t         lookups[NODUS_FV_MAX_INFLIGHT];
} dht_fv_state_t;

/** FV fd→lookup index mapping (indexed by fd number) */
typedef struct {
    int lookup_idx;   /**< Index into lookups[] (-1 = not an FV fd) */
    int query_idx;    /**< Index into lookup->queries[] */
} dht_fv_fd_entry_t;

/** One non-blocking republish TCP connection (fire-and-forget) */
typedef struct {
    int      fd;
    uint8_t *frame;       /**< malloc'd copy of frame data */
    size_t   frame_len;
    size_t   send_pos;    /**< Bytes sent so far */
    uint64_t started_at;  /**< For timeout detection (ms) */
    bool     active;
    bool     connected;   /**< connect() completed */
} dht_republish_conn_t;

/** Pending eviction entry for ping-before-evict (Kademlia spec) */
#define NODUS_MAX_PENDING_EVICTIONS 32
#define NODUS_EVICT_PING_TIMEOUT    10   /* seconds */

typedef struct {
    bool          active;
    nodus_peer_t  new_peer;       /**< Peer wanting to join */
    nodus_peer_t  lru_peer;       /**< Existing LRU peer being pinged */
    uint64_t      ping_sent_at;   /**< Unix timestamp of ping */
} nodus_pending_eviction_t;

/** Republish state (persistent across ticks) */
typedef struct {
    nodus_key_t last_key;       /**< Bookmark: last key_hash processed */
    bool        active;         /**< Republish cycle in progress */
    bool        first_batch;    /**< First batch of cycle (no bookmark yet) */
    uint64_t    cycle_start;    /**< When current cycle began */
    int         pending_fds;    /**< Outgoing connections in flight */
    dht_republish_conn_t conns[NODUS_REPUBLISH_MAX_FDS];
} dht_republish_state_t;

/* ── Server ──────────────────────────────────────────────────────── */

typedef struct nodus_server {
    nodus_server_config_t   config;
    nodus_identity_t        identity;

    /* Shared event loop */
    int                     epoll_fd;

    /* Transports */
    nodus_tcp_t             tcp;
    nodus_udp_t             udp;

    /* Storage */
    nodus_storage_t         storage;
    nodus_channel_store_t   ch_store;
    nodus_routing_t         routing;
    nodus_hashring_t        ring;

    /* Replication + consensus */
    nodus_replication_t     replication;
    nodus_pbft_t            pbft;

    /* Witness module (NULL when disabled) */
    nodus_witness_t        *witness;

    /* Presence tracking (connected clients, cluster-wide) */
    nodus_presence_table_t  presence;

    /* Sessions (indexed by conn->slot) */
    nodus_session_t         sessions[NODUS_MAX_SESSIONS];

    /* FIND_VALUE async state machine */
    dht_fv_state_t          fv_state;
    dht_fv_fd_entry_t       fv_fd_table[NODUS_FV_FD_TABLE_SIZE];
    int                     fv_epoll_fd;

    /* Periodic republish */
    dht_republish_state_t   republish;
    int                     rp_epoll_fd;

    /* Ping-before-evict pending entries */
    nodus_pending_eviction_t pending_evictions[NODUS_MAX_PENDING_EVICTIONS];

    bool                    running;
} nodus_server_t;

/**
 * Initialize server with config. Loads identity, opens storage, binds ports.
 */
int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config);

/**
 * Run the server event loop (blocks until stopped).
 */
int nodus_server_run(nodus_server_t *srv);

/**
 * Stop the server (sets running=false, returns from run).
 */
void nodus_server_stop(nodus_server_t *srv);

/**
 * Clean up all resources.
 */
void nodus_server_close(nodus_server_t *srv);

/* ── Auth helpers (used by server) ───────────────────────────────── */

/**
 * Handle HELLO message from a client/nodus.
 * Verifies fingerprint, generates challenge nonce.
 */
int nodus_auth_handle_hello(nodus_server_t *srv, nodus_session_t *sess,
                             const nodus_pubkey_t *pk, const nodus_key_t *fp,
                             uint32_t txn_id);

/**
 * Handle AUTH message (signed nonce).
 * Verifies signature, creates session token.
 */
int nodus_auth_handle_auth(nodus_server_t *srv, nodus_session_t *sess,
                            const nodus_sig_t *sig, uint32_t txn_id);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SERVER_H */
