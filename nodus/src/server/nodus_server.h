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
#include "core/nodus_media_storage.h"
#include "channel/nodus_hashring.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_channel_server.h"
#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_ring.h"
#include "consensus/nodus_cluster.h"
#include "crypto/nodus_identity.h"
#include "witness/nodus_witness.h"
#include "server/nodus_presence.h"
#include "circuit/nodus_circuit.h"
#include "circuit/nodus_inter_circuit.h"
#include "crypto/nodus_channel_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MAX_SESSIONS     NODUS_TCP_MAX_CONNS
#define NODUS_MAX_LISTEN_KEYS  128    /* Per session */
#define NODUS_MAX_SEED_NODES   16

/* ── Configuration ───────────────────────────────────────────────── */

typedef struct {
    char        bind_ip[64];
    char        external_ip[64];    /* Public IP to advertise to clients (empty = use bind_ip) */
    uint16_t    udp_port;
    uint16_t    tcp_port;
    uint16_t    peer_port;          /* Inter-node TCP port (default: 4002) */
    uint16_t    ch_port;            /* Channel client TCP port (default: 4003) */
    uint16_t    witness_port;       /* Witness BFT TCP port (default: 4004) */
    char        identity_path[256];
    char        data_path[256];
    char        seed_nodes[NODUS_MAX_SEED_NODES][64];
    uint16_t    seed_ports[NODUS_MAX_SEED_NODES];
    int         seed_count;

    /* Witness module (optional DNAC BFT consensus) */
    nodus_witness_config_t  witness;

    /* C-01/C-02: Require Dilithium5 auth on inter-node (4002) and witness (4004) ports.
     * Default false for backward compat. Set true once all nodes are updated. */
    bool        require_peer_auth;
} nodus_server_config_t;

/* ── Inter-node session (lightweight — rate limiting only, no auth) ── */

typedef struct {
    nodus_tcp_conn_t   *conn;

    /* C-01/C-02: Dilithium5 authentication (same as client sessions) */
    nodus_key_t         client_fp;
    nodus_pubkey_t      client_pk;
    uint8_t             nonce[NODUS_NONCE_LEN];
    bool                nonce_pending;
    bool                authenticated;

    /* Per-session rate limiting */
    uint64_t            sv_window_start;
    int                 sv_count;
    uint64_t            fv_window_start;
    int                 fv_count;
    uint64_t            ps_window_start;
    int                 ps_count;
    uint64_t            cr_window_start;
    int                 cr_count;
    uint64_t            w_window_start;
    int                 w_count;

    /* Peer protocol version (from hello) */
    uint32_t            proto_version;

    /* Channel encryption (Kyber handshake for inter-node) */
    nodus_channel_crypto_t  channel_crypto;
    uint8_t             pending_ss[32];     /* shared secret awaiting key_ack */
    uint8_t             pending_nc[32];     /* client nonce awaiting key_ack */
    bool                pending_kyber;
} nodus_inter_session_t;

#define NODUS_MAX_INTER_SESSIONS  NODUS_TCP_MAX_CONNS

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

    /* Rate limiting */
    uint64_t            rate_window_start;
    int                 puts_in_window;

    /* Circuit table (VPN mesh Faz 1) */
    nodus_circuit_table_t   circuits;

    /* Client protocol version (0=legacy, 2=channel encryption support) */
    uint32_t                proto_version;

    /* Channel encryption (Kyber handshake) */
    nodus_channel_crypto_t  channel_crypto;
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

/* ── Batch forward (get_batch miss → forward to closest peer) ────── */

#define NODUS_BF_MAX_FORWARDS   8    /* Max concurrent forwards per batch */
#define NODUS_BF_MAX_BATCHES    4    /* Max concurrent batch requests with forwards */
#define NODUS_BF_TIMEOUT_MS     5000 /* Per-forward timeout */

/** Batch forward connection states */
enum {
    BF_CONNECTING   = 0,
    BF_SEND_HELLO   = 1,
    BF_RECV_CHALL   = 2,
    BF_SEND_AUTH    = 3,
    BF_RECV_AUTHOK  = 4,
    BF_SEND_BATCH   = 5,
    BF_RECV_RESULT  = 6,
    BF_DONE         = 7,
};

/** One outgoing batch forward connection to a peer */
typedef struct {
    int         fd;              /**< Non-blocking socket (-1 if unused) */
    int         state;           /**< BF_CONNECTING..BF_DONE */
    char        ip[64];
    uint16_t    port;
    uint64_t    started_at;
    uint8_t    *send_buf;        /**< Current send frame (reused for hello/auth/batch) */
    size_t      send_len;
    size_t      send_pos;
    uint8_t    *recv_buf;        /**< Response buffer */
    size_t      recv_cap;
    size_t      recv_len;
    /* Auth state */
    uint8_t     token[NODUS_SESSION_TOKEN_LEN]; /**< Session token from auth_ok */
    /* Batch keys (stored for sending after auth) */
    nodus_key_t *batch_keys;     /**< Keys to query (heap, freed on cleanup) */
    int         batch_key_count;
    /* Which keys this forward carries (indices into parent batch) */
    int        *key_indices;     /**< Array of indices into batch's key array */
    int         key_count;
} dht_bf_conn_t;

/** One batch request being forwarded (coordinates multiple forwards) */
typedef struct {
    bool            active;
    uint32_t        txn_id;          /**< Client's transaction ID */
    int             session_slot;    /**< Client session index */
    uint64_t        started_at;

    /* All keys in the batch */
    nodus_key_t    *keys;
    int             key_count;

    /* Per-key results (local + forwarded merged) */
    nodus_value_t ***vals_per_key;
    size_t          *counts_per_key;

    /* Active forwards */
    dht_bf_conn_t   forwards[NODUS_BF_MAX_FORWARDS];
    int             pending_forwards;  /**< Countdown: when 0 → send response */
} dht_bf_batch_t;

/** Batch forward state (part of nodus_server_t) */
typedef struct {
    dht_bf_batch_t  batches[NODUS_BF_MAX_BATCHES];
    int             bf_epoll_fd;     /**< Separate epoll for batch forward fds */
} dht_bf_state_t;

/** bf fd→batch index mapping */
typedef struct {
    int batch_idx;
    int forward_idx;
} dht_bf_fd_entry_t;

#define NODUS_BF_FD_TABLE_SIZE  256

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
} dht_republish_state_t;

/** Media republish state (persistent across ticks) */
typedef struct {
    uint8_t     last_hash[64];  /**< Bookmark: last content_hash processed */
    bool        active;         /**< Republish cycle in progress */
    bool        first_batch;    /**< First batch of cycle (no bookmark yet) */
    uint64_t    cycle_start;    /**< When current cycle began */
} dht_media_republish_state_t;

/* ── Server ──────────────────────────────────────────────────────── */

typedef struct nodus_server {
    nodus_server_config_t   config;
    nodus_identity_t        identity;

    /* Shared event loop */
    int                     epoll_fd;

    /* Transports */
    nodus_tcp_t             tcp;
    nodus_tcp_t             inter_tcp;      /* Inter-node TCP transport (port 4002) */
    nodus_tcp_t             witness_tcp;    /* Witness BFT TCP transport (port 4004) */
    nodus_udp_t             udp;

    /* Storage */
    nodus_storage_t         storage;
    nodus_media_storage_t   media_storage;
    nodus_channel_store_t   ch_store;
    nodus_routing_t         routing;
    nodus_hashring_t        ring;

    /* Consensus */
    nodus_cluster_t         cluster;

    /* Witness module (NULL when disabled) */
    nodus_witness_t        *witness;

    /* Presence tracking (connected clients, cluster-wide) */
    nodus_presence_table_t  presence;

    /* Inter-node circuit forwarding (VPN mesh Faz 1) */
    nodus_inter_circuit_table_t inter_circuits;

    /* New channel system (TCP 4003) */
    nodus_channel_server_t      ch_server;
    nodus_ch_replication_t      ch_replication;
    nodus_ch_ring_t             ch_ring;
    bool                        ch_startup_done;  /* One-shot: rejoin sent */

    /* Sessions (indexed by conn->slot) */
    nodus_session_t         sessions[NODUS_MAX_SESSIONS];
    nodus_inter_session_t   inter_sessions[NODUS_MAX_INTER_SESSIONS];

    /* FIND_VALUE async state machine */
    dht_fv_state_t          fv_state;
    dht_fv_fd_entry_t       fv_fd_table[NODUS_FV_FD_TABLE_SIZE];
    int                     fv_epoll_fd;

    /* Batch forward state machine (get_batch miss → forward to closest peer) */
    dht_bf_state_t          bf_state;
    dht_bf_fd_entry_t       bf_fd_table[NODUS_BF_FD_TABLE_SIZE];

    /* Periodic republish */
    dht_republish_state_t   republish;
    dht_media_republish_state_t media_republish;

    /* Ping-before-evict pending entries */
    nodus_pending_eviction_t pending_evictions[NODUS_MAX_PENDING_EVICTIONS];

    /* CRIT-4: TCP idle connection sweep (every 30s) */
    uint64_t                last_idle_sweep;

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

/**
 * Replicate a DHT value to K-closest Kademlia peers.
 * Used for channel node announcements and client PUT replication.
 */
void nodus_server_replicate_value(nodus_server_t *srv, const nodus_value_t *val);

/**
 * Replicate a media chunk to K-closest Kademlia peers.
 * Used after storing each chunk from a client upload.
 */
void nodus_server_replicate_media_chunk(nodus_server_t *srv,
                                         const nodus_media_meta_t *meta,
                                         uint32_t chunk_index,
                                         const uint8_t *data, size_t data_len);

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

/**
 * Handle KEY_INIT message (Kyber ciphertext + client nonce).
 * Decapsulates, derives AES key, sends KEY_ACK.
 */
int nodus_auth_handle_key_init(nodus_server_t *srv, nodus_session_t *sess,
                                const uint8_t *kyber_ct, const uint8_t *nonce_c,
                                uint32_t txn_id);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SERVER_H */
