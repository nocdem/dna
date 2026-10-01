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

#include <signal.h>                /* sig_atomic_t — see stop_requested */

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
#include "crypto/nodus_channel_crypto.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_p2p.h"      /* nodus_p2p_config_t (P2P-PORT F5) */
#include "server/nodus_presence.h"
#include "circuit/nodus_circuit.h"
#include "circuit/nodus_inter_circuit.h"
#include "crypto/nodus_channel_crypto.h"
#include "protocol/nodus_tier2.h"   /* nodus_t2_cursor_t / page info (DHT Package A) */

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MAX_SESSIONS     NODUS_TCP_MAX_CONNS
#define NODUS_MAX_LISTEN_KEYS  128    /* Per session */
#define NODUS_MAX_SEED_NODES   16

/* ── Listen Forwarding (Scribe pattern) ─────────────────────────── */

#define NODUS_MAX_SUBSCRIPTIONS  4096
#define NODUS_SUBSCRIPTION_TTL   900     /* 15 min — must be > 2x renewal interval */

typedef struct {
    bool            active;
    nodus_key_t     key;                /* DHT key being listened */
    nodus_key_t     subscriber_node_id; /* Node that has the listener */
    char            subscriber_ip[64];
    uint16_t        subscriber_port;    /* TCP 4002 */
    uint64_t        expires_at;
} nodus_subscription_t;

typedef struct {
    nodus_subscription_t entries[NODUS_MAX_SUBSCRIPTIONS];
    int                  count;
} nodus_subscription_table_t;

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

    /* C-01: Require Dilithium5 auth on the inter-node port (4002).
     * Default false for backward compat. Set true once all nodes are
     * updated. P2P-PORT F5: the witness port 4004 no longer consults it —
     * every 4004 connection runs the secret-connection handshake
     * unconditionally (witness-port session design §2R R13). */
    bool        require_peer_auth;

    /* P2P-PORT F5 — the witness port 4004's p2p section (reference
     * config.go P2P key names; nodus_witness_p2p.h). */
    nodus_p2p_config_t p2p;

    /* R3 W4 — is_cold_bootstrap (the PR 3 Yol B / C-2 cold-DR escape) is
     * DELETED with the closed consensus lane, field and all: its one
     * reader (nodus_witness_bootstrap.c, which bypassed the DISCOVER
     * bootstrap state machine's C-2 cabal protection on incoming
     * w_chain_q when this flag was set) is deleted with that file, and
     * the field itself no longer exists in this struct — there is
     * nothing left for the CLI/config to set. */

    /* O15E Faz D — local successor genesis PIN for a fresh joiner. When
     * `has_v2_genesis_pin` is set and the node has no successor chain,
     * the joiner bootstrap pulls the canonical genesis bundle from a
     * peer, re-derives the genesis, and adopts it ONLY if the derivation
     * matches `v2_genesis_pin`. Operator-supplied (CLI/config), NEVER
     * wire-settable. Without it a fresh node is not a successor joiner.
     *
     * R3 W3 (D-24 rev 4 (1)): 32 bytes — the chain id, not a 64-byte
     * genesis BlockID. A version-3 chain has no genesis BLOCK to pin to
     * (D-19 rev 6 withdrew it); its only identity is the hash of its
     * stored genesis DOCUMENT (D-18 rev 4), which is exactly what this
     * field holds. */
    bool        has_v2_genesis_pin;
    uint8_t     v2_genesis_pin[32];

    /* P2P-PORT F6 — the published network file (decision
     * 2026-09-26-witness-port-session.md "Ağ config dosyası"): its path
     * (nodus.json key "network_file"; `--network-file` overrides) and, when
     * the file carries a pin, that pin. `has_network_pin` arms the start
     * check in nodus_server_init: a node that HOLDS a chain whose id is
     * not the file's pin refuses to start. A `--v2-genesis-pin` given
     * alone keeps its old meaning (inert when a chain is present). */
    char        network_file[256];
    bool        has_network_pin;
    uint8_t     network_pin[32];

    /* WebSocket entry of the client port (decision
     * 2026-09-25-web-wallet-nodus-send-transport.md; nodus_ws.h).
     * ws_port: nodus.json "ws_port"; 0 = OFF (default). The listener is
     * ALWAYS bound to 127.0.0.1 — there is no address setting; the public
     * side is a local TLS proxy (Caddy). It is a second listening socket of
     * `tcp` (the client transport), not a separate transport.
     * ws_origins: nodus.json "ws_origins" (array of strings); allowed
     * browser Origin values, exact match. count 0 = the default
     * NODUS_WS_DEFAULT_ORIGIN, applied in nodus_server_init. */
    uint16_t            ws_port;
    nodus_ws_origins_t  ws_origins;

    /* Node-local address history index (decision docs/plans/decisions/
     * 2026-10-01-node-address-history-index.md rev 2;
     * witness/nodus_witness_addr_index.h). nodus.json
     * "addr_history_index": true; default OFF. Off = the writers write
     * nothing. It changes no root — the setting may differ per node. */
    bool                addr_history_index;
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

    /* Channel encryption (Kyber handshake for inter-node).
     * B3 fix — channel_crypto storage moved to nodus_tcp_conn_t.
     * Read via sess->conn->channel_crypto. The pending_* fields stay
     * here because they're per-handshake-attempt state, not session
     * state — a new key_init can arrive before the previous handshake
     * completes, and the conn's channel_crypto only becomes valid on
     * key_ack/key_init completion. */
    uint8_t             pending_ss[32];     /* shared secret awaiting key_ack */
    uint8_t             pending_nc[32];     /* client nonce awaiting key_ack */
    bool                pending_kyber;

    /* CRIT-1: the auth challenge nonce we received and signed, retained so the
     * dialer can reconstruct the signed message (kyber_pk || nonce) and verify
     * the peer's kpk_sig at auth_ok time. Previously the nonce was signed and
     * immediately discarded, so the binding could not be checked at all. */
    uint8_t             challenge_nonce[NODUS_NONCE_LEN];
    bool                has_challenge_nonce;
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

    /* Channel encryption (Kyber handshake).
     * B3 fix — channel_crypto storage moved to nodus_tcp_conn_t.
     * Read via sess->conn->channel_crypto. */
} nodus_session_t;

/* ── Iterative Kademlia FIND_NODE Lookup (UDP) ───────────────────── */

/*
 * DESIGN NOTE: Only FIND_NODE is used. NOT FIND_VALUE.
 *
 * Nodus values are 1.5-6KB+ (Kyber1024 CT + Dilithium5 sig + envelope)
 * which exceed NODUS_MAX_FRAME_UDP (1400 bytes). nodus_udp_send() rejects
 * payloads > 1400 bytes, so most values can't be returned via UDP.
 *
 * Instead: FIND_NODE discovers K-closest nodes (small response, ~200-400B),
 * then BF forward over TCP 4002 fetches the actual value (no size limit).
 *
 * Used by: GET (find nodes → BF forward), PUT (find nodes → STORE),
 *          LISTEN (find nodes → SUBSCRIBE_FWD)
 */

/** States for individual UDP queries within a lookup */
typedef enum {
    LOOKUP_QUERY_IDLE,       /**< Slot available */
    LOOKUP_QUERY_SENT,       /**< UDP sent, waiting for response */
    LOOKUP_QUERY_DONE        /**< Response received or timed out */
} lookup_query_state_t;

/** One outgoing UDP query to a peer */
typedef struct {
    lookup_query_state_t state;
    nodus_key_t         node_id;        /**< Peer being queried */
    char                ip[64];
    uint16_t            udp_port;
    uint32_t            txn;            /**< Transaction ID for matching response */
    uint64_t            sent_at;        /**< For per-query timeout */
    int                 retries;        /**< 0 = first attempt, 1 = retry */
} lookup_query_t;

/** One iterative FIND_NODE lookup */
typedef struct {
    bool                active;
    nodus_key_t         target_key;         /**< Key being looked up */
    uint32_t            client_txn_id;      /**< Client's T2 transaction ID */
    int                 session_slot;       /**< Client session index (-1 internal) */
    uint64_t            started_at;

    /* Kademlia iterative state */
    nodus_peer_t        shortlist[NODUS_LOOKUP_MAX_CANDIDATES];
    int                 shortlist_count;
    nodus_key_t         queried[NODUS_LOOKUP_MAX_QUERIED];
    int                 queried_count;
    nodus_peer_t        closest_k[NODUS_K];      /**< Current K-closest snapshot */
    nodus_peer_t        prev_closest_k[NODUS_K]; /**< Previous round's K-closest */
    int                 closest_k_count;
    int                 stable_rounds;           /**< Rounds with unchanged closest_k */

    /* Active outgoing UDP queries */
    lookup_query_t      queries[NODUS_ALPHA];
    int                 queries_pending;

    /* Result: K-closest nodes (populated on convergence or timeout) */
    nodus_peer_t        result_nodes[NODUS_K];
    int                 result_node_count;

    /* Callback for async completion */
    void              (*on_complete)(struct nodus_server *srv,
                                     nodus_peer_t *closest, int count,
                                     void *user_data);
    void               *cb_data;
    void              (*cb_data_free)(void *);  /**< Cleanup cb_data on shutdown */
} iterative_lookup_t;

/** All in-flight iterative lookups */
typedef struct {
    iterative_lookup_t  lookups[NODUS_LOOKUP_MAX_INFLIGHT];
    uint32_t            next_txn;       /**< Unique UDP txn IDs (single-threaded, no atomic) */
} iterative_lookup_state_t;

/* ── Batch forward limits ────────────────────────────────────────── */

#define NODUS_BF_MAX_FORWARDS   8    /* Max concurrent forwards per batch */
#define NODUS_BF_MAX_BATCHES    4    /* Max concurrent batch requests with forwards */
#define NODUS_BF_TIMEOUT_MS     5000 /* Per-forward timeout */

/* ── DHT Package A: forwarded-read candidate sets (S1/S3, rev 2) ─── */

/** Signature verifications one forwarded read may spend (rev 2 item 11).
 *  A Dilithium5 verify costs ~0.1-0.2 ms; 1024 bounds one request to
 *  ~0.2 s of CPU. An honest read needs at most the rows it returns: a
 *  2 MiB page holds <= ~270 rows (NODUS_VALUE_SERIALIZED_EST >= ~7.6 KB),
 *  one forward reply <= NODUS_DHT_SRC_MAX_ROWS, and identical copies from
 *  several replicas are verified once. Failed verifies cost at most one per
 *  source (rev 3 R-b: a source whose row fails is discarded). Local rows
 *  (verified at put) are free. When the cap runs out (rev 3 R-a) the walk
 *  goes on and takes every row already settled valid (local rows, rows
 *  verified earlier); only rows still undecided are left out — an unpaged
 *  read skips them (logged), a paged read closes its page before the first
 *  PK with no settled row (more, next = last row kept: the rest comes on
 *  the next page, with a fresh budget). */
#define NODUS_DHT_VERIFY_CAP    1024

/** At most this many sources per key: the forwards + the local store. */
#define NODUS_DHT_MAX_SOURCES   (NODUS_BF_MAX_FORWARDS + 1)

/** Rev 3 R-e — unpaged per-source row bound. The originator receives one
 *  forward reply into a buffer of RESP_BUF_SIZE (NODUS_MAX_VALUE_SIZE +
 *  65536, nodus_server.c; bf_start_forward recv_cap), and every forwarded
 *  row that becomes a candidate carries an owner public key and a signature
 *  (R-c), so no honest reply holds more than RESP_BUF_SIZE /
 *  (NODUS_PK_BYTES + NODUS_SIG_BYTES) = 590 rows. Paged reads use the
 *  tighter bound of what the responder's page budget can hold. */
#define NODUS_DHT_SRC_MAX_ROWS \
    ((size_t)(NODUS_MAX_VALUE_SIZE + 65536) / (size_t)(NODUS_PK_BYTES + NODUS_SIG_BYTES))

/** Verification state of one candidate row. */
enum {
    NODUS_DHT_V_UNKNOWN = 0,   /**< not verified (yet) */
    NODUS_DHT_V_OK      = 1,   /**< nodus_value_verify passed, or a local row */
    NODUS_DHT_V_BAD     = 2    /**< nodus_value_verify failed, or every source
                                *   that sent it was discarded (R-b) */
};

/** One candidate row of a forwarded read. Every DISTINCT row a source sent
 *  for a (owner_fp, value_id) is kept until the read resolves — a newer
 *  row that later fails verification must not have evicted a valid older
 *  one. Exact copies (everything nodus_value_verify reads equal) are one
 *  candidate with the senders OR-ed into srcs. */
typedef struct {
    nodus_value_t *v;
    uint8_t        hash[32];   /**< SHA3-256(data) (empty → zeros); for local
                                *   rows the stored data_hash when present */
    uint8_t        vstate;     /**< NODUS_DHT_V_* */
    bool           trusted;    /**< a trusted source (the local store) sent it */
    uint16_t       srcs;       /**< bit s: source id s sent this exact row */
    uint32_t       order;      /**< arrival order (unpaged replies keep it) */
} nodus_dht_cand_t;

/** One source of a key: page outcome (paged reads) and bookkeeping. A
 *  source id is assigned by each nodus_dht_keyset_add call. */
typedef struct {
    bool              trusted;   /**< the local store */
    bool              noted;     /**< nodus_dht_keyset_note_page ran for it */
    bool              more;      /**< the source said rows remain (or R-e cut it) */
    bool              bounds;    /**< more AND (trusted OR its rows filled
                                  *   the responder's page budget) */
    bool              has_last;  /**< last is set */
    nodus_t2_cursor_t last;      /**< largest PK of its rows that passed the
                                  *   key / owner / cursor filters */
} nodus_dht_src_page_t;

/** Every candidate and every source outcome for one key of a read. The
 *  candidates are kept sorted by (PK ASC, rank) at all times (the sorted
 *  dedup index of rev 3 R-e). */
typedef struct {
    nodus_dht_cand_t     *c;
    size_t                n;
    size_t                cap;
    uint32_t              next_order;
    int                   nsrc;                        /**< source ids assigned */
    uint16_t              tainted;      /**< R-b: bit s = source s sent a row
                                         *   that failed verification */
    nodus_dht_src_page_t  src[NODUS_DHT_MAX_SOURCES];
    int                   peers;        /**< peers this key was to be asked (S6) */
    int                   answered;     /**< sources that LOOKED (an entry without "u") */
    bool                  local_fault;  /**< the local store could not be read */
} nodus_dht_keyset_t;

/** What adding one source's rows to a keyset did. */
typedef struct {
    int               src;           /**< source id given to these rows (-1 = none) */
    size_t            added;         /**< new distinct candidates */
    size_t            dup;           /**< exact copies of a present candidate (dropped, not verified) */
    size_t            bad;           /**< dropped: key mismatch / owner filter */
    size_t            below_cursor;  /**< dropped: PK <= the request cursor */
    size_t            refused;       /**< R-c: dropped, untrusted row without an
                                      *   owner public key or a signature */
    size_t            over_cap;      /**< R-e: dropped, past the source's row cap
                                      *   (the rows with the LARGEST PKs) */
    bool              truncated;     /**< over_cap > 0 */
    size_t            est_bytes;     /**< R-d: sum of NODUS_VALUE_SERIALIZED_EST
                                      *   over the rows kept from this source
                                      *   (passed the filters, R-c and R-e) */
    bool              has_last;      /**< last is set */
    nodus_t2_cursor_t last;          /**< largest PK among the rows kept */
} nodus_dht_merge_stats_t;

/** S6: what a read answers once every source has been asked. */
typedef enum {
    NODUS_DHT_READ_ROWS        = 0,  /**< rows to return */
    NODUS_DHT_READ_EMPTY       = 1,  /**< looked, nothing there: empty result */
    NODUS_DHT_READ_UNAVAILABLE = 2   /**< could not look: NODUS_ERR_UNAVAILABLE */
} nodus_dht_read_outcome_t;

/* ── Batch forward (get_batch miss → forward to closest peer) ────── */

/** Batch forward connection states */
enum {
    BF_CONNECTING      = 0,
    BF_SEND_HELLO      = 1,
    BF_RECV_CHALL      = 2,
    BF_SEND_AUTH       = 3,
    BF_RECV_AUTHOK     = 4,
    BF_SEND_KEY_INIT   = 5,
    BF_RECV_KEY_ACK    = 6,
    BF_SEND_BATCH      = 7,
    BF_RECV_RESULT     = 8,
    BF_DONE            = 9,
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
    /* Kyber handshake state */
    nodus_channel_crypto_t crypto;  /**< AES-256-GCM session (after Kyber handshake) */
    bool        encrypted;          /**< true after successful Kyber key exchange */
    uint8_t     pending_ss[32];     /**< Shared secret (cleared after key_ack) */
    uint8_t     pending_nc[32];     /**< Local nonce (cleared after key_ack) */
    /* CRIT-1: retained challenge nonce + EXPECTED peer identity, so the
     * batch-forward dialer can verify the peer's kpk_sig over
     * (kyber_pk || challenge_nonce) and pin fingerprint(server_pk) against the
     * FIND_NODE peer it actually dialed, before Kyber-encapsulating to it. */
    uint8_t     challenge_nonce[NODUS_NONCE_LEN];
    bool        has_challenge_nonce;
    nodus_key_t expected_node_id;   /**< the peer bf_start_forward dialed */
    bool        has_expected_node_id;
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

    /* Per-key candidates (local + forwarded), resolved when the batch
     * completes (heap array of key_count). */
    nodus_dht_keyset_t *sets;

    /* Active forwards */
    dht_bf_conn_t   forwards[NODUS_BF_MAX_FORWARDS];
    int             pending_forwards;  /**< Countdown: when 0 → send response */

    bool            is_get_all;        /**< True if this BF serves a get_all request
                                        *   (1 key, respond with result_multi not batch) */
    bool            is_single_get;     /**< True if this BF serves a single-value GET
                                        *   (1 key, respond with `result` (the newest
                                        *   verified value) or `result_empty`).
                                        *   Mutually exclusive with is_get_all. */

    /* DHT Package A */
    bool            has_own;           /**< S2 owner filter (forwarded + re-applied) */
    nodus_key_t     own;
    bool            paged;             /**< S3 paged get_all ("pg" or "after") */
    bool            has_after;
    nodus_t2_cursor_t after;           /**< S3 request cursor */
    int             verify_left;       /**< NODUS_DHT_VERIFY_CAP budget left */
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
    nodus_key_t last_owner;     /**< Bookmark: last owner_fp (composite tie-break) */
    uint64_t    last_vid;       /**< Bookmark: last value_id (composite tie-break) */
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
    /* Per-chunk pacing (one chunk per tick to avoid pending-queue overflow) */
    nodus_media_meta_t current_meta; /**< Entry currently being drained */
    uint32_t    chunk_cursor;        /**< Next chunk index to send (0..chunk_count) */
    bool        has_current;         /**< current_meta is valid */
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
    /* P2P-PORT F5 — `witness_tcp` (the nodus_tcp framed transport on port
     * 4004) is DELETED: 4004 is the witness's p2p host
     * (witness->p2p, nodus_witness_p2p.h). */
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

    /* Iterative Kademlia FIND_NODE lookup engine (UDP-based) */
    iterative_lookup_state_t lookup_state;

    /* Listen forwarding: Scribe pub/sub subscriptions from remote nodes */
    nodus_subscription_table_t  subscriptions;
    uint64_t                    last_sub_cleanup;

    /* Subscription renewal state (rate-limited across ticks) */
    struct {
        int      session_idx;    /* Current session being processed */
        int      key_idx;        /* Current listen_keys index within session */
        uint64_t last_renewal;   /* Last time renewal cycle started */
    } sub_renewal;

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

    /* DB maintenance timers */
    uint64_t                last_wal_checkpoint;
    uint64_t                last_vacuum;

    /* Phase 1 visibility: send diagnostics dump timer */
    uint64_t                last_stats_dump;

    /* Process start time for cluster-status uptime field (Task 0.2) */
    uint64_t                start_time;

    bool                    running;

    /* Set by nodus_server_stop(), which nodus-server calls from its
     * SIGINT/SIGTERM handler. SEPARATE from `running` because
     * nodus_server_run() sets `running = true` on entry: a stop that
     * arrives during nodus_server_init() — which is a long operation
     * (storage migration, VACUUM, identity generation, witness init) —
     * would otherwise be overwritten a moment later and the process
     * would ignore the signal for the rest of its life. The Stage F
     * harness kills its short-lived identity-generation spawns exactly
     * in that window, so it hit this intermittently and hung
     * stagef_up.sh in `wait`. sig_atomic_t because a signal handler
     * writes it. */
    volatile sig_atomic_t   stop_requested;
} nodus_server_t;

/**
 * Initialize server with config. Loads identity, opens storage, binds ports.
 */
int nodus_server_init(nodus_server_t *srv, const nodus_server_config_t *config);

/**
 * Marker file written by the witness module when the chain DB is first
 * created (nodus_witness_create_chain_db on genesis commit). Its
 * presence under <data_path> means "this node has crossed the genesis
 * boundary at least once" and is the signal that allows the
 * partial-wipe gate below to enforce its strict invariant.
 *
 * Without this marker, the gate cannot distinguish two file-level
 * indistinguishable states:
 *   - fresh node mid-bootstrap (storage opens populated nodus.db +
 *     channels.db before FETCH_GENESIS lands the first witness DB)
 *   - post-genesis node where the operator wiped only witness_*.db
 * Both look like (nodus=Y, channels=Y, witness=N) on disk.
 *
 * The marker is itself wipeable. Threat model: catches operator
 * MISTAKES (rm of one DB by accident), not a determined adversary
 * (who would just wipe everything → fresh state → bootstrap, the
 * intended recovery path).
 */
#define NODUS_PARTIAL_WIPE_GENESIS_MARKER  ".witness_db_seen"

/**
 * PR 3 / E5 — Partial-wipe XOR check (H-10 mitigation).
 *
 * The 3 SQLite DB files under <data_path> (nodus.db, channels.db,
 * any witness_<hex>.db) MUST be in a consistent state at boot, but
 * the invariant is gated on the genesis marker above:
 *
 *   - marker absent  -> pre-genesis (fresh node or mid-bootstrap),
 *                       any subset of the 3 DBs is allowed; pass
 *   - marker present + all 3 absent  -> someone wiped DBs but left
 *                                       the marker; treat as fresh
 *   - marker present + all 3 present -> normal running, pass
 *   - marker present + 1 or 2 present -> partial wipe, REFUSE START
 *
 * MUST be called BEFORE nodus_storage_open / nodus_channel_store_open
 * — those calls auto-create the missing files and defeat detection.
 *
 * Returns: 0 on consistent state (caller proceeds),
 *         -1 on partial-wipe detected (caller MUST refuse init).
 */
int nodus_server_check_partial_wipe(const char *data_path);

/* ── P2P-PORT F6 — the published network file ─────────────────────────
 *
 * Decision `docs/plans/decisions/2026-09-26-witness-port-session.md`
 * ("Ağ config dosyası (pin + seed'ler)", "Pin'i tören yazar"); design
 * `docs/plans/2026-09-26-p2p-port-design.md` §4. A JSON object, SEPARATE
 * from the node's own nodus.json, with exactly these keys:
 *
 *   {
 *     "v2_genesis_pin":   "<64 hex>" | "" | absent,
 *     "persistent_peers": ["<id>@<ip>:<port>", ...]  | absent
 *   }
 *
 * Any other key, a pin that is not 0 or 64 hex digits, a peer entry that
 * is not "id@ip:port" with a valid ID and an IP literal (R-P2P-24 /
 * R-P2P-33), a duplicate peer entry, or more than NODUS_P2P_MAX_PEER_LIST
 * peers makes the WHOLE file refused: a typo'd key would otherwise read
 * as "no pin" and silently change what the node does.
 *
 * Pin rules (operator): empty/absent → no join; set + no local chain →
 * join exactly like --v2-genesis-pin; set + local chain → must equal the
 * chain's 32-byte id or the node refuses to start; the offline
 * `--derive-v2-genesis` writes the derived id into an EMPTY pin (a pin
 * already there: equal → nothing written, different → refused, never
 * overwritten). A running node never writes the file.
 *
 * Built only with json-c (NODUS_HAS_JSONC), like nodus-server's own
 * config loader.
 */
#ifdef NODUS_HAS_JSONC
typedef struct {
    bool    has_pin;
    uint8_t pin[32];
    int     n_peers;
    char    peers[NODUS_P2P_MAX_PEER_LIST][CMT_P2P_NETADDR_STR_MAX];
} nodus_network_file_t;

/** Parse and validate `path` (rules above). @return 0; -1 refused (the
 *  reason is logged at ERROR). `out` is zeroed first. */
int nodus_network_file_load(const char *path, nodus_network_file_t *out);

/**
 * Apply a loaded file to a server config: the file's persistent peers are
 * merged into `cfg->p2p` (an entry already present — e.g. from `-s id@` or
 * nodus.json — is not added twice); a file pin arms the joiner
 * (`has_v2_genesis_pin`) and the start check (`has_network_pin`). A file
 * pin that differs from an already-given `--v2-genesis-pin` is refused.
 * @return 0; -1 refused (logged).
 */
int nodus_network_file_apply(const nodus_network_file_t *nf,
                             nodus_server_config_t *cfg);

/**
 * The pin-auto write of the genesis ceremony: put `chain32` into the
 * file's EMPTY pin — temp file in the same directory, fsync, rename,
 * directory fsync; every other key kept, in its order.
 * @return 0 written; 1 the file already holds exactly this pin (nothing
 *         written); -1 refused — the file is malformed or holds a
 *         DIFFERENT pin (never overwritten) — or an I/O fault (logged).
 */
int nodus_network_file_write_pin(const char *path, const uint8_t chain32[32]);
#endif /* NODUS_HAS_JSONC */

/**
 * The committed chain id (32 bytes) of the version-3 chain database at
 * `db_path`, read on a read-only handle through
 * nodus_witness_v2_gen_stored_chain_id. @return 0 / -1.
 */
int nodus_server_read_chain_id(const char *db_path, uint8_t out[32]);

/**
 * P2P-PORT F6 — the pin-at-start check. The chain database the witness
 * will open (nodus_witness_scan_chain_db's selection: the
 * lexicographically smallest canonical `witness_<32 lowercase hex>.db`)
 * must be a readable version-3 chain whose id equals `pin`.
 * @return 0 no chain database present, or it matches;
 *         -1 a chain with a different id, or one whose id cannot be read
 *         (logged at ERROR) — the caller refuses to start.
 */
int nodus_server_check_chain_pin(const char *data_path, const uint8_t pin[32]);

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

/**
 * Faz 1 KEM migration (docs/plans/decisions/2026-09-23-kem-mlkem-
 * migration.md) — algorithm-aware KEY_INIT handler. key_alg: 0 = round-3
 * Kyber (delegates to nodus_auth_handle_key_init() above, byte-identical
 * to pre-Faz-1 behaviour), 1 = ML-KEM-1024. D11, N1 delta 1.
 */
int nodus_auth_handle_key_init_alg(nodus_server_t *srv, nodus_session_t *sess,
                                    uint8_t key_alg,
                                    const uint8_t *ct, const uint8_t *nonce_c,
                                    uint32_t txn_id);

/* ════════════════════════════════════════════════════════════════════
 * INTERNAL — DHT Package A helpers. Exposed ONLY so unit tests can drive
 * them in-process (tests/test_bf_merge_pure.c, test_get_all_paging.c,
 * test_get_unavailable.c, test_inter_circuit_uaf.c,
 * test_inter_preauth_gate.c, test_bf_forward_frames.c,
 * test_inter_role_split.c, test_bf_recv_frame.c). Not an API: no other module calls these.
 * ════════════════════════════════════════════════════════════════════ */

/** Primary-key order of nodus_values: owner_fp bytewise, then value_id
 *  compared as SIGNED int64 (SQLite INTEGER) — nodus_storage_get_all_page.
 *  @return <0, 0, >0 */
int nodus_dht_pk_cmp(const nodus_key_t *a_owner, uint64_t a_vid,
                     const nodus_key_t *b_owner, uint64_t b_vid);

/** The replica predicate (nodus_storage.c PUT_IF_NEWER_SQL): 1 when `in`
 *  replaces `ex` — (int64)seq greater, or seq equal and SHA3-256(data)
 *  greater (empty data = 32 zero bytes). 0 otherwise (incl. identical). */
int nodus_dht_value_newer(const nodus_value_t *in, const nodus_value_t *ex);

/** Free every candidate of a keyset (the candidate list is emptied; the
 *  source bookkeeping, peers, answered and local_fault stay). */
void nodus_dht_keyset_clear(nodus_dht_keyset_t *ks);

/**
 * S1 + F6, rev 2 item 11, rev 3 R-b/R-c/R-e/R-f/R-g: add one source's rows
 * for `key` to a keyset. Each call is ONE source and gets the next source
 * id (stats->src); at most NODUS_DHT_MAX_SOURCES per keyset.
 *
 * A src row is dropped (counted bad) when its key_hash != key or `own` is
 * set and its owner_fp != own; dropped (below_cursor) when `after` is set
 * and its PK <= after; dropped (refused, R-c) when the source is untrusted
 * and the row carries no owner public key or no signature (all-zero
 * owner_pk / signature: what nodus_value_deserialize leaves when "owner" /
 * "sig" is absent or not the exact length). When more than max_rows rows
 * pass (max_rows 0 = no cap), only the max_rows with the SMALLEST PKs are
 * kept (R-e; deterministic, and a page is filled from the low end) and the
 * source is marked truncated (its page note then says more and bounds).
 *
 * A row that is an EXACT copy of a present candidate — same PK, seq,
 * type, ttl, SHA3-256(data), signature and owner_pk, i.e. everything
 * nodus_value_verify reads — is collapsed into it as dup without being
 * verified (its sender is added to the candidate's srcs). Of exact copies
 * the one whose created_at / expires_at stand is (R-f) the trusted copy
 * when there is one (created_at is not signed: a forwarding peer must not
 * age a row this node holds), else the copy with the smallest created_at —
 * independent of arrival order. Every other row becomes a candidate;
 * NOTHING is verified here. `trusted` marks the rows verified already (the
 * local store: verified at put).
 *
 * The candidates stay sorted by (PK, rank): this source's rows are sorted
 * and merged in, O((n + m) + m log m) per source — no pairwise scan.
 *
 * hashes (may be NULL, R-g): the stored data_hash of each src row (the
 * local store's page read); a row whose hash is not present is hashed.
 *
 * Ownership: a row taken in is NULLed in src (a trusted copy replacing an
 * equal untrusted candidate hands the replaced object back in its place);
 * the caller frees what src holds afterwards.
 * stats (may be NULL): counts, src id, est_bytes and last over the rows kept.
 * @return 0, or -1 on allocation failure or a source past
 *         NODUS_DHT_MAX_SOURCES (keyset unchanged; rows left in src).
 */
int nodus_dht_keyset_add_ex(nodus_dht_keyset_t *ks,
                            nodus_value_t **src, size_t src_count,
                            const nodus_key_t *key, const nodus_key_t *own,
                            const nodus_t2_cursor_t *after, bool trusted,
                            size_t max_rows,
                            const nodus_storage_data_hash_t *hashes,
                            nodus_dht_merge_stats_t *stats);

/** nodus_dht_keyset_add_ex with no stored hashes and the default row cap:
 *  none for a trusted source (the local store bounds its own reads),
 *  NODUS_DHT_SRC_MAX_ROWS for an untrusted one. */
int nodus_dht_keyset_add(nodus_dht_keyset_t *ks,
                         nodus_value_t **src, size_t src_count,
                         const nodus_key_t *key, const nodus_key_t *own,
                         const nodus_t2_cursor_t *after, bool trusted,
                         nodus_dht_merge_stats_t *stats);

/**
 * S3, rev 2 item 12, rev 3 R-d: record the page outcome of the source
 * stats->src. A more=true source BOUNDS the page (rows past its last PK
 * may interleave with rows it has not sent) only when it is trusted (the
 * local store) or its rows filled a page:
 *   - nx given (the responder named the size of the row it stopped on):
 *     est_bytes + *nx > responder_budget — exactly the responder's own
 *     stop rule (nodus_storage_get_all_page), so an honest source that
 *     stopped on a LARGE next row bounds the page and none of its rows is
 *     skipped;
 *   - no nx (a peer that predates it): est_bytes +
 *     NODUS_VALUE_SERIALIZED_EST(0) > responder_budget — not even one more
 *     zero-byte row would have fit;
 *   - a source cut by its row cap (stats->truncated) bounds, more forced.
 * A source answering one small row with more=true therefore cannot hold
 * the page to that row. A source discarded under R-b loses its note at
 * resolution.
 */
void nodus_dht_keyset_note_page(nodus_dht_keyset_t *ks, bool more, bool trusted,
                                size_t responder_budget, const uint64_t *nx,
                                const nodus_dht_merge_stats_t *stats);

/**
 * Resolve a keyset into the rows a reply carries; ownership of the rows
 * moves to *rows_out (heap array, NULL when empty), every other candidate
 * is freed and the candidate list emptied.
 *
 * Candidates are grouped by PK; within a group they are tried in rank
 * order (seq DESC signed, SHA3-256(data) DESC, then type, ttl, signature,
 * owner_pk bytes — a total order) and the first that verifies (or is a
 * local row) is the group's row; a group with none is dropped. Each verify
 * spends one unit of *verify_left.
 *
 * R-b: the first failed verify of a row discards every source that sent
 * it — their still-undecided candidates are dropped without a verify
 * (unless another, not discarded source sent the same exact row) and their
 * page notes no longer count (bound, more). Rows already settled valid stay.
 *
 * R-a: with the budget spent the walk goes on; within a group a candidate
 * still undecided is passed over and the best already-valid one taken
 * (local rows are always valid, so a local row is never dropped); a group
 * with no valid candidate and an undecided one is "undecided".
 *
 * Paged (S3): groups in PK order; the bound is the smallest last PK of a
 * bounding, not discarded source (nodus_dht_keyset_note_page) whose group
 * resolves to a valid row — a bound at a PK with no valid row is discarded
 * and the next one taken. Exception (R-a): a bound PK left undecided by the
 * budget is KEPT as the bound (conservative: a smaller page, never a
 * skipped row). Rows past the bound are cut; rows are added while the
 * cumulative NODUS_VALUE_SERIALIZED_EST stays <= budget (the first row
 * always). A failed verify drops only that candidate (and R-b) and the
 * walk continues. The page closes before the first undecided group (the
 * cursor must not pass a row nobody could check). page_out: more = a row
 * was cut, the page closed undecided, or any not-discarded source said more
 * — and only when the page is not empty; next = last kept PK.
 *
 * Unpaged: every group is resolved; undecided groups are skipped; rows are
 * returned in the order their PK first arrived (local rows first, then
 * forwarded), the order these replies had before Package A. page_out may
 * be NULL.
 * *capped_out (may be NULL): the verify budget ran out with a group the
 * walk needed still undecided — with no row out, the read could not look.
 * @return 0, or -1 on allocation failure (candidates freed, nothing out).
 */
int nodus_dht_keyset_resolve(nodus_dht_keyset_t *ks, bool paged, size_t budget,
                             int *verify_left,
                             nodus_value_t ***rows_out, size_t *count_out,
                             nodus_t2_page_info_t *page_out, bool *capped_out);

/** Single-GET rank: 1 when cand ranks above best. Order: (exclusive_first:
 *  EXCLUSIVE type first), seq DESC (signed), SHA3-256(data) DESC, owner_fp
 *  ASC, value_id ASC (signed). best == NULL → 1. */
int nodus_dht_single_better(const nodus_value_t *cand, const nodus_value_t *best,
                            bool exclusive_first);

/** S1 single GET: the best-ranked candidate (nodus_dht_single_better, ties
 *  broken by type, ttl, signature, owner_pk bytes) that verifies (or is a
 *  local row), trying candidates in rank order and spending *verify_left
 *  (R-b discards apply as in nodus_dht_keyset_resolve). R-a: with the
 *  budget spent, undecided candidates are passed over and the best
 *  already-valid one (e.g. the local row) is returned.
 *  Ownership of the returned value moves to the caller; every other
 *  candidate is freed and the keyset emptied. NULL when none qualifies.
 *  *capped_out (may be NULL): an undecided candidate was passed over for
 *  lack of budget — with NULL returned, the read could not look. */
nodus_value_t *nodus_dht_keyset_pick_best(nodus_dht_keyset_t *ks,
                                          bool exclusive_first, int *verify_left,
                                          bool *capped_out);

/** S6, rev 2 item 13: rows > 0 → ROWS; answered > 0 → EMPTY (some source
 *  looked and found nothing); peers == 0 and the local store was read →
 *  EMPTY (nobody else holds the key: single-node truth); anything else →
 *  UNAVAILABLE (a local fault with no other answer, or peers to ask and
 *  none answered: no slot, alloc failure, every forward failed / timed out
 *  / answered "u"). */
nodus_dht_read_outcome_t nodus_dht_read_outcome(size_t rows, int peers,
                                                int answered, bool local_fault);

/** Set up an idle batch slot for `n` keys (copied): zeroes it, forwards fd
 *  -1, allocates keys + one empty keyset per key, verify_left =
 *  NODUS_DHT_VERIFY_CAP, active. @return 0, -1 on alloc failure (slot
 *  left idle and zeroed). */
int nodus_server_bf_batch_setup(dht_bf_batch_t *b, const nodus_key_t *keys, int n);

/** Free everything a batch slot holds (forward sockets, keysets) and make
 *  it idle. */
void nodus_server_bf_batch_cleanup(nodus_server_t *srv, dht_bf_batch_t *b);

/**
 * Absorb one decrypted 4002 reply payload (T2 CBOR) of forward `c` into
 * batch `b`: each "batch" entry is matched to a key THIS forward asked for
 * by key AND position among identical keys (rev 2 item 16); an entry with
 * "u" counts as not looked (item 13/15); otherwise the key gains one
 * answered source, its rows go through nodus_dht_keyset_add_ex (+ the page
 * note for paged reads, responder budget NODUS_GET_ALL_PAGE_MAX_BYTES /
 * the forward's key count — the responder's own split — and the entry's
 * "nx" when sent). Row cap per source (R-e): paged, what the responder
 * budget can hold (budget / NODUS_VALUE_SERIALIZED_EST(0) + 1, the first
 * row always); unpaged, NODUS_DHT_SRC_MAX_ROWS.
 * @return 0 when the payload was a batch result, -1 otherwise (nothing
 *         absorbed: an error frame, garbage).
 */
int nodus_server_bf_absorb_reply(dht_bf_batch_t *b, const dht_bf_conn_t *c,
                                 const uint8_t *payload, size_t len);

/** A3: header check of the batch-forward receive buffer (bf_recv_frame).
 *  Parses the frame header with the transport's decoder (nodus_frame_decode:
 *  magic, little-endian length) and nodus_frame_validate (version, TCP
 *  size limit). @return 1 when buf holds a complete frame, 0 when more bytes
 *  are needed, -1 on bad magic / version / size, or when the declared frame
 *  (header + payload) is larger than `cap` — the receive buffer could never
 *  hold it. */
int nodus_server_bf_frame_status(const uint8_t *buf, size_t len, size_t cap);

/** Resolve batch `b` and encode the frame its client gets (result /
 *  result_empty / result_multi / result_page / result batch with "u"
 *  markers / UNAVAILABLE error) into buf. Keysets are consumed. bf_send_result
 *  sends exactly this frame. @return 0, -1 on encode failure. */
int nodus_server_bf_encode_result(dht_bf_batch_t *b, uint8_t *buf, size_t cap,
                                  size_t *len_out);

/** F1: a 4002 conn is going away — close every inter-circuit routed over
 *  it, tell the attached local client (circ_open_err while the open is
 *  pending, else circ_close) and unlink the client's circuit. Called by
 *  the inter-port disconnect callback before the conn is freed. */
void nodus_server_inter_conn_closed(nodus_server_t *srv,
                                    const nodus_tcp_conn_t *conn);

/** F1: free pending_open inter-circuits older than max_age_ms, unlinking
 *  the attached client circuit first (circ_open_err TIMEOUT to the client).
 *  @return number freed */
int nodus_server_inter_sweep_orphans(nodus_server_t *srv, uint64_t now_ms,
                                     uint64_t max_age_ms);

/** The 4002 frame dispatcher (F2/F3 gates), for in-process gate tests. */
void nodus_server_dispatch_inter_frame(nodus_server_t *srv,
                                       nodus_inter_session_t *sess,
                                       const uint8_t *payload, size_t len);

/** The body of the 4002 transport's on_disconnect callback (F1 circuit
 *  release + inter session clear), for in-process tests. */
void nodus_server_inter_disconnected(nodus_server_t *srv, nodus_tcp_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_SERVER_H */
