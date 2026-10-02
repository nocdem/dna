/**
 * Nodus — DHT / storage half of the server (component split S4)
 *
 * Decision docs/plans/decisions/2026-10-01-nodus-component-split.md
 * items 2-4, 16, 17: the server's DHT half — Kademlia routing, the
 * iterative lookup engine, replication / republish / hinted handoff,
 * listen subscriptions, batch forward, nodus.db (values + media) and
 * channels.db — lives in its own state (nodus_dht_t) and reaches the rest
 * of the node (core: identity, sessions, the 4001 / WebSocket / 4002 /
 * UDP 4000 sockets, cluster membership, presence) ONLY through the host
 * view below (nodus_dht_host_t, DHT → core). Core reaches the DHT only
 * through server/nodus_dht_backend.h (core → DHT). Neither direction
 * hands over a pointer into the other side's state: a session is an
 * ORIGIN (a slot number + its generation), a peer is (node id, ip, ports), a frame is
 * bytes. Step S5 runs this half as the `nodus-storage` process by putting
 * an IPC implementation behind the same two doors.
 *
 * Every function here runs on the server's single event-loop thread.
 *
 * @file nodus_dht.h
 */

#ifndef NODUS_DHT_H
#define NODUS_DHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"       /* NODUS_TCP_MAX_CONNS (session slots) */
#include "core/nodus_routing.h"
#include "core/nodus_storage.h"
#include "core/nodus_media_storage.h"
#include "channel/nodus_hashring.h"
#include "channel/nodus_channel_store.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_channel_crypto.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"   /* nodus_t2_cursor_t / page info (DHT Package A) */

#ifdef __cplusplus
extern "C" {
#endif

/* Session slots: one per connection of the client transport (4001 +
 * WebSocket) and of the inter-node transport (4002). A slot number and the
 * generation of the session in it are the ORIGIN of a request
 * (nodus_dht_origin_t). */
#define NODUS_MAX_SESSIONS        NODUS_TCP_MAX_CONNS
#define NODUS_MAX_INTER_SESSIONS  NODUS_TCP_MAX_CONNS
#define NODUS_MAX_LISTEN_KEYS     128    /* Per session */

struct nodus_dht;   /* nodus_dht_t, below */

/* ── Listen Forwarding (Scribe pattern) ─────────────────────────── */

#define NODUS_MAX_SUBSCRIPTIONS  4096
#define NODUS_SUBSCRIPTION_TTL   900     /* 15 min — must be > 2x renewal interval */

/* ── Origins ─────────────────────────────────────────────────────── */

/** Which transport a request came in on. */
typedef enum {
    NODUS_DHT_ORIGIN_CLIENT = 0,   /**< client port 4001 / WebSocket entry */
    NODUS_DHT_ORIGIN_INTER  = 1    /**< inter-node port 4002 */
} nodus_dht_origin_kind_t;

/**
 * The origin of a request and the destination of its replies: the slot of
 * that connection in its transport (core's session index) and the
 * GENERATION of the session that held the slot. An opaque id, never a
 * pointer into core.
 *
 * The generation is what tells two occupants of one slot apart. Core
 * gives every session it opens (client accept, 4002 connect / accept) a
 * fresh value from one server-wide counter that only increases (first
 * live value 1; 0 = a cleared slot, or one no open ever reached) and
 * hands it over in nodus_dht_session_opened. A reply the DHT sends LATER
 * (a forwarded get / get_all / get_batch, an iterative lookup's
 * completion) carries the origin recorded when the request came in: the
 * DHT drops it unless the slot's shadow is open AND has that generation,
 * and core's send_to_origin writes it only to a session of that same
 * generation. A client accepted into a reused slot therefore never
 * receives the previous client's deferred reply (nodus/BUGS.md, decision
 * 2026-10-01-nodus-component-split.md item 29). A reply sent while the
 * request is being handled carries the slot's current generation.
 */
typedef struct {
    nodus_dht_origin_kind_t kind;
    int                     slot;
    uint64_t                gen;
} nodus_dht_origin_t;

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
    nodus_dht_origin_t  origin;             /**< Client session (slot + generation);
                                             *   slot -1 = internal lookup */
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
    void              (*on_complete)(struct nodus_dht *dht,
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
 *  65536, nodus_dht_server.c; bf_start_forward recv_cap), and every forwarded
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
    nodus_dht_origin_t origin;       /**< Client session (slot + generation) the
                                      *   result goes to */
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

/** Batch forward state (part of nodus_dht_t) */
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

/* ── The host view, the session shadows ──────────────────────────── */

/**
 * The DHT's view of core (DHT → core). Core fills it
 * (nodus_server_dht_host); split S5 puts the storage process's IPC calls
 * behind the same members. HOT = per client put / get or per replicated
 * value; COLD = periodic or on failure only.
 */
typedef struct {
    /** This node's identity, read only: node_id (routing, self-skips), pk
     *  and sk (the batch-forward dialer's hello / auth). Configuration, not
     *  a crossing — split S5 loads it read-only in the storage process
     *  (decision items 10, 16). Must outlive the DHT. */
    const nodus_identity_t *identity;
    void                   *ctx;

    /** HOT — write one encoded reply / push frame to the session in
     *  `origin`'s slot (nodus_tcp_send) when that session has `origin`'s
     *  generation. Returns that send's result (-1 when the slot holds no
     *  connection, or a session of another generation — nothing sent). */
    int  (*send_to_origin)(void *ctx, nodus_dht_origin_t origin,
                           const uint8_t *frame, size_t len);

    /** HOT in a large cluster (iterative lookups), COLD at 7 nodes — send
     *  one T1 datagram from the UDP 4000 socket (raw CBOR; the transport
     *  frames it). 0 sent, -1 not. */
    int  (*udp_send)(void *ctx, const uint8_t *payload, size_t len,
                     const char *ip, uint16_t port);

    /** HOT (every put × R, every republished value, every remote listener
     *  notify) — send one PRE-FRAMED frame to a peer's 4002 over the node's
     *  persistent inter-node pool, dialing it (and pinning
     *  `expected_peer_id`) when there is no connection. SYNCHRONOUS: 0
     *  queued / written, -1 failed — the caller decides on hinted handoff
     *  from this result in the same call. */
    int  (*inter_send)(void *ctx, const char *ip, uint16_t port,
                       const nodus_key_t *expected_peer_id,
                       const uint8_t *frame, size_t flen);

    /** COLD (after a failed send only) — true when a failed send to
     *  `node_id` is worth a hint: a member of this node's cluster (DHT
     *  Package A rev 2 item 9) last seen less than
     *  NODUS_HINT_OFFLINE_SKIP_SEC ago. Cluster membership is core's
     *  (decision item 4). */
    bool (*hint_wanted)(void *ctx, const nodus_key_t *node_id);
} nodus_dht_host_t;

/**
 * The DHT's shadow of one CLIENT session; core holds the session itself
 * (connection, identity, token, circuits). Indexed by slot.
 *
 * `open` mirrors "core's session in this slot has a connection": core calls
 * nodus_dht_session_opened where it sets `sess->conn` (accept) and
 * nodus_dht_session_closed where it clears the session (disconnect). Before
 * the split the DHT read `sess->conn`, and for listeners also
 * `sess->authenticated`; `open` alone answers the same, because
 * listen_keys are only ever added by an authenticated session (`listen` is
 * served after the token check) and every path that ends a session's
 * authentication clears its slot (disconnect, and the same-identity
 * eviction, which disconnects synchronously — nodus_auth.c).
 */
typedef struct {
    bool                open;
    uint64_t            gen;     /**< the open session's generation
                                  *   (nodus_dht_origin_t); 0 when closed */

    /* LISTEN subscriptions (DHT keys) */
    nodus_key_t         listen_keys[NODUS_MAX_LISTEN_KEYS];
    int                 listen_count;

    /* Rate limiting */
    uint64_t            rate_window_start;
    int                 puts_in_window;
} nodus_dht_session_t;

/** The DHT's shadow of one 4002 session: the per-session rate windows of
 *  the DHT methods (`sv` and `m_sv` share the sv window). Zeroed where
 *  core opens or clears that session; `gen` is then the opened session's
 *  generation (nodus_dht_origin_t; 0 when cleared). */
typedef struct {
    uint64_t            gen;
    uint64_t            sv_window_start;
    int                 sv_count;
    uint64_t            fv_window_start;
    int                 fv_count;
} nodus_dht_inter_session_t;

/** What core saw of a peer on UDP 4000 or in its cluster
 *  (nodus_dht_peer_seen). Four kinds, so the routing updates keep the
 *  exact order they had around core's cluster update before the split. */
typedef enum {
    /** A T1 ping arrived (core answered the pong): routing insert —
     *  ping-before-evict when the bucket is full — then the pending
     *  eviction of that peer is cancelled. Core updates its cluster AFTER
     *  this. */
    NODUS_DHT_PEER_PING       = 0,
    /** A T1 pong arrived, step one — BEFORE core updates its cluster:
     *  routing touch. */
    NODUS_DHT_PEER_PONG_TOUCH = 1,
    /** The same pong, step two — AFTER core updated its cluster: the
     *  pending eviction is cancelled, then routing insert (ping-before-
     *  evict when full). */
    NODUS_DHT_PEER_PONG       = 2,
    /** Core's cluster saw a member turn ALIVE (nodus_cluster_on_pong):
     *  plain routing insert, so replication finds it at once. */
    NODUS_DHT_PEER_ALIVE      = 3
} nodus_dht_peer_seen_t;

/** One routing-table peer address (nodus_dht_routing_snapshot) — what
 *  core's presence sync dials. `node_id` is the routing entry's identity:
 *  the dial pins it as the expected peer (CRIT-1; decision
 *  2026-10-01-nodus-component-split item 30). */
typedef struct {
    nodus_key_t node_id;
    char        ip[64];
    uint16_t    tcp_port;
} nodus_dht_peer_addr_t;

/* ── The DHT state ───────────────────────────────────────────────── */

typedef struct nodus_dht {
    nodus_dht_host_t        host;

    /* Storage */
    nodus_storage_t         storage;
    nodus_media_storage_t   media_storage;
    nodus_channel_store_t   ch_store;
    nodus_routing_t         routing;
    nodus_hashring_t        ring;
    /* Which of the three databases nodus_dht_open opened (nodus_dht_close
     * closes exactly those). */
    bool                    storage_open;
    bool                    media_open;
    bool                    ch_open;

    /* Session shadows (indexed by slot = origin) */
    nodus_dht_session_t         sessions[NODUS_MAX_SESSIONS];
    nodus_dht_inter_session_t   inter_sessions[NODUS_MAX_INTER_SESSIONS];

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

    /* DB maintenance timers */
    uint64_t                last_wal_checkpoint;
    uint64_t                last_vacuum;
} nodus_dht_t;

/* ── Lifecycle (driven by server/nodus_dht_backend_inproc.c) ─────── */

/**
 * Phase one, run where nodus_server_init set this state up before the
 * split (BEFORE the identity is loaded): zero `dht`, copy `host`, every
 * batch-forward fd to -1, jitter the first republish cycles, start the
 * lookup txn counter, create the batch-forward epoll, clear its fd table.
 * @return 0, or -1 when the epoll cannot be created (logged; nothing is
 *         left open).
 */
int nodus_dht_init(nodus_dht_t *dht, const nodus_dht_host_t *host);

/**
 * Phase two, AFTER the identity is loaded (routing is keyed by node_id):
 * open nodus.db (values, then media on the same handle) and channels.db
 * under data_path ("/tmp" when empty), register the default channels, init
 * the routing table and the hash ring with this node at
 * self_ip:self_peer_port.
 * @return 0, or -1 when a database does not open (logged; what did open
 *         stays open for nodus_dht_close).
 */
int nodus_dht_open(nodus_dht_t *dht, const char *data_path,
                   const char *self_ip, uint16_t self_peer_port);

/** Abandon every in-flight lookup (its cb_data freed) and every batch
 *  forward, close the batch-forward epoll. First step of a shutdown. */
void nodus_dht_stop(nodus_dht_t *dht);

/** Close the databases nodus_dht_open opened (media, values, channels) and
 *  the batch-forward epoll when nodus_dht_stop has not. */
void nodus_dht_close(nodus_dht_t *dht);

/* ── Core → DHT: each call is one message of the seam ────────────── *
 *
 * In-process the decoded message (`msg` / `t1`) is passed along so the
 * frame is not parsed twice; it is transient request data, not state. An
 * IPC implementation (split S5) carries the frame's bytes and the storage
 * side decodes them with the same decoder. `slot` out of range → the call
 * does nothing. */

/** COLD — core's session in `origin`'s slot got a connection (accept /
 *  dial) — the slot's shadow starts empty, with `origin.gen` as its
 *  generation. */
void nodus_dht_session_opened(nodus_dht_t *dht, nodus_dht_origin_t origin);

/** COLD — core cleared the session in `origin`'s slot (disconnect) — the
 *  shadow is emptied (listen keys, rate windows, generation), whatever
 *  `origin.gen` says. Lookups and batch forwards started for that slot
 *  notice on their next tick, or when they would reply. */
void nodus_dht_session_closed(nodus_dht_t *dht, nodus_dht_origin_t origin);

/**
 * HOT — an authenticated client request with a DHT method: put, get,
 * get_all, get_batch, cnt_batch, listen, unlisten, ch_list, ch_search,
 * ch_get, m_put, m_meta, m_chunk. `client_fp` / `client_pk`: the session's
 * authenticated identity (split S5: the origin socket's preface). Replies
 * go to (CLIENT, slot).
 */
void nodus_dht_client_request(nodus_dht_t *dht, int slot,
                              const nodus_key_t *client_fp,
                              const nodus_pubkey_t *client_pk,
                              nodus_tier2_msg_t *msg);

/**
 * HOT — a T2 frame from a 4002 peer with a DHT method: `fv` (re-read from
 * `payload` as T1), `get_batch` (a forwarded read; answered from local
 * storage only), `m_sv` (a replicated media chunk; `msg->has_media`).
 * Replies go to (INTER, slot).
 */
void nodus_dht_inter_request(nodus_dht_t *dht, int slot,
                             const uint8_t *payload, size_t len,
                             nodus_tier2_msg_t *msg);

/**
 * HOT — a T1 frame from a 4002 peer that passed core's F2 gate: `sv`
 * (replication), `sub` / `unsub` (a remote listener), `ntf` (a notify for a
 * local listener). `peer_fp`: the peer's authenticated identity as core's
 * session holds it (zero when none); `peer_ip`: its connection's address
 * ("" when none).
 */
void nodus_dht_inter_t1(nodus_dht_t *dht, int slot,
                        const nodus_key_t *peer_fp, const char *peer_ip,
                        nodus_tier1_msg_t *t1);

/** HOT-ish — a T1 datagram on UDP 4000 that is not ping / pong: `fn`,
 *  `fn_r`, `sv`, `fv`. Replies leave through the host's udp_send. */
void nodus_dht_udp_request(nodus_dht_t *dht, const char *from_ip,
                           uint16_t from_port, nodus_tier1_msg_t *msg);

/** COLD — see nodus_dht_peer_seen_t. tcp_port is the peer's 4002. */
void nodus_dht_peer_seen(nodus_dht_t *dht, nodus_dht_peer_seen_t kind,
                         const nodus_key_t *node_id, const char *ip,
                         uint16_t udp_port, uint16_t tcp_port);

/** COLD — core's cluster marked a member DEAD: it leaves the routing table
 *  (no stale replication target). */
void nodus_dht_peer_dead(nodus_dht_t *dht, const nodus_key_t *node_id);

/** COLD — park one framed 4002 frame core's inter-node transport could not
 *  queue (pending-full) in the hinted-handoff table for `node_id`.
 *  @return nodus_storage_hinted_insert's result (0 parked,
 *          NODUS_STORAGE_RC_QUOTA a cap is reached, other -1). */
int nodus_dht_hint_store(nodus_dht_t *dht, const nodus_key_t *node_id,
                         const char *ip, uint16_t port,
                         const uint8_t *frame, size_t len);

/** COLD (every NODUS_PRESENCE_SYNC_SEC) — the routing table's peers
 *  (node id + address), active entries in bucket order, at most `max`,
 *  read at the moment of the call. @return the count written. */
int nodus_dht_routing_snapshot(const nodus_dht_t *dht,
                               nodus_dht_peer_addr_t *out, int max);

/** Ping-before-evict: evict the routing LRU peers that did not answer —
 *  the server loop runs it right after the cluster tick. */
void nodus_dht_evict_tick(nodus_dht_t *dht);

/** The DHT's periodic work, in this order: hinted-handoff retry,
 *  subscription cleanup (60 s) and renewal, lookup engine, batch forward,
 *  bucket refresh, storage cleanup, republish, media republish, WAL
 *  checkpoint, incremental vacuum — the server loop runs it right after
 *  the presence tick. */
void nodus_dht_tick(nodus_dht_t *dht);

/* ── Inside the DHT (shared with the media handlers' TU) ─────────── */

/** Send one encoded frame to (CLIENT, slot) while its request is being
 *  handled: the slot's current generation. */
static inline int nodus_dht_send_client(nodus_dht_t *dht, int slot,
                                        const uint8_t *frame, size_t len) {
    nodus_dht_origin_t o = { NODUS_DHT_ORIGIN_CLIENT, slot,
                             dht->sessions[slot].gen };
    return dht->host.send_to_origin(dht->host.ctx, o, frame, len);
}

/** Replicate a DHT value to the K-closest Kademlia peers (client put). */
void nodus_dht_replicate_value(nodus_dht_t *dht, const nodus_value_t *val);

/** Replicate a media chunk to the K-closest Kademlia peers (after each
 *  chunk of a client upload, and the paced media republish). */
void nodus_dht_replicate_media_chunk(nodus_dht_t *dht,
                                     const nodus_media_meta_t *meta,
                                     uint32_t chunk_index,
                                     const uint8_t *data, size_t data_len);

/* ════════════════════════════════════════════════════════════════════
 * INTERNAL — DHT Package A helpers. Exposed ONLY so unit tests can drive
 * them in-process (tests/test_bf_merge_pure.c, test_get_all_paging.c,
 * test_get_unavailable.c, test_bf_forward_frames.c,
 * test_bf_recv_frame.c, test_origin_gen.c). Not an API: no other module
 * calls these.
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
int nodus_dht_bf_batch_setup(dht_bf_batch_t *b, const nodus_key_t *keys, int n);

/** Free everything a batch slot holds (forward sockets, keysets) and make
 *  it idle. */
void nodus_dht_bf_batch_cleanup(nodus_dht_t *dht, dht_bf_batch_t *b);

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
int nodus_dht_bf_absorb_reply(dht_bf_batch_t *b, const dht_bf_conn_t *c,
                                 const uint8_t *payload, size_t len);

/** A3: header check of the batch-forward receive buffer (bf_recv_frame).
 *  Parses the frame header with the transport's decoder (nodus_frame_decode:
 *  magic, little-endian length) and nodus_frame_validate (version, TCP
 *  size limit). @return 1 when buf holds a complete frame, 0 when more bytes
 *  are needed, -1 on bad magic / version / size, or when the declared frame
 *  (header + payload) is larger than `cap` — the receive buffer could never
 *  hold it. */
int nodus_dht_bf_frame_status(const uint8_t *buf, size_t len, size_t cap);

/** Resolve batch `b` and encode the frame its client gets (result /
 *  result_empty / result_multi / result_page / result batch with "u"
 *  markers / UNAVAILABLE error) into buf. Keysets are consumed. bf_send_result
 *  sends exactly this frame. @return 0, -1 on encode failure. */
int nodus_dht_bf_encode_result(dht_bf_batch_t *b, uint8_t *buf, size_t cap,
                               size_t *len_out);

/** A batch forward is done (every forward answered, failed or timed out):
 *  send its client the frame nodus_dht_bf_encode_result builds — only when
 *  the slot of `b->origin` is still open with that origin's generation —
 *  and free the batch (idle afterwards, either way). Item 29: tests/
 *  test_origin_gen.c drives it. */
void nodus_dht_bf_send_result(nodus_dht_t *dht, dht_bf_batch_t *b);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_DHT_H */
