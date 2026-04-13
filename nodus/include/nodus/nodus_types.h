/**
 * Nodus — Core Type Definitions
 *
 * SHA3-512 key space (512-bit, 64 bytes).
 * Dilithium5 (ML-DSA-87) signatures throughout.
 *
 * @file nodus_types.h
 */

#ifndef NODUS_TYPES_H
#define NODUS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Protocol constants ──────────────────────────────────────────── */

#define NODUS_VERSION_MAJOR  0
#define NODUS_VERSION_MINOR  10
#define NODUS_VERSION_PATCH  45
#define NODUS_VERSION_STRING "0.10.45"

/* Wire frame */
#define NODUS_FRAME_MAGIC       0x4E44      /* "ND" */
#define NODUS_FRAME_VERSION     0x01
#define NODUS_FRAME_HEADER_SIZE 7           /* magic(2) + ver(1) + len(4) */
#define NODUS_MAX_FRAME_TCP     (5 * 1024 * 1024)  /* 5 MB (value + overhead) */
#define NODUS_MAX_FRAME_UDP     1400        /* Safe MTU */

/* Kademlia */
#define NODUS_KEY_BYTES         64          /* SHA3-512 = 64 bytes */
#define NODUS_KEY_HEX_LEN      129         /* 128 hex chars + NUL */
#define NODUS_KEYSPACE_BITS     512
#define NODUS_K                 8           /* Bucket size */
#define NODUS_R                 8           /* Replication factor (= K, Kademlia spec) */
#define NODUS_BUCKETS           512         /* One per key-space bit */
#define NODUS_ALPHA             3           /* Parallel lookups */

/* Crypto sizes (Dilithium5 / ML-DSA-87) */
#define NODUS_PK_BYTES          2592        /* Public key */
#define NODUS_SK_BYTES          4896        /* Secret key */
#define NODUS_SIG_BYTES         4627        /* Signature */
#define NODUS_SEED_BYTES        32          /* Identity seed */

/* Crypto sizes (Kyber1024 / ML-KEM-1024) — channel encryption */
#define NODUS_KYBER_PK_BYTES    1568        /* Kyber public key */
#define NODUS_KYBER_SK_BYTES    3168        /* Kyber secret key */
#define NODUS_KYBER_CT_BYTES    1568        /* Kyber ciphertext */
#define NODUS_KYBER_SS_BYTES    32          /* Kyber shared secret */

/* Networking */
#define NODUS_DEFAULT_UDP_PORT  4000
#define NODUS_DEFAULT_TCP_PORT  4001
#define NODUS_DEFAULT_PEER_PORT 4002
#define NODUS_DEFAULT_CH_PORT   4003        /* Channel client TCP port */
#define NODUS_DEFAULT_WITNESS_PORT 4004     /* Witness BFT TCP port */
#define NODUS_SESSION_TOKEN_LEN 32
#define NODUS_NONCE_LEN         32

/* DHT value limits */
#define NODUS_DEFAULT_TTL       604800      /* 7 days in seconds */
#define NODUS_PERMANENT_TTL     0           /* 0 = never expires */
#define NODUS_MAX_VALUE_SIZE    (4 * 1024 * 1024)   /* 4 MB value payload */
#define NODUS_MAX_VALUES_PER_OWNER 10000

/* Channel limits */
#define NODUS_UUID_BYTES        16          /* UUID v4 */
#define NODUS_MAX_POST_BODY     4000        /* UTF-8 chars */
#define NODUS_CHANNEL_RETENTION (7 * 86400) /* 7 days */
#define NODUS_MAX_HINTED_POSTS  1000
#define NODUS_HINTED_RETRY_SEC  60
#define NODUS_HINT_MAX_RETRIES  1       /* Delete hint after N failed delivery attempts */
#define NODUS_HINTED_TTL_SEC    86400       /* 24h */
#define NODUS_MAX_CH_SESSIONS   1024        /* Max channel TCP 4003 connections (must match NODUS_TCP_MAX_CONNS) */

/* Rate limiting defaults */
#define NODUS_RATE_PUTS_PER_MIN  60
#define NODUS_RATE_MAX_LISTENERS 100
#define NODUS_RATE_MAX_CONNS     1000

/* Cluster heartbeat */
#define NODUS_CLUSTER_HEARTBEAT_SEC 10
#define NODUS_CLUSTER_SUSPECT_SEC   30

/* DHT replication */
#define NODUS_ROUTING_STALE_SEC    3600    /* 1 hour — filter stale entries in find_closest */
#define NODUS_BUCKET_REFRESH_SEC   900     /* 15 min — bucket refresh via FIND_NODE */
#define NODUS_REPUBLISH_SEC        600     /* 10 min — periodic republish cycle */
#define NODUS_MEDIA_REPUBLISH_SEC  14400   /* 4 hours — media republish (immutable, less frequent) */
#define NODUS_REPUBLISH_BATCH      5       /* Values per main loop tick during republish */
#define NODUS_CLEANUP_SEC          3600    /* 1 hour — storage cleanup interval */
#define NODUS_WAL_CHECKPOINT_SEC   300     /* 5 min — WAL checkpoint interval */
#define NODUS_VACUUM_SEC           3600    /* 1 hour — incremental vacuum interval */
#define NODUS_STATS_DUMP_SEC       300     /* 5 min — send diagnostics dump interval */

/* Send-path backpressure (Phase 3): pending queue + hint fallback */
#define NODUS_PENDING_MAX_FRAMES   20                     /* per-conn frame queue cap */
#define NODUS_PENDING_MAX_BYTES    (32ULL * 1024 * 1024)  /* per-conn bytes queue cap (32 MB) */
#define NODUS_DRAIN_PER_CALL       10                     /* max pending frames promoted per handle_write */
#define NODUS_HINT_OFFLINE_SKIP_SEC 3600   /* 1 hour — skip hinted handoff for long-offline peers */
#define NODUS_REPLICATION_MIN      3      /* Min successful sends before skipping hinted handoff */

/* Iterative Kademlia FIND_NODE lookup engine (UDP-based). Replaces the
 * old TCP FIND_VALUE state machine. Values are fetched via BF forward
 * over TCP after FIND_NODE discovers the K-closest peers. */
#define NODUS_LOOKUP_MAX_INFLIGHT      32      /* Max concurrent iterative lookups */
#define NODUS_LOOKUP_TIMEOUT_MS        10000   /* Overall per-lookup timeout */
#define NODUS_LOOKUP_QUERY_TIMEOUT_MS  3000    /* Per-UDP-query timeout */
#define NODUS_LOOKUP_MAX_CANDIDATES    128     /* Shortlist size (K*16) */
#define NODUS_LOOKUP_MAX_QUERIED       128     /* Visited/queried set size */
#define NODUS_LOOKUP_CONVERGE_ROUNDS   3       /* Rounds with unchanged closest_k → done */
#define NODUS_UDP_MAX_VALUE_SIZE       1200    /* Max value size to return via UDP */

#define NODUS_SV_MAX_PER_SEC       200     /* Rate limit inter-node STORE_VALUE */
#define NODUS_FV_MAX_PER_SEC       100     /* Rate limit UDP FIND_VALUE responses */

/* Wire array count caps (HIGH-13: prevent OOM from untrusted CBOR counts) */
#define NODUS_MAX_WIRE_FPS         1000    /* Max fingerprints per message */
#define NODUS_MAX_WIRE_VALUES      10000   /* Max values per message */
#define NODUS_MAX_WIRE_POSTS       10000   /* Max channel posts per message */
#define NODUS_MAX_BATCH_KEYS       32      /* Max keys per get_batch request */

/* Tier 3: Witness/BFT consensus (DNAC) */
#define NODUS_T3_MAX_WITNESSES      128
#define NODUS_T3_MIN_WITNESSES      5
#define NODUS_T3_WITNESS_ID_LEN     32
#define NODUS_T3_NULLIFIER_LEN      64      /* SHA3-512 */
#define NODUS_T3_TX_HASH_LEN        64      /* SHA3-512 */
#define NODUS_T3_MAX_TX_SIZE        65536   /* 64 KB serialized TX */
#define NODUS_T3_MAX_TX_INPUTS      16
#define NODUS_T3_MAX_TX_OUTPUTS     16
#define NODUS_T3_MAX_TX_WITNESSES   3
#define NODUS_T3_ROUND_TIMEOUT_MS   15000
#define NODUS_T3_VIEWCHG_TIMEOUT_MS 10000
#define NODUS_T3_MAX_VIEW_CHANGES   3
#define NODUS_T3_EPOCH_DURATION_SEC 60      /* DNAC epoch = 60s */
#define NODUS_T3_BFT_PROTOCOL_VER   2

/* Token creation fee: 1 DNAC (100M raw units) */
#define NODUS_W_TOKEN_CREATE_FEE  100000000ULL

/* Block production (mempool + batch) */
#define NODUS_W_BLOCK_INTERVAL_MS   5000    /* 5s between block proposals */
#define NODUS_W_MAX_MEMPOOL         64      /* max pending TXs in mempool */
#define NODUS_W_MAX_BLOCK_TXS       10      /* max TXs per batch/block */
#define NODUS_W_MAX_PENDING_FWD     16      /* max pending forward slots */

/* Burn address: all-zero fingerprint (128 hex zero = 64 bytes zero)
 * Fee UTXOs are recorded here. Unspendable — no private key exists. */
#define DNAC_BURN_ADDRESS \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "0000000000000000000000000000000000000000000000000000000000000000"

/* Circuit (VPN mesh) — Faz 1 */
#define NODUS_MAX_CIRCUITS_PER_SESSION   16
#define NODUS_MAX_CIRCUIT_PAYLOAD        (64 * 1024)
#define NODUS_INTER_CIRCUITS_MAX         256
#define NODUS_CIRCUIT_OPEN_TIMEOUT_MS    5000   /* Bounded wait for circ_open ack */

/* TCP keepalive */
#define NODUS_TCP_KEEPIDLE       30
#define NODUS_TCP_KEEPINTVL      10
#define NODUS_TCP_KEEPCNT        3

/* ── Core types ──────────────────────────────────────────────────── */

/** 512-bit key (SHA3-512) — used for node IDs, DHT keys, fingerprints */
typedef struct {
    uint8_t bytes[NODUS_KEY_BYTES];
} nodus_key_t;

/** Dilithium5 public key */
typedef struct {
    uint8_t bytes[NODUS_PK_BYTES];
} nodus_pubkey_t;

/** Dilithium5 secret key */
typedef struct {
    uint8_t bytes[NODUS_SK_BYTES];
} nodus_seckey_t;

/** Dilithium5 signature */
typedef struct {
    uint8_t bytes[NODUS_SIG_BYTES];
} nodus_sig_t;

/** Nodus identity (keypair + derived node_id) */
typedef struct {
    nodus_pubkey_t pk;
    nodus_seckey_t sk;
    nodus_key_t    node_id;     /* SHA3-512(pk) */
    char           fingerprint[NODUS_KEY_HEX_LEN];
    /* Kyber1024 for channel encryption (optional — backward compat) */
    uint8_t        kyber_pk[NODUS_KYBER_PK_BYTES];
    uint8_t        kyber_sk[NODUS_KYBER_SK_BYTES];
    bool           has_kyber;
} nodus_identity_t;

/** DHT value type */
typedef enum {
    NODUS_VALUE_EPHEMERAL = 0x01,   /* Expires after TTL */
    NODUS_VALUE_PERMANENT = 0x02,   /* Never expires */
    NODUS_VALUE_EXCLUSIVE = 0x03    /* Never expires + first-writer-owns */
} nodus_value_type_t;

/** DHT value stored on Nodus */
typedef struct {
    nodus_key_t     key_hash;       /* SHA3-512(key) */
    uint64_t        value_id;       /* Writer-specific ID */
    uint8_t        *data;           /* Payload (caller-owned) */
    size_t          data_len;
    nodus_value_type_t type;
    uint32_t        ttl;            /* Seconds (0 = permanent) */
    uint64_t        created_at;     /* Unix timestamp */
    uint64_t        expires_at;     /* 0 if permanent */
    uint64_t        seq;            /* Sequence number for updates */
    nodus_pubkey_t  owner_pk;       /* Dilithium5 public key */
    nodus_key_t     owner_fp;       /* SHA3-512(owner_pk) */
    nodus_sig_t     signature;      /* SIGN(key + data + type + ttl + vid + seq) */
} nodus_value_t;

/** Channel post (stored per-channel, ordered by received_at) */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint8_t     post_uuid[NODUS_UUID_BYTES];
    nodus_key_t author_fp;      /* SHA3-512(author_pk) */
    uint64_t    timestamp;      /* Author's claimed time */
    uint64_t    received_at;    /* Nodus receive time (ms) */
    char       *body;           /* UTF-8, max 4000 chars */
    size_t      body_len;
    nodus_sig_t signature;      /* SIGN(ch + id + ts + body) */
} nodus_channel_post_t;

/** Peer info (for routing table and discovery) */
typedef struct {
    nodus_key_t node_id;
    char        ip[64];
    uint16_t    udp_port;
    uint16_t    tcp_port;
    uint64_t    last_seen;          /* Unix timestamp */
} nodus_peer_t;

/** Message type (query / response / error) */
typedef enum {
    NODUS_MSG_QUERY    = 'q',
    NODUS_MSG_RESPONSE = 'r',
    NODUS_MSG_ERROR    = 'e'
} nodus_msg_type_t;

/** Error codes */
typedef enum {
    NODUS_ERR_NOT_AUTHENTICATED = 1,
    NODUS_ERR_NOT_FOUND         = 2,
    NODUS_ERR_INVALID_SIGNATURE = 3,
    NODUS_ERR_RATE_LIMITED      = 4,
    NODUS_ERR_TOO_LARGE         = 5,
    NODUS_ERR_TIMEOUT           = 6,
    NODUS_ERR_PROTOCOL_ERROR    = 7,
    NODUS_ERR_INTERNAL_ERROR    = 8,
    NODUS_ERR_ALREADY_EXISTS    = 9,
    NODUS_ERR_CHANNEL_NOT_FOUND = 10,
    NODUS_ERR_NOT_RESPONSIBLE   = 11,
    NODUS_ERR_RING_MISMATCH     = 12,
    NODUS_ERR_DOUBLE_SPEND      = 13,
    NODUS_ERR_QUOTA_EXCEEDED    = 14,
    NODUS_ERR_KEY_OWNED         = 15,  /* EXCLUSIVE key owned by different identity */
    NODUS_ERR_CIRCUIT_LIMIT     = 16,  /* Per-session circuit cap reached */
    NODUS_ERR_CIRCUIT_NOT_FOUND = 17,  /* Unknown circuit_id */
    NODUS_ERR_PEER_OFFLINE      = 18,  /* Target peer not connected to any nodus */
    NODUS_ERR_CIRCUIT_CLOSED    = 19   /* Peer torn down circuit */
} nodus_error_t;

/** Cluster phases */
typedef enum {
    NODUS_CLUSTER_PRE_PREPARE = 1,
    NODUS_CLUSTER_PREPARE     = 2,
    NODUS_CLUSTER_COMMIT      = 3,
    NODUS_CLUSTER_VIEW_CHANGE = 4
} nodus_cluster_phase_t;

/** Ring membership change type */
typedef enum {
    NODUS_RING_ADD    = 1,
    NODUS_RING_REMOVE = 2
} nodus_ring_change_t;

/* ── DNAC Client Response Types ───────────────────────────────────── */

/** Maximum UTXO entries per query */
#define NODUS_DNAC_MAX_UTXO_RESULTS   100

/** Maximum ledger range entries per query */
#define NODUS_DNAC_MAX_RANGE_RESULTS  100

/** DNAC spend status */
typedef enum {
    NODUS_DNAC_APPROVED  = 0,
    NODUS_DNAC_REJECTED  = 1,
    NODUS_DNAC_ERROR     = 2
} nodus_dnac_status_t;

/** Spend result (returned after BFT consensus) */
typedef struct {
    nodus_dnac_status_t status;
    uint8_t  witness_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t  witness_pubkey[NODUS_PK_BYTES];
    uint8_t  signature[NODUS_SIG_BYTES];
    uint64_t timestamp;
} nodus_dnac_spend_result_t;

/** Nullifier check result */
typedef struct {
    bool     is_spent;
} nodus_dnac_nullifier_result_t;

/** Ledger entry query result */
typedef struct {
    bool     found;
    uint64_t sequence;
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t  tx_type;
    uint64_t epoch;
    uint64_t timestamp;
    uint64_t nullifier_count;
} nodus_dnac_ledger_result_t;

/** Supply state result */
typedef struct {
    uint64_t genesis_supply;
    uint64_t total_burned;
    uint64_t current_supply;
    uint64_t last_sequence;
    uint8_t  chain_id[32];
} nodus_dnac_supply_result_t;

/** UTXO entry in query response */
typedef struct {
    uint8_t  nullifier[NODUS_T3_NULLIFIER_LEN];
    char     owner[NODUS_KEY_HEX_LEN];
    uint64_t amount;
    uint8_t  token_id[64];          /* 64 bytes — zeros = native DNAC */
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint32_t output_index;
    uint64_t block_height;
} nodus_dnac_utxo_entry_t;

/** UTXO query result */
typedef struct {
    int count;
    nodus_dnac_utxo_entry_t *entries;   /* Heap-allocated, caller frees */
} nodus_dnac_utxo_result_t;

/** Ledger range entry */
typedef struct {
    uint64_t sequence;
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t  tx_type;
    uint64_t epoch;
    uint64_t timestamp;
    uint64_t nullifier_count;
} nodus_dnac_range_entry_t;

/** Ledger range query result */
typedef struct {
    uint64_t total_entries;
    int      count;
    nodus_dnac_range_entry_t *entries;  /* Heap-allocated, caller frees */
} nodus_dnac_range_result_t;

/** Transaction output in history entry */
typedef struct {
    char     owner_fp[129];
    uint64_t amount;
    uint32_t output_index;
    uint8_t  token_id[64];          /* zeros = native DNAC */
} nodus_dnac_history_output_t;

#define NODUS_DNAC_MAX_TX_OUTPUTS 8

/** Transaction history entry (per-owner query) */
typedef struct {
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t  tx_type;
    char     sender_fp[129];
    uint64_t fee;
    uint64_t block_height;
    uint64_t timestamp;
    nodus_dnac_history_output_t outputs[NODUS_DNAC_MAX_TX_OUTPUTS];
    int      output_count;
} nodus_dnac_history_entry_t;

/** Transaction history query result */
typedef struct {
    int      count;
    nodus_dnac_history_entry_t *entries;  /* Heap-allocated, caller frees */
} nodus_dnac_history_result_t;

/** Max history entries per query */
#define NODUS_DNAC_MAX_HISTORY_RESULTS 100

/** Roster witness entry */
typedef struct {
    uint8_t  witness_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t  pubkey[NODUS_PK_BYTES];
    char     address[256];
    bool     active;
} nodus_dnac_roster_entry_t;

/** Roster query result */
typedef struct {
    uint32_t version;
    int      count;
    nodus_dnac_roster_entry_t entries[NODUS_T3_MAX_WITNESSES];
} nodus_dnac_roster_result_t;

/** Full transaction query result (v0.10.0 hub/spoke) */
typedef struct {
    bool     found;
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t  tx_type;
    uint8_t  *tx_data;      /* Heap-allocated, caller frees */
    uint32_t tx_len;
    uint64_t block_height;
    uint64_t timestamp;
} nodus_dnac_tx_result_t;

/** Block query result (v0.10.0 hub/spoke) */
typedef struct {
    bool     found;
    uint64_t height;
    uint8_t  tx_hash[NODUS_T3_TX_HASH_LEN];
    uint8_t  tx_type;
    uint64_t timestamp;
    uint8_t  proposer_id[NODUS_T3_WITNESS_ID_LEN];
} nodus_dnac_block_result_t;

/** Token info (returned by token_list / token_info queries) */
#define NODUS_DNAC_MAX_TOKEN_RESULTS  100

typedef struct {
    uint8_t  token_id[64];
    char     name[64];
    char     symbol[16];
    uint8_t  decimals;
    uint64_t supply;
    char     creator_fp[NODUS_KEY_HEX_LEN];
} nodus_dnac_token_info_t;

/** Token list query result */
typedef struct {
    int count;
    nodus_dnac_token_info_t *tokens;   /* Heap-allocated, caller frees */
} nodus_dnac_token_list_result_t;

/** Block range query result (v0.10.0 hub/spoke) */
typedef struct {
    uint64_t total_blocks;
    int      count;
    nodus_dnac_block_result_t *blocks;  /* Heap-allocated, caller frees */
} nodus_dnac_block_range_result_t;

/* ── Utility ─────────────────────────────────────────────────────── */

/** Compare two nodus keys (memcmp wrapper) */
static inline int nodus_key_cmp(const nodus_key_t *a, const nodus_key_t *b) {
    return __builtin_memcmp(a->bytes, b->bytes, NODUS_KEY_BYTES);
}

/** XOR two nodus keys into result */
static inline void nodus_key_xor(nodus_key_t *result,
                                  const nodus_key_t *a,
                                  const nodus_key_t *b) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++)
        result->bytes[i] = a->bytes[i] ^ b->bytes[i];
}

/** Count leading zero bits in key (for bucket index) */
static inline int nodus_key_clz(const nodus_key_t *k) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++) {
        if (k->bytes[i] != 0) {
            /* __builtin_clz operates on unsigned int (>=32 bits) */
            return i * 8 + __builtin_clz((unsigned int)k->bytes[i]) - 24;
        }
    }
    return NODUS_KEYSPACE_BITS;
}

/** Check if key is zero */
static inline bool nodus_key_is_zero(const nodus_key_t *k) {
    for (int i = 0; i < NODUS_KEY_BYTES; i++) {
        if (k->bytes[i] != 0) return false;
    }
    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TYPES_H */
