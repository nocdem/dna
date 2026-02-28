/**
 * Nodus v5 — Core Type Definitions
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

#define NODUS_VERSION_MAJOR  1
#define NODUS_VERSION_MINOR  0
#define NODUS_VERSION_PATCH  0
#define NODUS_VERSION_STRING "1.0.0"

/* Wire frame */
#define NODUS_FRAME_MAGIC       0x4E44      /* "ND" */
#define NODUS_FRAME_VERSION     0x01
#define NODUS_FRAME_HEADER_SIZE 7           /* magic(2) + ver(1) + len(4) */
#define NODUS_MAX_FRAME_TCP     (4 * 1024 * 1024)  /* 4 MB */
#define NODUS_MAX_FRAME_UDP     1400        /* Safe MTU */

/* Kademlia */
#define NODUS_KEY_BYTES         64          /* SHA3-512 = 64 bytes */
#define NODUS_KEY_HEX_LEN      129         /* 128 hex chars + NUL */
#define NODUS_KEYSPACE_BITS     512
#define NODUS_K                 8           /* Bucket size */
#define NODUS_R                 3           /* Replication factor */
#define NODUS_BUCKETS           512         /* One per key-space bit */
#define NODUS_ALPHA             3           /* Parallel lookups */

/* Crypto sizes (Dilithium5 / ML-DSA-87) */
#define NODUS_PK_BYTES          2592        /* Public key */
#define NODUS_SK_BYTES          4896        /* Secret key */
#define NODUS_SIG_BYTES         4627        /* Signature */
#define NODUS_SEED_BYTES        32          /* Identity seed */

/* Networking */
#define NODUS_DEFAULT_UDP_PORT  4000
#define NODUS_DEFAULT_TCP_PORT  4001
#define NODUS_SESSION_TOKEN_LEN 32
#define NODUS_NONCE_LEN         32

/* DHT value limits */
#define NODUS_DEFAULT_TTL       604800      /* 7 days in seconds */
#define NODUS_PERMANENT_TTL     0           /* 0 = never expires */
#define NODUS_MAX_VALUE_SIZE    (1 * 1024 * 1024)   /* 1 MB value payload */
#define NODUS_MAX_VALUES_PER_OWNER 10000

/* Channel limits */
#define NODUS_UUID_BYTES        16          /* UUID v4 */
#define NODUS_MAX_POST_BODY     4000        /* UTF-8 chars */
#define NODUS_CHANNEL_RETENTION (7 * 86400) /* 7 days */
#define NODUS_MAX_HINTED_POSTS  1000
#define NODUS_HINTED_RETRY_SEC  30
#define NODUS_HINTED_TTL_SEC    86400       /* 24h */

/* Rate limiting defaults */
#define NODUS_RATE_PUTS_PER_MIN  60
#define NODUS_RATE_MAX_LISTENERS 100
#define NODUS_RATE_MAX_CONNS     1000

/* PBFT */
#define NODUS_PBFT_HEARTBEAT_SEC 10
#define NODUS_PBFT_SUSPECT_SEC   30

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
} nodus_identity_t;

/** DHT value type */
typedef enum {
    NODUS_VALUE_EPHEMERAL = 0x01,   /* Expires after TTL */
    NODUS_VALUE_PERMANENT = 0x02    /* Never expires */
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

/** Channel post (stored per-channel, assigned seq_id by primary) */
typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint32_t    seq_id;         /* Assigned by primary */
    uint8_t     post_uuid[NODUS_UUID_BYTES];
    nodus_key_t author_fp;      /* SHA3-512(author_pk) */
    uint64_t    timestamp;      /* Author's claimed time */
    uint64_t    received_at;    /* Nodus receive time */
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
    NODUS_ERR_CHANNEL_NOT_FOUND = 10,
    NODUS_ERR_NOT_RESPONSIBLE   = 11,
    NODUS_ERR_RING_MISMATCH     = 12
} nodus_error_t;

/** PBFT phases */
typedef enum {
    NODUS_PBFT_PRE_PREPARE = 1,
    NODUS_PBFT_PREPARE     = 2,
    NODUS_PBFT_COMMIT      = 3,
    NODUS_PBFT_VIEW_CHANGE = 4
} nodus_pbft_phase_t;

/** Ring membership change type */
typedef enum {
    NODUS_RING_ADD    = 1,
    NODUS_RING_REMOVE = 2
} nodus_ring_change_t;

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
