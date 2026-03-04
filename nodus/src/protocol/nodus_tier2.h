/**
 * Nodus v5 — Tier 2 Protocol (Client-Nodus)
 *
 * Encode/decode client↔server messages:
 *   Auth: hello, challenge, auth, auth_ok
 *   DHT:  put, get, get_all, listen, unlisten, ping/pong
 *   Push: result, error, value_changed
 *
 * @file nodus_tier2.h
 */

#ifndef NODUS_TIER2_H
#define NODUS_TIER2_H

#include "nodus/nodus_types.h"
#include "core/nodus_value.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Client → Nodus encode ───────────────────────────────────────── */

int nodus_t2_hello(uint32_t txn, const nodus_pubkey_t *pk,
                    const nodus_key_t *fp,
                    uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_auth(uint32_t txn, const nodus_sig_t *sig,
                   uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_put(uint32_t txn, const uint8_t *token,
                  const nodus_key_t *key, const uint8_t *data, size_t data_len,
                  nodus_value_type_t type, uint32_t ttl,
                  uint64_t vid, uint64_t seq,
                  const nodus_sig_t *sig,
                  uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_get(uint32_t txn, const uint8_t *token,
                  const nodus_key_t *key,
                  uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_get_all(uint32_t txn, const uint8_t *token,
                      const nodus_key_t *key,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_listen(uint32_t txn, const uint8_t *token,
                     const nodus_key_t *key,
                     uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_unlisten(uint32_t txn, const uint8_t *token,
                       const nodus_key_t *key,
                       uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ping(uint32_t txn, const uint8_t *token,
                   uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_servers(uint32_t txn, const uint8_t *token,
                      uint8_t *buf, size_t cap, size_t *out_len);

/* ── Channel operations (Client → Nodus) ─────────────────────────── */

int nodus_t2_ch_create(uint32_t txn, const uint8_t *token,
                        const uint8_t uuid[NODUS_UUID_BYTES],
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_post(uint32_t txn, const uint8_t *token,
                      const uint8_t ch_uuid[NODUS_UUID_BYTES],
                      const uint8_t post_uuid[NODUS_UUID_BYTES],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_get_posts(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint32_t since_seq, int max_count,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_subscribe(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_unsubscribe(uint32_t txn, const uint8_t *token,
                              const uint8_t uuid[NODUS_UUID_BYTES],
                              uint8_t *buf, size_t cap, size_t *out_len);

/* ── Nodus → Client encode ───────────────────────────────────────── */

int nodus_t2_challenge(uint32_t txn, const uint8_t *nonce,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_auth_ok(uint32_t txn, const uint8_t *token,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_result(uint32_t txn, const nodus_value_t *val,
                     uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_result_multi(uint32_t txn, nodus_value_t **vals, size_t count,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_result_empty(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_error(uint32_t txn, int code, const char *msg,
                    uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_value_changed(uint32_t txn, const nodus_key_t *key,
                            const nodus_value_t *val,
                            uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_pong(uint32_t txn,
                   uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_put_ok(uint32_t txn,
                     uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_listen_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len);

/* ── Channel responses (Nodus → Client) ──────────────────────────── */

int nodus_t2_ch_create_ok(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_post_ok(uint32_t txn, uint32_t seq_id,
                         uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_posts(uint32_t txn, const nodus_channel_post_t *posts,
                       size_t count,
                       uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_sub_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_post_notify(uint32_t txn,
                             const uint8_t ch_uuid[NODUS_UUID_BYTES],
                             const nodus_channel_post_t *post,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Server list response ─────────────────────────────────────────── */

/** Server endpoint for gossip response */
typedef struct {
    char        ip[64];
    uint16_t    tcp_port;
} nodus_t2_server_info_t;

int nodus_t2_servers_result(uint32_t txn,
                             const nodus_t2_server_info_t *servers,
                             int server_count,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Presence protocol ────────────────────────────────────────────── */

/** Client → Nodus: batch presence query (post-auth). */
int nodus_t2_presence_query(uint32_t txn, const uint8_t *token,
                              const nodus_key_t *fps, int count,
                              uint8_t *buf, size_t cap, size_t *out_len);

/** Nodus → Client: presence query result (sparse — only online entries). */
int nodus_t2_presence_result(uint32_t txn,
                               const nodus_key_t *fps, const bool *online,
                               const uint8_t *peers, int count,
                               uint8_t *buf, size_t cap, size_t *out_len);

/** Nodus → Nodus: inter-node presence sync (no auth). */
int nodus_t2_presence_sync(uint32_t txn, const nodus_key_t *fps, int count,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Inter-Nodus replication ──────────────────────────────────────── */

/** Encode a channel replication message (Nodus → Nodus, no auth). */
int nodus_t2_ch_replicate(uint32_t txn,
                           const uint8_t ch_uuid[NODUS_UUID_BYTES],
                           const nodus_channel_post_t *post,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_rep_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len);

/* ── Decoded message ─────────────────────────────────────────────── */

typedef struct {
    uint32_t        txn_id;
    char            type;           /* 'q', 'r', 'e' */
    char            method[16];
    uint8_t         token[NODUS_SESSION_TOKEN_LEN];
    bool            has_token;

    /* Method-specific fields */
    nodus_pubkey_t  pk;             /* hello: client pubkey */
    nodus_key_t     fp;             /* hello: client fingerprint */
    nodus_sig_t     sig;            /* auth: signature */
    uint8_t         nonce[NODUS_NONCE_LEN];  /* challenge nonce */
    nodus_key_t     key;            /* put/get/listen key */
    uint8_t        *data;           /* put: payload (heap) */
    size_t          data_len;
    nodus_value_type_t val_type;    /* put: type */
    uint32_t        ttl;            /* put: ttl */
    uint64_t        vid;            /* put: value_id */
    uint64_t        seq;            /* put: seq */
    nodus_value_t  *value;          /* result: single value (heap) */
    nodus_value_t **values;         /* result_multi: array (heap) */
    size_t          value_count;

    /* Channel fields */
    uint8_t         channel_uuid[NODUS_UUID_BYTES];
    uint8_t         post_uuid_ch[NODUS_UUID_BYTES];
    uint64_t        ch_timestamp;
    int             ch_max_count;
    uint32_t        ch_seq_id;
    nodus_channel_post_t *ch_posts;
    size_t          ch_post_count;

    /* Server list (servers response) */
    struct {
        char        ip[64];
        uint16_t    tcp_port;
    } servers[17];  /* NODUS_PBFT_MAX_PEERS(16) + 1 for self */
    int             server_count;

    /* Presence query/sync */
    nodus_key_t    *pq_fps;         /* FP array (heap) */
    int             pq_count;       /* FP count */
    bool           *pq_online;      /* Result: online status per FP (heap) */
    uint8_t        *pq_peers;       /* Result: peer index per FP (heap) */

    /* Error */
    int             error_code;
    char            error_msg[128];
} nodus_tier2_msg_t;

/**
 * Decode a Tier 2 CBOR payload into structured message.
 * Caller must call nodus_t2_msg_free() when done.
 */
int nodus_t2_decode(const uint8_t *buf, size_t len, nodus_tier2_msg_t *msg);

/** Free resources in decoded message. */
void nodus_t2_msg_free(nodus_tier2_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TIER2_H */
