/**
 * Nodus — Tier 2 Protocol (Client-Nodus)
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
#include "core/nodus_media_storage.h"
#include "channel/nodus_hashring.h"
#include "channel/nodus_channel_store.h"

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

/* Cluster-status query — Phase 0 / Task 0.2.
 *
 * Read-only ops query: server reports its own block_height, state_root,
 * chain_id, peer_count, uptime_sec, and wall_clock. Used by
 * `nodus-cli cluster-status` to render a side-by-side per-node table
 * during pre-deploy rehearsals and post-deploy checkins. The query
 * carries no arguments beyond the auth token.
 */
int nodus_t2_status(uint32_t txn, const uint8_t *token,
                     uint8_t *buf, size_t cap, size_t *out_len);

/* Cluster-status response. State fields are read straight from the
 * witness DB plus a few server-process metrics; all currently public.
 *
 * Field semantics (server-side):
 *   block_height — latest committed block in the active witness chain;
 *                  0 if no witness DB is open yet.
 *   state_root   — 64-byte SHA3-512 over the current UTXO set, or
 *                  zeros if no witness DB is open.
 *   chain_id     — 32-byte first-block hash that names the active chain;
 *                  zeros if no chain is open.
 *   peer_count   — number of inter-node TCP peers currently connected.
 *   uptime_sec   — seconds since this nodus-server process started.
 *   wall_clock   — server's local wall clock at response time (unix sec)
 *                  for clock skew detection (Task 10.4 telafi).
 */
typedef struct {
    uint64_t block_height;
    uint8_t  state_root[64];
    uint8_t  chain_id[32];
    uint32_t peer_count;
    uint64_t uptime_sec;
    uint64_t wall_clock;
    /* disk_free_pct is the percentage of the witness data directory's
     * filesystem that is currently free (0–100, integer). 255 = unknown
     * (statvfs failed or no data dir). Phase 0 / Task 0.12. */
    uint8_t  disk_free_pct;
} nodus_t2_status_info_t;

int nodus_t2_status_result(uint32_t txn,
                            const nodus_t2_status_info_t *info,
                            uint8_t *buf, size_t cap, size_t *out_len);

/* Circuit (VPN mesh) — Faz 1 + E2E encryption */
int nodus_t2_circ_open(uint32_t txn, const uint8_t *token,
                        uint64_t cid, const nodus_key_t *peer_fp,
                        uint8_t *buf, size_t cap, size_t *out_len);

/** circ_open with E2E Kyber ciphertext (onion layer) */
int nodus_t2_circ_open_e2e(uint32_t txn, const uint8_t *token,
                            uint64_t cid, const nodus_key_t *peer_fp,
                            const uint8_t *e2e_ct,
                            uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_circ_open_ok(uint32_t txn, uint64_t cid,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_circ_open_err(uint32_t txn, uint64_t cid, int code,
                            uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_circ_inbound(uint32_t txn, uint64_t cid, const nodus_key_t *peer_fp,
                           uint8_t *buf, size_t cap, size_t *out_len);

/** circ_inbound with E2E Kyber ciphertext (relayed from circ_open) */
int nodus_t2_circ_inbound_e2e(uint32_t txn, uint64_t cid, const nodus_key_t *peer_fp,
                               const uint8_t *e2e_ct,
                               uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_circ_data(uint32_t txn, const uint8_t *token,
                        uint64_t cid, const uint8_t *data, size_t data_len,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_circ_close(uint32_t txn, const uint8_t *token, uint64_t cid,
                         uint8_t *buf, size_t cap, size_t *out_len);

/* Inter-node circuit forwarding (Faz 1, TCP 4002) */
int nodus_t2_ri_open(uint32_t txn, uint64_t ups_cid,
                      const nodus_key_t *src_fp, const nodus_key_t *dst_fp,
                      uint8_t *buf, size_t cap, size_t *out_len);

/** ri_open with E2E ciphertext (relayed opaquely) */
int nodus_t2_ri_open_e2e(uint32_t txn, uint64_t ups_cid,
                          const nodus_key_t *src_fp, const nodus_key_t *dst_fp,
                          const uint8_t *e2e_ct,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ri_open_ok(uint32_t txn, uint64_t ups_cid, uint64_t dns_cid,
                         uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ri_open_err(uint32_t txn, uint64_t ups_cid, int code,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ri_data(uint32_t txn, uint64_t cid,
                      const uint8_t *data, size_t data_len,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ri_close(uint32_t txn, uint64_t cid,
                       uint8_t *buf, size_t cap, size_t *out_len);

/* ── Channel operations (Client → Nodus) ─────────────────────────── */

int nodus_t2_ch_create(uint32_t txn, const uint8_t *token,
                        const uint8_t uuid[NODUS_UUID_BYTES],
                        bool encrypted,
                        const char *name, const char *description,
                        bool is_public,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_post(uint32_t txn, const uint8_t *token,
                      const uint8_t ch_uuid[NODUS_UUID_BYTES],
                      const uint8_t post_uuid[NODUS_UUID_BYTES],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_get_posts(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint64_t since_received_at, int max_count,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_subscribe(uint32_t txn, const uint8_t *token,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_unsubscribe(uint32_t txn, const uint8_t *token,
                              const uint8_t uuid[NODUS_UUID_BYTES],
                              uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_member_update(uint32_t txn, const uint8_t *token,
                              const uint8_t ch_uuid[NODUS_UUID_BYTES],
                              uint8_t action,
                              const nodus_key_t *target_fp,
                              const nodus_sig_t *sig,
                              uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_member_update_ok(uint32_t txn,
                                  uint8_t *buf, size_t cap, size_t *out_len);

/* Channel discovery (Client → Nodus) */
int nodus_t2_ch_list(uint32_t txn, const uint8_t *token,
                      int offset, int limit,
                      uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_search(uint32_t txn, const uint8_t *token,
                        const char *query, int offset, int limit,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_get(uint32_t txn, const uint8_t *token,
                     const uint8_t uuid[NODUS_UUID_BYTES],
                     uint8_t *buf, size_t cap, size_t *out_len);

/* Channel discovery (Nodus → Client) */
int nodus_t2_ch_list_ok(uint32_t txn,
                         const nodus_channel_meta_t *metas, size_t count,
                         uint8_t *buf, size_t cap, size_t *out_len);

/* ── Media operations (Client → Nodus) ──────────────────────────── */

int nodus_t2_media_put(uint32_t txn, const uint8_t *token,
                       const uint8_t content_hash[64],
                       uint32_t chunk_index, uint32_t chunk_count,
                       uint64_t total_size, uint8_t media_type,
                       uint32_t ttl, bool encrypted,
                       const uint8_t *data, size_t data_len,
                       const nodus_sig_t *sig,
                       uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_media_get_meta(uint32_t txn, const uint8_t *token,
                            const uint8_t content_hash[64],
                            uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_media_get_chunk(uint32_t txn, const uint8_t *token,
                             const uint8_t content_hash[64],
                             uint32_t chunk_index,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Media responses (Nodus → Client) ───────────────────────────── */

int nodus_t2_media_put_ok(uint32_t txn, uint32_t chunk_index, bool complete,
                          uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_media_meta_result(uint32_t txn, const nodus_media_meta_t *meta,
                               uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_media_chunk_result(uint32_t txn, uint32_t chunk_index,
                                const uint8_t *data, size_t data_len,
                                uint8_t *buf, size_t cap, size_t *out_len);

/* ── Batch operations (Client → Nodus) ──────────────────────────── */

/** Client → Nodus: batch get_all for multiple keys */
int nodus_t2_get_batch(uint32_t txn, const uint8_t *token,
                        const nodus_key_t *keys, int key_count,
                        uint8_t *buf, size_t cap, size_t *out_len);

/** Client → Nodus: batch count for multiple keys (+ has_mine check) */
int nodus_t2_count_batch(uint32_t txn, const uint8_t *token,
                          const nodus_key_t *keys, int key_count,
                          const nodus_key_t *caller_fp,
                          uint8_t *buf, size_t cap, size_t *out_len);

/* ── Batch responses (Nodus → Client) ───────────────────────────── */

/** Nodus → Client: batch get_all result (per-key value arrays) */
int nodus_t2_result_get_batch(uint32_t txn,
                               const nodus_key_t *keys, int key_count,
                               nodus_value_t ***vals_per_key,
                               const size_t *counts_per_key,
                               uint8_t *buf, size_t cap, size_t *out_len);

/** Nodus → Client: batch count result (per-key count + has_mine) */
int nodus_t2_result_count_batch(uint32_t txn,
                                 const nodus_key_t *keys, int key_count,
                                 const size_t *counts,
                                 const bool *has_mine,
                                 uint8_t *buf, size_t cap, size_t *out_len);

/* ── Nodus → Client encode ───────────────────────────────────────── */

int nodus_t2_challenge(uint32_t txn, const uint8_t *nonce,
                        uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_auth_ok(uint32_t txn, const uint8_t *token,
                      uint8_t *buf, size_t cap, size_t *out_len);

/** auth_ok with Kyber pubkey for channel encryption handshake.
 *  Includes server's Dilithium5 pubkey and signature over (kyber_pk || nonce)
 *  so the client can verify the server's identity and detect MITM. */
int nodus_t2_auth_ok_kyber(uint32_t txn, const uint8_t *token,
                            const uint8_t *kyber_pk,
                            const nodus_pubkey_t *server_pk,
                            const nodus_sig_t *kpk_sig,
                            uint8_t *buf, size_t cap, size_t *out_len);

/** Client → Nodus: initiate channel encryption after auth_ok */
int nodus_t2_key_init(uint32_t txn, const uint8_t *kyber_ct,
                       const uint8_t *nonce_c,
                       uint8_t *buf, size_t cap, size_t *out_len);

/** Nodus → Client: acknowledge channel encryption setup */
int nodus_t2_key_ack(uint32_t txn, const uint8_t *nonce_s,
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

int nodus_t2_ch_post_ok(uint32_t txn, uint64_t received_at,
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
    uint8_t     dil_fp[16];     /* First 16 bytes of Dilithium5 fingerprint */
    bool        has_dil_fp;
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

/** Nodus → Client: presence query result (online entries + offline last_seen). */
int nodus_t2_presence_result(uint32_t txn,
                               const nodus_key_t *fps, const bool *online,
                               const uint8_t *peers, const uint64_t *last_seen,
                               int count,
                               uint8_t *buf, size_t cap, size_t *out_len);

/** Nodus → Nodus: inter-node presence sync (no auth). */
int nodus_t2_presence_sync(uint32_t txn, const nodus_key_t *fps, int count,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Inter-Nodus media replication ────────────────────────────────── */

/** Encode a media chunk for inter-node replication (Nodus → Nodus, no auth).
 * Method: "m_sv". Contains meta fields + chunk data for one chunk. */
int nodus_t2_media_store_value(uint32_t txn,
                               const nodus_media_meta_t *meta,
                               uint32_t chunk_index,
                               const uint8_t *data, size_t data_len,
                               uint8_t *buf, size_t cap, size_t *out_len);

/* ── Inter-Nodus replication ──────────────────────────────────────── */

/** Encode a channel replication message (Nodus → Nodus, no auth).
 * @param author_pk  Author's public key for signature verification (may be NULL for legacy) */
int nodus_t2_ch_replicate(uint32_t txn,
                           const uint8_t ch_uuid[NODUS_UUID_BYTES],
                           const nodus_channel_post_t *post,
                           const nodus_pubkey_t *author_pk,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_rep_ok(uint32_t txn,
                        uint8_t *buf, size_t cap, size_t *out_len);

/* ── Ring management (Nodus ↔ Nodus, TCP 4002) ─────────────────── */

/** ring_check: ask peer to confirm a node's status for a channel.
 * @param node_id   The node being checked
 * @param ch_uuid   Channel UUID
 * @param status    "dead" or "alive" */
int nodus_t2_ring_check(uint32_t txn,
                          const nodus_key_t *node_id,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          const char *status,
                          uint8_t *buf, size_t cap, size_t *out_len);

/** ring_ack: response to ring_check.
 * @param ch_uuid   Channel UUID
 * @param agree     true if confirming the status change */
int nodus_t2_ring_ack(uint32_t txn,
                        const uint8_t ch_uuid[NODUS_UUID_BYTES],
                        bool agree,
                        uint8_t *buf, size_t cap, size_t *out_len);

/** ring_evict: notify a node it's no longer responsible for a channel.
 * @param ch_uuid   Channel UUID
 * @param version   New ring version */
int nodus_t2_ring_evict(uint32_t txn,
                          const uint8_t ch_uuid[NODUS_UUID_BYTES],
                          uint32_t version,
                          uint8_t *buf, size_t cap, size_t *out_len);

/** ch_ring_changed: notify connected 4003 client that ring changed for a channel.
 * @param ch_uuid   Channel UUID
 * @param version   New ring version */
int nodus_t2_ch_ring_changed(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               uint32_t version,
                               uint8_t *buf, size_t cap, size_t *out_len);

/* ── Channel rewrite: node-to-node protocol (TCP 4003) ────────── */

int nodus_t2_ch_node_hello(uint32_t txn, const nodus_pubkey_t *pk,
                            const nodus_key_t *fp, uint32_t ring_version,
                            uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_node_auth_ok(uint32_t txn,
                              const uint8_t *token, size_t token_len,
                              uint32_t current_ring_version,
                              const nodus_ring_member_t *ring_members, int ring_count,
                              uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_heartbeat(uint32_t txn,
                           uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_heartbeat_ack(uint32_t txn,
                               uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_sync_request(uint32_t txn,
                              const uint8_t ch_uuid[NODUS_UUID_BYTES],
                              uint64_t since_ms,
                              uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_sync_response(uint32_t txn,
                               const uint8_t ch_uuid[NODUS_UUID_BYTES],
                               const nodus_channel_post_t *posts, size_t count,
                               uint8_t *buf, size_t cap, size_t *out_len);

int nodus_t2_ch_ring_rejoin(uint32_t txn,
                             const nodus_key_t *node_id,
                             uint32_t my_ring_version,
                             uint8_t *buf, size_t cap, size_t *out_len);

/* ── Decoded message ─────────────────────────────────────────────── */

typedef struct {
    uint32_t        txn_id;
    char            type;           /* 'q', 'r', 'e' */
    char            method[64];  /* longest: "dnac_validator_list_query" (25ch); 64 for headroom */
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
    uint64_t        ch_received_at;
    nodus_pubkey_t  author_pk;      /* ch_rep: author public key for sig verification */
    bool            has_author_pk;  /* true if apk was present in ch_rep */
    nodus_channel_post_t *ch_posts;
    size_t          ch_post_count;

    /* Ring management fields */
    nodus_key_t     ring_node_id;       /* ring_check/ring_rejoin: target node */
    char            ring_status[8];     /* ring_check: "dead" or "alive" */
    bool            ring_agree;         /* ring_ack: agree/disagree */
    uint32_t        ring_version;       /* ring_evict/ch_ring_changed/node_hello/ring_rejoin: version */

    /* Channel rewrite: sync fields */
    uint64_t        ch_since_ms;        /* ch_sync_req: since timestamp */
    bool            ch_encrypted;       /* ch_create: encrypted channel flag */
    char           *ch_name;            /* ch_create: channel name (heap, may be NULL) */
    char           *ch_description;     /* ch_create: channel description (heap, may be NULL) */
    bool            ch_is_public;       /* ch_create: discoverable flag */

    /* ch_list / ch_search fields */
    int             ch_offset;          /* ch_list/ch_search: pagination offset */
    int             ch_limit;           /* ch_list/ch_search: pagination limit */
    char           *ch_query;           /* ch_search: search query (heap, may be NULL) */
    nodus_channel_meta_t *ch_metas;     /* ch_list_ok/ch_search_ok: result array (heap) */
    size_t          ch_meta_count;      /* ch_list_ok/ch_search_ok: result count */

    /* ch_member_update fields */
    uint8_t         ch_mu_action;       /* 1=add, 2=remove */
    nodus_key_t     ch_mu_target_fp;    /* target fingerprint */
    bool            has_ch_mu;          /* true if ch_member_update fields present */

    /* Server list (servers response) */
    struct {
        char        ip[64];
        uint16_t    tcp_port;
        uint8_t     dil_fp[16];     /* First 16 bytes of Dilithium5 fingerprint */
        bool        has_dil_fp;
    } servers[17];  /* NODUS_CLUSTER_MAX_PEERS(16) + 1 for self */
    int             server_count;

    /* Cluster-status response (Phase 0 / Task 0.2) */
    nodus_t2_status_info_t status_info;
    bool                   has_status_info;

    /* Presence query/sync */
    nodus_key_t    *pq_fps;         /* FP array (heap) */
    int             pq_count;       /* FP count */
    bool           *pq_online;      /* Result: online status per FP (heap) */
    uint8_t        *pq_peers;       /* Result: peer index per FP (heap) */
    uint64_t       *pq_last_seen;   /* Result: last_seen timestamp per FP (heap) */

    /* Offline-seen entries (recently disconnected) */
    nodus_key_t    *os_fps;         /* FP array (heap) */
    uint64_t       *os_last_seen;   /* Last seen timestamps (heap) */
    int             os_count;

    /* Batch get/count fields */
    nodus_key_t    *batch_keys;       /* Array of keys (heap) */
    int             batch_key_count;
    nodus_value_t ***batch_vals;      /* get_batch: per-key value arrays (heap) */
    size_t         *batch_val_counts; /* get_batch: value count per key (heap) */
    size_t         *batch_counts;     /* count_batch: value count per key (heap) */
    bool           *batch_has_mine;   /* count_batch: client has value for key (heap) */
    nodus_key_t     batch_caller_fp;  /* count_batch: caller fingerprint */

    /* Media fields */
    uint8_t         media_hash[64];       /* content_hash (SHA3-512) */
    uint32_t        media_chunk_idx;      /* chunk index */
    uint32_t        media_chunk_count;    /* total chunks (chunk 0 only) */
    uint64_t        media_total_size;     /* total bytes (chunk 0 only) */
    uint8_t         media_type;           /* 0=image, 1=video, 2=audio */
    bool            media_encrypted;      /* true=DM/group, false=wall */
    bool            media_complete;       /* put_ok: all chunks received? */
    bool            has_media;            /* true if media fields present */

    /* Circuit fields (Faz 1) */
    uint64_t        circ_cid;
    nodus_key_t     circ_peer_fp;
    int             circ_err_code;
    uint8_t        *circ_data;           /* heap, may be NULL */
    size_t          circ_data_len;
    bool            has_circ;

    /* Circuit E2E encryption (onion layer) */
    uint8_t         e2e_ct[1568];       /* Kyber ciphertext for per-circuit E2E */
    bool            has_e2e_ct;

    /* Inter-node circuit fields (Faz 1) */
    uint64_t        ri_ups_cid;
    uint64_t        ri_dns_cid;
    uint64_t        ri_cid;              /* for ri_data / ri_close */
    nodus_key_t     ri_src_fp;
    nodus_key_t     ri_dst_fp;
    int             ri_err_code;
    uint8_t        *ri_data;             /* heap, for ri_data */
    size_t          ri_data_len;
    bool            has_ri;

    /* Protocol version (hello: v field, 0 = legacy, 2 = channel encryption) */
    uint32_t        proto_version;

    /* Channel encryption (Kyber handshake) */
    uint8_t         kyber_pk[1568];     /* auth_ok: server's Kyber pubkey */
    bool            has_kyber_pk;
    nodus_pubkey_t  server_pk;          /* auth_ok: server's Dilithium5 pubkey */
    bool            has_server_pk;
    nodus_sig_t     kpk_sig;            /* auth_ok: Dilithium5 sig over (kyber_pk || nonce) */
    bool            has_kpk_sig;
    uint8_t         kyber_ct[1568];     /* key_init: Kyber ciphertext */
    bool            has_kyber_ct;
    uint8_t         key_nonce[32];      /* key_init: nonce_c / key_ack: nonce_s */
    bool            has_key_nonce;

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
