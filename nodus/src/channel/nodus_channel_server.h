/**
 * Nodus -- Channel Server (TCP 4003 Session Management)
 *
 * Manages two types of connections on one port:
 *   1. Client sessions -- users connecting to PRIMARY to read/post to channels
 *   2. Node sessions   -- inter-node connections for replication, heartbeat, ring
 *
 * This module handles auth flow, session lifecycle, message dispatch,
 * and subscriber notification.  Real channel logic lives in the primary,
 * replication, and ring modules.
 *
 * @file nodus_channel_server.h
 */

#ifndef NODUS_CHANNEL_SERVER_H
#define NODUS_CHANNEL_SERVER_H

#include "nodus/nodus_types.h"
#include "transport/nodus_tcp.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_hashring.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Constants --------------------------------------------------------- */

#define NODUS_CH_MAX_CLIENT_SESSIONS   1024
#define NODUS_CH_MAX_NODE_SESSIONS     32
#define NODUS_CH_MAX_SUBS_PER_CLIENT   32
#define NODUS_CH_RATE_POSTS_PER_MIN    60
#define NODUS_CH_HEARTBEAT_INTERVAL_MS 15000   /* 15 seconds */
#define NODUS_CH_HEARTBEAT_TIMEOUT_MS  45000   /* 45 seconds */

/* ---- Client session (user -> PRIMARY) ---------------------------------- */

typedef struct {
    nodus_tcp_conn_t       *conn;
    nodus_key_t             client_fp;
    nodus_pubkey_t          client_pk;
    uint8_t                 token[NODUS_SESSION_TOKEN_LEN];
    bool                    authenticated;
    uint8_t                 nonce[NODUS_NONCE_LEN];
    bool                    nonce_pending;

    uint8_t                 ch_subs[NODUS_CH_MAX_SUBS_PER_CLIENT][NODUS_UUID_BYTES];
    int                     ch_sub_count;

    uint32_t                posts_this_minute;
    uint64_t                rate_window_start;
} nodus_ch_client_session_t;

/* ---- Node session (inter-node) ----------------------------------------- */

typedef struct {
    nodus_tcp_conn_t       *conn;
    nodus_key_t             node_id;
    nodus_pubkey_t          node_pk;
    uint8_t                 token[NODUS_SESSION_TOKEN_LEN];
    bool                    authenticated;
    uint8_t                 nonce[NODUS_NONCE_LEN];
    bool                    nonce_pending;
    uint32_t                ring_version;

    uint64_t                last_heartbeat_recv;
    uint64_t                last_heartbeat_sent;
} nodus_ch_node_session_t;

/* ---- Pending outbound connections -------------------------------------- */

#define NODUS_CH_MAX_PENDING_OUTBOUND 16

typedef struct {
    char          ip[64];
    uint16_t      port;
    nodus_key_t   node_id;
    bool          active;
} nodus_ch_pending_outbound_t;

/* ---- Forward declarations ---------------------------------------------- */

struct nodus_channel_server;

/** Called when a client posts to a channel (for replication). */
typedef void (*nodus_ch_on_post_fn)(struct nodus_channel_server *cs,
                                     const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                     const nodus_channel_post_t *post,
                                     const nodus_pubkey_t *author_pk);

/** Called when a replication message arrives from peer. */
typedef void (*nodus_ch_on_replicate_fn)(struct nodus_channel_server *cs,
                                          const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                          const nodus_channel_post_t *post);

/* ---- Channel server ---------------------------------------------------- */

typedef struct nodus_channel_server {
    nodus_tcp_t             tcp;
    uint16_t                port;

    nodus_ch_client_session_t  clients[NODUS_CH_MAX_CLIENT_SESSIONS];
    nodus_ch_node_session_t    nodes[NODUS_CH_MAX_NODE_SESSIONS];

    /* Shared state (set by caller, not owned) */
    nodus_channel_store_t  *ch_store;
    nodus_hashring_t       *ring;
    nodus_identity_t       *identity;   /* Server identity (for signing, pk, fp) */
    char                    self_ip[64];

    /* Callbacks for cross-module integration */
    nodus_ch_on_post_fn     on_post;       /* PRIMARY: after storing, before pushing */
    nodus_ch_on_replicate_fn on_replicate;  /* BACKUP: received replication */
    void                   *cb_ctx;         /* Opaque context for callbacks */

    /* Pending outbound connections (waiting for TCP connect + auth) */
    nodus_ch_pending_outbound_t pending_outbound[NODUS_CH_MAX_PENDING_OUTBOUND];

    /* Cross-module pointers (set by caller, avoids circular headers) */
    void                   *ch_ring_ptr;       /* nodus_ch_ring_t * */
    void                   *ch_replication_ptr; /* nodus_ch_replication_t * */

    /* DHT access (for announce) -- function pointer set by parent */
    int (*dht_put_signed)(const uint8_t *key_hash, size_t key_len,
                          const uint8_t *val, size_t val_len,
                          uint32_t ttl, void *ctx);
    void *dht_ctx;
} nodus_channel_server_t;

/* ---- Public API -------------------------------------------------------- */

int  nodus_channel_server_init(nodus_channel_server_t *cs);
int  nodus_channel_server_listen(nodus_channel_server_t *cs,
                                  const char *bind_ip, uint16_t port);
void nodus_channel_server_poll(nodus_channel_server_t *cs, int timeout_ms);
void nodus_channel_server_tick(nodus_channel_server_t *cs, uint64_t now_ms);
void nodus_channel_server_close(nodus_channel_server_t *cs);

/* Session lookup */
nodus_ch_client_session_t *nodus_ch_find_client(nodus_channel_server_t *cs,
                                                 nodus_tcp_conn_t *conn);
nodus_ch_node_session_t   *nodus_ch_find_node(nodus_channel_server_t *cs,
                                               nodus_tcp_conn_t *conn);

/* Subscriber notification */
void nodus_ch_notify_subscribers(nodus_channel_server_t *cs,
                                  const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                  const nodus_channel_post_t *post);
void nodus_ch_notify_ring_changed(nodus_channel_server_t *cs,
                                   const uint8_t channel_uuid[NODUS_UUID_BYTES],
                                   uint32_t new_version);

/* Outbound node connections */
int nodus_ch_server_connect_to_peer(nodus_channel_server_t *cs,
                                      const char *ip, uint16_t port,
                                      const nodus_key_t *node_id);

/* Subscription management */
int  nodus_ch_client_add_sub(nodus_ch_client_session_t *sess,
                              const uint8_t channel_uuid[NODUS_UUID_BYTES]);
void nodus_ch_client_remove_sub(nodus_ch_client_session_t *sess,
                                 const uint8_t channel_uuid[NODUS_UUID_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_SERVER_H */
