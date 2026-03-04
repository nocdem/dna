/**
 * Nodus v5 — Server Core
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
