/**
 * Nodus — test helper: a fake node that speaks the CLIENT session
 * (DHT v2 3b-2), and the client config that talks to it.
 *
 * The old fake nodes answered hello / auth / key_init by hand. A client now
 * opens a SecretConnection (nodus_tcp_sc.h, CLIENT profile) and waits for the
 * server's first sealed frame, the T2 `auth_ok` token message (txn 0). A
 * fake node therefore:
 *   1. keeps a th_node_t (identity with an ML-KEM key, a chain id);
 *   2. calls th_node_attach(tcp, &node) once after nodus_tcp_init — it sets
 *      tcp->on_accept (enable the layer as RESPONDER) and tcp->on_session
 *      (send the token message), and records the node in tcp->auth_ctx;
 *   3. answers only the REQUESTS in its on_frame (the session is already
 *      authenticated when a frame arrives).
 * A test that has its own on_accept / on_session calls th_node_accept /
 * th_node_session from them instead of th_node_attach.
 * th_client_cfg fills the pin and the chain id of a client config.
 *
 * Header-only, test code only. Not part of any product build.
 */

#ifndef TEST_SESSION_HELPER_H
#define TEST_SESSION_HELPER_H

#include <stdio.h>
#include <string.h>

#include "nodus/nodus.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_tcp_sc.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"

typedef struct {
    nodus_identity_t id;
    uint8_t          chain_id[32];
    nodus_key_t      pin;       /* fingerprint of id.pk: what a client pins */
} th_node_t;

static inline int th_node_init(th_node_t *n, uint8_t chain_byte) {
    memset(n, 0, sizeof(*n));
    if (nodus_identity_generate(&n->id) != 0) return -1;
    memset(n->chain_id, chain_byte ? chain_byte : 0x42, sizeof(n->chain_id));
    return nodus_fingerprint(&n->id.pk, &n->pin);
}

/** RESPONDER, CLIENT profile, on a connection just accepted. 0 / -1. */
static inline int th_node_accept(nodus_tcp_t *tcp, nodus_tcp_conn_t *conn,
                                 const th_node_t *n) {
    nodus_tcp_sc_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role      = CMT_P2P_SC_ROLE_RESPONDER;
    cfg.profile   = &CMT_P2P_SC_PROFILE_CLIENT;
    cfg.id        = &n->id;
    cfg.proto_ver = NODUS_CSESS_PROTO_VERSION;
    memcpy(cfg.chain_id, n->chain_id, sizeof(cfg.chain_id));
    return nodus_tcp_sc_enable(tcp, conn, &cfg);
}

/** The session is authenticated: send the token message (auth_ok, txn 0). */
static inline void th_node_session(nodus_tcp_conn_t *conn) {
    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    uint8_t buf[256];
    size_t len = 0;
    memset(token, 0x5a, sizeof(token));
    if (nodus_t2_auth_ok(0, token, buf, sizeof(buf), &len) == 0)
        nodus_tcp_send(conn, buf, len);
}

static inline void th_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    nodus_tcp_t *tcp = conn->tcp_parent;
    if (th_node_accept(tcp, conn, (const th_node_t *)tcp->auth_ctx) != 0)
        nodus_tcp_disconnect(tcp, conn);
}

static inline void th_on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    th_node_session(conn);
}

/** Install the session on a fake node's transport. */
static inline void th_node_attach(nodus_tcp_t *tcp, th_node_t *n) {
    tcp->auth_ctx   = n;
    tcp->on_accept  = th_on_accept;
    tcp->on_session = th_on_session;
}

/** The pin (one server) and the chain id of a client config. The node must
 *  outlive the client (pinned_server_fps is not copied). */
static inline void th_client_cfg(nodus_client_config_t *cfg, const th_node_t *n) {
    cfg->pinned_server_fps      = &n->pin;
    cfg->pinned_server_fp_count = 1;
    memcpy(cfg->expected_chain_id, n->chain_id, sizeof(cfg->expected_chain_id));
    cfg->has_expected_chain_id  = true;
}

#endif /* TEST_SESSION_HELPER_H */
