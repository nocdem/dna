/**
 * Test helper for the tests that run a fake node or a real server beside
 * a nodus_client (approved 4001 plan 4.2, build-order step 7). The 4001
 * handshake is the secret connection now: a fake node attaches the responder
 * module to its transport instead of answering hello / auth / key_init, and a
 * client config carries the fake's fingerprint and the chain id.
 *
 * What it gives a test:
 *   nts_attach(tcp, node)   responder module (proto_ver 4001, chain id
 *                           NODUS_TEST_CHAIN, workers 0 with inline jobs: the
 *                           fake's own polling thread runs them) that opens
 *                           every authenticated session. Call BEFORE listen.
 *   nts_trust(cfg, node)    the client's trusted list (the node's id) and chain
 *                           id.
 *   nts_fake_chain_be(be)   the in-process server table with a chain backend
 *                           that reports an open chain and the chain id
 *                           NODUS_TEST_CHAIN (for tests that run a real
 *                           nodus_server_t through nodus_server_init_ex).
 * Nothing here is a production value; the chain id is a test constant.
 */
#ifndef NODUS_TEST_SESSION_H
#define NODUS_TEST_SESSION_H

#include "nodus/nodus.h"
#include "server/nodus_inter_session.h"
#include "server/nodus_server.h"
#include "server/nodus_chain_backend.h"
#include "crypto/nodus_identity.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t NODUS_TEST_CHAIN[32] = {
    0x7e, 0x57, 0xc0, 0xde, 0x40, 0x01, [31] = 0x01
};

static inline void nts_on_authenticated(nodus_tcp_conn_t *conn,
                                        const nodus_pubkey_t *pk, void *ctx) {
    (void)pk; (void)ctx;
    (void)nodus_inter_session_open(conn);
}

static inline nodus_inter_session_module_t *nts_attach(nodus_tcp_t *tcp,
                                                       const nodus_identity_t *node) {
    nodus_inter_session_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.identity = node;
    cfg.proto_ver = CMT_P2P_SC_PROTO_VER_4001;
    cfg.chain_id = NODUS_TEST_CHAIN;
    cfg.inbound_depth = 8;
    cfg.outbound_depth = 8;
    cfg.workers = 0;
    cfg.run_jobs_inline = true;
    cfg.on_authenticated = nts_on_authenticated;
    return nodus_inter_session_new(tcp, &cfg);
}

static inline void nts_trust(nodus_client_config_t *cfg, const nodus_identity_t *node) {
    cfg->pinned_server_fps = &node->node_id;     /* outlives the client: caller's */
    cfg->pinned_server_fp_count = 1;
    memcpy(cfg->chain_id, NODUS_TEST_CHAIN, sizeof(cfg->chain_id));
    cfg->has_chain_id = true;
}

/* A chain backend that only reports "chain open" and the test chain id. */
typedef struct { nodus_chain_backend_t base; } nts_chain_t;
static inline void nts_tick(nodus_chain_backend_t *b) { (void)b; }
static inline bool nts_pending(nodus_chain_backend_t *b) { (void)b; return false; }
static inline bool nts_open(nodus_chain_backend_t *b) { (void)b; return true; }
static inline void nts_status(nodus_chain_backend_t *b, nodus_t2_status_info_t *st) {
    (void)b;
    st->block_height = 1;
    memcpy(st->chain_id_v3, NODUS_TEST_CHAIN, 32);
    st->chain_id_v3_valid = true;
}
static inline int nts_port(nodus_chain_backend_t *b, bool *opened) { (void)b; *opened = false; return 0; }
static inline void nts_closed(nodus_chain_backend_t *b, nodus_tcp_conn_t *c) { (void)b; (void)c; }
static inline void nts_close(nodus_chain_backend_t *b) { free(b); }
static const nodus_chain_backend_ops_t nts_ops = {
    .tick = nts_tick, .read_pending = nts_pending, .status = nts_status,
    .chain_open = nts_open, .listen_port = nts_port,
    .session_closed = nts_closed, .close = nts_close,
};
static inline int nts_new_chain(const nodus_witness_host_t *h, const nodus_witness_config_t *cfg,
                                nodus_chain_backend_t **out) {
    (void)h; (void)cfg;
    nts_chain_t *c = calloc(1, sizeof(*c));
    if (!c) return -2;
    c->base.ops = &nts_ops;
    *out = &c->base;
    return 0;
}
static inline void nts_fake_chain_be(nodus_server_backends_t *be) {
    *be = nodus_server_backends_inproc;
    be->chain_open = nts_new_chain;
}

#endif
