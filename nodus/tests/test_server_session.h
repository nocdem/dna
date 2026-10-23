/**
 * Nodus — test helper: a REAL nodus_server_t that serves client sessions
 * (DHT v2 3b-2), and the client config that connects to it.
 *
 * A server accepts a 4001 / WebSocket connection only when it knows the chain
 * id of its sessions (nodus_server_chain_id: from its chain backend, which a
 * test server does not have — no witness). A test therefore presets it in
 * the server thread, right after nodus_server_init returns and BEFORE it
 * reports ready (so the main thread's connect happens-after the write):
 *
 *     ts_server_chain(&server, 0x77);
 *
 * and fills each client config from the running server's identity (the pin
 * is its node id; the server identity is generated or loaded by
 * nodus_server_init):
 *
 *     ts_client_cfg(&cfg, &server, 0x77);
 *
 * Header-only, test code only.
 */

#ifndef TEST_SERVER_SESSION_H
#define TEST_SERVER_SESSION_H

#include <string.h>

#include "nodus/nodus.h"
#include "server/nodus_server.h"

/** Give `srv` a chain id (all bytes `b`): sessions are then served. */
static inline void ts_server_chain(nodus_server_t *srv, uint8_t b) {
    memset(srv->chain_id, b, sizeof(srv->chain_id));
    srv->chain_id_known = true;
}

/** Pin the server's key and bind the client to chain `b`. The server must
 *  outlive the client (pinned_server_fps is not copied). */
static inline void ts_client_cfg(nodus_client_config_t *cfg,
                                 const nodus_server_t *srv, uint8_t b) {
    cfg->pinned_server_fps      = &srv->identity.node_id;
    cfg->pinned_server_fp_count = 1;
    memset(cfg->expected_chain_id, b, sizeof(cfg->expected_chain_id));
    cfg->has_expected_chain_id  = true;
}

#endif /* TEST_SERVER_SESSION_H */
