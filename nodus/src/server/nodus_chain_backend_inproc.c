/**
 * Nodus — Chain backend, in-process implementation
 *
 * The witness module runs inside this process (the combined nodus-server).
 * Every operation is the call nodus_server.c made directly before the S1
 * witness seam (decision 2026-10-01-nodus-component-split.md), moved here
 * unchanged; the server reaches the witness through nodus_chain_backend.h
 * only.
 *
 * @file nodus_chain_backend_inproc.c
 */

#include "server/nodus_chain_backend.h"
#include "witness/nodus_witness.h"
#include "transport/nodus_tcp.h"               /* nodus_time_mono_ms */
#include "witness/nodus_witness_ipc.h"         /* nodus_witness_status_fill */
#include "witness/nodus_witness_p2p.h"         /* the 4004 listen port (log) */
#include "witness/nodus_witness_network_file.h" /* nodus_witness_check_chain_pin */

#include <stdlib.h>
#include <string.h>

typedef struct {
    nodus_chain_backend_t   base;       /* first member: ops */
    /* The witness's host view. Owned here so it lives exactly as long as
     * the witness that points at it (nodus_witness_t.host). */
    nodus_witness_host_t    host;
    nodus_witness_t        *w;
    /* The active-role set, refilled from the witness' 4004 host at most
     * every NODUS_ROLE_SET_EVERY_MS (a SQLite read) — has_role below. */
    nodus_role_set_t        roles;
} inproc_backend_t;

static nodus_witness_t *inproc_w(nodus_chain_backend_t *b) {
    return ((inproc_backend_t *)b)->w;
}

static void inproc_tick(nodus_chain_backend_t *b) {
    nodus_witness_tick(inproc_w(b));
}

/* The witness polls its own 4004 host inside the tick; nothing here for
 * the server loop to hurry for — its poll timings stay as they were. */
static bool inproc_read_pending(nodus_chain_backend_t *b) {
    (void)b;
    return false;
}

/* Cluster-status chain fields (nodus_server.c handle_t2_status). The fill
 * itself is witness-side (nodus_witness_status_fill), shared with the
 * nodus-witness process's `ipc_status` answer (split S3). */
static void inproc_status(nodus_chain_backend_t *b,
                          nodus_t2_status_info_t *info) {
    nodus_witness_status_fill(inproc_w(b), info);
}

/* The v3 chain id (witness/nodus_witness_ipc.c nodus_witness_dht_chain_id:
 * nodus_witness_v2_chain_id, served from the witness's cache once the post-
 * open gate has derived it). */
static bool inproc_chain_id_v3(nodus_chain_backend_t *b, uint8_t out[32]) {
    return nodus_witness_dht_chain_id(inproc_w(b), out) == 0;
}

static bool inproc_chain_open(nodus_chain_backend_t *b) {
    return inproc_w(b)->db != NULL;
}

static int inproc_listen_port(nodus_chain_backend_t *b, bool *opened) {
    nodus_witness_t *w = inproc_w(b);

    *opened = w->p2p != NULL;
    return (int)nodus_witness_p2p_listen_port(w->p2p);
}

static void inproc_dispatch_dnac(nodus_chain_backend_t *b,
                                 struct nodus_tcp_conn *conn,
                                 const uint8_t client_pk[NODUS_PK_BYTES],
                                 const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                 const uint8_t *payload, size_t len,
                                 const char *method, uint32_t txn_id) {
    (void)client_pk;    /* the witness reads the session from `conn` */
    (void)token;
    nodus_witness_dispatch_dnac(inproc_w(b), conn, payload, len,
                                method, txn_id);
}

static void inproc_cc_collect(nodus_chain_backend_t *b,
                              struct nodus_tcp_conn *conn,
                              const uint8_t client_pk[NODUS_PK_BYTES],
                              const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                              const uint8_t *payload, size_t len,
                              uint32_t txn_id) {
    nodus_witness_handle_cc_collect(inproc_w(b), conn, client_pk, token,
                                    payload, len, txn_id);
}

/* The in-process witness finds sessions in the server's own table
 * (nodus_server_witness_host's find_session_conn), which the server has
 * just cleared — nothing to forget here. */
static void inproc_session_closed(nodus_chain_backend_t *b,
                                  struct nodus_tcp_conn *conn) {
    (void)b;
    (void)conn;
}

/* Active on-chain role of a PROVEN key (operator addendum 2026-10-26): the
 * witness' own derivation (nodus_witness_p2p_roles_fill — the bonded set plus
 * the registry's ACTIVE / EXITING rows), cached for NODUS_ROLE_SET_EVERY_MS so
 * an accept burst does not read SQLite per session. Fail safe: a failed fill
 * leaves the set unknown (false). */
static bool inproc_roles_known(nodus_chain_backend_t *b) {
    inproc_backend_t *ib = (inproc_backend_t *)b;
    uint64_t now = nodus_time_mono_ms();
    if (!ib->w->p2p) return false;
    if (!ib->roles.fps) {
        ib->roles.fps = malloc((size_t)NODUS_ROLE_SET_MAX * 64);
        if (!ib->roles.fps) return false;
    }
    if (!ib->roles.at_ms || now - ib->roles.at_ms >= NODUS_ROLE_SET_EVERY_MS) {
        uint32_t n = 0;
        ib->roles.known = nodus_witness_p2p_roles_fill(ib->w->p2p, ib->roles.fps,
                                                      NODUS_ROLE_SET_MAX, &n) == 0;
        ib->roles.n = ib->roles.known ? n : 0;
        nodus_role_set_sort(&ib->roles);
        ib->roles.at_ms = now;
    }
    return nodus_role_set_known(&ib->roles, now);
}

static bool inproc_has_role(nodus_chain_backend_t *b, const nodus_key_t *node_id) {
    inproc_backend_t *ib = (inproc_backend_t *)b;
    return inproc_roles_known(b) &&
           nodus_role_set_has(&ib->roles, node_id, nodus_time_mono_ms());
}

static nodus_role_state_t inproc_role_state(nodus_chain_backend_t *b,
                                            const nodus_key_t *node_id,
                                            uint64_t now_ms) {
    return nodus_role_set_state(&((inproc_backend_t *)b)->roles, node_id, now_ms);
}

static void inproc_close(nodus_chain_backend_t *b) {
    inproc_backend_t *ib = (inproc_backend_t *)b;

    free(ib->roles.fps);
    nodus_witness_close(ib->w);
    free(ib->w);
    free(ib);
}

static const nodus_chain_backend_ops_t inproc_ops = {
    .tick          = inproc_tick,
    .read_pending  = inproc_read_pending,
    .status        = inproc_status,
    .chain_id_v3   = inproc_chain_id_v3,
    .has_role      = inproc_has_role,
    .roles_known   = inproc_roles_known,
    .role_state    = inproc_role_state,
    .chain_open    = inproc_chain_open,
    .listen_port   = inproc_listen_port,
    .dispatch_dnac = inproc_dispatch_dnac,
    .cc_collect    = inproc_cc_collect,
    .session_closed = inproc_session_closed,
    .close         = inproc_close,
};

int nodus_chain_backend_inproc_check_pin(const char *data_path,
                                         const uint8_t pin[32]) {
    return nodus_witness_check_chain_pin(data_path, pin);
}

int nodus_chain_backend_inproc_open(const nodus_witness_host_t *host,
                                    const nodus_witness_config_t *config,
                                    nodus_chain_backend_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!host || !config) return -1;

    inproc_backend_t *ib = calloc(1, sizeof(*ib));
    if (!ib) return -2;
    ib->w = calloc(1, sizeof(nodus_witness_t));
    if (!ib->w) {
        free(ib);
        return -2;
    }
    ib->base.ops = &inproc_ops;
    ib->host = *host;

    if (nodus_witness_init(ib->w, &ib->host, config) != 0) {
        /* A failed init is freed WITHOUT nodus_witness_close — the
         * witness stops its own p2p host on that path
         * (nodus_witness_init). */
        free(ib->w);
        free(ib);
        return -1;
    }
    *out = &ib->base;
    return 0;
}
