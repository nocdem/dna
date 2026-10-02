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
} inproc_backend_t;

static nodus_witness_t *inproc_w(nodus_chain_backend_t *b) {
    return ((inproc_backend_t *)b)->w;
}

static void inproc_tick(nodus_chain_backend_t *b) {
    nodus_witness_tick(inproc_w(b));
}

/* Cluster-status chain fields (nodus_server.c handle_t2_status). The fill
 * itself is witness-side (nodus_witness_status_fill), shared with the
 * nodus-witness process's `ipc_status` answer (split S3). */
static void inproc_status(nodus_chain_backend_t *b,
                          nodus_t2_status_info_t *info) {
    nodus_witness_status_fill(inproc_w(b), info);
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

static void inproc_close(nodus_chain_backend_t *b) {
    inproc_backend_t *ib = (inproc_backend_t *)b;

    nodus_witness_close(ib->w);
    free(ib->w);
    free(ib);
}

static const nodus_chain_backend_ops_t inproc_ops = {
    .tick          = inproc_tick,
    .status        = inproc_status,
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
