/**
 * Nodus — Chain backend, IPC implementation (split S3)
 *
 * The witness is the separate `nodus-witness` process (decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md items 5, 7, 11,
 * 19, 20); this server reaches it over the Unix socket
 * <data_path>/witness.sock. Frame formats: witness/nodus_witness_ipc.h.
 *
 * Its own nodus_tcp_t (never the client or the inter-node pool), polled
 * with a 0 ms wait from `tick`, i.e. once per server loop pass; while it
 * has connections left on its pending-read list (`read_pending`), the
 * server's own polls wait 0 ms too.
 *
 *  - Session sockets (item 19): a client session's first `dnac_*` request
 *    dials one socket, sends the ipc_hello preface (the session's key and
 *    token), then the client's payload unchanged; every later request of
 *    that session goes down the same socket, and every frame the witness
 *    writes on it is sent to the client connection unchanged
 *    (nodus_tcp_send applies the client's channel crypto, as for any
 *    reply). The socket is closed when the server clears the session
 *    (`session_closed`), so a reply the witness sends later finds no
 *    session and is dropped there.
 *  - A witness that cannot be reached, or a session beyond
 *    NODUS_CHAIN_IPC_MAX_SESSION_CONNS, is answered at once with the error
 *    a witness-less server gives (item 20, NODUS_CHAIN_NO_WITNESS_MSG).
 *    "Cannot be reached" includes "the control connection is down": a
 *    session without a socket is then answered without dialling — the
 *    control connection's backoff is the only re-dial driver, so a
 *    stopped witness costs no connect attempt per request.
 *    A request already forwarded when the witness goes away gets no
 *    answer; the client times out.
 *  - Per-session bound: a request whose session socket already has
 *    NODUS_WITNESS_IPC_QUEUE_MAX or more queued toward the witness
 *    (witness/nodus_witness_ipc.h) gets the same error and is not
 *    queued; the socket stays open. Only a failed send (a real transport
 *    fault) closes it.
 *  - The control socket: dialled on the first `tick`, re-dialled with a
 *    bounded backoff while the witness is down; an ipc_status query on
 *    connect and every IPC_STATUS_EVERY_MS after. The last answer is the
 *    chain view `status`, `chain_open` and `listen_port` report; it counts
 *    only while the control socket is up and the answer is younger than
 *    IPC_STATUS_STALE_MS — otherwise this server reports no chain, as a
 *    witness-less server does.
 *
 * Clock: nodus_time_mono_ms only schedules this node's own dialling and
 * ages its own status cache; nothing here is a consensus input.
 *
 * @file nodus_chain_backend_ipc.c
 */

#include "server/nodus_chain_backend.h"
#include "witness/nodus_witness_ipc.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CHAIN_IPC"

#define IPC_STATUS_EVERY_MS    1000    /* status query period            */
#define IPC_STATUS_STALE_MS    5000    /* an older answer is not reported */
#define IPC_DIAL_BACKOFF_MIN   250     /* control re-dial, first wait    */
#define IPC_DIAL_BACKOFF_MAX   5000    /* control re-dial, longest wait  */

/* by_ipc_slot values other than a client slot */
#define IPC_SLOT_FREE   (-1)
#define IPC_SLOT_CTL    (-2)

typedef struct {
    nodus_tcp_conn_t *client;      /* the client connection (server pool) */
    nodus_tcp_conn_t *ipc;         /* its socket to the witness, or NULL  */
    uint8_t           token[NODUS_SESSION_TOKEN_LEN];
} ipc_session_t;

typedef struct {
    nodus_chain_backend_t       base;          /* first member: ops */
    nodus_tcp_t                 tcp;
    char                        path[NODUS_TCP_UNIX_PATH_MAX];

    /* Indexed by the CLIENT connection's slot (server pool). */
    ipc_session_t               sess[NODUS_TCP_MAX_CONNS];
    /* Indexed by the IPC connection's slot (this backend's pool). */
    int                         by_ipc_slot[NODUS_TCP_MAX_CONNS];
    int                         n_sess;
    bool                        cap_logged;

    nodus_tcp_conn_t           *ctl;
    uint64_t                    ctl_next_dial_ms;
    uint64_t                    ctl_backoff_ms;
    uint64_t                    ctl_last_query_ms;

    bool                        snap_have;
    uint64_t                    snap_at_ms;
    nodus_witness_ipc_status_t  snap;
} ipc_backend_t;

static ipc_backend_t *ipc_be(nodus_chain_backend_t *b) {
    return (ipc_backend_t *)b;
}

/* ── Status snapshot ─────────────────────────────────────────────── */

/* Decode an ipc_status answer (witness/nodus_witness_ipc.h). Every key
 * must be present exactly once with its type and size. @return 0 / -1. */
static int ipc_status_decode(const uint8_t *p, size_t len,
                             nodus_witness_ipc_status_t *out) {
    enum { K_Q = 1, K_CO = 2, K_H = 4, K_SR = 8, K_CI = 16, K_PO = 32,
           K_LP = 64, K_ALL = 127 };
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);

    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count != 7) return -1;

    unsigned seen = 0;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        cbor_item_t v = cbor_decode_next(&dec);
        unsigned bit;
        if (k.tstr.len == 1 && memcmp(k.tstr.ptr, "q", 1) == 0) {
            if (v.type != CBOR_ITEM_TSTR ||
                v.tstr.len != strlen(NODUS_WITNESS_IPC_Q_STATUS) ||
                memcmp(v.tstr.ptr, NODUS_WITNESS_IPC_Q_STATUS,
                       v.tstr.len) != 0)
                return -1;
            bit = K_Q;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "co", 2) == 0) {
            if (v.type != CBOR_ITEM_BOOL) return -1;
            out->chain_open = v.bool_val;
            bit = K_CO;
        } else if (k.tstr.len == 1 && memcmp(k.tstr.ptr, "h", 1) == 0) {
            if (v.type != CBOR_ITEM_UINT) return -1;
            out->height = v.uint_val;
            bit = K_H;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "sr", 2) == 0) {
            if (v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != sizeof(out->state_root))
                return -1;
            memcpy(out->state_root, v.bstr.ptr, sizeof(out->state_root));
            bit = K_SR;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "ci", 2) == 0) {
            if (v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != sizeof(out->chain_id))
                return -1;
            memcpy(out->chain_id, v.bstr.ptr, sizeof(out->chain_id));
            bit = K_CI;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "po", 2) == 0) {
            if (v.type != CBOR_ITEM_BOOL) return -1;
            out->p2p_opened = v.bool_val;
            bit = K_PO;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "lp", 2) == 0) {
            if (v.type != CBOR_ITEM_UINT || v.uint_val > UINT16_MAX)
                return -1;
            out->listen_port = (uint16_t)v.uint_val;
            bit = K_LP;
        } else {
            return -1;
        }
        if (seen & bit) return -1;
        seen |= bit;
    }
    if (dec.error || dec.pos != len || seen != K_ALL) return -1;
    return 0;
}

/* The snapshot, if it may be reported now. */
static const nodus_witness_ipc_status_t *ipc_snap(ipc_backend_t *ib) {
    if (!ib->ctl || !ib->snap_have) return NULL;
    if (nodus_time_mono_ms() - ib->snap_at_ms > IPC_STATUS_STALE_MS)
        return NULL;
    return &ib->snap;
}

/* ── Control connection ──────────────────────────────────────────── */

static void ipc_ctl_send_q(ipc_backend_t *ib, const char *q) {
    uint8_t buf[64];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 1);
    cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, q);
    size_t n = cbor_encoder_len(&enc);
    if (n > 0)
        nodus_tcp_send(ib->ctl, buf, n);
}

static void ipc_ctl_tick(ipc_backend_t *ib) {
    uint64_t now = nodus_time_mono_ms();

    if (!ib->ctl) {
        if (now < ib->ctl_next_dial_ms) return;
        nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&ib->tcp, ib->path,
                                                     NODUS_TCP_UNIX_UID_SELF);
        if (!c) {
            ib->ctl_next_dial_ms = now + ib->ctl_backoff_ms;
            ib->ctl_backoff_ms *= 2;
            if (ib->ctl_backoff_ms > IPC_DIAL_BACKOFF_MAX)
                ib->ctl_backoff_ms = IPC_DIAL_BACKOFF_MAX;
            return;
        }
        ib->ctl = c;
        ib->by_ipc_slot[c->slot] = IPC_SLOT_CTL;
        ib->ctl_backoff_ms = IPC_DIAL_BACKOFF_MIN;
        QGP_LOG_INFO(LOG_TAG, "control connection to the witness up (%s)",
                     ib->path);
        ipc_ctl_send_q(ib, NODUS_WITNESS_IPC_Q_CTL);
        ipc_ctl_send_q(ib, NODUS_WITNESS_IPC_Q_STATUS);
        ib->ctl_last_query_ms = now;
        return;
    }
    if (now - ib->ctl_last_query_ms >= IPC_STATUS_EVERY_MS) {
        ipc_ctl_send_q(ib, NODUS_WITNESS_IPC_Q_STATUS);
        ib->ctl_last_query_ms = now;
    }
}

/* ── Session sockets ─────────────────────────────────────────────── */

static void ipc_session_close(ipc_backend_t *ib, ipc_session_t *s) {
    if (!s->ipc) return;
    /* nodus_tcp_disconnect runs ipc_on_disconnect, which clears `s`. */
    nodus_tcp_disconnect(&ib->tcp, s->ipc);
}

/* The open socket of this client session, dialling it (and sending the
 * preface) on the first request. NULL: the witness cannot be reached or
 * the session cap is reached — the caller answers the item-20 error. */
static nodus_tcp_conn_t *ipc_session_conn(ipc_backend_t *ib,
                                          nodus_tcp_conn_t *client,
                                          const uint8_t pk[NODUS_PK_BYTES],
                                          const uint8_t token[NODUS_SESSION_TOKEN_LEN]) {
    if (!client || client->slot < 0 || client->slot >= NODUS_TCP_MAX_CONNS)
        return NULL;
    ipc_session_t *s = &ib->sess[client->slot];

    /* A socket opened for another connection or token in this slot is
     * not this session's. */
    if (s->ipc && (s->client != client ||
                   memcmp(s->token, token, NODUS_SESSION_TOKEN_LEN) != 0))
        ipc_session_close(ib, s);
    if (s->ipc) return s->ipc;

    /* No control connection = the witness is known unreachable (its last
     * dial failed or it went away). Do not dial a session socket for it:
     * every `dnac_*` would otherwise cost a failed connect and a WARN.
     * The control connection's backoff (ipc_ctl_tick) is the one re-dial
     * driver; once it is back, sessions dial again. */
    if (!ib->ctl) return NULL;

    if (ib->n_sess >= NODUS_CHAIN_IPC_MAX_SESSION_CONNS) {
        if (!ib->cap_logged) {
            QGP_LOG_WARN(LOG_TAG, "%d client sessions already hold a witness "
                         "socket (the cap) — further sessions are answered "
                         "\"" NODUS_CHAIN_NO_WITNESS_MSG "\"",
                         NODUS_CHAIN_IPC_MAX_SESSION_CONNS);
            ib->cap_logged = true;
        }
        return NULL;
    }

    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&ib->tcp, ib->path,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) return NULL;

    uint8_t buf[NODUS_PK_BYTES + NODUS_SESSION_TOKEN_LEN + 64];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 3);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_HELLO);
    cbor_encode_cstr(&enc, "pk"); cbor_encode_bstr(&enc, pk, NODUS_PK_BYTES);
    cbor_encode_cstr(&enc, "tk"); cbor_encode_bstr(&enc, token,
                                                   NODUS_SESSION_TOKEN_LEN);
    size_t n = cbor_encoder_len(&enc);
    if (n == 0 || nodus_tcp_send(c, buf, n) != 0) {
        nodus_tcp_disconnect(&ib->tcp, c);
        return NULL;
    }

    s->client = client;
    s->ipc = c;
    memcpy(s->token, token, NODUS_SESSION_TOKEN_LEN);
    ib->by_ipc_slot[c->slot] = client->slot;
    ib->n_sess++;
    return c;
}

static void ipc_no_witness(nodus_tcp_conn_t *client, uint32_t txn_id) {
    uint8_t buf[256];
    size_t rlen = 0;
    if (nodus_t2_error(txn_id, NODUS_ERR_PROTOCOL_ERROR,
                       NODUS_CHAIN_NO_WITNESS_MSG,
                       buf, sizeof(buf), &rlen) == 0)
        nodus_tcp_send(client, buf, rlen);
}

static void ipc_forward(ipc_backend_t *ib, nodus_tcp_conn_t *client,
                        const uint8_t pk[NODUS_PK_BYTES],
                        const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                        const uint8_t *payload, size_t len, uint32_t txn_id) {
    nodus_tcp_conn_t *c = ipc_session_conn(ib, client, pk, token);
    if (!c) {
        ipc_no_witness(client, txn_id);
        return;
    }
    /* Per-session bound (NODUS_WITNESS_IPC_QUEUE_MAX): the witness is not
     * taking this session's requests as fast as the client sends them.
     * Answer this one request and queue nothing; the socket and what it
     * already carries stay. */
    if ((c->wlen - c->wpos) + c->pending_bytes >= NODUS_WITNESS_IPC_QUEUE_MAX) {
        ipc_no_witness(client, txn_id);
        return;
    }
    /* With the bound above, a send fails only on a real transport fault
     * (allocation, peer gone) — then the socket is useless. */
    if (nodus_tcp_send(c, payload, len) != 0) {
        ipc_session_close(ib, &ib->sess[client->slot]);
        ipc_no_witness(client, txn_id);
    }
}

/* ── Transport callbacks ─────────────────────────────────────────── */

static void ipc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    ipc_backend_t *ib = (ipc_backend_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    int cs = ib->by_ipc_slot[conn->slot];

    if (cs == IPC_SLOT_CTL && conn == ib->ctl) {
        nodus_witness_ipc_status_t st;
        if (ipc_status_decode(payload, len, &st) != 0) {
            QGP_LOG_WARN(LOG_TAG, "%s", "malformed ipc_status answer — "
                         "closing the control connection");
            nodus_tcp_disconnect(&ib->tcp, conn);
            return;
        }
        ib->snap = st;
        ib->snap_have = true;
        ib->snap_at_ms = nodus_time_mono_ms();
        return;
    }
    if (cs >= 0 && ib->sess[cs].ipc == conn) {
        /* The witness's reply, to the client, unchanged. */
        nodus_tcp_send(ib->sess[cs].client, payload, len);
    }
}

static void ipc_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_backend_t *ib = (ipc_backend_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    int cs = ib->by_ipc_slot[conn->slot];
    ib->by_ipc_slot[conn->slot] = IPC_SLOT_FREE;

    if (cs == IPC_SLOT_CTL && conn == ib->ctl) {
        ib->ctl = NULL;
        ib->snap_have = false;
        ib->ctl_next_dial_ms = nodus_time_mono_ms() + ib->ctl_backoff_ms;
        QGP_LOG_WARN(LOG_TAG, "control connection to the witness lost (%s) "
                     "— chain status unavailable until it is back", ib->path);
        return;
    }
    if (cs >= 0 && ib->sess[cs].ipc == conn) {
        memset(&ib->sess[cs], 0, sizeof(ib->sess[cs]));
        ib->n_sess--;
        if (ib->n_sess < NODUS_CHAIN_IPC_MAX_SESSION_CONNS)
            ib->cap_logged = false;
    }
}

/* ── Ops ─────────────────────────────────────────────────────────── */

static void ipcb_tick(nodus_chain_backend_t *b) {
    ipc_backend_t *ib = ipc_be(b);
    ipc_ctl_tick(ib);
    nodus_tcp_poll(&ib->tcp, 0);
}

static bool ipcb_read_pending(nodus_chain_backend_t *b) {
    return nodus_tcp_read_pending(&ipc_be(b)->tcp);
}

static void ipcb_status(nodus_chain_backend_t *b, nodus_t2_status_info_t *info) {
    const nodus_witness_ipc_status_t *st = ipc_snap(ipc_be(b));
    /* Mirrors inproc_status: untouched when no chain is open. */
    if (!st || !st->chain_open) return;
    info->block_height = st->height;
    memcpy(info->state_root, st->state_root, sizeof(info->state_root));
    memcpy(info->chain_id, st->chain_id, sizeof(info->chain_id));
}

static bool ipcb_chain_open(nodus_chain_backend_t *b) {
    const nodus_witness_ipc_status_t *st = ipc_snap(ipc_be(b));
    return st && st->chain_open;
}

static int ipcb_listen_port(nodus_chain_backend_t *b, bool *opened) {
    const nodus_witness_ipc_status_t *st = ipc_snap(ipc_be(b));
    *opened = st && st->p2p_opened;
    return st ? (int)st->listen_port : 0;
}

static void ipcb_dispatch_dnac(nodus_chain_backend_t *b,
                               nodus_tcp_conn_t *conn,
                               const uint8_t client_pk[NODUS_PK_BYTES],
                               const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                               const uint8_t *payload, size_t len,
                               const char *method, uint32_t txn_id) {
    (void)method;   /* the witness re-decodes the payload */
    ipc_forward(ipc_be(b), conn, client_pk, token, payload, len, txn_id);
}

static void ipcb_cc_collect(nodus_chain_backend_t *b,
                            nodus_tcp_conn_t *conn,
                            const uint8_t client_pk[NODUS_PK_BYTES],
                            const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                            const uint8_t *payload, size_t len,
                            uint32_t txn_id) {
    ipc_forward(ipc_be(b), conn, client_pk, token, payload, len, txn_id);
}

static void ipcb_session_closed(nodus_chain_backend_t *b,
                                nodus_tcp_conn_t *conn) {
    ipc_backend_t *ib = ipc_be(b);
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    ipc_session_close(ib, &ib->sess[conn->slot]);
}

static void ipcb_close(nodus_chain_backend_t *b) {
    ipc_backend_t *ib = ipc_be(b);
    /* nodus_tcp_close frees the connections without on_disconnect; the
     * tables go with `ib`. */
    nodus_tcp_close(&ib->tcp);
    free(ib);
}

static const nodus_chain_backend_ops_t ipc_ops = {
    .tick           = ipcb_tick,
    .read_pending   = ipcb_read_pending,
    .status         = ipcb_status,
    .chain_open     = ipcb_chain_open,
    .listen_port    = ipcb_listen_port,
    .dispatch_dnac  = ipcb_dispatch_dnac,
    .cc_collect     = ipcb_cc_collect,
    .session_closed = ipcb_session_closed,
    .close          = ipcb_close,
};

int nodus_chain_backend_ipc_open(const char *data_path,
                                 nodus_chain_backend_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!data_path) return -1;

    ipc_backend_t *ib = calloc(1, sizeof(*ib));
    if (!ib) return -2;
    if (nodus_witness_ipc_sock_path(data_path, ib->path,
                                    sizeof(ib->path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "witness socket path under \"%s\" does not "
                      "fit %d bytes", data_path, NODUS_TCP_UNIX_PATH_MAX - 1);
        free(ib);
        return -1;
    }
    if (nodus_tcp_init(&ib->tcp, -1) != 0) {
        free(ib);
        return -2;
    }
    ib->base.ops = &ipc_ops;
    ib->tcp.on_frame      = ipc_on_frame;
    ib->tcp.on_disconnect = ipc_on_disconnect;
    ib->tcp.cb_ctx        = ib;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        ib->by_ipc_slot[i] = IPC_SLOT_FREE;
    ib->ctl_backoff_ms = IPC_DIAL_BACKOFF_MIN;
    ib->ctl_next_dial_ms = 0;          /* first tick dials */
    *out = &ib->base;
    return 0;
}
