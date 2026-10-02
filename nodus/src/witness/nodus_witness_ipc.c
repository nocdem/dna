/**
 * Nodus — Witness IPC (the nodus-witness process's local socket)
 *
 * Component split S3: the listener side of <data_path>/witness.sock. The
 * frame formats and connection kinds are documented in nodus_witness_ipc.h;
 * the core side is server/nodus_chain_backend_ipc.c.
 *
 * Its own nodus_tcp_t (never the client or the inter-node pool), one
 * connection kind per slot of that pool, decided by the connection's first
 * frame. A session connection carries the client session's identity from
 * its preface onto the connection itself (peer_pk / peer_id /
 * peer_id_set), because the witness's dnac handlers read the requester
 * from `conn` exactly as they do on a client connection in the combined
 * binary (nodus_auth.c sets the same three fields there).
 *
 * Bound: a connection whose own queue toward core has reached
 * NODUS_WITNESS_IPC_REPLY_QUEUE_MAX is closed on its next frame instead of
 * dispatching it (ipc_on_frame) — the witness's memory per connection
 * stays bounded when core stops reading, and nothing here ever waits.
 *
 * @file nodus_witness_ipc.c
 */

#include "witness/nodus_witness_ipc.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"          /* nodus_witness_block_height */
#include "witness/nodus_witness_p2p.h"         /* nodus_witness_p2p_listen_port */
#include "witness/nodus_witness_v2_apply.h"    /* nodus_witness_v2_committed_global_root (W4-H) */
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"                 /* nodus_fingerprint */
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "WITNESS_IPC"

/* ── Status (shared with the in-process backend) ─────────────────── */

void nodus_witness_status_fill(nodus_witness_t *w,
                               nodus_t2_status_info_t *info) {
    if (!w->db) return;
    info->block_height = nodus_witness_block_height(w);
    if (w->v2_successor) {
        /* R3 W4 package H: on a version-3 chain the legacy cached
         * state root is never written (the Comet apply lane keeps
         * no `blocks` row), so the column was EMPTY while HEIGHT
         * already reported the `v2_blocks` tip. Report the committed
         * GLOBAL ROOT of that tip instead — the row the engine wrote
         * (`nodus_witness_v2_committed_global_root`: the authority is
         * the stored `v2_blocks.global_root`, never a recompute), the
         * same quantity `stagef_cmt_diff_at_floor` compares across
         * nodes. A chain with no committed row yet leaves it zero. */
        if (nodus_witness_v2_committed_global_root(w,
                                                   info->state_root) != 0) {
            memset(info->state_root, 0, sizeof(info->state_root));
        }
    }
    /* Root-layout round (K3): the legacy `else` branch that copied
     * `cached_state_root` is deleted with that field (it had no
     * writer); a non-successor witness reports the zeroed
     * state_root from the caller's memset, as it already did. */
    memcpy(info->chain_id, w->chain_id, 32);
}

/* ── Handlers bound to a witness ─────────────────────────────────── */

static void witness_h_dispatch_dnac(void *ctx, nodus_tcp_conn_t *conn,
                                    const uint8_t *payload, size_t len,
                                    const char *method, uint32_t txn_id) {
    nodus_witness_dispatch_dnac((nodus_witness_t *)ctx, conn, payload, len,
                                method, txn_id);
}

static void witness_h_cc_collect(void *ctx, nodus_tcp_conn_t *conn,
                                 const uint8_t client_pk[NODUS_PK_BYTES],
                                 const uint8_t token[NODUS_SESSION_TOKEN_LEN],
                                 const uint8_t *payload, size_t len,
                                 uint32_t txn_id) {
    nodus_witness_handle_cc_collect((nodus_witness_t *)ctx, conn, client_pk,
                                    token, payload, len, txn_id);
}

static void witness_h_status(void *ctx, nodus_witness_ipc_status_t *out) {
    nodus_witness_t *w = (nodus_witness_t *)ctx;
    nodus_t2_status_info_t info;

    memset(&info, 0, sizeof(info));
    nodus_witness_status_fill(w, &info);
    memset(out, 0, sizeof(*out));
    out->chain_open = w->db != NULL;
    out->height = info.block_height;
    memcpy(out->state_root, info.state_root, sizeof(out->state_root));
    memcpy(out->chain_id, info.chain_id, sizeof(out->chain_id));
    out->p2p_opened = w->p2p != NULL;
    out->listen_port = nodus_witness_p2p_listen_port(w->p2p);
}

void nodus_witness_ipc_handlers_for(nodus_witness_t *w,
                                    nodus_witness_ipc_handlers_t *out) {
    memset(out, 0, sizeof(*out));
    out->dispatch_dnac = witness_h_dispatch_dnac;
    out->cc_collect    = witness_h_cc_collect;
    out->status        = witness_h_status;
    out->ctx           = w;
}

/* ── The listener ────────────────────────────────────────────────── */

typedef enum {
    IPC_KIND_NONE = 0,      /* accepted, first frame not seen yet */
    IPC_KIND_SESSION,       /* ipc_hello: one core client session */
    IPC_KIND_CTL            /* ipc_ctl: core's control connection */
} ipc_kind_t;

typedef struct {
    ipc_kind_t  kind;
    uint8_t     token[NODUS_SESSION_TOKEN_LEN];
    uint8_t     pk[NODUS_PK_BYTES];
} ipc_slot_t;

struct nodus_witness_ipc {
    nodus_tcp_t                   tcp;
    nodus_witness_ipc_handlers_t  h;
    /* Indexed by conn->slot of `tcp` (its pool index). */
    ipc_slot_t                    slots[NODUS_TCP_MAX_CONNS];
};

static ipc_slot_t *ipc_slot(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn) {
    if (!conn || conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS)
        return NULL;
    return &ipc->slots[conn->slot];
}

static void ipc_slot_reset(ipc_slot_t *s) {
    memset(s, 0, sizeof(*s));
}

/* Parse a control-plane frame: a CBOR map of at most three entries with
 * "q" (text) and, for ipc_hello, "pk" and "tk" (byte strings of exactly
 * their sizes). Any other key, a repeated key, a wrong type or size, or
 * trailing bytes refuse the frame.
 * @return 0 and `q` (NUL-terminated) set; -1 refused. */
static int ipc_parse_ctl(const uint8_t *p, size_t len,
                         char q[32], bool *has_pk, uint8_t pk[NODUS_PK_BYTES],
                         bool *has_tk,
                         uint8_t tk[NODUS_SESSION_TOKEN_LEN]) {
    cbor_decoder_t dec;
    cbor_decoder_init(&dec, p, len);

    cbor_item_t m = cbor_decode_next(&dec);
    if (m.type != CBOR_ITEM_MAP || m.count == 0 || m.count > 3) return -1;

    bool has_q = false;
    *has_pk = false;
    *has_tk = false;
    for (size_t i = 0; i < m.count; i++) {
        cbor_item_t k = cbor_decode_next(&dec);
        if (k.type != CBOR_ITEM_TSTR) return -1;
        cbor_item_t v = cbor_decode_next(&dec);
        if (k.tstr.len == 1 && memcmp(k.tstr.ptr, "q", 1) == 0) {
            if (has_q || v.type != CBOR_ITEM_TSTR || v.tstr.len >= 32)
                return -1;
            memcpy(q, v.tstr.ptr, v.tstr.len);
            q[v.tstr.len] = '\0';
            has_q = true;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "pk", 2) == 0) {
            if (*has_pk || v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != NODUS_PK_BYTES)
                return -1;
            memcpy(pk, v.bstr.ptr, NODUS_PK_BYTES);
            *has_pk = true;
        } else if (k.tstr.len == 2 && memcmp(k.tstr.ptr, "tk", 2) == 0) {
            if (*has_tk || v.type != CBOR_ITEM_BSTR ||
                v.bstr.len != NODUS_SESSION_TOKEN_LEN)
                return -1;
            memcpy(tk, v.bstr.ptr, NODUS_SESSION_TOKEN_LEN);
            *has_tk = true;
        } else {
            return -1;
        }
    }
    if (dec.error || dec.pos != len || !has_q) return -1;
    return 0;
}

static void ipc_refuse(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn,
                       const char *why) {
    QGP_LOG_WARN(LOG_TAG, "closing IPC connection slot=%d: %s",
                 conn->slot, why);
    nodus_tcp_disconnect(&ipc->tcp, conn);
}

static void ipc_on_first_frame(nodus_witness_ipc_t *ipc, ipc_slot_t *s,
                               nodus_tcp_conn_t *conn,
                               const uint8_t *payload, size_t len) {
    char q[32];
    bool has_pk = false, has_tk = false;
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t tk[NODUS_SESSION_TOKEN_LEN];

    if (ipc_parse_ctl(payload, len, q, &has_pk, pk, &has_tk, tk) != 0) {
        ipc_refuse(ipc, conn, "first frame is not an IPC preface");
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_HELLO) == 0 && has_pk && has_tk) {
        nodus_pubkey_t pub;
        nodus_key_t fp;

        memcpy(pub.bytes, pk, NODUS_PK_BYTES);
        if (nodus_fingerprint(&pub, &fp) != 0) {
            ipc_refuse(ipc, conn, "preface key has no fingerprint");
            return;
        }
        s->kind = IPC_KIND_SESSION;
        memcpy(s->pk, pk, NODUS_PK_BYTES);
        memcpy(s->token, tk, NODUS_SESSION_TOKEN_LEN);
        /* The requester, on the connection, as nodus_auth.c records it
         * on a client connection after AUTH. */
        conn->peer_pk = pub;
        conn->peer_id = fp;
        conn->peer_id_set = true;
        return;
    }
    if (strcmp(q, NODUS_WITNESS_IPC_Q_CTL) == 0 && !has_pk && !has_tk) {
        s->kind = IPC_KIND_CTL;
        return;
    }
    ipc_refuse(ipc, conn, "first frame is neither ipc_hello nor ipc_ctl");
}

static void ipc_on_session_frame(nodus_witness_ipc_t *ipc, ipc_slot_t *s,
                                 nodus_tcp_conn_t *conn,
                                 const uint8_t *payload, size_t len) {
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    /* The decoder the server's dispatch_t2 uses. Core forwards only
     * frames that decoded there, with this session's token. */
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        ipc_refuse(ipc, conn, "session frame does not decode");
        return;
    }
    if (!msg.has_token ||
        memcmp(msg.token, s->token, NODUS_SESSION_TOKEN_LEN) != 0) {
        nodus_t2_msg_free(&msg);
        ipc_refuse(ipc, conn, "session frame carries another token");
        return;
    }
    if (strcmp(msg.method, "dnac_cc_collect") == 0) {
        ipc->h.cc_collect(ipc->h.ctx, conn, s->pk, s->token,
                          payload, len, msg.txn_id);
    } else if (strncmp(msg.method, "dnac_", 5) == 0) {
        ipc->h.dispatch_dnac(ipc->h.ctx, conn, payload, len,
                             msg.method, msg.txn_id);
    } else {
        nodus_t2_msg_free(&msg);
        ipc_refuse(ipc, conn, "session frame is not a dnac_* method");
        return;
    }
    nodus_t2_msg_free(&msg);
}

static void ipc_on_ctl_frame(nodus_witness_ipc_t *ipc, nodus_tcp_conn_t *conn,
                             const uint8_t *payload, size_t len) {
    char q[32];
    bool has_pk = false, has_tk = false;
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t tk[NODUS_SESSION_TOKEN_LEN];

    if (ipc_parse_ctl(payload, len, q, &has_pk, pk, &has_tk, tk) != 0 ||
        strcmp(q, NODUS_WITNESS_IPC_Q_STATUS) != 0 || has_pk || has_tk) {
        ipc_refuse(ipc, conn, "control frame is not ipc_status");
        return;
    }

    nodus_witness_ipc_status_t st;
    memset(&st, 0, sizeof(st));
    ipc->h.status(ipc->h.ctx, &st);

    uint8_t buf[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, sizeof(buf));
    cbor_encode_map(&enc, 7);
    cbor_encode_cstr(&enc, "q");  cbor_encode_cstr(&enc, NODUS_WITNESS_IPC_Q_STATUS);
    cbor_encode_cstr(&enc, "co"); cbor_encode_bool(&enc, st.chain_open);
    cbor_encode_cstr(&enc, "h");  cbor_encode_uint(&enc, st.height);
    cbor_encode_cstr(&enc, "sr"); cbor_encode_bstr(&enc, st.state_root,
                                                   sizeof(st.state_root));
    cbor_encode_cstr(&enc, "ci"); cbor_encode_bstr(&enc, st.chain_id,
                                                   sizeof(st.chain_id));
    cbor_encode_cstr(&enc, "po"); cbor_encode_bool(&enc, st.p2p_opened);
    cbor_encode_cstr(&enc, "lp"); cbor_encode_uint(&enc, st.listen_port);
    size_t n = cbor_encoder_len(&enc);
    if (n == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ipc_status answer does not fit its "
                      "buffer");
        return;
    }
    nodus_tcp_send(conn, buf, n);
}

static void ipc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_slot_t *s = ipc_slot((nodus_witness_ipc_t *)ctx, conn);
    if (s) ipc_slot_reset(s);
}

static void ipc_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_slot_t *s = ipc_slot((nodus_witness_ipc_t *)ctx, conn);
    if (s) ipc_slot_reset(s);
}

/* Bytes this connection has queued toward core and the kernel has not yet
 * taken (the write buffer's unsent part plus the pending FIFO). */
static size_t ipc_queued_bytes(const nodus_tcp_conn_t *conn) {
    return (conn->wlen - conn->wpos) + conn->pending_bytes;
}

static void ipc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                         size_t len, void *ctx) {
    nodus_witness_ipc_t *ipc = (nodus_witness_ipc_t *)ctx;
    ipc_slot_t *s = ipc_slot(ipc, conn);
    if (!s) return;

    /* Bound (NODUS_WITNESS_IPC_REPLY_QUEUE_MAX): core is not reading this
     * connection's replies. Close it rather than dispatch more work that
     * would only grow the queue. Closing is the choice that cannot hold
     * up consensus: it runs here, on this loop, and never waits; the
     * transport has no "stop reading this connection" switch, and leaving
     * frames unread would not shrink the queue either. Core sees the
     * close, forgets the session socket, and its next `dnac_*` dials a
     * new one; what it had forwarded on this one gets no answer (the
     * client times out), as when the witness goes away. */
    if (s->kind != IPC_KIND_NONE &&
        ipc_queued_bytes(conn) >= NODUS_WITNESS_IPC_REPLY_QUEUE_MAX) {
        ipc_refuse(ipc, conn, "its queue to core is over "
                   "NODUS_WITNESS_IPC_REPLY_QUEUE_MAX — core is not "
                   "reading it");
        return;
    }

    switch (s->kind) {
    case IPC_KIND_NONE:
        ipc_on_first_frame(ipc, s, conn, payload, len);
        break;
    case IPC_KIND_SESSION:
        ipc_on_session_frame(ipc, s, conn, payload, len);
        break;
    case IPC_KIND_CTL:
        ipc_on_ctl_frame(ipc, conn, payload, len);
        break;
    }
}

nodus_witness_ipc_t *nodus_witness_ipc_new(const nodus_witness_ipc_handlers_t *h) {
    if (!h || !h->dispatch_dnac || !h->cc_collect || !h->status) return NULL;

    nodus_witness_ipc_t *ipc = calloc(1, sizeof(*ipc));
    if (!ipc) return NULL;
    if (nodus_tcp_init(&ipc->tcp, -1) != 0) {
        free(ipc);
        return NULL;
    }
    ipc->h = *h;
    ipc->tcp.on_accept     = ipc_on_accept;
    ipc->tcp.on_frame      = ipc_on_frame;
    ipc->tcp.on_disconnect = ipc_on_disconnect;
    ipc->tcp.cb_ctx        = ipc;
    return ipc;
}

int nodus_witness_ipc_listen(nodus_witness_ipc_t *ipc, const char *path) {
    if (!ipc || !path) return -1;
    return nodus_tcp_unix_listen(&ipc->tcp, path, NODUS_TCP_UNIX_UID_SELF);
}

void nodus_witness_ipc_poll(nodus_witness_ipc_t *ipc, int timeout_ms) {
    if (!ipc) return;
    nodus_tcp_poll(&ipc->tcp, timeout_ms);
}

nodus_tcp_conn_t *nodus_witness_ipc_find_session_conn(
        void *ctx,
        const uint8_t pk[NODUS_PK_BYTES],
        const uint8_t token[NODUS_SESSION_TOKEN_LEN]) {
    nodus_witness_ipc_t *ipc = (nodus_witness_ipc_t *)ctx;
    if (!ipc || !pk || !token) return NULL;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        const ipc_slot_t *s = &ipc->slots[i];
        nodus_tcp_conn_t *c = ipc->tcp.pool[i];
        if (s->kind == IPC_KIND_SESSION && c != NULL && !c->close_pending &&
            memcmp(s->token, token, NODUS_SESSION_TOKEN_LEN) == 0 &&
            memcmp(s->pk, pk, NODUS_PK_BYTES) == 0) {
            return c;
        }
    }
    return NULL;
}

void nodus_witness_ipc_free(nodus_witness_ipc_t *ipc) {
    if (!ipc) return;
    nodus_tcp_close(&ipc->tcp);
    free(ipc);
}
