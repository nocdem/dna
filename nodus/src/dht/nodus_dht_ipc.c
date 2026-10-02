/**
 * Nodus — DHT IPC, the storage side (the nodus-storage process)
 *
 * Component split S5b. The listener of <data_path>/storage.sock with the
 * origin shadows and the control connection, plus the process's own
 * outbound 4002 pool. Frame formats and connection kinds:
 * dht/nodus_dht_ipc.h; the core side is server/nodus_dht_backend_ipc.c.
 *
 * Two transports of its own: `tcp` (the Unix socket; one connection kind per
 * slot, decided by the preface) and `out` (dialed 4002 connections only —
 * this process listens on no network port). Both are polled from
 * nodus_dht_ipc_poll, on the process's single loop thread.
 *
 *  - Origins (decision item 19, ORCHESTRATOR ruling on Fable S5 H2): ONE
 *    carrier for a session's lifetime. A preface opens the slot's shadow
 *    (nodus_dht_session_opened) and maps (kind, slot) → this connection; the
 *    connection's EOF clears the shadow (nodus_dht_session_closed) only
 *    while the slot still maps to THIS connection. A preface for a slot that
 *    is mapped to another live connection replaces it when it is newer
 *    (another core boot id, or the same boot id and a larger generation —
 *    core closed the old session and the old connection's EOF is still in
 *    flight); an older one is refused (closed). Frames on a connection the
 *    slot no longer maps to belong to an ended session and are dropped.
 *  - The DHT's replies and pushes go to the connection the origin maps to,
 *    only when its generation matches (item 29). A connection whose queue
 *    toward core is at NODUS_DHT_IPC_REPLY_QUEUE_MAX gets nothing more and
 *    is closed at the end of the pass (nodus_dht_ipc_tick); core then ends
 *    that session (decision item 32).
 *  - The control connection: core's UDP datagrams, peer events and
 *    membership snapshots in; datagrams to send and the routing snapshot
 *    out (decision items 17, 27). Never closed for a bound.
 *  - The outbound 4002 pool (decision items 16, 28): replication,
 *    republish, hinted retry and listen forwarding go out on it through the
 *    shared find-or-dial + pre-framed send (server/nodus_inter_dial.h), the
 *    dialer handshake is the shared module (CRIT-1 pin), a pending-full
 *    replication frame is parked in the hint table directly. Any frame on a
 *    dialed connection that is not a handshake reply is dropped with a
 *    WARN: this process serves no 4002 request (core's listener does, with
 *    its F2/F3 gates). Hygiene that core's presence tick and idle sweep did
 *    for the shared pool before the split: the idle / auth-timeout sweep
 *    every 30 s and, every 30 s, the close of dialed connections to IPs that
 *    left the routing table.
 *
 * Clock: nodus_time_mono_ms / nodus_time_now only schedule this node's own
 * pushes and sweeps and age its membership snapshot; nothing here is a
 * consensus input.
 *
 * Includes no server header but the shared dialer's (no server object):
 * tests/storage_linked.cmake checks the linked nodus-storage binary.
 *
 * @file nodus_dht_ipc.c
 */

#include "dht/nodus_dht_ipc.h"
#include "server/nodus_inter_dial.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier1.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "crypto/utils/qgp_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT_IPC"

/* How often the outbound pool is swept (core's IDLE_SWEEP_INTERVAL) and
 * cleaned of peers that left the routing table (core's presence sync). */
#define DIPC_SWEEP_SEC        30
#define DIPC_STALE_SEC        30

typedef enum {
    DIPC_NONE = 0,     /* accepted, preface not seen yet */
    DIPC_ORIGIN,       /* ds_origin: one core session */
    DIPC_CTL           /* ds_ctl: core's control connection */
} dipc_kind_t;

typedef struct {
    dipc_kind_t             kind;
    nodus_dht_ipc_preface_t pf;          /* DIPC_ORIGIN */
    bool                    overflow;    /* reply bound hit: close at tick */
} dipc_slot_t;

struct nodus_dht_ipc {
    nodus_tcp_t             tcp;         /* storage.sock */
    nodus_tcp_t             out;         /* dialed 4002 connections */
    nodus_dht_t            *dht;
    const nodus_identity_t *identity;

    /* Indexed by the IPC connection's slot (tcp pool index). */
    dipc_slot_t             slots[NODUS_TCP_MAX_CONNS];
    /* (kind, slot) → the IPC connection's slot, or -1. */
    int                     client_map[NODUS_MAX_SESSIONS];
    int                     inter_map[NODUS_MAX_INTER_SESSIONS];
    bool                    overflow_any;

    nodus_tcp_conn_t       *ctl;
    uint8_t                 ctl_boot[NODUS_DHT_IPC_BOOT_LEN];

    /* The dialer state of each outbound connection (out pool slot). */
    nodus_inter_dial_t      dial[NODUS_TCP_MAX_CONNS];

    /* Core's last membership snapshot (decision item 27). */
    nodus_dht_ipc_member_t  mbr[NODUS_DHT_IPC_MEMBERS_MAX];
    int                     mbr_n;
    bool                    mbr_have;
    uint64_t                mbr_at_ms;

    /* The routing snapshot last pushed (decision item 17). */
    nodus_dht_peer_addr_t  *rt_last;
    int                     rt_last_n;
    nodus_dht_peer_addr_t  *rt_scratch;
    uint8_t                *rt_buf;
    bool                    rt_force;
    uint64_t                rt_pushed_ms;
    uint64_t                rt_checked_ms;

    uint64_t                last_sweep;
    uint64_t                last_stale;
};

/* ── Small helpers ───────────────────────────────────────────────── */

static size_t dipc_queued(const nodus_tcp_conn_t *c) {
    return (c->wlen - c->wpos) + c->pending_bytes;
}

static int *dipc_map(nodus_dht_ipc_t *ipc, nodus_dht_origin_kind_t kind,
                     int slot) {
    if (slot < 0) return NULL;
    if (kind == NODUS_DHT_ORIGIN_CLIENT)
        return slot < NODUS_MAX_SESSIONS ? &ipc->client_map[slot] : NULL;
    return slot < NODUS_MAX_INTER_SESSIONS ? &ipc->inter_map[slot] : NULL;
}

/* The live IPC connection `origin` maps to, with that generation. */
static nodus_tcp_conn_t *dipc_origin_conn(nodus_dht_ipc_t *ipc,
                                          nodus_dht_origin_t origin) {
    int *m = dipc_map(ipc, origin.kind, origin.slot);
    if (!m || *m < 0) return NULL;
    nodus_tcp_conn_t *c = ipc->tcp.pool[*m];
    const dipc_slot_t *s = &ipc->slots[*m];
    if (!c || c->close_pending || s->kind != DIPC_ORIGIN ||
        s->pf.origin.gen != origin.gen)
        return NULL;
    return c;
}

/* A preface of the same boot id and a smaller generation is older; one of
 * another boot id is newer (core restarted; the old core is gone). */
static bool dipc_preface_newer(const nodus_dht_ipc_preface_t *a,
                               const nodus_dht_ipc_preface_t *b) {
    if (memcmp(a->boot, b->boot, NODUS_DHT_IPC_BOOT_LEN) != 0) return true;
    return a->origin.gen > b->origin.gen;
}

/* ── The DHT's host view (nodus_dht_host_t) ─────────────────────── */

static int dipc_send_to_origin(void *ctx, nodus_dht_origin_t origin,
                               const uint8_t *frame, size_t len) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    nodus_tcp_conn_t *c = dipc_origin_conn(ipc, origin);
    if (!c) return -1;
    dipc_slot_t *s = &ipc->slots[c->slot];
    if (s->overflow) return -1;
    if (dipc_queued(c) >= NODUS_DHT_IPC_REPLY_QUEUE_MAX) {
        /* Core is not reading this origin's replies. Close it — at the end
         * of the pass, not under the DHT handler that is sending — rather
         * than grow the queue; core ends the session (decision 32). */
        QGP_LOG_WARN(LOG_TAG, "origin %s slot=%d gen=%llu: queue to core is "
                     "over NODUS_DHT_IPC_REPLY_QUEUE_MAX — closing it",
                     origin.kind == NODUS_DHT_ORIGIN_CLIENT ? "client" : "inter",
                     origin.slot, (unsigned long long)origin.gen);
        s->overflow = true;
        ipc->overflow_any = true;
        return -1;
    }
    return nodus_tcp_send(c, frame, len);
}

/* Control-connection send of a COLD / snapshot frame (never closed for a
 * bound). @return 0 queued, -1 not (no control connection, or over the
 * bound). */
static int dipc_ctl_send(nodus_dht_ipc_t *ipc, const uint8_t *p, size_t n) {
    if (!ipc->ctl || n == 0) return -1;
    if (dipc_queued(ipc->ctl) >= NODUS_DHT_IPC_CTL_QUEUE_MAX) return -1;
    return nodus_tcp_send(ipc->ctl, p, n);
}

static int dipc_udp_send(void *ctx, const uint8_t *payload, size_t len,
                         const char *ip, uint16_t port) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (!ipc->ctl) return -1;
    /* A T1 datagram is at most NODUS_MAX_FRAME_UDP; the envelope adds the
     * address. Over the bound the newest datagram is dropped (UDP is lossy
     * anyway). */
    uint8_t buf[NODUS_MAX_FRAME_UDP + 160];
    if (len > NODUS_MAX_FRAME_UDP) return -1;
    size_t n = nodus_dht_ipc_encode_udp(NODUS_DHT_IPC_Q_UDP_OUT, ip, port,
                                        payload, len, buf, sizeof(buf));
    return dipc_ctl_send(ipc, buf, n);
}

static int dipc_inter_send(void *ctx, const char *ip, uint16_t port,
                           const nodus_key_t *expected_peer_id,
                           const uint8_t *frame, size_t flen) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    return nodus_inter_pool_send_framed(&ipc->out, ip, port,
                                        expected_peer_id, frame, flen);
}

static const nodus_dht_ipc_member_t *dipc_member(const nodus_dht_ipc_t *ipc,
                                                 const nodus_key_t *id) {
    if (!ipc->mbr_have) return NULL;
    for (int i = 0; i < ipc->mbr_n; i++)
        if (nodus_key_cmp(&ipc->mbr[i].node_id, id) == 0)
            return &ipc->mbr[i];
    return NULL;
}

/* Item 9 / 27: a member of core's cluster seen less than
 * NODUS_HINT_OFFLINE_SKIP_SEC ago — the offline seconds core reported, aged
 * by the time since that snapshot arrived. No snapshot yet → no hint (the
 * periodic republish covers it). */
static bool dipc_hint_wanted(void *ctx, const nodus_key_t *node_id) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    const nodus_dht_ipc_member_t *m = dipc_member(ipc, node_id);
    if (!m) return false;
    uint64_t aged = (nodus_time_mono_ms() - ipc->mbr_at_ms) / 1000;
    return m->offline_secs + aged < NODUS_HINT_OFFLINE_SKIP_SEC;
}

void nodus_dht_ipc_host(nodus_dht_ipc_t *ipc, nodus_dht_host_t *out) {
    memset(out, 0, sizeof(*out));
    if (!ipc) return;
    out->identity       = ipc->identity;
    out->ctx            = ipc;
    out->send_to_origin = dipc_send_to_origin;
    out->udp_send       = dipc_udp_send;
    out->inter_send     = dipc_inter_send;
    out->hint_wanted    = dipc_hint_wanted;
}

/* ── Origins ─────────────────────────────────────────────────────── */

static void dipc_refuse(nodus_dht_ipc_t *ipc, nodus_tcp_conn_t *conn,
                        const char *why) {
    QGP_LOG_WARN(LOG_TAG, "closing IPC connection slot=%d: %s", conn->slot, why);
    nodus_tcp_disconnect(&ipc->tcp, conn);
}

static void dipc_on_preface(nodus_dht_ipc_t *ipc, nodus_tcp_conn_t *conn,
                            const nodus_dht_ipc_preface_t *pf) {
    dipc_slot_t *s = &ipc->slots[conn->slot];
    int *m = dipc_map(ipc, pf->origin.kind, pf->origin.slot);
    if (!m) {
        dipc_refuse(ipc, conn, "preface slot out of range");
        return;
    }
    if (*m >= 0 && *m != conn->slot) {
        const dipc_slot_t *prev = &ipc->slots[*m];
        nodus_tcp_conn_t *pc = ipc->tcp.pool[*m];
        if (pc && !pc->close_pending && prev->kind == DIPC_ORIGIN &&
            !dipc_preface_newer(pf, &prev->pf)) {
            /* An older (or the same) session for a slot a newer one holds:
             * its EOF and frames would only race the live one. */
            dipc_refuse(ipc, conn, "preface older than the slot's session");
            return;
        }
        /* The previous connection's session has ended (core closed it); its
         * EOF, still in flight, will find the slot mapped elsewhere. */
    }
    s->kind = DIPC_ORIGIN;
    s->pf = *pf;
    s->overflow = false;
    *m = conn->slot;
    if (ipc->dht)
        nodus_dht_session_opened(ipc->dht, pf->origin);
}

/* The 4002 frame core routed to the DHT, classified as core's dispatch did
 * (same decoders, same bytes → same result): T2 fv / get_batch / m_sv with
 * media → nodus_dht_inter_request; otherwise T1 sv (with a value) / sub /
 * unsub / ntf (with a value) → nodus_dht_inter_t1. */
static void dipc_inter_dispatch(nodus_dht_ipc_t *ipc, const dipc_slot_t *s,
                                const uint8_t *payload, size_t len) {
    int slot = s->pf.origin.slot;
    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) == 0) {
        if (strcmp(msg.method, "fv") == 0 ||
            strcmp(msg.method, "get_batch") == 0 ||
            (strcmp(msg.method, "m_sv") == 0 && msg.has_media)) {
            nodus_dht_inter_request(ipc->dht, slot, payload, len, &msg);
            nodus_t2_msg_free(&msg);
            return;
        }
    }
    nodus_t2_msg_free(&msg);

    nodus_tier1_msg_t t1;
    memset(&t1, 0, sizeof(t1));
    if (nodus_t1_decode(payload, len, &t1) == 0 &&
        ((strcmp(t1.method, "sv") == 0 && t1.value) ||
         strcmp(t1.method, "sub") == 0 || strcmp(t1.method, "unsub") == 0 ||
         (strcmp(t1.method, "ntf") == 0 && t1.value))) {
        nodus_dht_inter_t1(ipc->dht, slot, &s->pf.fp, s->pf.ip, &t1);
    } else {
        QGP_LOG_WARN(LOG_TAG, "inter origin slot=%d: a frame that is no DHT "
                     "4002 method (len=%zu) — dropped", slot, len);
    }
    nodus_t1_msg_free(&t1);
}

static void dipc_on_origin_frame(nodus_dht_ipc_t *ipc, nodus_tcp_conn_t *conn,
                                 const uint8_t *payload, size_t len) {
    dipc_slot_t *s = &ipc->slots[conn->slot];
    int *m = dipc_map(ipc, s->pf.origin.kind, s->pf.origin.slot);
    /* A connection the slot no longer maps to carries an ended session. */
    if (!m || *m != conn->slot || s->overflow || !ipc->dht) return;

    if (s->pf.origin.kind == NODUS_DHT_ORIGIN_CLIENT) {
        nodus_tier2_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        if (nodus_t2_decode(payload, len, &msg) != 0) {
            nodus_t2_msg_free(&msg);
            dipc_refuse(ipc, conn, "client origin frame does not decode");
            return;
        }
        nodus_dht_client_request(ipc->dht, s->pf.origin.slot, &s->pf.fp,
                                 &s->pf.pk, &msg);
        nodus_t2_msg_free(&msg);
        return;
    }
    dipc_inter_dispatch(ipc, s, payload, len);
}

/* ── Control connection ─────────────────────────────────────────── */

static void dipc_on_ctl_frame(nodus_dht_ipc_t *ipc, const uint8_t *payload,
                              size_t len) {
    nodus_dht_ipc_msg_t *msg = malloc(sizeof(*msg));
    if (!msg) return;
    if (nodus_dht_ipc_decode(payload, len, msg, NULL, 0) != 0) {
        QGP_LOG_WARN(LOG_TAG, "malformed control frame (len=%zu) — dropped",
                     len);
        free(msg);
        return;
    }
    switch (msg->type) {
    case NODUS_DHT_IPC_MSG_UDP_IN: {
        nodus_tier1_msg_t t1;
        memset(&t1, 0, sizeof(t1));
        if (ipc->dht && nodus_t1_decode(msg->payload, msg->payload_len, &t1) == 0)
            nodus_dht_udp_request(ipc->dht, msg->ip, msg->port, &t1);
        nodus_t1_msg_free(&t1);
        break;
    }
    case NODUS_DHT_IPC_MSG_SEEN:
        if (ipc->dht)
            nodus_dht_peer_seen(ipc->dht, msg->seen_kind, &msg->node_id,
                                msg->ip, msg->port, msg->tcp_port);
        break;
    case NODUS_DHT_IPC_MSG_DEAD:
        if (ipc->dht)
            nodus_dht_peer_dead(ipc->dht, &msg->node_id);
        break;
    case NODUS_DHT_IPC_MSG_MEMBERS:
        memcpy(ipc->mbr, msg->members, sizeof(ipc->mbr));
        ipc->mbr_n = msg->member_count;
        ipc->mbr_have = true;
        ipc->mbr_at_ms = nodus_time_mono_ms();
        break;
    default:
        QGP_LOG_WARN(LOG_TAG, "control frame of a kind core does not send "
                     "(type=%d) — dropped", (int)msg->type);
        break;
    }
    free(msg);
}

/* ── IPC transport callbacks ─────────────────────────────────────── */

static void dipc_on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS)
        memset(&ipc->slots[conn->slot], 0, sizeof(ipc->slots[0]));
}

static void dipc_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    dipc_slot_t *s = &ipc->slots[conn->slot];

    if (s->kind == DIPC_CTL && conn == ipc->ctl) {
        ipc->ctl = NULL;
        QGP_LOG_WARN(LOG_TAG, "%s", "control connection from core lost — "
                     "datagrams and peer events wait for its return");
    } else if (s->kind == DIPC_ORIGIN) {
        int *m = dipc_map(ipc, s->pf.origin.kind, s->pf.origin.slot);
        /* EOF = session closed, but only for the session this connection
         * opened: a newer preface may own the slot already. */
        if (m && *m == conn->slot) {
            *m = -1;
            if (ipc->dht)
                nodus_dht_session_closed(ipc->dht, s->pf.origin);
        }
    }
    memset(s, 0, sizeof(*s));
}

static void dipc_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                          size_t len, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    dipc_slot_t *s = &ipc->slots[conn->slot];

    switch (s->kind) {
    case DIPC_NONE: {
        nodus_dht_ipc_msg_t *msg = malloc(sizeof(*msg));
        if (!msg) {
            dipc_refuse(ipc, conn, "out of memory decoding the preface");
            return;
        }
        if (nodus_dht_ipc_decode(payload, len, msg, NULL, 0) != 0) {
            free(msg);
            dipc_refuse(ipc, conn, "first frame is not a storage IPC preface "
                        "of this version");
            return;
        }
        if (msg->type == NODUS_DHT_IPC_MSG_ORIGIN) {
            dipc_on_preface(ipc, conn, &msg->preface);
        } else if (msg->type == NODUS_DHT_IPC_MSG_CTL) {
            /* One control connection: a new one (core restarted, or
             * reconnected) replaces the old; the core side then re-pushes its
             * membership in full and this side its routing snapshot. */
            if (ipc->ctl && ipc->ctl != conn) {
                nodus_tcp_conn_t *old = ipc->ctl;
                ipc->ctl = NULL;
                dipc_refuse(ipc, old, "replaced by a new control connection");
            }
            s->kind = DIPC_CTL;
            ipc->ctl = conn;
            memcpy(ipc->ctl_boot, msg->boot, NODUS_DHT_IPC_BOOT_LEN);
            ipc->rt_force = true;
            QGP_LOG_INFO(LOG_TAG, "%s", "control connection from core up");
        } else {
            dipc_refuse(ipc, conn, "first frame is neither ds_origin nor ds_ctl");
        }
        free(msg);
        return;
    }
    case DIPC_ORIGIN:
        dipc_on_origin_frame(ipc, conn, payload, len);
        return;
    case DIPC_CTL:
        dipc_on_ctl_frame(ipc, payload, len);
        return;
    }
}

/* ── The outbound 4002 pool ──────────────────────────────────────── */

static int dipc_out_send_raw(void *ctx, const uint8_t *payload, size_t len) {
    return nodus_tcp_send_raw((nodus_tcp_conn_t *)ctx, payload, len);
}

typedef struct {
    nodus_dht_ipc_t  *ipc;
    nodus_tcp_conn_t *conn;
} dipc_out_ctx_t;

static int dipc_out_send_raw_x(void *ctx, const uint8_t *payload, size_t len) {
    return nodus_tcp_send_raw(((dipc_out_ctx_t *)ctx)->conn, payload, len);
}

static void dipc_out_established(void *ctx, bool encrypted) {
    dipc_out_ctx_t *x = (dipc_out_ctx_t *)ctx;
    nodus_inter_dial_conn_sync(&x->ipc->dial[x->conn->slot], x->conn);
    nodus_inter_dial_conn_open(x->conn, encrypted);
}

static void dipc_out_on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS)
        memset(&ipc->dial[conn->slot], 0, sizeof(ipc->dial[0]));
    conn->is_nodus = true;
    conn->auth_required = ipc->out.auth_required;
    if (conn->auth_required) {
        /* The dialer module's hello (core's on_inter_connect does the same). */
        nodus_inter_dial_io_t io;
        memset(&io, 0, sizeof(io));
        io.identity = ipc->identity;
        io.send_raw = dipc_out_send_raw;
        io.ctx = conn;
        conn->auth_state = nodus_inter_dial_start(&io) == 0
                         ? NODUS_CONN_AUTH_HELLO_SENT : NODUS_CONN_AUTH_FAILED;
    } else {
        conn->auth_state = NODUS_CONN_AUTH_OK;
    }
}

static void dipc_out_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                              size_t len, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;

    nodus_tier2_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    if (nodus_t2_decode(payload, len, &msg) != 0) {
        nodus_t2_msg_free(&msg);
        QGP_LOG_WARN(LOG_TAG, "dialed 4002 conn %s:%u: a frame that is not a "
                     "handshake reply (len=%zu) — dropped",
                     conn->ip, (unsigned)conn->port, len);
        return;
    }
    if (strcmp(msg.method, "challenge") == 0 ||
        strcmp(msg.method, "auth_ok") == 0 ||
        strcmp(msg.method, "key_ack") == 0) {
        nodus_inter_dial_t *d = &ipc->dial[conn->slot];
        dipc_out_ctx_t x = { ipc, conn };
        nodus_inter_dial_io_t io;
        memset(&io, 0, sizeof(io));
        io.identity = ipc->identity;
        /* CRIT-1: the pin recorded at dial (nodus_inter_pool_dial). */
        io.expected_peer_id = conn->expected_peer_id_set
                            ? &conn->expected_peer_id : NULL;
        io.crypto = &conn->channel_crypto;
        io.peer_ip = conn->ip;
        io.peer_port = conn->port;
        io.slot = conn->slot;
        io.send_raw = dipc_out_send_raw_x;
        io.established = dipc_out_established;
        io.ctx = &x;
        nodus_inter_dial_rc_t rc = nodus_inter_dial_on_frame(d, &io, &msg);
        nodus_inter_dial_conn_sync(d, conn);
        nodus_t2_msg_free(&msg);
        if (rc == NODUS_INTER_DIAL_REFUSED) {
            conn->auth_state = NODUS_CONN_AUTH_FAILED;
            nodus_tcp_disconnect(&ipc->out, conn);
        }
        return;
    }
    if (strcmp(msg.method, "error") != 0)
        QGP_LOG_WARN(LOG_TAG, "dialed 4002 conn %s:%u: \"%s\" is not a "
                     "handshake reply — dropped (this process serves no "
                     "4002 request)", conn->ip, (unsigned)conn->port,
                     msg.method);
    nodus_t2_msg_free(&msg);
}

static void dipc_out_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (conn->slot >= 0 && conn->slot < NODUS_TCP_MAX_CONNS)
        memset(&ipc->dial[conn->slot], 0, sizeof(ipc->dial[0]));
}

/* The pending-full hook of the outbound pool — core's
 * nodus_server_on_pending_full rules, with the hint written here directly
 * (the hint table is this process's): an authenticated peer (F4), a member
 * of core's cluster in any state (item 9, from the membership snapshot), a
 * replication frame (item 33); anything else is dropped with a log line. */
static void dipc_out_on_pending_full(nodus_tcp_conn_t *conn,
                                     const uint8_t *payload, size_t len,
                                     void *ctx) {
    nodus_dht_ipc_t *ipc = (nodus_dht_ipc_t *)ctx;
    if (!ipc || !conn || !payload) return;
    if (!conn->peer_id_set) {
        fprintf(stderr, "PENDING_FULL: peer=%s:%u len=%zu not authenticated — "
                "frame DROPPED (no hint)\n", conn->ip, (unsigned)conn->port, len);
        return;
    }
    if (!dipc_member(ipc, &conn->peer_id)) {
        QGP_LOG_WARN(LOG_TAG, "PENDING_FULL: peer=%s:%u len=%zu not a cluster "
                     "member — frame DROPPED (no hint)",
                     conn->ip, (unsigned)conn->port, len);
        return;
    }
    if (!nodus_inter_frame_is_replication(payload, len)) {
        QGP_LOG_WARN(LOG_TAG, "PENDING_FULL: peer=%s:%u len=%zu not a "
                     "replication frame — frame DROPPED (no hint)",
                     conn->ip, (unsigned)conn->port, len);
        return;
    }
    if (!ipc->dht) return;
    size_t frame_size = NODUS_FRAME_HEADER_SIZE + len;
    uint8_t *framed = malloc(frame_size);
    if (!framed) {
        fprintf(stderr, "PENDING_FULL: malloc failed (peer=%s:%u len=%zu)\n",
                conn->ip, (unsigned)conn->port, len);
        return;
    }
    if (nodus_frame_encode(framed, frame_size, payload, (uint32_t)len) != frame_size) {
        fprintf(stderr, "PENDING_FULL: frame_encode failed (peer=%s:%u len=%zu)\n",
                conn->ip, (unsigned)conn->port, len);
        free(framed);
        return;
    }
    int rc = nodus_dht_hint_store(ipc->dht, &conn->peer_id, conn->ip,
                                  conn->port, framed, frame_size);
    free(framed);
    if (rc != 0) {
        fprintf(stderr, "PENDING_FULL: hint %s (peer=%s:%u len=%zu id=peer_id "
                "rc=%d) — frame DROPPED\n",
                rc == NODUS_STORAGE_RC_QUOTA ? "cap reached" : "insert failed",
                conn->ip, (unsigned)conn->port, len, rc);
        return;
    }
    fprintf(stderr, "PENDING_FULL: peer=%s:%u len=%zu queued to hint table "
            "(id=peer_id)\n", conn->ip, (unsigned)conn->port, len);
}

/* ── Periodic work ───────────────────────────────────────────────── */

/* Decision 17: push the routing snapshot when the PROJECTED set (node id,
 * ip, tcp port, in bucket order) changed — not on every routing touch —
 * at least every NODUS_DHT_IPC_SNAPSHOT_MAX_SEC, and in full on a new
 * control connection. Looked at every NODUS_DHT_IPC_SNAPSHOT_CHECK_MS. */
static void dipc_routing_tick(nodus_dht_ipc_t *ipc, uint64_t now_ms) {
    if (!ipc->ctl || !ipc->dht) return;
    if (!ipc->rt_force &&
        now_ms - ipc->rt_checked_ms < NODUS_DHT_IPC_SNAPSHOT_CHECK_MS)
        return;
    ipc->rt_checked_ms = now_ms;

    int n = nodus_dht_routing_snapshot(ipc->dht, ipc->rt_scratch,
                                       NODUS_DHT_IPC_ROUTING_MAX);
    for (int i = 0; i < n; i++) {
        /* Projected fields only: clear what snprintf left past the NUL so
         * two equal sets compare equal bytewise. */
        size_t l = strnlen(ipc->rt_scratch[i].ip, sizeof(ipc->rt_scratch[i].ip));
        memset(ipc->rt_scratch[i].ip + l, 0, sizeof(ipc->rt_scratch[i].ip) - l);
    }
    bool changed = n != ipc->rt_last_n ||
                   (n > 0 && memcmp(ipc->rt_scratch, ipc->rt_last,
                                    (size_t)n * sizeof(*ipc->rt_last)) != 0);
    bool due = now_ms - ipc->rt_pushed_ms >=
               (uint64_t)NODUS_DHT_IPC_SNAPSHOT_MAX_SEC * 1000;
    if (!changed && !due && !ipc->rt_force) return;

    size_t len = nodus_dht_ipc_encode_routing(ipc->rt_scratch, n, ipc->rt_buf,
                                              NODUS_DHT_IPC_ROUTING_FRAME_MAX);
    if (dipc_ctl_send(ipc, ipc->rt_buf, len) != 0) {
        /* Over the control bound, or no encoder room: try again at the next
         * check — never by closing the control connection. */
        ipc->rt_force = true;
        return;
    }
    memcpy(ipc->rt_last, ipc->rt_scratch, (size_t)n * sizeof(*ipc->rt_last));
    ipc->rt_last_n = n;
    ipc->rt_pushed_ms = now_ms;
    ipc->rt_force = false;
}

/* Dialed connections to an IP no longer in the routing table — what core's
 * presence tick did for the shared pool before the split
 * (nodus_presence.c, "Clean up stale outgoing p_sync connections"). */
static void dipc_stale_cleanup(nodus_dht_ipc_t *ipc) {
    if (!ipc->dht) return;
    int n = nodus_dht_routing_snapshot(ipc->dht, ipc->rt_scratch,
                                       NODUS_DHT_IPC_ROUTING_MAX);
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
        nodus_tcp_conn_t *c = ipc->out.pool[i];
        if (!c) continue;
        bool found = false;
        for (int p = 0; p < n; p++) {
            if (strcmp(ipc->rt_scratch[p].ip, c->ip) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "STORAGE_POOL: closing stale connection to %s:%d\n",
                    c->ip, c->port);
            nodus_tcp_disconnect(&ipc->out, c);
        }
    }
}

void nodus_dht_ipc_tick(nodus_dht_ipc_t *ipc) {
    if (!ipc) return;

    /* Origins over their reply bound (marked in send_to_origin), slot
     * order. */
    if (ipc->overflow_any) {
        ipc->overflow_any = false;
        for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
            nodus_tcp_conn_t *c = ipc->tcp.pool[i];
            if (c && ipc->slots[i].kind == DIPC_ORIGIN && ipc->slots[i].overflow)
                nodus_tcp_disconnect(&ipc->tcp, c);
        }
    }

    dipc_routing_tick(ipc, nodus_time_mono_ms());

    uint64_t now = nodus_time_now();
    if (now - ipc->last_sweep >= DIPC_SWEEP_SEC) {
        ipc->last_sweep = now;
        nodus_inter_pool_sweep(&ipc->out, now);
    }
    if (now - ipc->last_stale >= DIPC_STALE_SEC) {
        ipc->last_stale = now;
        dipc_stale_cleanup(ipc);
    }
}

/* ── Lifecycle ───────────────────────────────────────────────────── */

nodus_dht_ipc_t *nodus_dht_ipc_new(const nodus_identity_t *identity,
                                   bool require_peer_auth) {
    if (!identity) return NULL;
    nodus_dht_ipc_t *ipc = calloc(1, sizeof(*ipc));
    if (!ipc) return NULL;
    ipc->rt_last    = calloc(NODUS_DHT_IPC_ROUTING_MAX, sizeof(*ipc->rt_last));
    ipc->rt_scratch = calloc(NODUS_DHT_IPC_ROUTING_MAX, sizeof(*ipc->rt_scratch));
    ipc->rt_buf     = malloc(NODUS_DHT_IPC_ROUTING_FRAME_MAX);
    if (!ipc->rt_last || !ipc->rt_scratch || !ipc->rt_buf) goto fail;
    if (nodus_tcp_init(&ipc->tcp, -1) != 0) goto fail;
    if (nodus_tcp_init(&ipc->out, -1) != 0) {
        nodus_tcp_close(&ipc->tcp);
        goto fail;
    }
    ipc->identity = identity;
    for (int i = 0; i < NODUS_MAX_SESSIONS; i++) ipc->client_map[i] = -1;
    for (int i = 0; i < NODUS_MAX_INTER_SESSIONS; i++) ipc->inter_map[i] = -1;

    ipc->tcp.on_accept     = dipc_on_accept;
    ipc->tcp.on_frame      = dipc_on_frame;
    ipc->tcp.on_disconnect = dipc_on_disconnect;
    ipc->tcp.cb_ctx        = ipc;

    ipc->out.on_connect       = dipc_out_on_connect;
    ipc->out.on_frame         = dipc_out_on_frame;
    ipc->out.on_disconnect    = dipc_out_on_disconnect;
    ipc->out.cb_ctx           = ipc;
    ipc->out.auth_required    = require_peer_auth;
    ipc->out.auth_ctx         = (void *)identity;
    ipc->out.on_pending_full  = dipc_out_on_pending_full;
    ipc->out.pending_full_ctx = ipc;
    ipc->last_sweep = nodus_time_now();
    ipc->last_stale = ipc->last_sweep;
    return ipc;

fail:
    free(ipc->rt_last);
    free(ipc->rt_scratch);
    free(ipc->rt_buf);
    free(ipc);
    return NULL;
}

void nodus_dht_ipc_attach(nodus_dht_ipc_t *ipc, nodus_dht_t *dht) {
    if (ipc) ipc->dht = dht;
}

int nodus_dht_ipc_listen(nodus_dht_ipc_t *ipc, const char *path) {
    if (!ipc || !path) return -1;
    return nodus_tcp_unix_listen(&ipc->tcp, path, NODUS_TCP_UNIX_UID_SELF);
}

void nodus_dht_ipc_poll(nodus_dht_ipc_t *ipc, int timeout_ms) {
    if (!ipc) return;
    int ms = nodus_dht_ipc_read_pending(ipc) ? 0 : timeout_ms;
    nodus_tcp_poll(&ipc->tcp, ms);
    nodus_tcp_poll(&ipc->out, 0);
}

bool nodus_dht_ipc_read_pending(const nodus_dht_ipc_t *ipc) {
    if (!ipc) return false;
    return nodus_tcp_read_pending(&ipc->tcp) || nodus_tcp_read_pending(&ipc->out);
}

void nodus_dht_ipc_free(nodus_dht_ipc_t *ipc) {
    if (!ipc) return;
    /* nodus_tcp_close frees the connections without on_disconnect. */
    nodus_tcp_close(&ipc->out);
    nodus_tcp_close(&ipc->tcp);
    free(ipc->rt_last);
    free(ipc->rt_scratch);
    free(ipc->rt_buf);
    free(ipc);
}
