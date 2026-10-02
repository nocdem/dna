/**
 * Nodus — DHT backend, IPC implementation (split S5b)
 *
 * The DHT / storage half is the separate `nodus-storage` process (decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md items 7, 16, 17,
 * 19, 27, 29, 31, 32); this server reaches it over the Unix socket
 * <data_path>/storage.sock. Frame formats and the storage side:
 * dht/nodus_dht_ipc.h, dht/nodus_dht_ipc.c.
 *
 * Its own nodus_tcp_t (never the client or the inter-node pool), polled
 * with a 0 ms wait from `tick`, i.e. once per server loop pass; while it
 * has connections on its pending-read list (`read_pending`) the server's
 * own polls wait 0 ms too.
 *
 *  - Origin connections (item 19): a session's first DHT frame dials one
 *    connection and sends the ds_origin preface (kind, slot, the session's
 *    generation, this backend's boot id, and the identity the DHT reads:
 *    the client's fp + pk, or the 4002 peer's fp + address); every later
 *    DHT frame of that session goes down the same connection, unchanged,
 *    and every frame the storage process writes on it goes to the session
 *    through core's send_to_origin (generation-checked, item 29). Session
 *    open and close travel on this connection ONLY (ORCHESTRATOR ruling on
 *    Fable S5 H2): `session_opened` sends nothing — it records the
 *    generation and closes a connection left from the slot's previous
 *    session; `session_closed` closes the connection (its EOF is the
 *    storage side's "session closed").
 *  - Decision 31: with no control connection (storage not reachable), past
 *    NODUS_DHT_IPC_MAX_ORIGIN_CONNS, or with the session's queue at
 *    NODUS_DHT_IPC_QUEUE_MAX, a client DHT request is answered AT ONCE with
 *    NODUS_ERR_UNAVAILABLE / NODUS_DHT_NO_STORAGE_MSG and nothing is
 *    dialled or queued. A 4002 DHT frame in the same state is dropped (a
 *    rate-limited WARN); the remote side's own timeout / republish covers
 *    it. A request already forwarded when storage goes away gets no
 *    answer from it — but see the next point.
 *  - Decision 32: when an origin connection closes and THIS backend did
 *    not close it (the storage process closed it — e.g. its reply bound —
 *    or went away), core ends that session through close_origin: the
 *    client reconnects and re-LISTENs, never a silent re-dial that would
 *    leave it believing its listens are still in place. A send fault on an
 *    origin connection does the same.
 *  - The control connection: dialled on the first `tick`, re-dialled with a
 *    bounded backoff while storage is down. Carries, in call order, UDP
 *    4000 datagrams for the DHT (dropped — the newest — past
 *    NODUS_DHT_IPC_CTL_QUEUE_MAX), peer_seen / peer_dead, and core's
 *    membership snapshot (item 27: on change, at least every
 *    NODUS_DHT_IPC_SNAPSHOT_MAX_SEC, in full on every (re)connect); and
 *    back, datagrams to send from UDP 4000 and the routing snapshot
 *    (item 17) that `routing_snapshot` answers from — the last one
 *    received, kept while storage is away (presence keeps dialling the
 *    peers it knew). Never closed for a bound.
 *  - hint_store: no DHT frame leaves through core's 4002 pool any more
 *    (storage dials its own, item 16), so core's pending-full filter passes
 *    no frame to it; it logs and refuses.
 *
 * Clock: nodus_time_mono_ms only schedules this node's own dialling and
 * snapshot pushes; nothing here is a consensus input.
 *
 * @file nodus_dht_backend_ipc.c
 */

#include "server/nodus_dht_backend.h"
#include "dht/nodus_dht_ipc.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_sign.h"            /* nodus_random */
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT_IPC"

#define OB_DIAL_BACKOFF_MIN   250     /* control re-dial, first wait (ms) */
#define OB_DIAL_BACKOFF_MAX   5000    /* control re-dial, longest wait (ms) */
#define OB_DROP_LOG_MS        10000   /* rate of the "dropped" WARNs */

/* by_ipc values other than an origin (kind * NODUS_TCP_MAX_CONNS + slot) */
#define OB_FREE   (-1)
#define OB_CTL    (-2)

typedef struct {
    nodus_tcp_conn_t *ipc;      /* the origin connection, or NULL */
    uint64_t          gen;      /* the session's generation (0 = none) */
} ob_origin_t;

typedef struct {
    nodus_dht_backend_t     base;          /* first member: ops */
    nodus_tcp_t             tcp;
    char                    path[NODUS_TCP_UNIX_PATH_MAX];
    nodus_dht_ipc_core_t    core;
    uint8_t                 boot[NODUS_DHT_IPC_BOOT_LEN];

    ob_origin_t             client[NODUS_MAX_SESSIONS];
    ob_origin_t             inter[NODUS_MAX_INTER_SESSIONS];
    /* Indexed by the IPC connection's slot (this backend's pool). */
    int                     by_ipc[NODUS_TCP_MAX_CONNS];
    int                     n_origins;
    bool                    cap_logged;
    /* A disconnect this backend started: its on_disconnect must not end
     * the session (decision 32 is for closes storage made). */
    bool                    closing;

    nodus_tcp_conn_t       *ctl;
    uint64_t                ctl_next_dial_ms;
    uint64_t                ctl_backoff_ms;
    bool                    ctl_down_logged;

    /* Membership snapshot (item 27). */
    nodus_dht_ipc_member_t  mbr_last[NODUS_DHT_IPC_MEMBERS_MAX];
    int                     mbr_last_n;
    bool                    mbr_force;
    uint64_t                mbr_pushed_ms;
    uint64_t                mbr_checked_ms;

    /* Routing snapshot (item 17): the last one storage pushed. */
    nodus_dht_peer_addr_t  *rt;
    int                     rt_n;
    bool                    rt_logged;   /* since this control connection */

    uint64_t                drop_logged_ms;
    uint64_t                drops;
} ipc_be_t;

static ipc_be_t *ipc_be(nodus_dht_backend_t *b) {
    return (ipc_be_t *)b;
}

static size_t ob_queued(const nodus_tcp_conn_t *c) {
    return (c->wlen - c->wpos) + c->pending_bytes;
}

static ob_origin_t *ob_origin(ipc_be_t *ib, nodus_dht_origin_kind_t kind,
                              int slot) {
    if (slot < 0) return NULL;
    if (kind == NODUS_DHT_ORIGIN_CLIENT)
        return slot < NODUS_MAX_SESSIONS ? &ib->client[slot] : NULL;
    return slot < NODUS_MAX_INTER_SESSIONS ? &ib->inter[slot] : NULL;
}

/* A dropped 4002 frame / datagram, logged at most every OB_DROP_LOG_MS. */
static void ob_drop(ipc_be_t *ib, const char *what) {
    ib->drops++;
    uint64_t now = nodus_time_mono_ms();
    if (now - ib->drop_logged_ms < OB_DROP_LOG_MS) return;
    ib->drop_logged_ms = now;
    QGP_LOG_WARN(LOG_TAG, "%s dropped — nodus-storage %s (%llu dropped so "
                 "far)", what, ib->ctl ? "is not taking it" : "is not reachable",
                 (unsigned long long)ib->drops);
}

/* ── Origin connections ──────────────────────────────────────────── */

/* Close an origin connection this backend decided to close. */
static void ob_close(ipc_be_t *ib, ob_origin_t *o) {
    if (!o->ipc) return;
    ib->closing = true;
    /* ob_on_disconnect clears o->ipc. */
    nodus_tcp_disconnect(&ib->tcp, o->ipc);
    ib->closing = false;
}

/* The origin connection of (kind, slot), dialling it (and sending the
 * preface) on the session's first DHT frame. NULL: storage cannot be
 * reached (no control connection — no dial is attempted), the cap is
 * reached, or the dial / preface failed. */
static nodus_tcp_conn_t *ob_origin_conn(ipc_be_t *ib,
                                        nodus_dht_origin_kind_t kind, int slot,
                                        const nodus_key_t *fp,
                                        const nodus_pubkey_t *pk,
                                        const char *ip) {
    ob_origin_t *o = ob_origin(ib, kind, slot);
    if (!o) return NULL;
    if (o->ipc) return o->ipc;
    /* The control connection's backoff is the one re-dial driver: a
     * stopped storage costs no connect attempt per request. */
    if (!ib->ctl || o->gen == 0) return NULL;
    if (ib->n_origins >= NODUS_DHT_IPC_MAX_ORIGIN_CONNS) {
        if (!ib->cap_logged) {
            QGP_LOG_WARN(LOG_TAG, "%d sessions already hold a storage "
                         "connection (the cap) — further client DHT requests "
                         "are answered \"" NODUS_DHT_NO_STORAGE_MSG "\"",
                         NODUS_DHT_IPC_MAX_ORIGIN_CONNS);
            ib->cap_logged = true;
        }
        return NULL;
    }

    nodus_dht_ipc_preface_t *pf = calloc(1, sizeof(*pf));
    uint8_t *buf = malloc(NODUS_PK_BYTES + 512);
    if (!pf || !buf) {
        free(pf);
        free(buf);
        return NULL;
    }
    pf->origin.kind = kind;
    pf->origin.slot = slot;
    pf->origin.gen = o->gen;
    memcpy(pf->boot, ib->boot, NODUS_DHT_IPC_BOOT_LEN);
    if (fp) pf->fp = *fp;
    if (kind == NODUS_DHT_ORIGIN_CLIENT) {
        if (pk) pf->pk = *pk;
    } else {
        snprintf(pf->ip, sizeof(pf->ip), "%s", ip ? ip : "");
    }
    size_t n = nodus_dht_ipc_encode_origin(pf, buf, NODUS_PK_BYTES + 512);
    free(pf);

    nodus_tcp_conn_t *c = n ? nodus_tcp_unix_connect(&ib->tcp, ib->path,
                                                     NODUS_TCP_UNIX_UID_SELF)
                            : NULL;
    if (!c) {
        free(buf);
        return NULL;
    }
    if (nodus_tcp_send(c, buf, n) != 0) {
        free(buf);
        ib->closing = true;
        nodus_tcp_disconnect(&ib->tcp, c);
        ib->closing = false;
        return NULL;
    }
    free(buf);
    o->ipc = c;
    ib->by_ipc[c->slot] = (int)kind * NODUS_TCP_MAX_CONNS + slot;
    ib->n_origins++;
    return c;
}

/* Decision 31: the client's DHT request, answered at once. */
static void ob_no_storage(ipc_be_t *ib, nodus_dht_origin_t origin,
                          uint32_t txn_id) {
    uint8_t buf[256];
    size_t rlen = 0;
    if (nodus_t2_error(txn_id, NODUS_ERR_UNAVAILABLE, NODUS_DHT_NO_STORAGE_MSG,
                       buf, sizeof(buf), &rlen) == 0)
        ib->core.send_to_origin(ib->core.ctx, origin, buf, rlen);
}

/* A send fault on an origin connection (allocation, peer gone): the
 * connection is useless, and with it the session's listens — end the
 * session (decision 32). */
static void ob_fault(ipc_be_t *ib, nodus_dht_origin_t origin) {
    ob_origin_t *o = ob_origin(ib, origin.kind, origin.slot);
    if (!o) return;
    QGP_LOG_WARN(LOG_TAG, "send to nodus-storage failed for %s slot=%d — "
                 "ending that session (decision 32)",
                 origin.kind == NODUS_DHT_ORIGIN_CLIENT ? "client" : "4002",
                 origin.slot);
    ob_close(ib, o);
    ib->core.close_origin(ib->core.ctx, origin);
}

/* Forward one frame of (kind, slot). @return 0 forwarded; -1 not (the
 * caller answers / drops). */
static int ob_forward(ipc_be_t *ib, nodus_dht_origin_kind_t kind, int slot,
                      const nodus_key_t *fp, const nodus_pubkey_t *pk,
                      const char *ip, const uint8_t *payload, size_t len) {
    ob_origin_t *o = ob_origin(ib, kind, slot);
    if (!o) return -1;
    nodus_tcp_conn_t *c = ob_origin_conn(ib, kind, slot, fp, pk, ip);
    if (!c) return -1;
    /* Per-origin bound (NODUS_DHT_IPC_QUEUE_MAX): storage is not taking
     * this session's frames as fast as they come. Refuse this one; the
     * connection and what it already carries stay. */
    if (ob_queued(c) >= NODUS_DHT_IPC_QUEUE_MAX) return -1;
    if (nodus_tcp_send(c, payload, len) != 0) {
        nodus_dht_origin_t origin = { kind, slot, o->gen };
        ob_fault(ib, origin);
        return -2;
    }
    return 0;
}

/* ── Control connection ──────────────────────────────────────────── */

static void ob_members_tick(ipc_be_t *ib, uint64_t now) {
    if (!ib->ctl || !ib->core.members) return;
    if (!ib->mbr_force && now - ib->mbr_checked_ms < NODUS_DHT_IPC_SNAPSHOT_CHECK_MS)
        return;
    ib->mbr_checked_ms = now;

    nodus_dht_ipc_member_t m[NODUS_DHT_IPC_MEMBERS_MAX];
    memset(m, 0, sizeof(m));
    int n = ib->core.members(ib->core.ctx, m, NODUS_DHT_IPC_MEMBERS_MAX);
    if (n < 0) n = 0;
    /* Projected change: the member set, or a member crossing the hint
     * threshold. The offline seconds themselves move every second; the 30 s
     * re-push carries them. */
    bool changed = n != ib->mbr_last_n;
    for (int i = 0; i < n && !changed; i++) {
        bool was = ib->mbr_last[i].offline_secs < NODUS_HINT_OFFLINE_SKIP_SEC;
        bool is  = m[i].offline_secs < NODUS_HINT_OFFLINE_SKIP_SEC;
        changed = nodus_key_cmp(&m[i].node_id, &ib->mbr_last[i].node_id) != 0 ||
                  was != is;
    }
    bool due = now - ib->mbr_pushed_ms >=
               (uint64_t)NODUS_DHT_IPC_SNAPSHOT_MAX_SEC * 1000;
    if (!changed && !due && !ib->mbr_force) return;

    uint8_t buf[64 + NODUS_DHT_IPC_MEMBERS_MAX * (NODUS_KEY_BYTES + 16)];
    size_t len = nodus_dht_ipc_encode_members(m, n, buf, sizeof(buf));
    if (len == 0 || ob_queued(ib->ctl) >= NODUS_DHT_IPC_CTL_QUEUE_MAX ||
        nodus_tcp_send(ib->ctl, buf, len) != 0) {
        ib->mbr_force = true;      /* retried at the next check */
        return;
    }
    memcpy(ib->mbr_last, m, sizeof(ib->mbr_last));
    ib->mbr_last_n = n;
    ib->mbr_pushed_ms = now;
    ib->mbr_force = false;
}

static void ob_ctl_tick(ipc_be_t *ib, uint64_t now) {
    if (ib->ctl) return;
    if (now < ib->ctl_next_dial_ms) return;
    nodus_tcp_conn_t *c = nodus_tcp_unix_connect(&ib->tcp, ib->path,
                                                 NODUS_TCP_UNIX_UID_SELF);
    if (!c) {
        if (!ib->ctl_down_logged) {
            QGP_LOG_WARN(LOG_TAG, "nodus-storage is not reachable at %s — "
                         "client DHT requests are answered \""
                         NODUS_DHT_NO_STORAGE_MSG "\" until it is", ib->path);
            ib->ctl_down_logged = true;
        }
        ib->ctl_next_dial_ms = now + ib->ctl_backoff_ms;
        ib->ctl_backoff_ms *= 2;
        if (ib->ctl_backoff_ms > OB_DIAL_BACKOFF_MAX)
            ib->ctl_backoff_ms = OB_DIAL_BACKOFF_MAX;
        return;
    }
    uint8_t buf[64];
    size_t n = nodus_dht_ipc_encode_ctl(ib->boot, buf, sizeof(buf));
    if (n == 0 || nodus_tcp_send(c, buf, n) != 0) {
        ib->closing = true;
        nodus_tcp_disconnect(&ib->tcp, c);
        ib->closing = false;
        ib->ctl_next_dial_ms = now + ib->ctl_backoff_ms;
        return;
    }
    ib->ctl = c;
    ib->by_ipc[c->slot] = OB_CTL;
    ib->ctl_backoff_ms = OB_DIAL_BACKOFF_MIN;
    ib->ctl_down_logged = false;
    ib->rt_logged = false;
    /* Full re-push of the membership snapshot on every (re)connect; the
     * storage side re-pushes its routing snapshot on a new control
     * connection. */
    ib->mbr_force = true;
    QGP_LOG_INFO(LOG_TAG, "control connection to nodus-storage up (%s)",
                 ib->path);
}

/* ── Transport callbacks ─────────────────────────────────────────── */

static void ob_on_ctl_frame(ipc_be_t *ib, const uint8_t *payload, size_t len) {
    nodus_dht_ipc_msg_t *msg = malloc(sizeof(*msg));
    nodus_dht_peer_addr_t *rt = calloc(NODUS_DHT_IPC_ROUTING_MAX, sizeof(*rt));
    if (!msg || !rt) {
        free(msg);
        free(rt);
        return;
    }
    if (nodus_dht_ipc_decode(payload, len, msg, rt,
                             NODUS_DHT_IPC_ROUTING_MAX) != 0) {
        QGP_LOG_WARN(LOG_TAG, "malformed control frame from nodus-storage "
                     "(len=%zu) — dropped", len);
    } else if (msg->type == NODUS_DHT_IPC_MSG_UDP_OUT) {
        /* A T1 datagram the DHT sends — from this node's UDP 4000. */
        ib->core.udp_send(ib->core.ctx, msg->payload, msg->payload_len,
                          msg->ip, msg->port);
    } else if (msg->type == NODUS_DHT_IPC_MSG_ROUTING) {
        /* Logged on the first snapshot of a control connection and when
         * the count changes — the harness's evidence that the routing
         * table storage filled from this core's peer events came back
         * (stagef splits / mixeds bring-up). */
        if (!ib->rt_logged || msg->routing_count != ib->rt_n)
            QGP_LOG_INFO(LOG_TAG, "routing snapshot from nodus-storage: %d "
                         "peer(s)", msg->routing_count);
        ib->rt_logged = true;
        memcpy(ib->rt, rt, (size_t)msg->routing_count * sizeof(*rt));
        ib->rt_n = msg->routing_count;
    } else {
        QGP_LOG_WARN(LOG_TAG, "control frame of a kind nodus-storage does not "
                     "send (type=%d) — dropped", (int)msg->type);
    }
    free(msg);
    free(rt);
}

static void ob_on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                        size_t len, void *ctx) {
    ipc_be_t *ib = (ipc_be_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    int idx = ib->by_ipc[conn->slot];
    if (idx == OB_CTL && conn == ib->ctl) {
        ob_on_ctl_frame(ib, payload, len);
        return;
    }
    if (idx < 0) return;
    nodus_dht_origin_kind_t kind = (nodus_dht_origin_kind_t)(idx / NODUS_TCP_MAX_CONNS);
    int slot = idx % NODUS_TCP_MAX_CONNS;
    ob_origin_t *o = ob_origin(ib, kind, slot);
    if (!o || o->ipc != conn) return;
    /* A reply or push for the session — to it unchanged, only while it is
     * the session of this generation (core's send_to_origin checks). */
    nodus_dht_origin_t origin = { kind, slot, o->gen };
    ib->core.send_to_origin(ib->core.ctx, origin, payload, len);
}

static void ob_on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    ipc_be_t *ib = (ipc_be_t *)ctx;
    if (conn->slot < 0 || conn->slot >= NODUS_TCP_MAX_CONNS) return;
    int idx = ib->by_ipc[conn->slot];
    ib->by_ipc[conn->slot] = OB_FREE;

    if (idx == OB_CTL && conn == ib->ctl) {
        ib->ctl = NULL;
        ib->ctl_next_dial_ms = nodus_time_mono_ms() + ib->ctl_backoff_ms;
        QGP_LOG_WARN(LOG_TAG, "control connection to nodus-storage lost (%s) "
                     "— client DHT requests are answered \""
                     NODUS_DHT_NO_STORAGE_MSG "\" until it is back", ib->path);
        return;
    }
    if (idx < 0) return;
    nodus_dht_origin_kind_t kind = (nodus_dht_origin_kind_t)(idx / NODUS_TCP_MAX_CONNS);
    int slot = idx % NODUS_TCP_MAX_CONNS;
    ob_origin_t *o = ob_origin(ib, kind, slot);
    if (!o || o->ipc != conn) return;
    o->ipc = NULL;
    ib->n_origins--;
    if (ib->n_origins < NODUS_DHT_IPC_MAX_ORIGIN_CONNS)
        ib->cap_logged = false;
    if (!ib->closing) {
        /* Decision 32: storage closed it (or went away) — its shadow and
         * listen keys are gone; the session is ended, not re-dialled. */
        nodus_dht_origin_t origin = { kind, slot, o->gen };
        QGP_LOG_WARN(LOG_TAG, "nodus-storage closed the %s session slot=%d "
                     "gen=%llu — ending that session (decision 32)",
                     kind == NODUS_DHT_ORIGIN_CLIENT ? "client" : "4002",
                     slot, (unsigned long long)o->gen);
        ib->core.close_origin(ib->core.ctx, origin);
    }
}

/* ── Ops ─────────────────────────────────────────────────────────── */

static void ipcd_client_frame(nodus_dht_backend_t *b, int slot,
                              const nodus_key_t *client_fp,
                              const nodus_pubkey_t *client_pk,
                              const uint8_t *payload, size_t len,
                              nodus_tier2_msg_t *msg) {
    ipc_be_t *ib = ipc_be(b);
    ob_origin_t *o = ob_origin(ib, NODUS_DHT_ORIGIN_CLIENT, slot);
    if (!o || !msg) return;
    nodus_dht_origin_t origin = { NODUS_DHT_ORIGIN_CLIENT, slot, o->gen };
    int rc = ob_forward(ib, NODUS_DHT_ORIGIN_CLIENT, slot, client_fp,
                        client_pk, NULL, payload, len);
    if (rc == -1)
        ob_no_storage(ib, origin, msg->txn_id);
}

static void ipcd_inter_frame(nodus_dht_backend_t *b, int slot,
                             const nodus_key_t *peer_fp, const char *peer_ip,
                             const uint8_t *payload, size_t len,
                             nodus_tier2_msg_t *msg) {
    (void)msg;   /* the storage side re-decodes the payload */
    ipc_be_t *ib = ipc_be(b);
    if (ob_forward(ib, NODUS_DHT_ORIGIN_INTER, slot, peer_fp, NULL, peer_ip,
                   payload, len) == -1)
        ob_drop(ib, "4002 DHT frame");
}

static void ipcd_inter_t1(nodus_dht_backend_t *b, int slot,
                          const nodus_key_t *peer_fp, const char *peer_ip,
                          const uint8_t *payload, size_t len,
                          nodus_tier1_msg_t *t1) {
    (void)t1;
    ipc_be_t *ib = ipc_be(b);
    if (ob_forward(ib, NODUS_DHT_ORIGIN_INTER, slot, peer_fp, NULL, peer_ip,
                   payload, len) == -1)
        ob_drop(ib, "4002 DHT frame");
}

static void ipcd_udp_frame(nodus_dht_backend_t *b, const char *from_ip,
                           uint16_t from_port, const uint8_t *payload,
                           size_t len, nodus_tier1_msg_t *msg) {
    (void)msg;
    ipc_be_t *ib = ipc_be(b);
    if (!ib->ctl || ob_queued(ib->ctl) >= NODUS_DHT_IPC_CTL_QUEUE_MAX) {
        ob_drop(ib, "UDP datagram");
        return;
    }
    uint8_t buf[NODUS_MAX_FRAME_UDP + 160];
    if (len > NODUS_MAX_FRAME_UDP) return;
    size_t n = nodus_dht_ipc_encode_udp(NODUS_DHT_IPC_Q_UDP_IN, from_ip,
                                        from_port, payload, len,
                                        buf, sizeof(buf));
    if (n > 0)
        nodus_tcp_send(ib->ctl, buf, n);
}

/* COLD, and in call order on the one control connection (peer_seen's four
 * kinds keep their order around core's cluster update). Never dropped for
 * the bound; lost only while storage is away (routing refills on the next
 * heartbeat round). */
static void ipcd_peer_seen(nodus_dht_backend_t *b, nodus_dht_peer_seen_t kind,
                           const nodus_key_t *node_id, const char *ip,
                           uint16_t udp_port, uint16_t tcp_port) {
    ipc_be_t *ib = ipc_be(b);
    if (!ib->ctl || !node_id || !ip) return;
    uint8_t buf[256];
    size_t n = nodus_dht_ipc_encode_seen(kind, node_id, ip, udp_port,
                                         tcp_port, buf, sizeof(buf));
    if (n > 0)
        nodus_tcp_send(ib->ctl, buf, n);
}

static void ipcd_peer_dead(nodus_dht_backend_t *b, const nodus_key_t *node_id) {
    ipc_be_t *ib = ipc_be(b);
    if (!ib->ctl || !node_id) return;
    uint8_t buf[128];
    size_t n = nodus_dht_ipc_encode_dead(node_id, buf, sizeof(buf));
    if (n > 0)
        nodus_tcp_send(ib->ctl, buf, n);
}

static void ipcd_session_opened(nodus_dht_backend_t *b,
                                nodus_dht_origin_t origin) {
    ipc_be_t *ib = ipc_be(b);
    ob_origin_t *o = ob_origin(ib, origin.kind, origin.slot);
    if (!o) return;
    /* A connection left from this slot's previous session is not this
     * session's (its EOF tells storage that session ended). Nothing is
     * sent: the preface of this session's first DHT frame opens it. */
    ob_close(ib, o);
    o->gen = origin.gen;
}

static void ipcd_session_closed(nodus_dht_backend_t *b,
                                nodus_dht_origin_t origin) {
    ipc_be_t *ib = ipc_be(b);
    ob_origin_t *o = ob_origin(ib, origin.kind, origin.slot);
    if (!o) return;
    ob_close(ib, o);
    o->gen = 0;
}

static int ipcd_hint_store(nodus_dht_backend_t *b, const nodus_key_t *node_id,
                           const char *ip, uint16_t port,
                           const uint8_t *frame, size_t len) {
    (void)b;
    (void)node_id;
    (void)frame;
    QGP_LOG_WARN(LOG_TAG, "pending-full frame for %s:%u (len=%zu) not parked: "
                 "the hint table is nodus-storage's and no DHT frame leaves "
                 "through this process's 4002 pool", ip ? ip : "?",
                 (unsigned)port, len);
    return -1;
}

static int ipcd_routing_snapshot(nodus_dht_backend_t *b,
                                 nodus_dht_peer_addr_t *out, int max) {
    ipc_be_t *ib = ipc_be(b);
    if (!out || max <= 0) return 0;
    int n = ib->rt_n < max ? ib->rt_n : max;
    memcpy(out, ib->rt, (size_t)n * sizeof(*out));
    return n;
}

static bool ipcd_read_pending(nodus_dht_backend_t *b) {
    return nodus_tcp_read_pending(&ipc_be(b)->tcp);
}

/* Ping-before-evict runs in nodus-storage, before its own tick. */
static void ipcd_evict_tick(nodus_dht_backend_t *b) {
    (void)b;
}

static void ipcd_tick(nodus_dht_backend_t *b) {
    ipc_be_t *ib = ipc_be(b);
    uint64_t now = nodus_time_mono_ms();
    ob_ctl_tick(ib, now);
    ob_members_tick(ib, now);
    nodus_tcp_poll(&ib->tcp, 0);
}

static void ipcd_stop(nodus_dht_backend_t *b) {
    (void)b;   /* nothing in flight on this side */
}

static void ipcd_close(nodus_dht_backend_t *b) {
    ipc_be_t *ib = ipc_be(b);
    /* nodus_tcp_close frees the connections without on_disconnect. */
    nodus_tcp_close(&ib->tcp);
    free(ib->rt);
    free(ib);
}

static const nodus_dht_backend_ops_t ipc_ops = {
    .client_frame     = ipcd_client_frame,
    .inter_frame      = ipcd_inter_frame,
    .inter_t1         = ipcd_inter_t1,
    .udp_frame        = ipcd_udp_frame,
    .peer_seen        = ipcd_peer_seen,
    .peer_dead        = ipcd_peer_dead,
    .session_opened   = ipcd_session_opened,
    .session_closed   = ipcd_session_closed,
    .hint_store       = ipcd_hint_store,
    .routing_snapshot = ipcd_routing_snapshot,
    .read_pending     = ipcd_read_pending,
    .evict_tick       = ipcd_evict_tick,
    .tick             = ipcd_tick,
    .stop             = ipcd_stop,
    .close            = ipcd_close,
};

int nodus_dht_backend_ipc_open(const char *data_path,
                               const nodus_dht_ipc_core_t *core,
                               nodus_dht_backend_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!data_path || !core || !core->send_to_origin || !core->udp_send ||
        !core->close_origin)
        return -1;

    ipc_be_t *ib = calloc(1, sizeof(*ib));
    if (!ib) return -2;
    if (nodus_dht_ipc_sock_path(data_path, ib->path, sizeof(ib->path)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "storage socket path under \"%s\" does not fit "
                      "%d bytes", data_path, NODUS_TCP_UNIX_PATH_MAX - 1);
        free(ib);
        return -1;
    }
    ib->rt = calloc(NODUS_DHT_IPC_ROUTING_MAX, sizeof(*ib->rt));
    if (!ib->rt) {
        free(ib);
        return -2;
    }
    if (nodus_tcp_init(&ib->tcp, -1) != 0) {
        free(ib->rt);
        free(ib);
        return -2;
    }
    ib->base.ops = &ipc_ops;
    ib->core = *core;
    ib->tcp.on_frame      = ob_on_frame;
    ib->tcp.on_disconnect = ob_on_disconnect;
    ib->tcp.cb_ctx        = ib;
    for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++)
        ib->by_ipc[i] = OB_FREE;
    nodus_random(ib->boot, NODUS_DHT_IPC_BOOT_LEN);
    ib->ctl_backoff_ms = OB_DIAL_BACKOFF_MIN;
    ib->ctl_next_dial_ms = 0;           /* the first tick dials */
    *out = &ib->base;
    return 0;
}
