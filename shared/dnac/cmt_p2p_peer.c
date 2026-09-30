/**
 * @file shared/dnac/cmt_p2p_peer.c
 * @brief cometbft @v0.38.26 `p2p/peer.go`, `p2p/peer_set.go`,
 *        `p2p/conn_set.go` in C, plus the connection's byte buffers.
 *
 * Contract and deviations: cmt_p2p_peer.h. Functions in the reference's
 * order; each names its Go lines.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_peer.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_PEER"

/* ══ the connection ═══════════════════════════════════════════════════ */

cmt_p2p_conn_t *cmt_p2p_conn_new(void)
{
    cmt_p2p_conn_t *c = (cmt_p2p_conn_t *)calloc(1, sizeof(*c));

    if (c == NULL) {
        return NULL;
    }
    c->slot = -1;
    c->rbuf = (uint8_t *)malloc(CMT_P2P_CONN_RBUF_ALLOC);
    c->pbuf = (uint8_t *)malloc(CMT_P2P_CONN_PBUF_CAP);
    c->wbuf = (uint8_t *)malloc(CMT_P2P_CONN_WBUF_CAP);
    c->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    if (c->rbuf == NULL || c->pbuf == NULL || c->wbuf == NULL || c->sc == NULL) {
        cmt_p2p_conn_free(c);
        return NULL;
    }
    return c;
}

void cmt_p2p_conn_free(cmt_p2p_conn_t *c)
{
    if (c == NULL) {
        return;
    }
    if (c->sc != NULL) {
        cmt_p2p_sc_clear(c->sc);
        free(c->sc);
    }
    free(c->peer_ni);
    free(c->ni_out);
    free(c->rbuf);
    free(c->pbuf);
    free(c->wbuf);
    free(c);
}

size_t cmt_p2p_conn_rbuf_room(const cmt_p2p_conn_t *c)
{
    size_t cap;

    if (c == NULL || c->rbuf == NULL) {
        return 0;
    }
    cap = cmt_p2p_sc_is_authenticated(c->sc) ? (size_t)CMT_P2P_CONN_RBUF_CAP
                                             : (size_t)CMT_P2P_CONN_RBUF_PRE_AUTH_CAP;
    if (cap > (size_t)CMT_P2P_CONN_RBUF_ALLOC) {
        cap = (size_t)CMT_P2P_CONN_RBUF_ALLOC;   /* never beyond the allocation */
    }
    return c->rbuf_len < cap ? cap - c->rbuf_len : 0;
}

/* Free room at the end of wbuf, compacting first. */
static size_t wbuf_room(cmt_p2p_conn_t *c)
{
    if (c->wbuf_off > 0) {
        if (c->wbuf_len > 0) {
            memmove(c->wbuf, c->wbuf + c->wbuf_off, c->wbuf_len);
        }
        c->wbuf_off = 0;
    }
    return CMT_P2P_CONN_WBUF_CAP - c->wbuf_len;
}

void cmt_p2p_conn_take_sc_out(cmt_p2p_conn_t *c)
{
    const uint8_t *o;
    size_t n = 0, room;

    if (c == NULL || c->sc == NULL) {
        return;
    }
    o = cmt_p2p_sc_out(c->sc, &n);
    if (n == 0) {
        return;
    }
    room = wbuf_room(c);
    if (n > room) {
        n = room;
    }
    if (n == 0) {
        return;
    }
    memcpy(c->wbuf + c->wbuf_len, o, n);
    c->wbuf_len += n;
    cmt_p2p_sc_out_consume(c->sc, n);
}

static void rbuf_consume(cmt_p2p_conn_t *c, size_t n)
{
    if (n >= c->rbuf_len) {
        c->rbuf_len = 0;
        return;
    }
    memmove(c->rbuf, c->rbuf + n, c->rbuf_len - n);
    c->rbuf_len -= n;
}

/* secret_connection.go:232-273 Read, frame by frame, into pbuf. The
 * secret connection's own recvBuffer is served first (:236-241) — also
 * when rbuf is EMPTY: the tail of the frame that completed the AUTHSIG
 * (the start of the peer's NodeInfo, typically) sits there, and no later
 * frame need ever arrive to push it out (Codex 7). */
int cmt_p2p_conn_fill_plain(cmt_p2p_conn_t *c)
{
    if (c == NULL || c->sc == NULL) {
        return CMT_FAULT;
    }
    while ((c->rbuf_len > 0 || cmt_p2p_sc_read_pending(c->sc) > 0) &&
           CMT_P2P_CONN_PBUF_CAP - c->pbuf_len >= CMT_P2P_SC_DATA_MAX_SIZE) {
        size_t used = 0, n = 0;
        int rc = cmt_p2p_sc_read(c->sc, c->rbuf, c->rbuf_len, &used,
                                 c->pbuf + c->pbuf_len,
                                 CMT_P2P_CONN_PBUF_CAP - c->pbuf_len, &n);

        if (rc != CMT_OK) {
            return rc;
        }
        rbuf_consume(c, used);
        c->pbuf_len += n;
        if (used == 0 && n == 0) {
            break;
        }
    }
    return CMT_OK;
}

/* secret_connection.go:194-229 Write — whole frames that fit wbuf. */
int cmt_p2p_conn_write_plain(cmt_p2p_conn_t *c, const uint8_t *data,
                             size_t len, size_t *taken)
{
    size_t room, frames, take, olen = 0;
    int rc;

    if (c == NULL || c->sc == NULL || taken == NULL || (data == NULL && len != 0)) {
        return CMT_FAULT;
    }
    *taken = 0;
    if (len == 0) {
        return CMT_OK;
    }
    room = wbuf_room(c);
    frames = room / CMT_P2P_SC_SEALED_FRAME_SIZE;
    if (frames == 0) {
        return CMT_OK;
    }
    take = frames * CMT_P2P_SC_DATA_MAX_SIZE;
    if (take > len) {
        take = len;
    }
    rc = cmt_p2p_sc_write(c->sc, data, take, c->wbuf + c->wbuf_len, room, &olen);
    if (rc != CMT_OK) {
        return rc;
    }
    c->wbuf_len += olen;
    *taken = take;
    return CMT_OK;
}

void cmt_p2p_conn_pbuf_consume(cmt_p2p_conn_t *c, size_t n)
{
    if (c == NULL) {
        return;
    }
    if (n >= c->pbuf_len) {
        c->pbuf_len = 0;
        return;
    }
    memmove(c->pbuf, c->pbuf + n, c->pbuf_len - n);
    c->pbuf_len -= n;
}

/* ══ conn_set.go ══════════════════════════════════════════════════════ */

void cmt_p2p_conn_set_init(cmt_p2p_conn_set_t *cs)
{
    if (cs != NULL) {
        memset(cs, 0, sizeof(*cs));
    }
}

void cmt_p2p_conn_set_free(cmt_p2p_conn_set_t *cs)
{
    if (cs != NULL) {
        free(cs->items);
        memset(cs, 0, sizeof(*cs));
    }
}

static int conn_set_find(const cmt_p2p_conn_set_t *cs, const char *key)
{
    int i;

    for (i = 0; i < cs->n; i++) {
        if (strcmp(cs->items[i].addr, key) == 0) {
            return i;
        }
    }
    return -1;
}

/* conn_set.go:36-43 — c.RemoteAddr().String() is "ip:port". */
bool cmt_p2p_conn_set_has(const cmt_p2p_conn_set_t *cs,
                          const cmt_p2p_netaddr_t *remote)
{
    char key[CMT_P2P_NETADDR_STR_MAX];

    if (cs == NULL || remote == NULL) {
        return false;
    }
    (void)cmt_p2p_netaddr_dial_string(remote, key, sizeof(key));
    return conn_set_find(cs, key) >= 0;
}

/* conn_set.go:45-58 */
bool cmt_p2p_conn_set_has_ip(const cmt_p2p_conn_set_t *cs,
                             const cmt_p2p_ip_t *ip)
{
    int i;

    if (cs == NULL || ip == NULL) {
        return false;
    }
    for (i = 0; i < cs->n; i++) {
        if (cmt_p2p_ip_equal(&cs->items[i].ip, ip)) {
            return true;
        }
    }
    return false;
}

/* conn_set.go:74-82 — a map assignment: replaces an entry with the same
 * key. */
int cmt_p2p_conn_set_set(cmt_p2p_conn_set_t *cs,
                         const cmt_p2p_netaddr_t *remote)
{
    char key[CMT_P2P_NETADDR_STR_MAX];
    int i;

    if (cs == NULL || remote == NULL) {
        return CMT_FAULT;
    }
    (void)cmt_p2p_netaddr_dial_string(remote, key, sizeof(key));
    i = conn_set_find(cs, key);
    if (i < 0) {
        if (cs->n == cs->cap) {
            int ncap = cs->cap == 0 ? 16 : cs->cap * 2;
            cmt_p2p_conn_set_item_t *ni = (cmt_p2p_conn_set_item_t *)
                realloc(cs->items, (size_t)ncap * sizeof(*ni));

            if (ni == NULL) {
                return CMT_FAULT;
            }
            cs->items = ni;
            cs->cap = ncap;
        }
        i = cs->n++;
    }
    memcpy(cs->items[i].addr, key, sizeof(key));
    cs->items[i].ip = remote->ip;
    return CMT_OK;
}

/* conn_set.go:60-72 */
void cmt_p2p_conn_set_remove(cmt_p2p_conn_set_t *cs,
                             const cmt_p2p_netaddr_t *remote)
{
    char key[CMT_P2P_NETADDR_STR_MAX];
    int i;

    if (cs == NULL || remote == NULL) {
        return;
    }
    (void)cmt_p2p_netaddr_dial_string(remote, key, sizeof(key));
    i = conn_set_find(cs, key);
    if (i < 0) {
        return;
    }
    cs->items[i] = cs->items[cs->n - 1];
    cs->n--;
}

/* ══ peer.go ══════════════════════════════════════════════════════════ */

static int64_t peer_now(void *ctx)
{
    cmt_p2p_peer_t *p = (cmt_p2p_peer_t *)ctx;

    return p->now_fn(p->now_ctx);
}

/* peer.go:400-438 onReceive. The reactor lookup and the message decode
 * are the switch's / the reactor's (file header). */
static void peer_on_receive(void *ctx, uint8_t ch_id, const uint8_t *msg,
                            size_t len)
{
    cmt_p2p_peer_t *p = (cmt_p2p_peer_t *)ctx;

    if (p->cfg.on_receive != NULL) {
        p->cfg.on_receive(p->cfg.ctx, p, ch_id, msg, len);
    }
}

/* peer.go:440-442 onError → onPeerError(p, r). */
static void peer_on_error(void *ctx, int reason)
{
    cmt_p2p_peer_t *p = (cmt_p2p_peer_t *)ctx;

    if (p->cfg.on_peer_error != NULL) {
        p->cfg.on_peer_error(p->cfg.ctx, p, reason);
    }
}

/* transport.go:500-539 wrapPeer + peer.go:134-170 newPeer +
 * :390-451 createMConnection. */
cmt_p2p_peer_t *cmt_p2p_peer_new(cmt_p2p_conn_t *conn,
                                 cmt_p2p_node_info_t *node_info,
                                 const cmt_p2p_peer_config_t *cfg,
                                 const cmt_p2p_mconn_config_t *mcfg,
                                 int64_t (*now_ns)(void *ctx),
                                 void *now_ctx)
{
    cmt_p2p_peer_t *p;
    const uint8_t *id;
    size_t id_len;

    if (conn == NULL || node_info == NULL || cfg == NULL || now_ns == NULL) {
        return NULL;
    }
    id = cmt_p2p_node_info_get(node_info, CMT_P2P_NI_ID, &id_len);
    if (id_len >= CMT_P2P_ID_CAP) {
        return NULL;                  /* Validate already refuses this */
    }
    p = (cmt_p2p_peer_t *)calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->cfg = *cfg;
    p->now_fn = now_ns;
    p->now_ctx = now_ctx;
    memcpy(p->id, id, id_len);
    p->id[id_len] = '\0';
    p->outbound = cfg->outbound;

    /* transport.go:507-517 persistent */
    if (cfg->is_persistent != NULL) {
        if (cfg->outbound) {
            p->persistent = cfg->is_persistent(cfg->ctx, &conn->dialed);
        } else {
            cmt_p2p_netaddr_t self_reported;

            if (cmt_p2p_node_info_net_address(node_info, &self_reported) ==
                CMT_P2P_ERR_NONE) {
                p->persistent = cfg->is_persistent(cfg->ctx, &self_reported);
            }
        }
    }
    /* transport.go:238 (outbound: the dialed address) / :337-339
     * (inbound: NewNetAddress(id, c.RemoteAddr())) */
    if (cfg->outbound) {
        p->socket_addr = conn->dialed;
    } else {
        p->socket_addr = conn->remote;
        memcpy(p->socket_addr.id, conn->remote_id, sizeof(p->socket_addr.id));
    }

    p->mhost.ctx = p;
    p->mhost.now_ns = peer_now;
    p->mhost.on_receive = peer_on_receive;
    p->mhost.on_error = peer_on_error;
    if (cmt_p2p_mconn_init(&p->mconn, &p->mhost, cfg->ch_descs, cfg->n_ch_descs,
                           mcfg) != CMT_OK) {
        free(p);
        return NULL;
    }
    p->node_info = node_info;
    p->conn = conn;
    conn->peer = p;
    conn->state = CMT_P2P_CONN_PEER;
    return p;
}

void cmt_p2p_peer_free(cmt_p2p_peer_t *p)
{
    if (p == NULL) {
        return;
    }
    cmt_p2p_mconn_free(&p->mconn);
    free(p->node_info);
    if (p->conn != NULL) {
        p->conn->peer = NULL;
        cmt_p2p_conn_free(p->conn);
    }
    free(p);
}

/* peer.go:191-202 OnStart */
int cmt_p2p_peer_start(cmt_p2p_peer_t *p)
{
    int rc;

    if (p == NULL) {
        return CMT_FAULT;
    }
    if (p->started || p->stopped) {
        return CMT_REJECT;            /* ErrAlreadyStarted / ErrAlreadyStopped */
    }
    rc = cmt_p2p_mconn_start(&p->mconn);
    if (rc != CMT_OK) {
        return rc;
    }
    p->started = true;
    return CMT_OK;
}

/* peer.go:214-220 OnStop */
void cmt_p2p_peer_stop(cmt_p2p_peer_t *p)
{
    if (p == NULL || p->stopped) {
        return;
    }
    p->stopped = true;
    cmt_p2p_mconn_stop(&p->mconn);
}

/* peer.go:207-211 FlushStop */
void cmt_p2p_peer_flush_stop(cmt_p2p_peer_t *p)
{
    if (p == NULL || p->stopped) {
        return;
    }
    p->stopped = true;
    cmt_p2p_mconn_flush_stop(&p->mconn);
}

bool cmt_p2p_peer_is_running(const cmt_p2p_peer_t *p)
{
    return p != NULL && p->started && !p->stopped;
}

const char *cmt_p2p_peer_id(const cmt_p2p_peer_t *p)
{
    return p != NULL ? p->id : "";
}

bool cmt_p2p_peer_is_outbound(const cmt_p2p_peer_t *p)
{
    return p != NULL && p->outbound;
}

bool cmt_p2p_peer_is_persistent(const cmt_p2p_peer_t *p)
{
    return p != NULL && p->persistent;
}

const cmt_p2p_node_info_t *cmt_p2p_peer_node_info(const cmt_p2p_peer_t *p)
{
    return p != NULL ? p->node_info : NULL;
}

const cmt_p2p_netaddr_t *cmt_p2p_peer_socket_addr(const cmt_p2p_peer_t *p)
{
    return p != NULL ? &p->socket_addr : NULL;
}

const cmt_p2p_ip_t *cmt_p2p_peer_remote_ip(const cmt_p2p_peer_t *p)
{
    return (p != NULL && p->conn != NULL) ? &p->conn->remote.ip : NULL;
}

/* peer.go:309-325 hasChannel — the PEER's advertised channels. */
static bool peer_has_channel(const cmt_p2p_peer_t *p, uint8_t ch_id)
{
    if (cmt_p2p_node_info_has_channel(p->node_info, ch_id)) {
        return true;
    }
    QGP_LOG_DEBUG(LOG_TAG, "Unknown channel 0x%02x for peer %s", ch_id, p->id);
    return false;
}

/* peer.go:270-295 send */
bool cmt_p2p_peer_try_send(cmt_p2p_peer_t *p, uint8_t ch_id,
                           const uint8_t *msg, size_t len)
{
    if (!cmt_p2p_peer_is_running(p)) {
        return false;                                     /* :271-272 */
    }
    if (!peer_has_channel(p, ch_id)) {
        return false;                                     /* :273-275 */
    }
    return cmt_p2p_mconn_try_send(&p->mconn, ch_id, msg, len);  /* :285 */
}

/* peer.go:260-262 Send (R-P2P-19) */
bool cmt_p2p_peer_send(cmt_p2p_peer_t *p, uint8_t ch_id,
                       const uint8_t *msg, size_t len)
{
    if (!cmt_p2p_peer_is_running(p)) {
        return false;
    }
    if (!peer_has_channel(p, ch_id)) {
        return false;
    }
    return cmt_p2p_mconn_send(&p->mconn, ch_id, msg, len);
}

/* peer.go:355-360 CanSend */
bool cmt_p2p_peer_can_send(const cmt_p2p_peer_t *p, uint8_t ch_id)
{
    if (!cmt_p2p_peer_is_running(p)) {
        return false;
    }
    return cmt_p2p_mconn_can_send(&p->mconn, ch_id);
}

/* peer.go:298-305 */
void *cmt_p2p_peer_get(const cmt_p2p_peer_t *p, const char *key)
{
    int i;

    if (p == NULL || key == NULL) {
        return NULL;
    }
    for (i = 0; i < CMT_P2P_PEER_DATA_MAX; i++) {
        if (p->data[i].key != NULL && strcmp(p->data[i].key, key) == 0) {
            return p->data[i].val;
        }
    }
    return NULL;
}

bool cmt_p2p_peer_set(cmt_p2p_peer_t *p, const char *key, void *val)
{
    int i, free_i = -1;

    if (p == NULL || key == NULL) {
        return false;
    }
    for (i = 0; i < CMT_P2P_PEER_DATA_MAX; i++) {
        if (p->data[i].key != NULL && strcmp(p->data[i].key, key) == 0) {
            p->data[i].val = val;
            return true;
        }
        if (p->data[i].key == NULL && free_i < 0) {
            free_i = i;
        }
    }
    if (free_i < 0) {
        return false;
    }
    p->data[free_i].key = key;
    p->data[free_i].val = val;
    return true;
}

/* peer.go:332-338 */
void cmt_p2p_peer_set_removal_failed(cmt_p2p_peer_t *p)
{
    if (p != NULL) {
        p->removal_failed = true;
    }
}

bool cmt_p2p_peer_get_removal_failed(const cmt_p2p_peer_t *p)
{
    return p != NULL && p->removal_failed;
}

/* The recvRoutine / sendRoutine pass (header). Bounded so one busy peer
 * cannot hold the loop. */
#define PEER_PUMP_ROUNDS 16

/* The receive gate's two rows (header, "THE RECEIVE GATE"). */
static bool gate_may_receive(const cmt_p2p_recv_gate_t *g)
{
    return g == NULL || g->may_receive == NULL || g->may_receive(g->ctx);
}

static bool gate_near_full(const cmt_p2p_recv_gate_t *g)
{
    return g != NULL && g->recv_near_full != NULL && g->recv_near_full(g->ctx);
}

static uint64_t gate_mark(const cmt_p2p_recv_gate_t *g)
{
    return (g != NULL && g->queue_mark != NULL) ? g->queue_mark(g->ctx) : 0;
}

/* Did the delivery between `before` and now take an entry of the host's
 * queue? With no `queue_mark` row every delivered message counts. */
static bool gate_entered(const cmt_p2p_recv_gate_t *g, uint64_t before)
{
    return g == NULL || g->queue_mark == NULL || gate_mark(g) != before;
}

size_t cmt_p2p_peer_pump(cmt_p2p_peer_t *p, const cmt_p2p_recv_gate_t *gate)
{
    int round;
    size_t n_enq = 0;               /* queue-entering messages delivered   */
    bool recv_ended = false;        /* its turn is over (contended queue)  */
    bool send_only = gate != NULL && gate->send_only;

    if (p == NULL || p->conn == NULL) {
        return 0;
    }
    for (round = 0; round < PEER_PUMP_ROUNDS; round++) {
        cmt_p2p_conn_t *c = p->conn;
        bool progress = false;
        bool recv;
        const uint8_t *o;
        size_t n = 0;
        int rc;

        if (!cmt_p2p_peer_is_running(p) || c->state != CMT_P2P_CONN_PEER) {
            return n_enq;
        }
        /* recvRoutine (connection.go:590-694) — skipped while the host's
         * reactor Receive is "blocked" (header): the routine is stalled
         * inside a Receive and reads nothing. */
        recv = !send_only && !recv_ended && gate_may_receive(gate);
        rc = recv ? cmt_p2p_conn_fill_plain(c) : CMT_OK;
        if (rc != CMT_OK) {
            cmt_p2p_mconn_conn_failed(&p->mconn);        /* :628-635 */
            return n_enq;
        }
        /* One message per recv_n call, the gate asked again before each:
         * the reference's recvRoutine blocks in onReceive per MESSAGE
         * (connection.go:676-678), so "room for one" is the whole
         * condition — no per-step margin (header). */
        while (recv && c->pbuf_len > 0) {
            size_t used = 0, got = 0;
            uint64_t mark = gate_mark(gate);
            bool entered;

            rc = cmt_p2p_mconn_recv_n(&p->mconn, c->pbuf, c->pbuf_len, &used,
                                      1, &got);
            entered = got > 0 && gate_entered(gate, mark);
            if (entered) {
                n_enq++;
            }
            if (!cmt_p2p_peer_is_running(p) || c->state != CMT_P2P_CONN_PEER) {
                return n_enq;
            }
            cmt_p2p_conn_pbuf_consume(c, used);
            if (rc != CMT_OK) {
                return n_enq;
            }
            if (used > 0) {
                progress = true;
            }
            if (got == 0) {
                break;          /* no whole message left, or the recv Monitor
                                 * refused (connection.go:598) */
            }
            if (entered && gate_near_full(gate)) {
                /* The FIFO hand-out of freed slots: one queue-entering
                 * message, then the next peer (header). A message that
                 * took no entry is not a turn. The send half still
                 * runs. */
                recv_ended = true;
                break;
            }
            if (!gate_may_receive(gate)) {
                break;
            }
        }
        /* sendRoutine (connection.go:429-507) */
        cmt_p2p_mconn_tick(&p->mconn);
        if (!cmt_p2p_peer_is_running(p) || c->state != CMT_P2P_CONN_PEER) {
            return n_enq;
        }
        o = cmt_p2p_mconn_out(&p->mconn, &n);
        if (n > 0) {
            size_t taken = 0;

            rc = cmt_p2p_conn_write_plain(c, o, n, &taken);
            if (rc != CMT_OK) {
                cmt_p2p_mconn_conn_failed(&p->mconn);    /* :497-500 */
                return n_enq;
            }
            cmt_p2p_mconn_out_consume(&p->mconn, taken);
            if (taken > 0) {
                progress = true;
            }
        }
        if (!progress) {
            /* The socket failed and the receive half is EXHAUSTED (header,
             * "END OF STREAM"): it ran unstalled this round, moved nothing
             * and pbuf is empty — every opened plaintext went to the
             * MConnection, and rbuf holds less than one sealed frame that
             * can never complete. That is the reader's error
             * (connection.go:628-635). pbuf still holding bytes means the
             * recv Monitor throttled (:598) or the gate stalled the half:
             * those complete messages are delivered first, by a later
             * call — the reference's bufio serves what it buffered before
             * its Read returns the error. A stalled or send-only call
             * decides nothing. */
            if (recv && c->sock_failed && c->pbuf_len == 0) {
                cmt_p2p_mconn_conn_failed(&p->mconn);
            }
            return n_enq;
        }
    }
    return n_enq;
}

/* ══ peer_set.go ══════════════════════════════════════════════════════ */

void cmt_p2p_peer_set_init(cmt_p2p_peer_set_t *ps)
{
    if (ps != NULL) {
        memset(ps, 0, sizeof(*ps));
    }
}

void cmt_p2p_peer_set_free(cmt_p2p_peer_set_t *ps)
{
    if (ps != NULL) {
        free(ps->list);
        memset(ps, 0, sizeof(*ps));
    }
}

static int peer_set_index(const cmt_p2p_peer_set_t *ps, const char *id)
{
    int i;

    for (i = 0; i < ps->n; i++) {
        if (strcmp(ps->list[i]->id, id) == 0) {
            return i;
        }
    }
    return -1;
}

/* peer_set.go:42-60 */
int cmt_p2p_peer_set_add(cmt_p2p_peer_set_t *ps, cmt_p2p_peer_t *p)
{
    if (ps == NULL || p == NULL) {
        return CMT_FAULT;
    }
    if (peer_set_index(ps, p->id) >= 0) {
        return CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_ID;      /* :46-48 */
    }
    if (p->removal_failed) {
        return CMT_P2P_ERR_PEER_REMOVAL;                  /* :49-51 */
    }
    if (ps->n == ps->cap) {
        int ncap = ps->cap == 0 ? 16 : ps->cap * 2;
        cmt_p2p_peer_t **nl = (cmt_p2p_peer_t **)realloc(ps->list,
                                                         (size_t)ncap * sizeof(*nl));

        if (nl == NULL) {
            return CMT_FAULT;
        }
        ps->list = nl;
        ps->cap = ncap;
    }
    ps->list[ps->n++] = p;                                /* :53-58 */
    return CMT_P2P_ERR_NONE;
}

bool cmt_p2p_peer_set_has(const cmt_p2p_peer_set_t *ps, const char *id)
{
    return ps != NULL && id != NULL && peer_set_index(ps, id) >= 0;
}

bool cmt_p2p_peer_set_has_ip(const cmt_p2p_peer_set_t *ps,
                             const cmt_p2p_ip_t *ip)
{
    int i;

    if (ps == NULL || ip == NULL) {
        return false;
    }
    for (i = 0; i < ps->n; i++) {
        const cmt_p2p_ip_t *r = cmt_p2p_peer_remote_ip(ps->list[i]);

        if (r != NULL && cmt_p2p_ip_equal(r, ip)) {
            return true;
        }
    }
    return false;
}

cmt_p2p_peer_t *cmt_p2p_peer_set_get(const cmt_p2p_peer_set_t *ps,
                                     const char *id)
{
    int i;

    if (ps == NULL || id == NULL) {
        return NULL;
    }
    i = peer_set_index(ps, id);
    return i >= 0 ? ps->list[i] : NULL;
}

/* peer_set.go:107-143 — the last peer moves into the removed slot. The
 * lookup is by ID and the item must be THIS peer (the reference's lookup
 * holds the peer it added; a different peer with the same ID is never in
 * the set at the same time, :46-48). */
bool cmt_p2p_peer_set_remove(cmt_p2p_peer_set_t *ps, cmt_p2p_peer_t *p)
{
    int i;

    if (ps == NULL || p == NULL) {
        return false;
    }
    i = peer_set_index(ps, p->id);
    if (i < 0 || ps->list[i] != p) {
        cmt_p2p_peer_set_removal_failed(p);               /* :111-120 */
        return false;
    }
    if (i != ps->n - 1) {
        ps->list[i] = ps->list[ps->n - 1];                /* :134-141 */
    }
    ps->n--;
    return true;
}

int cmt_p2p_peer_set_size(const cmt_p2p_peer_set_t *ps)
{
    return ps != NULL ? ps->n : 0;
}
