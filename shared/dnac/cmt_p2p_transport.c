/**
 * @file shared/dnac/cmt_p2p_transport.c
 * @brief cometbft @709fd12b `p2p/transport.go` in C — the
 *        MultiplexTransport as per-connection state machines on one event
 *        loop.
 *
 * Contract, the goroutine → loop mapping and the deviations:
 * cmt_p2p_transport.h. Functions in the reference's order where one
 * exists; each names its Go lines.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_protoio.h"
#include "dnac/cmt_pb.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_TRANSPORT"

/* ══ small helpers ════════════════════════════════════════════════════ */

static int64_t now_ns(const cmt_p2p_transport_t *t)
{
    return t->host.now_ns(t->host.ctx);
}

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;

    while (n-- > 0) {
        *v++ = 0;
    }
}

static void job_free(cmt_p2p_hs_job_t *job)
{
    if (job != NULL) {
        secure_zero(job, sizeof(*job));
        free(job);
    }
}

static int slot_alloc(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    int i;

    for (i = 0; i < t->n_slots; i++) {
        if (t->slots[i] == NULL) {
            break;
        }
    }
    if (i == t->n_slots) {
        int ncap = t->n_slots == 0 ? 16 : t->n_slots * 2;
        cmt_p2p_conn_t **ns = (cmt_p2p_conn_t **)realloc(t->slots,
                                                         (size_t)ncap * sizeof(*ns));

        if (ns == NULL) {
            return -1;
        }
        memset(ns + t->n_slots, 0, (size_t)(ncap - t->n_slots) * sizeof(*ns));
        t->slots = ns;
        t->n_slots = ncap;
    }
    t->slots[i] = c;
    c->slot = i;
    c->gen = t->next_gen++;                        /* R-P2P-3: never reused */
    return i;
}

cmt_p2p_conn_t *cmt_p2p_transport_conn(const cmt_p2p_transport_t *t, int slot,
                                       uint64_t gen)
{
    cmt_p2p_conn_t *c;

    /* §2R4 "check pool membership BEFORE reading gen" */
    if (t == NULL || slot < 0 || slot >= t->n_slots) {
        return NULL;
    }
    c = t->slots[slot];
    if (c == NULL || c->gen != gen || c->state == CMT_P2P_CONN_CLOSED) {
        return NULL;
    }
    return c;
}

static int push_result(cmt_p2p_transport_t *t, bool outbound,
                       cmt_p2p_conn_t *conn, int err,
                       const cmt_p2p_netaddr_t *addr)
{
    cmt_p2p_transport_result_t *r;

    if (t->res_len == t->res_cap) {
        int ncap = t->res_cap == 0 ? 16 : t->res_cap * 2;
        cmt_p2p_transport_result_t *nr = (cmt_p2p_transport_result_t *)
            malloc((size_t)ncap * sizeof(*nr));
        int i;

        if (nr == NULL) {
            return CMT_FAULT;
        }
        for (i = 0; i < t->res_len; i++) {
            nr[i] = t->results[(t->res_head + i) % t->res_cap];
        }
        free(t->results);
        t->results = nr;
        t->res_cap = ncap;
        t->res_head = 0;
    }
    r = &t->results[(t->res_head + t->res_len) % t->res_cap];
    memset(r, 0, sizeof(*r));
    r->outbound = outbound;
    r->conn = conn;
    r->err = err;
    if (addr != NULL) {
        r->addr = *addr;
    }
    t->res_len++;
    return CMT_OK;
}

/* Close the socket and forget the connection: `mt.cleanup(c)`
 * (transport.go:362-366) — conns.Remove + Close — and the LimitListener
 * release. The memory stays (the caller frees it or a peer owns it). */
static void conn_close_socket(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    if (c->state == CMT_P2P_CONN_CLOSED) {
        return;
    }
    if (c->in_conn_set) {
        cmt_p2p_conn_set_remove(&t->conns, &c->remote);
        c->in_conn_set = false;
    }
    if (c->counted_inbound) {
        t->n_inbound--;
        c->counted_inbound = false;
    }
    if (c->slot >= 0 && c->slot < t->n_slots && t->slots[c->slot] == c) {
        t->slots[c->slot] = NULL;
    }
    /* A job still at the host is the host's; its result will find no
     * connection under (slot, gen) and be discarded (R-P2P-3). */
    c->job = NULL;
    c->state = CMT_P2P_CONN_CLOSED;
    c->deadline_ns = 0;
    t->host.close(t->host.ctx, c->slot, c->gen, c->host_handle);
}

/* An upgrade failed: close, free, and report it — `accept{err}`
 * (transport.go:343-344) for an inbound connection, `Dial`'s error
 * (:216-233) for an outbound one. */
static void conn_fail(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c, int err,
                      const cmt_p2p_netaddr_t *self_addr)
{
    bool outbound = c->outbound;
    cmt_p2p_netaddr_t addr;

    if (outbound) {
        addr = c->dialed;
    } else if (self_addr != NULL) {
        addr = *self_addr;
    } else {
        addr = c->remote;
    }
    QGP_LOG_INFO(LOG_TAG, "%s connection rejected: %s",
                 outbound ? "outbound" : "inbound", cmt_p2p_err_str(err));
    c->err = err;
    conn_close_socket(t, c);
    cmt_p2p_conn_free(c);
    (void)push_result(t, outbound, NULL, err, &addr);
}

/* ══ the job (R-P2P-8) ════════════════════════════════════════════════ */

int cmt_p2p_hs_job_run(cmt_p2p_hs_job_t *job)
{
    if (job == NULL) {
        return CMT_FAULT;
    }
    job->rc = cmt_p2p_sc_job_run(&job->job, job->sc_host);
    return job->rc;
}

static bool id_of(const uint8_t *pk, char out[CMT_P2P_ID_CAP])
{
    return pk != NULL && cmt_p2p_pubkey_to_id(pk, out) == CMT_OK;
}

/* Copy the machine's outstanding job into a self-contained one and hand
 * it to the host. The dial pin (R-P2P-14, transport.go:430-445) is
 * applied at ENCAPS, before anything is encapsulated. */
static int submit_job(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    const cmt_p2p_sc_job_t *sj = cmt_p2p_sc_job(c->sc);
    cmt_p2p_hs_job_t *job;

    if (sj == NULL || c->job != NULL) {
        return CMT_OK;
    }
    /* Every dial carries a valid ID (cmt_p2p_transport_dial refuses one
     * without), so the pin is unconditional for outbound connections. */
    if (sj->kind == CMT_P2P_SC_JOB_ENCAPS && c->outbound) {
        /* Initialised: id_of can fail before writing it, and the refusal
         * below logs it (no reference counterpart — Go's ID() of a nil
         * key cannot be logged uninitialised). */
        char claimed[CMT_P2P_ID_CAP] = "?";

        if (!id_of(cmt_p2p_sc_remote_pubkey(c->sc), claimed) ||
            strcmp(claimed, c->dialed.id) != 0) {
            QGP_LOG_WARN(LOG_TAG, "conn.ID (%s) dialed ID (%s) mismatch — "
                         "aborted before Encaps", claimed, c->dialed.id);
            cmt_p2p_sc_abort(c->sc);
            conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
            return CMT_REJECT;
        }
    }
    job = (cmt_p2p_hs_job_t *)calloc(1, sizeof(*job));
    if (job == NULL) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return CMT_FAULT;
    }
    job->slot = c->slot;
    job->gen = c->gen;
    job->job_class = c->outbound ? CMT_P2P_JOB_CLASS_OUTBOUND
                                 : CMT_P2P_JOB_CLASS_INBOUND;
    job->kind = sj->kind;
    job->sc_host = &t->cfg.sc_host;
    job->job.kind = sj->kind;
    switch (sj->kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        memcpy(job->kem_pk, sj->kem_pk, sizeof(job->kem_pk));
        job->job.kem_pk = job->kem_pk;
        job->job.kem_ct_out = job->kem_ct_out;
        job->job.kem_ss_out = job->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_DECAPS:
        memcpy(job->kem_ct, sj->kem_ct, sizeof(job->kem_ct));
        job->job.kem_ct = job->kem_ct;
        job->job.kem_sk = t->kem_sk;
        job->job.kem_ss_out = job->kem_ss_out;
        break;
    case CMT_P2P_SC_JOB_SIGN:
    case CMT_P2P_SC_JOB_VERIFY:
        if (sj->msg_len > sizeof(job->msg)) {
            job_free(job);
            conn_fail(t, c, CMT_FAULT, NULL);
            return CMT_FAULT;
        }
        memcpy(job->msg, sj->msg, sj->msg_len);
        job->msg_len = sj->msg_len;
        job->job.msg = job->msg;
        job->job.msg_len = job->msg_len;
        if (sj->kind == CMT_P2P_SC_JOB_SIGN) {
            job->job.sig_out = job->sig_out;
        } else {
            memcpy(job->dsa_pk, sj->dsa_pk, sizeof(job->dsa_pk));
            memcpy(job->sig, sj->sig, sizeof(job->sig));
            job->job.dsa_pk = job->dsa_pk;
            job->job.sig = job->sig;
        }
        break;
    default:
        job_free(job);
        conn_fail(t, c, CMT_FAULT, NULL);
        return CMT_FAULT;
    }
    if (t->host.submit_job(t->host.ctx, job) != 0) {
        /* §2R4 P3: a full queue closes the handshake (R-P2P-26 for an
         * outbound one). */
        job_free(job);
        conn_fail(t, c, CMT_P2P_ERR_BUSY, NULL);
        return CMT_REJECT;
    }
    c->job = job;
    c->job_class = job->job_class;
    return CMT_OK;
}

/* ══ upgrade (transport.go:411-498) as a state machine ════════════════ */

/* transport.go:447 / :541-581 — start the NodeInfo exchange: write ours
 * delimited (:558-561) under a fresh deadline (:546). */
static int start_node_info(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    uint8_t *msg;
    size_t msg_len = 0, out_len = 0;
    int rc;

    msg = (uint8_t *)malloc(CMT_P2P_MAX_NODE_INFO_SIZE + 16);
    c->ni_out = (uint8_t *)malloc(CMT_P2P_MAX_NODE_INFO_SIZE + 32);
    if (msg == NULL || c->ni_out == NULL) {
        free(msg);
        return CMT_FAULT;
    }
    rc = cmt_p2p_node_info_marshal(t->node_info, msg,
                                   CMT_P2P_MAX_NODE_INFO_SIZE + 16, &msg_len);
    if (rc == CMT_OK) {
        rc = cmt_pb_marshal_delimited(msg, msg_len, c->ni_out,
                                      CMT_P2P_MAX_NODE_INFO_SIZE + 32, &out_len);
    }
    free(msg);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    c->ni_out_off = 0;
    c->ni_out_len = out_len;
    c->state = CMT_P2P_CONN_NODE_INFO;
    c->deadline_ns = now_ns(t) + t->cfg.handshake_timeout_ns;     /* :546 */
    return CMT_OK;
}

/* The secret connection authenticated (transport.go:421-445). */
static int secret_done(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    /* :431 connID := PubKeyToID(secretConn.RemotePubKey()) */
    if (!id_of(cmt_p2p_sc_remote_pubkey(c->sc), c->remote_id)) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return CMT_FAULT;
    }
    /* :432-445 — already enforced at ENCAPS (R-P2P-14); kept. */
    if (c->outbound && strcmp(c->remote_id, c->dialed.id) != 0) {
        conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
        return CMT_REJECT;
    }
    if (start_node_info(t, c) != CMT_OK) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* transport.go:447-497 once both halves of the exchange are done.
 * @return true if upgraded; false if `c` failed (and is freed). */
static bool node_info_done(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    const uint8_t *nid;
    size_t nid_len;
    int rc;

    /* :456-462 Validate */
    rc = cmt_p2p_node_info_validate(c->peer_ni);
    if (rc != CMT_P2P_ERR_NONE) {
        conn_fail(t, c, rc == CMT_FAULT ? CMT_FAULT
                                        : CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID,
                  NULL);
        return false;
    }
    nid = cmt_p2p_node_info_get(c->peer_ni, CMT_P2P_NI_ID, &nid_len);
    /* :465-476 connID == NodeInfo.ID */
    if (nid_len != strlen(c->remote_id) ||
        memcmp(nid, c->remote_id, nid_len) != 0) {
        conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
        return false;
    }
    /* :479-486 reject self — addr = NewNetAddress(nodeInfo.ID(), remote) */
    if (nid_len == strlen(t->id) && memcmp(nid, t->id, nid_len) == 0) {
        cmt_p2p_netaddr_t self;

        self = c->remote;
        memcpy(self.id, c->remote_id, sizeof(self.id));
        conn_fail(t, c, CMT_P2P_ERR_REJECTED_SELF, &self);
        return false;
    }
    /* :488-495 CompatibleWith */
    rc = cmt_p2p_node_info_compatible_with(t->node_info, c->peer_ni);
    if (rc != CMT_P2P_ERR_NONE) {
        conn_fail(t, c, rc == CMT_FAULT ? CMT_FAULT
                                        : CMT_P2P_ERR_REJECTED_INCOMPATIBLE,
                  NULL);
        return false;
    }
    /* :580 SetDeadline(time.Time{}); :344 / :238 hand it over */
    c->deadline_ns = 0;
    c->state = CMT_P2P_CONN_UPGRADED;
    if (push_result(t, c->outbound, c, CMT_P2P_ERR_NONE, &c->dialed) != CMT_OK) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return false;
    }
    return true;
}

/* One NodeInfo-exchange step (transport.go:558-578). */
static bool step_node_info(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c,
                           bool *dead)
{
    bool progress = false;
    int rc;

    /* :558-561 our half — only once every handshake byte (our sealed
     * AUTHSIG, counters 0..4) is in wbuf, so the stream order is the
     * counter order. */
    cmt_p2p_conn_take_sc_out(c);
    if (c->ni_out_off < c->ni_out_len) {
        size_t taken = 0, pending = 0;

        (void)cmt_p2p_sc_out(c->sc, &pending);
        if (pending != 0) {
            return false;
        }

        rc = cmt_p2p_conn_write_plain(c, c->ni_out + c->ni_out_off,
                                      c->ni_out_len - c->ni_out_off, &taken);
        if (rc != CMT_OK) {
            conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
            *dead = true;
            return false;
        }
        c->ni_out_off += taken;
        progress = progress || taken > 0;
    }
    /* :562-566 their half, capped at MaxNodeInfoSize */
    if (c->peer_ni == NULL) {
        size_t before = c->rbuf_len + c->pbuf_len;
        size_t body_off = 0, body_len = 0;

        rc = cmt_p2p_conn_fill_plain(c);
        if (rc != CMT_OK) {
            conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
            *dead = true;
            return false;
        }
        progress = progress || (c->rbuf_len + c->pbuf_len != before);
        rc = cmt_p2p_protoio_read_msg(c->pbuf, c->pbuf_len,
                                      CMT_P2P_MAX_NODE_INFO_SIZE,
                                      &body_off, &body_len, NULL);
        if (rc == CMT_OK) {
            cmt_p2p_node_info_t *ni = (cmt_p2p_node_info_t *)malloc(sizeof(*ni));

            if (ni == NULL) {
                conn_fail(t, c, CMT_FAULT, NULL);
                *dead = true;
                return false;
            }
            /* :575-578 DefaultNodeInfoFromToProto after proto.Unmarshal */
            if (cmt_p2p_node_info_unmarshal(c->pbuf + body_off, body_len, ni) !=
                CMT_OK) {
                free(ni);
                conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
                *dead = true;
                return false;
            }
            c->peer_ni = ni;
            cmt_p2p_conn_pbuf_consume(c, body_off + body_len);
            progress = true;
        } else if (rc != CMT_P2P_PROTOIO_MORE) {
            conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
            *dead = true;
            return false;
        }
    }
    /* :568-573 both halves done */
    if (c->peer_ni != NULL && c->ni_out_off == c->ni_out_len) {
        *dead = !node_info_done(t, c);
        return false;
    }
    return progress;
}

/* One secret-connection step (upgradeSecretConn, transport.go:583-598). */
static bool step_secret(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c, bool *dead)
{
    bool progress = false;
    int rc;

    if (c->job != NULL) {
        return false;                          /* HOLD until the job returns */
    }
    if (cmt_p2p_sc_job(c->sc) != NULL) {
        rc = submit_job(t, c);
        if (rc != CMT_OK) {
            *dead = true;
        }
        return false;
    }
    if (c->rbuf_len > 0 && !cmt_p2p_sc_is_authenticated(c->sc)) {
        size_t used = 0;

        rc = cmt_p2p_sc_recv(c->sc, c->rbuf, c->rbuf_len, &used);
        if (rc != CMT_OK) {
            conn_fail(t, c, rc == CMT_FAULT ? CMT_FAULT
                                            : CMT_P2P_ERR_REJECTED_AUTH_FAILURE,
                      NULL);
            *dead = true;
            return false;
        }
        if (used > 0) {
            memmove(c->rbuf, c->rbuf + used, c->rbuf_len - used);
            c->rbuf_len -= used;
            progress = true;
        }
    }
    cmt_p2p_conn_take_sc_out(c);
    if (cmt_p2p_sc_job(c->sc) != NULL) {
        rc = submit_job(t, c);
        if (rc != CMT_OK) {
            *dead = true;
        }
        return false;
    }
    if (cmt_p2p_sc_is_authenticated(c->sc)) {
        if (secret_done(t, c) != CMT_OK) {
            *dead = true;
            return false;
        }
        return true;
    }
    return progress;
}

/* Advance one connection being upgraded as far as its bytes allow. */
static void advance(cmt_p2p_transport_t *t, cmt_p2p_conn_t *c)
{
    int guard;

    for (guard = 0; guard < 64; guard++) {
        bool dead = false, progress = false;

        if (c->state == CMT_P2P_CONN_SECRET) {
            progress = step_secret(t, c, &dead);
        } else if (c->state == CMT_P2P_CONN_NODE_INFO) {
            progress = step_node_info(t, c, &dead);
        } else {
            return;
        }
        if (dead) {
            return;
        }
        if (!progress) {
            /* The socket failed and nothing buffered moves the upgrade
             * on: MakeSecretConnection / handshake return its error. An
             * UPGRADED connection is already queued for the switch; its
             * peer meets the failure (cmt_p2p_peer_pump). */
            if (c->sock_failed && c->job == NULL &&
                (c->state == CMT_P2P_CONN_SECRET ||
                 c->state == CMT_P2P_CONN_NODE_INFO)) {
                conn_fail(t, c, CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
            }
            return;
        }
    }
}

/* ══ lifecycle ════════════════════════════════════════════════════════ */

/* transport.go:169-186 + node/setup.go:352-409 */
int cmt_p2p_transport_init(cmt_p2p_transport_t *t,
                           const cmt_p2p_transport_host_t *host,
                           const cmt_p2p_transport_config_t *cfg)
{
    const uint8_t *nid;
    size_t nid_len;

    if (t == NULL || host == NULL || cfg == NULL) {
        return CMT_FAULT;
    }
    memset(t, 0, sizeof(*t));
    if (host->now_ns == NULL || host->dial == NULL || host->close == NULL ||
        host->submit_job == NULL || cfg->dsa_pk == NULL || cfg->kem_pk == NULL ||
        cfg->kem_sk == NULL || cfg->chain_id == NULL || cfg->node_info == NULL ||
        cfg->sc_host.sign == NULL || cfg->sc_host.verify == NULL ||
        cfg->max_num_inbound_peers < 0 || cfg->n_unconditional_ids < 0) {
        return CMT_FAULT;
    }
    t->host = *host;
    t->cfg = *cfg;
    t->recv_last_served = -1;
    if (t->cfg.handshake_timeout_ns <= 0) {
        t->cfg.handshake_timeout_ns = CMT_P2P_DEFAULT_HANDSHAKE_TIMEOUT_NS; /* :179 */
    }
    if (t->cfg.dial_timeout_ns <= 0) {
        t->cfg.dial_timeout_ns = CMT_P2P_DEFAULT_DIAL_TIMEOUT_NS;           /* :177 */
    }
    memcpy(t->dsa_pk, cfg->dsa_pk, sizeof(t->dsa_pk));
    memcpy(t->kem_pk, cfg->kem_pk, sizeof(t->kem_pk));
    memcpy(t->kem_sk, cfg->kem_sk, sizeof(t->kem_sk));
    memcpy(t->chain_id, cfg->chain_id, sizeof(t->chain_id));
    t->cfg.dsa_pk = t->dsa_pk;
    t->cfg.kem_pk = t->kem_pk;
    t->cfg.kem_sk = t->kem_sk;
    t->cfg.chain_id = t->chain_id;
    if (cmt_p2p_pubkey_to_id(t->dsa_pk, t->id) != CMT_OK) {
        cmt_p2p_transport_free(t);
        return CMT_FAULT;
    }
    t->node_info = (cmt_p2p_node_info_t *)malloc(sizeof(*t->node_info));
    if (t->node_info == NULL) {
        cmt_p2p_transport_free(t);
        return CMT_FAULT;
    }
    memcpy(t->node_info, cfg->node_info, sizeof(*t->node_info));
    t->cfg.node_info = t->node_info;
    /* node.go:973 Validate; our NodeInfo must carry OUR ID (:944). */
    nid = cmt_p2p_node_info_get(t->node_info, CMT_P2P_NI_ID, &nid_len);
    if (cmt_p2p_node_info_validate(t->node_info) != CMT_P2P_ERR_NONE ||
        nid_len != strlen(t->id) || memcmp(nid, t->id, nid_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "our NodeInfo is invalid or not ours");
        cmt_p2p_transport_free(t);
        return CMT_FAULT;
    }
    cmt_p2p_conn_set_init(&t->conns);
    t->next_gen = 1;
    return CMT_OK;
}

void cmt_p2p_transport_free(cmt_p2p_transport_t *t)
{
    int i;

    if (t == NULL) {
        return;
    }
    for (i = 0; i < t->n_slots; i++) {
        cmt_p2p_conn_t *c = t->slots[i];

        if (c == NULL) {
            continue;
        }
        if (c->peer == NULL && c->state != CMT_P2P_CONN_UPGRADED) {
            conn_close_socket(t, c);
            cmt_p2p_conn_free(c);
        } else {
            /* a peer's connection is its owner's to free; an UPGRADED one
             * is still in the result queue and is freed below */
            conn_close_socket(t, c);
        }
    }
    while (t->res_len > 0) {
        cmt_p2p_transport_result_t *r = &t->results[t->res_head];

        cmt_p2p_conn_free(r->conn);
        t->res_head = (t->res_head + 1) % t->res_cap;
        t->res_len--;
    }
    free(t->results);
    free(t->slots);
    cmt_p2p_conn_set_free(&t->conns);
    free(t->node_info);
    secure_zero(t->kem_sk, sizeof(t->kem_sk));
    memset(t, 0, sizeof(*t));
}

/* transport.go:255-271 */
void cmt_p2p_transport_listen(cmt_p2p_transport_t *t,
                              const cmt_p2p_netaddr_t *addr)
{
    if (t == NULL || addr == NULL) {
        return;
    }
    t->net_addr = *addr;
    t->listening = true;
}

const cmt_p2p_netaddr_t *cmt_p2p_transport_net_address(
    const cmt_p2p_transport_t *t)
{
    return t != NULL ? &t->net_addr : NULL;
}

const char *cmt_p2p_transport_id(const cmt_p2p_transport_t *t)
{
    return t != NULL ? t->id : "";
}

/* transport.go:244-252 (+ R-P2P-28) */
void cmt_p2p_transport_close(cmt_p2p_transport_t *t)
{
    int i;

    if (t == NULL || t->closed) {
        return;
    }
    t->closed = true;
    t->listening = false;
    for (i = 0; i < t->n_slots; i++) {
        cmt_p2p_conn_t *c = t->slots[i];

        if (c != NULL && c->state != CMT_P2P_CONN_PEER &&
            c->state != CMT_P2P_CONN_UPGRADED) {
            conn_close_socket(t, c);
            cmt_p2p_conn_free(c);
        }
    }
}

/* ══ inbound ══════════════════════════════════════════════════════════ */

/* node/setup.go:404-406 (+ R-P2P-27) */
int cmt_p2p_transport_max_incoming(const cmt_p2p_transport_t *t)
{
    int bonded;

    if (t == NULL) {
        return 0;
    }
    bonded = t->host.bonded_count != NULL ? t->host.bonded_count(t->host.ctx) : 0;
    if (bonded < 0) {
        bonded = 0;
    }
    return t->cfg.max_num_inbound_peers + t->cfg.n_unconditional_ids + bonded;
}

bool cmt_p2p_transport_can_accept(const cmt_p2p_transport_t *t)
{
    int max;

    if (t == NULL || t->closed || !t->listening) {
        return false;
    }
    max = cmt_p2p_transport_max_incoming(t);
    return max <= 0 || t->n_inbound < max;          /* transport.go:261 */
}

/* transport.go:286-353 acceptPeers (one connection) + filterConn
 * :368-409. */
int cmt_p2p_transport_accept(cmt_p2p_transport_t *t,
                             const cmt_p2p_ip_t *remote_ip,
                             uint16_t remote_port, uint64_t host_handle,
                             int *slot, uint64_t *gen)
{
    cmt_p2p_netaddr_t remote;
    cmt_p2p_conn_t *c;

    if (t == NULL || remote_ip == NULL || slot == NULL || gen == NULL) {
        return CMT_FAULT;
    }
    if (t->closed) {
        return CMT_P2P_ERR_TRANSPORT_CLOSED;
    }
    if (!cmt_p2p_transport_can_accept(t)) {
        return CMT_P2P_ERR_LIMIT;                        /* LimitListener */
    }
    remote = cmt_p2p_netaddr_new_ip_port(remote_ip, remote_port);
    if (cmt_p2p_conn_set_has(&t->conns, &remote)) {
        return CMT_P2P_ERR_REJECTED_DUPLICATE;           /* :376-378 */
    }
    if (!t->cfg.allow_duplicate_ip &&
        cmt_p2p_conn_set_has_ip(&t->conns, remote_ip)) {
        return CMT_P2P_ERR_REJECTED_FILTERED;            /* :88-104, :398 */
    }
    c = cmt_p2p_conn_new();
    if (c == NULL) {
        return CMT_FAULT;
    }
    if (slot_alloc(t, c) < 0) {
        cmt_p2p_conn_free(c);
        return CMT_FAULT;
    }
    if (cmt_p2p_conn_set_set(&t->conns, &remote) != CMT_OK) {      /* :406 */
        t->slots[c->slot] = NULL;
        cmt_p2p_conn_free(c);
        return CMT_FAULT;
    }
    c->in_conn_set = true;
    c->counted_inbound = true;
    t->n_inbound++;
    c->host_handle = host_handle;
    c->outbound = false;
    c->remote = remote;
    c->state = CMT_P2P_CONN_SECRET;
    c->deadline_ns = now_ns(t) + t->cfg.handshake_timeout_ns;      /* :588 */
    if (cmt_p2p_sc_init(c->sc, CMT_P2P_SC_ROLE_RESPONDER, &t->cfg.sc_host,
                        t->dsa_pk, t->kem_pk, t->kem_sk, CMT_P2P_PROTOCOL_VERSION,
                        t->chain_id) != CMT_OK) {
        c->in_conn_set = false;
        cmt_p2p_conn_set_remove(&t->conns, &remote);
        c->counted_inbound = false;
        t->n_inbound--;
        t->slots[c->slot] = NULL;
        cmt_p2p_conn_free(c);
        return CMT_FAULT;
    }
    *slot = c->slot;
    *gen = c->gen;
    return CMT_P2P_ERR_NONE;
}

/* ══ outbound ═════════════════════════════════════════════════════════ */

/* transport.go:212-241 Dial — :216 addr.DialTimeout(mt.dialTimeout). */
int cmt_p2p_transport_dial(cmt_p2p_transport_t *t,
                           const cmt_p2p_netaddr_t *addr)
{
    cmt_p2p_conn_t *c;
    uint64_t handle = 0;

    if (t == NULL || addr == NULL) {
        return CMT_FAULT;
    }
    if (t->closed) {
        return CMT_P2P_ERR_TRANSPORT_CLOSED;
    }
    /* The reference refuses a dial whose address has no ID: its
     * `connID != dialedAddr.ID` (transport.go:432-433) can never match an
     * empty ID, so the upgrade fails after the handshake. Here it is
     * refused before anything is allocated or sent (R-P2P-33), so no
     * caller can dial unpinned. */
    if (addr->id[0] == '\0') {
        return CMT_P2P_ERR_NETADDR_NO_ID;
    }
    if (strnlen(addr->id, sizeof(addr->id)) == sizeof(addr->id) ||
        cmt_p2p_validate_id(addr->id, strlen(addr->id)) != CMT_P2P_ERR_NONE) {
        return CMT_P2P_ERR_NETADDR_INVALID;
    }
    c = cmt_p2p_conn_new();
    if (c == NULL) {
        return CMT_FAULT;
    }
    if (slot_alloc(t, c) < 0) {
        cmt_p2p_conn_free(c);
        return CMT_FAULT;
    }
    c->outbound = true;
    c->dialed = *addr;
    c->remote = cmt_p2p_netaddr_new_ip_port(&addr->ip, addr->port);
    c->state = CMT_P2P_CONN_DIALING;
    c->deadline_ns = now_ns(t) + t->cfg.dial_timeout_ns;
    if (t->host.dial(t->host.ctx, c->slot, c->gen, addr, &handle) != 0) {
        t->slots[c->slot] = NULL;
        cmt_p2p_conn_free(c);
        return CMT_P2P_ERR_NET;
    }
    c->host_handle = handle;
    return CMT_P2P_ERR_NONE;
}

void cmt_p2p_transport_dial_connected(cmt_p2p_transport_t *t, int slot,
                                      uint64_t gen,
                                      const cmt_p2p_ip_t *remote_ip,
                                      uint16_t remote_port)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL || c->state != CMT_P2P_CONN_DIALING) {
        return;
    }
    if (remote_ip != NULL) {
        c->remote = cmt_p2p_netaddr_new_ip_port(remote_ip, remote_port);
    }
    /* :226-229 filterConn */
    if (cmt_p2p_conn_set_has(&t->conns, &c->remote)) {
        conn_fail(t, c, CMT_P2P_ERR_REJECTED_DUPLICATE, NULL);   /* :376-378 */
        return;
    }
    if (!t->cfg.allow_duplicate_ip &&
        cmt_p2p_conn_set_has_ip(&t->conns, &c->remote.ip)) {
        conn_fail(t, c, CMT_P2P_ERR_REJECTED_FILTERED, NULL);    /* :88-104 */
        return;
    }
    if (cmt_p2p_conn_set_set(&t->conns, &c->remote) != CMT_OK) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return;
    }
    c->in_conn_set = true;
    /* :231 upgrade(c, &addr) */
    c->state = CMT_P2P_CONN_SECRET;
    c->deadline_ns = now_ns(t) + t->cfg.handshake_timeout_ns;      /* :588 */
    if (cmt_p2p_sc_init(c->sc, CMT_P2P_SC_ROLE_INITIATOR, &t->cfg.sc_host,
                        t->dsa_pk, NULL, NULL, CMT_P2P_PROTOCOL_VERSION,
                        t->chain_id) != CMT_OK) {
        conn_fail(t, c, CMT_FAULT, NULL);
        return;
    }
    advance(t, c);
}

/* ══ the host's bytes ═════════════════════════════════════════════════ */

uint8_t *cmt_p2p_transport_read_buf(cmt_p2p_transport_t *t, int slot,
                                    uint64_t gen, size_t *room)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (room != NULL) {
        *room = 0;
    }
    if (c == NULL || room == NULL || c->state == CMT_P2P_CONN_DIALING ||
        c->sock_failed) {
        return NULL;
    }
    *room = cmt_p2p_conn_rbuf_room(c);
    return *room > 0 ? c->rbuf + c->rbuf_len : NULL;
}

void cmt_p2p_transport_read_done(cmt_p2p_transport_t *t, int slot,
                                 uint64_t gen, size_t n)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);
    size_t room;

    if (c == NULL) {
        return;
    }
    room = cmt_p2p_conn_rbuf_room(c);
    if (n > room) {
        n = room;
    }
    c->rbuf_len += n;
}

const uint8_t *cmt_p2p_transport_write_buf(cmt_p2p_transport_t *t, int slot,
                                           uint64_t gen, size_t *len)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (len != NULL) {
        *len = 0;
    }
    if (c == NULL || len == NULL || c->wbuf_len == 0) {
        return NULL;
    }
    *len = c->wbuf_len;
    return c->wbuf + c->wbuf_off;
}

void cmt_p2p_transport_write_done(cmt_p2p_transport_t *t, int slot,
                                  uint64_t gen, size_t n)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL) {
        return;
    }
    if (n > c->wbuf_len) {
        n = c->wbuf_len;
    }
    c->wbuf_off += n;
    c->wbuf_len -= n;
    if (c->wbuf_len == 0) {
        c->wbuf_off = 0;
    }
}

void cmt_p2p_transport_conn_failed(cmt_p2p_transport_t *t, int slot,
                                   uint64_t gen)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL) {
        return;
    }
    if (c->state == CMT_P2P_CONN_DIALING) {
        conn_fail(t, c, CMT_P2P_ERR_NET, NULL);          /* :216-219 */
        return;
    }
    /* Bytes already read are still processed (the reference's reader
     * returns buffered data before the error); the tick fails the
     * upgrade / stops the peer once nothing more moves. */
    c->sock_failed = true;
}

int cmt_p2p_transport_job_done(cmt_p2p_transport_t *t, cmt_p2p_hs_job_t *job)
{
    cmt_p2p_conn_t *c;
    const cmt_p2p_sc_job_t *sj;
    int rc;

    if (t == NULL || job == NULL) {
        return CMT_FAULT;
    }
    c = cmt_p2p_transport_conn(t, job->slot, job->gen);
    if (c == NULL || c->job != job) {
        QGP_LOG_DEBUG(LOG_TAG, "stale handshake job (slot %d gen %llu) discarded",
                      job->slot, (unsigned long long)job->gen);
        job_free(job);
        return CMT_REJECT;
    }
    sj = cmt_p2p_sc_job(c->sc);
    if (sj == NULL || sj->kind != job->kind) {
        c->job = NULL;
        job_free(job);
        conn_fail(t, c, CMT_FAULT, NULL);
        return CMT_OK;
    }
    if (job->rc == 0) {
        switch (job->kind) {
        case CMT_P2P_SC_JOB_ENCAPS:
            memcpy(sj->kem_ct_out, job->kem_ct_out, sizeof(job->kem_ct_out));
            memcpy(sj->kem_ss_out, job->kem_ss_out, sizeof(job->kem_ss_out));
            break;
        case CMT_P2P_SC_JOB_DECAPS:
            memcpy(sj->kem_ss_out, job->kem_ss_out, sizeof(job->kem_ss_out));
            break;
        case CMT_P2P_SC_JOB_SIGN:
            memcpy(sj->sig_out, job->sig_out, sizeof(job->sig_out));
            break;
        default:
            break;
        }
    }
    c->job = NULL;
    rc = cmt_p2p_sc_job_done(c->sc, job->rc);
    job_free(job);
    if (rc != CMT_OK) {
        conn_fail(t, c, rc == CMT_FAULT ? CMT_FAULT
                                        : CMT_P2P_ERR_REJECTED_AUTH_FAILURE, NULL);
        return CMT_OK;
    }
    advance(t, c);
    return CMT_OK;
}

/* ══ the loop ═════════════════════════════════════════════════════════ */

/* The host's `may_receive` row (header): room for one more message?
 * NULL = always. */
static bool peer_may_receive(const cmt_p2p_transport_t *t)
{
    return t->host.may_receive == NULL || t->host.may_receive(t->host.ctx);
}

/* The receive gate handed to cmt_p2p_peer_pump: the host's three rows,
 * asked by the pump before / after every message (cmt_p2p_peer.h "THE
 * RECEIVE GATE"); `send_only` for the host's write path. */
static cmt_p2p_recv_gate_t peer_gate(const cmt_p2p_transport_t *t, bool send_only)
{
    cmt_p2p_recv_gate_t g;

    g.ctx = t->host.ctx;
    g.may_receive = t->host.may_receive;
    g.recv_near_full = t->host.recv_near_full;
    g.queue_mark = t->host.queue_mark;
    g.send_only = send_only;
    return g;
}

/* The host's `recv_near_full` row: is its queue contended? NULL = never. */
static bool peer_contended(const cmt_p2p_transport_t *t)
{
    return t->host.recv_near_full != NULL && t->host.recv_near_full(t->host.ctx);
}

/*
 * One pass over every connection. The walk STARTS just past the slot
 * whose peer this tick last served (delivered >= 1 queue-entering
 * message) and wraps — the served-goes-to-the-back round-robin of the
 * APPROVED fairness rule atlas-dec-efa4d29c (cmt_cs's poll start),
 * applied to the peers a contended consensus queue makes compete. The
 * reference needs no order: every peer's recvRoutine is its own goroutine
 * (connection.go:590-694) and the Go runtime hands freed channel slots to
 * blocked senders in FIFO order. A walk that always began at slot 0 let a
 * low slot that keeps the queue full be served first on every pass and
 * starve the rest (red-team H3). Deadlines and upgrade steps have no
 * order dependence; they ride the same walk.
 *
 * THE CONTENDED SWEEPS (decision 2026-09-27-p2p-fix-2.md (4), RT2 A-F1):
 * while the queue is contended each peer delivers ONE queue-entering
 * message per pump (cmt_p2p_peer.h "THE RECEIVE GATE"), so after the
 * first sweep the room the lane will drain before the next poll may be
 * mostly unused. Further sweeps in the SAME cyclic order ask again every
 * peer that delivered a queue-entering message in the sweep before (a
 * peer that delivered none has nothing complete buffered — its next
 * bytes come with the next socket read, not from this tick), until the
 * queue has no room or nobody delivers. Every peer with messages ready
 * gets one per sweep; the last, partial sweep ends where the room ran
 * out, and `recv_last_served` = the last peer it served, so the next
 * tick begins with the peers that sweep did not reach — over passes no
 * peer's count runs more than one ahead of another's. Termination: each
 * further sweep delivers >= 1 message out of bytes ALREADY buffered (the
 * tick reads no socket) and bounded, so the sweeps end; with a queue_mark
 * row each one also takes >= 1 entry of the host's bounded queue. No
 * reference counterpart (the goroutines need no sweep).
 */
void cmt_p2p_transport_tick(cmt_p2p_transport_t *t)
{
    int k, n, start;
    int64_t now;
    cmt_p2p_recv_gate_t gate;
    bool any = false;

    if (t == NULL) {
        return;
    }
    now = now_ns(t);
    gate = peer_gate(t, false);
    n = t->n_slots;                     /* a slot grown inside a step waits */
    start = (t->recv_last_served >= 0 && t->recv_last_served < n)
                ? t->recv_last_served + 1 : 0;
    for (k = 0; k < n; k++) {
        int i = (start + k) % n;
        cmt_p2p_conn_t *c = i < t->n_slots ? t->slots[i] : NULL;

        if (c == NULL) {
            continue;
        }
        c->recv_again = false;
        switch (c->state) {
        case CMT_P2P_CONN_DIALING:
            if (c->deadline_ns != 0 && now >= c->deadline_ns) {
                conn_fail(t, c, CMT_P2P_ERR_NET, NULL);  /* dial i/o timeout */
            }
            break;
        case CMT_P2P_CONN_SECRET:
        case CMT_P2P_CONN_NODE_INFO:
            if (c->deadline_ns != 0 && now >= c->deadline_ns) {
                /* :546 / :588 SetDeadline passed */
                if (c->state == CMT_P2P_CONN_SECRET) {
                    cmt_p2p_sc_abort(c->sc);
                }
                conn_fail(t, c, CMT_P2P_ERR_REJECTED_TIMEOUT, NULL);
                break;
            }
            advance(t, c);
            break;
        case CMT_P2P_CONN_PEER:
            /* the gate is asked per message: the previous peer's step
             * may have filled the host's queue */
            if (cmt_p2p_peer_pump(c->peer, &gate) > 0) {
                t->recv_last_served = i;
                c->recv_again = true;
                any = true;
            }
            break;
        default:
            break;
        }
    }
    /* The contended sweeps (above). */
    while (any && peer_contended(t) && peer_may_receive(t)) {
        any = false;
        for (k = 0; k < n; k++) {
            int i = (start + k) % n;
            cmt_p2p_conn_t *c = i < t->n_slots ? t->slots[i] : NULL;

            if (c == NULL || !c->recv_again) {
                continue;
            }
            c->recv_again = false;
            if (c->state != CMT_P2P_CONN_PEER) {
                continue;               /* stopped inside an earlier sweep */
            }
            if (!peer_may_receive(t)) {
                break;                  /* the room is used: a partial sweep */
            }
            if (cmt_p2p_peer_pump(c->peer, &gate) > 0) {
                t->recv_last_served = i;
                c->recv_again = true;
                any = true;
            }
        }
    }
}

/* The per-connection body of cmt_p2p_transport_tick without the deadline
 * checks (the tick keeps those): the recvRoutine / sendRoutine step of a
 * peer connection (its send half only when `with_recv` is false — the
 * host's write path), the upgrade step of one being upgraded. The host
 * calls it between socket reads and writes (header, "THE HOST'S BYTES"). */
void cmt_p2p_transport_pump_conn(cmt_p2p_transport_t *t, int slot,
                                 uint64_t gen, bool with_recv)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL) {
        return;
    }
    switch (c->state) {
    case CMT_P2P_CONN_SECRET:
    case CMT_P2P_CONN_NODE_INFO:
        advance(t, c);
        break;
    case CMT_P2P_CONN_PEER: {
        cmt_p2p_recv_gate_t gate = peer_gate(t, !with_recv);

        (void)cmt_p2p_peer_pump(c->peer, &gate);
        break;
    }
    default:
        break;                  /* DIALING / UPGRADED: nothing consumes yet */
    }
}

bool cmt_p2p_transport_may_receive(cmt_p2p_transport_t *t, int slot,
                                   uint64_t gen)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL || c->state != CMT_P2P_CONN_PEER) {
        return true;
    }
    return peer_may_receive(t);
}

bool cmt_p2p_transport_recv_near_full(cmt_p2p_transport_t *t, int slot,
                                      uint64_t gen)
{
    cmt_p2p_conn_t *c = cmt_p2p_transport_conn(t, slot, gen);

    if (c == NULL || c->state != CMT_P2P_CONN_PEER ||
        t->host.recv_near_full == NULL) {
        return false;
    }
    return t->host.recv_near_full(t->host.ctx);
}

bool cmt_p2p_transport_next_result(cmt_p2p_transport_t *t,
                                   cmt_p2p_transport_result_t *out)
{
    if (t == NULL || out == NULL || t->res_len == 0) {
        return false;
    }
    *out = t->results[t->res_head];
    t->res_head = (t->res_head + 1) % t->res_cap;
    t->res_len--;
    return true;
}

/* transport.go:500-539 wrapPeer */
cmt_p2p_peer_t *cmt_p2p_transport_wrap_peer(cmt_p2p_transport_t *t,
                                            cmt_p2p_conn_t *conn,
                                            const cmt_p2p_peer_config_t *cfg)
{
    cmt_p2p_peer_config_t pc;
    cmt_p2p_peer_t *p;

    if (t == NULL || conn == NULL || cfg == NULL ||
        conn->state != CMT_P2P_CONN_UPGRADED || conn->peer_ni == NULL) {
        if (t != NULL && conn != NULL) {
            cmt_p2p_transport_discard(t, conn);
        }
        return NULL;
    }
    pc = *cfg;
    pc.outbound = conn->outbound;                          /* :203, :236 */
    p = cmt_p2p_peer_new(conn, conn->peer_ni, &pc, &t->cfg.mconn,
                         t->host.now_ns, t->host.ctx);
    if (p == NULL) {
        cmt_p2p_transport_discard(t, conn);
        return NULL;
    }
    conn->peer_ni = NULL;                                  /* the peer owns it */
    return p;
}

/* transport.go:357-360 Cleanup */
void cmt_p2p_transport_cleanup(cmt_p2p_transport_t *t, cmt_p2p_peer_t *p)
{
    if (t == NULL || p == NULL || p->conn == NULL) {
        return;
    }
    /* :358 conns.RemoveAddr(p.RemoteAddr()) — conn_close_socket removes
     * the entry this connection set; :359 p.CloseConn() */
    conn_close_socket(t, p->conn);
}

void cmt_p2p_transport_discard(cmt_p2p_transport_t *t, cmt_p2p_conn_t *conn)
{
    if (t == NULL || conn == NULL) {
        return;
    }
    conn_close_socket(t, conn);
    cmt_p2p_conn_free(conn);
}
