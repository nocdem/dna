/**
 * @file shared/dnac/cmt_p2p_pex.c
 * @brief cometbft @709fd12b `p2p/pex/pex_reactor.go` in C — the PEX
 *        reactor as one event-loop pass, plus the PEX message codec.
 *
 * Contract, the goroutine → loop mapping, the NOT GROUNDED wire additions
 * and the deviations: cmt_p2p_pex.h. Functions in the reference's order;
 * each names its Go lines (pex_reactor.go unless another file is named).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_pex.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_wire.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_PEX"

/* ══ state ════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *b;
    size_t   n;
} part_t;

/* Everything the reference keeps per peer ID (requestsSent,
 * lastReceivedRequests — :90-91) plus the R-P2P-40 / -41 queues. */
typedef struct {
    char     id[CMT_P2P_ID_CAP];
    bool     req_sent;              /* requestsSent.Has(id)                  */
    int      parts_in;              /* parts of the answer received (R-P2P-40) */
    int      addrs_in, recs_in;     /* addresses / records taken from it     */
    bool     has_last_req;          /* lastReceivedRequests.Get(id) != nil   */
    int64_t  last_req;              /* INT64_MIN = time.Time{}               */
    bool     has_last_push_in;      /* R-P2P-41 receiver                     */
    int64_t  last_push_in;
    part_t  *out;                   /* response parts still to send          */
    int      n_out;
    int      out_head;
    bool     push_pending;          /* R-P2P-41 sender                       */
    bool     pushed;
    int64_t  last_push_out;
} pex_peer_t;

/* :125-128 _attemptsToDial, keyed by DialString (:528). */
typedef struct {
    char    dial[CMT_P2P_NETADDR_STR_MAX];
    int     number;
    int64_t last_dialed;
} atd_t;

/* A dialPeer call whose DialPeerWithAddress has not returned yet. */
typedef struct {
    cmt_p2p_netaddr_t addr;
    int attempts;
} pend_t;

struct cmt_p2p_pex {
    cmt_p2p_pex_host_t  host;
    cmt_p2p_addrbook_t *book;                              /* :84 */
    cmt_p2p_switch_t   *sw;
    int64_t persistent_max_dial_ns;                        /* config :118 */
    int64_t period;                                        /* :87 */

    pex_peer_t *peers;
    int n_peers, cap_peers;
    atd_t *atd;                                            /* :95 */
    int n_atd, cap_atd;
    pend_t *pend;
    int n_pend, cap_pend;
    cmt_p2p_netaddr_t *seed_addrs;                         /* :93 */
    int n_seed_addrs;
    char **seed_strs;
    int n_seed_strs;

    bool started;
    bool stopped;
    int  ens_phase;           /* 0 before the first run, 1 jitter, 2 loop */
    int64_t ens_at;
    bool ens_wake;            /* ensurePeersCh (:86)                      */

    /* dialSeeds (:610-628) as a chain of dial outcomes */
    bool seed_active;
    int *seed_perm;
    int  seed_pos;
    bool seed_waiting;
    bool seed_in_call;
    bool seed_failed_sync;
    cmt_p2p_netaddr_t seed_cur;
};

static const cmt_p2p_ch_desc_t PEX_DESC[] = {              /* :179-189 */
    { CMT_P2P_PEX_CHANNEL, 1, 10, 0, CMT_P2P_PEX_MAX_MSG_SIZE }
};

static void *grow(void *arr, int *cap, int n, size_t elem)
{
    if (n < *cap) {
        return arr;
    }
    {
        int ncap = *cap == 0 ? 8 : *cap * 2;
        void *na = realloc(arr, (size_t)ncap * elem);

        if (na == NULL) {
            return NULL;
        }
        *cap = ncap;
        return na;
    }
}

static int64_t px_now(const cmt_p2p_pex_t *r)
{
    return r->host.now_ns(r->host.ctx);
}

static int64_t px_rand(const cmt_p2p_pex_t *r, int64_t n)
{
    int64_t v;

    if (n <= 0) {
        return 0;
    }
    v = r->host.rand_int63n(r->host.ctx, n);
    return (v < 0 || v >= n) ? 0 : v;
}

static int64_t min_receive_request_interval(const cmt_p2p_pex_t *r)
{
    return r->period / 3;                                  /* :101-105 */
}

static pex_peer_t *peer_state(cmt_p2p_pex_t *r, const char *id, bool create)
{
    int i;
    void *na;

    for (i = 0; i < r->n_peers; i++) {
        if (strcmp(r->peers[i].id, id) == 0) {
            return &r->peers[i];
        }
    }
    if (!create || strlen(id) >= CMT_P2P_ID_CAP) {
        return NULL;
    }
    na = grow(r->peers, &r->cap_peers, r->n_peers, sizeof(*r->peers));
    if (na == NULL) {
        return NULL;
    }
    r->peers = (pex_peer_t *)na;
    memset(&r->peers[r->n_peers], 0, sizeof(r->peers[0]));
    memcpy(r->peers[r->n_peers].id, id, strlen(id) + 1);
    return &r->peers[r->n_peers++];
}

static void outbox_clear(pex_peer_t *s)
{
    int i;

    for (i = 0; i < s->n_out; i++) {
        free(s->out[i].b);
    }
    free(s->out);
    s->out = NULL;
    s->n_out = 0;
    s->out_head = 0;
}

static void peer_state_delete(cmt_p2p_pex_t *r, const char *id)
{
    int i;

    for (i = 0; i < r->n_peers; i++) {
        if (strcmp(r->peers[i].id, id) == 0) {
            outbox_clear(&r->peers[i]);
            memmove(&r->peers[i], &r->peers[i + 1],
                    (size_t)(r->n_peers - i - 1) * sizeof(r->peers[0]));
            r->n_peers--;
            return;
        }
    }
}

static int atd_index(const cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr)
{
    char d[CMT_P2P_NETADDR_STR_MAX];
    int i;

    (void)cmt_p2p_netaddr_dial_string(addr, d, sizeof(d));
    for (i = 0; i < r->n_atd; i++) {
        if (strcmp(r->atd[i].dial, d) == 0) {
            return i;
        }
    }
    return -1;
}

static void atd_delete(cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr)
{
    int i = atd_index(r, addr);

    if (i >= 0) {
        memmove(&r->atd[i], &r->atd[i + 1], (size_t)(r->n_atd - i - 1) * sizeof(r->atd[0]));
        r->n_atd--;
    }
}

static void atd_store(cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr, int number,
                      int64_t when)
{
    int i = atd_index(r, addr);
    void *na;

    if (i < 0) {
        na = grow(r->atd, &r->cap_atd, r->n_atd, sizeof(*r->atd));
        if (na == NULL) {
            return;
        }
        r->atd = (atd_t *)na;
        i = r->n_atd++;
        (void)cmt_p2p_netaddr_dial_string(addr, r->atd[i].dial, sizeof(r->atd[i].dial));
    }
    r->atd[i].number = number;
    r->atd[i].last_dialed = when;
}

/* ══ the message codec ════════════════════════════════════════════════ */

/* pex.pb.go:313-333 Message_PexRequest — `0a 00` (PexRequest has no
 * field, :236-242). */
int cmt_p2p_pex_marshal_request(uint8_t *out, size_t cap, size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    before = w.i;
    wf_close_msg(&w, 1, before);
    return w_finish(&w, out_len);
}

/* pex.pb.go:259-279 PexAddrs + :339-354 Message_PexAddrs, plus the NOT
 * GROUNDED fields 2 and 3 (file header of cmt_p2p_pex.h). */
int cmt_p2p_pex_marshal_addrs(const cmt_p2p_netaddr_t *const *addrs, int n_addrs,
                              const uint8_t *const *recs, int n_recs,
                              bool more, uint8_t *out, size_t cap,
                              size_t *out_len)
{
    pb_w_t w;
    size_t before;
    int i;

    if (out == NULL || out_len == NULL || n_addrs < 0 || n_recs < 0 ||
        (n_addrs > 0 && addrs == NULL) || (n_recs > 0 && recs == NULL)) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    before = w.i;
    wf_varint(&w, 3, more ? 1u : 0u);                      /* NOT GROUNDED */
    for (i = n_recs - 1; i >= 0; i--) {                    /* NOT GROUNDED */
        wf_bytes_elem(&w, 2, recs[i], CMT_P2P_ADDR_REC_SIZE);
    }
    for (i = n_addrs - 1; i >= 0; i--) {                   /* :264-277 */
        char ipb[CMT_P2P_IP_STR_MAX];
        cmt_p2p_netaddr_pb_t pb;
        uint8_t tmp[CMT_P2P_NETADDR_PROTO_MAX];
        size_t n = 0;

        if (addrs[i] == NULL) {
            continue;                    /* NetAddressesToProto skips nil */
        }
        if (cmt_p2p_netaddr_to_proto(addrs[i], ipb, &pb) != CMT_OK ||
            cmt_p2p_netaddr_pb_marshal(&pb, tmp, sizeof(tmp), &n) != CMT_OK) {
            return CMT_REJECT;
        }
        w_raw(&w, tmp, n);
        w_uvarint(&w, (uint64_t)n);
        w_tag(&w, 1, 2);
    }
    wf_close_msg(&w, 2, before);                           /* :339-354 */
    return w_finish(&w, out_len);
}

/* NOT GROUNDED: Message.pex_addr_push = 3 { bytes signed_addr = 1 }. */
int cmt_p2p_pex_marshal_push(const uint8_t *rec, size_t rec_len, uint8_t *out,
                             size_t cap, size_t *out_len)
{
    pb_w_t w;
    size_t before;

    if (rec == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    before = w.i;
    wf_bytes(&w, 1, rec, rec_len);
    wf_close_msg(&w, 3, before);
    return w_finish(&w, out_len);
}

/* A decoded Message (the last `sum` occurrence wins, pex.pb.go Unmarshal). */
typedef struct {
    int kind;                       /* 0 = nil Sum, 1 request, 2 addrs, 3 push */
    cmt_p2p_netaddr_pb_t *addrs;
    int n_addrs;
    const uint8_t **recs;
    size_t *rec_lens;
    int n_recs;
    bool more;
    const uint8_t *push;
    size_t push_len;
} pex_msg_t;

/* pex.pb.go PexRequest.Unmarshal — every field is unknown and skipped. */
static int request_unmarshal(const uint8_t *in, size_t len)
{
    size_t off = 0;

    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        off = pre;
        if (pb_skip(in, len, &off) != CMT_OK) {
            return CMT_REJECT;
        }
    }
    return CMT_OK;
}

/* pex.pb.go PexAddrs.Unmarshal (+ fields 2, 3). With NULL arrays it only
 * validates and counts. */
static int addrs_unmarshal(const uint8_t *in, size_t len, pex_msg_t *m, bool fill)
{
    size_t off = 0;

    m->n_addrs = 0;
    m->n_recs = 0;
    m->more = false;
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;
        uint64_t v;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 1) {                                     /* Addrs */
            cmt_p2p_netaddr_pb_t pb;

            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK ||
                cmt_p2p_netaddr_pb_unmarshal(p, n, &pb) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fill) {
                m->addrs[m->n_addrs] = pb;
            }
            m->n_addrs++;
        } else if (fn == 2) {                              /* signed_addrs */
            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fill) {
                m->recs[m->n_recs] = p;
                m->rec_lens[m->n_recs] = n;
            }
            m->n_recs++;
        } else if (fn == 3) {                              /* more */
            if (wt != 0 || cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            m->more = v != 0;
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

static int push_unmarshal(const uint8_t *in, size_t len, pex_msg_t *m)
{
    size_t off = 0;

    m->push = NULL;
    m->push_len = 0;
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 1) {
            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            m->push = p;
            m->push_len = n;
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

static void msg_free(pex_msg_t *m)
{
    free(m->addrs);
    free(m->recs);
    free(m->rec_lens);
    memset(m, 0, sizeof(*m));
}

/* pex.pb.go Message.Unmarshal: every occurrence decoded, the last wins. */
static int msg_unmarshal(const uint8_t *in, size_t len, pex_msg_t *m)
{
    size_t off = 0;
    const uint8_t *last = NULL;
    size_t last_n = 0;

    memset(m, 0, sizeof(*m));
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn >= 1 && fn <= 3) {
            pex_msg_t probe;

            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;                         /* wrong wireType */
            }
            memset(&probe, 0, sizeof(probe));
            if ((fn == 1 && request_unmarshal(p, n) != CMT_OK) ||
                (fn == 2 && addrs_unmarshal(p, n, &probe, false) != CMT_OK) ||
                (fn == 3 && push_unmarshal(p, n, &probe) != CMT_OK)) {
                return CMT_REJECT;
            }
            m->kind = fn;
            last = p;
            last_n = n;
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    if (m->kind == 2) {
        pex_msg_t cnt;

        memset(&cnt, 0, sizeof(cnt));
        (void)addrs_unmarshal(last, last_n, &cnt, false);
        m->addrs = (cmt_p2p_netaddr_pb_t *)calloc((size_t)cnt.n_addrs + 1, sizeof(*m->addrs));
        m->recs = (const uint8_t **)calloc((size_t)cnt.n_recs + 1, sizeof(*m->recs));
        m->rec_lens = (size_t *)calloc((size_t)cnt.n_recs + 1, sizeof(*m->rec_lens));
        if (m->addrs == NULL || m->recs == NULL || m->rec_lens == NULL) {
            msg_free(m);
            return CMT_FAULT;
        }
        (void)addrs_unmarshal(last, last_n, m, true);
    } else if (m->kind == 3) {
        (void)push_unmarshal(last, last_n, m);
    }
    return CMT_OK;
}

/* ══ construction ═════════════════════════════════════════════════════ */

static void on_dial(void *ctx, const cmt_p2p_netaddr_t *addr, int err);

/* :131-143 NewReactor */
cmt_p2p_pex_t *cmt_p2p_pex_new(const cmt_p2p_pex_config_t *cfg,
                               const cmt_p2p_pex_host_t *host,
                               cmt_p2p_addrbook_t *book, cmt_p2p_switch_t *sw)
{
    cmt_p2p_pex_t *r;
    int i;

    if (cfg == NULL || host == NULL || book == NULL || sw == NULL ||
        host->now_ns == NULL || host->rand_int63n == NULL ||
        cfg->n_seeds < 0 || (cfg->n_seeds > 0 && cfg->seeds == NULL)) {
        return NULL;
    }
    r = (cmt_p2p_pex_t *)calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->host = *host;
    r->book = book;
    r->sw = sw;
    r->persistent_max_dial_ns = cfg->persistent_peers_max_dial_period_ns;
    r->period = cfg->ensure_peers_period_ns > 0 ? cfg->ensure_peers_period_ns
                                                : CMT_P2P_PEX_DEFAULT_ENSURE_PEERS_PERIOD_NS;
    if (cfg->n_seeds > 0) {
        r->seed_strs = (char **)calloc((size_t)cfg->n_seeds, sizeof(char *));
        if (r->seed_strs == NULL) {
            free(r);
            return NULL;
        }
        for (i = 0; i < cfg->n_seeds; i++) {
            const char *s = cfg->seeds[i] != NULL ? cfg->seeds[i] : "";
            size_t n = strlen(s);

            r->seed_strs[i] = (char *)malloc(n + 1);
            if (r->seed_strs[i] == NULL) {
                r->n_seed_strs = i;
                cmt_p2p_pex_free(r);
                return NULL;
            }
            memcpy(r->seed_strs[i], s, n + 1);
        }
        r->n_seed_strs = cfg->n_seeds;
    }
    cmt_p2p_switch_set_dial_observer(sw, on_dial, r);
    return r;
}

void cmt_p2p_pex_free(cmt_p2p_pex_t *r)
{
    int i;

    if (r == NULL) {
        return;
    }
    if (r->sw != NULL && r->sw->dial_observer_ctx == r) {
        cmt_p2p_switch_set_dial_observer(r->sw, NULL, NULL);
    }
    for (i = 0; i < r->n_peers; i++) {
        outbox_clear(&r->peers[i]);
    }
    for (i = 0; i < r->n_seed_strs; i++) {
        free(r->seed_strs[i]);
    }
    free(r->seed_strs);
    free(r->peers);
    free(r->atd);
    free(r->pend);
    free(r->seed_addrs);
    free(r->seed_perm);
    free(r);
}

void cmt_p2p_pex_set_ensure_peers_period(cmt_p2p_pex_t *r, int64_t ns)
{
    if (r != NULL && ns > 0) {
        r->period = ns;                                    /* :401-403 */
    }
}

/* :591-607 checkSeeds. @return numOnline (-1: none configured) or
 * INT32_MIN on a configuration error. */
static int check_seeds(cmt_p2p_pex_t *r)
{
    int i, errs = 0, k = 0;

    if (r->n_seed_strs == 0) {
        return -1;                                         /* :593-595 */
    }
    free(r->seed_addrs);
    r->seed_addrs = (cmt_p2p_netaddr_t *)calloc((size_t)r->n_seed_strs,
                                                sizeof(*r->seed_addrs));
    if (r->seed_addrs == NULL) {
        return INT32_MIN;
    }
    for (i = 0; i < r->n_seed_strs; i++) {                 /* :596-605 */
        int rc = cmt_p2p_netaddr_new_string(r->seed_strs[i], strlen(r->seed_strs[i]),
                                            &r->seed_addrs[k]);

        if (rc == CMT_P2P_ERR_NONE) {
            k++;
        } else if (rc == CMT_P2P_ERR_NETADDR_LOOKUP) {
            QGP_LOG_ERROR(LOG_TAG, "Connecting to seed failed: %s", r->seed_strs[i]);
            errs++;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "seed node configuration has error: %s",
                          r->seed_strs[i]);
            return INT32_MIN;
        }
    }
    r->n_seed_addrs = k;
    return r->n_seed_strs - errs;
}

/* :146-169 OnStart */
static int pex_start(void *ctx)
{
    cmt_p2p_pex_t *r = (cmt_p2p_pex_t *)ctx;
    int online;

    if (cmt_p2p_addrbook_start(r->book) != CMT_OK) {       /* :147-150 */
        return -1;
    }
    online = check_seeds(r);                               /* :152 */
    if (online == INT32_MIN) {
        return -1;
    }
    if (online == 0 && cmt_p2p_addrbook_empty(r->book)) {  /* :155-157 */
        QGP_LOG_ERROR(LOG_TAG, "address book is empty and couldn't resolve any "
                      "seed nodes");
        return -1;
    }
    r->started = true;                                     /* :166 ensurePeersRoutine */
    r->ens_phase = 0;
    return 0;
}

/* :172-176 OnStop */
static void pex_stop(void *ctx)
{
    cmt_p2p_pex_t *r = (cmt_p2p_pex_t *)ctx;

    cmt_p2p_addrbook_stop(r->book);
    r->stopped = true;
}

/* :179-189 GetChannels */
static const cmt_p2p_ch_desc_t *pex_channels(void *ctx, int *n)
{
    (void)ctx;
    *n = 1;
    return PEX_DESC;
}

/* ══ own-record push and response parts (R-P2P-41, R-P2P-40) ═════════ */

static void try_push(cmt_p2p_pex_t *r, cmt_p2p_peer_t *p, pex_peer_t *s)
{
    uint8_t rec[CMT_P2P_ADDR_REC_SIZE];
    uint8_t buf[CMT_P2P_ADDR_REC_SIZE + 16];
    size_t n = 0;
    int64_t now;

    if (!s->push_pending || r->host.own_record == NULL) {
        return;
    }
    now = px_now(r);
    if (s->pushed && now - s->last_push_out < r->period) {
        return;                              /* spaced by ensurePeersPeriod */
    }
    if (!r->host.own_record(r->host.ctx, rec)) {
        s->push_pending = false;             /* nothing to push (not bonded) */
        return;
    }
    if (cmt_p2p_pex_marshal_push(rec, sizeof(rec), buf, sizeof(buf), &n) != CMT_OK) {
        s->push_pending = false;
        return;
    }
    if (cmt_p2p_peer_try_send(p, CMT_P2P_PEX_CHANNEL, buf, n)) {
        s->pushed = true;
        s->last_push_out = now;
        s->push_pending = false;
    }
}

static void flush_outbox(cmt_p2p_peer_t *p, pex_peer_t *s)
{
    while (s->out_head < s->n_out) {
        part_t *pt = &s->out[s->out_head];

        if (!cmt_p2p_peer_can_send(p, CMT_P2P_PEX_CHANNEL) ||
            !cmt_p2p_peer_try_send(p, CMT_P2P_PEX_CHANNEL, pt->b, pt->n)) {
            return;
        }
        s->out_head++;
    }
    if (s->n_out > 0) {
        outbox_clear(s);
    }
}

/* ══ Reactor (:193-300) ═══════════════════════════════════════════════ */

/* :193-217 AddPeer (+ R-P2P-41) */
static void pex_add_peer(void *ctx, cmt_p2p_peer_t *p)
{
    cmt_p2p_pex_t *r = (cmt_p2p_pex_t *)ctx;
    pex_peer_t *s;

    if (cmt_p2p_peer_is_outbound(p)) {                     /* :194-200 */
        if (cmt_p2p_addrbook_need_more_addrs(r->book)) {
            cmt_p2p_pex_request_addrs(r, p);
        }
    } else {                                               /* :201-216 */
        cmt_p2p_netaddr_t addr;
        int rc = cmt_p2p_node_info_net_address(cmt_p2p_peer_node_info(p), &addr);

        if (rc != CMT_P2P_ERR_NONE) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get peer NetAddress %s: %s",
                          cmt_p2p_peer_id(p), cmt_p2p_err_str(rc));
        } else {
            rc = cmt_p2p_addrbook_add_address(r->book, &addr, &addr);   /* :210-214 */
            if (rc != CMT_P2P_AB_OK) {
                QGP_LOG_DEBUG(LOG_TAG, "Failed to add new address: %s",
                              cmt_p2p_ab_err_str(rc));
            }
        }
    }
    if (r->host.own_record != NULL) {                      /* R-P2P-41 */
        s = peer_state(r, cmt_p2p_peer_id(p), true);
        if (s != NULL) {
            s->push_pending = true;
            try_push(r, p, s);
        }
    }
}

/* :220-224 RemovePeer */
static void pex_remove_peer(void *ctx, cmt_p2p_peer_t *p, int reason)
{
    (void)reason;
    peer_state_delete((cmt_p2p_pex_t *)ctx, cmt_p2p_peer_id(p));
}

/* :303-334 receiveRequest. @return 0 or CMT_P2P_PEX_ERR_REQUEST_TOO_SOON. */
static int receive_request(cmt_p2p_pex_t *r, cmt_p2p_peer_t *src)
{
    pex_peer_t *s = peer_state(r, cmt_p2p_peer_id(src), true);
    int64_t now;

    if (s == NULL) {
        return CMT_P2P_PEX_ERR_REQUEST_TOO_SOON;           /* memory: refuse */
    }
    if (!s->has_last_req) {                                /* :306-311 */
        s->has_last_req = true;
        s->last_req = INT64_MIN;
        return 0;
    }
    if (s->last_req == INT64_MIN) {                        /* :314-319 free pass */
        s->last_req = px_now(r);
        return 0;
    }
    now = px_now(r);                                       /* :321-333 */
    if (now - s->last_req < min_receive_request_interval(r)) {
        QGP_LOG_WARN(LOG_TAG, "peer (%s) sent next PEX request too soon. "
                     "Disconnecting", cmt_p2p_peer_id(src));
        return CMT_P2P_PEX_ERR_REQUEST_TOO_SOON;
    }
    s->last_req = now;
    return 0;
}

/* :338-349 RequestAddrs */
void cmt_p2p_pex_request_addrs(cmt_p2p_pex_t *r, cmt_p2p_peer_t *p)
{
    pex_peer_t *s;
    uint8_t buf[8];
    size_t n = 0;

    if (r == NULL || p == NULL) {
        return;
    }
    s = peer_state(r, cmt_p2p_peer_id(p), true);
    if (s == NULL || s->req_sent) {
        return;                                            /* :340-342 */
    }
    QGP_LOG_DEBUG(LOG_TAG, "Request addrs from %s", cmt_p2p_peer_id(p));
    s->req_sent = true;                                    /* :344 */
    s->parts_in = 0;
    s->addrs_in = 0;
    s->recs_in = 0;
    if (cmt_p2p_pex_marshal_request(buf, sizeof(buf), &n) == CMT_OK) {
        (void)cmt_p2p_peer_send(p, CMT_P2P_PEX_CHANNEL, buf, n);   /* :345-348 */
    }
}

/* :354-389 ReceiveAddrs (+ R-P2P-40 parts, R-P2P-4 records). @return 0 or
 * a CMT_P2P_PEX_ERR_*. */
static int receive_addrs(cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addrs,
                         int n_addrs, const uint8_t *const *recs,
                         const size_t *rec_lens, int n_recs, bool more,
                         cmt_p2p_peer_t *src)
{
    pex_peer_t *s = peer_state(r, cmt_p2p_peer_id(src), false);
    cmt_p2p_netaddr_t src_addr;
    int i, rc;

    if (s == NULL || !s->req_sent) {
        return CMT_P2P_PEX_ERR_UNSOLICITED;                /* :356-358 */
    }
    s->parts_in++;
    if (!more || s->parts_in >= CMT_P2P_PEX_MAX_PARTS) {
        s->req_sent = false;                               /* :359 */
    }
    if (cmt_p2p_node_info_net_address(cmt_p2p_peer_node_info(src), &src_addr) !=
        CMT_P2P_ERR_NONE) {
        return CMT_P2P_PEX_ERR_NODE_ADDR;                  /* :361-364 */
    }
    /* The cap PER RESPONSE (red-team R3 F3). The reference's response is
     * ONE message of at most maxMsgSize = maxAddressSize × maxGetSelection
     * bytes (pex_reactor.go:31, :185), filled from GetSelection, which
     * never returns more than maxGetSelection = 250 addresses
     * (addrbook.go:409, params.go:54). Split into parts (R-P2P-40), each
     * part is bounded but their sum is not, so a peer could hand this
     * book up to CMT_P2P_PEX_MAX_PARTS full messages of addresses per
     * request. An honest sender (this port's send_addrs, over
     * GetSelection) sends at most maxGetSelection addresses and as many
     * records; everything past that in one response is ignored. */
    if (n_addrs > CMT_P2P_AB_MAX_GET_SELECTION - s->addrs_in ||
        n_recs > CMT_P2P_AB_MAX_GET_SELECTION - s->recs_in) {
        QGP_LOG_DEBUG(LOG_TAG, "PEX response from %s over %d addresses / "
                      "records — the excess is ignored", cmt_p2p_peer_id(src),
                      CMT_P2P_AB_MAX_GET_SELECTION);
    }
    if (n_addrs > CMT_P2P_AB_MAX_GET_SELECTION - s->addrs_in) {
        n_addrs = CMT_P2P_AB_MAX_GET_SELECTION - s->addrs_in;
    }
    if (n_recs > CMT_P2P_AB_MAX_GET_SELECTION - s->recs_in) {
        n_recs = CMT_P2P_AB_MAX_GET_SELECTION - s->recs_in;
    }
    s->addrs_in += n_addrs;
    s->recs_in += n_recs;
    for (i = 0; i < n_addrs; i++) {                        /* :366-375 */
        rc = cmt_p2p_addrbook_add_address(r->book, &addrs[i], &src_addr);
        if (rc != CMT_P2P_AB_OK) {
            QGP_LOG_DEBUG(LOG_TAG, "Failed to add new address: %s",
                          cmt_p2p_ab_err_str(rc));
        }
    }
    for (i = 0; i < n_recs; i++) {                         /* R-P2P-4 */
        rc = cmt_p2p_addrbook_add_signed(r->book, NULL, &src_addr, recs[i],
                                         rec_lens[i], NULL);
        if (rc != CMT_P2P_AB_OK && rc != CMT_P2P_AB_PENDING) {   /* R-P2P-43 */
            QGP_LOG_DEBUG(LOG_TAG, "Failed to add signed address: %s",
                          cmt_p2p_ab_err_str(rc));
        }
    }
    for (i = 0; i < r->n_seed_addrs; i++) {                /* :378-386 */
        if (cmt_p2p_netaddr_equals(&r->seed_addrs[i], &src_addr)) {
            if (r->ens_phase == 2 && !r->seed_active) {
                r->ens_wake = true;
            }
            break;
        }
    }
    return 0;
}

/* :392-398 SendAddrs (+ R-P2P-4, R-P2P-40). */
void cmt_p2p_pex_send_addrs(cmt_p2p_pex_t *r, cmt_p2p_peer_t *p,
                            const cmt_p2p_netaddr_t *addrs, int n)
{
    const cmt_p2p_netaddr_t **ap;
    const uint8_t **rp;
    size_t *asz;
    int na = 0, nr = 0, i, ai = 0, ri = 0;
    pex_peer_t *s;
    part_t *parts = NULL;
    int n_parts = 0;
    bool fail = false;

    if (r == NULL || p == NULL || n < 0 || (n > 0 && addrs == NULL)) {
        return;
    }
    s = peer_state(r, cmt_p2p_peer_id(p), true);
    ap = (const cmt_p2p_netaddr_t **)calloc((size_t)n + 1, sizeof(*ap));
    rp = (const uint8_t **)calloc((size_t)n + 1, sizeof(*rp));
    asz = (size_t *)calloc((size_t)n + 1, sizeof(*asz));
    parts = (part_t *)calloc(CMT_P2P_PEX_MAX_PARTS, sizeof(*parts));
    if (s == NULL || ap == NULL || rp == NULL || asz == NULL || parts == NULL) {
        free(ap);
        free(rp);
        free(asz);
        free(parts);
        return;
    }
    for (i = 0; i < n; i++) {
        const uint8_t *rec = cmt_p2p_addrbook_record(r->book, addrs[i].id, NULL);
        char ipb[CMT_P2P_IP_STR_MAX];
        cmt_p2p_netaddr_pb_t pb;
        uint8_t tmp[CMT_P2P_NETADDR_PROTO_MAX];
        size_t sz = 0;

        if (rec == NULL && cmt_p2p_addrbook_is_bonded(r->book, addrs[i].id)) {
            continue;                    /* R-P2P-4: never gossip it unsigned */
        }
        if (cmt_p2p_netaddr_to_proto(&addrs[i], ipb, &pb) != CMT_OK ||
            cmt_p2p_netaddr_pb_marshal(&pb, tmp, sizeof(tmp), &sz) != CMT_OK) {
            continue;
        }
        ap[na] = &addrs[i];
        asz[na++] = 2 + sz;
        if (rec != NULL) {
            rp[nr++] = rec;
        }
    }
    /* R-P2P-40: greedy parts — addresses first, then records. */
    do {
        size_t used = 0, cap, len = 0;
        int a0 = ai, r0 = ri;
        uint8_t *buf;

        while (ai < na && used + asz[ai] <= CMT_P2P_PEX_PART_ROOM) {
            used += asz[ai++];
        }
        while (ri < nr && used + CMT_P2P_PEX_REC_ELEM <= CMT_P2P_PEX_PART_ROOM) {
            used += CMT_P2P_PEX_REC_ELEM;
            ri++;
        }
        if (n_parts >= CMT_P2P_PEX_MAX_PARTS ||
            (ai == a0 && ri == r0 && (ai < na || ri < nr))) {
            QGP_LOG_ERROR(LOG_TAG, "PEX response does not fit %d parts",
                          CMT_P2P_PEX_MAX_PARTS);
            fail = true;
            break;
        }
        cap = used + CMT_P2P_PEX_PART_OVERHEAD;
        buf = (uint8_t *)malloc(cap);
        if (buf == NULL ||
            cmt_p2p_pex_marshal_addrs(ap + a0, ai - a0, rp + r0, ri - r0,
                                      ai < na || ri < nr, buf, cap, &len) != CMT_OK) {
            free(buf);
            fail = true;
            break;
        }
        parts[n_parts].b = buf;
        parts[n_parts].n = len;
        n_parts++;
    } while (ai < na || ri < nr);
    free(ap);
    free(rp);
    free(asz);
    if (fail) {
        for (i = 0; i < n_parts; i++) {
            free(parts[i].b);
        }
        free(parts);
        return;
    }
    outbox_clear(s);                     /* a new answer replaces an old one */
    s->out = parts;
    s->n_out = n_parts;
    s->out_head = 0;
    flush_outbox(p, s);
}

/* R-P2P-41: a peer's own record. */
static void receive_push(cmt_p2p_pex_t *r, cmt_p2p_peer_t *src,
                         const uint8_t *rec, size_t len)
{
    cmt_p2p_addr_rec_t pr;
    cmt_p2p_netaddr_t src_addr;
    pex_peer_t *s;
    int64_t now;
    int rc;

    if (rec == NULL || cmt_p2p_addr_rec_parse(rec, len, &pr) != CMT_OK) {
        /* F4 OPEN item C9-4, closed in F5: an undecodable message stops
         * the peer — peer.go:410-421 (Unmarshal / Unwrap panic into
         * onPeerError → StopPeerForError), the same as every other
         * message this reactor cannot decode. */
        QGP_LOG_WARN(LOG_TAG, "malformed pushed record from %s", cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(r->sw, src, CMT_P2P_PEX_ERR_DECODE);
        return;
    }
    if (strcmp(pr.id, cmt_p2p_peer_id(src)) != 0) {
        QGP_LOG_WARN(LOG_TAG, "peer %s pushed a record of %s", cmt_p2p_peer_id(src), pr.id);
        cmt_p2p_switch_stop_peer_for_error(r->sw, src, CMT_P2P_PEX_ERR_PUSH_FOREIGN);
        return;
    }
    s = peer_state(r, cmt_p2p_peer_id(src), true);
    now = px_now(r);
    if (s == NULL ||
        (s->has_last_push_in && now - s->last_push_in < min_receive_request_interval(r))) {
        QGP_LOG_WARN(LOG_TAG, "peer %s pushed its record too soon", cmt_p2p_peer_id(src));
        cmt_p2p_switch_stop_peer_for_error(r->sw, src, CMT_P2P_PEX_ERR_PUSH_TOO_SOON);
        return;
    }
    s->has_last_push_in = true;
    s->last_push_in = now;
    if (cmt_p2p_node_info_net_address(cmt_p2p_peer_node_info(src), &src_addr) !=
        CMT_P2P_ERR_NONE) {
        return;
    }
    rc = cmt_p2p_addrbook_add_signed(r->book, NULL, &src_addr, rec, len, NULL);
    if (rc != CMT_P2P_AB_OK && rc != CMT_P2P_AB_PENDING) {       /* R-P2P-43 */
        QGP_LOG_DEBUG(LOG_TAG, "pushed record of %s not added: %s",
                      cmt_p2p_peer_id(src), cmt_p2p_ab_err_str(rc));
    }
}

/* :239-300 Receive */
static void pex_receive(void *ctx, cmt_p2p_peer_t *src, uint8_t ch_id,
                        const uint8_t *msg, size_t len)
{
    cmt_p2p_pex_t *r = (cmt_p2p_pex_t *)ctx;
    cmt_p2p_netaddr_t sock = *cmt_p2p_peer_socket_addr(src);
    pex_msg_t m;
    int rc;

    (void)ch_id;
    rc = msg_unmarshal(msg, len, &m);
    if (rc != CMT_OK || m.kind == 0) {                     /* peer.go:410-421 */
        QGP_LOG_WARN(LOG_TAG, "undecodable PEX message from %s", cmt_p2p_peer_id(src));
        msg_free(&m);
        cmt_p2p_switch_stop_peer_for_error(r->sw, src, CMT_P2P_PEX_ERR_DECODE);
        return;
    }
    switch (m.kind) {
    case 1: {                                              /* :243-278 */
        cmt_p2p_netaddr_t *sel;
        int n;

        rc = receive_request(r, src);
        if (rc != 0) {                                     /* :272-276 */
            cmt_p2p_switch_stop_peer_for_error(r->sw, src, rc);
            cmt_p2p_addrbook_mark_bad(r->book, &sock, CMT_P2P_PEX_DEFAULT_BAN_TIME_NS);
            break;
        }
        sel = (cmt_p2p_netaddr_t *)calloc(CMT_P2P_AB_MAX_GET_SELECTION, sizeof(*sel));
        if (sel == NULL) {
            break;
        }
        n = cmt_p2p_addrbook_get_selection(r->book, sel);  /* :277 */
        cmt_p2p_pex_send_addrs(r, src, sel, n);
        free(sel);
        break;
    }
    case 2: {                                              /* :280-295 */
        cmt_p2p_netaddr_t *addrs = (cmt_p2p_netaddr_t *)calloc((size_t)m.n_addrs + 1,
                                                               sizeof(*addrs));

        if (addrs == NULL) {
            break;
        }
        rc = cmt_p2p_netaddrs_from_proto(m.addrs, m.n_addrs, addrs);  /* :282 */
        if (rc != CMT_P2P_ERR_NONE) {                      /* :283-287 */
            free(addrs);
            cmt_p2p_switch_stop_peer_for_error(r->sw, src, CMT_P2P_PEX_ERR_BAD_ADDRS);
            cmt_p2p_addrbook_mark_bad(r->book, &sock, CMT_P2P_PEX_DEFAULT_BAN_TIME_NS);
            break;
        }
        rc = receive_addrs(r, addrs, m.n_addrs, m.recs, m.rec_lens, m.n_recs,
                           m.more, src);                   /* :288 */
        free(addrs);
        if (rc != 0) {                                     /* :289-294 */
            cmt_p2p_switch_stop_peer_for_error(r->sw, src, rc);
            if (rc == CMT_P2P_PEX_ERR_UNSOLICITED) {
                cmt_p2p_addrbook_mark_bad(r->book, &sock, CMT_P2P_PEX_DEFAULT_BAN_TIME_NS);
            }
        }
        break;
    }
    case 3:
        receive_push(r, src, m.push, m.push_len);
        break;
    default:
        break;
    }
    msg_free(&m);
}

void cmt_p2p_pex_reactor(cmt_p2p_pex_t *r, cmt_p2p_reactor_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->name = "PEX";
    out->ctx = r;
    out->get_channels = pex_channels;
    out->start = pex_start;
    out->stop = pex_stop;
    out->add_peer = pex_add_peer;
    out->remove_peer = pex_remove_peer;
    out->receive = pex_receive;
}

/* ══ dialing (:527-628) ═══════════════════════════════════════════════ */

/* :527-534 dialAttemptsInfo */
static int dial_attempts_info(const cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr,
                              int64_t *last)
{
    int i = atd_index(r, addr);

    if (i < 0) {
        *last = 0;
        return 0;
    }
    *last = r->atd[i].last_dialed;
    return r->atd[i].number;
}

/* :577-584 maxBackoffDurationForPeer */
static int64_t max_backoff_for_peer(cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr,
                                    int64_t planned)
{
    if (r->persistent_max_dial_ns > 0 && planned > r->persistent_max_dial_ns &&
        cmt_p2p_switch_is_peer_persistent(r->sw, addr)) {
        return r->persistent_max_dial_ns;
    }
    return planned;
}

static int pend_index(const cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr)
{
    int i;

    for (i = 0; i < r->n_pend; i++) {
        if (cmt_p2p_netaddr_equals(&r->pend[i].addr, addr)) {
            return i;
        }
    }
    return -1;
}

static void pend_delete_at(cmt_p2p_pex_t *r, int i)
{
    memmove(&r->pend[i], &r->pend[i + 1], (size_t)(r->n_pend - i - 1) * sizeof(r->pend[0]));
    r->n_pend--;
}

/* :747-755 markAddrInBookBasedOnErr */
static void mark_addr_in_book_based_on_err(cmt_p2p_pex_t *r,
                                           const cmt_p2p_netaddr_t *addr, int err)
{
    if (err == CMT_P2P_ERR_SWITCH_AUTH_FAILURE) {          /* :750-751 (header) */
        cmt_p2p_addrbook_mark_bad(r->book, addr, CMT_P2P_PEX_DEFAULT_BAN_TIME_NS);
    } else {
        cmt_p2p_addrbook_mark_attempt(r->book, addr);      /* :752-753 */
    }
}

/* :536-574 dialPeer — up to the DialPeerWithAddress call; the rest is in
 * on_dial. */
static void dial_peer(cmt_p2p_pex_t *r, const cmt_p2p_netaddr_t *addr)
{
    int64_t last, now = px_now(r);
    int attempts = dial_attempts_info(r, addr, &last);     /* :537 */
    void *na;
    int rc, i;

    if (!cmt_p2p_switch_is_peer_persistent(r->sw, addr) &&
        attempts > CMT_P2P_PEX_MAX_ATTEMPTS_TO_DIAL) {     /* :538-541 */
        cmt_p2p_addrbook_mark_bad(r->book, addr, CMT_P2P_PEX_DEFAULT_BAN_TIME_NS);
        QGP_LOG_DEBUG(LOG_TAG, "reached max attempts %d to dial %s",
                      CMT_P2P_PEX_MAX_ATTEMPTS_TO_DIAL, addr->id);
        return;
    }
    if (attempts > 0) {                                    /* :544-552 */
        double f = (double)px_rand(r, (int64_t)1 << 53) / (double)((int64_t)1 << 53);
        int64_t jitter = (int64_t)(f * 1e9);
        uint64_t mult = attempts >= 64 ? 0 : ((uint64_t)1 << (unsigned)attempts);
        int64_t backoff = (int64_t)((uint64_t)jitter +
                                    mult * (uint64_t)1000000000ULL);  /* Go wraps */

        backoff = max_backoff_for_peer(r, addr, backoff);
        if (now - last < backoff) {
            QGP_LOG_DEBUG(LOG_TAG, "too early to dial %s", addr->id);
            return;                                        /* errTooEarlyToDial */
        }
    }
    na = grow(r->pend, &r->cap_pend, r->n_pend, sizeof(*r->pend));
    if (na == NULL) {
        return;
    }
    r->pend = (pend_t *)na;
    r->pend[r->n_pend].addr = *addr;
    r->pend[r->n_pend].attempts = attempts;
    r->n_pend++;
    rc = cmt_p2p_switch_dial_peer_with_address(r->sw, addr);    /* :554 */
    if (rc == CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING || rc == CMT_FAULT) {
        i = pend_index(r, addr);                           /* :556-558 */
        if (i >= 0) {
            pend_delete_at(r, i);
        }
    }
}

static void seeds_advance(cmt_p2p_pex_t *r);

/* The switch's dial observer: dialPeer's tail (:554-573) and dialSeeds'
 * loop (:616-622). */
static void on_dial(void *ctx, const cmt_p2p_netaddr_t *addr, int err)
{
    cmt_p2p_pex_t *r = (cmt_p2p_pex_t *)ctx;
    int i = pend_index(r, addr);

    if (i >= 0) {
        int attempts = r->pend[i].attempts;

        pend_delete_at(r, i);
        if (err == CMT_P2P_ERR_NONE) {
            atd_delete(r, addr);                           /* :571-572 */
        } else {
            mark_addr_in_book_based_on_err(r, addr, err);  /* :560 */
            if (err == CMT_P2P_ERR_SWITCH_AUTH_FAILURE) {
                atd_delete(r, addr);                       /* :562-564 */
            } else {
                atd_store(r, addr, attempts + 1, px_now(r));   /* :565-566 */
            }
            QGP_LOG_DEBUG(LOG_TAG, "dialing failed (attempts: %d): %s",
                          attempts + 1, cmt_p2p_err_str(err));
        }
    }
    if (r->seed_active && r->seed_waiting &&
        cmt_p2p_netaddr_equals(&r->seed_cur, addr)) {
        r->seed_waiting = false;
        if (err == CMT_P2P_ERR_NONE) {                     /* :619-620 */
            r->seed_active = false;
            return;
        }
        QGP_LOG_ERROR(LOG_TAG, "Error dialing seed %s: %s", addr->id,
                      cmt_p2p_err_str(err));               /* :622 */
        if (r->seed_in_call) {
            r->seed_failed_sync = true;
        } else {
            seeds_advance(r);
        }
    }
}

/* :610-628 dialSeeds, one dial at a time. */
static void seeds_advance(cmt_p2p_pex_t *r)
{
    while (r->seed_pos < r->n_seed_addrs) {
        const cmt_p2p_netaddr_t *a = &r->seed_addrs[r->seed_perm[r->seed_pos++]];
        int rc;

        r->seed_cur = *a;
        r->seed_waiting = true;
        r->seed_failed_sync = false;
        r->seed_in_call = true;
        rc = cmt_p2p_switch_dial_peer_with_address(r->sw, a);   /* :616 */
        r->seed_in_call = false;
        if (rc == CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING) {
            r->seed_waiting = false;
            r->seed_active = false;                        /* :619-620 */
            return;
        }
        if (rc == CMT_P2P_ERR_NONE && r->seed_waiting) {
            return;                      /* in flight: on_dial continues */
        }
        if (rc == CMT_FAULT && r->seed_waiting) {
            QGP_LOG_ERROR(LOG_TAG, "Error dialing seed %s", a->id);
        }
        r->seed_waiting = false;
        if (!r->seed_active) {
            return;
        }
    }
    if (r->n_seed_addrs > 0) {                             /* :625-627 */
        QGP_LOG_ERROR(LOG_TAG, "Couldn't connect to any seeds");
    }
    r->seed_active = false;
}

static void dial_seeds(cmt_p2p_pex_t *r)
{
    int i;

    if (r->n_seed_addrs == 0) {
        return;
    }
    free(r->seed_perm);
    r->seed_perm = (int *)calloc((size_t)r->n_seed_addrs, sizeof(int));
    if (r->seed_perm == NULL) {
        return;
    }
    for (i = 0; i < r->n_seed_addrs; i++) {                /* :611 cmtrand.Perm */
        int j = (int)px_rand(r, (int64_t)i + 1);

        r->seed_perm[i] = r->seed_perm[j];
        r->seed_perm[j] = i;
    }
    r->seed_pos = 0;
    r->seed_active = true;
    seeds_advance(r);
}

/* :443-525 ensurePeers */
static void ensure_peers(cmt_p2p_pex_t *r, bool period_elapsed)
{
    int out = 0, in = 0, dial = 0, num_to_dial, new_bias, max_attempts, i, n_to = 0;
    cmt_p2p_netaddr_t *to_dial;

    cmt_p2p_switch_num_peers(r->sw, &out, &in, &dial);     /* :445 */
    num_to_dial = cmt_p2p_switch_max_num_outbound_peers(r->sw) - (out + dial);  /* :446 */
    QGP_LOG_INFO(LOG_TAG, "Ensure peers numOutPeers=%d numInPeers=%d numDialing=%d "
                 "numToDial=%d", out, in, dial, num_to_dial);
    if (num_to_dial <= 0) {
        return;                                            /* :456-458 */
    }
    new_bias = (out < 8 ? out : 8) * 10 + 10;              /* :463 */
    to_dial = (cmt_p2p_netaddr_t *)calloc((size_t)num_to_dial, sizeof(*to_dial));
    if (to_dial == NULL) {
        return;
    }
    max_attempts = num_to_dial * 3;                        /* :467 */
    for (i = 0; i < max_attempts && n_to < num_to_dial; i++) {   /* :469-484 */
        cmt_p2p_netaddr_t try_addr;
        bool dup = false;
        int k;

        if (!cmt_p2p_addrbook_pick_address(r->book, new_bias, &try_addr)) {
            continue;
        }
        for (k = 0; k < n_to; k++) {
            if (strcmp(to_dial[k].id, try_addr.id) == 0) {
                dup = true;
                break;
            }
        }
        if (dup || cmt_p2p_switch_is_dialing_or_existing_address(r->sw, &try_addr)) {
            continue;
        }
        to_dial[n_to++] = try_addr;
    }
    for (i = 0; i < n_to; i++) {                           /* :487-499, R-P2P-42 */
        dial_peer(r, &to_dial[i]);
    }
    free(to_dial);
    if (cmt_p2p_addrbook_need_more_addrs(r->book)) {       /* :501-504 */
        cmt_p2p_addrbook_reinstate_bad_peers(r->book);
    }
    if (cmt_p2p_addrbook_need_more_addrs(r->book)) {       /* :506-524 */
        const cmt_p2p_peer_set_t *ps = cmt_p2p_switch_peers(r->sw);
        int count = ps != NULL ? ps->n : 0;

        if (count > 0 && period_elapsed) {                 /* :511-515 */
            cmt_p2p_peer_t *p = ps->list[px_rand(r, count)];

            QGP_LOG_INFO(LOG_TAG, "We need more addresses. Sending pexRequest to "
                         "random peer %s", cmt_p2p_peer_id(p));
            cmt_p2p_pex_request_addrs(r, p);
        }
        if (n_to == 0) {                                   /* :520-523 */
            QGP_LOG_INFO(LOG_TAG, "No addresses to dial. Falling back to seeds");
            dial_seeds(r);
        }
    }
}

/* :669-674 nodeHasSomePeersOrDialingAny */
static bool has_some_peers_or_dialing(cmt_p2p_pex_t *r)
{
    int out = 0, in = 0, dial = 0;

    cmt_p2p_switch_num_peers(r->sw, &out, &in, &dial);
    return out + in + dial > 0;
}

int cmt_p2p_pex_attempts_to_dial(const cmt_p2p_pex_t *r,
                                 const cmt_p2p_netaddr_t *addr)
{
    int i;

    if (r == NULL || addr == NULL) {
        return 0;
    }
    i = atd_index(r, addr);                                /* :632-638 */
    return i >= 0 ? r->atd[i].number : 0;
}

void cmt_p2p_pex_own_record_changed(cmt_p2p_pex_t *r)
{
    const cmt_p2p_peer_set_t *ps;
    int i;

    if (r == NULL || r->host.own_record == NULL) {
        return;
    }
    ps = cmt_p2p_switch_peers(r->sw);
    for (i = 0; ps != NULL && i < ps->n; i++) {
        pex_peer_t *s = peer_state(r, cmt_p2p_peer_id(ps->list[i]), true);

        if (s != NULL) {
            s->push_pending = true;
        }
    }
}

bool cmt_p2p_pex_request_outstanding(const cmt_p2p_pex_t *r, const char *id)
{
    int i;

    if (r == NULL || id == NULL) {
        return false;
    }
    for (i = 0; i < r->n_peers; i++) {
        if (strcmp(r->peers[i].id, id) == 0) {
            return r->peers[i].req_sent;
        }
    }
    return false;
}

/* ══ the loop (:406-436 + the queues) ═════════════════════════════════ */

void cmt_p2p_pex_tick(cmt_p2p_pex_t *r)
{
    const cmt_p2p_peer_set_t *ps;
    int64_t now;
    int i;

    if (r == NULL || !r->started || r->stopped) {
        return;
    }
    now = px_now(r);
    cmt_p2p_addrbook_tick(r->book, now);                   /* saveRoutine */

    if (!r->seed_active) {               /* dialSeeds blocks the routine */
        if (r->ens_phase == 0) {                           /* :407-417 */
            int64_t jitter = px_rand(r, r->period);

            if (has_some_peers_or_dialing(r)) {
                r->ens_phase = 1;
                r->ens_at = now + jitter;
            } else {
                r->ens_phase = 2;
                ensure_peers(r, true);                     /* :421 */
                r->ens_at = now + r->period;               /* :424 ticker */
            }
        } else if (r->ens_phase == 1) {
            if (now >= r->ens_at) {
                r->ens_phase = 2;
                ensure_peers(r, true);                     /* :421 */
                r->ens_at = now + r->period;
            }
        } else if (now >= r->ens_at) {                     /* :427-428 */
            while (r->ens_at <= now) {
                r->ens_at += r->period;      /* a ticker drops missed ticks */
            }
            ensure_peers(r, true);
        } else if (r->ens_wake) {                          /* :429-430 */
            r->ens_wake = false;
            ensure_peers(r, false);
        }
    }

    ps = cmt_p2p_switch_peers(r->sw);
    for (i = 0; ps != NULL && i < ps->n; i++) {
        cmt_p2p_peer_t *p = ps->list[i];
        pex_peer_t *s = peer_state(r, cmt_p2p_peer_id(p), false);

        if (s != NULL) {
            flush_outbox(p, s);
            try_push(r, p, s);
        }
    }
}
