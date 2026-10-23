/**
 * Nodus — DHT v2: the holder service (package 6a).
 * See nodus_dht2_holder.h for the contract.
 *
 * @file nodus_dht2_holder.c
 */

#include "dht2/nodus_dht2_holder.h"

#include "crypto/utils/qgp_log.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_record.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT2_HOLDER"

_Static_assert(NODUS_PK_BYTES == DHT2_PUBKEY_LEN,
               "node identity key is the ML-DSA-87 key the envelope carries");
_Static_assert(NODUS_DHT2_HOLDER_WRITE_REFUSAL == DHT2_E_BUSY ||
               NODUS_DHT2_HOLDER_WRITE_REFUSAL == DHT2_E_NOT_CAUGHT_UP,
               "a refusal payload carries 14 or 15 only");

/* ══ the real view ═════════════════════════════════════════════════════ */

static bool wv_snap(void *user, uint64_t now_ms, nodus_witness_dht_snap_t *out)
{
    return nodus_dht2_wview_snap((const nodus_dht2_wview_t *)user, now_ms, out);
}

static const nodus_witness_dht_sets_t *wv_sets(void *user, uint64_t now_ms)
{
    return nodus_dht2_wview_sets((const nodus_dht2_wview_t *)user, now_ms);
}

static nodus_dht2_wview_name_t wv_name(void *user, uint64_t now_ms,
                                       const uint8_t fp[64], uint64_t *h_out)
{
    return nodus_dht2_wview_name((nodus_dht2_wview_t *)user, now_ms, fp,
                                 h_out);
}

void nodus_dht2_holder_view_wview(nodus_dht2_holder_view_t *v,
                                  nodus_dht2_wview_t *wv)
{
    if (v == NULL) {
        return;
    }
    v->snap = wv_snap;
    v->sets = wv_sets;
    v->name = wv_name;
    v->user = wv;
}

/* ══ setup, queue ══════════════════════════════════════════════════════ */

int nodus_dht2_holder_init(nodus_dht2_holder_t *h, nodus_dht2_store_t *store,
                           const nodus_identity_t *id,
                           const uint8_t chain[DHT2_CHAIN_LEN],
                           const nodus_dht2_holder_view_t *view)
{
    if (h == NULL || store == NULL || id == NULL || chain == NULL ||
        view == NULL || view->snap == NULL || view->sets == NULL ||
        view->name == NULL) {
        return -1;
    }
    memset(h, 0, sizeof(*h));
    h->store = store;
    h->id = id;
    h->view = *view;
    memcpy(h->chain, chain, DHT2_CHAIN_LEN);
    if (dht2_fp(id->pk.bytes, h->self_fp) != 0) {
        return -1;
    }
    nodus_dht2_limits_default(&h->limits);
    return 0;
}

bool nodus_dht2_holder_job_enter(nodus_dht2_holder_t *h)
{
    if (h == NULL || h->queued >= NODUS_DHT2_HOLDER_QUEUE_MAX) {
        return false;
    }
    h->queued++;
    return true;
}

void nodus_dht2_holder_job_leave(nodus_dht2_holder_t *h)
{
    if (h != NULL && h->queued > 0) {
        h->queued--;
    }
}

/* ══ the call's world ══════════════════════════════════════════════════ */

/* The store's name callback `user`: the view and this call's tick. */
typedef struct {
    const nodus_dht2_holder_view_t *view;
    uint64_t                        now_ms;
} name_user_t;

/* PENDING / UNAVAILABLE are FAULT for this call; FAULT is passed on so the
 * store consumes it as code 16 (header, NAME RULE). */
static nodus_dht2_name_t name_cb(void *user, const uint8_t fp[DHT2_FP_LEN])
{
    name_user_t *nu = (name_user_t *)user;

    switch (nu->view->name(nu->view->user, nu->now_ms, fp, NULL)) {
    case NODUS_DHT2_WVIEW_NAME_NAMED:
        return NODUS_DHT2_NAME_NAMED;
    case NODUS_DHT2_WVIEW_NAME_UNNAMED:
        return NODUS_DHT2_NAME_UNNAMED;
    case NODUS_DHT2_WVIEW_NAME_FAULT:
    case NODUS_DHT2_WVIEW_NAME_PENDING:
    case NODUS_DHT2_WVIEW_NAME_UNAVAILABLE:
    default:
        return NODUS_DHT2_NAME_FAULT;
    }
}

typedef struct {
    nodus_witness_dht_snap_t         snap;
    bool                             have_snap;   /* fresh snapshot, cu true */
    const nodus_witness_dht_sets_t  *sets;        /* NULL = not available    */
    name_user_t                      nu;
    nodus_dht2_ctx_t                 ctx;
} world_t;

/* Take the snapshot and sets of this call and fill the store's context. A
 * missing or block-syncing snapshot leaves ctx.snap NULL (the store answers
 * 15 for it, and so does serve() before asking). */
static void world_load(nodus_dht2_holder_t *h, uint64_t now_ms, world_t *w)
{
    memset(w, 0, sizeof(*w));
    w->nu.view = &h->view;
    w->nu.now_ms = now_ms;
    w->have_snap = h->view.snap(h->view.user, now_ms, &w->snap) &&
                   w->snap.consensus_up;
    /* The one chain gate: a snapshot of another chain than this holder's is
     * no snapshot at all — nothing below reads its h / t, so an answer never
     * mixes our `c` with a foreign tip. The caller gets the refusal 15. */
    if (w->have_snap &&
        memcmp(w->snap.chain_id, h->chain, DHT2_CHAIN_LEN) != 0) {
        if (!h->chain_warned) {
            h->chain_warned = true;
            QGP_LOG_ERROR(LOG_TAG, "the witness snapshot is of another chain");
        }
        w->have_snap = false;
    }
    memcpy(w->ctx.self_fp, h->self_fp, DHT2_FP_LEN);
    w->ctx.name = name_cb;
    w->ctx.name_user = &w->nu;
    w->ctx.limits = h->limits;
    if (!w->have_snap) {
        return;
    }
    w->ctx.snap = &w->snap;
    w->sets = h->view.sets(h->view.user, now_ms);
    if (w->sets != NULL) {
        w->ctx.have_sets = true;
        w->ctx.s0 = (const uint8_t (*)[DHT2_FP_LEN])w->sets->s0;
        w->ctx.n0 = w->sets->n0;
        w->ctx.s1 = (const uint8_t (*)[DHT2_FP_LEN])w->sets->s1;
        w->ctx.n1 = w->sets->n1;
    }
}

/* ══ sealing ═══════════════════════════════════════════════════════════ */

static int seal(const nodus_dht2_holder_t *h, const char *payload_type,
                const uint8_t *payload, size_t plen, uint8_t *out, size_t cap,
                size_t *out_len)
{
    if (cap < NODUS_DHT2_HOLDER_OUT_MIN) {
        return NODUS_DHT2_HOLDER_ERR;
    }
    if (dht2_answer_seal(payload_type, payload, plen, h->id->sk.bytes,
                         h->id->pk.bytes, out, cap, out_len) != DHT2_OK) {
        QGP_LOG_ERROR(LOG_TAG, "sealing an answer failed");
        return NODUS_DHT2_HOLDER_ERR;
    }
    return NODUS_DHT2_HOLDER_ANSWER;
}

/* Call-level refusal (row 7, row 18): {q, n, c, e}, no h / t. */
static int refuse(const nodus_dht2_holder_t *h, const uint8_t q[DHT2_NONCE_LEN],
                  uint64_t e, uint8_t *out, size_t cap, size_t *out_len)
{
    dht2_refusal_t m;
    uint8_t        payload[DHT2_ANSWER_PAYLOAD_MAX];
    size_t         plen = 0;

    memset(&m, 0, sizeof(m));
    memcpy(m.q, q, DHT2_NONCE_LEN);
    memcpy(m.n, h->self_fp, DHT2_FP_LEN);
    memcpy(m.c, h->chain, DHT2_CHAIN_LEN);
    m.e = e;
    if (dht2_refusal_encode(&m, payload, sizeof(payload), &plen) != DHT2_OK) {
        return NODUS_DHT2_HOLDER_ERR;
    }
    return seal(h, DHT2_PT_REFUSAL, payload, plen, out, cap, out_len);
}

/* The call-level states every request meets first: the row-20 queue (14),
 * then no fresh snapshot / block sync (15). Returns the refusal code, or 0. */
static uint64_t call_state(const nodus_dht2_holder_t *h, const world_t *w)
{
    if (h->queued >= NODUS_DHT2_HOLDER_QUEUE_MAX) {
        return DHT2_E_BUSY;
    }
    if (!w->have_snap) {
        return DHT2_E_NOT_CAUGHT_UP;
    }
    return 0;
}

/* Row 7 per-key code of a store return that is not 0 / 15 / 18. */
static void result_code(dht2_result_t *x, int rc)
{
    x->kind = DHT2_RV_CODE;
    x->code = (rc >= DHT2_E_TOO_LARGE && rc <= DHT2_E_NODE_FULL)
                  ? (uint64_t)rc : DHT2_E_HOLDER_FAULT;
}

/* ══ get / put ═════════════════════════════════════════════════════════ */

static int serve_get(const nodus_dht2_holder_t *h, world_t *w,
                     const dht2_req_t *rq, uint8_t *out, size_t cap,
                     size_t *out_len)
{
    dht2_answer_t *a;
    uint8_t       *rec;
    dht2_record_t *parsed;
    uint8_t        payload[DHT2_ANSWER_PAYLOAD_MAX];
    size_t         plen = 0, i, rlen = 0;
    int            res = NODUS_DHT2_HOLDER_ERR;

    a = (dht2_answer_t *)calloc(1, sizeof(*a));
    rec = (uint8_t *)malloc(DHT2_ENVELOPE_MAX);
    parsed = (dht2_record_t *)malloc(sizeof(*parsed));
    if (a == NULL || rec == NULL || parsed == NULL) {
        goto done;
    }
    memcpy(a->q, rq->nonce, DHT2_NONCE_LEN);
    memcpy(a->n, h->self_fp, DHT2_FP_LEN);
    memcpy(a->c, h->chain, DHT2_CHAIN_LEN);
    a->h = w->snap.height;
    a->t = w->snap.tip_time;
    a->r_count = rq->count;
    for (i = 0; i < rq->count; i++) {
        dht2_result_t *x = &a->r[i];
        int            rc;

        memcpy(x->key, rq->keys[i], DHT2_HASH_LEN);
        rc = nodus_dht2_store_get(h->store, &w->ctx, rq->keys[i], rec,
                                  DHT2_ENVELOPE_MAX, &rlen, x->hash);
        if (rc == NODUS_DHT2_GET_HELD) {
            /* Row 23: inbox-control reads are answered to the inbox OWNER
             * only. A GET is not owner-signed, so a held class-5 record is
             * per-key 17 — never its hash. The stored bytes parsed before
             * (they passed admission); a parse failure now is a fault. */
            if (dht2_record_parse(rec, rlen, h->chain, NULL, parsed)
                != DHT2_OK) {
                x->kind = DHT2_RV_CODE;
                x->code = DHT2_E_HOLDER_FAULT;
            } else if (parsed->d.cls == DHT2_CLASS_INBOX_CTL) {
                x->kind = DHT2_RV_CODE;
                x->code = DHT2_E_NOT_OWNER;
            } else {
                x->kind = DHT2_RV_HASH;
            }
        } else if (rc == NODUS_DHT2_GET_NOT_HELD) {
            x->kind = DHT2_RV_NULL;
        } else if (rc == DHT2_E_NOT_CAUGHT_UP) {
            res = refuse(h, rq->nonce, DHT2_E_NOT_CAUGHT_UP, out, cap,
                         out_len);
            goto done;
        } else {
            x->kind = DHT2_RV_CODE;      /* a store fault is 16, never absence */
            x->code = DHT2_E_HOLDER_FAULT;
        }
    }
    if (dht2_answer_encode(a, payload, sizeof(payload), &plen) != DHT2_OK) {
        goto done;
    }
    res = seal(h, DHT2_PT_ANSWER, payload, plen, out, cap, out_len);
done:
    free(a);
    free(rec);
    free(parsed);
    return res;
}

static int serve_put(const nodus_dht2_holder_t *h, world_t *w,
                     const dht2_req_t *rq, uint8_t *out, size_t cap,
                     size_t *out_len)
{
    dht2_answer_t *a;
    uint8_t        payload[DHT2_ANSWER_PAYLOAD_MAX];
    size_t         plen = 0, i;
    int            res = NODUS_DHT2_HOLDER_ERR;

    a = (dht2_answer_t *)calloc(1, sizeof(*a));
    if (a == NULL) {
        goto done;
    }
    memcpy(a->q, rq->nonce, DHT2_NONCE_LEN);
    memcpy(a->n, h->self_fp, DHT2_FP_LEN);
    memcpy(a->c, h->chain, DHT2_CHAIN_LEN);
    a->h = w->snap.height;
    a->t = w->snap.tip_time;
    a->r_count = rq->count;
    for (i = 0; i < rq->count; i++) {
        dht2_result_t   *x = &a->r[i];
        nodus_dht2_put_t pr;
        int              rc;

        /* ONE parse: the store's admission parses the envelope and hands the
         * address back. k = that address (row 14). An envelope that does not
         * get as far as an address keeps the all-zero key and the store's
         * parse code (1 too-large, 2 bad-encoding, 3 bad-chain, 16 fault);
         * the client matches by position, the array is in request order
         * (row 7). A result is never given under a key it does not have. */
        memset(&pr, 0, sizeof(pr));
        rc =nodus_dht2_store_put(h->store, &w->ctx, rq->envs[i],
                                  rq->env_lens[i], NULL, &pr);
        if (pr.has_address) {
            memcpy(x->key, pr.address, DHT2_HASH_LEN);
        }
        if ((rc == 0 || rc == DHT2_E_HANDLED) && !pr.has_address) {
            x->kind = DHT2_RV_CODE;
            x->code = DHT2_E_HOLDER_FAULT;
        } else if (rc == 0) {
            x->kind = DHT2_RV_HASH;
            memcpy(x->hash, pr.hash, DHT2_HASH_LEN);
        } else if (rc == DHT2_E_HANDLED) {
            x->kind = DHT2_RV_HANDLED;
            x->through = pr.through;
        } else if (rc == DHT2_E_NOT_CAUGHT_UP) {
            res = refuse(h, rq->nonce, DHT2_E_NOT_CAUGHT_UP, out, cap,
                         out_len);
            goto done;
        } else {
            result_code(x, rc);
        }
    }
    if (dht2_receipt_encode(a, payload, sizeof(payload), &plen) != DHT2_OK) {
        goto done;
    }
    res = seal(h, DHT2_PT_RECEIPT, payload, plen, out, cap, out_len);
done:
    free(a);
    return res;
}

/* ══ list ══════════════════════════════════════════════════════════════ */

static int serve_list(nodus_dht2_holder_t *h, uint64_t now_ms,
                      const uint8_t *req, size_t req_len, uint8_t *out,
                      size_t cap, size_t *out_len)
{
    dht2_list_req_t     lr;
    dht2_list_answer_t *la;
    world_t            *w;
    uint8_t             payload[DHT2_ANSWER_PAYLOAD_MAX];
    size_t              plen = 0;
    uint64_t            e;
    int                 rc, res = NODUS_DHT2_HOLDER_ERR;
    bool                denied = false;

    rc = dht2_list_req_open(req, req_len, h->chain, &lr, NULL);
    if (rc == DHT2_E_NOT_OWNER) {
        denied = true;
    } else if (rc == DHT2_E_MALFORMED_REQ || rc == DHT2_E_BAD_CHAIN ||
               rc == DHT2_E_BAD_SIGNATURE) {
        return NODUS_DHT2_HOLDER_NO_ANSWER;
    } else if (rc != DHT2_OK) {
        return NODUS_DHT2_HOLDER_ERR;
    }

    w = (world_t *)malloc(sizeof(*w));
    la = (dht2_list_answer_t *)calloc(1, sizeof(*la));
    if (w == NULL || la == NULL) {
        goto done;
    }
    world_load(h, now_ms, w);
    e = call_state(h, w);
    if (e != 0) {
        res = refuse(h, lr.nonce, e, out, cap, out_len);
        goto done;
    }
    if (denied) {
        /* Row 7 / row 23: a LIST not signed by the inbox owner is answered
         * r.v = 17, nothing listed. */
        memcpy(la->n, h->self_fp, DHT2_FP_LEN);
        memcpy(la->c, h->chain, DHT2_CHAIN_LEN);
        la->h = w->snap.height;
        la->t = w->snap.tip_time;
        memcpy(la->r.key, lr.inbox, DHT2_HASH_LEN);
        la->r.kind = DHT2_RV_CODE;
        la->r.code = DHT2_E_NOT_OWNER;
        la->complete = true;
        if (lr.has_cursor) {
            la->has_req_cursor = true;
            memcpy(la->req_cursor, lr.cursor, DHT2_FP_LEN);
        }
    } else {
        rc = nodus_dht2_store_list(h->store, &w->ctx, lr.inbox,
                                   lr.has_cursor ? lr.cursor : NULL, la);
        if (rc == DHT2_E_NOT_CAUGHT_UP) {
            res = refuse(h, lr.nonce, DHT2_E_NOT_CAUGHT_UP, out, cap, out_len);
            goto done;
        }
        if (rc == NODUS_DHT2_STORE_FAULT) {
            /* A LIST answer cannot carry 16 (row 18): no answer, never an
             * empty page. */
            res = NODUS_DHT2_HOLDER_NO_ANSWER;
            goto done;
        }
        if (rc != 0) {
            goto done;
        }
    }
    memcpy(la->q, lr.nonce, DHT2_NONCE_LEN);
    if (dht2_list_answer_encode(la, payload, sizeof(payload), &plen)
        != DHT2_OK) {
        goto done;
    }
    res = seal(h, DHT2_PT_ANSWER, payload, plen, out, cap, out_len);
done:
    free(w);
    free(la);
    return res;
}

/* ══ entry ═════════════════════════════════════════════════════════════ */

int nodus_dht2_holder_serve(nodus_dht2_holder_t *h,
                            nodus_dht2_holder_kind_t kind, uint64_t now_ms,
                            const uint8_t *req, size_t req_len, uint8_t *out,
                            size_t cap, size_t *out_len)
{
    dht2_req_t rq;
    world_t   *w;
    uint64_t   e;
    int        rc, res;

    if (h == NULL || out == NULL || out_len == NULL ||
        (req == NULL && req_len != 0) ||
        cap < NODUS_DHT2_HOLDER_OUT_MIN) {
        return NODUS_DHT2_HOLDER_ERR;
    }
    *out_len = 0;
    if (kind == NODUS_DHT2_HOLDER_LIST) {
        return serve_list(h, now_ms, req, req_len, out, cap, out_len);
    }
    if (kind != NODUS_DHT2_HOLDER_GET && kind != NODUS_DHT2_HOLDER_PUT) {
        return NODUS_DHT2_HOLDER_ERR;
    }

    rc = dht2_req_decode(req, req_len, &rq);
    if (rc == DHT2_E_MALFORMED_REQ ||
        (rc == DHT2_OK &&
         rq.kind != (kind == NODUS_DHT2_HOLDER_GET ? DHT2_REQ_GET
                                                   : DHT2_REQ_PUT))) {
        return NODUS_DHT2_HOLDER_NO_ANSWER;   /* row 7: no signed answer */
    }
    if (rc != DHT2_OK) {
        return NODUS_DHT2_HOLDER_ERR;
    }

    w = (world_t *)malloc(sizeof(*w));
    if (w == NULL) {
        return NODUS_DHT2_HOLDER_ERR;
    }
    world_load(h, now_ms, w);
    e = call_state(h, w);
    if (e == 0 && kind == NODUS_DHT2_HOLDER_PUT && w->sets != NULL &&
        w->sets->n0 < NODUS_DHT2_HOLDER_WRITE_MIN_SET) {
        e = NODUS_DHT2_HOLDER_WRITE_REFUSAL;   /* §2 precondition */
    }
    if (e != 0) {
        res = refuse(h, rq.nonce, e, out, cap, out_len);
    } else if (kind == NODUS_DHT2_HOLDER_GET) {
        res = serve_get(h, w, &rq, out, cap, out_len);
    } else {
        res = serve_put(h, w, &rq, out, cap, out_len);
    }
    free(w);
    return res;
}
