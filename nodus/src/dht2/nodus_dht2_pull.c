/**
 * Nodus — DHT v2: pull-sync (package 7 core). See nodus_dht2_pull.h for the
 * contract, the gaps and the governing records.
 *
 * Bee references are v2.8.2 (/home/nocdem/refs/bee-v2.8.2/pkg):
 *   PS  = pullsync/pullsync.go     PU  = puller/puller.go
 *   BV  = bitvector/bitvector.go
 * "row 12" = design rev 5 §13 row 12 (docs/plans/2026-10-14-dht-v2-design.md).
 *
 * LEFT OUT OF BEE (each with the line and what drops it):
 *   · stamps / batch ids (PS:290-296, :326-340, :348-352) — row 12 "stamps
 *     dropped (4d)";
 *   · bins (PS `bin`, PU `peer.po`, `storageRadius`, PU:285-333) — row 12
 *     "one cursor per source instead of per proximity bin";
 *   · the stream per exchange and its Reset / FullClose (PS:131-150,
 *     :233-240) — row 12 "exchanges share the framed node session";
 *   · the 250 chunks / s limiters (PS:100, :196-201; PU:142, :390) and the
 *     pageTimeout wait of collectAddrs (PS:49, :423-481) — a wait needs a
 *     scheduler or an event stream; header GAP list;
 *   · the live (subscribed) sync loop after the historical catch-up
 *     (PU:335-424) — the caller starts the next exchange (header GAP);
 *   · syncInProgress / quit / Close (PS:67, :128-134, :576-598),
 *     singleflight (PS:68, :424), metrics — process plumbing, no protocol
 *     content;
 *   · the intervals store (PU:443-536): row 12 keeps ONE cursor per source,
 *     which replaces Bee's interval set.
 *
 * @file nodus_dht2_pull.c
 */

#include "dht2/nodus_dht2_pull.h"

#include "crypto/utils/qgp_log.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_place.h"
#include "dht2/dht2_record.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "DHT2_PULL"

_Static_assert(NODUS_PK_BYTES == DHT2_PUBKEY_LEN,
               "node identity key is the ML-DSA-87 key the envelope carries");
/* ceil(250 / 8): the p_want bit-vector of a full page (row 12). */
#define BITS_BYTES_MAX ((DHT2_PULL_PAGE_MAX + 7u) / 8u)

/* ══ state ═════════════════════════════════════════════════════════════ */

typedef enum {
    EX_WAIT_HELLO = 0,
    EX_WAIT_OFFER,
    EX_WAIT_DELIVER
} ex_state_t;

/* The puller's exchange with one source (row 12 "one exchange in flight per
 * (puller, source)"). Heap: the offer alone is ~47 KB. */
typedef struct {
    uint8_t         fp[DHT2_FP_LEN];
    ex_state_t      state;
    uint64_t        g;                       /* the source's generation   */
    uint64_t        s;                       /* start index asked for     */
    uint64_t        top;                     /* the offer's top           */
    dht2_p_offer_t *offer;                   /* once the offer arrived    */
    uint8_t         want[BITS_BYTES_MAX];
    size_t          next;                    /* next offer index delivered */
    bool            held[DHT2_PULL_PAGE_MAX];/* held after this page      */
    uint8_t         held_hash[DHT2_PULL_PAGE_MAX][DHT2_HASH_LEN];
} ex_t;

/* The source's memory of the offer it made to one puller (PS:162-181 keeps
 * `offer` in the handler's stack frame for the stream; we keep it per peer). */
typedef struct {
    uint8_t            peer[DHT2_FP_LEN];
    size_t             n;
    dht2_offer_entry_t e[DHT2_PULL_PAGE_MAX];
} offered_t;

struct nodus_dht2_pull {
    nodus_dht2_holder_t      holder;     /* view, store, identity, chain  */
    nodus_dht2_pull_send_fn  send;
    void                    *send_user;
    ex_t                   **ex;
    size_t                   nex;
    offered_t              **off;
    size_t                   noff;
    bool                     have_e;     /* last epoch seen, in memory    */
    uint64_t                 last_e;
    uint8_t                 *buf;        /* outgoing message scratch      */
    uint8_t                 *rec;        /* one envelope scratch          */
};

/* ══ small helpers ═════════════════════════════════════════════════════ */

static int send_msg(nodus_dht2_pull_t *p, const uint8_t peer[DHT2_FP_LEN],
                    nodus_dht2_pull_msg_t kind, const uint8_t *msg, size_t len)
{
    return p->send(p->send_user, peer, kind, msg, len) == 0 ? 0 : -1;
}

static ex_t *ex_find(nodus_dht2_pull_t *p, const uint8_t fp[DHT2_FP_LEN])
{
    size_t i;

    for (i = 0; i < p->nex; i++) {
        if (memcmp(p->ex[i]->fp, fp, DHT2_FP_LEN) == 0) {
            return p->ex[i];
        }
    }
    return NULL;
}

static void ex_drop(nodus_dht2_pull_t *p, ex_t *ex)
{
    size_t i;

    for (i = 0; i < p->nex; i++) {
        if (p->ex[i] == ex) {
            p->ex[i] = p->ex[p->nex - 1];
            p->nex--;
            break;
        }
    }
    free(ex->offer);
    free(ex);
}

static offered_t *off_find(nodus_dht2_pull_t *p, const uint8_t peer[DHT2_FP_LEN])
{
    size_t i;

    for (i = 0; i < p->noff; i++) {
        if (memcmp(p->off[i]->peer, peer, DHT2_FP_LEN) == 0) {
            return p->off[i];
        }
    }
    return NULL;
}

static void off_drop(nodus_dht2_pull_t *p, const uint8_t peer[DHT2_FP_LEN])
{
    size_t i;

    for (i = 0; i < p->noff; i++) {
        if (memcmp(p->off[i]->peer, peer, DHT2_FP_LEN) == 0) {
            free(p->off[i]);
            p->off[i] = p->off[p->noff - 1];
            p->noff--;
            return;
        }
    }
}

/* Keep `o` (heap, filled) as the offer made to o->peer, replacing the
 * previous one. 0 / -1. */
static int off_keep(nodus_dht2_pull_t *p, offered_t *o)
{
    offered_t **grown;

    off_drop(p, o->peer);
    grown = (offered_t **)realloc(p->off, (p->noff + 1) * sizeof(*grown));
    if (grown == NULL) {
        return -1;
    }
    p->off = grown;
    p->off[p->noff++] = o;
    return 0;
}

/* The world of one call; 0 when there is a fresh snapshot AND the sets. */
static int world(nodus_dht2_pull_t *p, uint64_t now_ms, nodus_dht2_world_t *w)
{
    nodus_dht2_holder_world_load(&p->holder, now_ms, w);
    return (w->have_snap && w->sets != NULL && w->ctx.have_sets) ? 0 : -1;
}

/* Is `fp` one of the nearest_R members of `key` in `set`? 1 / 0 / -1. */
static int in_nearest_r(const uint8_t key[DHT2_HASH_LEN],
                        const uint8_t (*set)[DHT2_FP_LEN], size_t n,
                        const uint8_t fp[DHT2_FP_LEN])
{
    size_t idx[DHT2_R];
    int    cnt = dht2_nearest_r(key, set, n, idx), i;

    if (cnt < 0) {
        return -1;
    }
    for (i = 0; i < cnt; i++) {
        if (memcmp(set[idx[i]], fp, DHT2_FP_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

static bool all_zero(const uint8_t *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (b[i] != 0) {
            return false;
        }
    }
    return true;
}

/* ══ setup ═════════════════════════════════════════════════════════════ */

nodus_dht2_pull_t *nodus_dht2_pull_new(nodus_dht2_store_t *store,
                                       const nodus_identity_t *id,
                                       const uint8_t chain[DHT2_CHAIN_LEN],
                                       const nodus_dht2_holder_view_t *view,
                                       nodus_dht2_pull_send_fn send,
                                       void *send_user)
{
    nodus_dht2_pull_t *p;

    if (store == NULL || id == NULL || chain == NULL || view == NULL ||
        send == NULL) {
        return NULL;
    }
    p = (nodus_dht2_pull_t *)calloc(1, sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->buf = (uint8_t *)malloc(NODUS_DHT2_PULL_MSG_MAX);
    p->rec = (uint8_t *)malloc(DHT2_ENVELOPE_MAX);
    if (p->buf == NULL || p->rec == NULL ||
        nodus_dht2_holder_init(&p->holder, store, id, chain, view) != 0) {
        free(p->buf);
        free(p->rec);
        free(p);
        return NULL;
    }
    p->send = send;
    p->send_user = send_user;
    return p;
}

void nodus_dht2_pull_free(nodus_dht2_pull_t *p)
{
    size_t i;

    if (p == NULL) {
        return;
    }
    for (i = 0; i < p->nex; i++) {
        free(p->ex[i]->offer);
        free(p->ex[i]);
    }
    for (i = 0; i < p->noff; i++) {
        free(p->off[i]);
    }
    free(p->ex);
    free(p->off);
    free(p->buf);
    free(p->rec);
    free(p);
}

const uint8_t *nodus_dht2_pull_self_fp(const nodus_dht2_pull_t *p)
{
    return p != NULL ? p->holder.self_fp : NULL;
}

void nodus_dht2_pull_disconnect(nodus_dht2_pull_t *p,
                                const uint8_t peer_fp[DHT2_FP_LEN])
{
    ex_t *ex;

    if (p == NULL || peer_fp == NULL) {
        return;
    }
    /* PS:571-574 `disconnect` (clears the peer's limiter state); PU:226-238
     * `disconnectPeer` (cancels the peer's syncing). */
    ex = ex_find(p, peer_fp);
    if (ex != NULL) {
        ex_drop(p, ex);
    }
    off_drop(p, peer_fp);
}

/* ══ sources (§4.5 iii) ════════════════════════════════════════════════ */

int nodus_dht2_pull_sources(nodus_dht2_pull_t *p, uint64_t now_ms,
                            uint8_t (*out)[DHT2_FP_LEN], size_t cap)
{
    nodus_dht2_world_t w;
    size_t             n = 0, i, k, j;
    int                part;

    if (p == NULL || out == NULL) {
        return -1;
    }
    if (world(p, now_ms, &w) != 0) {
        return -1;
    }
    for (part = 0; part < 2; part++) {
        const uint8_t (*set)[DHT2_FP_LEN] = part == 0 ? w.ctx.s0 : w.ctx.s1;
        size_t cnt = part == 0 ? w.ctx.n0 : w.ctx.n1;

        for (i = 0; i < cnt; i++) {
            bool dup = false;

            if (memcmp(set[i], p->holder.self_fp, DHT2_FP_LEN) == 0) {
                continue;
            }
            /* sorted insert, each fp once: a stable total key */
            for (k = 0; k < n; k++) {
                int c = memcmp(set[i], out[k], DHT2_FP_LEN);

                if (c == 0) {
                    dup = true;
                    break;
                }
                if (c < 0) {
                    break;
                }
            }
            if (dup) {
                continue;
            }
            if (n >= cap) {
                return -1;
            }
            for (j = n; j > k; j--) {
                memcpy(out[j], out[j - 1], DHT2_FP_LEN);
            }
            memcpy(out[k], set[i], DHT2_FP_LEN);
            n++;
        }
    }
    return (int)n;
}

/* ══ puller ════════════════════════════════════════════════════════════ */

static int abort_ex(nodus_dht2_pull_t *p, ex_t *ex, const char *why)
{
    QGP_LOG_WARN(LOG_TAG, "exchange aborted: %s", why);
    ex_drop(p, ex);
    return NODUS_DHT2_PULL_ABORTED;
}

int nodus_dht2_pull_start(nodus_dht2_pull_t *p, uint64_t now_ms,
                          const uint8_t source_fp[DHT2_FP_LEN])
{
    dht2_p_hello_t m;
    ex_t          *ex, **grown;
    size_t         len = 0;
    uint64_t       top;

    (void)now_ms;
    if (p == NULL || source_fp == NULL ||
        memcmp(source_fp, p->holder.self_fp, DHT2_FP_LEN) == 0) {
        return NODUS_DHT2_PULL_ERR;
    }
    if (ex_find(p, source_fp) != NULL) {
        return NODUS_DHT2_PULL_BUSY;      /* row 12: one exchange per pair */
    }
    /* PS:529 `Syn`: Bee's request is an empty message; the codec has only
     * p_hello {g, top}, so the request carries this node's own {g, top}
     * (GAP reading; the source ignores its content). */
    if (nodus_dht2_store_top(p->holder.store, &top) != 0) {
        return NODUS_DHT2_PULL_ERR;
    }
    m.g = nodus_dht2_store_generation(p->holder.store);
    m.top = top;
    if (dht2_p_hello_encode(&m, p->buf, NODUS_DHT2_PULL_MSG_MAX, &len)
        != DHT2_OK) {
        return NODUS_DHT2_PULL_ERR;
    }
    ex = (ex_t *)calloc(1, sizeof(*ex));
    grown = (ex_t **)realloc(p->ex, (p->nex + 1) * sizeof(*grown));
    if (ex == NULL || grown == NULL) {
        free(ex);
        if (grown != NULL) {
            p->ex = grown;
        }
        return NODUS_DHT2_PULL_ERR;
    }
    p->ex = grown;
    memcpy(ex->fp, source_fp, DHT2_FP_LEN);
    ex->state = EX_WAIT_HELLO;
    p->ex[p->nex++] = ex;
    if (send_msg(p, source_fp, NODUS_DHT2_PULL_HELLO, p->buf, len) != 0) {
        ex_drop(p, ex);
        return NODUS_DHT2_PULL_ERR;
    }
    return NODUS_DHT2_PULL_STARTED;
}

/* A page is done: persist the cursor (PU:400-406 `top >= start` →
 * addPeerInterval, start = top + 1; row 12: ONLY here, after every wanted
 * entry was admitted or definitively refused), then — for a non-empty page —
 * send the ONE signed pull-receipt (row 12 "Handover acknowledgement"). */
static int page_done(nodus_dht2_pull_t *p, ex_t *ex)
{
    size_t               n = ex->offer != NULL ? ex->offer->e_count : 0, i, k;
    dht2_pull_receipt_t *r;
    size_t               plen = 0, slen = 0;

    if (ex->top >= ex->s) {
        if (nodus_dht2_store_pull_set(p->holder.store, ex->fp, ex->g,
                                      ex->top + 1) != 0) {
            return abort_ex(p, ex, "cursor not persisted (store fault)");
        }
    }
    if (n == 0) {
        ex_drop(p, ex);          /* PS:253-255: an empty interval ends here */
        return NODUS_DHT2_PULL_DONE;
    }
    r = (dht2_pull_receipt_t *)calloc(1, sizeof(*r));
    if (r == NULL) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: allocation failed");
        ex_drop(p, ex);
        return NODUS_DHT2_PULL_DONE;
    }
    memcpy(r->pf, p->holder.self_fp, DHT2_FP_LEN);
    memcpy(r->sf, ex->fp, DHT2_FP_LEN);
    memcpy(r->c, p->holder.chain, DHT2_CHAIN_LEN);
    r->g = ex->g;
    r->s = ex->s;
    r->top = ex->top;
    for (i = 0, k = 0; i < n; i++) {
        if (ex->held[i]) {
            memcpy(r->e[k].a, ex->offer->e[i].a, DHT2_HASH_LEN);
            memcpy(r->e[k].h, ex->held_hash[i], DHT2_HASH_LEN);
            k++;
        }
    }
    r->e_count = k;
    /* Decision 2026-10-23 addendum: dht2_env_seal under domain
     * `nodus.dht.answer.v1`, payload type `/nodus/dht/pull-receipt/v1`. */
    if (dht2_pull_receipt_encode(r, p->rec, DHT2_ENVELOPE_MAX, &plen)
            != DHT2_OK ||
        dht2_env_seal(DHT2_DOMAIN_ANSWER,
                      (const uint8_t *)DHT2_PT_PULL_RECEIPT,
                      strlen(DHT2_PT_PULL_RECEIPT), p->rec, plen,
                      p->holder.id->sk.bytes, p->holder.id->pk.bytes, p->buf,
                      NODUS_DHT2_PULL_MSG_MAX, &slen) != DHT2_OK ||
        send_msg(p, ex->fp, NODUS_DHT2_PULL_RECEIPT, p->buf, slen) != 0) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt not sent");
    }
    free(r);
    ex_drop(p, ex);
    return NODUS_DHT2_PULL_DONE;
}

/* First set bit of ex->want at an index >= from, or n. */
static size_t next_wanted(const ex_t *ex, size_t from)
{
    size_t n = ex->offer->e_count, i;

    for (i = from; i < n; i++) {
        if (dht2_bits_get(ex->want, i)) {
            return i;
        }
    }
    return n;
}

static int on_hello(nodus_dht2_pull_t *p, ex_t *ex, const uint8_t *msg,
                    size_t len)
{
    dht2_p_hello_t h;
    dht2_p_get_t   gm;
    bool           found = false;
    uint64_t       sg = 0, cursor = 0;
    size_t         olen = 0;

    if (dht2_p_hello_decode(msg, len, &h) != DHT2_OK) {
        return abort_ex(p, ex, "p_hello undecodable");
    }
    if (nodus_dht2_store_pull_get(p->holder.store, ex->fp, &found, &sg,
                                  &cursor) != 0) {
        return abort_ex(p, ex, "cursor not readable (store fault)");
    }
    /* PU:266-283 syncPeer: the peer's epoch (= its store generation g) is
     * compared with the stored one; a change resets the past synced
     * intervals (= the cursor to 0) and stores the new epoch. §4.5 (iii). */
    if (!found || sg != h.g) {
        cursor = 0;
        if (nodus_dht2_store_pull_set(p->holder.store, ex->fp, h.g, 0) != 0) {
            return abort_ex(p, ex, "cursor not persisted (store fault)");
        }
    }
    /* PU:357-361 historical sync: caught up when start > the peer's cursor
     * (here: the hello's top). */
    if (cursor > h.top) {
        ex_drop(p, ex);
        return NODUS_DHT2_PULL_DONE;
    }
    ex->g = h.g;
    ex->s = cursor;
    gm.g = h.g;
    gm.s = cursor;
    if (dht2_p_get_encode(&gm, p->buf, NODUS_DHT2_PULL_MSG_MAX, &olen)
            != DHT2_OK ||
        send_msg(p, ex->fp, NODUS_DHT2_PULL_GET, p->buf, olen) != 0) {
        return abort_ex(p, ex, "p_get not sent");
    }
    ex->state = EX_WAIT_OFFER;        /* PS:242 write the Get */
    return NODUS_DHT2_PULL_CONTINUE;
}

static int on_offer(nodus_dht2_pull_t *p, uint64_t now_ms, ex_t *ex,
                    const uint8_t *msg, size_t len)
{
    dht2_p_offer_t    *o;
    nodus_dht2_world_t w;
    dht2_p_want_t      wm;
    size_t             i, n, wl = 0;
    uint8_t            hash[DHT2_HASH_LEN];

    o = (dht2_p_offer_t *)calloc(1, sizeof(*o));
    if (o == NULL) {
        return abort_ex(p, ex, "allocation failed");
    }
    ex->offer = o;                    /* freed by ex_drop on every path */
    if (dht2_p_offer_decode(msg, len, o) != DHT2_OK) {
        return abort_ex(p, ex, "p_offer undecodable");
    }
    /* row 12: "a `g` change ... aborts it". */
    if (o->g != ex->g) {
        return abort_ex(p, ex, "the source's generation changed");
    }
    /* PU:374-379 `top == math.MaxUint64` → quit. Bound here: no index above
     * INT64_MAX is ever handed out (store scan), and top + 1 is persisted. */
    if (o->top >= (uint64_t)INT64_MAX) {
        return abort_ex(p, ex, "offer top out of range");
    }
    ex->top = o->top;
    n = o->e_count;
    /* PS:253-255: an empty interval returns the offer's topmost; nothing is
     * wanted and the exchange is over (PS:179-181 on the source). */
    if (n == 0) {
        return page_done(p, ex);
    }
    if (world(p, now_ms, &w) != 0) {
        return abort_ex(p, ex, "no snapshot / sets (cursor kept)");
    }
    memset(ex->want, 0, sizeof(ex->want));
    for (i = 0; i < n; i++) {
        size_t   hl = 0;
        int      resp, rc;

        /* PS:284-288: a zero address is skipped. */
        if (all_zero(o->e[i].a, DHT2_HASH_LEN)) {
            continue;
        }
        /* PS:290 IsWithinStorageRadius → §4.5 (ii): the placement key puts
         * this node in nearest_R(S(H)). */
        resp = in_nearest_r(o->e[i].p, w.ctx.s0, w.ctx.n0,
                            p->holder.self_fp);
        if (resp < 0) {
            return abort_ex(p, ex, "placement over a bad set (cursor kept)");
        }
        if (resp == 0) {
            continue;
        }
        /* PS:291-296 ReserveHas → "that it lacks or holds a different
         * version of" (§4.5 ii). */
        rc = nodus_dht2_store_get(p->holder.store, &w.ctx, o->e[i].a, p->rec,
                                  DHT2_ENVELOPE_MAX, &hl, hash);
        if (rc == NODUS_DHT2_GET_HELD &&
            memcmp(hash, o->e[i].h, DHT2_HASH_LEN) == 0) {
            ex->held[i] = true;       /* held: nothing to fetch, receipted */
            memcpy(ex->held_hash[i], hash, DHT2_HASH_LEN);
            continue;
        }
        if (rc != NODUS_DHT2_GET_HELD && rc != NODUS_DHT2_GET_NOT_HELD) {
            return abort_ex(p, ex, "local read failed (cursor kept)");
        }
        dht2_bits_set(ex->want, i);   /* PS:301 bv.Set(i) */
    }
    /* PS:306-310 write the Want; row 12: exactly ceil(n/8) bytes. */
    wm.b = ex->want;
    wm.b_len = dht2_bits_len(n);
    if (dht2_p_want_encode(&wm, n, p->buf, NODUS_DHT2_PULL_MSG_MAX, &wl)
            != DHT2_OK ||
        send_msg(p, ex->fp, NODUS_DHT2_PULL_WANT, p->buf, wl) != 0) {
        return abort_ex(p, ex, "p_want not sent");
    }
    ex->next = next_wanted(ex, 0);
    ex->state = EX_WAIT_DELIVER;
    if (ex->next >= n) {
        return page_done(p, ex);      /* PS:312 `for ; ctr > 0` runs 0 times */
    }
    return NODUS_DHT2_PULL_CONTINUE;
}

static int on_deliver(nodus_dht2_pull_t *p, uint64_t now_ms, ex_t *ex,
                      const uint8_t *msg, size_t len)
{
    dht2_p_deliver_t   d;
    nodus_dht2_world_t w;
    const dht2_offer_entry_t *e;
    size_t             n = ex->offer->e_count;

    if (dht2_p_deliver_decode(msg, len, &d) != DHT2_OK) {
        return abort_ex(p, ex, "p_deliver undecodable");
    }
    /* PS:337-346 ErrUnsolicitedChunk. Row 12 is stricter than Bee's map:
     * "exactly one per set bit, ascending i". */
    if (d.i != (uint64_t)ex->next) {
        return abort_ex(p, ex, "delivery out of order / unsolicited");
    }
    e = &ex->offer->e[ex->next];
    if (!d.has_v) {
        /* PS:321-326: a zero-address delivery ("gone") is consumed; nothing
         * to admit. */
    } else {
        dht2_record_t *rec = (dht2_record_t *)malloc(sizeof(*rec));
        uint8_t        pk[DHT2_HASH_LEN];
        bool           source_fault = false;

        if (rec == NULL) {
            return abort_ex(p, ex, "allocation failed (cursor kept)");
        }
        /* PS:364-370 validity check of the chunk → row 12: "the puller
         * recomputes address and placement key from v, a mismatch with e[i]
         * = source fault (logged, nothing stored)". */
        if (dht2_record_parse(d.v, d.v_len, p->holder.chain, e->a, rec)
                != DHT2_OK ||
            dht2_record_placement_key(rec, pk) != DHT2_OK ||
            memcmp(pk, e->p, DHT2_HASH_LEN) != 0) {
            source_fault = true;
        }
        free(rec);
        if (source_fault) {
            QGP_LOG_WARN(LOG_TAG, "source fault: delivery %zu does not match "
                                  "its offer (nothing stored)", ex->next);
        } else {
            nodus_dht2_put_t res;
            int              rc;

            if (world(p, now_ms, &w) != 0) {
                return abort_ex(p, ex, "no snapshot / sets (cursor kept)");
            }
            /* PS:379-396 ReservePutter().Put — the ONE admission path (§4.1),
             * with the offered address as the expected one. */
            memset(&res, 0, sizeof(res));
            rc = nodus_dht2_store_put(p->holder.store, &w.ctx, d.v, d.v_len,
                                      e->a, &res);
            if (rc == 0) {
                /* stored / equal / the held version won: PS:385-390
                 * ErrOverwriteNewerChunk is not an error ("same or newer"). */
                ex->held[ex->next] = true;
                memcpy(ex->held_hash[ex->next], res.hash, DHT2_HASH_LEN);
            } else if (rc == DHT2_E_NOT_CAUGHT_UP || rc == DHT2_E_HOLDER_FAULT ||
                       rc < 0) {
                /* PS:391-393 any other Put error returns: a transient local
                 * failure keeps the cursor (row 12). */
                return abort_ex(p, ex, "admission failed locally (cursor kept)");
            } else {
                /* row 12: "definitively refused" (codes 1-13, 18). */
                QGP_LOG_DEBUG(LOG_TAG, "delivery %zu refused: code %d",
                              ex->next, rc);
            }
        }
    }
    ex->next = next_wanted(ex, ex->next + 1);
    if (ex->next >= n) {
        return page_done(p, ex);
    }
    return NODUS_DHT2_PULL_CONTINUE;
}

int nodus_dht2_pull_on_reply(nodus_dht2_pull_t *p, uint64_t now_ms,
                             const uint8_t source_fp[DHT2_FP_LEN],
                             nodus_dht2_pull_msg_t kind, const uint8_t *msg,
                             size_t len)
{
    ex_t *ex;

    if (p == NULL || source_fp == NULL || (msg == NULL && len != 0)) {
        return NODUS_DHT2_PULL_ABORTED;
    }
    ex = ex_find(p, source_fp);
    if (ex == NULL) {
        QGP_LOG_WARN(LOG_TAG, "reply from a peer with no exchange");
        return NODUS_DHT2_PULL_ABORTED;
    }
    if (kind == NODUS_DHT2_PULL_HELLO && ex->state == EX_WAIT_HELLO) {
        return on_hello(p, ex, msg, len);
    }
    if (kind == NODUS_DHT2_PULL_OFFER && ex->state == EX_WAIT_OFFER) {
        return on_offer(p, now_ms, ex, msg, len);
    }
    if (kind == NODUS_DHT2_PULL_DELIVER && ex->state == EX_WAIT_DELIVER) {
        return on_deliver(p, now_ms, ex, msg, len);
    }
    return abort_ex(p, ex, "reply of the wrong kind for the exchange state");
}

/* ══ responsibility growth (PU:178-189) ════════════════════════════════ */

/* PU:178-189: "if newRadius < prevRadius → reset all intervals" — the
 * responsibility GREW. Translated exactly for XOR placement: this node is
 * responsible for key K under set S iff fewer than R members of S (other
 * than itself) are nearer K than it is. A member m is nearer K than self iff
 * K agrees with m at the highest bit where m and self differ. So K matters
 * only through one bit per such position, and growth = a K exists with
 * count_X(K) < R <= count_Y(K) (X = S(H), Y = S(H − E)). The positions are
 * independent, so a DP over them (state: count_X below R, value: the largest
 * count_Y reachable, capped at R) decides it. Pure function of its inputs. */
static bool responsibility_grew(const uint8_t self[DHT2_FP_LEN],
                                const uint8_t (*x)[DHT2_FP_LEN], size_t nx,
                                const uint8_t (*y)[DHT2_FP_LEN], size_t ny)
{
    static const unsigned R = DHT2_R;
    uint16_t xc[8 * DHT2_FP_LEN][2], yc[8 * DHT2_FP_LEN][2];
    int      best[DHT2_R], nb[DHT2_R];
    bool     in_x = false, in_y = false;
    size_t   i, pos;
    int      v;
    unsigned cx;

    memset(xc, 0, sizeof(xc));
    memset(yc, 0, sizeof(yc));
    for (i = 0; i < nx + ny; i++) {
        const uint8_t *m = i < nx ? x[i] : y[i - nx];
        uint16_t (*c)[2] = i < nx ? xc : yc;
        size_t   b;

        if (memcmp(m, self, DHT2_FP_LEN) == 0) {
            if (i < nx) {
                in_x = true;
            } else {
                in_y = true;
            }
            continue;
        }
        for (b = 0; b < DHT2_FP_LEN && m[b] == self[b]; b++) {
        }
        if (b == DHT2_FP_LEN) {
            continue;
        }
        {
            uint8_t d = (uint8_t)(m[b] ^ self[b]);
            unsigned bit = 0;

            while ((d & (0x80u >> bit)) == 0) {
                bit++;
            }
            c[b * 8 + bit][(m[b] >> (7 - bit)) & 1]++;
        }
    }
    if (!in_x) {
        return false;                  /* not responsible under S(H)      */
    }
    if (!in_y) {
        return true;                   /* K = self: responsible now, not before */
    }
    for (cx = 0; cx < R; cx++) {
        best[cx] = -1;
    }
    best[0] = 0;
    for (pos = 0; pos < 8 * DHT2_FP_LEN; pos++) {
        for (cx = 0; cx < R; cx++) {
            nb[cx] = -1;
        }
        for (cx = 0; cx < R; cx++) {
            if (best[cx] < 0) {
                continue;
            }
            for (v = 0; v < 2; v++) {
                unsigned ncx = cx + xc[pos][v];
                int      ncy = best[cx] + (int)yc[pos][v];

                if (ncx >= R) {
                    continue;
                }
                if (ncy > (int)R) {
                    ncy = (int)R;
                }
                if (ncy > nb[ncx]) {
                    nb[ncx] = ncy;
                }
            }
        }
        memcpy(best, nb, sizeof(best));
    }
    for (cx = 0; cx < R; cx++) {
        if (best[cx] >= (int)R) {
            return true;
        }
    }
    return false;
}

int nodus_dht2_pull_epoch_check(nodus_dht2_pull_t *p, uint64_t now_ms)
{
    nodus_dht2_world_t       w;
    nodus_dht2_perm_entry_t *page;
    uint64_t                 from = 0, next = 0;
    size_t                   cnt, i;
    int                      rc = 0;

    if (p == NULL) {
        return -1;
    }
    if (world(p, now_ms, &w) != 0) {
        return 1;
    }
    if (p->have_e && p->last_e == w.sets->e) {
        return 0;
    }
    if (responsibility_grew(p->holder.self_fp, w.ctx.s0, w.ctx.n0, w.ctx.s1,
                            w.ctx.n1)) {
        /* PU:181-186: disconnect every peer, reset every interval. */
        while (p->nex > 0) {
            ex_drop(p, p->ex[0]);
        }
        if (nodus_dht2_store_pull_reset(p->holder.store) != 0) {
            return -1;
        }
    }
    /* §4.5 (v): permanent records this node no longer holds. */
    page = (nodus_dht2_perm_entry_t *)malloc(DHT2_PULL_PAGE_MAX *
                                             sizeof(*page));
    if (page == NULL) {
        return -1;
    }
    for (;;) {
        if (nodus_dht2_store_permanent_scan(p->holder.store, from, page,
                                            DHT2_PULL_PAGE_MAX, &cnt, &next)
            != 0) {
            rc = -1;
            break;
        }
        for (i = 0; i < cnt && rc == 0; i++) {
            int el = dht2_eligible(page[i].placement, w.ctx.s0, w.ctx.n0,
                                   w.ctx.s1, w.ctx.n1, p->holder.self_fp);

            if (el < 0 ||
                (el == 0 &&
                 nodus_dht2_store_handover_set(p->holder.store,
                                               page[i].address, true, NULL)
                     != 0)) {
                rc = -1;
            }
        }
        if (rc != 0 || cnt < DHT2_PULL_PAGE_MAX) {
            break;
        }
        from = next;
    }
    free(page);
    if (rc == 0) {
        p->have_e = true;
        p->last_e = w.sets->e;
    }
    return rc;
}

/* ══ source ════════════════════════════════════════════════════════════ */

/* PS:541-568 cursorHandler: answer with the store's generation and top. */
static int serve_hello(nodus_dht2_pull_t *p, const uint8_t peer[DHT2_FP_LEN],
                       const uint8_t *msg, size_t len)
{
    dht2_p_hello_t req, rep;
    uint64_t       top;
    size_t         olen = 0;

    if (dht2_p_hello_decode(msg, len, &req) != DHT2_OK) {   /* PS:553 */
        QGP_LOG_WARN(LOG_TAG, "p_hello undecodable");
        return -1;
    }
    if (nodus_dht2_store_top(p->holder.store, &top) != 0) {
        return -1;
    }
    rep.g = nodus_dht2_store_generation(p->holder.store);
    rep.top = top;
    if (dht2_p_hello_encode(&rep, p->buf, NODUS_DHT2_PULL_MSG_MAX, &olen)
        != DHT2_OK) {
        return -1;
    }
    return send_msg(p, peer, NODUS_DHT2_PULL_HELLO, p->buf, olen);
}

/* PS:127-181 handler up to the offer; PS:400-411 makeOffer. */
static int serve_get(nodus_dht2_pull_t *p, uint64_t now_ms,
                     const uint8_t peer[DHT2_FP_LEN], const uint8_t *msg,
                     size_t len)
{
    dht2_p_get_t              gm;
    nodus_dht2_world_t        w;
    nodus_dht2_scan_entry_t  *ents = NULL;
    dht2_p_offer_t           *o = NULL;
    offered_t                *keep = NULL;
    size_t                    cnt = 0, i, olen = 0;
    uint64_t                  top = 0;
    int                       rc = -1;

    if (dht2_p_get_decode(msg, len, &gm) != DHT2_OK) {      /* PS:158 */
        QGP_LOG_WARN(LOG_TAG, "p_get undecodable");
        return -1;
    }
    /* row 12: a `g` change aborts the exchange. */
    if (gm.g != nodus_dht2_store_generation(p->holder.store)) {
        QGP_LOG_WARN(LOG_TAG, "p_get for another generation: dropped");
        off_drop(p, peer);
        return -1;
    }
    if (world(p, now_ms, &w) != 0) {
        QGP_LOG_WARN(LOG_TAG, "p_get: no snapshot / sets: dropped");
        return -1;
    }
    ents = (nodus_dht2_scan_entry_t *)malloc(DHT2_PULL_PAGE_MAX *
                                             sizeof(*ents));
    o = (dht2_p_offer_t *)calloc(1, sizeof(*o));
    keep = (offered_t *)calloc(1, sizeof(*keep));
    if (ents == NULL || o == NULL || keep == NULL) {
        goto done;
    }
    /* PS:424-481 collectAddrs, translated to ONE scan (header GAP: no
     * pageTimeout wait): entries with index >= s, ascending, <= 250
     * (DefaultMaxPage PS:48); top = the highest index scanned (PS:452-454),
     * the store's top for an empty interval (row 12). */
    if (nodus_dht2_store_scan(p->holder.store, &w.ctx, gm.s, ents,
                              DHT2_PULL_PAGE_MAX, &cnt, &top) != 0) {
        goto done;
    }
    for (i = 0; i < cnt; i++) {
        /* row 12: "The source offers an entry only to a puller that is in
         * eligible(p)". */
        int el = dht2_eligible(ents[i].placement, w.ctx.s0, w.ctx.n0,
                               w.ctx.s1, w.ctx.n1, peer);

        if (el < 0) {
            goto done;
        }
        if (el == 0) {
            continue;
        }
        memcpy(o->e[o->e_count].a, ents[i].address, DHT2_HASH_LEN);
        memcpy(o->e[o->e_count].h, ents[i].hash, DHT2_HASH_LEN);
        memcpy(o->e[o->e_count].p, ents[i].placement, DHT2_HASH_LEN);
        o->e_count++;
    }
    o->g = nodus_dht2_store_generation(p->holder.store);
    o->top = top;
    if (dht2_p_offer_encode(o, p->buf, NODUS_DHT2_PULL_MSG_MAX, &olen)
        != DHT2_OK) {
        goto done;
    }
    /* PS:173-181: write the offer; an empty one ends the exchange. */
    if (o->e_count == 0) {
        off_drop(p, peer);
    } else {
        memcpy(keep->peer, peer, DHT2_FP_LEN);
        keep->n = o->e_count;
        memcpy(keep->e, o->e, o->e_count * sizeof(keep->e[0]));
        if (off_keep(p, keep) != 0) {
            goto done;
        }
        keep = NULL;                 /* owned by p now */
    }
    rc = send_msg(p, peer, NODUS_DHT2_PULL_OFFER, p->buf, olen);
done:
    free(ents);
    free(o);
    free(keep);
    return rc;
}

/* PS:186-221 handler after the offer; PS:484-511 processWant. */
static int serve_want(nodus_dht2_pull_t *p, uint64_t now_ms,
                      const uint8_t peer[DHT2_FP_LEN], const uint8_t *msg,
                      size_t len)
{
    offered_t         *of = off_find(p, peer);
    dht2_p_want_t      wm;
    nodus_dht2_world_t w;
    size_t             i;
    int                rc = 0;

    if (of == NULL) {
        QGP_LOG_WARN(LOG_TAG, "p_want without an offer: dropped");
        return -1;
    }
    /* PS:485 bitvector.NewFromBytes(w.BitVector, len(o.Chunks)); row 12:
     * exactly ceil(n/8) bytes, any other length aborts the exchange. */
    if (dht2_p_want_decode(msg, len, of->n, &wm) != DHT2_OK) {
        QGP_LOG_WARN(LOG_TAG, "p_want of a wrong length: exchange aborted");
        off_drop(p, peer);
        return -1;
    }
    nodus_dht2_holder_world_load(&p->holder, now_ms, &w);
    for (i = 0; i < of->n; i++) {
        dht2_p_deliver_t d;
        uint8_t          hash[DHT2_HASH_LEN];
        size_t           vl = 0, ml = 0;
        int              g;

        if (!dht2_bits_get(wm.b, i)) {                      /* PS:496 */
            continue;
        }
        /* PS:497-505 ReserveGet: the entry NOW held (it may differ from the
         * offered hash — Select decides); any failure is the zero-address
         * chunk, i.e. `v` null (row 12 "gone"). */
        g = nodus_dht2_store_get(p->holder.store, &w.ctx, of->e[i].a, p->rec,
                                 DHT2_ENVELOPE_MAX, &vl, hash);
        d.i = i;
        d.has_v = g == NODUS_DHT2_GET_HELD;
        d.v = d.has_v ? p->rec : NULL;
        d.v_len = d.has_v ? vl : 0;
        if (g != NODUS_DHT2_GET_HELD && g != NODUS_DHT2_GET_NOT_HELD) {
            QGP_LOG_WARN(LOG_TAG, "delivery %zu: local read failed (%d): "
                                  "sent as gone", i, g);
        }
        if (dht2_p_deliver_encode(&d, p->buf, NODUS_DHT2_PULL_MSG_MAX, &ml)
                != DHT2_OK ||
            send_msg(p, peer, NODUS_DHT2_PULL_DELIVER, p->buf, ml) != 0) {
            rc = -1;                 /* PS:214-216 write failure ends it */
            break;
        }
    }
    off_drop(p, peer);
    return rc;
}

/* Row 12 "Handover acknowledgement": a valid pull-receipt from a member of
 * the record's nearest_R(S(H)) retires its hand-over obligation. */
static int serve_receipt(nodus_dht2_pull_t *p, uint64_t now_ms,
                         const uint8_t peer[DHT2_FP_LEN], const uint8_t *msg,
                         size_t len)
{
    dht2_env_t           env;
    dht2_pull_receipt_t *r;
    nodus_dht2_world_t   w;
    size_t               i;
    int                  rc = -1;

    if (dht2_env_decode(msg, len, DHT2_ENVELOPE_MAX, &env) != DHT2_OK) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: envelope undecodable");
        return -1;
    }
    /* Decision 2026-10-23 addendum: the verifier checks the payload type as
     * well as the domain. */
    if (env.payload_type_len != strlen(DHT2_PT_PULL_RECEIPT) ||
        memcmp(env.payload_type, DHT2_PT_PULL_RECEIPT, env.payload_type_len)
            != 0) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: wrong payload type");
        return -1;
    }
    if (dht2_env_verify(&env, DHT2_DOMAIN_ANSWER) != DHT2_OK) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: signature / domain refused");
        return -1;
    }
    r = (dht2_pull_receipt_t *)malloc(sizeof(*r));
    if (r == NULL) {
        return -1;
    }
    if (dht2_pull_receipt_decode(env.payload, env.payload_len, r) != DHT2_OK ||
        memcmp(r->pf, env.fp, DHT2_FP_LEN) != 0 ||
        memcmp(r->pf, peer, DHT2_FP_LEN) != 0 ||
        memcmp(r->sf, p->holder.self_fp, DHT2_FP_LEN) != 0 ||
        memcmp(r->c, p->holder.chain, DHT2_CHAIN_LEN) != 0 ||
        r->g != nodus_dht2_store_generation(p->holder.store)) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: not for this source / chain / "
                              "generation, or not from its signer");
        goto done;
    }
    if (world(p, now_ms, &w) != 0) {
        QGP_LOG_WARN(LOG_TAG, "pull-receipt: no sets: dropped");
        goto done;
    }
    rc = 0;
    for (i = 0; i < r->e_count; i++) {
        bool    found = false, pending = false;
        uint8_t held[DHT2_HASH_LEN], place[DHT2_HASH_LEN];
        int     member;

        if (nodus_dht2_store_handover_info(p->holder.store, r->e[i].a, &found,
                                           &pending, held, place) != 0) {
            rc = -1;
            break;
        }
        /* The source can verify "the same version" (the receipt names the
         * hash it holds); "or newer" it cannot (header GAP). */
        if (!found || !pending ||
            memcmp(held, r->e[i].h, DHT2_HASH_LEN) != 0) {
            continue;
        }
        member = in_nearest_r(place, w.ctx.s0, w.ctx.n0, r->pf);
        if (member < 0) {
            rc = -1;
            break;
        }
        if (member == 1 &&
            nodus_dht2_store_handover_set(p->holder.store, r->e[i].a, false,
                                          NULL) != 0) {
            rc = -1;
            break;
        }
    }
done:
    free(r);
    return rc;
}

int nodus_dht2_pull_serve(nodus_dht2_pull_t *p, uint64_t now_ms,
                          const uint8_t peer_fp[DHT2_FP_LEN],
                          nodus_dht2_pull_msg_t kind, const uint8_t *msg,
                          size_t len)
{
    if (p == NULL || peer_fp == NULL || (msg == NULL && len != 0)) {
        return -1;
    }
    switch (kind) {
    case NODUS_DHT2_PULL_HELLO:
        return serve_hello(p, peer_fp, msg, len);
    case NODUS_DHT2_PULL_GET:
        return serve_get(p, now_ms, peer_fp, msg, len);
    case NODUS_DHT2_PULL_WANT:
        return serve_want(p, now_ms, peer_fp, msg, len);
    case NODUS_DHT2_PULL_RECEIPT:
        return serve_receipt(p, now_ms, peer_fp, msg, len);
    default:
        QGP_LOG_WARN(LOG_TAG, "a request of a reply kind: dropped");
        return -1;
    }
}
