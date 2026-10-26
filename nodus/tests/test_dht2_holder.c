/**
 * Nodus — DHT v2 package 6a: the holder service
 * (nodus/src/dht2/nodus_dht2_holder.{c,h}).
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §4.4,
 * §13 rows 7, 14, 18, 20, 23; decisions/2026-10-26-dht-v2-no-single-node-
 * write-refusal.md.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false:
 *   · every answer is ONE RFC 0002 envelope signed by the node identity:
 *     it opens under the payload type of its kind (/nodus/dht/answer/v1 for
 *     get and LIST, /nodus/dht/receipt/v1 for put, /nodus/dht/refusal/v1
 *     for a refusal), verifies under domain nodus.dht.answer.v1 and NOT
 *     under another domain, carries the node's fp, and its payload says
 *     q = the request's nonce, n = the node's fp, c = the chain, h / t =
 *     the snapshot's (none in a refusal);
 *   · get: a held key answers its hash, an unheld key null, in request
 *     order; put: the receipt names the stored hash (the same hash a later
 *     get returns), an undecodable envelope is code 2 with an all-zero key
 *     and a receipt never carries null;
 *   · a malformed request gets NO answer: bytes that are not a request, a
 *     truncated request, a get sent as put (and the reverse), a LIST
 *     envelope that does not decode;
 *   · LIST: the owner's request lists the entries (writer fp, hash, and r.v
 *     = SHA3-512 of the listed hashes, q = the request nonce); a request
 *     signed by another key for that inbox is r.v = 17 with nothing
 *     listed; a LIST of another chain, and one with a flipped payload byte,
 *     get no answer;
 *   · consensus_up false, and no snapshot at all, answer the refusal 15 for
 *     get, put and list; a full signing queue (64 jobs) answers the refusal
 *     14, and a slot given back lets the next call through;
 *   · decision 2026-10-26-dht-v2-no-single-node-write-refusal.md: with
 *     |S(H)| = 1 a put is NOT refused — it is answered with a receipt naming
 *     the stored hash, and a later get returns that same hash;
 *   · a name FAULT is code 16 for that key (nothing stored), is asked once,
 *     and the NEXT name request is possible (the fault was consumed): the
 *     same put then succeeds; a PENDING name answer is also 16 for the
 *     call, never "unnamed";
 *   · fix round — an ABANDONED name fault (writer A never asks again) blocks
 *     writer B only until one poll period has passed, with a fake that
 *     keeps the real view's single fault slot per fp; a snapshot of another
 *     chain is refused (15, no h / t) for get, put, owner LIST and
 *     not-owner LIST alike; a GET of a held inbox-control record is per-key
 *     17; an envelope above 262,144 B inside a put is per-key code 1 with a
 *     zero key and its sibling is stored under its address.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no clock. Keys come from fixed seeds (qgp_dsa87_keypair_derand); signing
 * is HEDGED, so no signature byte is pinned — signatures are verified,
 * never compared to a constant. Chain time is injected (T0). Safe under
 * `ctest -j`: every run uses its own mkdtemp directory.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success: the temp directory and its .db files are removed. A
 * crash mid-run leaves /tmp/test_dht2_holder_XXXXXX.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The view is injected: nodus_dht2_holder_view_wview() (the three
 *     trampolines onto the package-4 view) is not exercised — that needs a
 *     witness socket (test_dht2_ipc covers the view itself). The PENDING /
 *     FAULT fakes follow the documented behaviour of the view, they are not
 *     the view.
 *  2. The holder sets are tiny (1 or 3 members): with ≤ 4 members every
 *     member is eligible for every key, so eligibility itself is not
 *     exercised here (package 1 / 5).
 *  3. Answers are checked structurally and by signature; whether a CLIENT
 *     accepts them (§4.4 client rules) is package 8's.
 *  4. Hedged signatures differ from run to run; the test never depends on
 *     two answers being byte-equal.
 * @file test_dht2_holder.c
 */

#include "dht2/nodus_dht2_holder.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_record.h"
#include "dht2/dht2_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "TEST_DHT2_HOLDER"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                              \
    if (cond) { g_pass++; }                                                \
    else { g_fail++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s:%d: %s",              \
                                   __FILE__, __LINE__, (msg)); }           \
} while (0)

#define T0      1792368000ull           /* 2026-10-19T00:00:00Z */

/* ══ fixture ═══════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[DHT2_PUBKEY_LEN];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[DHT2_FP_LEN];
} tkey_t;

typedef struct {
    uint8_t b[16384];
    size_t  n;
} env_t;

static uint8_t g_chain[DHT2_CHAIN_LEN];
static uint8_t g_other_chain[DHT2_CHAIN_LEN];
static char    g_dir[64];
static int     g_db_n = 0;

static int keygen(tkey_t *k, uint8_t b0)
{
    uint8_t seed[32];

    memset(seed, 0x5C, sizeof(seed));
    seed[0] = b0;
    if (qgp_dsa87_keypair_derand(k->pk, k->sk, seed) != 0 ||
        dht2_fp(k->pk, k->fp) != 0) {
        return -1;
    }
    return 0;
}

/* ── the injected view ──────────────────────────────────────────────── */

typedef struct {
    nodus_witness_dht_snap_t  snap;
    bool                      have_snap;
    nodus_witness_dht_sets_t *sets;       /* heap: ~200 KB */
    bool                      have_sets;
    uint8_t                   named[4][DHT2_FP_LEN];
    size_t                    nnamed;
    /* The real view's single fault slot (nodus_dht2_wview.c): a name store
     * error for `err_fp` is read after the request that met it; it blocks
     * every other fp (PENDING) until its own fp asks again (FAULT, consumed)
     * or until NODUS_DHT2_WVIEW_FAULT_KEEP_MS has passed (dropped). */
    bool                      err_armed;      /* the next name request of
                                               * err_fp meets a store error */
    uint8_t                   err_fp[DHT2_FP_LEN];
    bool                      fault_set;
    uint8_t                   fault_fp[DHT2_FP_LEN];
    uint64_t                  fault_at_ms;
    bool                      pending_next;   /* one PENDING              */
    int                       name_calls;
} fv_t;

static bool fv_snap(void *user, uint64_t now_ms, nodus_witness_dht_snap_t *out)
{
    fv_t *v = (fv_t *)user;

    (void)now_ms;
    if (!v->have_snap) {
        return false;
    }
    *out = v->snap;
    return true;
}

static const nodus_witness_dht_sets_t *fv_sets(void *user, uint64_t now_ms)
{
    fv_t *v = (fv_t *)user;

    (void)now_ms;
    return v->have_sets ? v->sets : NULL;
}

static nodus_dht2_wview_name_t fv_name(void *user, uint64_t now_ms,
                                       const uint8_t fp[64], uint64_t *h_out)
{
    fv_t   *v = (fv_t *)user;
    size_t  i;

    v->name_calls++;
    if (h_out != NULL) {
        *h_out = v->snap.height;
    }
    if (v->fault_set && now_ms >= v->fault_at_ms &&
        now_ms - v->fault_at_ms >= NODUS_DHT2_WVIEW_FAULT_KEEP_MS) {
        v->fault_set = false;                /* abandoned: dropped */
    }
    if (v->fault_set) {
        if (memcmp(v->fault_fp, fp, DHT2_FP_LEN) == 0) {
            v->fault_set = false;            /* reported once, consumed */
            return NODUS_DHT2_WVIEW_NAME_FAULT;
        }
        return NODUS_DHT2_WVIEW_NAME_PENDING;   /* blocked by an unread fault */
    }
    if (v->err_armed && memcmp(v->err_fp, fp, DHT2_FP_LEN) == 0) {
        /* the request goes out, the store answers {err}: the fault is
         * readable from the next call on */
        v->err_armed = false;
        v->fault_set = true;
        memcpy(v->fault_fp, fp, DHT2_FP_LEN);
        v->fault_at_ms = now_ms;
        return NODUS_DHT2_WVIEW_NAME_PENDING;
    }
    if (v->pending_next) {
        v->pending_next = false;
        return NODUS_DHT2_WVIEW_NAME_PENDING;
    }
    for (i = 0; i < v->nnamed; i++) {
        if (memcmp(v->named[i], fp, DHT2_FP_LEN) == 0) {
            return NODUS_DHT2_WVIEW_NAME_NAMED;
        }
    }
    return NODUS_DHT2_WVIEW_NAME_UNNAMED;
}

typedef struct {
    fv_t                 view;
    nodus_dht2_holder_t  h;
    nodus_dht2_store_t  *st;
    nodus_identity_t    *id;
} world_t;

/* `nset` members: this node plus nset − 1 fixed fakes. */
static int world_init(world_t *w, const tkey_t *node, size_t nset)
{
    nodus_dht2_holder_view_t vw;
    char                     path[128];
    size_t                   i;

    memset(w, 0, sizeof(*w));
    w->id = (nodus_identity_t *)calloc(1, sizeof(*w->id));
    w->view.sets = (nodus_witness_dht_sets_t *)calloc(1, sizeof(*w->view.sets));
    if (w->id == NULL || w->view.sets == NULL) {
        return -1;
    }
    memcpy(w->id->pk.bytes, node->pk, DHT2_PUBKEY_LEN);
    memcpy(w->id->sk.bytes, node->sk, QGP_DSA87_SECRETKEYBYTES);

    memcpy(w->view.snap.chain_id, g_chain, DHT2_CHAIN_LEN);
    w->view.snap.height = 1000;
    w->view.snap.tip_time = T0;
    w->view.snap.consensus_up = true;
    w->view.snap.epoch_start = 720;
    w->view.have_snap = true;
    w->view.have_sets = true;
    w->view.sets->e = 720;
    w->view.sets->n0 = (uint32_t)nset;
    memcpy(w->view.sets->s0[0], node->fp, DHT2_FP_LEN);
    for (i = 1; i < nset; i++) {
        memset(w->view.sets->s0[i], (int)(0xE0 + i), DHT2_FP_LEN);
    }

    snprintf(path, sizeof(path), "%s/s%d.db", g_dir, g_db_n++);
    w->st = nodus_dht2_store_open(path, g_chain);
    if (w->st == NULL) {
        return -1;
    }
    vw.snap = fv_snap;
    vw.sets = fv_sets;
    vw.name = fv_name;
    vw.user = &w->view;
    return nodus_dht2_holder_init(&w->h, w->st, w->id, g_chain, &vw);
}

static void world_free(world_t *w)
{
    if (w->st != NULL) {
        nodus_dht2_store_close(w->st);
    }
    free(w->view.sets);
    if (w->id != NULL) {
        memset(w->id, 0, sizeof(*w->id));
    }
    free(w->id);
}

/* ── requests, records ──────────────────────────────────────────────── */

static void nonce_of(uint8_t n[DHT2_NONCE_LEN], uint8_t b)
{
    memset(n, b, DHT2_NONCE_LEN);
}

static int mk_get(env_t *e, uint8_t nb, const uint8_t (*keys)[DHT2_HASH_LEN],
                  size_t count)
{
    dht2_req_t rq;
    size_t     i;

    memset(&rq, 0, sizeof(rq));
    rq.kind = DHT2_REQ_GET;
    nonce_of(rq.nonce, nb);
    rq.count = count;
    for (i = 0; i < count; i++) {
        memcpy(rq.keys[i], keys[i], DHT2_HASH_LEN);
    }
    return dht2_req_encode(&rq, e->b, sizeof(e->b), &e->n) == DHT2_OK ? 0 : -1;
}

static int mk_put(env_t *e, uint8_t nb, const env_t *recs, size_t count)
{
    dht2_req_t rq;
    size_t     i;

    memset(&rq, 0, sizeof(rq));
    rq.kind = DHT2_REQ_PUT;
    nonce_of(rq.nonce, nb);
    rq.count = count;
    for (i = 0; i < count; i++) {
        rq.envs[i] = recs[i].b;
        rq.env_lens[i] = recs[i].n;
    }
    return dht2_req_encode(&rq, e->b, sizeof(e->b), &e->n) == DHT2_OK ? 0 : -1;
}

/* A class-1 owner record of `k` at id byte `idb`, expiry one hour on. */
static int mk_owner(env_t *r, uint8_t addr[DHT2_HASH_LEN], const tkey_t *k,
                    uint8_t idb)
{
    static const uint8_t dat[4] = { 1, 2, 3, 4 };
    dht2_data_t          d;

    memset(&d, 0, sizeof(d));
    d.sequence = 1;
    d.validity_type = DHT2_VT_EOL;
    d.expiry = T0 + 3600;
    memset(d.id, idb, DHT2_ID_LEN);
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    d.cls = DHT2_CLASS_OWNER;
    d.has_data = true;
    d.data = dat;
    d.data_len = sizeof(dat);
    if (dht2_record_build(&d, k->sk, k->pk, r->b, sizeof(r->b), &r->n)
        != DHT2_OK) {
        return -1;
    }
    return dht2_address(d.id, k->fp, addr);
}

static int mk_inbox_entry(env_t *r, const tkey_t *writer,
                          const uint8_t inbox[DHT2_ID_LEN])
{
    static const uint8_t dat[4] = { 9, 8, 7, 6 };
    dht2_data_t          d;

    memset(&d, 0, sizeof(d));
    d.sequence = 1;
    d.validity_type = DHT2_VT_EOL;
    d.expiry = T0 + 3600;
    memcpy(d.id, inbox, DHT2_ID_LEN);
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    d.cls = DHT2_CLASS_INBOX_ENTRY;
    d.has_data = true;
    d.data = dat;
    d.data_len = sizeof(dat);
    return dht2_record_build(&d, writer->sk, writer->pk, r->b, sizeof(r->b),
                             &r->n) == DHT2_OK ? 0 : -1;
}

static int mk_list(env_t *e, uint8_t nb, const uint8_t chain[DHT2_CHAIN_LEN],
                   const uint8_t inbox[DHT2_ID_LEN], const tkey_t *signer)
{
    dht2_list_req_t lr;

    memset(&lr, 0, sizeof(lr));
    nonce_of(lr.nonce, nb);
    memcpy(lr.chain, chain, DHT2_CHAIN_LEN);
    memcpy(lr.inbox, inbox, DHT2_ID_LEN);
    return dht2_list_req_build(&lr, signer->sk, signer->pk, e->b, sizeof(e->b),
                               &e->n) == DHT2_OK ? 0 : -1;
}

/* ── serving and checking answers ───────────────────────────────────── */

static uint8_t  g_out[NODUS_DHT2_HOLDER_OUT_MIN];
static size_t   g_out_n;
static uint64_t g_now = 12345;     /* the caller's monotonic tick, ms */

static int serve_raw(world_t *w, nodus_dht2_holder_kind_t kind,
                     const uint8_t *req, size_t n)
{
    g_out_n = 0;
    return nodus_dht2_holder_serve(&w->h, kind, g_now, req, n, g_out,
                                   sizeof(g_out), &g_out_n);
}

static int serve(world_t *w, nodus_dht2_holder_kind_t kind, const env_t *req)
{
    return serve_raw(w, kind, req->b, req->n);
}

/* Open g_out as an envelope of `pt`, signed by the node, under the answer
 * domain and under no other. */
static bool open_ans(const world_t *w, const char *pt, dht2_env_t *env)
{
    bool ok = dht2_answer_open(g_out, g_out_n, pt, env) == DHT2_OK;

    CHECK(ok, "answer opens under its payload type and verifies");
    if (!ok) {
        return false;
    }
    CHECK(memcmp(env->fp, w->h.self_fp, DHT2_FP_LEN) == 0,
          "signed by the node identity");
    CHECK(dht2_env_verify(env, DHT2_DOMAIN_LIST) != DHT2_OK,
          "does not verify under another domain");
    return true;
}

static bool ans_head(const world_t *w, const char *pt, uint8_t nb,
                     dht2_answer_t *a)
{
    dht2_env_t env;

    if (!open_ans(w, pt, &env)) {
        return false;
    }
    if (strcmp(pt, DHT2_PT_RECEIPT) == 0) {
        if (dht2_receipt_decode(env.payload, env.payload_len, a) != DHT2_OK) {
            CHECK(false, "receipt payload decodes");
            return false;
        }
    } else if (dht2_answer_decode(env.payload, env.payload_len, a) != DHT2_OK) {
        CHECK(false, "answer payload decodes");
        return false;
    }
    {
        uint8_t q[DHT2_NONCE_LEN];

        nonce_of(q, nb);
        CHECK(memcmp(a->q, q, DHT2_NONCE_LEN) == 0, "q echoes the nonce");
    }
    CHECK(memcmp(a->n, w->h.self_fp, DHT2_FP_LEN) == 0, "n = self fp");
    CHECK(memcmp(a->c, g_chain, DHT2_CHAIN_LEN) == 0, "c = chain");
    CHECK(a->h == w->view.snap.height, "h = snapshot height");
    CHECK(a->t == w->view.snap.tip_time, "t = snapshot tip time");
    return true;
}

static bool refusal_is(const world_t *w, uint8_t nb, uint64_t e)
{
    dht2_env_t     env;
    dht2_refusal_t m;
    uint8_t        q[DHT2_NONCE_LEN];

    if (!open_ans(w, DHT2_PT_REFUSAL, &env) ||
        dht2_refusal_decode(env.payload, env.payload_len, &m) != DHT2_OK) {
        CHECK(false, "refusal opens and decodes");
        return false;
    }
    nonce_of(q, nb);
    CHECK(memcmp(m.q, q, DHT2_NONCE_LEN) == 0, "refusal q echoes the nonce");
    CHECK(memcmp(m.n, w->h.self_fp, DHT2_FP_LEN) == 0, "refusal n = self fp");
    CHECK(memcmp(m.c, g_chain, DHT2_CHAIN_LEN) == 0, "refusal c = chain");
    CHECK(m.e == e, "refusal code");
    return m.e == e;
}

static bool hash_is(const env_t *r, const uint8_t h[DHT2_HASH_LEN])
{
    uint8_t want[DHT2_HASH_LEN];

    return qgp_sha3_512(r->b, r->n, want) == 0 &&
           memcmp(want, h, DHT2_HASH_LEN) == 0;
}

/* ══ tests ═════════════════════════════════════════════════════════════ */

/* put -> receipt, get -> answer; request order, null for the unheld key. */
static void test_get_put(const tkey_t *node, const tkey_t *wr)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec, bad, req;
    env_t          recs[2];
    uint8_t        addr[DHT2_HASH_LEN], keys[2][DHT2_HASH_LEN];
    dht2_answer_t  a;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, wr, 0x11) == 0, "record");

    /* put: one good envelope, one that is not an envelope. */
    memset(bad.b, 0xFF, 10);
    bad.n = 10;
    recs[0] = rec;
    recs[1] = bad;
    CHECK(mk_put(&req, 0x71, recs, 2) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER,
          "put answered");
    if (ans_head(w, DHT2_PT_RECEIPT, 0x71, &a)) {
        CHECK(a.r_count == 2, "two results, request order");
        CHECK(memcmp(a.r[0].key, addr, DHT2_HASH_LEN) == 0, "k = the address");
        CHECK(a.r[0].kind == DHT2_RV_HASH && hash_is(&rec, a.r[0].hash),
              "receipt names the stored hash");
        CHECK(a.r[1].kind == DHT2_RV_CODE && a.r[1].code == DHT2_E_BAD_ENCODING,
              "not an envelope: code 2");
        {
            uint8_t zero[DHT2_HASH_LEN] = { 0 };

            CHECK(memcmp(a.r[1].key, zero, DHT2_HASH_LEN) == 0,
                  "no address: all-zero key");
        }
    }
    /* A receipt does not open as an answer. */
    {
        dht2_env_t env;

        CHECK(dht2_answer_open(g_out, g_out_n, DHT2_PT_ANSWER, &env)
                  != DHT2_OK,
              "a receipt is not an answer");
    }

    /* get: the held key, then one that is not held. */
    memcpy(keys[0], addr, DHT2_HASH_LEN);
    memset(keys[1], 0x77, DHT2_HASH_LEN);
    CHECK(mk_get(&req, 0x72, (const uint8_t (*)[DHT2_HASH_LEN])keys, 2) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER,
          "get answered");
    if (ans_head(w, DHT2_PT_ANSWER, 0x72, &a)) {
        CHECK(a.r_count == 2, "two results");
        CHECK(memcmp(a.r[0].key, keys[0], DHT2_HASH_LEN) == 0 &&
                  a.r[0].kind == DHT2_RV_HASH && hash_is(&rec, a.r[0].hash),
              "held key answers the same hash the receipt named");
        CHECK(memcmp(a.r[1].key, keys[1], DHT2_HASH_LEN) == 0 &&
                  a.r[1].kind == DHT2_RV_NULL,
              "unheld key answers null");
    }
    world_free(w);
    free(w);
}

static void test_malformed(const tkey_t *node, const tkey_t *wr)
{
    world_t     *w = (world_t *)calloc(1, sizeof(*w));
    static env_t rec, req, junk, lreq;
    uint8_t      addr[DHT2_HASH_LEN], keys[1][DHT2_HASH_LEN];
    uint8_t      inbox[DHT2_ID_LEN];

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, wr, 0x12) == 0, "record");
    memcpy(keys[0], addr, DHT2_HASH_LEN);
    CHECK(mk_get(&req, 0x73, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");

    memset(junk.b, 0x42, 33);
    junk.n = 33;
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &junk) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "bytes that are not a request: no answer");
    CHECK(g_out_n == 0, "and no bytes");
    junk.n = 0;
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &junk) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "empty request: no answer");
    {
        env_t trunc = req;

        trunc.n = req.n - 1;
        CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &trunc)
                  == NODUS_DHT2_HOLDER_NO_ANSWER,
              "truncated request: no answer");
    }
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "a get sent as put: no answer");
    {
        env_t put;

        CHECK(mk_put(&put, 0x74, &rec, 1) == 0, "put request");
        CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &put)
                  == NODUS_DHT2_HOLDER_NO_ANSWER,
              "a put sent as get: no answer");
    }
    /* LIST: bytes that are not an envelope; a get request as a LIST. */
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &junk) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "LIST of nothing: no answer");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &req) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "a get as LIST: no answer");
    /* LIST of another chain / with a flipped payload byte. */
    CHECK(dht2_id_inbox(g_chain, wr->fp, inbox) == 0, "inbox id");
    CHECK(mk_list(&lreq, 0x75, g_other_chain, inbox, wr) == 0, "list request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "LIST of another chain: no answer");
    CHECK(mk_list(&lreq, 0x75, g_chain, inbox, wr) == 0, "list request");
    lreq.b[lreq.n - 1] ^= 0x01;        /* the last signature byte */
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_NO_ANSWER,
          "LIST with a bad signature: no answer");
    world_free(w);
    free(w);
}

static void test_list(const tkey_t *node, const tkey_t *owner,
                      const tkey_t *writer, const tkey_t *other)
{
    world_t         *w = (world_t *)calloc(1, sizeof(*w));
    static env_t     ent, put, lreq;
    dht2_env_t       env;
    dht2_list_answer_t *la = (dht2_list_answer_t *)calloc(1, sizeof(*la));
    uint8_t          inbox[DHT2_ID_LEN], want[DHT2_HASH_LEN], q[DHT2_NONCE_LEN];

    CHECK(w != NULL && la != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(dht2_id_inbox(g_chain, owner->fp, inbox) == 0, "inbox id");
    CHECK(mk_inbox_entry(&ent, writer, inbox) == 0, "inbox entry");
    CHECK(mk_put(&put, 0x80, &ent, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &put) == NODUS_DHT2_HOLDER_ANSWER,
          "entry stored");

    /* The owner lists. */
    CHECK(mk_list(&lreq, 0x81, g_chain, inbox, owner) == 0, "list request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_ANSWER,
          "owner LIST answered");
    if (open_ans(w, DHT2_PT_ANSWER, &env) &&
        dht2_list_answer_decode(env.payload, env.payload_len, la) == DHT2_OK) {
        nonce_of(q, 0x81);
        CHECK(memcmp(la->q, q, DHT2_NONCE_LEN) == 0, "LIST q = nonce");
        CHECK(memcmp(la->n, w->h.self_fp, DHT2_FP_LEN) == 0, "LIST n = self");
        CHECK(memcmp(la->c, g_chain, DHT2_CHAIN_LEN) == 0, "LIST c = chain");
        CHECK(la->h == w->view.snap.height && la->t == w->view.snap.tip_time,
              "LIST h / t = snapshot");
        CHECK(la->list_count == 1 &&
                  memcmp(la->list[0].w, writer->fp, DHT2_FP_LEN) == 0 &&
                  hash_is(&ent, la->list[0].d),
              "the writer's entry is listed with its hash");
        CHECK(la->complete, "a one-entry page is complete");
        CHECK(la->r.kind == DHT2_RV_HASH &&
                  memcmp(la->r.key, inbox, DHT2_HASH_LEN) == 0 &&
                  qgp_sha3_512(la->list[0].d, DHT2_HASH_LEN, want) == 0 &&
                  memcmp(want, la->r.hash, DHT2_HASH_LEN) == 0,
              "r.v = SHA3-512 over the listed hashes");
    }

    /* Another key signs a request for that inbox: 17, nothing listed. */
    CHECK(mk_list(&lreq, 0x82, g_chain, inbox, other) == 0, "list request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_ANSWER,
          "not-owner LIST answered");
    memset(la, 0, sizeof(*la));
    if (open_ans(w, DHT2_PT_ANSWER, &env) &&
        dht2_list_answer_decode(env.payload, env.payload_len, la) == DHT2_OK) {
        nonce_of(q, 0x82);
        CHECK(memcmp(la->q, q, DHT2_NONCE_LEN) == 0, "17: q = nonce");
        CHECK(la->r.kind == DHT2_RV_CODE && la->r.code == DHT2_E_NOT_OWNER &&
                  memcmp(la->r.key, inbox, DHT2_HASH_LEN) == 0,
              "r.v = 17 for the inbox");
        CHECK(la->list_count == 0 && la->complete && !la->has_ctl,
              "nothing listed");
        CHECK(la->h == w->view.snap.height && la->t == w->view.snap.tip_time,
              "17: h / t = snapshot");
    }
    world_free(w);
    free(w);
    free(la);
}

static void test_call_level(const tkey_t *node, const tkey_t *wr)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec, req, lreq;
    uint8_t        addr[DHT2_HASH_LEN], keys[1][DHT2_HASH_LEN];
    uint8_t        inbox[DHT2_ID_LEN];
    dht2_answer_t  a;
    unsigned       i;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, wr, 0x13) == 0, "record");
    memcpy(keys[0], addr, DHT2_HASH_LEN);
    CHECK(dht2_id_inbox(g_chain, wr->fp, inbox) == 0, "inbox id");
    CHECK(mk_list(&lreq, 0x93, g_chain, inbox, wr) == 0, "list request");

    /* consensus_up false: block sync. */
    w->view.snap.consensus_up = false;
    CHECK(mk_get(&req, 0x91, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x91, DHT2_E_NOT_CAUGHT_UP),
          "get in block sync: refusal 15");
    CHECK(mk_put(&req, 0x92, &rec, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x92, DHT2_E_NOT_CAUGHT_UP),
          "put in block sync: refusal 15");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x93, DHT2_E_NOT_CAUGHT_UP),
          "list in block sync: refusal 15");

    /* No fresh snapshot at all. */
    w->view.snap.consensus_up = true;
    w->view.have_snap = false;
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x92, DHT2_E_NOT_CAUGHT_UP),
          "no snapshot: refusal 15");
    w->view.have_snap = true;

    /* No sets for the snapshot's e: the store's 15. */
    w->view.have_sets = false;
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x92, DHT2_E_NOT_CAUGHT_UP),
          "no sets: refusal 15");
    w->view.have_sets = true;

    /* Row 20: 64 queued jobs fill the holder; the 65th does not enter. */
    for (i = 0; i < NODUS_DHT2_HOLDER_QUEUE_MAX; i++) {
        CHECK(nodus_dht2_holder_job_enter(&w->h), "job slot taken");
    }
    CHECK(!nodus_dht2_holder_job_enter(&w->h), "the 65th job is refused");
    CHECK(mk_get(&req, 0x94, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0x94, DHT2_E_BUSY),
          "full queue: refusal 14");
    nodus_dht2_holder_job_leave(&w->h);
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_ANSWER, 0x94, &a),
          "a slot given back: answered again");
    for (i = 1; i < NODUS_DHT2_HOLDER_QUEUE_MAX; i++) {
        nodus_dht2_holder_job_leave(&w->h);
    }
    CHECK(w->h.queued == 0, "queue empty again");
    nodus_dht2_holder_job_leave(&w->h);
    CHECK(w->h.queued == 0, "leave of an empty queue is a no-op");
    world_free(w);
    free(w);
}

/* Decision 2026-10-26-dht-v2-no-single-node-write-refusal.md: a holder never
 * refuses a write because the storage set is small — one storage node stores. */
static void test_single_storage_node_stores(const tkey_t *node,
                                            const tkey_t *wr)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec, req;
    uint8_t        addr[DHT2_HASH_LEN], keys[1][DHT2_HASH_LEN];
    dht2_answer_t  a;

    CHECK(w != NULL && world_init(w, node, 1) == 0, "world, |S(H)| = 1");
    CHECK(mk_owner(&rec, addr, wr, 0x14) == 0, "record");
    memcpy(keys[0], addr, DHT2_HASH_LEN);

    CHECK(mk_put(&req, 0xA1, &rec, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xA1, &a),
          "|S(H)| = 1: put answered with a receipt, not a refusal");
    CHECK(a.r_count == 1 && a.r[0].kind == DHT2_RV_HASH &&
              hash_is(&rec, a.r[0].hash),
          "|S(H)| = 1: the put stored the record");
    CHECK(mk_get(&req, 0xA2, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_ANSWER, 0xA2, &a),
          "|S(H)| = 1: get answered");
    CHECK(a.r_count == 1 && a.r[0].kind == DHT2_RV_HASH &&
              hash_is(&rec, a.r[0].hash),
          "and the get returns the stored hash");
    world_free(w);
    free(w);
}

static void test_name_fault(const tkey_t *node, const tkey_t *wr)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec, req;
    uint8_t        addr[DHT2_HASH_LEN], keys[1][DHT2_HASH_LEN];
    dht2_answer_t  a;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, wr, 0x15) == 0, "record");
    memcpy(keys[0], addr, DHT2_HASH_LEN);
    CHECK(mk_put(&req, 0xB1, &rec, 1) == 0, "put request");

    /* A name FAULT: code 16, nothing stored, asked once. */
    w->view.err_armed = true;
    memcpy(w->view.err_fp, wr->fp, DHT2_FP_LEN);
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xB1, &a),
          "put whose name request met a store error answered");
    CHECK(a.r_count == 1 && a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_HOLDER_FAULT,
          "request sent (pending): code 16");
    CHECK(w->view.name_calls == 1 && w->view.fault_set,
          "asked once; the fault now waits to be read");
    /* The retry reads the fault: FAULT is code 16, never "unnamed", and the
     * call consumes it. */
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xB1, &a) &&
              a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_HOLDER_FAULT,
          "name fault: code 16");
    CHECK(w->view.name_calls == 2 && !w->view.fault_set,
          "the fault was consumed by the call that met it");

    /* The next name request is possible: the same put now succeeds. */
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xB1, &a),
          "the third try is answered");
    CHECK(w->view.name_calls == 3, "the next name request was made");
    CHECK(a.r_count == 1 && a.r[0].kind == DHT2_RV_HASH &&
              hash_is(&rec, a.r[0].hash),
          "and the record was stored");

    /* PENDING is also 16 for the call, never "unnamed": use a new record. */
    {
        static env_t rec2, req2;
        uint8_t      addr2[DHT2_HASH_LEN];

        CHECK(mk_owner(&rec2, addr2, wr, 0x16) == 0, "second record");
        CHECK(mk_put(&req2, 0xB2, &rec2, 1) == 0, "put request");
        w->view.pending_next = true;
        CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req2)
                      == NODUS_DHT2_HOLDER_ANSWER &&
                  ans_head(w, DHT2_PT_RECEIPT, 0xB2, &a),
              "put with a pending name answered");
        CHECK(a.r_count == 1 && a.r[0].kind == DHT2_RV_CODE &&
                  a.r[0].code == DHT2_E_HOLDER_FAULT,
              "pending name: code 16");
        memcpy(keys[0], addr2, DHT2_HASH_LEN);
        CHECK(mk_get(&req2, 0xB3, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1)
                  == 0, "get request");
        CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req2)
                      == NODUS_DHT2_HOLDER_ANSWER &&
                  ans_head(w, DHT2_PT_ANSWER, 0xB3, &a) &&
                  a.r[0].kind == DHT2_RV_NULL,
              "and it was not stored");
    }
    world_free(w);
    free(w);
}

/* Fix round, item 2: writer A's name request meets a store error and A never
 * asks again. The view keeps ONE unread fault; it must not block writer B
 * past one poll period. The fake consumes per fp the way the real view
 * does (fv_name). */
static void test_fault_abandoned(const tkey_t *node, const tkey_t *wa,
                                 const tkey_t *wb)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   ra, rb, req;
    uint8_t        addr[DHT2_HASH_LEN];
    dht2_answer_t  a;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&ra, addr, wa, 0x21) == 0 &&
              mk_owner(&rb, addr, wb, 0x22) == 0, "records");
    g_now = 50000;
    w->view.err_armed = true;
    memcpy(w->view.err_fp, wa->fp, DHT2_FP_LEN);

    CHECK(mk_put(&req, 0xC1, &ra, 1) == 0, "A's put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xC1, &a) &&
              a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_HOLDER_FAULT && w->view.fault_set,
          "A: code 16, and A never comes back (the fault stays unread)");

    CHECK(mk_put(&req, 0xC2, &rb, 1) == 0, "B's put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xC2, &a) &&
              a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_HOLDER_FAULT,
          "B at once: blocked by A's unread fault (16, not stored)");
    g_now += NODUS_DHT2_WVIEW_FAULT_KEEP_MS - 1;
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xC2, &a) &&
              a.r[0].kind == DHT2_RV_CODE,
          "B one ms before the period: still blocked");
    g_now += 1;
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xC2, &a) &&
              a.r[0].kind == DHT2_RV_HASH && hash_is(&rb, a.r[0].hash),
          "B after one poll period: the abandoned fault is dropped, B stored");
    CHECK(!w->view.fault_set, "and the slot is free");
    g_now = 12345;
    world_free(w);
    free(w);
}

/* Fix round, item 1: a snapshot of another chain is no snapshot. */
static void test_chain_gate(const tkey_t *node, const tkey_t *owner,
                            const tkey_t *other)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec, req, lreq;
    uint8_t        addr[DHT2_HASH_LEN], keys[1][DHT2_HASH_LEN];
    uint8_t        inbox[DHT2_ID_LEN];

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, owner, 0x23) == 0, "record");
    memcpy(keys[0], addr, DHT2_HASH_LEN);
    CHECK(dht2_id_inbox(g_chain, owner->fp, inbox) == 0, "inbox id");
    memcpy(w->view.snap.chain_id, g_other_chain, DHT2_CHAIN_LEN);

    CHECK(mk_get(&req, 0xD1, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0xD1, DHT2_E_NOT_CAUGHT_UP),
          "foreign-chain snapshot, get: refusal 15 (our c, no h / t)");
    CHECK(mk_put(&req, 0xD2, &rec, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0xD2, DHT2_E_NOT_CAUGHT_UP),
          "put: refusal 15");
    CHECK(mk_list(&lreq, 0xD3, g_chain, inbox, owner) == 0, "list request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0xD3, DHT2_E_NOT_CAUGHT_UP),
          "owner LIST: refusal 15");
    CHECK(mk_list(&lreq, 0xD4, g_chain, inbox, other) == 0, "list request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_LIST, &lreq) == NODUS_DHT2_HOLDER_ANSWER &&
              refusal_is(w, 0xD4, DHT2_E_NOT_CAUGHT_UP),
          "not-owner LIST: the same gate, refusal 15 (no 17 with a foreign tip)");
    world_free(w);
    free(w);
}

/* Fix round, item 3: an inbox-control record is never served by GET. */
static void test_ctl_get(const tkey_t *node, const tkey_t *owner)
{
    world_t             *w = (world_t *)calloc(1, sizeof(*w));
    static env_t         ctl, req;
    static const uint8_t none[1] = { 0 };
    dht2_data_t          d;
    uint8_t              ctl_id[DHT2_ID_LEN], addr[DHT2_HASH_LEN];
    uint8_t              keys[1][DHT2_HASH_LEN];
    dht2_answer_t        a;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");
    CHECK(dht2_id_inbox_ctl(g_chain, owner->fp, ctl_id) == 0 &&
              dht2_address(ctl_id, owner->fp, addr) == 0, "ctl ids");
    memset(&d, 0, sizeof(d));
    d.sequence = 1;
    d.validity_type = DHT2_VT_EOL;
    d.expiry = T0 + 3600;
    memcpy(d.id, ctl_id, DHT2_ID_LEN);
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    d.cls = DHT2_CLASS_INBOX_CTL;
    d.has_data = true;
    d.data = none;
    d.data_len = 0;                       /* an empty control list */
    CHECK(dht2_record_build(&d, owner->sk, owner->pk, ctl.b, sizeof(ctl.b),
                            &ctl.n) == DHT2_OK, "control record");
    CHECK(mk_put(&req, 0xE1, &ctl, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xE1, &a) &&
              a.r[0].kind == DHT2_RV_HASH && hash_is(&ctl, a.r[0].hash),
          "the owner's control record is stored");

    memcpy(keys[0], addr, DHT2_HASH_LEN);
    CHECK(mk_get(&req, 0xE2, (const uint8_t (*)[DHT2_HASH_LEN])keys, 1) == 0,
          "get request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_GET, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_ANSWER, 0xE2, &a),
          "get of the control address answered");
    CHECK(a.r_count == 1 && memcmp(a.r[0].key, addr, DHT2_HASH_LEN) == 0 &&
              a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_NOT_OWNER,
          "per-key 17: neither its hash nor its bytes");
    world_free(w);
    free(w);
}

/* Fix round, items 4 and 5: an envelope above 262,144 B inside a put is
 * per-key code 1 with a zero key; its sibling is still processed. */
static void test_oversize_put(const tkey_t *node, const tkey_t *wr)
{
    world_t       *w = (world_t *)calloc(1, sizeof(*w));
    static env_t   rec;
    dht2_req_t     rq;
    uint8_t       *big = (uint8_t *)calloc(1, DHT2_ENVELOPE_MAX + 1u);
    uint8_t       *buf = (uint8_t *)malloc(DHT2_REQ_MAX_LEN);
    uint8_t        addr[DHT2_HASH_LEN], zero[DHT2_HASH_LEN] = { 0 };
    size_t         n = 0;
    dht2_answer_t  a;

    CHECK(w != NULL && big != NULL && buf != NULL &&
              world_init(w, node, 3) == 0, "world");
    CHECK(mk_owner(&rec, addr, wr, 0x24) == 0, "record");
    memset(&rq, 0, sizeof(rq));
    rq.kind = DHT2_REQ_PUT;
    nonce_of(rq.nonce, 0xF1);
    rq.count = 2;
    rq.envs[0] = big;
    rq.env_lens[0] = DHT2_ENVELOPE_MAX + 1u;
    rq.envs[1] = rec.b;
    rq.env_lens[1] = rec.n;
    /* The record (pk + signature, > 7 KB) rides beside the 262,145 B
     * envelope: the buffer is the largest legal request. */
    CHECK(dht2_req_encode(&rq, buf, DHT2_REQ_MAX_LEN, &n) == DHT2_OK,
          "the request encodes");
    CHECK(serve_raw(w, NODUS_DHT2_HOLDER_PUT, buf, n)
                  == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xF1, &a),
          "the request is not malformed: answered");
    CHECK(a.r_count == 2 && a.r[0].kind == DHT2_RV_CODE &&
              a.r[0].code == DHT2_E_TOO_LARGE &&
              memcmp(a.r[0].key, zero, DHT2_HASH_LEN) == 0,
          "oversized envelope: code 1, key zeros");
    CHECK(memcmp(a.r[1].key, addr, DHT2_HASH_LEN) == 0 &&
              a.r[1].kind == DHT2_RV_HASH && hash_is(&rec, a.r[1].hash),
          "the sibling is processed and acknowledged under its address");
    world_free(w);
    free(w);
    free(big);
    free(buf);
}

/* Second fix round: a refusal after the parse is signed under the envelope's
 * ADDRESS (not zeros) - an expired record (7) and a real HANDLED cutoff
 * ([18, through]); the zero key stays for a parse failure. */
static void test_late_refusal(const tkey_t *node, const tkey_t *owner,
                              const tkey_t *wr)
{
    enum { THROUGH = 5 };
    world_t             *w = (world_t *)calloc(1, sizeof(*w));
    static env_t         exp_rec, ctl, ent, req, recs[3];
    static const uint8_t none[1] = { 0 };
    dht2_data_t          d;
    dht2_ctl_entry_t     en;
    uint8_t              cdata[DHT2_CTL_ENTRY_LEN];
    size_t               clen = 0;
    uint8_t              inbox[DHT2_ID_LEN], ctl_id[DHT2_ID_LEN];
    uint8_t              id[DHT2_ID_LEN], a_exp[DHT2_HASH_LEN];
    uint8_t              a_ent[DHT2_HASH_LEN], zero[DHT2_HASH_LEN] = { 0 };
    dht2_answer_t        a;

    CHECK(w != NULL && world_init(w, node, 3) == 0, "world");

    /* late refusal: an expired record, key = its address, v = 7 */
    memset(id, 0x25, sizeof(id));
    memset(&d, 0, sizeof(d));
    d.sequence = 1;
    d.validity_type = DHT2_VT_EOL;
    d.expiry = T0 - 1;
    memcpy(d.id, id, DHT2_ID_LEN);
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    d.cls = DHT2_CLASS_OWNER;
    d.has_data = true;
    d.data = none;
    d.data_len = 1;
    CHECK(dht2_record_build(&d, wr->sk, wr->pk, exp_rec.b, sizeof(exp_rec.b),
                            &exp_rec.n) == DHT2_OK &&
              dht2_address(id, wr->fp, a_exp) == 0, "expired record");

    /* HANDLED: the owner's control record marks the writer through 5 */
    CHECK(dht2_id_inbox(g_chain, owner->fp, inbox) == 0 &&
              dht2_id_inbox_ctl(g_chain, owner->fp, ctl_id) == 0, "ids");
    memset(&en, 0, sizeof(en));
    memcpy(en.fp, wr->fp, DHT2_FP_LEN);
    en.mark = DHT2_CTL_HANDLED;
    en.through = THROUGH;
    CHECK(dht2_ctl_encode(&en, 1, cdata, sizeof(cdata), &clen) == DHT2_OK,
          "control data");
    memset(&d, 0, sizeof(d));
    d.sequence = 1;
    d.validity_type = DHT2_VT_EOL;
    d.expiry = T0 + 3600;
    memcpy(d.id, ctl_id, DHT2_ID_LEN);
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    d.cls = DHT2_CLASS_INBOX_CTL;
    d.has_data = true;
    d.data = cdata;
    d.data_len = clen;
    CHECK(dht2_record_build(&d, owner->sk, owner->pk, ctl.b, sizeof(ctl.b),
                            &ctl.n) == DHT2_OK, "control record");
    CHECK(mk_inbox_entry(&ent, wr, inbox) == 0 &&
              dht2_address(inbox, wr->fp, a_ent) == 0, "entry (Sequence 1)");

    CHECK(mk_put(&req, 0xF2, &ctl, 1) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xF2, &a) &&
              a.r[0].kind == DHT2_RV_HASH, "control record stored");

    recs[0] = exp_rec;
    recs[1] = ent;
    memset(recs[2].b, 0xFF, 10);
    recs[2].n = 10;
    CHECK(mk_put(&req, 0xF3, recs, 3) == 0, "put request");
    CHECK(serve(w, NODUS_DHT2_HOLDER_PUT, &req) == NODUS_DHT2_HOLDER_ANSWER &&
              ans_head(w, DHT2_PT_RECEIPT, 0xF3, &a) && a.r_count == 3,
          "three results");
    CHECK(memcmp(a.r[0].key, a_exp, DHT2_HASH_LEN) == 0 &&
              a.r[0].kind == DHT2_RV_CODE && a.r[0].code == DHT2_E_EXPIRED,
          "late refusal: {k: address, v: 7}");
    CHECK(memcmp(a.r[1].key, a_ent, DHT2_HASH_LEN) == 0 &&
              a.r[1].kind == DHT2_RV_HANDLED && a.r[1].through == THROUGH,
          "HANDLED: {k: address, v: [18, through]} with the cutoff");
    CHECK(memcmp(a.r[2].key, zero, DHT2_HASH_LEN) == 0 &&
              a.r[2].kind == DHT2_RV_CODE &&
              a.r[2].code == DHT2_E_BAD_ENCODING,
          "parse failure: zero key, code 2");
    world_free(w);
    free(w);
}

/* ══ main ══════════════════════════════════════════════════════════════ */

static void cleanup(void)
{
    char path[160];
    int  i;

    for (i = 0; i < 64; i++) {
        snprintf(path, sizeof(path), "%s/s%d.db", g_dir, i);
        (void)unlink(path);
        snprintf(path, sizeof(path), "%s/s%d.db-journal", g_dir, i);
        (void)unlink(path);
    }
    (void)rmdir(g_dir);
}

int main(void)
{
    tkey_t *keys = (tkey_t *)calloc(5, sizeof(tkey_t));
    int     ok;

    if (keys == NULL) {
        return 1;
    }
    memset(g_chain, 0x22, sizeof(g_chain));
    memset(g_other_chain, 0x23, sizeof(g_other_chain));
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_dht2_holder_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "mkdtemp failed");
        free(keys);
        return 1;
    }
    ok = keygen(&keys[0], 0xA1) == 0 && keygen(&keys[1], 0xB2) == 0 &&
         keygen(&keys[2], 0xC3) == 0 && keygen(&keys[3], 0xD4) == 0 &&
         keygen(&keys[4], 0xE5) == 0;
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "keypairs");
        cleanup();
        free(keys);
        return 1;
    }

    /* keys[0] = the node, [1] = a writer, [2] = an inbox owner, [3] = an
     * inbox writer, [4] = a stranger. */
    QGP_LOG_INFO(LOG_TAG, "=== DHT v2 holder service (package 6a) ===");
    test_get_put(&keys[0], &keys[1]);
    test_malformed(&keys[0], &keys[1]);
    test_list(&keys[0], &keys[2], &keys[3], &keys[4]);
    test_call_level(&keys[0], &keys[1]);
    test_single_storage_node_stores(&keys[0], &keys[1]);
    test_name_fault(&keys[0], &keys[1]);
    test_fault_abandoned(&keys[0], &keys[1], &keys[3]);
    test_chain_gate(&keys[0], &keys[2], &keys[4]);
    test_ctl_get(&keys[0], &keys[2]);
    test_oversize_put(&keys[0], &keys[1]);
    test_late_refusal(&keys[0], &keys[2], &keys[3]);
    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===",
                 g_pass, g_fail);

    cleanup();
    memset(keys, 0, 5 * sizeof(tkey_t));
    free(keys);
    return g_fail == 0 ? 0 : 1;
}
