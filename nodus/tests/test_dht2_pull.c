/**
 * Nodus — DHT v2 package 7 (core): pull-sync
 * (nodus/src/dht2/nodus_dht2_pull.{c,h}, store additions in
 * nodus_dht2_store.{c,h}).
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §4.5, §13
 * row 12 (pull-sync, "Bee pkg/pullsync translated"), row 22 (behaviour
 * fixtures); decisions/2026-10-23-dht-v2-wire-gaps-package2.md and its
 * 2026-10-26 addendum (pull-receipt: dht2_env_seal, domain
 * nodus.dht.answer.v1, payload type /nodus/dht/pull-receipt/v1).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false (two SQLite stores in the
 * run's mkdtemp dir, A the source and B the puller, wired by the send fn):
 *   · a full exchange (p_hello, p_get, p_offer, p_want, p_deliver) copies
 *     every record with the SAME canonical hash; the cursor persisted for
 *     the source is top + 1 with the source's generation; a second exchange
 *     with nothing new sends no p_get; an empty source gives cursor 1;
 *   · one exchange per source: a second start is BUSY;
 *   · the pull-receipt B sends is an RFC 0002 envelope of payload type
 *     /nodus/dht/pull-receipt/v1 that verifies under nodus.dht.answer.v1
 *     and NOT under another domain, signed by B, with pf, sf, c, g, s, top
 *     and the stored [{a, h}] in offer order;
 *   · row 22 "> 250 pull entries": 300 records take two exchanges, the
 *     first ends at index 250 (cursor 251), the second at 300 (cursor 301);
 *   · row 22 "replacement during delivery": a record replaced at the source
 *     between its offer and its delivery arrives as the NEW version (a hash
 *     other than the offered one); the next exchange offers it again and B
 *     already holds it (no delivery);
 *   · row 22 "generation reset": a source with a new store generation is
 *     re-scanned from 0 (the stored cursor is reset, the new generation
 *     stored); a p_get for another generation is dropped; a p_offer of
 *     another generation aborts the exchange and keeps the cursor;
 *   · row 22 "interrupted handover": a permanent record that the source no
 *     longer holds (not in eligible(p)) gets the persisted hand-over flag at
 *     the epoch check; with the pull-receipt lost, the flag survives a
 *     store reopen and the source still offers the record; the repeated
 *     exchange's receipt of ONE member leaves the flag (operator decision
 *     2026-10-27-dht-v2-handover-one-receipt.md: TWO receipts);
 *   · the receipt is refused (flag stays) with a wrong payload type, a wrong
 *     domain, a signer that is not the sending peer; it counts for nothing
 *     when the signer is not in nearest_R(S(H)) of the record or the hash is
 *     not the held one; the same member twice counts once; a second DISTINCT
 *     member meets the quorum: the drop is SCHEDULED 48 epochs on (operator
 *     decision, same record) — still held one epoch before, DROPPED at the
 *     due epoch check (acknowledgements gone, a later receipt does nothing);
 *     with |nearest_R| = 1 one receipt meets it; the acknowledging fps
 *     survive a store reopen; an acknowledger that left nearest_R does not
 *     count; at the due epoch the quorum is re-counted (not met → not
 *     dropped; met at a later check → dropped); a pending record whose
 *     nearest_R shrinks to the member that already acknowledged is scheduled
 *     at the next epoch check with no new receipt, and one whose quorum is
 *     still not met stays pending with its acknowledgements; eligible again
 *     at the epoch check: flag, acks and schedule cleared, record kept past
 *     the old due epoch; a new permanent version: pending, no acks, no
 *     schedule; an EXPIRING replacement of a pending record carries no flag,
 *     so receipts naming it schedule and drop nothing;
 *   · a failed send of a non-empty p_offer leaves no offer kept at the
 *     source (a p_want afterwards is "without an offer");
 *   · row 22 "epoch-boundary sets": when the responsibility GREW (S(H) lost
 *     members relative to S(H − E)) every cursor is reset to 0 and an
 *     exchange in flight is aborted; when the sets are equal, when S(H)
 *     gained members, and when the epoch did not change, cursors are kept;
 *     the sources are S(H) ∪ S(H − E) minus self, ascending, once each;
 *   · row 22 "non-eligible puller gets no offer": the source offers an entry
 *     only to a puller in eligible(p) — an empty offer with the scanned top
 *     for another member, the entry for a member of nearest_R;
 *   · row 22 "wrong bit-vector length aborts": a p_want of ceil(n/8) ± 1
 *     bytes, or with a bit >= n, is dropped with no delivery, and the offer
 *     is forgotten; the exact length gets exactly one p_deliver per set bit;
 *   · row 12 "cursor := top + 1 ONLY after every wanted entry was durably
 *     admitted or definitively refused": a transient local failure (no
 *     snapshot at B during the delivery) aborts and keeps the cursor, the
 *     retry completes; a definitive refusal (code 7, expired at B) advances
 *     it and stores nothing; a delivery that does not match its offer
 *     (source fault) stores nothing and the other deliveries are admitted.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no clock (chain time and the caller's tick are injected constants). Keys
 * come from fixed seeds (qgp_dsa87_keypair_derand); signing is HEDGED, so no
 * signature byte is pinned — signatures are verified, never compared. Every
 * run uses its own mkdtemp directory (safe under `ctest -j`).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success; a crash leaves /tmp/test_dht2_pull_XXXXXX.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The harness is one queue: a message is delivered when step() pops it,
 *     in send order. Real sessions interleave; nothing here tests two
 *     exchanges at once or a real disconnect (nodus_dht2_pull_disconnect is
 *     only exercised through the epoch reset).
 *  2. The harness routes HELLO by "sent by the puller" because the module
 *     has no request/reply flag on the message kind (the framing is a GAP).
 *  3. Sets of at most 4 members make every member eligible and responsible
 *     for every key; the 6-member sets (hand-over, eligibility tests) pick
 *     their records by dht2_nearest_r itself, so a wrong nearest_R would be
 *     tested against itself (package 1 tests it against a vector).
 *  4. The group test of responsibility growth uses fixed fp patterns; it
 *     does not enumerate keys, so it pins the DP's answer for those sets,
 *     not for all sets.
 *  5. The view is injected (nodus_dht2_holder_view_wview is not exercised).
 *  6. Not covered, because the sources are silent (see the header GAPs):
 *     the rate limit, the pageTimeout wait, live pulling, transport framing,
 *     network addresses of sources, the "newer version" half of a receipt.
 *
 * @file test_dht2_pull.c
 */

#include "dht2/nodus_dht2_pull.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_place.h"
#include "dht2/dht2_record.h"
#include "dht2/dht2_types.h"
#include "dnac/dnac.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "TEST_DHT2_PULL"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                              \
    if (cond) { g_pass++; }                                                \
    else { g_fail++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s:%d: %s",              \
                                   __FILE__, __LINE__, (msg)); }           \
} while (0)

#define T0      1792368000ull           /* 2026-10-19T00:00:00Z */
#define NOW     5000ull                 /* the caller's monotonic tick, ms */

/* ══ keys, records ═════════════════════════════════════════════════════ */

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

static void fill_id(uint8_t id[DHT2_ID_LEN], uint32_t idn)
{
    memset(id, 0, DHT2_ID_LEN);
    id[0] = (uint8_t)(idn & 0xFF);
    id[1] = (uint8_t)((idn >> 8) & 0xFF);
    id[2] = 0x77;
}

/* A class-1 owner record of `k` at id number `idn`, version `seq`. `perm`:
 * no expiry (needs a named writer); otherwise expiry one hour on. */
static int mk_rec(env_t *r, uint8_t addr[DHT2_HASH_LEN], const tkey_t *k,
                  uint32_t idn, uint64_t seq, bool perm)
{
    uint8_t     dat[4] = { (uint8_t)seq, 2, 3, 4 };
    dht2_data_t d;

    memset(&d, 0, sizeof(d));
    d.sequence = seq;
    d.validity_type = perm ? DHT2_VT_NONE : DHT2_VT_EOL;
    d.expiry = perm ? 0 : T0 + 3600;
    fill_id(d.id, idn);
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

static bool hash_is(const env_t *r, const uint8_t h[DHT2_HASH_LEN])
{
    uint8_t want[DHT2_HASH_LEN];

    return qgp_sha3_512(r->b, r->n, want) == 0 &&
           memcmp(want, h, DHT2_HASH_LEN) == 0;
}

/* ══ the injected view ═════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_dht_snap_t  snap;
    bool                      have_snap;
    nodus_witness_dht_sets_t *sets;        /* heap: ~200 KB */
    bool                      named_all;   /* every writer has a name */
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
    (void)now_ms;
    return ((fv_t *)user)->sets;
}

static nodus_dht2_wview_name_t fv_name(void *user, uint64_t now_ms,
                                       const uint8_t fp[64], uint64_t *h_out)
{
    fv_t *v = (fv_t *)user;

    (void)now_ms;
    (void)fp;
    if (h_out != NULL) {
        *h_out = v->snap.height;
    }
    return v->named_all ? NODUS_DHT2_WVIEW_NAME_NAMED
                        : NODUS_DHT2_WVIEW_NAME_UNNAMED;
}

/* ══ the nodes and the wire between them ═══════════════════════════════ */

typedef struct {
    tkey_t                   key;
    fv_t                     view;
    nodus_dht2_holder_view_t hv;
    nodus_dht2_holder_t      ho;      /* world_load + put for the fixtures */
    nodus_dht2_store_t      *st;
    nodus_identity_t        *id;
    nodus_dht2_pull_t       *pull;
    char                     path[160];
    int                      idx;     /* index in g_n */
} node_t;

#define QCAP 600u

typedef struct {
    int                    from;
    int                    to;
    nodus_dht2_pull_msg_t  kind;
    uint8_t               *b;
    size_t                 n;
} qmsg_t;

static node_t  g_n[2];
static qmsg_t  g_q[QCAP];
static size_t  g_qh, g_qt;
static int     g_puller = 1;          /* who pulls: routes HELLO */
static int     g_sent[6];             /* messages sent, per kind */
static int     g_done, g_aborted, g_serve_fail;
static bool    g_drop_receipts;
static bool    g_fail_offer;          /* the send of a p_offer fails */
static const env_t *g_tamper0;        /* replaces delivery i == 0 */
static uint8_t g_last_offer[NODUS_DHT2_PULL_MSG_MAX];
static size_t  g_last_offer_n;
static uint8_t g_last_receipt[NODUS_DHT2_PULL_MSG_MAX];
static size_t  g_last_receipt_n;
static uint8_t g_scratch[DHT2_ENVELOPE_MAX];

static int send_cb(void *user, const uint8_t peer_fp[64],
                   nodus_dht2_pull_msg_t kind, const uint8_t *msg, size_t len)
{
    node_t  *me = (node_t *)user;
    qmsg_t  *m;
    int      to = -1, i;
    uint8_t *copy;

    g_sent[kind]++;
    if (kind == NODUS_DHT2_PULL_OFFER && g_fail_offer) {
        return -1;                          /* the peer is not reachable */
    }
    if (kind == NODUS_DHT2_PULL_OFFER) {
        memcpy(g_last_offer, msg, len);
        g_last_offer_n = len;
    }
    if (kind == NODUS_DHT2_PULL_RECEIPT) {
        memcpy(g_last_receipt, msg, len);
        g_last_receipt_n = len;
        if (g_drop_receipts) {
            return 0;                       /* the receipt is lost */
        }
    }
    for (i = 0; i < 2; i++) {
        if (memcmp(g_n[i].key.fp, peer_fp, DHT2_FP_LEN) == 0) {
            to = i;
        }
    }
    if (to < 0) {
        return 0;                           /* a peer that is not a node */
    }
    if (g_qt - g_qh >= QCAP) {
        return -1;
    }
    copy = (uint8_t *)malloc(len + 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, msg, len);
    m = &g_q[g_qt++ % QCAP];
    m->from = me->idx;
    m->to = to;
    m->kind = kind;
    m->b = copy;
    m->n = len;
    if (kind == NODUS_DHT2_PULL_DELIVER && g_tamper0 != NULL) {
        dht2_p_deliver_t d;

        if (dht2_p_deliver_decode(copy, len, &d) == DHT2_OK && d.i == 0) {
            static uint8_t tb[NODUS_DHT2_PULL_MSG_MAX];
            size_t         tl = 0;

            d.has_v = true;
            d.v = g_tamper0->b;
            d.v_len = g_tamper0->n;
            if (dht2_p_deliver_encode(&d, tb, sizeof(tb), &tl) == DHT2_OK) {
                free(m->b);
                m->b = (uint8_t *)malloc(tl + 1);
                memcpy(m->b, tb, tl);
                m->n = tl;
            }
        }
    }
    return 0;
}

/* Deliver the oldest message. */
static void step(void)
{
    qmsg_t  m;
    node_t *src, *dst;
    bool    req;
    int     rc;

    if (g_qh == g_qt) {
        return;
    }
    m = g_q[g_qh++ % QCAP];
    src = &g_n[m.from];
    dst = &g_n[m.to];
    req = m.kind == NODUS_DHT2_PULL_GET || m.kind == NODUS_DHT2_PULL_WANT ||
          m.kind == NODUS_DHT2_PULL_RECEIPT ||
          (m.kind == NODUS_DHT2_PULL_HELLO && m.from == g_puller);
    if (req) {
        rc = nodus_dht2_pull_serve(dst->pull, NOW, src->key.fp, m.kind, m.b,
                                   m.n);
        if (rc != 0) {
            g_serve_fail++;
        }
    } else {
        rc = nodus_dht2_pull_on_reply(dst->pull, NOW, src->key.fp, m.kind,
                                      m.b, m.n);
        if (rc == NODUS_DHT2_PULL_DONE) {
            g_done++;
        } else if (rc == NODUS_DHT2_PULL_ABORTED) {
            g_aborted++;
        }
    }
    free(m.b);
}

static void pump(void)
{
    size_t guard = 0;

    while (g_qh != g_qt && guard++ < 100000) {
        step();
    }
}

static void q_clear(void)
{
    while (g_qh != g_qt) {
        free(g_q[g_qh++ % QCAP].b);
    }
}

static void counters_reset(void)
{
    memset(g_sent, 0, sizeof(g_sent));
    g_done = g_aborted = g_serve_fail = 0;
}

/* ── node setup ──────────────────────────────────────────────────────── */

static void set_members(node_t *n, uint64_t e, size_t n0,
                        const uint8_t (*s0)[DHT2_FP_LEN], size_t n1,
                        const uint8_t (*s1)[DHT2_FP_LEN])
{
    memset(n->view.sets, 0, sizeof(*n->view.sets));
    n->view.sets->e = e;
    n->view.sets->n0 = (uint32_t)n0;
    n->view.sets->n1 = (uint32_t)n1;
    if (n0 > 0) {
        memcpy(n->view.sets->s0, s0, n0 * DHT2_FP_LEN);
    }
    if (n1 > 0) {
        memcpy(n->view.sets->s1, s1, n1 * DHT2_FP_LEN);
    }
    n->view.snap.epoch_start = e;
}

/* S(H) = {A, B}: every member is eligible and responsible for every key. */
static void set_pair(node_t *n)
{
    uint8_t s0[2][DHT2_FP_LEN];

    memcpy(s0[0], g_n[0].key.fp, DHT2_FP_LEN);
    memcpy(s0[1], g_n[1].key.fp, DHT2_FP_LEN);
    set_members(n, 720, 2, (const uint8_t (*)[DHT2_FP_LEN])s0, 0, NULL);
}

static int node_open(node_t *n)
{
    n->st = nodus_dht2_store_open(n->path, g_chain);
    if (n->st == NULL ||
        nodus_dht2_holder_init(&n->ho, n->st, n->id, g_chain, &n->hv) != 0) {
        return -1;
    }
    n->pull = nodus_dht2_pull_new(n->st, n->id, g_chain, &n->hv, send_cb, n);
    return n->pull != NULL ? 0 : -1;
}

static void node_close(node_t *n)
{
    nodus_dht2_pull_free(n->pull);
    n->pull = NULL;
    nodus_dht2_store_close(n->st);
    n->st = NULL;
}

static int node_init(node_t *n, int idx, const tkey_t *key)
{
    memset(n, 0, sizeof(*n));
    n->idx = idx;
    n->key = *key;
    n->id = (nodus_identity_t *)calloc(1, sizeof(*n->id));
    n->view.sets = (nodus_witness_dht_sets_t *)calloc(1, sizeof(*n->view.sets));
    if (n->id == NULL || n->view.sets == NULL) {
        return -1;
    }
    memcpy(n->id->pk.bytes, key->pk, DHT2_PUBKEY_LEN);
    memcpy(n->id->sk.bytes, key->sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(n->view.snap.chain_id, g_chain, DHT2_CHAIN_LEN);
    n->view.snap.height = 1000;
    n->view.snap.tip_time = T0;
    n->view.snap.consensus_up = true;
    n->view.have_snap = true;
    n->hv.snap = fv_snap;
    n->hv.sets = fv_sets;
    n->hv.name = fv_name;
    n->hv.user = &n->view;
    snprintf(n->path, sizeof(n->path), "%s/p%d.db", g_dir, g_db_n++);
    return 0;
}

static void node_free(node_t *n)
{
    node_close(n);
    free(n->view.sets);
    if (n->id != NULL) {
        memset(n->id, 0, sizeof(*n->id));
    }
    free(n->id);
}

/* Two fresh nodes A = g_n[0] (source) and B = g_n[1] (puller), S(H) = {A, B}. */
static int net_up(const tkey_t *ka, const tkey_t *kb)
{
    node_t *a = &g_n[0], *b = &g_n[1];

    q_clear();
    counters_reset();
    g_drop_receipts = false;
    g_fail_offer = false;
    g_tamper0 = NULL;
    g_puller = 1;
    if (node_init(a, 0, ka) != 0 || node_init(b, 1, kb) != 0) {
        return -1;
    }
    set_pair(a);
    set_pair(b);
    return (node_open(a) == 0 && node_open(b) == 0) ? 0 : -1;
}

static void net_down(void)
{
    q_clear();
    node_free(&g_n[0]);
    node_free(&g_n[1]);
}

/* ── fixtures on a node ──────────────────────────────────────────────── */

static int put_at(node_t *n, const env_t *r, nodus_dht2_put_t *res)
{
    nodus_dht2_world_t w;

    nodus_dht2_holder_world_load(&n->ho, NOW, &w);
    return nodus_dht2_store_put(n->st, &w.ctx, r->b, r->n, NULL, res);
}

static int get_at(node_t *n, const uint8_t addr[DHT2_HASH_LEN],
                  uint8_t hash[DHT2_HASH_LEN])
{
    nodus_dht2_world_t w;
    size_t             len = 0;

    nodus_dht2_holder_world_load(&n->ho, NOW, &w);
    return nodus_dht2_store_get(n->st, &w.ctx, addr, g_scratch,
                                sizeof(g_scratch), &len, hash);
}

/* B holds `addr` with exactly the hash of `r`. */
static bool holds(node_t *n, const uint8_t addr[DHT2_HASH_LEN], const env_t *r)
{
    uint8_t h[DHT2_HASH_LEN];

    return get_at(n, addr, h) == NODUS_DHT2_GET_HELD && hash_is(r, h);
}

static bool not_held(node_t *n, const uint8_t addr[DHT2_HASH_LEN])
{
    uint8_t h[DHT2_HASH_LEN];

    return get_at(n, addr, h) == NODUS_DHT2_GET_NOT_HELD;
}

static uint64_t cursor_of(node_t *puller, const node_t *src, bool *found,
                          uint64_t *gen)
{
    uint64_t g = 0, c = 0;

    *found = false;
    (void)nodus_dht2_store_pull_get(puller->st, src->key.fp, found, &g, &c);
    if (gen != NULL) {
        *gen = g;
    }
    return c;
}

static uint64_t top_of(node_t *n)
{
    uint64_t t = 0;

    (void)nodus_dht2_store_top(n->st, &t);
    return t;
}

/* B pulls from A until the queue is empty. */
static void pull_all(void)
{
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "exchange started");
    pump();
}

/* ══ tests ═════════════════════════════════════════════════════════════ */

static void test_basic(const tkey_t *ka, const tkey_t *kb, const tkey_t *kw)
{
    env_t           *r = (env_t *)calloc(3, sizeof(env_t));
    uint8_t          addr[3][DHT2_HASH_LEN];
    nodus_dht2_put_t pr;
    bool             found;
    uint64_t         gen, cur;
    int              i, getn;
    dht2_env_t       env;
    dht2_pull_receipt_t *rc;

    CHECK(r != NULL && net_up(ka, kb) == 0, "two nodes");

    /* An empty source: the offer is empty, its top is 0, the cursor 1. */
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, &gen);
    CHECK(g_done == 1 && g_aborted == 0 && g_serve_fail == 0,
          "empty source: the exchange ends normally");
    CHECK(found && cur == 1 && gen == nodus_dht2_store_generation(g_n[0].st),
          "empty source: cursor 1 with the source's generation");
    CHECK(g_sent[NODUS_DHT2_PULL_WANT] == 0 &&
              g_sent[NODUS_DHT2_PULL_RECEIPT] == 0,
          "empty offer: no p_want, no receipt (PS:253-255, PS:179-181)");

    for (i = 0; i < 3; i++) {
        CHECK(mk_rec(&r[i], addr[i], kw, (uint32_t)i, 1, false) == 0 &&
                  put_at(&g_n[0], &r[i], &pr) == 0, "record stored at A");
    }
    counters_reset();
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "exchange started");
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_BUSY, "row 12: one exchange per source in flight");
    pump();
    CHECK(g_done == 1 && g_aborted == 0 && g_serve_fail == 0,
          "exchange ends normally, nothing refused");
    for (i = 0; i < 3; i++) {
        CHECK(holds(&g_n[1], addr[i], &r[i]),
              "B holds the record with the canonical hash");
    }
    cur = cursor_of(&g_n[1], &g_n[0], &found, &gen);
    CHECK(found && cur == top_of(&g_n[0]) + 1 && cur == 4 &&
              gen == nodus_dht2_store_generation(g_n[0].st),
          "cursor = top + 1, generation of the source");
    CHECK(g_sent[NODUS_DHT2_PULL_DELIVER] == 3 &&
              g_sent[NODUS_DHT2_PULL_RECEIPT] == 1,
          "one p_deliver per wanted entry, ONE pull-receipt");

    /* The receipt: type, domain, signer, fields, stored entries in order. */
    rc = (dht2_pull_receipt_t *)malloc(sizeof(*rc));
    CHECK(rc != NULL &&
              dht2_env_decode(g_last_receipt, g_last_receipt_n,
                              DHT2_ENVELOPE_MAX, &env) == DHT2_OK,
          "receipt decodes as an envelope");
    if (rc != NULL) {
        CHECK(env.payload_type_len == strlen(DHT2_PT_PULL_RECEIPT) &&
                  memcmp(env.payload_type, DHT2_PT_PULL_RECEIPT,
                         env.payload_type_len) == 0,
              "payload type /nodus/dht/pull-receipt/v1");
        CHECK(dht2_env_verify(&env, DHT2_DOMAIN_ANSWER) == DHT2_OK,
              "verifies under nodus.dht.answer.v1");
        CHECK(dht2_env_verify(&env, DHT2_DOMAIN_LIST) != DHT2_OK &&
                  dht2_env_verify(&env, DHT2_DOMAIN_ADDR) != DHT2_OK,
              "does not verify under another domain");
        CHECK(memcmp(env.fp, g_n[1].key.fp, DHT2_FP_LEN) == 0,
              "signed by the puller");
        CHECK(dht2_pull_receipt_decode(env.payload, env.payload_len, rc)
                  == DHT2_OK, "receipt payload decodes");
        CHECK(memcmp(rc->pf, g_n[1].key.fp, DHT2_FP_LEN) == 0 &&
                  memcmp(rc->sf, g_n[0].key.fp, DHT2_FP_LEN) == 0 &&
                  memcmp(rc->c, g_chain, DHT2_CHAIN_LEN) == 0 &&
                  rc->g == nodus_dht2_store_generation(g_n[0].st) &&
                  rc->s == 1 && rc->top == 3 && rc->e_count == 3,
              "pf, sf, c, g, s, top, e_count");
        for (i = 0; i < 3 && rc->e_count == 3; i++) {
            CHECK(memcmp(rc->e[i].a, addr[i], DHT2_HASH_LEN) == 0 &&
                      hash_is(&r[i], rc->e[i].h),
                  "stored entry {a, h} in offer order");
        }
        free(rc);
    }

    /* Nothing new: the hello shows cursor > top, no p_get is sent. */
    counters_reset();
    pull_all();
    getn = g_sent[NODUS_DHT2_PULL_GET];
    CHECK(g_done == 1 && getn == 0, "caught up: no p_get");

    net_down();
    free(r);
}

static void test_more_than_250(const tkey_t *ka, const tkey_t *kb,
                               const tkey_t *kw)
{
    env_t    *r = (env_t *)calloc(300, sizeof(env_t));
    uint8_t (*addr)[DHT2_HASH_LEN] =
        (uint8_t (*)[DHT2_HASH_LEN])calloc(300, DHT2_HASH_LEN);
    nodus_dht2_put_t pr;
    bool     found;
    uint64_t cur;
    uint32_t i;

    CHECK(r != NULL && addr != NULL && net_up(ka, kb) == 0, "two nodes");
    for (i = 0; i < 300; i++) {
        if (mk_rec(&r[i], addr[i], kw, i, 1, false) != 0 ||
            put_at(&g_n[0], &r[i], &pr) != 0) {
            CHECK(false, "record stored at A");
            break;
        }
    }
    CHECK(top_of(&g_n[0]) == 300, "A holds 300 records");

    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && g_aborted == 0, "first exchange ends normally");
    CHECK(found && cur == 251, "first page: 250 entries, cursor 251");
    CHECK(holds(&g_n[1], addr[249], &r[249]) && not_held(&g_n[1], addr[250]),
          "B holds index 250 and not yet 251");
    CHECK(g_sent[NODUS_DHT2_PULL_DELIVER] == 250, "250 deliveries");

    counters_reset();
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(found && cur == 301 && g_sent[NODUS_DHT2_PULL_DELIVER] == 50,
          "second page: 50 entries, cursor 301");
    CHECK(holds(&g_n[1], addr[299], &r[299]), "B holds the last record");

    net_down();
    free(r);
    free(addr);
}

static void test_replacement(const tkey_t *ka, const tkey_t *kb,
                             const tkey_t *kw)
{
    env_t            v1, v2;
    uint8_t          addr[DHT2_HASH_LEN], addr2[DHT2_HASH_LEN];
    nodus_dht2_put_t pr;
    bool             found;
    uint64_t         cur;
    int              delivers;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&v1, addr, kw, 5, 1, false) == 0 &&
              mk_rec(&v2, addr2, kw, 5, 2, false) == 0 &&
              memcmp(addr, addr2, DHT2_HASH_LEN) == 0,
          "two versions of one address");
    CHECK(put_at(&g_n[0], &v1, &pr) == 0, "v1 at A");

    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "started");
    step(); step(); step(); step();   /* hello, hello, get, OFFER at B */
    CHECK(g_sent[NODUS_DHT2_PULL_WANT] == 1 && g_sent[NODUS_DHT2_PULL_DELIVER] == 0,
          "the offer (v1) is out, the delivery is not");
    CHECK(put_at(&g_n[0], &v2, &pr) == 0, "v2 replaces v1 at A, re-indexed");
    pump();
    CHECK(g_done == 1 && g_aborted == 0, "exchange ends normally");
    CHECK(holds(&g_n[1], addr, &v2),
          "B holds the NOW-held version (v2), not the offered one");
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(found && cur == 2, "cursor = the OFFER's top + 1");

    counters_reset();
    pull_all();
    delivers = g_sent[NODUS_DHT2_PULL_DELIVER];
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && delivers == 0 && cur == 3,
          "the re-indexed entry is offered again; B holds it, no delivery");

    net_down();
}

static void test_generation(const tkey_t *ka, const tkey_t *kb, const tkey_t *kw)
{
    env_t            r[5];
    uint8_t          addr[5][DHT2_HASH_LEN];
    nodus_dht2_put_t pr;
    bool             found;
    uint64_t         cur, gen, old_gen, wrong;
    uint8_t          mb[64];
    size_t           ml = 0;
    int              i;
    dht2_p_get_t     gm;
    dht2_p_offer_t  *of;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    for (i = 0; i < 5; i++) {
        CHECK(mk_rec(&r[i], addr[i], kw, (uint32_t)i, 1, false) == 0, "rec");
    }
    for (i = 0; i < 3; i++) {
        CHECK(put_at(&g_n[0], &r[i], &pr) == 0, "stored at A");
    }
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, &old_gen);
    CHECK(found && cur == 4, "cursor 4 after the first source");

    /* A's store is replaced by a fresh one: a new generation g. */
    node_close(&g_n[0]);
    snprintf(g_n[0].path, sizeof(g_n[0].path), "%s/p%d.db", g_dir, g_db_n++);
    CHECK(node_open(&g_n[0]) == 0, "A with a fresh store");
    CHECK(nodus_dht2_store_generation(g_n[0].st) != old_gen,
          "the fresh store has another generation");
    for (i = 3; i < 5; i++) {
        CHECK(put_at(&g_n[0], &r[i], &pr) == 0, "stored at the fresh A");
    }
    counters_reset();
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, &gen);
    CHECK(g_done == 1 && g_aborted == 0, "exchange ends normally");
    CHECK(found && gen == nodus_dht2_store_generation(g_n[0].st) && cur == 3,
          "generation changed: re-scanned from 0, new generation stored");
    CHECK(g_sent[NODUS_DHT2_PULL_DELIVER] == 2 &&
              holds(&g_n[1], addr[3], &r[3]) && holds(&g_n[1], addr[4], &r[4]),
          "both records of the fresh source pulled");

    /* A p_get for another generation is dropped (row 12: g change aborts). */
    counters_reset();
    gm.g = nodus_dht2_store_generation(g_n[0].st) ^ 1u;
    gm.s = 0;
    CHECK(dht2_p_get_encode(&gm, mb, sizeof(mb), &ml) == DHT2_OK &&
              nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                    NODUS_DHT2_PULL_GET, mb, ml) == -1 &&
              g_sent[NODUS_DHT2_PULL_OFFER] == 0,
          "p_get for another generation: dropped, no offer");

    /* A p_offer of another generation aborts the exchange, cursor kept. */
    q_clear();
    CHECK(nodus_dht2_store_pull_set(g_n[1].st, g_n[0].key.fp,
                                    nodus_dht2_store_generation(g_n[0].st), 0)
              == 0, "cursor back to 0");
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "started");
    step(); step();                  /* hello, hello reply -> p_get queued */
    q_clear();                       /* the real offer never arrives */
    of = (dht2_p_offer_t *)calloc(1, sizeof(*of));
    if (of != NULL) {
        uint8_t *ob = (uint8_t *)malloc(NODUS_DHT2_PULL_MSG_MAX);
        size_t   ol = 0;

        of->g = nodus_dht2_store_generation(g_n[0].st) ^ 1u;
        of->top = 5;
        of->e_count = 0;
        CHECK(ob != NULL &&
                  dht2_p_offer_encode(of, ob, NODUS_DHT2_PULL_MSG_MAX, &ol)
                      == DHT2_OK &&
                  nodus_dht2_pull_on_reply(g_n[1].pull, NOW, g_n[0].key.fp,
                                           NODUS_DHT2_PULL_OFFER, ob, ol)
                      == NODUS_DHT2_PULL_ABORTED,
              "an offer of another generation aborts the exchange");
        free(ob);
        free(of);
    }
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(found && cur == 0, "the cursor was not advanced");
    wrong = (uint64_t)nodus_dht2_pull_start(g_n[1].pull, NOW,
                                            g_n[0].key.fp);
    CHECK(wrong == NODUS_DHT2_PULL_STARTED,
          "the aborted exchange is gone: a new one starts");
    q_clear();

    net_down();
}

/* The six-member set of the hand-over tests: A, B, the writer W (a real key,
 * so it can sign the second receipt) and three fakes. */
static uint8_t g_s6[6][DHT2_FP_LEN];

static void build_s6(const tkey_t *w)
{
    int k;

    memcpy(g_s6[0], g_n[0].key.fp, DHT2_FP_LEN);
    memcpy(g_s6[1], g_n[1].key.fp, DHT2_FP_LEN);
    memcpy(g_s6[2], w->fp, DHT2_FP_LEN);
    /* The fakes spread over the keyspace (0x20, 0x60, 0xA0).
     * With all four at 0xE2-0xE5 (the first version) A (fp 0x64…) and B
     * (0x43…) share the top bit against all of them, so no key can put B in
     * nearest_R while leaving A out — the hand-over fixture search could
     * never succeed (found by the ORCHESTRATOR's run, 2026-10-27). */
    for (k = 3; k < 6; k++) {
        memset(g_s6[k], 0x20 + 0x40 * (k - 3), DHT2_FP_LEN);
    }
}

static bool in_nr(const uint8_t key[DHT2_HASH_LEN], const uint8_t fp[DHT2_FP_LEN])
{
    size_t idx[DHT2_R];
    int    n = dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 6, idx), i;

    for (i = 0; i < n; i++) {
        if (memcmp(g_s6[idx[i]], fp, DHT2_FP_LEN) == 0) {
            return true;
        }
    }
    return false;
}

/* A receipt envelope as `signer` would seal it. */
static int mk_receipt(uint8_t *out, size_t cap, size_t *olen, const char *domain,
                      const char *pt, const tkey_t *signer,
                      const uint8_t pf[DHT2_FP_LEN],
                      const uint8_t sf[DHT2_FP_LEN], uint64_t g,
                      const uint8_t a[DHT2_HASH_LEN],
                      const uint8_t h[DHT2_HASH_LEN])
{
    dht2_pull_receipt_t *r = (dht2_pull_receipt_t *)calloc(1, sizeof(*r));
    uint8_t              pay[4096];
    size_t               pl = 0;
    int                  rc = -1;

    if (r == NULL) {
        return -1;
    }
    memcpy(r->pf, pf, DHT2_FP_LEN);
    memcpy(r->sf, sf, DHT2_FP_LEN);
    memcpy(r->c, g_chain, DHT2_CHAIN_LEN);
    r->g = g;
    r->s = 1;
    r->top = 1;
    r->e_count = 1;
    memcpy(r->e[0].a, a, DHT2_HASH_LEN);
    memcpy(r->e[0].h, h, DHT2_HASH_LEN);
    if (dht2_pull_receipt_encode(r, pay, sizeof(pay), &pl) == DHT2_OK &&
        dht2_env_seal(domain, (const uint8_t *)pt, strlen(pt), pay, pl,
                      signer->sk, signer->pk, out, cap, olen) == DHT2_OK) {
        rc = 0;
    }
    free(r);
    return rc;
}

static bool pending_at(node_t *n, const uint8_t addr[DHT2_HASH_LEN])
{
    bool pending = false, found = false;

    (void)nodus_dht2_store_handover_get(n->st, addr, &pending, &found);
    return found && pending;
}

/* An acknowledgement of `fp` is stored at A for `addr`. */
static bool acked_by(node_t *n, const uint8_t addr[DHT2_HASH_LEN],
                     const uint8_t fp[DHT2_FP_LEN])
{
    bool has = false;

    (void)nodus_dht2_store_handover_ack_has(n->st, addr, fp, &has);
    return has;
}

/* The record `r` is stored again at A (after a drop: a NEW row). */
/* Store `r` at A again after a drop. The holder admits a write only when it
 * is in eligible(placement key) (§4.1), and under S6 A is not — so the put
 * runs under S(H) = {A, B} and A's sets are restored afterwards. */
static bool reput_at_a(const env_t *r)
{
    nodus_dht2_put_t          pr;
    nodus_witness_dht_sets_t *save = malloc(sizeof(*save));
    bool                      ok;

    if (save == NULL) {
        return false;
    }
    memcpy(save, g_n[0].view.sets, sizeof(*save));
    set_pair(&g_n[0]);
    ok = put_at(&g_n[0], r, &pr) == 0 && pr.outcome == NODUS_DHT2_PUT_STORED;
    memcpy(g_n[0].view.sets, save, sizeof(*save));
    g_n[0].view.snap.epoch_start = save->e;
    free(save);
    return ok;
}

/* The 48-epoch wait (decision 2026-10-27-dht-v2-handover-one-receipt.md,
 * operator "evet"): the drop is due WAIT_E blocks after the epoch the quorum
 * was met. epoch_at_a moves A's sets to epoch `e` (members unchanged) and
 * runs its epoch check. */
#define WAIT_E ((uint64_t)NODUS_DHT2_PULL_DROP_WAIT_EPOCHS * \
                (uint64_t)DNAC_EPOCH_LENGTH)

static bool epoch_at_a(uint64_t e)
{
    g_n[0].view.sets->e = e;
    g_n[0].view.snap.epoch_start = e;
    return nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0;
}

/* The drop of `addr` is scheduled at A for epoch `due`. */
static bool due_at(const uint8_t addr[DHT2_HASH_LEN], uint64_t due)
{
    bool     found = false;
    uint64_t de = 0;
    uint8_t  h[DHT2_HASH_LEN];

    return nodus_dht2_store_handover_retire_get(g_n[0].st, addr, &found, &de,
                                                h) == 0 &&
           found && de == due;
}

/* A's pull_serve of a valid receipt that `signer` sends for (addr, h) with
 * generation g. Returns the serve result, or -2 when the receipt could not
 * be built. */
static int receipt_from(const tkey_t *signer, uint64_t g,
                        const uint8_t addr[DHT2_HASH_LEN],
                        const uint8_t h[DHT2_HASH_LEN])
{
    static uint8_t rb[16384];
    size_t         rl = 0;

    if (mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_ANSWER,
                   DHT2_PT_PULL_RECEIPT, signer, signer->fp, g_n[0].key.fp, g,
                   addr, h) != 0) {
        return -2;
    }
    return nodus_dht2_pull_serve(g_n[0].pull, NOW, signer->fp,
                                 NODUS_DHT2_PULL_RECEIPT, rb, rl);
}

static void test_handover(const tkey_t *ka, const tkey_t *kb, const tkey_t *kw,
                          const tkey_t *kc)
{
    env_t            p;
    uint8_t          addr[DHT2_HASH_LEN], hash[DHT2_HASH_LEN], wid[DHT2_ID_LEN];
    nodus_dht2_put_t pr;
    uint32_t         idn;
    bool             found;
    uint64_t         gen_before, cur;
    int              k;
    uint8_t          rb[16384];
    size_t           rl = 0;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    build_s6(kw);
    g_n[0].view.named_all = true;      /* permanent records need a name */
    g_n[1].view.named_all = true;

    /* A record B and W are responsible for and A is not eligible for, under
     * S6 (two real members in nearest_R: the two receipts come from them). */
    for (idn = 0; idn < 5000; idn++) {
        fill_id(wid, idn);
        if (dht2_address(wid, kw->fp, addr) != 0) {
            continue;
        }
        if (dht2_eligible(addr, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 6, NULL,
                          0, g_n[0].key.fp) == 0 &&
            in_nr(addr, g_n[1].key.fp) && in_nr(addr, kw->fp)) {
            break;
        }
    }
    CHECK(idn < 5000,
          "a record with A not eligible, B and W responsible exists");
    CHECK(mk_rec(&p, addr, kw, idn, 1, true) == 0 &&
              put_at(&g_n[0], &p, &pr) == 0,
          "permanent record stored at A while S(H) = {A, B}");
    CHECK(!pending_at(&g_n[0], addr), "no hand-over flag yet");

    /* The epoch moves: S(H) = S6, S(H - E) empty. */
    set_members(&g_n[0], 1440, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0, NULL);
    set_members(&g_n[1], 1440, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0, NULL);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0,
          "epoch check at A");
    CHECK(pending_at(&g_n[0], addr),
          "§4.5 v: the permanent record A no longer holds is flagged");
    CHECK(nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 0,
          "epoch check at B");

    /* B pulls; the receipt is lost. */
    g_drop_receipts = true;
    pull_all();
    CHECK(g_done == 1 && holds(&g_n[1], addr, &p), "B pulled the record");
    CHECK(g_sent[NODUS_DHT2_PULL_RECEIPT] == 1 && pending_at(&g_n[0], addr),
          "the receipt was lost: the flag stays");

    /* A restarts: the flag persists, the record is still offered. */
    gen_before = nodus_dht2_store_generation(g_n[0].st);
    node_close(&g_n[0]);
    CHECK(node_open(&g_n[0]) == 0, "A reopened");
    CHECK(nodus_dht2_store_generation(g_n[0].st) == gen_before,
          "same generation after the reopen");
    CHECK(pending_at(&g_n[0], addr), "the hand-over flag survived the reopen");

    g_drop_receipts = false;
    CHECK(nodus_dht2_store_pull_reset(g_n[1].st) == 0, "B re-scans from 0");
    counters_reset();
    pull_all();
    CHECK(g_done == 1 && g_sent[NODUS_DHT2_PULL_DELIVER] == 0 &&
              g_sent[NODUS_DHT2_PULL_RECEIPT] == 1,
          "A offered the flagged record again; B held it: no delivery, a receipt");
    CHECK(g_serve_fail == 0 && pending_at(&g_n[0], addr),
          "ONE member's receipt (B) leaves the flag: two are needed");
    CHECK(get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
          "A still holds it");
    CHECK(acked_by(&g_n[0], addr, g_n[1].key.fp), "B's acknowledgement stored");
    CHECK(receipt_from(kw, nodus_dht2_store_generation(g_n[0].st), addr, hash)
              == 0 && get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD &&
              due_at(addr, 1440 + WAIT_E),
          "the receipt of a second DISTINCT member (W) met the quorum: the "
          "drop is scheduled 48 epochs on, the record still held");
    CHECK(epoch_at_a(1440 + WAIT_E - (uint64_t)DNAC_EPOCH_LENGTH) &&
              get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
          "one epoch before the due epoch: still held");
    CHECK(epoch_at_a(1440 + WAIT_E) && not_held(&g_n[0], addr),
          "at the due epoch the record is DROPPED at the source");
    CHECK(!acked_by(&g_n[0], addr, g_n[1].key.fp) &&
              !acked_by(&g_n[0], addr, kw->fp),
          "its acknowledgements went with the row");
    CHECK(receipt_from(kb, nodus_dht2_store_generation(g_n[0].st), addr, hash)
              == 0 && not_held(&g_n[0], addr) &&
              !acked_by(&g_n[0], addr, g_n[1].key.fp),
          "a receipt after the drop does nothing (no row, no new ack)");

    /* Receipts that must not retire: the record is stored again. */
    CHECK(reput_at_a(&p), "the record is stored again at A");
    CHECK(get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD, "A holds it");
    gen_before = nodus_dht2_store_generation(g_n[0].st);
    for (k = 0; k < 6; k++) {
        bool f;

        CHECK(nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0 && f,
              "flag set again");
        switch (k) {
        case 0:   /* wrong payload type */
            CHECK(mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_ANSWER,
                             DHT2_PT_ANSWER, kb, g_n[1].key.fp, g_n[0].key.fp,
                             gen_before, addr, hash) == 0 &&
                      nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                            NODUS_DHT2_PULL_RECEIPT, rb, rl)
                          == -1,
                  "receipt with another payload type: refused");
            break;
        case 1:   /* wrong domain */
            CHECK(mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_LIST,
                             DHT2_PT_PULL_RECEIPT, kb, g_n[1].key.fp,
                             g_n[0].key.fp, gen_before, addr, hash) == 0 &&
                      nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                            NODUS_DHT2_PULL_RECEIPT, rb, rl)
                          == -1,
                  "receipt under another domain: refused");
            break;
        case 2:   /* signed by B, sent by another peer */
            CHECK(mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_ANSWER,
                             DHT2_PT_PULL_RECEIPT, kb, g_n[1].key.fp,
                             g_n[0].key.fp, gen_before, addr, hash) == 0 &&
                      nodus_dht2_pull_serve(g_n[0].pull, NOW, g_s6[2],
                                            NODUS_DHT2_PULL_RECEIPT, rb, rl)
                          == -1,
                  "receipt not from its signer's session: refused");
            break;
        case 3:   /* a signer that is not in nearest_R(S(H)) of the record */
            CHECK(mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_ANSWER,
                             DHT2_PT_PULL_RECEIPT, kc, kc->fp, g_n[0].key.fp,
                             gen_before, addr, hash) == 0 &&
                      nodus_dht2_pull_serve(g_n[0].pull, NOW, kc->fp,
                                            NODUS_DHT2_PULL_RECEIPT, rb, rl)
                          == 0,
                  "receipt of a stranger: handled");
            break;
        case 4: { /* the member names another hash */
            uint8_t other[DHT2_HASH_LEN];

            memset(other, 0x42, sizeof(other));
            CHECK(mk_receipt(rb, sizeof(rb), &rl, DHT2_DOMAIN_ANSWER,
                             DHT2_PT_PULL_RECEIPT, kb, g_n[1].key.fp,
                             g_n[0].key.fp, gen_before, addr, other) == 0 &&
                      nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                            NODUS_DHT2_PULL_RECEIPT, rb, rl)
                          == 0,
                  "receipt naming another hash: handled");
            break;
        }
        default:  /* the right ones: two DISTINCT members */
            CHECK(receipt_from(kb, gen_before, addr, hash) == 0,
                  "the right receipt of B: handled");
            CHECK(pending_at(&g_n[0], addr), "one receipt: the flag stays");
            CHECK(receipt_from(kb, gen_before, addr, hash) == 0 &&
                      pending_at(&g_n[0], addr),
                  "the same member twice counts once: the flag stays");
            CHECK(receipt_from(kc, gen_before, addr, hash) == 0 &&
                      pending_at(&g_n[0], addr),
                  "a signer outside nearest_R after B's: still not retired");
            CHECK(receipt_from(kw, gen_before, addr, hash) == 0,
                  "the right receipt of W: handled");
            break;
        }
        if (k < 5) {
            CHECK(pending_at(&g_n[0], addr), "the flag stays");
        } else {
            const uint64_t cur_e = g_n[0].view.sets->e;

            CHECK(due_at(addr, cur_e + WAIT_E) &&
                      get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
                  "a second distinct member's receipt schedules the drop");
            CHECK(epoch_at_a(cur_e + WAIT_E) && not_held(&g_n[0], addr),
                  "dropped at the due epoch");
        }
    }
    CHECK(reput_at_a(&p), "the record is stored again for the offer checks");

    /* Eligibility of the puller (row 12 "only to a puller in eligible(p)"). */
    {
        dht2_p_get_t     gm;
        dht2_p_offer_t  *of = (dht2_p_offer_t *)calloc(1, sizeof(*of));
        uint8_t          mb[64], outsider[DHT2_FP_LEN];
        size_t           ml = 0;
        int              j;
        bool             have_out = false;

        for (j = 2; j < 6; j++) {
            if (!in_nr(addr, g_s6[j])) {
                memcpy(outsider, g_s6[j], DHT2_FP_LEN);
                have_out = true;
            }
        }
        CHECK(have_out && of != NULL, "a member outside nearest_R exists");
        gm.g = nodus_dht2_store_generation(g_n[0].st);
        gm.s = 0;
        CHECK(dht2_p_get_encode(&gm, mb, sizeof(mb), &ml) == DHT2_OK, "p_get");
        if (have_out && of != NULL) {
            q_clear();
            CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, outsider,
                                        NODUS_DHT2_PULL_GET, mb, ml) == 0 &&
                      dht2_p_offer_decode(g_last_offer, g_last_offer_n, of)
                          == DHT2_OK &&
                      of->e_count == 0 && of->top == top_of(&g_n[0]),
                  "a member outside nearest_R gets an empty offer, top = scanned");
            CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                        NODUS_DHT2_PULL_GET, mb, ml) == 0 &&
                      dht2_p_offer_decode(g_last_offer, g_last_offer_n, of)
                          == DHT2_OK &&
                      of->e_count == 1 &&
                      memcmp(of->e[0].a, addr, DHT2_HASH_LEN) == 0 &&
                      memcmp(of->e[0].p, addr, DHT2_HASH_LEN) == 0,
                  "a member of nearest_R gets the entry with its hint");
            q_clear();
        }
        free(of);
    }

    (void)cur;
    (void)found;
    net_down();
}

/* The two-receipt rule's remaining arms: the acknowledging fps persist, an
 * acknowledger that left nearest_R does not count at drop time, a membership
 * change alone meets the quorum at the epoch check, and with |nearest_R| = 1
 * one receipt drops the record. */
static void test_handover_quorum(const tkey_t *ka, const tkey_t *kb,
                                 const tkey_t *kw)
{
    env_t            p;
    uint8_t          addr[DHT2_HASH_LEN], hash[DHT2_HASH_LEN], wid[DHT2_ID_LEN];
    uint8_t          alt[6][DHT2_FP_LEN];
    nodus_dht2_put_t pr;
    uint32_t         idn;
    uint64_t         gen;
    bool             f;
    size_t           idx[DHT2_R];
    int              cnt, i;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    build_s6(kw);
    /* alt = S6 with B's slot taken by a fake: B has left the set. */
    memcpy(alt, g_s6, sizeof(alt));
    memset(alt[1], 0xE0, DHT2_FP_LEN);
    g_n[0].view.named_all = true;
    g_n[1].view.named_all = true;

    /* A not eligible under S6; B and W in nearest_R under S6; and W still in
     * nearest_R under alt (so W's receipt is valid there while B's ack is
     * not counted). */
    for (idn = 0; idn < 5000; idn++) {
        fill_id(wid, idn);
        if (dht2_address(wid, kw->fp, addr) != 0) {
            continue;
        }
        cnt = dht2_nearest_r(addr, (const uint8_t (*)[DHT2_FP_LEN])alt, 6, idx);
        if (dht2_eligible(addr, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 6, NULL,
                          0, g_n[0].key.fp) == 0 &&
            in_nr(addr, g_n[1].key.fp) && in_nr(addr, kw->fp) && cnt > 0) {
            bool w_in = false;

            for (i = 0; i < cnt; i++) {
                if (memcmp(alt[idx[i]], kw->fp, DHT2_FP_LEN) == 0) {
                    w_in = true;
                }
            }
            if (w_in) {
                break;
            }
        }
    }
    CHECK(idn < 5000, "a record for the quorum fixtures exists");
    CHECK(mk_rec(&p, addr, kw, idn, 1, true) == 0 &&
              put_at(&g_n[0], &p, &pr) == 0, "permanent record at A");
    set_members(&g_n[0], 1440, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0, NULL);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              pending_at(&g_n[0], addr), "flagged at the epoch check");
    CHECK(get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD, "A holds it");
    gen = nodus_dht2_store_generation(g_n[0].st);

    /* The acknowledgement persists: B's receipt, A restarts, W's receipt. */
    CHECK(receipt_from(kb, gen, addr, hash) == 0 && pending_at(&g_n[0], addr),
          "B's receipt: the flag stays");
    node_close(&g_n[0]);
    CHECK(node_open(&g_n[0]) == 0, "A reopened");
    CHECK(pending_at(&g_n[0], addr), "still pending after the reopen");
    CHECK(receipt_from(kw, gen, addr, hash) == 0 &&
              due_at(addr, 1440 + WAIT_E),
          "B's acknowledgement survived the reopen: W's receipt meets the "
          "quorum, the drop is scheduled");
    CHECK(epoch_at_a(1440 + WAIT_E) && not_held(&g_n[0], addr),
          "dropped at the due epoch");

    /* An acknowledger that left nearest_R does not count. */
    CHECK(reput_at_a(&p) &&
              nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0 &&
              f, "stored again, obligation again (a new row: no old acks)");
    CHECK(!acked_by(&g_n[0], addr, g_n[1].key.fp) &&
              !acked_by(&g_n[0], addr, kw->fp),
          "no acknowledgement survived the drop");
    CHECK(receipt_from(kb, gen, addr, hash) == 0 && pending_at(&g_n[0], addr),
          "B's receipt: the flag stays");
    set_members(&g_n[0], 1440, 6, (const uint8_t (*)[DHT2_FP_LEN])alt, 0, NULL);
    CHECK(receipt_from(kw, gen, addr, hash) == 0 && pending_at(&g_n[0], addr),
          "B is no longer in nearest_R: its acknowledgement does not count");
    set_members(&g_n[0], 1440, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0, NULL);
    CHECK(receipt_from(kw, gen, addr, hash) == 0 &&
              due_at(addr, 1440 + WAIT_E) &&
              get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
          "back in nearest_R, B counts again: the drop is scheduled");

    /* At the due epoch the quorum is re-counted: S(H) without A and B (A is
     * not eligible, B's acknowledgement no longer counts) → NOT dropped;
     * back to S6 one epoch later → dropped. */
    {
        uint8_t noab[5][DHT2_FP_LEN];

        memcpy(noab[0], alt[1], DHT2_FP_LEN);       /* the fake in B's slot */
        memcpy(noab[1], kw->fp, DHT2_FP_LEN);
        memcpy(noab[2], g_s6[3], DHT2_FP_LEN);
        memcpy(noab[3], g_s6[4], DHT2_FP_LEN);
        memcpy(noab[4], g_s6[5], DHT2_FP_LEN);
        set_members(&g_n[0], 1440 + WAIT_E, 5,
                    (const uint8_t (*)[DHT2_FP_LEN])noab, 0, NULL);
        CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
                  get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD &&
                  pending_at(&g_n[0], addr),
              "due, but the quorum is no longer met: NOT dropped");
        set_members(&g_n[0], 1440 + WAIT_E + (uint64_t)DNAC_EPOCH_LENGTH, 6,
                    (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0, NULL);
        CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
                  not_held(&g_n[0], addr),
              "met again after the due epoch: dropped");
    }

    /* Membership alone meets the quorum (no new receipt): the record is
     * pending with B's acknowledgement stored, then S(H) shrinks to {B}. */
    {
        uint8_t one[1][DHT2_FP_LEN];

        memcpy(one[0], g_n[1].key.fp, DHT2_FP_LEN);
        CHECK(reput_at_a(&p) &&
                  nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0
                  && f, "stored again, obligation again");
        CHECK(receipt_from(kb, gen, addr, hash) == 0 &&
                  pending_at(&g_n[0], addr) &&
                  acked_by(&g_n[0], addr, g_n[1].key.fp),
              "B's receipt under S6: stored, the flag stays (two are needed)");

        /* The quorum is NOT met at the epoch check: still pending, the
         * acknowledgement kept. */
        set_members(&g_n[0], 2160, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0,
                    NULL);
        CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
                  pending_at(&g_n[0], addr) &&
                  acked_by(&g_n[0], addr, g_n[1].key.fp) &&
                  get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
              "epoch check, quorum not met: still pending, ack kept, held");

        /* S(H) = {B}: |nearest_R| = 1, B's stored acknowledgement meets it. */
        set_members(&g_n[0], 2880, 1, (const uint8_t (*)[DHT2_FP_LEN])one, 0,
                    NULL);
        CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
                  get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD &&
                  due_at(addr, 2880 + WAIT_E),
              "S(H) = {B}: the quorum is met at the epoch check with no new "
              "receipt, the drop is scheduled");
        CHECK(epoch_at_a(2880 + WAIT_E) && not_held(&g_n[0], addr) &&
                  !acked_by(&g_n[0], addr, g_n[1].key.fp),
              "dropped at the due epoch, its acknowledgements with it");

        /* |nearest_R| = 1 and a fresh receipt: one receipt meets it. */
        CHECK(reput_at_a(&p) &&
                  nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0
                  && f && pending_at(&g_n[0], addr),
              "stored again, a new obligation set by hand");
        CHECK(receipt_from(kb, gen, addr, hash) == 0 &&
                  due_at(addr, 2880 + 2 * WAIT_E) &&
                  epoch_at_a(2880 + 2 * WAIT_E) && not_held(&g_n[0], addr),
              "|nearest_R| = 1: one receipt schedules the drop; dropped when due");
    }

    /* Eligible again: a pending record whose drop is SCHEDULED (two
     * acknowledgements), then S(H) = {A, B} (A eligible for every key). The
     * epoch check ends the obligation WITHOUT a drop: held, not pending, the
     * acks and the schedule gone; still held at the old due epoch. */
    set_members(&g_n[0], 2880, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0,
                NULL);
    CHECK(reput_at_a(&p) &&
              nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0 &&
              f, "stored again, obligation again");
    CHECK(receipt_from(kb, gen, addr, hash) == 0 &&
              receipt_from(kw, gen, addr, hash) == 0 &&
              pending_at(&g_n[0], addr) && due_at(addr, 2880 + WAIT_E),
          "B's and W's receipts under S6: the drop is scheduled");
    {
        uint8_t ab[2][DHT2_FP_LEN];

        memcpy(ab[0], g_n[0].key.fp, DHT2_FP_LEN);
        memcpy(ab[1], g_n[1].key.fp, DHT2_FP_LEN);
        set_members(&g_n[0], 3600, 2, (const uint8_t (*)[DHT2_FP_LEN])ab, 0,
                    NULL);
    }
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              !pending_at(&g_n[0], addr) &&
              !acked_by(&g_n[0], addr, g_n[1].key.fp) &&
              !due_at(addr, 2880 + WAIT_E) &&
              get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
          "eligible again: obligation and schedule cleared, the record kept");
    CHECK(epoch_at_a(2880 + WAIT_E) &&
              get_at(&g_n[0], addr, hash) == NODUS_DHT2_GET_HELD,
          "still held at the cancelled due epoch");

    /* A NEW permanent version cancels the schedule: it carries the pending
     * flag but no acknowledgement and no schedule (it needs its own
     * receipts), so it is still held at the old due epoch. */
    {
        static env_t     v3;
        uint8_t          a3[DHT2_HASH_LEN], h3[DHT2_HASH_LEN];
        const uint64_t   e0 = 2880 + 2 * WAIT_E;

        set_members(&g_n[0], e0, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0,
                    NULL);
        CHECK(nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0 &&
                  f && receipt_from(kb, gen, addr, hash) == 0 &&
                  receipt_from(kw, gen, addr, hash) == 0 &&
                  due_at(addr, e0 + WAIT_E),
              "pending, two receipts: the drop is scheduled");
        CHECK(mk_rec(&v3, a3, kw, idn, 3, true) == 0 &&
                  memcmp(a3, addr, DHT2_HASH_LEN) == 0 && reput_at_a(&v3) &&
                  get_at(&g_n[0], addr, h3) == NODUS_DHT2_GET_HELD &&
                  memcmp(h3, hash, DHT2_HASH_LEN) != 0,
              "a permanent version 3 replaces it at A");
        CHECK(pending_at(&g_n[0], addr) && !due_at(addr, e0 + WAIT_E) &&
                  !acked_by(&g_n[0], addr, g_n[1].key.fp) &&
                  !acked_by(&g_n[0], addr, kw->fp),
              "version 3: pending, no acknowledgement, no schedule");
        CHECK(epoch_at_a(e0 + WAIT_E) &&
                  get_at(&g_n[0], addr, h3) == NODUS_DHT2_GET_HELD,
              "version 3 still held at the old due epoch");
    }

    /* An EXPIRING replacement of a pending permanent record carries no
     * obligation (§4.5 v covers permanent records only; Sol 7a final
     * finding 1): it is not pending, and receipts naming it drop nothing. */
    {
        static env_t     q;
        uint8_t          qaddr[DHT2_HASH_LEN], qhash[DHT2_HASH_LEN];

        CHECK(nodus_dht2_store_handover_set(g_n[0].st, addr, true, &f) == 0 &&
                  f && pending_at(&g_n[0], addr),
              "permanent record pending again");
        CHECK(mk_rec(&q, qaddr, kw, idn, 4, false) == 0 &&
                  memcmp(qaddr, addr, DHT2_HASH_LEN) == 0 && reput_at_a(&q),
              "an expiring version 4 replaces it at A (put under {A, B})");
        CHECK(!pending_at(&g_n[0], addr),
              "the expiring replacement is not pending");
        CHECK(get_at(&g_n[0], addr, qhash) == NODUS_DHT2_GET_HELD,
              "version 4 held");
        set_members(&g_n[0], 3600, 6, (const uint8_t (*)[DHT2_FP_LEN])g_s6, 0,
                    NULL);
        CHECK(receipt_from(kb, gen, addr, qhash) == 0 &&
                  receipt_from(kw, gen, addr, qhash) == 0 &&
                  !due_at(addr, 3600 + WAIT_E) &&
                  epoch_at_a(3600 + WAIT_E) &&
                  get_at(&g_n[0], addr, qhash) == NODUS_DHT2_GET_HELD,
              "two receipts naming version 4: no schedule, nothing dropped "
              "48 epochs on");
    }
    net_down();
}

/* A failed send of a non-empty p_offer leaves no offer kept. */
static void test_offer_send_fail(const tkey_t *ka, const tkey_t *kb,
                                 const tkey_t *kw)
{
    env_t            r;
    uint8_t          addr[DHT2_HASH_LEN], mb[64], wb[64];
    nodus_dht2_put_t pr;
    dht2_p_get_t     gm;
    dht2_p_want_t    wm;
    uint8_t          none[1] = { 0 };
    size_t           ml = 0, wl = 0;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r, addr, kw, 1, 1, false) == 0 &&
              put_at(&g_n[0], &r, &pr) == 0, "a record at A");
    gm.g = nodus_dht2_store_generation(g_n[0].st);
    gm.s = 0;
    CHECK(dht2_p_get_encode(&gm, mb, sizeof(mb), &ml) == DHT2_OK, "p_get");
    wm.b = none;
    wm.b_len = 1;
    CHECK(dht2_p_want_encode(&wm, 1, wb, sizeof(wb), &wl) == DHT2_OK,
          "p_want over one entry, no bit set");

    g_fail_offer = true;
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == -1,
          "the offer's send failed: the p_get is dropped");
    g_fail_offer = false;
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, wb, wl) == -1,
          "a p_want afterwards is without an offer");

    /* Control: the same sequence with a working send keeps the offer. */
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == 0 &&
              nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                    NODUS_DHT2_PULL_WANT, wb, wl) == 0,
          "control: with a working send the p_want finds its offer");
    net_down();
}

/* §4.5 "re-scan when responsibility grows" / "otherwise cursors persist
 * across restarts", with the checked epoch persisted (Sol 7a finding 2):
 * a restart within the checked epoch keeps the cursors; a node that missed
 * one or more boundaries re-scans from 0 even when S(H) and S(H − E) are
 * equal at its next check. E = DNAC_EPOCH_LENGTH (design §2). */
static void test_epoch_persisted(const tkey_t *ka, const tkey_t *kb)
{
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint8_t        s0[2][DHT2_FP_LEN];
    bool           found = false;
    uint64_t       gen = 0, cur = 0, gb;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    memcpy(s0[0], g_n[0].key.fp, DHT2_FP_LEN);
    memcpy(s0[1], g_n[1].key.fp, DHT2_FP_LEN);
    gb = nodus_dht2_store_generation(g_n[1].st);

    /* Epoch 2E, S(H) = S(H − E) = {A, B}: the first check (no epoch kept). */
    set_members(&g_n[0], 2 * E, 2, (const uint8_t (*)[DHT2_FP_LEN])s0, 2,
                (const uint8_t (*)[DHT2_FP_LEN])s0);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0,
          "first check at 2E");
    CHECK(nodus_dht2_store_pull_set(g_n[0].st, g_n[1].key.fp, gb, 7) == 0,
          "a cursor 7 for source B");

    /* Same epoch, then a restart in the same epoch: the cursor stays. */
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              nodus_dht2_store_pull_get(g_n[0].st, g_n[1].key.fp, &found,
                                        &gen, &cur) == 0 &&
              found && cur == 7,
          "same epoch: cursor kept");
    node_close(&g_n[0]);
    CHECK(node_open(&g_n[0]) == 0, "A reopened");
    set_members(&g_n[0], 2 * E, 2, (const uint8_t (*)[DHT2_FP_LEN])s0, 2,
                (const uint8_t (*)[DHT2_FP_LEN])s0);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              nodus_dht2_store_pull_get(g_n[0].st, g_n[1].key.fp, &found,
                                        &gen, &cur) == 0 &&
              found && cur == 7,
          "restart within the checked epoch: cursor kept");

    /* The next boundary, nothing grew: the cursor stays. */
    set_members(&g_n[0], 3 * E, 2, (const uint8_t (*)[DHT2_FP_LEN])s0, 2,
                (const uint8_t (*)[DHT2_FP_LEN])s0);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              nodus_dht2_store_pull_get(g_n[0].st, g_n[1].key.fp, &found,
                                        &gen, &cur) == 0 &&
              found && cur == 7,
          "next boundary, equal sets: cursor kept");

    /* Down across 4E; back at 5E with equal sets: a boundary was missed, so
     * the cursor is reset although S(H) == S(H − E) now. */
    node_close(&g_n[0]);
    CHECK(node_open(&g_n[0]) == 0, "A reopened after missing a boundary");
    set_members(&g_n[0], 5 * E, 2, (const uint8_t (*)[DHT2_FP_LEN])s0, 2,
                (const uint8_t (*)[DHT2_FP_LEN])s0);
    CHECK(nodus_dht2_pull_epoch_check(g_n[0].pull, NOW) == 0 &&
              nodus_dht2_store_pull_get(g_n[0].st, g_n[1].key.fp, &found,
                                        &gen, &cur) == 0 &&
              found && cur == 0,
          "missed boundary: cursor reset to 0");
    net_down();
}

static void test_epoch_sets(const tkey_t *ka, const tkey_t *kb, const tkey_t *kw)
{
    env_t            r;
    uint8_t          addr[DHT2_HASH_LEN];
    nodus_dht2_put_t pr;
    bool             found;
    uint64_t         cur;
    uint8_t          big[7][DHT2_FP_LEN], two[2][DHT2_FP_LEN];
    uint8_t          src[8][DHT2_FP_LEN];
    int              k, n;

    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r, addr, kw, 1, 1, false) == 0 &&
              put_at(&g_n[0], &r, &pr) == 0, "a record at A");
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(found && cur == 2, "cursor 2");

    memcpy(big[0], g_n[0].key.fp, DHT2_FP_LEN);
    memcpy(big[1], g_n[1].key.fp, DHT2_FP_LEN);
    for (k = 2; k < 7; k++) {
        memset(big[k], 0xE0 + k, DHT2_FP_LEN);
    }
    memcpy(two[0], g_n[0].key.fp, DHT2_FP_LEN);
    memcpy(two[1], g_n[1].key.fp, DHT2_FP_LEN);

    /* S(H) = {A, B}, S(H - E) = 7 members: B's region GREW. */
    set_members(&g_n[1], 1440, 2, (const uint8_t (*)[DHT2_FP_LEN])two, 7,
                (const uint8_t (*)[DHT2_FP_LEN])big);
    q_clear();
    counters_reset();
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "an exchange in flight");
    CHECK(nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 0, "epoch check");
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(found && cur == 0,
          "responsibility grew (PU:178-189): every cursor reset to 0");
    q_clear();
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED,
          "and the exchange in flight was aborted (a new one starts)");
    q_clear();
    pump();

    /* Equal sets, then a bigger S(H): not grown, cursors kept. */
    CHECK(nodus_dht2_store_pull_set(g_n[1].st, g_n[0].key.fp,
                                    nodus_dht2_store_generation(g_n[0].st), 7)
              == 0, "cursor 7");
    set_members(&g_n[1], 2160, 7, (const uint8_t (*)[DHT2_FP_LEN])big, 7,
                (const uint8_t (*)[DHT2_FP_LEN])big);
    CHECK(nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 0, "epoch check");
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(cur == 7, "equal sets: cursor kept");
    set_members(&g_n[1], 2880, 7, (const uint8_t (*)[DHT2_FP_LEN])big, 2,
                (const uint8_t (*)[DHT2_FP_LEN])two);
    CHECK(nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 0, "epoch check");
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(cur == 7, "S(H) gained members: cursor kept");
    /* Same epoch again, with sets that WOULD grow: nothing happens. */
    set_members(&g_n[1], 2880, 2, (const uint8_t (*)[DHT2_FP_LEN])two, 7,
                (const uint8_t (*)[DHT2_FP_LEN])big);
    CHECK(nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 0, "epoch check");
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(cur == 7, "same epoch: nothing done");

    /* Sources: S(H) = {A, B, E2}, S(H - E) = {A, E3}: B's sources. */
    {
        uint8_t s0[3][DHT2_FP_LEN], s1[2][DHT2_FP_LEN];

        memcpy(s0[0], g_n[0].key.fp, DHT2_FP_LEN);
        memcpy(s0[1], g_n[1].key.fp, DHT2_FP_LEN);
        memset(s0[2], 0xE2, DHT2_FP_LEN);
        memcpy(s1[0], g_n[0].key.fp, DHT2_FP_LEN);
        memset(s1[1], 0xE3, DHT2_FP_LEN);
        set_members(&g_n[1], 3600, 3, (const uint8_t (*)[DHT2_FP_LEN])s0, 2,
                    (const uint8_t (*)[DHT2_FP_LEN])s1);
        n = nodus_dht2_pull_sources(g_n[1].pull, NOW, src, 8);
        CHECK(n == 3, "three sources: S(H) ∪ S(H - E) minus self, each once");
        for (k = 1; k < n; k++) {
            CHECK(memcmp(src[k - 1], src[k], DHT2_FP_LEN) < 0, "ascending");
        }
        CHECK(nodus_dht2_pull_sources(g_n[1].pull, NOW, src, 2) == -1,
              "a too small buffer is an error, never a truncated list");
        g_n[1].view.have_snap = false;
        CHECK(nodus_dht2_pull_sources(g_n[1].pull, NOW, src, 8) == -1 &&
                  nodus_dht2_pull_epoch_check(g_n[1].pull, NOW) == 1,
              "no snapshot: no sources, epoch check says try again");
    }
    net_down();
}

static void test_want_length(const tkey_t *ka, const tkey_t *kb, const tkey_t *kw)
{
    env_t            r;
    uint8_t          addr[DHT2_HASH_LEN], mb[64];
    nodus_dht2_put_t pr;
    dht2_p_get_t     gm;
    dht2_p_deliver_t d;
    size_t           ml = 0, before;
    static const uint8_t bad_len2[] = { 0xA1, 0x61, 0x62, 0x42, 0x00, 0x00 };
    static const uint8_t bad_bit[]  = { 0xA1, 0x61, 0x62, 0x41, 0x03 };
    static const uint8_t good[]     = { 0xA1, 0x61, 0x62, 0x41, 0x01 };
    static const uint8_t empty_b[]  = { 0xA1, 0x61, 0x62, 0x40 };

    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r, addr, kw, 9, 1, false) == 0 &&
              put_at(&g_n[0], &r, &pr) == 0, "a record at A");
    gm.g = nodus_dht2_store_generation(g_n[0].st);
    gm.s = 0;
    CHECK(dht2_p_get_encode(&gm, mb, sizeof(mb), &ml) == DHT2_OK, "p_get");

    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == 0, "offer made");
    q_clear();
    counters_reset();
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, bad_len2,
                                sizeof(bad_len2)) == -1 &&
              g_sent[NODUS_DHT2_PULL_DELIVER] == 0,
          "ceil(n/8) + 1 bytes: dropped, no delivery");
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, good, sizeof(good)) == -1,
          "the offer was forgotten with the aborted exchange");

    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == 0, "offer made");
    q_clear();
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, empty_b,
                                sizeof(empty_b)) == -1 &&
              g_sent[NODUS_DHT2_PULL_DELIVER] == 0,
          "ceil(n/8) - 1 bytes: dropped");
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == 0, "offer made");
    q_clear();
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, bad_bit, sizeof(bad_bit))
              == -1 && g_sent[NODUS_DHT2_PULL_DELIVER] == 0,
          "a bit >= n set: dropped");

    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_GET, mb, ml) == 0, "offer made");
    q_clear();
    before = g_qt;
    CHECK(nodus_dht2_pull_serve(g_n[0].pull, NOW, g_n[1].key.fp,
                                NODUS_DHT2_PULL_WANT, good, sizeof(good)) == 0 &&
              g_sent[NODUS_DHT2_PULL_DELIVER] == 1 && g_qt == before + 1,
          "the exact length: exactly one p_deliver");
    CHECK(dht2_p_deliver_decode(g_q[g_qh % QCAP].b, g_q[g_qh % QCAP].n, &d)
                  == DHT2_OK && d.i == 0 && d.has_v && d.v_len == r.n &&
              memcmp(d.v, r.b, r.n) == 0,
          "the delivery is the canonical envelope held, index 0");
    q_clear();
    net_down();
}

static void test_cursor_rules(const tkey_t *ka, const tkey_t *kb,
                              const tkey_t *kw)
{
    env_t            r[2];
    uint8_t          addr[2][DHT2_HASH_LEN];
    nodus_dht2_put_t pr;
    bool             found;
    uint64_t         cur;
    uint8_t          h[DHT2_HASH_LEN];

    /* transient local failure: keep the cursor, the retry completes. */
    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r[0], addr[0], kw, 1, 1, false) == 0 &&
              mk_rec(&r[1], addr[1], kw, 2, 1, false) == 0 &&
              put_at(&g_n[0], &r[0], &pr) == 0 &&
              put_at(&g_n[0], &r[1], &pr) == 0, "two records at A");
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "started");
    step(); step(); step(); step();     /* hello x2, get, offer at B */
    g_n[1].view.have_snap = false;      /* B loses its snapshot */
    pump();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    /* exactly 2: the first delivery aborts the exchange, the second one
     * meets no exchange (a reply for no exchange is also "aborted") */
    CHECK(g_aborted == 2 && g_done == 0,
          "no snapshot at B during the delivery: the exchange aborts");
    CHECK(found && cur == 0, "the cursor was kept");
    g_n[1].view.have_snap = true;
    CHECK(not_held(&g_n[1], addr[0]) && not_held(&g_n[1], addr[1]),
          "nothing was stored");
    counters_reset();
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && cur == 3 && holds(&g_n[1], addr[0], &r[0]) &&
              holds(&g_n[1], addr[1], &r[1]), "the retry completes");
    net_down();

    /* a source-side failure is never "gone": A loses its snapshot between
     * its offer and the want — no delivery, B's cursor does not move. */
    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r[0], addr[0], kw, 1, 1, false) == 0 &&
              mk_rec(&r[1], addr[1], kw, 2, 1, false) == 0 &&
              put_at(&g_n[0], &r[0], &pr) == 0 &&
              put_at(&g_n[0], &r[1], &pr) == 0, "two records at A");
    CHECK(nodus_dht2_pull_start(g_n[1].pull, NOW, g_n[0].key.fp) ==
              NODUS_DHT2_PULL_STARTED, "started");
    step(); step(); step(); step();     /* hello x2, get, offer at B */
    g_n[0].view.have_snap = false;
    pump();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_serve_fail == 1 && g_sent[NODUS_DHT2_PULL_DELIVER] == 0,
          "A without a snapshot: the p_want is dropped, nothing sent as gone");
    CHECK(found && cur == 0 && not_held(&g_n[1], addr[0]),
          "B's cursor did not move, nothing stored");
    g_n[0].view.have_snap = true;
    nodus_dht2_pull_disconnect(g_n[1].pull, g_n[0].key.fp);   /* stream gone */
    counters_reset();
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && cur == 3 && holds(&g_n[1], addr[1], &r[1]),
          "after the disconnect a new exchange completes");
    net_down();

    /* definitive refusal: code 7 (expired at B) advances the cursor. */
    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r[0], addr[0], kw, 1, 1, false) == 0 &&
              put_at(&g_n[0], &r[0], &pr) == 0, "a record at A");
    g_n[1].view.snap.tip_time = T0 + 7200;     /* past the record's expiry */
    pull_all();
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && g_aborted == 0 && found && cur == 2,
          "a definitive refusal (expired at B): the cursor advances");
    {
        bool f = true, pend;
        uint8_t hh[DHT2_HASH_LEN], pp[DHT2_HASH_LEN];

        CHECK(nodus_dht2_store_handover_info(g_n[1].st, addr[0], &f, &pend, hh,
                                             pp) == 0 && !f,
              "and nothing was stored");
    }
    net_down();

    /* source fault: a delivery that does not match its offer. */
    CHECK(net_up(ka, kb) == 0, "two nodes");
    CHECK(mk_rec(&r[0], addr[0], kw, 1, 1, false) == 0 &&
              mk_rec(&r[1], addr[1], kw, 2, 1, false) == 0 &&
              put_at(&g_n[0], &r[0], &pr) == 0 &&
              put_at(&g_n[0], &r[1], &pr) == 0, "two records at A");
    g_tamper0 = &r[1];          /* delivery 0 carries the OTHER record */
    pull_all();
    g_tamper0 = NULL;
    cur = cursor_of(&g_n[1], &g_n[0], &found, NULL);
    CHECK(g_done == 1 && g_aborted == 0, "the exchange ends normally");
    CHECK(not_held(&g_n[1], addr[0]),
          "the mismatching delivery stored nothing (source fault)");
    CHECK(holds(&g_n[1], addr[1], &r[1]),
          "the other delivery was admitted");
    CHECK(found && cur == 3, "and the cursor advanced past the page");
    (void)h;
    net_down();
}

static void cleanup(void)
{
    char path[160];
    int  i;

    for (i = 0; i < 64; i++) {
        snprintf(path, sizeof(path), "%s/p%d.db", g_dir, i);
        (void)unlink(path);
        snprintf(path, sizeof(path), "%s/p%d.db-journal", g_dir, i);
        (void)unlink(path);
    }
    (void)rmdir(g_dir);
}

int main(void)
{
    tkey_t *keys = (tkey_t *)calloc(4, sizeof(tkey_t));
    int     ok;

    if (keys == NULL) {
        return 1;
    }
    memset(g_chain, 0x22, sizeof(g_chain));
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_dht2_pull_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "mkdtemp failed");
        free(keys);
        return 1;
    }
    ok = keygen(&keys[0], 0xA1) == 0 && keygen(&keys[1], 0xB2) == 0 &&
         keygen(&keys[2], 0xC3) == 0 && keygen(&keys[3], 0xD4) == 0;
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "keypairs");
        cleanup();
        free(keys);
        return 1;
    }

    /* keys[0] = A (source), [1] = B (puller), [2] = a record writer, [3] = a
     * stranger. */
    QGP_LOG_INFO(LOG_TAG, "=== DHT v2 pull-sync (package 7 core) ===");
    test_basic(&keys[0], &keys[1], &keys[2]);
    test_more_than_250(&keys[0], &keys[1], &keys[2]);
    test_replacement(&keys[0], &keys[1], &keys[2]);
    test_generation(&keys[0], &keys[1], &keys[2]);
    test_handover(&keys[0], &keys[1], &keys[2], &keys[3]);
    test_handover_quorum(&keys[0], &keys[1], &keys[2]);
    test_offer_send_fail(&keys[0], &keys[1], &keys[2]);
    test_epoch_persisted(&keys[0], &keys[1]);
    test_epoch_sets(&keys[0], &keys[1], &keys[2]);
    test_want_length(&keys[0], &keys[1], &keys[2]);
    test_cursor_rules(&keys[0], &keys[1], &keys[2]);
    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===",
                 g_pass, g_fail);

    cleanup();
    memset(keys, 0, 4 * sizeof(tkey_t));
    free(keys);
    return g_fail == 0 ? 0 : 1;
}
