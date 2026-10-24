/**
 * Nodus — DHT v2 package 5: the holder store and admission
 * (nodus/src/dht2/nodus_dht2_store.{c,h}).
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §3.1
 * "Stored form", §3.3, §4.1, §4.2, §4.5 (i), §5, §6, §9 D3 / D4 / D6;
 * §13 rows 5, 7, 8, 12, 15, 16, 18.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false:
 *   · `put` answers the row-7 code of the FIRST failing check in §4.1's
 *     order: no snapshot / no sets 15; size 1; undecodable 2; chain 3;
 *     expected address 4; not-holder 5 (before class rules); class 6
 *     (before expiry and signature); the name fault 16 (before expiry);
 *     expired 7 / too-long 8 (before the signature) with the class max by
 *     the WRITER's name status, edges exact; signature 9;
 *   · a name FAULT is code 16, is asked exactly once per admission that
 *     reaches it, and is never read as "no name"; admissions that fail
 *     earlier never ask;
 *   · Select: an equal canonical write is acknowledged again (also when it
 *     arrives with an unknown field the canonical form drops, and the
 *     stored bytes are the canonical form), a losing write returns the
 *     winner's hash, stores nothing and costs 0 even with the quota full,
 *     and two stores admitting A (seq s, later expiry) and B (seq s+1,
 *     earlier expiry) in opposite orders end with the same bytes;
 *   · quota: a replacement costs new − old (the exact limit is accepted,
 *     one byte more is code 10), a tombstone refunds, the node pools
 *     (named / unnamed) refuse with 13 and do not touch each other;
 *   · inbox: pools 80 named / 20 unnamed (11 when full); a writer updating
 *     its own entry takes no second slot; a writer that gains a name moves
 *     pools on its next write (and meets the other pool's cap); a control
 *     record is accepted only from the recipient (6 otherwise), drops
 *     HANDLED (Sequence ≤ through) and DENIED entries at once and frees
 *     their slots; afterwards DENIED -> 12 and HANDLED -> [18, through] at
 *     admission, a Sequence above the cutoff is admitted again;
 *   · LIST pages: ascending writer fp, EXCLUSIVE cursor, ≤ 16 per page,
 *     `complete`, `r.v` = SHA3-512 of the listed hashes, the control
 *     record's hash beside it; an expired entry is not listed;
 *   · `get` never serves a record whose expiry ≤ chain time; `sweep`
 *     deletes only 3 h AFTER expiry (10,799 s later nothing, 10,800 s
 *     later it is gone) and a record without expiry is never swept;
 *   · every stored change is re-indexed at the counter's top and the old
 *     index entry is gone; the scan is ascending from `s`, bounded by 250,
 *     an empty interval returns the top; equal / losing writes do not move
 *     the counter; top and the generation g persist across reopen; the
 *     hand-over flag persists and survives a replacement;
 *   · review round: every call is 15 while the witness is in block sync
 *     (consensus_up false) or the tip time cannot fit int64, and 16 for a
 *     snapshot of another chain (open refuses such a store too); a FAILED
 *     BIND (blob length limit) is 16, never "not held"; an index above
 *     INT64_MAX is never handed out, a counter behind the records is a
 *     fault (never a silent row delete) and refuses open; ValidityType <=>
 *     Validity is code 6, after the chain check (3); admission follows the
 *     SELECTED live control record only (no holder memory — the HANDLED
 *     rule is a client rule, decision 2026-10-24-dht-v2-handled-client-
 *     rule.md); a losing and a quota-refused control record leave entries,
 *     counter and bytes unchanged; v2 (writer unlisted) before v1 keeps
 *     the entry on that store (documented, accepted); a control record
 *     that frees space is accepted at a full pool (one that frees nothing
 *     is not); an expired held row is replaced by a fresh lower Sequence;
 *     a tombstone is never refused by the pool of a writer who gained a
 *     name;
 *   · a SQLite fault is a fault code (16) on every call — a read-only
 *     connection refuses a put, a dropped table faults get / list / scan /
 *     sweep / put — never "not held" or an empty page.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no clock. Keys come from fixed seeds (qgp_dsa87_keypair_derand); signing
 * is HEDGED, so no signature byte is pinned (signatures are verified, never
 * compared to a constant) and no expected store bytes are signature
 * dependent: comparisons are between bytes the test itself produced. Chain
 * time is injected (T0 below). The ONE random value is the store
 * generation g, drawn by the store: the test only compares it with itself
 * across a reopen. Safe under `ctest -j`: every run uses its own mkdtemp
 * directory.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success: the temp directory and its .db files are removed at
 * the end. A crash mid-run leaves /tmp/test_dht2_store_XXXXXX.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The context is injected: the real snapshot / sets / name answers of
 *     package 4 (nodus_dht2_wview) are not exercised here, so a
 *     mis-mapping of PENDING / UNAVAILABLE name answers in the (later)
 *     serving layer is not covered.
 *  2. The holder sets are tiny (3 members; 5 for the not-holder case):
 *     eligibility itself is package 1's, tested there; here it only gates.
 *  3. The "forced SQLite fault" is made through the store's own handle
 *     (PRAGMA query_only, DROP TABLE): it proves the fault paths return
 *     16, not that a real I/O error mid-scan is reported — one mid-scan
 *     error cannot be injected portably.
 *  4. The 3 h sweep slack and the class maxima are asserted from the
 *     design's numbers as constants of this file, written by the same
 *     author as the code; they are not an independent oracle.
 *  5. Nothing here runs concurrently: the store is single-writer by
 *     construction (one connection) and that is not stress-tested.
 *
 * @file test_dht2_store.c
 */

#include "dht2/nodus_dht2_store.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_place.h"
#include "dht2/dht2_record.h"
#include "dht2/dht2_types.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "TEST_DHT2_STORE"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                              \
    if (cond) { g_pass++; }                                                \
    else { g_fail++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s:%d: %s",              \
                                   __FILE__, __LINE__, (msg)); }           \
} while (0)

#define T0      1792368000ull           /* 2026-10-19T00:00:00Z */
#define H3      10800ull
#define D1      86400ull
#define D7      604800ull

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

static int keygen(tkey_t *k, uint8_t b0, uint8_t b1)
{
    uint8_t seed[32];

    memset(seed, 0x5C, sizeof(seed));
    seed[0] = b0;
    seed[1] = b1;
    if (qgp_dsa87_keypair_derand(k->pk, k->sk, seed) != 0 ||
        dht2_fp(k->pk, k->fp) != 0) {
        return -1;
    }
    return 0;
}

/* ── the injected world ─────────────────────────────────────────────── */

#define NAMES_MAX 256

typedef struct {
    uint8_t fps[NAMES_MAX][DHT2_FP_LEN];
    size_t  n;
    bool    fault;
    int     calls;
} names_t;

static nodus_dht2_name_t name_cb(void *user, const uint8_t fp[DHT2_FP_LEN])
{
    names_t *nm = (names_t *)user;
    size_t   i;

    nm->calls++;
    if (nm->fault) {
        return NODUS_DHT2_NAME_FAULT;
    }
    for (i = 0; i < nm->n; i++) {
        if (memcmp(nm->fps[i], fp, DHT2_FP_LEN) == 0) {
            return NODUS_DHT2_NAME_NAMED;
        }
    }
    return NODUS_DHT2_NAME_UNNAMED;
}

static void names_add(names_t *nm, const uint8_t fp[DHT2_FP_LEN])
{
    if (nm->n < NAMES_MAX) {
        memcpy(nm->fps[nm->n++], fp, DHT2_FP_LEN);
    }
}

typedef struct {
    nodus_witness_dht_snap_t snap;
    nodus_dht2_ctx_t         ctx;
    uint8_t                  set[8][DHT2_FP_LEN];
    names_t                  names;
} world_t;

/* `nset` members: this node plus nset − 1 fixed fakes. With ≤ 4 members
 * every member is eligible for every key (nearest_R takes min(R, n)). */
static void world_init(world_t *w, const tkey_t *self, size_t nset)
{
    size_t i;

    memset(w, 0, sizeof(*w));
    memcpy(w->snap.chain_id, g_chain, DHT2_CHAIN_LEN);
    w->snap.height = 1000;
    w->snap.tip_time = T0;
    w->snap.consensus_up = true;
    w->snap.epoch_start = 720;
    memcpy(w->set[0], self->fp, DHT2_FP_LEN);
    for (i = 1; i < nset; i++) {
        memset(w->set[i], (int)(0xE0 + i), DHT2_FP_LEN);
    }
    w->ctx.snap = &w->snap;
    w->ctx.have_sets = true;
    w->ctx.s0 = (const uint8_t (*)[DHT2_FP_LEN])w->set;
    w->ctx.n0 = nset;
    w->ctx.s1 = NULL;
    w->ctx.n1 = 0;
    memcpy(w->ctx.self_fp, self->fp, DHT2_FP_LEN);
    w->ctx.name = name_cb;
    w->ctx.name_user = &w->names;
    nodus_dht2_limits_default(&w->ctx.limits);
}

/* ── records ────────────────────────────────────────────────────────── */

static void dbase(dht2_data_t *d, uint64_t cls, const uint8_t id[DHT2_ID_LEN],
                  uint64_t seq, uint64_t expiry)
{
    memset(d, 0, sizeof(*d));
    d->sequence = seq;
    d->validity_type = DHT2_VT_EOL;
    d->expiry = expiry;
    memcpy(d->id, id, DHT2_ID_LEN);
    memcpy(d->chain, g_chain, DHT2_CHAIN_LEN);
    d->cls = cls;
}

static void dfill(uint8_t id[DHT2_ID_LEN], uint8_t b)
{
    memset(id, b, DHT2_ID_LEN);
}

/* Build the canonical envelope of `d`, signed with `sk`, carrying `pk`. */
static int mk_with(env_t *e, const dht2_data_t *d, const uint8_t *sk,
                   const uint8_t *pk)
{
    return dht2_record_build(d, sk, pk, e->b, sizeof(e->b), &e->n) == DHT2_OK
               ? 0 : -1;
}

static int mk(env_t *e, const dht2_data_t *d, const tkey_t *k)
{
    return mk_with(e, d, k->sk, k->pk);
}

/* A class-1 owner record with `dlen` data bytes (all 0xAB). */
static int mk_owner(env_t *e, const tkey_t *k, const uint8_t id[DHT2_ID_LEN],
                    uint64_t seq, uint64_t expiry, size_t dlen)
{
    static uint8_t buf[4096];
    dht2_data_t    d;

    memset(buf, 0xAB, sizeof(buf));
    dbase(&d, DHT2_CLASS_OWNER, id, seq, expiry);
    d.has_data = true;
    d.data = buf;
    d.data_len = dlen;
    return mk(e, &d, k);
}

static int mk_tomb(env_t *e, const tkey_t *k, const uint8_t id[DHT2_ID_LEN],
                   uint64_t seq, uint64_t expiry)
{
    dht2_data_t d;

    dbase(&d, DHT2_CLASS_OWNER, id, seq, expiry);
    d.del = true;
    return mk(e, &d, k);
}

static int P(world_t *w, nodus_dht2_store_t *st, const env_t *e,
             nodus_dht2_put_t *res)
{
    return nodus_dht2_store_put(st, &w->ctx, e->b, e->n, NULL, res);
}

static int P0(world_t *w, nodus_dht2_store_t *st, const env_t *e)
{
    nodus_dht2_put_t r;

    return P(w, st, e, &r);
}

static bool hash_is(const env_t *e, const uint8_t h[DHT2_HASH_LEN])
{
    uint8_t want[DHT2_HASH_LEN];

    return qgp_sha3_512(e->b, e->n, want) == 0 &&
           memcmp(want, h, DHT2_HASH_LEN) == 0;
}

/* ── store / sql helpers ────────────────────────────────────────────── */

static nodus_dht2_store_t *open_store(char *path_out)
{
    char path[128];

    snprintf(path, sizeof(path), "%s/s%d.db", g_dir, g_db_n++);
    if (path_out != NULL) {
        snprintf(path_out, 128, "%s", path);
    }
    return nodus_dht2_store_open(path, g_chain);
}

static int64_t sql_i64(nodus_dht2_store_t *st, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int64_t       v = -1;

    if (sqlite3_prepare_v2(nodus_dht2_store_db(st), sql, -1, &s, NULL)
        != SQLITE_OK) {
        return -1;
    }
    if (sqlite3_step(s) == SQLITE_ROW) {
        v = sqlite3_column_int64(s, 0);
    }
    sqlite3_finalize(s);
    return v;
}

static int64_t used_bytes(nodus_dht2_store_t *st)
{
    return sql_i64(st, "SELECT COALESCE(SUM(size),0) FROM dht2_rec");
}

static int64_t top_of(nodus_dht2_store_t *st)
{
    uint64_t t = 0;

    return nodus_dht2_store_top(st, &t) == 0 ? (int64_t)t : -1;
}

static bool held(world_t *w, nodus_dht2_store_t *st, const uint8_t addr[64],
                 env_t *out)
{
    uint8_t h[DHT2_HASH_LEN];
    int     rc = nodus_dht2_store_get(st, &w->ctx, addr, out->b,
                                      sizeof(out->b), &out->n, h);

    if (rc == NODUS_DHT2_GET_HELD) {
        return hash_is(out, h);
    }
    return false;
}

static int get_rc(world_t *w, nodus_dht2_store_t *st, const uint8_t addr[64])
{
    static env_t e;
    uint8_t      h[DHT2_HASH_LEN];

    return nodus_dht2_store_get(st, &w->ctx, addr, e.b, sizeof(e.b), &e.n, h);
}

static void addr_of(uint8_t addr[64], const uint8_t id[DHT2_ID_LEN],
                    const tkey_t *k)
{
    (void)dht2_address(id, k->fp, addr);
}

/* ══ 1. §4.1 order and the row-7 codes ═════════════════════════════════ */

static int find_id(const world_t *w, const uint8_t owner_fp[DHT2_FP_LEN],
                   bool want_eligible, uint8_t id[DHT2_ID_LEN])
{
    uint32_t i;

    for (i = 0; i < 4000; i++) {
        uint8_t addr[DHT2_HASH_LEN];
        int     e;

        memset(id, 0, DHT2_ID_LEN);
        id[0] = (uint8_t)(i & 0xFF);
        id[1] = (uint8_t)(i >> 8);
        id[2] = 0x5A;
        if (dht2_address(id, owner_fp, addr) != 0) {
            return -1;
        }
        e = dht2_eligible(addr, w->ctx.s0, w->ctx.n0, NULL, 0,
                          w->ctx.self_fp);
        if (e < 0) {
            return -1;
        }
        if ((e == 1) == want_eligible) {
            return 0;
        }
    }
    return -1;
}

static void test_codes(const tkey_t *A, const tkey_t *B, const tkey_t *C)
{
    world_t           *w = (world_t *)calloc(1, sizeof(*w));
    world_t           *far = (world_t *)calloc(1, sizeof(*far));
    nodus_dht2_store_t *st = open_store(NULL);
    nodus_dht2_put_t   res;
    static env_t       e, e2;
    uint8_t            id[DHT2_ID_LEN], idf[DHT2_ID_LEN], bad[DHT2_HASH_LEN];
    dht2_data_t        d;
    static uint8_t     big[DHT2_ENVELOPE_MAX + 1];
    static const uint8_t three[3] = { 1, 2, 3 };
    int                calls;

    if (w == NULL || far == NULL || st == NULL) {
        CHECK(0, "codes: setup");
        free(w);
        free(far);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    world_init(far, A, 5);
    dfill(id, 0x11);
    memset(bad, 0xFF, sizeof(bad));

    /* 15: no snapshot, then no sets — before any byte is looked at. */
    CHECK(mk_owner(&e, A, id, 1, T0 + 3600, 3) == 0, "base record");
    w->ctx.snap = NULL;
    CHECK(P(w, st, &e, &res) == DHT2_E_NOT_CAUGHT_UP, "no snapshot -> 15");
    w->ctx.snap = &w->snap;
    w->ctx.have_sets = false;
    CHECK(P(w, st, &e, &res) == DHT2_E_NOT_CAUGHT_UP, "no sets -> 15");
    w->ctx.have_sets = true;

    /* 1: size, before any decode. 2: undecodable. 3: wrong chain. 4: the
     * expected address. None of these asks the name callback. */
    memset(big, 0, sizeof(big));
    CHECK(nodus_dht2_store_put(st, &w->ctx, big, sizeof(big), NULL, &res)
          == DHT2_E_TOO_LARGE, "262,145 B -> 1");
    CHECK(nodus_dht2_store_put(st, &w->ctx, big, 10, NULL, &res)
          == DHT2_E_BAD_ENCODING, "undecodable -> 2");
    dbase(&d, DHT2_CLASS_OWNER, id, 1, T0 + 3600);
    memcpy(d.chain, g_other_chain, DHT2_CHAIN_LEN);
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk(&e2, &d, A) == 0 && P(w, st, &e2, &res) == DHT2_E_BAD_CHAIN,
          "other chain -> 3");
    CHECK(nodus_dht2_store_put(st, &w->ctx, e.b, e.n, bad, &res)
          == DHT2_E_BAD_ADDRESS, "wrong expected address -> 4");
    CHECK(w->names.calls == 0, "no name request before the class rules");

    /* 5 before 6: a record this node does not hold, whose class is also
     * bad (a feed head with 3 data bytes). */
    CHECK(find_id(far, A->fp, false, idf) == 0, "an id outside this node");
    dbase(&d, DHT2_CLASS_FEED_HEAD, idf, 1, T0 + 3600);
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk(&e2, &d, A) == 0 &&
          nodus_dht2_store_put(st, &far->ctx, e2.b, e2.n, NULL, &res)
              == DHT2_E_NOT_HOLDER, "not-holder before bad-class -> 5");
    CHECK(far->names.calls == 0, "not-holder asked no name");
    /* The same id from a node that IS eligible reaches the class rules. */
    CHECK(P(w, st, &e2, &res) == DHT2_E_BAD_CLASS, "bad-class -> 6");

    /* 6 before 7 and before 9: expired AND wrongly signed AND bad class. */
    dbase(&d, DHT2_CLASS_FEED_HEAD, id, 1, T0);
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk_with(&e2, &d, B->sk, A->pk) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_BAD_CLASS,
          "bad-class before expired / bad-signature");
    CHECK(w->names.calls == 0, "bad-class asked no name");

    /* 16: the name fault, before the expiry check; asked exactly once. */
    w->names.fault = true;
    calls = w->names.calls;
    CHECK(P(w, st, &e, &res) == DHT2_E_HOLDER_FAULT, "name fault -> 16");
    CHECK(w->names.calls == calls + 1, "the fault was asked exactly once");
    CHECK(mk_owner(&e2, A, id, 1, T0, 3) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_HOLDER_FAULT,
          "name fault before expired");
    CHECK(top_of(st) == 0, "a fault stored nothing");
    w->names.fault = false;

    /* 7: expiry <= chain time; checked before the signature. */
    CHECK(mk_owner(&e2, A, id, 1, T0, 3) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_EXPIRED, "expiry == t -> 7");
    CHECK(mk_owner(&e2, A, id, 1, T0 - 1, 3) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_EXPIRED, "expiry < t -> 7");
    dbase(&d, DHT2_CLASS_OWNER, id, 1, T0);
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk_with(&e2, &d, B->sk, A->pk) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_EXPIRED,
          "expired before bad-signature");

    /* 8: class max by the WRITER's name status, edges exact. */
    dbase(&d, DHT2_CLASS_OWNER, id, 1, 0);
    d.validity_type = DHT2_VT_NONE;
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk(&e2, &d, A) == 0 && P(w, st, &e2, &res) == DHT2_E_TOO_LONG,
          "unnamed owner record without expiry -> 8");
    dfill(idf, 0x12);
    CHECK(mk_owner(&e2, A, idf, 1, T0 + D7 + H3 + 1, 3) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_TOO_LONG,
          "unnamed owner record, expiry t+7d+3h+1 -> 8");
    CHECK(mk_owner(&e2, A, idf, 1, T0 + D7 + H3, 3) == 0 &&
          P(w, st, &e2, &res) == 0, "unnamed owner record, expiry t+7d+3h ok");
    {
        uint8_t ib[DHT2_ID_LEN];

        dfill(ib, 0x13);
        dbase(&d, DHT2_CLASS_INBOX_ENTRY, ib, 1, T0 + D1 + H3 + 1);
        d.has_data = true; d.data = three; d.data_len = 3;
        CHECK(mk(&e2, &d, B) == 0 && P(w, st, &e2, &res) == DHT2_E_TOO_LONG,
              "unnamed inbox entry, expiry t+24h+3h+1 -> 8");
        d.expiry = T0 + D1 + H3;
        CHECK(mk(&e2, &d, B) == 0 && P(w, st, &e2, &res) == 0,
              "unnamed inbox entry, expiry t+24h+3h ok");
        names_add(&w->names, C->fp);
        d.expiry = T0 + D7 + H3;
        CHECK(mk(&e2, &d, C) == 0 && P(w, st, &e2, &res) == 0,
              "NAMED inbox entry, expiry t+7d+3h ok");
        d.expiry = T0 + D7 + H3 + 1;
        CHECK(mk(&e2, &d, C) == 0 && P(w, st, &e2, &res) == DHT2_E_TOO_LONG,
              "NAMED inbox entry, expiry t+7d+3h+1 -> 8");
        dfill(ib, 0x14);
        dbase(&d, DHT2_CLASS_OWNER, ib, 1, 0);
        d.validity_type = DHT2_VT_NONE;
        d.has_data = true; d.data = three; d.data_len = 3;
        CHECK(mk(&e2, &d, C) == 0 && P(w, st, &e2, &res) == 0,
              "NAMED owner record without expiry is admitted");
    }

    /* 9: a signature that does not verify. */
    dfill(idf, 0x15);
    dbase(&d, DHT2_CLASS_OWNER, idf, 1, T0 + 3600);
    d.has_data = true; d.data = three; d.data_len = 3;
    CHECK(mk_with(&e2, &d, B->sk, A->pk) == 0 &&
          P(w, st, &e2, &res) == DHT2_E_BAD_SIGNATURE, "bad signature -> 9");

    /* The happy path stores and hands back the hash of the canonical bytes. */
    CHECK(P(w, st, &e, &res) == 0 && res.outcome == NODUS_DHT2_PUT_STORED &&
          hash_is(&e, res.hash), "valid record stored; receipt hash");
    nodus_dht2_store_close(st);
    free(w);
    free(far);
}

/* ══ 2. Select, idempotence, A/B ═══════════════════════════════════════ */

static void test_select(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *s1 = open_store(NULL);
    nodus_dht2_store_t *s2 = open_store(NULL);
    static env_t        a, b, g1, g2, var, o;
    nodus_dht2_put_t    r1, r2;
    uint8_t             id[DHT2_ID_LEN], addr[DHT2_HASH_LEN];
    int64_t             used, top;

    if (w == NULL || s1 == NULL || s2 == NULL) {
        CHECK(0, "select: setup");
        free(w);
        nodus_dht2_store_close(s1);
        nodus_dht2_store_close(s2);
        return;
    }
    world_init(w, A, 3);
    dfill(id, 0x21);
    addr_of(addr, id, A);

    /* A = seq 5, expiry t+2d (later); B = seq 6, expiry t+1d (earlier). */
    CHECK(mk_owner(&a, A, id, 5, T0 + 2 * D1, 10) == 0 &&
          mk_owner(&b, A, id, 6, T0 + D1, 10) == 0, "A, B");
    CHECK(P(w, s1, &a, &r1) == 0 && r1.outcome == NODUS_DHT2_PUT_STORED &&
          P(w, s1, &b, &r1) == 0 && r1.outcome == NODUS_DHT2_PUT_STORED,
          "holder 1: A then B");
    CHECK(P(w, s2, &b, &r2) == 0 && r2.outcome == NODUS_DHT2_PUT_STORED &&
          P(w, s2, &a, &r2) == 0 && r2.outcome == NODUS_DHT2_PUT_LOST,
          "holder 2: B then A (A loses)");
    CHECK(hash_is(&b, r2.hash), "the loser gets the winner's hash");
    CHECK(held(w, s1, addr, &g1) && held(w, s2, addr, &g2) &&
          g1.n == g2.n && memcmp(g1.b, g2.b, g1.n) == 0 &&
          g1.n == b.n && memcmp(g1.b, b.b, b.n) == 0,
          "both holders store the SAME bytes, B's canonical envelope");

    /* Equal re-put is acknowledged; nothing moves. */
    top = top_of(s1);
    used = used_bytes(s1);
    CHECK(P(w, s1, &b, &r1) == 0 && r1.outcome == NODUS_DHT2_PUT_EQUAL &&
          hash_is(&b, r1.hash), "equal canonical write acknowledged again");
    CHECK(P(w, s1, &a, &r1) == 0 && r1.outcome == NODUS_DHT2_PUT_LOST,
          "a losing write at the held address");
    CHECK(top_of(s1) == top && used_bytes(s1) == used,
          "equal and losing writes: counter and bytes unchanged");

    /* §3.1 "Stored form": an envelope with an unknown field is not kept as
     * received; it is the same version and is acknowledged as equal, and
     * on an empty store the canonical bytes are what gets stored. */
    memcpy(var.b, b.b, b.n);
    var.b[b.n] = 0x78;                  /* field 15, varint */
    var.b[b.n + 1] = 0x01;
    var.n = b.n + 2;
    CHECK(P(w, s1, &var, &r1) == 0 && r1.outcome == NODUS_DHT2_PUT_EQUAL &&
          hash_is(&b, r1.hash), "unknown field dropped: equal to the held");
    CHECK(P(w, s2, &var, &r2) == 0 && r2.outcome == NODUS_DHT2_PUT_EQUAL,
          "same on the other holder");
    {
        nodus_dht2_store_t *s3 = open_store(NULL);

        CHECK(s3 != NULL && P(w, s3, &var, &r1) == 0 &&
              r1.outcome == NODUS_DHT2_PUT_STORED &&
              hash_is(&b, r1.hash) && held(w, s3, addr, &o) &&
              o.n == b.n && memcmp(o.b, b.b, b.n) == 0,
              "the stored form is the canonical envelope, not the received");
        nodus_dht2_store_close(s3);
    }
    nodus_dht2_store_close(s1);
    nodus_dht2_store_close(s2);
    free(w);
}

/* ══ 3. quota ══════════════════════════════════════════════════════════ */

static void test_quota(const tkey_t *A, const tkey_t *B, const tkey_t *C)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        r1, r1b, r1big, r2, tomb, regrow, c1, x;
    nodus_dht2_put_t    res;
    uint8_t             id1[DHT2_ID_LEN], id2[DHT2_ID_LEN], id3[DHT2_ID_LEN];
    int64_t             used, before;

    if (w == NULL || st == NULL) {
        CHECK(0, "quota: setup");
        free(w);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    dfill(id1, 0x31);
    dfill(id2, 0x32);
    dfill(id3, 0x33);
    CHECK(mk_owner(&r1, A, id1, 1, T0 + 3600, 1000) == 0 &&
          mk_owner(&r2, A, id2, 1, T0 + 3600, 500) == 0 &&
          mk_owner(&r1b, A, id1, 2, T0 + 3600, 1100) == 0 &&
          mk_owner(&r1big, A, id1, 3, T0 + 3600, 1101) == 0, "records");
    /* Identity limit = r1 + r2 + 100 bytes. */
    w->ctx.limits.ident_unnamed = (uint64_t)(r1.n + r2.n + 100);
    CHECK(P0(w, st, &r1) == 0 && P0(w, st, &r2) == 0, "r1, r2 fit");
    CHECK((uint64_t)used_bytes(st) == r1.n + r2.n, "charged whole envelopes");
    /* Replacement costs new - old: +100 reaches the limit exactly. */
    CHECK(r1b.n == r1.n + 100 && r1big.n == r1.n + 101, "size steps");
    CHECK(P0(w, st, &r1big) == DHT2_E_QUOTA, "+101 over the limit -> 10");
    CHECK((uint64_t)used_bytes(st) == r1.n + r2.n, "a refusal costs 0");
    CHECK(P(w, st, &r1b, &res) == 0 && res.outcome == NODUS_DHT2_PUT_STORED,
          "+100 reaches the limit exactly: accepted");
    CHECK((uint64_t)used_bytes(st) == r1b.n + r2.n, "now full");
    /* At a full quota: equal and losing writes cost 0 and are NOT 10. */
    CHECK(P(w, st, &r1b, &res) == 0 && res.outcome == NODUS_DHT2_PUT_EQUAL,
          "equal at a full quota: acknowledged");
    CHECK(P(w, st, &r1, &res) == 0 && res.outcome == NODUS_DHT2_PUT_LOST,
          "losing at a full quota: the winner's hash, not 10");
    CHECK(P0(w, st, &r2) == 0, "equal r2 at a full quota");
    /* A new address does not fit. */
    CHECK(mk_owner(&x, A, id3, 1, T0 + 3600, 1) == 0 &&
          P0(w, st, &x) == DHT2_E_QUOTA, "new address at a full quota -> 10");
    /* A tombstone replacing a larger record refunds. */
    CHECK(mk_tomb(&tomb, A, id1, 3, T0 + 3600) == 0 && tomb.n < r1b.n,
          "tombstone is smaller");
    before = used_bytes(st);
    CHECK(P(w, st, &tomb, &res) == 0 && res.outcome == NODUS_DHT2_PUT_STORED,
          "tombstone stored");
    used = used_bytes(st);
    CHECK((uint64_t)used == tomb.n + r2.n && used < before,
          "the larger record's bytes were refunded");
    CHECK(mk_owner(&regrow, A, id1, 4, T0 + 3600, 1100) == 0 &&
          regrow.n == r1b.n && P0(w, st, &regrow) == 0 &&
          (uint64_t)used_bytes(st) == r1b.n + r2.n,
          "re-growing to the old size fits again (refund was real)");

    /* Node pools: unnamed pool = A's r1 + 10 bytes; the named pool is a
     * separate budget. */
    nodus_dht2_store_close(st);
    st = open_store(NULL);
    CHECK(st != NULL, "second store");
    if (st == NULL) {
        free(w);
        return;
    }
    nodus_dht2_limits_default(&w->ctx.limits);
    w->ctx.limits.pool_unnamed = (uint64_t)r1.n + 10;
    CHECK(P0(w, st, &r1) == 0, "A fills the unnamed pool but 10 bytes");
    CHECK(mk_owner(&x, B, id2, 1, T0 + 3600, 1000) == 0 &&
          P0(w, st, &x) == DHT2_E_NODE_FULL, "B (unnamed): pool full -> 13");
    names_add(&w->names, C->fp);
    CHECK(mk_owner(&c1, C, id3, 1, T0 + 3600, 1000) == 0 &&
          P0(w, st, &c1) == 0, "C (named) uses the named pool: admitted");
    CHECK(mk_owner(&x, A, id1, 2, T0 + 3600, 1010) == 0 &&
          P0(w, st, &x) == 0, "A grows by 10 within its pool: new - old");
    CHECK(mk_owner(&x, A, id1, 3, T0 + 3600, 1011) == 0 &&
          P0(w, st, &x) == DHT2_E_NODE_FULL, "one byte more -> 13");
    nodus_dht2_store_close(st);
    free(w);
}

/* ══ 4. inbox: pools, control, LIST ═══════════════════════════════════ */

static int put_entry(world_t *w, nodus_dht2_store_t *st, const tkey_t *wr,
                     const uint8_t inbox[DHT2_ID_LEN], uint64_t seq,
                     nodus_dht2_put_t *res)
{
    static env_t   e;
    static const uint8_t dat[4] = { 9, 8, 7, 6 };
    dht2_data_t    d;

    dbase(&d, DHT2_CLASS_INBOX_ENTRY, inbox, seq, T0 + 3600);
    d.has_data = true; d.data = dat; d.data_len = sizeof(dat);
    if (mk(&e, &d, wr) != 0) {
        return -1000;
    }
    return P(w, st, &e, res);
}

static void sort_ctl(dht2_ctl_entry_t *e, size_t n)
{
    size_t i, j;

    for (i = 1; i < n; i++) {
        dht2_ctl_entry_t t = e[i];

        for (j = i; j > 0 && memcmp(e[j - 1].fp, t.fp, DHT2_FP_LEN) > 0;
             j--) {
            e[j] = e[j - 1];
        }
        e[j] = t;
    }
}

static int mk_ctl(env_t *e, const tkey_t *signer, const uint8_t ctl_id[64],
                  uint64_t seq, uint64_t expiry, dht2_ctl_entry_t *ents,
                  size_t n)
{
    static uint8_t data[DHT2_CTL_ENTRY_LEN * 8];
    size_t         len = 0;
    dht2_data_t    d;

    sort_ctl(ents, n);
    if (dht2_ctl_encode(ents, n, data, sizeof(data), &len) != DHT2_OK) {
        return -1;
    }
    dbase(&d, DHT2_CLASS_INBOX_CTL, ctl_id, seq, expiry);
    d.has_data = true; d.data = data; d.data_len = len;
    return mk(e, &d, signer);
}

/* All pages of `inbox`; verifies the page rules; returns the total. */
static int list_all(world_t *w, nodus_dht2_store_t *st,
                    const uint8_t inbox[DHT2_ID_LEN], int *pages,
                    dht2_list_answer_t *last_page)
{
    dht2_list_answer_t *a = (dht2_list_answer_t *)malloc(sizeof(*a));
    uint8_t             cur[DHT2_FP_LEN], prev[DHT2_FP_LEN];
    bool                have_cur = false, have_prev = false;
    int                 total = 0, guard;

    *pages = 0;
    if (a == NULL) {
        return -1;
    }
    for (guard = 0; guard < 64; guard++) {
        uint8_t  hs[DHT2_LIST_PAGE_MAX * DHT2_HASH_LEN], want[DHT2_HASH_LEN];
        size_t   i;
        int      rc = nodus_dht2_store_list(st, &w->ctx, inbox,
                                            have_cur ? cur : NULL, a);

        if (rc != 0) {
            free(a);
            return -2;
        }
        (*pages)++;
        CHECK(a->list_count <= DHT2_LIST_PAGE_MAX, "page <= 16");
        for (i = 0; i < a->list_count; i++) {
            if (have_prev) {
                CHECK(memcmp(prev, a->list[i].w, DHT2_FP_LEN) < 0,
                      "ascending writer fp, no overlap across pages");
            }
            memcpy(prev, a->list[i].w, DHT2_FP_LEN);
            have_prev = true;
            memcpy(hs + i * DHT2_HASH_LEN, a->list[i].d, DHT2_HASH_LEN);
        }
        CHECK(qgp_sha3_512(hs, a->list_count * DHT2_HASH_LEN, want) == 0 &&
              a->r.kind == DHT2_RV_HASH &&
              memcmp(want, a->r.hash, DHT2_HASH_LEN) == 0 &&
              memcmp(a->r.key, inbox, DHT2_HASH_LEN) == 0,
              "r = {inbox, SHA3-512 of the listed hashes}");
        CHECK(a->has_req_cursor == have_cur &&
              (!have_cur || memcmp(a->req_cursor, cur, DHT2_FP_LEN) == 0),
              "req_cursor present exactly after the first page");
        total += (int)a->list_count;
        if (a->list_count > 0) {
            CHECK(a->has_cursor &&
                  memcmp(a->cursor, a->list[a->list_count - 1].w,
                         DHT2_FP_LEN) == 0, "cursor = the last w listed");
        } else {
            CHECK(!a->has_cursor && a->complete, "empty page: complete");
        }
        if (last_page != NULL) {
            *last_page = *a;
        }
        if (a->complete) {
            free(a);
            return total;
        }
        CHECK(a->list_count > 0, "each page advances");
        memcpy(cur, a->cursor, DHT2_FP_LEN);
        have_cur = true;
    }
    free(a);
    return -3;
}

#define NU 21   /* unnamed writers: 20 fit, the 21st is refused */
#define NN 81   /* named writers: 80 fit, the 81st is refused   */

static void test_inbox(const tkey_t *R, const tkey_t *X)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    tkey_t             *u = (tkey_t *)calloc(NU, sizeof(tkey_t));
    tkey_t             *n = (tkey_t *)calloc(NN, sizeof(tkey_t));
    nodus_dht2_put_t    res;
    static env_t        e, ctl_env, dropped;
    uint8_t             inbox[DHT2_ID_LEN], ctl_id[DHT2_ID_LEN];
    uint8_t             inbox2[DHT2_ID_LEN], addr[DHT2_HASH_LEN];
    dht2_ctl_entry_t    ents[3];
    dht2_list_answer_t *last = (dht2_list_answer_t *)malloc(sizeof(*last));
    char                sql[256];
    int                 i, pages, total, ok = 1;

    if (w == NULL || st == NULL || u == NULL || n == NULL || last == NULL) {
        CHECK(0, "inbox: setup");
        goto done;
    }
    for (i = 0; i < NU; i++) {
        ok &= keygen(&u[i], (uint8_t)i, 0x01) == 0;
    }
    for (i = 0; i < NN; i++) {
        ok &= keygen(&n[i], (uint8_t)i, 0x02) == 0;
    }
    CHECK(ok, "writer keys");
    if (!ok) {
        goto done;
    }
    world_init(w, X, 3);
    for (i = 0; i < NN; i++) {
        names_add(&w->names, n[i].fp);
    }
    CHECK(dht2_id_inbox(g_chain, R->fp, inbox) == 0 &&
          dht2_id_inbox_ctl(g_chain, R->fp, ctl_id) == 0, "inbox ids");

    /* Pools: 20 unnamed + 80 named fit; the next of each is 11. */
    ok = 1;
    for (i = 0; i < NU - 1; i++) {
        ok &= put_entry(w, st, &u[i], inbox, 1, &res) == 0;
    }
    CHECK(ok, "20 unnamed writers admitted");
    CHECK(put_entry(w, st, &u[NU - 1], inbox, 1, &res) == DHT2_E_POOL_FULL,
          "21st unnamed writer -> 11");
    ok = 1;
    for (i = 0; i < NN - 1; i++) {
        ok &= put_entry(w, st, &n[i], inbox, 1, &res) == 0;
    }
    CHECK(ok, "80 named writers admitted");
    CHECK(put_entry(w, st, &n[NN - 1], inbox, 1, &res) == DHT2_E_POOL_FULL,
          "81st named writer -> 11");
    /* A writer updating its own entry takes no second slot, in a full pool. */
    CHECK(put_entry(w, st, &u[0], inbox, 2, &res) == 0 &&
          res.outcome == NODUS_DHT2_PUT_STORED,
          "own entry updated in a full unnamed pool");
    CHECK(put_entry(w, st, &n[5], inbox, 2, &res) == 0,
          "own entry updated in a full named pool");

    /* LIST: 100 live entries, ≤ 16 a page, ascending, exclusive cursor. */
    total = list_all(w, st, inbox, &pages, last);
    CHECK(total == 100 && pages == 7, "100 entries in 7 pages of ≤ 16");
    CHECK(!last->has_ctl, "no control record yet: ctl null");

    /* A control record: only from the recipient. */
    ents[0] = (dht2_ctl_entry_t){ .mark = DHT2_CTL_DENIED, .through = 0 };
    memcpy(ents[0].fp, u[1].fp, DHT2_FP_LEN);
    ents[1] = (dht2_ctl_entry_t){ .mark = DHT2_CTL_HANDLED, .through = 5 };
    memcpy(ents[1].fp, n[0].fp, DHT2_FP_LEN);
    ents[2] = (dht2_ctl_entry_t){ .mark = DHT2_CTL_HANDLED, .through = 0 };
    memcpy(ents[2].fp, u[2].fp, DHT2_FP_LEN);
    CHECK(mk_ctl(&e, &u[3], ctl_id, 1, T0 + 3600, ents, 3) == 0 &&
          P(w, st, &e, &res) == DHT2_E_BAD_CLASS,
          "control signed by a stranger (id of R's inbox) -> 6");
    {
        uint8_t other_ctl[DHT2_ID_LEN];

        CHECK(dht2_id_inbox_ctl(g_chain, u[3].fp, other_ctl) == 0 &&
              mk_ctl(&e, R, other_ctl, 1, T0 + 3600, ents, 3) == 0 &&
              P(w, st, &e, &res) == DHT2_E_BAD_CLASS,
              "control signed by R for another recipient's id -> 6");
    }
    CHECK(total == 100 &&
          sql_i64(st, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4") == 100,
          "the refused controls dropped nothing");
    CHECK(mk_ctl(&ctl_env, R, ctl_id, 1, T0 + 3600, ents, 3) == 0 &&
          P(w, st, &ctl_env, &res) == 0 &&
          res.outcome == NODUS_DHT2_PUT_STORED, "control from R admitted");

    /* It dropped DENIED u1 and HANDLED n0 (seq 1 <= 5) at once; u2's
     * HANDLED through 0 dropped nothing (its Sequence is 1). */
    dht2_address(inbox, u[1].fp, addr);
    CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_NOT_HELD, "u1 dropped");
    dht2_address(inbox, n[0].fp, addr);
    CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_NOT_HELD, "n0 dropped");
    dht2_address(inbox, u[2].fp, addr);
    CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_HELD, "u2 kept");
    total = list_all(w, st, inbox, &pages, last);
    CHECK(total == 98, "98 entries listed after the control record");
    CHECK(last->has_ctl && hash_is(&ctl_env, last->ctl),
          "LIST carries the control record's hash");

    /* Admission against the selected control record. */
    CHECK(put_entry(w, st, &u[1], inbox, 7, &res) == DHT2_E_DENIED,
          "DENIED writer -> 12 (any Sequence)");
    CHECK(put_entry(w, st, &n[0], inbox, 3, &res) == DHT2_E_HANDLED &&
          res.through == 5, "HANDLED, Sequence 3 <= 5 -> [18, 5]");
    CHECK(put_entry(w, st, &n[0], inbox, 5, &res) == DHT2_E_HANDLED &&
          res.through == 5, "HANDLED, Sequence == through -> [18, 5]");
    CHECK(put_entry(w, st, &n[0], inbox, 6, &res) == 0 &&
          res.outcome == NODUS_DHT2_PUT_STORED,
          "Sequence 1 + through is admitted again");
    /* A dropped entry cannot come back by repair: its bytes again -> 18. */
    {
        static const uint8_t dat[4] = { 9, 8, 7, 6 };
        dht2_data_t          d;

        dbase(&d, DHT2_CLASS_INBOX_ENTRY, inbox, 1, T0 + 3600);
        d.has_data = true; d.data = dat; d.data_len = sizeof(dat);
        CHECK(mk(&dropped, &d, &n[0]) == 0 &&
              P(w, st, &dropped, &res) == DHT2_E_HANDLED && res.through == 5,
              "a repaired / pulled copy of the dropped entry -> 18");
    }
    /* Slots freed by the control record: u1 left the unnamed pool (19). */
    CHECK(put_entry(w, st, &u[NU - 1], inbox, 1, &res) == 0,
          "an unnamed slot freed by the control record is usable");

    /* A writer that gains a name moves pools on its next write: the
     * named pool is full again (80), so it is refused there while its old
     * unnamed entry stays where it was. */
    names_add(&w->names, u[4].fp);
    CHECK(put_entry(w, st, &u[4], inbox, 2, &res) == DHT2_E_POOL_FULL,
          "gained a name: judged against the NAMED pool (full) -> 11");
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4 AND named = 0");
    CHECK(sql_i64(st, sql) == 20, "the old unnamed entry is untouched");
    /* On a free pool it moves. */
    CHECK(dht2_id_inbox(g_chain, X->fp, inbox2) == 0 &&
          put_entry(w, st, &u[5], inbox2, 1, &res) == 0, "u5 in inbox 2");
    {
        char hex[2 * DHT2_HASH_LEN + 1];
        int  k;

        for (k = 0; k < (int)DHT2_HASH_LEN; k++) {
            snprintf(hex + 2 * k, 3, "%02x", inbox2[k]);
        }
        snprintf(sql, sizeof(sql),
                 "SELECT named FROM dht2_rec WHERE placement = x'%s'", hex);
    }
    CHECK(sql_i64(st, sql) == 0, "u5 starts in the unnamed pool");
    names_add(&w->names, u[5].fp);
    CHECK(put_entry(w, st, &u[5], inbox2, 2, &res) == 0 &&
          sql_i64(st, sql) == 1, "u5 gained a name: moved to the named pool");

    /* An expired entry is neither served nor listed. */
    w->snap.tip_time = T0 + 3600;
    dht2_address(inbox, u[2].fp, addr);
    CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_NOT_HELD,
          "expired entry not served");
    CHECK(list_all(w, st, inbox, &pages, last) == 0 && pages == 1,
          "expired entries are not listed (and the control record, which "
          "also expires at t+3600, no longer applies)");
    CHECK(!last->has_ctl, "an expired control record is not offered");

done:
    nodus_dht2_store_close(st);
    free(w);
    free(u);
    free(n);
    free(last);
}

/* ══ 5. get / sweep ════════════════════════════════════════════════════ */

static void test_expiry(const tkey_t *A, const tkey_t *C)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        r, tomb, perm;
    uint8_t             id[DHT2_ID_LEN], idt[DHT2_ID_LEN], idp[DHT2_ID_LEN];
    uint8_t             a1[DHT2_HASH_LEN], a2[DHT2_HASH_LEN],
                        a3[DHT2_HASH_LEN];
    uint64_t            del = 99;
    dht2_data_t         d;

    if (w == NULL || st == NULL) {
        CHECK(0, "expiry: setup");
        free(w);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    names_add(&w->names, C->fp);
    dfill(id, 0x41);
    dfill(idt, 0x42);
    dfill(idp, 0x43);
    addr_of(a1, id, A);
    addr_of(a2, idt, A);
    addr_of(a3, idp, C);
    CHECK(mk_owner(&r, A, id, 1, T0 + 1000, 5) == 0 &&
          mk_tomb(&tomb, A, idt, 1, T0 + 1000) == 0, "records");
    dbase(&d, DHT2_CLASS_OWNER, idp, 1, 0);
    d.validity_type = DHT2_VT_NONE;
    d.has_data = true; d.data = (const uint8_t *)"x"; d.data_len = 1;
    CHECK(mk(&perm, &d, C) == 0, "permanent record of a named writer");
    CHECK(P0(w, st, &r) == 0 && P0(w, st, &tomb) == 0 && P0(w, st, &perm) == 0,
          "stored: record, tombstone, permanent");

    CHECK(get_rc(w, st, a1) == NODUS_DHT2_GET_HELD &&
          get_rc(w, st, a2) == NODUS_DHT2_GET_HELD, "served before expiry");
    w->snap.tip_time = T0 + 999;
    CHECK(get_rc(w, st, a1) == NODUS_DHT2_GET_HELD, "served at expiry - 1");
    w->snap.tip_time = T0 + 1000;
    CHECK(get_rc(w, st, a1) == NODUS_DHT2_GET_NOT_HELD &&
          get_rc(w, st, a2) == NODUS_DHT2_GET_NOT_HELD,
          "never served at expiry <= t");
    CHECK(get_rc(w, st, a3) == NODUS_DHT2_GET_HELD, "permanent still served");

    /* The 3 h slack is for deletion only. */
    w->snap.tip_time = T0 + 1000 + H3 - 1;
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == 0 && del == 0 &&
          used_bytes(st) == (int64_t)(r.n + tomb.n + perm.n),
          "sweep 3 h - 1 s after expiry deletes nothing");
    w->snap.tip_time = T0 + 1000 + H3;
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == 0 && del == 2,
          "sweep 3 h after expiry deletes the record AND the tombstone");
    CHECK(used_bytes(st) == (int64_t)perm.n, "quota refunded by the delete");
    CHECK(get_rc(w, st, a3) == NODUS_DHT2_GET_HELD,
          "a record without expiry is never swept");
    w->ctx.snap = NULL;
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == DHT2_E_NOT_CAUGHT_UP &&
          get_rc(w, st, a3) == DHT2_E_NOT_CAUGHT_UP, "no snapshot -> 15");
    nodus_dht2_store_close(st);
    free(w);
}

/* ══ 6. insertion index, persistence, hand-over ════════════════════════ */

static void test_index(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    char                path[128];
    nodus_dht2_store_t *st = open_store(path);
    static env_t        a1, b1, a2;
    nodus_dht2_scan_entry_t se[4];
    uint8_t             ida[DHT2_ID_LEN], idb[DHT2_ID_LEN];
    uint8_t             aa[DHT2_HASH_LEN], ab[DHT2_HASH_LEN];
    size_t              cnt = 0;
    uint64_t            top = 99, g1;
    bool                pend = true, found = false;

    if (w == NULL || st == NULL) {
        CHECK(0, "index: setup");
        free(w);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    dfill(ida, 0x51);
    dfill(idb, 0x52);
    addr_of(aa, ida, A);
    addr_of(ab, idb, A);
    CHECK(top_of(st) == 0, "a fresh store: top = 0 (empty)");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 4, &cnt, &top) == 0 && cnt == 0 &&
          top == 0, "empty scan returns the top (0)");
    CHECK(mk_owner(&a1, A, ida, 1, T0 + 3600, 4) == 0 &&
          mk_owner(&b1, A, idb, 1, T0 + 3600, 4) == 0 &&
          mk_owner(&a2, A, ida, 2, T0 + 3600, 4) == 0, "records");
    CHECK(P0(w, st, &a1) == 0 && P0(w, st, &b1) == 0, "A1, B1 stored");
    CHECK(top_of(st) == 2, "the first index handed out is 1: top = 2");
    CHECK(P0(w, st, &a2) == 0, "A2 replaces A1");
    CHECK(top_of(st) == 3, "re-indexed at the top");
    CHECK(P0(w, st, &a2) == 0 && P0(w, st, &a1) == 0 && top_of(st) == 3,
          "equal / losing writes leave the counter alone");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 4, &cnt, &top) == 0 && cnt == 2 &&
          top == 3, "scan from 1: two entries, topmost 3");
    CHECK(se[0].index == 2 && memcmp(se[0].address, ab, 64) == 0 &&
          se[1].index == 3 && memcmp(se[1].address, aa, 64) == 0,
          "ascending; A's old index entry is gone (B at 2, A at 3)");
    CHECK(hash_is(&b1, se[0].hash) && hash_is(&a2, se[1].hash) &&
          memcmp(se[0].placement, ab, 64) == 0,
          "entries carry the envelope hash and the placement key");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,3, se, 4, &cnt, &top) == 0 && cnt == 1 &&
          se[0].index == 3, "scan from 3");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 1, &cnt, &top) == 0 && cnt == 1 &&
          top == 2, "page of 1: topmost is the highest scanned");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,4, se, 4, &cnt, &top) == 0 && cnt == 0 &&
          top == 3, "an empty interval still returns the top");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 251, &cnt, &top) == DHT2_E_ARG &&
          nodus_dht2_store_scan(st, &w->ctx,1, se, 0, &cnt, &top) == DHT2_E_ARG,
          "more than 250 per page is refused");

    /* Hand-over flag: data only; survives a replacement. */
    CHECK(nodus_dht2_store_handover_get(st, aa, &pend, &found) == 0 &&
          found && !pend, "no obligation by default");
    CHECK(nodus_dht2_store_handover_set(st, aa, true, &found) == 0 && found &&
          nodus_dht2_store_handover_get(st, aa, &pend, &found) == 0 && pend,
          "obligation set");
    {
        static env_t a3;
        uint8_t      unknown[DHT2_HASH_LEN];

        memset(unknown, 0x99, sizeof(unknown));
        CHECK(mk_owner(&a3, A, ida, 3, T0 + 3600, 4) == 0 &&
              P0(w, st, &a3) == 0 &&
              nodus_dht2_store_handover_get(st, aa, &pend, &found) == 0 &&
              pend, "a replacement keeps the obligation");
        CHECK(nodus_dht2_store_handover_set(st, unknown, true, &found) == 0 &&
              !found, "no such record");
    }

    /* Persistence: g and top across a reopen; the scan too. */
    g1 = nodus_dht2_store_generation(st);
    nodus_dht2_store_close(st);
    CHECK(nodus_dht2_store_open(path, g_other_chain) == NULL,
          "a store of another chain is not opened");
    st = nodus_dht2_store_open(path, g_chain);
    CHECK(st != NULL, "reopen");
    if (st != NULL) {
        CHECK(nodus_dht2_store_generation(st) == g1, "g persists");
        CHECK(top_of(st) == 4, "top persists");
        CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 4, &cnt, &top) == 0 &&
              cnt == 2 && top == 4, "scan after reopen");
        CHECK(nodus_dht2_store_handover_get(st, aa, &pend, &found) == 0 &&
              pend, "obligation persists");
    }
    nodus_dht2_store_close(st);
    CHECK(nodus_dht2_store_open("/nonexistent-dir-dht2/x.db", g_chain) == NULL,
          "an unopenable path is NULL, not a store");
    free(w);
}

/* ══ 7. a SQLite fault is a fault ══════════════════════════════════════ */

static void test_faults(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        r, r2;
    nodus_dht2_put_t    res;
    nodus_dht2_scan_entry_t se[2];
    dht2_list_answer_t *la = (dht2_list_answer_t *)malloc(sizeof(*la));
    uint8_t             id[DHT2_ID_LEN], id2[DHT2_ID_LEN], addr[DHT2_HASH_LEN],
                        inbox[DHT2_ID_LEN];
    uint64_t            del, top;
    size_t              cnt;

    if (w == NULL || st == NULL || la == NULL) {
        CHECK(0, "faults: setup");
        goto done;
    }
    world_init(w, A, 3);
    dfill(id, 0x61);
    dfill(id2, 0x62);
    dfill(inbox, 0x63);
    addr_of(addr, id, A);
    CHECK(mk_owner(&r, A, id, 1, T0 + 3600, 4) == 0 &&
          mk_owner(&r2, A, id2, 1, T0 + 3600, 4) == 0 &&
          P0(w, st, &r) == 0, "one record stored");

    /* A connection that refuses writes: a put is a fault; a read is not. */
    CHECK(sqlite3_exec(nodus_dht2_store_db(st), "PRAGMA query_only = ON",
                       NULL, NULL, NULL) == SQLITE_OK, "query_only on");
    CHECK(P(w, st, &r2, &res) == DHT2_E_HOLDER_FAULT, "write refused -> 16");
    CHECK(res.outcome == 0 && res.through == 0, "a fault carries no outcome");
    CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_HELD,
          "reads still work on that connection");
    CHECK(sqlite3_exec(nodus_dht2_store_db(st), "PRAGMA query_only = OFF",
                       NULL, NULL, NULL) == SQLITE_OK, "query_only off");
    CHECK(P0(w, st, &r2) == 0, "and the store recovers: nothing was half-done");
    CHECK(top_of(st) == 2, "counter consistent after the refused write");

    /* A FAILED BIND is a fault, not "not held" and not success: with the
     * blob length limit below 64 bytes every key bind returns TOOBIG
     * (before the fix the statement ran with NULL bound). */
    {
        bool found = true, pend2 = false;
        int  old_lim = sqlite3_limit(nodus_dht2_store_db(st),
                                     SQLITE_LIMIT_LENGTH, 32);

        CHECK(get_rc(w, st, addr) == DHT2_E_HOLDER_FAULT,
              "get with a failing bind -> 16, not 'not held'");
        CHECK(nodus_dht2_store_handover_set(st, addr, true, &found)
              == DHT2_E_HOLDER_FAULT, "handover update, failing bind -> 16");
        CHECK(nodus_dht2_store_handover_get(st, addr, &pend2, &found)
              == DHT2_E_HOLDER_FAULT, "handover read, failing bind -> 16");
        CHECK(P(w, st, &r, &res) == DHT2_E_HOLDER_FAULT,
              "put with failing binds -> 16");
        (void)sqlite3_limit(nodus_dht2_store_db(st), SQLITE_LIMIT_LENGTH,
                            old_lim);
        CHECK(get_rc(w, st, addr) == NODUS_DHT2_GET_HELD,
              "limit restored: the record was never touched");
    }

    /* The table is gone: every call that touches it is a fault. */
    CHECK(sqlite3_exec(nodus_dht2_store_db(st), "DROP TABLE dht2_rec", NULL,
                       NULL, NULL) == SQLITE_OK, "table dropped");
    CHECK(get_rc(w, st, addr) == DHT2_E_HOLDER_FAULT, "get -> 16, not absent");
    CHECK(nodus_dht2_store_list(st, &w->ctx, inbox, NULL, la)
          == DHT2_E_HOLDER_FAULT, "list -> 16, not an empty page");
    CHECK(nodus_dht2_store_scan(st, &w->ctx,1, se, 2, &cnt, &top)
          == DHT2_E_HOLDER_FAULT, "scan -> 16");
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == DHT2_E_HOLDER_FAULT,
          "sweep -> 16");
    CHECK(P(w, st, &r, &res) == DHT2_E_HOLDER_FAULT, "put -> 16");

done:
    nodus_dht2_store_close(st);
    free(w);
    free(la);
}

/* ══ main ══════════════════════════════════════════════════════════════ */

/* ══ 8. the review round: gate, precedence, memo, credit, select ══════ */

static int mk_entry(env_t *e, const tkey_t *wr,
                    const uint8_t inbox[DHT2_ID_LEN], uint64_t seq)
{
    static const uint8_t dat[4] = { 9, 8, 7, 6 };
    dht2_data_t          d;

    dbase(&d, DHT2_CLASS_INBOX_ENTRY, inbox, seq, T0 + 3600);
    d.has_data = true; d.data = dat; d.data_len = sizeof(dat);
    return mk(e, &d, wr);
}

/* A control record with at most one entry (fp NULL = an empty list). */
static int mk_ctl1(env_t *e, const tkey_t *R, const uint8_t ctl_id[64],
                   uint64_t seq, uint64_t expiry, const uint8_t *fp,
                   uint8_t mark, uint64_t through)
{
    dht2_ctl_entry_t en;

    memset(&en, 0, sizeof(en));
    if (fp != NULL) {
        memcpy(en.fp, fp, DHT2_FP_LEN);
    }
    en.mark = mark;
    en.through = through;
    return mk_ctl(e, R, ctl_id, seq, expiry, &en, fp != NULL ? 1 : 0);
}

/* items 2, 6, 9: the call-level gate, the u64 / int64 edges, the chain. */
static void test_gate(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    char                path[128];
    nodus_dht2_store_t *st = open_store(path);
    static env_t        r, r2, buf;
    nodus_dht2_put_t    res;
    dht2_list_answer_t *la = (dht2_list_answer_t *)malloc(sizeof(*la));
    nodus_dht2_scan_entry_t se[2];
    uint8_t             id[DHT2_ID_LEN], id2[DHT2_ID_LEN], addr[DHT2_HASH_LEN];
    uint8_t             h[DHT2_HASH_LEN];
    uint64_t            del = 0, top = 0;
    size_t              cnt = 0, n = 0;
    nodus_witness_dht_snap_t good;

    if (w == NULL || st == NULL || la == NULL) {
        CHECK(0, "gate: setup");
        goto done;
    }
    world_init(w, A, 3);
    dfill(id, 0x71);
    dfill(id2, 0x72);
    addr_of(addr, id, A);
    CHECK(mk_owner(&r, A, id, 1, T0 + 3600, 4) == 0 &&
          mk_owner(&r2, A, id2, 1, T0 + 3600, 4) == 0 &&
          P0(w, st, &r) == 0, "one record stored");
    good = w->snap;

    /* item 2: the witness is in block sync -> every call is 15. */
    w->snap.consensus_up = false;
    CHECK(P(w, st, &r2, &res) == DHT2_E_NOT_CAUGHT_UP, "put, cu false -> 15");
    CHECK(nodus_dht2_store_get(st, &w->ctx, addr, buf.b, sizeof(buf.b), &n, h)
          == DHT2_E_NOT_CAUGHT_UP, "get, cu false -> 15");
    CHECK(nodus_dht2_store_list(st, &w->ctx, id, NULL, la)
          == DHT2_E_NOT_CAUGHT_UP, "list, cu false -> 15");
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == DHT2_E_NOT_CAUGHT_UP,
          "sweep, cu false -> 15");
    CHECK(nodus_dht2_store_scan(st, &w->ctx, 1, se, 2, &cnt, &top)
          == DHT2_E_NOT_CAUGHT_UP, "scan, cu false -> 15");
    CHECK(top_of(st) == 1, "nothing stored while behind");
    w->snap = good;
    CHECK(P0(w, st, &r2) == 0, "caught up again: admitted");

    /* item 6: a snapshot time no bound fits into SQLite's int64. */
    w->snap.tip_time = (uint64_t)INT64_MAX;
    CHECK(P(w, st, &r2, &res) == DHT2_E_NOT_CAUGHT_UP &&
          nodus_dht2_store_sweep(st, &w->ctx, &del) == DHT2_E_NOT_CAUGHT_UP,
          "tip time near INT64_MAX -> 15");
    w->snap = good;

    /* item 9: a snapshot of another chain -> 16 on every call. */
    memcpy(w->snap.chain_id, g_other_chain, DHT2_CHAIN_LEN);
    CHECK(P(w, st, &r2, &res) == DHT2_E_HOLDER_FAULT, "put, other chain -> 16");
    CHECK(nodus_dht2_store_get(st, &w->ctx, addr, buf.b, sizeof(buf.b), &n, h)
          == DHT2_E_HOLDER_FAULT, "get, other chain -> 16");
    CHECK(nodus_dht2_store_list(st, &w->ctx, id, NULL, la)
          == DHT2_E_HOLDER_FAULT, "list, other chain -> 16");
    CHECK(nodus_dht2_store_sweep(st, &w->ctx, &del) == DHT2_E_HOLDER_FAULT,
          "sweep, other chain -> 16");
    CHECK(nodus_dht2_store_scan(st, &w->ctx, 1, se, 2, &cnt, &top)
          == DHT2_E_HOLDER_FAULT, "scan, other chain -> 16");
    w->snap = good;

    /* item 6: an index above INT64_MAX is never handed out. */
    CHECK(nodus_dht2_store_scan(st, &w->ctx, UINT64_MAX, se, 2, &cnt, &top)
          == 0 && cnt == 0 && top == 2,
          "scan from above INT64_MAX: empty page, current top");
    CHECK(sqlite3_exec(nodus_dht2_store_db(st),
                       "UPDATE dht2_meta SET v = 9223372036854775807 "
                       "WHERE k = 'top'", NULL, NULL, NULL) == SQLITE_OK,
          "counter at INT64_MAX");
    {
        static env_t r3;
        uint8_t      id3[DHT2_ID_LEN];

        dfill(id3, 0x73);
        CHECK(mk_owner(&r3, A, id3, 1, T0 + 3600, 4) == 0 &&
              P(w, st, &r3, &res) == DHT2_E_HOLDER_FAULT,
              "no index above INT64_MAX: a fault");
    }

    /* item 7: a counter BEHIND the highest index makes the clash a fault
     * and leaves every row where it was. */
    CHECK(sqlite3_exec(nodus_dht2_store_db(st),
                       "UPDATE dht2_meta SET v = 1 WHERE k = 'top'", NULL,
                       NULL, NULL) == SQLITE_OK, "counter behind (1 < 2)");
    {
        static env_t r4;
        uint8_t      id4[DHT2_ID_LEN];

        dfill(id4, 0x74);
        CHECK(mk_owner(&r4, A, id4, 1, T0 + 3600, 4) == 0 &&
              P(w, st, &r4, &res) == DHT2_E_HOLDER_FAULT,
              "index clash: a fault, not a silent delete");
        CHECK(sql_i64(st, "SELECT COUNT(*) FROM dht2_rec") == 2,
              "both rows survived");
    }
    nodus_dht2_store_close(st);
    st = nodus_dht2_store_open(path, g_chain);
    CHECK(st == NULL, "open refuses a counter below the highest index");

    /* item 7: records without a counter / incomplete meta are not opened. */
    {
        nodus_dht2_store_t *s2 = open_store(path);
        nodus_dht2_store_t *s3;

        CHECK(s2 != NULL && P0(w, s2, &r) == 0, "second store, one record");
        CHECK(s2 != NULL &&
              sqlite3_exec(nodus_dht2_store_db(s2),
                           "DELETE FROM dht2_meta WHERE k = 'top'", NULL,
                           NULL, NULL) == SQLITE_OK, "counter row removed");
        nodus_dht2_store_close(s2);
        s3 = nodus_dht2_store_open(path, g_chain);
        CHECK(s3 == NULL, "records but no counter: not opened, not reset");
        nodus_dht2_store_close(s3);
    }
done:
    nodus_dht2_store_close(st);
    free(w);
    free(la);
}

/* item 5: ValidityType <=> Validity is a class rule, after chain. */
static void test_mismatch(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        e;
    nodus_dht2_put_t    res;
    uint8_t             id[DHT2_ID_LEN];
    dht2_data_t         d;

    if (w == NULL || st == NULL) {
        CHECK(0, "mismatch: setup");
        free(w);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    dfill(id, 0x75);
    /* A no-expiry record (ValidityType 1, empty Validity), then its LAST
     * byte — the data map's last key is ValidityType — flipped to 0: type 0
     * with an empty Validity. The signature no longer verifies, which is
     * exactly the point: the verdict must come before the signature. */
    dbase(&d, DHT2_CLASS_OWNER, id, 1, 0);
    d.validity_type = DHT2_VT_NONE;
    d.has_data = true; d.data = (const uint8_t *)"x"; d.data_len = 1;
    memcpy(d.chain, g_other_chain, DHT2_CHAIN_LEN);
    CHECK(mk(&e, &d, A) == 0 && e.b[e.n - 1] == 0x01, "other-chain record");
    e.b[e.n - 1] = 0x00;
    CHECK(P(w, st, &e, &res) == DHT2_E_BAD_CHAIN,
          "mismatch + wrong chain -> 3 (chain comes first)");
    memcpy(d.chain, g_chain, DHT2_CHAIN_LEN);
    CHECK(mk(&e, &d, A) == 0, "right-chain record");
    e.b[e.n - 1] = 0x00;
    CHECK(P(w, st, &e, &res) == DHT2_E_BAD_CLASS,
          "mismatch on the right chain -> 6 (a class rule)");
    CHECK(w->names.calls == 0, "refused before the name request");
    nodus_dht2_store_close(st);
    free(w);
}

/* item 3: a dropped entry cannot come back; item 4: a control record's
 * own deletions are credited. */
static void test_memo(const tkey_t *R, const tkey_t *X)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    world_t            *w2 = (world_t *)calloc(1, sizeof(*w2));
    tkey_t             *k = (tkey_t *)calloc(3, sizeof(tkey_t));
    nodus_dht2_store_t *s1 = open_store(NULL);
    nodus_dht2_store_t *s2 = open_store(NULL);
    nodus_dht2_store_t *sa = open_store(NULL);
    nodus_dht2_store_t *sb = open_store(NULL);
    static env_t        e, ctl, ga, gb;
    nodus_dht2_put_t    res;
    uint8_t             inbox[DHT2_ID_LEN], ctl_id[DHT2_ID_LEN];
    uint8_t             a_ctl[DHT2_HASH_LEN];
    int                 i, ok = 1;

    if (w == NULL || w2 == NULL || k == NULL || s1 == NULL || s2 == NULL ||
        sa == NULL || sb == NULL) {
        CHECK(0, "memo: setup");
        goto done;
    }
    for (i = 0; i < 3; i++) {
        ok &= keygen(&k[i], (uint8_t)(0x90 + i), 0x01) == 0;
    }
    CHECK(ok, "writer keys");
    if (!ok) {
        goto done;
    }
    world_init(w, X, 3);
    world_init(w2, X, 3);
    CHECK(dht2_id_inbox(g_chain, R->fp, inbox) == 0 &&
          dht2_id_inbox_ctl(g_chain, R->fp, ctl_id) == 0, "ids");
    dht2_address(ctl_id, R->fp, a_ctl);

    /* The selected control record drops E and is the only thing admission
     * consults: [18, through] while it lists W, nothing once it does not
     * (no holder memory — the owner keeps W listed, a client rule). */
    CHECK(put_entry(w, s1, &k[0], inbox, 1, &res) == 0, "E stored");
    CHECK(mk_ctl1(&ctl, R, ctl_id, 1, T0 + 3600, k[0].fp, DHT2_CTL_HANDLED, 5)
          == 0 && P0(w, s1, &ctl) == 0, "control v1 stored");
    CHECK(sql_i64(s1, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4") == 0,
          "E dropped by v1");
    CHECK(put_entry(w, s1, &k[0], inbox, 1, &res) == DHT2_E_HANDLED &&
          res.through == 5, "E again -> [18, 5]");
    CHECK(put_entry(w, s1, &k[0], inbox, 5, &res) == DHT2_E_HANDLED &&
          res.through == 5, "Sequence == cutoff -> [18, 5]");
    CHECK(put_entry(w, s1, &k[0], inbox, 6, &res) == 0,
          "Sequence above the cutoff is admitted");
    CHECK(mk_ctl1(&ctl, R, ctl_id, 2, T0 + 3600, NULL, 0, 0) == 0 &&
          P(w, s1, &ctl, &res) == 0 && res.outcome == NODUS_DHT2_PUT_STORED,
          "control v2 (W no longer listed) wins");
    CHECK(put_entry(w, s1, &k[0], inbox, 7, &res) == 0 &&
          res.outcome == NODUS_DHT2_PUT_STORED,
          "and nothing remembers v1: the holder follows the selected record");

    /* The selected control record expiring ends its effect on admission. */
    CHECK(put_entry(w2, s2, &k[1], inbox, 1, &res) == 0, "E2 stored");
    CHECK(mk_ctl1(&ctl, R, ctl_id, 1, T0 + 100, k[1].fp, DHT2_CTL_HANDLED, 5)
          == 0 && P0(w2, s2, &ctl) == 0, "short-lived control stored");
    w2->snap.tip_time = T0 + 200;
    CHECK(put_entry(w2, s2, &k[1], inbox, 1, &res) == 0,
          "control expired: it no longer applies (no memo)");

    /* DENIED: refused while listed; an un-listed writer may write again. */
    CHECK(mk_ctl1(&ctl, R, ctl_id, 3, T0 + 3600, k[2].fp, DHT2_CTL_DENIED, 0)
          == 0 && P0(w, s1, &ctl) == 0 &&
          put_entry(w, s1, &k[2], inbox, 1, &res) == DHT2_E_DENIED,
          "DENIED while listed");
    CHECK(mk_ctl1(&ctl, R, ctl_id, 4, T0 + 3600, NULL, 0, 0) == 0 &&
          P0(w, s1, &ctl) == 0 &&
          put_entry(w, s1, &k[2], inbox, 1, &res) == 0,
          "un-denied: admitted again");

    /* Arrival order: v1 {W 5} then v2 {W 7}, against v2 then v1 (v1 loses
     * Select and changes nothing): the same entries, the same cutoff. */
    CHECK(put_entry(w, sa, &k[0], inbox, 1, &res) == 0 &&
          put_entry(w, sa, &k[1], inbox, 1, &res) == 0 &&
          put_entry(w, sb, &k[0], inbox, 1, &res) == 0 &&
          put_entry(w, sb, &k[1], inbox, 1, &res) == 0, "E, F on both");
    {
        static env_t v1, v2;

        CHECK(mk_ctl1(&v1, R, ctl_id, 1, T0 + 3600, k[0].fp,
                      DHT2_CTL_HANDLED, 5) == 0 &&
              mk_ctl1(&v2, R, ctl_id, 2, T0 + 3600, k[0].fp,
                      DHT2_CTL_HANDLED, 7) == 0, "v1, v2");
        CHECK(P0(w, sa, &v1) == 0 && P0(w, sa, &v2) == 0, "A: v1 then v2");
        CHECK(P0(w, sb, &v2) == 0 && P(w, sb, &v1, &res) == 0 &&
              res.outcome == NODUS_DHT2_PUT_LOST, "B: v2 then v1 (loses)");
    }
    CHECK(sql_i64(sa, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4") == 1 &&
          sql_i64(sb, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4") == 1,
          "both stores hold only F");
    CHECK(held(w, sa, a_ctl, &ga) && held(w, sb, a_ctl, &gb) &&
          ga.n == gb.n && memcmp(ga.b, gb.b, ga.n) == 0,
          "and the same control record");
    CHECK(put_entry(w, sa, &k[0], inbox, 6, &res) == DHT2_E_HANDLED &&
          res.through == 7 &&
          put_entry(w, sb, &k[0], inbox, 6, &res) == DHT2_E_HANDLED &&
          res.through == 7, "same verdict on both: [18, 7]");

    /* ACCEPTED BEHAVIOUR, documented: v1 = {W HANDLED 5} seq 1, v2 = empty
     * seq 2 (W no longer listed). v1 then v2 drops E; v2 then v1 keeps E
     * (v1 loses Select and changes nothing — row 16). The operator's CLIENT
     * rule (decision 2026-10-24-dht-v2-handled-client-rule.md: the owner
     * keeps W listed until its entries expired) prevents this case in
     * practice; the holder does not. */
    {
        nodus_dht2_store_t *sc = open_store(NULL);
        nodus_dht2_store_t *sd = open_store(NULL);
        static env_t        v1, v2, ha, hb;

        CHECK(sc != NULL && sd != NULL, "stores");
        CHECK(mk_ctl1(&v1, R, ctl_id, 1, T0 + 3600, k[0].fp,
                      DHT2_CTL_HANDLED, 5) == 0 &&
              mk_ctl1(&v2, R, ctl_id, 2, T0 + 3600, NULL, 0, 0) == 0, "v1, v2");
        if (sc != NULL && sd != NULL) {
            CHECK(put_entry(w, sc, &k[0], inbox, 1, &res) == 0 &&
                  put_entry(w, sc, &k[1], inbox, 1, &res) == 0 &&
                  put_entry(w, sd, &k[0], inbox, 1, &res) == 0 &&
                  put_entry(w, sd, &k[1], inbox, 1, &res) == 0, "E, F");
            CHECK(P0(w, sc, &v1) == 0 && P0(w, sc, &v2) == 0, "C: v1, v2");
            CHECK(P0(w, sd, &v2) == 0 &&
                  P(w, sd, &v1, &res) == 0 &&
                  res.outcome == NODUS_DHT2_PUT_LOST,
                  "D: v2, then v1 (loses Select)");
            CHECK(sql_i64(sc, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4")
                  == 1 &&
                  sql_i64(sd, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4")
                  == 2, "v1 -> v2: E dropped (1 left); v2 -> v1: E kept (2)");
            {
                uint8_t ea[DHT2_HASH_LEN];

                dht2_address(inbox, k[0].fp, ea);
                CHECK(get_rc(w, sc, ea) == NODUS_DHT2_GET_NOT_HELD &&
                      get_rc(w, sd, ea) == NODUS_DHT2_GET_HELD,
                      "E is gone on C and still held on D");
            }
            CHECK(held(w, sc, a_ctl, &ha) && held(w, sd, a_ctl, &hb) &&
                  ha.n == hb.n && memcmp(ha.b, hb.b, ha.n) == 0,
                  "the selected control record is v2 on both (the loser "
                  "is not stored)");
        }
        nodus_dht2_store_close(sc);
        nodus_dht2_store_close(sd);
    }

    /* Row 16: a LOSING control record and a QUOTA-REFUSED control record
     * change nothing — entries, counter and bytes stay exactly as they
     * were (no HANDLED side effect). */
    {
        nodus_dht2_store_t *sq = open_store(NULL);
        static env_t        v1, v2, v3;
        int64_t             top0, used0;
        uint8_t             ea[DHT2_HASH_LEN];

        dht2_address(inbox, k[0].fp, ea);
        CHECK(sq != NULL && mk_ctl1(&v1, R, ctl_id, 1, T0 + 3600, k[0].fp,
                                    DHT2_CTL_HANDLED, 5) == 0 &&
              mk_ctl1(&v2, R, ctl_id, 2, T0 + 3600, NULL, 0, 0) == 0 &&
              mk_ctl1(&v3, R, ctl_id, 3, T0 + 3600, k[0].fp,
                      DHT2_CTL_HANDLED, 5) == 0 &&
              put_entry(w, sq, &k[0], inbox, 1, &res) == 0 &&
              put_entry(w, sq, &k[1], inbox, 1, &res) == 0 &&
              P0(w, sq, &v2) == 0, "sq: E, F, control v2 stored");
        if (sq != NULL) {
            top0 = top_of(sq);
            used0 = used_bytes(sq);
            CHECK(P(w, sq, &v1, &res) == 0 &&
                  res.outcome == NODUS_DHT2_PUT_LOST, "v1 loses Select");
            CHECK(top_of(sq) == top0 && used_bytes(sq) == used0 &&
                  sql_i64(sq, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4")
                  == 2 && get_rc(w, sq, ea) == NODUS_DHT2_GET_HELD,
                  "a losing control: entries, counter, bytes unchanged");
            w->ctx.limits.ident_unnamed = 1;
            CHECK(P0(w, sq, &v3) == DHT2_E_QUOTA, "v3 is refused by quota: 10");
            nodus_dht2_limits_default(&w->ctx.limits);
            CHECK(top_of(sq) == top0 && used_bytes(sq) == used0 &&
                  sql_i64(sq, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4")
                  == 2 && get_rc(w, sq, ea) == NODUS_DHT2_GET_HELD,
                  "a quota-refused control: full rollback, E not dropped");
        }
        nodus_dht2_store_close(sq);
    }

    /* item 4: a control record that frees space is accepted at a full pool.
     * Unnamed pool = entry + control - 10 bytes. */
    {
        nodus_dht2_store_t *sc = open_store(NULL);
        static env_t        en, c_free, c_none;
        uint8_t             stranger[DHT2_FP_LEN];

        memset(stranger, 0x44, sizeof(stranger));
        CHECK(sc != NULL && mk_entry(&en, &k[0], inbox, 1) == 0 &&
              mk_ctl1(&c_free, R, ctl_id, 1, T0 + 3600, k[0].fp,
                      DHT2_CTL_DENIED, 0) == 0 &&
              mk_ctl1(&c_none, R, ctl_id, 1, T0 + 3600, stranger,
                      DHT2_CTL_DENIED, 0) == 0, "records");
        if (sc != NULL) {
            nodus_dht2_limits_default(&w->ctx.limits);
            w->ctx.limits.pool_unnamed = en.n + c_free.n - 10;
            CHECK(P0(w, sc, &en) == 0, "entry fits the pool");
            CHECK(P0(w, sc, &c_none) == DHT2_E_NODE_FULL,
                  "a control that frees nothing does not fit -> 13");
            CHECK(sql_i64(sc, "SELECT COUNT(*) FROM dht2_rec") == 1,
                  "the refusal rolled back");
            CHECK(P0(w, sc, &c_free) == 0, "a control that frees the entry's "
                  "bytes IS accepted at the full pool");
            CHECK(sql_i64(sc, "SELECT COUNT(*) FROM dht2_rec WHERE cls = 4")
                  == 0, "and the entry is gone");
        }
        nodus_dht2_store_close(sc);
    }
    (void)e;
    (void)gb;

done:
    nodus_dht2_store_close(s1);
    nodus_dht2_store_close(s2);
    nodus_dht2_store_close(sa);
    nodus_dht2_store_close(sb);
    free(w);
    free(w2);
    free(k);
}

/* items 8, 10: an expired held row counts as absent; a tombstone never
 * moves pools. */
static void test_select_pool(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        old5, fresh1, big, tomb, again, got;
    nodus_dht2_put_t    res;
    uint8_t             id[DHT2_ID_LEN], id2[DHT2_ID_LEN], addr[DHT2_HASH_LEN];
    uint8_t             addr2[DHT2_HASH_LEN];

    if (w == NULL || st == NULL) {
        CHECK(0, "select_pool: setup");
        free(w);
        nodus_dht2_store_close(st);
        return;
    }
    world_init(w, A, 3);
    dfill(id, 0x81);
    dfill(id2, 0x82);
    addr_of(addr, id, A);
    addr_of(addr2, id2, A);

    /* item 8: seq 5 expired (unswept) is replaced by a fresh seq 1. */
    CHECK(mk_owner(&old5, A, id, 5, T0 + 1000, 4) == 0 &&
          P0(w, st, &old5) == 0, "seq 5 stored");
    w->snap.tip_time = T0 + 2000;
    CHECK(mk_owner(&fresh1, A, id, 1, T0 + 4000, 4) == 0 &&
          P(w, st, &fresh1, &res) == 0 &&
          res.outcome == NODUS_DHT2_PUT_STORED && hash_is(&fresh1, res.hash),
          "expired seq 5 counts as absent: seq 1 STORED");
    CHECK(held(w, st, addr, &got) && got.n == fresh1.n &&
          memcmp(got.b, fresh1.b, got.n) == 0 && top_of(st) == 2,
          "the fresh version is served; re-indexed at the top");
    CHECK(P(w, st, &old5, &res) == DHT2_E_EXPIRED, "the old one is 7 now");
    w->snap.tip_time = T0;

    /* item 10: A gained a name; the named pool is full; the tombstone
     * replacing a larger record is still accepted and stays in its pool. */
    CHECK(mk_owner(&big, A, id2, 1, T0 + 3600, 1000) == 0 &&
          P0(w, st, &big) == 0, "large unnamed record stored");
    names_add(&w->names, A->fp);
    w->ctx.limits.pool_named = 1;
    CHECK(mk_tomb(&tomb, A, id2, 2, T0 + 3600) == 0 && tomb.n < big.n &&
          P(w, st, &tomb, &res) == 0 && res.outcome == NODUS_DHT2_PUT_STORED,
          "tombstone accepted despite the full named pool");
    {
        char hex[2 * DHT2_HASH_LEN + 1], sql[256];
        int  k;

        for (k = 0; k < (int)DHT2_HASH_LEN; k++) {
            snprintf(hex + 2 * k, 3, "%02x", addr2[k]);
        }
        snprintf(sql, sizeof(sql),
                 "SELECT named FROM dht2_rec WHERE address = x'%s'", hex);
        CHECK(sql_i64(st, sql) == 0, "charged to the pool it was in");
    }
    CHECK(mk_owner(&again, A, id2, 3, T0 + 3600, 10) == 0 &&
          P0(w, st, &again) == DHT2_E_NODE_FULL,
          "a live record of the named writer meets the named pool (13)");
    nodus_dht2_store_close(st);
    free(w);
}

/* Package 6a second fix round: a refusal that comes AFTER the parse keeps the
 * envelope's address in the result (the serving layer names the result by
 * it); one that fails the parse has none. */
static void test_put_address(const tkey_t *A)
{
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static env_t        e;
    nodus_dht2_put_t    res;
    uint8_t             id[DHT2_ID_LEN], want[DHT2_HASH_LEN];
    int                 rc;

    CHECK(w != NULL && st != NULL, "alloc");
    if (w == NULL || st == NULL) {
        free(w);
        return;
    }
    world_init(w, A, 3);
    dfill(id, 0x5B);
    CHECK(dht2_address(id, A->fp, want) == 0, "address");

    CHECK(mk_owner(&e, A, id, 1, T0 - 1, 4) == 0, "expired record");
    rc = P(w, st, &e, &res);
    CHECK(rc == DHT2_E_EXPIRED, "late refusal: expired (7)");
    CHECK(res.has_address && memcmp(res.address, want, DHT2_HASH_LEN) == 0,
          "late refusal keeps the address");

    CHECK(mk_owner(&e, A, id, 1, T0 + 3600, 4) == 0, "good record");
    rc = P(w, st, &e, &res);
    CHECK(rc == 0 && res.has_address &&
              memcmp(res.address, want, DHT2_HASH_LEN) == 0,
          "success carries the address too");

    memset(e.b, 0xFF, 10);
    e.n = 10;
    rc = P(w, st, &e, &res);
    CHECK(rc == DHT2_E_BAD_ENCODING && !res.has_address,
          "a parse failure has no address");
    nodus_dht2_store_close(st);
    free(w);
}

/* Package 6a fix round (item 6): the live control record's bytes are part of
 * the 2 MiB LIST page. Eight entries of 262,000 B (2,096,000 B) fit the
 * budget alone, but not beside a control record: the first page lists 7 and
 * is not complete; the next page lists the eighth. */
static void test_list_ctl_budget(const tkey_t *R)
{
    enum { NW = 8, ENTRY_TARGET = 262000 };
    world_t            *w = (world_t *)calloc(1, sizeof(*w));
    nodus_dht2_store_t *st = open_store(NULL);
    static uint8_t      big[262144];
    static uint8_t      payload[262144];
    static env_t        ctl;
    tkey_t             *wr = (tkey_t *)calloc(NW, sizeof(*wr));
    dht2_list_answer_t *la = (dht2_list_answer_t *)malloc(sizeof(*la));
    uint8_t             inbox[DHT2_ID_LEN], ctl_id[DHT2_ID_LEN];
    size_t              blen = 0, overhead = 0, dlen = 0;
    int                 i;
    bool                all_ok = true;

    CHECK(w != NULL && st != NULL && wr != NULL && la != NULL, "alloc");
    if (w == NULL || st == NULL || wr == NULL || la == NULL) {
        goto done;
    }
    world_init(w, R, 3);
    CHECK(dht2_id_inbox(g_chain, R->fp, inbox) == 0 &&
              dht2_id_inbox_ctl(g_chain, R->fp, ctl_id) == 0, "ids");
    memset(payload, 0xCD, sizeof(payload));
    CHECK(mk_ctl1(&ctl, R, ctl_id, 1, T0 + 3600, NULL, 0, 0) == 0 &&
              P0(w, st, &ctl) == 0, "control record stored");

    for (i = 0; i < NW; i++) {
        dht2_data_t d;
        nodus_dht2_put_t res;

        all_ok = all_ok && keygen(&wr[i], (uint8_t)(0x40 + i), 7) == 0;
        dbase(&d, DHT2_CLASS_INBOX_ENTRY, inbox, 1, T0 + 3600);
        d.has_data = true;
        d.data = payload;
        /* The first build measures the envelope overhead; the data length
         * then makes every entry ENTRY_TARGET bytes. */
        d.data_len = dlen == 0 ? 200000 : dlen;
        all_ok = all_ok &&
                 dht2_record_build(&d, wr[i].sk, wr[i].pk, big, sizeof(big),
                                   &blen) == DHT2_OK;
        if (dlen == 0 && all_ok) {
            overhead = blen - 200000;
            dlen = (size_t)ENTRY_TARGET - overhead;
            d.data_len = dlen;
            all_ok = dht2_record_build(&d, wr[i].sk, wr[i].pk, big,
                                       sizeof(big), &blen) == DHT2_OK;
        }
        all_ok = all_ok && blen == (size_t)ENTRY_TARGET &&
                 nodus_dht2_store_put(st, &w->ctx, big, blen, NULL, &res) == 0;
    }
    CHECK(all_ok, "eight 262,000 B entries built and stored");

    CHECK(nodus_dht2_store_list(st, &w->ctx, inbox, NULL, la) == 0, "page 1");
    CHECK(la->has_ctl, "the control record is beside the page");
    CHECK(la->list_count == 7 && !la->complete,
          "entries + control stay within 2 MiB: 7 entries, not complete");
    {
        uint8_t cur[DHT2_FP_LEN];

        memcpy(cur, la->cursor, DHT2_FP_LEN);
        CHECK(nodus_dht2_store_list(st, &w->ctx, inbox, cur, la) == 0 &&
                  la->list_count == 1 && la->complete,
              "page 2: the eighth entry, complete");
    }
done:
    if (st != NULL) {
        nodus_dht2_store_close(st);
    }
    free(w);
    free(wr);
    free(la);
}

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
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_dht2_store_XXXXXX");
    if (mkdtemp(g_dir) == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "mkdtemp failed");
        free(keys);
        return 1;
    }
    ok = keygen(&keys[0], 0xA1, 0) == 0 && keygen(&keys[1], 0xB2, 0) == 0 &&
         keygen(&keys[2], 0xC3, 0) == 0 && keygen(&keys[3], 0xD4, 0) == 0 &&
         keygen(&keys[4], 0xE5, 0) == 0;
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "keypairs");
        cleanup();
        free(keys);
        return 1;
    }

    QGP_LOG_INFO(LOG_TAG, "=== DHT v2 holder store (package 5) ===");
    test_codes(&keys[0], &keys[1], &keys[2]);
    test_select(&keys[0]);
    test_quota(&keys[0], &keys[1], &keys[2]);
    test_inbox(&keys[3], &keys[4]);
    test_expiry(&keys[0], &keys[2]);
    test_index(&keys[0]);
    test_faults(&keys[0]);
    test_gate(&keys[0]);
    test_mismatch(&keys[0]);
    test_memo(&keys[3], &keys[4]);
    test_select_pool(&keys[1]);
    test_list_ctl_budget(&keys[2]);
    test_put_address(&keys[0]);
    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===",
                 g_pass, g_fail);

    cleanup();
    memset(keys, 0, 5 * sizeof(tkey_t));
    free(keys);
    return g_fail == 0 ? 0 : 1;
}
