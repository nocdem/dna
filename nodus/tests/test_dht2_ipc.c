/**
 * Nodus — DHT v2 package 4: the `ipc_dht` connection kind of witness.sock
 * and the storage-side view of it.
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) §2, §6
 * "Name check", §13 row 13 (witness side: witness/nodus_witness_ipc.c;
 * storage side: dht/nodus_dht2_wview.c).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false:
 *   WITNESS SIDE (the real listener, a raw peer, test handlers):
 *   · a connection whose first frame is {"q":"ipc_dht"} is answered
 *     ipc_dht_snap with EXACTLY {q, ci, h, t, cu, e}, ipc_dht_sets with
 *     {q, e, s0, s1, rg:[{f, st}]}, ipc_name with {q, fp, h, n}; the bytes
 *     are pinned here by hand-built expectations;
 *   · a handler fault is answered {q, err} (a name fault keeps "fp") and
 *     is never an empty or partial answer; the e = 0 / e ≤ E / e > E
 *     answers carry the empty arrays the row states;
 *   · a sets answer with DNA_V2_STORAGE_SET_MAX members in S(e), S(e − E)
 *     and the registry is EXACTLY NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX
 *     bytes (the term-by-term arithmetic of the header) and fits
 *     NODUS_WITNESS_IPC_DHT_FRAME_MAX; the bound's _Static_asserts
 *     compile in this TU too;
 *   · frames the dht kind does not serve close the connection: ipc_status,
 *     an unknown q, an extra key, ipc_name without / with a short fp, a
 *     malformed map, a request over NODUS_WITNESS_IPC_CTL_FRAME_MAX; a
 *     dht request on an ipc_ctl connection; a request whose handler is
 *     NULL;
 *   · the control kind is unchanged: ipc_status is answered with the same
 *     seven-key map, byte for byte, as before this package.
 *   STORAGE SIDE (nodus_dht2_wview against a scripted socket server, with
 *   INJECTED time — no clock, no sleep):
 *   · the first frame is {"q":"ipc_dht"}, then a snapshot request and a
 *     sets request ("requested at start");
 *   · a snapshot is served for 5000 ms and is no snapshot from 5001 ms;
 *     a new snapshot request is sent each 1000 ms, not before; a snapshot
 *     {err} answer clears it;
 *   · sets are handed out only while a fresh snapshot has the same `e`; a
 *     snapshot with another `e` withdraws them and triggers one new sets
 *     request; the new answer restores them;
 *   · one outstanding request per call type: a second name request is not
 *     sent while one is out; no second snapshot request before the first
 *     is answered;
 *   · name cache: a positive is kept (no new request); a negative holds
 *     while the snapshot's h ≤ the answer's h and is asked again once h
 *     moved; an {err} answer is reported once as FAULT and never cached;
 *   · an unanswered request closes the connection at 5000 ms; the dial is
 *     retried only after the backoff (250 ms) and the state is empty
 *     again;
 *   · a malformed answer (registry status 3, missing key, unsolicited,
 *     over NODUS_WITNESS_IPC_DHT_FRAME_MAX) closes the connection;
 *   · a reply that is on the wire when its 5000 ms deadline passes is
 *     refused (the connection closes, no snapshot); a snapshot's age runs
 *     from its request, so a reply at 3000 to a request of 1000 is fresh
 *     until 6000, not 8000;
 *   · a name {err} stays readable: no further name request goes out until
 *     the fault was reported once — or is 1000 ms old (an abandoned fault
 *     is dropped, the next writer is asked, the dropped fp is never
 *     answered "unnamed");
 *   · a frame header declaring more than the cap closes the connection
 *     with no payload sent (client: FRAME_MAX; witness dht kind:
 *     CTL_FRAME_MAX);
 *   · a "q" containing a NUL byte is not served (witness dht parser).
 *   END TO END: the view against the real listener with test handlers
 *   reads the snapshot, the sets and a name.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build; no environment, no network, no ports. Uses mkdtemp
 * directories under /tmp (unix sockets only). Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing: sockets are closed (their files unlinked), the directories are
 * removed, heap fixtures freed.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The witness FILL functions (nodus_witness_dht_snap_fill / _sets_fill
 *     / _name_fill: tip meta, set_get, registry SQL, v2_names lookup) are
 *     NOT exercised here — they need an open witness database; the test
 *     handlers stand in for them. What is proven is the wire and the
 *     client, not the chain reads.
 *  2. Expected frames are hand-built from the header text, by the same
 *     author as the encoder: self-consistent, not an independent oracle.
 *  3. Waits are bounded poll loops whose exhaustion FAILs; "no further
 *     request was sent" checks are absences read after a fixed number of
 *     poll rounds, each backed by a positive check in the same case that
 *     the previous request did arrive.
 *  4. Time is whatever the test passes in; it does not prove the callers
 *     (the serving loop, package 6b; the holder of package 6a only hands
 *     on the `now_ms` it is given) pass a monotonic clock.
 */

#define _DEFAULT_SOURCE 1   /* mkdtemp under -std=c11 */

#include "witness/nodus_witness_ipc.h"
#include "dht/nodus_dht2_wview.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_cbor.h"
#include "protocol/nodus_wire.h"     /* nodus_frame_encode (header-only cases) */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-62s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

#define POLL_ROUNDS 400
#define NSET DNA_V2_STORAGE_SET_MAX

/* The bound compiles here as well (the header carries them). */
_Static_assert(NODUS_WITNESS_IPC_DHT_FRAME_MAX >=
               NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX, "bound below derived");
_Static_assert(NODUS_WITNESS_IPC_DHT_FRAME_MAX <= NODUS_MAX_FRAME_TCP,
               "bound above the transport cap");

static int passed = 0;
static int failed = 0;

static char g_dir[64];
static char g_dir2[64];

/* ── Helpers: fingerprints and frames ─────────────────────────────── */

static void fp_of(uint8_t kind, unsigned i, uint8_t out[64]) {
    for (unsigned j = 0; j < 64; j++)
        out[j] = (uint8_t)(kind * 31u + i * 7u + j);
}

static size_t enc_q1(uint8_t *b, size_t cap, const char *q) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, q);
    return cbor_encoder_len(&e);
}

static size_t enc_name_req(uint8_t *b, size_t cap, const uint8_t *fp,
                           size_t fp_len) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_name");
    cbor_encode_cstr(&e, "fp"); cbor_encode_bstr(&e, fp, fp_len);
    return cbor_encoder_len(&e);
}

static size_t enc_snap(uint8_t *b, size_t cap, uint8_t ci_seed, uint64_t h,
                       uint64_t t, bool cu, uint64_t ep) {
    uint8_t ci[32];
    for (int i = 0; i < 32; i++) ci[i] = (uint8_t)(ci_seed + i);
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, 6);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_dht_snap");
    cbor_encode_cstr(&e, "ci"); cbor_encode_bstr(&e, ci, 32);
    cbor_encode_cstr(&e, "h");  cbor_encode_uint(&e, h);
    cbor_encode_cstr(&e, "t");  cbor_encode_uint(&e, t);
    cbor_encode_cstr(&e, "cu"); cbor_encode_bool(&e, cu);
    cbor_encode_cstr(&e, "e");  cbor_encode_uint(&e, ep);
    return cbor_encoder_len(&e);
}

static size_t enc_err(uint8_t *b, size_t cap, const char *q,
                      const uint8_t *fp, const char *why) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, fp ? 3 : 2);
    cbor_encode_cstr(&e, "q"); cbor_encode_cstr(&e, q);
    if (fp) { cbor_encode_cstr(&e, "fp"); cbor_encode_bstr(&e, fp, 64); }
    cbor_encode_cstr(&e, "err"); cbor_encode_cstr(&e, why);
    return cbor_encoder_len(&e);
}

/* sets frame: s0 = fp_of(1, i), s1 = fp_of(2, i), rg = fp_of(3, i) with
 * status 1 for even i, 2 for odd i. `bad_status` != 0 puts that status in
 * the first rg row (a malformed answer). */
static size_t enc_sets(uint8_t *b, size_t cap, uint64_t ep, uint32_t n0,
                       uint32_t n1, uint32_t nrg, unsigned bad_status) {
    uint8_t fp[64];
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, 5);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_dht_sets");
    cbor_encode_cstr(&e, "e");  cbor_encode_uint(&e, ep);
    cbor_encode_cstr(&e, "s0"); cbor_encode_array(&e, n0);
    for (uint32_t i = 0; i < n0; i++) { fp_of(1, i, fp); cbor_encode_bstr(&e, fp, 64); }
    cbor_encode_cstr(&e, "s1"); cbor_encode_array(&e, n1);
    for (uint32_t i = 0; i < n1; i++) { fp_of(2, i, fp); cbor_encode_bstr(&e, fp, 64); }
    cbor_encode_cstr(&e, "rg"); cbor_encode_array(&e, nrg);
    for (uint32_t i = 0; i < nrg; i++) {
        fp_of(3, i, fp);
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "f");  cbor_encode_bstr(&e, fp, 64);
        cbor_encode_cstr(&e, "st");
        cbor_encode_uint(&e, (i == 0 && bad_status) ? bad_status
                                                    : (i % 2 ? 2u : 1u));
    }
    return cbor_encoder_len(&e);
}

static size_t enc_name_ans(uint8_t *b, size_t cap, const uint8_t *fp,
                           uint64_t h, unsigned n) {
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, cap);
    cbor_encode_map(&e, 4);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_name");
    cbor_encode_cstr(&e, "fp"); cbor_encode_bstr(&e, fp, 64);
    cbor_encode_cstr(&e, "h");  cbor_encode_uint(&e, h);
    cbor_encode_cstr(&e, "n");  cbor_encode_uint(&e, n);
    return cbor_encoder_len(&e);
}

/* ── The witness stand-in (test handlers) ─────────────────────────── */

static int                       g_snap_rc;
static nodus_witness_dht_snap_t  g_snap;
static int                       g_sets_rc;
static nodus_witness_dht_sets_t *g_sets;           /* heap */
static int                       g_name_rc;
static nodus_witness_dht_name_t  g_name;
static uint8_t                   g_name_fp_seen[64];
static int                       g_dispatch_calls;

static void h_dispatch(void *ctx, nodus_tcp_conn_t *conn,
                       const uint8_t *payload, size_t len,
                       const char *method, uint32_t txn_id) {
    (void)ctx; (void)conn; (void)payload; (void)len; (void)method;
    (void)txn_id;
    g_dispatch_calls++;
}

static void h_cc(void *ctx, nodus_tcp_conn_t *conn,
                 const uint8_t pk[NODUS_PK_BYTES],
                 const uint8_t tk[NODUS_SESSION_TOKEN_LEN],
                 const uint8_t *payload, size_t len, uint32_t txn_id) {
    (void)ctx; (void)conn; (void)pk; (void)tk; (void)payload; (void)len;
    (void)txn_id;
    g_dispatch_calls++;
}

static void h_status(void *ctx, nodus_witness_ipc_status_t *out) {
    (void)ctx;
    memset(out, 0, sizeof(*out));
    out->chain_open = true;
    out->height = 4242;
    for (int i = 0; i < 64; i++) out->state_root[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) out->chain_id[i] = (uint8_t)(0x10 + i);
    out->p2p_opened = true;
    out->listen_port = 14004;
}

static int h_dht_snap(void *ctx, nodus_witness_dht_snap_t *out) {
    (void)ctx;
    if (g_snap_rc != 0) return -1;
    *out = g_snap;
    return 0;
}

static int h_dht_sets(void *ctx, nodus_witness_dht_sets_t *out) {
    (void)ctx;
    if (g_sets_rc != 0) return -1;
    memcpy(out, g_sets, sizeof(*out));
    return 0;
}

static int h_dht_name(void *ctx, const uint8_t fp[64],
                      nodus_witness_dht_name_t *out) {
    (void)ctx;
    memcpy(g_name_fp_seen, fp, 64);
    if (g_name_rc != 0) return -1;
    *out = g_name;
    return 0;
}

/* g_sets from the same generator as enc_sets. */
static void set_sets(uint64_t ep, uint32_t n0, uint32_t n1, uint32_t nrg) {
    memset(g_sets, 0, sizeof(*g_sets));
    g_sets->e = ep;
    g_sets->n0 = n0; g_sets->n1 = n1; g_sets->nrg = nrg;
    for (uint32_t i = 0; i < n0; i++) fp_of(1, i, g_sets->s0[i]);
    for (uint32_t i = 0; i < n1; i++) fp_of(2, i, g_sets->s1[i]);
    for (uint32_t i = 0; i < nrg; i++) {
        fp_of(3, i, g_sets->rg[i].fp);
        g_sets->rg[i].status = (uint8_t)(i % 2 ? 2 : 1);
    }
}

static void set_snap(uint8_t ci_seed, uint64_t h, uint64_t t, bool cu,
                     uint64_t ep) {
    for (int i = 0; i < 32; i++) g_snap.chain_id[i] = (uint8_t)(ci_seed + i);
    g_snap.height = h; g_snap.tip_time = t;
    g_snap.consensus_up = cu; g_snap.epoch_start = ep;
}

/* ── A raw peer of the real listener ──────────────────────────────── */

static nodus_tcp_t       g_raw;
static nodus_tcp_conn_t *g_rc = NULL;
static uint8_t          *g_rbuf = NULL;
static size_t            g_rlen = 0;
static int               g_rframes = 0;
static int               g_rclosed = 0;

static void raw_on_frame(nodus_tcp_conn_t *c, const uint8_t *p, size_t len,
                         void *ctx) {
    (void)c; (void)ctx;
    g_rframes++;
    g_rlen = len <= NODUS_WITNESS_IPC_DHT_FRAME_MAX ? len : 0;
    if (g_rlen) memcpy(g_rbuf, p, len);
}

static void raw_on_disconnect(nodus_tcp_conn_t *c, void *ctx) {
    (void)c; (void)ctx;
    g_rclosed++;
    g_rc = NULL;
}

static void raw_poll(nodus_witness_ipc_t *ipc) {
    nodus_witness_ipc_poll(ipc, 2);
    nodus_tcp_poll(&g_raw, 2);
}

/* Dial `sock`, send the preface frame `first`. */
static bool raw_open(nodus_witness_ipc_t *ipc, const char *sock,
                     const uint8_t *first, size_t n) {
    g_rframes = 0; g_rclosed = 0; g_rlen = 0;
    g_rc = nodus_tcp_unix_connect(&g_raw, sock, NODUS_TCP_UNIX_UID_SELF);
    if (!g_rc) return false;
    if (nodus_tcp_send(g_rc, first, n) != 0) return false;
    for (int i = 0; i < 5; i++) raw_poll(ipc);
    return true;
}

/* Send `req`; wait for one frame or a close. */
static void raw_ask(nodus_witness_ipc_t *ipc, const uint8_t *req, size_t n) {
    int want = g_rframes + 1;
    if (g_rc) nodus_tcp_send(g_rc, req, n);
    for (int i = 0; i < POLL_ROUNDS && g_rframes < want && !g_rclosed; i++)
        raw_poll(ipc);
}

static void raw_end(void) {
    if (g_rc) nodus_tcp_disconnect(&g_raw, g_rc);
    g_rc = NULL;
}

static bool raw_got(const uint8_t *exp, size_t n) {
    return g_rlen == n && memcmp(g_rbuf, exp, n) == 0;
}

/* ── Witness-side cases ───────────────────────────────────────────── */

static uint8_t g_pre[32];
static size_t  g_pre_n;

static void test_snap(nodus_witness_ipc_t *ipc, const char *sock,
                      uint8_t *exp, size_t cap) {
    TEST("ipc_dht_snap: {q, ci, h, t, cu, e} bytes");
    g_snap_rc = 0;
    set_snap(0x40, 1500, 1700000000ull, true, 1440);
    uint8_t rq[32];
    size_t rn = enc_q1(rq, sizeof(rq), "ipc_dht_snap");
    if (!raw_open(ipc, sock, g_pre, g_pre_n)) { FAIL("connect"); return; }
    raw_ask(ipc, rq, rn);
    size_t en = enc_snap(exp, cap, 0x40, 1500, 1700000000ull, true, 1440);
    bool ok = g_rframes == 1 && raw_got(exp, en);

    g_snap_rc = -1;                          /* no tip meta / t = -1 */
    raw_ask(ipc, rq, rn);
    en = enc_err(exp, cap, "ipc_dht_snap", NULL, "snapshot unavailable");
    bool ok_err = g_rframes == 2 && raw_got(exp, en);
    raw_end();
    g_snap_rc = 0;
    if (!ok) { FAIL("snap answer bytes"); return; }
    if (!ok_err) { FAIL("snap err answer bytes"); return; }
    PASS();
}

static void test_sets(nodus_witness_ipc_t *ipc, const char *sock,
                      uint8_t *exp, size_t cap) {
    TEST("ipc_dht_sets: e>E, e<=E, e=0 answers; fault = {err}");
    uint8_t rq[32];
    size_t rn = enc_q1(rq, sizeof(rq), "ipc_dht_sets");
    if (!raw_open(ipc, sock, g_pre, g_pre_n)) { FAIL("connect"); return; }
    g_sets_rc = 0;

    set_sets(2160, 3, 2, 4);                 /* e > E: both sets */
    raw_ask(ipc, rq, rn);
    size_t en = enc_sets(exp, cap, 2160, 3, 2, 4, 0);
    if (g_rframes != 1 || !raw_got(exp, en)) { FAIL("e > E bytes"); raw_end(); return; }

    set_sets(720, 3, 0, 4);                  /* e <= E: s1 = [] */
    raw_ask(ipc, rq, rn);
    en = enc_sets(exp, cap, 720, 3, 0, 4, 0);
    if (g_rframes != 2 || !raw_got(exp, en)) { FAIL("e <= E bytes"); raw_end(); return; }

    set_sets(0, 0, 0, 2);                    /* e = 0: s0 = s1 = [] */
    raw_ask(ipc, rq, rn);
    en = enc_sets(exp, cap, 0, 0, 0, 2, 0);
    if (g_rframes != 3 || !raw_got(exp, en)) { FAIL("e = 0 bytes"); raw_end(); return; }

    g_sets_rc = -1;                          /* set missing / hash failure */
    raw_ask(ipc, rq, rn);
    en = enc_err(exp, cap, "ipc_dht_sets", NULL, "sets unavailable");
    bool ok = g_rframes == 4 && raw_got(exp, en);
    g_sets_rc = 0;
    raw_end();
    if (!ok) { FAIL("sets err bytes"); return; }
    PASS();
}

static void test_sets_max(nodus_witness_ipc_t *ipc, const char *sock,
                          uint8_t *exp, size_t cap) {
    TEST("ipc_dht_sets: SET_MAX members = DERIVED_MAX bytes, fits the bound");
    uint8_t rq[32];
    size_t rn = enc_q1(rq, sizeof(rq), "ipc_dht_sets");
    const uint64_t big_e = 1ull << 40;       /* 9-byte uint form */
    set_sets(big_e, NSET, NSET, NSET);
    g_sets_rc = 0;
    if (!raw_open(ipc, sock, g_pre, g_pre_n)) { FAIL("connect"); return; }
    raw_ask(ipc, rq, rn);
    raw_end();
    size_t en = enc_sets(exp, cap, big_e, NSET, NSET, NSET, 0);
    if (g_rframes != 1 || g_rlen == 0) { FAIL("no answer"); return; }
    if (en != NODUS_WITNESS_IPC_DHT_SETS_DERIVED_MAX) {
        FAIL("encoded size differs from the derived maximum");
        return;
    }
    if (g_rlen != en || memcmp(g_rbuf, exp, en) != 0) { FAIL("bytes"); return; }
    if (g_rlen > NODUS_WITNESS_IPC_DHT_FRAME_MAX) { FAIL("over the bound"); return; }
    PASS();
}

static void test_name(nodus_witness_ipc_t *ipc, const char *sock,
                      uint8_t *exp, size_t cap) {
    TEST("ipc_name: named, unnamed, unreadable (keeps fp)");
    uint8_t fp[64], rq[160];
    fp_of(9, 1, fp);
    size_t rn = enc_name_req(rq, sizeof(rq), fp, 64);
    if (!raw_open(ipc, sock, g_pre, g_pre_n)) { FAIL("connect"); return; }

    g_name_rc = 0;
    g_name.height = 777; g_name.named = true;
    raw_ask(ipc, rq, rn);
    size_t en = enc_name_ans(exp, cap, fp, 777, 1);
    if (g_rframes != 1 || !raw_got(exp, en) ||
        memcmp(g_name_fp_seen, fp, 64) != 0) {
        FAIL("named bytes / fp not passed"); raw_end(); return;
    }
    g_name.named = false;
    raw_ask(ipc, rq, rn);
    en = enc_name_ans(exp, cap, fp, 777, 0);
    if (g_rframes != 2 || !raw_got(exp, en)) { FAIL("unnamed bytes"); raw_end(); return; }

    g_name_rc = -1;
    raw_ask(ipc, rq, rn);
    en = enc_err(exp, cap, "ipc_name", fp, "names store unreadable");
    bool ok = g_rframes == 3 && raw_got(exp, en);
    g_name_rc = 0;
    raw_end();
    if (!ok) { FAIL("unreadable is not {fp, err}"); return; }
    PASS();
}

static bool closes(nodus_witness_ipc_t *ipc, const char *sock,
                   const uint8_t *first, size_t fn, const uint8_t *bad,
                   size_t bn) {
    if (!raw_open(ipc, sock, first, fn)) return false;
    if (g_rclosed) return false;             /* the preface itself is fine */
    raw_ask(ipc, bad, bn);
    bool closed = g_rclosed >= 1 && g_rframes == 0;
    raw_end();
    return closed;
}

static void test_unserved(nodus_witness_ipc_t *ipc, const char *sock) {
    TEST("frames the dht kind does not serve close the connection");
    uint8_t b[1024], fp[64];
    fp_of(9, 2, fp);
    size_t n;
    cbor_encoder_t e;

    n = enc_q1(b, sizeof(b), "ipc_status");
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("ipc_status"); return; }
    n = enc_q1(b, sizeof(b), "ipc_dht_nope");
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("unknown q"); return; }
    n = enc_q1(b, sizeof(b), "ipc_name");
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("ipc_name without fp"); return; }
    n = enc_name_req(b, sizeof(b), fp, 63);
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("short fp"); return; }
    cbor_encoder_init(&e, b, sizeof(b));     /* extra key on a snap request */
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_dht_snap");
    cbor_encode_cstr(&e, "fp"); cbor_encode_bstr(&e, fp, 64);
    n = cbor_encoder_len(&e);
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("snap with fp"); return; }
    cbor_encoder_init(&e, b, sizeof(b));     /* unknown key */
    cbor_encode_map(&e, 2);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_dht_snap");
    cbor_encode_cstr(&e, "zz"); cbor_encode_uint(&e, 1);
    n = cbor_encoder_len(&e);
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("unknown key"); return; }
    b[0] = 0xFF;                             /* not a map */
    if (!closes(ipc, sock, g_pre, g_pre_n, b, 1)) { FAIL("not a map"); return; }
    {                                        /* over CTL_FRAME_MAX */
        static const uint8_t zeros[NODUS_WITNESS_IPC_CTL_FRAME_MAX];
        uint8_t *big = calloc(1, NODUS_WITNESS_IPC_CTL_FRAME_MAX + 64);
        if (!big) { FAIL("alloc"); return; }
        cbor_encoder_init(&e, big, NODUS_WITNESS_IPC_CTL_FRAME_MAX + 64);
        cbor_encode_map(&e, 2);
        cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_name");
        cbor_encode_cstr(&e, "fp");
        cbor_encode_bstr(&e, zeros, NODUS_WITNESS_IPC_CTL_FRAME_MAX);
        n = cbor_encoder_len(&e);
        bool ok = n > NODUS_WITNESS_IPC_CTL_FRAME_MAX &&
                  closes(ipc, sock, g_pre, g_pre_n, big, n);
        free(big);
        if (!ok) { FAIL("oversized request"); return; }
    }
    /* a dht request on an ipc_ctl connection */
    uint8_t ctl[32];
    size_t cn = enc_q1(ctl, sizeof(ctl), "ipc_ctl");
    n = enc_q1(b, sizeof(b), "ipc_dht_snap");
    if (!closes(ipc, sock, ctl, cn, b, n)) { FAIL("dht request on ipc_ctl"); return; }
    PASS();
}

static void test_nul_in_q(nodus_witness_ipc_t *ipc, const char *sock) {
    TEST("a NUL inside the request's q text is refused");
    uint8_t b[128];
    static const char q[] = "ipc_dht_snap\0junk";      /* 17 bytes of text */
    cbor_encoder_t e;
    cbor_encoder_init(&e, b, sizeof(b));
    cbor_encode_map(&e, 1);
    cbor_encode_cstr(&e, "q");
    cbor_encode_tstr(&e, q, sizeof(q) - 1);
    size_t n = cbor_encoder_len(&e);
    g_snap_rc = 0;
    if (!closes(ipc, sock, g_pre, g_pre_n, b, n)) { FAIL("served as ipc_dht_snap"); return; }
    PASS();
}

static void test_request_header_cap(nodus_witness_ipc_t *ipc, const char *sock) {
    TEST("dht kind: a header declaring > CTL_FRAME_MAX closes at once");
    if (!raw_open(ipc, sock, g_pre, g_pre_n)) { FAIL("connect"); return; }
    uint8_t one = 0, h[16];
    if (nodus_frame_encode(h, sizeof(h), &one, 1) != 8) { FAIL("encode"); raw_end(); return; }
    uint32_t declared = NODUS_WITNESS_IPC_CTL_FRAME_MAX + 1;   /* no payload follows */
    h[3] = (uint8_t)declared; h[4] = (uint8_t)(declared >> 8);
    h[5] = 0; h[6] = 0;
    bool w = write(g_rc->fd, h, 7) == 7;
    for (int i = 0; i < POLL_ROUNDS && !g_rclosed; i++) raw_poll(ipc);
    bool closed = g_rclosed >= 1;
    raw_end();
    if (!w) { FAIL("write"); return; }
    if (!closed) { FAIL("still open waiting for a payload"); return; }
    PASS();
}

static void test_null_handler(void) {
    TEST("a dht request whose handler is NULL closes the connection");
    nodus_witness_ipc_handlers_t h = {
        .dispatch_dnac = h_dispatch, .cc_collect = h_cc, .status = h_status,
    };
    nodus_witness_ipc_t *ipc2 = nodus_witness_ipc_new(&h);
    char sock2[NODUS_TCP_UNIX_PATH_MAX];
    nodus_witness_ipc_sock_path(g_dir2, sock2, sizeof(sock2));
    if (!ipc2 || nodus_witness_ipc_listen(ipc2, sock2) != 0) {
        FAIL("listen"); nodus_witness_ipc_free(ipc2); return;
    }
    uint8_t rq[32];
    size_t rn = enc_q1(rq, sizeof(rq), "ipc_dht_snap");
    bool ok = closes(ipc2, sock2, g_pre, g_pre_n, rq, rn);
    nodus_witness_ipc_free(ipc2);
    if (!ok) { FAIL("stayed open"); return; }
    PASS();
}

static void test_status_unchanged(nodus_witness_ipc_t *ipc, const char *sock,
                                  uint8_t *exp, size_t cap) {
    TEST("ipc_ctl / ipc_status answer: the seven keys unchanged + c3");
    uint8_t ctl[32], rq[32];
    size_t cn = enc_q1(ctl, sizeof(ctl), "ipc_ctl");
    size_t rn = enc_q1(rq, sizeof(rq), "ipc_status");
    if (!raw_open(ipc, sock, ctl, cn)) { FAIL("connect"); return; }
    raw_ask(ipc, rq, rn);
    raw_end();

    uint8_t sr[64], ci[32], c3[32];
    for (int i = 0; i < 64; i++) sr[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 32; i++) ci[i] = (uint8_t)(0x10 + i);
    memset(c3, 0, sizeof(c3));   /* h_status leaves the v3 chain id zero */
    cbor_encoder_t e;
    cbor_encoder_init(&e, exp, cap);         /* the pre-package layout + c3 */
    cbor_encode_map(&e, 8);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_status");
    cbor_encode_cstr(&e, "co"); cbor_encode_bool(&e, true);
    cbor_encode_cstr(&e, "h");  cbor_encode_uint(&e, 4242);
    cbor_encode_cstr(&e, "sr"); cbor_encode_bstr(&e, sr, 64);
    cbor_encode_cstr(&e, "ci"); cbor_encode_bstr(&e, ci, 32);
    cbor_encode_cstr(&e, "c3"); cbor_encode_bstr(&e, c3, 32);   /* DHT v2 3b-2: the v3 chain id */
    cbor_encode_cstr(&e, "po"); cbor_encode_bool(&e, true);
    cbor_encode_cstr(&e, "lp"); cbor_encode_uint(&e, 14004);
    if (g_rframes != 1 || !raw_got(exp, cbor_encoder_len(&e))) {
        FAIL("status bytes changed");
        return;
    }
    PASS();
}

/* ── Storage-side cases: a scripted server ────────────────────────── */

static nodus_tcp_t       g_srv;
static nodus_tcp_conn_t *g_srv_conn = NULL;
static int               g_srv_accepts = 0;
static int               g_srv_closes = 0;
#define SRV_MAX_FRAMES 64
static uint8_t           g_srv_frame[SRV_MAX_FRAMES][512];
static size_t            g_srv_len[SRV_MAX_FRAMES];
static int               g_srv_n = 0;

static void srv_on_accept(nodus_tcp_conn_t *c, void *ctx) {
    (void)ctx;
    g_srv_conn = c;
    g_srv_accepts++;
}

static void srv_on_frame(nodus_tcp_conn_t *c, const uint8_t *p, size_t len,
                         void *ctx) {
    (void)c; (void)ctx;
    if (g_srv_n < SRV_MAX_FRAMES && len <= sizeof(g_srv_frame[0])) {
        memcpy(g_srv_frame[g_srv_n], p, len);
        g_srv_len[g_srv_n] = len;
        g_srv_n++;
    }
}

static void srv_on_disconnect(nodus_tcp_conn_t *c, void *ctx) {
    (void)ctx;
    if (c == g_srv_conn) g_srv_conn = NULL;
    g_srv_closes++;
}

/* Is recorded frame i exactly the one-key request {"q":q}? */
static bool srv_is_q(int i, const char *q) {
    uint8_t b[64];
    size_t n = enc_q1(b, sizeof(b), q);
    return i < g_srv_n && g_srv_len[i] == n && memcmp(g_srv_frame[i], b, n) == 0;
}

static int srv_count_q(const char *q) {
    int c = 0;
    for (int i = 0; i < g_srv_n; i++) c += srv_is_q(i, q);
    return c;
}

static int srv_count_name(const uint8_t *fp) {
    uint8_t b[160];
    size_t n = enc_name_req(b, sizeof(b), fp, 64);
    int c = 0;
    for (int i = 0; i < g_srv_n; i++)
        c += g_srv_len[i] == n && memcmp(g_srv_frame[i], b, n) == 0;
    return c;
}

/* Tick the view at `now` and let the server read, until `done()` or the
 * rounds are exhausted. The same `now` many times is idempotent. */
static void pump(nodus_dht2_wview_t *wv, uint64_t now, int rounds) {
    for (int i = 0; i < rounds; i++) {
        nodus_dht2_wview_tick(wv, now);
        nodus_tcp_poll(&g_srv, 1);
    }
}

static void srv_reset(void) {
    /* read out whatever a previous view left in flight, then forget it */
    for (int i = 0; i < 30; i++) nodus_tcp_poll(&g_srv, 1);
    g_srv_n = 0;
    g_srv_accepts = 0;
    g_srv_closes = 0;
}

static bool srv_send(const uint8_t *b, size_t n) {
    return g_srv_conn && nodus_tcp_send(g_srv_conn, b, n) == 0;
}

/* Connect a fresh view and run it until the preface + snap + sets requests
 * reached the server (t = 0). */
static nodus_dht2_wview_t *wv_start(const char *sock) {
    srv_reset();
    nodus_dht2_wview_t *wv = nodus_dht2_wview_new(sock);
    if (!wv) return NULL;
    for (int i = 0; i < POLL_ROUNDS && g_srv_n < 3; i++) pump(wv, 0, 1);
    return wv;
}

static bool answer_snap(nodus_dht2_wview_t *wv, uint64_t now, uint64_t h,
                        uint64_t ep) {
    uint8_t b[256];
    size_t n = enc_snap(b, sizeof(b), 0x60, h, 1700000000ull + h, true, ep);
    if (!srv_send(b, n)) return false;
    pump(wv, now, 20);
    nodus_witness_dht_snap_t sn;
    return nodus_dht2_wview_snap(wv, now, &sn) && sn.height == h &&
           sn.epoch_start == ep;
}

static bool answer_sets(nodus_dht2_wview_t *wv, uint64_t now, uint64_t ep) {
    uint8_t *b = malloc(NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    if (!b) return false;
    size_t n = enc_sets(b, NODUS_WITNESS_IPC_DHT_FRAME_MAX, ep, 3, 2, 4, 0);
    bool ok = srv_send(b, n);
    free(b);
    pump(wv, now, 20);
    return ok;
}

static void test_c_start(const char *sock) {
    TEST("view: preface {ipc_dht}, then snap and sets requests at start");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    bool ok = g_srv_n >= 3 && srv_is_q(0, "ipc_dht") &&
              srv_is_q(1, "ipc_dht_snap") && srv_is_q(2, "ipc_dht_sets") &&
              nodus_dht2_wview_connected(wv);
    nodus_witness_dht_snap_t sn;
    bool none = !nodus_dht2_wview_snap(wv, 0, &sn) &&
                nodus_dht2_wview_sets(wv, 0) == NULL;
    nodus_dht2_wview_free(wv);
    if (!ok) { FAIL("requests / order"); return; }
    if (!none) { FAIL("a snapshot or sets before any answer"); return; }
    PASS();
}

static void test_c_snap_age(const char *sock) {
    TEST("view: snapshot fresh for 5000 ms, none from 5001 ms");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    if (!answer_snap(wv, 100, 1500, 1440)) { FAIL("answer"); nodus_dht2_wview_free(wv); return; }
    nodus_witness_dht_snap_t sn;
    uint8_t ci[32];
    for (int i = 0; i < 32; i++) ci[i] = (uint8_t)(0x60 + i);
    bool a = nodus_dht2_wview_snap(wv, 100, &sn) &&
             memcmp(sn.chain_id, ci, 32) == 0 && sn.tip_time == 1700000000ull + 1500 &&
             sn.consensus_up && sn.height == 1500 && sn.epoch_start == 1440;
    /* aged from the request (sent at 0), not from the reply (at 100) */
    bool b = nodus_dht2_wview_snap(wv, 5000, &sn);
    bool c = !nodus_dht2_wview_snap(wv, 5001, &sn);
    nodus_dht2_wview_free(wv);
    if (!a) { FAIL("fields"); return; }
    if (!b) { FAIL("5000 ms old must still count"); return; }
    if (!c) { FAIL("older than 5000 ms must not count"); return; }
    PASS();
}

static void test_c_poll_rate(const char *sock) {
    TEST("view: snap polled each 1000 ms; one outstanding per type");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    if (!answer_snap(wv, 0, 1500, 1440)) { FAIL("answer"); nodus_dht2_wview_free(wv); return; }
    int base = srv_count_q("ipc_dht_snap");          /* the first one */
    pump(wv, 999, 20);
    bool early = srv_count_q("ipc_dht_snap") == base;
    pump(wv, 1000, 20);
    bool due = srv_count_q("ipc_dht_snap") == base + 1;
    /* unanswered: not asked again at 2000 / 3000 / 4000 */
    pump(wv, 2000, 20); pump(wv, 3000, 20); pump(wv, 4000, 20);
    bool one = srv_count_q("ipc_dht_snap") == base + 1;
    bool up = nodus_dht2_wview_connected(wv);
    nodus_dht2_wview_free(wv);
    if (!early) { FAIL("asked before 1000 ms"); return; }
    if (!due) { FAIL("not asked at 1000 ms"); return; }
    if (!one) { FAIL("a second snap request while one was outstanding"); return; }
    if (!up) { FAIL("closed before the timeout"); return; }
    PASS();
}

static void test_c_snap_err(const char *sock) {
    TEST("view: a snapshot {err} answer clears the snapshot");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    if (!answer_snap(wv, 0, 1500, 1440)) { FAIL("answer"); nodus_dht2_wview_free(wv); return; }
    pump(wv, 1000, 20);                              /* next request out */
    uint8_t b[128];
    size_t n = enc_err(b, sizeof(b), "ipc_dht_snap", NULL, "snapshot unavailable");
    bool sent = srv_send(b, n);
    pump(wv, 1000, 20);
    nodus_witness_dht_snap_t sn;
    bool cleared = !nodus_dht2_wview_snap(wv, 1000, &sn);
    bool up = nodus_dht2_wview_connected(wv);
    nodus_dht2_wview_free(wv);
    if (!sent) { FAIL("send"); return; }
    if (!cleared) { FAIL("the old snapshot survived an {err}"); return; }
    if (!up) { FAIL("an {err} answer must not close"); return; }
    PASS();
}

static void test_c_sets(const char *sock) {
    TEST("view: sets only with a same-e fresh snapshot; e change re-asks");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    bool ok = answer_snap(wv, 0, 1500, 1440) && answer_sets(wv, 0, 1440);
    const nodus_witness_dht_sets_t *s = nodus_dht2_wview_sets(wv, 0);
    uint8_t fp[64];
    bool got = ok && s && s->e == 1440 && s->n0 == 3 && s->n1 == 2 && s->nrg == 4;
    if (got) {
        fp_of(1, 2, fp);  got = memcmp(s->s0[2], fp, 64) == 0;
        fp_of(2, 1, fp);  got = got && memcmp(s->s1[1], fp, 64) == 0;
        fp_of(3, 3, fp);  got = got && memcmp(s->rg[3].fp, fp, 64) == 0 &&
                                s->rg[3].status == 2 && s->rg[0].status == 1;
    }
    int sets_asked = srv_count_q("ipc_dht_sets");
    if (!got) { FAIL("sets with the same e"); nodus_dht2_wview_free(wv); return; }

    pump(wv, 1000, 20);                              /* snap #2 is out */
    bool a2 = answer_snap(wv, 1000, 2200, 2160);     /* e moved */
    bool withdrawn = nodus_dht2_wview_sets(wv, 1000) == NULL;
    bool reasked = srv_count_q("ipc_dht_sets") == sets_asked + 1;
    bool back = answer_sets(wv, 1000, 2160) &&
                nodus_dht2_wview_sets(wv, 1000) != NULL &&
                nodus_dht2_wview_sets(wv, 1000)->e == 2160;
    bool stale = nodus_dht2_wview_sets(wv, 1000 + 5001) == NULL;
    nodus_dht2_wview_free(wv);
    if (!a2) { FAIL("second snapshot"); return; }
    if (!withdrawn) { FAIL("sets of another e were handed out"); return; }
    if (!reasked) { FAIL("no (or more than one) new sets request"); return; }
    if (!back) { FAIL("sets of the new e not served"); return; }
    if (!stale) { FAIL("sets served without a fresh snapshot"); return; }
    PASS();
}

static void test_c_name(const char *sock) {
    TEST("view: name cache - positive kept, negative until h moves");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    if (!answer_snap(wv, 0, 100, 0)) { FAIL("snap"); nodus_dht2_wview_free(wv); return; }
    uint8_t a[64], b[64], r[160];
    fp_of(9, 10, a); fp_of(9, 11, b);
    uint64_t h = 0;

    if (nodus_dht2_wview_name(wv, 0, a, &h) != NODUS_DHT2_WVIEW_NAME_PENDING) { FAIL("first call"); nodus_dht2_wview_free(wv); return; }
    pump(wv, 0, 20);
    bool one = srv_count_name(a) == 1;
    /* one outstanding: asking for b while a is out sends nothing */
    bool busy = nodus_dht2_wview_name(wv, 0, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 0, 20);
    bool not_sent = srv_count_name(b) == 0;
    size_t n = enc_name_ans(r, sizeof(r), a, 100, 1);       /* a: named */
    bool sent = srv_send(r, n);
    pump(wv, 0, 20);
    bool pos = nodus_dht2_wview_name(wv, 0, a, &h) == NODUS_DHT2_WVIEW_NAME_NAMED && h == 100;
    /* positives for good: even with no fresh snapshot, much later */
    bool pos_late = nodus_dht2_wview_name(wv, 999999, a, &h) == NODUS_DHT2_WVIEW_NAME_NAMED;
    bool no_more = srv_count_name(a) == 1;
    if (!(one && busy && not_sent && sent && pos && pos_late && no_more)) {
        FAIL("positive / one-outstanding rules");
        nodus_dht2_wview_free(wv);
        return;
    }

    /* b: now it is sent; answered unnamed at h = 100 */
    bool b_pend = nodus_dht2_wview_name(wv, 0, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 0, 20);
    bool b_out = srv_count_name(b) == 1;
    n = enc_name_ans(r, sizeof(r), b, 100, 0);
    srv_send(r, n);
    pump(wv, 0, 20);
    bool neg = nodus_dht2_wview_name(wv, 0, b, &h) == NODUS_DHT2_WVIEW_NAME_UNNAMED && h == 100;
    bool neg_cached = srv_count_name(b) == 1;
    /* h moves: a snapshot with h = 101 */
    pump(wv, 1000, 20);
    bool s2 = answer_snap(wv, 1000, 101, 0);
    bool again = nodus_dht2_wview_name(wv, 1000, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 1000, 20);
    bool re_asked = srv_count_name(b) == 2;
    nodus_dht2_wview_free(wv);
    if (!(b_pend && b_out)) { FAIL("second key not asked after the first answered"); return; }
    if (!(neg && neg_cached)) { FAIL("negative not cached while h is unchanged"); return; }
    if (!(s2 && again && re_asked)) { FAIL("negative kept after h moved"); return; }
    PASS();
}

static void test_c_name_fault(const char *sock) {
    TEST("view: name {err} is FAULT once and never cached");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    uint8_t a[64], r[256];
    fp_of(9, 20, a);
    uint64_t h = 0;
    nodus_dht2_wview_name(wv, 0, a, &h);
    pump(wv, 0, 20);
    size_t n = enc_err(r, sizeof(r), "ipc_name", a, "names store unreadable");
    srv_send(r, n);
    pump(wv, 0, 20);
    bool fault = nodus_dht2_wview_name(wv, 0, a, &h) == NODUS_DHT2_WVIEW_NAME_FAULT;
    bool again = nodus_dht2_wview_name(wv, 0, a, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 0, 20);
    bool re_asked = srv_count_name(a) == 2;
    nodus_dht2_wview_free(wv);
    if (!fault) { FAIL("no FAULT"); return; }
    if (!again || !re_asked) { FAIL("a fault was cached"); return; }
    PASS();
}

static void test_c_timeout(const char *sock) {
    TEST("view: timeout closes at 5000 ms; redial after the 250 ms backoff");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    /* The snapshot is answered; the sets request sent at start (t = 0) is
     * never answered. */
    if (!answer_snap(wv, 0, 1500, 1440)) { FAIL("snap"); nodus_dht2_wview_free(wv); return; }
    pump(wv, 4999, 20);
    bool still = nodus_dht2_wview_connected(wv);
    pump(wv, 5000, 20);
    bool closed = !nodus_dht2_wview_connected(wv);
    nodus_witness_dht_snap_t sn;
    bool empty = !nodus_dht2_wview_snap(wv, 5000, &sn) &&
                 nodus_dht2_wview_sets(wv, 5000) == NULL;
    int accepts = g_srv_accepts;
    pump(wv, 5249, 20);
    bool waiting = !nodus_dht2_wview_connected(wv) && g_srv_accepts == accepts;
    for (int i = 0; i < POLL_ROUNDS && g_srv_accepts == accepts; i++)
        pump(wv, 5250, 1);
    bool redialled = nodus_dht2_wview_connected(wv) && g_srv_accepts == accepts + 1;
    nodus_dht2_wview_free(wv);
    if (!still) { FAIL("closed before 5000 ms"); return; }
    if (!closed) { FAIL("not closed at 5000 ms"); return; }
    if (!empty) { FAIL("state survived the close"); return; }
    if (!waiting) { FAIL("redialled before the backoff"); return; }
    if (!redialled) { FAIL("not redialled after the backoff"); return; }
    PASS();
}

static void test_c_late_reply(const char *sock) {
    TEST("view: a reply after its deadline is refused, not accepted");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    /* sets answered, so only the snapshot request (sent at 0) is overdue */
    if (!answer_sets(wv, 0, 1440)) { FAIL("sets"); nodus_dht2_wview_free(wv); return; }
    pump(wv, 4999, 20);
    bool up = nodus_dht2_wview_connected(wv);
    uint8_t b[256];
    size_t n = enc_snap(b, sizeof(b), 0x60, 1500, 1700001500ull, true, 1440);
    bool sent = srv_send(b, n);          /* on the wire before the 5000 tick */
    pump(wv, 5000, 20);
    nodus_witness_dht_snap_t sn;
    bool closed = !nodus_dht2_wview_connected(wv);
    bool none = !nodus_dht2_wview_snap(wv, 5000, &sn);
    nodus_dht2_wview_free(wv);
    if (!up) { FAIL("closed early"); return; }
    if (!sent) { FAIL("send"); return; }
    if (!closed || !none) { FAIL("the late snapshot was accepted"); return; }
    PASS();
}

static void test_c_snap_age_from_request(const char *sock) {
    TEST("view: a snapshot is aged from its request, not its reply");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    if (!answer_snap(wv, 0, 1500, 1440)) { FAIL("snap 1"); nodus_dht2_wview_free(wv); return; }
    pump(wv, 1000, 20);                  /* request #2 sent at 1000 */
    bool a2 = answer_snap(wv, 3000, 1600, 1440);   /* answered at 3000 */
    nodus_witness_dht_snap_t sn;
    bool fresh = nodus_dht2_wview_snap(wv, 6000, &sn) && sn.height == 1600;
    bool stale = !nodus_dht2_wview_snap(wv, 6001, &sn);
    nodus_dht2_wview_free(wv);
    if (!a2) { FAIL("snap 2"); return; }
    if (!fresh) { FAIL("not fresh 5000 ms after the request"); return; }
    if (!stale) { FAIL("the reply time extended the freshness"); return; }
    PASS();
}

static void test_c_fault_kept(const char *sock) {
    TEST("view: a second name {err} cannot overwrite an unread fault");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    uint8_t a[64], b[64], r[256];
    fp_of(9, 60, a); fp_of(9, 61, b);
    uint64_t h = 0;
    nodus_dht2_wview_name(wv, 0, a, &h);
    pump(wv, 0, 20);
    size_t n = enc_err(r, sizeof(r), "ipc_name", a, "names store unreadable");
    srv_send(r, n);
    pump(wv, 0, 20);
    /* b is asked for while a's fault is unread: nothing is sent for it */
    bool b_wait = nodus_dht2_wview_name(wv, 0, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 0, 20);
    bool b_unsent = srv_count_name(b) == 0;
    bool a_fault = nodus_dht2_wview_name(wv, 0, a, &h) == NODUS_DHT2_WVIEW_NAME_FAULT;
    bool b_pend = nodus_dht2_wview_name(wv, 0, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 0, 20);
    bool b_sent = srv_count_name(b) == 1;
    nodus_dht2_wview_free(wv);
    if (!(b_wait && b_unsent)) { FAIL("a request went out over an unread fault"); return; }
    if (!a_fault) { FAIL("the first caller lost its FAULT"); return; }
    if (!(b_pend && b_sent)) { FAIL("b not asked after the fault was read"); return; }
    PASS();
}

static void test_c_fault_abandoned(const char *sock) {
    TEST("view: an abandoned name {err} is dropped after one poll period");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    uint8_t a[64], b[64], r[256];
    fp_of(9, 70, a); fp_of(9, 71, b);
    uint64_t h = 0;
    nodus_dht2_wview_name(wv, 0, a, &h);
    pump(wv, 0, 20);
    size_t n = enc_err(r, sizeof(r), "ipc_name", a, "names store unreadable");
    srv_send(r, n);
    pump(wv, 0, 20);                      /* the fault is read at tick 0 */
    /* before one period: still held, b waits and nothing is sent for it */
    bool early = nodus_dht2_wview_name(wv, 999, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 999, 20);
    bool early_unsent = srv_count_name(b) == 0;
    /* at one period: dropped, b is asked, a is not reported as FAULT and
     * never as unnamed */
    bool b_pend = nodus_dht2_wview_name(wv, 1000, b, &h) == NODUS_DHT2_WVIEW_NAME_PENDING;
    pump(wv, 1000, 20);
    bool b_sent = srv_count_name(b) == 1;
    nodus_dht2_wview_name_t ra = nodus_dht2_wview_name(wv, 1000, a, &h);
    nodus_dht2_wview_free(wv);
    if (!(early && early_unsent)) { FAIL("fault dropped before one period"); return; }
    if (!(b_pend && b_sent)) { FAIL("b still blocked by an abandoned fault"); return; }
    if (ra != NODUS_DHT2_WVIEW_NAME_PENDING) { FAIL("a dropped fault became FAULT/unnamed"); return; }
    PASS();
}

/* Write a 7-byte frame header declaring `declared` payload bytes and no
 * payload, straight onto the connection's socket. */
static bool write_header_only(nodus_tcp_conn_t *c, uint32_t declared) {
    uint8_t one = 0, buf[16];
    if (!c || nodus_frame_encode(buf, sizeof(buf), &one, 1) != 8) return false;
    buf[3] = (uint8_t)declared;
    buf[4] = (uint8_t)(declared >> 8);
    buf[5] = (uint8_t)(declared >> 16);
    buf[6] = (uint8_t)(declared >> 24);
    return write(c->fd, buf, 7) == 7;
}

static void test_c_header_cap(const char *sock) {
    TEST("view: a header declaring more than FRAME_MAX closes at once");
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) { FAIL("new"); return; }
    /* header only, no payload: without the cap the view would wait for
     * the payload (the transport default is NODUS_MAX_FRAME_TCP) */
    bool w = write_header_only(g_srv_conn, NODUS_WITNESS_IPC_DHT_FRAME_MAX + 1);
    pump(wv, 0, 30);
    bool closed = !nodus_dht2_wview_connected(wv);
    nodus_dht2_wview_free(wv);
    if (!w) { FAIL("write"); return; }
    if (!closed) { FAIL("not closed on the header"); return; }
    PASS();
}

static bool closes_on(const char *sock, const uint8_t *ans, size_t n) {
    nodus_dht2_wview_t *wv = wv_start(sock);
    if (!wv) return false;
    bool sent = srv_send(ans, n);
    pump(wv, 0, 30);
    bool closed = !nodus_dht2_wview_connected(wv);
    nodus_dht2_wview_free(wv);
    return sent && closed;
}

static void test_c_malformed(const char *sock) {
    TEST("view: malformed / unsolicited / over-long answers close");
    uint8_t *b = malloc(NODUS_WITNESS_IPC_DHT_FRAME_MAX + 64);
    uint8_t *zeros = calloc(1, NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    uint8_t fp[64];
    if (!b || !zeros) { FAIL("alloc"); free(b); free(zeros); return; }
    size_t n;
    cbor_encoder_t e;

    /* a registry row with status 3 (RELEASED) */
    n = enc_sets(b, NODUS_WITNESS_IPC_DHT_FRAME_MAX, 1440, 3, 2, 4, 3);
    if (!closes_on(sock, b, n)) { FAIL("registry status 3"); goto out; }

    /* a snapshot answer with an unknown key instead of "e" */
    cbor_encoder_init(&e, b, 256);
    cbor_encode_map(&e, 6);
    cbor_encode_cstr(&e, "q");  cbor_encode_cstr(&e, "ipc_dht_snap");
    cbor_encode_cstr(&e, "ci"); cbor_encode_bstr(&e, zeros, 32);
    cbor_encode_cstr(&e, "h");  cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "t");  cbor_encode_uint(&e, 1);
    cbor_encode_cstr(&e, "cu"); cbor_encode_bool(&e, true);
    cbor_encode_cstr(&e, "zz"); cbor_encode_uint(&e, 1);
    n = cbor_encoder_len(&e);
    if (!closes_on(sock, b, n)) { FAIL("snap missing a key"); goto out; }

    /* a name answer nobody asked for */
    fp_of(9, 40, fp);
    n = enc_name_ans(b, 256, fp, 1, 1);
    if (!closes_on(sock, b, n)) { FAIL("unsolicited name answer"); goto out; }

    /* a frame over the bound */
    cbor_encoder_init(&e, b, NODUS_WITNESS_IPC_DHT_FRAME_MAX + 64);
    cbor_encode_bstr(&e, zeros, NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    n = cbor_encoder_len(&e);
    if (n <= NODUS_WITNESS_IPC_DHT_FRAME_MAX || !closes_on(sock, b, n)) {
        FAIL("over-long answer");
        goto out;
    }
    free(b);
    free(zeros);
    PASS();
    return;
out:
    free(b);
    free(zeros);
}

/* ── End to end: the view against the real listener ───────────────── */

static void test_end_to_end(nodus_witness_ipc_t *ipc, const char *sock) {
    TEST("end to end: view reads snapshot, sets and a name from the listener");
    g_snap_rc = 0; g_sets_rc = 0; g_name_rc = 0;
    set_snap(0x70, 2200, 1700002200ull, true, 2160);
    set_sets(2160, 3, 2, 4);
    uint8_t fp[64];
    fp_of(9, 50, fp);
    g_name.height = 2200; g_name.named = true;

    nodus_dht2_wview_t *wv = nodus_dht2_wview_new(sock);
    if (!wv) { FAIL("new"); return; }
    nodus_witness_dht_snap_t sn;
    bool have = false;
    for (int i = 0; i < POLL_ROUNDS && !have; i++) {
        nodus_dht2_wview_tick(wv, 10);
        nodus_witness_ipc_poll(ipc, 1);
        have = nodus_dht2_wview_snap(wv, 10, &sn) &&
               nodus_dht2_wview_sets(wv, 10) != NULL;
    }
    bool snap_ok = have && sn.height == 2200 && sn.tip_time == 1700002200ull &&
                   sn.consensus_up && sn.epoch_start == 2160 &&
                   sn.chain_id[0] == 0x70 && sn.chain_id[31] == 0x70 + 31;
    const nodus_witness_dht_sets_t *s = nodus_dht2_wview_sets(wv, 10);
    bool sets_ok = s && s->e == 2160 && s->n0 == 3 && s->n1 == 2 && s->nrg == 4 &&
                   s->rg[1].status == 2;
    uint64_t h = 0;
    nodus_dht2_wview_name_t r = nodus_dht2_wview_name(wv, 10, fp, &h);
    for (int i = 0; i < POLL_ROUNDS && r == NODUS_DHT2_WVIEW_NAME_PENDING; i++) {
        nodus_dht2_wview_tick(wv, 10);
        nodus_witness_ipc_poll(ipc, 1);
        r = nodus_dht2_wview_name(wv, 10, fp, &h);
    }
    nodus_dht2_wview_free(wv);
    if (!snap_ok) { FAIL("snapshot"); return; }
    if (!sets_ok) { FAIL("sets"); return; }
    if (r != NODUS_DHT2_WVIEW_NAME_NAMED || h != 2200) { FAIL("name"); return; }
    PASS();
}

int main(void) {
    printf("test_dht2_ipc:\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/nodus_d2ipc_XXXXXX");
    snprintf(g_dir2, sizeof(g_dir2), "/tmp/nodus_d2ipc2_XXXXXX");
    if (!mkdtemp(g_dir) || !mkdtemp(g_dir2)) {
        printf("mkdtemp failed\n");
        return 1;
    }
    g_sets = calloc(1, sizeof(*g_sets));
    g_rbuf = malloc(NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    uint8_t *exp = malloc(NODUS_WITNESS_IPC_DHT_FRAME_MAX);
    if (!g_sets || !g_rbuf || !exp) { printf("alloc failed\n"); return 1; }
    g_pre_n = enc_q1(g_pre, sizeof(g_pre), "ipc_dht");

    char wsock[NODUS_TCP_UNIX_PATH_MAX], ssock[NODUS_TCP_UNIX_PATH_MAX];
    nodus_witness_ipc_sock_path(g_dir, wsock, sizeof(wsock));
    snprintf(ssock, sizeof(ssock), "%s/script.sock", g_dir);

    nodus_witness_ipc_handlers_t h = {
        .dispatch_dnac = h_dispatch, .cc_collect = h_cc, .status = h_status,
        .dht_snap = h_dht_snap, .dht_sets = h_dht_sets, .dht_name = h_dht_name,
    };
    nodus_witness_ipc_t *ipc = nodus_witness_ipc_new(&h);
    if (!ipc || nodus_witness_ipc_listen(ipc, wsock) != 0) {
        printf("witness IPC listen failed\n");
        return 1;
    }
    nodus_tcp_init(&g_raw, -1);
    g_raw.on_frame = raw_on_frame;
    g_raw.on_disconnect = raw_on_disconnect;

    nodus_tcp_init(&g_srv, -1);
    g_srv.on_accept = srv_on_accept;
    g_srv.on_frame = srv_on_frame;
    g_srv.on_disconnect = srv_on_disconnect;
    if (nodus_tcp_unix_listen(&g_srv, ssock, NODUS_TCP_UNIX_UID_SELF) != 0) {
        printf("scripted server listen failed\n");
        return 1;
    }

    const size_t cap = NODUS_WITNESS_IPC_DHT_FRAME_MAX;
    printf(" witness side\n");
    test_snap(ipc, wsock, exp, cap);
    test_sets(ipc, wsock, exp, cap);
    test_sets_max(ipc, wsock, exp, cap);
    test_name(ipc, wsock, exp, cap);
    test_unserved(ipc, wsock);
    test_nul_in_q(ipc, wsock);
    test_request_header_cap(ipc, wsock);
    test_null_handler();
    test_status_unchanged(ipc, wsock, exp, cap);
    printf(" storage side\n");
    test_c_start(ssock);
    test_c_snap_age(ssock);
    test_c_late_reply(ssock);
    test_c_snap_age_from_request(ssock);
    test_c_fault_kept(ssock);
    test_c_fault_abandoned(ssock);
    test_c_header_cap(ssock);
    test_c_poll_rate(ssock);
    test_c_snap_err(ssock);
    test_c_sets(ssock);
    test_c_name(ssock);
    test_c_name_fault(ssock);
    test_c_timeout(ssock);
    test_c_malformed(ssock);
    test_end_to_end(ipc, wsock);

    nodus_witness_ipc_free(ipc);
    nodus_tcp_close(&g_raw);
    nodus_tcp_close(&g_srv);
    free(exp);
    free(g_rbuf);
    free(g_sets);
    rmdir(g_dir);
    rmdir(g_dir2);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
