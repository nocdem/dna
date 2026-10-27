/**
 * Nodus — DHT v2 package 2: the wire messages (shared/dht2/dht2_msg.*).
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §4.4,
 * §4.5, §13 rows 7, 11, 12, 14, 15, 18, 21, 22; decisions
 * docs/plans/decisions/2026-10-23-dht-v2-wire-gaps-package2.md and
 * 2026-10-23-dht-v2-id-param-bytes.md.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false:
 *   · each message — get / put request, read answer, receipt, LIST answer,
 *     refusal, p_hello, p_get, p_offer, p_want, p_deliver (bytes and
 *     null), pull-receipt payload — encodes to EXACTLY the bytes
 *     assembled by hand here (keys in length-first-then-bytewise order),
 *     decodes back to the same struct, and re-encodes to the same bytes;
 *   · every strict reject holds per message: trailing byte, every strict
 *     prefix, unsorted / duplicate / unknown key, long-form integer and
 *     length, wrong byte-string length, and each count bound (9 keys /
 *     envs, 17 LIST entries, 251 offer / receipt entries, 3,501 control
 *     entries), incl. an unknown op and a nonce of 31 B (MALFORMED_REQ);
 *   · row 7 `v`: a 64 B hash, null (read answer only), codes 1…13, 16, 17,
 *     [18, through] are accepted where the context allows; 0, 14, 15, 19,
 *     a bare 18, a 63 B hash, an array of another shape, a negative int
 *     are refused; null is refused in a receipt and in a LIST answer;
 *   · LIST rules: non-ascending / equal `w`, a cursor ≠ the last `w`, a
 *     cursor on an empty page, an empty page with `complete` false are
 *     refused; a first page carries no `req_cursor`; `ctl` null and hash;
 *   · the refusal carries `e` 14 / 15 only and no h / t;
 *   · the p_want bit-vector: for n = 0, 1, 7, 8, 9, 250 the vector is
 *     exactly ⌈n/8⌉ bytes, LSB-first, a set bit ≥ n and a wrong length are
 *     refused, n = 251 is refused; bit i = byte ⌊i/8⌋ mask 1 << (i mod 8);
 *   · the control `_data` is entries of 73 B, strictly ascending by fp,
 *     marks 1 / 2, ≤ 3,500; a wrong length / mark / order is refused;
 *     lookup by fp finds the entry and its `through` (u64 BE);
 *   · the five typed `_id` helpers equal SHA3-512 of the preimages
 *     assembled by hand from the decision record (label ‖ chain ‖ params,
 *     key version u64 BE (8 B); head and feed take no version);
 *   · an answer sealed with dht2_answer_seal opens under
 *     `nodus.dht.answer.v1`, a tampered payload is `bad-signature`,
 *     another payload type is refused; the row-11 constants equal the
 *     measured sizes (8-key payload 1,262 B, envelope 8,516 B) and the
 *     derived maximum message is below NODUS_MAX_FRAME_TCP (_Static_assert);
 *   · the strict CBOR additions (array, false, null, peek) behave.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock. The one signing test uses an ML-DSA-87 key from a
 * fixed seed (qgp_dsa87_keypair_derand); signing is hedged, so no
 * signature byte is pinned. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. Heap buffers are freed; no files, processes or state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. Pinned bytes are assembled BY HAND here from the design rows and
 *     the two decisions; they are self-consistent with this codec's
 *     author, not an oracle from another implementation (the design's
 *     C ↔ WASM cross-check is what will ground them).
 *  2. Where the text is silent nothing is tested either way (0 keys in a
 *     get, an empty env, offer entry order, which LIST fields accompany
 *     code 17, `through` range, [18, x] in a read answer): passing here
 *     says nothing about those.
 *  3. The prefix sweep proves a truncated message is refused, not that
 *     every malformed message is — the targeted rejects are the list in
 *     WHAT IT PROVES and no more.
 *  4. The `_id` helpers are compared to hand-built preimages hashed by the
 *     same SHA3-512 the helpers use; a wrong label in the decision record
 *     itself would pass.
 *  5. The pull-receipt envelope domain is undecided: only its payload is
 *     tested.
 *
 * @file test_dht2_msg.c
 */

#include "dht2/dht2_cbor.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_msg.h"
#include "dht2/dht2_record.h"
#include "dht2/dht2_types.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_DHT2_MSG"

/* Row 11: the derived maximum answer MESSAGE fits ONE frame. */
_Static_assert(DHT2_ANSWER_MSG_MAX < NODUS_MAX_FRAME_TCP,
               "row 11: 8 x 262,144 B of records + the answer envelope "
               "must fit NODUS_MAX_FRAME_TCP");

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                              \
    if (cond) { g_pass++; }                                                \
    else { g_fail++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s:%d: %s",              \
                                   __FILE__, __LINE__, (msg)); }           \
} while (0)

/* ══ byte assembler for the pinned vectors ═════════════════════════════ */

typedef struct {
    uint8_t b[70000];
    size_t  n;
    int     err;
} asm_t;

static asm_t g_a;      /* the expected bytes */
static asm_t g_m;      /* a mutated / hand-built variant */

static void a_init(asm_t *a)
{
    a->n = 0;
    a->err = 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Hex pairs; spaces ignored. */
static void a_hex(asm_t *a, const char *hex)
{
    while (*hex != '\0') {
        int hi, lo;

        if (*hex == ' ') {
            hex++;
            continue;
        }
        hi = hexval(hex[0]);
        lo = (hex[1] != '\0') ? hexval(hex[1]) : -1;
        if (hi < 0 || lo < 0 || a->n >= sizeof(a->b)) {
            a->err = 1;
            return;
        }
        a->b[a->n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
}

static void a_fill(asm_t *a, uint8_t v, size_t n)
{
    if (n > sizeof(a->b) - a->n) {
        a->err = 1;
        return;
    }
    memset(a->b + a->n, v, n);
    a->n += n;
}

static void a_raw(asm_t *a, const void *p, size_t n)
{
    if (n > sizeof(a->b) - a->n) {
        a->err = 1;
        return;
    }
    memcpy(a->b + a->n, p, n);
    a->n += n;
}

/* A byte string of `n` (< 256) bytes all `v`: head 58 nn (long enough for
 * 32 / 64 B, the only lengths used) then the fill. */
static void a_bs(asm_t *a, uint8_t v, size_t n)
{
    uint8_t head[2];

    head[0] = 0x58;
    head[1] = (uint8_t)n;
    a_raw(a, head, 2);
    a_fill(a, v, n);
}

/* A uint in its shortest form (values < 2^32). */
static void a_uint(asm_t *a, uint64_t v)
{
    uint8_t t[5];

    if (v < 24) {
        t[0] = (uint8_t)v;
        a_raw(a, t, 1);
    } else if (v <= 0xFF) {
        t[0] = 0x18;
        t[1] = (uint8_t)v;
        a_raw(a, t, 2);
    } else if (v <= 0xFFFF) {
        t[0] = 0x19;
        t[1] = (uint8_t)(v >> 8);
        t[2] = (uint8_t)v;
        a_raw(a, t, 3);
    } else {
        t[0] = 0x1a;
        t[1] = (uint8_t)(v >> 24);
        t[2] = (uint8_t)(v >> 16);
        t[3] = (uint8_t)(v >> 8);
        t[4] = (uint8_t)v;
        a_raw(a, t, 5);
    }
}

/* Text keys as their DAG-CBOR encodings. */
#define KC     "61 63"
#define KH     "61 68"
#define KN     "61 6e"
#define KQ     "61 71"
#define KR     "61 72"
#define KT     "61 74"
#define KK     "61 6b"
#define KV     "61 76"
#define KE     "61 65"
#define KG     "61 67"
#define KS     "61 73"
#define KB     "61 62"
#define KI     "61 69"
#define KA     "61 61"
#define KP     "61 70"
#define KD     "61 64"
#define KW     "61 77"
#define KOP    "62 6f70"
#define KPF    "62 7066"
#define KSF    "62 7366"
#define KTOP   "63 746f70"
#define KCTL   "63 63746c"
#define KKEYS  "64 6b657973"
#define KENVS  "64 656e7673"
#define KLIST  "64 6c697374"
#define KCUR   "66 637572736f72"
#define KCOMPL "68 636f6d706c657465"
#define KREQC  "6a 7265715f637572736f72"

static bool same(const uint8_t *got, size_t got_len, const asm_t *want)
{
    return !want->err && got_len == want->n &&
           memcmp(got, want->b, want->n) == 0;
}

/* ══ expected-bytes builders ═══════════════════════════════════════════ */

/* get: {n, op "get", keys[...]} */
static void exp_get(asm_t *a)
{
    a_init(a);
    a_hex(a, "a3" KN);
    a_bs(a, 0x01, 32);
    a_hex(a, KOP "63 676574" KKEYS "82");
    a_bs(a, 0x02, 64);
    a_bs(a, 0x03, 64);
}

/* put: {n, op "put", envs[aabbcc, ddee]} */
static void exp_put(asm_t *a)
{
    a_init(a);
    a_hex(a, "a3" KN);
    a_bs(a, 0x01, 32);
    a_hex(a, KOP "63 707574" KENVS "82 43 aabbcc 42 ddee");
}

/* A result element {k, v}: the value is written by the caller. */
static void elem_begin(asm_t *a, uint8_t kb)
{
    a_hex(a, "a2" KK);
    a_bs(a, kb, 64);
    a_hex(a, KV);
}

static void ans_head(asm_t *a, unsigned nres)
{
    uint8_t arr = (uint8_t)(0x80u + nres);

    a_init(a);
    a_hex(a, "a6" KC);
    a_bs(a, 0x06, 32);
    a_hex(a, KH "0a" KN);
    a_bs(a, 0x05, 64);
    a_hex(a, KQ);
    a_bs(a, 0x04, 32);
    a_hex(a, KR);
    a_raw(a, &arr, 1);
}

static void ans_tail(asm_t *a)
{
    a_hex(a, KT "19 012c");
}

/* The pinned read answer: hash, null, code 7, [18, 5]. */
static void exp_answer(asm_t *a)
{
    ans_head(a, 4);
    elem_begin(a, 0x10);
    a_bs(a, 0x20, 64);
    elem_begin(a, 0x11);
    a_hex(a, "f6");
    elem_begin(a, 0x12);
    a_hex(a, "07");
    elem_begin(a, 0x13);
    a_hex(a, "82 12 05");
    ans_tail(a);
}

/* The pinned receipt: hash, code 10, [18, 5]. */
static void exp_receipt(asm_t *a)
{
    ans_head(a, 3);
    elem_begin(a, 0x10);
    a_bs(a, 0x20, 64);
    elem_begin(a, 0x12);
    a_hex(a, "0a");
    elem_begin(a, 0x13);
    a_hex(a, "82 12 05");
    ans_tail(a);
}

/* An answer with ONE element whose `v` is the given hex (not validated). */
static void ans_one(asm_t *a, const char *v_hex)
{
    ans_head(a, 1);
    elem_begin(a, 0x10);
    a_hex(a, v_hex);
    ans_tail(a);
}

/* A LIST answer, hand-built and NOT validated. `w[]` are the fill bytes of
 * the listed writer fps (their `d` is w + 0x10); cursor / req_cursor < 0 →
 * absent, else the fill byte; ctl_byte < 0 → null; v_hex the `r` value. */
static void list_build(asm_t *a, unsigned nlist, const uint8_t *w,
                       int cursor, int complete, int req_cursor,
                       int ctl_byte, const char *v_hex)
{
    unsigned i;
    uint8_t  head = (uint8_t)(0xa9u + (cursor >= 0 ? 1u : 0u) +
                              (req_cursor >= 0 ? 1u : 0u));

    a_init(a);
    a_raw(a, &head, 1);
    a_hex(a, KC);
    a_bs(a, 0x06, 32);
    a_hex(a, KH "01" KN);
    a_bs(a, 0x05, 64);
    a_hex(a, KQ);
    a_bs(a, 0x04, 32);
    a_hex(a, KR "81");
    elem_begin(a, 0x30);
    a_hex(a, v_hex);
    a_hex(a, KT "02" KCTL);
    if (ctl_byte < 0) {
        a_hex(a, "f6");
    } else {
        a_bs(a, (uint8_t)ctl_byte, 64);
    }
    a_hex(a, KLIST);
    if (nlist < 24) {
        uint8_t arr = (uint8_t)(0x80u + nlist);

        a_raw(a, &arr, 1);
    } else {
        uint8_t arr[2];

        arr[0] = 0x98;
        arr[1] = (uint8_t)nlist;
        a_raw(a, arr, 2);
    }
    for (i = 0; i < nlist; i++) {
        a_hex(a, "a2" KD);
        a_bs(a, (uint8_t)(w[i] + 0x10u), 64);
        a_hex(a, KW);
        a_bs(a, w[i], 64);
    }
    if (cursor >= 0) {
        a_hex(a, KCUR);
        a_bs(a, (uint8_t)cursor, 64);
    }
    a_hex(a, KCOMPL);
    a_hex(a, complete ? "f5" : "f4");
    if (req_cursor >= 0) {
        a_hex(a, KREQC);
        a_bs(a, (uint8_t)req_cursor, 64);
    }
}

static void exp_refusal(asm_t *a)
{
    a_init(a);
    a_hex(a, "a4" KC);
    a_bs(a, 0x06, 32);
    a_hex(a, KE "0f" KN);
    a_bs(a, 0x05, 64);
    a_hex(a, KQ);
    a_bs(a, 0x04, 32);
}

static void exp_hello(asm_t *a)
{
    a_init(a);
    a_hex(a, "a2" KG "01" KTOP "19 1234");
}

static void exp_pget(asm_t *a)
{
    a_init(a);
    a_hex(a, "a2" KG "01" KS "19 012c");
}

/* One offer entry {a 0x61, h 0x62, p 0x63}, g 1, top 2. */
static void exp_offer(asm_t *a)
{
    a_init(a);
    a_hex(a, "a3" KE "81 a3" KA);
    a_bs(a, 0x61, 64);
    a_hex(a, KH);
    a_bs(a, 0x62, 64);
    a_hex(a, KP);
    a_bs(a, 0x63, 64);
    a_hex(a, KG "01" KTOP "02");
}

/* n = 9: bits 0, 2, 8. */
static void exp_want9(asm_t *a)
{
    a_init(a);
    a_hex(a, "a1" KB "42 0501");
}

static void exp_deliver_bytes(asm_t *a)
{
    a_init(a);
    a_hex(a, "a2" KI "03" KV "42 0102");
}

static void exp_deliver_null(asm_t *a)
{
    a_init(a);
    a_hex(a, "a2" KI "03" KV "f6");
}

/* One entry {a 0x61, h 0x62}, g 1, s 2, top 3. */
static void exp_pull_receipt(asm_t *a)
{
    a_init(a);
    a_hex(a, "a7" KC);
    a_bs(a, 0x06, 32);
    a_hex(a, KE "81 a2" KA);
    a_bs(a, 0x61, 64);
    a_hex(a, KH);
    a_bs(a, 0x62, 64);
    a_hex(a, KG "01" KS "02" KPF);
    a_bs(a, 0x71, 64);
    a_hex(a, KSF);
    a_bs(a, 0x72, 64);
    a_hex(a, KTOP "03");
}

/* ══ decode wrappers on static scratch ═════════════════════════════════ */

static dht2_req_t           g_req;
static dht2_answer_t        g_ans;
static dht2_list_answer_t   g_la;
static dht2_refusal_t       g_ref;
static dht2_p_hello_t       g_hello;
static dht2_p_get_t         g_pget;
static dht2_p_offer_t       g_off;
static dht2_p_want_t        g_want;
static dht2_p_deliver_t     g_del;
static dht2_pull_receipt_t  g_pr;

static int d_req(const uint8_t *p, size_t n)    { return dht2_req_decode(p, n, &g_req); }
static int d_ans(const uint8_t *p, size_t n)    { return dht2_answer_decode(p, n, &g_ans); }
static int d_rcp(const uint8_t *p, size_t n)    { return dht2_receipt_decode(p, n, &g_ans); }
static int d_la(const uint8_t *p, size_t n)     { return dht2_list_answer_decode(p, n, &g_la); }
static int d_ref(const uint8_t *p, size_t n)    { return dht2_refusal_decode(p, n, &g_ref); }
static int d_hello(const uint8_t *p, size_t n)  { return dht2_p_hello_decode(p, n, &g_hello); }
static int d_pget(const uint8_t *p, size_t n)   { return dht2_p_get_decode(p, n, &g_pget); }
static int d_off(const uint8_t *p, size_t n)    { return dht2_p_offer_decode(p, n, &g_off); }
static int d_want9(const uint8_t *p, size_t n)  { return dht2_p_want_decode(p, n, 9, &g_want); }
static int d_del(const uint8_t *p, size_t n)    { return dht2_p_deliver_decode(p, n, &g_del); }
static int d_pr(const uint8_t *p, size_t n)     { return dht2_pull_receipt_decode(p, n, &g_pr); }

typedef int (*dec_fn)(const uint8_t *, size_t);

/* The pinned bytes decode; a trailing byte and EVERY strict prefix are
 * refused with `bad`. */
static void strict_sweep(const char *name, dec_fn d, const asm_t *a, int bad)
{
    size_t k;
    int    prefix_ok = 1;

    CHECK(!a->err, name);
    CHECK(d(a->b, a->n) == DHT2_OK, name);
    g_m = *a;
    g_m.b[g_m.n++] = 0x00;
    CHECK(d(g_m.b, g_m.n) == bad, "trailing byte refused");
    for (k = 0; k < a->n; k++) {
        if (d(a->b, k) != bad) {
            prefix_ok = 0;
        }
    }
    CHECK(prefix_ok, "every strict prefix refused");
}

/* ══ CBOR additions ════════════════════════════════════════════════════ */

static void test_cbor_additions(void)
{
    static const uint8_t arr1[] = { 0x81, 0x01 };
    static const uint8_t arr_long[] = { 0x98, 0x01, 0x01 };
    static const uint8_t arr_indef[] = { 0x9f, 0xff };
    static const uint8_t f4[] = { 0xf4 };
    static const uint8_t f5[] = { 0xf5 };
    static const uint8_t f6[] = { 0xf6 };
    static const uint8_t f7[] = { 0xf7 };
    static const uint8_t bs[] = { 0x42, 0x01, 0x02 };
    dht2_cbor_rd_t r;
    dht2_cbor_wr_t w;
    uint8_t        out[8];
    uint64_t       c = 99;
    bool           b = true;

    dht2_cbor_rd_init(&r, arr1, sizeof(arr1));
    CHECK(dht2_cbor_rd_array(&r, &c) == 0 && c == 1, "array head");
    dht2_cbor_rd_init(&r, arr_long, sizeof(arr_long));
    CHECK(dht2_cbor_rd_array(&r, &c) != 0, "long-form array count refused");
    dht2_cbor_rd_init(&r, arr_indef, sizeof(arr_indef));
    CHECK(dht2_cbor_rd_array(&r, &c) != 0, "indefinite array refused");
    dht2_cbor_rd_init(&r, bs, sizeof(bs));
    CHECK(dht2_cbor_rd_array(&r, &c) != 0, "bstr is not an array");

    dht2_cbor_rd_init(&r, f4, 1);
    CHECK(dht2_cbor_rd_bool(&r, &b) == 0 && !b && dht2_cbor_rd_done(&r),
          "false");
    dht2_cbor_rd_init(&r, f5, 1);
    CHECK(dht2_cbor_rd_bool(&r, &b) == 0 && b, "true");
    dht2_cbor_rd_init(&r, f6, 1);
    CHECK(dht2_cbor_rd_bool(&r, &b) != 0, "null is not a bool");
    dht2_cbor_rd_init(&r, f6, 1);
    CHECK(dht2_cbor_rd_null(&r) == 0 && dht2_cbor_rd_done(&r), "null");
    dht2_cbor_rd_init(&r, f7, 1);
    CHECK(dht2_cbor_rd_null(&r) != 0, "undefined is not null");
    dht2_cbor_rd_init(&r, f5, 1);
    CHECK(dht2_cbor_rd_null(&r) != 0, "true is not null");

    dht2_cbor_rd_init(&r, bs, sizeof(bs));
    CHECK(dht2_cbor_rd_peek_mt(&r) == 2 && r.pos == 0, "peek does not consume");
    dht2_cbor_rd_init(&r, f6, 1);
    CHECK(dht2_cbor_rd_peek_null(&r) && r.pos == 0, "peek null");
    dht2_cbor_rd_init(&r, f5, 1);
    CHECK(!dht2_cbor_rd_peek_null(&r), "peek: true is not null");
    dht2_cbor_rd_init(&r, f5, 0);
    CHECK(dht2_cbor_rd_peek_mt(&r) == -1 && !dht2_cbor_rd_peek_null(&r),
          "peek at the end");

    dht2_cbor_wr_init(&w, out, sizeof(out));
    dht2_cbor_wr_array(&w, 24);
    dht2_cbor_wr_bool(&w, false);
    dht2_cbor_wr_bool(&w, true);
    dht2_cbor_wr_null(&w);
    CHECK(dht2_cbor_wr_ok(&w) && w.len == 5 && out[0] == 0x98 &&
          out[1] == 0x18 && out[2] == 0xf4 && out[3] == 0xf5 &&
          out[4] == 0xf6, "writer: array(24) shortest, false, true, null");
}

/* ══ requests (row 14) ═════════════════════════════════════════════════ */

static void test_requests(void)
{
    dht2_req_t   q;
    uint8_t      out[512];
    size_t       n = 0, k;
    static const uint8_t e1[] = { 0xaa, 0xbb, 0xcc };
    static const uint8_t e2[] = { 0xdd, 0xee };
    uint8_t     *big;

    /* get: pinned bytes, round trip. */
    memset(&q, 0, sizeof(q));
    q.kind = DHT2_REQ_GET;
    memset(q.nonce, 0x01, 32);
    q.count = 2;
    memset(q.keys[0], 0x02, 64);
    memset(q.keys[1], 0x03, 64);
    exp_get(&g_a);
    CHECK(dht2_req_encode(&q, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "get request pinned bytes");
    CHECK(dht2_req_encode(&q, NULL, 0, &k) == DHT2_OK && k == n,
          "get request count pass");
    CHECK(dht2_req_decode(g_a.b, g_a.n, &g_req) == DHT2_OK &&
          g_req.kind == DHT2_REQ_GET && g_req.count == 2 &&
          memcmp(g_req.nonce, q.nonce, 32) == 0 &&
          memcmp(g_req.keys, q.keys, sizeof(q.keys)) == 0, "get decodes");
    strict_sweep("get", d_req, &g_a, DHT2_E_MALFORMED_REQ);

    /* put: pinned bytes (also the read-repair form). */
    memset(&q, 0, sizeof(q));
    q.kind = DHT2_REQ_PUT;
    memset(q.nonce, 0x01, 32);
    q.count = 2;
    q.envs[0] = e1;
    q.env_lens[0] = sizeof(e1);
    q.envs[1] = e2;
    q.env_lens[1] = sizeof(e2);
    exp_put(&g_a);
    CHECK(dht2_req_encode(&q, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "put request pinned bytes");
    CHECK(dht2_req_decode(g_a.b, g_a.n, &g_req) == DHT2_OK &&
          g_req.kind == DHT2_REQ_PUT && g_req.count == 2 &&
          g_req.env_lens[0] == 3 && memcmp(g_req.envs[0], e1, 3) == 0 &&
          g_req.env_lens[1] == 2 && memcmp(g_req.envs[1], e2, 2) == 0,
          "put decodes");
    strict_sweep("put", d_req, &g_a, DHT2_E_MALFORMED_REQ);

    /* Rejects (row 7: nonce ≠ 32 B, > 8 keys, a key ≠ 64 B, unknown op). */
    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 31);
    a_hex(&g_m, KOP "63 676574" KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "nonce of 31 B");

    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 706f70" KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "unknown op");
    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "66 726570616972" KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ,
          "op \"repair\" is not on the wire (repair = put)");

    for (k = 8; k <= 9; k++) {
        size_t i;

        a_init(&g_m);
        a_hex(&g_m, "a3" KN);
        a_bs(&g_m, 0x01, 32);
        a_hex(&g_m, KOP "63 676574" KKEYS);
        a_uint(&g_m, 0);
        g_m.b[g_m.n - 1] = (uint8_t)(0x80u + k);
        for (i = 0; i < k; i++) {
            a_bs(&g_m, (uint8_t)i, 64);
        }
        CHECK((d_req(g_m.b, g_m.n) == DHT2_OK) == (k == 8),
              "get: 8 keys accepted, 9 refused");
        a_init(&g_m);
        a_hex(&g_m, "a3" KN);
        a_bs(&g_m, 0x01, 32);
        a_hex(&g_m, KOP "63 707574" KENVS);
        a_uint(&g_m, 0);
        g_m.b[g_m.n - 1] = (uint8_t)(0x80u + k);
        for (i = 0; i < k; i++) {
            a_hex(&g_m, "41 aa");
        }
        CHECK((d_req(g_m.b, g_m.n) == DHT2_OK) == (k == 8),
              "put: 8 envs accepted, 9 refused");
    }

    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 676574" KKEYS "81");
    a_bs(&g_m, 0x02, 63);
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "a key of 63 B");

    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 676574" KENVS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "get with envs");
    a_init(&g_m);
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 707574" KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "put with keys");

    a_init(&g_m);                                     /* unsorted: op < n */
    a_hex(&g_m, "a3" KOP "63 676574" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "unsorted keys");
    a_init(&g_m);                                     /* duplicate n */
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 676574");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ, "duplicate key");
    a_init(&g_m);                                     /* unknown key "x" */
    a_hex(&g_m, "a4" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 676574" KKEYS "80" "64 7a7a7a7a 00");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ,
          "unknown key (sorts after keys, so not an ordering fault)");
    a_init(&g_m);                                     /* long-form length */
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "63 676574" KKEYS "98 01");
    a_bs(&g_m, 0x02, 64);
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ,
          "long-form array count");
    a_init(&g_m);                                     /* long-form text len */
    a_hex(&g_m, "a3" KN);
    a_bs(&g_m, 0x01, 32);
    a_hex(&g_m, KOP "78 03 676574" KKEYS "80");
    CHECK(d_req(g_m.b, g_m.n) == DHT2_E_MALFORMED_REQ,
          "long-form text length");

    /* An env above the 262,144 B cap: encoder and decoder both refuse. */
    big = (uint8_t *)malloc(DHT2_ENVELOPE_MAX + 1u + 64u);
    if (big != NULL) {
        uint8_t *buf = (uint8_t *)malloc(DHT2_ENVELOPE_MAX + 1u + 128u);

        memset(big, 0x5a, DHT2_ENVELOPE_MAX + 1u);
        memset(&q, 0, sizeof(q));
        q.kind = DHT2_REQ_PUT;
        q.count = 1;
        q.envs[0] = big;
        q.env_lens[0] = DHT2_ENVELOPE_MAX + 1u;
        CHECK(dht2_req_encode(&q, NULL, 0, &n) == DHT2_E_MALFORMED_REQ,
              "encoder refuses an env > 262,144 B");
        q.env_lens[0] = DHT2_ENVELOPE_MAX;
        CHECK(dht2_req_encode(&q, NULL, 0, &n) == DHT2_OK,
              "an env of exactly 262,144 B is encodable");
        if (buf != NULL) {
            size_t   o = 0;
            uint8_t  hdr[] = { 0xa3, 0x61, 0x6e, 0x58, 0x20 };

            memcpy(buf + o, hdr, sizeof(hdr));
            o += sizeof(hdr);
            memset(buf + o, 0x01, 32);
            o += 32;
            {
                static const uint8_t mid[] = {
                    0x62, 0x6f, 0x70, 0x63, 0x70, 0x75, 0x74,
                    0x64, 0x65, 0x6e, 0x76, 0x73, 0x81,
                    0x5a, 0x00, 0x04, 0x00, 0x01
                };

                memcpy(buf + o, mid, sizeof(mid));
                o += sizeof(mid);
            }
            memset(buf + o, 0x5a, DHT2_ENVELOPE_MAX + 1u);
            o += DHT2_ENVELOPE_MAX + 1u;
            CHECK(d_req(buf, o) == DHT2_E_MALFORMED_REQ,
                  "decoder refuses an env of 262,145 B");
            free(buf);
        }
        free(big);
    }

    /* Encoder refusals. */
    memset(&q, 0, sizeof(q));
    q.kind = DHT2_REQ_GET;
    q.count = 9;
    CHECK(dht2_req_encode(&q, NULL, 0, &n) == DHT2_E_MALFORMED_REQ,
          "encoder: 9 keys refused");
    CHECK(dht2_req_encode(NULL, NULL, 0, &n) == DHT2_E_ARG, "NULL request");
    q.count = 0;
    CHECK(dht2_req_encode(&q, out, 4, &n) == DHT2_E_ARG, "buffer too small");
}

/* ══ row 7 results, answers, receipts ══════════════════════════════════ */

static void fill_answer(dht2_answer_t *a)
{
    memset(a, 0, sizeof(*a));
    memset(a->q, 0x04, 32);
    memset(a->n, 0x05, 64);
    memset(a->c, 0x06, 32);
    a->h = 10;
    a->t = 300;
}

static void test_answers(void)
{
    dht2_answer_t a, back;
    uint8_t       out[2048];
    size_t        n = 0, k;
    static const struct { const char *v; int ok_read; int ok_rcp; } vs[] = {
        { "07", 1, 1 },                 /* code 7 */
        { "01", 1, 1 }, { "0d", 1, 1 }, /* 1 and 13 */
        { "10", 1, 1 }, { "11", 1, 1 }, /* 16 and 17 */
        { "82 12 00", 1, 1 },           /* [18, 0] */
        { "82 12 1a ffffffff", 1, 1 },  /* [18, 2^32-1] */
        { "f6", 1, 0 },                 /* null: read only */
        { "00", 0, 0 },                 /* 0 is not a wire code */
        { "0e", 0, 0 },                 /* 14: call-level */
        { "0f", 0, 0 },                 /* 15: call-level */
        { "12", 0, 0 },                 /* bare 18 */
        { "13", 0, 0 },                 /* 19 */
        { "20", 0, 0 },                 /* negative int */
        { "81 12", 0, 0 },              /* [18] */
        { "83 12 00 00", 0, 0 },        /* [18, 0, 0] */
        { "82 11 00", 0, 0 },           /* [17, 0] */
        { "82 12 20", 0, 0 },           /* [18, -1] */
        { "f4", 0, 0 },                 /* false */
        { "f5", 0, 0 },                 /* true */
        { "60", 0, 0 },                 /* text */
        { "18 07", 0, 0 },              /* long-form 7 */
    };

    /* Pinned read answer: hash, null, code 7, [18, 5]. */
    fill_answer(&a);
    a.r_count = 4;
    memset(a.r[0].key, 0x10, 64);
    a.r[0].kind = DHT2_RV_HASH;
    memset(a.r[0].hash, 0x20, 64);
    memset(a.r[1].key, 0x11, 64);
    a.r[1].kind = DHT2_RV_NULL;
    memset(a.r[2].key, 0x12, 64);
    a.r[2].kind = DHT2_RV_CODE;
    a.r[2].code = 7;
    memset(a.r[3].key, 0x13, 64);
    a.r[3].kind = DHT2_RV_HANDLED;
    a.r[3].through = 5;
    exp_answer(&g_a);
    CHECK(dht2_answer_encode(&a, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "read answer pinned bytes");
    CHECK(dht2_answer_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          memcmp(&back, &a, sizeof(a)) == 0, "read answer round trip");
    strict_sweep("answer", d_ans, &g_a, DHT2_E_BAD_ENCODING);
    CHECK(dht2_receipt_decode(g_a.b, g_a.n, &back) == DHT2_E_BAD_ENCODING,
          "a receipt context refuses the answer's null");
    CHECK(dht2_receipt_encode(&a, out, sizeof(out), &n) ==
          DHT2_E_BAD_ENCODING, "receipt encoder refuses null");

    /* Pinned receipt. */
    a.r_count = 3;
    a.r[1] = a.r[2];
    a.r[2] = a.r[3];
    memset(&a.r[3], 0, sizeof(a.r[3]));
    a.r[1].code = 10;
    exp_receipt(&g_a);
    CHECK(dht2_receipt_encode(&a, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "receipt pinned bytes");
    CHECK(dht2_receipt_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          memcmp(&back, &a, sizeof(a)) == 0, "receipt round trip");
    strict_sweep("receipt", d_rcp, &g_a, DHT2_E_BAD_ENCODING);

    /* Row 7 `v` variants, read and receipt contexts. */
    for (k = 0; k < sizeof(vs) / sizeof(vs[0]); k++) {
        ans_one(&g_a, vs[k].v);
        CHECK((d_ans(g_a.b, g_a.n) == DHT2_OK) == (vs[k].ok_read != 0), vs[k].v);
        CHECK((d_rcp(g_a.b, g_a.n) == DHT2_OK) == (vs[k].ok_rcp != 0), vs[k].v);
    }
    ans_head(&g_a, 1);                                /* hash of 63 B */
    elem_begin(&g_a, 0x10);
    a_bs(&g_a, 0x20, 63);
    ans_tail(&g_a);
    CHECK(d_ans(g_a.b, g_a.n) == DHT2_E_BAD_ENCODING, "hash of 63 B");
    ans_head(&g_a, 1);                                /* key of 63 B */
    a_hex(&g_a, "a2" KK);
    a_bs(&g_a, 0x10, 63);
    a_hex(&g_a, KV "07");
    ans_tail(&g_a);
    CHECK(d_ans(g_a.b, g_a.n) == DHT2_E_BAD_ENCODING, "k of 63 B");
    ans_head(&g_a, 1);                                /* {v, k} unsorted */
    a_hex(&g_a, "a2" KV "07" KK);
    a_bs(&g_a, 0x10, 64);
    ans_tail(&g_a);
    CHECK(d_ans(g_a.b, g_a.n) == DHT2_E_BAD_ENCODING, "unsorted {k, v}");
    ans_head(&g_a, 1);                                /* unknown key in {k,v} */
    a_hex(&g_a, "a3" KK);
    a_bs(&g_a, 0x10, 64);
    a_hex(&g_a, KV "07" "61 78 00");
    ans_tail(&g_a);
    CHECK(d_ans(g_a.b, g_a.n) == DHT2_E_BAD_ENCODING, "unknown key in {k, v}");

    /* Top-level strict rejects. */
    exp_answer(&g_a);
    g_m = g_a;
    g_m.b[0] = 0xa7;                                  /* count 7, six keys */
    CHECK(d_ans(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "map count too large");
    a_init(&g_m);                                     /* h long-form */
    a_hex(&g_m, "a6" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KH "18 0a" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KR "80" KT "00");
    CHECK(d_ans(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "long-form h");
    a_init(&g_m);                                     /* q of 31 B */
    a_hex(&g_m, "a6" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KH "0a" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 31);
    a_hex(&g_m, KR "80" KT "00");
    CHECK(d_ans(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "q of 31 B");
    a_init(&g_m);                                     /* n before h: unsorted */
    a_hex(&g_m, "a6" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KH "0a" KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KR "80" KT "00");
    CHECK(d_ans(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "unsorted answer keys");
    ans_head(&g_m, 9);                                /* 9 results */
    for (k = 0; k < 9; k++) {
        elem_begin(&g_m, (uint8_t)(0x10 + k));
        a_hex(&g_m, "07");
    }
    ans_tail(&g_m);
    CHECK(d_ans(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "9 results refused");

    /* Encoder refusals. */
    fill_answer(&a);
    a.r_count = 1;
    a.r[0].kind = DHT2_RV_CODE;
    a.r[0].code = 14;
    CHECK(dht2_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "code 14 per key refused");
    a.r[0].code = 15;
    CHECK(dht2_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "code 15 per key refused");
    a.r[0].code = 18;
    CHECK(dht2_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "bare code 18 refused");
    a.r_count = 9;
    CHECK(dht2_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "9 results refused");
    CHECK(dht2_answer_encode(NULL, NULL, 0, &n) == DHT2_E_ARG, "NULL answer");
}

/* ══ LIST answer ═══════════════════════════════════════════════════════ */

static void fill_list(dht2_list_answer_t *a)
{
    memset(a, 0, sizeof(*a));
    memset(a->q, 0x04, 32);
    memset(a->n, 0x05, 64);
    memset(a->c, 0x06, 32);
    a->h = 1;
    a->t = 2;
    memset(a->r.key, 0x30, 64);
    a->r.kind = DHT2_RV_HASH;
    memset(a->r.hash, 0x31, 64);
    a->has_ctl = false;
    a->list_count = 2;
    memset(a->list[0].w, 0x41, 64);
    memset(a->list[0].d, 0x51, 64);
    memset(a->list[1].w, 0x42, 64);
    memset(a->list[1].d, 0x52, 64);
    a->has_cursor = true;
    memset(a->cursor, 0x42, 64);
    a->complete = true;
    a->has_req_cursor = true;
    memset(a->req_cursor, 0x40, 64);
}

static void test_list(void)
{
    static const uint8_t w2[] = { 0x41, 0x42 };
    dht2_list_answer_t   a, back;
    uint8_t              out[4096];
    size_t               n = 0, k;
    uint8_t              w17[17];

    /* Pinned continuation page: ctl null, cursor, req_cursor. */
    fill_list(&a);
    {
        asm_t *p = &g_a;

        a_init(p);
        a_hex(p, "ab" KC);
        a_bs(p, 0x06, 32);
        a_hex(p, KH "01" KN);
        a_bs(p, 0x05, 64);
        a_hex(p, KQ);
        a_bs(p, 0x04, 32);
        a_hex(p, KR "81");
        elem_begin(p, 0x30);
        a_bs(p, 0x31, 64);
        a_hex(p, KT "02" KCTL "f6" KLIST "82 a2" KD);
        a_bs(p, 0x51, 64);
        a_hex(p, KW);
        a_bs(p, 0x41, 64);
        a_hex(p, "a2" KD);
        a_bs(p, 0x52, 64);
        a_hex(p, KW);
        a_bs(p, 0x42, 64);
        a_hex(p, KCUR);
        a_bs(p, 0x42, 64);
        a_hex(p, KCOMPL "f5" KREQC);
        a_bs(p, 0x40, 64);
    }
    CHECK(dht2_list_answer_encode(&a, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "LIST answer pinned bytes");
    CHECK(dht2_list_answer_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          memcmp(&back, &a, sizeof(a)) == 0, "LIST answer round trip");
    strict_sweep("list answer", d_la, &g_a, DHT2_E_BAD_ENCODING);

    /* First page: no req_cursor (decision 4); ctl as a hash. */
    a.has_req_cursor = false;
    memset(a.req_cursor, 0, 64);
    a.has_ctl = true;
    memset(a.ctl, 0x77, 64);
    a_init(&g_a);
    a_hex(&g_a, "aa" KC);
    a_bs(&g_a, 0x06, 32);
    a_hex(&g_a, KH "01" KN);
    a_bs(&g_a, 0x05, 64);
    a_hex(&g_a, KQ);
    a_bs(&g_a, 0x04, 32);
    a_hex(&g_a, KR "81");
    elem_begin(&g_a, 0x30);
    a_bs(&g_a, 0x31, 64);
    a_hex(&g_a, KT "02" KCTL);
    a_bs(&g_a, 0x77, 64);
    a_hex(&g_a, KLIST "82 a2" KD);
    a_bs(&g_a, 0x51, 64);
    a_hex(&g_a, KW);
    a_bs(&g_a, 0x41, 64);
    a_hex(&g_a, "a2" KD);
    a_bs(&g_a, 0x52, 64);
    a_hex(&g_a, KW);
    a_bs(&g_a, 0x42, 64);
    a_hex(&g_a, KCUR);
    a_bs(&g_a, 0x42, 64);
    a_hex(&g_a, KCOMPL "f5");
    CHECK(dht2_list_answer_encode(&a, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "first page: no req_cursor, ctl hash");
    CHECK(dht2_list_answer_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          !back.has_req_cursor && back.has_ctl &&
          memcmp(&back, &a, sizeof(a)) == 0, "first page round trip");

    /* Empty page: complete = true, no cursor; v = code 17 allowed. */
    memset(&a, 0, sizeof(a));
    fill_list(&a);
    a.list_count = 0;
    memset(a.list, 0, sizeof(a.list));
    a.has_cursor = false;
    memset(a.cursor, 0, 64);
    a.has_req_cursor = false;
    memset(a.req_cursor, 0, 64);
    a.complete = true;
    a.r.kind = DHT2_RV_CODE;
    a.r.code = 17;
    memset(a.r.hash, 0, 64);
    a_init(&g_a);
    a_hex(&g_a, "a9" KC);
    a_bs(&g_a, 0x06, 32);
    a_hex(&g_a, KH "01" KN);
    a_bs(&g_a, 0x05, 64);
    a_hex(&g_a, KQ);
    a_bs(&g_a, 0x04, 32);
    a_hex(&g_a, KR "81");
    elem_begin(&g_a, 0x30);
    a_hex(&g_a, "11" KT "02" KCTL "f6" KLIST "80" KCOMPL "f5");
    CHECK(dht2_list_answer_encode(&a, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "empty page pinned bytes");
    CHECK(dht2_list_answer_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          memcmp(&back, &a, sizeof(a)) == 0, "empty page round trip");
    strict_sweep("empty page", d_la, &g_a, DHT2_E_BAD_ENCODING);

    /* Decoder: the LIST rules, on hand-built bytes. */
    list_build(&g_m, 2, w2, 0x42, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_OK, "baseline hand-built LIST page");
    list_build(&g_m, 2, w2, 0x42, 1, 0x40, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_OK,
          "continuation: first w strictly after req_cursor");
    list_build(&g_m, 2, w2, 0x42, 1, 0x41, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "first w equal to req_cursor refused (cursor is exclusive)");
    list_build(&g_m, 2, w2, 0x42, 1, 0x42, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "first w before req_cursor refused");
    {
        static const uint8_t desc[] = { 0x42, 0x41 };
        static const uint8_t eq[] = { 0x41, 0x41 };

        list_build(&g_m, 2, desc, 0x41, 1, -1, -1, "11");
        CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
              "descending writers refused");
        list_build(&g_m, 2, eq, 0x41, 1, -1, -1, "11");
        CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
              "equal writers refused");
    }
    list_build(&g_m, 2, w2, 0x41, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "cursor that is not the last w refused");
    list_build(&g_m, 0, w2, -1, 0, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "empty page with complete false refused");
    list_build(&g_m, 0, w2, 0x41, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "empty page with a cursor refused");
    list_build(&g_m, 0, w2, -1, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_OK, "empty page, complete true");
    for (k = 0; k < 17; k++) {
        w17[k] = (uint8_t)(0x41 + k);
    }
    list_build(&g_m, 16, w17, 0x50, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_OK, "16 entries accepted");
    list_build(&g_m, 17, w17, 0x51, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "17 entries refused");
    fill_list(&a);
    a.list_count = 17;
    CHECK(dht2_list_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "encoder: 17 entries refused");
    fill_list(&a);
    memset(a.req_cursor, 0x41, 64);
    CHECK(dht2_list_answer_encode(&a, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "encoder: first w equal to req_cursor refused");

    /* `r` rules in the LIST context: hash or 17 only. */
    list_build(&g_m, 0, w2, -1, 1, -1, -1, "f6");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "null in LIST r refused");
    list_build(&g_m, 0, w2, -1, 1, -1, -1, "07");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "code 7 in LIST r refused");
    list_build(&g_m, 0, w2, -1, 1, -1, -1, "82 12 05");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "[18, x] in LIST r refused");
    /* r with two elements. */
    a_init(&g_m);
    a_hex(&g_m, "a9" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KH "01" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KR "82");
    elem_begin(&g_m, 0x30);
    a_hex(&g_m, "11");
    elem_begin(&g_m, 0x31);
    a_hex(&g_m, "11" KT "02" KCTL "f6" KLIST "80" KCOMPL "f5");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "LIST r with two elements refused");

    /* Unsorted optional keys: complete before cursor. */
    list_build(&g_m, 2, w2, 0x42, 1, -1, -1, "11");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_OK, "baseline again");
    a_init(&g_m);
    a_hex(&g_m, "aa" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KH "01" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KR "81");
    elem_begin(&g_m, 0x30);
    a_hex(&g_m, "11" KT "02" KCTL "f6" KLIST "80" KCOMPL "f5" KCUR);
    a_bs(&g_m, 0x41, 64);
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "complete before cursor (unsorted) refused");
    /* {d, w} swapped. */
    a_init(&g_m);
    a_hex(&g_m, "a9" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KH "01" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KR "81");
    elem_begin(&g_m, 0x30);
    a_hex(&g_m, "11" KT "02" KCTL "f6" KLIST "81 a2" KW);
    a_bs(&g_m, 0x41, 64);
    a_hex(&g_m, KD);
    a_bs(&g_m, 0x51, 64);
    a_hex(&g_m, KCOMPL "f5");
    CHECK(d_la(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "{w, d} unsorted refused");
}

/* ══ refusal ═══════════════════════════════════════════════════════════ */

static void test_refusal(void)
{
    dht2_refusal_t m, back;
    uint8_t        out[512];
    size_t         n = 0;

    memset(&m, 0, sizeof(m));
    memset(m.q, 0x04, 32);
    memset(m.n, 0x05, 64);
    memset(m.c, 0x06, 32);
    m.e = 15;
    exp_refusal(&g_a);
    CHECK(dht2_refusal_encode(&m, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "refusal pinned bytes");
    CHECK(dht2_refusal_decode(g_a.b, g_a.n, &back) == DHT2_OK &&
          memcmp(&back, &m, sizeof(m)) == 0, "refusal round trip");
    strict_sweep("refusal", d_ref, &g_a, DHT2_E_BAD_ENCODING);
    m.e = 14;
    CHECK(dht2_refusal_encode(&m, out, sizeof(out), &n) == DHT2_OK,
          "e = 14");
    m.e = 13;
    CHECK(dht2_refusal_encode(&m, out, sizeof(out), &n) ==
          DHT2_E_BAD_ENCODING, "e = 13 refused");
    g_m = g_a;
    g_m.b[0] = 0xa5;                                  /* count 5, four keys */
    CHECK(d_ref(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "count mismatch");
    a_init(&g_m);                                     /* with h and t */
    a_hex(&g_m, "a6" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KE "0f" KH "01" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    a_hex(&g_m, KT "02");
    CHECK(d_ref(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
          "a refusal carries no h / t");
    a_init(&g_m);                                     /* e = 16 */
    a_hex(&g_m, "a4" KC);
    a_bs(&g_m, 0x06, 32);
    a_hex(&g_m, KE "10" KN);
    a_bs(&g_m, 0x05, 64);
    a_hex(&g_m, KQ);
    a_bs(&g_m, 0x04, 32);
    CHECK(d_ref(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "e = 16 refused");
}

/* ══ seal / open ═══════════════════════════════════════════════════════ */

static uint8_t g_pk[DHT2_PUBKEY_LEN];
static uint8_t g_sk[QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_env[4 * DHT2_SIG_LEN];

static void test_seal_and_sizes(void)
{
    dht2_answer_t a;
    uint8_t       pay[DHT2_ANSWER_PAYLOAD_MAX];
    size_t        plen = 0, elen = 0, k;
    dht2_env_t    env;
    dht2_answer_t back;

    /* Sizes: the derived constants against the real encoder / sealer. */
    fill_answer(&a);
    a.h = UINT64_MAX;
    a.t = UINT64_MAX;
    a.r_count = 8;
    for (k = 0; k < 8; k++) {
        a.r[k].kind = DHT2_RV_HASH;
    }
    CHECK(dht2_answer_encode(&a, pay, sizeof(pay), &plen) == DHT2_OK &&
          plen == DHT2_READ_ANSWER_PAYLOAD_MAX && plen == 1262u &&
          plen <= DHT2_ANSWER_PAYLOAD_MAX,
          "row 11: the 8-key read answer payload is 1,262 B");
    CHECK(dht2_answer_seal(DHT2_PT_RECEIPT, pay, plen, NULL, g_pk, NULL, 0,
                           &elen) == DHT2_OK &&
          elen == 8516u && elen <= DHT2_ANSWER_ENV_MAX,
          "row 11: the read answer envelope is 8,516 B");

    /* The maximal LIST answer: 16 entries, both cursors, hash r and ctl,
     * 9-byte h / t — the largest payload of the four. */
    {
        dht2_list_answer_t la;
        uint8_t            lpay[DHT2_ANSWER_PAYLOAD_MAX];
        size_t             lplen = 0, lelen = 0;

        memset(&la, 0, sizeof(la));
        la.h = UINT64_MAX;
        la.t = UINT64_MAX;
        la.r.kind = DHT2_RV_HASH;
        la.has_ctl = true;
        la.list_count = DHT2_LIST_PAGE_MAX;
        for (k = 0; k < DHT2_LIST_PAGE_MAX; k++) {
            memset(la.list[k].w, (int)(0x41 + k), 64);
            memset(la.list[k].d, 0x51, 64);
        }
        la.has_req_cursor = true;
        memset(la.req_cursor, 0x40, 64);
        la.has_cursor = true;
        memset(la.cursor, (int)(0x41 + DHT2_LIST_PAGE_MAX - 1u), 64);
        la.complete = true;
        CHECK(dht2_list_answer_encode(&la, lpay, sizeof(lpay), &lplen) ==
              DHT2_OK && lplen == DHT2_LIST_ANSWER_PAYLOAD_MAX &&
              lplen == 2731u && lplen == DHT2_ANSWER_PAYLOAD_MAX,
              "row 11: the maximal LIST answer payload is 2,731 B");
        CHECK(dht2_answer_seal(DHT2_PT_ANSWER, lpay, lplen, NULL, g_pk, NULL,
                               0, &lelen) == DHT2_OK &&
              lelen <= DHT2_ANSWER_ENV_MAX,
              "row 11: the maximal LIST envelope fits the constant");
        /* Payload-type length 21 is the longest: the constant equals the
         * LIST envelope under the 21-byte types (receipt / refusal). */
        CHECK(dht2_env_seal(DHT2_DOMAIN_ANSWER,
                            (const uint8_t *)DHT2_PT_RECEIPT,
                            strlen(DHT2_PT_RECEIPT), lpay, lplen, NULL,
                            g_pk, NULL, 0, &lelen) == DHT2_OK &&
              lelen == DHT2_ANSWER_ENV_MAX,
              "row 11: the constant is the LIST term under a 21-byte type");
    }
    CHECK(DHT2_ANSWER_MSG_MAX ==
          8u * 262144u + (unsigned)DHT2_ANSWER_ENV_MAX,
          "row 11: message = 8 x 262,144 + the largest envelope");

    /* Seal / open round trip with a fixed-seed key. */
    fill_answer(&a);
    a.r_count = 1;
    a.r[0].kind = DHT2_RV_CODE;
    a.r[0].code = 10;
    CHECK(dht2_answer_encode(&a, pay, sizeof(pay), &plen) == DHT2_OK,
          "payload");
    CHECK(dht2_answer_seal(DHT2_PT_RECEIPT, pay, plen, g_sk, g_pk, g_env,
                           sizeof(g_env), &elen) == DHT2_OK, "seal");
    CHECK(dht2_answer_open(g_env, elen, DHT2_PT_RECEIPT, &env) == DHT2_OK &&
          env.payload_len == plen &&
          memcmp(env.payload, pay, plen) == 0 &&
          dht2_receipt_decode(env.payload, env.payload_len, &back) ==
          DHT2_OK && back.r[0].code == 10, "open + decode the payload");
    CHECK(dht2_answer_open(g_env, elen, DHT2_PT_ANSWER, &env) ==
          DHT2_E_BAD_ENCODING, "another payload type refused");
    CHECK(dht2_answer_seal("/nodus/dht/list/v1", pay, plen, g_sk, g_pk, g_env,
                           sizeof(g_env), &k) == DHT2_E_ARG,
          "seal refuses a payload type that is not answer / receipt / refusal");
    /* Flip the last payload byte inside the envelope. */
    CHECK(dht2_answer_open(g_env, elen, DHT2_PT_RECEIPT, &env) == DHT2_OK,
          "still opens before tamper");
    g_env[(size_t)(env.payload - g_env) + plen - 1u] ^= 0x01;
    CHECK(dht2_answer_open(g_env, elen, DHT2_PT_RECEIPT, &env) ==
          DHT2_E_BAD_SIGNATURE, "tampered payload is bad-signature");
}

/* ══ pull-sync ═════════════════════════════════════════════════════════ */

static void test_pull(void)
{
    uint8_t out[70000];
    size_t  n = 0, i;

    /* p_hello / p_get. */
    {
        dht2_p_hello_t h = { 1, 0x1234 }, hb;

        exp_hello(&g_a);
        CHECK(dht2_p_hello_encode(&h, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "p_hello pinned bytes");
        CHECK(dht2_p_hello_decode(g_a.b, g_a.n, &hb) == DHT2_OK &&
              hb.g == 1 && hb.top == 0x1234, "p_hello round trip");
        strict_sweep("p_hello", d_hello, &g_a, DHT2_E_BAD_ENCODING);
        a_init(&g_m);
        a_hex(&g_m, "a2" KTOP "19 1234" KG "01");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "p_hello unsorted");
        a_init(&g_m);
        a_hex(&g_m, "a2" KG "01" KG "01");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "p_hello duplicate");
        a_init(&g_m);
        a_hex(&g_m, "a2" KG "01" KS "02");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "p_hello unknown key");
        a_init(&g_m);
        a_hex(&g_m, "a2" KG "18 01" KTOP "02");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "long-form int");
        a_init(&g_m);
        a_hex(&g_m, "a2" KG "21" KTOP "02");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "negative int");
        a_init(&g_m);
        a_hex(&g_m, "a2" KG "1b ffffffffffffffff" KTOP "00");
        CHECK(d_hello(g_m.b, g_m.n) == DHT2_OK && g_hello.g == UINT64_MAX,
              "u64 maximum accepted");
    }
    {
        dht2_p_get_t m = { 1, 300 }, mb;

        exp_pget(&g_a);
        CHECK(dht2_p_get_encode(&m, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "p_get pinned bytes");
        CHECK(dht2_p_get_decode(g_a.b, g_a.n, &mb) == DHT2_OK &&
              mb.g == 1 && mb.s == 300, "p_get round trip");
        strict_sweep("p_get", d_pget, &g_a, DHT2_E_BAD_ENCODING);
    }

    /* p_offer. */
    {
        dht2_p_offer_t *ob = (dht2_p_offer_t *)malloc(sizeof(*ob));
        dht2_p_offer_t *src = (dht2_p_offer_t *)malloc(sizeof(*src));

        if (ob == NULL || src == NULL) {
            CHECK(0, "alloc");
            free(ob);
            free(src);
            return;
        }
        memset(src, 0, sizeof(*src));
        src->g = 1;
        src->top = 2;
        src->e_count = 1;
        memset(src->e[0].a, 0x61, 64);
        memset(src->e[0].h, 0x62, 64);
        memset(src->e[0].p, 0x63, 64);
        exp_offer(&g_a);
        CHECK(dht2_p_offer_encode(src, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "p_offer pinned bytes");
        CHECK(dht2_p_offer_decode(g_a.b, g_a.n, ob) == DHT2_OK &&
              memcmp(ob, src, sizeof(*src)) == 0, "p_offer round trip");
        strict_sweep("p_offer", d_off, &g_a, DHT2_E_BAD_ENCODING);

        /* 250 accepted, 251 refused (decoder and encoder). */
        for (i = 250; i <= 251; i++) {
            size_t k;

            a_init(&g_m);
            a_hex(&g_m, "a3" KE "98");
            a_uint(&g_m, 0);
            g_m.b[g_m.n - 1] = (uint8_t)i;
            for (k = 0; k < i; k++) {
                a_hex(&g_m, "a3" KA);
                a_bs(&g_m, 0x61, 64);
                a_hex(&g_m, KH);
                a_bs(&g_m, 0x62, 64);
                a_hex(&g_m, KP);
                a_bs(&g_m, 0x63, 64);
            }
            a_hex(&g_m, KG "01" KTOP "02");
            CHECK((d_off(g_m.b, g_m.n) == DHT2_OK) == (i == 250),
                  "p_offer: 250 entries accepted, 251 refused");
        }
        src->e_count = 251;
        CHECK(dht2_p_offer_encode(src, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
              "p_offer encoder: 251 refused");
        /* Entry with a 63 B hash; entry keys unsorted. */
        a_init(&g_m);
        a_hex(&g_m, "a3" KE "81 a3" KA);
        a_bs(&g_m, 0x61, 64);
        a_hex(&g_m, KH);
        a_bs(&g_m, 0x62, 63);
        a_hex(&g_m, KP);
        a_bs(&g_m, 0x63, 64);
        a_hex(&g_m, KG "01" KTOP "02");
        CHECK(d_off(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "h of 63 B");
        a_init(&g_m);
        a_hex(&g_m, "a3" KE "81 a3" KH);
        a_bs(&g_m, 0x62, 64);
        a_hex(&g_m, KA);
        a_bs(&g_m, 0x61, 64);
        a_hex(&g_m, KP);
        a_bs(&g_m, 0x63, 64);
        a_hex(&g_m, KG "01" KTOP "02");
        CHECK(d_off(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
              "offer entry keys unsorted");
        free(ob);
        free(src);
    }

    /* p_deliver. */
    {
        dht2_p_deliver_t m, mb;
        static const uint8_t v[] = { 0x01, 0x02 };

        memset(&m, 0, sizeof(m));
        m.i = 3;
        m.has_v = true;
        m.v = v;
        m.v_len = 2;
        exp_deliver_bytes(&g_a);
        CHECK(dht2_p_deliver_encode(&m, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "p_deliver pinned bytes");
        CHECK(dht2_p_deliver_decode(g_a.b, g_a.n, &mb) == DHT2_OK &&
              mb.i == 3 && mb.has_v && mb.v_len == 2 &&
              memcmp(mb.v, v, 2) == 0, "p_deliver round trip");
        strict_sweep("p_deliver", d_del, &g_a, DHT2_E_BAD_ENCODING);
        m.has_v = false;
        m.v = NULL;
        m.v_len = 0;
        exp_deliver_null(&g_a);
        CHECK(dht2_p_deliver_encode(&m, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "p_deliver null pinned bytes");
        CHECK(dht2_p_deliver_decode(g_a.b, g_a.n, &mb) == DHT2_OK &&
              mb.i == 3 && !mb.has_v, "p_deliver null round trip");
        strict_sweep("p_deliver null", d_del, &g_a, DHT2_E_BAD_ENCODING);
        a_init(&g_m);                                 /* v a uint */
        a_hex(&g_m, "a2" KI "03" KV "01");
        CHECK(d_del(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "v must be bstr|null");
        m.i = 249;
        m.has_v = false;
        CHECK(dht2_p_deliver_encode(&m, NULL, 0, &n) == DHT2_OK,
              "i = 249 encodes (null v)");
        a_init(&g_m);
        a_hex(&g_m, "a2" KI "18 f9" KV "f6");
        CHECK(d_del(g_m.b, g_m.n) == DHT2_OK && g_del.i == 249,
              "p_deliver: i = 249 accepted");
        a_init(&g_m);
        a_hex(&g_m, "a2" KI "18 fa" KV "f6");
        CHECK(d_del(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING,
              "p_deliver: i = 250 refused (decode)");
        m.i = 250;
        CHECK(dht2_p_deliver_encode(&m, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
              "p_deliver: i = 250 refused (encode)");
        m.i = 3;
        m.has_v = true;
        m.v = v;
        m.v_len = DHT2_ENVELOPE_MAX + 1u;
        CHECK(dht2_p_deliver_encode(&m, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
              "p_deliver: v > 262,144 B refused");
    }

    /* pull-receipt payload. */
    {
        dht2_pull_receipt_t *src = (dht2_pull_receipt_t *)malloc(sizeof(*src));
        dht2_pull_receipt_t *bk = (dht2_pull_receipt_t *)malloc(sizeof(*bk));

        if (src == NULL || bk == NULL) {
            CHECK(0, "alloc");
            free(src);
            free(bk);
            return;
        }
        memset(src, 0, sizeof(*src));
        memset(src->pf, 0x71, 64);
        memset(src->sf, 0x72, 64);
        memset(src->c, 0x06, 32);
        src->g = 1;
        src->s = 2;
        src->top = 3;
        src->e_count = 1;
        memset(src->e[0].a, 0x61, 64);
        memset(src->e[0].h, 0x62, 64);
        exp_pull_receipt(&g_a);
        CHECK(dht2_pull_receipt_encode(src, out, sizeof(out), &n) == DHT2_OK &&
              same(out, n, &g_a), "pull-receipt pinned bytes");
        CHECK(dht2_pull_receipt_decode(g_a.b, g_a.n, bk) == DHT2_OK &&
              memcmp(bk, src, sizeof(*src)) == 0, "pull-receipt round trip");
        strict_sweep("pull-receipt", d_pr, &g_a, DHT2_E_BAD_ENCODING);
        for (i = 250; i <= 251; i++) {
            size_t k;

            a_init(&g_m);
            a_hex(&g_m, "a7" KC);
            a_bs(&g_m, 0x06, 32);
            a_hex(&g_m, KE "98");
            a_uint(&g_m, 0);
            g_m.b[g_m.n - 1] = (uint8_t)i;
            for (k = 0; k < i; k++) {
                a_hex(&g_m, "a2" KA);
                a_bs(&g_m, 0x61, 64);
                a_hex(&g_m, KH);
                a_bs(&g_m, 0x62, 64);
            }
            a_hex(&g_m, KG "01" KS "02" KPF);
            a_bs(&g_m, 0x71, 64);
            a_hex(&g_m, KSF);
            a_bs(&g_m, 0x72, 64);
            a_hex(&g_m, KTOP "03");
            CHECK((d_pr(g_m.b, g_m.n) == DHT2_OK) == (i == 250),
                  "pull-receipt: 250 entries accepted, 251 refused");
        }
        src->e_count = 251;
        CHECK(dht2_pull_receipt_encode(src, NULL, 0, &n) ==
              DHT2_E_BAD_ENCODING, "pull-receipt encoder: 251 refused");
        a_init(&g_m);                                 /* pf of 63 B */
        a_hex(&g_m, "a7" KC);
        a_bs(&g_m, 0x06, 32);
        a_hex(&g_m, KE "80" KG "01" KS "02" KPF);
        a_bs(&g_m, 0x71, 63);
        a_hex(&g_m, KSF);
        a_bs(&g_m, 0x72, 64);
        a_hex(&g_m, KTOP "03");
        CHECK(d_pr(g_m.b, g_m.n) == DHT2_E_BAD_ENCODING, "pf of 63 B");
        free(src);
        free(bk);
    }
}

/* ══ p_want bit-vector ═════════════════════════════════════════════════ */

static void test_want(void)
{
    static const size_t ns[] = { 0, 1, 7, 8, 9, 250 };
    uint8_t             out[128];
    size_t              n = 0, t, i;
    dht2_p_want_t       m, back;
    uint8_t             bits[32];

    /* Bit order: bit i = byte floor(i/8), mask 1 << (i mod 8). */
    memset(bits, 0, sizeof(bits));
    dht2_bits_set(bits, 0);
    dht2_bits_set(bits, 2);
    dht2_bits_set(bits, 8);
    CHECK(bits[0] == 0x05 && bits[1] == 0x01, "LSB-first bit order");
    CHECK(dht2_bits_get(bits, 0) && !dht2_bits_get(bits, 1) &&
          dht2_bits_get(bits, 2) && dht2_bits_get(bits, 8) &&
          !dht2_bits_get(bits, 9), "bit get");
    CHECK(dht2_bits_len(0) == 0 && dht2_bits_len(1) == 1 &&
          dht2_bits_len(8) == 1 && dht2_bits_len(9) == 2 &&
          dht2_bits_len(250) == 32, "ceil(n/8)");

    /* Pinned n = 9 vector, and n = 0. */
    exp_want9(&g_a);
    m.b = bits;
    m.b_len = 2;
    CHECK(dht2_p_want_encode(&m, 9, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "p_want n=9 pinned bytes");
    CHECK(dht2_p_want_decode(g_a.b, g_a.n, 9, &back) == DHT2_OK &&
          back.b_len == 2 && back.b[0] == 0x05 && back.b[1] == 0x01,
          "p_want n=9 decodes");
    strict_sweep("p_want", d_want9, &g_a, DHT2_E_BAD_ENCODING);
    a_init(&g_a);
    a_hex(&g_a, "a1" KB "40");
    m.b = NULL;
    m.b_len = 0;
    CHECK(dht2_p_want_encode(&m, 0, out, sizeof(out), &n) == DHT2_OK &&
          same(out, n, &g_a), "p_want n=0 is an empty byte string");
    CHECK(dht2_p_want_decode(g_a.b, g_a.n, 0, &back) == DHT2_OK &&
          back.b_len == 0, "p_want n=0 decodes");

    for (t = 0; t < sizeof(ns) / sizeof(ns[0]); t++) {
        size_t nn = ns[t], len = dht2_bits_len(nn);

        memset(bits, 0, sizeof(bits));
        for (i = 0; i < nn; i++) {
            if ((i * 7u + 3u) % 5u == 0) {
                dht2_bits_set(bits, i);
            }
        }
        m.b = bits;
        m.b_len = len;
        CHECK(dht2_p_want_encode(&m, nn, out, sizeof(out), &n) == DHT2_OK,
              "p_want encodes");
        CHECK(dht2_p_want_decode(out, n, nn, &back) == DHT2_OK &&
              back.b_len == len, "p_want round trip");
        if (back.b_len == len) {
            int bits_ok = 1;

            for (i = 0; i < nn; i++) {
                if (dht2_bits_get(back.b, i) !=
                    (((i * 7u + 3u) % 5u) == 0)) {
                    bits_ok = 0;
                }
            }
            CHECK(bits_ok, "every bit survives");
        }
        /* The same bytes with another n: length (or a stray bit) differs. */
        if (nn > 0) {
            CHECK(dht2_p_want_decode(out, n, nn + 8, &back) ==
                  DHT2_E_BAD_ENCODING, "n + 8: wrong length refused");
            /* too short: a vector of len - 1 bytes */
            m.b_len = len - 1u;
            CHECK(dht2_p_want_encode(&m, nn, out, sizeof(out), &n) ==
                  DHT2_E_BAD_ENCODING, "encoder: too short refused");
        }
        m.b = bits;
        m.b_len = len + 1u;
        CHECK(dht2_p_want_encode(&m, nn, out, sizeof(out), &n) ==
              DHT2_E_BAD_ENCODING, "encoder: too long refused");
        /* A set bit >= n (possible only when n is not a multiple of 8). */
        if ((nn % 8u) != 0u) {
            memset(bits, 0, sizeof(bits));
            dht2_bits_set(bits, nn);
            m.b_len = len;
            CHECK(dht2_p_want_encode(&m, nn, out, sizeof(out), &n) ==
                  DHT2_E_BAD_ENCODING, "encoder: bit >= n refused");
            a_init(&g_m);
            a_init(&g_m);
            a_hex(&g_m, "a1" KB);
            if (len < 24) {
                uint8_t h1 = (uint8_t)(0x40u + len);

                a_raw(&g_m, &h1, 1);
            } else {
                uint8_t h2[2];

                h2[0] = 0x58;
                h2[1] = (uint8_t)len;
                a_raw(&g_m, h2, 2);
            }
            a_raw(&g_m, bits, len);
            CHECK(dht2_p_want_decode(g_m.b, g_m.n, nn, &back) ==
                  DHT2_E_BAD_ENCODING, "decoder: bit >= n refused");
        }
    }

    /* Wrong length on the wire; long-form length; n > 250. */
    a_init(&g_m);
    a_hex(&g_m, "a1" KB "43 050100");
    CHECK(dht2_p_want_decode(g_m.b, g_m.n, 9, &back) == DHT2_E_BAD_ENCODING,
          "3 bytes for n = 9 refused");
    a_init(&g_m);
    a_hex(&g_m, "a1" KB "41 05");
    CHECK(dht2_p_want_decode(g_m.b, g_m.n, 9, &back) == DHT2_E_BAD_ENCODING,
          "1 byte for n = 9 refused");
    a_init(&g_m);
    a_hex(&g_m, "a1" KB "58 02 0501");
    CHECK(dht2_p_want_decode(g_m.b, g_m.n, 9, &back) == DHT2_E_BAD_ENCODING,
          "long-form length refused");
    a_init(&g_m);
    a_hex(&g_m, "a1" KB "58 20");
    a_fill(&g_m, 0, 32);
    CHECK(dht2_p_want_decode(g_m.b, g_m.n, 251, &back) == DHT2_E_BAD_ENCODING,
          "n = 251 refused");
    a_init(&g_m);
    a_hex(&g_m, "a1" KB "42 0501" "61 78 00");
    CHECK(dht2_p_want_decode(g_m.b, g_m.n, 9, &back) == DHT2_E_BAD_ENCODING,
          "p_want with an extra key refused");
}

/* ══ inbox control `_data` ═════════════════════════════════════════════ */

static void test_ctl(void)
{
    dht2_ctl_entry_t e[2], got;
    uint8_t          out[256];
    size_t           n = 0, cnt = 0, i;
    bool             found = false;
    uint8_t          fp[64];
    uint8_t         *big;

    memset(e, 0, sizeof(e));
    memset(e[0].fp, 0x01, 64);
    e[0].mark = 1;
    e[0].through = 5;
    memset(e[1].fp, 0x02, 64);
    e[1].mark = 2;
    e[1].through = 0x0102030405060708ull;

    a_init(&g_a);
    a_fill(&g_a, 0x01, 64);
    a_hex(&g_a, "01 0000000000000005");
    a_fill(&g_a, 0x02, 64);
    a_hex(&g_a, "02 0102030405060708");
    CHECK(dht2_ctl_encode(e, 2, out, sizeof(out), &n) == DHT2_OK &&
          n == 146 && same(out, n, &g_a), "control pinned bytes (2 x 73 B)");
    CHECK(dht2_ctl_encode(e, 2, NULL, 0, &cnt) == DHT2_OK && cnt == 146,
          "control count pass");
    CHECK(dht2_ctl_check(g_a.b, g_a.n, &cnt) == DHT2_OK && cnt == 2,
          "control check");
    CHECK(dht2_ctl_at(g_a.b, g_a.n, 1, &got) == DHT2_OK &&
          got.mark == 2 && got.through == 0x0102030405060708ull &&
          memcmp(got.fp, e[1].fp, 64) == 0, "control entry 1");
    CHECK(dht2_ctl_at(g_a.b, g_a.n, 2, &got) == DHT2_E_ARG,
          "control index out of range");
    memset(fp, 0x02, 64);
    CHECK(dht2_ctl_lookup(g_a.b, g_a.n, fp, &found, &got) == DHT2_OK &&
          found && got.mark == 2 && got.through == 0x0102030405060708ull,
          "lookup finds the entry and its through");
    memset(fp, 0x01, 64);
    CHECK(dht2_ctl_lookup(g_a.b, g_a.n, fp, &found, NULL) == DHT2_OK &&
          found, "lookup of the first entry");
    memset(fp, 0x03, 64);
    CHECK(dht2_ctl_lookup(g_a.b, g_a.n, fp, &found, &got) == DHT2_OK &&
          !found, "lookup of an unlisted fp");
    memset(fp, 0x00, 64);
    CHECK(dht2_ctl_lookup(g_a.b, g_a.n, fp, &found, &got) == DHT2_OK &&
          !found, "lookup below the first");
    CHECK(dht2_ctl_check(NULL, 0, &cnt) == DHT2_OK && cnt == 0,
          "an empty control list is valid");

    /* Rejects. */
    CHECK(dht2_ctl_check(g_a.b, 72, &cnt) == DHT2_E_BAD_ENCODING, "72 B");
    CHECK(dht2_ctl_check(g_a.b, 145, &cnt) == DHT2_E_BAD_ENCODING, "145 B");
    g_m = g_a;
    g_m.n = 147;
    g_m.b[146] = 0;
    CHECK(dht2_ctl_check(g_m.b, g_m.n, &cnt) == DHT2_E_BAD_ENCODING, "147 B");
    g_m = g_a;
    g_m.b[64] = 0;
    CHECK(dht2_ctl_check(g_m.b, g_m.n, &cnt) == DHT2_E_BAD_ENCODING, "mark 0");
    g_m.b[64] = 3;
    CHECK(dht2_ctl_check(g_m.b, g_m.n, &cnt) == DHT2_E_BAD_ENCODING, "mark 3");
    g_m = g_a;                                        /* equal fps */
    memset(g_m.b + 73, 0x01, 64);
    CHECK(dht2_ctl_check(g_m.b, g_m.n, &cnt) == DHT2_E_BAD_ENCODING,
          "equal fps");
    g_m = g_a;                                        /* descending */
    memset(g_m.b, 0x03, 64);
    CHECK(dht2_ctl_check(g_m.b, g_m.n, &cnt) == DHT2_E_BAD_ENCODING,
          "descending fps");
    CHECK(dht2_ctl_lookup(g_m.b, g_m.n, fp, &found, NULL) ==
          DHT2_E_BAD_ENCODING, "lookup validates first");
    memcpy(&e[1], &e[0], sizeof(e[0]));
    CHECK(dht2_ctl_encode(e, 2, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "encoder: equal fps refused");
    e[1].mark = 9;
    memset(e[1].fp, 0x09, 64);
    CHECK(dht2_ctl_encode(e, 2, NULL, 0, &n) == DHT2_E_BAD_ENCODING,
          "encoder: mark 9 refused");

    /* 3,500 accepted, 3,501 refused. */
    big = (uint8_t *)malloc((DHT2_CTL_ENTRIES_MAX + 1u) * DHT2_CTL_ENTRY_LEN);
    if (big != NULL) {
        for (i = 0; i < DHT2_CTL_ENTRIES_MAX + 1u; i++) {
            uint8_t *p = big + i * DHT2_CTL_ENTRY_LEN;

            memset(p, 0, DHT2_CTL_ENTRY_LEN);
            p[0] = (uint8_t)(i >> 8);
            p[1] = (uint8_t)i;
            p[64] = 1;
        }
        CHECK(dht2_ctl_check(big, 3500u * 73u, &cnt) == DHT2_OK &&
              cnt == 3500u, "3,500 entries accepted");
        CHECK(dht2_ctl_check(big, 3501u * 73u, &cnt) == DHT2_E_BAD_ENCODING,
              "3,501 entries refused");
        free(big);
    }
    {
        dht2_ctl_entry_t *many = (dht2_ctl_entry_t *)calloc(3501u,
                                                            sizeof(*many));

        if (many != NULL) {
            for (i = 0; i < 3501u; i++) {
                many[i].fp[0] = (uint8_t)(i >> 8);
                many[i].fp[1] = (uint8_t)i;
                many[i].mark = 1;
            }
            CHECK(dht2_ctl_encode(many, 3500, NULL, 0, &n) == DHT2_OK &&
                  n == 3500u * 73u, "encoder: 3,500 accepted");
            CHECK(dht2_ctl_encode(many, 3501, NULL, 0, &n) ==
                  DHT2_E_BAD_ENCODING, "encoder: 3,501 refused");
            free(many);
        }
    }
}

/* ══ typed `_id` helpers ═══════════════════════════════════════════════ */

/* SHA3-512 of label ‖ chain ‖ params, assembled here from the decision
 * record's preimage list. */
static void expect_id(uint8_t out[64], const char *label,
                      const uint8_t chain[32], const asm_t *params)
{
    static asm_t pre;

    a_init(&pre);
    a_raw(&pre, label, strlen(label));
    a_raw(&pre, chain, 32);
    a_raw(&pre, params->b, params->n);
    if (pre.err || qgp_sha3_512(pre.b, pre.n, out) != 0) {
        memset(out, 0xEE, 64);
    }
}

static void test_ids(void)
{
    uint8_t chain[32], fp[64], salt[32], gid[32], got[64], want[64];
    asm_t   p;
    size_t  i;

    memset(chain, 0x22, sizeof(chain));
    memset(fp, 0xA5, sizeof(fp));
    for (i = 0; i < 32; i++) {
        salt[i] = (uint8_t)(0x30 + i);
        gid[i] = (uint8_t)(0x60 + i);
    }

    /* dm: "nodus.dht.dm.v1" ‖ chain ‖ recipient fp ‖ salt */
    a_init(&p);
    a_raw(&p, fp, 64);
    a_raw(&p, salt, 32);
    expect_id(want, "nodus.dht.dm.v1", chain, &p);
    CHECK(dht2_id_dm(chain, fp, salt, got) == 0 &&
          memcmp(got, want, 64) == 0, "dm topic preimage");
    salt[31] ^= 1;
    CHECK(dht2_id_dm(chain, fp, salt, got) == 0 &&
          memcmp(got, want, 64) != 0, "the salt changes the topic");
    salt[31] ^= 1;

    /* group head / feed: chain ‖ group id, no version */
    a_init(&p);
    a_raw(&p, gid, 32);
    expect_id(want, "nodus.dht.group.head.v1", chain, &p);
    CHECK(dht2_id_group_head(chain, gid, got) == 0 &&
          memcmp(got, want, 64) == 0, "group head preimage (no version)");
    expect_id(want, "nodus.dht.group.feed.v1", chain, &p);
    CHECK(dht2_id_group_feed(chain, gid, got) == 0 &&
          memcmp(got, want, 64) == 0, "group feed preimage (no version)");

    /* Independent KATs for the three version-independent helpers: the
     * digests were computed OUTSIDE this tree (Python hashlib), with
     *   python3 -c "import hashlib; print(hashlib.sha3_512(
     *       bytes.fromhex('<preimage hex>')).hexdigest())"
     * chain = 0x22 x 32, fp = 0xA5 x 64, salt = 0x30..0x4f, group id =
     * 0x60..0x7f. */
    {
        /* dm: preimage hex (143 B)
         * 6e6f6475732e6468742e646d2e7631 (label) ‖ 22 x 32 ‖ a5 x 64 ‖
         * 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f */
        static const char dm_dig[] =
            "b3e8741d9dc88c2724c24dfafe04edfb4aa8d14912a42c5c270902f0fd49dae0"
            "8203e10d59ef70872cac60e86869e2ebbff91fa43764fd8ed2989a787e044818";
        /* head: preimage hex (87 B)
         * 6e6f6475732e6468742e67726f75702e686561642e7631 (label) ‖ 22 x 32 ‖
         * 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f */
        static const char head_dig[] =
            "8fca0170a0fa82e5c13b3b0637884f3fe4761d9068ecab2297db801542dfbf65"
            "754fbf8c3b3c03ff2a8c092d5e334dd05c1380b46d3ca310ce829eee96fe3062";
        /* feed: preimage hex (87 B)
         * 6e6f6475732e6468742e67726f75702e666565642e7631 (label) ‖ 22 x 32 ‖
         * 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f */
        static const char feed_dig[] =
            "aa0a0a22671ef3bf7d8171851dffd1023c0816c9cd9cf9798693c516bd5b6c7c"
            "07efa322eb836861b571d7f0b591c881c2a085b26f3f95cb9d449b3ef71cddce";
        asm_t *k = &g_m;

        a_init(k);
        a_hex(k, dm_dig);
        CHECK(!k->err && k->n == 64 && dht2_id_dm(chain, fp, salt, got) == 0 &&
              memcmp(got, k->b, 64) == 0, "dm topic KAT (independent digest)");
        a_init(k);
        a_hex(k, head_dig);
        CHECK(!k->err && k->n == 64 &&
              dht2_id_group_head(chain, gid, got) == 0 &&
              memcmp(got, k->b, 64) == 0, "group head KAT (independent digest)");
        a_init(k);
        a_hex(k, feed_dig);
        CHECK(!k->err && k->n == 64 &&
              dht2_id_group_feed(chain, gid, got) == 0 &&
              memcmp(got, k->b, 64) == 0, "group feed KAT (independent digest)");
    }

    /* Independent KATs for group record / keys, version 0x0102030405060708
     * (u64 BE, 8 B — decision id-param-bytes, Amendment); digests computed
     * OUTSIDE this tree with
     *   python3 -c "import hashlib; print(hashlib.sha3_512(
     *       bytes.fromhex('<preimage hex>')).hexdigest())"
     * chain = 0x22 x 32, group id = 0x60..0x7f. */
    {
        /* record: preimage hex (97 B)
         * 6e6f6475732e6468742e67726f75702e7265636f72642e7631 (label) ‖
         * 22 x 32 ‖ 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
         * ‖ 0102030405060708 */
        static const char rec_dig[] =
            "cc9b44e1d58880380cafe885c712274f878ee958ee061b4b9ba028d617e7ef08"
            "e19cf2bef83c0a13093221eb3e6dca9efc69bc8e4e1a46b56872beb383999826";
        /* keys: preimage hex (95 B)
         * 6e6f6475732e6468742e67726f75702e6b6579732e7631 (label) ‖ 22 x 32 ‖
         * 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
         * ‖ 0102030405060708 */
        static const char keys_dig[] =
            "6f784178281a4a20c7ca190e7f6c5c559460053f8fcd1a494716d1ccf547db75"
            "80f355e91391191bb5450b440c7c9cf5910477789f4e11eb275f67388d156089";
        asm_t *k = &g_m;

        a_init(k);
        a_hex(k, rec_dig);
        CHECK(!k->err && k->n == 64 &&
              dht2_id_group_record(chain, gid, 0x0102030405060708ull, got) == 0 &&
              memcmp(got, k->b, 64) == 0,
              "group record KAT (independent digest)");
        a_init(k);
        a_hex(k, keys_dig);
        CHECK(!k->err && k->n == 64 &&
              dht2_id_group_keys(chain, gid, 0x0102030405060708ull, got) == 0 &&
              memcmp(got, k->b, 64) == 0,
              "group keys KAT (independent digest)");
    }

    /* group record / keys: chain ‖ group id ‖ version u64 BE (8 B) */
    a_init(&p);
    a_raw(&p, gid, 32);
    a_hex(&p, "0102030405060708");
    expect_id(want, "nodus.dht.group.record.v1", chain, &p);
    CHECK(dht2_id_group_record(chain, gid, 0x0102030405060708ull, got) == 0 &&
          memcmp(got, want, 64) == 0, "group record preimage, 8-byte version");
    expect_id(want, "nodus.dht.group.keys.v1", chain, &p);
    CHECK(dht2_id_group_keys(chain, gid, 0x0102030405060708ull, got) == 0 &&
          memcmp(got, want, 64) == 0, "group keys preimage, 8-byte version");
    a_init(&p);                       /* a 32-bit value is zero-extended */
    a_raw(&p, gid, 32);
    a_hex(&p, "0000000001020304");
    expect_id(want, "nodus.dht.group.record.v1", chain, &p);
    CHECK(dht2_id_group_record(chain, gid, 0x01020304u, got) == 0 &&
          memcmp(got, want, 64) == 0,
          "group record, v = 0x01020304 zero-extended to 8 bytes");
    a_init(&p);
    a_raw(&p, gid, 32);
    a_hex(&p, "0000000000000000");
    expect_id(want, "nodus.dht.group.record.v1", chain, &p);
    CHECK(dht2_id_group_record(chain, gid, 0, got) == 0 &&
          memcmp(got, want, 64) == 0, "group record, v = 0");
    a_init(&p);
    a_raw(&p, gid, 32);
    a_hex(&p, "ffffffffffffffff");
    expect_id(want, "nodus.dht.group.keys.v1", chain, &p);
    CHECK(dht2_id_group_keys(chain, gid, 0xFFFFFFFFFFFFFFFFull, got) == 0 &&
          memcmp(got, want, 64) == 0, "group keys, v = 2^64-1");
    {
        uint8_t other[64];

        CHECK(dht2_id_group_record(chain, gid, 1, got) == 0 &&
              dht2_id_group_keys(chain, gid, 1, other) == 0 &&
              memcmp(got, other, 64) != 0, "record and keys differ by label");
    }
    CHECK(dht2_id_group_head(chain, NULL, got) != 0 &&
          dht2_id_dm(chain, NULL, salt, got) != 0 &&
          dht2_id_dm(chain, fp, NULL, got) != 0, "NULL parameters refused");
}

/* ══ main ══════════════════════════════════════════════════════════════ */

int main(void)
{
    uint8_t seed[32];

    memset(seed, 0xC3, sizeof(seed));
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "keypair");
        return 1;
    }

    QGP_LOG_INFO(LOG_TAG, "=== DHT v2 wire messages (package 2) ===");
    test_cbor_additions();
    test_requests();
    test_answers();
    test_list();
    test_refusal();
    test_seal_and_sizes();
    test_pull();
    test_want();
    test_ctl();
    test_ids();

    QGP_LOG_INFO(LOG_TAG, "passed %d, failed %d", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
