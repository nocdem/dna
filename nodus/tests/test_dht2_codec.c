/**
 * Nodus — DHT v2 package 1: the record codec (shared/dht2/).
 *
 * Design: docs/plans/2026-10-14-dht-v2-design.md rev 5 (FROZEN) — §3.1,
 * §3.2, §4.2, §13 rows 1, 3, 4, 5, 6, 22, 23. These are the row-22 vectors
 * this package covers.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * If this file failed, one of these would be false:
 *   · the data map of every class (owner record, feed entry, feed head,
 *     inbox entry, inbox control, tombstone) encodes to EXACTLY the bytes
 *     pinned here, key order TTL, _id, _del, Value, _data, _prev, _chain,
 *     _class, Sequence, Validity, ValidityType (dag-cbor/spec.md:58);
 *   · a record built and signed with ctx `nodus.dht.record.v1` parses,
 *     verifies, and its canonical envelope (fields 7, 8, 9 only, row 4)
 *     is the built bytes; an envelope with reordered / repeated / unknown
 *     fields canonicalises to the SAME bytes (§3.1 "Stored form");
 *   · every strict-decode reject of row 22 is refused as `bad-encoding`:
 *     long-form int, long-form length, unsorted keys, duplicate key,
 *     indefinite length (map and string), tag 42, float, trailing byte,
 *     negative int, `_prev` of 63 B, an unknown key — plus the row-6
 *     range edges (Sequence 0, TTL ≠ 0, ValidityType 2, Validity forms);
 *   · every §3.2 / §3.1 identifier is the SHA3-512 of exactly the
 *     preimage the design writes (label ASCII without NUL ‖ chain ‖ params;
 *     feed entry = topic ‖ index BE8 with no label; address = `_id` ‖
 *     owner fp; fp = SHA3-512(raw key)) — checked against hand-assembled
 *     preimages, not against the functions themselves;
 *   · §4.1's first codes come in its order: too-large before decode,
 *     bad-chain before a bad key, bad-address, bad-signature (tampered
 *     signature, data signed under another ctx);
 *   · row 5's matrix and class max refuse what they must (bad-class,
 *     expired, too-long) and accept the edges exactly;
 *   · §4.2: the A/B two-arrival case — two simulated holders, each with
 *     its OWN store, admitting in opposite orders — ends with the same
 *     stored bytes (B's canonical envelope), and every tie-break step
 *     decides in the stated order;
 *   · the strict READER itself refuses every non-shortest integer / length
 *     head (not only the re-encode check behind it); proto3 merge rules
 *     hold (IPNS field 7 last-one-wins incl. a trailing empty one; RFC
 *     0002 field 1 merged — a later empty PublicKey keeps the key);
 *     non-canonical PublicKey bytes collapse to the canonical form; every
 *     prefix of an envelope and of a data map is refused; canonical
 *     refuses a non-4627-byte signature; a set over 256 members is
 *     refused; LIST unsorted / duplicate keys are malformed;
 *   · nearest_R over a fixed set returns the pinned members nearest
 *     first, all members when fewer than R, and refuses a repeated fp;
 *   · the Validity text ↔ seconds conversion matches fixed instants and
 *     round-trips every month boundary of a leap and a non-leap year;
 *   · row 23: an owner-signed LIST request round-trips; a request signed
 *     by another key is `not-owner`; a flipped payload byte is
 *     `bad-signature`; another domain is `bad-signature`; the RFC 0002
 *     signed buffer is EXACTLY uvarint(len)‖domain‖uvarint(len)‖type‖
 *     uvarint(len)‖payload (verified here with an independently built
 *     buffer, RFC/0002-signed-envelopes.md:111-122).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock. ML-DSA-87 keys come from fixed seeds
 * (qgp_dsa87_keypair_derand); signing is HEDGED (randomized), so no
 * signature byte is pinned — signatures are verified, never compared to
 * a constant. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. Heap fixtures are freed; no files, no processes, no state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The pinned data-map bytes are written BY HAND here from the design
 *     text and dag-cbor/spec.md; they are self-consistent with this
 *     codec's author, not an oracle from another implementation. The
 *     design's C ↔ WASM cross-check (§9 test plan) is what will ground
 *     them independently.
 *  2. The Validity instants were computed with GNU `date -u -d … +%s`
 *     (coreutils on this host), one external source; the month-boundary
 *     sweep is a round trip of this codec against itself.
 *  3. The payload-type bytes are the ASCII path whose leading '/' is the
 *     0x2f "path" multicodec (RFC/0002-signed-envelopes.md:50-54, design
 *     §13 row 1); this file checks the first byte is 0x2f and that the
 *     whole string is what DHT2_PT_* says, not another implementation's
 *     output.
 *  4. Nothing here exercises admission order across the holder check,
 *     quota, storage or pull-sync — those are later packages.
 *
 * @file test_dht2_codec.c
 */

#include "dht2/dht2_cbor.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_place.h"
#include "dht2/dht2_record.h"
#include "dht2/dht2_time.h"
#include "dht2/dht2_types.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_pb.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "TEST_DHT2"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do {                                              \
    if (cond) { g_pass++; }                                                \
    else { g_fail++; QGP_LOG_ERROR(LOG_TAG, "FAIL %s:%d: %s",              \
                                   __FILE__, __LINE__, (msg)); }           \
} while (0)

/* ══ fixture ═══════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk_a[DHT2_PUBKEY_LEN];
    uint8_t sk_a[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp_a[DHT2_FP_LEN];
    uint8_t pk_b[DHT2_PUBKEY_LEN];
    uint8_t sk_b[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp_b[DHT2_FP_LEN];
    uint8_t chain[DHT2_CHAIN_LEN];
    uint8_t other_chain[DHT2_CHAIN_LEN];
    uint8_t env[DHT2_ENVELOPE_MAX + 64];
    uint8_t env2[DHT2_ENVELOPE_MAX + 64];
    uint8_t canon[DHT2_ENVELOPE_MAX + 64];
} fixture_t;

/* ══ byte assembler for the pinned vectors ══════════════════════════════ */

typedef struct {
    uint8_t b[1024];
    size_t  n;
    int     err;
} asm_t;

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

/* The data-map keys, as their DAG-CBOR text-string encodings. */
#define H_TTL   "63 54544c"
#define H_ID    "63 5f6964"
#define H_DEL   "64 5f64656c"
#define H_VALUE "65 56616c7565"
#define H_DATA  "65 5f64617461"
#define H_PREV  "65 5f70726576"
#define H_CHAIN "66 5f636861696e"
#define H_CLASS "66 5f636c617373"
#define H_SEQ   "68 53657175656e6365"
#define H_VAL   "68 56616c6964697479"
#define H_VTYPE "6c 56616c696469747954797065"
#define H_FOO   "64 5f666f6f"

#define VTEXT   "2026-10-19T00:00:00Z"
#define VSECS   1792368000ull          /* date -u -d 2026-10-19T00:00:00Z +%s */

/* The class-1 KAT and its one-change variants (row 22 rejects). */
enum {
    V_OK = 0, V_LONG_INT, V_LONG_LEN, V_UNSORTED, V_DUP, V_INDEF_MAP,
    V_INDEF_BSTR, V_TAG42, V_FLOAT, V_TRAILING, V_NEG, V_UNKNOWN, V_SEQ0,
    V_TTL1, V_VT2, V_VALIDITY19, V_VT1_TEXT, V_VT0_EMPTY,
    V_VALUE_NONEMPTY, V_ID63, V_CHAIN31, V_VALIDITY_TSTR, V_MISSING_TTL,
    V_UNDEFINED, V_SEQ_MAX, V_HOUR24, V_COUNT
};

static void kat1(asm_t *a, int v)
{
    a_init(a);
    if (v == V_INDEF_MAP) {
        a_hex(a, "bf");
    } else if (v == V_DUP || v == V_UNKNOWN) {
        a_hex(a, "aa");                       /* 10 entries */
    } else if (v == V_MISSING_TTL) {
        a_hex(a, "a8");
    } else {
        a_hex(a, "a9");                       /* 9 entries */
    }
    if (v != V_MISSING_TTL) {
        a_hex(a, H_TTL);
        a_hex(a, v == V_LONG_INT ? "1800" : v == V_TTL1 ? "01" : "00");
    }
    a_hex(a, H_ID);
    if (v == V_ID63) {
        a_hex(a, "583f");
        a_fill(a, 0x11, 63);
    } else {
        a_hex(a, "5840");
        a_fill(a, 0x11, 64);
    }
    if (v == V_UNKNOWN) {
        a_hex(a, H_FOO "01");
    }
    if (v == V_UNSORTED) {
        a_hex(a, H_DATA "43 010203");
        a_hex(a, H_VALUE "40");
    } else {
        a_hex(a, H_VALUE);
        a_hex(a, v == V_VALUE_NONEMPTY ? "4100" : "40");
        a_hex(a, H_DATA);
        if (v == V_LONG_LEN) {
            a_hex(a, "5803 010203");
        } else if (v == V_INDEF_BSTR) {
            a_hex(a, "5f 43010203 ff");
        } else if (v == V_TAG42) {
            a_hex(a, "d82a 43010203");
        } else {
            a_hex(a, "43 010203");
        }
    }
    a_hex(a, H_CHAIN);
    if (v == V_CHAIN31) {
        a_hex(a, "581f");
        a_fill(a, 0x22, 31);
    } else {
        a_hex(a, "5820");
        a_fill(a, 0x22, 32);
    }
    a_hex(a, H_CLASS);
    a_hex(a, v == V_NEG ? "20" : "01");
    if (v == V_DUP) {
        a_hex(a, H_CLASS "01");
    }
    a_hex(a, H_SEQ);
    if (v == V_FLOAT) {
        a_hex(a, "fb 3ff0000000000000");
    } else if (v == V_SEQ0) {
        a_hex(a, "00");
    } else if (v == V_UNDEFINED) {
        a_hex(a, "f7");
    } else if (v == V_SEQ_MAX) {
        a_hex(a, "1b ffffffffffffffff");
    } else {
        a_hex(a, "01");
    }
    a_hex(a, H_VAL);
    if (v == V_VALIDITY19) {
        a_hex(a, "53");
        a_raw(a, VTEXT, 19);
    } else if (v == V_VT0_EMPTY) {
        a_hex(a, "40");
    } else if (v == V_VALIDITY_TSTR) {
        a_hex(a, "74");
        a_raw(a, VTEXT, 20);
    } else if (v == V_HOUR24) {
        a_hex(a, "54");
        a_raw(a, "2026-10-19T24:00:00Z", 20);
    } else {
        a_hex(a, "54");
        a_raw(a, VTEXT, 20);
    }
    a_hex(a, H_VTYPE);
    a_hex(a, v == V_VT2 ? "02" : v == V_VT1_TEXT ? "01" : "00");
    if (v == V_INDEF_MAP) {
        a_hex(a, "ff");
    }
    if (v == V_TRAILING) {
        a_hex(a, "00");
    }
}

/* A tombstone-shaped map with `_del` = false (row 5: only `true`). */
static void kat_del_false(asm_t *a)
{
    a_init(a);
    a_hex(a, "a9");
    a_hex(a, H_TTL "00");
    a_hex(a, H_ID "5840");
    a_fill(a, 0x11, 64);
    a_hex(a, H_DEL "f4");
    a_hex(a, H_VALUE "40");
    a_hex(a, H_CHAIN "5820");
    a_fill(a, 0x22, 32);
    a_hex(a, H_CLASS "01");
    a_hex(a, H_SEQ "02");
    a_hex(a, H_VAL "54");
    a_raw(a, VTEXT, 20);
    a_hex(a, H_VTYPE "00");
}

static void data_base(dht2_data_t *d, uint64_t cls)
{
    memset(d, 0, sizeof(*d));
    d->sequence = 1;
    d->validity_type = DHT2_VT_EOL;
    d->expiry = VSECS;
    memset(d->id, 0x11, DHT2_ID_LEN);
    memset(d->chain, 0x22, DHT2_CHAIN_LEN);
    d->cls = cls;
}

static int eq(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && (an == 0 || memcmp(a, b, an) == 0);
}

/* ══ 1. strict decode: the pinned class-1 bytes and every reject ════════ */

static void test_strict_decode(void)
{
    static const uint8_t payload[3] = { 1, 2, 3 };
    asm_t       a;
    dht2_data_t d, e;
    uint8_t     out[1024];
    size_t      n = 0;
    int         v;

    kat1(&a, V_OK);
    CHECK(a.err == 0, "assembler");
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.data = payload;
    d.data_len = sizeof(payload);
    CHECK(dht2_data_encode(&d, out, sizeof(out), &n) == DHT2_OK, "encode c1");
    CHECK(eq(out, n, a.b, a.n), "class-1 data bytes = the pinned KAT");
    CHECK(dht2_data_encode(&d, NULL, 0, &n) == DHT2_OK && n == a.n,
          "count mode = written size");
    CHECK(dht2_data_decode(a.b, a.n, &e) == DHT2_OK, "decode KAT");
    CHECK(e.sequence == 1 && e.expiry == VSECS && e.cls == 1 &&
          e.has_data && e.data_len == 3 && !e.del && !e.has_prev,
          "decoded fields");
    CHECK(dht2_data_encode(&d, out, a.n - 1, &n) == DHT2_E_ARG,
          "a buffer one byte short is refused, not truncated");

    for (v = V_LONG_INT; v < V_COUNT; v++) {
        int want = (v == V_SEQ_MAX) ? DHT2_OK : DHT2_E_BAD_ENCODING;

        kat1(&a, v);
        CHECK(a.err == 0, "assembler variant");
        if (dht2_data_decode(a.b, a.n, &e) != want) {
            QGP_LOG_ERROR(LOG_TAG, "variant %d: wrong verdict", v);
            g_fail++;
        } else {
            g_pass++;
        }
    }
    /* Sequence 2^64−1 decodes and re-encodes (row 6 upper edge). */
    kat1(&a, V_SEQ_MAX);
    CHECK(dht2_data_decode(a.b, a.n, &e) == DHT2_OK &&
          e.sequence == UINT64_MAX, "Sequence 2^64-1 accepted");

    kat_del_false(&a);
    CHECK(dht2_data_decode(a.b, a.n, &e) == DHT2_E_BAD_ENCODING,
          "_del = false refused");

    /* The encoder refuses what the canonical form cannot carry. */
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.sequence = 0;
    CHECK(dht2_data_encode(&d, out, sizeof(out), &n) == DHT2_E_BAD_ENCODING,
          "encode Sequence 0");
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.expiry = DHT2_VALIDITY_MAX_SECONDS + 1;
    CHECK(dht2_data_encode(&d, out, sizeof(out), &n) == DHT2_E_BAD_ENCODING,
          "encode expiry past 9999-12-31T23:59:59Z");
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.validity_type = 2;
    CHECK(dht2_data_encode(&d, out, sizeof(out), &n) == DHT2_E_BAD_ENCODING,
          "encode ValidityType 2");
}

/* ══ 2. per-class KATs + signed round trip ══════════════════════════════ */

static int build_parse(fixture_t *fx, const dht2_data_t *d, const uint8_t *sk,
                       const uint8_t *pk, dht2_record_t *rec, size_t *env_len)
{
    if (dht2_record_build(d, sk, pk, fx->env, sizeof(fx->env), env_len)
        != DHT2_OK) {
        return -1;
    }
    return dht2_record_parse(fx->env, *env_len, d->chain, NULL, rec);
}

/* Pins the data bytes (`want`), then signs, parses, verifies, checks the
 * canonical form and the class rules. */
static void kat_class(fixture_t *fx, const char *what, const dht2_data_t *d,
                      const asm_t *want, dht2_record_t *rec)
{
    uint8_t out[1024];
    size_t  n = 0, env_len = 0, cn = 0, sz = 0;

    CHECK(want->err == 0, "assembler");
    CHECK(dht2_data_encode(d, out, sizeof(out), &n) == DHT2_OK &&
          eq(out, n, want->b, want->n), what);
    CHECK(dht2_record_build(d, fx->sk_a, fx->pk_a, NULL, 0, &sz) == DHT2_OK,
          "size-only build");
    CHECK(build_parse(fx, d, fx->sk_a, fx->pk_a, rec, &env_len) == DHT2_OK,
          "build + parse");
    CHECK(sz == env_len, "size-only build = built size");
    CHECK(eq(rec->data, rec->data_len, want->b, want->n),
          "envelope field 9 = the pinned data");
    CHECK(rec->sig_len == DHT2_SIG_LEN, "signature 4627 B");
    CHECK(memcmp(rec->fp, fx->fp_a, DHT2_FP_LEN) == 0, "fp = SHA3-512(pk)");
    CHECK(dht2_record_verify(rec) == DHT2_OK, "signature verifies");
    CHECK(dht2_record_check_class(rec) == DHT2_OK, "class rules pass");
    CHECK(dht2_record_canonical(rec, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_OK && eq(fx->canon, cn, fx->env, env_len),
          "built envelope is already canonical");
}

static void test_class_kats(fixture_t *fx)
{
    static const uint8_t p1[1] = { 0xAB };
    static const uint8_t idx[8] = { 0, 0, 0, 0, 0, 0, 0, 5 };
    uint8_t        ctl_id[DHT2_ID_LEN], ctl_data[73], addr[DHT2_HASH_LEN];
    asm_t          a;
    dht2_data_t    d;
    dht2_record_t *rec = (dht2_record_t *)malloc(sizeof(*rec));

    if (rec == NULL) {
        CHECK(0, "malloc");
        return;
    }

    /* Class 1, owner record (data 01 02 03) — same bytes as kat1(V_OK). */
    {
        static const uint8_t p3[3] = { 1, 2, 3 };

        data_base(&d, DHT2_CLASS_OWNER);
        d.has_data = true;
        d.data = p3;
        d.data_len = 3;
        kat1(&a, V_OK);
        kat_class(fx, "class 1 data bytes", &d, &a, rec);
        CHECK(dht2_address(d.id, fx->fp_a, addr) == 0 &&
              memcmp(addr, rec->address, DHT2_HASH_LEN) == 0,
              "address = SHA3-512(_id || owner fp)");
    }

    /* Class 2, first feed entry: `_prev` present and EMPTY (row 3). */
    data_base(&d, DHT2_CLASS_FEED_ENTRY);
    d.has_data = true;
    d.data = p1;
    d.data_len = 1;
    d.has_prev = true;
    d.prev = NULL;
    d.prev_len = 0;
    a_init(&a);
    a_hex(&a, "aa");
    a_hex(&a, H_TTL "00");
    a_hex(&a, H_ID "5840");
    a_fill(&a, 0x11, 64);
    a_hex(&a, H_VALUE "40");
    a_hex(&a, H_DATA "41 ab");
    a_hex(&a, H_PREV "40");
    a_hex(&a, H_CHAIN "5820");
    a_fill(&a, 0x22, 32);
    a_hex(&a, H_CLASS "02");
    a_hex(&a, H_SEQ "01");
    a_hex(&a, H_VAL "54");
    a_raw(&a, VTEXT, 20);
    a_hex(&a, H_VTYPE "00");
    kat_class(fx, "class 2 data bytes (first entry)", &d, &a, rec);

    /* Class 2 with a 64-byte `_prev`, and the 63-byte reject (row 22). */
    {
        static uint8_t prev[64];
        dht2_data_t    e;

        memset(prev, 0x33, sizeof(prev));
        d.prev = prev;
        d.prev_len = 64;
        a_init(&a);
        a_hex(&a, "aa");
        a_hex(&a, H_TTL "00");
        a_hex(&a, H_ID "5840");
        a_fill(&a, 0x11, 64);
        a_hex(&a, H_VALUE "40");
        a_hex(&a, H_DATA "41 ab");
        a_hex(&a, H_PREV "5840");
        a_fill(&a, 0x33, 64);
        a_hex(&a, H_CHAIN "5820");
        a_fill(&a, 0x22, 32);
        a_hex(&a, H_CLASS "02");
        a_hex(&a, H_SEQ "01");
        a_hex(&a, H_VAL "54");
        a_raw(&a, VTEXT, 20);
        a_hex(&a, H_VTYPE "00");
        kat_class(fx, "class 2 data bytes (_prev 64 B)", &d, &a, rec);

        a_init(&a);
        a_hex(&a, "aa");
        a_hex(&a, H_TTL "00");
        a_hex(&a, H_ID "5840");
        a_fill(&a, 0x11, 64);
        a_hex(&a, H_VALUE "40");
        a_hex(&a, H_DATA "41 ab");
        a_hex(&a, H_PREV "583f");
        a_fill(&a, 0x33, 63);
        a_hex(&a, H_CHAIN "5820");
        a_fill(&a, 0x22, 32);
        a_hex(&a, H_CLASS "02");
        a_hex(&a, H_SEQ "01");
        a_hex(&a, H_VAL "54");
        a_raw(&a, VTEXT, 20);
        a_hex(&a, H_VTYPE "00");
        CHECK(dht2_data_decode(a.b, a.n, &e) == DHT2_E_BAD_ENCODING,
              "_prev of 63 B refused (row 22)");
    }

    /* Class 3, feed head: `_data` = latest index 8 B BE (here 5). */
    data_base(&d, DHT2_CLASS_FEED_HEAD);
    d.has_data = true;
    d.data = idx;
    d.data_len = 8;
    a_init(&a);
    a_hex(&a, "a9");
    a_hex(&a, H_TTL "00");
    a_hex(&a, H_ID "5840");
    a_fill(&a, 0x11, 64);
    a_hex(&a, H_VALUE "40");
    a_hex(&a, H_DATA "48 0000000000000005");
    a_hex(&a, H_CHAIN "5820");
    a_fill(&a, 0x22, 32);
    a_hex(&a, H_CLASS "03");
    a_hex(&a, H_SEQ "01");
    a_hex(&a, H_VAL "54");
    a_raw(&a, VTEXT, 20);
    a_hex(&a, H_VTYPE "00");
    kat_class(fx, "class 3 data bytes", &d, &a, rec);

    /* Class 4, inbox entry (`_id` = the inbox id; a pattern here). */
    data_base(&d, DHT2_CLASS_INBOX_ENTRY);
    d.has_data = true;
    d.data = p1;
    d.data_len = 1;
    d.sequence = 300;                         /* 19 012c: a 2-byte uint */
    a_init(&a);
    a_hex(&a, "a9");
    a_hex(&a, H_TTL "00");
    a_hex(&a, H_ID "5840");
    a_fill(&a, 0x11, 64);
    a_hex(&a, H_VALUE "40");
    a_hex(&a, H_DATA "41 ab");
    a_hex(&a, H_CHAIN "5820");
    a_fill(&a, 0x22, 32);
    a_hex(&a, H_CLASS "04");
    a_hex(&a, H_SEQ "19 012c");
    a_hex(&a, H_VAL "54");
    a_raw(&a, VTEXT, 20);
    a_hex(&a, H_VTYPE "00");
    kat_class(fx, "class 4 data bytes", &d, &a, rec);
    {
        uint8_t pk_key[DHT2_HASH_LEN];

        CHECK(dht2_record_placement_key(rec, pk_key) == DHT2_OK &&
              memcmp(pk_key, d.id, DHT2_ID_LEN) == 0,
              "class 4 placement key = the inbox id (_id)");
    }

    /* Class 5, inbox control, no expiry (ValidityType 1, Validity empty).
     * `_id` must be ctl(chain, signer fp) — computed, then pinned in
     * place; `_data` = one HANDLED entry, through = 7. */
    CHECK(dht2_id_inbox_ctl(d.chain, fx->fp_a, ctl_id) == 0, "ctl id");
    memset(ctl_data, 0x44, 64);
    ctl_data[64] = 1;
    memset(ctl_data + 65, 0, 7);
    ctl_data[72] = 7;
    data_base(&d, DHT2_CLASS_INBOX_CTL);
    memcpy(d.id, ctl_id, DHT2_ID_LEN);
    d.validity_type = DHT2_VT_NONE;
    d.expiry = 0;
    d.has_data = true;
    d.data = ctl_data;
    d.data_len = sizeof(ctl_data);
    a_init(&a);
    a_hex(&a, "a9");
    a_hex(&a, H_TTL "00");
    a_hex(&a, H_ID "5840");
    a_raw(&a, ctl_id, 64);
    a_hex(&a, H_VALUE "40");
    a_hex(&a, H_DATA "5849");
    a_fill(&a, 0x44, 64);
    a_hex(&a, "01 0000000000000007");
    a_hex(&a, H_CHAIN "5820");
    a_fill(&a, 0x22, 32);
    a_hex(&a, H_CLASS "05");
    a_hex(&a, H_SEQ "01");
    a_hex(&a, H_VAL "40");
    a_hex(&a, H_VTYPE "01");
    kat_class(fx, "class 5 data bytes", &d, &a, rec);
    {
        uint8_t pk_key[DHT2_HASH_LEN], inbox[DHT2_ID_LEN];

        CHECK(dht2_id_inbox(d.chain, fx->fp_a, inbox) == 0 &&
              dht2_record_placement_key(rec, pk_key) == DHT2_OK &&
              memcmp(pk_key, inbox, DHT2_ID_LEN) == 0,
              "class 5 placement key = the signer's inbox id");
    }

    /* Tombstone of a class-1 record: `_del` true, no `_data`. */
    data_base(&d, DHT2_CLASS_OWNER);
    d.del = true;
    d.sequence = 2;
    a_init(&a);
    a_hex(&a, "a9");
    a_hex(&a, H_TTL "00");
    a_hex(&a, H_ID "5840");
    a_fill(&a, 0x11, 64);
    a_hex(&a, H_DEL "f5");
    a_hex(&a, H_VALUE "40");
    a_hex(&a, H_CHAIN "5820");
    a_fill(&a, 0x22, 32);
    a_hex(&a, H_CLASS "01");
    a_hex(&a, H_SEQ "02");
    a_hex(&a, H_VAL "54");
    a_raw(&a, VTEXT, 20);
    a_hex(&a, H_VTYPE "00");
    kat_class(fx, "tombstone data bytes", &d, &a, rec);

    free(rec);
}

/* ══ 2b. §3.2 / §3.1 preimages, assembled by hand ═══════════════════════
 * Each identifier is recomputed here from its preimage bytes written out
 * literally (label ASCII with no NUL ‖ chain ‖ params; topic ‖ index BE8
 * with NO label or chain; `_id` ‖ owner fp; the raw 2592-byte key), hashed
 * with qgp_sha3_512 directly, and compared with the dht2 function. */

static void test_preimages(fixture_t *fx)
{
    static const uint8_t salt[5] = { 's', 'a', 'l', 't', '!' };
    uint8_t  topic[DHT2_HASH_LEN], want[DHT2_HASH_LEN], got[DHT2_HASH_LEN];
    uint8_t  id[DHT2_ID_LEN], fpb[DHT2_FP_LEN];
    uint8_t *pre = (uint8_t *)malloc(DHT2_PUBKEY_LEN);
    asm_t    a;

    if (pre == NULL) {
        CHECK(0, "malloc");
        return;
    }
    memset(topic, 0x77, sizeof(topic));
    memset(id, 0x11, sizeof(id));

    /* owner fp = SHA3-512(raw key) */
    memcpy(pre, fx->pk_b, DHT2_PUBKEY_LEN);
    CHECK(qgp_sha3_512(pre, DHT2_PUBKEY_LEN, want) == 0 &&
          dht2_fp(fx->pk_b, fpb) == 0 && memcmp(want, fpb, 64) == 0,
          "fp preimage = the raw 2592-byte key");

    /* address = SHA3-512(_id ‖ owner fp) */
    a_init(&a);
    a_fill(&a, 0x11, 64);
    a_raw(&a, fpb, 64);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_address(id, fpb, got) == 0 && memcmp(want, got, 64) == 0,
          "address preimage = _id || owner fp");

    /* profile: label ‖ chain, no params */
    a_init(&a);
    a_raw(&a, "nodus.dht.profile.v1", 20);
    a_raw(&a, fx->chain, 32);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id(DHT2_LABEL_PROFILE, fx->chain, NULL, 0, got) == 0 &&
          memcmp(want, got, 64) == 0, "profile _id preimage");

    /* contact list */
    a_init(&a);
    a_raw(&a, "nodus.dht.contactlist.v1", 24);
    a_raw(&a, fx->chain, 32);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id(DHT2_LABEL_CONTACTLIST, fx->chain, NULL, 0, got) == 0 &&
          memcmp(want, got, 64) == 0, "contact list _id preimage");

    /* 1:1 topic: label ‖ chain ‖ recipient fp ‖ salt (salt as given) */
    a_init(&a);
    a_raw(&a, "nodus.dht.dm.v1", 15);
    a_raw(&a, fx->chain, 32);
    a_raw(&a, fpb, 64);
    a_raw(&a, salt, sizeof(salt));
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0, "dm want");
    {
        uint8_t params[64 + sizeof(salt)];

        memcpy(params, fpb, 64);
        memcpy(params + 64, salt, sizeof(salt));
        CHECK(dht2_id(DHT2_LABEL_DM, fx->chain, params, sizeof(params),
                      got) == 0 && memcmp(want, got, 64) == 0,
              "dm topic preimage");
    }

    /* feed entry: topic ‖ index 8 B BE — no label, no chain */
    a_init(&a);
    a_raw(&a, topic, 64);
    a_hex(&a, "00 00 00 00 00 00 01 05");
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id_feed_entry(topic, 0x105u, got) == 0 &&
          memcmp(want, got, 64) == 0, "feed entry _id = H(topic || BE8)");

    /* feed head: "nodus.dht.head.v1" ‖ chain ‖ topic (§3.2 resolved form) */
    a_init(&a);
    a_raw(&a, "nodus.dht.head.v1", 17);
    a_raw(&a, fx->chain, 32);
    a_raw(&a, topic, 64);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id_feed_head(fx->chain, topic, got) == 0 &&
          memcmp(want, got, 64) == 0, "feed head _id preimage");

    /* inbox id */
    a_init(&a);
    a_raw(&a, "nodus.dht.inbox.v1", 18);
    a_raw(&a, fx->chain, 32);
    a_raw(&a, fpb, 64);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id_inbox(fx->chain, fpb, got) == 0 &&
          memcmp(want, got, 64) == 0, "inbox id preimage");

    /* inbox control */
    a_init(&a);
    a_raw(&a, "nodus.dht.inbox.ctl.v1", 22);
    a_raw(&a, fx->chain, 32);
    a_raw(&a, fpb, 64);
    CHECK(a.err == 0 && qgp_sha3_512(a.b, a.n, want) == 0 &&
          dht2_id_inbox_ctl(fx->chain, fpb, got) == 0 &&
          memcmp(want, got, 64) == 0, "inbox control _id preimage");

    free(pre);
}

/* ══ 3. envelope: canonical form, §4.1 code order ═══════════════════════ */

/* tag ‖ uvarint(n) ‖ bytes — a test-local proto writer for hand-made
 * non-canonical envelopes. */
static size_t pb_ld(uint8_t *out, size_t off, uint32_t field,
                    const uint8_t *p, size_t n)
{
    size_t o = off;

    cmt_pb_put_uvarint(out, SIZE_MAX, &o, ((uint64_t)field << 3) | 2u);
    cmt_pb_put_uvarint(out, SIZE_MAX, &o, (uint64_t)n);
    memcpy(out + o, p, n);
    return o + n;
}

static void test_envelope(fixture_t *fx)
{
    static const uint8_t p3[3] = { 1, 2, 3 };
    static const uint8_t junk[3] = { 0xa0, 0x00, 0x00 };
    dht2_data_t    d;
    dht2_record_t *r1 = (dht2_record_t *)malloc(sizeof(*r1));
    dht2_record_t *r2 = (dht2_record_t *)malloc(sizeof(*r2));
    uint8_t        pkm[3 + DHT2_PUBKEY_LEN];
    uint8_t        sig[DHT2_SIG_LEN], badaddr[DHT2_HASH_LEN];
    cmt_pb_public_key_t pkv;
    size_t         env_len = 0, pkm_len = 0, off, cn = 0, siglen = 0;

    if (r1 == NULL || r2 == NULL) {
        CHECK(0, "malloc");
        free(r1);
        free(r2);
        return;
    }
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.data = p3;
    d.data_len = 3;
    CHECK(build_parse(fx, &d, fx->sk_a, fx->pk_a, r1, &env_len) == DHT2_OK,
          "build + parse");

    /* Reordered fields (9, 8, 7), IPNS V1 field 5 (unknown to us), a junk
     * field 9 BEFORE the real one (last-one-wins) and a repeated field 8:
     * canonicalises to the built bytes (§3.1 "Stored form", row 4). */
    pkv.present = true;
    memcpy(pkv.key, fx->pk_a, DHT2_PUBKEY_LEN);
    CHECK(cmt_pb_public_key_marshal(&pkv, pkm, sizeof(pkm), &pkm_len)
          == CMT_OK && pkm_len == sizeof(pkm), "PublicKey marshal 2595 B");
    off = 0;
    fx->env2[off++] = 0x28;                   /* field 5 varint: sequence */
    fx->env2[off++] = 0x07;
    off = pb_ld(fx->env2, off, 9, junk, sizeof(junk));
    off = pb_ld(fx->env2, off, 8, junk, sizeof(junk));
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 7, pkm, pkm_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, r1->address, r2)
          == DHT2_OK, "non-canonical envelope parses");
    CHECK(dht2_record_verify(r2) == DHT2_OK, "and verifies");
    CHECK(dht2_record_canonical(r2, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_OK && eq(fx->canon, cn, fx->env, env_len),
          "canonical(non-canonical) = canonical(built)");
    CHECK(dht2_record_compare(r1, r2) == 0, "same version");

    /* too-large: checked before any decode (garbage of 262,145 B). */
    memset(fx->env2, 0xff, DHT2_ENVELOPE_MAX + 1);
    CHECK(dht2_record_parse(fx->env2, DHT2_ENVELOPE_MAX + 1, d.chain, NULL,
                            r2) == DHT2_E_TOO_LARGE, "too-large first");
    CHECK(dht2_record_parse(fx->env2, DHT2_ENVELOPE_MAX, d.chain, NULL,
                            r2) == DHT2_E_BAD_ENCODING,
          "262,144 B of garbage is bad-encoding, not too-large");

    /* bad-chain */
    CHECK(dht2_record_parse(fx->env, env_len, fx->other_chain, NULL, r2)
          == DHT2_E_BAD_CHAIN, "bad-chain");
    /* precedence: no pubKey AND wrong chain → bad-chain (chain first). */
    off = pb_ld(fx->env2, 0, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, fx->other_chain, NULL, r2)
          == DHT2_E_BAD_CHAIN, "bad-chain precedes a missing key");
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2)
          == DHT2_E_BAD_ENCODING, "missing pubKey = bad-encoding");
    /* a 2591-byte key branch is refused (cmt_pb K-2 size rule). */
    {
        uint8_t shortpk[3 + DHT2_PUBKEY_LEN];

        memcpy(shortpk, pkm, pkm_len);
        shortpk[1] = 0x9f;                    /* uvarint 2591 = 9f 14 */
        off = pb_ld(fx->env2, 0, 7, shortpk, pkm_len - 1);
        off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
        off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
        CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2)
              == DHT2_E_BAD_ENCODING, "short key refused");
    }
    /* field 9 with the wrong wire type */
    fx->env2[0] = 0x48;                       /* field 9, varint */
    fx->env2[1] = 0x01;
    CHECK(dht2_record_parse(fx->env2, 2, d.chain, NULL, r2)
          == DHT2_E_BAD_ENCODING, "wrong wire type");

    /* bad-address */
    memcpy(badaddr, r1->address, DHT2_HASH_LEN);
    badaddr[0] ^= 1;
    CHECK(dht2_record_parse(fx->env, env_len, d.chain, badaddr, r2)
          == DHT2_E_BAD_ADDRESS, "bad-address");

    /* bad-signature: a flipped signature byte */
    memcpy(fx->env2, fx->env, env_len);
    fx->env2[(size_t)(r1->sig - fx->env) + 100] ^= 0x01;
    CHECK(dht2_record_parse(fx->env2, env_len, d.chain, NULL, r2) == DHT2_OK &&
          dht2_record_verify(r2) == DHT2_E_BAD_SIGNATURE,
          "tampered signature");
    /* bad-signature: signed with the IPNS prefix rule's ctx-less form */
    CHECK(qgp_dsa87_sign(sig, &siglen, r1->data, r1->data_len, fx->sk_a) == 0,
          "ctx-less sign");
    off = pb_ld(fx->env2, 0, 7, pkm, pkm_len);
    off = pb_ld(fx->env2, off, 8, sig, siglen);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          dht2_record_verify(r2) == DHT2_E_BAD_SIGNATURE,
          "a signature without ctx nodus.dht.record.v1 is refused");
    /* bad-signature: another key's signature */
    CHECK(qgp_dsa87_sign_ctx(sig, &siglen, r1->data, r1->data_len,
                             (const uint8_t *)DHT2_CTX_RECORD,
                             strlen(DHT2_CTX_RECORD), fx->sk_b) == 0,
          "sign with B");
    off = pb_ld(fx->env2, 0, 7, pkm, pkm_len);
    off = pb_ld(fx->env2, off, 8, sig, siglen);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          dht2_record_verify(r2) == DHT2_E_BAD_SIGNATURE,
          "a signature by another key is refused");

    free(r1);
    free(r2);
}

/* ══ 4. row 5 matrix and class max ══════════════════════════════════════ */

static int class_of(fixture_t *fx, const dht2_data_t *d)
{
    dht2_record_t *rec = (dht2_record_t *)malloc(sizeof(*rec));
    size_t         env_len = 0;
    int            rc;

    if (rec == NULL) {
        return -100;
    }
    rc = build_parse(fx, d, fx->sk_a, fx->pk_a, rec, &env_len);
    if (rc == DHT2_OK) {
        rc = dht2_record_check_class(rec);
    } else {
        rc = -100 - rc;
    }
    free(rec);
    return rc;
}

static void test_matrix(fixture_t *fx)
{
    static const uint8_t p1[1] = { 0xAB };
    static uint8_t prev[64];
    uint8_t        ctl[2 * 73];
    dht2_data_t    d;

    memset(prev, 0x33, sizeof(prev));

    data_base(&d, 0);
    d.has_data = true; d.data = p1; d.data_len = 1;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 0");
    d.cls = 6;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 6");
    d.cls = UINT64_MAX;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 2^64-1");

    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true; d.data = p1; d.data_len = 1;
    d.has_prev = true; d.prev = prev; d.prev_len = 64;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 1 with _prev");

    data_base(&d, DHT2_CLASS_FEED_ENTRY);
    d.has_data = true; d.data = p1; d.data_len = 1;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 2 without _prev");

    data_base(&d, DHT2_CLASS_OWNER);
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "class 1 without _data");

    data_base(&d, DHT2_CLASS_OWNER);
    d.del = true; d.has_data = true; d.data = p1; d.data_len = 1;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "tombstone with _data");

    data_base(&d, DHT2_CLASS_FEED_ENTRY);
    d.del = true; d.has_prev = true; d.prev = prev; d.prev_len = 64;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "tombstone with _prev");

    data_base(&d, DHT2_CLASS_FEED_ENTRY);
    d.del = true;
    CHECK(class_of(fx, &d) == DHT2_OK, "class-2 tombstone (no _prev)");

    data_base(&d, DHT2_CLASS_FEED_HEAD);
    d.has_data = true; d.data = prev; d.data_len = 7;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "feed head _data 7 B");

    /* class 5: `_id` not the signer's control id */
    data_base(&d, DHT2_CLASS_INBOX_CTL);
    d.has_data = true; d.data = NULL; d.data_len = 0;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "ctl _id of someone else");
    CHECK(dht2_id_inbox_ctl(d.chain, fx->fp_a, d.id) == 0, "ctl id");
    CHECK(class_of(fx, &d) == DHT2_OK, "ctl with an empty list");
    /* row 15 shape */
    memset(ctl, 0, sizeof(ctl));
    memset(ctl, 0x10, 64);  ctl[64] = 1;
    memset(ctl + 73, 0x20, 64);  ctl[73 + 64] = 2;
    d.data = ctl; d.data_len = sizeof(ctl);
    CHECK(class_of(fx, &d) == DHT2_OK, "ctl two ascending entries");
    d.data_len = sizeof(ctl) - 1;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "ctl length not 73·k");
    d.data_len = sizeof(ctl);
    ctl[73 + 64] = 3;
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "ctl mark 3");
    ctl[73 + 64] = 2;
    memset(ctl + 73, 0x10, 64);
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "ctl repeated fp");
    memset(ctl + 73, 0x05, 64);
    CHECK(class_of(fx, &d) == DHT2_E_BAD_CLASS, "ctl descending fps");
}

/* check_expiry needs no signature: a struct is enough. */
static int expiry_of(uint64_t cls, uint64_t vt, uint64_t expiry,
                     uint64_t now, bool named)
{
    dht2_record_t rec;

    memset(&rec, 0, sizeof(rec));
    rec.d.cls = cls;
    rec.d.validity_type = vt;
    rec.d.expiry = expiry;
    return dht2_record_check_expiry(&rec, now, named);
}

static void test_class_max(void)
{
    const uint64_t now = VSECS;
    const uint64_t s7 = DHT2_SEC_7D, s24 = DHT2_SEC_24H, s3 = DHT2_SEC_SLACK_3H;
    uint64_t       c;

    /* no expiry: only classes 1, 3, 5 with a name */
    for (c = 1; c <= 5; c++) {
        bool perm = (c == 1 || c == 3 || c == 5);

        CHECK(expiry_of(c, 1, 0, now, true) ==
              (perm ? DHT2_OK : DHT2_E_TOO_LONG), "VT1 named");
        CHECK(expiry_of(c, 1, 0, now, false) == DHT2_E_TOO_LONG,
              "VT1 unnamed is too-long");
        /* lower bound: design §4.1 "expiry > holder chain time". NAMED:
         * boxo validation.go:73 (`time.Now().After(eol)`) still accepts
         * eol == now; ours is one second stricter. */
        CHECK(expiry_of(c, 0, now, now, true) == DHT2_E_EXPIRED,
              "expiry == now is expired");
        CHECK(expiry_of(c, 0, now - 1, now, false) == DHT2_E_EXPIRED,
              "expiry < now is expired");
        CHECK(expiry_of(c, 0, now + 1, now, false) == DHT2_OK,
              "expiry now+1 accepted");
    }
    /* class max + 3 h, inclusive */
    CHECK(expiry_of(1, 0, now + s7 + s3, now, false) == DHT2_OK, "c1 7d+3h");
    CHECK(expiry_of(1, 0, now + s7 + s3 + 1, now, false) == DHT2_E_TOO_LONG,
          "c1 7d+3h+1");
    CHECK(expiry_of(1, 0, DHT2_VALIDITY_MAX_SECONDS, now, true) == DHT2_OK,
          "c1 named: any future EOL");
    CHECK(expiry_of(2, 0, now + s7 + s3, now, true) == DHT2_OK, "c2 7d+3h");
    CHECK(expiry_of(2, 0, now + s7 + s3 + 1, now, true) == DHT2_E_TOO_LONG,
          "c2 named still 7d");
    CHECK(expiry_of(4, 0, now + s24 + s3, now, false) == DHT2_OK, "c4 24h+3h");
    CHECK(expiry_of(4, 0, now + s24 + s3 + 1, now, false) == DHT2_E_TOO_LONG,
          "c4 unnamed 24h+3h+1");
    CHECK(expiry_of(4, 0, now + s7 + s3, now, true) == DHT2_OK, "c4 named 7d");
    CHECK(expiry_of(4, 0, now + s7 + s3 + 1, now, true) == DHT2_E_TOO_LONG,
          "c4 named 7d+3h+1");
    CHECK(expiry_of(3, 0, now + s7 + s3 + 1, now, false) == DHT2_E_TOO_LONG,
          "c3 unnamed 7d");
    CHECK(expiry_of(5, 0, now + s7 + s3 + 1, now, false) == DHT2_E_TOO_LONG,
          "c5 unnamed 7d");
}

/* ══ 5. Validity text ↔ seconds ═════════════════════════════════════════ */

static void test_validity(void)
{
    static const struct { const char *t; uint64_t s; } ok[] = {
        /* seconds: GNU date -u -d <t> +%s */
        { "1970-01-01T00:00:00Z", 0ull },
        { "1972-02-29T23:59:59Z", 68255999ull },
        { "2000-02-29T12:34:56Z", 951827696ull },
        { "2024-12-31T23:59:59Z", 1735689599ull },
        { "2026-10-19T00:00:00Z", 1792368000ull },
        { "2100-03-01T00:00:00Z", 4107542400ull },
        { "9999-12-31T23:59:59Z", 253402300799ull },
    };
    static const char *bad[] = {
        "1969-12-31T23:59:59Z",   /* before 1970 */
        "2026-10-19T24:00:00Z",   /* hour 24 */
        "2026-10-19T23:60:00Z",   /* minute 60 */
        "2026-10-19T23:59:60Z",   /* no leap second */
        "2100-02-29T00:00:00Z",   /* 2100 is not a leap year */
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-10-00T00:00:00Z",
        "2026-10-19t00:00:00Z",   /* lowercase t */
        "2026-10-19T00:00:00z",   /* lowercase z */
        "2026-10-19 00:00:00Z",
        "2026-10-19T00:00:0aZ",
        "+026-10-19T00:00:00Z",
    };
    static const char *badlen[] = {
        "2026-10-19T00:00:00",              /* 19 B */
        "2026-10-19T00:00:00.5Z",           /* fraction */
        "2026-10-19T00:00:00+00:00",        /* offset */
        "2026-10-19T00:00:00ZZ",            /* 21 B */
    };
    uint8_t  txt[20];
    uint64_t s, y;
    size_t   k;

    for (k = 0; k < sizeof(ok) / sizeof(ok[0]); k++) {
        CHECK(dht2_validity_parse((const uint8_t *)ok[k].t, 20, &s) == 0 &&
              s == ok[k].s, ok[k].t);
        CHECK(dht2_validity_format(ok[k].s, txt) == 0 &&
              memcmp(txt, ok[k].t, 20) == 0, "format matches");
    }
    for (k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
        CHECK(dht2_validity_parse((const uint8_t *)bad[k], 20, &s) != 0,
              bad[k]);
    }
    for (k = 0; k < sizeof(badlen) / sizeof(badlen[0]); k++) {
        CHECK(dht2_validity_parse((const uint8_t *)badlen[k],
                                  strlen(badlen[k]), &s) != 0, badlen[k]);
    }
    CHECK(dht2_validity_format(DHT2_VALIDITY_MAX_SECONDS + 1, txt) != 0,
          "format refuses year 10000");

    /* round trip: the first and last second of every month, 2024 (leap)
     * and 2025 */
    for (y = 2024; y <= 2025; y++) {
        uint64_t m;

        for (m = 1; m <= 12; m++) {
            char     t[21];
            uint64_t s0, s1;
            uint8_t  back[20];

            t[0] = (char)('0' + (y / 1000) % 10);
            t[1] = (char)('0' + (y / 100) % 10);
            t[2] = (char)('0' + (y / 10) % 10);
            t[3] = (char)('0' + y % 10);
            memcpy(t + 4, "-00-01T00:00:00Z", 17);
            t[5] = (char)('0' + m / 10);
            t[6] = (char)('0' + m % 10);
            CHECK(dht2_validity_parse((const uint8_t *)t, 20, &s0) == 0,
                  "month start parses");
            CHECK(dht2_validity_format(s0, back) == 0 &&
                  memcmp(back, t, 20) == 0, "month start round trip");
            CHECK(dht2_validity_format(s0 - 1, back) == 0 &&
                  dht2_validity_parse(back, 20, &s1) == 0 && s1 == s0 - 1 &&
                  memcmp(back + 11, "23:59:59Z", 9) == 0,
                  "previous second is 23:59:59 of the month before");
        }
    }
}

/* ══ 6. §4.2 order of versions ══════════════════════════════════════════ */

static void synth(dht2_record_t *r, uint64_t seq, uint64_t vt, uint64_t exp,
                  const uint8_t *data, size_t dlen, const uint8_t *sig,
                  size_t slen)
{
    memset(r, 0, sizeof(*r));
    r->d.sequence = seq;
    r->d.validity_type = vt;
    r->d.expiry = exp;
    r->data = data;
    r->data_len = dlen;
    r->sig = sig;
    r->sig_len = slen;
}

/* A simulated holder with its OWN store: it keeps the canonical bytes of
 * the winner of the held version and the incoming one (Validate → Select
 * → store; kad-dht value_store.go:131-150). Nothing it holds points into
 * the arriving buffer. */
typedef struct {
    uint8_t      *buf;          /* DHT2_ENVELOPE_MAX bytes */
    size_t        len;
    bool          has;
    dht2_record_t rec;          /* parsed from buf */
} holder_t;

static int holder_admit(holder_t *h, const uint8_t *in, size_t len,
                        const uint8_t *chain)
{
    dht2_record_t *tmp = (dht2_record_t *)malloc(sizeof(*tmp));
    size_t         n = 0;
    int            rc = -1;

    if (tmp == NULL) {
        return -1;
    }
    if (dht2_record_parse(in, len, chain, NULL, tmp) != DHT2_OK ||
        dht2_record_verify(tmp) != DHT2_OK) {
        goto out;
    }
    if (!h->has || dht2_record_compare(tmp, &h->rec) > 0) {
        if (dht2_record_canonical(tmp, h->buf, DHT2_ENVELOPE_MAX, &n)
            != DHT2_OK ||
            dht2_record_parse(h->buf, n, chain, NULL, &h->rec) != DHT2_OK) {
            goto out;
        }
        h->len = n;
        h->has = true;
    }
    rc = 0;
out:
    free(tmp);
    return rc;
}

static void test_order(fixture_t *fx)
{
    static const uint8_t pa[1] = { 0x01 }, pb[1] = { 0x02 };
    static const uint8_t da[2] = { 0x10, 0x00 }, db[2] = { 0x10, 0x01 };
    static const uint8_t dshort[1] = { 0x10 };
    static const uint8_t sa[3] = { 1, 2, 3 }, sb[3] = { 1, 2, 4 };
    dht2_record_t *A = (dht2_record_t *)malloc(sizeof(*A));
    dht2_record_t *B = (dht2_record_t *)malloc(sizeof(*B));
    dht2_record_t  x, y;
    dht2_data_t    d;
    size_t         env_len = 0, env2_len = 0, ca = 0, cb = 0;
    holder_t      *h1, *h2;

    if (A == NULL || B == NULL) {
        CHECK(0, "malloc");
        free(A);
        free(B);
        return;
    }

    /* The A/B two-arrival case (§4.2 "Why 3C is gone"): A = seq s with a
     * LATER expiry, B = seq s+1 with an EARLIER expiry. Real signed
     * records, one owner, one address. */
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true; d.data = pa; d.data_len = 1;
    d.sequence = 5;
    d.expiry = VSECS + 2 * 86400;
    CHECK(build_parse(fx, &d, fx->sk_a, fx->pk_a, A, &env_len) == DHT2_OK,
          "A");
    memcpy(fx->env2, fx->env, env_len);
    CHECK(dht2_record_parse(fx->env2, env_len, d.chain, NULL, A) == DHT2_OK,
          "A re-parsed from its own buffer");
    d.data = pb;
    d.sequence = 6;
    d.expiry = VSECS + 86400;
    CHECK(build_parse(fx, &d, fx->sk_a, fx->pk_a, B, &env2_len) == DHT2_OK,
          "B");
    CHECK(memcmp(A->address, B->address, DHT2_HASH_LEN) == 0, "same address");
    CHECK(dht2_record_compare(B, A) > 0 && dht2_record_compare(A, B) < 0,
          "B (seq s+1) beats A despite the earlier expiry");
    /* Two holders, two arrival orders, each with its own store: A's bytes
     * live in env2, B's in env. */
    h1 = (holder_t *)calloc(1, sizeof(*h1));
    h2 = (holder_t *)calloc(1, sizeof(*h2));
    if (h1 != NULL) {
        h1->buf = (uint8_t *)malloc(DHT2_ENVELOPE_MAX);
    }
    if (h2 != NULL) {
        h2->buf = (uint8_t *)malloc(DHT2_ENVELOPE_MAX);
    }
    if (h1 != NULL && h2 != NULL && h1->buf != NULL && h2->buf != NULL) {
        CHECK(holder_admit(h1, fx->env2, env_len, d.chain) == 0 &&
              holder_admit(h1, fx->env, env2_len, d.chain) == 0,
              "holder 1: A then B");
        CHECK(holder_admit(h2, fx->env, env2_len, d.chain) == 0 &&
              holder_admit(h2, fx->env2, env_len, d.chain) == 0,
              "holder 2: B then A");
        CHECK(h1->has && h2->has && eq(h1->buf, h1->len, h2->buf, h2->len),
              "both holders store the SAME bytes");
        CHECK(dht2_record_canonical(B, fx->canon, sizeof(fx->canon), &ca)
              == DHT2_OK && eq(h1->buf, h1->len, fx->canon, ca),
              "and those bytes are B's canonical envelope");
        CHECK(h1->rec.d.sequence == 6 && h2->rec.d.sequence == 6,
              "the stored winner is seq s+1");
        cb = h2->len;
        CHECK(cb == ca, "same length");
    } else {
        CHECK(0, "malloc");
    }
    if (h1 != NULL) {
        free(h1->buf);
    }
    if (h2 != NULL) {
        free(h2->buf);
    }
    free(h1);
    free(h2);

    /* Each tie-break step, on synthetic versions. */
    synth(&x, 2, 0, 100, da, 2, sa, 3);
    synth(&y, 1, 1, 0,   db, 2, sb, 3);
    CHECK(dht2_record_compare(&x, &y) > 0, "1. larger Sequence first");
    synth(&y, 2, 0, 99,  db, 2, sb, 3);
    CHECK(dht2_record_compare(&x, &y) > 0, "2. later expiry");
    synth(&y, 2, 1, 0,   da, 2, sa, 3);
    CHECK(dht2_record_compare(&y, &x) > 0, "2. no expiry above any expiry");
    synth(&x, 2, 1, 0,   da, 2, sa, 3);
    synth(&y, 2, 1, 0,   db, 2, sa, 3);
    CHECK(dht2_record_compare(&y, &x) > 0 && dht2_record_compare(&x, &y) < 0,
          "3. both no-expiry: larger data bytes");
    synth(&x, 2, 0, 50,  dshort, 1, sa, 3);
    synth(&y, 2, 0, 50,  da, 2, sa, 3);
    CHECK(dht2_record_compare(&y, &x) > 0,
          "3. bytes.Compare: a proper prefix is smaller");
    synth(&x, 2, 0, 50,  da, 2, sa, 3);
    synth(&y, 2, 0, 50,  da, 2, sb, 3);
    CHECK(dht2_record_compare(&y, &x) > 0 && dht2_record_compare(&x, &y) < 0,
          "4. same data: larger signature bytes");
    synth(&y, 2, 0, 50,  da, 2, sa, 3);
    CHECK(dht2_record_compare(&x, &y) == 0, "identical = same version");

    free(A);
    free(B);
}

/* ══ 7. placement vector ═════════════════════════════════════════════════ */

static void test_placement(void)
{
    static const uint8_t b0[6] = { 0x80, 0x01, 0x40, 0x03, 0x10, 0x02 };
    uint8_t set[6][DHT2_FP_LEN], key[DHT2_HASH_LEN], dup[2][DHT2_FP_LEN];
    size_t  idx[DHT2_R];
    size_t  k;
    int     m;

    memset(set, 0, sizeof(set));
    for (k = 0; k < 6; k++) {
        set[k][0] = b0[k];
    }
    /* key 0: distance = the member itself → 0x01, 0x02, 0x03, 0x10 */
    memset(key, 0, sizeof(key));
    m = dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])set, 6, idx);
    CHECK(m == 4 && idx[0] == 1 && idx[1] == 5 && idx[2] == 3 && idx[3] == 4,
          "nearest_R(key 00…) = members 1, 5, 3, 4");
    /* key 80 00…: distances 00, 81, c0, 83, 90, 82 → 0, 1, 5, 3 */
    key[0] = 0x80;
    m = dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])set, 6, idx);
    CHECK(m == 4 && idx[0] == 0 && idx[1] == 1 && idx[2] == 5 && idx[3] == 3,
          "nearest_R(key 80…) = members 0, 1, 5, 3");
    /* a low byte decides only when the high bytes tie */
    key[0] = 0x00;
    key[63] = 0xff;
    m = dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])set, 6, idx);
    CHECK(m == 4 && idx[0] == 1 && idx[1] == 5 && idx[2] == 3 && idx[3] == 4,
          "the most significant byte decides first");
    /* fewer than R → all, nearest first */
    memset(key, 0, sizeof(key));
    m = dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])set, 3, idx);
    CHECK(m == 3 && idx[0] == 1 && idx[1] == 2 && idx[2] == 0,
          "3 members: all hold");
    m = dht2_nearest_r(key, NULL, 0, idx);
    CHECK(m == 0, "empty set: no holder");
    memset(dup, 0x07, sizeof(dup));
    CHECK(dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])dup, 2, idx)
          == -1, "a repeated fp is refused");

    /* eligible = nearest_R(S(H)) ∪ nearest_R(S(H−E)) */
    CHECK(dht2_eligible(key, (const uint8_t (*)[DHT2_FP_LEN])set, 6, NULL, 0,
                        set[4]) == 1, "member 4 eligible under S(H)");
    CHECK(dht2_eligible(key, (const uint8_t (*)[DHT2_FP_LEN])set, 6, NULL, 0,
                        set[2]) == 0, "member 2 (0x40) not eligible");
    CHECK(dht2_eligible(key, (const uint8_t (*)[DHT2_FP_LEN])set + 4, 2,
                        (const uint8_t (*)[DHT2_FP_LEN])set, 6, set[3]) == 1,
          "member 3 eligible through S(H-E) only");
}

/* ══ 8. RFC 0002 envelopes and the row-23 LIST request ═══════════════════ */

static void test_envelopes_and_list(fixture_t *fx)
{
    static const uint8_t payload[4] = { 0xa0, 1, 2, 3 };
    dht2_env_t      env;
    dht2_list_req_t req, got;
    uint8_t         inbox_a[DHT2_ID_LEN], owner[DHT2_FP_LEN];
    size_t          n = 0, sz = 0, pt_len = strlen(DHT2_PT_ANSWER), off;
    uint8_t        *sb;

    /* Generic envelope, answer domain. */
    CHECK(dht2_env_seal(DHT2_DOMAIN_ANSWER, (const uint8_t *)DHT2_PT_ANSWER,
                        pt_len, payload, sizeof(payload), fx->sk_b, fx->pk_b,
                        NULL, 0, &sz) == DHT2_OK, "seal size");
    CHECK(dht2_env_seal(DHT2_DOMAIN_ANSWER, (const uint8_t *)DHT2_PT_ANSWER,
                        pt_len, payload, sizeof(payload), fx->sk_b, fx->pk_b,
                        fx->env, sizeof(fx->env), &n) == DHT2_OK && n == sz,
          "seal");
    CHECK(dht2_env_decode(fx->env, n, DHT2_ENVELOPE_MAX, &env) == DHT2_OK,
          "decode");
    CHECK(memcmp(env.fp, fx->fp_b, DHT2_FP_LEN) == 0 &&
          eq(env.payload, env.payload_len, payload, sizeof(payload)) &&
          eq(env.payload_type, env.payload_type_len,
             (const uint8_t *)DHT2_PT_ANSWER, pt_len), "fields");
    CHECK(env.payload_type[0] == 0x2f, "payload type starts with 0x2f");
    CHECK(dht2_env_verify(&env, DHT2_DOMAIN_ANSWER) == DHT2_OK, "verify");
    CHECK(dht2_env_verify(&env, DHT2_DOMAIN_ADDR) == DHT2_E_BAD_SIGNATURE,
          "another domain does not verify");
    CHECK(dht2_env_decode(fx->env, n, n - 1, &env) == DHT2_E_TOO_LARGE,
          "max_len checked first");
    CHECK(dht2_env_decode(fx->env, n, DHT2_ENVELOPE_MAX, &env) == DHT2_OK,
          "decode again");

    /* RFC 0002 :111-122, built independently: 13 'nodus.dht.answer.v1'
     * … — and ctx = the domain (§4.4 deviation). */
    sb = (uint8_t *)malloc(64 + sizeof(payload));
    if (sb != NULL) {
        size_t dl = strlen(DHT2_DOMAIN_ANSWER);

        off = 0;
        sb[off++] = (uint8_t)dl;              /* 19 < 128: one-byte uvarint */
        memcpy(sb + off, DHT2_DOMAIN_ANSWER, dl);
        off += dl;
        sb[off++] = (uint8_t)pt_len;
        memcpy(sb + off, DHT2_PT_ANSWER, pt_len);
        off += pt_len;
        sb[off++] = (uint8_t)sizeof(payload);
        memcpy(sb + off, payload, sizeof(payload));
        off += sizeof(payload);
        CHECK(qgp_dsa87_verify_ctx(env.sig, env.sig_len, sb, off,
                                   (const uint8_t *)DHT2_DOMAIN_ANSWER, dl,
                                   fx->pk_b) == 0,
              "signature is over uvarint(len)||domain||uvarint(len)||type||"
              "uvarint(len)||payload with ctx = domain");
        CHECK(qgp_dsa87_verify(env.sig, env.sig_len, sb, off, fx->pk_b) != 0,
              "and NOT without the ctx");
        free(sb);
    } else {
        CHECK(0, "malloc");
    }

    /* Row 23 LIST: owner A asks for its own inbox, with a cursor. */
    memset(&req, 0, sizeof(req));
    memset(req.nonce, 0x5a, DHT2_NONCE_LEN);
    memcpy(req.chain, fx->chain, DHT2_CHAIN_LEN);
    CHECK(dht2_id_inbox(fx->chain, fx->fp_a, inbox_a) == 0, "inbox id");
    memcpy(req.inbox, inbox_a, DHT2_ID_LEN);
    req.has_cursor = true;
    memset(req.cursor, 0x66, DHT2_FP_LEN);
    CHECK(dht2_list_req_build(&req, fx->sk_a, fx->pk_a, fx->env,
                              sizeof(fx->env), &n) == DHT2_OK, "LIST build");
    CHECK(dht2_list_req_open(fx->env, n, fx->chain, &got, owner) == DHT2_OK,
          "LIST open");
    CHECK(memcmp(owner, fx->fp_a, DHT2_FP_LEN) == 0 &&
          memcmp(&got.nonce, req.nonce, DHT2_NONCE_LEN) == 0 &&
          memcmp(got.inbox, inbox_a, DHT2_ID_LEN) == 0 && got.has_cursor &&
          memcmp(got.cursor, req.cursor, DHT2_FP_LEN) == 0,
          "LIST round trip");
    CHECK(dht2_list_req_open(fx->env, n, fx->other_chain, &got, NULL)
          == DHT2_E_BAD_CHAIN, "LIST for another chain");

    /* The pinned payload bytes: {c, n, op "list", inbox, cursor}. */
    {
        asm_t   a;
        uint8_t pl[256];
        size_t  pn = 0;

        a_init(&a);
        a_hex(&a, "a5");
        a_hex(&a, "61 63 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "61 6e 5820");
        a_fill(&a, 0x5a, 32);
        a_hex(&a, "62 6f70 64 6c697374");
        a_hex(&a, "65 696e626f78 5840");
        a_raw(&a, inbox_a, 64);
        a_hex(&a, "66 637572736f72 5840");
        a_fill(&a, 0x66, 64);
        CHECK(a.err == 0 &&
              dht2_list_payload_encode(&req, pl, sizeof(pl), &pn) == DHT2_OK &&
              eq(pl, pn, a.b, a.n), "LIST payload bytes pinned");
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_OK,
              "LIST payload decodes");
        a.b[0] = 0xa4;                       /* drop the cursor entry */
        a.n -= 7 + 2 + 64;
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_OK &&
              !got.has_cursor, "first page: no cursor");
    }

    /* Flip one nonce byte inside the signed payload → bad-signature. */
    CHECK(dht2_env_decode(fx->env, n, DHT2_ENVELOPE_MAX, &env) == DHT2_OK,
          "decode LIST env");
    memcpy(fx->env2, fx->env, n);
    off = (size_t)(env.payload - fx->env);
    fx->env2[off + 1 + 2 + 2 + 32 + 2 + 2] ^= 0x01;   /* nonce byte 0 */
    CHECK(dht2_list_req_open(fx->env2, n, fx->chain, &got, NULL)
          == DHT2_E_BAD_SIGNATURE, "flipped payload byte = bad-signature");
    /* Flip a payload-type byte → not a LIST request (malformed). */
    memcpy(fx->env2, fx->env, n);
    off = (size_t)(env.payload_type - fx->env);
    fx->env2[off + 3] ^= 0x01;
    CHECK(dht2_list_req_open(fx->env2, n, fx->chain, &got, NULL)
          == DHT2_E_MALFORMED_REQ, "wrong payload type = malformed request");

    /* Wrong owner: B signs a LIST for A's inbox → not-owner (17). */
    CHECK(dht2_list_req_build(&req, fx->sk_b, fx->pk_b, fx->env,
                              sizeof(fx->env), &n) == DHT2_OK, "B builds");
    CHECK(dht2_list_req_open(fx->env, n, fx->chain, &got, NULL)
          == DHT2_E_NOT_OWNER, "wrong owner = not-owner");

    /* The LIST payload signed under the ANSWER domain → bad-signature. */
    {
        uint8_t pl[256];
        size_t  pn = 0;

        CHECK(dht2_list_payload_encode(&req, pl, sizeof(pl), &pn) == DHT2_OK,
              "payload");
        CHECK(dht2_env_seal(DHT2_DOMAIN_ANSWER, (const uint8_t *)DHT2_PT_LIST,
                            strlen(DHT2_PT_LIST), pl, pn, fx->sk_a, fx->pk_a,
                            fx->env, sizeof(fx->env), &n) == DHT2_OK, "seal");
        CHECK(dht2_list_req_open(fx->env, n, fx->chain, &got, NULL)
              == DHT2_E_BAD_SIGNATURE, "another domain = bad-signature");
    }

    /* Malformed payloads (row 7): short nonce, unknown op, bad cursor. */
    {
        asm_t a;

        a_init(&a);
        a_hex(&a, "a4 6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "616e 581f");
        a_fill(&a, 0x5a, 31);
        a_hex(&a, "626f70 646c697374 65696e626f78 5840");
        a_raw(&a, inbox_a, 64);
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_E_MALFORMED_REQ,
              "nonce of 31 B");
        a_init(&a);
        a_hex(&a, "a4 6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "616e 5820");
        a_fill(&a, 0x5a, 32);
        a_hex(&a, "626f70 63676574 65696e626f78 5840");
        a_raw(&a, inbox_a, 64);
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_E_MALFORMED_REQ,
              "op \"get\" is not a LIST");
        a_init(&a);
        a_hex(&a, "a5 6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "616e 5820");
        a_fill(&a, 0x5a, 32);
        a_hex(&a, "626f70 646c697374 65696e626f78 5840");
        a_raw(&a, inbox_a, 64);
        a_hex(&a, "66637572736f72 5820");
        a_fill(&a, 0x66, 32);
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_E_MALFORMED_REQ,
              "cursor of 32 B");
    }
}

/* ══ 9. hardening vectors (audit round) ═════════════════════════════════ */

/* (b) The strict READER itself refuses non-shortest heads — the refusal
 * does not depend on the re-encode check that runs after it. Each vector
 * is fed straight to dht2_cbor_rd_*; the shortest form of the same value
 * is accepted beside it. */
static void test_reader_shortest(void)
{
    static const struct { const char *hex; int ok; uint64_t v; } ints[] = {
        { "17",                  1, 23 },
        { "1817",                0, 0 },     /* 23 in 1 byte */
        { "1818",                1, 24 },
        { "1800",                0, 0 },
        { "1900ff",              0, 0 },     /* 255 in 2 bytes */
        { "190100",              1, 256 },
        { "1a0000ffff",          0, 0 },     /* 65535 in 4 bytes */
        { "1a00010000",          1, 65536 },
        { "1b00000000ffffffff",  0, 0 },     /* 2^32-1 in 8 bytes */
        { "1b0000000100000000",  1, 4294967296ull },
        { "1c",                  0, 0 },     /* reserved */
        { "1f",                  0, 0 },     /* indefinite */
    };
    asm_t          a;
    dht2_cbor_rd_t r;
    uint64_t       v;
    const uint8_t *p, *k;
    size_t         n, kl, i;

    for (i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
        int rc;

        a_init(&a);
        a_hex(&a, ints[i].hex);
        dht2_cbor_rd_init(&r, a.b, a.n);
        rc = dht2_cbor_rd_uint(&r, &v);
        CHECK(ints[i].ok ? (rc == 0 && v == ints[i].v && dht2_cbor_rd_done(&r))
                         : (rc != 0), ints[i].hex);
    }
    /* long-form byte-string length: 58 03 vs 43 */
    a_init(&a);
    a_hex(&a, "5803 010203");
    dht2_cbor_rd_init(&r, a.b, a.n);
    CHECK(dht2_cbor_rd_bytes(&r, &p, &n) != 0, "reader: bstr len 3 in 1 byte");
    a_init(&a);
    a_hex(&a, "43 010203");
    dht2_cbor_rd_init(&r, a.b, a.n);
    CHECK(dht2_cbor_rd_bytes(&r, &p, &n) == 0 && n == 3 &&
          dht2_cbor_rd_done(&r), "reader: bstr len 3 short form");
    /* long-form map count and key length */
    a_init(&a);
    a_hex(&a, "b801");
    dht2_cbor_rd_init(&r, a.b, a.n);
    CHECK(dht2_cbor_rd_map(&r, &v) != 0, "reader: map count 1 in 1 byte");
    a_init(&a);
    a_hex(&a, "7803 616263");
    dht2_cbor_rd_init(&r, a.b, a.n);
    CHECK(dht2_cbor_rd_key(&r, NULL, 0, &k, &kl) != 0,
          "reader: key length 3 in 1 byte");
    /* a sticky error: after one refusal, nothing more is read */
    a_init(&a);
    a_hex(&a, "1800 01");
    dht2_cbor_rd_init(&r, a.b, a.n);
    CHECK(dht2_cbor_rd_uint(&r, &v) != 0 && dht2_cbor_rd_uint(&r, &v) != 0 &&
          !dht2_cbor_rd_done(&r), "reader error is sticky");
}

static void test_hardening(fixture_t *fx)
{
    static const uint8_t p3[3] = { 1, 2, 3 };
    dht2_data_t    d, e;
    dht2_record_t *r1 = (dht2_record_t *)malloc(sizeof(*r1));
    dht2_record_t *r2 = (dht2_record_t *)malloc(sizeof(*r2));
    cmt_pb_public_key_t pkv;
    uint8_t        pkm_a[3 + DHT2_PUBKEY_LEN], pkm_b[3 + DHT2_PUBKEY_LEN];
    uint8_t       *inner = (uint8_t *)malloc(2 * (4 + DHT2_PUBKEY_LEN));
    size_t         env_len = 0, pa_len = 0, pb_len = 0, off, cn = 0, k;
    dht2_env_t     env;
    asm_t          a;
    int            all;

    if (r1 == NULL || r2 == NULL || inner == NULL) {
        CHECK(0, "malloc");
        goto done;
    }
    data_base(&d, DHT2_CLASS_OWNER);
    d.has_data = true;
    d.data = p3;
    d.data_len = 3;
    CHECK(build_parse(fx, &d, fx->sk_a, fx->pk_a, r1, &env_len) == DHT2_OK,
          "build + parse");
    pkv.present = true;
    memcpy(pkv.key, fx->pk_a, DHT2_PUBKEY_LEN);
    CHECK(cmt_pb_public_key_marshal(&pkv, pkm_a, sizeof(pkm_a), &pa_len)
          == CMT_OK, "pk A msg");
    memcpy(pkv.key, fx->pk_b, DHT2_PUBKEY_LEN);
    CHECK(cmt_pb_public_key_marshal(&pkv, pkm_b, sizeof(pkm_b), &pb_len)
          == CMT_OK, "pk B msg");

    /* (c) IPNS field 7 is `bytes`: last-one-wins. B then A → A; A then B
     * → B (and the signature no longer matches); A then an EMPTY 7 → no
     * key at all → bad-encoding. */
    off = pb_ld(fx->env2, 0, 7, pkm_b, pb_len);
    off = pb_ld(fx->env2, off, 7, pkm_a, pa_len);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          memcmp(r2->fp, fx->fp_a, DHT2_FP_LEN) == 0 &&
          dht2_record_verify(r2) == DHT2_OK, "field 7 B then A: A wins");
    CHECK(dht2_record_canonical(r2, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_OK && eq(fx->canon, cn, fx->env, env_len),
          "repeated field 7 collapses to the canonical form");
    off = pb_ld(fx->env2, 0, 7, pkm_a, pa_len);
    off = pb_ld(fx->env2, off, 7, pkm_b, pb_len);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          memcmp(r2->fp, fx->fp_b, DHT2_FP_LEN) == 0 &&
          dht2_record_verify(r2) == DHT2_E_BAD_SIGNATURE,
          "field 7 A then B: B wins and does not verify");
    off = pb_ld(fx->env2, 0, 7, pkm_a, pa_len);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    fx->env2[off++] = 0x3a;                   /* field 7, length 0 */
    fx->env2[off++] = 0x00;
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2)
          == DHT2_E_BAD_ENCODING, "a trailing EMPTY field 7 erases the key");

    /* (d) non-canonical PublicKey bytes inside field 7: a repeated inner
     * field 9 (B then A → A) and a non-minimal inner length (2592 as the
     * 3-byte uvarint a0 94 00) both collapse to the one canonical form. */
    memcpy(inner, pkm_b, pb_len);
    memcpy(inner + pb_len, pkm_a, pa_len);
    off = pb_ld(fx->env2, 0, 7, inner, pb_len + pa_len);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          memcmp(r2->fp, fx->fp_a, DHT2_FP_LEN) == 0 &&
          dht2_record_canonical(r2, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_OK && eq(fx->canon, cn, fx->env, env_len),
          "repeated inner field 9 collapses to canonical");
    inner[0] = 0x4a;
    inner[1] = 0xa0;
    inner[2] = 0x94;
    inner[3] = 0x00;
    memcpy(inner + 4, fx->pk_a, DHT2_PUBKEY_LEN);
    off = pb_ld(fx->env2, 0, 7, inner, 4 + DHT2_PUBKEY_LEN);
    off = pb_ld(fx->env2, off, 8, r1->sig, r1->sig_len);
    off = pb_ld(fx->env2, off, 9, r1->data, r1->data_len);
    CHECK(dht2_record_parse(fx->env2, off, d.chain, NULL, r2) == DHT2_OK &&
          dht2_record_canonical(r2, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_OK && eq(fx->canon, cn, fx->env, env_len),
          "non-minimal inner length collapses to canonical");

    /* canonical refuses a signature that is not 4627 B (item 5) */
    *r2 = *r1;
    r2->sig_len = DHT2_SIG_LEN - 1;
    CHECK(dht2_record_canonical(r2, fx->canon, sizeof(fx->canon), &cn)
          == DHT2_E_BAD_SIGNATURE, "canonical refuses a 4626-byte signature");
    r2->sig_len = 0;
    CHECK(dht2_record_canonical(r2, NULL, 0, &cn) == DHT2_E_BAD_SIGNATURE,
          "canonical refuses an absent signature");
    CHECK(dht2_record_compare(NULL, r1) < 0 && dht2_record_compare(r1, NULL) > 0
          && dht2_record_compare(NULL, NULL) == 0, "compare with NULL");

    /* (c) RFC 0002 field 1 is an embedded message: MERGED. A later EMPTY
     * PublicKey keeps the key; a later key B replaces A. */
    CHECK(dht2_env_seal(DHT2_DOMAIN_ANSWER, (const uint8_t *)DHT2_PT_ANSWER,
                        strlen(DHT2_PT_ANSWER), p3, sizeof(p3), fx->sk_a,
                        fx->pk_a, fx->env2, sizeof(fx->env2), &off) == DHT2_OK,
          "seal");
    fx->env2[off++] = 0x0a;                   /* field 1, empty message */
    fx->env2[off++] = 0x00;
    CHECK(dht2_env_decode(fx->env2, off, DHT2_ENVELOPE_MAX, &env) == DHT2_OK &&
          memcmp(env.fp, fx->fp_a, DHT2_FP_LEN) == 0 &&
          dht2_env_verify(&env, DHT2_DOMAIN_ANSWER) == DHT2_OK,
          "field 1: a later empty PublicKey keeps the key");
    off -= 2;
    off = pb_ld(fx->env2, off, 1, pkm_b, pb_len);
    CHECK(dht2_env_decode(fx->env2, off, DHT2_ENVELOPE_MAX, &env) == DHT2_OK &&
          memcmp(env.fp, fx->fp_b, DHT2_FP_LEN) == 0 &&
          dht2_env_verify(&env, DHT2_DOMAIN_ANSWER) == DHT2_E_BAD_SIGNATURE,
          "field 1: a later key replaces it (and does not verify)");
    off = 0;
    fx->env2[off++] = 0x0a;
    fx->env2[off++] = 0x00;
    CHECK(dht2_env_decode(fx->env2, off, DHT2_ENVELOPE_MAX, &env)
          == DHT2_E_BAD_ENCODING, "only an empty PublicKey: no key");

    /* (e) truncation sweep: every proper prefix of a class-1 envelope and
     * of its data map is refused, none crashes. */
    all = 1;
    for (k = 0; k < env_len; k++) {
        if (dht2_record_parse(fx->env, k, d.chain, NULL, r2) == DHT2_OK) {
            all = 0;
        }
    }
    CHECK(all, "every envelope prefix refused");
    kat1(&a, V_OK);
    all = 1;
    for (k = 0; k < a.n; k++) {
        if (dht2_data_decode(a.b, k, &e) == DHT2_OK) {
            all = 0;
        }
    }
    CHECK(all, "every data-map prefix refused");

    /* (f) LIST payload: unsorted keys ("n" before "c") and a duplicate
     * key ("c" twice). */
    {
        dht2_list_req_t got;
        uint8_t         inbox[DHT2_ID_LEN];

        memset(inbox, 0x44, sizeof(inbox));
        a_init(&a);
        a_hex(&a, "a4 616e 5820");
        a_fill(&a, 0x5a, 32);
        a_hex(&a, "6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "626f70 646c697374 65696e626f78 5840");
        a_raw(&a, inbox, 64);
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_E_MALFORMED_REQ,
              "LIST unsorted keys");
        a_init(&a);
        a_hex(&a, "a5 6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "6163 5820");
        a_raw(&a, fx->chain, 32);
        a_hex(&a, "616e 5820");
        a_fill(&a, 0x5a, 32);
        a_hex(&a, "626f70 646c697374 65696e626f78 5840");
        a_raw(&a, inbox, 64);
        CHECK(dht2_list_payload_decode(a.b, a.n, &got) == DHT2_E_MALFORMED_REQ,
              "LIST duplicate key");
    }

    /* item 7: a set over DHT2_SET_MAX is refused */
    {
        uint8_t (*big)[DHT2_FP_LEN] =
            (uint8_t (*)[DHT2_FP_LEN])calloc(DHT2_SET_MAX + 1, DHT2_FP_LEN);
        uint8_t key[DHT2_HASH_LEN];
        size_t  idx[DHT2_R];

        memset(key, 0, sizeof(key));
        if (big != NULL) {
            for (k = 0; k <= DHT2_SET_MAX; k++) {
                big[k][0] = (uint8_t)(k & 0xff);
                big[k][1] = (uint8_t)(k >> 8);
            }
            CHECK(dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])big,
                                 DHT2_SET_MAX, idx) == (int)DHT2_R,
                  "256 members accepted");
            CHECK(dht2_nearest_r(key, (const uint8_t (*)[DHT2_FP_LEN])big,
                                 DHT2_SET_MAX + 1, idx) == -1,
                  "257 members refused");
            free(big);
        } else {
            CHECK(0, "malloc");
        }
    }

done:
    free(inner);
    free(r1);
    free(r2);
}

int main(void)
{
    fixture_t *fx = (fixture_t *)malloc(sizeof(*fx));
    uint8_t    seed[32];

    if (fx == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "fixture malloc failed");
        return 1;
    }
    memset(fx, 0, sizeof(*fx));
    memset(seed, 0xA1, sizeof(seed));
    if (qgp_dsa87_keypair_derand(fx->pk_a, fx->sk_a, seed) != 0 ||
        dht2_fp(fx->pk_a, fx->fp_a) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "keypair A");
        free(fx);
        return 1;
    }
    memset(seed, 0xB2, sizeof(seed));
    if (qgp_dsa87_keypair_derand(fx->pk_b, fx->sk_b, seed) != 0 ||
        dht2_fp(fx->pk_b, fx->fp_b) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "keypair B");
        free(fx);
        return 1;
    }
    memset(fx->chain, 0x22, DHT2_CHAIN_LEN);
    memset(fx->other_chain, 0x23, DHT2_CHAIN_LEN);

    QGP_LOG_INFO(LOG_TAG, "=== DHT v2 record codec (package 1) ===");
    test_strict_decode();
    test_class_kats(fx);
    test_preimages(fx);
    test_envelope(fx);
    test_matrix(fx);
    test_class_max();
    test_validity();
    test_order(fx);
    test_placement();
    test_envelopes_and_list(fx);
    test_reader_shortest();
    test_hardening(fx);
    QGP_LOG_INFO(LOG_TAG, "=== Results: %d passed, %d failed ===",
                 g_pass, g_fail);

    memset(fx, 0, sizeof(*fx));
    free(fx);
    return g_fail == 0 ? 0 : 1;
}
