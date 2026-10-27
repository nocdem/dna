/**
 * Nodus — HF-9 package H1: the generation-6 leaves, compositions, trie
 * key encoders and the shared HRW holder selector
 * (shared/dnac/ledger_roots_v2.{c,h}).
 *
 * WHAT IT PROVES. Against docs/plans/2026-10-23-hf9-byte-spec.md rev 3
 * (APPROVED 2026-10-27) §1, §4, §6, §11, §12a.1, §12a.3, §12a.4, §12b and
 * Appendix A, with every preimage assembled IN THIS FILE byte by byte (own
 * helpers, offsets written out from the spec text) and hashed with
 * qgp_sha3_512 directly:
 *   · STLEAF.v3 = tag ‖ the 165-byte v2 preimage ‖ ipv4 ‖ ipv4_since
 *     (and the v2 routine still equals the same independently built v2
 *     preimage, so the "v2 ‖ new fields" relation is checked on both ends);
 *   · STREP.v2 (empty, 1, 8, 9, 1024 members), SMLEAF.v2, STSLEAF.v2;
 *   · the five composition tags: each composition equals SHA3-512(new tag
 *     ‖ the legs in the old routine's order) and differs from the old
 *     routine's output on the same legs;
 *   · refusals: status 0 / 4, bitmap_len > 128, count > 1024,
 *     bitmap_len != ceil(count/8), a non-zero unused bitmap bit, stmem
 *     range violations, placeable 2, copies 2 / 17;
 *   · the HRW selector equals a brute-force reference (every placeable
 *     member weighted with the spec's 144-byte preimage, ranked by weight
 *     descending), the placeable filter, fewer-than-R, rank order, the
 *     prefix property, n = 0, and the refusals: unsorted, duplicate,
 *     R = 0 / 17, n = 1025, placeable value 2, NULL;
 *   · the trie key encoders: widths, column order, big-endian, name
 *     length 3..36.
 *
 * REQUIRES. A default nodus build; no compile flag, no environment, no
 * network, no file read, no clock.
 *
 * LEAVES BEHIND. Nothing.
 *
 * HOW IT CAN LIE. No known-answer constants: the expected values come from
 * this file's own reading of the spec, so a green run proves the C equals
 * the spec text as THIS file read it — not that the spec is sound, and not
 * that the independent oracle (a later package) agrees. The HRW tie rule
 * (equal weights -> larger node_fp first) cannot be reached with a real
 * 512-bit hash, so it is NOT exercised here; only the strictly-ascending
 * input requirement that makes it total is. Error cases assert only "-1",
 * not which check refused. The selector is checked at n <= 1024 with
 * synthetic node_fps (SHA3 of a counter), not live registry data.
 *
 * @file test_hf9_leaves.c
 */

#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── independent byte assembly ───────────────────────────────────────── */

typedef struct { uint8_t b[8192]; size_t n; } buf_t;

static void b_tag(buf_t *x, const char *ascii) {
    size_t l = strlen(ascii);
    memset(x->b + x->n, 0, 16);
    memcpy(x->b + x->n, ascii, l);
    x->n += 16;
}
static void b_raw(buf_t *x, const uint8_t *p, size_t l) {
    memcpy(x->b + x->n, p, l); x->n += l;
}
static void b_u8(buf_t *x, uint8_t v) { x->b[x->n++] = v; }
static void b_u16(buf_t *x, uint16_t v) {
    x->b[x->n++] = (uint8_t)(v >> 8); x->b[x->n++] = (uint8_t)v;
}
static void b_u32(buf_t *x, uint32_t v) {
    for (int i = 3; i >= 0; i--) x->b[x->n++] = (uint8_t)(v >> (8 * i));
}
static void b_u64(buf_t *x, uint64_t v) {
    for (int i = 7; i >= 0; i--) x->b[x->n++] = (uint8_t)(v >> (8 * i));
}
static void b_hash(const buf_t *x, uint8_t out[64]) {
    if (qgp_sha3_512(x->b, x->n, out) != 0) { fprintf(stderr, "sha3\n"); exit(2); }
}

/* a deterministic 64-byte value: SHA3-512(label ‖ u32 i) */
static void synth(const char *label, uint32_t i, uint8_t out[64]) {
    buf_t x; x.n = 0;
    b_raw(&x, (const uint8_t *)label, strlen(label));
    b_u32(&x, i);
    b_hash(&x, out);
}

/* ── the leaves ──────────────────────────────────────────────────────── */

static int test_registry_v3(void) {
    dna_v2_storage_node_row_v3_t r;
    memset(&r, 0, sizeof(r));
    synth("node", 1, r.base.node_fp);
    synth("payee", 1, r.base.payee_fp);
    r.base.bond = 0x0102030405060708ull;
    r.base.status = DNA_V2_STORAGE_EXITING;
    r.base.registered_height = 0x1112131415161718ull;
    r.base.exit_height = 0x2122232425262728ull;
    r.base.fail_streak = 0x31323334u;
    r.base.grace_until = 0x4142434445464748ull;
    r.ipv4 = 0xC0A80107u;                           /* 192.168.1.7 */
    r.ipv4_since = 0x5152535455565758ull;

    /* the v2 preimage after its tag: 165 bytes (spec §12a.3) */
    buf_t v2body; v2body.n = 0;
    b_raw(&v2body, r.base.node_fp, 64);
    b_raw(&v2body, r.base.payee_fp, 64);
    b_u64(&v2body, r.base.bond);
    b_u8(&v2body, r.base.status);
    b_u64(&v2body, r.base.registered_height);
    b_u64(&v2body, r.base.exit_height);
    b_u32(&v2body, r.base.fail_streak);
    b_u64(&v2body, r.base.grace_until);
    CHECK(v2body.n == 165, "v2 body is 165 bytes");

    buf_t v2; v2.n = 0;
    b_tag(&v2, "NDS.STLEAF.v2"); b_raw(&v2, v2body.b, v2body.n);
    uint8_t want[64], got[64];
    b_hash(&v2, want);
    CHECK(dna_v2_storage_node_leaf_hash(&r.base, got) == 0, "v2 leaf");
    CHECK(memcmp(want, got, 64) == 0, "v2 leaf = independent v2 preimage");
    OK();

    buf_t v3; v3.n = 0;
    b_tag(&v3, "NDS.STLEAF.v3"); b_raw(&v3, v2body.b, v2body.n);
    b_u32(&v3, r.ipv4); b_u64(&v3, r.ipv4_since);
    CHECK(v3.n == 16 + 177, "v3 preimage is 193 bytes with the tag");
    b_hash(&v3, want);
    CHECK(dna_v2_storage_node_leaf_hash_v3(&r, got) == 0, "v3 leaf");
    CHECK(memcmp(want, got, 64) == 0, "v3 leaf = v2 body ‖ ipv4 ‖ since");
    OK();

    uint8_t v2out[64];
    CHECK(dna_v2_storage_node_leaf_hash(&r.base, v2out) == 0, "v2");
    CHECK(memcmp(v2out, got, 64) != 0, "v3 differs from v2");
    OK();

    /* every new field is committed */
    dna_v2_storage_node_row_v3_t m = r; m.ipv4 ^= 1u;
    CHECK(dna_v2_storage_node_leaf_hash_v3(&m, v2out) == 0 &&
          memcmp(v2out, got, 64) != 0, "ipv4 committed");
    m = r; m.ipv4_since ^= 1u;
    CHECK(dna_v2_storage_node_leaf_hash_v3(&m, v2out) == 0 &&
          memcmp(v2out, got, 64) != 0, "ipv4_since committed");
    OK();

    /* status rule as v2 */
    m = r; m.base.status = 0;
    CHECK(dna_v2_storage_node_leaf_hash_v3(&m, v2out) == -1, "status 0");
    m.base.status = 4;
    CHECK(dna_v2_storage_node_leaf_hash_v3(&m, v2out) == -1, "status 4");
    CHECK(dna_v2_storage_node_leaf_hash_v3(NULL, v2out) == -1, "NULL row");
    CHECK(dna_v2_storage_node_leaf_hash_v3(&r, NULL) == -1, "NULL out");
    OK();
    return 0;
}

static int report_expected(const dna_v2_storage_report_v2_t *rep,
                           uint32_t count, const uint8_t (*ip)[4],
                           uint8_t out[64]) {
    buf_t x; x.n = 0;
    b_tag(&x, "NDS.STREP.v2");
    b_u64(&x, rep->epoch_start);
    b_u32(&x, rep->seat);
    b_raw(&x, rep->set_hash, 64);
    b_u16(&x, rep->bitmap_len);
    b_raw(&x, rep->bitmap, rep->bitmap_len);
    for (uint32_t i = 0; i < count; i++) b_raw(&x, ip[i], 4);
    b_hash(&x, out);
    return 0;
}

static uint8_t g_ip[1024][4];

static int test_report_v2(void) {
    static const uint32_t counts[] = {0, 1, 7, 8, 9, 255, 256, 1023, 1024};
    for (size_t t = 0; t < sizeof(counts) / sizeof(counts[0]); t++) {
        uint32_t c = counts[t];
        dna_v2_storage_report_v2_t r;
        memset(&r, 0, sizeof(r));
        r.epoch_start = 0x0A0B0C0D0E0F1011ull + c;
        r.seat = 0x21222324u;
        synth("sethash", c, r.set_hash);
        r.bitmap_len = (uint16_t)((c + 7u) / 8u);
        for (uint32_t i = 0; i < c; i++) {
            if (i % 3 == 0) r.bitmap[i / 8] |= (uint8_t)(1u << (i % 8));
            g_ip[i][0] = 10; g_ip[i][1] = (uint8_t)(i >> 8);
            g_ip[i][2] = (uint8_t)i; g_ip[i][3] = (uint8_t)(i * 7 + 1);
        }
        uint8_t want[64], got[64];
        report_expected(&r, c, (const uint8_t (*)[4])g_ip, want);
        CHECK(dna_v2_storage_report_leaf_hash_v2(
                  &r, c, c ? (const uint8_t (*)[4])g_ip : NULL, got) == 0,
              "report v2 accepted");
        CHECK(memcmp(want, got, 64) == 0, "report v2 = independent preimage");
        OK();
    }

    /* refusals */
    dna_v2_storage_report_v2_t r;
    uint8_t out[64];
    memset(&r, 0, sizeof(r));
    r.bitmap_len = 2;                                   /* count 9 */
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 9, (const uint8_t (*)[4])g_ip, out) == 0, "9 / 2 ok");
    r.bitmap[1] = 0x02;                                 /* bit 9 unused */
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 9, (const uint8_t (*)[4])g_ip, out) == -1,
          "unused bit set");
    r.bitmap[1] = 0x01;                                 /* bit 8 = member 8 */
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 9, (const uint8_t (*)[4])g_ip, out) == 0, "used bit ok");
    r.bitmap[1] = 0;
    r.bitmap_len = 1;
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 9, (const uint8_t (*)[4])g_ip, out) == -1, "len too short");
    r.bitmap_len = 3;
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 9, (const uint8_t (*)[4])g_ip, out) == -1, "len too long");
    r.bitmap_len = 129;
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 1025, (const uint8_t (*)[4])g_ip, out) == -1, "count 1025");
    CHECK(dna_v2_storage_report_leaf_hash_v2(
              &r, 1024, (const uint8_t (*)[4])g_ip, out) == -1, "len 129");
    r.bitmap_len = 0;
    CHECK(dna_v2_storage_report_leaf_hash_v2(&r, 0, NULL, out) == 0,
          "count 0 without addresses");
    CHECK(dna_v2_storage_report_leaf_hash_v2(&r, 1, NULL, out) == -1,
          "count 1 without addresses");
    CHECK(dna_v2_storage_report_leaf_hash_v2(NULL, 0, NULL, out) == -1,
          "NULL report");
    OK();
    return 0;
}

static int test_stmem_v2(void) {
    dna_v2_stmem_row_v2_t r;
    memset(&r, 0, sizeof(r));
    r.base.epoch_start = 0x0102030405060708ull;
    synth("m", 3, r.base.node_fp);
    r.base.fail_streak = 2;
    r.base.grace_until = 0x1112131415161718ull;
    for (uint8_t p = 0; p <= 1; p++) {
        r.placeable = p;
        buf_t x; x.n = 0;
        b_tag(&x, "NDS.SMLEAF.v2");
        b_u64(&x, r.base.epoch_start);
        b_raw(&x, r.base.node_fp, 64);
        b_u32(&x, (uint32_t)r.base.fail_streak);
        b_u64(&x, r.base.grace_until);
        b_u8(&x, p);
        CHECK(x.n == 16 + 85, "stmem v2 is 101 bytes with the tag");
        uint8_t want[64], got[64];
        b_hash(&x, want);
        CHECK(dna_v2_stmem_leaf_hash_v2(&r, got) == 0, "stmem v2");
        CHECK(memcmp(want, got, 64) == 0, "stmem v2 = independent");
    }
    OK();
    uint8_t a[64], b[64];
    r.placeable = 0; CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == 0, "p0");
    r.placeable = 1; CHECK(dna_v2_stmem_leaf_hash_v2(&r, b) == 0, "p1");
    CHECK(memcmp(a, b, 64) != 0, "placeable committed");
    r.placeable = 2;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == -1, "placeable 2");
    r.placeable = 1;
    r.base.epoch_start = 0;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == -1, "epoch 0");
    r.base.epoch_start = DNA_V2_HF7_U63_MAX + 1;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == -1, "epoch 2^63");
    r.base.epoch_start = 1;
    r.base.fail_streak = (uint64_t)UINT32_MAX + 1;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == -1, "fail_streak 2^32");
    r.base.fail_streak = UINT32_MAX;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == 0, "fail_streak 2^32-1");
    r.base.grace_until = DNA_V2_HF7_U63_MAX + 1;
    CHECK(dna_v2_stmem_leaf_hash_v2(&r, a) == -1, "grace 2^63");
    CHECK(dna_v2_stmem_leaf_hash_v2(NULL, a) == -1, "NULL row");
    OK();
    return 0;
}

static int test_sets_v2(void) {
    uint8_t sh[64], want[64], got[64];
    synth("set", 9, sh);
    for (uint32_t c = 3; c <= 16; c++) {
        buf_t x; x.n = 0;
        b_tag(&x, "NDS.STSLEAF.v2");
        b_u64(&x, 0x0102030405060708ull);
        b_raw(&x, sh, 64);
        b_u32(&x, c);
        CHECK(x.n == 16 + 76, "sets v2 is 92 bytes with the tag");
        b_hash(&x, want);
        CHECK(dna_v2_storage_sets_leaf_hash_v2(0x0102030405060708ull, sh, c,
                                               got) == 0, "sets v2");
        CHECK(memcmp(want, got, 64) == 0, "sets v2 = independent");
    }
    CHECK(dna_v2_storage_sets_leaf_hash_v2(1, sh, 2, got) == -1, "copies 2");
    CHECK(dna_v2_storage_sets_leaf_hash_v2(1, sh, 17, got) == -1, "copies 17");
    CHECK(dna_v2_storage_sets_leaf_hash_v2(1, sh, 0, got) == -1, "copies 0");
    CHECK(dna_v2_storage_sets_leaf_hash_v2(1, NULL, 3, got) == -1, "NULL");
    OK();
    return 0;
}

/* ── compositions ────────────────────────────────────────────────────── */

static int comp_expected(const char *tag, const uint8_t (*legs)[64], int n,
                         uint8_t out[64]) {
    buf_t x; x.n = 0;
    b_tag(&x, tag);
    for (int i = 0; i < n; i++) b_raw(&x, legs[i], 64);
    b_hash(&x, out);
    return 0;
}

static int test_compositions(void) {
    uint8_t L[12][64];
    for (uint32_t i = 0; i < 12; i++) synth("leg", i, L[i]);
    uint8_t want[64], got[64], old[64];

    comp_expected("NDS.CORE.v3", (const uint8_t (*)[64])L, 7, want);
    CHECK(dna_v2_core_root_v3(L[0], L[1], L[2], L[3], L[4], L[5], L[6],
                              got) == 0, "core v3");
    CHECK(memcmp(want, got, 64) == 0, "core v3 = tag ‖ 7 legs");
    CHECK(dna_v2_core_root(L[0], L[1], L[2], L[3], L[4], L[5], L[6],
                           old) == 0 && memcmp(old, got, 64) != 0,
          "core v3 differs from v2 on the same legs");
    CHECK(dna_v2_core_root_v3(L[0], L[1], L[2], L[3], L[4], L[5], NULL,
                              got) == -1, "core v3 NULL leg");
    OK();

    comp_expected("NDS.SYS.v7", (const uint8_t (*)[64])L, 12, want);
    CHECK(dna_v2_system_root_v7(L[0], L[1], L[2], L[3], L[4], L[5], L[6],
                                L[7], L[8], L[9], L[10], L[11], got) == 0,
          "sys v7");
    CHECK(memcmp(want, got, 64) == 0, "sys v7 = tag ‖ 12 legs");
    CHECK(dna_v2_system_root_v6(L[0], L[1], L[2], L[3], L[4], L[5], L[6],
                                L[7], L[8], L[9], L[10], L[11], old) == 0 &&
          memcmp(old, got, 64) != 0, "sys v7 differs from v6");
    CHECK(dna_v2_system_root_v7(L[0], L[1], L[2], L[3], L[4], L[5], L[6],
                                L[7], L[8], L[9], L[10], NULL, got) == -1,
          "sys v7 NULL leg");
    OK();

    comp_expected("NDS.STOR.v3", (const uint8_t (*)[64])L, 4, want);
    CHECK(dna_v2_storage_root_v3(L[0], L[1], L[2], L[3], got) == 0, "stor v3");
    CHECK(memcmp(want, got, 64) == 0, "stor v3 = tag ‖ 4 legs");
    CHECK(dna_v2_storage_root(L[0], L[1], L[2], L[3], old) == 0 &&
          memcmp(old, got, 64) != 0, "stor v3 differs from v2");
    CHECK(dna_v2_storage_root_v3(L[0], L[1], L[2], NULL, got) == -1,
          "stor v3 NULL leg");
    OK();

    comp_expected("NDS.GLOBAL.v3", (const uint8_t (*)[64])L, 2, want);
    CHECK(dna_v2_global_root_v3(L[0], L[1], got) == 0, "global v3");
    CHECK(memcmp(want, got, 64) == 0, "global v3 = tag ‖ 2 legs");
    CHECK(dna_v2_global_root_v2(L[0], L[1], old) == 0 &&
          memcmp(old, got, 64) != 0, "global v3 differs from v2");
    CHECK(dna_v2_global_root_v3(L[0], NULL, got) == -1, "global v3 NULL leg");
    OK();

    comp_expected("NDS.SYSPAYL.v4", (const uint8_t (*)[64])L, 5, want);
    CHECK(dna_v2_system_payload_root_v4(L[0], L[1], L[2], L[3], L[4],
                                        got) == 0, "payload v4");
    CHECK(memcmp(want, got, 64) == 0, "payload v4 = tag ‖ 5 legs");
    CHECK(dna_v2_system_payload_root(L[0], L[1], L[2], L[3], L[4], old) == 0 &&
          memcmp(old, got, 64) != 0, "payload v4 differs from v3");
    CHECK(dna_v2_system_payload_root_v4(NULL, L[1], L[2], L[3], L[4],
                                        got) == -1, "payload v4 NULL leg");
    OK();
    return 0;
}

/* ── HRW ─────────────────────────────────────────────────────────────── */

static int fp_cmp(const void *a, const void *b) {
    return memcmp(a, b, 64);
}

typedef struct { uint8_t w[64]; size_t idx; } ref_t;
static int ref_cmp(const void *a, const void *b) {   /* weight descending */
    const ref_t *x = a, *y = b;
    int c = memcmp(y->w, x->w, 64);
    if (c) return c;
    return x->idx < y->idx ? 1 : (x->idx > y->idx ? -1 : 0);
}

static uint8_t g_fps[1025][64];
static uint8_t g_pl[1025];

/* brute force: weight every placeable member from the spec's 144-byte
 * preimage, rank by weight descending, take R. */
static size_t hrw_ref(const uint8_t key[64], size_t n, uint32_t R,
                      size_t out[16]) {
    ref_t *e = malloc(n * sizeof(*e));
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        if (!g_pl[i]) continue;
        buf_t x; x.n = 0;
        b_tag(&x, "NDS.STHRW.v1");
        b_raw(&x, key, 64);
        b_raw(&x, g_fps[i], 64);
        if (x.n != 144) { fprintf(stderr, "preimage len\n"); exit(2); }
        b_hash(&x, e[m].w);
        e[m].idx = i; m++;
    }
    qsort(e, m, sizeof(*e), ref_cmp);
    size_t k = m < R ? m : R;
    for (size_t i = 0; i < k; i++) out[i] = e[i].idx;
    free(e);
    return k;
}

static void make_members(size_t n) {
    for (size_t i = 0; i < n; i++) synth("member", (uint32_t)i, g_fps[i]);
    qsort(g_fps, n, 64, fp_cmp);                    /* strictly ascending */
}

static int test_hrw(void) {
    uint8_t key[64];
    synth("key", 1, key);
    size_t got[16], want[16], ng, nw;

    static const size_t sizes[] = {1, 2, 3, 4, 5, 16, 17, 40, 256, 1024};
    for (size_t t = 0; t < sizeof(sizes) / sizeof(sizes[0]); t++) {
        size_t n = sizes[t];
        make_members(n);
        for (size_t i = 0; i < n; i++) g_pl[i] = (uint8_t)((i % 5) != 2);
        for (uint32_t R = 1; R <= 16; R++) {
            synth("key", 100 + R, key);
            nw = hrw_ref(key, n, R, want);
            CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps,
                                             g_pl, n, R, got, &ng) == 0,
                  "hrw accepted");
            CHECK(ng == nw, "hrw count = reference");
            CHECK(memcmp(got, want, nw * sizeof(size_t)) == 0,
                  "hrw order = reference (rank by weight descending)");
            for (size_t i = 0; i < ng; i++)
                CHECK(g_pl[got[i]] == 1, "only placeable members chosen");
        }
        OK();
    }

    /* prefix property: top-R is a prefix of top-16 for one key */
    make_members(300);
    for (size_t i = 0; i < 300; i++) g_pl[i] = 1;
    size_t all[16], some[16], na, ns;
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     300, 16, all, &na) == 0 && na == 16, "16");
    for (uint32_t R = 1; R < 16; R++) {
        CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps,
                                         g_pl, 300, R, some, &ns) == 0 &&
              ns == R && memcmp(some, all, R * sizeof(size_t)) == 0,
              "top-R is a prefix of top-16");
    }
    OK();

    /* the input order of placeable does not matter beyond its value:
     * only-placeable-members are ranked; none placeable -> 0 holders */
    memset(g_pl, 0, 300);
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     300, 4, some, &ns) == 0 && ns == 0,
          "none placeable -> empty");
    g_pl[7] = 1; g_pl[250] = 1;
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     300, 4, some, &ns) == 0 && ns == 2,
          "fewer than R placeable -> all placeable");
    CHECK((some[0] == 7 && some[1] == 250) || (some[0] == 250 && some[1] == 7),
          "both placeable members returned");
    OK();

    /* n = 0 */
    CHECK(dna_v2_storage_holders_hrw(key, NULL, NULL, 0, 4, some, &ns) == 0 &&
          ns == 0, "n = 0");
    OK();

    /* refusals */
    make_members(10);
    for (size_t i = 0; i < 10; i++) g_pl[i] = 1;
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 4, some, &ns) == 0, "baseline ok");
    uint8_t tmp[64];
    memcpy(tmp, g_fps[3], 64); memcpy(g_fps[3], g_fps[4], 64);
    memcpy(g_fps[4], tmp, 64);                       /* adjacent swap */
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 4, some, &ns) == -1, "unsorted");
    memcpy(g_fps[4], g_fps[3], 64);                  /* equal pair */
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 4, some, &ns) == -1, "duplicate");
    make_members(10);
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 0, some, &ns) == -1, "R = 0");
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 17, some, &ns) == -1, "R = 17");
    g_pl[2] = 2;
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 4, some, &ns) == -1, "placeable 2");
    g_pl[2] = 1;
    CHECK(dna_v2_storage_holders_hrw(NULL, (const uint8_t (*)[64])g_fps, g_pl,
                                     10, 4, some, &ns) == -1, "NULL key");
    CHECK(dna_v2_storage_holders_hrw(key, NULL, g_pl, 10, 4, some, &ns) == -1,
          "NULL fps");
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, NULL,
                                     10, 4, some, &ns) == -1, "NULL placeable");
    make_members(1025);
    for (size_t i = 0; i < 1025; i++) g_pl[i] = 1;
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     1025, 4, some, &ns) == -1, "n = 1025");
    CHECK(dna_v2_storage_holders_hrw(key, (const uint8_t (*)[64])g_fps, g_pl,
                                     1024, 4, some, &ns) == 0, "n = 1024");
    OK();
    return 0;
}

/* ── trie keys ───────────────────────────────────────────────────────── */

static int test_keys(void) {
    uint8_t a[64], b[64], c[64], k[DNA_V2_TRIE_KEY_MAX], e[DNA_V2_TRIE_KEY_MAX];
    synth("a", 1, a); synth("b", 2, b); synth("c", 3, c);

    dna_v2_trie_key_u64(0x0102030405060708ull, k);
    static const uint8_t u[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    CHECK(memcmp(k, u, 8) == 0, "u64 BE");
    dna_v2_trie_key_u64(0, k);
    static const uint8_t z[8] = {0};
    CHECK(memcmp(k, z, 8) == 0, "u64 zero");
    OK();

    CHECK(dna_v2_trie_key_blob64(a, k) == 0 && memcmp(k, a, 64) == 0, "blob");
    CHECK(dna_v2_trie_key_blob64(NULL, k) == -1, "blob NULL");
    OK();

    CHECK(dna_v2_trie_key_delegation(a, b, k) == 0, "delegation");
    memcpy(e, a, 64); memcpy(e + 64, b, 64);
    CHECK(memcmp(k, e, 128) == 0, "delegation = delegator ‖ validator");
    CHECK(dna_v2_trie_key_delegation(a, NULL, k) == -1, "delegation NULL");
    OK();

    dna_v2_trie_key_chain_config(0x1112131415161718ull, 0x2122232425262728ull,
                                 k);
    static const uint8_t cc[16] = {0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
                                   0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28};
    CHECK(memcmp(k, cc, 16) == 0, "chain_config = param_id ‖ effective");
    dna_v2_trie_key_reports(0x1112131415161718ull, 0x2122232425262728ull, k);
    CHECK(memcmp(k, cc, 16) == 0, "reports = epoch ‖ seat");
    OK();

    CHECK(dna_v2_trie_key_stmem(0x0102030405060708ull, a, k) == 0, "stmem");
    memcpy(e, u, 8); memcpy(e + 8, a, 64);
    CHECK(memcmp(k, e, 72) == 0, "stmem = epoch ‖ node_fp");
    CHECK(dna_v2_trie_key_stmem(1, NULL, k) == -1, "stmem NULL");
    OK();

    CHECK(dna_v2_trie_key_bcopy(0x0102030405060708ull, a, b,
                                0x1112131415161718ull, k) == 0, "bcopy");
    memcpy(e, u, 8); memcpy(e + 8, a, 64); memcpy(e + 72, b, 64);
    memcpy(e + 136, cc, 8);
    CHECK(memcmp(k, e, 144) == 0, "bcopy = epoch ‖ validator ‖ owner ‖ kind");
    CHECK(dna_v2_trie_key_bcopy(1, a, NULL, 0, k) == -1, "bcopy NULL");
    OK();

    uint8_t nm[DNA_V2_NAME_MAX_LEN]; size_t nl = 99;
    static const uint8_t name36[36] = "abcdefghijklmnopqrstuvwxyz0123456789";
    CHECK(dna_v2_trie_key_name(name36, 36, nm, &nl) == 0 && nl == 36 &&
          memcmp(nm, name36, 36) == 0, "name 36");
    CHECK(dna_v2_trie_key_name(name36, 3, nm, &nl) == 0 && nl == 3 &&
          memcmp(nm, name36, 3) == 0, "name 3");
    nl = 99;
    CHECK(dna_v2_trie_key_name(name36, 2, nm, &nl) == -1, "name 2");
    CHECK(dna_v2_trie_key_name(name36, 0, nm, &nl) == -1, "name 0");
    CHECK(dna_v2_trie_key_name(name36, 37, nm, &nl) == -1, "name 37");
    CHECK(dna_v2_trie_key_name(NULL, 5, nm, &nl) == -1, "name NULL");
    CHECK(nl == 99, "length untouched on refusal");
    OK();
    (void)c;
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_registry_v3();
    rc |= rc ? 0 : test_report_v2();
    rc |= rc ? 0 : test_stmem_v2();
    rc |= rc ? 0 : test_sets_v2();
    rc |= rc ? 0 : test_compositions();
    rc |= rc ? 0 : test_hrw();
    rc |= rc ? 0 : test_keys();
    if (rc) { fprintf(stderr, "test_hf9_leaves FAILED\n"); return 1; }
    printf("test_hf9_leaves: %d check groups passed\n", g_checks);
    return 0;
}
