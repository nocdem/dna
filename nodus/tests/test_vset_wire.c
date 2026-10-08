/**
 * Nodus — Ledger V2 S3: validator-set snapshot codec tests (INACTIVE layer).
 *
 * Every pinned literal was produced by an INDEPENDENT implementation
 * (python3 hashlib.sha3_512 over the layout in shared/dnac/vset_wire.h) —
 * the same oracle discipline as test_roots_v2.c. If the C encoder and a
 * pinned KAT disagree, the ENCODER is wrong.
 *
 * Sections:
 *   1. Oracle KATs — fixture A (2 entries) and fixture B (1 entry): exact
 *      encoded length + snapshot hash.
 *   2. Round-trip byte identity (encode → decode → encode).
 *   3. Structural negatives: count 0 / 129 (both as an in-memory snapshot
 *      and as a forged length field), truncation by 1, trailing +1,
 *      duplicate voter_id, duplicate pubkey, ruleset 0, ruleset 2, a
 *      nonzero reserved seed byte.
 *   4. (deleted — final pre-testnet wipe W-B removed the caller-less
 *      dna_vset_validate_bonds policy helper it tested; the exact-bond
 *      rule lives in the STAKE exec and the genesis Rule P.1.)
 *   5. The u16 count boundary: 128 distinct entries encode, decode and
 *      re-encode byte-identically.
 *   6. HF-6 slice 1 (INERT) — ruleset 2 through the `_ex` functions
 *      (design 2026-10-03-hf5-validator-owner-stake §6.5, Kurultay #14 K6):
 *      a. v1 unchanged: fixture A through every `_ex` variant gives the
 *         same bytes and the same pinned KAT; v1 decode leaves
 *         validator_id / owner_fp zero; the v1 encoder REJECTS a nonzero
 *         validator_id / owner_fp (all entry points).
 *      b. v2 round-trip: exact length, field-by-field and byte identity,
 *         hash == in-test SHA3-512("NDS.VSET.v2"+5×0 ‖ bytes), and the
 *         3-entry fixture hash == the independent oracle's value; the
 *         same three entries as a ruleset-1 snapshot == the oracle's v1
 *         hash.
 *      c. legacy functions reject ruleset 2 (encoded_len / encode /
 *         decode / hash); legacy dna_vset_hash_bytes keeps its pre-HF-6
 *         behaviour (v1 tag, header not read) — pinned as such.
 *      d. v2 rejects: nonzero seed, duplicate voter_id, duplicate
 *         validator_id, duplicate consensus_pk, all-zero validator_id,
 *         all-zero owner_fp, voter_id ≠
 *         SHA3-512(pk)[0..31] (encode AND decode), ruleset 3, bad
 *         max_ruleset, truncated / trailing bytes, hash_bytes_ex bounds.
 *      e. the v2 u16 boundary: 128 entries = 354638 bytes round-trip.
 *
 * Section 6 fixture bytes: fill(label, n) = SHA3-512(label ‖ u32 BE 0) ‖
 * SHA3-512(label ‖ u32 BE 1) ‖ … truncated to n bytes. The section-6
 * hash pins come from the independent python oracle
 * shared/dnac/tests/valbind_oracle.py (full output:
 * shared/dnac/tests/valbind_oracle_out.txt; each constant names its line).
 *
 * @file test_vset_wire.c
 */

#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"

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

static int hex_eq(const uint8_t h[64], const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

/* ── Pinned python3-oracle literals ─────────────────────────────────── */
/* Re-derived 2026-09-30 for the NDS. tag rename (decision
 * 2026-09-30-tag-rebrand-nds.md). */
static const char *KAT_SNAP_A =
    "6b3d7392000589c3f523399d92ddcaa9872f6b56f23687c459cc3e9908606812"
    "f5c465d221fdbfe825110b073c935bf0eec998eead2cafd343d3a1051fea517b";
static const char *KAT_SNAP_B =
    "b8f40b99735f0cea3dfe4c3a50a6d365ca74c6ef3066cbc3b4926d43ab65053d"
    "7b275ff64039842df05a9ee99dd73f05c58a42a62ec96364007895aa2e69de10";

#define SNAP_A_LEN 5362u
#define SNAP_B_LEN 2720u

/**
 * Oracle fixture builder. Entry i:
 *   voter_id = (i+1) repeated 32×, pubkey = (0xA0+i) repeated 2592×,
 *   total_stake = 2000000000000000 - i, self_bond = 1000000000000000,
 *   commission_bps = 500 + i.
 * Valid for the small oracle fixtures only (n <= 2 keeps 0xA0+i in range).
 */
static dna_vset_snapshot_t *make_fixture(uint64_t epoch, uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    if (!s) return NULL;
    s->epoch             = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    memset(s->sortition_seed, 0, DNA_VSET_SEED_LEN);
    for (uint16_t i = 0; i < n; i++) {
        memset(s->entries[i].voter_id, (uint8_t)(i + 1),
               DNA_VSET_VOTER_ID_LEN);
        memset(s->entries[i].pubkey, (uint8_t)(0xA0 + i), DNA_VSET_PUBKEY_LEN);
        s->entries[i].total_stake    = 2000000000000000ULL - i;
        s->entries[i].self_bond      = 1000000000000000ULL;
        s->entries[i].commission_bps = (uint16_t)(500 + i);
    }
    return s;
}

/** Large-set builder: n distinct entries, valid for n up to 255. */
static void fill_big(dna_vset_entry_t *ents, uint16_t n) {
    for (uint16_t i = 0; i < n; i++) {
        memset(ents[i].voter_id, (uint8_t)(i + 1), DNA_VSET_VOTER_ID_LEN);
        memset(ents[i].pubkey, (uint8_t)i, DNA_VSET_PUBKEY_LEN);
        ents[i].total_stake    = 9000000000000000ULL - i;
        ents[i].self_bond      = 1000000000000000ULL;
        ents[i].commission_bps = (uint16_t)(100 + i);
    }
}

/* ── 1 + 2: oracle KATs and round-trip byte identity ────────────────── */

static int test_kats_and_roundtrip(void) {
    struct { uint64_t epoch; uint16_t n; size_t len; const char *kat;
             const char *name; } fx[2] = {
        { 720,  2, SNAP_A_LEN, KAT_SNAP_A, "fixture A" },
        { 1440, 1, SNAP_B_LEN, KAT_SNAP_B, "fixture B" },
    };

    for (int f = 0; f < 2; f++) {
        dna_vset_snapshot_t *s = make_fixture(fx[f].epoch, fx[f].n);
        CHECK(s != NULL, "alloc fixture");

        size_t need = dna_vset_encoded_len(s);
        CHECK(need == fx[f].len, "encoded length drifted"); OK();

        uint8_t *buf = malloc(need);
        CHECK(buf != NULL, "alloc buf");
        size_t written = 0;
        CHECK(dna_vset_encode(s, buf, need, &written) == 0, "encode");
        CHECK(written == fx[f].len, "written length"); OK();

        uint8_t h[DNA_VSET_HASH_LEN];
        CHECK(dna_vset_hash(s, h) == 0, "hash");
        CHECK(hex_eq(h, fx[f].kat, fx[f].name), "snapshot hash KAT"); OK();

        /* The bytes-level variant must agree with the struct-level one. */
        uint8_t hb[DNA_VSET_HASH_LEN];
        CHECK(dna_vset_hash_bytes(buf, written, hb) == 0, "hash_bytes");
        CHECK(memcmp(h, hb, DNA_VSET_HASH_LEN) == 0,
              "hash_bytes != hash"); OK();

        /* Round-trip: decode then re-encode must be byte-identical. */
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(buf, written, &d) == 0, "decode");
        CHECK(d->epoch == fx[f].epoch, "epoch round-trip"); OK();
        CHECK(d->active_count == fx[f].n, "count round-trip"); OK();
        CHECK(d->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
              "ruleset round-trip"); OK();
        for (uint16_t i = 0; i < fx[f].n; i++) {
            CHECK(memcmp(d->entries[i].voter_id, s->entries[i].voter_id,
                         DNA_VSET_VOTER_ID_LEN) == 0, "voter_id"); OK();
            CHECK(memcmp(d->entries[i].pubkey, s->entries[i].pubkey,
                         DNA_VSET_PUBKEY_LEN) == 0, "pubkey"); OK();
            CHECK(d->entries[i].total_stake == s->entries[i].total_stake,
                  "total_stake"); OK();
            CHECK(d->entries[i].self_bond == s->entries[i].self_bond,
                  "self_bond"); OK();
            CHECK(d->entries[i].commission_bps ==
                  s->entries[i].commission_bps, "commission_bps"); OK();
        }
        uint8_t *buf2 = malloc(need);
        CHECK(buf2 != NULL, "alloc buf2");
        size_t w2 = 0;
        CHECK(dna_vset_encode(d, buf2, need, &w2) == 0, "re-encode");
        CHECK(w2 == written && memcmp(buf, buf2, written) == 0,
              "round-trip not byte-identical"); OK();

        /* A short destination must reject, not truncate. */
        CHECK(dna_vset_encode(s, buf2, need - 1, NULL) != 0,
              "encode accepted a short buffer"); OK();

        free(buf2);
        dna_vset_free(&d);
        CHECK(d == NULL, "free did not NULL the pointer"); OK();
        free(buf);
        dna_vset_free(&s);
    }
    return 0;
}

/* ── 3: structural negatives ────────────────────────────────────────── */

static int test_negatives(void) {
    dna_vset_snapshot_t *s = make_fixture(720, 2);
    CHECK(s != NULL, "alloc");
    size_t need = dna_vset_encoded_len(s);
    uint8_t *buf = malloc(need + 1);
    CHECK(buf != NULL, "alloc");
    CHECK(dna_vset_encode(s, buf, need, NULL) == 0, "encode");

    /* -- count 0 ---------------------------------------------------- */
    CHECK(dna_vset_alloc(0) == NULL, "alloc(0) succeeded"); OK();
    {
        dna_vset_snapshot_t z;
        memset(&z, 0, sizeof(z));
        z.epoch = 720;
        z.selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        z.active_count = 0;
        z.entries = s->entries;                 /* non-NULL, count is 0 */
        uint8_t small[DNA_VSET_HDR_LEN];
        CHECK(dna_vset_encoded_len(&z) == 0, "len(count 0)"); OK();
        CHECK(dna_vset_encode(&z, small, sizeof(small), NULL) != 0,
              "encoded a zero-count snapshot"); OK();
    }
    {   /* forged header: count 0, otherwise a well-formed 78-byte body */
        uint8_t hdr[DNA_VSET_HDR_LEN];
        memcpy(hdr, buf, DNA_VSET_HDR_LEN);
        hdr[8] = 0; hdr[9] = 0;
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(hdr, sizeof(hdr), &d) != 0,
              "decoded a zero-count header"); OK();
    }

    /* -- count 129 (over DNA_MAX_ACTIVE_VALIDATORS) ------------------ */
    CHECK(DNA_MAX_ACTIVE_VALIDATORS == 128, "ceiling changed"); OK();
    CHECK(dna_vset_alloc(129) == NULL, "alloc(129) succeeded"); OK();
    {
        dna_vset_entry_t *ents = calloc(129, sizeof(*ents));
        CHECK(ents != NULL, "alloc 129");
        fill_big(ents, 129);
        dna_vset_snapshot_t big;
        memset(&big, 0, sizeof(big));
        big.epoch = 720;
        big.selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        big.active_count = 129;
        big.entries = ents;
        uint8_t small[DNA_VSET_HDR_LEN];
        CHECK(dna_vset_encoded_len(&big) == 0, "len(129)"); OK();
        CHECK(dna_vset_encode(&big, small, sizeof(small), NULL) != 0,
              "encoded a 129-entry snapshot"); OK();
        free(ents);
    }
    {   /* forged length field: a full-size 129-entry buffer must still
         * reject on the COUNT, before any allocation. */
        size_t n129 = (size_t)DNA_VSET_HDR_LEN + 129u * DNA_VSET_ENTRY_LEN;
        uint8_t *b129 = calloc(1, n129);
        CHECK(b129 != NULL, "alloc 129 buf");
        memcpy(b129, buf, DNA_VSET_HDR_LEN);
        b129[8] = 0; b129[9] = 129;
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(b129, n129, &d) != 0,
              "decoded a 129-entry buffer"); OK();
        free(b129);
    }

    /* -- length exactness ------------------------------------------- */
    {
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(buf, need - 1, &d) != 0,
              "decoded a truncated buffer"); OK();
        buf[need] = 0x00;
        CHECK(dna_vset_decode(buf, need + 1, &d) != 0,
              "decoded a buffer with a trailing byte"); OK();
        CHECK(dna_vset_decode(buf, 0, &d) != 0, "decoded 0 bytes"); OK();
        CHECK(dna_vset_decode(buf, DNA_VSET_HDR_LEN - 1, &d) != 0,
              "decoded a sub-header buffer"); OK();
    }

    /* -- duplicate voter_id ----------------------------------------- */
    {
        dna_vset_snapshot_t *m = make_fixture(720, 2);
        CHECK(m != NULL, "alloc");
        memcpy(m->entries[1].voter_id, m->entries[0].voter_id,
               DNA_VSET_VOTER_ID_LEN);
        uint8_t *b = malloc(need);
        CHECK(b != NULL, "alloc");
        CHECK(dna_vset_encode(m, b, need, NULL) != 0,
              "encoded a duplicate voter_id"); OK();
        /* Forge it on the wire too — decode must reject independently. */
        memcpy(b, buf, need);
        memcpy(b + DNA_VSET_HDR_LEN + DNA_VSET_ENTRY_LEN,
               b + DNA_VSET_HDR_LEN, DNA_VSET_VOTER_ID_LEN);
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(b, need, &d) != 0,
              "decoded a duplicate voter_id"); OK();
        free(b);
        dna_vset_free(&m);
    }

    /* -- duplicate pubkey ------------------------------------------- */
    {
        dna_vset_snapshot_t *m = make_fixture(720, 2);
        CHECK(m != NULL, "alloc");
        memcpy(m->entries[1].pubkey, m->entries[0].pubkey,
               DNA_VSET_PUBKEY_LEN);
        uint8_t *b = malloc(need);
        CHECK(b != NULL, "alloc");
        CHECK(dna_vset_encode(m, b, need, NULL) != 0,
              "encoded a duplicate pubkey"); OK();
        memcpy(b, buf, need);
        memcpy(b + DNA_VSET_HDR_LEN + DNA_VSET_ENTRY_LEN +
                   DNA_VSET_VOTER_ID_LEN,
               b + DNA_VSET_HDR_LEN + DNA_VSET_VOTER_ID_LEN,
               DNA_VSET_PUBKEY_LEN);
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(b, need, &d) != 0,
              "decoded a duplicate pubkey"); OK();
        free(b);
        dna_vset_free(&m);
    }

    /* -- ruleset 0 (INVALID) and 2 (reserved) ------------------------ */
    {
        uint32_t bad[2] = { 0u, 2u };
        for (int k = 0; k < 2; k++) {
            dna_vset_snapshot_t *m = make_fixture(720, 2);
            CHECK(m != NULL, "alloc");
            m->selection_ruleset = bad[k];
            uint8_t *b = malloc(need);
            CHECK(b != NULL, "alloc");
            CHECK(dna_vset_encode(m, b, need, NULL) != 0,
                  "encoded a rejected ruleset"); OK();
            memcpy(b, buf, need);
            b[10] = (uint8_t)(bad[k] >> 24); b[11] = (uint8_t)(bad[k] >> 16);
            b[12] = (uint8_t)(bad[k] >> 8);  b[13] = (uint8_t)bad[k];
            dna_vset_snapshot_t *d = NULL;
            CHECK(dna_vset_decode(b, need, &d) != 0,
                  "decoded a rejected ruleset"); OK();
            free(b);
            dna_vset_free(&m);
        }
    }

    /* -- reserved seed slot must stay all-zero under TOPN_V1 --------- */
    {
        dna_vset_snapshot_t *m = make_fixture(720, 2);
        CHECK(m != NULL, "alloc");
        m->sortition_seed[63] = 0x01;          /* last byte, worst case */
        uint8_t *b = malloc(need);
        CHECK(b != NULL, "alloc");
        CHECK(dna_vset_encode(m, b, need, NULL) != 0,
              "encoded a nonzero reserved seed"); OK();
        memcpy(b, buf, need);
        b[14 + 63] ^= 0x01;
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_decode(b, need, &d) != 0,
              "decoded a nonzero reserved seed"); OK();
        free(b);
        dna_vset_free(&m);
    }

    /* -- NULL guards -------------------------------------------------- */
    {
        uint8_t h[DNA_VSET_HASH_LEN];
        dna_vset_snapshot_t *d = NULL;
        CHECK(dna_vset_encode(NULL, buf, need, NULL) != 0, "encode NULL"); OK();
        CHECK(dna_vset_encode(s, NULL, need, NULL) != 0, "encode NULL dst"); OK();
        CHECK(dna_vset_decode(NULL, need, &d) != 0, "decode NULL src"); OK();
        CHECK(dna_vset_decode(buf, need, NULL) != 0, "decode NULL out"); OK();
        CHECK(dna_vset_hash(NULL, h) != 0, "hash NULL"); OK();
        CHECK(dna_vset_hash_bytes(buf, 0, h) != 0, "hash_bytes 0"); OK();
        CHECK(dna_vset_hash_bytes(buf, DNA_VSET_MAX_ENC_LEN + 1, h) != 0,
              "hash_bytes over cap"); OK();
        dna_vset_free(NULL);            /* must not crash */
        OK();
    }

    free(buf);
    dna_vset_free(&s);
    return 0;
}

/* ── 5: the u16 count boundary — 128 entries ────────────────────────── */

static int test_boundary_128(void) {
    dna_vset_snapshot_t *s = dna_vset_alloc(DNA_MAX_ACTIVE_VALIDATORS);
    CHECK(s != NULL, "alloc 128");
    s->epoch = 2160;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    fill_big(s->entries, DNA_MAX_ACTIVE_VALIDATORS);

    size_t need = dna_vset_encoded_len(s);
    CHECK(need == DNA_VSET_MAX_ENC_LEN, "128-entry length != max"); OK();
    CHECK(need == 338254u, "max encoding drifted"); OK();

    uint8_t *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b1 && b2, "alloc");
    CHECK(dna_vset_encode(s, b1, need, NULL) == 0, "encode 128"); OK();

    dna_vset_snapshot_t *d = NULL;
    CHECK(dna_vset_decode(b1, need, &d) == 0, "decode 128"); OK();
    CHECK(d->active_count == DNA_MAX_ACTIVE_VALIDATORS, "count 128"); OK();
    CHECK(dna_vset_encode(d, b2, need, NULL) == 0, "re-encode 128");
    CHECK(memcmp(b1, b2, need) == 0, "128 round-trip not byte-identical");
    OK();

    dna_vset_free(&d);
    free(b1); free(b2);
    dna_vset_free(&s);
    return 0;
}

/* ── 6: HF-6 slice 1 — ruleset 2 (INERT) ────────────────────────────── */

static int fill(const char *label, uint8_t *out, size_t n) {
    size_t ll = strlen(label);
    if (ll > 64) return -1;
    uint8_t pre[64 + 4];
    uint8_t h[64];
    memcpy(pre, label, ll);
    size_t done = 0;
    for (uint32_t i = 0; done < n; i++) {
        pre[ll + 0] = (uint8_t)(i >> 24); pre[ll + 1] = (uint8_t)(i >> 16);
        pre[ll + 2] = (uint8_t)(i >> 8);  pre[ll + 3] = (uint8_t)i;
        if (qgp_sha3_512(pre, ll + 4, h) != 0) return -1;
        size_t take = (n - done < 64) ? (n - done) : 64;
        memcpy(out + done, h, take);
        done += take;
    }
    return 0;
}

/* Oracle pins — shared/dnac/tests/valbind_oracle.py. */
/* valbind_oracle_out.txt line "vset_v2.snapshot_hash" */
static const char *PIN_VSET_V2_3 =
    "dcc5b64dd912550cb3703bdb176dd46ba2582966062705190bf6b92c2f7adad0"
    "66cf36848e2e885d5369f51ebdfa88748dc0367320e597260e92c9db991a36aa";
/* valbind_oracle_out.txt line "vset_v1.snapshot_hash" (same 3 entries,
 * ruleset 1, no validator_id / owner_fp) */
static const char *PIN_VSET_V1_3 =
    "1fdf0f39f824450048db3f69d9c1b89a6fa398ba3090860ad29441fe034c9aa6"
    "090813c0060977457421fe85d6b7f2466874605cb6d8cc4b881d26d748188885";

static void set_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/** voter_id = SHA3-512(pubkey)[0..31] — the ruleset-2 binding. */
static int bind_voter(dna_vset_entry_t *e) {
    uint8_t d[64];
    if (qgp_sha3_512(e->pubkey, DNA_VSET_PUBKEY_LEN, d) != 0) return -1;
    memcpy(e->voter_id, d, DNA_VSET_VOTER_ID_LEN);
    return 0;
}

/**
 * Ruleset-2 fixture, entry i (labels with the decimal index appended):
 *   consensus_pk = fill("pk<i>", 2592), voter_id = SHA3-512(pk)[0..31],
 *   validator_id = fill("vid<i>", 64), owner_fp = fill("own<i>", 64),
 *   total_stake = 10^15 + i, self_bond = 2·10^14, commission = 500 + i.
 * The codec checks no entry order (vset_wire.h honest label); entries are
 * encoded in index order 0, 1, 2, ….
 */
static dna_vset_snapshot_t *make_v2(uint64_t epoch, uint16_t n) {
    dna_vset_snapshot_t *s = dna_vset_alloc(n);
    if (!s) return NULL;
    s->epoch             = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V2;
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        char lab[16];
        snprintf(lab, sizeof(lab), "pk%u", (unsigned)i);
        if (fill(lab, e->pubkey, DNA_VSET_PUBKEY_LEN) != 0) goto fail;
        if (bind_voter(e) != 0) goto fail;
        snprintf(lab, sizeof(lab), "vid%u", (unsigned)i);
        if (fill(lab, e->validator_id, DNA_VSET_VALIDATOR_ID_LEN) != 0)
            goto fail;
        snprintf(lab, sizeof(lab), "own%u", (unsigned)i);
        if (fill(lab, e->owner_fp, DNA_VSET_OWNER_FP_LEN) != 0) goto fail;
        e->total_stake    = 1000000000000000ULL + i;
        e->self_bond      = 200000000000000ULL;
        e->commission_bps = (uint16_t)(500 + i);
    }
    return s;
fail:
    dna_vset_free(&s);
    return NULL;
}

/* 6a — every ruleset-1 output is unchanged through the `_ex` path. */
static int test_v1_unchanged(void) {
    dna_vset_snapshot_t *s = make_fixture(720, 2);
    CHECK(s != NULL, "alloc");
    size_t need = dna_vset_encoded_len(s);
    CHECK(need == SNAP_A_LEN, "v1 length"); OK();
    CHECK(dna_vset_encoded_len_ex(s, 1) == SNAP_A_LEN &&
          dna_vset_encoded_len_ex(s, 2) == SNAP_A_LEN,
          "v1 length through _ex"); OK();

    uint8_t *b0 = malloc(need), *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b0 && b1 && b2, "alloc");
    CHECK(dna_vset_encode(s, b0, need, NULL) == 0, "encode"); OK();
    CHECK(dna_vset_encode_ex(s, 1, b1, need, NULL) == 0, "encode_ex 1");
    OK();
    CHECK(dna_vset_encode_ex(s, 2, b2, need, NULL) == 0, "encode_ex 2");
    OK();
    CHECK(memcmp(b0, b1, need) == 0 && memcmp(b0, b2, need) == 0,
          "v1 bytes differ through _ex"); OK();

    uint8_t h[DNA_VSET_HASH_LEN];
    CHECK(dna_vset_hash_ex(s, 1, h) == 0, "hash_ex 1");
    CHECK(hex_eq(h, KAT_SNAP_A, "fixture A, hash_ex 1"), "KAT"); OK();
    CHECK(dna_vset_hash_ex(s, 2, h) == 0, "hash_ex 2");
    CHECK(hex_eq(h, KAT_SNAP_A, "fixture A, hash_ex 2"), "KAT"); OK();
    CHECK(dna_vset_hash_bytes_ex(b0, need, 1, h) == 0, "hash_bytes_ex 1");
    CHECK(hex_eq(h, KAT_SNAP_A, "fixture A, hash_bytes_ex 1"), "KAT"); OK();
    CHECK(dna_vset_hash_bytes_ex(b0, need, 2, h) == 0, "hash_bytes_ex 2");
    CHECK(hex_eq(h, KAT_SNAP_A, "fixture A, hash_bytes_ex 2"), "KAT"); OK();

    /* v1 decode (legacy and _ex 2) leaves the v2-only fields zero. */
    for (uint32_t mx = 1; mx <= 2; mx++) {
        dna_vset_snapshot_t *d = NULL;
        CHECK((mx == 1 ? dna_vset_decode(b0, need, &d)
                       : dna_vset_decode_ex(b0, need, mx, &d)) == 0,
              "v1 decode");
        for (uint16_t i = 0; i < d->active_count; i++) {
            uint8_t z = 0;
            for (size_t k = 0; k < DNA_VSET_VALIDATOR_ID_LEN; k++)
                z |= d->entries[i].validator_id[k];
            for (size_t k = 0; k < DNA_VSET_OWNER_FP_LEN; k++)
                z |= d->entries[i].owner_fp[k];
            CHECK(z == 0, "v1 decode set validator_id / owner_fp"); OK();
        }
        dna_vset_free(&d);
    }

    /* The v1 encoder fails closed on a nonzero validator_id / owner_fp:
     * v1 has no wire slot, so silently dropping them is forbidden. */
    for (int which = 0; which < 2; which++) {
        dna_vset_snapshot_t *m = make_fixture(720, 2);
        CHECK(m != NULL, "alloc");
        if (which == 0) m->entries[1].validator_id[0]  = 0x01;
        else            m->entries[1].owner_fp[63]     = 0x01;
        CHECK(dna_vset_encoded_len(m) == 0, "v1 len accepted v2 field");
        OK();
        CHECK(dna_vset_encode(m, b1, need, NULL) != 0,
              "v1 encode accepted v2 field"); OK();
        CHECK(dna_vset_encode_ex(m, 2, b1, need, NULL) != 0,
              "v1 encode_ex(2) accepted v2 field"); OK();
        CHECK(dna_vset_hash(m, h) != 0, "v1 hash accepted v2 field"); OK();
        CHECK(dna_vset_hash_ex(m, 2, h) != 0,
              "v1 hash_ex(2) accepted v2 field"); OK();
        dna_vset_free(&m);
    }

    free(b0); free(b1); free(b2);
    dna_vset_free(&s);
    return 0;
}

/* 6b + 6c — ruleset-2 round-trip, hash domain, legacy rejects. */
static int test_v2_roundtrip(void) {
    CHECK(DNA_VSET_ENTRY_LEN_V2 == 2770, "v2 entry length"); OK();
    CHECK(DNA_VSET_MAX_ENC_LEN_V2 == 354638u, "v2 max encoding"); OK();
    CHECK(DNA_VSET_MAX_ENC_LEN == 338254u, "v1 max encoding moved"); OK();

    dna_vset_snapshot_t *s = make_v2(1440, 3);
    CHECK(s != NULL, "make_v2");
    const size_t want = (size_t)DNA_VSET_HDR_LEN + 3u * DNA_VSET_ENTRY_LEN_V2;
    size_t need = dna_vset_encoded_len_ex(s, 2);
    CHECK(need == want && want == 8388u, "v2 length"); OK();

    uint8_t *buf = malloc(need), *buf2 = malloc(need);
    CHECK(buf && buf2, "alloc");
    size_t written = 0;
    CHECK(dna_vset_encode_ex(s, 2, buf, need, &written) == 0 &&
          written == need, "v2 encode"); OK();
    CHECK(dna_vset_encode_ex(s, 2, buf2, need - 1, NULL) != 0,
          "v2 encode into a short buffer"); OK();

    /* Header layout is the v1 layout with ruleset 2. */
    CHECK(buf[8] == 0 && buf[9] == 3, "count"); OK();
    CHECK(buf[10] == 0 && buf[11] == 0 && buf[12] == 0 && buf[13] == 2,
          "ruleset 2 in header"); OK();
    /* Entry 1 field offsets (design §6.5). */
    {
        const uint8_t *e = buf + DNA_VSET_HDR_LEN + DNA_VSET_ENTRY_LEN_V2;
        CHECK(memcmp(e, s->entries[1].voter_id, 32) == 0, "voter_id @0");
        OK();
        CHECK(memcmp(e + 32, s->entries[1].validator_id, 64) == 0,
              "validator_id @32"); OK();
        CHECK(memcmp(e + 96, s->entries[1].owner_fp, 64) == 0,
              "owner_fp @96"); OK();
        CHECK(memcmp(e + 160, s->entries[1].pubkey, 2592) == 0,
              "consensus_pk @160"); OK();
        CHECK(e[2752 + 7] == 0x01 && e[2768] == 0x01 && e[2769] == 0xF5,
              "stake / commission BE tail (10^15+1, 501)"); OK();
    }

    /* Decode → re-encode byte identity, field by field. */
    dna_vset_snapshot_t *d = NULL;
    CHECK(dna_vset_decode_ex(buf, need, 2, &d) == 0, "v2 decode"); OK();
    CHECK(d->epoch == 1440 && d->active_count == 3 &&
          d->selection_ruleset == DNA_VSET_RULESET_TOPN_V2, "v2 header");
    OK();
    for (uint16_t i = 0; i < 3; i++) {
        const dna_vset_entry_t *a = &s->entries[i], *b = &d->entries[i];
        CHECK(memcmp(a->voter_id, b->voter_id, 32) == 0 &&
              memcmp(a->validator_id, b->validator_id, 64) == 0 &&
              memcmp(a->owner_fp, b->owner_fp, 64) == 0 &&
              memcmp(a->pubkey, b->pubkey, 2592) == 0 &&
              a->total_stake == b->total_stake &&
              a->self_bond == b->self_bond &&
              a->commission_bps == b->commission_bps, "v2 entry fields");
        OK();
    }
    CHECK(dna_vset_encode_ex(d, 2, buf2, need, NULL) == 0 &&
          memcmp(buf, buf2, need) == 0, "v2 round-trip not identical"); OK();
    dna_vset_free(&d);

    /* Hash domain: SHA3-512("NDS.VSET.v2" + 5×0 ‖ bytes), in-test. */
    uint8_t h[DNA_VSET_HASH_LEN], hb[DNA_VSET_HASH_LEN], ho[DNA_VSET_HASH_LEN];
    {
        uint8_t *pre = malloc(16 + need);
        CHECK(pre != NULL, "alloc");
        memset(pre, 0, 16);
        memcpy(pre, "NDS.VSET.v2", 11);
        memcpy(pre + 16, buf, need);
        CHECK(qgp_sha3_512(pre, 16 + need, ho) == 0, "sha3");
        free(pre);
    }
    CHECK(dna_vset_hash_ex(s, 2, h) == 0, "v2 hash_ex"); OK();
    CHECK(dna_vset_hash_bytes_ex(buf, need, 2, hb) == 0, "v2 hash_bytes_ex");
    OK();
    CHECK(memcmp(h, ho, 64) == 0 && memcmp(hb, ho, 64) == 0,
          "v2 hash != in-test tagged SHA3"); OK();
    /* Fixture: epoch 1440; pk0..2, vid0..2, own0..2; total 10^15+i,
     * self 2*10^14, commission 500+i; entries in index order. */
    CHECK(hex_eq(h, PIN_VSET_V2_3, "vset_v2.snapshot_hash"),
          "v2 snapshot hash != oracle"); OK();

    /* The same three entries as a ruleset-1 snapshot (validator_id /
     * owner_fp cleared — v1 has no slot) == the oracle's v1 hash. */
    {
        dna_vset_snapshot_t *v1 = make_v2(1440, 3);
        CHECK(v1 != NULL, "make_v2");
        v1->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        for (uint16_t i = 0; i < 3; i++) {
            memset(v1->entries[i].validator_id, 0, DNA_VSET_VALIDATOR_ID_LEN);
            memset(v1->entries[i].owner_fp, 0, DNA_VSET_OWNER_FP_LEN);
        }
        CHECK(dna_vset_encoded_len(v1) == 8004u, "v1 3-entry length"); OK();
        uint8_t h1[DNA_VSET_HASH_LEN];
        CHECK(dna_vset_hash(v1, h1) == 0, "v1 hash");
        CHECK(hex_eq(h1, PIN_VSET_V1_3, "vset_v1.snapshot_hash"),
              "v1 snapshot hash != oracle"); OK();
        CHECK(dna_vset_hash_ex(v1, 2, h1) == 0 &&
              hex_eq(h1, PIN_VSET_V1_3, "vset_v1.snapshot_hash via _ex(2)"),
              "v1 hash via _ex(2) != oracle"); OK();
        dna_vset_free(&v1);
    }

    /* 6c — legacy functions keep rejecting ruleset 2. */
    CHECK(dna_vset_encoded_len(s) == 0, "legacy len accepted v2"); OK();
    CHECK(dna_vset_encode(s, buf2, need, NULL) != 0,
          "legacy encode accepted v2"); OK();
    CHECK(dna_vset_hash(s, hb) != 0, "legacy hash accepted v2"); OK();
    CHECK(dna_vset_encoded_len_ex(s, 1) == 0, "_ex(1) len accepted v2");
    OK();
    {
        dna_vset_snapshot_t *x = NULL;
        CHECK(dna_vset_decode(buf, need, &x) != 0,
              "legacy decode accepted v2"); OK();
        CHECK(dna_vset_decode_ex(buf, need, 1, &x) != 0,
              "decode_ex(1) accepted v2"); OK();
        CHECK(x == NULL, "failed decode wrote *out"); OK();
    }
    CHECK(dna_vset_hash_bytes_ex(buf, need, 1, hb) != 0,
          "hash_bytes_ex(1) accepted v2"); OK();
    /* Legacy dna_vset_hash_bytes is NOT ruleset-aware (pre-HF-6 body,
     * unchanged): it hashes these bytes under the v1 tag. Pinned so a
     * future change to it is a visible, deliberate one. */
    CHECK(dna_vset_hash_bytes(buf, need, hb) == 0,
          "legacy hash_bytes behaviour changed"); OK();
    CHECK(memcmp(hb, ho, 64) != 0, "v1 and v2 tags collide"); OK();

    free(buf); free(buf2);
    dna_vset_free(&s);
    return 0;
}

/* 6d — ruleset-2 structural rejects. */
static int test_v2_negatives(void) {
    dna_vset_snapshot_t *s = make_v2(1440, 3);
    CHECK(s != NULL, "make_v2");
    size_t need = dna_vset_encoded_len_ex(s, 2);
    CHECK(need != 0, "len");
    uint8_t *buf = malloc(need + 1), *b = malloc(need + 1);
    CHECK(buf && b, "alloc");
    CHECK(dna_vset_encode_ex(s, 2, buf, need, NULL) == 0, "encode");
    uint8_t h[DNA_VSET_HASH_LEN];
    const size_t E = DNA_VSET_ENTRY_LEN_V2, HD = DNA_VSET_HDR_LEN;

#define DEC_REJECTS(bytes, n, what) do { \
        dna_vset_snapshot_t *x_ = NULL; \
        CHECK(dna_vset_decode_ex((bytes), (n), 2, &x_) != 0, (what)); \
        CHECK(x_ == NULL, "failed decode wrote *out"); OK(); \
    } while (0)

    /* -- nonzero seed (K6) ------------------------------------------- */
    {
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        m->sortition_seed[63] = 0x01;
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
              "v2 encoded a nonzero seed"); OK();
        CHECK(dna_vset_hash_ex(m, 2, h) != 0, "v2 hashed a nonzero seed");
        OK();
        dna_vset_free(&m);
        memcpy(b, buf, need);
        b[14] = 0x80;                          /* first seed byte */
        DEC_REJECTS(b, need, "v2 decoded a nonzero seed");
    }

    /* -- voter_id != SHA3-512(consensus_pk)[0..31] -------------------- */
    {
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        m->entries[2].voter_id[31] ^= 0x01;    /* last voter_id byte */
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
              "v2 encoded a mismatched voter_id"); OK();
        dna_vset_free(&m);
        memcpy(b, buf, need);
        b[HD + 2 * E + 31] ^= 0x01;
        DEC_REJECTS(b, need, "v2 decoded a mismatched voter_id");
        /* A pk change without the voter_id change is the same mismatch. */
        memcpy(b, buf, need);
        b[HD + 0 * E + 160 + 2591] ^= 0x01;    /* last pk byte, entry 0 */
        DEC_REJECTS(b, need, "v2 decoded a pk that no longer binds");
    }

    /* -- duplicate consensus_pk (and therefore duplicate voter_id: the
     *    binding makes an independent duplicate-voter_id case impossible
     *    to build without also failing the binding) ------------------- */
    {
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        memcpy(m->entries[2].pubkey, m->entries[0].pubkey,
               DNA_VSET_PUBKEY_LEN);
        memcpy(m->entries[2].voter_id, m->entries[0].voter_id,
               DNA_VSET_VOTER_ID_LEN);
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
              "v2 encoded a duplicate consensus_pk"); OK();
        dna_vset_free(&m);
        memcpy(b, buf, need);
        memcpy(b + HD + 2 * E, b + HD, 32);                  /* voter_id */
        memcpy(b + HD + 2 * E + 160, b + HD + 160, 2592);    /* pk       */
        DEC_REJECTS(b, need, "v2 decoded a duplicate consensus_pk");
    }

    /* -- duplicate voter_id with a binding-consistent pair: entry 2 keeps
     *    its own pk but copies entry 0's voter_id → rejected (binding
     *    and/or duplicate); pinned as a reject, whichever rule fires. --- */
    {
        memcpy(b, buf, need);
        memcpy(b + HD + 2 * E, b + HD, 32);
        DEC_REJECTS(b, need, "v2 decoded a duplicate voter_id");
    }

    /* -- duplicate validator_id ---------------------------------------- */
    {
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        memcpy(m->entries[1].validator_id, m->entries[0].validator_id,
               DNA_VSET_VALIDATOR_ID_LEN);
        CHECK(dna_vset_encoded_len_ex(m, 2) == 0,
              "v2 len accepted a duplicate validator_id"); OK();
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
              "v2 encoded a duplicate validator_id"); OK();
        dna_vset_free(&m);
        memcpy(b, buf, need);
        memcpy(b + HD + 1 * E + 32, b + HD + 32, 64);
        DEC_REJECTS(b, need, "v2 decoded a duplicate validator_id");
    }

    /* -- all-zero validator_id / owner_fp (both are SHA3-512 outputs in
     *    every legal state; zero = unset → fail closed) --------------- */
    for (int which = 0; which < 2; which++) {
        /* which 0: validator_id (entry off 32); 1: owner_fp (off 96) */
        const size_t off = which == 0 ? 32u : 96u;
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        if (which == 0)
            memset(m->entries[2].validator_id, 0, DNA_VSET_VALIDATOR_ID_LEN);
        else
            memset(m->entries[2].owner_fp, 0, DNA_VSET_OWNER_FP_LEN);
        CHECK(dna_vset_encoded_len_ex(m, 2) == 0,
              "v2 len accepted an all-zero validator_id / owner_fp"); OK();
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
              "v2 encoded an all-zero validator_id / owner_fp"); OK();
        CHECK(dna_vset_hash_ex(m, 2, h) != 0,
              "v2 hashed an all-zero validator_id / owner_fp"); OK();
        /* One nonzero byte is enough to be accepted (the rule is
         * "all-zero", not "has a zero byte"). */
        if (which == 0) m->entries[2].validator_id[63] = 0x01;
        else            m->entries[2].owner_fp[63]     = 0x01;
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) == 0,
              "v2 rejected a single-nonzero-byte field"); OK();
        dna_vset_free(&m);
        memcpy(b, buf, need);
        memset(b + HD + 2 * E + off, 0, 64);
        DEC_REJECTS(b, need,
                    "v2 decoded an all-zero validator_id / owner_fp");
    }

    /* -- duplicate owner_fp is ALLOWED (one owner may run several
     *    validators — design §5 "Sahip-başına tavan YOK") -------------- */
    {
        dna_vset_snapshot_t *m = make_v2(1440, 3);
        CHECK(m != NULL, "make_v2");
        memcpy(m->entries[1].owner_fp, m->entries[0].owner_fp,
               DNA_VSET_OWNER_FP_LEN);
        CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) == 0,
              "v2 rejected a shared owner_fp"); OK();
        dna_vset_free(&m);
    }

    /* -- rulesets: 0 and 3 under max 2; bad max_ruleset ---------------- */
    {
        const uint32_t bad[2] = { 0u, 3u };
        for (int k = 0; k < 2; k++) {
            dna_vset_snapshot_t *m = make_v2(1440, 3);
            CHECK(m != NULL, "make_v2");
            m->selection_ruleset = bad[k];
            CHECK(dna_vset_encode_ex(m, 2, b, need, NULL) != 0,
                  "v2 encoded ruleset 0/3"); OK();
            dna_vset_free(&m);
            memcpy(b, buf, need);
            set_be32(b + 10, bad[k]);
            DEC_REJECTS(b, need, "decoded ruleset 0/3");
            CHECK(dna_vset_hash_bytes_ex(b, need, 2, h) != 0,
                  "hash_bytes_ex accepted ruleset 0/3"); OK();
        }
        const uint32_t badmax[3] = { 0u, 3u, 0xFFFFFFFFu };
        for (int k = 0; k < 3; k++) {
            dna_vset_snapshot_t *x = NULL;
            CHECK(dna_vset_encoded_len_ex(s, badmax[k]) == 0,
                  "len_ex bad max"); OK();
            CHECK(dna_vset_encode_ex(s, badmax[k], b, need, NULL) != 0,
                  "encode_ex bad max"); OK();
            CHECK(dna_vset_decode_ex(buf, need, badmax[k], &x) != 0 &&
                  x == NULL, "decode_ex bad max"); OK();
            CHECK(dna_vset_hash_ex(s, badmax[k], h) != 0, "hash_ex bad max");
            OK();
            CHECK(dna_vset_hash_bytes_ex(buf, need, badmax[k], h) != 0,
                  "hash_bytes_ex bad max"); OK();
        }
    }

    /* -- length exactness ---------------------------------------------- */
    DEC_REJECTS(buf, need - 1, "v2 decoded a truncated buffer");
    buf[need] = 0x00;
    DEC_REJECTS(buf, need + 1, "v2 decoded a trailing byte");
    DEC_REJECTS(buf, HD - 1, "v2 decoded a sub-header buffer");
    {   /* a v1-length body under a v2 header (count 3) */
        size_t v1len = HD + 3u * DNA_VSET_ENTRY_LEN;
        DEC_REJECTS(buf, v1len, "v2 header with a v1-sized body");
    }

    /* -- hash_bytes_ex bounds ------------------------------------------ */
    CHECK(dna_vset_hash_bytes_ex(buf, HD - 1, 2, h) != 0,
          "hash_bytes_ex below the header"); OK();
    CHECK(dna_vset_hash_bytes_ex(NULL, need, 2, h) != 0,
          "hash_bytes_ex NULL buf"); OK();
    CHECK(dna_vset_hash_bytes_ex(buf, need, 2, NULL) != 0,
          "hash_bytes_ex NULL out"); OK();
    {
        size_t big = DNA_VSET_MAX_ENC_LEN_V2 + 1;
        uint8_t *bb = calloc(1, big);
        CHECK(bb != NULL, "alloc");
        set_be32(bb + 10, 2u);
        CHECK(dna_vset_hash_bytes_ex(bb, big, 2, h) != 0,
              "hash_bytes_ex over the v2 cap"); OK();
        CHECK(dna_vset_hash_bytes_ex(bb, big - 1, 2, h) == 0,
              "hash_bytes_ex at the v2 cap"); OK();
        set_be32(bb + 10, 1u);
        CHECK(dna_vset_hash_bytes_ex(bb, DNA_VSET_MAX_ENC_LEN + 1, 2, h) != 0,
              "v1 header over the v1 cap"); OK();
        CHECK(dna_vset_hash_bytes_ex(bb, DNA_VSET_MAX_ENC_LEN, 2, h) == 0,
              "v1 header at the v1 cap"); OK();
        free(bb);
    }

#undef DEC_REJECTS
    free(buf); free(b);
    dna_vset_free(&s);
    return 0;
}

/* 6e — the ruleset-2 u16 boundary: 128 entries. */
static int test_v2_boundary_128(void) {
    dna_vset_snapshot_t *s = make_v2(2160, DNA_MAX_ACTIVE_VALIDATORS);
    CHECK(s != NULL, "make_v2 128");
    size_t need = dna_vset_encoded_len_ex(s, 2);
    CHECK(need == DNA_VSET_MAX_ENC_LEN_V2 && need == 354638u,
          "128-entry v2 length != v2 max"); OK();
    uint8_t *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b1 && b2, "alloc");
    CHECK(dna_vset_encode_ex(s, 2, b1, need, NULL) == 0, "encode 128"); OK();
    dna_vset_snapshot_t *d = NULL;
    CHECK(dna_vset_decode_ex(b1, need, 2, &d) == 0, "decode 128"); OK();
    CHECK(dna_vset_encode_ex(d, 2, b2, need, NULL) == 0 &&
          memcmp(b1, b2, need) == 0, "128 v2 round-trip"); OK();
    uint8_t h[DNA_VSET_HASH_LEN];
    CHECK(dna_vset_hash_bytes_ex(b1, need, 2, h) == 0, "hash 128"); OK();
    dna_vset_free(&d);
    free(b1); free(b2);
    dna_vset_free(&s);
    return 0;
}

int main(void) {
    if (test_kats_and_roundtrip() != 0) return 1;
    if (test_negatives() != 0) return 1;
    if (test_boundary_128() != 0) return 1;
    if (test_v1_unchanged() != 0) return 1;
    if (test_v2_roundtrip() != 0) return 1;
    if (test_v2_negatives() != 0) return 1;
    if (test_v2_boundary_128() != 0) return 1;
    printf("test_vset_wire: %d checks OK\n", g_checks);
    return 0;
}
