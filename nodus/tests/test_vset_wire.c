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
 *   4. validate_bonds: below-minimum rejects, exactly-at-minimum accepts.
 *   5. The u16 count boundary: 128 distinct entries encode, decode and
 *      re-encode byte-identically.
 *
 * @file test_vset_wire.c
 */

#include "dnac/vset_wire.h"

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
static const char *KAT_SNAP_A =
    "475894349123cc8ab4eced0b47a5f55e97a18ab618c082623d21983d619b470c"
    "a8bde24fe1cec7d038ef19a14ef59729eefacf2371083d19865afbf3375969fd";
static const char *KAT_SNAP_B =
    "c00730cce1dc2489a01acdbe226886d7edfd76ea676570dcd157819abd96a463"
    "b1e2d3cc36c526af97493c546615ea307e67f53fb122124c4f2204d5e1e31ca4";

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

/* ── 4: validate_bonds ──────────────────────────────────────────────── */

static int test_bonds(void) {
    dna_vset_snapshot_t *s = make_fixture(720, 2);
    CHECK(s != NULL, "alloc");
    const uint64_t bond = 1000000000000000ULL;   /* both fixture entries */

    CHECK(dna_vset_validate_bonds(s, bond) == 0,
          "exactly-at-minimum rejected"); OK();
    CHECK(dna_vset_validate_bonds(s, bond - 1) == 0,
          "above-minimum rejected"); OK();
    CHECK(dna_vset_validate_bonds(s, bond + 1) != 0,
          "below-minimum accepted"); OK();
    CHECK(dna_vset_validate_bonds(s, 0) == 0, "zero minimum rejected"); OK();

    /* One under-bonded entry sinks the whole set. */
    s->entries[1].self_bond = bond - 1;
    CHECK(dna_vset_validate_bonds(s, bond) != 0,
          "one under-bonded entry accepted"); OK();
    CHECK(dna_vset_validate_bonds(NULL, bond) != 0, "NULL accepted"); OK();

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

int main(void) {
    if (test_kats_and_roundtrip() != 0) return 1;
    if (test_negatives() != 0) return 1;
    if (test_bonds() != 0) return 1;
    if (test_boundary_128() != 0) return 1;
    printf("test_vset_wire: %d checks OK\n", g_checks);
    return 0;
}
