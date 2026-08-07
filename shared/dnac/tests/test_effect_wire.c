/**
 * @file shared/dnac/tests/test_effect_wire.c
 * @brief Ledger V2 — round-trip, boundary, ordering and reject tests for
 *        the generic typed-effect RESULT codec
 *        (shared/dnac/effect_wire.{h,c}).
 *
 * Four properties are pinned here, in increasing order of importance:
 *
 *   1. CANONICALITY — exactly one encoding exists per result, and
 *      encode->decode->encode is byte-identical. Drift between encoder and
 *      decoder is a silent consensus break.
 *   2. FAIL-CLOSED — every malformed input is REJECTED (never clamped),
 *      after EVERY failing decode the view is fully zeroed, and after
 *      EVERY failing encode *written_out is 0. Output structs are
 *      pre-filled with 0xAA so a missing memset cannot pass silently.
 *   3. THE ORDER IS THE FORMAT — the encoder never sorts and never
 *      canonicalizes. A non-canonical or duplicated effect list is a
 *      REJECT, not a repaired encoding. The load-bearing case is the
 *      CROSS-KIND duplicate: because effect_kind is the MAJOR sort axis,
 *      two records sharing a logical key under different kinds are NOT
 *      adjacent, so only the explicit pairwise scan can see them.
 *   4. RESERVED-FIELD DISCIPLINE — expected_version outside
 *      EXISTS_VERSION and expected_vhash outside EXISTS_VHASH are
 *      rejected, so one result cannot have two encodings.
 *
 * KAT values come from an independent python3 hashlib.sha3_512 oracle
 * (effect_wire_oracle.py) written from the effect_wire.h specification.
 *
 * Buffers are HEAP allocated throughout: DNA_EFFECT_MAX_TOTAL_LEN is
 * 64 KiB and dna_effect_view_t is several KB, so the stack-local shape
 * used by smaller wire tests would not be safe here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/effect_wire.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int g_checks = 0;

#define CHECK(cond) do {                                                 \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
    } else {                                                             \
        g_checks++;                                                      \
    }                                                                    \
} while (0)

/* Every allocation below is checked; a NULL would otherwise crash the whole
 * binary and report as a segfault rather than a test failure. */
#define MUST_ALLOC(p) do {                                               \
    if (!(p)) {                                                          \
        fprintf(stderr, "FATAL %s:%d: allocation failed\n",              \
                __FILE__, __LINE__);                                     \
        exit(2);                                                         \
    }                                                                    \
} while (0)

#define HASH_LEN  DNA_EFFECT_HASH_LEN
#define MAXN      DNA_EFFECT_MAX_COUNT

/** Byte offset of record i. */
#define REC(i)  ((size_t)DNA_EFFECT_FIXED_HEAD + \
                 (size_t)(i) * (size_t)DNA_EFFECT_RECORD_LEN)

/* Field offsets WITHIN one record — restated here so a drift in the .c
 * layout shows up as a test failure rather than as a matching change. */
#define R_OP      0
#define R_KIND    4
#define R_PRE     5
#define R_VER     6
#define R_VHASH  14
#define R_KEYLEN 78
#define R_VALLEN 80

static uint8_t *buf_new(void) {
    uint8_t *b = calloc(1, (size_t)DNA_EFFECT_MAX_TOTAL_LEN + 16);
    MUST_ALLOC(b);
    return b;
}

static void print_hex(const char *label, const uint8_t *b, size_t len) {
    printf("%s (%zu bytes):\n  ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", b[i]);
        if ((i % 32) == 31 && i + 1 < len) printf("\n  ");
    }
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════
 * Fixture: a mutable description of one result. Every mutation test
 * copies a fixture, changes exactly one thing, and re-encodes.
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint16_t         n;
    dna_effect_hdr_t hdr[MAXN];
    uint8_t         *key[MAXN];   /* hdr[i].key_len bytes   */
    uint8_t         *val[MAXN];   /* hdr[i].value_len bytes */
} fixture_t;

static fixture_t *fx_alloc(void) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    return f;
}

static void fx_free(fixture_t *f) {
    if (!f) return;
    for (uint16_t i = 0; i < MAXN; i++) { free(f->key[i]); free(f->val[i]); }
    free(f);
}

/** Replace effect i's key blob (frees the old one). len 0 leaves NULL. */
static void fx_set_key(fixture_t *f, uint16_t i, uint32_t len, uint8_t seed) {
    free(f->key[i]);
    f->key[i] = NULL;
    if (len) {
        f->key[i] = malloc(len);
        MUST_ALLOC(f->key[i]);
        for (uint32_t j = 0; j < len; j++)
            f->key[i][j] = (uint8_t)(seed + j * 7u + i);
    }
    f->hdr[i].key_len = (uint16_t)len;
}

/** Replace effect i's key blob with EXACT bytes. */
static void fx_key_bytes(fixture_t *f, uint16_t i, const uint8_t *b,
                         uint32_t len) {
    free(f->key[i]);
    f->key[i] = NULL;
    if (len) {
        f->key[i] = malloc(len);
        MUST_ALLOC(f->key[i]);
        memcpy(f->key[i], b, len);
    }
    f->hdr[i].key_len = (uint16_t)len;
}

/** Replace effect i's value blob (frees the old one). */
static void fx_set_val(fixture_t *f, uint16_t i, uint32_t len, uint8_t seed) {
    free(f->val[i]);
    f->val[i] = NULL;
    if (len) {
        f->val[i] = malloc(len);
        MUST_ALLOC(f->val[i]);
        for (uint32_t j = 0; j < len; j++)
            f->val[i][j] = (uint8_t)(seed + j * 13u + i);
    }
    f->hdr[i].value_len = len;
}

/** Replace effect i's value blob with EXACT bytes. */
static void fx_val_bytes(fixture_t *f, uint16_t i, const uint8_t *b,
                         uint32_t len) {
    free(f->val[i]);
    f->val[i] = NULL;
    if (len) {
        f->val[i] = malloc(len);
        MUST_ALLOC(f->val[i]);
        memcpy(f->val[i], b, len);
    }
    f->hdr[i].value_len = len;
}

/**
 * A structurally valid, CANONICAL n-effect fixture: one kind (SET) with
 * EXISTS, op ids strictly ascending, one-byte keys, small values. op_id is
 * the discriminator, so both the canonical order and logical-key
 * uniqueness hold whatever the key bytes are.
 */
static fixture_t *fx_new(uint16_t n) {
    fixture_t *f = fx_alloc();
    f->n = n;
    for (uint16_t i = 0; i < n; i++) {
        f->hdr[i].op_id       = 1u + i;
        f->hdr[i].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[i].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_set_key(f, i, 1 + (i % 4), (uint8_t)(0x10 + i));
        fx_set_val(f, i, 4, (uint8_t)(0x80 + i));
    }
    return f;
}

/** Deep copy, so a mutation never disturbs the base fixture. */
static fixture_t *fx_clone(const fixture_t *src) {
    fixture_t *f = fx_alloc();
    *f = *src;
    for (uint16_t i = 0; i < MAXN; i++) {
        f->key[i] = NULL;
        f->val[i] = NULL;
        if (src->hdr[i].key_len) {
            f->key[i] = malloc(src->hdr[i].key_len);
            MUST_ALLOC(f->key[i]);
            memcpy(f->key[i], src->key[i], src->hdr[i].key_len);
        }
        if (src->hdr[i].value_len) {
            f->val[i] = malloc(src->hdr[i].value_len);
            MUST_ALLOC(f->val[i]);
            memcpy(f->val[i], src->val[i], src->hdr[i].value_len);
        }
    }
    return f;
}

/** Build the encoder input array for a fixture. */
static void fx_input(const fixture_t *f, dna_effect_in_t *arr) {
    for (uint16_t i = 0; i < f->n; i++) {
        arr[i].hdr   = f->hdr[i];
        arr[i].key   = f->key[i];
        arr[i].value = f->val[i];
    }
}

/** Encode a fixture into `dst`. @return the encode return code. */
static int fx_encode(const fixture_t *f, uint8_t *dst, size_t cap,
                     size_t *written) {
    dna_effect_in_t *arr = calloc(MAXN, sizeof(*arr));
    MUST_ALLOC(arr);
    fx_input(f, arr);
    int rc = dna_effect_result_encode(arr, f->n, dst, cap, written);
    free(arr);
    return rc;
}

/** Encode a fixture, aborting loudly if it was supposed to be valid. */
static size_t fx_must_encode(const fixture_t *f, uint8_t *dst) {
    size_t w = 0;
    if (fx_encode(f, dst, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &w) != 0) {
        fprintf(stderr, "FATAL: fixture failed to encode\n");
        exit(2);
    }
    return w;
}

/* ── Failure-contract helpers ───────────────────────────────────────── */

/**
 * Decode must reject, and the view must be FULLY zeroed afterwards. The
 * view is pre-filled with 0xAA so a missing memset cannot pass silently.
 *
 * The whole-object memcmp below is DELIBERATE and is NOT the padding-
 * dependent struct comparison that field-by-field assertions replace
 * elsewhere in this file. It is a byte-level verification that the
 * decoder's memset covered every byte of the object: both operands are
 * explicitly byte-initialised (0xAA here, calloc for the reference) and
 * memset writes every byte, so padding is deterministic on both sides by
 * construction. Rewriting it field-by-field would WEAKEN it — it would
 * stop catching a field the memset missed or a hole left at 0xAA.
 */
static void expect_decode_reject(const uint8_t *src, size_t len,
                                 const char *what) {
    dna_effect_view_t *v = malloc(sizeof(*v));
    MUST_ALLOC(v);
    dna_effect_view_t *zero = calloc(1, sizeof(*zero));
    MUST_ALLOC(zero);

    memset(v, 0xAA, sizeof(*v));
    if (dna_effect_result_decode(src, len, v) != -1) {
        fprintf(stderr, "FAIL %s: decode ACCEPTED a malformed result\n", what);
        failures++;
    } else if (memcmp(v, zero, sizeof(*v)) != 0) {
        fprintf(stderr, "FAIL %s: view not fully zeroed after reject\n", what);
        failures++;
    } else {
        g_checks++;
    }
    /* The explicit probes the failure contract names, on top of the
     * whole-object compare: a zeroed view must be unmistakable. */
    CHECK(v->effect_count == 0);
    CHECK(v->buf          == NULL);
    CHECK(v->res_len      == 0);
    CHECK(v->eff[0].op_id == 0);
    CHECK(v->eff[0].effect_kind == 0);
    CHECK(v->key_off[0]   == 0);
    CHECK(v->val_off[0]   == 0);

    free(zero);
    free(v);
}

/** Encode must reject, and *written_out must be 0 (prefilled 0xdead). */
static void expect_encode_reject(const fixture_t *f, const char *what) {
    uint8_t *b = buf_new();
    size_t written = 0xdead;
    if (fx_encode(f, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &written) != -1) {
        fprintf(stderr, "FAIL %s: encode ACCEPTED an invalid result\n", what);
        failures++;
    } else if (written != 0) {
        fprintf(stderr, "FAIL %s: written_out not zeroed on reject\n", what);
        failures++;
    } else {
        g_checks++;
    }
    free(b);
}

/* ── Round trip ─────────────────────────────────────────────────────── */

/** Re-encode straight from a DECODED view's field values. */
static int view_reencode(const dna_effect_view_t *v, uint8_t *dst, size_t cap,
                         size_t *written) {
    dna_effect_in_t *arr = calloc(MAXN, sizeof(*arr));
    MUST_ALLOC(arr);
    for (uint16_t i = 0; i < v->effect_count; i++) {
        arr[i].hdr   = v->eff[i];
        arr[i].key   = v->buf + v->key_off[i];
        arr[i].value = v->eff[i].value_len ? v->buf + v->val_off[i] : NULL;
    }
    int rc = dna_effect_result_encode(arr, v->effect_count, dst, cap, written);
    free(arr);
    return rc;
}

/** Field-by-field comparison of one decoded record against a fixture. */
static void cmp_hdr(const dna_effect_hdr_t *got, const dna_effect_hdr_t *want) {
    /* FIELD-BY-FIELD, never memcmp over the struct: dna_effect_hdr_t has
     * padding after effect_kind/precond_tag and after key_len under every
     * ABI this project targets. A struct memcmp would compare those
     * padding bytes, which C leaves unspecified after a struct assignment
     * — the assertion would then pass or fail on padding rather than on
     * the seven wire fields it exists to check. */
    CHECK(got->op_id            == want->op_id);
    CHECK(got->effect_kind      == want->effect_kind);
    CHECK(got->precond_tag      == want->precond_tag);
    CHECK(got->expected_version == want->expected_version);
    CHECK(memcmp(got->expected_vhash, want->expected_vhash, HASH_LEN) == 0);
    CHECK(got->key_len          == want->key_len);
    CHECK(got->value_len        == want->value_len);
}

/** encode -> decode -> encode must be byte-identical, and every field and
 *  offset must survive the round trip. */
static void roundtrip(const fixture_t *f, const char *what) {
    uint8_t *a = buf_new();
    uint8_t *b = buf_new();
    size_t la = 0, lb = 0;

    if (fx_encode(f, a, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &la) != 0) {
        fprintf(stderr, "FAIL %s: encode rejected a valid fixture\n", what);
        failures++;
        free(a); free(b);
        return;
    }

    dna_effect_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    if (dna_effect_result_decode(a, la, v) != 0) {
        fprintf(stderr, "FAIL %s: decode rejected its own encoding\n", what);
        failures++;
        free(a); free(b); free(v);
        return;
    }

    CHECK(v->result_version == DNA_EFFECT_RESULT_VERSION);
    CHECK(v->effect_count   == f->n);
    CHECK(v->res_len        == la);
    CHECK(v->buf            == a);   /* BORROWED, never copied */

    size_t key_base = REC(f->n);
    size_t off = key_base;
    for (uint16_t i = 0; i < f->n; i++) {
        cmp_hdr(&v->eff[i], &f->hdr[i]);
        CHECK(v->key_off[i] == off);
        CHECK(memcmp(v->buf + v->key_off[i], f->key[i],
                     f->hdr[i].key_len) == 0);
        off += f->hdr[i].key_len;
    }
    for (uint16_t i = 0; i < f->n; i++) {
        CHECK(v->val_off[i] == off);
        if (f->hdr[i].value_len)
            CHECK(memcmp(v->buf + v->val_off[i], f->val[i],
                         f->hdr[i].value_len) == 0);
        off += f->hdr[i].value_len;
    }
    CHECK(off == la);

    /* Slots at or beyond effect_count stay zeroed — that is what makes a
     * decoded view re-encode byte-identically. */
    for (uint16_t i = f->n; i < MAXN; i++) {
        CHECK(v->eff[i].op_id            == 0);
        CHECK(v->eff[i].effect_kind      == 0);
        CHECK(v->eff[i].precond_tag      == 0);
        CHECK(v->eff[i].expected_version == 0);
        CHECK(v->eff[i].key_len          == 0);
        CHECK(v->eff[i].value_len        == 0);
        CHECK(v->key_off[i] == 0);
        CHECK(v->val_off[i] == 0);
    }

    CHECK(view_reencode(v, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &lb) == 0);
    CHECK(lb == la);
    CHECK(memcmp(a, b, la) == 0);

    free(v);
    free(a);
    free(b);
}

/* ══════════════════════════════════════════════════════════════════════
 * 1. Canonical representation
 * ════════════════════════════════════════════════════════════════════ */

static void test_canonical_shapes(void) {
    /* The EMPTY result: a leg that mutates nothing. */
    {
        fixture_t *f = fx_alloc();
        f->n = 0;
        roundtrip(f, "empty result");

        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        CHECK(la == (size_t)DNA_EFFECT_FIXED_HEAD);

        /* The distinguisher documented in effect_wire.h: an ACCEPTED
         * empty result has buf != NULL, so effect_count == 0 alone can
         * never be read as "this view was rejected". */
        dna_effect_view_t *v = calloc(1, sizeof(*v));
        MUST_ALLOC(v);
        CHECK(dna_effect_result_decode(a, la, v) == 0);
        CHECK(v->effect_count == 0);
        CHECK(v->buf     == a);
        CHECK(v->res_len == (size_t)DNA_EFFECT_FIXED_HEAD);
        free(v);
        free(a);

        /* n == 0 with a NULL effects array is accepted by BOTH the size
         * function and the encoder (effect_wire.h). */
        size_t need = 0xdead;
        CHECK(dna_effect_result_encoded_size(NULL, 0, &need) == 0);
        CHECK(need == (size_t)DNA_EFFECT_FIXED_HEAD);
        uint8_t small[DNA_EFFECT_FIXED_HEAD];
        size_t w = 0xdead;
        CHECK(dna_effect_result_encode(NULL, 0, small, sizeof(small), &w) == 0);
        CHECK(w == (size_t)DNA_EFFECT_FIXED_HEAD);
        fx_free(f);
    }

    /* One effect of each kind, individually. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        roundtrip(f, "single CREATE");
        fx_free(f);

        f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        roundtrip(f, "single SET");
        fx_free(f);

        f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_set_val(f, 0, 0, 0);          /* a DELETE carries no value */
        roundtrip(f, "single DELETE");
        fx_free(f);
    }

    /* A multi-effect canonical result exercising every precondition and
     * both blob-length extremes the fixture can reach cheaply. */
    {
        fixture_t *f = fx_new(6);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        f->hdr[1].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[1].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        fx_set_val(f, 1, 0, 0);          /* CREATE with an empty value */
        f->hdr[2].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
        f->hdr[2].expected_version = 0;  /* 0 IS a legal expected version */
        f->hdr[3].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
        f->hdr[3].expected_version = 0xFFFFFFFFFFFFFFFFULL;
        f->hdr[4].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
        for (int j = 0; j < HASH_LEN; j++)
            f->hdr[4].expected_vhash[j] = (uint8_t)(0x30 + j);
        f->hdr[5].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        f->hdr[5].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
        for (int j = 0; j < HASH_LEN; j++) f->hdr[5].expected_vhash[j] = 0xFF;
        fx_set_val(f, 5, 0, 0);
        fx_set_key(f, 5, DNA_EFFECT_MAX_KEY_LEN, 0x5a);
        roundtrip(f, "6 effects, every precondition");
        fx_free(f);
    }

    /* The full effect ceiling. */
    {
        fixture_t *f = fx_new(MAXN);
        roundtrip(f, "64 effects");
        fx_free(f);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. KATs — pinned from the independent oracle
 * ════════════════════════════════════════════════════════════════════ */

/* ORACLE: python3 hashlib.sha3_512 — effect_wire_oracle.py */
static const uint8_t K_EFF_EMPTY[23] = {0x44,0x4e,0x41,0x2e,0x45,0x46,0x46,0x52,0x45,0x53,0x2e,0x76,0x31,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00};
static const uint8_t K_EFF_SINGLE[119] = {0x44,0x4e,0x41,0x2e,0x45,0x46,0x46,0x52,0x45,0x53,0x2e,0x76,0x31,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x04,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0xa0,0xa1,0xa2,0xa3};
static const uint8_t K_EFF_MULTI[531] = {0x44,0x4e,0x41,0x2e,0x45,0x46,0x46,0x52,0x45,0x53,0x2e,0x76,0x31,0x00,0x00,0x00,0x01,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x02,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x01,0x02,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf3,0xac,0xac,0x2a,0x90,0xd6,0xa6,0x99,0x7e,0x76,0xa7,0x7b,0xd7,0xee,0xb5,0x45,0xa0,0x8e,0xe3,0xef,0xc2,0xf8,0xb0,0x3b,0x57,0xf1,0x47,0xe0,0xaa,0x89,0xa4,0x13,0x5f,0x2a,0xd0,0x07,0xa9,0xab,0x56,0x0d,0x6b,0x20,0xed,0x90,0xb6,0x6d,0x1e,0x44,0x4d,0x6d,0xf8,0x75,0x78,0x8d,0xc3,0xd4,0x85,0x61,0xdc,0xec,0xb1,0xfc,0x53,0xe9,0x00,0x03,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x03,0x03,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x20,0x21,0x20,0x21,0x22,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xd0,0xd1,0xd2,0xd3};
static const uint8_t K_VH_EMPTY[64] = {0xf8,0x04,0x79,0x67,0x75,0xbb,0xb8,0x47,0x09,0x01,0xb8,0xa0,0x45,0x9a,0xf4,0xeb,0x20,0xfc,0x1d,0x65,0x58,0x51,0x7f,0xbd,0xf0,0xe3,0x01,0xd3,0xde,0x99,0x40,0x48,0x7f,0xa0,0xbc,0x3b,0x76,0xc5,0xef,0x4a,0x3e,0x4d,0xfb,0x1e,0xab,0x65,0xd9,0x1c,0xa8,0x96,0xbe,0xd3,0xb9,0xfa,0x7f,0xff,0xd0,0x34,0xc7,0x42,0x9a,0x52,0xa4,0x73};
static const uint8_t K_VH_A0A1A2A3[64] = {0x76,0xc8,0xf8,0x7a,0xde,0xeb,0x12,0x4b,0x1c,0x4c,0x77,0xad,0xe5,0xb0,0x4b,0x0c,0x7f,0x60,0x2c,0xef,0xe0,0x8b,0x58,0x99,0xee,0xd8,0x7c,0x6c,0xed,0x6d,0x99,0x0b,0x50,0xd1,0x03,0x4a,0x45,0x05,0xb0,0xa8,0x2c,0x43,0xbd,0x48,0xa9,0x92,0xb4,0x9b,0xee,0x8a,0x3c,0x9a,0x34,0x4f,0x04,0x4a,0x45,0xa4,0x5e,0x65,0xa7,0xf9,0x1e,0xb5};
static const uint8_t K_VH_EEEF[64] = {0xf3,0xac,0xac,0x2a,0x90,0xd6,0xa6,0x99,0x7e,0x76,0xa7,0x7b,0xd7,0xee,0xb5,0x45,0xa0,0x8e,0xe3,0xef,0xc2,0xf8,0xb0,0x3b,0x57,0xf1,0x47,0xe0,0xaa,0x89,0xa4,0x13,0x5f,0x2a,0xd0,0x07,0xa9,0xab,0x56,0x0d,0x6b,0x20,0xed,0x90,0xb6,0x6d,0x1e,0x44,0x4d,0x6d,0xf8,0x75,0x78,0x8d,0xc3,0xd4,0x85,0x61,0xdc,0xec,0xb1,0xfc,0x53,0xe9};

/**
 * KAT STRUCTURE (asserted below, never assumed):
 *   K_EFF_EMPTY  — the empty result, head only.
 *   K_EFF_SINGLE — one CREATE: op 7, key 01..08 (8 B), value a0a1a2a3 (4 B).
 *   K_EFF_MULTI  — five effects in canonical order:
 *       e0 CREATE op1 key {10}                       val {c0,c1}
 *       e1 CREATE op2 key {11..18}                   val {c2..c5}
 *       e2 SET    op1 key {20,21}    EXISTS_VERSION expected_version = 5
 *                                                    val {d0,d1,d2}
 *       e3 SET    op1 key {20,21,22} EXISTS_VHASH   expected_vhash = K_VH_EEEF
 *                                                    val {d3}
 *       e4 DELETE op3 key {00..3f} (64 B) EXISTS     val (empty)
 *     e2/e3 pin rule 3 of the canonical order: identical prefix, SHORTER
 *     key first. e3's expected_vhash is byte-for-byte K_VH_EEEF, which is
 *     dna_effect_value_hash of {ee,ef} — asserted, so the KAT records a
 *     real precondition rather than an arbitrary 64 bytes.
 *   K_VH_* — value hashes of the empty value, of a0a1a2a3, and of eeef.
 */

/** Build the K_EFF_SINGLE fixture from literals. */
static fixture_t *kat_single_fixture(void) {
    fixture_t *f = fx_alloc();
    f->n = 1;
    f->hdr[0].op_id       = 7;
    f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
    f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
    {
        uint8_t k[8]; for (int j = 0; j < 8; j++) k[j] = (uint8_t)(j + 1);
        fx_key_bytes(f, 0, k, 8);
    }
    {
        uint8_t v[4] = {0xa0, 0xa1, 0xa2, 0xa3};
        fx_val_bytes(f, 0, v, 4);
    }
    return f;
}

/** Build the K_EFF_MULTI fixture from literals. */
static fixture_t *kat_multi_fixture(void) {
    fixture_t *f = fx_alloc();
    f->n = 5;

    f->hdr[0].op_id       = 1;
    f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
    f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
    { uint8_t k[1] = {0x10};                fx_key_bytes(f, 0, k, 1); }
    { uint8_t v[2] = {0xc0, 0xc1};          fx_val_bytes(f, 0, v, 2); }

    f->hdr[1].op_id       = 2;
    f->hdr[1].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
    f->hdr[1].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
    { uint8_t k[8]; for (int j = 0; j < 8; j++) k[j] = (uint8_t)(0x11 + j);
      fx_key_bytes(f, 1, k, 8); }
    { uint8_t v[4] = {0xc2, 0xc3, 0xc4, 0xc5}; fx_val_bytes(f, 1, v, 4); }

    f->hdr[2].op_id            = 1;
    f->hdr[2].effect_kind      = (uint8_t)DNA_EFFECT_SET;
    f->hdr[2].precond_tag      = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
    f->hdr[2].expected_version = 5;
    { uint8_t k[2] = {0x20, 0x21};          fx_key_bytes(f, 2, k, 2); }
    { uint8_t v[3] = {0xd0, 0xd1, 0xd2};    fx_val_bytes(f, 2, v, 3); }

    f->hdr[3].op_id       = 1;
    f->hdr[3].effect_kind = (uint8_t)DNA_EFFECT_SET;
    f->hdr[3].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
    memcpy(f->hdr[3].expected_vhash, K_VH_EEEF, HASH_LEN);
    { uint8_t k[3] = {0x20, 0x21, 0x22};    fx_key_bytes(f, 3, k, 3); }
    { uint8_t v[1] = {0xd3};                fx_val_bytes(f, 3, v, 1); }

    f->hdr[4].op_id       = 3;
    f->hdr[4].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
    f->hdr[4].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
    { uint8_t k[64]; for (int j = 0; j < 64; j++) k[j] = (uint8_t)j;
      fx_key_bytes(f, 4, k, 64); }
    fx_set_val(f, 4, 0, 0);
    return f;
}

/**
 * Decode a pinned KAT, verify EVERY field of EVERY record against the
 * fixture that claims to describe it, then re-encode and demand the bytes
 * back. Encoding the same fixture from literals must produce the KAT too,
 * so encoder and decoder are pinned INDEPENDENTLY to the oracle.
 */
static void kat_roundtrip(const uint8_t *kat, size_t klen,
                          const fixture_t *f, const char *what) {
    dna_effect_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    if (dna_effect_result_decode(kat, klen, v) != 0) {
        fprintf(stderr, "FAIL %s: decode rejected the pinned KAT\n", what);
        failures++;
        free(v);
        return;
    }
    CHECK(v->result_version == DNA_EFFECT_RESULT_VERSION);
    CHECK(v->effect_count   == f->n);
    CHECK(v->res_len        == klen);
    CHECK(v->buf            == kat);

    size_t off = REC(f->n);
    for (uint16_t i = 0; i < f->n; i++) {
        cmp_hdr(&v->eff[i], &f->hdr[i]);
        CHECK(v->key_off[i] == off);
        CHECK(memcmp(v->buf + v->key_off[i], f->key[i],
                     f->hdr[i].key_len) == 0);
        off += f->hdr[i].key_len;
    }
    for (uint16_t i = 0; i < f->n; i++) {
        CHECK(v->val_off[i] == off);
        if (f->hdr[i].value_len)
            CHECK(memcmp(v->buf + v->val_off[i], f->val[i],
                         f->hdr[i].value_len) == 0);
        off += f->hdr[i].value_len;
    }
    CHECK(off == klen);

    /* decode -> re-encode must reproduce the KAT byte for byte. */
    uint8_t *b = buf_new();
    size_t lb = 0;
    CHECK(view_reencode(v, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &lb) == 0);
    CHECK(lb == klen);
    CHECK(memcmp(b, kat, klen) == 0);

    /* encode straight from the literal fixture must reproduce it too. */
    size_t lc = 0;
    memset(b, 0, (size_t)DNA_EFFECT_MAX_TOTAL_LEN + 16);
    CHECK(fx_encode(f, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &lc) == 0);
    CHECK(lc == klen);
    CHECK(memcmp(b, kat, klen) == 0);

    free(b);
    free(v);
}

/** Pinned byte positions of the KAT encodings. */
static void test_pinned_offsets(void) {
    static const uint8_t family[DNA_EFFECT_WIRE_FAMILY_LEN] = {
        'D','N','A','.','E','F','F','R','E','S','.','v','1', 0, 0, 0
    };
    /* Fixed head, in all three KATs. */
    CHECK(memcmp(K_EFF_EMPTY,  family, DNA_EFFECT_WIRE_FAMILY_LEN) == 0);
    CHECK(memcmp(K_EFF_SINGLE, family, DNA_EFFECT_WIRE_FAMILY_LEN) == 0);
    CHECK(memcmp(K_EFF_MULTI,  family, DNA_EFFECT_WIRE_FAMILY_LEN) == 0);
    CHECK(K_EFF_EMPTY[16]  == DNA_EFFECT_RESULT_VERSION);
    CHECK(K_EFF_SINGLE[16] == DNA_EFFECT_RESULT_VERSION);
    CHECK(K_EFF_MULTI[16]  == DNA_EFFECT_RESULT_VERSION);
    /* effect_count u16 BE at 17. */
    CHECK(K_EFF_EMPTY[17]  == 0 && K_EFF_EMPTY[18]  == 0);
    CHECK(K_EFF_SINGLE[17] == 0 && K_EFF_SINGLE[18] == 1);
    CHECK(K_EFF_MULTI[17]  == 0 && K_EFF_MULTI[18]  == 5);
    /* reserved u32 BE at 19, all four bytes zero. */
    for (int j = 19; j < 23; j++) {
        CHECK(K_EFF_EMPTY[j]  == 0);
        CHECK(K_EFF_SINGLE[j] == 0);
        CHECK(K_EFF_MULTI[j]  == 0);
    }
    /* Total lengths follow the layout formula exactly. */
    CHECK(sizeof(K_EFF_EMPTY)  == (size_t)DNA_EFFECT_FIXED_HEAD);
    CHECK(sizeof(K_EFF_SINGLE) == REC(1) + 8 + 4);
    CHECK(sizeof(K_EFF_MULTI)  == REC(5) + (1 + 8 + 2 + 3 + 64) +
                                  (2 + 4 + 3 + 1 + 0));
    CHECK(REC(5) == 443);

    /* K_EFF_SINGLE record 0, field by field, at its exact offsets. */
    const uint8_t *r = K_EFF_SINGLE + REC(0);
    CHECK(r[R_OP] == 0 && r[R_OP+1] == 0 && r[R_OP+2] == 0 && r[R_OP+3] == 7);
    CHECK(r[R_KIND] == (uint8_t)DNA_EFFECT_CREATE);
    CHECK(r[R_PRE]  == (uint8_t)DNA_EFFECT_PRE_ABSENT);
    for (int j = 0; j < 8;  j++) CHECK(r[R_VER + j]   == 0);
    for (int j = 0; j < 64; j++) CHECK(r[R_VHASH + j] == 0);
    CHECK(r[R_KEYLEN] == 0 && r[R_KEYLEN + 1] == 8);
    CHECK(r[R_VALLEN] == 0 && r[R_VALLEN+1] == 0 &&
          r[R_VALLEN + 2] == 0 && r[R_VALLEN + 3] == 4);
    /* Key section starts at KEY_BASE(1), value section right after it. */
    CHECK(K_EFF_SINGLE[REC(1)]     == 0x01);
    CHECK(K_EFF_SINGLE[REC(1) + 7] == 0x08);
    CHECK(K_EFF_SINGLE[REC(1) + 8] == 0xa0);

    /* K_EFF_MULTI: the two records that pin the reserved-field rules. */
    const uint8_t *r2 = K_EFF_MULTI + REC(2);
    CHECK(r2[R_KIND] == (uint8_t)DNA_EFFECT_SET);
    CHECK(r2[R_PRE]  == (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION);
    CHECK(r2[R_VER + 7] == 5);                     /* expected_version = 5 */
    for (int j = 0; j < 64; j++) CHECK(r2[R_VHASH + j] == 0);
    const uint8_t *r3 = K_EFF_MULTI + REC(3);
    CHECK(r3[R_PRE] == (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH);
    for (int j = 0; j < 8; j++) CHECK(r3[R_VER + j] == 0);
    /* The KAT's expected_vhash IS the real value hash of {ee,ef}. */
    CHECK(memcmp(r3 + R_VHASH, K_VH_EEEF, HASH_LEN) == 0);
    /* Key section: e2's 2-byte key immediately precedes e3's 3-byte key,
     * which is rule 3 (equal prefix, shorter first) on the wire. */
    size_t kb = REC(5);
    CHECK(K_EFF_MULTI[kb + 1 + 8]     == 0x20);
    CHECK(K_EFF_MULTI[kb + 1 + 8 + 1] == 0x21);
    CHECK(K_EFF_MULTI[kb + 1 + 8 + 2] == 0x20);
    CHECK(K_EFF_MULTI[kb + 1 + 8 + 3] == 0x21);
    CHECK(K_EFF_MULTI[kb + 1 + 8 + 4] == 0x22);
    /* Value section starts after all 78 key bytes. */
    CHECK(K_EFF_MULTI[kb + 78] == 0xc0);
}

static void test_kat(void) {
    printf("\n──── KAT FIXTURES (feed these to the independent oracle) ────\n");

    /* Empty. */
    {
        fixture_t *f = fx_alloc();
        f->n = 0;
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        print_hex("K_EFF_EMPTY", a, la);
        CHECK(la == sizeof(K_EFF_EMPTY));
        CHECK(memcmp(a, K_EFF_EMPTY, la) == 0);
        kat_roundtrip(K_EFF_EMPTY, sizeof(K_EFF_EMPTY), f, "K_EFF_EMPTY");
        free(a);
        fx_free(f);
    }
    /* Single. */
    {
        fixture_t *f = kat_single_fixture();
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        print_hex("K_EFF_SINGLE", a, la);
        CHECK(la == sizeof(K_EFF_SINGLE));
        kat_roundtrip(K_EFF_SINGLE, sizeof(K_EFF_SINGLE), f, "K_EFF_SINGLE");
        free(a);
        fx_free(f);
    }
    /* Multi. */
    {
        fixture_t *f = kat_multi_fixture();
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        print_hex("K_EFF_MULTI", a, la);
        CHECK(la == sizeof(K_EFF_MULTI));
        kat_roundtrip(K_EFF_MULTI, sizeof(K_EFF_MULTI), f, "K_EFF_MULTI");
        free(a);
        fx_free(f);
    }

    /* The three pinned value hashes. */
    {
        uint8_t out[HASH_LEN];
        static const uint8_t va[4] = {0xa0, 0xa1, 0xa2, 0xa3};
        static const uint8_t vb[2] = {0xee, 0xef};
        memset(out, 0xAA, sizeof(out));
        CHECK(dna_effect_value_hash(NULL, 0, out) == 0);
        CHECK(memcmp(out, K_VH_EMPTY, HASH_LEN) == 0);
        print_hex("K_VH_EMPTY", out, HASH_LEN);
        memset(out, 0xAA, sizeof(out));
        CHECK(dna_effect_value_hash(va, 4, out) == 0);
        CHECK(memcmp(out, K_VH_A0A1A2A3, HASH_LEN) == 0);
        print_hex("K_VH_A0A1A2A3", out, HASH_LEN);
        memset(out, 0xAA, sizeof(out));
        CHECK(dna_effect_value_hash(vb, 2, out) == 0);
        CHECK(memcmp(out, K_VH_EEEF, HASH_LEN) == 0);
        print_hex("K_VH_EEEF", out, HASH_LEN);
        /* An empty value with a NON-NULL pointer must hash identically to
         * the NULL case — the pointer is not part of the preimage. */
        memset(out, 0xAA, sizeof(out));
        CHECK(dna_effect_value_hash(va, 0, out) == 0);
        CHECK(memcmp(out, K_VH_EMPTY, HASH_LEN) == 0);
    }
    printf("─────────────────────────────────────────────────────────────\n\n");
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. Truncation, trailing bytes, and the fixed-head field rejects
 * ════════════════════════════════════════════════════════════════════ */

static void test_truncation_and_suffix(void) {
    /* Every truncation of the multi KAT rejects — every boundary, not a
     * sample of them. */
    for (size_t l = 0; l < sizeof(K_EFF_MULTI); l++)
        expect_decode_reject(K_EFF_MULTI, l, "truncated K_EFF_MULTI");
    for (size_t l = 0; l < sizeof(K_EFF_EMPTY); l++)
        expect_decode_reject(K_EFF_EMPTY, l, "truncated K_EFF_EMPTY");

    /* Strict suffix rejection: a valid encoding plus one trailing byte. */
    uint8_t *m = buf_new();
    memcpy(m, K_EFF_MULTI, sizeof(K_EFF_MULTI));
    m[sizeof(K_EFF_MULTI)] = 0x00;
    expect_decode_reject(m, sizeof(K_EFF_MULTI) + 1, "one trailing zero byte");
    m[sizeof(K_EFF_MULTI)] = 0xFF;
    expect_decode_reject(m, sizeof(K_EFF_MULTI) + 1, "one trailing 0xFF byte");
    memcpy(m, K_EFF_EMPTY, sizeof(K_EFF_EMPTY));
    m[sizeof(K_EFF_EMPTY)] = 0x00;
    expect_decode_reject(m, sizeof(K_EFF_EMPTY) + 1,
                         "empty result + trailing byte");
    free(m);

    /* NULL arguments. */
    expect_decode_reject(NULL, sizeof(K_EFF_MULTI), "NULL src");
    CHECK(dna_effect_result_decode(K_EFF_MULTI, sizeof(K_EFF_MULTI),
                                   NULL) == -1);
}

/**
 * Base for byte-level mutation: ONE CREATE, key {0x41}, no value. Every
 * reserved field is zero and every bound is slack, so the only thing that
 * can explain a rejection is the byte the test changed.
 */
static uint8_t *mutation_base(size_t *len_out) {
    fixture_t *f = fx_alloc();
    f->n = 1;
    f->hdr[0].op_id       = 9;
    f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
    f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
    { uint8_t k[1] = {0x41}; fx_key_bytes(f, 0, k, 1); }
    fx_set_val(f, 0, 0, 0);
    uint8_t *b = buf_new();
    *len_out = fx_must_encode(f, b);
    fx_free(f);
    return b;
}

static void test_head_field_rejects(void) {
    size_t blen = 0;
    uint8_t *base = mutation_base(&blen);
    CHECK(blen == REC(1) + 1);
    uint8_t *m = buf_new();

#define WITH_COPY() memcpy(m, base, blen)

    /* Sanity: the untouched encoding decodes. */
    {
        dna_effect_view_t *v = calloc(1, sizeof(*v));
        MUST_ALLOC(v);
        CHECK(dna_effect_result_decode(base, blen, v) == 0);
        free(v);
    }

    /* Family marker: a content byte, and each PADDING byte (13..15 of
     * "DNA.EFFRES.v1" are the zero padding). */
    WITH_COPY(); m[0] ^= 0x01;
    expect_decode_reject(m, blen, "wrong family byte 0");
    WITH_COPY(); m[12] = 'X';
    expect_decode_reject(m, blen, "wrong family version char");
    WITH_COPY(); m[13] = 'X';
    expect_decode_reject(m, blen, "corrupted family padding 13");
    WITH_COPY(); m[14] = 0x01;
    expect_decode_reject(m, blen, "corrupted family padding 14");
    WITH_COPY(); m[15] = 0xFF;
    expect_decode_reject(m, blen, "corrupted family padding 15");

    /* Unknown result_version. */
    WITH_COPY(); m[16] = 0;
    expect_decode_reject(m, blen, "result_version 0");
    WITH_COPY(); m[16] = 2;
    expect_decode_reject(m, blen, "result_version 2");
    WITH_COPY(); m[16] = 0xFF;
    expect_decode_reject(m, blen, "result_version 255");

    /* Reserved u32 at 19: each of the four bytes individually. */
    for (int j = 0; j < 4; j++) {
        WITH_COPY(); m[19 + j] = 0x01;
        expect_decode_reject(m, blen, "reserved byte set");
        WITH_COPY(); m[19 + j] = 0x80;
        expect_decode_reject(m, blen, "reserved high bit set");
    }

    /* Unknown effect_kind. */
    WITH_COPY(); m[REC(0) + R_KIND] = 0;
    expect_decode_reject(m, blen, "effect_kind 0");
    WITH_COPY(); m[REC(0) + R_KIND] = 4;
    expect_decode_reject(m, blen, "effect_kind 4");
    WITH_COPY(); m[REC(0) + R_KIND] = 0xFF;
    expect_decode_reject(m, blen, "effect_kind 255");

    /* Unknown precond_tag. */
    WITH_COPY(); m[REC(0) + R_PRE] = 0;
    expect_decode_reject(m, blen, "precond_tag 0");
    WITH_COPY(); m[REC(0) + R_PRE] = 5;
    expect_decode_reject(m, blen, "precond_tag 5");
    WITH_COPY(); m[REC(0) + R_PRE] = 0xFF;
    expect_decode_reject(m, blen, "precond_tag 255");

    /* RESERVED-FIELD MISUSE: expected_version non-zero under ABSENT (the
     * base's tag), at the first, a middle and the last byte of the 8. */
    {
        const int pos[3] = {0, 4, 7};
        for (int t = 0; t < 3; t++) {
            WITH_COPY(); m[REC(0) + R_VER + pos[t]] = 0x01;
            expect_decode_reject(m, blen, "expected_version set under ABSENT");
        }
    }
    /* expected_vhash non-zero under a tag that is not EXISTS_VHASH, at the
     * start, the middle and the end of the 64. */
    {
        const int pos[3] = {0, 32, 63};
        for (int t = 0; t < 3; t++) {
            WITH_COPY(); m[REC(0) + R_VHASH + pos[t]] = 0x01;
            expect_decode_reject(m, blen, "expected_vhash set under ABSENT");
        }
    }
    /* The same two rules under the OTHER wrong tags: a version field under
     * EXISTS_VHASH, and a hash field under EXISTS_VERSION. This is the
     * pin for "an expected version and an expected value hash can never
     * both be active" — the conflicting state is unrepresentable, so the
     * assertion is that each field is rejected outside its own tag. */
    WITH_COPY();
    m[REC(0) + R_KIND] = (uint8_t)DNA_EFFECT_SET;
    m[REC(0) + R_PRE]  = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
    m[REC(0) + R_VER + 7] = 0x01;
    expect_decode_reject(m, blen, "expected_version set under EXISTS_VHASH");
    WITH_COPY();
    m[REC(0) + R_KIND] = (uint8_t)DNA_EFFECT_SET;
    m[REC(0) + R_PRE]  = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
    m[REC(0) + R_VHASH + 63] = 0x01;
    expect_decode_reject(m, blen, "expected_vhash set under EXISTS_VERSION");

    /* ...and the accepting side of both, so the rules are pinned from both
     * directions rather than being a blanket "non-zero rejects". */
    WITH_COPY();
    m[REC(0) + R_KIND] = (uint8_t)DNA_EFFECT_SET;
    m[REC(0) + R_PRE]  = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
    m[REC(0) + R_VER + 7] = 0x2a;
    {
        dna_effect_view_t *v = calloc(1, sizeof(*v));
        MUST_ALLOC(v);
        CHECK(dna_effect_result_decode(m, blen, v) == 0);
        CHECK(v->eff[0].expected_version == 0x2a);
        free(v);
    }
    WITH_COPY();
    m[REC(0) + R_KIND] = (uint8_t)DNA_EFFECT_SET;
    m[REC(0) + R_PRE]  = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
    m[REC(0) + R_VHASH + 5] = 0x2a;
    {
        dna_effect_view_t *v = calloc(1, sizeof(*v));
        MUST_ALLOC(v);
        CHECK(dna_effect_result_decode(m, blen, v) == 0);
        CHECK(v->eff[0].expected_vhash[5] == 0x2a);
        free(v);
    }

    /* A DELETE may not carry a value. Give the base a 1-byte value first
     * so the length stays self-consistent. */
    {
        fixture_t *g = fx_alloc();
        g->n = 1;
        g->hdr[0].op_id       = 9;
        g->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_SET;
        g->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        { uint8_t k[1] = {0x41}; fx_key_bytes(g, 0, k, 1); }
        fx_set_val(g, 0, 1, 0x99);
        uint8_t *w = buf_new();
        size_t wl = fx_must_encode(g, w);
        w[REC(0) + R_KIND] = (uint8_t)DNA_EFFECT_DELETE;
        expect_decode_reject(w, wl, "DELETE with value_len 1");
        free(w);
        fx_free(g);
    }

#undef WITH_COPY
    free(m);
    free(base);
}

/* ══════════════════════════════════════════════════════════════════════
 * 4. Bounds: count, key_len, value_len, length arithmetic, total cap
 * ════════════════════════════════════════════════════════════════════ */

static void test_size_formula(void) {
    dna_effect_in_t *arr = calloc(MAXN + 1, sizeof(*arr));
    MUST_ALLOC(arr);
    size_t out = 0;

    for (uint16_t i = 0; i <= MAXN; i++) {
        arr[i].hdr.key_len   = 1;
        arr[i].hdr.value_len = 0;
    }

    CHECK(dna_effect_result_encoded_size(arr, 0, &out) == 0);
    CHECK(out == (size_t)DNA_EFFECT_FIXED_HEAD);

    arr[0].hdr.key_len   = 10;
    arr[0].hdr.value_len = 20;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == 0);
    CHECK(out == REC(1) + 30);

    arr[1].hdr.key_len   = 1;
    arr[1].hdr.value_len = 2;
    arr[2].hdr.key_len   = 5;
    arr[2].hdr.value_len = 0;
    CHECK(dna_effect_result_encoded_size(arr, 3, &out) == 0);
    CHECK(out == REC(3) + (10 + 1 + 5) + (20 + 2 + 0));

    /* 64 effects, 1-byte keys, no values = the whole record region + 64. */
    for (uint16_t i = 0; i < MAXN; i++) {
        arr[i].hdr.key_len   = 1;
        arr[i].hdr.value_len = 0;
    }
    CHECK(dna_effect_result_encoded_size(arr, MAXN, &out) == 0);
    CHECK(out == 5399 + MAXN);
    CHECK(REC(MAXN) == 5399);

    /* Rejects, each leaving *out == 0. */
    CHECK(dna_effect_result_encoded_size(arr, 1, NULL) == -1);
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(NULL, 1, &out) == -1);
    CHECK(out == 0);
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, MAXN + 1, &out) == -1);
    CHECK(out == 0);

    /* key_len bounds. */
    out = 0xdead;
    arr[0].hdr.key_len = 0;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == -1);
    CHECK(out == 0);
    arr[0].hdr.key_len = DNA_EFFECT_MAX_KEY_LEN;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == 0);
    CHECK(out == REC(1) + DNA_EFFECT_MAX_KEY_LEN);
    arr[0].hdr.key_len = DNA_EFFECT_MAX_KEY_LEN + 1;
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == -1);
    CHECK(out == 0);
    arr[0].hdr.key_len = 1;

    /* value_len bounds. */
    arr[0].hdr.value_len = DNA_EFFECT_MAX_VALUE_LEN;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == 0);
    CHECK(out == REC(1) + 1 + DNA_EFFECT_MAX_VALUE_LEN);
    arr[0].hdr.value_len = DNA_EFFECT_MAX_VALUE_LEN + 1;
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == -1);
    CHECK(out == 0);

    /* Length arithmetic near UINT32_MAX: the cap check fires first and the
     * subtraction-form guard stands behind it, so neither a wrap nor a
     * small total is reachable. Both legs are asserted. */
    arr[0].hdr.value_len = 0xFFFFFFFFu;
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == -1);
    CHECK(out == 0);
    arr[0].hdr.value_len = 0;
    arr[0].hdr.key_len = 0xFFFF;
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, 1, &out) == -1);
    CHECK(out == 0);
    arr[0].hdr.key_len = 1;

    /* In-cap lengths whose SUM passes the total cap: this is the case the
     * accumulation guard itself rejects. 9 * 8192 = 73728 > 65536. */
    for (uint16_t i = 0; i < 9; i++) {
        arr[i].hdr.key_len   = 1;
        arr[i].hdr.value_len = DNA_EFFECT_MAX_VALUE_LEN;
    }
    out = 0xdead;
    CHECK(dna_effect_result_encoded_size(arr, 9, &out) == -1);
    CHECK(out == 0);
    /* Not all eight fit either (703 + 8*8192 = 66239 > 65536), so seven do. */
    CHECK(dna_effect_result_encoded_size(arr, 7, &out) == 0);
    CHECK(out == REC(7) + 7 + 7 * (size_t)DNA_EFFECT_MAX_VALUE_LEN);

    free(arr);
}

static void test_count_bounds(void) {
    /* ACCEPT: exactly the ceiling. */
    {
        fixture_t *f = fx_new(MAXN);
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        CHECK(la > REC(MAXN));
        roundtrip(f, "exactly 64 effects");
        free(a);
        fx_free(f);
    }

    /* REJECT (encode side): 65 individually VALID effects, so only the
     * count can be the reason. The array is built directly because the
     * fixture's arrays are sized to the ceiling. */
    {
        dna_effect_in_t *big = calloc(MAXN + 1, sizeof(*big));
        MUST_ALLOC(big);
        static uint8_t keys[MAXN + 1];
        for (uint16_t i = 0; i <= MAXN; i++) {
            keys[i] = (uint8_t)i;
            big[i].hdr.op_id       = 1u + i;
            big[i].hdr.effect_kind = (uint8_t)DNA_EFFECT_SET;
            big[i].hdr.precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
            big[i].hdr.key_len     = 1;
            big[i].key             = &keys[i];
        }
        uint8_t *b = buf_new();
        size_t w = 0xdead;
        CHECK(dna_effect_result_encode(big, MAXN + 1, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == -1);
        CHECK(w == 0);
        /* Exactly the ceiling, same effects: accepted. */
        CHECK(dna_effect_result_encode(big, MAXN, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == 0);
        CHECK(w == REC(MAXN) + MAXN);
        free(b);
        free(big);
    }

    /* REJECT (decode side): a fully self-consistent 65-effect encoding.
     *
     * The count bound is MEMORY-SAFETY load-bearing: dna_effect_view_t.eff
     * holds DNA_EFFECT_MAX_COUNT entries while the wire count is u16, so a
     * 65-effect result would walk one slot past the array (and past
     * key_off[]/val_off[] with it). Nothing here is malformed except the
     * count, so a decoder without the bound would populate that 65th slot
     * before any other check could fire. */
    {
        const uint16_t over = MAXN + 1;                  /* 65 */
        size_t reg  = (size_t)DNA_EFFECT_FIXED_HEAD +
                      (size_t)over * DNA_EFFECT_RECORD_LEN;
        size_t total = reg + over;                       /* 1-byte keys */
        CHECK(reg == 5483);
        CHECK(total == 5548);
        uint8_t *m = calloc(1, total);
        MUST_ALLOC(m);
        static const uint8_t family[DNA_EFFECT_WIRE_FAMILY_LEN] = {
            'D','N','A','.','E','F','F','R','E','S','.','v','1', 0, 0, 0
        };
        memcpy(m, family, DNA_EFFECT_WIRE_FAMILY_LEN);
        m[16] = DNA_EFFECT_RESULT_VERSION;
        m[17] = (uint8_t)(over >> 8);
        m[18] = (uint8_t)over;
        for (uint16_t i = 0; i < over; i++) {
            uint8_t *r = m + DNA_EFFECT_FIXED_HEAD +
                         (size_t)i * DNA_EFFECT_RECORD_LEN;
            r[R_OP + 2]     = (uint8_t)(i >> 8);
            r[R_OP + 3]     = (uint8_t)i;      /* op_id ascending 0..64  */
            r[R_KIND]       = (uint8_t)DNA_EFFECT_SET;
            r[R_PRE]        = (uint8_t)DNA_EFFECT_PRE_EXISTS;
            r[R_KEYLEN + 1] = 1;
            /* value_len and both reserved fields stay 0. */
        }
        for (uint16_t i = 0; i < over; i++) m[reg + i] = (uint8_t)i;
        expect_decode_reject(m, total, "65 effects, self-consistent 5548 B");
        /* The same buffer with the count corrected to 64 (and the extra
         * record + key byte trimmed) must decode, so the rejection above
         * really was the count. */
        m[18] = (uint8_t)MAXN;
        size_t reg64   = REC(MAXN);
        size_t total64 = reg64 + MAXN;
        memmove(m + reg64, m + reg, MAXN);
        {
            dna_effect_view_t *v = calloc(1, sizeof(*v));
            MUST_ALLOC(v);
            CHECK(dna_effect_result_decode(m, total64, v) == 0);
            CHECK(v->effect_count == MAXN);
            free(v);
        }
        free(m);
    }

    /* REJECT (decode side): the u16 maximum. */
    {
        size_t blen = 0;
        uint8_t *base = mutation_base(&blen);
        uint8_t *m = buf_new();
        memcpy(m, base, blen);
        m[17] = 0xFF; m[18] = 0xFF;
        expect_decode_reject(m, blen, "count 65535");
        memcpy(m, base, blen);
        m[17] = 0x00; m[18] = (uint8_t)(MAXN + 1);
        expect_decode_reject(m, blen, "count 65 (short buffer)");
        free(m);
        free(base);
    }
}

static void test_blob_bounds(void) {
    /* key_len 0 rejects, 1 accepts, 128 accepts, 129 rejects — both
     * directions for each. */
    {
        fixture_t *f = fx_new(1);
        fx_set_key(f, 0, 1, 0x11);
        roundtrip(f, "key_len 1");
        fx_set_key(f, 0, DNA_EFFECT_MAX_KEY_LEN, 0x22);
        roundtrip(f, "key_len 128");

        fixture_t *g = fx_clone(f);
        g->hdr[0].key_len = 0;
        expect_encode_reject(g, "encode key_len 0");
        fx_free(g);
        g = fx_clone(f);
        g->hdr[0].key_len = DNA_EFFECT_MAX_KEY_LEN + 1;  /* buffer stays 128 */
        expect_encode_reject(g, "encode key_len 129");
        fx_free(g);

        /* Decode side: patch the length field on a valid 128-byte-key
         * encoding, and hand decode a buffer whose SIZE matches the patched
         * length, so only the bound can explain the rejection. */
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        a[REC(0) + R_KEYLEN]     = 0;
        a[REC(0) + R_KEYLEN + 1] = (uint8_t)(DNA_EFFECT_MAX_KEY_LEN + 1);
        expect_decode_reject(a, la + 1, "decode key_len 129");
        la = fx_must_encode(f, a);
        a[REC(0) + R_KEYLEN]     = 0;
        a[REC(0) + R_KEYLEN + 1] = 0;
        expect_decode_reject(a, la - DNA_EFFECT_MAX_KEY_LEN,
                             "decode key_len 0");
        free(a);
        fx_free(f);
    }

    /* value_len 0 accepts on CREATE and SET, 8192 accepts, 8193 rejects. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        fx_set_val(f, 0, 0, 0);
        roundtrip(f, "CREATE value_len 0");
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        roundtrip(f, "SET value_len 0");

        fx_set_val(f, 0, DNA_EFFECT_MAX_VALUE_LEN, 0x33);
        roundtrip(f, "value_len 8192");

        fixture_t *g = fx_clone(f);
        g->hdr[0].value_len = DNA_EFFECT_MAX_VALUE_LEN + 1;
        expect_encode_reject(g, "encode value_len 8193");
        fx_free(g);

        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        uint32_t over = DNA_EFFECT_MAX_VALUE_LEN + 1;
        a[REC(0) + R_VALLEN]     = (uint8_t)(over >> 24);
        a[REC(0) + R_VALLEN + 1] = (uint8_t)(over >> 16);
        a[REC(0) + R_VALLEN + 2] = (uint8_t)(over >> 8);
        a[REC(0) + R_VALLEN + 3] = (uint8_t)over;
        expect_decode_reject(a, la + 1, "decode value_len 8193");
        /* And the 32-bit extreme. */
        la = fx_must_encode(f, a);
        memset(a + REC(0) + R_VALLEN, 0xFF, 4);
        expect_decode_reject(a, la, "decode value_len 0xFFFFFFFF");
        free(a);
        fx_free(f);
    }

    /* NULL data pointers. key_len >= 1 always, so a NULL key is always
     * illegal; a NULL value is legal ONLY with value_len 0. */
    {
        fixture_t *f = fx_new(2);
        dna_effect_in_t *arr = calloc(MAXN, sizeof(*arr));
        MUST_ALLOC(arr);
        uint8_t *b = buf_new();
        size_t w = 0xdead;

        fx_input(f, arr);
        CHECK(dna_effect_result_encode(arr, f->n, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == 0);
        arr[1].key = NULL;
        w = 0xdead;
        CHECK(dna_effect_result_encode(arr, f->n, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == -1);
        CHECK(w == 0);
        arr[1].key   = f->key[1];
        arr[0].value = NULL;
        w = 0xdead;
        CHECK(dna_effect_result_encode(arr, f->n, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == -1);
        CHECK(w == 0);
        /* NULL value with length 0 is legal. */
        arr[0].hdr.value_len = 0;
        w = 0xdead;
        CHECK(dna_effect_result_encode(arr, f->n, b,
                                       (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                       &w) == 0);
        CHECK(w != 0);

        /* NULL dst / NULL written_out / insufficient capacity. */
        fx_input(f, arr);
        size_t need = 0;
        CHECK(dna_effect_result_encoded_size(arr, f->n, &need) == 0);
        CHECK(dna_effect_result_encode(arr, f->n, b, need, NULL) == -1);
        w = 0xdead;
        CHECK(dna_effect_result_encode(arr, f->n, NULL, need, &w) == -1);
        CHECK(w == 0);
        w = 0xdead;
        CHECK(dna_effect_result_encode(arr, f->n, b, need - 1, &w) == -1);
        CHECK(w == 0);
        CHECK(dna_effect_result_encode(arr, f->n, b, need, &w) == 0);
        CHECK(w == need);
        /* NULL effects with n > 0. */
        w = 0xdead;
        CHECK(dna_effect_result_encode(NULL, 1, b, need, &w) == -1);
        CHECK(w == 0);

        free(b);
        free(arr);
        fx_free(f);
    }
}

/**
 * The total cap, INCLUSIVE, from both sides: a result of EXACTLY
 * DNA_EFFECT_MAX_TOTAL_LEN bytes is valid, and one byte more is not.
 *
 *   23 + 8*84 = 695 head+records, + 8 one-byte keys = 703,
 *   + 7 * 8192 = 58047, + one tuned value of 7489 = 65536 exactly.
 */
static void test_total_cap(void) {
    fixture_t *f = fx_alloc();
    f->n = 8;
    for (uint16_t i = 0; i < 8; i++) {
        f->hdr[i].op_id       = 1u + i;
        f->hdr[i].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[i].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_set_key(f, i, 1, (uint8_t)(0x60 + i));
        fx_set_val(f, i, (i < 7) ? DNA_EFFECT_MAX_VALUE_LEN : 7489u,
                   (uint8_t)(0x70 + i));
    }
    size_t need = 0;
    {
        dna_effect_in_t *arr = calloc(MAXN, sizeof(*arr));
        MUST_ALLOC(arr);
        fx_input(f, arr);
        CHECK(dna_effect_result_encoded_size(arr, f->n, &need) == 0);
        free(arr);
    }
    CHECK(need == (size_t)DNA_EFFECT_MAX_TOTAL_LEN);

    uint8_t *a = buf_new();
    size_t la = fx_must_encode(f, a);
    CHECK(la == (size_t)DNA_EFFECT_MAX_TOTAL_LEN);
    roundtrip(f, "exactly 65536 bytes");

    /* One byte over, encode side. */
    fixture_t *g = fx_clone(f);
    fx_set_val(g, 7, 7490u, 0x77);
    expect_encode_reject(g, "65537 bytes");
    fx_free(g);

    /* One byte over, decode side: bump the last value_len and hand decode
     * one more byte. The buffer really is 65537 bytes long, so only the
     * cap can explain the rejection. */
    la = fx_must_encode(f, a);
    uint32_t plus = 7490u;
    a[REC(7) + R_VALLEN]     = (uint8_t)(plus >> 24);
    a[REC(7) + R_VALLEN + 1] = (uint8_t)(plus >> 16);
    a[REC(7) + R_VALLEN + 2] = (uint8_t)(plus >> 8);
    a[REC(7) + R_VALLEN + 3] = (uint8_t)plus;
    expect_decode_reject(a, (size_t)DNA_EFFECT_MAX_TOTAL_LEN + 1,
                         "declared size 65537");

    free(a);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * 5. Ordering and duplicates
 * ════════════════════════════════════════════════════════════════════ */

static void test_ordering(void) {
    /* Correctly ordered effects are accepted — the control for everything
     * below. */
    {
        fixture_t *f = fx_alloc();
        f->n = 4;
        /* kind-major: two CREATEs, then a SET, then a DELETE. */
        f->hdr[0].op_id = 1;
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        f->hdr[1].op_id = 9;
        f->hdr[1].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[1].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        f->hdr[2].op_id = 2;
        f->hdr[2].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[2].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        f->hdr[3].op_id = 0;
        f->hdr[3].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        f->hdr[3].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        for (uint16_t i = 0; i < 4; i++) {
            fx_set_key(f, i, 2, (uint8_t)(0x50 + i));
            fx_set_val(f, i, (i == 3) ? 0 : 2, (uint8_t)(0xB0 + i));
        }
        roundtrip(f, "canonical kind-major order");

        /* kind-order inversion: the SET moved in front of a CREATE. */
        fixture_t *g = fx_clone(f);
        dna_effect_hdr_t th = g->hdr[1]; g->hdr[1] = g->hdr[2]; g->hdr[2] = th;
        uint8_t *tk = g->key[1]; g->key[1] = g->key[2]; g->key[2] = tk;
        uint8_t *tv = g->val[1]; g->val[1] = g->val[2]; g->val[2] = tv;
        expect_encode_reject(g, "SET before CREATE (kind inversion)");
        fx_free(g);
        fx_free(f);
    }

    /* op_id-order inversion inside one kind. */
    {
        fixture_t *f = fx_new(3);
        f->hdr[0].op_id = 5;
        f->hdr[1].op_id = 4;
        f->hdr[2].op_id = 9;
        expect_encode_reject(f, "descending op_id");
        /* Equal op ids with DESCENDING keys: the tie-break axis is what
         * has to reject here, so the keys are set explicitly rather than
         * left to the fixture generator. */
        f->hdr[0].op_id = 4; f->hdr[1].op_id = 4; f->hdr[2].op_id = 9;
        { uint8_t a[1] = {0x30}; fx_key_bytes(f, 0, a, 1); }
        { uint8_t b[1] = {0x20}; fx_key_bytes(f, 1, b, 1); }
        expect_encode_reject(f, "equal op_id, descending keys");
        /* Equal op ids AND equal keys: a duplicate, not merely unordered. */
        { uint8_t c[1] = {0x30}; fx_key_bytes(f, 1, c, 1); }
        expect_encode_reject(f, "equal op_id, equal keys");
        fx_free(f);
    }

    /* key-order inversion with the same kind AND the same op. */
    {
        fixture_t *f = fx_new(2);
        f->hdr[0].op_id = 3;
        f->hdr[1].op_id = 3;
        { uint8_t a[2] = {0x20, 0x22}; fx_key_bytes(f, 0, a, 2); }
        { uint8_t b[2] = {0x20, 0x21}; fx_key_bytes(f, 1, b, 2); }
        expect_encode_reject(f, "descending keys, same kind+op");
        /* The same pair the right way round is accepted. */
        { uint8_t a[2] = {0x20, 0x21}; fx_key_bytes(f, 0, a, 2); }
        { uint8_t b[2] = {0x20, 0x22}; fx_key_bytes(f, 1, b, 2); }
        roundtrip(f, "ascending keys, same kind+op");
        fx_free(f);
    }

    /* Rule 3, the PREFIX rule: {20,21} then {20,21,22} is canonical
     * (shorter first); reversed is not. */
    {
        fixture_t *f = fx_new(2);
        f->hdr[0].op_id = 3;
        f->hdr[1].op_id = 3;
        { uint8_t a[2] = {0x20, 0x21};       fx_key_bytes(f, 0, a, 2); }
        { uint8_t b[3] = {0x20, 0x21, 0x22}; fx_key_bytes(f, 1, b, 3); }
        roundtrip(f, "prefix rule: shorter key first");

        fixture_t *g = fx_clone(f);
        { uint8_t a[3] = {0x20, 0x21, 0x22}; fx_key_bytes(g, 0, a, 3); }
        { uint8_t b[2] = {0x20, 0x21};       fx_key_bytes(g, 1, b, 2); }
        expect_encode_reject(g, "prefix rule: longer key first");
        fx_free(g);
        fx_free(f);
    }

    /* Two different adapter operations with EQUAL raw key bytes stay
     * DISTINCT: op_id is part of the canonical namespace. */
    {
        fixture_t *f = fx_new(2);
        f->hdr[0].op_id = 1;
        f->hdr[1].op_id = 2;
        { uint8_t k[3] = {0xAB, 0xCD, 0xEF};
          fx_key_bytes(f, 0, k, 3); fx_key_bytes(f, 1, k, 3); }
        roundtrip(f, "same key bytes under two different op ids");
        fx_free(f);
    }
}

static void test_duplicates(void) {
    /* Adjacent duplicate: same kind, same op, same key. */
    {
        fixture_t *f = fx_new(2);
        f->hdr[0].op_id = 4;
        f->hdr[1].op_id = 4;
        { uint8_t k[2] = {0x77, 0x88};
          fx_key_bytes(f, 0, k, 2); fx_key_bytes(f, 1, k, 2); }
        expect_encode_reject(f, "adjacent duplicate (kind, op, key)");
        fx_free(f);
    }

    /* CROSS-KIND duplicate — the load-bearing case. CREATE(op1, K) and
     * DELETE(op1, K) are NOT adjacent under a kind-major order once a
     * middle record separates them, so the strict-ascent check alone
     * cannot see them; only the pairwise scan can. */
    {
        fixture_t *f = fx_alloc();
        f->n = 3;
        static const uint8_t K[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        f->hdr[0].op_id = 1;
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        fx_key_bytes(f, 0, K, 4);
        fx_set_val(f, 0, 2, 0x01);

        f->hdr[1].op_id = 5;
        f->hdr[1].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[1].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_set_key(f, 1, 3, 0x40);
        fx_set_val(f, 1, 2, 0x02);

        f->hdr[2].op_id = 1;
        f->hdr[2].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        f->hdr[2].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_key_bytes(f, 2, K, 4);
        fx_set_val(f, 2, 0, 0);

        /* The three records ARE strictly ascending under the total order
         * (kinds 1 < 2 < 3), so this fixture isolates the uniqueness rule
         * from the ordering rule. */
        expect_encode_reject(f, "cross-kind duplicate logical key");

        /* Same three records with effect 2's op changed: accepted, which
         * proves the rejection above was the shared logical key and not
         * the shape. */
        f->hdr[2].op_id = 6;
        roundtrip(f, "same shape, distinct logical keys");
        fx_free(f);
    }

    /* Non-adjacent duplicate within one kind is impossible under a strict
     * ascent (equal records would have to be adjacent), so the
     * three-record version of it is the cross-kind one above. What IS
     * reachable inside one kind is a duplicate separated by a different
     * op — assert it rejects. */
    {
        fixture_t *f = fx_new(3);
        static const uint8_t K[2] = {0x11, 0x22};
        f->hdr[0].op_id = 1; fx_key_bytes(f, 0, K, 2);
        f->hdr[1].op_id = 2; fx_set_key(f, 1, 2, 0x30);
        f->hdr[2].op_id = 1; fx_key_bytes(f, 2, K, 2);
        /* (records 0 and 2 share the logical key AND break the ascent —
         * both rules bite; the point is that neither lets it through) */
        expect_encode_reject(f, "non-adjacent duplicate logical key");
        fx_free(f);
    }

    /* Decode side of the ordering rules: rewrite the record region of a
     * valid two-effect encoding so the two records swap places, keeping
     * every length and both key blobs where the offsets say they are. The
     * result is a well-formed, self-consistent, NON-CANONICAL encoding —
     * exactly what a hostile peer would send. */
    {
        fixture_t *f = fx_new(2);
        f->hdr[0].op_id = 1;
        f->hdr[1].op_id = 2;
        fx_set_key(f, 0, 2, 0x10);
        fx_set_key(f, 1, 2, 0x20);
        fx_set_val(f, 0, 2, 0x30);
        fx_set_val(f, 1, 2, 0x40);
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);

        uint8_t *m = buf_new();
        memcpy(m, a, la);
        /* Swap only the op_id fields: record 0 now claims op 2 and record
         * 1 claims op 1, which is a descent. Every length is untouched. */
        m[REC(0) + R_OP + 3] = 2;
        m[REC(1) + R_OP + 3] = 1;
        expect_decode_reject(m, la, "decode: descending op_id");

        /* Make both records claim the same op and the same key length,
         * then make the second key equal to the first: a duplicate on the
         * wire. */
        memcpy(m, a, la);
        m[REC(1) + R_OP + 3] = 1;
        memcpy(m + REC(2) + 2, m + REC(2), 2);
        expect_decode_reject(m, la, "decode: duplicate logical key");
        free(m);
        free(a);
        fx_free(f);
    }

    /* CROSS-KIND duplicate on the WIRE — the decode-side twin of the
     * load-bearing case. CREATE(op1, K) then SET(op1, K) is strictly
     * ascending (kind 1 < 2), so the ascent check waves it through and
     * ONLY the pairwise uniqueness scan can reject it.
     *
     * The encoder cannot produce this buffer (it rejects it), so it is
     * built by encoding a VALID pair whose keys differ and then
     * overwriting the second key with the first. Both keys have the same
     * length, so every offset and the total length stay untouched. */
    {
        fixture_t *f = fx_alloc();
        f->n = 2;
        f->hdr[0].op_id       = 1;
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        { uint8_t k[4] = {0xDE, 0xAD, 0xBE, 0xEF}; fx_key_bytes(f, 0, k, 4); }
        fx_set_val(f, 0, 2, 0x11);

        f->hdr[1].op_id       = 1;
        f->hdr[1].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[1].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        { uint8_t k[4] = {0x00, 0x11, 0x22, 0x33}; fx_key_bytes(f, 1, k, 4); }
        fx_set_val(f, 1, 3, 0x22);

        /* Control: with distinct keys the pair is legal. */
        uint8_t *a = buf_new();
        size_t la = fx_must_encode(f, a);
        roundtrip(f, "cross-kind, same op, DISTINCT keys");

        /* Now make the second key equal to the first, on the wire only. */
        uint8_t *m = buf_new();
        memcpy(m, a, la);
        memcpy(m + REC(2) + 4, m + REC(2), 4);
        expect_decode_reject(m, la, "decode: cross-kind duplicate logical key");

        free(m);
        free(a);
        fx_free(f);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * 6. Precondition FORM — the codec side only. Whether a precondition is
 *    TRUE is the adapter/runtime's question, never this file's.
 * ════════════════════════════════════════════════════════════════════ */

/** Is (kind, precond) one of the seven legal pairs? */
static int pair_is_legal(uint8_t kind, uint8_t pre) {
    if (kind == (uint8_t)DNA_EFFECT_CREATE)
        return pre == (uint8_t)DNA_EFFECT_PRE_ABSENT;
    if (kind == (uint8_t)DNA_EFFECT_SET || kind == (uint8_t)DNA_EFFECT_DELETE)
        return pre == (uint8_t)DNA_EFFECT_PRE_EXISTS ||
               pre == (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION ||
               pre == (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
    return 0;
}

/**
 * ALL (kind 0..4) x (precond 0..5) pairs, exhaustively, on BOTH paths.
 * value_len is 0 and both reserved fields are zero throughout, so the ONLY
 * thing under test is the legality biconditional.
 *
 * Exactly SEVEN pairs are legal: CREATE+ABSENT, and SET/DELETE x
 * {EXISTS, EXISTS_VERSION, EXISTS_VHASH}.
 */
static void test_precond_matrix(void) {
    size_t blen = 0;
    uint8_t *base = mutation_base(&blen);   /* CREATE+ABSENT, key {0x41} */
    uint8_t *m = buf_new();
    uint8_t *b = buf_new();
    uint8_t key = 0x41;
    int accepts = 0, rejects = 0;

    for (unsigned k = 0; k <= 4; k++) {
        for (unsigned p = 0; p <= 5; p++) {
            int legal = pair_is_legal((uint8_t)k, (uint8_t)p);
            char what[96];
            snprintf(what, sizeof(what), "pair kind=%u precond=%u", k, p);

            /* ── encode path ── */
            dna_effect_in_t e;
            memset(&e, 0, sizeof(e));
            e.hdr.op_id       = 1;
            e.hdr.effect_kind = (uint8_t)k;
            e.hdr.precond_tag = (uint8_t)p;
            e.hdr.key_len     = 1;
            e.key             = &key;
            e.value           = NULL;
            size_t w = 0xdead;
            int rc = dna_effect_result_encode(&e, 1, b,
                                              (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                              &w);
            if (legal) {
                CHECK(rc == 0);
                CHECK(w == REC(1) + 1);
                accepts++;
            } else {
                if (rc != -1) {
                    fprintf(stderr, "FAIL %s: encode ACCEPTED an illegal "
                                    "pair\n", what);
                    failures++;
                } else if (w != 0) {
                    fprintf(stderr, "FAIL %s: written_out not zeroed\n", what);
                    failures++;
                } else {
                    g_checks++;
                }
                rejects++;
            }

            /* ── decode path (patch the two bytes of a valid record) ── */
            memcpy(m, base, blen);
            m[REC(0) + R_KIND] = (uint8_t)k;
            m[REC(0) + R_PRE]  = (uint8_t)p;
            if (legal) {
                dna_effect_view_t *v = calloc(1, sizeof(*v));
                MUST_ALLOC(v);
                CHECK(dna_effect_result_decode(m, blen, v) == 0);
                CHECK(v->eff[0].effect_kind == (uint8_t)k);
                CHECK(v->eff[0].precond_tag == (uint8_t)p);
                free(v);
            } else {
                expect_decode_reject(m, blen, what);
            }
        }
    }
    /* The biconditional yields SEVEN legal pairs out of thirty. */
    CHECK(accepts == 7);
    CHECK(rejects == 23);

    free(b);
    free(m);
    free(base);
}

/**
 * The FORM cases the matrix covers only structurally, restated as named
 * assertions, plus the two field-vs-tag pins that make an expected version
 * and an expected value hash mutually exclusive.
 */
static void test_precond_form(void) {
    /* CREATE + ABSENT accepted; CREATE + each EXISTS* rejected. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        roundtrip(f, "CREATE + ABSENT");

        const uint8_t bad[3] = {DNA_EFFECT_PRE_EXISTS,
                                DNA_EFFECT_PRE_EXISTS_VERSION,
                                DNA_EFFECT_PRE_EXISTS_VHASH};
        for (int t = 0; t < 3; t++) {
            fixture_t *g = fx_clone(f);
            g->hdr[0].precond_tag = bad[t];
            expect_encode_reject(g, "CREATE with an EXISTS* precondition");
            fx_free(g);
        }
        fx_free(f);
    }

    /* SET + ABSENT and DELETE + ABSENT rejected. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_SET;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        expect_encode_reject(f, "SET + ABSENT");
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        fx_set_val(f, 0, 0, 0);
        expect_encode_reject(f, "DELETE + ABSENT");
        fx_free(f);
    }

    /* SET / DELETE with each EXISTS* accepted, including expected_version
     * == 0 (0 IS a legal expected version; only the TAG gates the field). */
    {
        const uint8_t kinds[2] = {DNA_EFFECT_SET, DNA_EFFECT_DELETE};
        for (int ki = 0; ki < 2; ki++) {
            fixture_t *f = fx_new(1);
            f->hdr[0].effect_kind = kinds[ki];
            if (kinds[ki] == DNA_EFFECT_DELETE) fx_set_val(f, 0, 0, 0);

            f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
            roundtrip(f, "kind + EXISTS");

            f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
            f->hdr[0].expected_version = 0;
            roundtrip(f, "kind + EXISTS_VERSION, expected_version 0");
            f->hdr[0].expected_version = 0x0123456789ABCDEFULL;
            roundtrip(f, "kind + EXISTS_VERSION, expected_version non-zero");
            f->hdr[0].expected_version = 0;

            f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
            memset(f->hdr[0].expected_vhash, 0, HASH_LEN);
            roundtrip(f, "kind + EXISTS_VHASH, all-zero hash");
            memcpy(f->hdr[0].expected_vhash, K_VH_EEEF, HASH_LEN);
            roundtrip(f, "kind + EXISTS_VHASH, real value hash");
            fx_free(f);
        }
    }

    /* Mutual exclusion, pinned as the two reserved-field rules: a version
     * under the hash tag and a hash under the version tag. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH;
        f->hdr[0].expected_version = 1;
        expect_encode_reject(f, "expected_version != 0 under EXISTS_VHASH");
        f->hdr[0].expected_version = 0;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION;
        f->hdr[0].expected_vhash[0] = 1;
        expect_encode_reject(f, "expected_vhash != 0 under EXISTS_VERSION");
        memset(f->hdr[0].expected_vhash, 0, HASH_LEN);
        /* ...and under the two tags that consume neither field. */
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        f->hdr[0].expected_version = 7;
        expect_encode_reject(f, "expected_version != 0 under EXISTS");
        f->hdr[0].expected_version = 0;
        f->hdr[0].expected_vhash[63] = 1;
        expect_encode_reject(f, "expected_vhash != 0 under EXISTS");
        memset(f->hdr[0].expected_vhash, 0, HASH_LEN);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_CREATE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        f->hdr[0].expected_version = 1;
        expect_encode_reject(f, "expected_version != 0 under ABSENT");
        fx_free(f);
    }

    /* DELETE with a non-zero value_len is rejected on both paths. */
    {
        fixture_t *f = fx_new(1);
        f->hdr[0].effect_kind = (uint8_t)DNA_EFFECT_DELETE;
        f->hdr[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_EXISTS;
        fx_set_val(f, 0, 1, 0x5c);
        expect_encode_reject(f, "DELETE with value_len 1");
        fx_set_val(f, 0, DNA_EFFECT_MAX_VALUE_LEN, 0x5c);
        expect_encode_reject(f, "DELETE with value_len 8192");
        fx_set_val(f, 0, 0, 0);
        roundtrip(f, "DELETE with value_len 0");
        fx_free(f);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * 7. dna_effect_value_hash negatives
 * ════════════════════════════════════════════════════════════════════ */

static void test_value_hash_rejects(void) {
    uint8_t out[HASH_LEN];
    uint8_t ref[HASH_LEN];
    static const uint8_t v[4] = {0xa0, 0xa1, 0xa2, 0xa3};

    /* The digest buffer must be UNTOUCHED after every reject: prefill it
     * with 0xAA and demand every byte back. */
    memset(ref, 0xAA, sizeof(ref));

    memset(out, 0xAA, sizeof(out));
    CHECK(dna_effect_value_hash(NULL, 1, out) == -1);
    CHECK(memcmp(out, ref, HASH_LEN) == 0);

    memset(out, 0xAA, sizeof(out));
    CHECK(dna_effect_value_hash(NULL, 0xFFFFFFFFu, out) == -1);
    CHECK(memcmp(out, ref, HASH_LEN) == 0);

    memset(out, 0xAA, sizeof(out));
    CHECK(dna_effect_value_hash(v, DNA_EFFECT_MAX_VALUE_LEN + 1, out) == -1);
    CHECK(memcmp(out, ref, HASH_LEN) == 0);

    memset(out, 0xAA, sizeof(out));
    CHECK(dna_effect_value_hash(v, 0xFFFFFFFFu, out) == -1);
    CHECK(memcmp(out, ref, HASH_LEN) == 0);

    CHECK(dna_effect_value_hash(v, 4, NULL) == -1);
    CHECK(dna_effect_value_hash(NULL, 0, NULL) == -1);

    /* The accept side of the length bound: exactly 8192 hashes. */
    {
        uint8_t *big = malloc(DNA_EFFECT_MAX_VALUE_LEN);
        MUST_ALLOC(big);
        for (uint32_t j = 0; j < DNA_EFFECT_MAX_VALUE_LEN; j++)
            big[j] = (uint8_t)(j * 31u + 7u);
        memset(out, 0xAA, sizeof(out));
        CHECK(dna_effect_value_hash(big, DNA_EFFECT_MAX_VALUE_LEN, out) == 0);
        CHECK(memcmp(out, ref, HASH_LEN) != 0);
        /* Deterministic: the same input must hash identically every time. */
        uint8_t again[HASH_LEN];
        CHECK(dna_effect_value_hash(big, DNA_EFFECT_MAX_VALUE_LEN,
                                    again) == 0);
        CHECK(memcmp(out, again, HASH_LEN) == 0);
        /* The length prefix separates a truncated value from a short one. */
        uint8_t h1[HASH_LEN], h2[HASH_LEN];
        CHECK(dna_effect_value_hash(big, 8, h1) == 0);
        CHECK(dna_effect_value_hash(big, 9, h2) == 0);
        CHECK(memcmp(h1, h2, HASH_LEN) != 0);
        free(big);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * 8. DETERMINISTIC PROPERTY TESTS — seeded, never time() or rand().
 * ════════════════════════════════════════════════════════════════════ */

/**
 * xorshift64* with a PINNED literal seed: the same sequence on every
 * machine, every run, forever. A wall-clock or rand() seed here would make
 * a failure unreproducible, which this project forbids outright.
 *
 * THE SEASON'S PROPERTY SEED: 0xEFFEC70123456789.
 */
#define PROP_SEED  0xEFFEC70123456789ULL
static uint64_t g_rng;

static void rng_reset(void) { g_rng = PROP_SEED; }

static uint64_t rng_next(void) {
    uint64_t x = g_rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint32_t rng_below(uint32_t bound) {
    return (uint32_t)(rng_next() % (uint64_t)bound);
}

static void seed_note(const char *what, size_t iter) {
    fprintf(stderr, "  (reproduce: seed=0x%016llx %s iter=%zu)\n",
            (unsigned long long)PROP_SEED, what, iter);
}

/**
 * Generate a random VALID effect list of at least `min_n` effects.
 *
 * CANONICALITY BY CONSTRUCTION: effect_kind is NON-DECREASING and op_id is
 * GLOBALLY strictly increasing. Together those make (kind, op_id) strictly
 * ascending, so the record order is canonical whatever the key bytes are,
 * AND every logical key (op_id, key) is distinct because op_id already is.
 * The key bytes can therefore be fully random without ever colliding.
 */
static uint16_t gen_valid(fixture_t *f, uint16_t min_n) {
    uint16_t n = (uint16_t)(min_n + rng_below((uint32_t)(9 - min_n)));
    for (uint16_t i = 0; i < MAXN; i++) {
        fx_set_key(f, i, 0, 0);
        fx_set_val(f, i, 0, 0);
        memset(&f->hdr[i], 0, sizeof(f->hdr[i]));
    }
    f->n = n;
    uint8_t  kind = 1;
    uint32_t op   = rng_below(5);
    for (uint16_t i = 0; i < n; i++) {
        if (kind < 3 && rng_below(3) == 0) kind++;
        op += 1u + rng_below(3);
        f->hdr[i].op_id       = op;
        f->hdr[i].effect_kind = kind;
        f->hdr[i].precond_tag = (kind == (uint8_t)DNA_EFFECT_CREATE)
                                    ? (uint8_t)DNA_EFFECT_PRE_ABSENT
                                    : (uint8_t)(2 + rng_below(3));
        f->hdr[i].expected_version = 0;
        memset(f->hdr[i].expected_vhash, 0, HASH_LEN);
        if (f->hdr[i].precond_tag == (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION)
            f->hdr[i].expected_version = rng_next();
        if (f->hdr[i].precond_tag == (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH)
            for (int j = 0; j < HASH_LEN; j++)
                f->hdr[i].expected_vhash[j] = (uint8_t)rng_next();
        fx_set_key(f, i, 1 + rng_below(16), (uint8_t)rng_next());
        fx_set_val(f, i,
                   (kind == (uint8_t)DNA_EFFECT_DELETE) ? 0 : rng_below(65),
                   (uint8_t)rng_next());
    }
    return n;
}

/** encode -> decode -> field compare -> re-encode byte-identical. */
static void prop_roundtrip(void) {
    rng_reset();
    fixture_t *f = fx_alloc();
    uint8_t *a = buf_new();
    uint8_t *b = buf_new();
    dna_effect_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);

    for (size_t it = 0; it < 500; it++) {
        int before = failures;
        uint16_t n = gen_valid(f, 0);
        size_t la = 0, lb = 0;
        /* These two are hard gates rather than plain CHECKs: everything
         * below dereferences the decoded view, so a failure here has to
         * stop the battery instead of walking a zeroed view. */
        if (fx_encode(f, a, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &la) != 0) {
            fprintf(stderr, "FAIL property roundtrip: encode rejected a "
                            "generated valid result\n");
            failures++;
            seed_note("roundtrip-encode", it);
            break;
        }
        if (dna_effect_result_decode(a, la, v) != 0) {
            fprintf(stderr, "FAIL property roundtrip: decode rejected its "
                            "own encoding\n");
            failures++;
            seed_note("roundtrip-decode", it);
            break;
        }
        g_checks += 2;
        CHECK(v->effect_count == n);
        CHECK(v->res_len == la);
        for (uint16_t i = 0; i < n; i++) {
            cmp_hdr(&v->eff[i], &f->hdr[i]);
            CHECK(memcmp(v->buf + v->key_off[i], f->key[i],
                         f->hdr[i].key_len) == 0);
            if (f->hdr[i].value_len)
                CHECK(memcmp(v->buf + v->val_off[i], f->val[i],
                             f->hdr[i].value_len) == 0);
        }
        CHECK(view_reencode(v, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN, &lb) == 0);
        CHECK(lb == la);
        CHECK(memcmp(a, b, la) == 0);
        if (failures != before) { seed_note("roundtrip", it); break; }
    }
    free(v);
    free(b);
    free(a);
    fx_free(f);
}

/** Any truncation of a valid encoding must be rejected. */
static void prop_truncation(void) {
    rng_reset();
    fixture_t *f = fx_alloc();
    uint8_t *a = buf_new();

    for (size_t it = 0; it < 200; it++) {
        int before = failures;
        gen_valid(f, 0);
        size_t la = fx_must_encode(f, a);
        size_t cut = (size_t)rng_below((uint32_t)la);   /* 0 .. la-1 */
        expect_decode_reject(a, cut, "property truncation");
        if (failures != before) { seed_note("truncation", it); break; }
    }
    free(a);
    fx_free(f);
}

/** Swapping two adjacent effects at the INPUT level must be rejected. */
static void prop_order_swap(void) {
    rng_reset();
    fixture_t *f = fx_alloc();

    for (size_t it = 0; it < 200; it++) {
        int before = failures;
        uint16_t n = gen_valid(f, 2);
        uint16_t i = (uint16_t)rng_below((uint32_t)(n - 1));
        dna_effect_hdr_t th = f->hdr[i];
        f->hdr[i] = f->hdr[i + 1]; f->hdr[i + 1] = th;
        uint8_t *tk = f->key[i];
        f->key[i] = f->key[i + 1]; f->key[i + 1] = tk;
        uint8_t *tv = f->val[i];
        f->val[i] = f->val[i + 1]; f->val[i + 1] = tv;
        expect_encode_reject(f, "property adjacent swap");
        if (failures != before) { seed_note("order-swap", it); break; }
    }
    fx_free(f);
}

/** Duplicating one effect's logical key into another must be rejected. */
static void prop_duplicate_key(void) {
    rng_reset();
    fixture_t *f = fx_alloc();

    for (size_t it = 0; it < 200; it++) {
        int before = failures;
        uint16_t n = gen_valid(f, 2);
        uint16_t a = (uint16_t)rng_below(n);
        uint16_t b = (uint16_t)rng_below(n);
        if (a == b) b = (uint16_t)((a + 1) % n);
        f->hdr[b].op_id = f->hdr[a].op_id;
        fx_key_bytes(f, b, f->key[a], f->hdr[a].key_len);
        expect_encode_reject(f, "property duplicated logical key");
        if (failures != before) { seed_note("duplicate-key", it); break; }
    }
    fx_free(f);
}

/**
 * Corrupt ONE byte of the header region of a valid encoding: the fixed
 * head's tail (offsets 16..22) or a record's kind / precond / reserved
 * fields. Decode must either REJECT, or — if it accepts — the re-encoding
 * must be byte-identical to the corrupted input, i.e. the corruption
 * landed on something that is still canonical.
 */
static void prop_header_corruption(void) {
    rng_reset();
    fixture_t *f = fx_alloc();
    uint8_t *a = buf_new();
    uint8_t *m = buf_new();
    uint8_t *b = buf_new();
    dna_effect_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);

    for (size_t it = 0; it < 100; it++) {
        int before = failures;
        uint16_t n = gen_valid(f, 1);
        size_t la = fx_must_encode(f, a);
        memcpy(m, a, la);

        /* Candidate offsets: the head fields that are not the family
         * marker, plus the per-record kind, precond and reserved fields. */
        size_t cand[7 + MAXN * (2 + 8 + HASH_LEN)];
        size_t nc = 0;
        for (size_t j = 16; j < 23; j++) cand[nc++] = j;
        for (uint16_t i = 0; i < n; i++) {
            cand[nc++] = REC(i) + R_KIND;
            cand[nc++] = REC(i) + R_PRE;
            for (int j = 0; j < 8;       j++) cand[nc++] = REC(i) + R_VER + j;
            for (int j = 0; j < HASH_LEN; j++) cand[nc++] = REC(i) + R_VHASH + j;
        }
        size_t pos = cand[rng_below((uint32_t)nc)];
        m[pos] ^= (uint8_t)(1u + rng_below(255));

        if (dna_effect_result_decode(m, la, v) == 0) {
            size_t lb = 0;
            CHECK(view_reencode(v, b, (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
                                &lb) == 0);
            CHECK(lb == la);
            /* CANONICALITY: an accepted input must be its own encoding. */
            CHECK(memcmp(b, m, la) == 0);
        } else {
            /* Rejected: the view must be fully zeroed. */
            CHECK(v->effect_count == 0);
            CHECK(v->buf == NULL);
            g_checks++;
        }
        if (failures != before) { seed_note("header-corruption", it); break; }
    }
    free(v);
    free(b);
    free(m);
    free(a);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("sizeof(dna_effect_view_t) = %zu bytes, "
           "sizeof(dna_effect_hdr_t) = %zu bytes\n",
           sizeof(dna_effect_view_t), sizeof(dna_effect_hdr_t));

    test_canonical_shapes();
    test_pinned_offsets();
    test_kat();
    test_truncation_and_suffix();
    test_head_field_rejects();
    test_size_formula();
    test_count_bounds();
    test_blob_bounds();
    test_total_cap();
    test_ordering();
    test_duplicates();
    test_precond_matrix();
    test_precond_form();
    test_value_hash_rejects();
    prop_roundtrip();
    prop_truncation();
    prop_order_swap();
    prop_duplicate_key();
    prop_header_corruption();

    if (failures) {
        fprintf(stderr, "test_effect_wire: %d check(s) failed (%d passed)\n",
                failures, g_checks);
        return 1;
    }
    printf("test_effect_wire: all %d checks passed\n", g_checks);
    return 0;
}
