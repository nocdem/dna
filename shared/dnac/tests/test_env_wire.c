/**
 * @file shared/dnac/tests/test_env_wire.c
 * @brief Ledger V2 K1 — round-trip, boundary, reject and BINDING tests for
 *        the generic envelope codec (shared/dnac/env_wire.{h,c}).
 *
 * Three properties are pinned here, in increasing order of importance:
 *
 *   1. CANONICALITY — exactly one encoding exists per envelope, and
 *      encode->decode->encode is byte-identical. Drift between encoder and
 *      decoder is a silent consensus break.
 *   2. FAIL-CLOSED — every malformed input is REJECTED (never clamped),
 *      and after EVERY failing decode the view is fully zeroed, so a caller
 *      can never read a half-walked envelope.
 *   3. BINDING (the mutation battery) — which commitment moves when which
 *      field moves. The load-bearing case is the NON-CIRCULARITY pin:
 *      mutating `auth_data` moves tx_id ONLY and leaves every auth_digest
 *      byte-identical. If that ever breaks, a leg's authorization would
 *      have to sign a value that depends on the signature itself.
 *
 * Buffers are HEAP allocated throughout: DNA_ENV_MAX_TOTAL_LEN is 64 KiB
 * and the fixture struct carries 64 ruleset hashes, so the stack-local
 * shape used by smaller wire tests would not be safe here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/env_wire.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond) do {                                                 \
    if (!(cond)) {                                                       \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
        failures++;                                                      \
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

#define HASH_LEN  DNA_ENV_HASH_LEN

static uint8_t *buf_new(void) {
    uint8_t *b = calloc(1, (size_t)DNA_ENV_MAX_TOTAL_LEN + 16);
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
 * Fixture: a mutable description of one envelope plus its CONTEXTUAL
 * inputs (chain_id, per-leg ruleset_hash). Every mutation test copies a
 * fixture, changes exactly one thing, and re-derives all commitments.
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t          expiry;
    uint64_t          fee;
    uint64_t          res_total;
    uint16_t          n;
    dna_env_leg_hdr_t hdr[DNA_ENV_MAX_LEGS];
    uint8_t          *call[DNA_ENV_MAX_LEGS];   /* hdr[i].call_len bytes */
    uint8_t          *auth[DNA_ENV_MAX_LEGS];   /* hdr[i].auth_len bytes */
    uint8_t           chain_id[DNA_ENV_CHAIN_ID_LEN];
    uint8_t           rh[DNA_ENV_MAX_LEGS][DNA_ENV_RULESET_HASH_LEN];
} fixture_t;

/** Replace leg i's call blob (frees the old one). */
static void fx_set_call(fixture_t *f, uint16_t i, uint32_t len, uint8_t seed) {
    free(f->call[i]);
    f->call[i] = NULL;
    if (len) {
        f->call[i] = malloc(len);
        MUST_ALLOC(f->call[i]);
        for (uint32_t j = 0; j < len; j++)
            f->call[i][j] = (uint8_t)(seed + j * 7u + i);
    }
    f->hdr[i].call_len = len;
}

/** Replace leg i's auth blob (frees the old one). */
static void fx_set_auth(fixture_t *f, uint16_t i, uint32_t len, uint8_t seed) {
    free(f->auth[i]);
    f->auth[i] = NULL;
    if (len) {
        f->auth[i] = malloc(len);
        MUST_ALLOC(f->auth[i]);
        for (uint32_t j = 0; j < len; j++)
            f->auth[i][j] = (uint8_t)(seed + j * 13u + i);
    }
    f->hdr[i].auth_len = len;
}

/**
 * A structurally valid n-leg fixture with deterministic content: domain
 * ids strictly ascending, both access modes exercised, non-zero auth kinds,
 * small blobs.
 */
static fixture_t *fx_new(uint16_t n) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    f->expiry    = 0x0000000000112233ULL;
    f->fee       = 1000;
    f->res_total = 50000;
    f->n         = n;
    for (uint16_t i = 0; i < n; i++) {
        f->hdr[i].domain_id            = 1u + 7u * i;
        f->hdr[i].runtime_op           = (uint32_t)(i % 256);
        f->hdr[i].ruleset_version      = 2u + i;
        f->hdr[i].access_mode          = (i % 2) ? (uint8_t)DNA_ENV_ACCESS_READ
                                                 : (uint8_t)DNA_ENV_ACCESS_INVOKE;
        f->hdr[i].auth_kind            = (uint8_t)(1 + (i % 5));
        f->hdr[i].res_max_effects      = 16u + i;
        f->hdr[i].res_max_effect_bytes = 1024u + i;
        fx_set_call(f, i, 4, (uint8_t)(0x10 + i));
        fx_set_auth(f, i, 3, (uint8_t)(0x90 + i));
    }
    for (int j = 0; j < DNA_ENV_CHAIN_ID_LEN; j++)
        f->chain_id[j] = (uint8_t)(0x10 + j);
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++)
        for (int j = 0; j < DNA_ENV_RULESET_HASH_LEN; j++)
            f->rh[i][j] = (uint8_t)(0x40 + j + i);
    return f;
}

static void fx_free(fixture_t *f) {
    if (!f) return;
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        free(f->call[i]);
        free(f->auth[i]);
    }
    free(f);
}

/** Deep copy, so a mutation never disturbs the base fixture. */
static fixture_t *fx_clone(const fixture_t *src) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    *f = *src;
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        f->call[i] = NULL;
        f->auth[i] = NULL;
        if (src->hdr[i].call_len) {
            f->call[i] = malloc(src->hdr[i].call_len);
            MUST_ALLOC(f->call[i]);
            memcpy(f->call[i], src->call[i], src->hdr[i].call_len);
        }
        if (src->hdr[i].auth_len) {
            f->auth[i] = malloc(src->hdr[i].auth_len);
            MUST_ALLOC(f->auth[i]);
            memcpy(f->auth[i], src->auth[i], src->hdr[i].auth_len);
        }
    }
    return f;
}

/** Build the encoder input arrays for a fixture. */
static void fx_input(const fixture_t *f, dna_env_leg_in_t *legs,
                     dna_env_in_t *in) {
    for (uint16_t i = 0; i < f->n; i++) {
        legs[i].hdr       = f->hdr[i];
        legs[i].call_data = f->call[i];
        legs[i].auth_data = f->auth[i];
    }
    in->expiry_height       = f->expiry;
    in->fee_amount          = f->fee;
    in->res_max_total_units = f->res_total;
    in->leg_count           = f->n;
    in->legs                = legs;
}

/** Encode a fixture into `dst`. @return the encode return code. */
static int fx_encode(const fixture_t *f, uint8_t *dst, size_t cap,
                     size_t *written) {
    dna_env_leg_in_t *legs = calloc(DNA_ENV_MAX_LEGS, sizeof(*legs));
    MUST_ALLOC(legs);
    dna_env_in_t in;
    fx_input(f, legs, &in);
    int rc = dna_env_encode(&in, dst, cap, written);
    free(legs);
    return rc;
}

/* ── Derived commitments of one fixture ─────────────────────────────── */

typedef struct {
    uint8_t  call[DNA_ENV_MAX_LEGS][HASH_LEN];
    uint8_t  ctx[HASH_LEN];
    uint8_t  auth[DNA_ENV_MAX_LEGS][HASH_LEN];
    uint8_t  txid[HASH_LEN];
    uint8_t *bytes;      /* the encoded envelope (heap) */
    size_t   len;
    uint16_t n;
} digests_t;

/** Encode, decode, and derive every commitment. Fails loudly. */
static digests_t *fx_digests(const fixture_t *f) {
    digests_t *d = calloc(1, sizeof(*d));
    MUST_ALLOC(d);
    d->bytes = buf_new();
    d->n     = f->n;

    size_t written = 0;
    if (fx_encode(f, d->bytes, (size_t)DNA_ENV_MAX_TOTAL_LEN, &written) != 0) {
        fprintf(stderr, "FATAL: fixture failed to encode\n");
        exit(2);
    }
    d->len = written;

    dna_env_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    if (dna_env_decode(d->bytes, d->len, v) != 0) {
        fprintf(stderr, "FATAL: fixture failed to decode\n");
        exit(2);
    }
    for (uint16_t i = 0; i < f->n; i++)
        CHECK(dna_env_call_commit(v, i, f->rh[i], d->call[i]) == 0);
    CHECK(dna_env_auth_context_commit(
              v, f->chain_id,
              (const uint8_t (*)[HASH_LEN])d->call, d->ctx) == 0);
    for (uint16_t i = 0; i < f->n; i++)
        CHECK(dna_env_auth_digest(d->ctx, i, f->hdr[i].domain_id,
                                  f->hdr[i].runtime_op, d->auth[i]) == 0);
    CHECK(dna_env_tx_id(d->ctx, d->bytes, d->len, d->txid) == 0);
    free(v);
    return d;
}

static void dg_free(digests_t *d) {
    if (!d) return;
    free(d->bytes);
    free(d);
}

/* ── Difference assertions ──────────────────────────────────────────── */

static void expect(const char *what, const uint8_t a[HASH_LEN],
                   const uint8_t b[HASH_LEN], int want_diff) {
    int diff = (memcmp(a, b, HASH_LEN) != 0);
    if (diff != want_diff) {
        fprintf(stderr, "FAIL %s: expected %s, got %s\n", what,
                want_diff ? "DIFFERENT" : "IDENTICAL",
                diff ? "DIFFERENT" : "IDENTICAL");
        failures++;
    }
}

/** Every auth_digest of two derivations must differ / be identical. */
static void expect_all_auth(const char *what, const digests_t *a,
                            const digests_t *b, int want_diff) {
    uint16_t n = (a->n < b->n) ? a->n : b->n;
    for (uint16_t i = 0; i < n; i++) {
        char label[128];
        snprintf(label, sizeof(label), "%s auth_digest[%u]", what, i);
        expect(label, a->auth[i], b->auth[i], want_diff);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * 1. Size formula
 * ════════════════════════════════════════════════════════════════════ */

static void test_size_formula(void) {
    dna_env_leg_in_t *legs = calloc(DNA_ENV_MAX_LEGS, sizeof(*legs));
    MUST_ALLOC(legs);
    size_t out = 0;

    legs[0].hdr.call_len = 10;
    legs[0].hdr.auth_len = 20;
    CHECK(dna_env_encoded_size(legs, 1, &out) == 0);
    CHECK(out == (size_t)DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN + 30);

    legs[1].hdr.call_len = 1;
    legs[1].hdr.auth_len = 2;
    legs[2].hdr.call_len = 0;
    legs[2].hdr.auth_len = 0;
    CHECK(dna_env_encoded_size(legs, 3, &out) == 0);
    CHECK(out == (size_t)DNA_ENV_FIXED_HEAD + 3 * DNA_ENV_LEG_HDR_LEN + 33);

    /* 64 empty legs = the whole leg-header region, nothing else. */
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        legs[i].hdr.call_len = 0;
        legs[i].hdr.auth_len = 0;
    }
    CHECK(dna_env_encoded_size(legs, DNA_ENV_MAX_LEGS, &out) == 0);
    CHECK(out == 1963);

    /* Rejects: NULL out, NULL legs, count bounds. */
    CHECK(dna_env_encoded_size(legs, 1, NULL) == -1);
    out = 0xdead;
    CHECK(dna_env_encoded_size(NULL, 1, &out) == -1);
    CHECK(out == 0);                       /* *out zeroed before reject */
    out = 0xdead;
    CHECK(dna_env_encoded_size(legs, 0, &out) == -1);
    CHECK(out == 0);
    out = 0xdead;
    CHECK(dna_env_encoded_size(legs, DNA_ENV_MAX_LEGS + 1, &out) == -1);
    CHECK(out == 0);

    /* Length-arithmetic overflow attempt: the subtraction-form guard must
     * reject, never wrap into a small total. */
    out = 0xdead;
    legs[0].hdr.call_len = 0xFFFFFFFFu;
    CHECK(dna_env_encoded_size(legs, 1, &out) == -1);
    CHECK(out == 0);
    legs[0].hdr.call_len = 0;
    legs[0].hdr.auth_len = 0xFFFFFFFFu;
    CHECK(dna_env_encoded_size(legs, 1, &out) == -1);
    legs[0].hdr.auth_len = 0;

    /* Cap is INCLUSIVE: exactly DNA_ENV_MAX_TOTAL_LEN accepts, +1 rejects. */
    legs[0].hdr.call_len = DNA_ENV_MAX_TOTAL_LEN -
                           (DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN);
    CHECK(dna_env_encoded_size(legs, 1, &out) == 0);
    CHECK(out == (size_t)DNA_ENV_MAX_TOTAL_LEN);
    legs[0].hdr.call_len += 1;
    CHECK(dna_env_encoded_size(legs, 1, &out) == -1);
    CHECK(out == 0);

    /* Split across the two sections: the cap is on the TOTAL. */
    legs[0].hdr.call_len = 30000;
    legs[0].hdr.auth_len = DNA_ENV_MAX_TOTAL_LEN -
                           (DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN) - 30000;
    CHECK(dna_env_encoded_size(legs, 1, &out) == 0);
    CHECK(out == (size_t)DNA_ENV_MAX_TOTAL_LEN);
    legs[0].hdr.auth_len += 1;
    CHECK(dna_env_encoded_size(legs, 1, &out) == -1);

    free(legs);
}

/* ══════════════════════════════════════════════════════════════════════
 * 2. Round trips
 * ════════════════════════════════════════════════════════════════════ */

/** encode -> decode -> encode must be byte-identical, and every field
 *  and offset must survive the round trip. */
static void roundtrip(fixture_t *f, const char *what) {
    uint8_t *a = buf_new();
    uint8_t *b = buf_new();
    size_t la = 0, lb = 0;

    if (fx_encode(f, a, (size_t)DNA_ENV_MAX_TOTAL_LEN, &la) != 0) {
        fprintf(stderr, "FAIL %s: encode rejected a valid fixture\n", what);
        failures++;
        free(a); free(b);
        return;
    }

    dna_env_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    if (dna_env_decode(a, la, v) != 0) {
        fprintf(stderr, "FAIL %s: decode rejected its own encoding\n", what);
        failures++;
        free(a); free(b); free(v);
        return;
    }

    CHECK(v->envelope_version    == DNA_ENV_VERSION);
    CHECK(v->expiry_height       == f->expiry);
    CHECK(v->fee_amount          == f->fee);
    CHECK(v->res_max_total_units == f->res_total);
    CHECK(v->leg_count           == f->n);
    CHECK(v->env_len             == la);
    CHECK(v->buf                 == a);   /* BORROWED, never copied */

    size_t call_base = (size_t)DNA_ENV_FIXED_HEAD +
                       (size_t)f->n * DNA_ENV_LEG_HDR_LEN;
    size_t off = call_base;
    for (uint16_t i = 0; i < f->n; i++) {
        /* FIELD-BY-FIELD, never memcmp over the struct: dna_env_leg_hdr_t
         * has 2 bytes of padding after the two uint8_t fields under every
         * ABI this project targets. A struct memcmp would compare those
         * padding bytes, which C leaves unspecified after a struct
         * assignment — the assertion would then pass or fail on padding
         * rather than on the nine wire fields it exists to check. */
        CHECK(v->leg[i].domain_id            == f->hdr[i].domain_id);
        CHECK(v->leg[i].runtime_op           == f->hdr[i].runtime_op);
        CHECK(v->leg[i].ruleset_version      == f->hdr[i].ruleset_version);
        CHECK(v->leg[i].access_mode          == f->hdr[i].access_mode);
        CHECK(v->leg[i].auth_kind            == f->hdr[i].auth_kind);
        CHECK(v->leg[i].call_len             == f->hdr[i].call_len);
        CHECK(v->leg[i].auth_len             == f->hdr[i].auth_len);
        CHECK(v->leg[i].res_max_effects      == f->hdr[i].res_max_effects);
        CHECK(v->leg[i].res_max_effect_bytes == f->hdr[i].res_max_effect_bytes);
        CHECK(v->call_off[i] == off);
        if (f->hdr[i].call_len)
            CHECK(memcmp(v->buf + v->call_off[i], f->call[i],
                         f->hdr[i].call_len) == 0);
        off += f->hdr[i].call_len;
    }
    for (uint16_t i = 0; i < f->n; i++) {
        CHECK(v->auth_off[i] == off);
        if (f->hdr[i].auth_len)
            CHECK(memcmp(v->buf + v->auth_off[i], f->auth[i],
                         f->hdr[i].auth_len) == 0);
        off += f->hdr[i].auth_len;
    }
    CHECK(off == la);

    /* Slots at or beyond leg_count stay zeroed — that is what makes a
     * decoded view re-encode byte-identically. */
    for (uint16_t i = f->n; i < DNA_ENV_MAX_LEGS; i++) {
        /* Field-by-field for the same reason as the loop above. */
        CHECK(v->leg[i].domain_id            == 0);
        CHECK(v->leg[i].runtime_op           == 0);
        CHECK(v->leg[i].ruleset_version      == 0);
        CHECK(v->leg[i].access_mode          == 0);
        CHECK(v->leg[i].auth_kind            == 0);
        CHECK(v->leg[i].call_len             == 0);
        CHECK(v->leg[i].auth_len             == 0);
        CHECK(v->leg[i].res_max_effects      == 0);
        CHECK(v->leg[i].res_max_effect_bytes == 0);
        CHECK(v->call_off[i] == 0);
        CHECK(v->auth_off[i] == 0);
    }

    /* Re-encode from the DECODED view's field values. */
    fixture_t *g = fx_clone(f);
    for (uint16_t i = 0; i < v->leg_count; i++)
        g->hdr[i] = v->leg[i];
    g->expiry    = v->expiry_height;
    g->fee       = v->fee_amount;
    g->res_total = v->res_max_total_units;
    g->n         = v->leg_count;
    CHECK(fx_encode(g, b, (size_t)DNA_ENV_MAX_TOTAL_LEN, &lb) == 0);
    CHECK(lb == la);
    CHECK(memcmp(a, b, la) == 0);
    fx_free(g);

    free(v);
    free(a);
    free(b);
}

static void test_roundtrip_shapes(void) {
    fixture_t *f = fx_new(1);
    roundtrip(f, "1 leg");
    fx_free(f);

    f = fx_new(5);
    roundtrip(f, "5 legs");
    fx_free(f);

    /* Zero-length call data, and zero-length auth data under a NON-ZERO
     * auth_kind (a leg may declare a kind and carry no bytes). */
    f = fx_new(3);
    fx_set_call(f, 0, 0, 0);
    fx_set_auth(f, 1, 0, 0);
    fx_set_call(f, 2, 0, 0);
    fx_set_auth(f, 2, 0, 0);
    CHECK(f->hdr[1].auth_kind != 0);
    CHECK(f->hdr[2].auth_kind != 0);
    roundtrip(f, "zero-length blobs");
    fx_free(f);

    /* Mixed, uneven lengths. */
    f = fx_new(4);
    fx_set_call(f, 0, 1,    0x21);
    fx_set_call(f, 1, 255,  0x22);
    fx_set_call(f, 2, 1000, 0x23);
    fx_set_call(f, 3, 0,    0);
    fx_set_auth(f, 0, 4096, 0x31);
    fx_set_auth(f, 1, 0,    0);
    fx_set_auth(f, 2, 17,   0x33);
    fx_set_auth(f, 3, 2,    0x34);
    roundtrip(f, "mixed lengths");
    fx_free(f);

    /* The full leg ceiling. */
    f = fx_new(DNA_ENV_MAX_LEGS);
    roundtrip(f, "64 legs");
    fx_free(f);
}

/**
 * The two ACCEPT-side boundaries the generated fixture never reaches:
 *   - runtime_op EXACTLY at DNA_ENV_MAX_RUNTIME_OP (255). The fixture
 *     assigns i % 256, so a 64-leg envelope only ever reaches 63; the
 *     reject side (256, 0xFFFFFFFF) is covered elsewhere, and a cap is
 *     only pinned when BOTH sides of it are asserted.
 *   - auth_kind that no scheme defines. K1 checks non-zero ONLY —
 *     whether a kind is SUPPORTED is out of scope (env_wire.h honest
 *     label), so a clearly-unassigned kind must still round-trip.
 */
static void test_accept_boundaries(void) {
    fixture_t *f = fx_new(2);
    f->hdr[0].runtime_op = DNA_ENV_MAX_RUNTIME_OP;   /* exactly 255 */
    f->hdr[1].runtime_op = 0;                        /* exactly 0   */
    f->hdr[0].auth_kind  = 0xFF;   /* non-zero, no scheme defines it */
    f->hdr[1].auth_kind  = 0x7F;
    roundtrip(f, "runtime_op 255 + unsupported auth_kind accepted");
    fx_free(f);
}

/**
 * Build a canonical `n`-leg header region into `m` (caller sizes it).
 *
 * PRECONDITION: n <= 256. domain_id is written as a single low byte, so
 * beyond 256 the ids would wrap, stop being strictly ascending, and the
 * envelope would be rejected for the WRONG reason.
 */
static void build_over_cap_envelope(uint8_t *m, uint16_t n) {
    CHECK(n <= 256);
    static const uint8_t family[DNA_ENV_WIRE_FAMILY_LEN] = {
        'D','N','A','.','E','N','V','W','I','R','E','.','v','1', 0, 0
    };
    memcpy(m, family, DNA_ENV_WIRE_FAMILY_LEN);
    m[16] = DNA_ENV_VERSION;
    m[41] = (uint8_t)(n >> 8);
    m[42] = (uint8_t)n;
    for (uint16_t i = 0; i < n; i++) {
        uint8_t *h = m + DNA_ENV_FIXED_HEAD + (size_t)i * DNA_ENV_LEG_HDR_LEN;
        h[3]  = (uint8_t)i;   /* domain_id, strictly ascending 0..64      */
        h[7]  = 1;            /* runtime_op = 1 (<= 255)                  */
        h[11] = 1;            /* ruleset_version                          */
        h[12] = DNA_ENV_ACCESS_INVOKE;
        h[13] = 1;            /* auth_kind non-zero                       */
        /* call_len, auth_len and the reservations stay 0. */
    }
}

/**
 * Reject + the FULL failure-state contract, checked field by field.
 * Never a struct memcmp: dna_env_leg_hdr_t carries padding after its two
 * uint8_t fields, and a padding-sensitive compare is not an assertion
 * about the nine wire fields.
 */
static void expect_reject_and_untouched(const uint8_t *src, size_t len,
                                        const char *what) {
    dna_env_view_t *v = malloc(sizeof(*v));
    MUST_ALLOC(v);
    memset(v, 0xAA, sizeof(*v));

    int rc = dna_env_decode(src, len, v);
    if (rc != -1) {
        fprintf(stderr, "FAIL %s: decode returned %d, expected -1 "
                        "(leg_count=%u env_len=%zu)\n",
                what, rc, v->leg_count, v->env_len);
        failures++;
    }
    /* Envelope metadata. */
    CHECK(v->envelope_version    == 0);
    CHECK(v->expiry_height       == 0);
    CHECK(v->fee_amount          == 0);
    CHECK(v->res_max_total_units == 0);
    CHECK(v->leg_count           == 0);
    /* Borrowed-buffer state. */
    CHECK(v->buf     == NULL);
    CHECK(v->env_len == 0);
    /* Every leg slot and both offset arrays, field by field. */
    for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
        CHECK(v->leg[i].domain_id            == 0);
        CHECK(v->leg[i].runtime_op           == 0);
        CHECK(v->leg[i].ruleset_version      == 0);
        CHECK(v->leg[i].access_mode          == 0);
        CHECK(v->leg[i].auth_kind            == 0);
        CHECK(v->leg[i].call_len             == 0);
        CHECK(v->leg[i].auth_len             == 0);
        CHECK(v->leg[i].res_max_effects      == 0);
        CHECK(v->leg[i].res_max_effect_bytes == 0);
        CHECK(v->call_off[i] == 0);
        CHECK(v->auth_off[i] == 0);
    }
    free(v);
}

/*
 * Case (b) below is only the ACCEPTING length for an unbounded decoder
 * while leg[DNA_ENV_MAX_LEGS] aliases call_off[0] exactly. If
 * dna_env_leg_hdr_t ever changes shape that stops being true, the 3*1993
 * arithmetic silently stops biting and this test goes quietly vacuous
 * again. Pin the layout so the rot is a build failure, not a silence.
 */
_Static_assert(offsetof(dna_env_view_t, leg) +
                   (size_t)DNA_ENV_MAX_LEGS * sizeof(dna_env_leg_hdr_t) ==
               offsetof(dna_env_view_t, call_off),
               "leg[DNA_ENV_MAX_LEGS] must alias call_off[0]: the 65-leg "
               "mutation proof depends on it");

/**
 * The leg-count upper bound, pinned NON-VACUOUSLY.
 *
 * The bound
 *     if (n == 0 || n > DNA_ENV_MAX_LEGS) return -1;
 * is memory-safety load-bearing: dna_env_view_t.leg[] holds
 * DNA_ENV_MAX_LEGS entries while the wire count is u16, so a 65-leg
 * envelope walks one slot past the array. leg[64] aliases call_off[0..7]
 * EXACTLY (asserted above), so the overflow is INTRA-object — ASan
 * cannot see it.
 *
 * Two envelopes are needed, and the second is the one that bites:
 *
 *  (a) 1993 bytes = 43 + 65*30, fully self-consistent, every non-count
 *      field canonical. Nothing but the count can explain a rejection.
 *      With the bound removed this STILL rejects, because the aliased
 *      65th header makes the length walk overshoot — so (a) alone is
 *      vacuous. It is kept because it is the canonical statement of the
 *      rule, and because it proves the rejection is not caused by some
 *      unrelated malformed field.
 *
 *  (b) 3 * 1993 = 5979 bytes, same header. With the bound removed the
 *      walk reads the 65th leg's call_len and auth_len out of
 *      call_off[4] and call_off[5], both of which hold call_base (1993);
 *      the accumulator therefore lands on exactly 3*1993, the length
 *      check passes, and the final-offset proof passes too because it
 *      compares the same aliased value against itself. An unbounded
 *      decoder ACCEPTS this envelope and publishes a view reporting
 *      leg_count == 65. The real decoder rejects it at the count bound
 *      before touching anything.
 *
 * Both cases assert the failure contract FIELD-BY-FIELD (never a struct
 * memcmp): rc == -1 and every semantic output field still zero, which is
 * what "rejection happens before any output is populated" means. Against
 * a decoder with the bound removed, case (b) fails on rc and on
 * leg_count/env_len/buf and on the leg and offset arrays.
 */
static void test_leg_count_guard_is_load_bearing(void) {
    const uint16_t over = DNA_ENV_MAX_LEGS + 1;              /* 65 */
    const size_t base = (size_t)DNA_ENV_FIXED_HEAD +
                        (size_t)over * DNA_ENV_LEG_HDR_LEN;
    CHECK(base == 1993);                       /* 43 + 65*30 */

    /* The accept side of the same bound: exactly DNA_ENV_MAX_LEGS legs,
     * zero payload, must round-trip and be exactly 43 + 64*30 bytes. */
    {
        fixture_t *f = fx_new(DNA_ENV_MAX_LEGS);
        for (uint16_t i = 0; i < DNA_ENV_MAX_LEGS; i++) {
            fx_set_call(f, i, 0, 0);
            fx_set_auth(f, i, 0, 0);
        }
        uint8_t *a = buf_new();
        size_t la = 0;
        CHECK(fx_encode(f, a, (size_t)DNA_ENV_MAX_TOTAL_LEN, &la) == 0);
        CHECK(la == 1963);                     /* 43 + 64*30 */
        roundtrip(f, "64 legs, zero payload, exactly 1963 bytes");
        free(a);
        fx_free(f);
    }

    /* (a) canonical self-consistent 65-leg envelope. */
    uint8_t *m = calloc(1, base);
    MUST_ALLOC(m);
    build_over_cap_envelope(m, over);
    expect_reject_and_untouched(m, base, "65 legs, self-consistent 1993 B");
    free(m);

    /* (b) the case an unbounded decoder ACCEPTS — see the block comment. */
    const size_t big = 3 * base;
    CHECK(big == 5979);
    uint8_t *g = calloc(1, big);
    MUST_ALLOC(g);
    build_over_cap_envelope(g, over);
    expect_reject_and_untouched(g, big, "65 legs, 5979 B (unbounded decoder "
                                        "would ACCEPT this)");
    free(g);
}

static void test_max_size_envelope(void) {
    /* Exactly DNA_ENV_MAX_TOTAL_LEN bytes: 1 leg, everything in call data. */
    fixture_t *f = fx_new(1);
    uint32_t big = DNA_ENV_MAX_TOTAL_LEN -
                   (DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN);
    fx_set_call(f, 0, big, 0x55);
    fx_set_auth(f, 0, 0, 0);
    CHECK(f->hdr[0].auth_kind != 0);

    uint8_t *a = buf_new();
    size_t la = 0;
    CHECK(fx_encode(f, a, (size_t)DNA_ENV_MAX_TOTAL_LEN, &la) == 0);
    CHECK(la == (size_t)DNA_ENV_MAX_TOTAL_LEN);
    roundtrip(f, "exactly 65536 bytes");

    /* One byte more must be rejected by BOTH directions. */
    fixture_t *g = fx_clone(f);
    fx_set_auth(g, 0, 1, 0x66);
    size_t lg = 0;
    CHECK(fx_encode(g, a, (size_t)DNA_ENV_MAX_TOTAL_LEN + 16, &lg) == -1);
    CHECK(lg == 0);
    fx_free(g);

    free(a);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * 3. Decode rejects — and the fully-zeroed view after every one of them
 * ════════════════════════════════════════════════════════════════════ */

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
    dna_env_view_t *v = malloc(sizeof(*v));
    MUST_ALLOC(v);
    dna_env_view_t *zero = calloc(1, sizeof(*zero));
    MUST_ALLOC(zero);

    memset(v, 0xAA, sizeof(*v));
    if (dna_env_decode(src, len, v) != -1) {
        fprintf(stderr, "FAIL %s: decode ACCEPTED a malformed envelope\n",
                what);
        failures++;
    } else if (memcmp(v, zero, sizeof(*v)) != 0) {
        fprintf(stderr, "FAIL %s: view not fully zeroed after reject\n", what);
        failures++;
    }
    free(zero);
    free(v);
}

static void test_decode_rejects(void) {
    fixture_t *f = fx_new(3);
    uint8_t *ok = buf_new();
    size_t len = 0;
    CHECK(fx_encode(f, ok, (size_t)DNA_ENV_MAX_TOTAL_LEN, &len) == 0);

    /* Sanity: the untouched encoding decodes. */
    dna_env_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    CHECK(dna_env_decode(ok, len, v) == 0);
    free(v);

    uint8_t *m = buf_new();
    size_t call_base = (size_t)DNA_ENV_FIXED_HEAD + 3 * DNA_ENV_LEG_HDR_LEN;

#define WITH_COPY() memcpy(m, ok, len)

    /* NULL arguments. */
    expect_decode_reject(NULL, len, "NULL src");
    CHECK(dna_env_decode(ok, len, NULL) == -1);

    /* Family marker: a content byte, and a PADDING byte (bytes 14-15 of
     * "DNA.ENVWIRE.v1" are the zero padding). */
    WITH_COPY(); m[0] ^= 0x01;
    expect_decode_reject(m, len, "wrong family byte");
    WITH_COPY(); m[13] = 'X';
    expect_decode_reject(m, len, "wrong family version char");
    WITH_COPY(); m[14] = 'X';
    expect_decode_reject(m, len, "corrupted family zero padding");
    WITH_COPY(); m[15] = 0x01;
    expect_decode_reject(m, len, "corrupted family trailing padding");

    /* Envelope version. */
    WITH_COPY(); m[16] = 0;
    expect_decode_reject(m, len, "version 0");
    WITH_COPY(); m[16] = 2;
    expect_decode_reject(m, len, "unknown version 2");

    /* Leg count bounds (offset 41, u16 BE). */
    WITH_COPY(); m[41] = 0; m[42] = 0;
    expect_decode_reject(m, len, "0 legs");
    WITH_COPY(); m[41] = 0; m[42] = DNA_ENV_MAX_LEGS + 1;
    expect_decode_reject(m, len, "65 legs");
    WITH_COPY(); m[41] = 0xFF; m[42] = 0xFF;
    expect_decode_reject(m, len, "65535 legs");

    /* Per-leg rules. Leg i header starts at DNA_ENV_FIXED_HEAD + 30*i. */
    size_t leg1 = (size_t)DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN;

    /* domain_id ordering: duplicate, then descending. */
    WITH_COPY();
    memcpy(m + leg1, m + DNA_ENV_FIXED_HEAD, 4);
    expect_decode_reject(m, len, "duplicate domain_id");
    WITH_COPY();
    m[DNA_ENV_FIXED_HEAD + 3] = 0xFF;      /* leg0 domain far above leg1 */
    expect_decode_reject(m, len, "descending domain_id");

    /* runtime_op == 256 (one past the accepted window). */
    WITH_COPY();
    m[leg1 + 4] = 0; m[leg1 + 5] = 0; m[leg1 + 6] = 1; m[leg1 + 7] = 0;
    expect_decode_reject(m, len, "runtime_op == 256");
    WITH_COPY();
    m[leg1 + 4] = 0xFF; m[leg1 + 5] = 0xFF;
    m[leg1 + 6] = 0xFF; m[leg1 + 7] = 0xFF;
    expect_decode_reject(m, len, "runtime_op == 0xFFFFFFFF");

    /* access_mode 0 (INVALID) and 3 (unknown) — fail closed, never
     * "treat as read". */
    WITH_COPY(); m[leg1 + 12] = 0;
    expect_decode_reject(m, len, "access_mode 0");
    WITH_COPY(); m[leg1 + 12] = 3;
    expect_decode_reject(m, len, "access_mode 3");
    WITH_COPY(); m[leg1 + 12] = 0xFF;
    expect_decode_reject(m, len, "access_mode 255");

    /* auth_kind 0. */
    WITH_COPY(); m[leg1 + 13] = 0;
    expect_decode_reject(m, len, "auth_kind 0");

    /* Truncation and trailing bytes. */
    expect_decode_reject(ok, (size_t)DNA_ENV_FIXED_HEAD - 1,
                         "truncated fixed header");
    expect_decode_reject(ok, 0, "empty input");
    expect_decode_reject(ok, call_base - 1, "truncated leg header region");
    expect_decode_reject(ok, call_base, "leg headers only, no payload");
    expect_decode_reject(ok, len - 1, "truncated auth section");
    /* One byte short of the end of the call section. */
    expect_decode_reject(ok, call_base + 3 * 4 - 1, "truncated call section");
    WITH_COPY();
    m[len] = 0x00;
    expect_decode_reject(m, len + 1, "one trailing byte");

    /* Length arithmetic: a hostile call_len must be rejected, never wrap. */
    WITH_COPY();
    m[DNA_ENV_FIXED_HEAD + 14] = 0xFF; m[DNA_ENV_FIXED_HEAD + 15] = 0xFF;
    m[DNA_ENV_FIXED_HEAD + 16] = 0xFF; m[DNA_ENV_FIXED_HEAD + 17] = 0xFF;
    expect_decode_reject(m, len, "call_len 0xFFFFFFFF");
    WITH_COPY();
    m[DNA_ENV_FIXED_HEAD + 18] = 0xFF; m[DNA_ENV_FIXED_HEAD + 19] = 0xFF;
    m[DNA_ENV_FIXED_HEAD + 20] = 0xFF; m[DNA_ENV_FIXED_HEAD + 21] = 0xFF;
    expect_decode_reject(m, len, "auth_len 0xFFFFFFFF");

#undef WITH_COPY

    free(m);
    free(ok);
    fx_free(f);

    /* Declared size above the cap: a REAL buffer of 65537 bytes whose
     * header declares every one of them. The cap is inclusive, so this is
     * the first rejected size. */
    fixture_t *g = fx_new(1);
    uint32_t over = DNA_ENV_MAX_TOTAL_LEN -
                    (DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN);
    fx_set_call(g, 0, over, 0x77);
    fx_set_auth(g, 0, 0, 0);
    uint8_t *big = calloc(1, (size_t)DNA_ENV_MAX_TOTAL_LEN + 16);
    MUST_ALLOC(big);
    size_t blen = 0;
    CHECK(fx_encode(g, big, (size_t)DNA_ENV_MAX_TOTAL_LEN, &blen) == 0);
    CHECK(blen == (size_t)DNA_ENV_MAX_TOTAL_LEN);
    /* Bump call_len by one and hand decode one more byte: 65537 total. */
    uint32_t plus = over + 1;
    big[DNA_ENV_FIXED_HEAD + 14] = (uint8_t)(plus >> 24);
    big[DNA_ENV_FIXED_HEAD + 15] = (uint8_t)(plus >> 16);
    big[DNA_ENV_FIXED_HEAD + 16] = (uint8_t)(plus >> 8);
    big[DNA_ENV_FIXED_HEAD + 17] = (uint8_t)plus;
    expect_decode_reject(big, (size_t)DNA_ENV_MAX_TOTAL_LEN + 1,
                         "declared size 65537");
    free(big);
    fx_free(g);
}

/* ══════════════════════════════════════════════════════════════════════
 * 4. Encode rejects
 * ════════════════════════════════════════════════════════════════════ */

/** Encode must reject, and *written_out must be 0. */
static void expect_encode_reject(const fixture_t *f, const char *what) {
    uint8_t *b = buf_new();
    size_t written = 0xdead;
    if (fx_encode(f, b, (size_t)DNA_ENV_MAX_TOTAL_LEN, &written) != -1) {
        fprintf(stderr, "FAIL %s: encode ACCEPTED an invalid envelope\n",
                what);
        failures++;
    } else if (written != 0) {
        fprintf(stderr, "FAIL %s: written_out not zeroed on reject\n", what);
        failures++;
    }
    free(b);
}

static void test_encode_rejects(void) {
    fixture_t *f = fx_new(3);
    uint8_t *b = buf_new();
    size_t written = 0;

    /* NULL arguments — written_out is MANDATORY. */
    dna_env_leg_in_t *legs = calloc(DNA_ENV_MAX_LEGS, sizeof(*legs));
    MUST_ALLOC(legs);
    dna_env_in_t in;
    fx_input(f, legs, &in);
    CHECK(dna_env_encode(&in, b, (size_t)DNA_ENV_MAX_TOTAL_LEN, NULL) == -1);
    written = 0xdead;
    CHECK(dna_env_encode(NULL, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == -1);
    CHECK(written == 0);
    written = 0xdead;
    CHECK(dna_env_encode(&in, NULL, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == -1);
    CHECK(written == 0);

    /* Insufficient capacity: need - 1 rejects, need accepts. */
    size_t need = 0;
    CHECK(dna_env_encoded_size(legs, f->n, &need) == 0);
    written = 0xdead;
    CHECK(dna_env_encode(&in, b, need - 1, &written) == -1);
    CHECK(written == 0);
    CHECK(dna_env_encode(&in, b, need, &written) == 0);
    CHECK(written == need);

    /* NULL legs array. */
    in.legs = NULL;
    written = 0xdead;
    CHECK(dna_env_encode(&in, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == -1);
    CHECK(written == 0);
    in.legs = legs;

    /* NULL data pointer with a NON-ZERO length (the one combination the
     * header forbids; NULL with length 0 is legal and covered above). */
    legs[1].call_data = NULL;
    written = 0xdead;
    CHECK(dna_env_encode(&in, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == -1);
    CHECK(written == 0);
    legs[1].call_data = f->call[1];
    legs[2].auth_data = NULL;
    written = 0xdead;
    CHECK(dna_env_encode(&in, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == -1);
    CHECK(written == 0);
    legs[2].auth_data = f->auth[2];

    /* A zero length with a NULL pointer must still encode. */
    legs[2].hdr.auth_len = 0;
    legs[2].auth_data    = NULL;
    written = 0;
    CHECK(dna_env_encode(&in, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                         &written) == 0);
    free(legs);

    /* Leg-count bounds. */
    fixture_t *g = fx_clone(f);
    g->n = 0;
    expect_encode_reject(g, "encode 0 legs");
    fx_free(g);

    /* 65 legs: built directly, because the fixture's arrays are sized to
     * the ceiling and a 65th entry would run off the end of them. Every
     * leg here is individually VALID, so only the count can be rejected. */
    {
        dna_env_leg_in_t *big = calloc(DNA_ENV_MAX_LEGS + 1, sizeof(*big));
        MUST_ALLOC(big);
        for (uint16_t i = 0; i <= DNA_ENV_MAX_LEGS; i++) {
            big[i].hdr.domain_id   = 1u + i;
            big[i].hdr.runtime_op  = 1;
            big[i].hdr.access_mode = (uint8_t)DNA_ENV_ACCESS_READ;
            big[i].hdr.auth_kind   = 1;
        }
        dna_env_in_t over;
        over.expiry_height       = 1;
        over.fee_amount          = 1;
        over.res_max_total_units = 1;
        over.leg_count           = DNA_ENV_MAX_LEGS + 1;
        over.legs                = big;
        written = 0xdead;
        CHECK(dna_env_encode(&over, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                             &written) == -1);
        CHECK(written == 0);
        /* Exactly the ceiling, same legs: accepted. */
        over.leg_count = DNA_ENV_MAX_LEGS;
        CHECK(dna_env_encode(&over, b, (size_t)DNA_ENV_MAX_TOTAL_LEN,
                             &written) == 0);
        CHECK(written == 1963);
        free(big);
    }

    /* Structural rules: encode rejects everything decode rejects. */
    g = fx_clone(f); g->hdr[1].access_mode = 0;
    expect_encode_reject(g, "encode access_mode 0"); fx_free(g);
    g = fx_clone(f); g->hdr[1].access_mode = 3;
    expect_encode_reject(g, "encode access_mode 3"); fx_free(g);
    g = fx_clone(f); g->hdr[1].auth_kind = 0;
    expect_encode_reject(g, "encode auth_kind 0"); fx_free(g);
    g = fx_clone(f); g->hdr[1].runtime_op = 256;
    expect_encode_reject(g, "encode runtime_op 256"); fx_free(g);
    g = fx_clone(f); g->hdr[1].domain_id = g->hdr[0].domain_id;
    expect_encode_reject(g, "encode duplicate domain_id"); fx_free(g);
    g = fx_clone(f); g->hdr[0].domain_id = g->hdr[2].domain_id + 1;
    expect_encode_reject(g, "encode descending domain_id"); fx_free(g);
    g = fx_clone(f); g->hdr[1].call_len = 0xFFFFFFFFu;   /* data stays short */
    expect_encode_reject(g, "encode call_len overflow"); fx_free(g);

    free(b);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * 5. Commitment helper rejects
 * ════════════════════════════════════════════════════════════════════ */

static void test_commit_rejects(void) {
    fixture_t *f = fx_new(2);
    uint8_t *bytes = buf_new();
    size_t len = 0;
    CHECK(fx_encode(f, bytes, (size_t)DNA_ENV_MAX_TOTAL_LEN, &len) == 0);

    dna_env_view_t *v = calloc(1, sizeof(*v));
    MUST_ALLOC(v);
    CHECK(dna_env_decode(bytes, len, v) == 0);

    uint8_t out[HASH_LEN], ctx[HASH_LEN];
    uint8_t (*cc)[HASH_LEN] = calloc(DNA_ENV_MAX_LEGS, HASH_LEN);
    MUST_ALLOC(cc);
    for (uint16_t i = 0; i < v->leg_count; i++)
        CHECK(dna_env_call_commit(v, i, f->rh[i], cc[i]) == 0);
    CHECK(dna_env_auth_context_commit(v, f->chain_id,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      ctx) == 0);

    /* call_commit rejects. */
    CHECK(dna_env_call_commit(NULL, 0, f->rh[0], out) == -1);
    CHECK(dna_env_call_commit(v, 0, NULL, out) == -1);
    CHECK(dna_env_call_commit(v, 0, f->rh[0], NULL) == -1);
    CHECK(dna_env_call_commit(v, v->leg_count, f->rh[0], out) == -1);
    CHECK(dna_env_call_commit(v, 0xFFFF, f->rh[0], out) == -1);

    /* A ZEROED view is not a decoded view: leg_count 0 and buf NULL. */
    dna_env_view_t *zv = calloc(1, sizeof(*zv));
    MUST_ALLOC(zv);
    CHECK(dna_env_call_commit(zv, 0, f->rh[0], out) == -1);
    CHECK(dna_env_auth_context_commit(zv, f->chain_id,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      out) == -1);
    free(zv);

    /* auth_context_commit rejects. */
    CHECK(dna_env_auth_context_commit(NULL, f->chain_id,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      out) == -1);
    CHECK(dna_env_auth_context_commit(v, NULL,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      out) == -1);
    CHECK(dna_env_auth_context_commit(v, f->chain_id, NULL, out) == -1);
    CHECK(dna_env_auth_context_commit(v, f->chain_id,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      NULL) == -1);

    /* auth_digest rejects. */
    CHECK(dna_env_auth_digest(NULL, 0, 1, 1, out) == -1);
    CHECK(dna_env_auth_digest(ctx, 0, 1, 1, NULL) == -1);
    CHECK(dna_env_auth_digest(ctx, DNA_ENV_MAX_LEGS, 1, 1, out) == -1);
    CHECK(dna_env_auth_digest(ctx, 0, 1, 256, out) == -1);

    /* tx_id rejects. */
    CHECK(dna_env_tx_id(NULL, bytes, len, out) == -1);
    CHECK(dna_env_tx_id(ctx, NULL, len, out) == -1);
    CHECK(dna_env_tx_id(ctx, bytes, len, NULL) == -1);
    CHECK(dna_env_tx_id(ctx, bytes, DNA_ENV_FIXED_HEAD - 1, out) == -1);
    CHECK(dna_env_tx_id(ctx, bytes, (size_t)DNA_ENV_MAX_TOTAL_LEN + 1,
                        out) == -1);

    /* Determinism: the same inputs always produce the same digests. */
    uint8_t again[HASH_LEN];
    CHECK(dna_env_call_commit(v, 0, f->rh[0], again) == 0);
    CHECK(memcmp(again, cc[0], HASH_LEN) == 0);
    CHECK(dna_env_auth_context_commit(v, f->chain_id,
                                      (const uint8_t (*)[HASH_LEN])cc,
                                      again) == 0);
    CHECK(memcmp(again, ctx, HASH_LEN) == 0);

    free(cc);
    free(v);
    free(bytes);
    fx_free(f);
}

/* ══════════════════════════════════════════════════════════════════════
 * 6. BINDING — which commitment moves when which field moves
 * ════════════════════════════════════════════════════════════════════ */

/* Shorthand: D=different, S=same, for the four commitment families. */
static void compare(const char *what, const digests_t *a, const digests_t *b,
                    int call0_diff, int call1_diff, int ctx_diff,
                    int auth_diff, int txid_diff) {
    char label[128];
    snprintf(label, sizeof(label), "%s call_commit[0]", what);
    expect(label, a->call[0], b->call[0], call0_diff);
    snprintf(label, sizeof(label), "%s call_commit[1]", what);
    expect(label, a->call[1], b->call[1], call1_diff);
    snprintf(label, sizeof(label), "%s auth_context_commit", what);
    expect(label, a->ctx, b->ctx, ctx_diff);
    expect_all_auth(what, a, b, auth_diff);
    snprintf(label, sizeof(label), "%s tx_id", what);
    expect(label, a->txid, b->txid, txid_diff);
}

static void test_binding(void) {
    fixture_t *base = fx_new(2);
    fx_set_call(base, 0, 8, 0x00);
    fx_set_call(base, 1, 6, 0x50);
    fx_set_auth(base, 0, 5, 0xA0);
    fx_set_auth(base, 1, 3, 0xB0);
    digests_t *d0 = fx_digests(base);

    fixture_t *g;
    digests_t *d;

    /* (a) call data of leg 0. Only leg 0's call_commit moves; every
     *     downstream commitment moves with it. */
    g = fx_clone(base); g->call[0][2] ^= 0x01;
    d = fx_digests(g);
    compare("call_data[0] mutation", d0, d, 1, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (b) chain_id — contextual, not on the wire: call commits are
     *     unaffected, everything downstream moves. */
    g = fx_clone(base); g->chain_id[7] ^= 0x01;
    d = fx_digests(g);
    compare("chain_id mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (c) ruleset_hash of leg 1 — contextual, binds the leg to the exact
     *     ruleset behind its version number. */
    g = fx_clone(base); g->rh[1][63] ^= 0x01;
    d = fx_digests(g);
    compare("ruleset_hash[1] mutation", d0, d, 0, 1, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (d) domain_id of leg 1 (kept ascending). */
    g = fx_clone(base); g->hdr[1].domain_id += 1;
    d = fx_digests(g);
    compare("domain_id[1] mutation", d0, d, 0, 1, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (e) runtime_op of leg 0. */
    g = fx_clone(base); g->hdr[0].runtime_op = 200;
    d = fx_digests(g);
    compare("runtime_op[0] mutation", d0, d, 1, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (f) ruleset_version of leg 0. */
    g = fx_clone(base); g->hdr[0].ruleset_version += 1;
    d = fx_digests(g);
    compare("ruleset_version[0] mutation", d0, d, 1, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (g) access_mode of leg 0 (INVOKE -> READ). */
    g = fx_clone(base);
    CHECK(g->hdr[0].access_mode == (uint8_t)DNA_ENV_ACCESS_INVOKE);
    g->hdr[0].access_mode = (uint8_t)DNA_ENV_ACCESS_READ;
    d = fx_digests(g);
    compare("access_mode[0] mutation", d0, d, 1, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (h) auth_kind — committed in AUTHCTX_BYTES, NOT in call_commit. */
    g = fx_clone(base); g->hdr[0].auth_kind += 1;
    d = fx_digests(g);
    compare("auth_kind[0] mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (i) reservation declarations — per-leg and envelope-wide. */
    g = fx_clone(base); g->hdr[1].res_max_effects += 1;
    d = fx_digests(g);
    compare("res_max_effects[1] mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    g = fx_clone(base); g->hdr[1].res_max_effect_bytes += 1;
    d = fx_digests(g);
    compare("res_max_effect_bytes[1] mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    g = fx_clone(base); g->res_total += 1;
    d = fx_digests(g);
    compare("res_max_total_units mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    g = fx_clone(base); g->fee += 1;
    d = fx_digests(g);
    compare("fee_amount mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    g = fx_clone(base); g->expiry += 1;
    d = fx_digests(g);
    compare("expiry_height mutation", d0, d, 0, 0, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (j) ── THE NON-CIRCULARITY PIN ────────────────────────────────────
     * Mutating auth_data must move tx_id and NOTHING else. Every
     * auth_digest must stay byte-identical to the PRE-mutation values, so
     * a signature produced over auth_digest[i] stays valid once it is
     * placed into that leg's auth_data. */
    g = fx_clone(base); g->auth[0][0] ^= 0xFF;
    d = fx_digests(g);
    compare("auth_data[0] mutation", d0, d, 0, 0, 0, 0, 1);
    dg_free(d); fx_free(g);

    g = fx_clone(base);
    for (uint32_t j = 0; j < g->hdr[1].auth_len; j++) g->auth[1][j] ^= 0xFF;
    d = fx_digests(g);
    compare("auth_data[1] full mutation", d0, d, 0, 0, 0, 0, 1);
    dg_free(d); fx_free(g);

    /* (k) REPARTITION: move one byte from call_len to auth_len. The base
     *     for this one gives leg 1 empty blobs, so the payload region is
     *     exactly call_data[0] ‖ auth_data[0] and the repartitioned
     *     envelope's payload REGION is byte-identical — only the two
     *     length fields differ. That is what pins that the LENGTHS
     *     themselves are committed, not just the bytes. */
    {
        fixture_t *b2 = fx_clone(base);
        fx_set_call(b2, 1, 0, 0);
        fx_set_auth(b2, 1, 0, 0);
        digests_t *db2 = fx_digests(b2);

        g = fx_clone(b2);
        uint32_t cl = b2->hdr[0].call_len;
        uint32_t al = b2->hdr[0].auth_len;
        CHECK(cl >= 1);
        uint8_t *joined = malloc((size_t)cl + al);
        MUST_ALLOC(joined);
        memcpy(joined, b2->call[0], cl);
        memcpy(joined + cl, b2->auth[0], al);
        fx_set_call(g, 0, cl - 1, 0);
        fx_set_auth(g, 0, al + 1, 0);
        memcpy(g->call[0], joined, cl - 1);
        memcpy(g->auth[0], joined + (cl - 1), al + 1);
        free(joined);

        d = fx_digests(g);
        /* Same total length, and the payload region is unchanged. */
        CHECK(d->len == db2->len);
        {
            size_t cb = (size_t)DNA_ENV_FIXED_HEAD + 2 * DNA_ENV_LEG_HDR_LEN;
            CHECK(memcmp(d->bytes + cb, db2->bytes + cb, d->len - cb) == 0);
        }
        compare("call/auth repartition", db2, d, 1, 0, 1, 1, 1);
        dg_free(d); fx_free(g);
        dg_free(db2); fx_free(b2);
    }

    /* (l) LEG REORDER. A raw byte swap of two leg headers would break the
     *     ascending-domain_id rule and never decode, so the reorder is
     *     built as a second VALID envelope: same domain ids, the two legs'
     *     payloads and ops exchanged. Every auth_digest must move. */
    g = fx_clone(base);
    {
        uint32_t op0 = base->hdr[0].runtime_op;
        uint32_t rv0 = base->hdr[0].ruleset_version;
        uint8_t  am0 = base->hdr[0].access_mode;
        uint8_t  ak0 = base->hdr[0].auth_kind;
        g->hdr[0].runtime_op      = base->hdr[1].runtime_op;
        g->hdr[0].ruleset_version = base->hdr[1].ruleset_version;
        g->hdr[0].access_mode     = base->hdr[1].access_mode;
        g->hdr[0].auth_kind       = base->hdr[1].auth_kind;
        g->hdr[1].runtime_op      = op0;
        g->hdr[1].ruleset_version = rv0;
        g->hdr[1].access_mode     = am0;
        g->hdr[1].auth_kind       = ak0;
        fx_set_call(g, 0, base->hdr[1].call_len, 0);
        memcpy(g->call[0], base->call[1], base->hdr[1].call_len);
        fx_set_call(g, 1, base->hdr[0].call_len, 0);
        memcpy(g->call[1], base->call[0], base->hdr[0].call_len);
    }
    d = fx_digests(g);
    compare("leg content reorder", d0, d, 1, 1, 1, 1, 1);
    dg_free(d); fx_free(g);

    /* (m) LEG REMOVAL and INSERTION — leg_count is committed in
     *     AUTHCTX_BYTES, so every surviving auth_digest moves too. */
    g = fx_clone(base); g->n = 1;
    d = fx_digests(g);
    expect("leg removal auth_context_commit", d0->ctx, d->ctx, 1);
    expect("leg removal auth_digest[0]", d0->auth[0], d->auth[0], 1);
    expect("leg removal call_commit[0]", d0->call[0], d->call[0], 0);
    expect("leg removal tx_id", d0->txid, d->txid, 1);
    dg_free(d); fx_free(g);

    {
        fixture_t *three = fx_new(3);
        three->expiry    = base->expiry;
        three->fee       = base->fee;
        three->res_total = base->res_total;
        for (uint16_t i = 0; i < 2; i++) {
            three->hdr[i] = base->hdr[i];
            fx_set_call(three, i, base->hdr[i].call_len, 0);
            if (base->hdr[i].call_len)
                memcpy(three->call[i], base->call[i], base->hdr[i].call_len);
            fx_set_auth(three, i, base->hdr[i].auth_len, 0);
            if (base->hdr[i].auth_len)
                memcpy(three->auth[i], base->auth[i], base->hdr[i].auth_len);
        }
        three->hdr[2].domain_id = base->hdr[1].domain_id + 1;
        d = fx_digests(three);
        /* The first two legs are byte-identical, so their call commits are
         * too — but the context (and therefore every auth_digest) moved. */
        expect("leg insertion call_commit[0]", d0->call[0], d->call[0], 0);
        expect("leg insertion call_commit[1]", d0->call[1], d->call[1], 0);
        expect("leg insertion auth_context_commit", d0->ctx, d->ctx, 1);
        expect_all_auth("leg insertion", d0, d, 1);
        expect("leg insertion tx_id", d0->txid, d->txid, 1);
        dg_free(d);
        fx_free(three);
    }

    /* Every leg gets a DISTINCT auth_digest under the same context — the
     * leg_index / domain_id / runtime_op binding is what separates them. */
    expect("distinct legs share a digest", d0->auth[0], d0->auth[1], 1);

    /* Same context, different leg index, same domain/op: still distinct. */
    {
        uint8_t a0[HASH_LEN], a1[HASH_LEN];
        CHECK(dna_env_auth_digest(d0->ctx, 0, 5, 9, a0) == 0);
        CHECK(dna_env_auth_digest(d0->ctx, 1, 5, 9, a1) == 0);
        expect("leg_index binding", a0, a1, 1);
    }

    dg_free(d0);
    fx_free(base);
}

/* ══════════════════════════════════════════════════════════════════════
 * 7. KAT — known-answer vectors from an INDEPENDENT oracle
 *
 * Every placeholder below carries the marker line
 *     KAT: filled by the ORCHESTRATOR from an independent Python oracle
 *
 * The arrays below are PINNED. They were NOT produced by this C code: a
 * digest produced by the same implementation the test exercises would
 * prove self-consistency and nothing else. They come from
 * shared/dnac/tests/env_wire_oracle.py, an independent python3
 * hashlib.sha3_512 implementation written from the K1 specification.
 *
 * The skip mechanism below remains armed for any FUTURE array added here:
 * while an array is all-zero its comparison prints "[KAT PENDING]" and
 * does NOT count as a pass — a silent skip is how a pin quietly stops
 * pinning. No array in this file is currently in that state.
 *
 * The fixture is fully determined by the bytes printed at run time:
 *   - KAT_ENV_BYTES  the encoded envelope (the ONLY input to tx_id besides
 *                    auth_context_commit)
 *   - KAT_CHAIN_ID   contextual, 32 bytes
 *   - KAT_RULESET_0  contextual ruleset_hash for leg 0, 64 bytes
 *   - KAT_RULESET_1  contextual ruleset_hash for leg 1, 64 bytes
 * ════════════════════════════════════════════════════════════════════ */

/* KAT: pinned by the ORCHESTRATOR from the independent oracle
 * shared/dnac/tests/env_wire_oracle.py — python3 hashlib.sha3_512, written
 * from the K1 specification and sharing no code with this implementation.
 * It re-parses KAT_ENV_BYTES rather than re-declaring the fields, so the
 * pinned bytes and the pinned digests cannot drift apart.
 * Reproduce:  python3 shared/dnac/tests/env_wire_oracle.py             */
static const uint8_t KAT_CALL_COMMIT_0[HASH_LEN] = {
    0x43, 0x24, 0xed, 0x14, 0x2c, 0xb5, 0x3b, 0x79,
    0x1b, 0xe4, 0x97, 0x1e, 0x93, 0x1b, 0x36, 0x7a,
    0x8d, 0x28, 0xec, 0x0d, 0xee, 0x14, 0x72, 0x48,
    0xa5, 0x6a, 0x39, 0x34, 0x48, 0xa3, 0xfa, 0xd2,
    0x28, 0xe7, 0x8e, 0xc0, 0xa2, 0x37, 0x0c, 0x73,
    0x8b, 0x50, 0x02, 0x50, 0x54, 0xef, 0x0c, 0x1b,
    0x92, 0x52, 0x47, 0x44, 0x7e, 0x9c, 0x90, 0x5d,
    0x06, 0x9a, 0xb3, 0x69, 0xcd, 0x80, 0x3a, 0xe6
};
static const uint8_t KAT_CALL_COMMIT_1[HASH_LEN] = {
    0xe5, 0x1c, 0xd8, 0xd6, 0x6b, 0xae, 0x5d, 0x98,
    0x14, 0xb1, 0x20, 0x80, 0xb2, 0x70, 0x0a, 0x1f,
    0x30, 0xcc, 0x54, 0x68, 0xcd, 0xfe, 0x14, 0xdb,
    0x59, 0x8f, 0xfc, 0x83, 0x49, 0x2f, 0x52, 0x69,
    0xff, 0xa4, 0xb2, 0xed, 0x89, 0xae, 0x43, 0x76,
    0x03, 0x04, 0x2f, 0x97, 0x35, 0x47, 0x05, 0xd5,
    0x05, 0x43, 0x3e, 0xab, 0x01, 0x4f, 0x49, 0x71,
    0x67, 0x37, 0xa5, 0xf1, 0x61, 0x6d, 0x14, 0x9f
};
static const uint8_t KAT_AUTH_CONTEXT_COMMIT[HASH_LEN] = {
    0x3a, 0x11, 0xa6, 0x33, 0xc9, 0xec, 0x5c, 0x89,
    0xeb, 0x62, 0x1c, 0x5e, 0x1e, 0xb7, 0x09, 0x53,
    0xa6, 0xa3, 0x08, 0xbc, 0xde, 0xeb, 0x33, 0x06,
    0x30, 0xd7, 0xdb, 0x8b, 0x6f, 0xc8, 0xb3, 0x60,
    0x58, 0xc2, 0x25, 0x92, 0x8f, 0x8e, 0xc0, 0x85,
    0x7e, 0xf2, 0x31, 0x06, 0x69, 0x7a, 0xf9, 0xbd,
    0xb9, 0xfb, 0x3b, 0xbb, 0x17, 0x96, 0xd6, 0x70,
    0xde, 0x6e, 0xdd, 0x9d, 0xf3, 0x81, 0xe5, 0x88
};
static const uint8_t KAT_AUTH_DIGEST_0[HASH_LEN] = {
    0x65, 0xf7, 0xb7, 0x7d, 0x30, 0xe2, 0x32, 0x51,
    0xc0, 0x5e, 0x8a, 0x60, 0xab, 0x05, 0x2b, 0x75,
    0x8c, 0xaa, 0x26, 0x65, 0xb2, 0x1a, 0xaa, 0x64,
    0x38, 0xaf, 0xf8, 0xb7, 0xaf, 0x07, 0xff, 0xa9,
    0xc6, 0x26, 0x9c, 0xa1, 0x4f, 0x55, 0xeb, 0x63,
    0xed, 0x70, 0x92, 0x15, 0x07, 0x68, 0xa9, 0x2a,
    0x9e, 0x95, 0xd5, 0xe9, 0x04, 0x0c, 0x63, 0xd3,
    0x5c, 0x2a, 0x02, 0xe8, 0x1e, 0x24, 0x20, 0x09
};
static const uint8_t KAT_AUTH_DIGEST_1[HASH_LEN] = {
    0xfc, 0xa6, 0xc4, 0xbc, 0xde, 0x99, 0x95, 0xf2,
    0xbc, 0xbf, 0xac, 0x29, 0x59, 0xed, 0xfa, 0x91,
    0x4b, 0x30, 0xd3, 0xb2, 0x83, 0x1b, 0x11, 0x71,
    0xdf, 0x88, 0xd4, 0x1c, 0x6e, 0x1b, 0x9d, 0x82,
    0x9d, 0x21, 0x23, 0x8b, 0x79, 0xa6, 0x4a, 0x98,
    0xd0, 0xcd, 0x96, 0x10, 0xaa, 0x6d, 0x62, 0xf3,
    0x60, 0x06, 0x96, 0xc2, 0x8f, 0x92, 0x00, 0xf6,
    0x3a, 0x9c, 0xc7, 0x07, 0x19, 0xf6, 0xeb, 0xc3
};
static const uint8_t KAT_TX_ID[HASH_LEN] = {
    0x09, 0x32, 0x45, 0x6c, 0xd6, 0x0d, 0xb5, 0x67,
    0xb0, 0x54, 0xb4, 0x00, 0x2a, 0x8d, 0x6b, 0xe4,
    0x76, 0x71, 0xbb, 0x78, 0xd9, 0x8f, 0x36, 0x7d,
    0x6b, 0xd9, 0x2f, 0x15, 0xa3, 0xd6, 0x71, 0xba,
    0x54, 0x70, 0x50, 0x59, 0x04, 0x37, 0x33, 0x98,
    0xb6, 0xc1, 0xdf, 0x8d, 0x97, 0xd4, 0x08, 0xd5,
    0xb7, 0xd1, 0x5d, 0x39, 0x63, 0x5c, 0x01, 0xc9,
    0x6f, 0xaf, 0xec, 0x4b, 0xc6, 0x1b, 0x94, 0xc7
};

/**
 * The exact envelope bytes the fixture below must produce. Left zero-length
 * until the ORCHESTRATOR pins it; the fixture PRINTS its bytes on every run
 * so the oracle and this pin are fed from the same source.
 *
 * KAT: filled by the ORCHESTRATOR from an independent Python oracle
 */
static const uint8_t KAT_ENV_BYTES[] = {
    0x44, 0x4e, 0x41, 0x2e, 0x45, 0x4e, 0x56, 0x57,
    0x49, 0x52, 0x45, 0x2e, 0x76, 0x31, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22,
    0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3,
    0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x02,
    0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xa0,
    0xa1, 0xa2, 0xa3, 0xa4, 0xb0, 0xb1, 0xb2
};
static const size_t  KAT_ENV_BYTES_LEN = sizeof(KAT_ENV_BYTES);

static int is_zero(const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) if (b[i]) return 0;
    return 1;
}

static void kat_expect(const char *what, const uint8_t *got,
                       const uint8_t *want) {
    if (is_zero(want, HASH_LEN)) {
        printf("[KAT PENDING] %s — no oracle value pinned yet\n", what);
        return;
    }
    if (memcmp(got, want, HASH_LEN) != 0) {
        fprintf(stderr, "FAIL KAT %s mismatch\n", what);
        failures++;
    }
}

/** The pinned 2-leg fixture. Every value here is a literal constant. */
static fixture_t *kat_fixture(void) {
    fixture_t *f = calloc(1, sizeof(*f));
    MUST_ALLOC(f);
    f->expiry    = 0x0000000000112233ULL;
    f->fee       = 1000;
    f->res_total = 50000;
    f->n         = 2;

    f->hdr[0].domain_id            = 1;
    f->hdr[0].runtime_op           = 7;
    f->hdr[0].ruleset_version      = 3;
    f->hdr[0].access_mode          = (uint8_t)DNA_ENV_ACCESS_INVOKE;
    f->hdr[0].auth_kind            = 1;
    f->hdr[0].res_max_effects      = 16;
    f->hdr[0].res_max_effect_bytes = 1024;

    f->hdr[1].domain_id            = 42;
    f->hdr[1].runtime_op           = 0;
    f->hdr[1].ruleset_version      = 1;
    f->hdr[1].access_mode          = (uint8_t)DNA_ENV_ACCESS_READ;
    f->hdr[1].auth_kind            = 2;
    f->hdr[1].res_max_effects      = 0;
    f->hdr[1].res_max_effect_bytes = 0;

    /* call_data[0] = 00 01 02 03 04 05 06 07 ; call_data[1] = (empty) */
    f->hdr[0].call_len = 8;
    f->call[0] = malloc(8);
    MUST_ALLOC(f->call[0]);
    for (uint32_t j = 0; j < 8; j++) f->call[0][j] = (uint8_t)j;
    f->hdr[1].call_len = 0;
    f->call[1] = NULL;

    /* auth_data[0] = A0..A4 ; auth_data[1] = B0 B1 B2 */
    f->hdr[0].auth_len = 5;
    f->auth[0] = malloc(5);
    MUST_ALLOC(f->auth[0]);
    for (uint32_t j = 0; j < 5; j++) f->auth[0][j] = (uint8_t)(0xA0 + j);
    f->hdr[1].auth_len = 3;
    f->auth[1] = malloc(3);
    MUST_ALLOC(f->auth[1]);
    for (uint32_t j = 0; j < 3; j++) f->auth[1][j] = (uint8_t)(0xB0 + j);

    /* chain_id     = 10 11 12 ... 2f            */
    for (int j = 0; j < DNA_ENV_CHAIN_ID_LEN; j++)
        f->chain_id[j] = (uint8_t)(0x10 + j);
    /* ruleset_hash[0] = 40 41 ... 7f            */
    /* ruleset_hash[1] = 80 81 ... bf            */
    for (int j = 0; j < DNA_ENV_RULESET_HASH_LEN; j++) {
        f->rh[0][j] = (uint8_t)(0x40 + j);
        f->rh[1][j] = (uint8_t)(0x80 + j);
    }
    return f;
}

static void test_kat(void) {
    fixture_t *f = kat_fixture();
    digests_t *d = fx_digests(f);

    printf("\n──── KAT FIXTURE (feed these to the independent oracle) ────\n");
    print_hex("KAT_ENV_BYTES",  d->bytes, d->len);
    print_hex("KAT_CHAIN_ID",   f->chain_id, DNA_ENV_CHAIN_ID_LEN);
    print_hex("KAT_RULESET_0",  f->rh[0], DNA_ENV_RULESET_HASH_LEN);
    print_hex("KAT_RULESET_1",  f->rh[1], DNA_ENV_RULESET_HASH_LEN);
    print_hex("this build's call_commit[0]",      d->call[0], HASH_LEN);
    print_hex("this build's call_commit[1]",      d->call[1], HASH_LEN);
    print_hex("this build's auth_context_commit", d->ctx,     HASH_LEN);
    print_hex("this build's auth_digest[0]",      d->auth[0], HASH_LEN);
    print_hex("this build's auth_digest[1]",      d->auth[1], HASH_LEN);
    print_hex("this build's tx_id",               d->txid,    HASH_LEN);
    printf("────────────────────────────────────────────────────────────\n\n");

    /* Layout arithmetic of this exact fixture, independent of any digest:
     * 43 + 2*30 + (8 + 0) + (5 + 3) = 119. */
    CHECK(d->len == 119);

    if (KAT_ENV_BYTES_LEN == 0) {
        printf("[KAT PENDING] KAT_ENV_BYTES — no oracle bytes pinned yet\n");
    } else {
        CHECK(KAT_ENV_BYTES_LEN == d->len);
        if (KAT_ENV_BYTES_LEN == d->len)
            CHECK(memcmp(KAT_ENV_BYTES, d->bytes, d->len) == 0);
    }

    kat_expect("call_commit[0]",      d->call[0], KAT_CALL_COMMIT_0);
    kat_expect("call_commit[1]",      d->call[1], KAT_CALL_COMMIT_1);
    kat_expect("auth_context_commit", d->ctx,     KAT_AUTH_CONTEXT_COMMIT);
    kat_expect("auth_digest[0]",      d->auth[0], KAT_AUTH_DIGEST_0);
    kat_expect("auth_digest[1]",      d->auth[1], KAT_AUTH_DIGEST_1);
    kat_expect("tx_id",               d->txid,    KAT_TX_ID);

    dg_free(d);
    fx_free(f);
}

int main(void) {
    test_size_formula();
    test_roundtrip_shapes();
    test_accept_boundaries();
    test_leg_count_guard_is_load_bearing();
    test_max_size_envelope();
    test_decode_rejects();
    test_encode_rejects();
    test_commit_rejects();
    test_binding();
    test_kat();

    if (failures) {
        fprintf(stderr, "test_env_wire: %d check(s) failed\n", failures);
        return 1;
    }
    printf("test_env_wire: all checks passed\n");
    return 0;
}
