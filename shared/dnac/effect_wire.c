/**
 * @file shared/dnac/effect_wire.c
 * @brief Ledger V2 — generic typed-effect RESULT codec.
 *
 * INACTIVE: no live consensus path calls anything here. See effect_wire.h
 * for the tag table, the exact wire layout, the kind/precondition
 * legality biconditional, the canonical total order, the LIFETIME RULE on
 * decoded views, and the honest label on what this codec does and does not
 * check.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "effect_wire.h"

#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* ── Tags: each EXACTLY 16 bytes, zero-padded ASCII — same discipline as
 *    TAG_ENV_FAMILY (env_wire.c:26) and DNAC_TXW_V5_TAG (tx_wire.c:140).
 *    Explicit character initialisers, so the padding is visible and
 *    pinned rather than implied by a string literal's length. ──────── */

/** Wire family marker: "DNA.EFFRES.v1" (13 chars) + 3 zero bytes. */
static const uint8_t TAG_EFF_FAMILY[DNA_EFFECT_WIRE_FAMILY_LEN] = {
    'D','N','A','.','E','F','F','R','E','S','.','v','1', 0, 0, 0
};
/** Value-hash tag: "DNA.EFFVAL.v1" (13 chars) + 3 zero bytes. */
static const uint8_t TAG_EFF_VALUE[DNA_EFFECT_TAG_LEN] = {
    'D','N','A','.','E','F','F','V','A','L','.','v','1', 0, 0, 0
};

/* ── Preimage geometry (internal; the header documents the layout) ──── */

/** value-hash preimage without the value bytes: tag(16) + value_len(4). */
#define EFF_VH_PRE_FIXED   20
/** Largest value-hash preimage (value_len = DNA_EFFECT_MAX_VALUE_LEN). */
#define EFF_VH_PRE_MAX     (EFF_VH_PRE_FIXED + DNA_EFFECT_MAX_VALUE_LEN)

/* ── Layout arithmetic is pinned, not assumed ───────────────────────── */
_Static_assert(DNA_EFFECT_FIXED_HEAD ==
                   DNA_EFFECT_WIRE_FAMILY_LEN + 1 + 2 + 4,
               "result fixed head layout drifted (must be 16+1+2+4)");
_Static_assert(DNA_EFFECT_RECORD_LEN ==
                   4 + 1 + 1 + 8 + DNA_EFFECT_HASH_LEN + 2 + 4,
               "effect record layout drifted (must be 4+1+1+8+64+2+4)");
/* The effect count is u16 on the wire; the ceiling must fit that width. */
_Static_assert(DNA_EFFECT_MAX_COUNT > 0 && DNA_EFFECT_MAX_COUNT <= 0xFFFF,
               "effect ceiling does not fit the u16 count");
/* A full record region: 23 + 64*84. Bounded, so the head arithmetic in
 * both the size walk and the decode walk cannot overflow. */
_Static_assert((size_t)DNA_EFFECT_FIXED_HEAD +
                   (size_t)DNA_EFFECT_MAX_COUNT * DNA_EFFECT_RECORD_LEN ==
                   5399,
               "maximum record region drifted (23 + 84*64)");
/* ...and it must leave room for payload under the total cap. */
_Static_assert((size_t)DNA_EFFECT_FIXED_HEAD +
                   (size_t)DNA_EFFECT_MAX_COUNT * DNA_EFFECT_RECORD_LEN <
                   (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
               "record region does not fit under the total cap");
/* Blob bounds: a key is never empty, and neither blob may on its own be
 * the reason a result is unencodable. */
_Static_assert(DNA_EFFECT_MAX_KEY_LEN > 0 &&
                   DNA_EFFECT_MAX_KEY_LEN <= 0xFFFF,
               "key ceiling does not fit the u16 key_len");
_Static_assert((size_t)DNA_EFFECT_MAX_VALUE_LEN <
                   (size_t)DNA_EFFECT_MAX_TOTAL_LEN,
               "value ceiling does not fit under the total cap");
/* dna_effect_value_hash builds its preimage on the STACK; this is the
 * justification for that choice — 8212 bytes worst case. */
_Static_assert(EFF_VH_PRE_MAX == 8212,
               "value-hash max preimage drifted (20 + 8192)");

/* ── Fixed-width big-endian helpers ─────────────────────────────────── */

static void put_be16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}
static void put_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static uint16_t get_be16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}
static uint32_t get_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  | (uint32_t)in[3];
}
static uint64_t get_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}

/* ── Structural validation (shared by encode and decode) ────────────── */

/** @return 1 if all `len` bytes of `b` are zero, 0 otherwise. */
static int all_zero(const uint8_t *b, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= b[i];
    return acc == 0;
}

/**
 * Every rule ONE effect record must satisfy in BOTH directions. Ordering
 * and logical-key uniqueness are not decidable here (they need the other
 * records) and are checked by the caller's walk.
 *
 * @return 0 if valid, -1 otherwise.
 */
static int effect_hdr_ok(const dna_effect_hdr_t *h) {
    /* kind 0 is INVALID by design: zeroed memory must not decode as a
     * valid effect. Anything above DELETE is an unknown kind — fail
     * closed, never "treat as set". */
    if (h->effect_kind != (uint8_t)DNA_EFFECT_CREATE &&
        h->effect_kind != (uint8_t)DNA_EFFECT_SET &&
        h->effect_kind != (uint8_t)DNA_EFFECT_DELETE) return -1;
    /* precond 0 is INVALID (same fail-closed rule); above EXISTS_VHASH is
     * an unknown precondition. */
    if (h->precond_tag != (uint8_t)DNA_EFFECT_PRE_ABSENT &&
        h->precond_tag != (uint8_t)DNA_EFFECT_PRE_EXISTS &&
        h->precond_tag != (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION &&
        h->precond_tag != (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH) return -1;

    /* The legality BICONDITIONAL (effect_wire.h): CREATE <=> ABSENT.
     * Written as the two implications so neither direction can be lost:
     * a CREATE with EXISTS* would assert the key it creates already
     * exists, and a SET/DELETE with ABSENT would mutate a key it asserts
     * is not there. Both are rejected before any other field is read as
     * meaningful. */
    if (h->effect_kind == (uint8_t)DNA_EFFECT_CREATE &&
        h->precond_tag != (uint8_t)DNA_EFFECT_PRE_ABSENT) return -1;
    if (h->precond_tag == (uint8_t)DNA_EFFECT_PRE_ABSENT &&
        h->effect_kind != (uint8_t)DNA_EFFECT_CREATE) return -1;

    /* RESERVED-FIELD MISUSE: a field no precondition consumes MUST be
     * zero, or the same result would have two encodings. Note the gate is
     * the TAG only — expected_version == 0 under EXISTS_VERSION is legal,
     * because 0 is a legal expected version. */
    if (h->precond_tag != (uint8_t)DNA_EFFECT_PRE_EXISTS_VERSION &&
        h->expected_version != 0) return -1;
    if (h->precond_tag != (uint8_t)DNA_EFFECT_PRE_EXISTS_VHASH &&
        !all_zero(h->expected_vhash, DNA_EFFECT_HASH_LEN)) return -1;

    /* Blob bounds. A zero-length key names nothing and is REJECTED. */
    if (h->key_len == 0 || h->key_len > DNA_EFFECT_MAX_KEY_LEN) return -1;
    if (h->value_len > DNA_EFFECT_MAX_VALUE_LEN) return -1;
    /* A DELETE carries no replacement value. */
    if (h->effect_kind == (uint8_t)DNA_EFFECT_DELETE && h->value_len != 0)
        return -1;
    return 0;
}

/**
 * Key-byte comparison, rule 3 of the canonical order: memcmp over the
 * shared prefix decides; on an equal prefix the SHORTER key sorts first.
 *
 * @return <0, 0 or >0.
 */
static int eff_key_cmp(const uint8_t *ka, uint16_t la,
                       const uint8_t *kb, uint16_t lb) {
    uint16_t m = (la < lb) ? la : lb;
    if (m) {
        int c = memcmp(ka, kb, (size_t)m);
        if (c != 0) return c;
    }
    if (la < lb) return -1;
    if (la > lb) return 1;
    return 0;
}

/**
 * The full canonical total order: effect_kind, then op_id, then key bytes
 * (eff_key_cmp). A return of 0 means the two records are IDENTICAL under
 * the order — a duplicate.
 *
 * @return <0, 0 or >0.
 */
static int eff_order_cmp(const dna_effect_hdr_t *a, const uint8_t *ka,
                         const dna_effect_hdr_t *b, const uint8_t *kb) {
    if (a->effect_kind != b->effect_kind)
        return (a->effect_kind < b->effect_kind) ? -1 : 1;
    if (a->op_id != b->op_id)
        return (a->op_id < b->op_id) ? -1 : 1;
    return eff_key_cmp(ka, a->key_len, kb, b->key_len);
}

/**
 * The ONE order + uniqueness walk, shared by encode and decode so the two
 * can never disagree about what canonical means.
 *
 *   - adjacent records must be STRICTLY ascending (equality and descent
 *     are both non-canonical);
 *   - the LOGICAL key (op_id, key bytes) must be unique across the WHOLE
 *     result regardless of kind. Because kind is the MAJOR sort axis, two
 *     records sharing a logical key under different kinds are generally
 *     NOT adjacent, so the strict-ascent check alone cannot see them —
 *     hence the explicit pairwise scan. n <= DNA_EFFECT_MAX_COUNT (64), so
 *     the O(n^2) is bounded at 2016 comparisons and is deterministic.
 *
 * Both walks take ARRAYS OF POINTERS rather than an array of records, so
 * the encoder (whose records live inside dna_effect_in_t) and the decoder
 * (whose records live in the view) can share this one implementation
 * without either side copying a record.
 *
 * @param hdr  n record pointers
 * @param keys n key pointers, keys[i] being hdr[i]->key_len bytes
 * @return 0 if canonical, -1 otherwise.
 */
static int eff_order_ok(const dna_effect_hdr_t *const *hdr,
                        const uint8_t *const *keys, uint16_t n) {
    for (uint16_t i = 1; i < n; i++)
        if (eff_order_cmp(hdr[i - 1], keys[i - 1], hdr[i], keys[i]) >= 0)
            return -1;
    for (uint16_t i = 0; i < n; i++)
        for (uint16_t j = (uint16_t)(i + 1); j < n; j++)
            if (hdr[i]->op_id == hdr[j]->op_id &&
                eff_key_cmp(keys[i], hdr[i]->key_len,
                            keys[j], hdr[j]->key_len) == 0)
                return -1;
    return 0;
}

/**
 * The ONE length-accumulation guard, shared by the encoder's size walk and
 * the decoder's offset walk so the two can never disagree about the cap.
 *
 * SUBTRACTION form against the invariant *acc <= DNA_EFFECT_MAX_TOTAL_LEN:
 * `len > CAP - acc` can never wrap, whereas `acc + len > CAP` can.
 *
 * HONEST LABEL: with the per-blob caps enforced by effect_hdr_ok /
 * dna_effect_result_encoded_size before any accumulation, the largest
 * reachable total is 5399 + 64*128 + 64*8192 = 537879, so on this tree's
 * targets the addition could not in fact wrap. The subtraction form is
 * kept as defence in depth: it stays correct if a future
 * result_version widens a cap, and it is the same idiom the sibling codec
 * uses (env_acc_add, env_wire.c:160).
 *
 * @return 0 if the addition stayed under the cap, -1 otherwise.
 */
static int eff_acc_add(size_t *acc, uint32_t len) {
    if (*acc > (size_t)DNA_EFFECT_MAX_TOTAL_LEN) return -1;   /* invariant */
    if ((size_t)len > (size_t)DNA_EFFECT_MAX_TOTAL_LEN - *acc) return -1;
    *acc += (size_t)len;
    return 0;
}

/* ── Codec ──────────────────────────────────────────────────────────── */

int dna_effect_result_encoded_size(const dna_effect_in_t *effects, uint16_t n,
                                   size_t *out) {
    if (!out) return -1;
    *out = 0;   /* no stale length survives a reject */
    /* n == 0 with a NULL array is ACCEPTED — the empty result needs no
     * array (effect_wire.h). A NULL array with n > 0 is not. */
    if (!effects && n > 0) return -1;
    if (n > DNA_EFFECT_MAX_COUNT) return -1;

    /* Bounded by 5399 (_Static_assert above), so this cannot overflow. */
    size_t acc = (size_t)DNA_EFFECT_FIXED_HEAD +
                 (size_t)n * (size_t)DNA_EFFECT_RECORD_LEN;

    /* All key blobs first, then all value blobs — the section order IS the
     * wire layout, so the size walk mirrors the encode walk exactly. The
     * caps are judged here too, so this function and the encoder can never
     * disagree about which inputs have a length at all. */
    for (uint16_t i = 0; i < n; i++) {
        if (effects[i].hdr.key_len == 0 ||
            effects[i].hdr.key_len > DNA_EFFECT_MAX_KEY_LEN) return -1;
        if (eff_acc_add(&acc, effects[i].hdr.key_len) != 0) return -1;
    }
    for (uint16_t i = 0; i < n; i++) {
        if (effects[i].hdr.value_len > DNA_EFFECT_MAX_VALUE_LEN) return -1;
        if (eff_acc_add(&acc, effects[i].hdr.value_len) != 0) return -1;
    }

    *out = acc;
    return 0;
}

int dna_effect_result_encode(const dna_effect_in_t *effects, uint16_t n,
                             uint8_t *dst, size_t dst_cap,
                             size_t *written_out) {
    if (!written_out) return -1;
    *written_out = 0;   /* no stale length survives a reject */
    if (!dst) return -1;
    if (!effects && n > 0) return -1;
    if (n > DNA_EFFECT_MAX_COUNT) return -1;

    /* Never emit a non-canonical result: the encoder runs the SAME rule
     * list the decoder enforces, so encode(x) is decodable by
     * construction, and a caller cannot obtain a second encoding of one
     * result by handing the effects over in a different order. */
    const dna_effect_hdr_t *hdrs[DNA_EFFECT_MAX_COUNT] = {0};
    const uint8_t          *keys[DNA_EFFECT_MAX_COUNT] = {0};
    for (uint16_t i = 0; i < n; i++) {
        const dna_effect_in_t *e = &effects[i];
        if (effect_hdr_ok(&e->hdr) != 0) return -1;
        /* key_len >= 1 is already guaranteed, so a NULL key is always a
         * NULL pointer with a non-zero length. */
        if (!e->key) return -1;
        if (!e->value && e->hdr.value_len != 0) return -1;
        hdrs[i] = &e->hdr;
        keys[i] = e->key;
    }
    if (eff_order_ok(hdrs, keys, n) != 0) return -1;

    size_t need = 0;
    if (dna_effect_result_encoded_size(effects, n, &need) != 0) return -1;
    if (dst_cap < need) return -1;

    uint8_t *p = dst;
    memcpy(p, TAG_EFF_FAMILY, DNA_EFFECT_WIRE_FAMILY_LEN);
    p += DNA_EFFECT_WIRE_FAMILY_LEN;                       /* off 0  */
    *p++ = (uint8_t)DNA_EFFECT_RESULT_VERSION;             /* off 16 */
    put_be16(n, p);   p += 2;                              /* off 17 */
    put_be32(0u, p);  p += 4;                              /* off 19 reserved */

    for (uint16_t i = 0; i < n; i++) {
        const dna_effect_hdr_t *h = &effects[i].hdr;
        put_be32(h->op_id, p);            p += 4;          /* +0  */
        *p++ = h->effect_kind;                             /* +4  */
        *p++ = h->precond_tag;                             /* +5  */
        put_be64(h->expected_version, p);  p += 8;         /* +6  */
        memcpy(p, h->expected_vhash, DNA_EFFECT_HASH_LEN);
        p += DNA_EFFECT_HASH_LEN;                          /* +14 */
        put_be16(h->key_len, p);          p += 2;          /* +78 */
        put_be32(h->value_len, p);        p += 4;          /* +80 */
    }

    for (uint16_t i = 0; i < n; i++) {
        uint16_t len = effects[i].hdr.key_len;
        memcpy(p, effects[i].key, len);
        p += len;
    }
    for (uint16_t i = 0; i < n; i++) {
        uint32_t len = effects[i].hdr.value_len;
        if (len) { memcpy(p, effects[i].value, len); p += len; }
    }

    /* final-offset proof: the walk landed EXACTLY on the length the
     * records predict — a drifted field width cannot be emitted silently */
    if ((size_t)(p - dst) != need) return -1;

    *written_out = need;
    return 0;
}

int dna_effect_result_decode(const uint8_t *src, size_t src_len,
                             dna_effect_view_t *out) {
    /* Fail closed FIRST: `out` is NULL-checked ALONE and zeroed before any
     * other argument is judged, so even a NULL `src` reject honours the
     * header's "on ANY rejection *out is zeroed" contract. Zeroing also
     * clears the slots at or beyond effect_count, which is what makes a
     * decoded view re-encode byte-identically. */
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!src) return -1;

    if (src_len < (size_t)DNA_EFFECT_FIXED_HEAD) return -1;   /* truncated */
    if (memcmp(src, TAG_EFF_FAMILY, DNA_EFFECT_WIRE_FAMILY_LEN) != 0)
        return -1;                    /* wrong family — validates the zero
                                       * padding of the marker too         */
    if (src[DNA_EFFECT_WIRE_FAMILY_LEN] !=
        (uint8_t)DNA_EFFECT_RESULT_VERSION) return -1;

    uint16_t n = get_be16(src + 17);
    if (n > DNA_EFFECT_MAX_COUNT) return -1;   /* 0 is a VALID empty result */
    if (get_be32(src + 19) != 0u) return -1;   /* reserved MUST be zero     */

    /* KEY_BASE(n): the record region must be present in full BEFORE a
     * single record byte is read. Bounded by 5399, cannot overflow. */
    size_t key_base = (size_t)DNA_EFFECT_FIXED_HEAD +
                      (size_t)n * (size_t)DNA_EFFECT_RECORD_LEN;
    if (src_len < key_base) return -1;

    /* From here fields are copied into *out, so every reject goes through
     * `fail:` — a bare return would leave a half-walked view visible. */
    const uint8_t *p = src + DNA_EFFECT_FIXED_HEAD;
    for (uint16_t i = 0; i < n; i++) {
        dna_effect_hdr_t *h = &out->eff[i];
        h->op_id            = get_be32(p);   p += 4;          /* +0  */
        h->effect_kind      = *p++;                           /* +4  */
        h->precond_tag      = *p++;                           /* +5  */
        h->expected_version = get_be64(p);   p += 8;          /* +6  */
        memcpy(h->expected_vhash, p, DNA_EFFECT_HASH_LEN);
        p += DNA_EFFECT_HASH_LEN;                             /* +14 */
        h->key_len          = get_be16(p);   p += 2;          /* +78 */
        h->value_len        = get_be32(p);   p += 4;          /* +80 */

        if (effect_hdr_ok(h) != 0) goto fail;
    }
    /* final-offset proof for the record region */
    if ((size_t)(p - src) != key_base) goto fail;

    /* Offsets: all key blobs, then all value blobs. Every accumulation is
     * capped through the shared subtraction-form guard. */
    size_t acc = key_base;
    for (uint16_t i = 0; i < n; i++) {
        out->key_off[i] = (uint32_t)acc;
        if (eff_acc_add(&acc, out->eff[i].key_len) != 0) goto fail;
    }
    for (uint16_t i = 0; i < n; i++) {
        out->val_off[i] = (uint32_t)acc;
        if (eff_acc_add(&acc, out->eff[i].value_len) != 0) goto fail;
    }

    /* EXACT length: truncation AND trailing bytes are both rejected. This
     * runs BEFORE the order walk, which is what makes dereferencing the
     * key blobs below safe. */
    if (src_len != acc) goto fail;

    /* Canonical order + logical-key uniqueness, over the key bytes now
     * proven to lie inside src. */
    {
        const dna_effect_hdr_t *hdrs[DNA_EFFECT_MAX_COUNT] = {0};
        const uint8_t          *keys[DNA_EFFECT_MAX_COUNT] = {0};
        for (uint16_t i = 0; i < n; i++) {
            hdrs[i] = &out->eff[i];
            keys[i] = src + out->key_off[i];
        }
        if (eff_order_ok(hdrs, keys, n) != 0) goto fail;
    }

    out->result_version = src[DNA_EFFECT_WIRE_FAMILY_LEN];
    out->effect_count   = n;
    out->buf            = src;      /* BORROWED — see LIFETIME RULE */
    out->res_len        = acc;

    /* final-offset proof for the payload walk: the last value blob must
     * end exactly at the result length. An empty result has no payload,
     * and its head length was already proven by the exact-length check. */
    if (n > 0 &&
        (size_t)out->val_off[n - 1] + (size_t)out->eff[n - 1].value_len !=
        out->res_len) goto fail;

    return 0;

fail:
    /* The ONE reject exit for every check that can fire after a field has
     * been copied into *out. Re-zeroing here is what makes the header's
     * "on ANY rejection *out is zeroed" true for a result rejected in the
     * middle of its walk — the leading memset alone cannot. */
    memset(out, 0, sizeof(*out));
    return -1;
}

/* ── The one hash this module defines ───────────────────────────────── */

int dna_effect_value_hash(const uint8_t *value, uint32_t value_len,
                          uint8_t out[DNA_EFFECT_HASH_LEN]) {
    if (!out) return -1;
    if (!value && value_len != 0) return -1;
    /* Bound the length BEFORE the preimage addition: this both keeps the
     * helper inside the codec's own value bound and makes the 20 +
     * value_len arithmetic unwrappable on any size_t width. */
    if (value_len > DNA_EFFECT_MAX_VALUE_LEN) return -1;

    /* STACK: bounded by EFF_VH_PRE_MAX = 8212 bytes (_Static_assert above
     * is the justification). The digest buffer is not touched until the
     * whole preimage is built, so every reject above leaves it as it was. */
    uint8_t pre[EFF_VH_PRE_MAX];
    size_t pre_len = (size_t)EFF_VH_PRE_FIXED + (size_t)value_len;

    uint8_t *p = pre;
    memcpy(p, TAG_EFF_VALUE, DNA_EFFECT_TAG_LEN);  p += DNA_EFFECT_TAG_LEN;
    put_be32(value_len, p);                        p += 4;
    if (value_len) { memcpy(p, value, value_len);  p += value_len; }

    int rc = -1;
    /* final-offset proof: the preimage walk landed EXACTLY on the length
     * the geometry predicts — a drifted field cannot be hashed silently */
    if ((size_t)(p - pre) == pre_len)
        rc = (qgp_sha3_512(pre, pre_len, out) == 0) ? 0 : -1;

    /* Value material hygiene: wipe the temporary preimage. */
    memset(pre, 0, sizeof(pre));
    return rc;
}
