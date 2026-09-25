/**
 * @file shared/dnac/env_wire.c
 * @brief Ledger V2 K1 — generic envelope codec + commitment helpers.
 *
 * INACTIVE: no live consensus path calls anything here (K1 charter). See
 * env_wire.h for the tag table, the exact wire layout, the commitment
 * preimages, the LIFETIME RULE on decoded views, the NON-CIRCULARITY
 * property, and the honest label on what decode does and does not check.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "env_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* ── Tags: each EXACTLY 16 bytes, zero-padded ASCII — same discipline as
 *    DNAC_TXW_V5_TAG (tx_wire.c:140-142) and vset_wire.c:22. Explicit
 *    character initialisers, so the padding is visible and pinned. ──── */

/** Wire family marker: "DNA.ENVWIRE.v1" (14 chars) + 2 zero bytes. */
static const uint8_t TAG_ENV_FAMILY[DNA_ENV_WIRE_FAMILY_LEN] = {
    'D','N','A','.','E','N','V','W','I','R','E','.','v','1', 0, 0
};
/** "DNA.ENVCALL.v1" (14 chars) + 2 zero bytes. */
static const uint8_t TAG_ENV_CALL[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','C','A','L','L','.','v','1', 0, 0
};
/** "DNA.ENVCTX.v1" (13 chars) + 3 zero bytes. */
static const uint8_t TAG_ENV_CTX[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','C','T','X','.','v','1', 0, 0, 0
};
/** "DNA.ENVAUTH.v1" (14 chars) + 2 zero bytes. */
static const uint8_t TAG_ENV_AUTH[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','A','U','T','H','.','v','1', 0, 0
};
/** "DNA.ENVTXID.v1" (14 chars) + 2 zero bytes. */
static const uint8_t TAG_ENV_TXID[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','T','X','I','D','.','v','1', 0, 0
};
/** "DNA.ENVILEG.v1" (14 chars) + 2 zero bytes (intent season). */
static const uint8_t TAG_ENV_ILEG[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','I','L','E','G','.','v','1', 0, 0
};
/** "DNA.ENVINTID.v1" (15 chars) + 1 zero byte (intent season). */
static const uint8_t TAG_ENV_INTENT[DNA_ENV_TAG_LEN] = {
    'D','N','A','.','E','N','V','I','N','T','I','D','.','v','1', 0
};

/* ── Preimage geometry (internal; the header documents the layouts) ─── */

/** AUTHCTX_BYTES head: family(16)+ver(1)+chain(32)+8+8+8+count(2). */
#define ENV_AUTHCTX_HEAD  75
/** AUTHCTX_BYTES per-leg segment: 4+4+4+1+1+4+4+4+4+call_commit(64). */
#define ENV_AUTHCTX_LEG   94
/** auth_context_commit preimage = tag(16) + AUTHCTX_HEAD. */
#define ENV_AUTHCTX_PRE_FIXED  (DNA_ENV_TAG_LEN + ENV_AUTHCTX_HEAD)
/** Largest auth_context_commit preimage (n = DNA_ENV_MAX_LEGS). */
#define ENV_AUTHCTX_PRE_MAX \
    (ENV_AUTHCTX_PRE_FIXED + ENV_AUTHCTX_LEG * DNA_ENV_MAX_LEGS)
/** call_commit preimage without the call data: 16+4+4+4+64+1+4. */
#define ENV_CALL_PRE_FIXED     97
/** auth_digest preimage, fixed: 16+64+2+4+4. */
#define ENV_AUTH_PRE_LEN       90
/** tx_id preimage without the envelope bytes: 16+64+4. */
#define ENV_TXID_PRE_FIXED     84
/** intent_leg_commit preimage, fixed: 16+4+4+4+1+1+4+4+64 (intent
 *  season — auth_len is EXCLUDED by construction, auth_kind included). */
#define ENV_ILEG_PRE_LEN       102
/** intent_id preimage head: tag(16) + family(16) + ver(1) + chain(32)
 *  + expiry(8) + fee(8) + res(8) + count(2). */
#define ENV_INTENT_PRE_FIXED   91
/** Largest intent_id preimage (n = DNA_ENV_MAX_LEGS legs of 64 B). */
#define ENV_INTENT_PRE_MAX \
    (ENV_INTENT_PRE_FIXED + DNA_ENV_HASH_LEN * DNA_ENV_MAX_LEGS)

/* ── Layout arithmetic is pinned, not assumed ───────────────────────── */
_Static_assert(DNA_ENV_FIXED_HEAD ==
                   DNA_ENV_WIRE_FAMILY_LEN + 1 + 8 + 8 + 8 + 2,
               "envelope fixed header layout drifted");
_Static_assert(DNA_ENV_LEG_HDR_LEN == 4 + 4 + 4 + 1 + 1 + 4 + 4 + 4 + 4,
               "envelope leg header layout drifted");
_Static_assert(ENV_AUTHCTX_HEAD == DNA_ENV_WIRE_FAMILY_LEN + 1 +
                   DNA_ENV_CHAIN_ID_LEN + 8 + 8 + 8 + 2,
               "AUTHCTX_BYTES head layout drifted");
_Static_assert(ENV_AUTHCTX_LEG == 4 + 4 + 4 + 1 + 1 + 4 + 4 + 4 + 4 +
                   DNA_ENV_HASH_LEN,
               "AUTHCTX_BYTES per-leg segment drifted (must be 94)");
_Static_assert(ENV_CALL_PRE_FIXED == DNA_ENV_TAG_LEN + 4 + 4 + 4 +
                   DNA_ENV_RULESET_HASH_LEN + 1 + 4,
               "call_commit fixed preimage drifted");
_Static_assert(ENV_AUTH_PRE_LEN == DNA_ENV_TAG_LEN + DNA_ENV_HASH_LEN +
                   2 + 4 + 4,
               "auth_digest preimage drifted");
_Static_assert(ENV_TXID_PRE_FIXED == DNA_ENV_TAG_LEN + DNA_ENV_HASH_LEN + 4,
               "tx_id fixed preimage drifted");
_Static_assert(ENV_ILEG_PRE_LEN == DNA_ENV_TAG_LEN + 4 + 4 + 4 + 1 + 1 +
                   4 + 4 + DNA_ENV_HASH_LEN,
               "intent_leg_commit preimage drifted (must be 102)");
/* The intent leg projection is the 94-byte AUTHCTX leg segment MINUS the
 * 4-byte auth_len MINUS the 4-byte call_len (call_len is committed inside
 * the nested call_commit) PLUS the 16-byte tag: 94 - 4 - 4 + 16 = 102.
 * This identity is the auditable statement that auth_len is the ONE
 * envelope field excluded from intent identity. */
_Static_assert(ENV_ILEG_PRE_LEN == ENV_AUTHCTX_LEG - 4 - 4 + DNA_ENV_TAG_LEN,
               "intent leg projection no longer AUTHCTX-minus-auth_len");
_Static_assert(ENV_INTENT_PRE_FIXED == DNA_ENV_TAG_LEN +
                   DNA_ENV_WIRE_FAMILY_LEN + 1 + DNA_ENV_CHAIN_ID_LEN +
                   8 + 8 + 8 + 2,
               "intent_id preimage head drifted (must be 91)");
/* intent_id builds its preimage on the STACK; 4187 bytes worst case. */
_Static_assert(ENV_INTENT_PRE_MAX == 4187,
               "intent_id max preimage drifted (91 + 64*64)");
/* The leg count is u16 on the wire; the ceiling must fit that width. */
_Static_assert(DNA_ENV_MAX_LEGS > 0 && DNA_ENV_MAX_LEGS <= 0xFFFF,
               "leg ceiling does not fit the u16 count");
/* A full leg-header region must leave room for payload under the cap. */
_Static_assert((size_t)DNA_ENV_FIXED_HEAD +
                   (size_t)DNA_ENV_MAX_LEGS * DNA_ENV_LEG_HDR_LEN == 1963,
               "maximum leg-header region drifted (43 + 30*64)");
_Static_assert((size_t)DNA_ENV_FIXED_HEAD +
                   (size_t)DNA_ENV_MAX_LEGS * DNA_ENV_LEG_HDR_LEN <
                   (size_t)DNA_ENV_MAX_TOTAL_LEN,
               "leg-header region does not fit under the total cap");
/* auth_context_commit builds its preimage on the STACK; this is the
 * justification for that choice — 6107 bytes worst case. */
_Static_assert(ENV_AUTHCTX_PRE_MAX == 6107,
               "auth_context_commit max preimage drifted (91 + 94*64)");
/* tx_id and call_commit preimages are HEAP (up to ~1 MiB — the
 * capacity-season envelope ceiling; nothing here scales the STACK with
 * it: the one stack preimage, auth_context_commit, is leg-count-bounded
 * at 6107 bytes above). */
_Static_assert(ENV_TXID_PRE_FIXED + (size_t)DNA_ENV_MAX_TOTAL_LEN ==
                   1048660,
               "tx_id max preimage drifted (84 + 1048576)");
/* The ceiling is the capacity-season derived bound (env_wire.h block):
 * the smallest power of two containing the worst-case legal envelope. */
_Static_assert(DNA_ENV_MAX_TOTAL_LEN == 1048576u &&
                   (DNA_ENV_MAX_TOTAL_LEN &
                    (DNA_ENV_MAX_TOTAL_LEN - 1u)) == 0,
               "envelope ceiling must stay the derived power of two");
/* Every stored blob offset is u32 (dna_env_view_t.call_off/auth_off):
 * the ceiling must fit that width with room for the length addition. */
_Static_assert((uint64_t)DNA_ENV_MAX_TOTAL_LEN <= 0xFFFFFFFFull,
               "envelope ceiling exceeds the u32 offset space");

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

/**
 * Every rule ONE leg header must satisfy in BOTH directions. Ordering is
 * not decidable here (it needs the predecessor) and is checked by the
 * caller's walk.
 *
 * @return 0 if valid, -1 otherwise.
 */
static int leg_hdr_ok(const dna_env_leg_hdr_t *h) {
    /* access_mode 0 is INVALID by design: zeroed memory must not decode as
     * a valid leg. Anything above INVOKE is an unknown mode — fail closed,
     * never "treat as read". */
    if (h->access_mode != (uint8_t)DNA_ENV_ACCESS_READ &&
        h->access_mode != (uint8_t)DNA_ENV_ACCESS_INVOKE) return -1;
    /* auth_kind 0 is INVALID (same fail-closed rule). Whether a non-zero
     * kind is SUPPORTED is out of K1 scope — env_wire.h honest label. */
    if (h->auth_kind == 0) return -1;
    if (h->runtime_op > DNA_ENV_MAX_RUNTIME_OP) return -1;
    return 0;
}

/**
 * The ONE length-accumulation guard, shared by the encoder's size walk and
 * the decoder's offset walk so the two can never disagree about the cap.
 *
 * SUBTRACTION form against the invariant *acc <= DNA_ENV_MAX_TOTAL_LEN:
 * `len > CAP - acc` can never wrap, whereas `acc + len > CAP` can.
 *
 * @return 0 if the addition stayed under the cap, -1 otherwise.
 */
static int env_acc_add(size_t *acc, uint32_t len) {
    if (*acc > (size_t)DNA_ENV_MAX_TOTAL_LEN) return -1;   /* invariant   */
    if ((size_t)len > (size_t)DNA_ENV_MAX_TOTAL_LEN - *acc) return -1;
    *acc += (size_t)len;
    return 0;
}

/**
 * A blob slice must lie entirely inside [0, v->env_len). True by
 * construction for any view dna_env_decode produced; checked anyway as
 * defence in depth. Subtraction form again.
 *
 * HONEST LABEL: this validates the slice against the view's DECLARED
 * env_len, not against the real size of the v->buf allocation — the codec
 * is never told that size. A hand-built view whose env_len exceeds its
 * buffer can therefore still over-read; keeping buf and env_len consistent
 * is the caller's obligation (see the LIFETIME RULE in env_wire.h). For a
 * decode-produced view the two agree by construction.
 *
 * @return 0 if [off, off+len) fits in env_len, -1 otherwise.
 */
static int view_slice_ok(const dna_env_view_t *v, uint32_t off, uint32_t len) {
    if ((size_t)off > v->env_len) return -1;
    if ((size_t)len > v->env_len - (size_t)off) return -1;
    return 0;
}

/* ── Codec ──────────────────────────────────────────────────────────── */

int dna_env_encoded_size(const dna_env_leg_in_t *legs, uint16_t leg_count,
                         size_t *out) {
    if (!out) return -1;
    *out = 0;   /* no stale length survives a reject */
    if (!legs) return -1;
    if (leg_count == 0 || leg_count > DNA_ENV_MAX_LEGS) return -1;

    /* Bounded by 1963 (_Static_assert above), so this cannot overflow. */
    size_t acc = (size_t)DNA_ENV_FIXED_HEAD +
                 (size_t)leg_count * (size_t)DNA_ENV_LEG_HDR_LEN;

    /* All call blobs first, then all auth blobs — the section order IS the
     * wire layout, so the size walk mirrors the encode walk exactly. */
    for (uint16_t i = 0; i < leg_count; i++)
        if (env_acc_add(&acc, legs[i].hdr.call_len) != 0) return -1;
    for (uint16_t i = 0; i < leg_count; i++)
        if (env_acc_add(&acc, legs[i].hdr.auth_len) != 0) return -1;

    *out = acc;
    return 0;
}

int dna_env_encode(const dna_env_in_t *in, uint8_t *dst, size_t dst_cap,
                   size_t *written_out) {
    if (!written_out) return -1;
    *written_out = 0;   /* no stale length survives a reject */
    if (!in || !dst) return -1;
    if (!in->legs) return -1;
    if (in->leg_count == 0 || in->leg_count > DNA_ENV_MAX_LEGS) return -1;

    /* Never emit a non-canonical envelope: the encoder runs the SAME rule
     * list the decoder enforces, so encode(x) is decodable by construction. */
    for (uint16_t i = 0; i < in->leg_count; i++) {
        const dna_env_leg_in_t *l = &in->legs[i];
        if (leg_hdr_ok(&l->hdr) != 0) return -1;
        if (!l->call_data && l->hdr.call_len != 0) return -1;
        if (!l->auth_data && l->hdr.auth_len != 0) return -1;
        /* Strictly ascending by domain_id — equal (duplicate) or
         * descending are both non-canonical (tx_wire.c:851-854 idiom). */
        if (i > 0 && in->legs[i - 1].hdr.domain_id >= l->hdr.domain_id)
            return -1;
    }

    size_t need = 0;
    if (dna_env_encoded_size(in->legs, in->leg_count, &need) != 0) return -1;
    if (dst_cap < need) return -1;

    uint8_t *p = dst;
    memcpy(p, TAG_ENV_FAMILY, DNA_ENV_WIRE_FAMILY_LEN);
    p += DNA_ENV_WIRE_FAMILY_LEN;                          /* off 0  */
    *p++ = (uint8_t)DNA_ENV_VERSION;                       /* off 16 */
    put_be64(in->expiry_height, p);       p += 8;          /* off 17 */
    put_be64(in->fee_amount, p);          p += 8;          /* off 25 */
    put_be64(in->res_max_total_units, p); p += 8;          /* off 33 */
    put_be16(in->leg_count, p);           p += 2;          /* off 41 */

    for (uint16_t i = 0; i < in->leg_count; i++) {
        const dna_env_leg_hdr_t *h = &in->legs[i].hdr;
        put_be32(h->domain_id, p);            p += 4;      /* +0  */
        put_be32(h->runtime_op, p);           p += 4;      /* +4  */
        put_be32(h->ruleset_version, p);      p += 4;      /* +8  */
        *p++ = h->access_mode;                             /* +12 */
        *p++ = h->auth_kind;                               /* +13 */
        put_be32(h->call_len, p);             p += 4;      /* +14 */
        put_be32(h->auth_len, p);             p += 4;      /* +18 */
        put_be32(h->res_max_effects, p);      p += 4;      /* +22 */
        put_be32(h->res_max_effect_bytes, p); p += 4;      /* +26 */
    }

    for (uint16_t i = 0; i < in->leg_count; i++) {
        uint32_t len = in->legs[i].hdr.call_len;
        if (len) { memcpy(p, in->legs[i].call_data, len); p += len; }
    }
    for (uint16_t i = 0; i < in->leg_count; i++) {
        uint32_t len = in->legs[i].hdr.auth_len;
        if (len) { memcpy(p, in->legs[i].auth_data, len); p += len; }
    }

    /* final-offset proof: the walk landed EXACTLY on the length the leg
     * headers predict — a drifted field width cannot be emitted silently */
    if ((size_t)(p - dst) != need) return -1;

    *written_out = need;
    return 0;
}

int dna_env_decode(const uint8_t *src, size_t src_len, dna_env_view_t *out) {
    /* Fail closed FIRST: `out` is NULL-checked ALONE and zeroed before any
     * other argument is judged, so even a NULL `src` reject honours the
     * header's "on ANY rejection *out is zeroed" contract. Zeroing also
     * clears the slots at or beyond leg_count, which is what makes a
     * decoded view re-encode byte-identically (tx_wire.c:919-931). */
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!src) return -1;

    if (src_len < (size_t)DNA_ENV_FIXED_HEAD) return -1;   /* truncated    */
    if (memcmp(src, TAG_ENV_FAMILY, DNA_ENV_WIRE_FAMILY_LEN) != 0)
        return -1;                    /* wrong family — validates the
                                       * zero padding of the marker too   */
    if (src[DNA_ENV_WIRE_FAMILY_LEN] != (uint8_t)DNA_ENV_VERSION) return -1;

    uint16_t n = get_be16(src + 41);
    if (n == 0 || n > DNA_ENV_MAX_LEGS) return -1;

    /* CALL_BASE(n): the leg-header region must be present in full BEFORE a
     * single leg-header byte is read. Bounded by 1963, cannot overflow. */
    size_t call_base = (size_t)DNA_ENV_FIXED_HEAD +
                       (size_t)n * (size_t)DNA_ENV_LEG_HDR_LEN;
    if (src_len < call_base) return -1;

    /* From here fields are copied into *out, so every reject goes through
     * `fail:` — a bare return would leave a half-walked view visible. */
    const uint8_t *p = src + DNA_ENV_FIXED_HEAD;
    for (uint16_t i = 0; i < n; i++) {
        dna_env_leg_hdr_t *h = &out->leg[i];
        h->domain_id            = get_be32(p);      p += 4;   /* +0  */
        h->runtime_op           = get_be32(p);      p += 4;   /* +4  */
        h->ruleset_version      = get_be32(p);      p += 4;   /* +8  */
        h->access_mode          = *p++;                       /* +12 */
        h->auth_kind            = *p++;                       /* +13 */
        h->call_len             = get_be32(p);      p += 4;   /* +14 */
        h->auth_len             = get_be32(p);      p += 4;   /* +18 */
        h->res_max_effects      = get_be32(p);      p += 4;   /* +22 */
        h->res_max_effect_bytes = get_be32(p);      p += 4;   /* +26 */

        if (leg_hdr_ok(h) != 0) goto fail;
        if (i > 0 && out->leg[i - 1].domain_id >= h->domain_id)
            goto fail;               /* equal (duplicate) or descending    */
    }
    /* final-offset proof for the header region */
    if ((size_t)(p - src) != call_base) goto fail;

    /* Offsets: all call blobs, then all auth blobs. Every accumulation is
     * capped through the shared subtraction-form guard, so a hostile
     * call_len/auth_len cannot wrap the arithmetic. */
    size_t acc = call_base;
    for (uint16_t i = 0; i < n; i++) {
        out->call_off[i] = (uint32_t)acc;
        if (env_acc_add(&acc, out->leg[i].call_len) != 0) goto fail;
    }
    for (uint16_t i = 0; i < n; i++) {
        out->auth_off[i] = (uint32_t)acc;
        if (env_acc_add(&acc, out->leg[i].auth_len) != 0) goto fail;
    }

    /* EXACT length: truncation AND trailing bytes are both rejected. */
    if (src_len != acc) goto fail;

    out->envelope_version    = src[DNA_ENV_WIRE_FAMILY_LEN];
    out->expiry_height       = get_be64(src + 17);
    out->fee_amount          = get_be64(src + 25);
    out->res_max_total_units = get_be64(src + 33);
    out->leg_count           = n;
    out->buf                 = src;      /* BORROWED — see LIFETIME RULE  */
    out->env_len             = acc;

    /* final-offset proof for the payload walk: the last auth blob must end
     * exactly at the envelope length. */
    if ((size_t)out->auth_off[n - 1] + (size_t)out->leg[n - 1].auth_len !=
        out->env_len) goto fail;

    return 0;

fail:
    /* The ONE reject exit for every check that can fire after a field has
     * been copied into *out. Re-zeroing here is what makes the header's
     * "on ANY rejection *out is zeroed" true for an envelope rejected in
     * the middle of its walk — the leading memset alone cannot. */
    memset(out, 0, sizeof(*out));
    return -1;
}

/* ── Commitments ────────────────────────────────────────────────────── */

int dna_env_call_commit(const dna_env_view_t *v, uint16_t leg_index,
                        const uint8_t ruleset_hash[DNA_ENV_RULESET_HASH_LEN],
                        uint8_t out[DNA_ENV_HASH_LEN]) {
    if (!v || !ruleset_hash || !out) return -1;
    if (!v->buf) return -1;                       /* uninitialised view    */
    /* leg_count itself must be in range BEFORE it is used as the index
     * bound — otherwise a hand-built view with an over-large leg_count
     * turns `leg_index < leg_count` into an out-of-bounds read of the
     * fixed leg[]/call_off[] arrays. Same guard the sibling
     * dna_env_auth_context_commit already applies. */
    if (v->leg_count == 0 || v->leg_count > DNA_ENV_MAX_LEGS) return -1;
    if (leg_index >= v->leg_count) return -1;

    const dna_env_leg_hdr_t *h = &v->leg[leg_index];
    if (view_slice_ok(v, v->call_off[leg_index], h->call_len) != 0) return -1;
    /* Bound the length BEFORE the preimage addition: on a 32-bit size_t
     * an unbounded call_len would wrap 97 + call_len. Same shape as the
     * env_len bound in dna_env_tx_id. */
    if ((size_t)h->call_len > (size_t)DNA_ENV_MAX_TOTAL_LEN) return -1;

    /* HEAP: call_len can be tens of KB, and there is no streaming SHA3 API
     * in this tree (qgp_sha3.h has one-shot qgp_sha3_512 only), so the whole
     * preimage is materialised exactly once — tx_wire.c:236-247 pattern. */
    size_t pre_len = (size_t)ENV_CALL_PRE_FIXED + (size_t)h->call_len;
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;

    uint8_t *p = pre;
    memcpy(p, TAG_ENV_CALL, DNA_ENV_TAG_LEN);  p += DNA_ENV_TAG_LEN;
    put_be32(h->domain_id, p);                 p += 4;
    put_be32(h->runtime_op, p);                p += 4;
    put_be32(h->ruleset_version, p);           p += 4;
    memcpy(p, ruleset_hash, DNA_ENV_RULESET_HASH_LEN);
    p += DNA_ENV_RULESET_HASH_LEN;
    *p++ = h->access_mode;
    put_be32(h->call_len, p);                  p += 4;
    if (h->call_len) {
        memcpy(p, v->buf + v->call_off[leg_index], h->call_len);
        p += h->call_len;
    }

    int rc = -1;
    /* final-offset proof: the preimage walk landed EXACTLY on the length
     * the geometry predicts — a drifted field cannot be hashed silently */
    if ((size_t)(p - pre) == pre_len)
        rc = (qgp_sha3_512(pre, pre_len, out) == 0) ? 0 : -1;

    /* Transaction material hygiene: wipe the temporary preimage. */
    memset(pre, 0, pre_len);
    free(pre);
    return rc;
}

int dna_env_auth_context_commit(const dna_env_view_t *v,
                                const uint8_t chain_id[DNA_ENV_CHAIN_ID_LEN],
                                const uint8_t (*call_commits)[DNA_ENV_HASH_LEN],
                                uint8_t out[DNA_ENV_HASH_LEN]) {
    if (!v || !chain_id || !call_commits || !out) return -1;
    if (!v->buf) return -1;                       /* uninitialised view    */
    if (v->leg_count == 0 || v->leg_count > DNA_ENV_MAX_LEGS) return -1;

    /* STACK: bounded by ENV_AUTHCTX_PRE_MAX = 6107 bytes (_Static_assert
     * above is the justification). auth_data is NOT part of this preimage —
     * see NON-CIRCULARITY in env_wire.h. */
    uint8_t pre[ENV_AUTHCTX_PRE_MAX];
    size_t pre_len = (size_t)ENV_AUTHCTX_PRE_FIXED +
                     (size_t)v->leg_count * (size_t)ENV_AUTHCTX_LEG;

    uint8_t *p = pre;
    memcpy(p, TAG_ENV_CTX, DNA_ENV_TAG_LEN);   p += DNA_ENV_TAG_LEN;
    /* AUTHCTX_BYTES begins here: the wire family marker is a FIELD of the
     * committed string, not just a tag, so a future family cannot collide
     * with this one even under the same context tag. */
    memcpy(p, TAG_ENV_FAMILY, DNA_ENV_WIRE_FAMILY_LEN);
    p += DNA_ENV_WIRE_FAMILY_LEN;
    /* The VIEW's version byte, not the compile-time constant: decode pins
     * it to DNA_ENV_VERSION today, so this is byte-identical now — but a
     * future accepted version must hash as ITSELF, never as 1. */
    *p++ = v->envelope_version;
    memcpy(p, chain_id, DNA_ENV_CHAIN_ID_LEN); p += DNA_ENV_CHAIN_ID_LEN;
    put_be64(v->expiry_height, p);             p += 8;
    put_be64(v->fee_amount, p);                p += 8;
    put_be64(v->res_max_total_units, p);       p += 8;
    put_be16(v->leg_count, p);                 p += 2;

    for (uint16_t i = 0; i < v->leg_count; i++) {
        const dna_env_leg_hdr_t *h = &v->leg[i];
        put_be32(h->domain_id, p);            p += 4;
        put_be32(h->runtime_op, p);           p += 4;
        put_be32(h->ruleset_version, p);      p += 4;
        *p++ = h->access_mode;
        *p++ = h->auth_kind;
        put_be32(h->call_len, p);             p += 4;
        put_be32(h->auth_len, p);             p += 4;
        put_be32(h->res_max_effects, p);      p += 4;
        put_be32(h->res_max_effect_bytes, p); p += 4;
        memcpy(p, call_commits[i], DNA_ENV_HASH_LEN);
        p += DNA_ENV_HASH_LEN;
    }

    /* final-offset proof */
    if ((size_t)(p - pre) != pre_len) return -1;

    return (qgp_sha3_512(pre, pre_len, out) == 0) ? 0 : -1;
}

int dna_env_auth_digest(const uint8_t auth_context_commit[DNA_ENV_HASH_LEN],
                        uint16_t leg_index, uint32_t domain_id,
                        uint32_t runtime_op, uint8_t out[DNA_ENV_HASH_LEN]) {
    if (!auth_context_commit || !out) return -1;
    if (leg_index >= DNA_ENV_MAX_LEGS) return -1;
    if (runtime_op > DNA_ENV_MAX_RUNTIME_OP) return -1;

    /* STACK: fixed 90-byte preimage. */
    uint8_t pre[ENV_AUTH_PRE_LEN];
    uint8_t *p = pre;
    memcpy(p, TAG_ENV_AUTH, DNA_ENV_TAG_LEN);  p += DNA_ENV_TAG_LEN;
    memcpy(p, auth_context_commit, DNA_ENV_HASH_LEN);
    p += DNA_ENV_HASH_LEN;
    put_be16(leg_index, p);                    p += 2;
    put_be32(domain_id, p);                    p += 4;
    put_be32(runtime_op, p);                   p += 4;

    /* final-offset proof */
    if ((size_t)(p - pre) != (size_t)ENV_AUTH_PRE_LEN) return -1;

    return (qgp_sha3_512(pre, (size_t)ENV_AUTH_PRE_LEN, out) == 0) ? 0 : -1;
}

int dna_env_tx_id(const uint8_t auth_context_commit[DNA_ENV_HASH_LEN],
                  const uint8_t *env_bytes, size_t env_len,
                  uint8_t out[DNA_ENV_HASH_LEN]) {
    if (!auth_context_commit || !env_bytes || !out) return -1;
    if (env_len < (size_t)DNA_ENV_FIXED_HEAD) return -1;
    if (env_len > (size_t)DNA_ENV_MAX_TOTAL_LEN) return -1;

    /* HEAP: up to ENV_TXID_PRE_FIXED + DNA_ENV_MAX_TOTAL_LEN = 1,048,660
     * bytes (the capacity-season ceiling; the _Static_assert above pins
     * the number) — tx_wire.c:236-247 pattern. This is the ONE preimage
     * that covers auth_data, and it covers it exactly once. */
    size_t pre_len = (size_t)ENV_TXID_PRE_FIXED + env_len;
    uint8_t *pre = (uint8_t *)malloc(pre_len);
    if (!pre) return -1;

    uint8_t *p = pre;
    memcpy(p, TAG_ENV_TXID, DNA_ENV_TAG_LEN);  p += DNA_ENV_TAG_LEN;
    memcpy(p, auth_context_commit, DNA_ENV_HASH_LEN);
    p += DNA_ENV_HASH_LEN;
    put_be32((uint32_t)env_len, p);            p += 4;
    memcpy(p, env_bytes, env_len);             p += env_len;

    int rc = -1;
    /* final-offset proof */
    if ((size_t)(p - pre) == pre_len)
        rc = (qgp_sha3_512(pre, pre_len, out) == 0) ? 0 : -1;

    /* Transaction material hygiene: wipe the temporary preimage. */
    memset(pre, 0, pre_len);
    free(pre);
    return rc;
}

int dna_env_intent_leg_commit(const dna_env_view_t *v, uint16_t leg_index,
                              const uint8_t call_commit[DNA_ENV_HASH_LEN],
                              uint8_t out[DNA_ENV_HASH_LEN]) {
    /* Fail closed: the output identity is zeroed BEFORE any other check,
     * so no failure path can leave a stale digest usable (season rule:
     * failure zeroes the output identity). */
    if (out) memset(out, 0, DNA_ENV_HASH_LEN);
    if (!v || !call_commit || !out) return -1;
    if (!v->buf) return -1;                       /* uninitialised view    */
    if (v->leg_count == 0 || v->leg_count > DNA_ENV_MAX_LEGS) return -1;
    if (leg_index >= v->leg_count) return -1;

    const dna_env_leg_hdr_t *h = &v->leg[leg_index];

    /* STACK: fixed 102-byte preimage. auth_len is DELIBERATELY absent —
     * it is authorization-witness cardinality, not semantics (the
     * _Static_assert above pins the arithmetic of that exclusion).
     * call_len and the call bytes enter through the nested call_commit. */
    uint8_t pre[ENV_ILEG_PRE_LEN];
    uint8_t *p = pre;
    memcpy(p, TAG_ENV_ILEG, DNA_ENV_TAG_LEN);  p += DNA_ENV_TAG_LEN;
    put_be32(h->domain_id, p);                 p += 4;
    put_be32(h->runtime_op, p);                p += 4;
    put_be32(h->ruleset_version, p);           p += 4;
    *p++ = h->access_mode;
    *p++ = h->auth_kind;
    put_be32(h->res_max_effects, p);           p += 4;
    put_be32(h->res_max_effect_bytes, p);      p += 4;
    memcpy(p, call_commit, DNA_ENV_HASH_LEN);  p += DNA_ENV_HASH_LEN;

    /* final-offset proof */
    if ((size_t)(p - pre) != (size_t)ENV_ILEG_PRE_LEN) return -1;

    if (qgp_sha3_512(pre, (size_t)ENV_ILEG_PRE_LEN, out) != 0) {
        /* a backend fault may have written a partial digest before its
         * own reject — the season rule is "failure zeroes the output
         * identity", so re-zero rather than rely on the caller */
        memset(out, 0, DNA_ENV_HASH_LEN);
        return -1;
    }
    return 0;
}

int dna_env_intent_id(const dna_env_view_t *v,
                      const uint8_t chain_id[DNA_ENV_CHAIN_ID_LEN],
                      const uint8_t (*intent_leg_commits)[DNA_ENV_HASH_LEN],
                      uint8_t out[DNA_ENV_HASH_LEN]) {
    /* Fail closed FIRST (season rule: failure zeroes the output identity). */
    if (out) memset(out, 0, DNA_ENV_HASH_LEN);
    if (!v || !chain_id || !intent_leg_commits || !out) return -1;
    if (!v->buf) return -1;                       /* uninitialised view    */
    if (v->leg_count == 0 || v->leg_count > DNA_ENV_MAX_LEGS) return -1;

    /* STACK: bounded by ENV_INTENT_PRE_MAX = 4187 bytes (_Static_assert
     * above is the justification). The global fields mirror AUTHCTX_BYTES
     * exactly (family marker as a FIELD, the view's version byte, the
     * full contextual chain id) — the per-leg segments are the ONLY
     * difference, and they carry no authorization evidence. */
    uint8_t pre[ENV_INTENT_PRE_MAX];
    size_t pre_len = (size_t)ENV_INTENT_PRE_FIXED +
                     (size_t)v->leg_count * (size_t)DNA_ENV_HASH_LEN;

    uint8_t *p = pre;
    memcpy(p, TAG_ENV_INTENT, DNA_ENV_TAG_LEN); p += DNA_ENV_TAG_LEN;
    memcpy(p, TAG_ENV_FAMILY, DNA_ENV_WIRE_FAMILY_LEN);
    p += DNA_ENV_WIRE_FAMILY_LEN;
    *p++ = v->envelope_version;
    memcpy(p, chain_id, DNA_ENV_CHAIN_ID_LEN);  p += DNA_ENV_CHAIN_ID_LEN;
    put_be64(v->expiry_height, p);              p += 8;
    put_be64(v->fee_amount, p);                 p += 8;
    put_be64(v->res_max_total_units, p);        p += 8;
    put_be16(v->leg_count, p);                  p += 2;

    for (uint16_t i = 0; i < v->leg_count; i++) {
        memcpy(p, intent_leg_commits[i], DNA_ENV_HASH_LEN);
        p += DNA_ENV_HASH_LEN;
    }

    /* final-offset proof */
    if ((size_t)(p - pre) != pre_len) return -1;

    if (qgp_sha3_512(pre, pre_len, out) != 0) {
        memset(out, 0, DNA_ENV_HASH_LEN);   /* same fail-closed rule */
        return -1;
    }
    return 0;
}
