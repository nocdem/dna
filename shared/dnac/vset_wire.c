/**
 * @file shared/dnac/vset_wire.c
 * @brief Ledger V2 Season 3 — validator-set snapshot codec implementation.
 *
 * LIVE (ruleset 1): block apply hashes snapshots (dna_vset_hash) and the
 * snapshot store hashes/decodes them (nodus_witness_vset.c). See
 * vset_wire.h for the tag, the exact wire layout, and the honest label on
 * what decode does and does not check.
 *
 * Ruleset 2 (HF-6 slice 1, design 2026-10-03-hf5-validator-owner-stake
 * §6.5) is INERT: only the `_ex` functions with max_ruleset = 2 reach it;
 * every legacy function keeps its ruleset-1-only behaviour.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "vset_wire.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* Tag is EXACTLY 16 bytes, zero-padded ASCII — same discipline as
 * ledger_roots_v2.c. */
static const uint8_t TAG_VSET[DNA_VSET_TAG_LEN] = "NDS.VSET.v1\0\0\0\0";

/** "NDS.VSET.v2" (11 chars) + 5 zero bytes — design §6.5; collision scan
 *  for the string recorded in design §6 (0 hits, 2026-10-08). */
static const uint8_t TAG_VSET_V2[DNA_VSET_TAG_LEN] = {
    'N','D','S','.','V','S','E','T','.','v','2', 0, 0, 0, 0, 0
};

/* Layout arithmetic is pinned, not assumed. */
_Static_assert(DNA_VSET_HDR_LEN == 8 + 2 + 4 + DNA_VSET_SEED_LEN,
               "vset header layout drifted");
_Static_assert(DNA_VSET_ENTRY_LEN ==
                   DNA_VSET_VOTER_ID_LEN + DNA_VSET_PUBKEY_LEN + 8 + 8 + 2,
               "vset entry layout drifted");
_Static_assert(DNA_VSET_MAX_ENC_LEN == 338254,
               "vset max encoding drifted (78 + 128*2642)");
_Static_assert(DNA_VSET_ENTRY_LEN_V2 ==
                   DNA_VSET_VOTER_ID_LEN + DNA_VSET_VALIDATOR_ID_LEN +
                   DNA_VSET_OWNER_FP_LEN + DNA_VSET_PUBKEY_LEN + 8 + 8 + 2,
               "vset v2 entry layout drifted");
_Static_assert(DNA_VSET_ENTRY_LEN_V2 == 2770,
               "vset v2 entry length drifted (design §6.5)");
_Static_assert(DNA_VSET_MAX_ENC_LEN_V2 == 354638,
               "vset v2 max encoding drifted (78 + 128*2770)");
_Static_assert(DNA_VSET_VOTER_ID_LEN <= DNA_VSET_HASH_LEN,
               "voter_id must be a prefix of a SHA3-512 digest");
/* Counts are u16 on the wire; the ceiling must fit that width. */
_Static_assert(DNA_MAX_ACTIVE_VALIDATORS > 0 &&
                   DNA_MAX_ACTIVE_VALIDATORS <= 0xFFFF,
               "active-validator ceiling does not fit the u16 count");

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

/* ── Ruleset dispatch ───────────────────────────────────────────────── */

/** max_ruleset is a caller argument: only 1 and 2 exist. */
static int max_ruleset_ok(uint32_t max_ruleset) {
    return max_ruleset == DNA_VSET_RULESET_TOPN_V1 ||
           max_ruleset == DNA_VSET_RULESET_TOPN_V2;
}

/** A ruleset value is accepted iff 1 <= ruleset <= max_ruleset. */
static int ruleset_ok(uint32_t ruleset, uint32_t max_ruleset) {
    if (!max_ruleset_ok(max_ruleset)) return 0;
    return ruleset != DNA_VSET_RULESET_INVALID && ruleset <= max_ruleset;
}

/** Entry length for an ACCEPTED ruleset (callers check ruleset_ok first). */
static size_t entry_len_for(uint32_t ruleset) {
    return ruleset == DNA_VSET_RULESET_TOPN_V2 ? (size_t)DNA_VSET_ENTRY_LEN_V2
                                               : (size_t)DNA_VSET_ENTRY_LEN;
}

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0) return 0;
    return 1;
}

/* ── Structural validation (shared by encode and decode) ────────────── */

/**
 * Every rule a snapshot must satisfy in BOTH directions. Duplicate
 * detection is O(n²) memcmp: n <= 128 so the worst case is 8128 pairs,
 * and the alternative (sorting a copy) would need another ~355 KB of heap
 * for no measurable gain.
 *
 * Ruleset 1: exactly the pre-HF-6 rules, plus validator_id / owner_fp
 * must be all-zero (v1 has no wire slot for them; a nonzero value would
 * be dropped silently — reject instead). voter_id is NOT recomputed.
 * Ruleset 2: additionally rejects a duplicated validator_id, an all-zero
 * validator_id or owner_fp, and any voter_id that is not
 * SHA3-512(pubkey)[0..31].
 *
 * @return 0 if valid, -1 otherwise.
 */
static int vset_check(const dna_vset_snapshot_t *s, uint32_t max_ruleset) {
    if (!s || !s->entries) return -1;
    if (s->active_count == 0 ||
        s->active_count > DNA_MAX_ACTIVE_VALIDATORS) return -1;

    /* Ruleset 0 is INVALID by design; nothing above max_ruleset passes. */
    if (!ruleset_ok(s->selection_ruleset, max_ruleset)) return -1;

    /* The seed slot is committed-but-reserved under TOPN_V1 and TOPN_V2
     * (Kurultay #14 K6): a nonzero byte would be an unconsumed input
     * silently entering the hash. */
    if (!all_zero(s->sortition_seed, DNA_VSET_SEED_LEN)) return -1;

    const int v2 = (s->selection_ruleset == DNA_VSET_RULESET_TOPN_V2);
    const size_t n = (size_t)s->active_count;

    for (size_t i = 0; i < n; i++) {
        const dna_vset_entry_t *e = &s->entries[i];
        if (!v2) {
            if (!all_zero(e->validator_id, DNA_VSET_VALIDATOR_ID_LEN) ||
                !all_zero(e->owner_fp, DNA_VSET_OWNER_FP_LEN))
                return -1;          /* v1 cannot carry them — fail closed */
        } else {
            /* Both are SHA3-512 outputs in every legal state (validator_id
             * §6.2, owner_fp a fingerprint): all-zero means "unset" —
             * fail closed. */
            if (all_zero(e->validator_id, DNA_VSET_VALIDATOR_ID_LEN) ||
                all_zero(e->owner_fp, DNA_VSET_OWNER_FP_LEN))
                return -1;
            uint8_t d[DNA_VSET_HASH_LEN];
            if (qgp_sha3_512(e->pubkey, DNA_VSET_PUBKEY_LEN, d) != 0)
                return -1;
            if (memcmp(d, e->voter_id, DNA_VSET_VOTER_ID_LEN) != 0)
                return -1;          /* voter_id not bound to consensus_pk */
        }
    }

    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (memcmp(s->entries[i].voter_id, s->entries[j].voter_id,
                       DNA_VSET_VOTER_ID_LEN) == 0)
                return -1;                      /* duplicate voter_id */
            if (memcmp(s->entries[i].pubkey, s->entries[j].pubkey,
                       DNA_VSET_PUBKEY_LEN) == 0)
                return -1;                      /* duplicate pubkey   */
            if (v2 && memcmp(s->entries[i].validator_id,
                             s->entries[j].validator_id,
                             DNA_VSET_VALIDATOR_ID_LEN) == 0)
                return -1;                      /* duplicate validator_id */
        }
    }
    return 0;
}

/* ── Lifecycle ──────────────────────────────────────────────────────── */

dna_vset_snapshot_t *dna_vset_alloc(uint16_t active_count) {
    if (active_count == 0 || active_count > DNA_MAX_ACTIVE_VALIDATORS)
        return NULL;
    dna_vset_snapshot_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->entries = calloc((size_t)active_count, sizeof(*s->entries));
    if (!s->entries) { free(s); return NULL; }
    s->active_count      = active_count;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    return s;
}

void dna_vset_free(dna_vset_snapshot_t **snap) {
    if (!snap || !*snap) return;
    free((*snap)->entries);
    free(*snap);
    *snap = NULL;
}

/* ── Codec ──────────────────────────────────────────────────────────── */

size_t dna_vset_encoded_len_ex(const dna_vset_snapshot_t *snap,
                               uint32_t max_ruleset) {
    if (vset_check(snap, max_ruleset) != 0) return 0;
    /* active_count <= 128 and the product is compile-time bounded by
     * DNA_VSET_MAX_ENC_LEN_V2, so this cannot overflow size_t. */
    return (size_t)DNA_VSET_HDR_LEN +
           (size_t)snap->active_count * entry_len_for(snap->selection_ruleset);
}

size_t dna_vset_encoded_len(const dna_vset_snapshot_t *snap) {
    return dna_vset_encoded_len_ex(snap, DNA_VSET_RULESET_TOPN_V1);
}

int dna_vset_encode_ex(const dna_vset_snapshot_t *snap, uint32_t max_ruleset,
                       uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    /* 0 == structurally bad (incl. a bad max_ruleset) */
    size_t need = dna_vset_encoded_len_ex(snap, max_ruleset);
    if (need == 0 || cap < need) return -1;

    const int v2 = (snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V2);

    uint8_t *p = dst;
    put_be64(snap->epoch, p);                       p += 8;
    put_be16(snap->active_count, p);                p += 2;
    put_be32(snap->selection_ruleset, p);           p += 4;
    memcpy(p, snap->sortition_seed, DNA_VSET_SEED_LEN);
    p += DNA_VSET_SEED_LEN;

    for (size_t i = 0; i < (size_t)snap->active_count; i++) {
        const dna_vset_entry_t *e = &snap->entries[i];
        memcpy(p, e->voter_id, DNA_VSET_VOTER_ID_LEN);
        p += DNA_VSET_VOTER_ID_LEN;
        if (v2) {
            memcpy(p, e->validator_id, DNA_VSET_VALIDATOR_ID_LEN);
            p += DNA_VSET_VALIDATOR_ID_LEN;
            memcpy(p, e->owner_fp, DNA_VSET_OWNER_FP_LEN);
            p += DNA_VSET_OWNER_FP_LEN;
        }
        memcpy(p, e->pubkey, DNA_VSET_PUBKEY_LEN);
        p += DNA_VSET_PUBKEY_LEN;
        put_be64(e->total_stake, p);    p += 8;
        put_be64(e->self_bond, p);      p += 8;
        put_be16(e->commission_bps, p); p += 2;
    }

    if ((size_t)(p - dst) != need) return -1;   /* layout drift guard */
    if (written) *written = need;
    return 0;
}

int dna_vset_encode(const dna_vset_snapshot_t *snap,
                    uint8_t *dst, size_t cap, size_t *written) {
    return dna_vset_encode_ex(snap, DNA_VSET_RULESET_TOPN_V1,
                              dst, cap, written);
}

int dna_vset_decode_ex(const uint8_t *src, size_t len, uint32_t max_ruleset,
                       dna_vset_snapshot_t **out) {
    if (!src || !out) return -1;
    if (!max_ruleset_ok(max_ruleset)) return -1;

    /* ── Everything checkable from the header runs BEFORE any allocation:
     * a malformed or oversized claim must never reach calloc. ── */
    if (len < (size_t)DNA_VSET_HDR_LEN) return -1;

    uint16_t count   = get_be16(src + 8);
    uint32_t ruleset = get_be32(src + 10);
    if (count == 0 || count > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (!ruleset_ok(ruleset, max_ruleset)) return -1;

    const int    v2   = (ruleset == DNA_VSET_RULESET_TOPN_V2);
    const size_t elen = entry_len_for(ruleset);

    /* count <= 128 ⇒ the product is bounded by DNA_VSET_MAX_ENC_LEN_V2. */
    size_t need = (size_t)DNA_VSET_HDR_LEN + (size_t)count * elen;
    if (len != need) return -1;   /* truncation AND trailing bytes reject */

    dna_vset_snapshot_t *s = dna_vset_alloc(count);
    if (!s) return -1;

    s->epoch             = get_be64(src);
    s->active_count      = count;
    s->selection_ruleset = ruleset;
    memcpy(s->sortition_seed, src + 14, DNA_VSET_SEED_LEN);

    const uint8_t *p = src + DNA_VSET_HDR_LEN;
    for (size_t i = 0; i < (size_t)count; i++) {
        dna_vset_entry_t *e = &s->entries[i];
        memcpy(e->voter_id, p, DNA_VSET_VOTER_ID_LEN);
        p += DNA_VSET_VOTER_ID_LEN;
        if (v2) {
            memcpy(e->validator_id, p, DNA_VSET_VALIDATOR_ID_LEN);
            p += DNA_VSET_VALIDATOR_ID_LEN;
            memcpy(e->owner_fp, p, DNA_VSET_OWNER_FP_LEN);
            p += DNA_VSET_OWNER_FP_LEN;
        }
        /* v1: validator_id / owner_fp stay zero (dna_vset_alloc callocs). */
        memcpy(e->pubkey, p, DNA_VSET_PUBKEY_LEN);
        p += DNA_VSET_PUBKEY_LEN;
        e->total_stake    = get_be64(p); p += 8;
        e->self_bond      = get_be64(p); p += 8;
        e->commission_bps = get_be16(p); p += 2;
    }

    /* Same structural rules as encode — a decoded snapshot that could not
     * have been encoded is rejected, never returned partially. */
    if (vset_check(s, max_ruleset) != 0) {
        dna_vset_free(&s);
        return -1;
    }
    *out = s;
    return 0;
}

int dna_vset_decode(const uint8_t *src, size_t len,
                    dna_vset_snapshot_t **out) {
    return dna_vset_decode_ex(src, len, DNA_VSET_RULESET_TOPN_V1, out);
}

/* ── Hashing ────────────────────────────────────────────────────────── */

/** SHA3-512(tag ‖ buf[0..len)); len already bounded by the caller. */
static int vset_hash_tagged(const uint8_t tag[DNA_VSET_TAG_LEN],
                            const uint8_t *buf, size_t len,
                            uint8_t out[DNA_VSET_HASH_LEN]) {
    /* qgp_sha3_512 is one-shot, so tag ‖ buf must be contiguous. The max
     * is ~355 KB — heap, never the stack. */
    uint8_t *pre = malloc((size_t)DNA_VSET_TAG_LEN + len);
    if (!pre) return -1;
    memcpy(pre, tag, DNA_VSET_TAG_LEN);
    memcpy(pre + DNA_VSET_TAG_LEN, buf, len);
    int rc = qgp_sha3_512(pre, (size_t)DNA_VSET_TAG_LEN + len, out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

/* Pre-HF-6 body, kept as is: any 1..DNA_VSET_MAX_ENC_LEN bytes, v1 tag,
 * header not read. Not a dna_vset_hash_bytes_ex wrapper — the strict
 * variant rejects inputs (short / non-v1 header) this one accepts. */
int dna_vset_hash_bytes(const uint8_t *buf, size_t len,
                        uint8_t out[DNA_VSET_HASH_LEN]) {
    if (!buf || !out) return -1;
    if (len == 0 || len > DNA_VSET_MAX_ENC_LEN) return -1;
    return vset_hash_tagged(TAG_VSET, buf, len, out);
}

int dna_vset_hash_bytes_ex(const uint8_t *buf, size_t len,
                           uint32_t max_ruleset,
                           uint8_t out[DNA_VSET_HASH_LEN]) {
    if (!buf || !out) return -1;
    if (!max_ruleset_ok(max_ruleset)) return -1;
    if (len < (size_t)DNA_VSET_HDR_LEN) return -1;   /* ruleset unreadable */

    uint32_t ruleset = get_be32(buf + 10);
    if (!ruleset_ok(ruleset, max_ruleset)) return -1;

    if (ruleset == DNA_VSET_RULESET_TOPN_V2) {
        if (len > DNA_VSET_MAX_ENC_LEN_V2) return -1;
        return vset_hash_tagged(TAG_VSET_V2, buf, len, out);
    }
    if (len > DNA_VSET_MAX_ENC_LEN) return -1;
    return vset_hash_tagged(TAG_VSET, buf, len, out);
}

int dna_vset_hash_ex(const dna_vset_snapshot_t *snap, uint32_t max_ruleset,
                     uint8_t out[DNA_VSET_HASH_LEN]) {
    if (!out) return -1;
    size_t need = dna_vset_encoded_len_ex(snap, max_ruleset);
    if (need == 0) return -1;

    uint8_t *buf = malloc(need);
    if (!buf) return -1;
    size_t written = 0;
    if (dna_vset_encode_ex(snap, max_ruleset, buf, need, &written) != 0 ||
        written != need) {
        free(buf);
        return -1;
    }
    int rc = dna_vset_hash_bytes_ex(buf, written, max_ruleset, out);
    free(buf);
    return rc;
}

int dna_vset_hash(const dna_vset_snapshot_t *snap,
                  uint8_t out[DNA_VSET_HASH_LEN]) {
    return dna_vset_hash_ex(snap, DNA_VSET_RULESET_TOPN_V1, out);
}
