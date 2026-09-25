/**
 * @file shared/dnac/vset_wire.c
 * @brief Ledger V2 Season 3 — validator-set snapshot codec implementation.
 *
 * INACTIVE: no live consensus path calls anything here (S3 charter). See
 * vset_wire.h for the tag, the exact wire layout, and the honest label on
 * what decode does and does not check.
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
static const uint8_t TAG_VSET[DNA_VSET_TAG_LEN] = "DNA.VSET.v1\0\0\0\0";

/* Layout arithmetic is pinned, not assumed. */
_Static_assert(DNA_VSET_HDR_LEN == 8 + 2 + 4 + DNA_VSET_SEED_LEN,
               "vset header layout drifted");
_Static_assert(DNA_VSET_ENTRY_LEN ==
                   DNA_VSET_VOTER_ID_LEN + DNA_VSET_PUBKEY_LEN + 8 + 8 + 2,
               "vset entry layout drifted");
_Static_assert(DNA_VSET_MAX_ENC_LEN == 338254,
               "vset max encoding drifted (78 + 128*2642)");
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

/* ── Structural validation (shared by encode and decode) ────────────── */

/**
 * Every rule a snapshot must satisfy in BOTH directions. Duplicate
 * detection is O(n²) memcmp: n <= 128 so the worst case is 8128 pairs,
 * and the alternative (sorting a copy) would need another 339 KB of heap
 * for no measurable gain.
 *
 * @return 0 if valid, -1 otherwise.
 */
static int vset_check(const dna_vset_snapshot_t *s) {
    if (!s || !s->entries) return -1;
    if (s->active_count == 0 ||
        s->active_count > DNA_MAX_ACTIVE_VALIDATORS) return -1;

    /* Ruleset 0 is INVALID by design; only TOPN_V1 is accepted today. */
    if (s->selection_ruleset != DNA_VSET_RULESET_TOPN_V1) return -1;

    /* The seed slot is committed-but-reserved under TOPN_V1: a nonzero
     * byte would be an unconsumed input silently entering the hash. */
    if (s->selection_ruleset == DNA_VSET_RULESET_TOPN_V1) {
        for (size_t i = 0; i < DNA_VSET_SEED_LEN; i++)
            if (s->sortition_seed[i] != 0) return -1;
    }

    const size_t n = (size_t)s->active_count;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (memcmp(s->entries[i].voter_id, s->entries[j].voter_id,
                       DNA_VSET_VOTER_ID_LEN) == 0)
                return -1;                      /* duplicate voter_id */
            if (memcmp(s->entries[i].pubkey, s->entries[j].pubkey,
                       DNA_VSET_PUBKEY_LEN) == 0)
                return -1;                      /* duplicate pubkey   */
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

size_t dna_vset_encoded_len(const dna_vset_snapshot_t *snap) {
    if (vset_check(snap) != 0) return 0;
    /* active_count <= 128 and the product is compile-time bounded by
     * DNA_VSET_MAX_ENC_LEN, so this cannot overflow size_t. */
    return (size_t)DNA_VSET_HDR_LEN +
           (size_t)snap->active_count * (size_t)DNA_VSET_ENTRY_LEN;
}

int dna_vset_encode(const dna_vset_snapshot_t *snap,
                    uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    size_t need = dna_vset_encoded_len(snap);   /* 0 == structurally bad */
    if (need == 0 || cap < need) return -1;

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

int dna_vset_decode(const uint8_t *src, size_t len,
                    dna_vset_snapshot_t **out) {
    if (!src || !out) return -1;

    /* ── Everything checkable from the header runs BEFORE any allocation:
     * a malformed or oversized claim must never reach calloc. ── */
    if (len < (size_t)DNA_VSET_HDR_LEN) return -1;

    uint16_t count   = get_be16(src + 8);
    uint32_t ruleset = get_be32(src + 10);
    if (count == 0 || count > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (ruleset != DNA_VSET_RULESET_TOPN_V1) return -1;

    /* count <= 128 ⇒ the product is bounded by DNA_VSET_MAX_ENC_LEN. */
    size_t need = (size_t)DNA_VSET_HDR_LEN +
                  (size_t)count * (size_t)DNA_VSET_ENTRY_LEN;
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
        memcpy(e->pubkey, p, DNA_VSET_PUBKEY_LEN);
        p += DNA_VSET_PUBKEY_LEN;
        e->total_stake    = get_be64(p); p += 8;
        e->self_bond      = get_be64(p); p += 8;
        e->commission_bps = get_be16(p); p += 2;
    }

    /* Same structural rules as encode — a decoded snapshot that could not
     * have been encoded is rejected, never returned partially. */
    if (vset_check(s) != 0) {
        dna_vset_free(&s);
        return -1;
    }
    *out = s;
    return 0;
}

/* ── Policy ─────────────────────────────────────────────────────────── */

int dna_vset_validate_bonds(const dna_vset_snapshot_t *snap,
                            uint64_t min_self_bond_raw) {
    if (vset_check(snap) != 0) return -1;
    for (size_t i = 0; i < (size_t)snap->active_count; i++) {
        if (snap->entries[i].self_bond < min_self_bond_raw) return -1;
    }
    return 0;
}

/* ── Hashing ────────────────────────────────────────────────────────── */

int dna_vset_hash_bytes(const uint8_t *buf, size_t len,
                        uint8_t out[DNA_VSET_HASH_LEN]) {
    if (!buf || !out) return -1;
    if (len == 0 || len > DNA_VSET_MAX_ENC_LEN) return -1;

    /* qgp_sha3_512 is one-shot, so tag ‖ buf must be contiguous. The max
     * is ~339 KB — heap, never the stack. */
    uint8_t *pre = malloc((size_t)DNA_VSET_TAG_LEN + len);
    if (!pre) return -1;
    memcpy(pre, TAG_VSET, DNA_VSET_TAG_LEN);
    memcpy(pre + DNA_VSET_TAG_LEN, buf, len);
    int rc = qgp_sha3_512(pre, (size_t)DNA_VSET_TAG_LEN + len, out);
    free(pre);
    return rc == 0 ? 0 : -1;
}

int dna_vset_hash(const dna_vset_snapshot_t *snap,
                  uint8_t out[DNA_VSET_HASH_LEN]) {
    if (!out) return -1;
    size_t need = dna_vset_encoded_len(snap);
    if (need == 0) return -1;

    uint8_t *buf = malloc(need);
    if (!buf) return -1;
    size_t written = 0;
    if (dna_vset_encode(snap, buf, need, &written) != 0 || written != need) {
        free(buf);
        return -1;
    }
    int rc = dna_vset_hash_bytes(buf, written, out);
    free(buf);
    return rc;
}
