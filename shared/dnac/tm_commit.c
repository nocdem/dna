/**
 * @file shared/dnac/tm_commit.c
 * @brief Tendermint T3 — `nodus.commit.v1` codec, BFT-time median, verify.
 *
 * INACTIVE: no consensus path calls anything here (wave 1 is additive).
 * See tm_commit.h for the tag, the wire layout and the reference pins.
 *
 * This file computes NO consensus value: no clock, no randomness, and no
 * ordering decision. Entries are emitted in the order the caller holds them
 * (set order) and never re-sorted; the median's ascending copy of the
 * timestamps is private to that one function and yields a value, not an
 * order.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "tm_commit.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

/* Tag is EXACTLY 16 bytes, zero-padded ASCII. */
static const uint8_t TAG_TM_COMMIT[DNA_TM_COMMIT_TAG_LEN] = "nodus.commit.v1";

/* ── Header field offsets (T2 §4.3) ─────────────────────────────────────
 * PRIVATE on purpose: the public surface is the one tm_commit.h declares,
 * and the tests hand-build their byte arrays from the layout itself so an
 * offset bug cannot hide behind a constant shared with the encoder. */
#define CM_OFF_TAG        0u
#define CM_OFF_HEIGHT     16u
#define CM_OFF_ROUND      24u
#define CM_OFF_BLOCK_ID   28u
#define CM_OFF_N          92u

/* Layout arithmetic is pinned, not assumed. */
_Static_assert(CM_OFF_HEIGHT   == CM_OFF_TAG + DNA_TM_COMMIT_TAG_LEN,
               "commit header: height offset drifted from T2 §4.3");
_Static_assert(CM_OFF_ROUND    == CM_OFF_HEIGHT + 8u,
               "commit header: round offset drifted from T2 §4.3");
_Static_assert(CM_OFF_BLOCK_ID == CM_OFF_ROUND + 4u,
               "commit header: block_id offset drifted from T2 §4.3");
_Static_assert(CM_OFF_N        == CM_OFF_BLOCK_ID + DNA_TM_BLOCK_ID_LEN,
               "commit header: n offset drifted from T2 §4.3");
_Static_assert(DNA_TM_COMMIT_HDR_LEN == CM_OFF_N + 2u,
               "commit header length drifted from 94 bytes");
_Static_assert(DNA_TM_COMMIT_ENTRY_ABSENT_LEN == 1u + 8u,
               "ABSENT entry drifted from flag + timestamp");
/* The signature width must match the primitive we verify with. */
_Static_assert(DNA_TM_COMMIT_ENTRY_SIGNED_LEN ==
                   DNA_TM_COMMIT_ENTRY_ABSENT_LEN + QGP_DSA87_SIGNATURE_BYTES,
               "signed entry != ABSENT entry + Dilithium5 signature");
_Static_assert(DNA_VSET_PUBKEY_LEN == QGP_DSA87_PUBLICKEYBYTES,
               "snapshot pubkey width != Dilithium5 public key width");
/* The empty certificate is the header and nothing else. */
_Static_assert(DNA_TM_COMMIT_EMPTY_LEN == DNA_TM_COMMIT_HDR_LEN,
               "empty certificate drifted from the bare header");

/* ── Fixed-width big-endian helpers ─────────────────────────────────── */

static void put_be16(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}
static void put_be32(uint32_t v, uint8_t out[4]) {
    for (int i = 3; i >= 0; i--) { out[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}
static uint16_t get_be16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}
static uint32_t get_be32(const uint8_t in[4]) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v = (v << 8) | (uint32_t)in[i];
    return v;
}
static uint64_t get_be64(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)in[i];
    return v;
}

/* ── Structural validation (shared by encode, decode and verify) ────── */

/**
 * On-wire length of one entry, or 0 for an unknown flag.
 * ABSENT carries no signature; COMMIT and NIL carry one.
 */
static size_t entry_len(uint8_t flag) {
    switch (flag) {
        case DNA_TM_COMMIT_FLAG_ABSENT:
            return DNA_TM_COMMIT_ENTRY_ABSENT_LEN;
        /* COMMIT and NIL share one wire size: both carry a signature, and
         * they differ only in WHICH block_id that signature covers. */
        case DNA_TM_COMMIT_FLAG_COMMIT:
        case DNA_TM_COMMIT_FLAG_NIL:
            return DNA_TM_COMMIT_ENTRY_SIGNED_LEN;
        default:
            return 0;
    }
}

/**
 * Everything encode, decode and verify all require of the object itself:
 * a bounded count, an entry array exactly when there are entries, a known
 * flag on every entry, and timestamp 0 on every ABSENT entry.
 *
 * The ABSENT rule is enforced HERE, so it holds on the encode side too —
 * an ABSENT entry that carried a time would otherwise be a second, silent
 * channel for a byte the reference does not have (block.go:616-620).
 *
 * @return 0 if valid, -1 otherwise.
 */
static int cert_check(const dna_tm_commit_t *c) {
    if (!c) return -1;
    if (c->n > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (c->n == 0) return 0;            /* the empty shape: entries unused */
    if (!c->entries) return -1;

    for (size_t i = 0; i < (size_t)c->n; i++) {
        const dna_tm_commit_entry_t *e = &c->entries[i];
        if (entry_len(e->flag) == 0) return -1;      /* unknown flag */
        if (e->flag == DNA_TM_COMMIT_FLAG_ABSENT && e->timestamp_ms != 0)
            return -1;
    }
    return 0;
}

/* ── Lifecycle ──────────────────────────────────────────────────────── */

dna_tm_commit_t *dna_tm_commit_alloc(uint16_t n) {
    if (n > DNA_MAX_ACTIVE_VALIDATORS) return NULL;
    dna_tm_commit_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    if (n > 0) {
        /* calloc(0, ...) may or may not return NULL, so the empty case
         * never reaches it: entries stays NULL and n stays 0. */
        c->entries = calloc((size_t)n, sizeof(*c->entries));
        if (!c->entries) { free(c); return NULL; }
        c->n = n;
    }
    return c;
}

void dna_tm_commit_free(dna_tm_commit_t **c) {
    if (!c || !*c) return;
    free((*c)->entries);
    free(*c);
    *c = NULL;
}

int dna_tm_commit_set_empty(dna_tm_commit_t *c) {
    if (!c) return -1;
    free(c->entries);
    c->entries = NULL;
    c->n = 0;
    c->height = 0;
    c->round = 0;
    memset(c->block_id, 0, DNA_TM_BLOCK_ID_LEN);
    return 0;
}

int dna_tm_commit_is_empty(const dna_tm_commit_t *c) {
    if (!c) return 0;
    if (c->n != 0 || c->height != 0 || c->round != 0) return 0;
    for (size_t i = 0; i < (size_t)DNA_TM_BLOCK_ID_LEN; i++) {
        if (c->block_id[i] != 0) return 0;
    }
    return 1;
}

/* ── Codec ──────────────────────────────────────────────────────────── */

size_t dna_tm_commit_encoded_len(const dna_tm_commit_t *c) {
    if (cert_check(c) != 0) return 0;

    /* n <= 128 and every entry is <= 4636 bytes, so the sum is bounded by
     * DNA_TM_COMMIT_MAX_LEN and cannot overflow. */
    size_t need = (size_t)DNA_TM_COMMIT_HDR_LEN;
    for (size_t i = 0; i < (size_t)c->n; i++) {
        need += entry_len(c->entries[i].flag);
    }
    return need;
}

int dna_tm_commit_encode(const dna_tm_commit_t *c,
                         uint8_t *dst, size_t cap, size_t *written) {
    if (!dst) return -1;
    size_t need = dna_tm_commit_encoded_len(c);   /* 0 == structurally bad */
    if (need == 0 || cap < need) return -1;

    uint8_t *p = dst;
    memcpy(p, TAG_TM_COMMIT, DNA_TM_COMMIT_TAG_LEN); p += DNA_TM_COMMIT_TAG_LEN;
    put_be64(c->height, p); p += 8;
    put_be32(c->round, p);  p += 4;
    memcpy(p, c->block_id, DNA_TM_BLOCK_ID_LEN); p += DNA_TM_BLOCK_ID_LEN;
    put_be16(c->n, p);      p += 2;

    for (size_t i = 0; i < (size_t)c->n; i++) {
        const dna_tm_commit_entry_t *e = &c->entries[i];
        *p++ = e->flag;
        put_be64(e->timestamp_ms, p); p += 8;      /* 0 for ABSENT (cert_check) */
        if (e->flag != DNA_TM_COMMIT_FLAG_ABSENT) {
            memcpy(p, e->sig, QGP_DSA87_SIGNATURE_BYTES);
            p += QGP_DSA87_SIGNATURE_BYTES;
        }
    }

    if ((size_t)(p - dst) != need) return -1;      /* layout drift guard */
    if (written) *written = need;
    return 0;
}

int dna_tm_commit_decode(const uint8_t *src, size_t len, dna_tm_commit_t **out) {
    /* A NULL argument is a caller bug — there is no certificate here to
     * judge, so it cannot be a reject (qc_v2.c:143-147, O15A). */
    if (!src || !out) return -2;

    if (len < (size_t)DNA_TM_COMMIT_HDR_LEN) return -1;
    if (memcmp(src + CM_OFF_TAG, TAG_TM_COMMIT, DNA_TM_COMMIT_TAG_LEN) != 0)
        return -1;

    uint16_t n = get_be16(src + CM_OFF_N);
    if (n > DNA_MAX_ACTIVE_VALIDATORS) return -1;   /* BEFORE any allocation */

    /* ── Pre-pass: walk the entries WITHOUT allocating. The entry sizes
     *    depend on the flags, so this walk is the only way to know the
     *    exact length; it enforces every flag and ABSENT-timestamp rule on
     *    the way, and the total afterwards. `off <= len` is an invariant:
     *    it starts at 94 <= len and only advances by a length that was
     *    just checked to fit. ── */
    size_t off = (size_t)DNA_TM_COMMIT_HDR_LEN;
    for (size_t i = 0; i < (size_t)n; i++) {
        if (len - off < (size_t)DNA_TM_COMMIT_ENTRY_ABSENT_LEN) return -1;
        size_t elen = entry_len(src[off]);
        if (elen == 0) return -1;                   /* unknown flag */
        if (len - off < elen) return -1;            /* truncated entry */
        if (src[off] == DNA_TM_COMMIT_FLAG_ABSENT &&
            get_be64(src + off + 1) != 0)
            return -1;                              /* ABSENT must carry 0 */
        off += elen;
    }
    if (off != len) return -1;   /* truncation AND trailing bytes reject */

    /* `n` was bounds-checked above, so the only remaining failure mode is
     * an allocation failure — a node-local fault, never a statement about
     * these bytes. */
    dna_tm_commit_t *c = dna_tm_commit_alloc(n);
    if (!c) return -2;

    c->height = get_be64(src + CM_OFF_HEIGHT);
    c->round  = get_be32(src + CM_OFF_ROUND);
    memcpy(c->block_id, src + CM_OFF_BLOCK_ID, DNA_TM_BLOCK_ID_LEN);

    const uint8_t *p = src + DNA_TM_COMMIT_HDR_LEN;
    for (size_t i = 0; i < (size_t)n; i++) {
        dna_tm_commit_entry_t *e = &c->entries[i];
        e->flag = *p++;
        e->timestamp_ms = get_be64(p); p += 8;
        if (e->flag != DNA_TM_COMMIT_FLAG_ABSENT) {
            memcpy(e->sig, p, QGP_DSA87_SIGNATURE_BYTES);
            p += QGP_DSA87_SIGNATURE_BYTES;
        }
    }

    /* The pre-pass already proved this holds; re-checking costs nothing and
     * keeps the decoded object's guarantee independent of that walk. */
    if (cert_check(c) != 0) {
        dna_tm_commit_free(&c);
        return -1;
    }
    *out = c;
    return 0;
}

/* ── BFT-time median ────────────────────────────────────────────────── */

int dna_tm_commit_median_time(const dna_tm_commit_t *c, uint64_t *out_ms) {
    if (!c || !out_ms) return -1;
    /* A hand-built certificate could name more entries than the release
     * ceiling; the buffer below is sized to that ceiling, so the bound is
     * checked before anything is copied into it. */
    if (cert_check(c) != 0) return -1;

    /* 128 × 8 bytes on the stack — no allocation, so no OOM path exists in
     * this implementation and -2 is unreachable here. The contract keeps
     * it for callers that must handle every class uniformly. */
    uint64_t times[DNA_MAX_ACTIVE_VALIDATORS];
    size_t total = 0;
    for (size_t i = 0; i < (size_t)c->n; i++) {
        /* The reference skips exactly BlockIDFlagAbsent; NIL entries count
         * (state/state.go:270-276). */
        if (c->entries[i].flag == DNA_TM_COMMIT_FLAG_ABSENT) continue;
        times[total++] = c->entries[i].timestamp_ms;
    }
    if (total == 0) return -1;   /* nothing to take a median of */

    /* Insertion sort, ascending. Values are plain u64, so "stable" has no
     * observable meaning here: equal timestamps are indistinguishable and
     * any correct sort yields the same array. O(n²) at n <= 128 is ~16 k
     * comparisons worst case. */
    for (size_t i = 1; i < total; i++) {
        uint64_t v = times[i];
        size_t j = i;
        while (j > 0 && times[j - 1] > v) { times[j] = times[j - 1]; j--; }
        times[j] = v;
    }

    /* The reference's WeightedMedian walk with every weight 1
     * (types/time/time.go; state/state.go:264-289): median = total/2, then
     * pick the first element at which median <= 1. Written as the walk, not
     * as its closed form, so it stays comparable to the reference line by
     * line; the tests pin the closed form sorted[max(0, total/2 - 1)]
     * against it. */
    size_t median = total / 2u;
    size_t pick = total;                    /* sentinel: nothing picked */
    for (size_t i = 0; i < total; i++) {
        if (median <= 1) { pick = i; break; }
        median -= 1;
    }
    if (pick >= total) return -1;   /* unreachable: median <= total/2 <= total */

    *out_ms = times[pick];
    return 0;
}

/* ── Verification ───────────────────────────────────────────────────── */

int dna_tm_commit_verify(const dna_tm_commit_t *c,
                         int expect_empty,
                         uint64_t expect_height,
                         const uint8_t expect_block_id[DNA_TM_BLOCK_ID_LEN],
                         const dna_vset_snapshot_t *snap,
                         const uint8_t header_vset_hash[DNA_VSET_HASH_LEN],
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN]) {
    /* A NULL certificate is a caller bug, not a bad certificate. */
    if (!c) return -2;

    /* ── 1. Height 1: the certificate must be EXACTLY the empty shape, and
     *      no snapshot is consulted (consensus/state.go:1287-1291). This
     *      returns before any other argument is read, which is why they
     *      may be NULL in this case. ── */
    if (expect_empty) return dna_tm_commit_is_empty(c) ? 0 : -1;

    if (!expect_block_id || !snap || !header_vset_hash || !chain_id)
        return -2;

    /* Structure first: bounded n, entries present, known flags, ABSENT
     * timestamps 0. Re-checked here so verify does not depend on having
     * come through decode (qc_v2.c:215-217). */
    if (cert_check(c) != 0) return -1;

    /* ── 2. Identity: this certificate must be about the block the caller
     *      is asking about. ── */
    if (c->height != expect_height) return -1;
    if (memcmp(c->block_id, expect_block_id, DNA_TM_BLOCK_ID_LEN) != 0)
        return -1;

    /* ── 3. The snapshot is trusted ONLY if it IS the committed set.
     *
     * dna_vset_hash allocates its preimage buffer, so its failure is a
     * NODE-LOCAL FAULT and is reported as one — the same classification
     * dna_qc_v2_verify makes at qc_v2.c:202 and for the same reason: a
     * node under memory pressure must not declare a valid, quorum-
     * certified block consensus-invalid. ── */
    uint8_t computed[DNA_VSET_HASH_LEN];
    if (dna_vset_hash(snap, computed) != 0) return -2;
    if (memcmp(computed, header_vset_hash, DNA_VSET_HASH_LEN) != 0) return -1;

    /* ── 4. One entry per member, in set order. N comes from the SNAPSHOT,
     *      never from a compile-time committee size. ── */
    uint16_t n_set = snap->active_count;
    if (n_set == 0 || n_set > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    if (c->n != n_set) return -1;
    /* dna_vset_hash succeeded, so the snapshot encoded, so entries is
     * non-NULL; the guard states the dependency rather than assuming it. */
    if (!snap->entries) return -2;

    /* ── 5. Every present signature verifies over the 229-byte PRECOMMIT
     *      preimage built from SNAPSHOT ENTRY i's voter_id, against the
     *      pubkey COMMITTED IN THAT ENTRY — position is identity, and the
     *      committed pubkey is what makes historical verification
     *      key-rotation safe. One bad signature rejects the WHOLE
     *      certificate (types/validation.go:309/382). ── */
    static const uint8_t NIL_BLOCK_ID[DNA_TM_BLOCK_ID_LEN] = { 0 };
    uint32_t committed_votes = 0;

    for (size_t i = 0; i < (size_t)n_set; i++) {
        const dna_tm_commit_entry_t *e = &c->entries[i];

        /* ABSENT: the member did not precommit THIS block. Its timestamp
         * was already required to be 0 by cert_check, and nothing else
         * about it is checked (block.go:616-620). */
        if (e->flag == DNA_TM_COMMIT_FLAG_ABSENT) continue;

        const uint8_t *bid = (e->flag == DNA_TM_COMMIT_FLAG_COMMIT)
                                 ? c->block_id : NIL_BLOCK_ID;

        uint8_t pre[DNA_TM_VOTE_PREIMAGE_LEN];
        /* Pure byte layout over non-NULL inputs: only a NULL argument or a
         * compile-time layout drift can fail it, both local conditions
         * rather than anything the certificate did. */
        if (dna_tm_vote_preimage(DNA_TM_VOTE_PRECOMMIT, bid,
                                 snap->entries[i].voter_id,
                                 c->height, c->round, e->timestamp_ms,
                                 chain_id, header_vset_hash, pre) != 0)
            return -2;

        /* THE verdict this function exists to deliver. Deliberately -1:
         * the signature check allocates nothing, so no fault can hide
         * behind it. */
        if (qgp_dsa87_verify(e->sig, QGP_DSA87_SIGNATURE_BYTES,
                             pre, DNA_TM_VOTE_PREIMAGE_LEN,
                             snap->entries[i].pubkey) != 0)
            return -1;

        /* NIL is verified but never counted (types/validation.go:375-390). */
        if (e->flag == DNA_TM_COMMIT_FLAG_COMMIT) committed_votes++;
    }

    /* ── 6. Quorum over COMMIT entries only. ── */
    if (committed_votes < dna_bft_quorum((uint32_t)n_set)) return -1;

    /* Stake was never read: one validator = one vote. */
    return 0;
}

/* ── last_commit_hash ───────────────────────────────────────────────── */

int dna_tm_commit_hash(const uint8_t *cert_bytes, size_t len,
                       uint8_t out[64]) {
    if (!cert_bytes || !out) return -1;
    /* Flat: no tag is prepended, because the certificate's own 16-byte
     * marker is already its first bytes (D-19 rev 3). */
    if (len < (size_t)DNA_TM_COMMIT_HDR_LEN || len > DNA_TM_COMMIT_MAX_LEN)
        return -1;
    if (qgp_sha3_512(cert_bytes, len, out) != 0) return -2;
    return 0;
}
