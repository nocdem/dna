/**
 * @file shared/dnac/tm_commit.h
 * @brief Tendermint T3 — commit certificate `nodus.commit.v1` (INACTIVE).
 *
 * The certificate is the set of PRECOMMIT votes that decided one block. It
 * mirrors the reference's Commit: one entry per member of the governing
 * validator set, IN SET ORDER, so a member's position is its identity and
 * no validator address travels on the wire.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No consensus path calls anything in this file. It is wave 1 of the T3
 * host integration: additive only. The live 144-byte cert path
 * (nodus/src/witness/nodus_witness_cert.{h,c}) and QC V2 (qc_v2.{h,c}) are
 * byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── TAG ────────────────────────────────────────────────────────────────
 *   "nodus.commit.v1"  (16 bytes, zero-padded). A FORMAT marker only — no
 *   signature covers it; the entries' signatures cover vote preimages.
 *
 * ── Wire layout (T2 wire design §4.3; D-17 rev 3) ──────────────────────
 *     off   0  16  tag          "nodus.commit.v1" + 1 x 0x00
 *     off  16   8  height       u64 BE
 *     off  24   4  round        u32 BE
 *     off  28  64  block_id
 *     off  92   2  n            u16 BE = the governing snapshot's N
 *     off  94      n entries, IN SET ORDER (entry i = the i-th ascending
 *                  voter_id of the snapshot):
 *                    1     flag       1 ABSENT | 2 COMMIT | 3 NIL
 *                    8     timestamp  u64 BE ms — MUST be 0 when ABSENT
 *                 4627     sig        present iff flag != ABSENT
 *     entry: 9 (ABSENT) or 4636 (COMMIT/NIL); max 94 + 128 × 4636 = 593 502
 *
 * A COMMIT entry is a PRECOMMIT vote over the 229-byte nodus.vote.v1
 * preimage (tm_vote.h) with the certificate's block_id; a NIL entry is the
 * same vote with block_id 64 × 0x00. A member that precommitted a DIFFERENT
 * block is recorded ABSENT (vote_set.go:652-654; block.go:1132-1143).
 *
 * ── Empty certificate (height 1) ───────────────────────────────────────
 * Height 1 has no previous commit, so its certificate is exactly 94 bytes
 * with n = 0 (consensus/state.go:1287-1291; state/validation.go:86-89).
 * dna_tm_commit_verify's `expect_empty` selects that rule.
 *
 * ── This codec computes NO consensus value ─────────────────────────────
 * It reads no clock, seeds no randomness, and makes no ordering decision:
 * entries are stored and emitted in the order the caller supplied (set
 * order), never re-sorted. The ONE ordering that happens anywhere in this
 * file is the median's private ascending copy of the timestamps, which
 * produces a value, not an order (dna_tm_commit_median_time).
 *
 * ── REJECT vs FAULT ────────────────────────────────────────────────────
 * The same three-class contract as qc_v2.h (O15A): 0 accept, -1 REJECT
 * (the bytes are bad — deterministic, every honest node agrees), -2 FAULT
 * (this process could not decide: allocation or hash backend). A caller
 * MUST NOT count -2 as a negative vote or as an invalid block.
 *
 * Governing records: D-17 rev 3 (atlas-dec-9d96e2ec31ad4840cf258df21732b67f),
 * D-19 rev 3 (atlas-dec-d106407a31d7d16d49d51990b75c36c6), D-20
 * (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19). Reference @709fd12b:
 * state/validation.go:85-96; types/validation.go:292/398, :309/382,
 * :375-390; types/block.go:616-620, :1132-1143; state/state.go:264-289.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_TM_COMMIT_H
#define SHARED_DNAC_TM_COMMIT_H

#include <stdint.h>
#include <stddef.h>

#include "tm_bounds.h"      /* DNA_TM_COMMIT_* sizes, QGP_DSA87_SIGNATURE_BYTES */
#include "tm_vote.h"        /* DNA_TM_BLOCK_ID_LEN, the 229-byte preimage       */
#include "vset_wire.h"      /* dna_vset_snapshot_t, dna_vset_hash               */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Tag and flags ──────────────────────────────────────────────────── */
#define DNA_TM_COMMIT_TAG          "nodus.commit.v1"      /* 15 ASCII + 1 × 0x00 = 16 */
#define DNA_TM_COMMIT_TAG_LEN      16
#define DNA_TM_COMMIT_FLAG_ABSENT  1
#define DNA_TM_COMMIT_FLAG_COMMIT  2
#define DNA_TM_COMMIT_FLAG_NIL     3

/** The height-1 certificate: n = 0, 94 bytes. */
#define DNA_TM_COMMIT_EMPTY_LEN    DNA_TM_COMMIT_HDR_LEN   /* h = 1: n = 0, 94 bytes */

/* ── Types ──────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  flag;                                  /* 1 ABSENT | 2 COMMIT | 3 NIL          */
    uint64_t timestamp_ms;                          /* MUST be 0 when ABSENT                */
    uint8_t  sig[QGP_DSA87_SIGNATURE_BYTES];        /* meaningful iff flag != ABSENT        */
} dna_tm_commit_entry_t;

/**
 * A decoded certificate. `entries` is ALWAYS heap-owned (128 entries are
 * ~593 KB — never a stack object) and is NULL exactly when n == 0.
 * Allocate with dna_tm_commit_alloc, release with dna_tm_commit_free.
 */
typedef struct {
    uint64_t height;
    uint32_t round;
    uint8_t  block_id[DNA_TM_BLOCK_ID_LEN];
    uint16_t n;                                     /* entries in SET ORDER: i = i-th ascending voter_id */
    dna_tm_commit_entry_t *entries;                 /* n slots; NULL iff n == 0 */
} dna_tm_commit_t;

/* ── Lifecycle ──────────────────────────────────────────────────────── */

/** Allocate a zeroed certificate with n zeroed entry slots.
 *  n == 0 is ALLOWED and yields the empty shape (entries stays NULL) —
 *  unlike dna_qc_v2_alloc, because height 1's certificate has no entries.
 *  @return NULL if n > DNA_MAX_ACTIVE_VALIDATORS or on allocation failure. */
dna_tm_commit_t *dna_tm_commit_alloc(uint16_t n);

/** NULL-safe release. Frees entries + the certificate and zeroes *c. */
void             dna_tm_commit_free(dna_tm_commit_t **c);

/** Build the empty certificate of height 1 in place (height 0, round 0,
 *  block_id 0, n 0). Any entry array the certificate held is released, so
 *  the object afterwards IS the empty shape rather than merely encoding
 *  like it. @return 0 / -1 (NULL). */
int    dna_tm_commit_set_empty(dna_tm_commit_t *c);

/** @return 1 iff exactly the empty shape: height 0, round 0, block_id all
 *  zero, n == 0. (With n == 0 the entries pointer is not part of the
 *  shape — it encodes to the same 94 bytes either way.) 0 otherwise, and
 *  0 for NULL. */
int    dna_tm_commit_is_empty(const dna_tm_commit_t *c);

/* ── Codec ──────────────────────────────────────────────────────────── */

/** Encoded length of a structurally valid certificate, or 0 if encode
 *  would reject (a valid encoding is never 0 bytes, so 0 is unambiguous). */
size_t dna_tm_commit_encoded_len(const dna_tm_commit_t *c);

/** Canonical bytes (T2 §4.3). Rejects (-1): NULL; flag outside {1,2,3}; ABSENT with timestamp != 0;
 *  n > DNA_MAX_ACTIVE_VALIDATORS; cap too small.
 *  @param written [out] bytes written on success (may be NULL). */
int    dna_tm_commit_encode(const dna_tm_commit_t *c, uint8_t *dst, size_t cap, size_t *written);

/** Strict decode: tag, exact length implied by the flags, trailing bytes reject, flag/ABSENT-ts rules
 *  enforced BEFORE allocation where possible.
 *
 *  The entry sizes depend on the flags, so the exact length cannot be read
 *  off the header alone: the decoder walks the entries once WITHOUT
 *  allocating, enforcing every flag and ABSENT-timestamp rule and the
 *  exact total, and only then allocates and fills.
 *
 *  @param out [out] heap certificate on success, untouched on failure.
 *  @return 0 / -1 REJECT / -2 FAULT (OOM). */
int    dna_tm_commit_decode(const uint8_t *src, size_t len, dna_tm_commit_t **out);

/* ── BFT-time median ────────────────────────────────────────────────── */

/** BFT-time median (T2 §4.3; state/state.go:264-289; types/time/time.go WeightedMedian, weight 1):
 *  times of the non-ABSENT entries, ascending; total = count; median = total/2; walk:
 *  if median <= 1 → pick, else median -= 1. Closed form sorted[max(0, total/2 - 1)].
 *
 *  ABSENT entries contribute nothing (the reference skips exactly
 *  BlockIDFlagAbsent, state.go:270-276); NIL entries DO contribute.
 *  The result is always one of the input values, so ≤ f dishonest stamps
 *  cannot pull it outside the honest range.
 *
 *  @return 0 / -1 (NULL, or no non-ABSENT entry) / -2 FAULT (OOM for the sort buffer). */
int    dna_tm_commit_median_time(const dna_tm_commit_t *c, uint64_t *out_ms);

/* ── Verification ───────────────────────────────────────────────────── */

/** Verification — the codec-level core shared by list A (embedded, h-1) and list B (served, h)
 *  of T2 §4.3. The HOST resolves the snapshot from committed authority and passes it in; this
 *  function never resolves anything.
 *  Steps, fail-closed, first failure rejects the WHOLE certificate:
 *   1. expect_empty == 1 → c must be exactly the empty shape (height 0, round 0, block_id 0, n 0);
 *      return 0 without touching snap (h == 1 rule; consensus/state.go:1287-1291). Otherwise:
 *   2. c->height == expect_height; memcmp(c->block_id, expect_block_id, 64) == 0
 *   3. dna_vset_hash(snap) == header_vset_hash (recomputed, as dna_qc_v2_verify does)
 *   4. N = snap->active_count; 1 <= N <= DNA_MAX_ACTIVE_VALIDATORS; c->n == N
 *   5. every entry: flag ∈ {1,2,3}; ABSENT → timestamp 0 and nothing else checked;
 *      COMMIT/NIL → signature verifies over dna_tm_vote_preimage(PRECOMMIT, block_id_or_zero,
 *      snap entry i voter_id, c->height, c->round, entry timestamp, chain_id, header_vset_hash)
 *      with the pubkey COMMITTED IN SNAPSHOT ENTRY i (NIL → block_id 64 × 0)
 *   6. count(COMMIT) >= dna_bft_quorum(N)   (NIL verified, not counted)
 *
 *  There is deliberately NO "count the good signatures and compare to
 *  quorum" path: one bad signature rejects everything, so a certificate
 *  cannot be padded with garbage and still finalize (qc_v2.h:151-175;
 *  types/validation.go:309/382).
 *
 *  Because step 1 returns before snap is read, `snap`, `expect_block_id`,
 *  `header_vset_hash` and `chain_id` may be NULL when expect_empty is 1.
 *
 *  @return 0 accept / -1 REJECT / -2 FAULT (hash backend or OOM). */
int    dna_tm_commit_verify(const dna_tm_commit_t *c,
                            int expect_empty,
                            uint64_t expect_height,
                            const uint8_t expect_block_id[DNA_TM_BLOCK_ID_LEN],
                            const dna_vset_snapshot_t *snap,
                            const uint8_t header_vset_hash[DNA_VSET_HASH_LEN],
                            const uint8_t chain_id[DNA_CHAIN_ID_LEN]);

/** last_commit_hash (T2 §4.4, D-19 rev 3): flat SHA3-512 over the canonical certificate bytes.
 *  No tag is prepended — the certificate's own 16-byte marker is already
 *  the first thing hashed. Rejects (-1) NULL and a length outside
 *  [DNA_TM_COMMIT_HDR_LEN, DNA_TM_COMMIT_MAX_LEN]; -2 if the hash backend
 *  fails. @return 0 / -1 / -2 */
int    dna_tm_commit_hash(const uint8_t *cert_bytes, size_t len, uint8_t out[64]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_TM_COMMIT_H */
