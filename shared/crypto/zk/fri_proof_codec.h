/**
 * @file fri_proof_codec.h
 * @brief Deterministic wire (de)serialization for the batched STARK proof shape.
 *
 * The LIVE surface is the DZKF **version 4** batched-proof wire
 * (dnac_batch_wire_encode / dnac_batch_wire_decode + accessors): the exact
 * in-memory tuple dnac_batch_verify consumes and dnac_batch_prove produces.
 * The Fiat-Shamir transcript is NOT part of the wire (batched priming is a
 * separate layer, batch_priming.h).
 *
 * Source of truth:
 *   - docs/plans/2026-05-29-fri-proof-wire-codec-design.md (v3 field encodings,
 *     inherited verbatim by v4 for params + FriProof)
 *   - fri_verifier.h / batch_verify.h (the structs encoded)
 *   - Plonky3 82cfad73: fri/src/proof.rs, fri/src/two_adic_pcs.rs,
 *     commit/src/mmcs.rs, batch-stark/src/proof.rs, lookup/src/types.rs
 *
 * Common field encodings (v3 and v4 alike): header = magic "DZKF" + u16 version
 * + u32 total_len; all integers little-endian; Goldilocks = canonical u64-LE
 * (decoder rejects >= p); fp2 = c0 then c1; digest = 4 Goldilocks lanes = 32
 * bytes (each lane canonical, rejected >= p — G-DET-P1-5); vectors = u32 count
 * prefix; Merkle opening proof = u32 depth + depth digests. The M3b salted-leaf
 * tails (u32 salt_elems + canonical base salts, per batch opening per matrix
 * and per commit-phase step; 0 = unsalted) ride inside the FriProof — without
 * them a SALTED (hiding) proof, which the shielded pool mandates (dm design
 * §3a), could not cross the wire at all.
 *
 * P2L-d d4.d (2026-07-26) — v3 uni-stark RETIREMENT. The ENTIRE v3
 * single-instance wire is GONE (encoder, decoder, read accessors, opening-point
 * structures, both verify wrappers): the only wire this file speaks is DZKF v4,
 * and the only consensus verify entry is dnac_shielded_verify_statement
 * (shielded_verify.h) over dnac_batch_wire_decode + dnac_batch_verify.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_PROOF_CODEC_H
#define DNAC_ZK_FRI_PROOF_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "fri_verifier.h"  /* dnac_fri_params_t, dnac_fri_proof_t, commitments, dnac_fri_status_t */
#include "batch_verify.h"  /* v4: dnac_batch_vcommits_t / vopened / rand_openings shapes */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Wire constants (DNAC wire decisions — design doc § 2, § 3, § 11)
 * ========================================================================== */
#define DNAC_FRI_WIRE_MAGIC0 0x44u /* 'D' */
#define DNAC_FRI_WIRE_MAGIC1 0x5Au /* 'Z' */
#define DNAC_FRI_WIRE_MAGIC2 0x4Bu /* 'K' */
#define DNAC_FRI_WIRE_MAGIC3 0x46u /* 'F' */
/* Versions 1..3 were the single-instance uni-stark wire (v2→v3 was the P1c
 * Poseidon2 digest cutover, 64 → 32 bytes). ALL of them are retired at d4.d;
 * the sole live version constant is DNAC_BATCH_WIRE_VERSION below, and the v4
 * decoder rejects any older tag on VERSION rather than on a shape coincidence
 * (P1.0 F8). No live proof ever existed at any retired version. */

/* Maximum bounds (defense-in-depth; the primary OOM guard is the
 * remaining-bytes check). These bound the v4 FriProof. */
#define DNAC_FRI_WIRE_MAX_TOTAL_LEN     (64u * 1024u * 1024u) /* 64 MiB */
#define DNAC_FRI_WIRE_MAX_ROUNDS        64u
#define DNAC_FRI_WIRE_MAX_QUERIES       1024u
#define DNAC_FRI_WIRE_MAX_FINAL_POLY    4096u
#define DNAC_FRI_WIRE_MAX_BATCHES       64u
#define DNAC_FRI_WIRE_MAX_MATRICES      256u
#define DNAC_FRI_WIRE_MAX_COLS          65536u
#define DNAC_FRI_WIRE_MAX_SIBLINGS      64u
#define DNAC_FRI_WIRE_MAX_SIBLING_VALUES 4096u
/* MAX_POINTS / MAX_CLAIMED / MAX_COMMITMENTS retired at d4.d — they bounded
 * the v3 opening-point encoding, which the v4 wire does not carry at all. */
/* M3b leaf salts: SALT_ELEMS is 2 in every deployed config (hiding_mmcs.rs
 * SALT×64bit >= 128); 8 is a generous decode ceiling, not a crypto choice. */
#define DNAC_FRI_WIRE_MAX_SALT_ELEMS    8u

/* ============================================================================
 * DZKF v4 — batched proof wire (P2L-d d4.a).
 *
 * The v4 wire carries the BatchProof tuple (batch-stark proof.rs:12-56 shape,
 * as consumed by dnac_batch_verify):
 *   is_zk, num_instances, the 5 commits (main/preprocessed/permutation/
 *   quotient/random — prep/perm/random presence-flagged; main+quotient
 *   always), per-instance UNMERGED opened values (dnac_batch_vopened_t) +
 *   global_lookup_data entries (len-prefixed bus name, aux_column,
 *   cumulative_sum — lookup/src/types.rs:108-115), the random-codeword
 *   openings iff is_zk, the FRI params, and the FriProof (same encoding as
 *   v3: u32 counts, canonical u64-LE fail-close, fp2 c0‖c1, 4-lane digests,
 *   salt tails).
 *
 * STRUCTURAL RULE (closes the v3 H2 class by construction): the v4 wire
 * carries NO opening points and NO per-commitment opening-point lists — the
 * verifier (dnac_batch_verify) assembles the N2 opening rounds itself around
 * the SAMPLED ζ. A wire buffer cannot even express a foreign opening point.
 *
 * Version = 4 under the same DZKF magic; a buffer at ANY older version is
 * REJECTED on VERSION by the v4 decoder (tests/test_batch_wire.c N2b).
 * ========================================================================== */
#define DNAC_BATCH_WIRE_VERSION 4u

/* v4 decode bounds (defense-in-depth; primary OOM guard stays the
 * remaining-bytes check). Instance cap == the verifier's BV_MAX_INSTANCES. */
#define DNAC_BATCH_WIRE_MAX_INSTANCES    32u
#define DNAC_BATCH_WIRE_MAX_OPENED_VALS  65536u
#define DNAC_BATCH_WIRE_MAX_QC           1024u
#define DNAC_BATCH_WIRE_MAX_GLOBALS      64u
#define DNAC_BATCH_WIRE_MAX_BUS_NAME     64u
#define DNAC_BATCH_WIRE_MAX_RAND_ENTRIES 4096u

/* Opaque owner of a decoded v4 batched-proof package. */
typedef struct dnac_batch_wire_package_s dnac_batch_wire_package_t;

/* ============================================================================
 * Codec status — SEPARATE from dnac_fri_status_t (which is unchanged).
 * ========================================================================== */
typedef enum {
    DNAC_FRI_CODEC_OK = 0,
    DNAC_FRI_CODEC_ERR_NULL = 1,               /* null buf/out argument               */
    DNAC_FRI_CODEC_ERR_TRUNCATED = 2,          /* read would pass end of buffer        */
    DNAC_FRI_CODEC_ERR_BAD_MAGIC = 3,          /* header magic mismatch                */
    DNAC_FRI_CODEC_ERR_BAD_VERSION = 4,        /* header version mismatch              */
    DNAC_FRI_CODEC_ERR_NONCANONICAL = 5,       /* Goldilocks limb >= p                 */
    DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW = 6,    /* count > MAX or count*elem > remaining */
    DNAC_FRI_CODEC_ERR_INCONSISTENT_LENGTH = 7,/* total_len != actual buffer length    */
    DNAC_FRI_CODEC_ERR_BAD_DEPTH = 8,          /* Merkle proof depth out of bounds     */
    DNAC_FRI_CODEC_ERR_TRAILING = 9,           /* bytes remain after the last field    */
    DNAC_FRI_CODEC_ERR_OOM = 10,               /* allocation failure                   */
    DNAC_FRI_CODEC_ERR_TOO_LARGE = 11,         /* total_len > MAX_TOTAL_LEN             */
    DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH = 12, /* wire FRI params != pinned consensus set (S0/C5) */
    /* 13 was SHIELDED_HEIGHT_MISMATCH — retired at d4.d with the v3 wrapper
     * that scanned wire opening-point domains for the height. The v4 path pins
     * the height as a compile-time verifier constant instead
     * (shielded_verify.c:243, vi.degree_bits), so no codec-level height status
     * can fire; the value is left unused rather than reassigned. */
    DNAC_FRI_CODEC_ERR_SHIELDED_VERIFY_FAILED = 14   /* shielded verify != OK (fail-closed) */
} dnac_fri_codec_status_t;

/* ============================================================================
 * DZKF v4 batched-proof wire API (P2L-d d4.a — layout notes at the constants
 * block above).
 * ========================================================================== */

/**
 * Encode a batched proof to the DZKF v4 wire.
 *
 * Inputs are the EXACT in-memory shapes dnac_batch_verify consumes (and
 * dnac_batch_prove produces via its accessors). rand_openings MUST be
 * non-NULL iff is_zk (fail-close ERR_NULL otherwise). commits->main_commit
 * and commits->quotient_commit are mandatory; per-instance permutation
 * local/next must both be present when permutation_len > 0.
 *
 * On success sets *out_buf (caller frees with free()) and *out_len, returns
 * DNAC_FRI_CODEC_OK. On failure *out_buf is left NULL.
 */
dnac_fri_codec_status_t dnac_batch_wire_encode(
    int                               is_zk,
    uint32_t                          num_instances,
    const dnac_batch_vcommits_t      *commits,
    const dnac_batch_vopened_t       *opened,
    const dnac_batch_rand_openings_t *rand_openings,
    const dnac_fri_params_t          *params,
    const dnac_fri_proof_t           *proof,
    uint8_t                         **out_buf,
    size_t                           *out_len);

/**
 * Decode a DZKF v4 buffer. On success sets *out_pkg (free with
 * dnac_batch_wire_free), returns DNAC_FRI_CODEC_OK. On ANY failure no package
 * is returned and every intermediate allocation has been freed. Version 3
 * (single-instance) buffers are rejected with ERR_BAD_VERSION.
 *
 * The decode is STRUCTURAL only (bounds, canonicality, presence flags 0/1,
 * exact-length): the semantic gates (random-commit iff is_zk, opened-length
 * vs widths, permutation lens, lookup metadata) live in dnac_batch_verify,
 * which the caller MUST run on the decoded package. There are no opening
 * points on the wire to validate — the verifier samples ζ itself.
 */
dnac_fri_codec_status_t dnac_batch_wire_decode(
    const uint8_t              *buf,
    size_t                      len,
    dnac_batch_wire_package_t **out_pkg);

/* Accessors into a decoded package (borrowed; owned by the package). */
int      dnac_batch_wire_is_zk(const dnac_batch_wire_package_t *pkg);
uint32_t dnac_batch_wire_num_instances(const dnac_batch_wire_package_t *pkg);
const dnac_batch_vcommits_t *dnac_batch_wire_commits(
    const dnac_batch_wire_package_t *pkg);
/* Array of num_instances entries. */
const dnac_batch_vopened_t *dnac_batch_wire_opened(
    const dnac_batch_wire_package_t *pkg);
/* NULL when the package is not ZK (matches the dnac_batch_verify contract). */
const dnac_batch_rand_openings_t *dnac_batch_wire_rand_openings(
    const dnac_batch_wire_package_t *pkg);
const dnac_fri_params_t *dnac_batch_wire_params(
    const dnac_batch_wire_package_t *pkg);
const dnac_fri_proof_t *dnac_batch_wire_proof(
    const dnac_batch_wire_package_t *pkg);

/* Free a decoded package (all nested allocations + the package). NULL-safe. */
void dnac_batch_wire_free(dnac_batch_wire_package_t *pkg);

/* ============================================================================
 * SHIELDED (consensus) verify — WHERE IT LIVES NOW (d4.d).
 *
 * The hardened shielded entry is dnac_shielded_verify_statement
 * (shielded_verify.h). It decodes with dnac_batch_wire_decode above and
 * verifies with dnac_batch_verify, carrying every pin the retired v3 wrapper
 * dnac_fri_verify_wire_shielded held, and more:
 *   - params equality vs the pinned consensus set, then SUBSTITUTION of the
 *     pinned struct into the verify (shielded_verify.c:188-204, :252) — the
 *     verifier's OWN constant sets the security level, never a wire value;
 *   - SALT_ELEMS == DNAC_SHIELDED_SALT_ELEMS on EVERY input-batch opening and
 *     commit-phase step (shielded_verify.c:91-103, :221 — G-SEC-P1-6);
 *   - the trace-height pin, now a COMPILE-TIME verifier constant rather than a
 *     wire scan: vi.degree_bits = DNAC_SHIELDED_COMMITTED_LOG_HEIGHT
 *     (shielded_verify.c:243) — a proof at any other height fails the FRI
 *     verify because its query depths / opened counts cannot match;
 *   - is_zk == 1 and num_instances == 1 (shielded_verify.c:179-182), plus the
 *     full opened-value shape pin (:210-216).
 *
 * The v3 wrapper's two recorded HARD BLOCKERS are closed by construction on
 * this path: (H2) the v4 wire carries NO opening points at all — the verifier
 * samples ζ itself, so a wire-chosen opening coordinate cannot be expressed;
 * (H3) the transcript is built INSIDE dnac_batch_verify from the recomputed
 * publics and the wire commitments, so there is no caller-supplied,
 * possibly-unprimed transcript to collapse Fiat-Shamir.
 * ========================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_PROOF_CODEC_H */
