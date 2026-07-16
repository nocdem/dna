/**
 * @file fri_proof_codec.h
 * @brief Deterministic wire (de)serialization for the FRI verifier proof shape.
 *
 * Encodes / decodes the EXACT inputs of dnac_fri_verify — (params, proof,
 * commitments_with_opening_points) — to/from a byte buffer. The Fiat-Shamir
 * transcript is NOT part of the wire (transcript priming is a separate layer).
 *
 * This module is ADDITIVE: it does not modify fri_verifier.{c,h}, does not
 * change dnac_fri_status_t, and does not alter FRI verifier semantics. Decoded
 * structs are fed to dnac_fri_verify unchanged.
 *
 * Source of truth:
 *   - docs/plans/2026-05-29-fri-proof-wire-codec-design.md (whole document)
 *   - fri_verifier.h (the structs encoded)
 *   - Plonky3 82cfad73: fri/src/proof.rs, fri/src/two_adic_pcs.rs,
 *     commit/src/mmcs.rs (field/struct order grounding)
 *
 * Wire layout (version 1): see design doc § 3. Header = magic "DZKF" + u16
 * version + u32 total_len; all integers little-endian; Goldilocks = canonical
 * u64-LE (decoder rejects >= p); fp2 = c0 then c1; digest = raw 64 bytes;
 * vectors = u32 count prefix; Merkle opening proof = u32 depth + depth digests.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_PROOF_CODEC_H
#define DNAC_ZK_FRI_PROOF_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "fri_verifier.h"  /* dnac_fri_params_t, dnac_fri_proof_t, commitments, dnac_fri_status_t */
#include "transcript.h"    /* dnac_transcript_t (for dnac_fri_verify_wire) */

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
#define DNAC_FRI_WIRE_VERSION 1u

/* Maximum bounds (defense-in-depth; the primary OOM guard is the
 * remaining-bytes check). Generous vs the v3.0 single-TX shape. */
#define DNAC_FRI_WIRE_MAX_TOTAL_LEN     (64u * 1024u * 1024u) /* 64 MiB */
#define DNAC_FRI_WIRE_MAX_ROUNDS        64u
#define DNAC_FRI_WIRE_MAX_QUERIES       1024u
#define DNAC_FRI_WIRE_MAX_FINAL_POLY    4096u
#define DNAC_FRI_WIRE_MAX_BATCHES       64u
#define DNAC_FRI_WIRE_MAX_MATRICES      256u
#define DNAC_FRI_WIRE_MAX_COLS          65536u
#define DNAC_FRI_WIRE_MAX_SIBLINGS      64u
#define DNAC_FRI_WIRE_MAX_SIBLING_VALUES 4096u
#define DNAC_FRI_WIRE_MAX_POINTS        256u
#define DNAC_FRI_WIRE_MAX_CLAIMED       65536u
#define DNAC_FRI_WIRE_MAX_COMMITMENTS   64u

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
    DNAC_FRI_CODEC_ERR_SHIELDED_HEIGHT_MISMATCH = 13, /* committed trace domain != pinned shielded height */
    DNAC_FRI_CODEC_ERR_SHIELDED_VERIFY_FAILED = 14   /* shielded FRI verify != DNAC_FRI_OK (fail-closed) */
} dnac_fri_codec_status_t;

/* Opaque owner of a decoded proof package (params + proof + commitments + all
 * nested allocations, tracked by an internal registry). */
typedef struct dnac_fri_wire_package_s dnac_fri_wire_package_t;

/* ============================================================================
 * Encode — (params, proof, commitments) -> malloc'd byte buffer.
 *
 * On success sets *out_buf (caller frees with free()) and *out_len, returns
 * DNAC_FRI_CODEC_OK. On failure returns an error and leaves *out_buf NULL.
 * ========================================================================== */
dnac_fri_codec_status_t dnac_fri_proof_encode(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    const dnac_fri_commitment_with_opening_points_t *commitments,
    size_t                                           num_commitments,
    uint8_t                                        **out_buf,
    size_t                                          *out_len);

/* ============================================================================
 * Decode — byte buffer -> allocated package. On success sets *out_pkg (caller
 * frees with dnac_fri_wire_free), returns DNAC_FRI_CODEC_OK. On ANY failure no
 * package is returned (*out_pkg = NULL) and every intermediate allocation has
 * been freed (no partial leak).
 * ========================================================================== */
dnac_fri_codec_status_t dnac_fri_proof_decode(
    const uint8_t                *buf,
    size_t                        len,
    dnac_fri_wire_package_t     **out_pkg);

/* Accessors into a decoded package (borrowed; owned by the package). */
const dnac_fri_params_t *dnac_fri_wire_params(const dnac_fri_wire_package_t *pkg);
const dnac_fri_proof_t  *dnac_fri_wire_proof(const dnac_fri_wire_package_t *pkg);
const dnac_fri_commitment_with_opening_points_t *dnac_fri_wire_commitments(
    const dnac_fri_wire_package_t *pkg, size_t *out_num_commitments);

/* Free a decoded package (all nested allocations + the package). NULL-safe. */
void dnac_fri_wire_free(dnac_fri_wire_package_t *pkg);

/* ============================================================================
 * Convenience wrapper: decode + dnac_fri_verify + free. Does NOT replace
 * dnac_fri_verify and does NOT touch dnac_fri_status_t.
 *
 * Returns the CODEC status. If it is DNAC_FRI_CODEC_OK, *out_fri_status receives
 * the dnac_fri_verify result (computed on the decoded structs with the supplied,
 * externally-primed transcript). If decode fails, *out_fri_status is left
 * unchanged and the caller must inspect the returned codec status.
 * ========================================================================== */
dnac_fri_codec_status_t dnac_fri_verify_wire(
    const uint8_t        *buf,
    size_t                len,
    dnac_transcript_t    *transcript,
    dnac_fri_status_t    *out_fri_status);

/* ============================================================================
 * SHIELDED (consensus) verify — the hardened entry point (S0/C5, EXISTENTIAL).
 *
 * Unlike dnac_fri_verify_wire (which trusts the wire-decoded params — correct
 * only for the parked B1/test paths at their own test params), this:
 *   1. REJECTS if the wire-embedded FRI params differ from the pinned consensus
 *      set DNAC_SHIELDED_FRI_PARAMS (tamper detection) →
 *      DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH.
 *   2. REJECTS if the largest committed matrix domain height != the pinned
 *      shielded trace height DNAC_SHIELDED_STARK_LOG_HEIGHT (dm-c5 C5e) →
 *      DNAC_FRI_CODEC_ERR_SHIELDED_HEIGHT_MISMATCH.
 *   3. SUBSTITUTES the pinned params into dnac_fri_verify — the verifier's OWN
 *      constant sets the security level, NEVER a wire value (dm-c5 C5a′). Even
 *      if step 1 somehow passed a crafted-equal set, verification uses the
 *      pinned struct, not the wire pointer.
 *
 * FAIL-CLOSED (red-team S0-M4): `out_fri_status` MUST be non-NULL (else
 * DNAC_FRI_CODEC_ERR_NULL) and is pre-set to a rejecting value; a non-OK verify
 * verdict returns DNAC_FRI_CODEC_ERR_SHIELDED_VERIFY_FAILED (not a silent
 * CODEC_OK a caller might treat as accept). CODEC_OK ⟺ *out_fri_status ==
 * DNAC_FRI_OK.
 *
 * ⚠ NOT YET CONSENSUS-COMPLETE — S4/S8 HARD BLOCKERS (red-team S0-H2/H3, recorded
 * as numbered goals): the wrapper pins the security LEVEL + height but does NOT
 * yet pin the STATEMENT. (H2) The DEEP/zeta opening point is currently WIRE-READ
 * (dec_point, fri_verifier fri_open_input) and transcript-unbound — Plonky3
 * samples zeta after observing the trace/quotient roots (uni-stark verifier.rs).
 * (H3) This wrapper does not observe the wire commitments into `transcript`, so
 * an unprimed transcript collapses Fiat–Shamir (alpha is the first op,
 * fri_verifier.c:511). The S4 shielded verify layer MUST route through
 * dnac_stark_priming (reconstruct round structure, observe roots, SAMPLE zeta,
 * fail-close on any wire-supplied opening point) BEFORE this is wired into
 * consensus. Until then this entry is param/height-hardened but statement-open;
 * do NOT gate value on it. The transcript arg MUST already be primed by that
 * caller (public inputs + tx_binding observed).
 * ========================================================================== */
dnac_fri_codec_status_t dnac_fri_verify_wire_shielded(
    const uint8_t        *buf,
    size_t                len,
    dnac_transcript_t    *transcript,
    dnac_fri_status_t    *out_fri_status);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_PROOF_CODEC_H */
