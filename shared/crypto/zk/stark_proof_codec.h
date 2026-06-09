/**
 * @file stark_proof_codec.h
 * @brief Additive STARK/PCS wire wrapper (DZKS) around the FRI proof wire (DZKF).
 *
 * The DZKS wrapper carries the STARK-instance scalars that transcript priming
 * needs but the FRI wire does not — `degree_bits` + `public_values` — plus the
 * inner DZKF FRI-proof wire as an OPAQUE length-prefixed blob. It is purely
 * additive (design § 8): the existing DZKF wire stays byte-identical, and this
 * module is INDEPENDENT of fri_proof_codec (it never parses the inner). The
 * caller hands the extracted inner to dnac_fri_proof_decode separately.
 *
 * NOT wired (verifier-derived / config, never trusted from a proof wire, design
 * § 5 note C + § 8): base_degree_bits (= degree_bits − is_zk), preprocessed_width,
 * zeta, zeta_next, and the opening coordinate z.
 *
 * Wire layout (version 1), all integers little-endian:
 *   magic "DZKS" (4) | u16 version | u32 total_len | u32 degree_bits
 *   | u32 num_public_values | public_values[num] (each canonical u64-LE Goldilocks)
 *   | u32 inner_dzkf_len | inner DZKF bytes[inner_dzkf_len]
 * total_len == the whole buffer length. Decoder rejects: bad magic/version,
 * total_len != len, public limb >= p, count/length overflow, and trailing bytes.
 *
 * Source of truth:
 *   - docs/plans/2026-05-30-pcs-transcript-priming-design.md § 8
 *   - fri_proof_codec.h (DZKF wire + conventions this mirrors)
 *   - stark_priming.h (the priming layer that consumes degree_bits + public_values)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROOF_CODEC_H
#define DNAC_ZK_STARK_PROOF_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h" /* gold_fp_t, GOLDILOCKS_P */

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Wire constants
 * ========================================================================== */
#define DNAC_STARK_WIRE_MAGIC0 0x44u /* 'D' */
#define DNAC_STARK_WIRE_MAGIC1 0x5Au /* 'Z' */
#define DNAC_STARK_WIRE_MAGIC2 0x4Bu /* 'K' */
#define DNAC_STARK_WIRE_MAGIC3 0x53u /* 'S' */
#define DNAC_STARK_WIRE_VERSION 1u

/* Fixed-header size: magic(4)+version(2)+total_len(4)+degree_bits(4)+num_public(4). */
#define DNAC_STARK_WIRE_HEADER_MIN 18u

#define DNAC_STARK_WIRE_MAX_TOTAL_LEN     (64u * 1024u * 1024u) /* 64 MiB */
#define DNAC_STARK_WIRE_MAX_PUBLIC_VALUES 4096u
#define DNAC_STARK_WIRE_MAX_INNER_LEN     (64u * 1024u * 1024u)

/* ============================================================================
 * Codec status — SEPARATE from both dnac_fri_status_t (FRI verifier; unchanged)
 * and dnac_fri_codec_status_t (FRI wire codec).
 * ========================================================================== */
typedef enum {
    DNAC_STARK_WIRE_OK = 0,
    DNAC_STARK_WIRE_ERR_NULL = 1,                /* null buf/out argument                */
    DNAC_STARK_WIRE_ERR_TRUNCATED = 2,           /* read would pass end of buffer        */
    DNAC_STARK_WIRE_ERR_BAD_MAGIC = 3,           /* header magic != "DZKS"               */
    DNAC_STARK_WIRE_ERR_BAD_VERSION = 4,         /* header version mismatch              */
    DNAC_STARK_WIRE_ERR_NONCANONICAL = 5,        /* public-value limb >= p               */
    DNAC_STARK_WIRE_ERR_LENGTH_OVERFLOW = 6,     /* count/length > MAX or > remaining    */
    DNAC_STARK_WIRE_ERR_INCONSISTENT_LENGTH = 7, /* total_len != actual buffer length    */
    DNAC_STARK_WIRE_ERR_TRAILING = 8,            /* bytes remain after the inner blob    */
    DNAC_STARK_WIRE_ERR_OOM = 9,                 /* allocation failure                   */
    DNAC_STARK_WIRE_ERR_TOO_LARGE = 10           /* total_len > MAX_TOTAL_LEN            */
} dnac_stark_wire_status_t;

/* ============================================================================
 * Decoded wrapper. degree_bits + public_values are the STARK scalars; inner_dzkf
 * is the opaque DZKF blob to hand to dnac_fri_proof_decode. Heap-owned; free with
 * dnac_stark_wire_free.
 * ========================================================================== */
typedef struct {
    size_t     degree_bits;
    gold_fp_t *public_values;   /* malloc'd, num_public_values entries (canonical) */
    size_t     num_public_values;
    uint8_t   *inner_dzkf;      /* malloc'd, inner_dzkf_len bytes (opaque)         */
    size_t     inner_dzkf_len;
} dnac_stark_wire_decoded_t;

/* ============================================================================
 * Encode — (degree_bits, public_values, inner DZKF blob) -> malloc'd buffer.
 *
 * public_values are written canonical (gold_fp_to_u64). On success sets *out_buf
 * (caller frees with free()) + *out_len, returns OK. On failure returns an error
 * and leaves *out_buf NULL.
 * ========================================================================== */
dnac_stark_wire_status_t dnac_stark_proof_encode(
    size_t           degree_bits,
    const gold_fp_t *public_values,
    size_t           num_public_values,
    const uint8_t   *inner_dzkf,
    size_t           inner_dzkf_len,
    uint8_t        **out_buf,
    size_t          *out_len);

/* ============================================================================
 * Decode — byte buffer -> heap-allocated decoded wrapper. On success sets *out
 * (caller frees with dnac_stark_wire_free), returns OK. On ANY failure no
 * structure is returned (*out = NULL) and every intermediate allocation is freed
 * (no partial leak). The inner DZKF blob is NOT validated here — feed it to
 * dnac_fri_proof_decode separately.
 * ========================================================================== */
dnac_stark_wire_status_t dnac_stark_proof_decode(
    const uint8_t              *buf,
    size_t                      len,
    dnac_stark_wire_decoded_t **out);

/* Free a decoded wrapper (public_values + inner_dzkf + the struct). NULL-safe. */
void dnac_stark_wire_free(dnac_stark_wire_decoded_t *dec);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROOF_CODEC_H */
