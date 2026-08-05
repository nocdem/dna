/**
 * @file shared/dnac/qc_v2.h
 * @brief Ledger V2 Season 3 — quorum certificate V2 (INACTIVE).
 *
 * A QC V2 is the set of per-validator signatures that finalize one block,
 * verified against the validator-set SNAPSHOT the block header committed
 * to (shared/dnac/vset_wire.h). Because the snapshot freezes each voter's
 * PUBLIC KEY, a historical block stays verifiable after every one of its
 * signers has rotated keys, unbonded, or left the set — the verifier never
 * consults the mutable validators table.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * No consensus path calls anything in this file. The LEGACY 144-byte
 * certificate path (nodus/src/witness/nodus_witness_cert.{h,c}) remains the
 * live finalization mechanism and is byte-identically untouched by this
 * module. QC V2 activates only with the Ledger V2 devnet reset.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── TAG ────────────────────────────────────────────────────────────────
 *   "DNA.CERT.v2"  (16 bytes, zero-padded)
 *
 * ── Signed preimage (EXACTLY 216 bytes) ────────────────────────────────
 *     tag                 (16)   "DNA.CERT.v2" zero-padded
 *     block_id            (64)   the block hash being certified
 *     voter_id            (32)   THIS cert's signer
 *     height              ( 8)   u64 BE
 *     chain_id            (32)
 *     validator_set_hash  (64)   dna_vset_hash of the governing snapshot
 *
 * Binding voter_id into the preimage makes a cert non-transferable between
 * signers; binding validator_set_hash makes it non-transferable between
 * validator sets, so a signature gathered under one set can never be
 * replayed to satisfy a quorum under another.
 *
 * ── QC wire layout ─────────────────────────────────────────────────────
 *     n_certs   u16 BE   (2)
 *     n_certs × ( voter_id (32) ‖ signature (4627) )     = n × 4659
 *
 * Certs MUST be sorted STRICTLY ASCENDING by voter_id (byte-lexicographic).
 * Equal neighbors are a duplicate and reject. Strict sorting gives the QC a
 * single canonical byte form and makes double-counting a signer structurally
 * impossible — enforced by BOTH encode and decode.
 *
 * ── ONE VALIDATOR = ONE VOTE ───────────────────────────────────────────
 * Stake NEVER influences verification. dna_qc_v2_verify counts members, not
 * weight; it does not read total_stake or self_bond from any entry.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_QC_V2_H
#define SHARED_DNAC_QC_V2_H

#include <stdint.h>
#include <stddef.h>

#include "ledger_ids.h"
#include "vset_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Field widths ───────────────────────────────────────────────────── */
#define DNA_CERT_V2_TAG_LEN      16
#define DNA_CERT_V2_BLOCK_ID_LEN 64
#define DNA_CERT_V2_VOTER_ID_LEN DNA_VSET_VOTER_ID_LEN   /* 32 */
#define DNA_CERT_V2_VSET_HASH_LEN DNA_VSET_HASH_LEN      /* 64 */
#define DNA_CERT_V2_SIG_LEN    4627   /* Dilithium5 (ML-DSA-87) signature */

/** The signed preimage is a fixed 216 bytes. */
#define DNA_CERT_V2_PREIMAGE_LEN 216

/* ── QC wire sizes ──────────────────────────────────────────────────── */
#define DNA_QC_V2_HDR_LEN   2      /* n_certs u16 BE                      */
#define DNA_QC_V2_CERT_LEN (DNA_CERT_V2_VOTER_ID_LEN + DNA_CERT_V2_SIG_LEN)
                                   /* 32 + 4627 = 4659                    */
#define DNA_QC_V2_MAX_ENC_LEN \
    ((size_t)DNA_QC_V2_HDR_LEN + \
     (size_t)DNA_MAX_ACTIVE_VALIDATORS * (size_t)DNA_QC_V2_CERT_LEN)

/* ── Types ──────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t voter_id[DNA_CERT_V2_VOTER_ID_LEN];
    uint8_t sig[DNA_CERT_V2_SIG_LEN];
} dna_qc_v2_cert_t;

/**
 * A decoded QC. `certs` is ALWAYS heap-owned (128 certs are ~596 KB —
 * never a stack object). Allocate with dna_qc_v2_alloc, release with
 * dna_qc_v2_free.
 */
typedef struct {
    uint16_t          n_certs;
    dna_qc_v2_cert_t *certs;      /* heap, n_certs items, voter_id ASC */
} dna_qc_v2_t;

/* ── Preimage ───────────────────────────────────────────────────────── */

/**
 * Build the exact 216-byte preimage a QC V2 cert signs.
 * @return 0 / -1 (any NULL argument).
 */
int dna_cert_v2_preimage(const uint8_t block_id[DNA_CERT_V2_BLOCK_ID_LEN],
                         const uint8_t voter_id[DNA_CERT_V2_VOTER_ID_LEN],
                         uint64_t height,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         const uint8_t vset_hash[DNA_CERT_V2_VSET_HASH_LEN],
                         uint8_t out[DNA_CERT_V2_PREIMAGE_LEN]);

/* ── Lifecycle ──────────────────────────────────────────────────────── */

/** Allocate a zeroed QC with n_certs zeroed cert slots.
 *  @return NULL if n_certs is 0, exceeds DNA_MAX_ACTIVE_VALIDATORS, or on
 *          allocation failure. */
dna_qc_v2_t *dna_qc_v2_alloc(uint16_t n_certs);

/** NULL-safe release. Frees certs + the QC and zeroes *qc. */
void dna_qc_v2_free(dna_qc_v2_t **qc);

/* ── Codec ──────────────────────────────────────────────────────────── */

/** Encoded length of a structurally valid QC, or 0 if encode would reject. */
size_t dna_qc_v2_encoded_len(const dna_qc_v2_t *qc);

/**
 * Encode canonical bytes. Rejects (-1): NULL; certs == NULL; n_certs == 0
 * or > DNA_MAX_ACTIVE_VALIDATORS; certs not strictly ascending by voter_id
 * (which subsumes duplicates); cap smaller than the encoding.
 * @param written [out] bytes written on success (may be NULL).
 */
int dna_qc_v2_encode(const dna_qc_v2_t *qc,
                     uint8_t *dst, size_t cap, size_t *written);

/**
 * Decode canonical bytes. `len` must be EXACTLY the length implied by the
 * header count — truncation and trailing bytes both reject. The count is
 * bounds-checked and the exact length verified BEFORE any allocation; the
 * strict sort/duplicate rule is then enforced on the decoded certs.
 * @param out [out] heap QC on success, untouched on failure.
 */
int dna_qc_v2_decode(const uint8_t *src, size_t len, dna_qc_v2_t **out);

/* ── Verification ───────────────────────────────────────────────────── */

/**
 * Verify a QC against the validator-set snapshot the block header
 * committed to. Every step below must pass; the first failure rejects the
 * WHOLE QC:
 *
 *   1. The snapshot is re-encoded and hashed; the result must equal
 *      header_vset_hash. A snapshot is trusted ONLY if it IS the committed
 *      set — otherwise an attacker could hand over any set they like.
 *   2. N = snapshot->active_count; quorum = dna_bft_quorum(N)
 *      (= floor(2N/3)+1, shared/dnac/ledger_ids.h). N == 0 or
 *      N > DNA_MAX_ACTIVE_VALIDATORS rejects.
 *   3. n_certs < quorum rejects (not enough signers);
 *      n_certs > N rejects (more signers than the set has members).
 *   4. Certs strictly ascending by voter_id, hence distinct (re-verified
 *      here, cheaply, so verify does not depend on having come through
 *      decode).
 *   5. Every voter_id must be a member of the snapshot. A non-member
 *      rejects the whole QC.
 *   6. Every signature must verify over the 216-byte preimage built from
 *      THIS cert's voter_id together with the caller's block_id, height,
 *      chain_id and header_vset_hash, against the pubkey COMMITTED IN THE
 *      SNAPSHOT ENTRY for that voter. One invalid signature rejects the
 *      whole QC — fail-closed. There is deliberately no "count the good
 *      ones and compare to quorum" path: that would let an attacker pad a
 *      QC with garbage and still finalize.
 *
 * Stake is never consulted: one validator = one vote.
 *
 * @return 0 accept, -1 reject.
 */
int dna_qc_v2_verify(const dna_qc_v2_t *qc,
                     const uint8_t block_id[DNA_CERT_V2_BLOCK_ID_LEN],
                     uint64_t height,
                     const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                     const uint8_t header_vset_hash[DNA_CERT_V2_VSET_HASH_LEN],
                     const dna_vset_snapshot_t *snapshot);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_QC_V2_H */
