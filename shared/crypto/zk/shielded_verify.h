/**
 * @file shielded_verify.h
 * @brief Phase-C C2.1 — the CONSENSUS shielded-statement verify entry.
 *
 * dnac_shielded_verify_statement() is the single function a witness calls to
 * decide whether a DNAC_TX_SHIELDED (type 11) transaction's aggregate STARK
 * proof is valid FOR THE STATEMENT ON THE WIRE. It is the consensus analog of
 * the prover-side dnac_agg_prover_wire_selfcheck_shielded (stark_prover_agg.c),
 * which primes from the prover's OWN struct and whose comment defers "the
 * wire-recompute of the publics themselves" to Phase-C — this module IS that
 * wire-recompute (C2 design v2 §4.2).
 *
 * Verify chain (every branch fail-closes; C2 design v2 §0-§2):
 *   0. Statement-version pin (S8 Gate 2): the caller-supplied
 *      dnac_shielded_verify_ctx_t must declare statement_version ==
 *      DNAC_SHIELDED_STATEMENT_VERSION; the wire_version / sect_version halves
 *      of the binding tuple are PINNED internally, never read from the prover.
 *   1. Wire canonicalization: counts in range (num_input == 0 IS legal — the
 *      SHIELD case), unused nf/output slots zero (DET-S5-3), every lane
 *      canonical < p (G-DET-5), a zero-input statement's anchor all-zero,
 *      boundary_in/boundary_out in the frozen B2 range [0, 2^63), sf->fee ==
 *      committed_fee (G-SEC-6, D7.2).
 *   2. Statement binding (G-SEC-3, closes H3): sighash_v5 is recomputed from
 *      the wire fields through the SHARED codec (shared/dnac/tx_wire.h —
 *      compiled identically into libdna and libnodus, single source, G-DET-2;
 *      re-implementation forbidden) over the full ExecutionContext, mapped
 *      through conf_txbind_map (conf_txbind.h:55), and REQUIRED to equal the
 *      wire tx_binding lanes.
 *   3. The 45 public values (CONF_AGGZK_PUB_* layout, conf_action_agg_fold.h)
 *      are recomputed FROM THE WIRE — never read from the proof.
 *   4. DZKF v4 decode (dnac_batch_wire_decode, fri_proof_codec.h) + the
 *      STRUCTURAL pins applied to the decoded package before any verify work:
 *      is_zk==1 and exactly ONE instance, wire FRI params equal to the pinned
 *      consensus set and then SUBSTITUTED by it, the opened-value shape, and
 *      SALT_ELEMS==2 on every FRI opening (G-SEC-P1-6).
 *      NOTE (d4.c-3 / d4.d): the v4 wire carries NO opening points — the
 *      verifier assembles the N2 rounds around the ζ it SAMPLES itself, so the
 *      v3 "wire coordinate must equal the sampled point" check (G-DET-4 /
 *      G-SEC-5, H2) closes STRUCTURALLY: a wire buffer cannot express a
 *      foreign opening point at all.
 *   5. dnac_batch_verify (batch_verify.h — the p3-batch-stark verify_batch
 *      mirror) over the pinned 1-instance descriptor: it runs the batched
 *      transcript priming (which SAMPLES ζ and α), the FRI verify at the
 *      pinned params + compile-time pinned degree_bits 11 with 16-bit query
 *      PoW (G-SEC-4), **AND** the N-chunk AIR constraint check over the
 *      recomputed publics with DNAC_CONF_ACTION_AGG_FOLD_AIR, plus the per-bus
 *      lookup sums (vacuous — the aggregate AIR has no lookups). FRI alone is
 *      soundness-vacuous (CRIT-1): it proves only low-degreeness + opening
 *      consistency — the constraint check is the ONLY step binding the publics
 *      to the trace (balance, 52-bit range, output routing, count binds). ALL
 *      of them must pass.
 *
 * What this function does NOT do (C3 scope, design v2 G-SEC-7/9): anchor
 * root-set membership (the wire anchor is attacker-chosen pre-C3), nullifier
 * set insert/double-spend check, any state mutation. Through all of C2 the
 * witness admission path REJECTS type-11 unconditionally regardless of this
 * function's verdict.
 *
 * Determinism (G-DET-1): the verdict is a PURE function of (sf bytes, the
 * caller-supplied verify context bytes, committed_fee, compile-time pinned
 * constants). No wall clock, no map iteration, no RNG, no node-local state.
 * The context is consensus-authoritative input (see
 * dnac_shielded_verify_ctx_t) — two witnesses that agree on the block's
 * execution context and on the TX bytes reach the same verdict.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_VERIFY_H
#define DNAC_ZK_SHIELDED_VERIFY_H

#include <stdint.h>

/* dnac_tx_shielded_fields_t only — the statement binding moved off the legacy
 * libdna sighash_v4 symbol onto the SHARED sighash_v5 codec (see .c). */
#include "dnac/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Status — one distinct code per failure class so the unit KATs can assert the
 * EXACT branch that fired (fail-close isolation, C2 design v2 §4.2 KAT list).
 * OK == 0; every non-zero value is a REJECT.
 * ========================================================================== */
typedef enum {
    DNAC_SHIELDED_VERIFY_OK = 0,
    DNAC_SHIELDED_VERIFY_ERR_NULL = 1,        /* NULL sf, or no proof blob. A NULL
                                                 vctx is ERR_STATEMENT_VERSION,
                                                 not this.                        */
    DNAC_SHIELDED_VERIFY_ERR_OVERSIZE = 2,    /* blob len > wire cap (fail-close,
                                                 never crash/OOM — design §0)     */
    DNAC_SHIELDED_VERIFY_ERR_COUNT = 3,       /* num_input/num_output out of range */
    DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO = 4,/* unused nf/output slot != 0
                                                 (DET-S5-3 canonical encoding)    */
    DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL = 5,/* a wire lane >= Goldilocks p
                                                 (G-DET-5)                        */
    DNAC_SHIELDED_VERIFY_ERR_FEE = 6,         /* sf->fee != committed_fee
                                                 (G-SEC-6, D7.2 single fee)       */
    DNAC_SHIELDED_VERIFY_ERR_TXBIND = 7,      /* context init / sighash_v5 /
                                                 conf_txbind_map failed, or the
                                                 mapped lanes != wire tx_binding
                                                 (G-SEC-3)                        */
    DNAC_SHIELDED_VERIFY_ERR_DECODE = 8,      /* dnac_batch_wire_decode failed
                                                 (DZKF v4; every codec status is
                                                 folded into this one class)     */
    DNAC_SHIELDED_VERIFY_ERR_SHAPE = 9,       /* commitment/matrix/eval shape !=
                                                 the pinned aggregate proof shape */
    /* 10 / 11 / 12 are RETIRED as live verdicts (d4.c-3 v4 re-base; comment
     * corrected at d4.d). They are never assigned any more — the checks they
     * named closed STRUCTURALLY when the wire stopped carrying opening points
     * and heights: the height is a compile-time verifier pin (.c:243), priming
     * happens inside dnac_batch_verify (its failures surface as SHAPE/FRI), and
     * a foreign opening coordinate is inexpressible on the v4 wire. The values
     * are kept unassigned rather than reused, so an old log line cannot be
     * misread as a new verdict. */
    DNAC_SHIELDED_VERIFY_ERR_HEIGHT = 10,        /* RETIRED — never assigned */
    DNAC_SHIELDED_VERIFY_ERR_PRIMING = 11,       /* RETIRED — never assigned */
    DNAC_SHIELDED_VERIFY_ERR_OPENING_POINT = 12, /* RETIRED — never assigned */
    DNAC_SHIELDED_VERIFY_ERR_FRI = 13,        /* pinned FRI verify rejected
                                                 (params/height/PoW/openings)     */
    DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS = 14,/* N-chunk AIR constraint check
                                                 rejected (CRIT-1: the ONLY step
                                                 binding publics to the trace)    */
    /* ── S8 Gate 2 (45-public / D=24 / sighash_v5 statement) ── */
    DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION = 15,
                                              /* vctx == NULL, or
                                                 vctx->statement_version !=
                                                 DNAC_SHIELDED_STATEMENT_VERSION.
                                                 The statement shape (public
                                                 count, layout, AIR) is frozen
                                                 per version — a foreign version
                                                 must never be verified against
                                                 THIS shape.                      */
    DNAC_SHIELDED_VERIFY_ERR_BOUNDARY = 16,   /* boundary_in or boundary_out
                                                 outside the frozen B2 range
                                                 [0, 2^63): the two transparent
                                                 legs are signed-magnitude-safe
                                                 amounts, so a value at or above
                                                 2^63 could wrap the balance
                                                 identity in the field.           */
    DNAC_SHIELDED_VERIFY_ERR_ANCHOR = 17      /* num_input == 0 but an anchor lane
                                                 is non-zero. A zero-input
                                                 statement proves NO membership,
                                                 so it must carry the all-zero
                                                 anchor; 0 is never a real tree
                                                 root, so the zero anchor cannot
                                                 be confused with one.            */
} dnac_shielded_verify_status_t;

/**
 * The ONLY ZK statement version this entry knows how to verify. The 45-public
 * layout, the D=24 membership depth and the sighash_v5 preimage are frozen
 * TOGETHER under this number: a proof declaring any other version is rejected
 * rather than checked against the wrong shape.
 */
#define DNAC_SHIELDED_STATEMENT_VERSION 1u

/**
 * @brief The consensus-authoritative binding context for one shielded TX.
 *
 * sighash_v5 binds the FULL execution context, not just the chain id, so the
 * verify entry can no longer take a bare chain_id. Every field here is supplied
 * by the CALLER from consensus-authoritative state (the block's execution
 * context and the ACTIVE domain-registry / runtime ruleset), never parsed out of
 * the transaction and never chosen by the prover:
 *
 *   - ruleset_version + ruleset_hash are the ACTIVE pair the witness is
 *     executing under. A prover that proves against a different ruleset
 *     produces a different sighash_v5 and therefore a different tx_binding, so
 *     the proof simply fails to bind — it cannot select its own rules.
 *   - statement_version MUST be DNAC_SHIELDED_STATEMENT_VERSION (1); anything
 *     else is DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION.
 *   - wire_version (DNAC_TXW3_WIRE_VERSION) and the shielded section version
 *     (DNAC_TXW3_SECT_VERSION) are NOT caller-supplied: the entry pins both
 *     internally, so neither the caller nor the prover can vary them.
 */
typedef struct {
    uint8_t  chain_id[32];      /**< 32-byte chain identifier (anti cross-zone) */
    uint32_t domain_id;         /**< executing domain                           */
    uint32_t pool_id;           /**< executing pool (shielded pool for type 11) */
    uint8_t  tx_type;           /**< transaction type byte                      */
    uint32_t ruleset_version;   /**< ACTIVE ruleset version                     */
    uint32_t statement_version; /**< MUST be DNAC_SHIELDED_STATEMENT_VERSION    */
    uint8_t  ruleset_hash[64];  /**< ACTIVE ruleset hash (registry/runtime)     */
} dnac_shielded_verify_ctx_t;

/**
 * @brief Verify a shielded TX's aggregate STARK proof against the WIRE
 *        statement (Phase-C C2.1 consensus entry).
 *
 * @param sf            The wire shielded fields (dnac_tx_shielded_fields_t,
 *                      transaction.h) INCLUDING the fri_proof blob and the S8
 *                      boundary_in / boundary_out / expiry_height fields.
 * @param vctx          The consensus-authoritative binding context (see
 *                      dnac_shielded_verify_ctx_t). NULL is rejected as
 *                      DNAC_SHIELDED_VERIFY_ERR_STATEMENT_VERSION.
 * @param committed_fee The TX header committed_fee the fee-pool logic reads;
 *                      MUST equal sf->fee (D7.2 — re-enforced here because the
 *                      witness does not run libdna deserialize).
 * @return DNAC_SHIELDED_VERIFY_OK iff EVERY check passes; the first failing
 *         check's distinct code otherwise (fail-close — no partial accept).
 */
dnac_shielded_verify_status_t dnac_shielded_verify_statement(
    const dnac_tx_shielded_fields_t  *sf,
    const dnac_shielded_verify_ctx_t *vctx,
    uint64_t                          committed_fee);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_VERIFY_H */
