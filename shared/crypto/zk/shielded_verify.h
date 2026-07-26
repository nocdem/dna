/**
 * @file shielded_verify.h
 * @brief Phase-C C2.1 — the CONSENSUS shielded-statement verify entry.
 *
 * dnac_shielded_verify_statement() is the single function a witness calls to
 * decide whether a DNAC_TX_SHIELDED (type 11) transaction's aggregate STARK
 * proof is valid FOR THE STATEMENT ON THE WIRE. It is the consensus analog of
 * the prover-side dnac_agg_prover_wire_selfcheck_shielded
 * (stark_prover_agg.c:1135), which primes from the prover's OWN struct and
 * whose comment defers "the wire-recompute of the publics themselves" to
 * Phase-C — this module IS that wire-recompute (C2 design v2 §4.2).
 *
 * Verify chain (every branch fail-closes; C2 design v2 §0-§2):
 *   1. Wire canonicalization: counts in range, unused nf/output slots zero
 *      (DET-S5-3), every lane canonical < p (G-DET-5), sf->fee ==
 *      committed_fee (G-SEC-6, D7.2).
 *   2. Statement binding (G-SEC-3, closes H3): sighash_v4 is recomputed from
 *      the wire fields via the LINKED libdna symbol dnac_tx_shielded_sighash
 *      (serialize.c:673-707 — single source, G-DET-2; re-implementation
 *      forbidden), mapped through conf_txbind_map (conf_txbind.h:55), and
 *      REQUIRED to equal the wire tx_binding lanes.
 *   3. The 43 public values (CONF_AGGZK_PUB_* layout, conf_action_agg_fold.h:
 *      115-127) are recomputed FROM THE WIRE — never read from the proof.
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
 * Determinism (G-DET-1): the verdict is a PURE function of (sf bytes,
 * chain_id, committed_fee, compile-time pinned constants). No wall clock, no
 * map iteration, no RNG, no node-local state.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_VERIFY_H
#define DNAC_ZK_SHIELDED_VERIFY_H

#include <stdint.h>

#include "dnac/transaction.h" /* dnac_tx_shielded_fields_t + dnac_tx_shielded_sighash */

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
    DNAC_SHIELDED_VERIFY_ERR_NULL = 1,        /* NULL sf/chain_id/blob            */
    DNAC_SHIELDED_VERIFY_ERR_OVERSIZE = 2,    /* blob len > wire cap (fail-close,
                                                 never crash/OOM — design §0)     */
    DNAC_SHIELDED_VERIFY_ERR_COUNT = 3,       /* num_input/num_output out of range */
    DNAC_SHIELDED_VERIFY_ERR_SLOT_NONZERO = 4,/* unused nf/output slot != 0
                                                 (DET-S5-3 canonical encoding)    */
    DNAC_SHIELDED_VERIFY_ERR_NONCANONICAL = 5,/* a wire lane >= Goldilocks p
                                                 (G-DET-5)                        */
    DNAC_SHIELDED_VERIFY_ERR_FEE = 6,         /* sf->fee != committed_fee
                                                 (G-SEC-6, D7.2 single fee)       */
    DNAC_SHIELDED_VERIFY_ERR_TXBIND = 7,      /* conf_txbind_map(sighash_v4) !=
                                                 wire tx_binding (G-SEC-3)        */
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
    DNAC_SHIELDED_VERIFY_ERR_CONSTRAINTS = 14 /* N-chunk AIR constraint check
                                                 rejected (CRIT-1: the ONLY step
                                                 binding publics to the trace)    */
} dnac_shielded_verify_status_t;

/**
 * @brief Verify a shielded TX's aggregate STARK proof against the WIRE
 *        statement (Phase-C C2.1 consensus entry).
 *
 * @param sf            The wire shielded fields (dnac_tx_shielded_fields_t,
 *                      transaction.h:95-105) INCLUDING the fri_proof blob.
 * @param chain_id      32-byte chain identifier (bound into sighash_v4 —
 *                      anti cross-zone replay, G6).
 * @param committed_fee The TX header committed_fee@74 the fee-pool logic reads;
 *                      MUST equal sf->fee (D7.2 — re-enforced here because the
 *                      witness does not run libdna deserialize).
 * @return DNAC_SHIELDED_VERIFY_OK iff EVERY check passes; the first failing
 *         check's distinct code otherwise (fail-close — no partial accept).
 */
dnac_shielded_verify_status_t dnac_shielded_verify_statement(
    const dnac_tx_shielded_fields_t *sf,
    const uint8_t                    chain_id[32],
    uint64_t                         committed_fee);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_VERIFY_H */
