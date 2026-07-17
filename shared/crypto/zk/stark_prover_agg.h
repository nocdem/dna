/**
 * @file stark_prover_agg.h
 * @brief Dual-mode S4b.4 — pure-C prover for the AGGREGATE Action AIR
 *        (ConfActionAggAir ZK layout, width 1946, is_zk=1, num_qc=8, 43 publics).
 *
 * The aggregate sibling of dnac_action_prover_prove (stark_prover_action.h):
 * the SAME S1→S12 pipeline over the parametric stage library (stark_prover.h),
 * with the aggregate-specific pieces swapped in:
 *
 *   S1  trace     = the 1946-wide ZK trace (C1 scatter + membership walk +
 *                   nullifier sponge + is_zero SELECTOR columns + S4c output
 *                   routing/fee-acc), byte-matching Rust generate_conf_action_agg_trace
 *   S6  quotient  = the aggregate constraint set evaluated domain-wide by
 *                   REUSING dnac_conf_action_agg_fold_air_eval row-by-row (with
 *                   the 43 public values) — ONE emission source prover+verifier
 *   publics       = anchor[4] || num_input || nf_slot[MI][4] || num_output ||
 *                   output_commit[MO][4] || fee || tx_binding[4]  (43, S4c)
 *
 * Draw layout (SmallRng order, D1-B): trace (W+8)·h @0 ‖ codeword 32h ‖
 *   blinding 42h ‖ R 12h  — total (W+94)h = 2040h at W=1946 (only the trace
 *   section grows vs C1; symbolic in A_W so it tracks the width).
 *
 * UNSALTED (M3b leaf-salt hiding deferred to S7/wallet). See stark_prover_action.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_AGG_H
#define DNAC_ZK_STARK_PROVER_AGG_H

#include <stddef.h>
#include <stdint.h>

#include "conf_action_agg_fold.h"
#include "conf_action_air.h"
#include "fri_verifier.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Total SmallRng draws for an is_zk=1 aggregate instance: trace (W+8)h ‖
 *  codeword 32h ‖ blinding 42h ‖ R 12h = (W+94)h. W = CONF_AGGZK_WIDTH = 1946
 *  (S4c), so 2040h; symbolic so it tracks any future width change. */
#define DNAC_AGG_PROVER_TOTAL_DRAWS(height) \
    ((size_t)(CONF_AGGZK_WIDTH + 94) * (size_t)(height))

/**
 * An aggregate prove request — one shielded action's notes + the INPUT notes'
 * Merkle-membership siblings. Same conserving/range preconditions as the C1
 * instance; INPUT notes are addressed to Poseidon2(ak,nk) (condition-3) and must
 * be members of ONE tree at ONE anchor (the generator computes it).
 */
typedef struct {
    const uint64_t *value;      /* num_notes note values (< 2^52) */
    const uint64_t *addr;       /* num_notes * 4 recipient addresses */
    const uint64_t *rcm;        /* num_notes * 2 commitment randomness */
    const uint8_t  *roles;      /* num_notes role tags (CONF_ACTION_ROLE_*) */
    const uint64_t *pos;        /* num_notes tree positions */
    const uint64_t *nk;         /* num_notes nullifier-key components */
    const uint64_t *ak;         /* num_notes spend-authority keys */
    size_t          num_notes;  /* real note-blocks; num_notes+1 <= H/K */
    const uint64_t *memb_siblings; /* num_notes * D * 4 (INPUT blocks consumed) */
    const uint64_t *tx_binding; /* 4 canonical lanes; FS-observed statement binding.
                                 * Production = conf_txbind_map(sighash_v4) (dnac S5
                                 * sighash → 4 lanes, wired at S6). NULL => zero. */
    unsigned        log_height; /* height = 2^log_height, in [LOG_K, 10] */
    const uint64_t *draws;
    size_t          num_draws;  /* must equal DNAC_AGG_PROVER_TOTAL_DRAWS */
} dnac_agg_prover_instance_t;

/** Opaque produced proof; free with dnac_agg_prover_proof_free. */
typedef struct dnac_agg_prover_proof_s dnac_agg_prover_proof_t;

/**
 * Prove an aggregate instance and SELF-VERIFY (priming with the 43 publics +
 * zeta cross-check + dnac_fri_verify == DNAC_FRI_OK + the N-chunk constraint
 * check == OK). Fail-close on any inconsistency.
 */
dnac_prover_status_t dnac_agg_prover_prove(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof);

/** Re-verify (priming + FRI + N-chunk constraint check). */
dnac_fri_status_t dnac_agg_prover_proof_verify(const dnac_agg_prover_proof_t *p);

/** Cross-check accessors (byte-match vs the reference Plonky3 proof). */
void dnac_agg_prover_proof_zeta(const dnac_agg_prover_proof_t *p,
                                gold_fp2_t *zeta, gold_fp2_t *zeta_next);
void dnac_agg_prover_proof_roots(const dnac_agg_prover_proof_t *p,
                                 uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                                 uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                                 uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]);
const gold_fp2_t *dnac_agg_prover_proof_final_poly(
    const dnac_agg_prover_proof_t *p, size_t *out_len);
/** The computed public values (anchor[4] || num_input || nf_slot[M][4]). */
const gold_fp_t *dnac_agg_prover_proof_publics(const dnac_agg_prover_proof_t *p,
                                               size_t *out_len);

void dnac_agg_prover_proof_free(dnac_agg_prover_proof_t *p);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_AGG_H */
