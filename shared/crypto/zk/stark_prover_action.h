/**
 * @file stark_prover_action.h
 * @brief Dual-mode S1e.4 — pure-C prover for the C1 Action AIR
 *        (conf_action layout, width 813, is_zk=1, num_qc=8, 0 publics).
 *
 * The conf-AIR sibling of `dnac_conf_prover_prove` (stark_prover_conf.h): same
 * S1→S12 pipeline over the SAME parametric stage library (stark_prover.h), with
 * the C1-specific pieces swapped in:
 *
 *   S1  trace     = conf_action_air_generate (the BUILT construction-gate
 *                   generator, WIDTH 813)
 *   S6  quotient  = the C1 constraint set evaluated domain-wide by REUSING
 *                   dnac_conf_action_fold_air_eval (conf_action_fold.c)
 *                   row-by-row — ONE emission source for prover + verifier
 *   publics       = NONE (the as-built C1 reads no eval publics; balance
 *                   conservation is the internal last-row BAL=0 invariant)
 *
 * Shape (grounded, Plonky3 82cfad73; empirically confirmed by the oracle's
 * measured num_qc=8 STOP gate on conf_action_air_zk.json):
 *   base_db = log2(height); degree_bits = base_db+1; log_max_height = base_db+3
 *   num_qc = 8 (log_num_qc = 2; degree-3 AIR at is_zk=1) — HEIGHT-INDEPENDENT
 *   q_size = 2^(degree_bits + log_num_qc) = 8·height = lde_h
 *   next_step = 2^(is_zk+log_num_qc) = 8
 *
 * Draws (SmallRng consumption order, D1-B; hiding not soundness) — the
 * codeword/blinding/R lengths match the conf_root prover (same num_qc/C_CW);
 * only the trace section grows with the wider AIR:
 *   trace (813+8)·h = 821h @0 ‖ codeword 8·4·h = 32h @821h ‖
 *   blinding 7·6·h = 42h @853h ‖ R 2h·6 = 12h @895h  — total 907h.
 *
 * UNSALTED (M3b leaf-salt hiding is deferred to S7/wallet): this proves the
 * KAT-stream byte-match vs the REAL Plonky3 proof + self-verify. The confidential
 * amounts are hidden by the is_zk codeword blinding; leaf-salt hiding at the FRI
 * query openings is a wallet-side hardening tracked separately.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_STARK_PROVER_ACTION_H
#define DNAC_ZK_STARK_PROVER_ACTION_H

#include <stddef.h>
#include <stdint.h>

#include "conf_action_air.h"
#include "conf_action_fold.h"
#include "fri_verifier.h"
#include "stark_prover.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Total SmallRng draws for an is_zk=1 C1-Action-AIR instance (width 813). */
#define DNAC_ACTION_PROVER_TOTAL_DRAWS(height) ((size_t)907 * (size_t)(height))

/**
 * A C1 Action prove request — one shielded action's notes. The signed balance
 * MUST conserve (Σ INPUT − Σ OUTPUT − Σ FEE = 0) and every value < 2^52 (the
 * conf_action_air_generate honest-prover preconditions). INPUT notes are
 * addressed to Poseidon2(ak, nk) (condition-3); OUTPUT/FEE use `addr`.
 * `draws` = the SmallRng-order stream (KAT: oracle dump; production: OS entropy).
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
    unsigned        log_height; /* height = 2^log_height, in [LOG_K, 10] */
    const uint64_t *draws;
    size_t          num_draws;  /* must equal DNAC_ACTION_PROVER_TOTAL_DRAWS */
} dnac_action_prover_instance_t;

/** Opaque produced proof; free with dnac_action_prover_proof_free. */
typedef struct dnac_action_prover_proof_s dnac_action_prover_proof_t;

/**
 * Prove a C1-Action-AIR instance and SELF-VERIFY (priming with 0 publics + zeta
 * cross-check + dnac_fri_verify == DNAC_FRI_OK + the N-chunk constraint check
 * dnac_stark_verify_constraints_nchunk == OK). Fail-close on any inconsistency.
 */
dnac_prover_status_t dnac_action_prover_prove(
    const dnac_action_prover_instance_t *inst,
    dnac_action_prover_proof_t         **out_proof);

/**
 * PRODUCTION entry (G2): fills the is_zk codeword/blinding stream (907h) from OS
 * entropy via dnac_zk_fill_draws (rejection-sampled canonical Goldilocks,
 * fail-close), then proves. `draws`/`num_draws` are IGNORED (filled internally).
 * Returns DNAC_PROVER_ERR_PARAM on invalid shape or entropy failure (fail-close).
 */
dnac_prover_status_t dnac_action_prover_prove_production(
    const dnac_action_prover_instance_t *inst,
    dnac_action_prover_proof_t         **out_proof);

/** Re-verify (priming + FRI + N-chunk constraint check). */
dnac_fri_status_t dnac_action_prover_proof_verify(const dnac_action_prover_proof_t *p);

/** Cross-check accessors (byte-match vs the reference Plonky3 proof). */
void dnac_action_prover_proof_zeta(const dnac_action_prover_proof_t *p,
                                   gold_fp2_t *zeta, gold_fp2_t *zeta_next);
void dnac_action_prover_proof_roots(const dnac_action_prover_proof_t *p,
                                    uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                                    uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                                    uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]);
const gold_fp2_t *dnac_action_prover_proof_final_poly(
    const dnac_action_prover_proof_t *p, size_t *out_len);

void dnac_action_prover_proof_free(dnac_action_prover_proof_t *p);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_STARK_PROVER_ACTION_H */
