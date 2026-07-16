/**
 * @file shielded_fri_params.h
 * @brief Consensus-constant FRI/STARK parameters for the shielded pool (S0/C5).
 *
 * EXISTENTIAL SOUNDNESS BACKSTOP. Per dm-c6/parent §3.2 (E2), STARK-constraint +
 * DEEP-FRI soundness is the SOLE barrier against an in-pool mint (the shielded
 * pool has no cleartext value ground-truth). Therefore the FRI parameters that
 * fix the security level MUST be prover-independent consensus constants — a
 * verifier that reads them from the wire lets an attacker down-tune the level
 * (log_blowup=0 → ~0-bit low-degree test) and forge a false proof → mint
 * (parent RT-8 / dm-c5 C5a′).
 *
 * ── Pinned set (grounded, NOT invented) ────────────────────────────────────
 * The shielded proof is is_zk=1 (M3b salted hiding). The grounded production
 * params for a zk proof are Plonky3 `FriParameters::new_benchmark_zk`
 * (fri/src/config.rs:102-113 @ 82cfad73):
 *     log_blowup               = 2
 *     log_final_poly_len       = 0
 *     max_log_arity            = 1   (binary folding)
 *     num_queries              = 100
 *     commit_proof_of_work_bits= 0
 *     query_proof_of_work_bits = 16
 * Conjectured soundness (config.rs:42-43, ethSTARK eprint 2021/582):
 *     log_blowup·num_queries + query_proof_of_work_bits = 2·100 + 16 = 216 bits.
 * Only query_pow counts toward soundness (config.rs:43); commit_pow does NOT
 * (dm-c5 C5b′). 216 ≫ the 100-bit target. These are copied from config.rs, not
 * chosen (KAFADAN YASAK).
 *
 * ── Trace-height pin (dm-c5 C5e) ───────────────────────────────────────────
 * FRI-param pinning is necessary but INSUFFICIENT: the round count / lgmh is a
 * PROOF field bound to the statement only via the largest committed matrix
 * domain height. That height comes from the STARK caller, not the FRI params, so
 * it MUST ALSO be pinned. C1 pins the shielded AIR trace to a FIXED power-of-two
 * physical height H = 1024 = 2^10 (STARK_PROVER_MAX_HEIGHT, stark_prover.h:69 ==
 * SUM_BALANCE_MAX_OUTPUTS, sum_balance.h:83; the 8-in/8-out cap = 19 blocks ×
 * K=32 = 608 ≤ 1024, padded up). Variable note count is carried by IS_REAL
 * padding INSIDE this fixed height.
 *
 * ⚠ is_zk COMMITTED-DOMAIN DOUBLING (red-team S0-H1 fix, was WRONG). The shielded
 * proof is is_zk=1, and the is_zk hiding transform commits the trace/quotient/
 * random matrices at a domain of `base_degree_bits + 1`, NOT the physical
 * base_degree_bits. This is NOT "FRI-internal only" — it is the COMMITTED opening-
 * point domain the verifier reads. Grounded to the REAL Plonky3 is_zk proofs:
 * tools/vectors/conf_root_air_zk.json (`base_degree_bits:3 → degree_bits:4`) and
 * conf_root_air_zk_h16.json (`4 → 5`); the C prover matches (stark_prover_prove.c
 * is_zk path). So a physical H=2^10 shielded trace commits a main-trace domain of
 * log_size == 11 = base(10) + is_zk(1). The verifier pins THAT (== 11) and rejects
 * any other height. Pinning 10 (the physical base) would reject every honest
 * proof and let a smaller H=512 (base 9 → committed 10) trace pass.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_FRI_PARAMS_H
#define DNAC_ZK_SHIELDED_FRI_PARAMS_H

#include <stdbool.h>
#include <stddef.h>

#include "fri_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Pinned scalar values (see file header for grounding to config.rs:102-113). */
#define DNAC_SHIELDED_FRI_LOG_BLOWUP           ((size_t)2)
#define DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN   ((size_t)0)
#define DNAC_SHIELDED_FRI_MAX_LOG_ARITY        ((size_t)1)
#define DNAC_SHIELDED_FRI_NUM_QUERIES          ((size_t)100)
#define DNAC_SHIELDED_FRI_COMMIT_POW_BITS      ((size_t)0)
#define DNAC_SHIELDED_FRI_QUERY_POW_BITS       ((size_t)16)

/* Conjectured soundness bits = log_blowup·num_queries + query_pow (config.rs:43).
 * commit_pow is NOT credited (dm-c5 C5b′). */
#define DNAC_SHIELDED_FRI_SOUNDNESS_BITS       ((size_t)216)

/* Minimum acceptable soundness target (policy floor; the pinned set clears it). */
#define DNAC_SHIELDED_FRI_SOUNDNESS_TARGET     ((size_t)100)

/* is_zk hiding is ON for every shielded proof (M3b salted). */
#define DNAC_SHIELDED_IS_ZK                    ((size_t)1)

/* Pinned PHYSICAL shielded-AIR trace height, log2 (C1 fixed H=1024=2^10). This is
 * the base_degree_bits, NOT what the verifier sees on the wire. */
#define DNAC_SHIELDED_BASE_LOG_HEIGHT          ((size_t)10)

/* Pinned COMMITTED main-trace domain height the verifier reads = base + is_zk
 * doubling (see header). == 11. THIS is the value the height guard compares
 * against; grounded to conf_root_air_zk.json base_degree_bits+1. */
#define DNAC_SHIELDED_COMMITTED_LOG_HEIGHT \
    (DNAC_SHIELDED_BASE_LOG_HEIGHT + DNAC_SHIELDED_IS_ZK)

/**
 * @brief The consensus-constant shielded FRI parameters. The verifier uses THIS,
 *        never the wire-decoded params, for every shielded proof.
 */
const dnac_fri_params_t *dnac_shielded_fri_params(void);

/**
 * @brief Exact field-by-field equality of two param sets (all six scalars).
 *        Used to REJECT a shielded proof whose embedded wire params differ from
 *        the pinned set (tamper detection; the pinned set is what actually
 *        verifies, this makes a mismatch an explicit reject not a silent ignore).
 */
bool dnac_fri_params_eq(const dnac_fri_params_t *a, const dnac_fri_params_t *b);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_FRI_PARAMS_H */
