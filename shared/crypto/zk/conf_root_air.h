/**
 * @file conf_root_air.h
 * @brief Confidential COMMITMENT-SET-ROOT accumulator AIR (B1 Stage-1, is_zk=0).
 *
 * Increment 3 (final) of the B1 Stage-1 build: binds the SET of value commitments
 * {c_0..c_{N-1}, c_claimed, c_fee} to a single `commitment_root` public, so the
 * proof commits to exactly the ordered set the verifier independently recomputes.
 * Composes conf_commit_air (balance + VC) with a running commitment accumulator.
 *
 * ── Accumulator = capacity-IV sponge fold (the red-team-PINNED sound choice;
 *    TruncatedPermutation<2,4,8> was REJECTED — zero-capacity, no domain sep) ──
 * Per row r, fold this row's commitment c_r into the running digest:
 *     cacc_r = is_real_r ? W(cacc_{r-1}, c_r) : cacc_{r-1}     (is_real-gated FREEZE)
 * where W is a WIDTH-8 / RATE-4 PaddingFreeSponge seeded with DOMSEP_ACC in the
 * capacity, absorbing the 8-element message (cacc_prev ‖ c_r) as TWO rate-4 blocks
 * (2 Poseidon2 permutations, so the 256-bit chaining keeps real capacity):
 *     init  : state = [0,0,0,0 | DOMSEP_ACC, 0, 0, 0]
 *     block1: state[0..4] = cacc_prev ; permute        → s1   (CA1 block)
 *     block2: state[0..4] = c_r       ; permute        → s2   (CA2 block, capacity from s1)
 *     squeeze: W = s2[0..4]
 * cacc_{-1} = [0,0,0,0]. On padding rows the CA1/CA2 blocks are still VALID
 * permutations (so their poseidon2 constraints hold) but cacc FREEZES (gated), so
 * padding cannot inject a commitment. At the physical last row cacc == the folded
 * digest of exactly the N+2 real commitments, bound to `commitment_root`.
 *
 * ── Combined layout (WIDTH = 614) ─────────────────────────────────────────
 *   [ COMMIT : 250 ]  conf_commit_air row (balance 70 + VC 180)
 *   [ CA1    : 180 ]  first fold permutation (absorb cacc_prev)
 *   [ CA2    : 180 ]  second fold permutation (absorb c_r)
 *   [ CACC   : 4   ]  running commitment digest
 *
 * ── Composition constraints (on top of conf_commit + 2× poseidon2) ─────────
 *   CA1.inputs[0..4] == cacc_{r-1} (prev row; [0,0,0,0] at row 0)
 *   CA1.inputs[4] == DOMSEP_ACC ; CA1.inputs[5..8] == 0
 *   CA2.inputs[0..4] == c_r (this row's VC commitment)
 *   CA2.inputs[4..8] == CA1.output[4..8]                 (capacity carry)
 *   cacc_r == is_real_r · CA2.output[0..4] + (1 − is_real_r) · cacc_{r-1}   (gated)
 *   last physical row: cacc == commitment_root (public; verifier recompute).
 *
 * Grounding: conf_commit (SEC-2 constructed), poseidon2 (byte-matched, FP1c),
 * DOMSEP_ACC verified = SHA3-512("DNAC commitment-accumulator v1")[0:8] BE.
 * Validated by CONSTRUCTION + a mini-red-team (order-forgery, root-mismatch,
 * padding-inject, gating-bypass, ACC_IV collision).
 *
 * ⚠ The capacity-IV sponge WRAPPER (init override) is DNAC-original composition,
 * not a stock Plonky3 sponge; a Plonky3-sponge oracle byte-match is the grounding
 * follow-on (design v3.1 §2 caveat). The permutation itself IS byte-matched.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ROOT_AIR_H
#define DNAC_ZK_CONF_ROOT_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "conf_commit_air.h"
#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Accumulator domain separator = SHA3-512("DNAC commitment-accumulator v1")[0:8]
 * BE (verified < p, ≠ DOMSEP_VAL). */
#define CONF_ROOT_DOMSEP_ACC ((uint64_t)0x71ad771d32611915ULL)

#define CONF_ROOT_COMMIT_OFF 0
#define CONF_ROOT_CA1_OFF    CONF_COMMIT_WIDTH                       /* 250 */
#define CONF_ROOT_CA2_OFF    (CONF_ROOT_CA1_OFF + P2AIR_NUM_COLS)    /* 430 */
#define CONF_ROOT_CACC_OFF   (CONF_ROOT_CA2_OFF + P2AIR_NUM_COLS)    /* 610 */
#define CONF_ROOT_WIDTH      (CONF_ROOT_CACC_OFF + CONF_COMMIT_C_LANES) /* 614 */

/**
 * @brief Honest-prover combined-trace generation. Signature mirrors
 *        conf_commit_air_generate; also writes `commitment_root` out.
 * @param root_out  the folded commitment-set root (CONF_COMMIT_C_LANES lanes).
 */
bool conf_root_air_generate(const uint64_t *outputs, size_t n_out,
                            uint64_t claimed, uint64_t fee,
                            const uint64_t *blind, unsigned log_height,
                            uint64_t *trace_out,
                            uint64_t root_out[CONF_COMMIT_C_LANES]);

/**
 * @brief Evaluate ALL combined constraints, binding the last-row cacc to
 *        `commitment_root`.
 * @return number of violated constraints; 0 == valid witness for this root.
 */
int conf_root_air_eval(const uint64_t *trace, size_t n_rows,
                       const uint64_t commitment_root[CONF_COMMIT_C_LANES]);

/**
 * @brief Independent verifier recompute of `commitment_root` from an ordered
 *        commitment set (the same capacity-IV sponge fold).
 * @param c_list  count × CONF_COMMIT_C_LANES commitments, in canonical order.
 */
void conf_root_air_recompute_root(const uint64_t *c_list, size_t count,
                                  uint64_t root_out[CONF_COMMIT_C_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ROOT_AIR_H */
