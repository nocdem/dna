/**
 * @file conf_action_air.h
 * @brief Dual-mode shielded Action AIR (C1) — phase-block balance + note-commitment
 *        binding. Built INCREMENTALLY (S1a → S1f); is_zk=0 construction-gate style.
 *
 * This is the C1 component of the dual-mode design
 * (dnac/docs/plans/2026-07-16-dm-c1-balance-air-design.md §4d): the forced-counter
 * (φ) + freeze-carry cross-region binding that the 13-round red-team converged to —
 * NO LogUp, NO preprocessed columns, only forced-counter + freeze + single-row
 * note-commitment, all grounded to B1 (conf_balance_air / conf_commit_air /
 * conf_root_fold), all degree ≤ 2.
 *
 * ── Build status ───────────────────────────────────────────────────────────
 *   S1a: the FORCED PHASE COUNTER skeleton — prover-independent intra-block
 *   positioning every later binding rides on.
 *     columns: φ, φ-bits[LOG_K], w (wrap indicator), inv (is_zero witness).
 *     constraints (all degree ≤ 2):
 *       E1  range gate     φ = Σ b_i·2^i, each b_i²=b_i           ⇒ φ ∈ {0..K−1}
 *       E2  wrap indicator is_zero(φ−(K−1)): (φ−(K−1))·inv = 1−w,
 *                          (φ−(K−1))·w = 0, w²=w                  ⇒ w=1 ⟺ φ=K−1
 *       E3  forced counter (1−w_prev)·(φ−φ_prev−1)=0 [climb] AND
 *                          w_prev·φ = 0 [reset]                   ⇒ φ FORCED every row
 *       E13 φ anchor       is_first_row · φ = 0                   ⇒ φ[0]=0
 *   S1b (THIS increment): the FREEZE-CARRY binding — each note-block's cm is
 *   loaded at its φ=0 row and held constant block-wide, prover-independently
 *   (grounded to conf_root_fold.c:281-292's gated frozen-accumulator).
 *     columns: IS_REAL (per-block real/dummy), cm_output[4] (block note-
 *              commitment at φ=0; a free witness here, bound to the S0 note_commit
 *              sponge in S1c), cm_carry[4] (the frozen carry).
 *     constraints (all degree ≤ 2, w_prev = local wrap gates the transition):
 *       E6  block-const   (1−w_prev)·(IS_REAL−IS_REAL_prev)=0, IS_REAL²=IS_REAL
 *                                                               ⇒ real/dummy const per block
 *       E7  dummy-last    is_last_row · IS_REAL = 0             ⇒ last block dummy (with E6)
 *       PZ  padding-zero  (1−IS_REAL)·cm_carry_j=0, (1−IS_REAL)·cm_output_j=0
 *       E8′ block-0 init  is_first_row·IS_REAL·(cm_carry_j−cm_output_j)=0
 *       E4  freeze        (1−w_prev)·(cm_carry_j−cm_carry_prev_j)=0   [hold block-wide]
 *       E11 wrap-load     w_prev·(cm_carry_j−cm_output_j)=0           [seed next block]
 *     ⇒ at EVERY row, cm_carry == that block's φ=0 cm_output (in-trace same-row
 *       binding like B1 SEC-2; the cross-region read E5 lands in S2 with C3).
 *   Later increments EXTEND this same trace (one row = one shared witness):
 *     S1c single-row note-commitment (E9′, binds cm_output to the S0 note_commit
 *     sponge over value/addr_pub/rcm), S1d balance once-per-block (E10′/E14) +
 *     boundary public-bind + role selectors per block (E17) + nk/pos/addr carries
 *     (E15), S1e constraint-eval fold + degree/num_qc, S1f prover + self-verify.
 *
 * ── Block structure ────────────────────────────────────────────────────────
 * K = 32 rows per note-block (power of two so 2^k tiling + the E7 dummy-last hold;
 * dm-c1 §4d.7 E13). Trace height H = 2^log_height, log_height ≥ LOG_K, so H is an
 * exact multiple of K; φ runs 0..K−1 repeatedly. The wrap H−1→0 is is_transition-
 * exempt (stark_constraints.c:41 / the B1 eval treats row 0 as first-row-init, not
 * a transition target), so the final block is a DUMMY by construction (E7).
 *
 * Grounding: B1 conf_balance_air (selector/booleanity/range/accumulator + first-
 * row-init/transition/last-row equalities), conf_root_fold.c:281-292 (frozen-
 * accumulator row-0 seed, used from S1b). Determinism: pure function of the
 * witness; canonical cells; no map iteration / wall-clock / rand.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ACTION_AIR_H
#define DNAC_ZK_CONF_ACTION_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Phase-block size K = 32 (dm-c1 §4d.7 E13: power of two). */
#define CONF_ACTION_K       32
/* log2(K); φ decomposes into this many bits (E1). */
#define CONF_ACTION_LOG_K   5
/* note-commitment digest width (lanes) — matches S0 note_commit NOTE_COMMIT_LANES. */
#define CONF_ACTION_CM_LANES 4

/* ── Column layout (S1a+S1b; grows in later increments) ─────────────────────
 * Leads with the phase-counter block, then the freeze-carry block; the B1
 * balance/selector block and the note-commitment sponge are appended by S1c-S1d. */
#define CONF_ACTION_PHI_OFF     0                                     /* φ */
#define CONF_ACTION_PHIBITS_OFF (CONF_ACTION_PHI_OFF + 1)             /* [1, 1+LOG_K) */
#define CONF_ACTION_W_OFF       (CONF_ACTION_PHIBITS_OFF + CONF_ACTION_LOG_K) /* wrap ind. */
#define CONF_ACTION_INV_OFF     (CONF_ACTION_W_OFF + 1)               /* is_zero witness */
/* ── S1b freeze-carry block ── */
#define CONF_ACTION_ISREAL_OFF  (CONF_ACTION_INV_OFF + 1)            /* per-block real/dummy */
#define CONF_ACTION_CMOUT_OFF   (CONF_ACTION_ISREAL_OFF + 1)         /* cm_output[4] (φ=0 note cm) */
#define CONF_ACTION_CMCARRY_OFF (CONF_ACTION_CMOUT_OFF + CONF_ACTION_CM_LANES) /* cm_carry[4] frozen */
#define CONF_ACTION_WIDTH       (CONF_ACTION_CMCARRY_OFF + CONF_ACTION_CM_LANES) /* S1b WIDTH = 17 */

/** Max log2(height). H = 2^log_height, log_height ∈ [LOG_K, this]. The shielded
 *  cap is H = 1024 = 2^10 (dm-c1 §4d.8; STARK_PROVER_MAX_HEIGHT). */
#define CONF_ACTION_MIN_LOG_HEIGHT CONF_ACTION_LOG_K
#define CONF_ACTION_MAX_LOG_HEIGHT 10

/**
 * @brief Honest-prover trace generation for the S1a+S1b skeleton.
 *        Fills the phase counter (φ cycling 0..K−1, bits, w, inv) and the
 *        freeze-carry block: the first `num_notes` K-row blocks are REAL, each
 *        carrying commitment `cm[i][0..CM_LANES)`; remaining blocks (incl. the
 *        mandatory dummy-last, E7) are dummy (IS_REAL=0, carry 0). cm_output is
 *        written at each real block's φ=0 row and cm_carry is frozen block-wide.
 * @param log_height  trace height = 2^log_height, ∈ [LOG_K, MAX_LOG_HEIGHT].
 * @param cm          num_notes × CONF_ACTION_CM_LANES canonical commitments.
 * @param num_notes   number of REAL note-blocks; MUST be ≤ (H/K − 1) so the last
 *                    block is dummy (E7). 0 is allowed (all-dummy trace).
 * @param trace_out   caller buffer of (2^log_height * CONF_ACTION_WIDTH) uint64.
 * @return true on success; false on a parameter error.
 */
bool conf_action_air_generate(unsigned log_height, const uint64_t *cm,
                              size_t num_notes, uint64_t *trace_out);

/**
 * @brief Evaluate ALL S1a constraints (E1/E2/E3/E13) over a trace.
 * @param trace   2^log_height rows × CONF_ACTION_WIDTH canonical columns.
 * @param n_rows  number of rows (= 2^log_height).
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_action_air_eval(const uint64_t *trace, size_t n_rows);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AIR_H */
