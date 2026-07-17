/**
 * @file conf_action_agg_air.h
 * @brief Dual-mode S4 — AGGREGATE Action AIR (C1 ⊕ C3 ⊕ C4), is_zk=0 gate.
 *
 * The full shielded-spend AIR: the C1 balance/note-commitment/spend-auth AIR
 * (conf_action_air, WIDTH 813) with the C3 Merkle-membership and C4 nullifier
 * sub-proofs embedded as PHASES inside each K=32 note-block, consuming C1's
 * frozen carries (cm_carry / pos_carry / nk_carry). Built INCREMENTALLY
 * (S4a.1 → S4a.f) exactly like C1 was (S1a → cond3).
 *
 * Design: dnac/docs/plans/2026-07-17-dm-s4-aggregate-design.md (v2, DESIGN
 * red-team PASSED, 0 CRITICAL). The cross-region binding that REFUTED all 5
 * dm-c2 approaches is closed by C1's in-row note-commitment (cm⇔value) + the
 * FORCED phase-counter (φ) that replaces dm-c2's fatal FREE `same_note`.
 *
 * ── Aggregation strategy (zero-risk C1 reuse) ───────────────────────────────
 * The C1 columns occupy [0, CONF_ACTION_WIDTH) of every 1915-wide row. generate
 * fills them via a SCATTER from a standalone conf_action_air_generate (813-wide
 * scratch); eval GATHERS them back and calls the UNMODIFIED conf_action_air_eval
 * (C1 stays byte-identical, its test the safety net), then adds the phase
 * constraints reading the wide trace directly.
 *
 * ── Phase schedule (φ ∈ {0..K−1}, forced by C1's E1/E2/E3/E13) ───────────────
 *   φ = 0        : C1 note-commitment + balance + spend-auth + carry seed
 *   φ ∈ [1, D]   : C3 membership level φ (leaf φ=1 CUR==cm_carry; root φ=D==anchor)
 *   φ = D+1      : C4 nullifier (cm/pos/nk == frozen carries; nf public)
 *   φ ∈ [D+2, K) : inert
 * D = CONF_AGG_TREE_DEPTH is a COMPILE-TIME consensus constant (DET-S4-2).
 *
 * ── Build status ────────────────────────────────────────────────────────────
 *   S4a.1 (THIS increment): the AGGREGATE SCAFFOLD — C1 embedded + reused
 *     losslessly (gather/scatter) + the FORCED `is_nf = [φ==D+1]` phase selector
 *     (is_zero(φ−(D+1)), the red-team-critical "phase selectors must be forced"
 *     property, same gadget as C1's phi_is0). Membership + nullifier regions are
 *     RESERVED (zeroed, unconstrained) — filled by S4a.2 (membership + POSACC
 *     gating) and S4a.3 (nullifier + exact-count).
 *   S4a.2: C3 membership phases + the §3 POSACC init/stop/wrap gating (the
 *     design red-team F6 double-spend fix).
 *   S4a.3: C4 nullifier phase + nullifier EXACT-COUNT bijective bind + publics.
 *   S4b-e: width-cap bump, Rust oracle + num_qc, fp2 fold, pure-C prover
 *     byte-match (all S1e precedent). S4f: 10+ agent red-team.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ACTION_AGG_AIR_H
#define DNAC_ZK_CONF_ACTION_AGG_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "conf_action_air.h"     /* C1 region (WIDTH 813) + params */
#include "conf_membership_air.h" /* CONF_MEMB_WIDTH (370) */
#include "conf_nullifier_air.h"  /* CONF_NF_WIDTH (730) */

#ifdef __cplusplus
extern "C" {
#endif

/* Tree depth D — COMPILE-TIME consensus constant (DET-S4-2; ≤26 to fit K=32).
 * Small value for the construction-gate KATs; the production depth is pinned at
 * S6 with the real note-commitment tree. */
#define CONF_AGG_TREE_DEPTH 4

/* ── Column layout ──────────────────────────────────────────────────────────
 * [0, 813)          C1 region (conf_action_air, offsets unchanged)
 * [813, 1183)       C3 membership region (conf_membership offsets, +CONF_AGG_MEMB_OFF)
 * [1183, 1913)      C4 nullifier region  (conf_nullifier offsets, +CONF_AGG_NF_OFF)
 * 1913              IS_NF   = [φ==D+1] indicator (forced phase selector)
 * 1914              INV_NF  = is_zero(φ−(D+1)) witness
 */
#define CONF_AGG_C1_OFF    0
#define CONF_AGG_MEMB_OFF  CONF_ACTION_WIDTH                       /* 813 */
#define CONF_AGG_NF_OFF    (CONF_AGG_MEMB_OFF + CONF_MEMB_WIDTH)   /* 1183 */
#define CONF_AGG_ISNF_OFF  (CONF_AGG_NF_OFF + CONF_NF_WIDTH)       /* 1913 */
#define CONF_AGG_INVNF_OFF (CONF_AGG_ISNF_OFF + 1)                 /* 1914 */
#define CONF_AGG_WIDTH     (CONF_AGG_INVNF_OFF + 1)                /* 1915 */

/**
 * @brief Honest-prover aggregate trace generation (S4a.1: C1 region + is_nf).
 *        Fills the C1 region via conf_action_air_generate (scatter) and the
 *        forced is_nf/inv_nf phase-selector columns; leaves the membership and
 *        nullifier regions zeroed (RESERVED for S4a.2/3). Same C1 note params as
 *        conf_action_air_generate.
 * @param log_height  trace height = 2^log_height, ∈ [LOG_K, MAX_LOG_HEIGHT].
 * @param value,addr,rcm,roles,pos,nk,ak,num_notes  the C1 note-block inputs.
 * @param trace_out   caller buffer of (2^log_height * CONF_AGG_WIDTH) uint64.
 * @return true on success; false on a C1 parameter error.
 */
bool conf_action_agg_air_generate(unsigned log_height, const uint64_t *value,
                                  const uint64_t *addr, const uint64_t *rcm,
                                  const uint8_t *roles, const uint64_t *pos,
                                  const uint64_t *nk, const uint64_t *ak,
                                  size_t num_notes, uint64_t *trace_out);

/**
 * @brief Evaluate ALL aggregate constraints (S4a.1: C1 constraints via the
 *        gathered C1 region + the is_nf is_zero phase-selector constraints).
 * @param trace   2^log_height rows × CONF_AGG_WIDTH canonical columns.
 * @param n_rows  number of rows (= 2^log_height).
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_action_agg_air_eval(const uint64_t *trace, size_t n_rows);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AGG_AIR_H */
