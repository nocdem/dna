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
 *   S4a.1 (DONE): the AGGREGATE SCAFFOLD — C1 embedded + reused losslessly
 *     (gather/scatter) + the FORCED `is_nf = [φ==D+1]` phase selector.
 *   S4a.2 (THIS increment): C3 MEMBERSHIP embedded at φ∈[1,D] (level = φ−1),
 *     gated on `[φ∈1..D]·IS_INPUT`. Poseidon MC1/MC2 always-on (inert rows =
 *     valid zero-perm); the pins (BIT bool, ordering, capacity, leaf φ=1
 *     CUR==cm_carry, chaining, root φ=D MC2.out==anchor) fire only when active.
 *     **§3 POSACC init/stop/wrap gating (design red-team F6 double-spend fix):**
 *       φ=1  PURE-INIT  POSACC == bit·2^0    (NEVER reads the φ=0 C1 row);
 *       φ∈[2,D] chain   POSACC == prev.POSACC + bit·2^(φ−1);
 *       inert           (1 − active)·POSACC == 0  (no leak over φ=0 / K-wrap);
 *       φ=D  final      POSACC == pos_carry  (ties the walk to the pos C4 nullifies).
 *     Membership runs iff IS_INPUT (an OUTPUT is a NEW note, inserted by
 *     consensus, not proven-member). anchor is a public (verifier-substituted).
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
 * @brief Honest-prover aggregate trace generation (S4a.1 C1+is_nf; S4a.2
 *        membership). Fills the C1 region (scatter), is_nf/inv_nf, and — for
 *        each INPUT note-block — the C3 membership walk at φ∈[1,D]: `cm_carry`
 *        walked up D levels using `pos`'s LSB-first bits and the block's
 *        siblings. Inert membership rows carry a valid zero-perm (poseidon is
 *        always-on). The nullifier region stays zeroed (RESERVED for S4a.3).
 * @param log_height  trace height = 2^log_height, ∈ [LOG_K, MAX_LOG_HEIGHT].
 * @param value,addr,rcm,roles,pos,nk,ak,num_notes  the C1 note-block inputs.
 * @param memb_siblings  num_notes × CONF_AGG_TREE_DEPTH × CONF_MEMB_LANES sibling
 *                       digests (level-0 first); only INPUT blocks are consumed.
 *                       May be NULL only if there are no INPUT notes.
 * @param anchor_out  the computed common root of the INPUT notes' paths (the
 *                    verifier-substituted anchor). Zeroed if no INPUT notes.
 * @param trace_out   caller buffer of (2^log_height * CONF_AGG_WIDTH) uint64.
 * @return true on success; false on a C1 parameter error OR if two INPUT notes'
 *         paths yield DIFFERENT roots (inconsistent siblings — all inputs must
 *         be members of ONE tree at ONE anchor).
 */
bool conf_action_agg_air_generate(unsigned log_height, const uint64_t *value,
                                  const uint64_t *addr, const uint64_t *rcm,
                                  const uint8_t *roles, const uint64_t *pos,
                                  const uint64_t *nk, const uint64_t *ak,
                                  size_t num_notes,
                                  const uint64_t *memb_siblings,
                                  uint64_t anchor_out[CONF_MEMB_LANES],
                                  uint64_t *trace_out);

/**
 * @brief Evaluate ALL aggregate constraints (S4a.1 C1 + is_nf; S4a.2 membership
 *        with §3 POSACC gating). Membership pins are gated on [φ∈1..D]·IS_INPUT;
 *        the root binds to the public `anchor`.
 * @param trace   2^log_height rows × CONF_AGG_WIDTH canonical columns.
 * @param n_rows  number of rows (= 2^log_height).
 * @param anchor  the public note-tree root (verifier-substituted) the last
 *                membership level (φ=D) of every INPUT block must reach.
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_action_agg_air_eval(const uint64_t *trace, size_t n_rows,
                             const uint64_t anchor[CONF_MEMB_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AGG_AIR_H */
