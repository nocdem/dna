/**
 * @file conf_membership_air.h
 * @brief Dual-mode C3 — Poseidon2 Merkle-path membership AIR (is_zk=0 gate).
 *
 * Proves a note commitment `cm` is a leaf of the note-commitment tree at a recent
 * `anchor` (dm-c3). One of the C1 phase-block SUB-PROOFS: in the full circuit the
 * leaf and position come from the C1 frozen carries (cm_carry / pos_carry, S1b);
 * here they are standalone inputs so the path-verification logic is proven by
 * construction on its own, then composed at S4.
 *
 * ── Construction (grounded) ─────────────────────────────────────────────────
 * Tree walk (adopt merkle_smt.h:28-30 order, SHA3→Poseidon2): index bits
 * LSB-first, bit i selects at level i; sibling level-0 first. Per level i:
 *     (left, right) = bit_i==0 ? (cur_i, sib_i) : (sib_i, cur_i)
 *     cur_{i+1}     = note_merkle_compress(left, right)   [S0, capacity-preserving]
 * The compress is the S0 PaddingFreeSponge<8,4,4> over (left‖right) = TWO
 * poseidon2 permutations (MC1 absorbs left with zero capacity; MC2 absorbs right
 * with MC1's capacity carry; digest = MC2.out[0..4]) — dm-c3 F1: a capacity-
 * preserving compress (CR 2^128), NOT a zero-capacity TruncatedPermutation.
 *
 * ── Per-level row columns (WIDTH = 370) ─────────────────────────────────────
 *   [ CUR   : 4   ]  current hash entering level i (cur_0 = leaf)
 *   [ SIB   : 4   ]  sibling at level i (witness)
 *   [ BIT   : 1   ]  direction bit (the ONE cell — dm-c3 F2 — used for BOTH the
 *                    walk ordering AND the position recomposition)
 *   [ MC1   : 180 ]  poseidon2 block 1 (absorbs left, zero capacity)
 *   [ MC2   : 180 ]  poseidon2 block 2 (absorbs right, MC1 capacity carry)
 *   [ POSACC: 1   ]  running Σ bit_j·2^j (F3 accumulator; final == pos)
 *
 * ── Constraints (all degree ≤ 2) ────────────────────────────────────────────
 *   BIT boolean; ordering  MC1.in[j] = cur_j + bit·(sib_j − cur_j)  (left),
 *                          MC2.in[j] = sib_j + bit·(cur_j − sib_j)  (right);
 *   compress pins  MC1.in[4..8]=0, MC2.in[4..8]=MC1.out[4..8] (capacity carry),
 *                  poseidon2_air_eval(MC1)=poseidon2_air_eval(MC2)=0;
 *   chaining  next.CUR == this.MC2.out[0..4] (cur_{i+1});
 *   level-0  CUR == leaf (public / C1 carry);
 *   root  last level MC2.out[0..4] == anchor (public, verifier-substituted);
 *   POSACC  row0 = bit_0; row i = POSACC_{i-1} + bit_i·2^i (verifier-known 2^i,
 *           F3); final == pos ⇒ walk position == the pos C4 will nullify.
 *
 * Determinism: pure function of (leaf, pos, siblings); Poseidon2 deterministic;
 * LSB-first order pinned. Grounding: dm-c3 §0-§4, S0 note_merkle_compress,
 * poseidon2_air (byte-matched Plonky3 82cfad73), merkle_smt.h:28-30 walk order.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_MEMBERSHIP_AIR_H
#define DNAC_ZK_CONF_MEMBERSHIP_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONF_MEMB_LANES 4  /* digest width (matches note_commit) */

/* Column layout (per level row). */
#define CONF_MEMB_CUR_OFF    0
#define CONF_MEMB_SIB_OFF     (CONF_MEMB_CUR_OFF + CONF_MEMB_LANES)  /* 4 */
#define CONF_MEMB_BIT_OFF     (CONF_MEMB_SIB_OFF + CONF_MEMB_LANES)  /* 8 */
#define CONF_MEMB_MC1_OFF     (CONF_MEMB_BIT_OFF + 1)                /* 9 */
#define CONF_MEMB_MC2_OFF     (CONF_MEMB_MC1_OFF + P2AIR_NUM_COLS)   /* 189 */
#define CONF_MEMB_POSACC_OFF  (CONF_MEMB_MC2_OFF + P2AIR_NUM_COLS)   /* 369 */
#define CONF_MEMB_WIDTH       (CONF_MEMB_POSACC_OFF + 1)             /* 370 */

/* Max tree depth (dm-c3: D ≤ 26 to fit the C1 K=32 block). */
#define CONF_MEMB_MAX_DEPTH 26

/**
 * @brief Honest-prover trace generation. Walks `leaf` up `depth` levels using
 *        `pos`'s LSB-first bits and the given `siblings`, computing the root.
 * @param depth     tree depth D (1..CONF_MEMB_MAX_DEPTH); trace has D rows.
 * @param leaf      the note commitment cm (CONF_MEMB_LANES lanes).
 * @param pos       leaf position (< 2^depth); bit i selects at level i.
 * @param siblings  depth × CONF_MEMB_LANES sibling digests, level-0 first.
 * @param trace_out caller buffer of (depth * CONF_MEMB_WIDTH) uint64.
 * @param root_out  the computed anchor (CONF_MEMB_LANES lanes).
 * @return true on success; false on a parameter error.
 */
bool conf_membership_air_generate(unsigned depth, const uint64_t leaf[CONF_MEMB_LANES],
                                  uint64_t pos, const uint64_t *siblings,
                                  uint64_t *trace_out,
                                  uint64_t root_out[CONF_MEMB_LANES]);

/**
 * @brief Evaluate ALL membership constraints against public (leaf, pos, anchor).
 *
 * STANDALONE-SCOPE PRECONDITIONS (discharged by S4 composition, red-team C3):
 *   - `depth` is VERIFIER-FIXED (a compile-time / phase-schedule constant), NOT
 *     prover-chosen — otherwise a shorter/longer path could be substituted. C3
 *     alone does NOT enforce a canonical depth; S4 pins it.
 *   - `leaf` MUST be the C1 `cm_carry` (a real note commitment) — this is what
 *     gives leaf/internal separation (see shielded_domsep.h). C3 accepts any
 *     public leaf; the binding is C1's/S4's.
 *   - `pos` MUST be canonical (< p) — supplied as the range-constrained C1
 *     `pos_carry`. C3 does not range-bound pos; POSACC itself cannot wrap
 *     (Σ bit·2^i < 2^depth ≤ 2^26 ≪ p).
 * @param trace   depth rows × CONF_MEMB_WIDTH canonical columns.
 * @param depth   tree depth D (= number of rows).
 * @param leaf    public leaf (C1 cm_carry) the level-0 CUR must equal.
 * @param pos     public position (C1 pos_carry) the POSACC must equal.
 * @param anchor  public root the final level must equal.
 * @return number of violated constraints; 0 == valid membership witness.
 */
int conf_membership_air_eval(const uint64_t *trace, unsigned depth,
                             const uint64_t leaf[CONF_MEMB_LANES], uint64_t pos,
                             const uint64_t anchor[CONF_MEMB_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_MEMBERSHIP_AIR_H */
