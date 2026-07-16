/**
 * @file conf_nullifier_air.h
 * @brief Dual-mode C4 — nullifier-PRF AIR (is_zk=0 construction gate).
 *
 * Computes a shielded note's nullifier from the C1 frozen carries and exposes it
 * as a public output (dm-c4). A C1 phase-block SUB-PROOF; here cm/pos/nk are
 * standalone inputs (in the full circuit they are the frozen cm_carry / pos_carry
 * / nk_carry, S1b/E15), so the nullifier-derivation logic is proven by
 * construction on its own, then composed at S4.
 *
 * ── Construction (grounded — parent §1.5 corrected-Orchard) ──────────────────
 *   ρ  = Poseidon2_CRH(cm, pos)   — collision-resistant, binds cm AND pos
 *        (Faerie-Gold ρ-uniqueness, Zcash §4.14/§8.4). Fixed-length preimage,
 *        capacity-preserving PaddingFreeSponge<8,4,4> (dm-c4 F1 lesson):
 *          in = [cm0, cm1, cm2, cm3, pos, DOMSEP_RHO, 0, 0]   (2 perms RHO1/RHO2)
 *          ρ  = RHO2.out[0..4]
 *   nf = Poseidon2_PRF(nk, ρ)     — keyed PRF, nk as the FIRST message element
 *        (Orchard PoseidonHash(nk,ρ), Zcash §5.4.1.10); DISTINCT DOMSEP_NF:
 *          in = [nk, ρ0, ρ1, ρ2, ρ3, DOMSEP_NF, 0, 0]         (2 perms NF1/NF2)
 *          nf = NF2.out[0..4]     (256-bit; the public nullifier)
 *   Both sponges are the S0 note_commit PaddingFreeSponge<8,4,4> primitive
 *   (all-zero IV, DOMSEP as a preimage element). DOMSEP_RHO ≠ DOMSEP_NF (G5).
 *
 * ── Row columns (single row; WIDTH = 4·P2AIR_NUM_COLS + 10) ──────────────────
 *   [ CM  : 4 ] [ POS : 1 ] [ NK : 1 ]   inputs (C1 frozen carries)
 *   [ RHO1: 180 ] [ RHO2: 180 ]          ρ sponge (CRH)
 *   [ NF1 : 180 ] [ NF2 : 180 ]          nf sponge (PRF)
 *   [ NF  : 4 ]                          the public nullifier (== NF2.out[0..4])
 *
 * ── Constraints (all degree ≤ 2 in the poseidon2 sense) ─────────────────────
 *   poseidon2_air_eval(RHO1/RHO2/NF1/NF2)=0 (each perm internally consistent);
 *   G2 ρ-input pins to the carries: RHO1.in[0..4]==cm, RHO2.in[0]==pos (one cell);
 *   G1 absorb-pad pins: RHO1.in[4..8]==0, RHO2.in[1]==DOMSEP_RHO, RHO2.in[2..4]==0,
 *      RHO2.in[4..8]==RHO1.out[4..8] (capacity carry); symmetric for NF (nk one
 *      cell, ρ carried from RHO2.out, DOMSEP_NF, pads, capacity carry);
 *   G4 nf single-source: the public NF column == NF2.out[0..4].
 *
 * Determinism: pure function of (cm, pos, nk); Poseidon2 deterministic; DOMSEPs
 * pinned. Grounding: parent §1.5, dm-c4 §0-§4, S0 shielded_domsep, poseidon2_air
 * (byte-matched Plonky3 82cfad73).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_NULLIFIER_AIR_H
#define DNAC_ZK_CONF_NULLIFIER_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "poseidon2_air_cols.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONF_NF_LANES 4  /* cm / ρ / nf digest width */

/* Column layout (single row). */
#define CONF_NF_CM_OFF    0
#define CONF_NF_POS_OFF   (CONF_NF_CM_OFF + CONF_NF_LANES)   /* 4 */
#define CONF_NF_NK_OFF    (CONF_NF_POS_OFF + 1)              /* 5 */
#define CONF_NF_RHO1_OFF  (CONF_NF_NK_OFF + 1)               /* 6 */
#define CONF_NF_RHO2_OFF  (CONF_NF_RHO1_OFF + P2AIR_NUM_COLS)
#define CONF_NF_NF1_OFF   (CONF_NF_RHO2_OFF + P2AIR_NUM_COLS)
#define CONF_NF_NF2_OFF   (CONF_NF_NF1_OFF + P2AIR_NUM_COLS)
#define CONF_NF_NF_OFF    (CONF_NF_NF2_OFF + P2AIR_NUM_COLS) /* public nullifier */
#define CONF_NF_WIDTH     (CONF_NF_NF_OFF + CONF_NF_LANES)

/**
 * @brief Honest-prover trace generation. Computes ρ=CRH(cm,pos), nf=PRF(nk,ρ),
 *        fills the four poseidon2 blocks + the public nf.
 * @param cm         note commitment (CONF_NF_LANES lanes; the C1 cm_carry).
 * @param pos        note position (the C1 pos_carry).
 * @param nk         spend-key nullifier component (the C1 nk_carry; secret).
 * @param trace_out  caller buffer of CONF_NF_WIDTH uint64 (one row).
 * @param nf_out     the derived nullifier (CONF_NF_LANES lanes).
 * @return true on success.
 */
bool conf_nullifier_air_generate(const uint64_t cm[CONF_NF_LANES], uint64_t pos,
                                 uint64_t nk, uint64_t *trace_out,
                                 uint64_t nf_out[CONF_NF_LANES]);

/**
 * @brief Evaluate ALL nullifier constraints against public (cm, pos, nf).
 *
 * PRECONDITION (red-team MF-3): cm, pos, and the trace's nk cell MUST be canonical
 * (< GOLDILOCKS_P) — supplied as the C1 range-constrained cm_carry / pos_carry /
 * nk_carry. eval compares raw uint64 for the cell pins, so a non-canonical witness
 * is (deterministically) over-rejected, never falsely accepted. The ρ input is
 * bound to the CM/POS trace CELLS (not just these params) so S4 can wire the C1
 * carries into those cells and the nullifier is forced to use the spent note.
 * @param trace   one row × CONF_NF_WIDTH canonical columns.
 * @param cm      public/carry commitment the ρ input (via its cell) must equal.
 * @param pos     public/carry position the ρ input (via its cell) must equal.
 * @param nf      the public nullifier the derived value must equal (G4).
 * @return number of violated constraints; 0 == valid nullifier witness.
 */
int conf_nullifier_air_eval(const uint64_t *trace, const uint64_t cm[CONF_NF_LANES],
                            uint64_t pos, const uint64_t nf[CONF_NF_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_NULLIFIER_AIR_H */
