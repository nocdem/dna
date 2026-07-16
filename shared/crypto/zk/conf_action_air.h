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
 *   S1c (THIS increment): the single-row NOTE-COMMITMENT (E9′) — cm_output is now
 *   the in-circuit S0 note_commit sponge over the note fields, so the value is
 *   bound to cm by a collision-resistant HASH (closes the §4b mint/theft class).
 *     columns (at the φ=0 row): value, addr_pub[4], rcm[2], and two poseidon2-air
 *     blocks NC1/NC2 (P2AIR_NUM_COLS each; mirrors conf_root_air do_fold CA1/CA2).
 *     construction (== S0 note_sponge_hash8, all-zero IV, DOMSEP as last element):
 *       NC1.in = [value, addr0, addr1, addr2, 0, 0, 0, 0]
 *       NC2.in = [addr3, rcm0, rcm1, DOMSEP_NOTE, NC1.out[4..8]]   (capacity carry)
 *       cm_output = NC2.out[0..4]
 *     constraints (gated on the block-start φ=0 REAL rows, r==0 ∨ w_prev==1):
 *       poseidon2_air_eval(NC1)=poseidon2_air_eval(NC2)=0 (every row — valid perm),
 *       NC1.in pins + NC1 capacity==0, NC2.in pins + NC2 capacity==NC1.out[4..8],
 *       DOMSEP_NOTE pin, cm_output == NC2.out[0..4]. The value cell is same-row
 *       (SEC-2) — bound to the balance AMOUNT in S1d.
 *   S1d (THIS increment): the BALANCE-CONSERVATION layer — the money mint barrier.
 *     columns: value bits[52] (range), role selectors IS_INPUT/IS_OUTPUT/IS_FEE,
 *              phi_is0 (is_zero(φ) indicator) + inv0, IS_BAL_CONTRIB, bal_coeff,
 *              BAL (running signed balance).
 *     constraints (all degree ≤ 2):
 *       RANGE  value = Σ bits_j·2^j (52 bits) ⇒ value < 2^52; recomp == value
 *       ROLE   IS_* boolean; IS_INPUT+IS_OUTPUT+IS_FEE == IS_REAL (one role/real
 *              block); E17 each role per-block const (1−w_prev)·(role−role_prev)=0
 *       PHI0   is_zero(φ): φ·inv0=1−phi_is0, φ·phi_is0=0, phi_is0²=phi_is0
 *       E10′   IS_BAL_CONTRIB = phi_is0·IS_REAL (fires once/block at φ=0)
 *       E14    bal_coeff = IS_BAL_CONTRIB·(IS_INPUT − IS_OUTPUT − IS_FEE) (deg-2)
 *       BAL    first row BAL = bal_coeff·value; transition next.BAL = local.BAL +
 *              next.bal_coeff·next.value; last row BAL = 0 ⇒ Σin = Σout + fee.
 *     The value cell IS the note-commitment preimage value (S1c) AND the balance
 *     summand — completing the E9′ same-row value↔cm↔balance chain.
 *   S1-E15 (THIS increment): the nk/pos/addr FROZEN CARRIES — composition plumbing.
 *     columns: pos_src/nk_src (φ=0 sources), pos_carry, nk_carry, addr_carry[4].
 *     Each carry uses the SAME S1b freeze pattern (E8′ block-0 init, E4 freeze,
 *     E11 wrap-load, padding-zero) so it holds its block's φ=0 source value
 *     block-wide. addr_carry's source is the note's ADDR[4] cells (already
 *     committed into cm at S1c), so addr_carry == the committed recipient address.
 *     At S4 composition: C3 reads pos_carry, C4 reads cm_carry/pos_carry/nk_carry
 *     — all frozen, all provably one note's fields.
 *   S1-cond3 (THIS increment): SPEND AUTHORITY (parent §1.6 condition-3, D3 hash-
 *   based — no signature). Two poseidon2 blocks AC1/AC2 compute
 *   addr_pub = PaddingFreeSponge(ak, nk, DOMSEP_ADDR, 0,0,0,0,0), and (on INPUT
 *   φ=0 rows) the result MUST equal the note's committed ADDR[4] (S1c, ==
 *   addr_carry). Since ADDR is bound into cm, spending a note requires knowing the
 *   (ak, nk) whose hash is its address — closing the theft vector (present a
 *   victim's public cm + your own nk: addr_pub ≠ the committed addr → reject).
 *   The nk here is the SAME nk_src cell C4 nullifies (one-cell). ak is a witness.
 *   Scoped OUT (own step): shield/deshield BOUNDARY public binding (C6 turnstile,
 *   needs AIR public inputs).
 *   Later: S1e constraint-eval fold + degree/num_qc, S1f prover + self-verify.
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

#include "poseidon2_air_cols.h" /* P2AIR_NUM_COLS, p2air offsets (S1c) */

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
/* ── S1c single-row note-commitment block (E9′) ── */
#define CONF_ACTION_VALUE_OFF   (CONF_ACTION_CMCARRY_OFF + CONF_ACTION_CM_LANES) /* note value */
#define CONF_ACTION_ADDR_OFF    (CONF_ACTION_VALUE_OFF + 1)          /* addr_pub[4] */
#define CONF_ACTION_RCM_OFF     (CONF_ACTION_ADDR_OFF + 4)           /* rcm[2] */
#define CONF_ACTION_NC1_OFF     (CONF_ACTION_RCM_OFF + 2)            /* poseidon2 block 1 */
#define CONF_ACTION_NC2_OFF     (CONF_ACTION_NC1_OFF + P2AIR_NUM_COLS) /* poseidon2 block 2 */
/* ── S1d balance-conservation block ── */
#define CONF_ACTION_VBITS_OFF   (CONF_ACTION_NC2_OFF + P2AIR_NUM_COLS) /* value bits[52] */
#define CONF_ACTION_ISIN_OFF    (CONF_ACTION_VBITS_OFF + CONF_ACTION_VALUE_BITS) /* IS_INPUT */
#define CONF_ACTION_ISOUT_OFF   (CONF_ACTION_ISIN_OFF + 1)          /* IS_OUTPUT */
#define CONF_ACTION_ISFEE_OFF   (CONF_ACTION_ISOUT_OFF + 1)         /* IS_FEE */
#define CONF_ACTION_PHI0_OFF    (CONF_ACTION_ISFEE_OFF + 1)         /* is_zero(φ) indicator */
#define CONF_ACTION_INV0_OFF    (CONF_ACTION_PHI0_OFF + 1)          /* is_zero(φ) witness */
#define CONF_ACTION_BALCON_OFF  (CONF_ACTION_INV0_OFF + 1)          /* IS_BAL_CONTRIB */
#define CONF_ACTION_BALCOEF_OFF (CONF_ACTION_BALCON_OFF + 1)        /* bal_coeff */
#define CONF_ACTION_BAL_OFF     (CONF_ACTION_BALCOEF_OFF + 1)       /* running signed BAL */
/* ── E15 frozen carries (composition plumbing for C3/C4) ── */
#define CONF_ACTION_POSSRC_OFF   (CONF_ACTION_BAL_OFF + 1)          /* pos source (φ=0) */
#define CONF_ACTION_NKSRC_OFF    (CONF_ACTION_POSSRC_OFF + 1)       /* nk source (φ=0) */
#define CONF_ACTION_POSCARRY_OFF (CONF_ACTION_NKSRC_OFF + 1)        /* pos_carry (frozen) */
#define CONF_ACTION_NKCARRY_OFF  (CONF_ACTION_POSCARRY_OFF + 1)     /* nk_carry (frozen) */
#define CONF_ACTION_ADDRCARRY_OFF (CONF_ACTION_NKCARRY_OFF + 1)     /* addr_carry[4] (frozen) */
/* ── condition-3 spend authority (addr_pub = Poseidon2(ak,nk)) ── */
#define CONF_ACTION_AK_OFF      (CONF_ACTION_ADDRCARRY_OFF + CONF_ACTION_ADDR_LANES) /* ak (φ=0, input) */
#define CONF_ACTION_AC1_OFF     (CONF_ACTION_AK_OFF + 1)            /* poseidon2 block 1 */
#define CONF_ACTION_AC2_OFF     (CONF_ACTION_AC1_OFF + P2AIR_NUM_COLS) /* poseidon2 block 2 */
#define CONF_ACTION_WIDTH       (CONF_ACTION_AC2_OFF + P2AIR_NUM_COLS) /* WIDTH = 813 */

/* addr_pub / rcm widths (S0 note_commit layout). */
#define CONF_ACTION_ADDR_LANES  4
#define CONF_ACTION_RCM_LANES   2
/* Range width for a hidden note value (< 2^52), dm-c1 §5 / RANGE_AIR_BITS. */
#define CONF_ACTION_VALUE_BITS  52

/* Per-block role tags (passed to generate; a real block has exactly one). */
#define CONF_ACTION_ROLE_INPUT  0
#define CONF_ACTION_ROLE_OUTPUT 1
#define CONF_ACTION_ROLE_FEE    2

/** Max log2(height). H = 2^log_height, log_height ∈ [LOG_K, this]. The shielded
 *  cap is H = 1024 = 2^10 (dm-c1 §4d.8; STARK_PROVER_MAX_HEIGHT). */
#define CONF_ACTION_MIN_LOG_HEIGHT CONF_ACTION_LOG_K
#define CONF_ACTION_MAX_LOG_HEIGHT 10

/**
 * @brief Honest-prover trace generation for the S1a+S1b+S1c skeleton.
 *        Fills the phase counter, the freeze-carry block, AND the single-row
 *        note-commitment (E9′): each of the first `num_notes` REAL blocks carries
 *        a note (value, addr_pub[4], rcm[2]); its commitment cm = note_commit
 *        sponge is COMPUTED IN-CIRCUIT (two poseidon2 blocks NC1/NC2 at the φ=0
 *        row) and equals the S0 note_commit() digest. cm_output := NC2 output at
 *        φ=0; cm_carry freezes it block-wide (S1b). Remaining blocks (incl. the
 *        mandatory dummy-last, E7) are dummy. The poseidon2 blocks at non-φ=0
 *        rows hold a valid permutation of zeros (inert; later phases use them).
 * @param log_height  trace height = 2^log_height, ∈ [LOG_K, MAX_LOG_HEIGHT].
 * @param value       num_notes note values (canonical; caller ensures < 2^52).
 * @param addr        num_notes × CONF_ACTION_ADDR_LANES recipient addresses.
 * @param rcm         num_notes × CONF_ACTION_RCM_LANES commitment randomness.
 * @param roles       num_notes per-block role tags (CONF_ACTION_ROLE_*). The
 *                    signed balance MUST conserve: Σ INPUT − Σ OUTPUT − Σ FEE = 0.
 * @param pos         num_notes tree positions (E15 pos_carry source; C3 reads it).
 * @param nk          num_notes spend-key nullifier components (E15 nk_carry
 *                    source; C4 reads it). May be NULL only if num_notes == 0.
 * @param ak          num_notes spend-authority keys (condition-3). For INPUT
 *                    notes the note ADDRESS is DERIVED as Poseidon2(ak,nk)
 *                    (overriding `addr` for those blocks — your input notes are
 *                    addressed to YOU); for OUTPUT/FEE `ak` is unused and `addr`
 *                    is the recipient/filler. May be NULL only if num_notes == 0.
 * @param num_notes   number of REAL note-blocks; MUST be ≤ (H/K − 1) (E7).
 * @param trace_out   caller buffer of (2^log_height * CONF_ACTION_WIDTH) uint64.
 * @return true on success; false on a parameter error (incl. non-conserving
 *         balance or a value ≥ 2^52).
 */
bool conf_action_air_generate(unsigned log_height, const uint64_t *value,
                              const uint64_t *addr, const uint64_t *rcm,
                              const uint8_t *roles, const uint64_t *pos,
                              const uint64_t *nk, const uint64_t *ak,
                              size_t num_notes, uint64_t *trace_out);

/**
 * @brief Evaluate ALL constraints over a trace (see file header for the set).
 * @param trace   2^log_height rows × CONF_ACTION_WIDTH canonical columns.
 * @param n_rows  number of rows (= 2^log_height).
 * @return number of violated constraints; 0 == valid witness.
 */
int conf_action_air_eval(const uint64_t *trace, size_t n_rows);

/**
 * @brief Derive a shielded input-note address addr_pub = Poseidon2(ak, nk)
 *        (condition-3): PaddingFreeSponge<8,4,4>(ak, nk, DOMSEP_ADDR, 0,…). The
 *        same computation the in-circuit AC1/AC2 blocks perform; exposed so a
 *        caller/test can construct a note addressed to (ak, nk).
 * @param ak       spend-authority key (canonical).
 * @param nk       nullifier key (canonical).
 * @param addr_out 4-lane derived address.
 */
void conf_action_derive_addr(uint64_t ak, uint64_t nk,
                             uint64_t addr_out[CONF_ACTION_ADDR_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AIR_H */
