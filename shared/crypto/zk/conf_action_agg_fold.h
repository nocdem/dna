/**
 * @file conf_action_agg_fold.h
 * @brief Dual-mode S4b — the AGGREGATE Action AIR in VERIFIER-FOLD form (fp2
 *        alpha-fold over the opened trace window at zeta).
 *
 * The real-STARK (is_zk=1) counterpart of conf_action_agg_air.c: it evaluates
 * the ConfActionAggAir constraint polynomial ONCE at the out-of-domain point
 * zeta over the opened fp2 values, alpha-folding every constraint in the SAME
 * order as the Rust-oracle `ConfActionAggAir::eval`
 * (tools/plonky3_oracle/src/main.rs), which itself is proven by a REAL is_zk=1
 * p3_uni_stark proof (tools/vectors/conf_action_agg_air_zk.json).
 *
 * ── ZK trace layout (WIDTH 2318 post-F3 — DIFFERENT from the 2287-wide
 *    construction gate: the real-STARK adds committed is_zero SELECTOR columns
 *    the C construction gate replaced with runtime phi-branches). ──
 *   [0,1002)        C1 region (conf_action_air, offsets unchanged)
 *   [1002,1372)     C3 membership region
 *   [1372,2285)     C4 nullifier region (nk[4] + NF1/NF2/NF3, F3)
 *   2285            IS_NF   = [phi==D+1]
 *   2286            INV_NF
 *   [2287,2291)     IS_LVL[1..D]   = [phi==i]
 *   [2291,2295)     INV_LVL[1..D]
 *   [2295,2299)     ACTIVE_LVL[1..D] = IS_LVL[i]*IS_INPUT
 *   2299            N_INPUT (running INPUT-block counter)
 *   [2300,2304)     SLOT_SEL[MAX_INPUTS] = is_zero(N_INPUT-1-s)
 *   [2304,2308)     INV_SLOT[MAX_INPUTS]
 *   2308            N_OUTPUT (running OUTPUT-block counter, S4c)
 *   [2309,2313)     OSLOT_SEL[MAX_OUTPUTS] = is_zero(N_OUTPUT-1-s)
 *   [2313,2317)     INV_OSLOT[MAX_OUTPUTS]
 *   2317            FEE_ACC (Σ IS_FEE·value accumulator)
 *
 * ── Publics (43, S4c): anchor[4] || num_input || nf_slot[MI][4] || num_output ||
 *    output_commit[MO][4] || fee || tx_binding[4] (tx_binding FS-observed). ──
 *
 * EMISSION ORDER (the alpha-fold is order-sensitive) mirrors the oracle:
 *   ConfActionAir.eval (C1, via dnac_conf_action_fold_air_eval) ->
 *   is_nf gadget -> is_lvl[i]/active_lvl[i] gadgets ->
 *   MC1/MC2 Poseidon2 -> membership pins (BIT, ordering, caps, leaf, POSACC
 *   init, POSACC inert, chaining+POSACC transitions, root+final) ->
 *   RHO1/RHO2/NF1/NF2 Poseidon2 -> nullifier pins + inert ->
 *   N_input counter -> slot_sel gadgets -> nf-slot routing.
 *
 * Gate: tests/test_conf_action_agg_verify.c — folded * inv_vanishing must equal
 * the REAL recompose_quotient_from_chunks output on the REAL Plonky3 proof.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_CONF_ACTION_AGG_FOLD_H
#define DNAC_ZK_CONF_ACTION_AGG_FOLD_H

#include "conf_action_agg_air.h" /* CONF_AGG_TREE_DEPTH + region params */
#include "conf_action_air.h"     /* CONF_ACTION_* C1 offsets (width = CONF_ACTION_WIDTH) */
#include "poseidon2_air_cols.h"  /* P2AIR_NUM_COLS */
#include "stark_constraints.h"   /* dnac_stark_air_t / folder */

#ifdef __cplusplus
extern "C" {
#endif

/* ── ZK trace layout constants (is_zk=1 STARK form; distinct from the 1915-wide
 *    construction-gate CONF_AGG_* layout in conf_action_agg_air.h). ── */
#define CONF_AGGZK_MEMB_LANES 4
#define CONF_AGGZK_NF_LANES 4
#define CONF_AGGZK_D CONF_AGG_TREE_DEPTH /* 4 */
#define CONF_AGGZK_MAX_INPUTS 4          /* MAX_INPUTS — S6-pinned consensus constant */

/* membership sub-offsets (within the MEMB region) */
#define CONF_AGGZK_MEMB_CUR 0
#define CONF_AGGZK_MEMB_SIB 4
#define CONF_AGGZK_MEMB_BIT 8
#define CONF_AGGZK_MEMB_MC1 9
#define CONF_AGGZK_MEMB_MC2 (CONF_AGGZK_MEMB_MC1 + P2AIR_NUM_COLS)    /* 189 */
#define CONF_AGGZK_MEMB_POSACC (CONF_AGGZK_MEMB_MC2 + P2AIR_NUM_COLS) /* 369 */
#define CONF_AGGZK_MEMB_WIDTH (CONF_AGGZK_MEMB_POSACC + 1)            /* 370 */

/* nullifier sub-offsets (within the NF region) */
/* F3: nk 4-lane + third nf-sponge perm (NF3) — 12-slot PRF preimage
 * [nk0..3, ρ0..3, DOMSEP_NF, 0,0,0], §3b pinned order. */
#define CONF_AGGZK_NF_NK_LANES 4 /* CONF_NF_NK_LANES */
#define CONF_AGGZK_NF_CM 0
#define CONF_AGGZK_NF_POS 4
#define CONF_AGGZK_NF_NK 5 /* [5,9) */
#define CONF_AGGZK_NF_RHO1 (CONF_AGGZK_NF_NK + CONF_AGGZK_NF_NK_LANES) /* 9 */
#define CONF_AGGZK_NF_RHO2 (CONF_AGGZK_NF_RHO1 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF1 (CONF_AGGZK_NF_RHO2 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF2 (CONF_AGGZK_NF_NF1 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF3 (CONF_AGGZK_NF_NF2 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF (CONF_AGGZK_NF_NF3 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_WIDTH (CONF_AGGZK_NF_NF + CONF_AGGZK_NF_LANES) /* 913 */

/* region offsets within the wide row */
#define CONF_AGGZK_C1_OFF 0
#define CONF_AGGZK_MEMB_OFF CONF_ACTION_WIDTH                              /* 1002 */
#define CONF_AGGZK_NF_OFF (CONF_AGGZK_MEMB_OFF + CONF_AGGZK_MEMB_WIDTH)    /* 1372 */
#define CONF_AGGZK_ISNF_OFF (CONF_AGGZK_NF_OFF + CONF_AGGZK_NF_WIDTH)      /* 2285 */
#define CONF_AGGZK_INVNF_OFF (CONF_AGGZK_ISNF_OFF + 1)                     /* 2286 */
#define CONF_AGGZK_ISLVL_OFF (CONF_AGGZK_INVNF_OFF + 1)                    /* 2287 */
#define CONF_AGGZK_INVLVL_OFF (CONF_AGGZK_ISLVL_OFF + CONF_AGGZK_D)        /* 2291 */
#define CONF_AGGZK_ACTLVL_OFF (CONF_AGGZK_INVLVL_OFF + CONF_AGGZK_D)       /* 2295 */
#define CONF_AGGZK_NIN_OFF (CONF_AGGZK_ACTLVL_OFF + CONF_AGGZK_D)          /* 2299 */
#define CONF_AGGZK_SLOTSEL_OFF (CONF_AGGZK_NIN_OFF + 1)                    /* 2300 */
#define CONF_AGGZK_INVSLOT_OFF (CONF_AGGZK_SLOTSEL_OFF + CONF_AGGZK_MAX_INPUTS) /* 2304 */
/* S4c output routing columns (OUTPUT analog of the N_input machinery) + fee acc. */
#define CONF_AGGZK_MAX_OUTPUTS 4 /* MAX_OUTPUTS — S6-pinned (mirrors MAX_INPUTS) */
#define CONF_AGGZK_NOUT_OFF (CONF_AGGZK_INVSLOT_OFF + CONF_AGGZK_MAX_INPUTS)    /* 2308 */
#define CONF_AGGZK_OSLOTSEL_OFF (CONF_AGGZK_NOUT_OFF + 1)                       /* 2309 */
#define CONF_AGGZK_INVOSLOT_OFF (CONF_AGGZK_OSLOTSEL_OFF + CONF_AGGZK_MAX_OUTPUTS) /* 2313 */
#define CONF_AGGZK_FEEACC_OFF (CONF_AGGZK_INVOSLOT_OFF + CONF_AGGZK_MAX_OUTPUTS)    /* 2317 */
#define CONF_AGGZK_WIDTH (CONF_AGGZK_FEEACC_OFF + 1)                            /* 2318 */

#define CONF_AGGZK_NF_PHI (CONF_AGGZK_D + 1) /* D+1 = 5 */

/* public-value layout (S4c: 21 → 43):
 *   anchor[4] ‖ num_input ‖ nf_slot[MI][4] ‖ num_output ‖ output_commit[MO][4]
 *   ‖ fee ‖ tx_binding[4]. */
#define CONF_AGGZK_PUB_ANCHOR 0
#define CONF_AGGZK_PUB_NUMIN (CONF_AGGZK_PUB_ANCHOR + CONF_AGGZK_MEMB_LANES) /* 4 */
#define CONF_AGGZK_PUB_NFSLOT (CONF_AGGZK_PUB_NUMIN + 1)                     /* 5 */
#define CONF_AGGZK_PUB_NUMOUT \
    (CONF_AGGZK_PUB_NFSLOT + CONF_AGGZK_MAX_INPUTS * CONF_AGGZK_NF_LANES) /* 21 */
#define CONF_AGGZK_PUB_OCOMMIT (CONF_AGGZK_PUB_NUMOUT + 1)                   /* 22 */
#define CONF_AGGZK_PUB_FEE \
    (CONF_AGGZK_PUB_OCOMMIT + CONF_AGGZK_MAX_OUTPUTS * CONF_ACTION_CM_LANES) /* 38 */
#define CONF_AGGZK_PUB_TXBIND (CONF_AGGZK_PUB_FEE + 1)                       /* 39 */
#define CONF_AGGZK_NUM_PUBLICS (CONF_AGGZK_PUB_TXBIND + CONF_AGGZK_MEMB_LANES) /* 43 */

/**
 * @brief The aggregate Action AIR fold-form eval (dnac_stark_air_t callback).
 *        Emits every constraint in the ORACLE-pinned order via the folder
 *        helpers. Requires folder->main_width == CONF_AGGZK_WIDTH and
 *        folder->num_public_values == CONF_AGGZK_NUM_PUBLICS.
 */
void dnac_conf_action_agg_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 2318 post-F3,
 *  43 publics, main_next=1). */
extern const dnac_stark_air_t DNAC_CONF_ACTION_AGG_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AGG_FOLD_H */
