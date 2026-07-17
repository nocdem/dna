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
 * ── ZK trace layout (WIDTH 1936 — DIFFERENT from the 1915-wide construction
 *    gate: the real-STARK adds committed is_zero SELECTOR columns the C
 *    construction gate replaced with runtime phi-branches). ──
 *   [0,813)         C1 region (conf_action_air, offsets unchanged)
 *   [813,1183)      C3 membership region
 *   [1183,1913)     C4 nullifier region
 *   1913            IS_NF   = [phi==D+1]
 *   1914            INV_NF
 *   [1915,1919)     IS_LVL[1..D]   = [phi==i]
 *   [1919,1923)     INV_LVL[1..D]
 *   [1923,1927)     ACTIVE_LVL[1..D] = IS_LVL[i]*IS_INPUT
 *   1927            N_INPUT (running INPUT-block counter)
 *   [1928,1932)     SLOT_SEL[MAX_INPUTS] = is_zero(N_INPUT-1-s)
 *   [1932,1936)     INV_SLOT[MAX_INPUTS]
 *
 * ── Publics (21): anchor[4] || num_input || nf_slot[MAX_INPUTS][4]. ──
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
#include "conf_action_air.h"     /* CONF_ACTION_* C1 offsets (width 813) */
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
#define CONF_AGGZK_NF_CM 0
#define CONF_AGGZK_NF_POS 4
#define CONF_AGGZK_NF_NK 5
#define CONF_AGGZK_NF_RHO1 6
#define CONF_AGGZK_NF_RHO2 (CONF_AGGZK_NF_RHO1 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF1 (CONF_AGGZK_NF_RHO2 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF2 (CONF_AGGZK_NF_NF1 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_NF (CONF_AGGZK_NF_NF2 + P2AIR_NUM_COLS)
#define CONF_AGGZK_NF_WIDTH (CONF_AGGZK_NF_NF + CONF_AGGZK_NF_LANES) /* 730 */

/* region offsets within the wide row */
#define CONF_AGGZK_C1_OFF 0
#define CONF_AGGZK_MEMB_OFF CONF_ACTION_WIDTH                              /* 813 */
#define CONF_AGGZK_NF_OFF (CONF_AGGZK_MEMB_OFF + CONF_AGGZK_MEMB_WIDTH)    /* 1183 */
#define CONF_AGGZK_ISNF_OFF (CONF_AGGZK_NF_OFF + CONF_AGGZK_NF_WIDTH)      /* 1913 */
#define CONF_AGGZK_INVNF_OFF (CONF_AGGZK_ISNF_OFF + 1)                     /* 1914 */
#define CONF_AGGZK_ISLVL_OFF (CONF_AGGZK_INVNF_OFF + 1)                    /* 1915 */
#define CONF_AGGZK_INVLVL_OFF (CONF_AGGZK_ISLVL_OFF + CONF_AGGZK_D)        /* 1919 */
#define CONF_AGGZK_ACTLVL_OFF (CONF_AGGZK_INVLVL_OFF + CONF_AGGZK_D)       /* 1923 */
#define CONF_AGGZK_NIN_OFF (CONF_AGGZK_ACTLVL_OFF + CONF_AGGZK_D)          /* 1927 */
#define CONF_AGGZK_SLOTSEL_OFF (CONF_AGGZK_NIN_OFF + 1)                    /* 1928 */
#define CONF_AGGZK_INVSLOT_OFF (CONF_AGGZK_SLOTSEL_OFF + CONF_AGGZK_MAX_INPUTS) /* 1932 */
#define CONF_AGGZK_WIDTH (CONF_AGGZK_INVSLOT_OFF + CONF_AGGZK_MAX_INPUTS)  /* 1936 */

#define CONF_AGGZK_NF_PHI (CONF_AGGZK_D + 1) /* D+1 = 5 */

/* public-value layout */
#define CONF_AGGZK_PUB_ANCHOR 0
#define CONF_AGGZK_PUB_NUMIN (CONF_AGGZK_PUB_ANCHOR + CONF_AGGZK_MEMB_LANES) /* 4 */
#define CONF_AGGZK_PUB_NFSLOT (CONF_AGGZK_PUB_NUMIN + 1)                     /* 5 */
#define CONF_AGGZK_NUM_PUBLICS \
    (CONF_AGGZK_PUB_NFSLOT + CONF_AGGZK_MAX_INPUTS * CONF_AGGZK_NF_LANES) /* 21 */

/**
 * @brief The aggregate Action AIR fold-form eval (dnac_stark_air_t callback).
 *        Emits every constraint in the ORACLE-pinned order via the folder
 *        helpers. Requires folder->main_width == CONF_AGGZK_WIDTH and
 *        folder->num_public_values == CONF_AGGZK_NUM_PUBLICS.
 */
void dnac_conf_action_agg_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 1936,
 *  21 publics, main_next=1). */
extern const dnac_stark_air_t DNAC_CONF_ACTION_AGG_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AGG_FOLD_H */
