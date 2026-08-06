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
 * ── ZK trace layout (WIDTH 2378 = 2306 + 3·D at D=24 — DIFFERENT from the
 *    2287-wide construction gate: the real-STARK adds 3 committed is_zero
 *    SELECTOR columns PER LEVEL that the C construction gate replaced with
 *    runtime phi-branches, which is why THIS width is D-dependent and the
 *    construction gate's is not. Was 2318 at D=4). ──
 *   [0,1002)        C1 region (conf_action_air, offsets unchanged)
 *   [1002,1372)     C3 membership region
 *   [1372,2285)     C4 nullifier region (nk[4] + NF1/NF2/NF3, F3)
 *   2285            IS_NF   = [phi==D+1]        (D+1 = 25 at D=24)
 *   2286            INV_NF
 *   [2287,2311)     IS_LVL[1..D]   = [phi==i]
 *   [2311,2335)     INV_LVL[1..D]
 *   [2335,2359)     ACTIVE_LVL[1..D] = IS_LVL[i]*IS_INPUT
 *   2359            N_INPUT (running INPUT-block counter)
 *   [2360,2364)     SLOT_SEL[MAX_INPUTS] = is_zero(N_INPUT-1-s)
 *   [2364,2368)     INV_SLOT[MAX_INPUTS]
 *   2368            N_OUTPUT (running OUTPUT-block counter, S4c)
 *   [2369,2373)     OSLOT_SEL[MAX_OUTPUTS] = is_zero(N_OUTPUT-1-s)
 *   [2373,2377)     INV_OSLOT[MAX_OUTPUTS]
 *   2377            FEE_ACC (Σ IS_FEE·value accumulator — S8: pinned 0, see below)
 *
 * ── Publics (45, S8 Gate 2): anchor[4] || num_input || nf_slot[MI][4] ||
 *    num_output || output_commit[MO][4] || fee || boundary_in || boundary_out ||
 *    tx_binding[4]. tx_binding is FS-observed only; `fee` became FS/sighash-only
 *    too at S8 (nothing in the eval reads it any more). ──
 *
 * ── LEDGER-V2 S8 Gate 2 (2026-08-06) ───────────────────────────────────────
 *   · D 4 → 24 (production note-tree depth) ⇒ WIDTH 2318 → 2378, NF_PHI 5 → 25.
 *   · IS_FEE pinned ZERO in the C1 evaluator ⇒ FEE_ACC can only ever be 0, so
 *     its last-row constraint becomes `FEE_ACC == 0` instead of
 *     `FEE_ACC == fee_pub`. The COLUMNS (IS_FEE, FEE_ACC) are KEPT — the trace
 *     width is frozen — and the FEE_ACC first-row/transition constraints are
 *     UNCHANGED, so the accumulator still forces every IS_FEE·value to zero.
 *   · The C1 last-row terminal becomes BAL == boundary_out − boundary_in, via
 *     the caller-owned dnac_conf_action_bnd_ctx_t installed as this
 *     descriptor's `ctx` (the aggregate calls the C1 evaluator with the SAME
 *     folder, so folder->ctx there IS this ctx — that is the intent).
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

/* ── ZK trace layout constants (is_zk=1 STARK form; distinct from the 2287-wide
 *    construction-gate CONF_AGG_* layout in conf_action_agg_air.h). ── */
#define CONF_AGGZK_MEMB_LANES 4
#define CONF_AGGZK_NF_LANES 4
#define CONF_AGGZK_D CONF_AGG_TREE_DEPTH /* 24 (S8 production depth) */
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
#define CONF_AGGZK_INVLVL_OFF (CONF_AGGZK_ISLVL_OFF + CONF_AGGZK_D)        /* 2311 */
#define CONF_AGGZK_ACTLVL_OFF (CONF_AGGZK_INVLVL_OFF + CONF_AGGZK_D)       /* 2335 */
#define CONF_AGGZK_NIN_OFF (CONF_AGGZK_ACTLVL_OFF + CONF_AGGZK_D)          /* 2359 */
#define CONF_AGGZK_SLOTSEL_OFF (CONF_AGGZK_NIN_OFF + 1)                    /* 2360 */
#define CONF_AGGZK_INVSLOT_OFF (CONF_AGGZK_SLOTSEL_OFF + CONF_AGGZK_MAX_INPUTS) /* 2364 */
/* S4c output routing columns (OUTPUT analog of the N_input machinery) + fee acc. */
#define CONF_AGGZK_MAX_OUTPUTS 4 /* MAX_OUTPUTS — S6-pinned (mirrors MAX_INPUTS) */
#define CONF_AGGZK_NOUT_OFF (CONF_AGGZK_INVSLOT_OFF + CONF_AGGZK_MAX_INPUTS)    /* 2368 */
#define CONF_AGGZK_OSLOTSEL_OFF (CONF_AGGZK_NOUT_OFF + 1)                       /* 2369 */
#define CONF_AGGZK_INVOSLOT_OFF (CONF_AGGZK_OSLOTSEL_OFF + CONF_AGGZK_MAX_OUTPUTS) /* 2373 */
#define CONF_AGGZK_FEEACC_OFF (CONF_AGGZK_INVOSLOT_OFF + CONF_AGGZK_MAX_OUTPUTS)    /* 2377 */
#define CONF_AGGZK_WIDTH (CONF_AGGZK_FEEACC_OFF + 1)                            /* 2378 */

#define CONF_AGGZK_NF_PHI (CONF_AGGZK_D + 1) /* D+1 = 25 */

/* public-value layout (S4c: 21 → 43; LEDGER-V2 S8 Gate 2: 43 → 45 — the two
 * turnstile publics are inserted AFTER fee and BEFORE tx_binding, so tx_binding
 * shifts 39..42 → 41..44):
 *   0..3   anchor[4]
 *   4      num_input
 *   5..20  nf_slot[MI][4]
 *   21     num_output
 *   22..37 output_commit[MO][4]
 *   38     fee            (FS/sighash-bound ONLY — S8: no longer eval-read)
 *   39     boundary_in    (S8, transparent value entering the shielded pool)
 *   40     boundary_out   (S8, transparent value leaving it)
 *   41..44 tx_binding[4]  (FS-observed, eval-free) */
#define CONF_AGGZK_PUB_ANCHOR 0
#define CONF_AGGZK_PUB_NUMIN (CONF_AGGZK_PUB_ANCHOR + CONF_AGGZK_MEMB_LANES) /* 4 */
#define CONF_AGGZK_PUB_NFSLOT (CONF_AGGZK_PUB_NUMIN + 1)                     /* 5 */
#define CONF_AGGZK_PUB_NUMOUT \
    (CONF_AGGZK_PUB_NFSLOT + CONF_AGGZK_MAX_INPUTS * CONF_AGGZK_NF_LANES) /* 21 */
#define CONF_AGGZK_PUB_OCOMMIT (CONF_AGGZK_PUB_NUMOUT + 1)                   /* 22 */
#define CONF_AGGZK_PUB_FEE \
    (CONF_AGGZK_PUB_OCOMMIT + CONF_AGGZK_MAX_OUTPUTS * CONF_ACTION_CM_LANES) /* 38 */
#define CONF_AGGZK_PUB_BIN (CONF_AGGZK_PUB_FEE + 1)                          /* 39 */
#define CONF_AGGZK_PUB_BOUT (CONF_AGGZK_PUB_BIN + 1)                         /* 40 */
#define CONF_AGGZK_PUB_TXBIND (CONF_AGGZK_PUB_BOUT + 1)                      /* 41 */
#define CONF_AGGZK_NUM_PUBLICS (CONF_AGGZK_PUB_TXBIND + CONF_AGGZK_MEMB_LANES) /* 45 */

/**
 * @brief The aggregate Action AIR fold-form eval (dnac_stark_air_t callback).
 *        Emits every constraint in the ORACLE-pinned order via the folder
 *        helpers. Requires folder->main_width == CONF_AGGZK_WIDTH and
 *        folder->num_public_values == CONF_AGGZK_NUM_PUBLICS.
 */
void dnac_conf_action_agg_fold_air_eval(dnac_stark_folder_t *folder);

/** AIR descriptor for dnac_stark_verify_constraints_nchunk (width 2378 at D=24,
 *  45 publics, main_next=1; `ctx` = the boundary-index pair the reused C1
 *  evaluator reads for its last-row terminal). */
extern const dnac_stark_air_t DNAC_CONF_ACTION_AGG_FOLD_AIR;

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_CONF_ACTION_AGG_FOLD_H */
