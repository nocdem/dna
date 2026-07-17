/**
 * @file conf_action_agg_fold.c
 * @brief Dual-mode S4b — the AGGREGATE Action AIR, verifier-fold (fp2) form.
 *
 * EMISSION ORDER is the contract: it mirrors the Rust-oracle
 * ConfActionAggAir::eval (tools/plonky3_oracle/src/main.rs) call-for-call —
 * see conf_action_agg_fold.h. The C1 region is folded by REUSING
 * dnac_conf_action_fold_air_eval (the C analog of the oracle's
 * `ConfActionAir.eval(builder)`); the six Poseidon2 sub-blocks (MC1/MC2
 * membership, RHO1/RHO2/NF1/NF2 nullifier) fold through the shared
 * dnac_poseidon2_fold_eval.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_action_agg_fold.h"

#include "conf_action_fold.h" /* dnac_conf_action_fold_air_eval (C1 reuse) */
#include "poseidon2_air_cols.h"
#include "poseidon2_fold.h"  /* dnac_poseidon2_fold_eval */
#include "shielded_domsep.h" /* DNAC_DOMSEP_RHO / DNAC_DOMSEP_NF */

/* end_post(3, ·) lane of a poseidon2 block (== the C nc_out()). */
#define AGG_END_POST3(k) p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (k))

static inline gold_fp2_t fp2u(uint64_t v) {
    return gold_fp2_from_base(gold_fp_from_u64(v));
}

void dnac_conf_action_agg_fold_air_eval(dnac_stark_folder_t *f) {
    /* ── C1 reuse: emits every conf_action constraint on [0,813) in the SAME
     * order as the oracle's ConfActionAir.eval(builder). ── */
    dnac_conf_action_fold_air_eval(f);

    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp_t *PUB = f->public_values;

    const gold_fp2_t phi = L[CONF_ACTION_PHI_OFF];
    const gold_fp2_t is_input = L[CONF_ACTION_ISIN_OFF];

    /* anchor[4] publics (promoted to fp2). */
    gold_fp2_t anchor[CONF_AGGZK_MEMB_LANES];
    for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++)
        anchor[j] = gold_fp2_from_base(PUB[CONF_AGGZK_PUB_ANCHOR + j]);
    const gold_fp2_t num_input_pub = gold_fp2_from_base(PUB[CONF_AGGZK_PUB_NUMIN]);

    const size_t M = CONF_AGGZK_MEMB_OFF;  /* membership region base */
    const size_t NF = CONF_AGGZK_NF_OFF;   /* nullifier region base */

    /* ── is_nf = is_zero(phi − (D+1)). ── */
    const gold_fp2_t is_nf = L[CONF_AGGZK_ISNF_OFF];
    dnac_stark_folder_assert_bool(f, is_nf);
    const gold_fp2_t d_nf = gold_fp2_sub(phi, fp2u(CONF_AGGZK_NF_PHI));
    dnac_stark_folder_assert_eq(f, gold_fp2_mul(d_nf, L[CONF_AGGZK_INVNF_OFF]),
                                gold_fp2_sub(one, is_nf));
    dnac_stark_folder_assert_zero(f, gold_fp2_mul(d_nf, is_nf));

    /* ── is_lvl[i]=is_zero(phi−i); active_lvl[i]=is_lvl[i]·IS_INPUT (i=1..D). ── */
    for (unsigned i = 1; i <= CONF_AGGZK_D; i++) {
        const gold_fp2_t il = L[CONF_AGGZK_ISLVL_OFF + (i - 1)];
        dnac_stark_folder_assert_bool(f, il);
        const gold_fp2_t d_i = gold_fp2_sub(phi, fp2u(i));
        dnac_stark_folder_assert_eq(
            f, gold_fp2_mul(d_i, L[CONF_AGGZK_INVLVL_OFF + (i - 1)]),
            gold_fp2_sub(one, il));
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(d_i, il));
        dnac_stark_folder_assert_eq(f, L[CONF_AGGZK_ACTLVL_OFF + (i - 1)],
                                    gold_fp2_mul(il, is_input));
    }
    /* active_memb = Σ active_lvl[i] (mutually exclusive ⇒ ∈ {0,1}). */
    gold_fp2_t active_memb = gold_fp2_zero();
    for (unsigned i = 0; i < CONF_AGGZK_D; i++)
        active_memb = gold_fp2_add(active_memb, L[CONF_AGGZK_ACTLVL_OFF + i]);

    /* ── C3 membership: MC1/MC2 Poseidon2 always-on + gated pins. ── */
    dnac_poseidon2_fold_eval(f, M + CONF_AGGZK_MEMB_MC1);
    dnac_poseidon2_fold_eval(f, M + CONF_AGGZK_MEMB_MC2);

    const gold_fp2_t bit = L[M + CONF_AGGZK_MEMB_BIT];
    /* BIT booleanity (gated active). */
    dnac_stark_folder_when(f, active_memb, gold_fp2_mul(bit, gold_fp2_sub(bit, one)));
    /* Ordering: MC1.in=left, MC2.in=right; capacity carry. */
    for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++) {
        const gold_fp2_t cur = L[M + CONF_AGGZK_MEMB_CUR + j];
        const gold_fp2_t sib = L[M + CONF_AGGZK_MEMB_SIB + j];
        const gold_fp2_t left = gold_fp2_add(cur, gold_fp2_mul(bit, gold_fp2_sub(sib, cur)));
        const gold_fp2_t right = gold_fp2_add(sib, gold_fp2_mul(bit, gold_fp2_sub(cur, sib)));
        dnac_stark_folder_when(
            f, active_memb,
            gold_fp2_sub(L[M + CONF_AGGZK_MEMB_MC1 + p2air_input_off(j)], left));
        dnac_stark_folder_when(
            f, active_memb,
            gold_fp2_sub(L[M + CONF_AGGZK_MEMB_MC2 + p2air_input_off(j)], right));
    }
    for (size_t k = 4; k < 8; k++) {
        dnac_stark_folder_when(f, active_memb,
                               L[M + CONF_AGGZK_MEMB_MC1 + p2air_input_off(k)]);
        dnac_stark_folder_when(
            f, active_memb,
            gold_fp2_sub(L[M + CONF_AGGZK_MEMB_MC2 + p2air_input_off(k)],
                         L[M + CONF_AGGZK_MEMB_MC1 + AGG_END_POST3(k)]));
    }
    /* Leaf (phi=1): CUR == cm_carry. */
    for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++)
        dnac_stark_folder_when(
            f, L[CONF_AGGZK_ACTLVL_OFF],
            gold_fp2_sub(L[M + CONF_AGGZK_MEMB_CUR + j], L[CONF_ACTION_CMCARRY_OFF + j]));
    /* POSACC init (phi=1): POSACC == bit·2^0 == bit. */
    dnac_stark_folder_when(f, L[CONF_AGGZK_ACTLVL_OFF],
                           gold_fp2_sub(L[M + CONF_AGGZK_MEMB_POSACC], bit));
    /* POSACC inert: (1 − active_memb)·POSACC == 0. */
    dnac_stark_folder_assert_zero(
        f, gold_fp2_mul(gold_fp2_sub(one, active_memb), L[M + CONF_AGGZK_MEMB_POSACC]));
    /* Chaining + POSACC chain (phi=i, i=2..D): transition gated
     * active_lvl[i−1]·active_lvl[i]. */
    for (unsigned i = 2; i <= CONF_AGGZK_D; i++) {
        const gold_fp2_t gate =
            gold_fp2_mul(L[CONF_AGGZK_ACTLVL_OFF + (i - 2)],
                         N[CONF_AGGZK_ACTLVL_OFF + (i - 1)]);
        for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++) {
            const gold_fp2_t loc_out = L[M + CONF_AGGZK_MEMB_MC2 + AGG_END_POST3(j)];
            const gold_fp2_t nxt_cur = N[M + CONF_AGGZK_MEMB_CUR + j];
            dnac_stark_folder_when(f, f->is_transition,
                                   gold_fp2_mul(gate, gold_fp2_sub(nxt_cur, loc_out)));
        }
        const gold_fp2_t w = fp2u((uint64_t)1 << (i - 1));
        const gold_fp2_t posacc_step =
            gold_fp2_sub(gold_fp2_sub(N[M + CONF_AGGZK_MEMB_POSACC],
                                      L[M + CONF_AGGZK_MEMB_POSACC]),
                         gold_fp2_mul(N[M + CONF_AGGZK_MEMB_BIT], w));
        dnac_stark_folder_when(f, f->is_transition, gold_fp2_mul(gate, posacc_step));
    }
    /* Last level (phi=D): root MC2.out == anchor; POSACC == pos_carry. */
    for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++)
        dnac_stark_folder_when(
            f, L[CONF_AGGZK_ACTLVL_OFF + (CONF_AGGZK_D - 1)],
            gold_fp2_sub(L[M + CONF_AGGZK_MEMB_MC2 + AGG_END_POST3(j)], anchor[j]));
    dnac_stark_folder_when(
        f, L[CONF_AGGZK_ACTLVL_OFF + (CONF_AGGZK_D - 1)],
        gold_fp2_sub(L[M + CONF_AGGZK_MEMB_POSACC], L[CONF_ACTION_POSCARRY_OFF]));

    /* ── C4 nullifier: RHO1/RHO2/NF1/NF2 Poseidon2 always-on + gated pins. ── */
    dnac_poseidon2_fold_eval(f, NF + CONF_AGGZK_NF_RHO1);
    dnac_poseidon2_fold_eval(f, NF + CONF_AGGZK_NF_RHO2);
    dnac_poseidon2_fold_eval(f, NF + CONF_AGGZK_NF_NF1);
    dnac_poseidon2_fold_eval(f, NF + CONF_AGGZK_NF_NF2);

    const gold_fp2_t gate_nf = gold_fp2_mul(is_nf, is_input);
    /* cm/pos/nk cells == C1 frozen carries. */
    for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_CM + j], L[CONF_ACTION_CMCARRY_OFF + j]));
    dnac_stark_folder_when(
        f, gate_nf, gold_fp2_sub(L[NF + CONF_AGGZK_NF_POS], L[CONF_ACTION_POSCARRY_OFF]));
    dnac_stark_folder_when(
        f, gate_nf, gold_fp2_sub(L[NF + CONF_AGGZK_NF_NK], L[CONF_ACTION_NKCARRY_OFF]));
    /* ρ = CRH(cm,pos): RHO1.in=[cm,0,0,0,0]; RHO2.in=[pos,DOMSEP_RHO,0,0,cap]. */
    for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_RHO1 + p2air_input_off(j)],
                         L[NF + CONF_AGGZK_NF_CM + j]));
    for (size_t k = 4; k < 8; k++)
        dnac_stark_folder_when(f, gate_nf,
                               L[NF + CONF_AGGZK_NF_RHO1 + p2air_input_off(k)]);
    dnac_stark_folder_when(
        f, gate_nf,
        gold_fp2_sub(L[NF + CONF_AGGZK_NF_RHO2 + p2air_input_off(0)],
                     L[NF + CONF_AGGZK_NF_POS]));
    dnac_stark_folder_when(
        f, gate_nf,
        gold_fp2_sub(L[NF + CONF_AGGZK_NF_RHO2 + p2air_input_off(1)], fp2u(DNAC_DOMSEP_RHO)));
    dnac_stark_folder_when(f, gate_nf, L[NF + CONF_AGGZK_NF_RHO2 + p2air_input_off(2)]);
    dnac_stark_folder_when(f, gate_nf, L[NF + CONF_AGGZK_NF_RHO2 + p2air_input_off(3)]);
    for (size_t k = 4; k < 8; k++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_RHO2 + p2air_input_off(k)],
                         L[NF + CONF_AGGZK_NF_RHO1 + AGG_END_POST3(k)]));
    /* nf = PRF(nk,ρ): NF1.in=[nk,ρ0,ρ1,ρ2,0,0,0,0]; NF2.in=[ρ3,DOMSEP_NF,0,0,cap]. */
    dnac_stark_folder_when(
        f, gate_nf,
        gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF1 + p2air_input_off(0)],
                     L[NF + CONF_AGGZK_NF_NK]));
    for (unsigned j = 0; j < 3; j++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF1 + p2air_input_off(1 + j)],
                         L[NF + CONF_AGGZK_NF_RHO2 + AGG_END_POST3(j)]));
    for (size_t k = 4; k < 8; k++)
        dnac_stark_folder_when(f, gate_nf,
                               L[NF + CONF_AGGZK_NF_NF1 + p2air_input_off(k)]);
    dnac_stark_folder_when(
        f, gate_nf,
        gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF2 + p2air_input_off(0)],
                     L[NF + CONF_AGGZK_NF_RHO2 + AGG_END_POST3(3)]));
    dnac_stark_folder_when(
        f, gate_nf,
        gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF2 + p2air_input_off(1)], fp2u(DNAC_DOMSEP_NF)));
    dnac_stark_folder_when(f, gate_nf, L[NF + CONF_AGGZK_NF_NF2 + p2air_input_off(2)]);
    dnac_stark_folder_when(f, gate_nf, L[NF + CONF_AGGZK_NF_NF2 + p2air_input_off(3)]);
    for (size_t k = 4; k < 8; k++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF2 + p2air_input_off(k)],
                         L[NF + CONF_AGGZK_NF_NF1 + AGG_END_POST3(k)]));
    /* NF cell == NF2.out. */
    for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++)
        dnac_stark_folder_when(
            f, gate_nf,
            gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF + j],
                         L[NF + CONF_AGGZK_NF_NF2 + AGG_END_POST3(j)]));
    /* Inert nf (¬gate_nf): CM/POS/NK/NF cells == 0. */
    const gold_fp2_t ninert = gold_fp2_sub(one, gate_nf);
    for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++)
        dnac_stark_folder_when(f, ninert, L[NF + CONF_AGGZK_NF_CM + j]);
    dnac_stark_folder_when(f, ninert, L[NF + CONF_AGGZK_NF_POS]);
    dnac_stark_folder_when(f, ninert, L[NF + CONF_AGGZK_NF_NK]);
    for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++)
        dnac_stark_folder_when(f, ninert, L[NF + CONF_AGGZK_NF_NF + j]);

    /* ── nf-public routing (N_input counter + position-forced slots). ── */
    const gold_fp2_t phi0 = L[CONF_ACTION_PHI0_OFF];
    /* first row: N_input == PHI0·IS_INPUT. */
    dnac_stark_folder_when(
        f, f->is_first_row,
        gold_fp2_sub(L[CONF_AGGZK_NIN_OFF], gold_fp2_mul(phi0, is_input)));
    /* transition: next.N_input − N_input − next.PHI0·next.IS_INPUT == 0. */
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_sub(gold_fp2_sub(N[CONF_AGGZK_NIN_OFF], L[CONF_AGGZK_NIN_OFF]),
                     gold_fp2_mul(N[CONF_ACTION_PHI0_OFF], N[CONF_ACTION_ISIN_OFF])));
    /* last row: N_input == num_input public (EXACT total-count). */
    dnac_stark_folder_when(f, f->is_last_row,
                           gold_fp2_sub(L[CONF_AGGZK_NIN_OFF], num_input_pub));
    /* slot_sel[s] = is_zero(N_input − 1 − s). */
    for (unsigned s = 0; s < CONF_AGGZK_MAX_INPUTS; s++) {
        const gold_fp2_t ss = L[CONF_AGGZK_SLOTSEL_OFF + s];
        dnac_stark_folder_assert_bool(f, ss);
        const gold_fp2_t e_s = gold_fp2_sub(L[CONF_AGGZK_NIN_OFF], fp2u((uint64_t)s + 1));
        dnac_stark_folder_assert_eq(f, gold_fp2_mul(e_s, L[CONF_AGGZK_INVSLOT_OFF + s]),
                                    gold_fp2_sub(one, ss));
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(e_s, ss));
    }
    /* Routing: gate_nf·slot_sel[s]·(NF cell − nf_slot[s]) == 0. */
    for (unsigned s = 0; s < CONF_AGGZK_MAX_INPUTS; s++) {
        const gold_fp2_t sel = gold_fp2_mul(gate_nf, L[CONF_AGGZK_SLOTSEL_OFF + s]);
        for (unsigned j = 0; j < CONF_AGGZK_NF_LANES; j++) {
            const gold_fp2_t slot = gold_fp2_from_base(
                PUB[CONF_AGGZK_PUB_NFSLOT + s * CONF_AGGZK_NF_LANES + j]);
            dnac_stark_folder_assert_zero(
                f, gold_fp2_mul(sel, gold_fp2_sub(L[NF + CONF_AGGZK_NF_NF + j], slot)));
        }
    }
    /* S4f GAP-1 fix: at every INPUT nullifier row EXACTLY ONE slot must be
     * selected — gate_nf·(Σ slot_sel[s] − 1) == 0 — forcing N_input ∈
     * [1, MAX_INPUTS] (a >MAX_INPUTS input has all slot_sel[s]=0 ⇒ sum 0 ≠ 1 ⇒
     * reject). Closes the unpublished-nullifier double-spend the red-team found. */
    {
        gold_fp2_t slot_sum = gold_fp2_zero();
        for (unsigned s = 0; s < CONF_AGGZK_MAX_INPUTS; s++)
            slot_sum = gold_fp2_add(slot_sum, L[CONF_AGGZK_SLOTSEL_OFF + s]);
        dnac_stark_folder_assert_zero(
            f, gold_fp2_mul(gate_nf, gold_fp2_sub(slot_sum, one)));
    }
}

const dnac_stark_air_t DNAC_CONF_ACTION_AGG_FOLD_AIR = {
    CONF_AGGZK_WIDTH,        /* main_width = 1936 */
    CONF_AGGZK_NUM_PUBLICS,  /* 21 */
    1,                       /* main_next: C1 counter/freeze + membership chaining + N_input */
    dnac_conf_action_agg_fold_air_eval,
};
