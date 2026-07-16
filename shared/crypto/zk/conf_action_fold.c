/**
 * @file conf_action_fold.c
 * @brief Dual-mode S1e — C1 Action AIR, verifier-fold (fp2) form.
 *
 * EMISSION ORDER is the contract: it mirrors the Rust-oracle
 * ConfActionAir::eval (tools/plonky3_oracle/src/main.rs) line for line — see
 * conf_action_fold.h. The four Poseidon2 sub-blocks (NC1/NC2 note-commitment,
 * AC1/AC2 spend-auth) fold through the shared dnac_poseidon2_fold_eval.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "conf_action_fold.h"

#include "poseidon2_air_cols.h"
#include "poseidon2_fold.h"  /* dnac_poseidon2_fold_eval */
#include "shielded_domsep.h" /* DNAC_DOMSEP_NOTE / DNAC_DOMSEP_ADDR */

/* end_post(3, ·) lane of a poseidon2 block (== the C nc_out()). */
#define CA_END_POST3(k) p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (k))

static inline gold_fp2_t fp2u(uint64_t v) {
    return gold_fp2_from_base(gold_fp_from_u64(v));
}

void dnac_conf_action_fold_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *L = f->trace_local;
    const gold_fp2_t *N = f->trace_next;
    const gold_fp2_t one = gold_fp2_one();
    /* No public values (as-built C1). */

    const gold_fp2_t phi = L[CONF_ACTION_PHI_OFF];
    const gold_fp2_t w = L[CONF_ACTION_W_OFF];
    const gold_fp2_t is_real = L[CONF_ACTION_ISREAL_OFF];
    const gold_fp2_t nreal = gold_fp2_sub(one, is_real);

    /* ── E1 range gate: phi = Σ b_i·2^i, each b_i boolean. ── */
    {
        gold_fp2_t recomp = gold_fp2_zero();
        gold_fp2_t weight = one;
        for (unsigned i = 0; i < CONF_ACTION_LOG_K; i++) {
            dnac_stark_folder_assert_bool(f, L[CONF_ACTION_PHIBITS_OFF + i]);
            recomp = gold_fp2_add(recomp,
                                  gold_fp2_mul(L[CONF_ACTION_PHIBITS_OFF + i], weight));
            weight = gold_fp2_add(weight, weight);
        }
        dnac_stark_folder_assert_eq(f, recomp, phi);
    }

    /* ── E2 wrap indicator via is_zero on d = phi − (K−1). ── */
    {
        const gold_fp2_t d = gold_fp2_sub(phi, fp2u((uint64_t)(CONF_ACTION_K - 1)));
        dnac_stark_folder_assert_bool(f, w);
        dnac_stark_folder_assert_eq(f, gold_fp2_mul(d, L[CONF_ACTION_INV_OFF]),
                                    gold_fp2_sub(one, w));
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(d, w));
    }

    /* ── E13 phi anchor: is_first_row·phi = 0. ── */
    dnac_stark_folder_when(f, f->is_first_row, phi);

    /* ── E3 forced counter (transition; w_prev = local w). ── */
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_mul(gold_fp2_sub(one, w),
                     gold_fp2_sub(gold_fp2_sub(N[CONF_ACTION_PHI_OFF], phi), one)));
    dnac_stark_folder_when(f, f->is_transition,
                           gold_fp2_mul(w, N[CONF_ACTION_PHI_OFF]));

    /* ── S1b freeze-carry: E6 booleanity + PZ + E8'/E4/E11. ── */
    dnac_stark_folder_assert_bool(f, is_real);
    for (unsigned j = 0; j < CONF_ACTION_CM_LANES; j++) {
        const gold_fp2_t carry = L[CONF_ACTION_CMCARRY_OFF + j];
        const gold_fp2_t out = L[CONF_ACTION_CMOUT_OFF + j];
        /* PZ padding-zero */
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(nreal, carry));
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(nreal, out));
        /* E8' block-0 init */
        dnac_stark_folder_when(f, f->is_first_row,
                               gold_fp2_mul(is_real, gold_fp2_sub(carry, out)));
        /* E4 freeze (non-wrap) */
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_mul(gold_fp2_sub(one, w),
                         gold_fp2_sub(N[CONF_ACTION_CMCARRY_OFF + j], carry)));
        /* E11 wrap-load (block start) */
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_mul(w, gold_fp2_sub(N[CONF_ACTION_CMCARRY_OFF + j],
                                         N[CONF_ACTION_CMOUT_OFF + j])));
    }
    /* E6 block-const: IS_REAL constant across a non-wrap adjacent pair. */
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_mul(gold_fp2_sub(one, w),
                     gold_fp2_sub(N[CONF_ACTION_ISREAL_OFF], is_real)));

    /* ── E15 frozen carries (pos/nk/addr) — same freeze pattern as cm. ── */
    {
        const size_t carry_off[3] = {CONF_ACTION_POSCARRY_OFF,
                                     CONF_ACTION_NKCARRY_OFF,
                                     CONF_ACTION_ADDRCARRY_OFF};
        const size_t src_off[3] = {CONF_ACTION_POSSRC_OFF, CONF_ACTION_NKSRC_OFF,
                                   CONF_ACTION_ADDR_OFF};
        const unsigned lanes[3] = {1, 1, CONF_ACTION_ADDR_LANES};
        for (unsigned c = 0; c < 3; c++) {
            for (unsigned j = 0; j < lanes[c]; j++) {
                const gold_fp2_t carry = L[carry_off[c] + j];
                /* padding-zero */
                dnac_stark_folder_assert_zero(f, gold_fp2_mul(nreal, carry));
                /* E8' block-0 init */
                dnac_stark_folder_when(
                    f, f->is_first_row,
                    gold_fp2_mul(is_real, gold_fp2_sub(carry, L[src_off[c] + j])));
                /* E4 freeze */
                dnac_stark_folder_when(
                    f, f->is_transition,
                    gold_fp2_mul(gold_fp2_sub(one, w),
                                 gold_fp2_sub(N[carry_off[c] + j], carry)));
                /* E11 wrap-load */
                dnac_stark_folder_when(
                    f, f->is_transition,
                    gold_fp2_mul(w, gold_fp2_sub(N[carry_off[c] + j],
                                                 N[src_off[c] + j])));
            }
        }
    }

    /* ── S1c note-commitment: NC1/NC2 Poseidon2 + gated pins. ── */
    dnac_poseidon2_fold_eval(f, CONF_ACTION_NC1_OFF);
    dnac_poseidon2_fold_eval(f, CONF_ACTION_NC2_OFF);
    {
        const gold_fp2_t nc_gate = gold_fp2_mul(L[CONF_ACTION_PHI0_OFF], is_real);
        /* NC1.in = [value, addr0, addr1, addr2, 0,0,0,0]. */
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC1_OFF + p2air_input_off(0)],
                         L[CONF_ACTION_VALUE_OFF]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC1_OFF + p2air_input_off(1)],
                         L[CONF_ACTION_ADDR_OFF + 0]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC1_OFF + p2air_input_off(2)],
                         L[CONF_ACTION_ADDR_OFF + 1]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC1_OFF + p2air_input_off(3)],
                         L[CONF_ACTION_ADDR_OFF + 2]));
        for (size_t k = 4; k < 8; k++)
            dnac_stark_folder_when(f, nc_gate,
                                   L[CONF_ACTION_NC1_OFF + p2air_input_off(k)]);
        /* NC2.in = [addr3, rcm0, rcm1, DOMSEP_NOTE, NC1.end_post(3,4..8)]. */
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC2_OFF + p2air_input_off(0)],
                         L[CONF_ACTION_ADDR_OFF + 3]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC2_OFF + p2air_input_off(1)],
                         L[CONF_ACTION_RCM_OFF + 0]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC2_OFF + p2air_input_off(2)],
                         L[CONF_ACTION_RCM_OFF + 1]));
        dnac_stark_folder_when(
            f, nc_gate,
            gold_fp2_sub(L[CONF_ACTION_NC2_OFF + p2air_input_off(3)],
                         fp2u(DNAC_DOMSEP_NOTE)));
        for (size_t k = 4; k < 8; k++)
            dnac_stark_folder_when(
                f, nc_gate,
                gold_fp2_sub(L[CONF_ACTION_NC2_OFF + p2air_input_off(k)],
                             L[CONF_ACTION_NC1_OFF + CA_END_POST3(k)]));
        /* cm_output == NC2.end_post(3, 0..4). */
        for (size_t j = 0; j < CONF_ACTION_CM_LANES; j++)
            dnac_stark_folder_when(
                f, nc_gate,
                gold_fp2_sub(L[CONF_ACTION_CMOUT_OFF + j],
                             L[CONF_ACTION_NC2_OFF + CA_END_POST3(j)]));
    }

    /* ── condition-3 spend-auth: AC1/AC2 Poseidon2 + gated pins. ── */
    dnac_poseidon2_fold_eval(f, CONF_ACTION_AC1_OFF);
    dnac_poseidon2_fold_eval(f, CONF_ACTION_AC2_OFF);
    {
        const gold_fp2_t ac_gate =
            gold_fp2_mul(L[CONF_ACTION_PHI0_OFF], L[CONF_ACTION_ISIN_OFF]);
        /* AC1.in = [ak, nk, DOMSEP_ADDR, 0, 0,0,0,0]. */
        dnac_stark_folder_when(
            f, ac_gate,
            gold_fp2_sub(L[CONF_ACTION_AC1_OFF + p2air_input_off(0)],
                         L[CONF_ACTION_AK_OFF]));
        dnac_stark_folder_when(
            f, ac_gate,
            gold_fp2_sub(L[CONF_ACTION_AC1_OFF + p2air_input_off(1)],
                         L[CONF_ACTION_NKSRC_OFF]));
        dnac_stark_folder_when(
            f, ac_gate,
            gold_fp2_sub(L[CONF_ACTION_AC1_OFF + p2air_input_off(2)],
                         fp2u(DNAC_DOMSEP_ADDR)));
        dnac_stark_folder_when(f, ac_gate,
                               L[CONF_ACTION_AC1_OFF + p2air_input_off(3)]);
        for (size_t k = 4; k < 8; k++)
            dnac_stark_folder_when(f, ac_gate,
                                   L[CONF_ACTION_AC1_OFF + p2air_input_off(k)]);
        /* AC2.in[0..4] = 0 (pad); AC2.in[4..8] = AC1.end_post(3, 4..8). */
        for (size_t k = 0; k < 4; k++)
            dnac_stark_folder_when(f, ac_gate,
                                   L[CONF_ACTION_AC2_OFF + p2air_input_off(k)]);
        for (size_t k = 4; k < 8; k++)
            dnac_stark_folder_when(
                f, ac_gate,
                gold_fp2_sub(L[CONF_ACTION_AC2_OFF + p2air_input_off(k)],
                             L[CONF_ACTION_AC1_OFF + CA_END_POST3(k)]));
        /* addr_pub (AC2.end_post) == the committed note ADDR[4]. */
        for (size_t j = 0; j < CONF_ACTION_ADDR_LANES; j++)
            dnac_stark_folder_when(
                f, ac_gate,
                gold_fp2_sub(L[CONF_ACTION_ADDR_OFF + j],
                             L[CONF_ACTION_AC2_OFF + CA_END_POST3(j)]));
    }

    /* ── S1d balance conservation ── */
    /* RANGE: value = Σ bits_j·2^j (52 bits). */
    {
        gold_fp2_t vrecomp = gold_fp2_zero();
        gold_fp2_t vweight = one;
        for (unsigned j = 0; j < CONF_ACTION_VALUE_BITS; j++) {
            dnac_stark_folder_assert_bool(f, L[CONF_ACTION_VBITS_OFF + j]);
            vrecomp = gold_fp2_add(
                vrecomp, gold_fp2_mul(L[CONF_ACTION_VBITS_OFF + j], vweight));
            vweight = gold_fp2_add(vweight, vweight);
        }
        dnac_stark_folder_assert_eq(f, vrecomp, L[CONF_ACTION_VALUE_OFF]);
    }
    /* ROLE: booleanity + exactly one role per real block. */
    dnac_stark_folder_assert_bool(f, L[CONF_ACTION_ISIN_OFF]);
    dnac_stark_folder_assert_bool(f, L[CONF_ACTION_ISOUT_OFF]);
    dnac_stark_folder_assert_bool(f, L[CONF_ACTION_ISFEE_OFF]);
    dnac_stark_folder_assert_eq(
        f, is_real,
        gold_fp2_add(gold_fp2_add(L[CONF_ACTION_ISIN_OFF], L[CONF_ACTION_ISOUT_OFF]),
                     L[CONF_ACTION_ISFEE_OFF]));
    /* PHI0 is_zero(phi). */
    {
        const gold_fp2_t phi0 = L[CONF_ACTION_PHI0_OFF];
        dnac_stark_folder_assert_bool(f, phi0);
        dnac_stark_folder_assert_eq(f, gold_fp2_mul(phi, L[CONF_ACTION_INV0_OFF]),
                                    gold_fp2_sub(one, phi0));
        dnac_stark_folder_assert_zero(f, gold_fp2_mul(phi, phi0));
        /* E10' IS_BAL_CONTRIB = phi0·IS_REAL. */
        dnac_stark_folder_assert_eq(f, L[CONF_ACTION_BALCON_OFF],
                                    gold_fp2_mul(phi0, is_real));
    }
    /* E14 bal_coeff = IS_BAL_CONTRIB·(IS_INPUT − IS_OUTPUT − IS_FEE). */
    {
        const gold_fp2_t sign =
            gold_fp2_sub(gold_fp2_sub(L[CONF_ACTION_ISIN_OFF], L[CONF_ACTION_ISOUT_OFF]),
                         L[CONF_ACTION_ISFEE_OFF]);
        dnac_stark_folder_assert_eq(f, L[CONF_ACTION_BALCOEF_OFF],
                                    gold_fp2_mul(L[CONF_ACTION_BALCON_OFF], sign));
    }
    /* BAL accumulator: first = own contribution; transition adds this row's;
     * last = 0. */
    dnac_stark_folder_when(
        f, f->is_first_row,
        gold_fp2_sub(L[CONF_ACTION_BAL_OFF],
                     gold_fp2_mul(L[CONF_ACTION_BALCOEF_OFF], L[CONF_ACTION_VALUE_OFF])));
    dnac_stark_folder_when(
        f, f->is_transition,
        gold_fp2_sub(gold_fp2_sub(N[CONF_ACTION_BAL_OFF], L[CONF_ACTION_BAL_OFF]),
                     gold_fp2_mul(N[CONF_ACTION_BALCOEF_OFF], N[CONF_ACTION_VALUE_OFF])));
    dnac_stark_folder_when(f, f->is_last_row, L[CONF_ACTION_BAL_OFF]);

    /* E17 role selectors per-block const (non-wrap transition). */
    {
        const gold_fp2_t g = gold_fp2_sub(one, w);
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_mul(g, gold_fp2_sub(N[CONF_ACTION_ISIN_OFF], L[CONF_ACTION_ISIN_OFF])));
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_mul(g, gold_fp2_sub(N[CONF_ACTION_ISOUT_OFF], L[CONF_ACTION_ISOUT_OFF])));
        dnac_stark_folder_when(
            f, f->is_transition,
            gold_fp2_mul(g, gold_fp2_sub(N[CONF_ACTION_ISFEE_OFF], L[CONF_ACTION_ISFEE_OFF])));
    }

    /* E7 dummy-last: the final row is dummy. */
    dnac_stark_folder_when(f, f->is_last_row, is_real);
}

const dnac_stark_air_t DNAC_CONF_ACTION_FOLD_AIR = {
    CONF_ACTION_WIDTH,            /* main_width = 813 */
    CONF_ACTION_FOLD_NUM_PUBLICS, /* 0 */
    1,                           /* main_next: counter/freeze/carry/BAL read next */
    dnac_conf_action_fold_air_eval,
};
