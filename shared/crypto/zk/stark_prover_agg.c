/**
 * @file stark_prover_agg.c
 * @brief Dual-mode S4b.4 — pure-C prover for the AGGREGATE Action AIR.
 *
 * Mirrors the C1 Action prover (stark_prover_action.c) with the aggregate
 * constants and the two AIR-specific stages swapped (S1 trace = the
 * CONF_AGGZK_WIDTH-wide ZK generator agg_zk_generate, S6 quotient =
 * dnac_conf_action_agg_fold_air_eval
 * with the 43 public values). SALT (P4): optional M3b leaf-salt via
 * instance.salt_draws (SE=0 when NULL => byte-identical unsalted). See stark_prover_agg.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_prover_agg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "batch_prover.h"         /* d4.c-2: the batched prover this delegates to */
#include "batch_verify.h"         /* d4.c-2: re-verify the wrapped 1-instance proof */
#include "field_goldilocks.h"
#include "fri_proof_codec.h"      /* Phase-P: shielded wire self-check (DZKF v4) */
#include "poseidon2_air_cols.h"
#include "poseidon2_air_trace.h"
#include "shielded_domsep.h"
#include "shielded_fri_params.h"  /* Phase-P: pinned production FRI params */
#include "stark_constraints.h"
#include "zk_entropy.h"           /* Phase-P: OS-entropy production draws */

/* Fixed aggregate / is_zk=1 config constants. */
#define A_IS_ZK 1u
#define A_LOG_BLOWUP 2u
#define A_LOG_FINAL_POLY_LEN 2u
#define A_MAX_LOG_ARITY 1u
#define A_NUM_QUERIES 2u
#define A_NUM_QC 8u
#define A_LOG_NUM_QC 2u
#define A_NUM_RANDOM 4u
#define A_W ((size_t)CONF_AGGZK_WIDTH)     /* 2318 (post-F3) */
#define A_RAND_W (A_W + A_NUM_RANDOM)      /* 1950 */
#define A_CW ((size_t)2 + A_NUM_RANDOM)    /* 6 */
#define A_NUM_PUBLICS ((size_t)CONF_AGGZK_NUM_PUBLICS) /* 43 (S4c) */
#define A_SALT_ELEMS 2u                    /* P4: M3b leaf-salt (128-bit nominal), mirror C_SALT_ELEMS */

/* ── Phase-P: runtime FRI config (the pipeline is parametric over these; the
 * A_* values above stay the byte-stable KAT/test set). ── */
#define A_MAX_QUERIES 128u /* proof-struct bound; >= the pinned production 100 */
typedef struct {
    unsigned num_queries;
    unsigned log_final_poly_len;
    unsigned commit_pow_bits;
    unsigned query_pow_bits;
} agg_fri_cfg_t;
static const agg_fri_cfg_t AGG_CFG_TEST = {
    A_NUM_QUERIES, A_LOG_FINAL_POLY_LEN, 0u, 0u};
static const agg_fri_cfg_t AGG_CFG_SHIELDED = {
    (unsigned)DNAC_SHIELDED_FRI_NUM_QUERIES,
    (unsigned)DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN,
    (unsigned)DNAC_SHIELDED_FRI_COMMIT_POW_BITS,
    (unsigned)DNAC_SHIELDED_FRI_QUERY_POW_BITS};
/* The compile-time half of the pinned set MUST equal the shielded consensus
 * constants — a drifted A_LOG_BLOWUP would silently change the security level
 * the production entry claims (mutation-hardening, same pattern as
 * SB_CT_ASSERT in test_air_column_layout_sum_balance.c). */
#define AGG_CT_ASSERT(cond, tag) typedef char agg_ct_assert_##tag[(cond) ? 1 : -1]
AGG_CT_ASSERT(A_LOG_BLOWUP == DNAC_SHIELDED_FRI_LOG_BLOWUP, blowup_pinned);
AGG_CT_ASSERT(A_MAX_LOG_ARITY == DNAC_SHIELDED_FRI_MAX_LOG_ARITY, arity_pinned);
AGG_CT_ASSERT(A_IS_ZK == DNAC_SHIELDED_IS_ZK, is_zk_pinned);
AGG_CT_ASSERT(DNAC_SHIELDED_FRI_NUM_QUERIES <= A_MAX_QUERIES, queries_fit);
/* The DNAC_AGG_PROVER_SALT_DRAWS coefficient (160 per height unit) is EXACTLY
 * tight against the max stream-A index used in S12
 * (SE·lde_h·(1 trace + A_NUM_QC quotient + 1 random) − 1, lde_h =
 * 2^(blowup+is_zk)·h): any bump to SE/A_NUM_QC/blowup/is_zk without updating
 * the header macro would be an OOB heap read (Phase-P red-team INFO-3). Pin it. */
AGG_CT_ASSERT((size_t)A_SALT_ELEMS * ((size_t)1 << (A_LOG_BLOWUP + A_IS_ZK)) *
                      (2u + A_NUM_QC) ==
                  DNAC_AGG_PROVER_SALT_DRAWS(1),
              salt_draws_coeff_tight);
/* G-SEC-P1-6 (P1c): the prover's salt count IS the consensus pin — the
 * shielded wire entry rejects any other value fail-close. A drift here would
 * make every honest proof unverifiable (liveness), never unsound. */
AGG_CT_ASSERT((size_t)A_SALT_ELEMS == DNAC_SHIELDED_SALT_ELEMS,
              salt_elems_matches_consensus_pin);

/* d4.c-2: the aggregate proof is now a THIN WRAPPER over a batched proof
 * (dnac_batch_prove, 1-instance is_zk=1) — the v3 S1-S13 uni-stark pipeline is
 * retired. The wrapper owns the batched proof + the 43 publics agg_zk_generate
 * computed + the FRI params it was proved with (for re-verify + wire encode);
 * every accessor reads straight from the batched proof. */
struct dnac_agg_prover_proof_s {
    dnac_batch_proof_t *bp;              /* owns the whole batched proof         */
    gold_fp_t publics[A_NUM_PUBLICS];    /* 43, from agg_zk_generate             */
    size_t base_degree_bits;             /* log_height                           */
    size_t degree_bits;                  /* log_height + A_IS_ZK                  */
    dnac_fri_params_t params;            /* the params bp was proved with        */
};

/* poseidon2-air block output lane k (end_post of the final full round). */
static uint64_t p2out(const uint64_t *blk, unsigned k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)k)];
}

/* ── S1: the CONF_AGGZK_WIDTH-wide (2318 post-F3) ZK trace — byte-matches
 * generate_conf_action_agg_trace.
 * C1 scatter + membership walk (φ∈[1,D]) + nullifier sponge (φ=D+1) + the
 * is_zero SELECTOR columns (is_nf / is_lvl / active_lvl / N_input / slot_sel).
 * Also computes the 43 public values (anchor / num_input / nf_slots). ── */
static bool agg_zk_generate(unsigned log_height,
                            const dnac_agg_prover_instance_t *inst,
                            uint64_t *trace_out, gold_fp_t *pub_out) {
    const size_t rows = (size_t)1 << log_height;
    const size_t K = CONF_ACTION_K;
    const unsigned D = CONF_AGGZK_D;

    uint64_t *c1 =
        (uint64_t *)calloc(rows * CONF_ACTION_WIDTH, sizeof(uint64_t));
    if (!c1) return false;
    if (!conf_action_air_generate(log_height, inst->value, inst->addr, inst->rcm,
                                  inst->roles, inst->pos, inst->nk, inst->ak,
                                  inst->num_notes, c1)) {
        free(c1);
        return false;
    }

    for (size_t i = 0; i < rows * CONF_AGGZK_WIDTH; i++) trace_out[i] = 0;

    uint64_t zero_in[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t zero_blk[P2AIR_NUM_COLS];
    poseidon2_air_generate_row(zero_in, zero_blk);

    /* ── Pass 1: scatter C1 + selectors + inert poseidon blocks. ── */
    uint64_t n_in_acc = 0;
    uint64_t n_out_acc = 0; /* S4c: running OUTPUT-block counter. */
    uint64_t f_acc = 0;     /* S4c: running Σ(IS_FEE·value). */
    for (size_t r = 0; r < rows; r++) {
        uint64_t *row = trace_out + r * CONF_AGGZK_WIDTH;
        memcpy(row, c1 + r * CONF_ACTION_WIDTH,
               CONF_ACTION_WIDTH * sizeof(uint64_t));

        const uint64_t phi = (uint64_t)(r % K);
        const size_t blk = r / K;
        const int is_input =
            blk < inst->num_notes && inst->roles[blk] == CONF_ACTION_ROLE_INPUT;

        const int is_nf = (phi == CONF_AGGZK_NF_PHI);
        row[CONF_AGGZK_ISNF_OFF] = is_nf ? 1u : 0u;
        {
            const gold_fp_t d = gold_fp_sub(gold_fp_from_u64(phi),
                                            gold_fp_from_u64(CONF_AGGZK_NF_PHI));
            row[CONF_AGGZK_INVNF_OFF] = is_nf ? 0 : gold_fp_to_u64(gold_fp_inv(d));
        }
        for (unsigned i = 1; i <= D; i++) {
            const int is_lvl = (phi == (uint64_t)i);
            row[CONF_AGGZK_ISLVL_OFF + (i - 1)] = is_lvl ? 1u : 0u;
            const gold_fp_t d = gold_fp_sub(gold_fp_from_u64(phi),
                                            gold_fp_from_u64((uint64_t)i));
            row[CONF_AGGZK_INVLVL_OFF + (i - 1)] =
                is_lvl ? 0 : gold_fp_to_u64(gold_fp_inv(d));
            row[CONF_AGGZK_ACTLVL_OFF + (i - 1)] = (is_lvl && is_input) ? 1u : 0u;
        }
        if (phi == 0 && is_input) n_in_acc += 1;
        row[CONF_AGGZK_NIN_OFF] = n_in_acc;
        for (unsigned s = 0; s < CONF_AGGZK_MAX_INPUTS; s++) {
            const int sel = (n_in_acc == (uint64_t)s + 1);
            row[CONF_AGGZK_SLOTSEL_OFF + s] = sel ? 1u : 0u;
            const gold_fp_t e = gold_fp_sub(gold_fp_from_u64(n_in_acc),
                                            gold_fp_from_u64((uint64_t)s + 1));
            row[CONF_AGGZK_INVSLOT_OFF + s] = sel ? 0 : gold_fp_to_u64(gold_fp_inv(e));
        }

        /* S4c: N_output counter + oslot_sel[s] = is_zero(N_output−1−s). */
        const int is_output =
            blk < inst->num_notes && inst->roles[blk] == CONF_ACTION_ROLE_OUTPUT;
        if (phi == 0 && is_output) n_out_acc += 1;
        row[CONF_AGGZK_NOUT_OFF] = n_out_acc;
        for (unsigned s = 0; s < CONF_AGGZK_MAX_OUTPUTS; s++) {
            const int osel = (n_out_acc == (uint64_t)s + 1);
            row[CONF_AGGZK_OSLOTSEL_OFF + s] = osel ? 1u : 0u;
            const gold_fp_t e = gold_fp_sub(gold_fp_from_u64(n_out_acc),
                                            gold_fp_from_u64((uint64_t)s + 1));
            row[CONF_AGGZK_INVOSLOT_OFF + s] = osel ? 0 : gold_fp_to_u64(gold_fp_inv(e));
        }
        /* S4c: FEE_ACC = running Σ(IS_FEE·value) (fee binding, mirrors N_input). */
        const int is_fee =
            blk < inst->num_notes && inst->roles[blk] == CONF_ACTION_ROLE_FEE;
        if (phi == 0 && is_fee) f_acc += inst->value[blk];
        row[CONF_AGGZK_FEEACC_OFF] = f_acc;

        uint64_t *m = row + CONF_AGGZK_MEMB_OFF;
        memcpy(m + CONF_AGGZK_MEMB_MC1, zero_blk, sizeof zero_blk);
        memcpy(m + CONF_AGGZK_MEMB_MC2, zero_blk, sizeof zero_blk);
        uint64_t *nfr = row + CONF_AGGZK_NF_OFF;
        memcpy(nfr + CONF_AGGZK_NF_RHO1, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_RHO2, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_NF1, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_NF2, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_NF3, zero_blk, sizeof zero_blk);
    }

    /* ── Pass 2: membership walk + nullifier + publics. ── */
    uint64_t anchor[4] = {0, 0, 0, 0};
    int have_anchor = 0;
    uint64_t num_input = 0;
    uint64_t nf_slots[CONF_AGGZK_MAX_INPUTS][4];
    memset(nf_slots, 0, sizeof nf_slots);

    for (size_t blk = 0; blk < inst->num_notes; blk++) {
        if (inst->roles[blk] != CONF_ACTION_ROLE_INPUT) continue;
        if (!inst->memb_siblings) { free(c1); return false; }

        const uint64_t *blk0 = trace_out + (blk * K) * CONF_AGGZK_WIDTH;
        uint64_t cur[4], cm0[4];
        for (unsigned j = 0; j < 4; j++)
            cur[j] = blk0[CONF_ACTION_CMCARRY_OFF + j];
        memcpy(cm0, cur, sizeof cm0);

        const uint64_t *sibs = inst->memb_siblings + blk * (size_t)D * 4;
        uint64_t pacc = 0;
        for (unsigned i = 0; i < D; i++) {
            const size_t rr = blk * K + (i + 1);
            uint64_t *m = trace_out + rr * CONF_AGGZK_WIDTH + CONF_AGGZK_MEMB_OFF;
            const uint64_t *sib = sibs + (size_t)i * 4;
            const uint64_t bit = (inst->pos[blk] >> i) & 1u;
            for (unsigned j = 0; j < 4; j++) {
                m[CONF_AGGZK_MEMB_CUR + j] = cur[j];
                m[CONF_AGGZK_MEMB_SIB + j] = sib[j];
            }
            m[CONF_AGGZK_MEMB_BIT] = bit;
            uint64_t left[4], right[4];
            for (unsigned j = 0; j < 4; j++) {
                left[j] = bit ? sib[j] : cur[j];
                right[j] = bit ? cur[j] : sib[j];
            }
            uint64_t in1[8] = {left[0], left[1], left[2], left[3], 0, 0, 0, 0};
            poseidon2_air_generate_row(in1, m + CONF_AGGZK_MEMB_MC1);
            uint64_t s1[8];
            for (unsigned k = 0; k < 8; k++)
                s1[k] = p2out(m + CONF_AGGZK_MEMB_MC1, k);
            uint64_t in2[8] = {right[0], right[1], right[2], right[3],
                               s1[4], s1[5], s1[6], s1[7]};
            poseidon2_air_generate_row(in2, m + CONF_AGGZK_MEMB_MC2);
            for (unsigned j = 0; j < 4; j++)
                cur[j] = p2out(m + CONF_AGGZK_MEMB_MC2, j);
            pacc += bit << i;
            m[CONF_AGGZK_MEMB_POSACC] = pacc;
        }

        if (!have_anchor) {
            memcpy(anchor, cur, sizeof cur);
            have_anchor = 1;
        } else {
            for (unsigned j = 0; j < 4; j++)
                if (cur[j] != anchor[j]) { free(c1); return false; }
        }

        const size_t nfrow = blk * K + (size_t)(D + 1);
        uint64_t *nfr = trace_out + nfrow * CONF_AGGZK_WIDTH + CONF_AGGZK_NF_OFF;
        const uint64_t np = inst->pos[blk];
        const uint64_t *nnk = inst->nk + blk * CONF_AGGZK_NF_NK_LANES;
        for (unsigned j = 0; j < 4; j++) nfr[CONF_AGGZK_NF_CM + j] = cm0[j];
        nfr[CONF_AGGZK_NF_POS] = np;
        for (unsigned j = 0; j < CONF_AGGZK_NF_NK_LANES; j++)
            nfr[CONF_AGGZK_NF_NK + j] = nnk[j];
        uint64_t rin1[8] = {cm0[0], cm0[1], cm0[2], cm0[3], 0, 0, 0, 0};
        poseidon2_air_generate_row(rin1, nfr + CONF_AGGZK_NF_RHO1);
        uint64_t rs1[8];
        for (unsigned k = 0; k < 8; k++) rs1[k] = p2out(nfr + CONF_AGGZK_NF_RHO1, k);
        uint64_t rin2[8] = {np, DNAC_DOMSEP_RHO, 0, 0, rs1[4], rs1[5], rs1[6], rs1[7]};
        poseidon2_air_generate_row(rin2, nfr + CONF_AGGZK_NF_RHO2);
        uint64_t rho[4];
        for (unsigned j = 0; j < 4; j++) rho[j] = p2out(nfr + CONF_AGGZK_NF_RHO2, j);
        /* F3 nf sponge: 12-slot [nk0..3, ρ0..3, DOMSEP_NF, 0,0,0] = 3 perms. */
        uint64_t nin1[8] = {nnk[0], nnk[1], nnk[2], nnk[3], 0, 0, 0, 0};
        poseidon2_air_generate_row(nin1, nfr + CONF_AGGZK_NF_NF1);
        uint64_t ns1[8];
        for (unsigned k = 0; k < 8; k++) ns1[k] = p2out(nfr + CONF_AGGZK_NF_NF1, k);
        uint64_t nin2[8] = {rho[0], rho[1], rho[2], rho[3],
                            ns1[4], ns1[5], ns1[6], ns1[7]};
        poseidon2_air_generate_row(nin2, nfr + CONF_AGGZK_NF_NF2);
        uint64_t ns2[8];
        for (unsigned k = 0; k < 8; k++) ns2[k] = p2out(nfr + CONF_AGGZK_NF_NF2, k);
        uint64_t nin3[8] = {DNAC_DOMSEP_NF, 0, 0, 0, ns2[4], ns2[5], ns2[6], ns2[7]};
        poseidon2_air_generate_row(nin3, nfr + CONF_AGGZK_NF_NF3);
        uint64_t nf[4];
        for (unsigned j = 0; j < 4; j++) nf[j] = p2out(nfr + CONF_AGGZK_NF_NF3, j);
        for (unsigned j = 0; j < 4; j++) nfr[CONF_AGGZK_NF_NF + j] = nf[j];

        if (num_input >= CONF_AGGZK_MAX_INPUTS) { free(c1); return false; }
        for (unsigned j = 0; j < 4; j++) nf_slots[num_input][j] = nf[j];
        num_input++;
    }
    free(c1);

    for (unsigned j = 0; j < 4; j++)
        pub_out[CONF_AGGZK_PUB_ANCHOR + j] = gold_fp_from_u64(anchor[j]);
    pub_out[CONF_AGGZK_PUB_NUMIN] = gold_fp_from_u64(num_input);
    for (unsigned s = 0; s < CONF_AGGZK_MAX_INPUTS; s++)
        for (unsigned j = 0; j < 4; j++)
            pub_out[CONF_AGGZK_PUB_NFSLOT + s * 4 + j] =
                gold_fp_from_u64(nf_slots[s][j]);

    /* ── S4c OUTPUT/FEE publics: output_commit[s] = s-th OUTPUT block's frozen
     *    cm_carry (φ=0 row); fee = FEE_ACC last-row total; tx_binding = 0. ── */
    uint64_t num_output = 0;
    for (size_t blk = 0; blk < inst->num_notes; blk++) {
        if (inst->roles[blk] != CONF_ACTION_ROLE_OUTPUT) continue;
        if (num_output >= CONF_AGGZK_MAX_OUTPUTS) return false;
        const uint64_t *blk0 = trace_out + (blk * K) * CONF_AGGZK_WIDTH;
        for (unsigned j = 0; j < 4; j++)
            pub_out[CONF_AGGZK_PUB_OCOMMIT + num_output * 4 + j] =
                gold_fp_from_u64(blk0[CONF_ACTION_CMCARRY_OFF + j]);
        num_output++;
    }
    pub_out[CONF_AGGZK_PUB_NUMOUT] = gold_fp_from_u64(num_output);
    {
        const uint64_t *lastrow = trace_out + (rows - 1) * CONF_AGGZK_WIDTH;
        pub_out[CONF_AGGZK_PUB_FEE] = gold_fp_from_u64(lastrow[CONF_AGGZK_FEEACC_OFF]);
    }
    for (unsigned j = 0; j < CONF_AGGZK_MEMB_LANES; j++)
        pub_out[CONF_AGGZK_PUB_TXBIND + j] =
            gold_fp_from_u64(inst->tx_binding ? inst->tx_binding[j] : 0); /* FS-observed */
    return true;
}

/* ── d4.c-2: the pinned 1-instance aggregate batched descriptor. The AIR is
 * DNAC_CONF_ACTION_AGG_FOLD_AIR; is_zk=1, log_num_qc=2 (num_qc=8), 43 publics,
 * NO lookups / preprocessed / permutation. Both the prove delegation and the
 * re-verify build exactly this. ── */
static void agg_fill_vinstance(dnac_batch_vinstance_t *vi, size_t degree_bits,
                               const gold_fp_t *publics) {
    memset(vi, 0, sizeof(*vi));
    vi->air = DNAC_CONF_ACTION_AGG_FOLD_AIR;
    vi->preprocessed_width = 0;
    vi->prep_next = 0;
    vi->pool = NULL;
    vi->pool_len = 0;
    vi->lookups = NULL;
    vi->num_lookups = 0;
    /* vi->view zeroed by memset (num_locals = num_globals = 0). */
    vi->degree_bits = (uint32_t)degree_bits;
    vi->log_num_qc = A_LOG_NUM_QC;
    vi->public_values = publics;
    vi->num_publics = (uint32_t)A_NUM_PUBLICS;
}

/* ζ_next(i) = ζ · two_adic_generator(base_db) (verifier/mod.rs:306-310). */
static gold_fp2_t agg_zeta_next(gold_fp2_t zeta, size_t base_db) {
    return gold_fp2_mul(
        zeta, gold_fp2_from_base(gold_fp_two_adic_generator((unsigned)base_db)));
}

/* Batch commit lanes (gold_fp_t[4]) → 4-lane u64 digest. */
static void agg_lanes_to_digest(const gold_fp_t lanes[4],
                                dnac_p2_digest_t *out) {
    for (unsigned k = 0; k < 4; k++) out->lanes[k] = gold_fp_to_u64(lanes[k]);
}

/* Re-verify: rebuild the 1-instance vinstance + run the d2 batched verify on
 * the wrapped proof (the prover already self-verified inside dnac_batch_prove;
 * this is the KAT-facing re-check). */
dnac_fri_status_t dnac_agg_prover_proof_verify(const dnac_agg_prover_proof_t *cp) {
    if (cp == NULL || cp->bp == NULL) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    dnac_agg_prover_proof_t *p = (dnac_agg_prover_proof_t *)cp;
    dnac_batch_vinstance_t vi;
    agg_fill_vinstance(&vi, p->degree_bits, p->publics);
    dnac_batch_vcommits_t commits;
    dnac_batch_proof_commits(p->bp, &commits);
    const dnac_batch_vopened_t *opened = dnac_batch_proof_opened(p->bp, 0);
    dnac_batch_verify_out_t vo;
    memset(&vo, 0, sizeof(vo));
    dnac_batch_verify_status_t st = dnac_batch_verify(
        &vi, opened, 1, A_IS_ZK, &commits, NULL, 0, &p->params,
        dnac_batch_proof_fri(p->bp), dnac_batch_proof_rand_openings(p->bp), &vo);
    return st == DNAC_BV_OK ? DNAC_FRI_OK : DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
}

void dnac_agg_prover_proof_zeta(const dnac_agg_prover_proof_t *p,
                                gold_fp2_t *zeta, gold_fp2_t *zeta_next) {
    gold_fp2_t a, z;
    dnac_batch_proof_alpha_zeta(p->bp, &a, &z);
    if (zeta) *zeta = z;
    if (zeta_next) *zeta_next = agg_zeta_next(z, p->base_degree_bits);
}

void dnac_agg_prover_proof_roots(const dnac_agg_prover_proof_t *p,
                                 dnac_p2_digest_t *trace_root,
                                 dnac_p2_digest_t *quot_root,
                                 dnac_p2_digest_t *rand_root) {
    dnac_batch_vcommits_t c;
    dnac_batch_proof_commits(p->bp, &c);
    if (trace_root && c.main_commit) agg_lanes_to_digest(c.main_commit, trace_root);
    if (quot_root && c.quotient_commit)
        agg_lanes_to_digest(c.quotient_commit, quot_root);
    if (rand_root && c.random_commit) agg_lanes_to_digest(c.random_commit, rand_root);
}

const gold_fp2_t *dnac_agg_prover_proof_final_poly(
    const dnac_agg_prover_proof_t *p, size_t *out_len) {
    const dnac_fri_proof_t *fp = dnac_batch_proof_fri(p->bp);
    if (out_len) *out_len = fp->num_final_poly;
    return fp->final_poly;
}

const gold_fp_t *dnac_agg_prover_proof_publics(const dnac_agg_prover_proof_t *p,
                                               size_t *out_len) {
    if (out_len) *out_len = A_NUM_PUBLICS;
    return p->publics;
}

void dnac_agg_prover_proof_free(dnac_agg_prover_proof_t *p) {
    if (p == NULL) return;
    if (p->bp) dnac_batch_proof_free(p->bp);
    free(p);
}

/* ── d4.c-2: prove by DELEGATING to dnac_batch_prove (1-instance is_zk=1 batch).
 * agg_zk_generate builds the raw 2318-wide witness + the 43 publics; the batched
 * prover does the whole pipeline and SELF-VERIFIES. SE = A_SALT_ELEMS iff
 * inst->salt_draws is set (unsalted otherwise, byte-identical). fs_publics_
 * override != NULL is the C2.1 CRIT-1 forge (test-wire only): the FS observes
 * the forged publics while the quotient folds the TRUE ones. ── */
static dnac_prover_status_t agg_prove_cfg(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof,
    const agg_fri_cfg_t              *cfg,
    const uint64_t                   *fs_publics_override) {
    (void)fs_publics_override;
    if (inst == NULL || out_proof == NULL || inst->draws == NULL || cfg == NULL) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (inst->log_height < CONF_ACTION_MIN_LOG_HEIGHT ||
        inst->log_height > CONF_ACTION_MAX_LOG_HEIGHT) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t height = (size_t)1 << inst->log_height;
    if (height > STARK_PROVER_MAX_HEIGHT) return DNAC_PROVER_ERR_PARAM;
    if (inst->num_draws != DNAC_AGG_PROVER_TOTAL_DRAWS(height)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (cfg->num_queries == 0 || cfg->num_queries > A_MAX_QUERIES) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* P4: if salted, the input-mmcs salt stream must cover >= 160h (mirror). */
    const size_t SE = inst->salt_draws ? (size_t)A_SALT_ELEMS : 0;
    if (inst->salt_draws &&
        inst->num_salt_draws < DNAC_AGG_PROVER_SALT_DRAWS(height)) {
        return DNAC_PROVER_ERR_PARAM;
    }

    dnac_agg_prover_proof_t *p =
        (dnac_agg_prover_proof_t *)calloc(1, sizeof(*p));
    if (p == NULL) return DNAC_PROVER_ERR_PARAM;
    p->base_degree_bits = inst->log_height;
    p->degree_bits = inst->log_height + A_IS_ZK;

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    uint64_t *raw_trace = (uint64_t *)malloc(height * A_W * sizeof(uint64_t));
    if (raw_trace == NULL) { free(p); return DNAC_PROVER_ERR_PARAM; }

    /* ── S1: raw witness + the 43 publics (agg_zk_generate zero-fills the whole
     * trace; the pubs live in the calloc'd struct so unused slots stay 0). ── */
    if (!agg_zk_generate(inst->log_height, inst, raw_trace, p->publics)) {
        rc = DNAC_PROVER_ERR_RANGE;
        goto cleanup;
    }

    dnac_batch_vinstance_t vi;
    agg_fill_vinstance(&vi, p->degree_bits, p->publics);
    dnac_batch_pwitness_t wi;
    wi.main_trace = raw_trace;
    wi.prep_trace = NULL;

    memset(&p->params, 0, sizeof(p->params));
    p->params.log_blowup = A_LOG_BLOWUP;
    p->params.log_final_poly_len = cfg->log_final_poly_len;
    p->params.max_log_arity = A_MAX_LOG_ARITY;
    p->params.num_queries = cfg->num_queries;
    p->params.commit_proof_of_work_bits = cfg->commit_pow_bits;
    p->params.query_proof_of_work_bits = cfg->query_pow_bits;

    /* Stream B (FRI mmcs) = the INDEPENDENT fri_salt_draws when set; NULL falls
     * back to salt_draws@0 (KAT clone-seed parity, P1e-HIGH1). */
    const uint64_t *fri_sd =
        inst->salt_draws
            ? (inst->fri_salt_draws ? inst->fri_salt_draws : inst->salt_draws)
            : NULL;
    const size_t nfs =
        inst->salt_draws
            ? (inst->fri_salt_draws ? inst->num_fri_salt_draws
                                    : inst->num_salt_draws)
            : 0;

    dnac_batch_proof_t *bp = NULL;
    dnac_prover_status_t s;
#ifdef DNAC_ZK_ENABLE_TEST_WIRE
    if (fs_publics_override != NULL) {
        gold_fp_t forged_fp[A_NUM_PUBLICS];
        for (size_t i = 0; i < A_NUM_PUBLICS; i++)
            forged_fp[i] = gold_fp_from_u64(fs_publics_override[i]);
        s = dnac_batch_prove_forged_fs_testonly(
            &vi, &wi, 1, A_IS_ZK, &p->params, A_NUM_RANDOM, inst->draws,
            inst->num_draws, SE ? inst->salt_draws : NULL,
            SE ? inst->num_salt_draws : 0, SE ? fri_sd : NULL, SE ? nfs : 0, SE,
            forged_fp, &bp);
    } else
#endif
    {
        s = dnac_batch_prove(&vi, &wi, 1, A_IS_ZK, &p->params, A_NUM_RANDOM,
                             inst->draws, inst->num_draws,
                             SE ? inst->salt_draws : NULL,
                             SE ? inst->num_salt_draws : 0, SE ? fri_sd : NULL,
                             SE ? nfs : 0, SE, &bp);
    }
    if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
    p->bp = bp;

    /* num_qc STOP gate (P1d precedent): the batched symbolic analysis MUST land
     * on the pinned chunk count — a deviation would silently invalidate the
     * shielded verifier's SV_NUM_QC pin. */
    {
        const dnac_batch_vopened_t *op = dnac_batch_proof_opened(p->bp, 0);
        if (op == NULL || op->num_quotient_chunks != (uint32_t)A_NUM_QC) {
            rc = DNAC_PROVER_ERR_VERIFY;
            goto cleanup;
        }
    }

    rc = DNAC_PROVER_OK;
    *out_proof = p;
    p = NULL;

cleanup:
    free(raw_trace);
    if (p) dnac_agg_prover_proof_free(p);
    return rc;
}

dnac_prover_status_t dnac_agg_prover_prove(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof) {
    /* The byte-stable KAT/test entry — TEST FRI params, PoW 0/0. Unsalted
     * unless the caller sets inst->salt_draws (salted byte-match). */
    return agg_prove_cfg(inst, out_proof, &AGG_CFG_TEST, NULL);
}

/* ── Phase-P production entry: pinned shielded FRI params + OS entropy + salt ── */
dnac_prover_status_t dnac_agg_prover_prove_production(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof) {
    if (inst == NULL || out_proof == NULL) return DNAC_PROVER_ERR_PARAM;
    /* The shielded pool pins the trace height to 2^10 (C1 fixed H=1024) so the
     * committed is_zk domain equals DNAC_SHIELDED_COMMITTED_LOG_HEIGHT (=11). */
    if (inst->log_height != (unsigned)DNAC_SHIELDED_BASE_LOG_HEIGHT) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t height = (size_t)1 << inst->log_height;
    const size_t nd = DNAC_AGG_PROVER_TOTAL_DRAWS(height);
    const size_t ns = DNAC_AGG_PROVER_SALT_DRAWS(height);
    const size_t nfs = DNAC_AGG_PROVER_FRI_SALT_DRAWS(height);
    uint64_t *draws = (uint64_t *)malloc(nd * sizeof(uint64_t));
    uint64_t *salts = (uint64_t *)malloc(ns * sizeof(uint64_t));
    uint64_t *fri_salts = (uint64_t *)malloc(nfs * sizeof(uint64_t));
    if (draws == NULL || salts == NULL || fri_salts == NULL) {
        free(draws);
        free(salts);
        free(fri_salts);
        return DNAC_PROVER_ERR_PARAM;
    }
    /* Production MUST be genuinely salted (M3b) with INDEPENDENT streams
     * (P1e-HIGH1): fill the zk codeword stream + the input-mmcs salt stream A +
     * the FRI-mmcs salt stream B, each from its OWN OS entropy. Fail-close on
     * any entropy error — never a partial/non-hiding proof. */
    if (dnac_zk_fill_draws(draws, nd) != 0 ||
        dnac_zk_fill_draws(salts, ns) != 0 ||
        dnac_zk_fill_draws(fri_salts, nfs) != 0) {
        for (volatile uint64_t *z = draws; z < draws + nd; z++) *z = 0;
        for (volatile uint64_t *z = salts; z < salts + ns; z++) *z = 0;
        for (volatile uint64_t *z = fri_salts; z < fri_salts + nfs; z++) *z = 0;
        free(draws);
        free(salts);
        free(fri_salts);
        return DNAC_PROVER_ERR_PARAM;
    }
    dnac_agg_prover_instance_t local = *inst;
    local.draws = draws;
    local.num_draws = nd;
    local.salt_draws = salts;
    local.num_salt_draws = ns;
    local.fri_salt_draws = fri_salts;
    local.num_fri_salt_draws = nfs;
    const dnac_prover_status_t rc =
        agg_prove_cfg(&local, out_proof, &AGG_CFG_SHIELDED, NULL);
    /* Zeroize the three secret streams before free (client-side hygiene). */
    for (volatile uint64_t *z = draws; z < draws + nd; z++) *z = 0;
    for (volatile uint64_t *z = salts; z < salts + ns; z++) *z = 0;
    for (volatile uint64_t *z = fri_salts; z < fri_salts + nfs; z++) *z = 0;
    free(draws);
    free(salts);
    free(fri_salts);
    return rc;
}

/* ── Phase-P: shielded wire self-check — encode the batched proof to DZKF v4,
 * decode it, and run the d2 batched verify on the round-tripped package. This
 * proves the produced proof survives the wire and verifies; the CONSENSUS-side
 * statement recompute is dnac_shielded_verify_statement (shielded_verify.c). ── */
dnac_fri_codec_status_t dnac_agg_prover_wire_selfcheck_shielded(
    const dnac_agg_prover_proof_t *cp,
    dnac_fri_status_t             *out_fri_status) {
    if (cp == NULL || out_fri_status == NULL) return DNAC_FRI_CODEC_ERR_NULL;
    *out_fri_status = DNAC_FRI_ERR_INVALID_POW_WITNESS; /* fail-closed default */
    dnac_agg_prover_proof_t *p = (dnac_agg_prover_proof_t *)cp;

    dnac_batch_vcommits_t commits;
    dnac_batch_proof_commits(p->bp, &commits);
    uint8_t *buf = NULL;
    size_t   len = 0;
    dnac_fri_codec_status_t cs = dnac_batch_wire_encode(
        A_IS_ZK, 1, &commits, dnac_batch_proof_opened(p->bp, 0),
        dnac_batch_proof_rand_openings(p->bp), &p->params,
        dnac_batch_proof_fri(p->bp), &buf, &len);
    if (cs != DNAC_FRI_CODEC_OK) return cs;

    dnac_batch_wire_package_t *pkg = NULL;
    cs = dnac_batch_wire_decode(buf, len, &pkg);
    free(buf);
    if (cs != DNAC_FRI_CODEC_OK) return cs;

    /* Shielded param pin (mirror the consensus entry): a proof whose params are
     * not the pinned shielded set is rejected here — the same PARAM_MISMATCH the
     * consensus verify raises, so a TEST-params proof never passes this gate. */
    const dnac_fri_params_t *wp = dnac_batch_wire_params(pkg);
    if (wp == NULL || wp->log_blowup != DNAC_SHIELDED_FRI_LOG_BLOWUP ||
        wp->log_final_poly_len != DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN ||
        wp->max_log_arity != DNAC_SHIELDED_FRI_MAX_LOG_ARITY ||
        wp->num_queries != DNAC_SHIELDED_FRI_NUM_QUERIES ||
        wp->commit_proof_of_work_bits != DNAC_SHIELDED_FRI_COMMIT_POW_BITS ||
        wp->query_proof_of_work_bits != DNAC_SHIELDED_FRI_QUERY_POW_BITS) {
        dnac_batch_wire_free(pkg);
        return DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH;
    }

    dnac_batch_vinstance_t vi;
    agg_fill_vinstance(&vi, p->degree_bits, p->publics);
    dnac_batch_verify_out_t vo;
    memset(&vo, 0, sizeof(vo));
    dnac_batch_verify_status_t st = dnac_batch_verify(
        &vi, dnac_batch_wire_opened(pkg), 1, A_IS_ZK,
        dnac_batch_wire_commits(pkg), NULL, 0, dnac_batch_wire_params(pkg),
        dnac_batch_wire_proof(pkg), dnac_batch_wire_rand_openings(pkg), &vo);
    dnac_batch_wire_free(pkg);
    if (st == DNAC_BV_OK) {
        *out_fri_status = DNAC_FRI_OK;
        return DNAC_FRI_CODEC_OK;
    }
    return DNAC_FRI_CODEC_ERR_SHIELDED_VERIFY_FAILED;
}

#ifdef DNAC_ZK_ENABLE_TEST_WIRE
/* ── C2.1 test-only exports (M5-gated: only the zk standalone Makefile defines
 * DNAC_ZK_ENABLE_TEST_WIRE, so neither symbol exists in libnodus/libdna). ── */

/* Serialize a produced aggregate proof to the DZKF v4 wire bytes the consensus
 * verify consumes (the KAT feeds them to dnac_shielded_verify_statement). */
dnac_fri_codec_status_t dnac_agg_prover_proof_wire_encode_testonly(
    const dnac_agg_prover_proof_t *cp, uint8_t **out_buf, size_t *out_len) {
    if (cp == NULL || out_buf == NULL || out_len == NULL)
        return DNAC_FRI_CODEC_ERR_NULL;
    *out_buf = NULL;
    *out_len = 0;
    dnac_agg_prover_proof_t *p = (dnac_agg_prover_proof_t *)cp;
    dnac_batch_vcommits_t commits;
    dnac_batch_proof_commits(p->bp, &commits);
    return dnac_batch_wire_encode(A_IS_ZK, 1, &commits,
                                  dnac_batch_proof_opened(p->bp, 0),
                                  dnac_batch_proof_rand_openings(p->bp),
                                  &p->params, dnac_batch_proof_fri(p->bp),
                                  out_buf, out_len);
}

/* Produce the CRIT-1 isolating negative vector: a PRODUCTION-params proof whose
 * Fiat-Shamir transcript is honest for the FORGED publics while the committed
 * quotient was built from the TRUE trace publics. FRI accepts it; ONLY the
 * N-chunk constraint check can reject it (dnac_batch_prove_forged_fs_testonly). */
dnac_prover_status_t dnac_agg_prover_prove_production_forged_publics_testonly(
    const dnac_agg_prover_instance_t *inst,
    const uint64_t                    forged_publics[CONF_AGGZK_NUM_PUBLICS],
    dnac_agg_prover_proof_t         **out_proof) {
    if (inst == NULL || forged_publics == NULL || out_proof == NULL)
        return DNAC_PROVER_ERR_PARAM;
    if (inst->log_height != (unsigned)DNAC_SHIELDED_BASE_LOG_HEIGHT)
        return DNAC_PROVER_ERR_PARAM;
    for (size_t i = 0; i < A_NUM_PUBLICS; i++)
        if (forged_publics[i] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_PARAM;
    const size_t height = (size_t)1 << inst->log_height;
    const size_t nd = DNAC_AGG_PROVER_TOTAL_DRAWS(height);
    const size_t ns = DNAC_AGG_PROVER_SALT_DRAWS(height);
    const size_t nfs = DNAC_AGG_PROVER_FRI_SALT_DRAWS(height);
    uint64_t *draws = (uint64_t *)malloc(nd * sizeof(uint64_t));
    uint64_t *salts = (uint64_t *)malloc(ns * sizeof(uint64_t));
    uint64_t *fri_salts = (uint64_t *)malloc(nfs * sizeof(uint64_t));
    if (draws == NULL || salts == NULL || fri_salts == NULL ||
        dnac_zk_fill_draws(draws, nd) != 0 ||
        dnac_zk_fill_draws(salts, ns) != 0 ||
        dnac_zk_fill_draws(fri_salts, nfs) != 0) {
        free(draws);
        free(salts);
        free(fri_salts);
        return DNAC_PROVER_ERR_PARAM;
    }
    dnac_agg_prover_instance_t local = *inst;
    local.draws = draws;
    local.num_draws = nd;
    local.salt_draws = salts;
    local.num_salt_draws = ns;
    local.fri_salt_draws = fri_salts;
    local.num_fri_salt_draws = nfs;
    const dnac_prover_status_t rc =
        agg_prove_cfg(&local, out_proof, &AGG_CFG_SHIELDED, forged_publics);
    for (volatile uint64_t *z = draws; z < draws + nd; z++) *z = 0;
    for (volatile uint64_t *z = salts; z < salts + ns; z++) *z = 0;
    for (volatile uint64_t *z = fri_salts; z < fri_salts + nfs; z++) *z = 0;
    free(draws);
    free(salts);
    free(fri_salts);
    return rc;
}

/* d4.c KAT-only: expose the aggregate S1 generator so test_batch_shielded_agg
 * feeds the SAME raw witness to dnac_batch_prove (1-instance is_zk=1 batch). */
int dnac_agg_zk_generate_trace_testonly(
    unsigned log_height, const dnac_agg_prover_instance_t *inst,
    uint64_t *trace_out, gold_fp_t *pub_out) {
    if (inst == NULL || trace_out == NULL || pub_out == NULL) return 0;
    return agg_zk_generate(log_height, inst, trace_out, pub_out) ? 1 : 0;
}
#endif /* DNAC_ZK_ENABLE_TEST_WIRE */
