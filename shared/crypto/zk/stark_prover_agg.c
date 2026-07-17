/**
 * @file stark_prover_agg.c
 * @brief Dual-mode S4b.4 — pure-C prover for the AGGREGATE Action AIR.
 *
 * Mirrors the C1 Action prover (stark_prover_action.c) with the aggregate
 * constants and the two AIR-specific stages swapped (S1 trace = the 1936-wide
 * ZK generator agg_zk_generate, S6 quotient = dnac_conf_action_agg_fold_air_eval
 * with the 21 public values). UNSALTED. See stark_prover_agg.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_prover_agg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "poseidon2_air_cols.h"
#include "poseidon2_air_trace.h"
#include "shielded_domsep.h"
#include "stark_constraints.h"
#include "stark_priming.h"
#include "transcript.h"

/* Fixed aggregate / is_zk=1 config constants. */
#define A_IS_ZK 1u
#define A_LOG_BLOWUP 2u
#define A_LOG_FINAL_POLY_LEN 2u
#define A_MAX_LOG_ARITY 1u
#define A_NUM_QUERIES 2u
#define A_NUM_QC 8u
#define A_LOG_NUM_QC 2u
#define A_NUM_RANDOM 4u
#define A_W ((size_t)CONF_AGGZK_WIDTH)     /* 1936 */
#define A_RAND_W (A_W + A_NUM_RANDOM)      /* 1940 */
#define A_CW ((size_t)2 + A_NUM_RANDOM)    /* 6 */
#define A_NUM_PUBLICS ((size_t)CONF_AGGZK_NUM_PUBLICS) /* 21 */

struct dnac_agg_prover_proof_s {
    size_t base_degree_bits, degree_bits, log_max_height, lde_h, num_fri_rounds;
    size_t num_queries;

    gold_fp_t publics[A_NUM_PUBLICS];

    dnac_merkle_digest_t trace_c, quot_c, rand_c;
    gold_fp2_t r_open[A_CW];
    gold_fp2_t *t_open;      /* A_RAND_W */
    gold_fp2_t *t_open_n;    /* A_RAND_W */
    gold_fp2_t q_open[A_NUM_QC * A_CW];

    dnac_merkle_digest_t *cp_commits;
    gold_fp_t            *cp_pow;
    gold_fp2_t           *final_poly;
    size_t                final_poly_len;

    dnac_fri_query_proof_t *query_proofs;
    dnac_fri_batch_opening_t *batches;
    gold_fp_t  *rand_rows, *trace_rows, *quot_rows;
    const gold_fp_t **rand_rowptr, **trace_rowptr, **quot_rowptr;
    size_t *rand_len, *trace_len, *quot_len;
    dnac_merkle_digest_t *rand_sib, *trace_sib, *quot_sib;
    dnac_fri_commit_phase_proof_step_t *cp_steps;
    gold_fp2_t *cp_step_sib;
    dnac_merkle_digest_t *cp_step_psib;

    dnac_fri_proof_t proof;
    dnac_fri_params_t params;
    dnac_fri_opening_point_t rand_pt[1], trace_pt[2];
    dnac_fri_opening_point_t quot_pt[A_NUM_QC];
    dnac_fri_matrix_openings_t rand_mx, trace_mx;
    dnac_fri_matrix_openings_t quot_mx[A_NUM_QC];
    dnac_fri_commitment_with_opening_points_t coms[3];
    dnac_stark_priming_input_t prime_in;
    const gold_fp2_t *qcptr[A_NUM_QC];
    size_t qclen[A_NUM_QC];

    gold_fp2_t zeta, zeta_next;
    uint64_t query_indices[64];
};

static size_t ilog2_pow2(size_t n) {
    size_t l = 0;
    while ((((size_t)1) << l) < n) l++;
    return l;
}

/* poseidon2-air block output lane k (end_post of the final full round). */
static uint64_t p2out(const uint64_t *blk, unsigned k) {
    return blk[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)k)];
}

/* ── S1: the 1936-wide ZK trace — byte-matches generate_conf_action_agg_trace.
 * C1 scatter + membership walk (φ∈[1,D]) + nullifier sponge (φ=D+1) + the
 * is_zero SELECTOR columns (is_nf / is_lvl / active_lvl / N_input / slot_sel).
 * Also computes the 21 public values (anchor / num_input / nf_slots). ── */
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

        uint64_t *m = row + CONF_AGGZK_MEMB_OFF;
        memcpy(m + CONF_AGGZK_MEMB_MC1, zero_blk, sizeof zero_blk);
        memcpy(m + CONF_AGGZK_MEMB_MC2, zero_blk, sizeof zero_blk);
        uint64_t *nfr = row + CONF_AGGZK_NF_OFF;
        memcpy(nfr + CONF_AGGZK_NF_RHO1, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_RHO2, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_NF1, zero_blk, sizeof zero_blk);
        memcpy(nfr + CONF_AGGZK_NF_NF2, zero_blk, sizeof zero_blk);
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
        const uint64_t np = inst->pos[blk], nnk = inst->nk[blk];
        for (unsigned j = 0; j < 4; j++) nfr[CONF_AGGZK_NF_CM + j] = cm0[j];
        nfr[CONF_AGGZK_NF_POS] = np;
        nfr[CONF_AGGZK_NF_NK] = nnk;
        uint64_t rin1[8] = {cm0[0], cm0[1], cm0[2], cm0[3], 0, 0, 0, 0};
        poseidon2_air_generate_row(rin1, nfr + CONF_AGGZK_NF_RHO1);
        uint64_t rs1[8];
        for (unsigned k = 0; k < 8; k++) rs1[k] = p2out(nfr + CONF_AGGZK_NF_RHO1, k);
        uint64_t rin2[8] = {np, DNAC_DOMSEP_RHO, 0, 0, rs1[4], rs1[5], rs1[6], rs1[7]};
        poseidon2_air_generate_row(rin2, nfr + CONF_AGGZK_NF_RHO2);
        uint64_t rho[4];
        for (unsigned j = 0; j < 4; j++) rho[j] = p2out(nfr + CONF_AGGZK_NF_RHO2, j);
        uint64_t nin1[8] = {nnk, rho[0], rho[1], rho[2], 0, 0, 0, 0};
        poseidon2_air_generate_row(nin1, nfr + CONF_AGGZK_NF_NF1);
        uint64_t ns1[8];
        for (unsigned k = 0; k < 8; k++) ns1[k] = p2out(nfr + CONF_AGGZK_NF_NF1, k);
        uint64_t nin2[8] = {rho[3], DNAC_DOMSEP_NF, 0, 0, ns1[4], ns1[5], ns1[6], ns1[7]};
        poseidon2_air_generate_row(nin2, nfr + CONF_AGGZK_NF_NF2);
        uint64_t nf[4];
        for (unsigned j = 0; j < 4; j++) nf[j] = p2out(nfr + CONF_AGGZK_NF_NF2, j);
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
    return true;
}

/* ── S6: aggregate quotient values — REUSES the verifier-fold eval per row
 * (WITH the 21 public values). ── */
static dnac_prover_status_t agg_quotient_values(
    const uint64_t *trace_q, size_t q_rows, size_t next_step, gold_fp2_t alpha,
    const gold_fp_t *publics, const uint64_t *sf, const uint64_t *sl,
    const uint64_t *st, const uint64_t *iv, uint64_t *out_q) {

    gold_fp2_t *lrow = (gold_fp2_t *)malloc(A_W * sizeof(gold_fp2_t));
    gold_fp2_t *nrow = (gold_fp2_t *)malloc(A_W * sizeof(gold_fp2_t));
    if (!lrow || !nrow) {
        free(lrow);
        free(nrow);
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < q_rows; i++) {
        const size_t nidx = (i + next_step) & (q_rows - 1);
        for (size_t c = 0; c < A_W; c++) {
            lrow[c] = gold_fp2_from_base(gold_fp_from_u64(trace_q[i * A_W + c]));
            nrow[c] = gold_fp2_from_base(gold_fp_from_u64(trace_q[nidx * A_W + c]));
        }
        dnac_stark_folder_t folder;
        memset(&folder, 0, sizeof(folder));
        folder.trace_local = lrow;
        folder.trace_next = nrow;
        folder.main_width = A_W;
        folder.public_values = publics;
        folder.num_public_values = A_NUM_PUBLICS;
        folder.is_first_row = gold_fp2_from_base(gold_fp_from_u64(sf[i]));
        folder.is_last_row = gold_fp2_from_base(gold_fp_from_u64(sl[i]));
        folder.is_transition = gold_fp2_from_base(gold_fp_from_u64(st[i]));
        dnac_stark_fold_init(&folder.fold, alpha);
        folder.capture = NULL;
        dnac_conf_action_agg_fold_air_eval(&folder);
        const gold_fp2_t q = gold_fp2_mul(
            folder.fold.acc, gold_fp2_from_base(gold_fp_from_u64(iv[i])));
        out_q[2 * i] = gold_fp_to_u64(q.a);
        out_q[2 * i + 1] = gold_fp_to_u64(q.b);
    }
    free(lrow);
    free(nrow);
    return DNAC_PROVER_OK;
}

/* ── priming input (21 publics, num_qc=8) ── */
static void build_prime_input(dnac_agg_prover_proof_t *p) {
    memset(&p->prime_in, 0, sizeof(p->prime_in));
    p->prime_in.degree_bits = p->degree_bits;
    p->prime_in.is_zk = A_IS_ZK;
    p->prime_in.preprocessed_width = 0;
    p->prime_in.trace_commit = p->trace_c;
    p->prime_in.quotient_commit = p->quot_c;
    p->prime_in.random_commit = &p->rand_c;
    p->prime_in.random_local = p->r_open;
    p->prime_in.random_local_len = A_CW;
    p->prime_in.public_values = p->publics;
    p->prime_in.num_public_values = A_NUM_PUBLICS;
    p->prime_in.trace_local = p->t_open;
    p->prime_in.trace_local_len = A_RAND_W;
    p->prime_in.trace_next = p->t_open_n;
    p->prime_in.trace_next_len = A_RAND_W;
    for (size_t k = 0; k < A_NUM_QC; k++) {
        p->qcptr[k] = &p->q_open[k * A_CW];
        p->qclen[k] = A_CW;
    }
    p->prime_in.quotient_chunks = p->qcptr;
    p->prime_in.quotient_chunk_lens = p->qclen;
    p->prime_in.num_quotient_chunks = A_NUM_QC;
}

static void build_coms(dnac_agg_prover_proof_t *p, gold_fp2_t zeta,
                       gold_fp2_t zeta_next) {
    const uint32_t ls = (uint32_t)p->degree_bits;
    p->rand_pt[0].point = zeta;
    p->rand_pt[0].claimed_evals = p->r_open;
    p->rand_pt[0].num_claimed_evals = A_CW;
    p->rand_mx.domain.shift = gold_fp_from_u64(0);
    p->rand_mx.domain.shift_inverse = gold_fp_from_u64(0);
    p->rand_mx.domain.log_size = ls;
    p->rand_mx.points = p->rand_pt;
    p->rand_mx.num_points = 1;
    p->coms[0].commitment = p->rand_c;
    p->coms[0].matrices = &p->rand_mx;
    p->coms[0].num_matrices = 1;

    p->trace_pt[0].point = zeta;
    p->trace_pt[0].claimed_evals = p->t_open;
    p->trace_pt[0].num_claimed_evals = A_RAND_W;
    p->trace_pt[1].point = zeta_next;
    p->trace_pt[1].claimed_evals = p->t_open_n;
    p->trace_pt[1].num_claimed_evals = A_RAND_W;
    p->trace_mx.domain.shift = gold_fp_from_u64(0);
    p->trace_mx.domain.shift_inverse = gold_fp_from_u64(0);
    p->trace_mx.domain.log_size = ls;
    p->trace_mx.points = p->trace_pt;
    p->trace_mx.num_points = 2;
    p->coms[1].commitment = p->trace_c;
    p->coms[1].matrices = &p->trace_mx;
    p->coms[1].num_matrices = 1;

    for (size_t k = 0; k < A_NUM_QC; k++) {
        p->quot_pt[k].point = zeta;
        p->quot_pt[k].claimed_evals = &p->q_open[k * A_CW];
        p->quot_pt[k].num_claimed_evals = A_CW;
        p->quot_mx[k].domain.shift = gold_fp_from_u64(0);
        p->quot_mx[k].domain.shift_inverse = gold_fp_from_u64(0);
        p->quot_mx[k].domain.log_size = ls;
        p->quot_mx[k].points = &p->quot_pt[k];
        p->quot_mx[k].num_points = 1;
    }
    p->coms[2].commitment = p->quot_c;
    p->coms[2].matrices = p->quot_mx;
    p->coms[2].num_matrices = A_NUM_QC;
}

dnac_fri_status_t dnac_agg_prover_proof_verify(const dnac_agg_prover_proof_t *cp) {
    dnac_agg_prover_proof_t *p = (dnac_agg_prover_proof_t *)cp;
    dnac_transcript_t *vt =
        dnac_transcript_init((const uint8_t *)"DNAC|ZK|FRI|TRANSCRIPT|V1", 25);
    if (vt == NULL) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    build_prime_input(p);
    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof(out));
    if (dnac_stark_prime_transcript(vt, &p->prime_in, &out) !=
        DNAC_STARK_PRIMING_OK) {
        fprintf(stderr, "agg-prover self-verify: priming FAILED\n");
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    if (!(gold_fp_to_u64(out.zeta.a) == gold_fp_to_u64(p->zeta.a) &&
          gold_fp_to_u64(out.zeta.b) == gold_fp_to_u64(p->zeta.b) &&
          gold_fp_to_u64(out.zeta_next.a) == gold_fp_to_u64(p->zeta_next.a) &&
          gold_fp_to_u64(out.zeta_next.b) == gold_fp_to_u64(p->zeta_next.b))) {
        fprintf(stderr, "agg-prover self-verify: zeta MISMATCH\n");
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    build_coms(p, out.zeta, out.zeta_next);
    dnac_fri_status_t fs = dnac_fri_verify(&p->params, &p->proof, vt, p->coms, 3);
    dnac_transcript_free(vt);
    if (fs != DNAC_FRI_OK) {
        fprintf(stderr, "agg-prover self-verify: dnac_fri_verify -> %d\n", (int)fs);
        return fs;
    }

    {
        const dnac_stark_verify_status_t vs = dnac_stark_verify_constraints_nchunk(
            &DNAC_CONF_ACTION_AGG_FOLD_AIR,
            p->t_open, A_W, p->t_open_n, A_W,
            p->publics, A_NUM_PUBLICS,
            out.zeta, p->degree_bits, A_LOG_NUM_QC, A_IS_ZK,
            out.alpha, p->q_open, A_NUM_QC, A_CW);
        if (vs != DNAC_STARK_VERIFY_OK) {
            fprintf(stderr,
                    "agg-prover self-verify: N-chunk constraint check -> %d\n",
                    (int)vs);
            return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
        }
    }
    return DNAC_FRI_OK;
}

void dnac_agg_prover_proof_zeta(const dnac_agg_prover_proof_t *p,
                                gold_fp2_t *zeta, gold_fp2_t *zeta_next) {
    if (zeta) *zeta = p->zeta;
    if (zeta_next) *zeta_next = p->zeta_next;
}

void dnac_agg_prover_proof_roots(const dnac_agg_prover_proof_t *p,
                                 uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                                 uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                                 uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]) {
    if (trace_root) memcpy(trace_root, p->trace_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (quot_root) memcpy(quot_root, p->quot_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (rand_root) memcpy(rand_root, p->rand_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
}

const gold_fp2_t *dnac_agg_prover_proof_final_poly(
    const dnac_agg_prover_proof_t *p, size_t *out_len) {
    if (out_len) *out_len = p->final_poly_len;
    return p->final_poly;
}

const gold_fp_t *dnac_agg_prover_proof_publics(const dnac_agg_prover_proof_t *p,
                                               size_t *out_len) {
    if (out_len) *out_len = A_NUM_PUBLICS;
    return p->publics;
}

void dnac_agg_prover_proof_free(dnac_agg_prover_proof_t *p) {
    if (p == NULL) return;
    free(p->t_open);
    free(p->t_open_n);
    free(p->cp_commits);
    free(p->cp_pow);
    free(p->final_poly);
    free(p->query_proofs);
    free(p->batches);
    free(p->rand_rows);
    free(p->trace_rows);
    free(p->quot_rows);
    free(p->rand_rowptr);
    free(p->trace_rowptr);
    free(p->quot_rowptr);
    free(p->rand_len);
    free(p->trace_len);
    free(p->quot_len);
    free(p->rand_sib);
    free(p->trace_sib);
    free(p->quot_sib);
    free(p->cp_steps);
    free(p->cp_step_sib);
    free(p->cp_step_psib);
    free(p);
}

dnac_prover_status_t dnac_agg_prover_prove(
    const dnac_agg_prover_instance_t *inst,
    dnac_agg_prover_proof_t         **out_proof) {
    if (inst == NULL || out_proof == NULL || inst->draws == NULL) {
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

    const size_t base_db = inst->log_height;
    const size_t degree_bits = base_db + A_IS_ZK;
    const size_t log_max_height = base_db + A_LOG_BLOWUP + A_IS_ZK;
    const size_t lde_h = (size_t)1 << log_max_height;
    const size_t q_size = (size_t)1 << (degree_bits + A_LOG_NUM_QC);
    const size_t next_step = (size_t)1 << (A_IS_ZK + A_LOG_NUM_QC);
    const size_t num_rounds_expected = base_db - 1;

    /* draw slices: trace (A_W+8)h @0, codeword 32h, blinding 42h, R 12h. */
    const uint64_t *trace_draws = inst->draws;
    const uint64_t *codeword = inst->draws + (A_W + 8) * height;
    const uint64_t *blinding = inst->draws + (A_W + 8 + 32) * height;
    const uint64_t *r_draws = inst->draws + (A_W + 8 + 32 + 42) * height;

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    dnac_agg_prover_proof_t *p =
        (dnac_agg_prover_proof_t *)calloc(1, sizeof(*p));
    if (p == NULL) return DNAC_PROVER_ERR_PARAM;
    p->base_degree_bits = base_db;
    p->degree_bits = degree_bits;
    p->log_max_height = log_max_height;
    p->lde_h = lde_h;
    p->num_queries = A_NUM_QUERIES;

    uint64_t *base_c = NULL, *rand_c = NULL, *lde_c = NULL, *trace_q = NULL,
             *qflat = NULL, *chunk_ldes = NULL, *r_lde = NULL;
    uint64_t *sf = NULL, *sl = NULL, *st = NULL, *iv = NULL;
    gold_fp2_t *ro = NULL;
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = NULL;
    dnac_prover_fri_result_t res;
    memset(&res, 0, sizeof(res));
    int have_res = 0;

    base_c = (uint64_t *)malloc(height * A_W * 8);
    rand_c = (uint64_t *)malloc((2 * height) * A_RAND_W * 8);
    lde_c = (uint64_t *)malloc(lde_h * A_RAND_W * 8);
    trace_q = (uint64_t *)malloc(q_size * A_W * 8);
    qflat = (uint64_t *)malloc(2 * q_size * 8);
    chunk_ldes = (uint64_t *)malloc(A_NUM_QC * lde_h * A_CW * 8);
    r_lde = (uint64_t *)malloc(lde_h * A_CW * 8);
    sf = (uint64_t *)malloc(q_size * 8);
    sl = (uint64_t *)malloc(q_size * 8);
    st = (uint64_t *)malloc(q_size * 8);
    iv = (uint64_t *)malloc(q_size * 8);
    ro = (gold_fp2_t *)malloc(lde_h * sizeof(gold_fp2_t));
    p->t_open = (gold_fp2_t *)malloc(A_RAND_W * sizeof(gold_fp2_t));
    p->t_open_n = (gold_fp2_t *)malloc(A_RAND_W * sizeof(gold_fp2_t));
    if (!base_c || !rand_c || !lde_c || !trace_q || !qflat || !chunk_ldes ||
        !r_lde || !sf || !sl || !st || !iv || !ro || !p->t_open ||
        !p->t_open_n) {
        goto cleanup;
    }

    /* ── S1: the 1936-wide ZK trace + the 21 public values ── */
    if (!agg_zk_generate(inst->log_height, inst, base_c, p->publics)) {
        rc = DNAC_PROVER_ERR_RANGE;
        goto cleanup;
    }
    uint64_t publics_u[A_NUM_PUBLICS];
    for (size_t i = 0; i < A_NUM_PUBLICS; i++)
        publics_u[i] = gold_fp_to_u64(p->publics[i]);

    /* ── S2-S8 (parametric stages; UNSALTED SE=0) ── */
    t = dnac_transcript_init_default();
    if (t == NULL) goto cleanup;
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
    {
        dnac_prover_status_t s;
        s = dnac_prover_randomize_trace(base_c, height, A_W, A_NUM_RANDOM,
                                        trace_draws, rand_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_coset_lde_bitrev(rand_c, 2 * height, A_RAND_W,
                                         A_LOG_BLOWUP, 7, lde_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_commit_matrix(lde_c, lde_h, A_RAND_W, NULL, 0,
                                      p->trace_c.bytes, &ttree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_alpha(t, degree_bits, base_db, 0,
                                    p->trace_c.bytes, publics_u, A_NUM_PUBLICS,
                                    &alpha);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_selectors(
            (unsigned)base_db, (unsigned)(degree_bits + A_LOG_NUM_QC), 7, sf,
            sl, st, iv);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_trace_on_quotient_domain(lde_c, lde_h, A_RAND_W, q_size,
                                                 A_W, trace_q);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = agg_quotient_values(trace_q, q_size, next_step, alpha, p->publics,
                                sf, sl, st, iv, qflat);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_commit(qflat, q_size, A_NUM_QC, A_NUM_RANDOM,
                                        A_LOG_BLOWUP, 7, codeword, blinding,
                                        NULL, 0, chunk_ldes, p->quot_c.bytes,
                                        &qtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_random_commit(r_draws, 2 * height, A_CW, A_LOG_BLOWUP,
                                      NULL, 0, r_lde, p->rand_c.bytes, &rtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_zeta(t, p->quot_c.bytes, p->rand_c.bytes,
                                   base_db, &zeta, &zeta_next);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
    }
    p->zeta = zeta;
    p->zeta_next = zeta_next;

    /* ── S9 open ── */
    if (dnac_prover_open_matrix_at(r_lde, lde_h, A_CW, A_LOG_BLOWUP, zeta,
                                   p->r_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, A_RAND_W, A_LOG_BLOWUP, zeta,
                                   p->t_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, A_RAND_W, A_LOG_BLOWUP,
                                   zeta_next, p->t_open_n) != DNAC_PROVER_OK) {
        goto cleanup;
    }
    for (size_t k = 0; k < A_NUM_QC; k++) {
        if (dnac_prover_open_matrix_at(&chunk_ldes[k * lde_h * A_CW], lde_h,
                                       A_CW, A_LOG_BLOWUP, zeta,
                                       &p->q_open[k * A_CW]) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    dnac_prover_observe_opened(t, p->r_open, A_CW);
    dnac_prover_observe_opened(t, p->t_open, A_RAND_W);
    dnac_prover_observe_opened(t, p->t_open_n, A_RAND_W);
    for (size_t k = 0; k < A_NUM_QC; k++)
        dnac_prover_observe_opened(t, &p->q_open[k * A_CW], A_CW);
    fri_alpha = dnac_transcript_sample_fp2(t);

    /* ── S10 reduced openings + commit phase ── */
    {
        const gold_fp2_t zpts[2] = {zeta, zeta_next};
        const gold_fp2_t *r_ov[1] = {p->r_open};
        const gold_fp2_t *t_ov[2] = {p->t_open, p->t_open_n};
        const gold_fp2_t *q_ov[A_NUM_QC][1];
        dnac_prover_fri_input_round_t rounds[2 + A_NUM_QC];
        rounds[0] = (dnac_prover_fri_input_round_t){r_lde, lde_h, A_CW, 1,
                                                    &zeta, r_ov};
        rounds[1] = (dnac_prover_fri_input_round_t){lde_c, lde_h, A_RAND_W, 2,
                                                    zpts, t_ov};
        for (size_t k = 0; k < A_NUM_QC; k++) {
            q_ov[k][0] = &p->q_open[k * A_CW];
            rounds[2 + k] = (dnac_prover_fri_input_round_t){
                &chunk_ldes[k * lde_h * A_CW], lde_h, A_CW, 1, &zeta, q_ov[k]};
        }
        if (dnac_prover_fri_reduced_openings(rounds, 2 + A_NUM_QC,
                                             (unsigned)log_max_height,
                                             fri_alpha, ro) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    if (dnac_prover_fri_commit_phase(ro, lde_h, A_LOG_BLOWUP,
                                     A_LOG_FINAL_POLY_LEN, A_MAX_LOG_ARITY,
                                     NULL, 0, t, &res) != DNAC_PROVER_OK) {
        goto cleanup;
    }
    have_res = 1;
    if (res.num_rounds != num_rounds_expected) goto cleanup;
    p->num_fri_rounds = res.num_rounds;
    p->final_poly_len = res.final_poly_len;

    p->cp_commits = (dnac_merkle_digest_t *)malloc(
        res.num_rounds * sizeof(dnac_merkle_digest_t));
    p->cp_pow = (gold_fp_t *)calloc(res.num_rounds, sizeof(gold_fp_t));
    p->final_poly =
        (gold_fp2_t *)malloc(res.final_poly_len * sizeof(gold_fp2_t));
    if (!p->cp_commits || !p->cp_pow || !p->final_poly) goto cleanup;
    for (size_t r = 0; r < res.num_rounds; r++)
        p->cp_commits[r] = *(dnac_merkle_digest_t *)res.roots[r];
    memcpy(p->final_poly, res.final_poly,
           res.final_poly_len * sizeof(gold_fp2_t));

    /* ── S11 query indices ── */
    uint64_t qidx[A_NUM_QUERIES];
    for (size_t q = 0; q < A_NUM_QUERIES; q++) {
        qidx[q] = dnac_transcript_sample_bits(t, (size_t)log_max_height);
        p->query_indices[q] = qidx[q];
    }

    /* ── S12 query openings (UNSALTED) ── */
    {
        const size_t nq = A_NUM_QUERIES, nr = res.num_rounds;
        const size_t in_depth = log_max_height;
        size_t cp_depth_sum = 0;
        for (size_t r = 0; r < nr; r++)
            cp_depth_sum += ilog2_pow2(res.layer_heights[r]);

        p->query_proofs = (dnac_fri_query_proof_t *)calloc(
            nq, sizeof(dnac_fri_query_proof_t));
        p->batches = (dnac_fri_batch_opening_t *)calloc(
            nq * 3, sizeof(dnac_fri_batch_opening_t));
        p->rand_rows = (gold_fp_t *)malloc(nq * A_CW * sizeof(gold_fp_t));
        p->trace_rows = (gold_fp_t *)malloc(nq * A_RAND_W * sizeof(gold_fp_t));
        p->quot_rows =
            (gold_fp_t *)malloc(nq * A_NUM_QC * A_CW * sizeof(gold_fp_t));
        p->rand_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->trace_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->quot_rowptr =
            (const gold_fp_t **)malloc(nq * A_NUM_QC * sizeof(gold_fp_t *));
        p->rand_len = (size_t *)malloc(nq * sizeof(size_t));
        p->trace_len = (size_t *)malloc(nq * sizeof(size_t));
        p->quot_len = (size_t *)malloc(nq * A_NUM_QC * sizeof(size_t));
        p->rand_sib = (dnac_merkle_digest_t *)malloc(
            nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->trace_sib = (dnac_merkle_digest_t *)malloc(
            nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->quot_sib = (dnac_merkle_digest_t *)malloc(
            nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->cp_steps = (dnac_fri_commit_phase_proof_step_t *)calloc(
            nq * nr, sizeof(dnac_fri_commit_phase_proof_step_t));
        p->cp_step_sib = (gold_fp2_t *)malloc(nq * nr * sizeof(gold_fp2_t));
        p->cp_step_psib = (dnac_merkle_digest_t *)malloc(
            nq * cp_depth_sum * sizeof(dnac_merkle_digest_t));
        if (!p->query_proofs || !p->batches || !p->rand_rows ||
            !p->trace_rows || !p->quot_rows || !p->rand_rowptr ||
            !p->trace_rowptr || !p->quot_rowptr || !p->rand_len ||
            !p->trace_len || !p->quot_len || !p->rand_sib || !p->trace_sib ||
            !p->quot_sib || !p->cp_steps || !p->cp_step_sib ||
            !p->cp_step_psib) {
            goto cleanup;
        }

        for (size_t q = 0; q < nq; q++) {
            const uint64_t index = qidx[q];
            dnac_fri_batch_opening_t *B = &p->batches[q * 3];
            dnac_merkle_proof_t pr;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;

            for (size_t i = 0; i < A_CW; i++)
                p->rand_rows[q * A_CW + i] =
                    gold_fp_from_u64(r_lde[index * A_CW + i]);
            p->rand_rowptr[q] = &p->rand_rows[q * A_CW];
            p->rand_len[q] = A_CW;
            memset(&pr, 0, sizeof(pr));
            pr.siblings = &p->rand_sib[q * in_depth];
            pr.depth = (uint32_t)in_depth;
            if (dnac_merkle_open(rtree, index, &leaf, &leaf_len, &pr) !=
                DNAC_MERKLE_OK) goto cleanup;
            B[0].opened_values = &p->rand_rowptr[q];
            B[0].opened_values_lens = &p->rand_len[q];
            B[0].num_matrices = 1;
            B[0].opening_proof.leaf_index = 0;
            B[0].opening_proof.depth = (uint32_t)in_depth;
            B[0].opening_proof.num_matrices = 1;
            B[0].opening_proof.siblings = &p->rand_sib[q * in_depth];

            for (size_t i = 0; i < A_RAND_W; i++)
                p->trace_rows[q * A_RAND_W + i] =
                    gold_fp_from_u64(lde_c[index * A_RAND_W + i]);
            p->trace_rowptr[q] = &p->trace_rows[q * A_RAND_W];
            p->trace_len[q] = A_RAND_W;
            memset(&pr, 0, sizeof(pr));
            pr.siblings = &p->trace_sib[q * in_depth];
            pr.depth = (uint32_t)in_depth;
            if (dnac_merkle_open(ttree, index, &leaf, &leaf_len, &pr) !=
                DNAC_MERKLE_OK) goto cleanup;
            B[1].opened_values = &p->trace_rowptr[q];
            B[1].opened_values_lens = &p->trace_len[q];
            B[1].num_matrices = 1;
            B[1].opening_proof.leaf_index = 0;
            B[1].opening_proof.depth = (uint32_t)in_depth;
            B[1].opening_proof.num_matrices = 1;
            B[1].opening_proof.siblings = &p->trace_sib[q * in_depth];

            for (size_t m = 0; m < A_NUM_QC; m++) {
                for (size_t i = 0; i < A_CW; i++)
                    p->quot_rows[(q * A_NUM_QC + m) * A_CW + i] =
                        gold_fp_from_u64(
                            chunk_ldes[m * lde_h * A_CW + index * A_CW + i]);
                p->quot_rowptr[q * A_NUM_QC + m] =
                    &p->quot_rows[(q * A_NUM_QC + m) * A_CW];
                p->quot_len[q * A_NUM_QC + m] = A_CW;
            }
            {
                const uint8_t *rows[A_NUM_QC];
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->quot_sib[q * in_depth];
                pr.depth = (uint32_t)in_depth;
                if (dnac_merkle_batch_open(qtree, index, rows, &pr) !=
                    DNAC_MERKLE_OK) goto cleanup;
            }
            B[2].opened_values = &p->quot_rowptr[q * A_NUM_QC];
            B[2].opened_values_lens = &p->quot_len[q * A_NUM_QC];
            B[2].num_matrices = A_NUM_QC;
            B[2].opening_proof.leaf_index = 0;
            B[2].opening_proof.depth = (uint32_t)in_depth;
            B[2].opening_proof.num_matrices = A_NUM_QC;
            B[2].opening_proof.siblings = &p->quot_sib[q * in_depth];

            uint64_t cur = index;
            size_t psib_off = q * cp_depth_sum;
            for (size_t r = 0; r < nr; r++) {
                const unsigned a = res.layer_log_arities[r];
                if (a != 1) goto cleanup;
                const size_t arity = (size_t)1 << a;
                const uint64_t iig = cur & (arity - 1);
                const uint64_t gid = cur >> a;
                const size_t depth = ilog2_pow2(res.layer_heights[r]);
                dnac_fri_commit_phase_proof_step_t *S = &p->cp_steps[q * nr + r];
                p->cp_step_sib[q * nr + r] =
                    res.layer_leaves[r][gid * arity + (1 - iig)];
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->cp_step_psib[psib_off];
                pr.depth = (uint32_t)depth;
                if (dnac_merkle_open(res.layer_trees[r], gid, &leaf, &leaf_len,
                                     &pr) != DNAC_MERKLE_OK) goto cleanup;
                S->log_arity = (uint8_t)a;
                S->sibling_values = &p->cp_step_sib[q * nr + r];
                S->num_sibling_values = arity - 1;
                S->opening_proof.leaf_index = 0;
                S->opening_proof.depth = (uint32_t)depth;
                S->opening_proof.num_matrices = 1;
                S->opening_proof.siblings = &p->cp_step_psib[psib_off];
                psib_off += depth;
                cur = gid;
            }

            p->query_proofs[q].input_proof = B;
            p->query_proofs[q].num_input_batches = 3;
            p->query_proofs[q].commit_phase_openings = &p->cp_steps[q * nr];
            p->query_proofs[q].num_commit_phase_openings = nr;
        }
    }
    dnac_transcript_free(t);
    t = NULL;

    memset(&p->proof, 0, sizeof(p->proof));
    p->proof.commit_phase_commits = p->cp_commits;
    p->proof.num_commit_phase_commits = res.num_rounds;
    p->proof.commit_pow_witnesses = p->cp_pow;
    p->proof.num_commit_pow_witnesses = res.num_rounds;
    p->proof.query_proofs = p->query_proofs;
    p->proof.num_query_proofs = A_NUM_QUERIES;
    p->proof.final_poly = p->final_poly;
    p->proof.num_final_poly = res.final_poly_len;
    p->proof.query_pow_witness = gold_fp_from_u64(0);

    memset(&p->params, 0, sizeof(p->params));
    p->params.log_blowup = A_LOG_BLOWUP;
    p->params.log_final_poly_len = A_LOG_FINAL_POLY_LEN;
    p->params.max_log_arity = A_MAX_LOG_ARITY;
    p->params.num_queries = A_NUM_QUERIES;
    p->params.commit_proof_of_work_bits = 0;
    p->params.query_proof_of_work_bits = 0;

    dnac_prover_fri_result_free(&res);
    have_res = 0;
    dnac_merkle_tree_free(ttree); ttree = NULL;
    dnac_merkle_tree_free(rtree); rtree = NULL;
    dnac_merkle_batch_tree_free(qtree); qtree = NULL;

    if (dnac_agg_prover_proof_verify(p) != DNAC_FRI_OK) {
        rc = DNAC_PROVER_ERR_VERIFY;
        goto cleanup;
    }

    rc = DNAC_PROVER_OK;
    *out_proof = p;
    p = NULL;

cleanup:
    free(base_c); free(rand_c); free(lde_c); free(trace_q); free(qflat);
    free(chunk_ldes); free(r_lde); free(sf); free(sl); free(st); free(iv);
    free(ro);
    if (have_res) dnac_prover_fri_result_free(&res);
    if (t) dnac_transcript_free(t);
    if (ttree) dnac_merkle_tree_free(ttree);
    if (rtree) dnac_merkle_tree_free(rtree);
    if (qtree) dnac_merkle_batch_tree_free(qtree);
    if (p) dnac_agg_prover_proof_free(p);
    return rc;
}
