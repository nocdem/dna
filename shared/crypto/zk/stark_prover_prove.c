/**
 * @file stark_prover_prove.c
 * @brief C STARK prover — P1: instance-generic end-to-end prove + assemble.
 *
 * See stark_prover_prove.h. All shapes are derived from the instance height per
 * the P1 grounding (Plonky3 82cfad73):
 *   base_degree_bits = log2(height); degree_bits = base+is_zk;
 *   log_max_height = base+log_blowup+is_zk (= base+3); lde_h = 2^log_max_height;
 *   num_qc = 4 (AIR-fixed); quotient_size = 2^(degree_bits+log_num_qc);
 *   num_fri_rounds = base_degree_bits-1; input batch depth = log_max_height;
 *   reduced_index shift = 0 (uniform height); coms domain.log_size = degree_bits.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_prover_prove.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "fri_proof_codec.h"
#include "stark_priming.h"
#include "stark_proof_codec.h"
#include "transcript.h"

/* Fixed RangeProofAir / is_zk=1 config constants. */
#define P_IS_ZK 1u
#define P_LOG_BLOWUP 2u
#define P_LOG_FINAL_POLY_LEN 2u
#define P_MAX_LOG_ARITY 1u
#define P_NUM_QUERIES 2u
#define P_NUM_QC 4u
#define P_NUM_RANDOM 4u
#define P_W 56u          /* RANGE_PROOF_WIDTH */
#define P_RAND_W 60u     /* W + num_random */
#define P_CW 6u          /* quotient/random chunk width = 2 + num_random */
#define P_NUM_INPUT_BATCHES 3u

/* Opaque handle: owns everything the assembled proof/coms/priming reference. */
struct dnac_prover_proof_s {
    /* derived shape */
    size_t base_degree_bits, degree_bits, log_max_height, lde_h, num_fri_rounds;
    size_t num_queries;

    /* commit roots + merged opened values (coms claimed_evals + priming) */
    dnac_merkle_digest_t trace_c, quot_c, rand_c;
    gold_fp2_t r_open[P_CW];
    gold_fp2_t *t_open;      /* P_RAND_W */
    gold_fp2_t *t_open_n;    /* P_RAND_W */
    gold_fp2_t q_open[P_NUM_QC * P_CW];
    gold_fp_t  publics[3];

    /* FRI commit-phase proof pieces */
    dnac_merkle_digest_t *cp_commits;   /* num_fri_rounds */
    gold_fp_t            *cp_pow;        /* num_fri_rounds (all 0) */
    gold_fp2_t           *final_poly;    /* final_poly_len */
    size_t                final_poly_len;

    /* per-query storage */
    dnac_fri_query_proof_t *query_proofs;         /* num_queries */
    dnac_fri_batch_opening_t *batches;            /* num_queries * 3 */
    /* input batch rows (owned copies) */
    gold_fp_t  *rand_rows;   /* num_queries * P_CW */
    gold_fp_t  *trace_rows;  /* num_queries * P_RAND_W */
    gold_fp_t  *quot_rows;   /* num_queries * P_NUM_QC * P_CW */
    const gold_fp_t **rand_rowptr, **trace_rowptr, **quot_rowptr;
    size_t *rand_len, *trace_len, *quot_len;
    dnac_merkle_digest_t *rand_sib, *trace_sib, *quot_sib; /* q * depth each */
    /* commit-phase steps */
    dnac_fri_commit_phase_proof_step_t *cp_steps; /* num_queries * num_fri_rounds */
    gold_fp2_t *cp_step_sib;   /* num_queries * num_fri_rounds * (arity-1)=1 */
    dnac_merkle_digest_t *cp_step_psib; /* num_queries * sum(depths) */

    /* assembled proof + coms + priming */
    dnac_fri_proof_t proof;
    dnac_fri_params_t params;
    dnac_fri_opening_point_t rand_pt[1], trace_pt[2];
    dnac_fri_opening_point_t *quot_pt;   /* num_qc */
    dnac_fri_matrix_openings_t rand_mx, trace_mx;
    dnac_fri_matrix_openings_t *quot_mx; /* num_qc */
    dnac_fri_commitment_with_opening_points_t coms[3];
    dnac_stark_priming_input_t prime_in;
    const gold_fp2_t *qcptr[P_NUM_QC];
    size_t qclen[P_NUM_QC];

    gold_fp2_t zeta, zeta_next; /* prover's own, for the verify cross-check */
    uint64_t query_indices[64];  /* sampled query indices (num_queries) */
};

static size_t ilog2_pow2(size_t n) {
    size_t l = 0;
    while ((((size_t)1) << l) < n) l++;
    return l;
}

/* ── build the priming input (NO zeta needed — priming produces it) ── */
static void build_prime_input(dnac_prover_proof_t *p) {
    memset(&p->prime_in, 0, sizeof(p->prime_in));
    p->prime_in.degree_bits = p->degree_bits;
    p->prime_in.is_zk = P_IS_ZK;
    p->prime_in.preprocessed_width = 0;
    p->prime_in.trace_commit = p->trace_c;
    p->prime_in.quotient_commit = p->quot_c;
    p->prime_in.random_commit = &p->rand_c;
    p->prime_in.random_local = p->r_open;
    p->prime_in.random_local_len = P_CW;
    p->prime_in.public_values = p->publics;
    p->prime_in.num_public_values = 3;
    p->prime_in.trace_local = p->t_open;
    p->prime_in.trace_local_len = P_RAND_W;
    p->prime_in.trace_next = p->t_open_n;
    p->prime_in.trace_next_len = P_RAND_W;
    for (size_t k = 0; k < P_NUM_QC; k++) {
        p->qcptr[k] = &p->q_open[k * P_CW];
        p->qclen[k] = P_CW;
    }
    p->prime_in.quotient_chunks = p->qcptr;
    p->prime_in.quotient_chunk_lens = p->qclen;
    p->prime_in.num_quotient_chunks = P_NUM_QC;
}

/* ── build the 3-round coms from stored data (needs the primed zeta) ── */
static void build_coms(dnac_prover_proof_t *p, gold_fp2_t zeta,
                       gold_fp2_t zeta_next) {
    const uint32_t ls = (uint32_t)p->degree_bits;
    p->rand_pt[0].point = zeta;
    p->rand_pt[0].claimed_evals = p->r_open;
    p->rand_pt[0].num_claimed_evals = P_CW;
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
    p->trace_pt[0].num_claimed_evals = P_RAND_W;
    p->trace_pt[1].point = zeta_next;
    p->trace_pt[1].claimed_evals = p->t_open_n;
    p->trace_pt[1].num_claimed_evals = P_RAND_W;
    p->trace_mx.domain.shift = gold_fp_from_u64(0);
    p->trace_mx.domain.shift_inverse = gold_fp_from_u64(0);
    p->trace_mx.domain.log_size = ls;
    p->trace_mx.points = p->trace_pt;
    p->trace_mx.num_points = 2;
    p->coms[1].commitment = p->trace_c;
    p->coms[1].matrices = &p->trace_mx;
    p->coms[1].num_matrices = 1;

    for (size_t k = 0; k < P_NUM_QC; k++) {
        p->quot_pt[k].point = zeta;
        p->quot_pt[k].claimed_evals = &p->q_open[k * P_CW];
        p->quot_pt[k].num_claimed_evals = P_CW;
        p->quot_mx[k].domain.shift = gold_fp_from_u64(0);
        p->quot_mx[k].domain.shift_inverse = gold_fp_from_u64(0);
        p->quot_mx[k].domain.log_size = ls;
        p->quot_mx[k].points = &p->quot_pt[k];
        p->quot_mx[k].num_points = 1;
    }
    p->coms[2].commitment = p->quot_c;
    p->coms[2].matrices = p->quot_mx;
    p->coms[2].num_matrices = P_NUM_QC;
}

dnac_fri_status_t dnac_prover_proof_verify(const dnac_prover_proof_t *cp) {
    dnac_prover_proof_t *p = (dnac_prover_proof_t *)cp;
    dnac_transcript_t *vt =
        dnac_transcript_init((const uint8_t *)"DNAC|ZK|FRI|TRANSCRIPT|V1", 25);
    if (vt == NULL) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    build_prime_input(p);
    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof(out));
    if (dnac_stark_prime_transcript(vt, &p->prime_in, &out) !=
        DNAC_STARK_PRIMING_OK) {
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    /* fail-close: primed zeta must match the prover's own (any divergence is
     * an upstream transcript-order bug). */
    if (!(gold_fp_to_u64(out.zeta.a) == gold_fp_to_u64(p->zeta.a) &&
          gold_fp_to_u64(out.zeta.b) == gold_fp_to_u64(p->zeta.b) &&
          gold_fp_to_u64(out.zeta_next.a) == gold_fp_to_u64(p->zeta_next.a) &&
          gold_fp_to_u64(out.zeta_next.b) == gold_fp_to_u64(p->zeta_next.b))) {
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    build_coms(p, out.zeta, out.zeta_next);
    dnac_fri_status_t fs =
        dnac_fri_verify(&p->params, &p->proof, vt, p->coms, 3);
    dnac_transcript_free(vt);
    return fs;
}

size_t dnac_prover_proof_degree_bits(const dnac_prover_proof_t *p) {
    return p->degree_bits;
}
size_t dnac_prover_proof_num_fri_rounds(const dnac_prover_proof_t *p) {
    return p->num_fri_rounds;
}
size_t dnac_prover_proof_log_max_height(const dnac_prover_proof_t *p) {
    return p->log_max_height;
}

void dnac_prover_proof_zeta(const dnac_prover_proof_t *p, gold_fp2_t *zeta,
                            gold_fp2_t *zeta_next) {
    if (zeta) *zeta = p->zeta;
    if (zeta_next) *zeta_next = p->zeta_next;
}

void dnac_prover_proof_roots(const dnac_prover_proof_t *p,
                             uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                             uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                             uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]) {
    if (trace_root) memcpy(trace_root, p->trace_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (quot_root) memcpy(quot_root, p->quot_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (rand_root) memcpy(rand_root, p->rand_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
}

const gold_fp2_t *dnac_prover_proof_final_poly(const dnac_prover_proof_t *p,
                                               size_t *out_len) {
    if (out_len) *out_len = p->final_poly_len;
    return p->final_poly;
}

size_t dnac_prover_proof_query_indices(const dnac_prover_proof_t *p,
                                       uint64_t *out, size_t max) {
    size_t n = p->num_queries;
    if (out) {
        for (size_t i = 0; i < n && i < max; i++) out[i] = p->query_indices[i];
    }
    return n;
}

size_t dnac_prover_proof_wire_size(const dnac_prover_proof_t *cp) {
    dnac_prover_proof_t *p = (dnac_prover_proof_t *)cp;
    /* coms were built during the self-verify with the primed zeta (== p->zeta);
     * rebuild them here so the accessor is independent of verify state. */
    build_coms(p, p->zeta, p->zeta_next);
    uint8_t *dzkf = NULL, *dzks = NULL;
    size_t dzkf_len = 0, dzks_len = 0, out = 0;
    if (dnac_fri_proof_encode(&p->params, &p->proof, p->coms, 3, &dzkf,
                              &dzkf_len) == DNAC_FRI_CODEC_OK) {
        if (dnac_stark_proof_encode(p->degree_bits, p->publics, 3, dzkf,
                                    dzkf_len, &dzks, &dzks_len) ==
            DNAC_STARK_WIRE_OK) {
            out = dzks_len;
        }
    }
    free(dzkf);
    free(dzks);
    return out;
}

void dnac_prover_proof_free(dnac_prover_proof_t *p) {
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
    free(p->quot_pt);
    free(p->quot_mx);
    free(p);
}

/* ── the prove ── */
dnac_prover_status_t dnac_prover_prove(
    const dnac_prover_instance_t *inst,
    dnac_prover_proof_t         **out_proof) {
    if (inst == NULL || out_proof == NULL || inst->amounts == NULL ||
        inst->draws == NULL) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t height = inst->height;
    /* Minimum valid height is 4 (base_degree_bits >= 2): Plonky3 asserts
     * log_min_height > log_final_poly_len + log_blowup (fri/prover.rs:79-81),
     * i.e. degree_bits+log_blowup > log_final_poly_len+log_blowup ⇒
     * degree_bits > log_final_poly_len (=2) ⇒ base_degree_bits >= 2. height=2
     * gives 0 FRI rounds (no folding low-degree binding) which Plonky3 PANICS
     * on — fail-close (red-team A1/A6). */
    if (height < 4 || (height & (height - 1)) != 0 ||
        height > STARK_PROVER_MAX_HEIGHT || inst->n_real == 0 ||
        inst->n_real > height) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (inst->num_draws != DNAC_PROVER_TOTAL_DRAWS(height)) {
        return DNAC_PROVER_ERR_PARAM;
    }

    /* ── derive shape ── */
    const size_t base_db = ilog2_pow2(height);
    const size_t degree_bits = base_db + P_IS_ZK;
    const size_t log_max_height = base_db + P_LOG_BLOWUP + P_IS_ZK;
    const size_t lde_h = (size_t)1 << log_max_height;      /* 8*height */
    /* num_qc = 1<<(log_num_quotient_chunks + is_zk); log_num_quotient_chunks =
     * log2_ceil((max_constraint_degree+is_zk).max(2) - 1). RangeProofAir has
     * max_constraint_degree 2 ⇒ (2+1).max(2)-1 = 2 ⇒ log2_ceil(2) = 1 ⇒
     * num_qc = 1<<(1+1) = 4 — HEIGHT-INDEPENDENT, function of the AIR only
     * (uni-stark symbolic.rs + prover.rs:124-127). The oracle's num_qc gate
     * (STOP if != measured) enforces this against real p3; P_NUM_QC=4 is
     * correct for RangeProofAir and MUST be re-derived if the AIR degree
     * changes (red-team A10). */
    const size_t log_num_qc = 1;
    const size_t q_size = (size_t)1 << (degree_bits + log_num_qc);
    const size_t num_rounds_expected = base_db - 1;        /* G4 */
    const size_t total = DNAC_PROVER_TOTAL_DRAWS(height);
    (void)total;

    /* draw slices (G6): trace 64h @0, codeword 16h @64h, blinding 18h @80h,
     * R 12h @98h. */
    const uint64_t *trace_draws = inst->draws;
    const uint64_t *codeword = inst->draws + (size_t)64 * height;
    const uint64_t *blinding = inst->draws + (size_t)80 * height;
    const uint64_t *r_draws = inst->draws + (size_t)98 * height;

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    dnac_prover_proof_t *p = (dnac_prover_proof_t *)calloc(1, sizeof(*p));
    if (p == NULL) return DNAC_PROVER_ERR_PARAM;
    p->base_degree_bits = base_db;
    p->degree_bits = degree_bits;
    p->log_max_height = log_max_height;
    p->lde_h = lde_h;
    p->num_queries = P_NUM_QUERIES;

    /* working buffers */
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

    base_c = (uint64_t *)malloc(height * P_W * 8);
    rand_c = (uint64_t *)malloc((2 * height) * P_RAND_W * 8);
    lde_c = (uint64_t *)malloc(lde_h * P_RAND_W * 8);
    trace_q = (uint64_t *)malloc(q_size * P_W * 8);
    qflat = (uint64_t *)malloc(2 * q_size * 8);
    chunk_ldes = (uint64_t *)malloc(P_NUM_QC * lde_h * P_CW * 8);
    r_lde = (uint64_t *)malloc(lde_h * P_CW * 8);
    sf = (uint64_t *)malloc(q_size * 8);
    sl = (uint64_t *)malloc(q_size * 8);
    st = (uint64_t *)malloc(q_size * 8);
    iv = (uint64_t *)malloc(q_size * 8);
    ro = (gold_fp2_t *)malloc(lde_h * sizeof(gold_fp2_t));
    p->t_open = (gold_fp2_t *)malloc(P_RAND_W * sizeof(gold_fp2_t));
    p->t_open_n = (gold_fp2_t *)malloc(P_RAND_W * sizeof(gold_fp2_t));
    p->quot_pt = (dnac_fri_opening_point_t *)malloc(P_NUM_QC * sizeof(dnac_fri_opening_point_t));
    p->quot_mx = (dnac_fri_matrix_openings_t *)malloc(P_NUM_QC * sizeof(dnac_fri_matrix_openings_t));
    if (!base_c || !rand_c || !lde_c || !trace_q || !qflat || !chunk_ldes ||
        !r_lde || !sf || !sl || !st || !iv || !ro || !p->t_open ||
        !p->t_open_n || !p->quot_pt || !p->quot_mx) {
        goto cleanup;
    }

    /* publics */
    {
        uint64_t claimed = inst->fee;
        for (size_t i = 0; i < inst->n_real; i++) claimed += inst->amounts[i];
        p->publics[0] = gold_fp_from_u64(claimed);
        p->publics[1] = gold_fp_from_u64(inst->fee);
        p->publics[2] = gold_fp_from_u64((uint64_t)inst->n_real);
    }
    const uint64_t publics_u[3] = {gold_fp_to_u64(p->publics[0]),
                                   gold_fp_to_u64(p->publics[1]),
                                   gold_fp_to_u64(p->publics[2])};

    /* ── S1-S8 ── */
    t = dnac_transcript_init_default();
    if (t == NULL) goto cleanup;
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
    {
        dnac_prover_status_t s;
        s = dnac_prover_build_range_proof_trace(inst->amounts, inst->n_real,
                                                height, base_c, NULL);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_randomize_trace(base_c, height, P_W, P_NUM_RANDOM,
                                        trace_draws, rand_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_coset_lde_bitrev(rand_c, 2 * height, P_RAND_W,
                                         P_LOG_BLOWUP, 7, lde_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_commit_matrix(lde_c, lde_h, P_RAND_W,
                                      p->trace_c.bytes, &ttree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_alpha(t, degree_bits, base_db, 0, p->trace_c.bytes,
                                    publics_u, 3, &alpha);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_selectors((unsigned)base_db,
                                           (unsigned)(degree_bits + log_num_qc),
                                           7, sf, sl, st, iv);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_trace_on_quotient_domain(lde_c, lde_h, P_RAND_W, q_size,
                                                 P_W, trace_q);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_values_range_zk(trace_q, q_size, 4, publics_u,
                                                 alpha, sf, sl, st, iv, qflat);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_commit(qflat, q_size, P_NUM_QC, P_NUM_RANDOM,
                                        P_LOG_BLOWUP, 7, codeword, blinding,
                                        chunk_ldes, p->quot_c.bytes, &qtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_random_commit(r_draws, 2 * height, P_CW, P_LOG_BLOWUP,
                                      r_lde, p->rand_c.bytes, &rtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_zeta(t, p->quot_c.bytes, p->rand_c.bytes,
                                   base_db, &zeta, &zeta_next);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
    }
    p->zeta = zeta;
    p->zeta_next = zeta_next;

    /* ── S9 open ── */
    if (dnac_prover_open_matrix_at(r_lde, lde_h, P_CW, P_LOG_BLOWUP, zeta,
                                   p->r_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, P_RAND_W, P_LOG_BLOWUP, zeta,
                                   p->t_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, P_RAND_W, P_LOG_BLOWUP,
                                   zeta_next, p->t_open_n) != DNAC_PROVER_OK) {
        goto cleanup;
    }
    for (size_t k = 0; k < P_NUM_QC; k++) {
        if (dnac_prover_open_matrix_at(&chunk_ldes[k * lde_h * P_CW], lde_h,
                                       P_CW, P_LOG_BLOWUP, zeta,
                                       &p->q_open[k * P_CW]) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    dnac_prover_observe_opened(t, p->r_open, P_CW);
    dnac_prover_observe_opened(t, p->t_open, P_RAND_W);
    dnac_prover_observe_opened(t, p->t_open_n, P_RAND_W);
    for (size_t k = 0; k < P_NUM_QC; k++)
        dnac_prover_observe_opened(t, &p->q_open[k * P_CW], P_CW);
    fri_alpha = dnac_transcript_sample_fp2(t);

    /* ── S10 reduced openings + commit phase ── */
    {
        const gold_fp2_t zpts[2] = {zeta, zeta_next};
        const gold_fp2_t *r_ov[1] = {p->r_open};
        const gold_fp2_t *t_ov[2] = {p->t_open, p->t_open_n};
        const gold_fp2_t *q_ov[P_NUM_QC][1];
        dnac_prover_fri_input_round_t rounds[2 + P_NUM_QC];
        rounds[0] = (dnac_prover_fri_input_round_t){r_lde, lde_h, P_CW, 1, &zeta, r_ov};
        rounds[1] = (dnac_prover_fri_input_round_t){lde_c, lde_h, P_RAND_W, 2, zpts, t_ov};
        for (size_t k = 0; k < P_NUM_QC; k++) {
            q_ov[k][0] = &p->q_open[k * P_CW];
            rounds[2 + k] = (dnac_prover_fri_input_round_t){
                &chunk_ldes[k * lde_h * P_CW], lde_h, P_CW, 1, &zeta, q_ov[k]};
        }
        if (dnac_prover_fri_reduced_openings(rounds, 2 + P_NUM_QC,
                                             (unsigned)log_max_height, fri_alpha,
                                             ro) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    if (dnac_prover_fri_commit_phase(ro, lde_h, P_LOG_BLOWUP,
                                     P_LOG_FINAL_POLY_LEN, P_MAX_LOG_ARITY, t,
                                     &res) != DNAC_PROVER_OK) {
        goto cleanup;
    }
    have_res = 1;
    if (res.num_rounds != num_rounds_expected) goto cleanup;
    p->num_fri_rounds = res.num_rounds;
    p->final_poly_len = res.final_poly_len;

    /* copy commit-phase scalars into owned storage */
    p->cp_commits = (dnac_merkle_digest_t *)malloc(res.num_rounds * sizeof(dnac_merkle_digest_t));
    p->cp_pow = (gold_fp_t *)calloc(res.num_rounds, sizeof(gold_fp_t));
    p->final_poly = (gold_fp2_t *)malloc(res.final_poly_len * sizeof(gold_fp2_t));
    if (!p->cp_commits || !p->cp_pow || !p->final_poly) goto cleanup;
    for (size_t r = 0; r < res.num_rounds; r++)
        p->cp_commits[r] = *(dnac_merkle_digest_t *)res.roots[r];
    memcpy(p->final_poly, res.final_poly, res.final_poly_len * sizeof(gold_fp2_t));

    /* ── S11 sample query indices ── */
    uint64_t *qidx = (uint64_t *)malloc(P_NUM_QUERIES * sizeof(uint64_t));
    if (qidx == NULL) goto cleanup;
    for (size_t q = 0; q < P_NUM_QUERIES; q++) {
        qidx[q] = dnac_transcript_sample_bits(t, (size_t)log_max_height);
        p->query_indices[q] = qidx[q];
    }

    /* ── S12 query openings (generalized, multi-round) ── */
    {
        const size_t nq = P_NUM_QUERIES, nr = res.num_rounds;
        const size_t in_depth = log_max_height;
        /* sum of per-round commit-phase depths for path storage */
        size_t cp_depth_sum = 0;
        for (size_t r = 0; r < nr; r++)
            cp_depth_sum += ilog2_pow2(res.layer_heights[r]);

        p->query_proofs = (dnac_fri_query_proof_t *)calloc(nq, sizeof(dnac_fri_query_proof_t));
        p->batches = (dnac_fri_batch_opening_t *)calloc(nq * 3, sizeof(dnac_fri_batch_opening_t));
        p->rand_rows = (gold_fp_t *)malloc(nq * P_CW * sizeof(gold_fp_t));
        p->trace_rows = (gold_fp_t *)malloc(nq * P_RAND_W * sizeof(gold_fp_t));
        p->quot_rows = (gold_fp_t *)malloc(nq * P_NUM_QC * P_CW * sizeof(gold_fp_t));
        p->rand_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->trace_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->quot_rowptr = (const gold_fp_t **)malloc(nq * P_NUM_QC * sizeof(gold_fp_t *));
        p->rand_len = (size_t *)malloc(nq * sizeof(size_t));
        p->trace_len = (size_t *)malloc(nq * sizeof(size_t));
        p->quot_len = (size_t *)malloc(nq * P_NUM_QC * sizeof(size_t));
        p->rand_sib = (dnac_merkle_digest_t *)malloc(nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->trace_sib = (dnac_merkle_digest_t *)malloc(nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->quot_sib = (dnac_merkle_digest_t *)malloc(nq * in_depth * sizeof(dnac_merkle_digest_t));
        p->cp_steps = (dnac_fri_commit_phase_proof_step_t *)calloc(nq * nr, sizeof(dnac_fri_commit_phase_proof_step_t));
        p->cp_step_sib = (gold_fp2_t *)malloc(nq * nr * sizeof(gold_fp2_t)); /* arity-2: 1 each */
        p->cp_step_psib = (dnac_merkle_digest_t *)malloc(nq * cp_depth_sum * sizeof(dnac_merkle_digest_t));
        if (!p->query_proofs || !p->batches || !p->rand_rows || !p->trace_rows ||
            !p->quot_rows || !p->rand_rowptr || !p->trace_rowptr ||
            !p->quot_rowptr || !p->rand_len || !p->trace_len || !p->quot_len ||
            !p->rand_sib || !p->trace_sib || !p->quot_sib || !p->cp_steps ||
            !p->cp_step_sib || !p->cp_step_psib) {
            free(qidx);
            goto cleanup;
        }

        for (size_t q = 0; q < nq; q++) {
            const uint64_t index = qidx[q];
            dnac_fri_batch_opening_t *B = &p->batches[q * 3];
            dnac_merkle_proof_t pr;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;

            /* reduced_index = index >> (log_gmh - log_batch_height); all batches
             * share log_gmh ⇒ shift 0 (assert). */
            /* batch 0: random */
            for (size_t i = 0; i < P_CW; i++)
                p->rand_rows[q * P_CW + i] =
                    gold_fp_from_u64(r_lde[index * P_CW + i]);
            p->rand_rowptr[q] = &p->rand_rows[q * P_CW];
            p->rand_len[q] = P_CW;
            memset(&pr, 0, sizeof(pr));
            pr.siblings = &p->rand_sib[q * in_depth];
            pr.depth = (uint32_t)in_depth;
            if (dnac_merkle_open(rtree, index, &leaf, &leaf_len, &pr) !=
                DNAC_MERKLE_OK) { free(qidx); goto cleanup; }
            B[0].opened_values = &p->rand_rowptr[q];
            B[0].opened_values_lens = &p->rand_len[q];
            B[0].num_matrices = 1;
            B[0].opening_proof.leaf_index = 0;
            B[0].opening_proof.depth = (uint32_t)in_depth;
            B[0].opening_proof.num_matrices = 1;
            B[0].opening_proof.siblings = &p->rand_sib[q * in_depth];

            /* batch 1: trace */
            for (size_t i = 0; i < P_RAND_W; i++)
                p->trace_rows[q * P_RAND_W + i] =
                    gold_fp_from_u64(lde_c[index * P_RAND_W + i]);
            p->trace_rowptr[q] = &p->trace_rows[q * P_RAND_W];
            p->trace_len[q] = P_RAND_W;
            memset(&pr, 0, sizeof(pr));
            pr.siblings = &p->trace_sib[q * in_depth];
            pr.depth = (uint32_t)in_depth;
            if (dnac_merkle_open(ttree, index, &leaf, &leaf_len, &pr) !=
                DNAC_MERKLE_OK) { free(qidx); goto cleanup; }
            B[1].opened_values = &p->trace_rowptr[q];
            B[1].opened_values_lens = &p->trace_len[q];
            B[1].num_matrices = 1;
            B[1].opening_proof.leaf_index = 0;
            B[1].opening_proof.depth = (uint32_t)in_depth;
            B[1].opening_proof.num_matrices = 1;
            B[1].opening_proof.siblings = &p->trace_sib[q * in_depth];

            /* batch 2: quotient (num_qc matrices, shared path) */
            for (size_t m = 0; m < P_NUM_QC; m++) {
                for (size_t i = 0; i < P_CW; i++)
                    p->quot_rows[(q * P_NUM_QC + m) * P_CW + i] =
                        gold_fp_from_u64(chunk_ldes[m * lde_h * P_CW + index * P_CW + i]);
                p->quot_rowptr[q * P_NUM_QC + m] =
                    &p->quot_rows[(q * P_NUM_QC + m) * P_CW];
                p->quot_len[q * P_NUM_QC + m] = P_CW;
            }
            {
                const uint8_t *rows[P_NUM_QC];
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->quot_sib[q * in_depth];
                pr.depth = (uint32_t)in_depth;
                if (dnac_merkle_batch_open(qtree, index, rows, &pr) !=
                    DNAC_MERKLE_OK) { free(qidx); goto cleanup; }
            }
            B[2].opened_values = &p->quot_rowptr[q * P_NUM_QC];
            B[2].opened_values_lens = &p->quot_len[q * P_NUM_QC];
            B[2].num_matrices = P_NUM_QC;
            B[2].opening_proof.leaf_index = 0;
            B[2].opening_proof.depth = (uint32_t)in_depth;
            B[2].opening_proof.num_matrices = P_NUM_QC;
            B[2].opening_proof.siblings = &p->quot_sib[q * in_depth];

            /* commit-phase openings: loop ALL rounds (answer_query, G2) */
            uint64_t cur = index;
            size_t psib_off = q * cp_depth_sum;
            for (size_t r = 0; r < nr; r++) {
                const unsigned a = res.layer_log_arities[r];
                /* arity-2-only sibling math (max_log_arity=1); fail-close if a
                 * future config bumps the arity (red-team A4/A6). */
                if (a != 1) { free(qidx); goto cleanup; }
                const size_t arity = (size_t)1 << a;
                const uint64_t iig = cur & (arity - 1);
                const uint64_t gid = cur >> a;
                const size_t depth = ilog2_pow2(res.layer_heights[r]);
                dnac_fri_commit_phase_proof_step_t *S = &p->cp_steps[q * nr + r];
                /* sibling = ascending-j layer_leaves[gid*arity + j], j != iig
                 * (arity-2 ⇒ exactly one) */
                p->cp_step_sib[q * nr + r] =
                    res.layer_leaves[r][gid * arity + (1 - iig)];
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->cp_step_psib[psib_off];
                pr.depth = (uint32_t)depth;
                if (dnac_merkle_open(res.layer_trees[r], gid, &leaf, &leaf_len,
                                     &pr) != DNAC_MERKLE_OK) {
                    free(qidx);
                    goto cleanup;
                }
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
    free(qidx);
    dnac_transcript_free(t);
    t = NULL;

    /* ── assemble dnac_fri_proof_t ── */
    memset(&p->proof, 0, sizeof(p->proof));
    p->proof.commit_phase_commits = p->cp_commits;
    p->proof.num_commit_phase_commits = res.num_rounds;
    p->proof.commit_pow_witnesses = p->cp_pow;
    p->proof.num_commit_pow_witnesses = res.num_rounds;
    p->proof.query_proofs = p->query_proofs;
    p->proof.num_query_proofs = P_NUM_QUERIES;
    p->proof.final_poly = p->final_poly;
    p->proof.num_final_poly = res.final_poly_len;
    p->proof.query_pow_witness = gold_fp_from_u64(0);

    memset(&p->params, 0, sizeof(p->params));
    p->params.log_blowup = P_LOG_BLOWUP;
    p->params.log_final_poly_len = P_LOG_FINAL_POLY_LEN;
    p->params.max_log_arity = P_MAX_LOG_ARITY;
    p->params.num_queries = P_NUM_QUERIES;
    p->params.commit_proof_of_work_bits = 0;
    p->params.query_proof_of_work_bits = 0;

    /* trees + working buffers no longer needed (all proof data is copied) */
    dnac_prover_fri_result_free(&res);
    have_res = 0;
    dnac_merkle_tree_free(ttree); ttree = NULL;
    dnac_merkle_tree_free(rtree); rtree = NULL;
    dnac_merkle_batch_tree_free(qtree); qtree = NULL;

    /* ── self-verify (fail-close) ── */
    if (dnac_prover_proof_verify(p) != DNAC_FRI_OK) {
        rc = DNAC_PROVER_ERR_VERIFY;
        goto cleanup;
    }

    rc = DNAC_PROVER_OK;
    *out_proof = p;
    p = NULL; /* ownership transferred */

cleanup:
    free(base_c); free(rand_c); free(lde_c); free(trace_q); free(qflat);
    free(chunk_ldes); free(r_lde); free(sf); free(sl); free(st); free(iv);
    free(ro);
    if (have_res) dnac_prover_fri_result_free(&res);
    if (t) dnac_transcript_free(t);
    if (ttree) dnac_merkle_tree_free(ttree);
    if (rtree) dnac_merkle_tree_free(rtree);
    if (qtree) dnac_merkle_batch_tree_free(qtree);
    if (p) dnac_prover_proof_free(p);
    return rc;
}
