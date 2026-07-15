/**
 * @file stark_prover_conf.c
 * @brief B1 Stage-2 — pure-C prover for the combined confidential AIR.
 *
 * Mirrors the P1 assembler (stark_prover_prove.c) with the conf-AIR constants
 * and the two AIR-specific stages swapped (S1 trace, S6 quotient). See
 * stark_prover_conf.h for the shape/draw grounding.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stark_prover_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf_commit_air.h"
#include "conf_root_air.h"
#include "field_goldilocks.h"
#include "stark_constraints.h"
#include "stark_priming.h"
#include "transcript.h"
#include "zk_entropy.h"

/* Fixed combined-conf-AIR / is_zk=1 config constants. */
#define C_IS_ZK 1u
#define C_LOG_BLOWUP 2u
#define C_LOG_FINAL_POLY_LEN 2u
#define C_MAX_LOG_ARITY 1u
#define C_NUM_QUERIES 2u
#define C_NUM_QC 8u          /* degree-3 AIR at is_zk=1; oracle-measured */
#define C_LOG_NUM_QC 2u
#define C_NUM_RANDOM 4u
#define C_W ((size_t)CONF_ROOT_WIDTH)          /* 614 */
#define C_RAND_W (C_W + C_NUM_RANDOM)          /* 618 */
#define C_CW ((size_t)2 + C_NUM_RANDOM)        /* 6 */
#define C_NPUB ((size_t)CONF_ROOT_FOLD_NUM_PUBLICS) /* 17 */

struct dnac_conf_prover_proof_s {
    size_t base_degree_bits, degree_bits, log_max_height, lde_h, num_fri_rounds;
    size_t num_queries;

    dnac_merkle_digest_t trace_c, quot_c, rand_c;
    gold_fp2_t r_open[C_CW];
    gold_fp2_t *t_open;      /* C_RAND_W */
    gold_fp2_t *t_open_n;    /* C_RAND_W */
    gold_fp2_t q_open[C_NUM_QC * C_CW];
    gold_fp_t  publics[C_NPUB];

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

    /* M3b salted openings: per-query salt values (gold_fp_t) + per-matrix
     * pointer arrays (the opening structs' `salts` field is
     * `const gold_fp_t * const *`). NULL/0 when unsalted. */
    gold_fp_t *rand_salt, *trace_salt, *quot_salt, *cp_salt;
    const gold_fp_t **rand_saltp, **trace_saltp, **quot_saltp;
    int salted; size_t salt_elems;

    dnac_fri_proof_t proof;
    dnac_fri_params_t params;
    dnac_fri_opening_point_t rand_pt[1], trace_pt[2];
    dnac_fri_opening_point_t quot_pt[C_NUM_QC];
    dnac_fri_matrix_openings_t rand_mx, trace_mx;
    dnac_fri_matrix_openings_t quot_mx[C_NUM_QC];
    dnac_fri_commitment_with_opening_points_t coms[3];
    dnac_stark_priming_input_t prime_in;
    const gold_fp2_t *qcptr[C_NUM_QC];
    size_t qclen[C_NUM_QC];

    gold_fp2_t zeta, zeta_next;
    uint64_t query_indices[64];
};

static size_t ilog2_pow2(size_t n) {
    size_t l = 0;
    while ((((size_t)1) << l) < n) l++;
    return l;
}

/* ── S6: conf quotient values — REUSES the verifier-fold eval per row ──
 *
 * quotient_values (prover.rs:399-513 scalar equivalent): per quotient-domain
 * row i, fold the conf constraints over the base-field trace window with the
 * Horner rule acc = acc*alpha + C (identical to the verifier fold,
 * folder.rs:216) and multiply by inv_vanishing[i]. Driving the SAME
 * dnac_conf_root_fold_air_eval used by the verifier gives ONE emission source
 * — base cells promoted to fp2 (c1 = 0), which is exact (the constraints are
 * polynomial; promotion is a ring homomorphism). */
static dnac_prover_status_t conf_quotient_values(
    const uint64_t *trace_q, size_t q_rows, size_t next_step,
    const gold_fp_t *publics, gold_fp2_t alpha,
    const uint64_t *sf, const uint64_t *sl, const uint64_t *st,
    const uint64_t *iv, uint64_t *out_q) {

    gold_fp2_t *lrow = (gold_fp2_t *)malloc(C_W * sizeof(gold_fp2_t));
    gold_fp2_t *nrow = (gold_fp2_t *)malloc(C_W * sizeof(gold_fp2_t));
    if (!lrow || !nrow) {
        free(lrow);
        free(nrow);
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t i = 0; i < q_rows; i++) {
        const size_t nidx = (i + next_step) & (q_rows - 1);
        for (size_t c = 0; c < C_W; c++) {
            lrow[c] = gold_fp2_from_base(gold_fp_from_u64(trace_q[i * C_W + c]));
            nrow[c] = gold_fp2_from_base(gold_fp_from_u64(trace_q[nidx * C_W + c]));
        }
        dnac_stark_folder_t folder;
        memset(&folder, 0, sizeof(folder));
        folder.trace_local = lrow;
        folder.trace_next = nrow;
        folder.main_width = C_W;
        folder.public_values = publics;
        folder.num_public_values = C_NPUB;
        folder.is_first_row = gold_fp2_from_base(gold_fp_from_u64(sf[i]));
        folder.is_last_row = gold_fp2_from_base(gold_fp_from_u64(sl[i]));
        folder.is_transition = gold_fp2_from_base(gold_fp_from_u64(st[i]));
        dnac_stark_fold_init(&folder.fold, alpha);
        folder.capture = NULL;
        dnac_conf_root_fold_air_eval(&folder);
        const gold_fp2_t q = gold_fp2_mul(
            folder.fold.acc, gold_fp2_from_base(gold_fp_from_u64(iv[i])));
        out_q[2 * i] = gold_fp_to_u64(q.a);
        out_q[2 * i + 1] = gold_fp_to_u64(q.b);
    }
    free(lrow);
    free(nrow);
    return DNAC_PROVER_OK;
}

/* ── priming input (17 publics, num_qc=8) ── */
static void build_prime_input(dnac_conf_prover_proof_t *p) {
    memset(&p->prime_in, 0, sizeof(p->prime_in));
    p->prime_in.degree_bits = p->degree_bits;
    p->prime_in.is_zk = C_IS_ZK;
    p->prime_in.preprocessed_width = 0;
    p->prime_in.trace_commit = p->trace_c;
    p->prime_in.quotient_commit = p->quot_c;
    p->prime_in.random_commit = &p->rand_c;
    p->prime_in.random_local = p->r_open;
    p->prime_in.random_local_len = C_CW;
    p->prime_in.public_values = p->publics;
    p->prime_in.num_public_values = C_NPUB;
    p->prime_in.trace_local = p->t_open;
    p->prime_in.trace_local_len = C_RAND_W;
    p->prime_in.trace_next = p->t_open_n;
    p->prime_in.trace_next_len = C_RAND_W;
    for (size_t k = 0; k < C_NUM_QC; k++) {
        p->qcptr[k] = &p->q_open[k * C_CW];
        p->qclen[k] = C_CW;
    }
    p->prime_in.quotient_chunks = p->qcptr;
    p->prime_in.quotient_chunk_lens = p->qclen;
    p->prime_in.num_quotient_chunks = C_NUM_QC;
}

static void build_coms(dnac_conf_prover_proof_t *p, gold_fp2_t zeta,
                       gold_fp2_t zeta_next) {
    const uint32_t ls = (uint32_t)p->degree_bits;
    p->rand_pt[0].point = zeta;
    p->rand_pt[0].claimed_evals = p->r_open;
    p->rand_pt[0].num_claimed_evals = C_CW;
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
    p->trace_pt[0].num_claimed_evals = C_RAND_W;
    p->trace_pt[1].point = zeta_next;
    p->trace_pt[1].claimed_evals = p->t_open_n;
    p->trace_pt[1].num_claimed_evals = C_RAND_W;
    p->trace_mx.domain.shift = gold_fp_from_u64(0);
    p->trace_mx.domain.shift_inverse = gold_fp_from_u64(0);
    p->trace_mx.domain.log_size = ls;
    p->trace_mx.points = p->trace_pt;
    p->trace_mx.num_points = 2;
    p->coms[1].commitment = p->trace_c;
    p->coms[1].matrices = &p->trace_mx;
    p->coms[1].num_matrices = 1;

    for (size_t k = 0; k < C_NUM_QC; k++) {
        p->quot_pt[k].point = zeta;
        p->quot_pt[k].claimed_evals = &p->q_open[k * C_CW];
        p->quot_pt[k].num_claimed_evals = C_CW;
        p->quot_mx[k].domain.shift = gold_fp_from_u64(0);
        p->quot_mx[k].domain.shift_inverse = gold_fp_from_u64(0);
        p->quot_mx[k].domain.log_size = ls;
        p->quot_mx[k].points = &p->quot_pt[k];
        p->quot_mx[k].num_points = 1;
    }
    p->coms[2].commitment = p->quot_c;
    p->coms[2].matrices = p->quot_mx;
    p->coms[2].num_matrices = C_NUM_QC;
}

dnac_fri_status_t dnac_conf_prover_proof_verify(
    const dnac_conf_prover_proof_t *cp) {
    dnac_conf_prover_proof_t *p = (dnac_conf_prover_proof_t *)cp;
    dnac_transcript_t *vt =
        dnac_transcript_init((const uint8_t *)"DNAC|ZK|FRI|TRANSCRIPT|V1", 25);
    if (vt == NULL) return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    build_prime_input(p);
    dnac_stark_priming_out_t out;
    memset(&out, 0, sizeof(out));
    if (dnac_stark_prime_transcript(vt, &p->prime_in, &out) !=
        DNAC_STARK_PRIMING_OK) {
        fprintf(stderr, "conf-prover self-verify: priming FAILED\n");
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    if (!(gold_fp_to_u64(out.zeta.a) == gold_fp_to_u64(p->zeta.a) &&
          gold_fp_to_u64(out.zeta.b) == gold_fp_to_u64(p->zeta.b) &&
          gold_fp_to_u64(out.zeta_next.a) == gold_fp_to_u64(p->zeta_next.a) &&
          gold_fp_to_u64(out.zeta_next.b) == gold_fp_to_u64(p->zeta_next.b))) {
        fprintf(stderr,
                "conf-prover self-verify: zeta MISMATCH (primed %llu,%llu vs "
                "prover %llu,%llu) — transcript-order bug upstream\n",
                (unsigned long long)gold_fp_to_u64(out.zeta.a),
                (unsigned long long)gold_fp_to_u64(out.zeta.b),
                (unsigned long long)gold_fp_to_u64(p->zeta.a),
                (unsigned long long)gold_fp_to_u64(p->zeta.b));
        dnac_transcript_free(vt);
        return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
    }
    build_coms(p, out.zeta, out.zeta_next);
    dnac_fri_status_t fs =
        dnac_fri_verify(&p->params, &p->proof, vt, p->coms, 3);
    dnac_transcript_free(vt);
    if (fs != DNAC_FRI_OK) {
        fprintf(stderr, "conf-prover self-verify: dnac_fri_verify -> %d\n",
                (int)fs);
        return fs;
    }

    /* N-chunk constraint check (verifier.rs:463-498 order: pcs.verify ->
     * recompose -> verify_constraints). Unmerged views: trace = first C_W of
     * the merged open; chunks = first 2 of each merged 6-wide chunk (the
     * nchunk recompose reads only [0..2) per stride). */
    {
        const dnac_stark_verify_status_t vs = dnac_stark_verify_constraints_nchunk(
            &DNAC_CONF_ROOT_FOLD_AIR,
            p->t_open, C_W, p->t_open_n, C_W,
            p->publics, C_NPUB,
            out.zeta, p->degree_bits, C_LOG_NUM_QC, C_IS_ZK,
            out.alpha, p->q_open, C_NUM_QC, C_CW);
        if (vs != DNAC_STARK_VERIFY_OK) {
            fprintf(stderr,
                    "conf-prover self-verify: N-chunk constraint check -> %d\n",
                    (int)vs);
            return DNAC_FRI_ERR_INVALID_PROOF_SHAPE;
        }
    }
    return DNAC_FRI_OK;
}

void dnac_conf_prover_proof_zeta(const dnac_conf_prover_proof_t *p,
                                 gold_fp2_t *zeta, gold_fp2_t *zeta_next) {
    if (zeta) *zeta = p->zeta;
    if (zeta_next) *zeta_next = p->zeta_next;
}

void dnac_conf_prover_proof_roots(const dnac_conf_prover_proof_t *p,
                                  uint8_t trace_root[DNAC_MERKLE_DIGEST_BYTES],
                                  uint8_t quot_root[DNAC_MERKLE_DIGEST_BYTES],
                                  uint8_t rand_root[DNAC_MERKLE_DIGEST_BYTES]) {
    if (trace_root) memcpy(trace_root, p->trace_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (quot_root) memcpy(quot_root, p->quot_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
    if (rand_root) memcpy(rand_root, p->rand_c.bytes, DNAC_MERKLE_DIGEST_BYTES);
}

const gold_fp2_t *dnac_conf_prover_proof_final_poly(
    const dnac_conf_prover_proof_t *p, size_t *out_len) {
    if (out_len) *out_len = p->final_poly_len;
    return p->final_poly;
}

const gold_fp_t *dnac_conf_prover_proof_publics(const dnac_conf_prover_proof_t *p,
                                                size_t *out_n) {
    if (out_n) *out_n = C_NPUB;
    return p->publics;
}

void dnac_conf_prover_proof_free(dnac_conf_prover_proof_t *p) {
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
    free(p->rand_salt);
    free(p->trace_salt);
    free(p->quot_salt);
    free(p->cp_salt);
    free(p->rand_saltp);
    free(p->trace_saltp);
    free(p->quot_saltp);
    free(p);
}

/* ── production entry (G2): fill draws from OS entropy, then prove ── */
dnac_prover_status_t dnac_conf_prover_prove_production(
    const dnac_conf_prover_instance_t *inst,
    dnac_conf_prover_proof_t         **out_proof) {
    if (inst == NULL || out_proof == NULL) return DNAC_PROVER_ERR_PARAM;
    const size_t height = inst->height;
    if (height < 4 || (height & (height - 1)) != 0 ||
        height > STARK_PROVER_MAX_HEIGHT) {
        return DNAC_PROVER_ERR_PARAM; /* validate before sizing the stream */
    }
    const size_t nd = DNAC_CONF_PROVER_TOTAL_DRAWS(height);
    /* M3b (red-team prover fix): production must be GENUINELY SALTED, else the
     * FRI query openings expose the committed trace rows (confidential amounts)
     * and the caller gets a non-hiding proof it cannot detect. Fill BOTH the
     * is_zk codeword stream (nd = 708h) AND the salt stream (ns = 160h) from OS
     * entropy — the salt streams A/B are independent fresh CSPRNG streams (design
     * §3a), so a fresh OS-entropy salt buffer is a valid production salt source. */
    const size_t ns = DNAC_CONF_PROVER_SALT_DRAWS(height);
    uint64_t *draws = (uint64_t *)malloc(nd * sizeof(uint64_t));
    uint64_t *salts = (uint64_t *)malloc(ns * sizeof(uint64_t));
    if (draws == NULL || salts == NULL) { free(draws); free(salts); return DNAC_PROVER_ERR_PARAM; }
    if (dnac_zk_fill_draws(draws, nd) != 0 || dnac_zk_fill_draws(salts, ns) != 0) {
        /* fail-close on entropy error — no partial/non-hiding proof. */
        for (volatile uint64_t *z = draws; z < draws + nd; z++) *z = 0;
        for (volatile uint64_t *z = salts; z < salts + ns; z++) *z = 0;
        free(draws); free(salts);
        return DNAC_PROVER_ERR_PARAM;
    }
    dnac_conf_prover_instance_t local = *inst;
    local.draws = draws;
    local.num_draws = nd;
    local.salt_draws = salts;      /* genuinely salted production proof */
    local.num_salt_draws = ns;
    const dnac_prover_status_t rc = dnac_conf_prover_prove(&local, out_proof);
    /* Zeroize both secret streams before free (client-side hygiene): the
     * codeword blinding AND the leaf salts hide the committed amounts — don't
     * leave them in freed heap. volatile so the compiler cannot elide it. */
    for (volatile uint64_t *z = draws; z < draws + nd; z++) *z = 0;
    for (volatile uint64_t *z = salts; z < salts + ns; z++) *z = 0;
    free(draws); free(salts);
    return rc;
}

/* ── the prove ── */
dnac_prover_status_t dnac_conf_prover_prove(
    const dnac_conf_prover_instance_t *inst,
    dnac_conf_prover_proof_t         **out_proof) {
    if (inst == NULL || out_proof == NULL || inst->outputs == NULL ||
        inst->blind == NULL || inst->draws == NULL) {
        return DNAC_PROVER_ERR_PARAM;
    }
    const size_t height = inst->height;
    /* height >= 4 (fri/prover.rs:79-81 fail-close, P1 red-team); upper bound =
     * the library pipeline cap STARK_PROVER_MAX_HEIGHT (1024) — tighter than
     * the Stage-1 AIR's 2^11 and aligned with the SEC-1 wrap bound's N <= 1024
     * assumption. Stage-1 generator bounds: n_out >= 1, n_out+2 <= height. */
    if (height < 4 || (height & (height - 1)) != 0 ||
        height > STARK_PROVER_MAX_HEIGHT || inst->n_out == 0 ||
        inst->n_out + 2 > height) {
        return DNAC_PROVER_ERR_PARAM;
    }
    if (inst->num_draws != DNAC_CONF_PROVER_TOTAL_DRAWS(height)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    /* M3b: salt_draws optional (NULL=unsalted). If present, must cover stream A
     * (160h). Stream B reuses the same buffer from position 0 (< 2*lde_h < 160h). */
    if (inst->salt_draws != NULL &&
        inst->num_salt_draws < DNAC_CONF_PROVER_SALT_DRAWS(height)) {
        return DNAC_PROVER_ERR_PARAM;
    }
    for (size_t j = 0; j < 4; j++) {
        if (inst->tx_binding[j] >= GOLDILOCKS_P) return DNAC_PROVER_ERR_NONCANONICAL;
    }

    /* ── derive shape (header grounding) ── */
    const size_t base_db = ilog2_pow2(height);
    const size_t degree_bits = base_db + C_IS_ZK;
    const size_t log_max_height = base_db + C_LOG_BLOWUP + C_IS_ZK;
    const size_t lde_h = (size_t)1 << log_max_height;
    const size_t q_size = (size_t)1 << (degree_bits + C_LOG_NUM_QC); /* == lde_h */
    const size_t next_step = (size_t)1 << (C_IS_ZK + C_LOG_NUM_QC);  /* 8 */
    const size_t num_rounds_expected = base_db - 1;

    /* draw slices: trace 622h @0, codeword 32h @622h, blinding 42h @654h,
     * R 12h @696h. */
    const uint64_t *trace_draws = inst->draws;
    const uint64_t *codeword = inst->draws + (size_t)622 * height;
    const uint64_t *blinding = inst->draws + (size_t)654 * height;
    const uint64_t *r_draws = inst->draws + (size_t)696 * height;

    dnac_prover_status_t rc = DNAC_PROVER_ERR_PARAM;
    dnac_conf_prover_proof_t *p =
        (dnac_conf_prover_proof_t *)calloc(1, sizeof(*p));
    if (p == NULL) return DNAC_PROVER_ERR_PARAM;
    p->base_degree_bits = base_db;
    p->degree_bits = degree_bits;
    p->log_max_height = log_max_height;
    p->lde_h = lde_h;
    p->num_queries = C_NUM_QUERIES;

    uint64_t *base_c = NULL, *rand_c = NULL, *lde_c = NULL, *trace_q = NULL,
             *qflat = NULL, *chunk_ldes = NULL, *r_lde = NULL;
    uint64_t *sf = NULL, *sl = NULL, *st = NULL, *iv = NULL;
    gold_fp2_t *ro = NULL;
    uint64_t root_u[CONF_COMMIT_C_LANES];
    dnac_merkle_tree_t *ttree = NULL, *rtree = NULL;
    dnac_merkle_batch_tree_t *qtree = NULL;
    dnac_transcript_t *t = NULL;
    dnac_prover_fri_result_t res;
    memset(&res, 0, sizeof(res));
    int have_res = 0;

    base_c = (uint64_t *)malloc(height * C_W * 8);
    rand_c = (uint64_t *)malloc((2 * height) * C_RAND_W * 8);
    lde_c = (uint64_t *)malloc(lde_h * C_RAND_W * 8);
    trace_q = (uint64_t *)malloc(q_size * C_W * 8);
    qflat = (uint64_t *)malloc(2 * q_size * 8);
    chunk_ldes = (uint64_t *)malloc(C_NUM_QC * lde_h * C_CW * 8);
    r_lde = (uint64_t *)malloc(lde_h * C_CW * 8);
    sf = (uint64_t *)malloc(q_size * 8);
    sl = (uint64_t *)malloc(q_size * 8);
    st = (uint64_t *)malloc(q_size * 8);
    iv = (uint64_t *)malloc(q_size * 8);
    ro = (gold_fp2_t *)malloc(lde_h * sizeof(gold_fp2_t));
    p->t_open = (gold_fp2_t *)malloc(C_RAND_W * sizeof(gold_fp2_t));
    p->t_open_n = (gold_fp2_t *)malloc(C_RAND_W * sizeof(gold_fp2_t));
    if (!base_c || !rand_c || !lde_c || !trace_q || !qflat || !chunk_ldes ||
        !r_lde || !sf || !sl || !st || !iv || !ro || !p->t_open ||
        !p->t_open_n) {
        goto cleanup;
    }

    /* ── S1: Stage-1 combined trace + publics from the built trace ── */
    {
        uint64_t claimed = inst->fee;
        for (size_t i = 0; i < inst->n_out; i++) claimed += inst->outputs[i];
        if (!conf_root_air_generate(inst->outputs, inst->n_out, claimed,
                                    inst->fee, inst->blind,
                                    (unsigned)base_db, base_c, root_u)) {
            rc = DNAC_PROVER_ERR_RANGE;
            goto cleanup;
        }
        /* c_r = VC end_post(3, .) of rows n_out / n_out+1. NOTE
         * conf_commit_air_get_commitment assumes a CONF_COMMIT_WIDTH (250)
         * row stride — the combined trace is CONF_ROOT_WIDTH (614) wide, so
         * read the cells directly at the combined stride. */
        uint64_t c_claimed[CONF_COMMIT_C_LANES], c_fee[CONF_COMMIT_C_LANES];
        for (size_t j = 0; j < CONF_COMMIT_C_LANES; j++) {
            const size_t off = CONF_COMMIT_VC_OFF +
                p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, j);
            c_claimed[j] = base_c[inst->n_out * C_W + off];
            c_fee[j] = base_c[(inst->n_out + 1) * C_W + off];
        }
        for (size_t j = 0; j < 4; j++) {
            p->publics[CONF_ROOT_FOLD_PUB_ROOT_OFF + j] =
                gold_fp_from_u64(root_u[j]);
            p->publics[CONF_ROOT_FOLD_PUB_C_CLAIMED_OFF + j] =
                gold_fp_from_u64(c_claimed[j]);
            p->publics[CONF_ROOT_FOLD_PUB_C_FEE_OFF + j] =
                gold_fp_from_u64(c_fee[j]);
            p->publics[CONF_ROOT_FOLD_PUB_TX_BINDING_OFF + j] =
                gold_fp_from_u64(inst->tx_binding[j]);
        }
        p->publics[CONF_ROOT_FOLD_PUB_HASH_ID_OFF] =
            gold_fp_from_u64(CONF_COMMIT_HASH_ID);
    }
    uint64_t publics_u[C_NPUB];
    for (size_t i = 0; i < C_NPUB; i++)
        publics_u[i] = gold_fp_to_u64(p->publics[i]);

    /* ── S2-S8 (parametric library stages) ── */
    t = dnac_transcript_init_default();
    if (t == NULL) goto cleanup;
    gold_fp2_t alpha, zeta, zeta_next, fri_alpha;
    {
        dnac_prover_status_t s;
        /* M3b salt slices (all into the ONE stream-A salt_draws buffer; the
         * input-mmcs consumes trace→quotient→random contiguously, design §3a).
         * salt_draws==NULL -> unsalted (SE=0). The FRI commit-phase uses stream
         * B = a SEPARATE fresh SmallRng(1) = the SAME buffer FROM POSITION 0. */
        const size_t SE = inst->salt_draws ? (size_t)C_SALT_ELEMS : 0;
        const uint64_t *sd = inst->salt_draws;
        const size_t salt_quot_off = lde_h * SE;                    /* 16h */
        const size_t salt_rand_off = lde_h * SE * (1 + C_NUM_QC);   /* 16h*9 */
        s = dnac_prover_randomize_trace(base_c, height, C_W, C_NUM_RANDOM,
                                        trace_draws, rand_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_coset_lde_bitrev(rand_c, 2 * height, C_RAND_W,
                                         C_LOG_BLOWUP, 7, lde_c);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_commit_matrix(lde_c, lde_h, C_RAND_W,
                                      sd ? &sd[0] : NULL, SE,
                                      p->trace_c.bytes, &ttree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_alpha(t, degree_bits, base_db, 0,
                                    p->trace_c.bytes, publics_u, C_NPUB,
                                    &alpha);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_selectors(
            (unsigned)base_db, (unsigned)(degree_bits + C_LOG_NUM_QC), 7, sf,
            sl, st, iv);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_trace_on_quotient_domain(lde_c, lde_h, C_RAND_W, q_size,
                                                 C_W, trace_q);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = conf_quotient_values(trace_q, q_size, next_step, p->publics, alpha,
                                 sf, sl, st, iv, qflat);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_quotient_commit(qflat, q_size, C_NUM_QC, C_NUM_RANDOM,
                                        C_LOG_BLOWUP, 7, codeword, blinding,
                                        sd ? &sd[salt_quot_off] : NULL, SE,
                                        chunk_ldes, p->quot_c.bytes, &qtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_random_commit(r_draws, 2 * height, C_CW, C_LOG_BLOWUP,
                                      sd ? &sd[salt_rand_off] : NULL, SE,
                                      r_lde, p->rand_c.bytes, &rtree);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
        s = dnac_prover_fs_to_zeta(t, p->quot_c.bytes, p->rand_c.bytes,
                                   base_db, &zeta, &zeta_next);
        if (s != DNAC_PROVER_OK) { rc = s; goto cleanup; }
    }
    p->zeta = zeta;
    p->zeta_next = zeta_next;

    if (getenv("DNAC_CONF_PROVER_DEBUG")) {
        fprintf(stderr, "[conf-dbg] publics:");
        for (size_t i = 0; i < C_NPUB; i++)
            fprintf(stderr, " %llu",
                    (unsigned long long)gold_fp_to_u64(p->publics[i]));
        fprintf(stderr, "\n[conf-dbg] trace_root: ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p->trace_c.bytes[i]);
        fprintf(stderr, "\n[conf-dbg] quot_root : ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p->quot_c.bytes[i]);
        fprintf(stderr, "\n[conf-dbg] rand_root : ");
        for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", p->rand_c.bytes[i]);
        fprintf(stderr, "\n[conf-dbg] alpha=(%llu,%llu) zeta=(%llu,%llu)\n",
                (unsigned long long)gold_fp_to_u64(alpha.a),
                (unsigned long long)gold_fp_to_u64(alpha.b),
                (unsigned long long)gold_fp_to_u64(zeta.a),
                (unsigned long long)gold_fp_to_u64(zeta.b));
    }

    /* ── S9 open ── */
    if (dnac_prover_open_matrix_at(r_lde, lde_h, C_CW, C_LOG_BLOWUP, zeta,
                                   p->r_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, C_RAND_W, C_LOG_BLOWUP, zeta,
                                   p->t_open) != DNAC_PROVER_OK ||
        dnac_prover_open_matrix_at(lde_c, lde_h, C_RAND_W, C_LOG_BLOWUP,
                                   zeta_next, p->t_open_n) != DNAC_PROVER_OK) {
        goto cleanup;
    }
    for (size_t k = 0; k < C_NUM_QC; k++) {
        if (dnac_prover_open_matrix_at(&chunk_ldes[k * lde_h * C_CW], lde_h,
                                       C_CW, C_LOG_BLOWUP, zeta,
                                       &p->q_open[k * C_CW]) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    dnac_prover_observe_opened(t, p->r_open, C_CW);
    dnac_prover_observe_opened(t, p->t_open, C_RAND_W);
    dnac_prover_observe_opened(t, p->t_open_n, C_RAND_W);
    for (size_t k = 0; k < C_NUM_QC; k++)
        dnac_prover_observe_opened(t, &p->q_open[k * C_CW], C_CW);
    fri_alpha = dnac_transcript_sample_fp2(t);

    /* ── S10 reduced openings + commit phase ── */
    {
        const gold_fp2_t zpts[2] = {zeta, zeta_next};
        const gold_fp2_t *r_ov[1] = {p->r_open};
        const gold_fp2_t *t_ov[2] = {p->t_open, p->t_open_n};
        const gold_fp2_t *q_ov[C_NUM_QC][1];
        dnac_prover_fri_input_round_t rounds[2 + C_NUM_QC];
        rounds[0] = (dnac_prover_fri_input_round_t){r_lde, lde_h, C_CW, 1,
                                                    &zeta, r_ov};
        rounds[1] = (dnac_prover_fri_input_round_t){lde_c, lde_h, C_RAND_W, 2,
                                                    zpts, t_ov};
        for (size_t k = 0; k < C_NUM_QC; k++) {
            q_ov[k][0] = &p->q_open[k * C_CW];
            rounds[2 + k] = (dnac_prover_fri_input_round_t){
                &chunk_ldes[k * lde_h * C_CW], lde_h, C_CW, 1, &zeta, q_ov[k]};
        }
        if (dnac_prover_fri_reduced_openings(rounds, 2 + C_NUM_QC,
                                             (unsigned)log_max_height,
                                             fri_alpha, ro) != DNAC_PROVER_OK) {
            goto cleanup;
        }
    }
    if (dnac_prover_fri_commit_phase(ro, lde_h, C_LOG_BLOWUP,
                                     C_LOG_FINAL_POLY_LEN, C_MAX_LOG_ARITY,
                                     inst->salt_draws, /* stream B from pos 0 */
                                     inst->salt_draws ? (size_t)C_SALT_ELEMS : 0,
                                     t, &res) != DNAC_PROVER_OK) {
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
    uint64_t qidx[C_NUM_QUERIES];
    for (size_t q = 0; q < C_NUM_QUERIES; q++) {
        qidx[q] = dnac_transcript_sample_bits(t, (size_t)log_max_height);
        p->query_indices[q] = qidx[q];
    }

    /* ── S12 query openings (mirrors the P1 generalized answer_query) ── */
    {
        const size_t nq = C_NUM_QUERIES, nr = res.num_rounds;
        const size_t in_depth = log_max_height;
        size_t cp_depth_sum = 0;
        for (size_t r = 0; r < nr; r++)
            cp_depth_sum += ilog2_pow2(res.layer_heights[r]);

        p->query_proofs = (dnac_fri_query_proof_t *)calloc(
            nq, sizeof(dnac_fri_query_proof_t));
        p->batches = (dnac_fri_batch_opening_t *)calloc(
            nq * 3, sizeof(dnac_fri_batch_opening_t));
        p->rand_rows = (gold_fp_t *)malloc(nq * C_CW * sizeof(gold_fp_t));
        p->trace_rows = (gold_fp_t *)malloc(nq * C_RAND_W * sizeof(gold_fp_t));
        p->quot_rows =
            (gold_fp_t *)malloc(nq * C_NUM_QC * C_CW * sizeof(gold_fp_t));
        p->rand_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->trace_rowptr = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
        p->quot_rowptr =
            (const gold_fp_t **)malloc(nq * C_NUM_QC * sizeof(gold_fp_t *));
        p->rand_len = (size_t *)malloc(nq * sizeof(size_t));
        p->trace_len = (size_t *)malloc(nq * sizeof(size_t));
        p->quot_len = (size_t *)malloc(nq * C_NUM_QC * sizeof(size_t));
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
        /* M3b salt storage (per-query opening salts, gold_fp_t) + pointer arrays */
        const size_t SE = inst->salt_draws ? (size_t)C_SALT_ELEMS : 0;
        p->salted = inst->salt_draws != NULL;
        p->salt_elems = SE;
        if (SE > 0) {
            p->rand_salt  = (gold_fp_t *)malloc(nq * SE * sizeof(gold_fp_t));
            p->trace_salt = (gold_fp_t *)malloc(nq * SE * sizeof(gold_fp_t));
            p->quot_salt  = (gold_fp_t *)malloc(nq * C_NUM_QC * SE * sizeof(gold_fp_t));
            p->cp_salt    = (gold_fp_t *)malloc(nq * nr * SE * sizeof(gold_fp_t));
            p->rand_saltp  = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
            p->trace_saltp = (const gold_fp_t **)malloc(nq * sizeof(gold_fp_t *));
            p->quot_saltp  = (const gold_fp_t **)malloc(nq * C_NUM_QC * sizeof(gold_fp_t *));
        }
        if (!p->query_proofs || !p->batches || !p->rand_rows ||
            !p->trace_rows || !p->quot_rows || !p->rand_rowptr ||
            !p->trace_rowptr || !p->quot_rowptr || !p->rand_len ||
            !p->trace_len || !p->quot_len || !p->rand_sib || !p->trace_sib ||
            !p->quot_sib || !p->cp_steps || !p->cp_step_sib ||
            !p->cp_step_psib ||
            (SE > 0 && (!p->rand_salt || !p->trace_salt || !p->quot_salt ||
                        !p->cp_salt || !p->rand_saltp || !p->trace_saltp ||
                        !p->quot_saltp))) {
            goto cleanup;
        }

        for (size_t q = 0; q < nq; q++) {
            const uint64_t index = qidx[q];
            dnac_fri_batch_opening_t *B = &p->batches[q * 3];
            dnac_merkle_proof_t pr;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;

            /* batch 0: random */
            for (size_t i = 0; i < C_CW; i++)
                p->rand_rows[q * C_CW + i] =
                    gold_fp_from_u64(r_lde[index * C_CW + i]);
            p->rand_rowptr[q] = &p->rand_rows[q * C_CW];
            p->rand_len[q] = C_CW;
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
            if (SE > 0) {
                /* random salt (stream A random section = draws[lde_h*SE*(1+C_NUM_QC)]) */
                const size_t off = lde_h * SE * (1 + C_NUM_QC) + (size_t)index * SE;
                for (size_t s = 0; s < SE; s++)
                    p->rand_salt[q * SE + s] = gold_fp_from_u64(inst->salt_draws[off + s]);
                p->rand_saltp[q] = &p->rand_salt[q * SE];
                B[0].salts = &p->rand_saltp[q];
                B[0].salt_elems = SE;
            }

            /* batch 1: trace */
            for (size_t i = 0; i < C_RAND_W; i++)
                p->trace_rows[q * C_RAND_W + i] =
                    gold_fp_from_u64(lde_c[index * C_RAND_W + i]);
            p->trace_rowptr[q] = &p->trace_rows[q * C_RAND_W];
            p->trace_len[q] = C_RAND_W;
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
            if (SE > 0) {
                /* trace salt (stream A trace section = draws[2*index]) */
                const size_t off = (size_t)index * SE;
                for (size_t s = 0; s < SE; s++)
                    p->trace_salt[q * SE + s] = gold_fp_from_u64(inst->salt_draws[off + s]);
                p->trace_saltp[q] = &p->trace_salt[q * SE];
                B[1].salts = &p->trace_saltp[q];
                B[1].salt_elems = SE;
            }

            /* batch 2: quotient (num_qc matrices, shared path) */
            for (size_t m = 0; m < C_NUM_QC; m++) {
                for (size_t i = 0; i < C_CW; i++)
                    p->quot_rows[(q * C_NUM_QC + m) * C_CW + i] =
                        gold_fp_from_u64(
                            chunk_ldes[m * lde_h * C_CW + index * C_CW + i]);
                p->quot_rowptr[q * C_NUM_QC + m] =
                    &p->quot_rows[(q * C_NUM_QC + m) * C_CW];
                p->quot_len[q * C_NUM_QC + m] = C_CW;
            }
            {
                const uint8_t *rows[C_NUM_QC];
                memset(&pr, 0, sizeof(pr));
                pr.siblings = &p->quot_sib[q * in_depth];
                pr.depth = (uint32_t)in_depth;
                if (dnac_merkle_batch_open(qtree, index, rows, &pr) !=
                    DNAC_MERKLE_OK) goto cleanup;
            }
            B[2].opened_values = &p->quot_rowptr[q * C_NUM_QC];
            B[2].opened_values_lens = &p->quot_len[q * C_NUM_QC];
            B[2].num_matrices = C_NUM_QC;
            B[2].opening_proof.leaf_index = 0;
            B[2].opening_proof.depth = (uint32_t)in_depth;
            B[2].opening_proof.num_matrices = C_NUM_QC;
            B[2].opening_proof.siblings = &p->quot_sib[q * in_depth];
            if (SE > 0) {
                /* quotient salts (stream A quotient section = draws[lde_h*SE +
                 * m*lde_h*SE + 2*index]) per chunk matrix m. */
                for (size_t m = 0; m < C_NUM_QC; m++) {
                    const size_t off = lde_h * SE + m * lde_h * SE + (size_t)index * SE;
                    gold_fp_t *dst = &p->quot_salt[(q * C_NUM_QC + m) * SE];
                    for (size_t s = 0; s < SE; s++)
                        dst[s] = gold_fp_from_u64(inst->salt_draws[off + s]);
                    p->quot_saltp[q * C_NUM_QC + m] = dst;
                }
                B[2].salts = &p->quot_saltp[q * C_NUM_QC];
                B[2].salt_elems = SE;
            }

            /* commit-phase openings */
            uint64_t cur = index;
            size_t psib_off = q * cp_depth_sum;
            size_t cp_salt_off = 0; /* stream B cumulative offset (layer-major) */
            for (size_t r = 0; r < nr; r++) {
                const unsigned a = res.layer_log_arities[r];
                if (a != 1) goto cleanup; /* arity-2 only; fail-close */
                const size_t arity = (size_t)1 << a;
                const uint64_t iig = cur & (arity - 1);
                const uint64_t gid = cur >> a;
                const size_t depth = ilog2_pow2(res.layer_heights[r]);
                dnac_fri_commit_phase_proof_step_t *S =
                    &p->cp_steps[q * nr + r];
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
                if (SE > 0) {
                    /* stream B: layer r salt for folded row gid at
                     * draws[cp_salt_off + gid*SE] (design §3a). */
                    const size_t off = cp_salt_off + (size_t)gid * SE;
                    gold_fp_t *dst = &p->cp_salt[(q * nr + r) * SE];
                    for (size_t s = 0; s < SE; s++)
                        dst[s] = gold_fp_from_u64(inst->salt_draws[off + s]);
                    S->salts = dst;
                    S->salt_elems = SE;
                }
                cp_salt_off += res.layer_heights[r] * SE;
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

    /* ── assemble ── */
    memset(&p->proof, 0, sizeof(p->proof));
    p->proof.commit_phase_commits = p->cp_commits;
    p->proof.num_commit_phase_commits = res.num_rounds;
    p->proof.commit_pow_witnesses = p->cp_pow;
    p->proof.num_commit_pow_witnesses = res.num_rounds;
    p->proof.query_proofs = p->query_proofs;
    p->proof.num_query_proofs = C_NUM_QUERIES;
    p->proof.final_poly = p->final_poly;
    p->proof.num_final_poly = res.final_poly_len;
    p->proof.query_pow_witness = gold_fp_from_u64(0);

    memset(&p->params, 0, sizeof(p->params));
    p->params.log_blowup = C_LOG_BLOWUP;
    p->params.log_final_poly_len = C_LOG_FINAL_POLY_LEN;
    p->params.max_log_arity = C_MAX_LOG_ARITY;
    p->params.num_queries = C_NUM_QUERIES;
    p->params.commit_proof_of_work_bits = 0;
    p->params.query_proof_of_work_bits = 0;

    dnac_prover_fri_result_free(&res);
    have_res = 0;
    dnac_merkle_tree_free(ttree); ttree = NULL;
    dnac_merkle_tree_free(rtree); rtree = NULL;
    dnac_merkle_batch_tree_free(qtree); qtree = NULL;

    /* ── self-verify (fail-close: FRI + N-chunk constraint check) ── */
    if (dnac_conf_prover_proof_verify(p) != DNAC_FRI_OK) {
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
    if (p) dnac_conf_prover_proof_free(p);
    return rc;
}
