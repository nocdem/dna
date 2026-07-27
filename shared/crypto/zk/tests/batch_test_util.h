/**
 * @file batch_test_util.h
 * @brief Shared batch-STARK test fixtures + serde-JSON decoding — extracted
 *        VERBATIM from test_batch_verify.c (P2L-d d2) so the d3 prover KAT
 *        (test_batch_prover.c) reuses the SAME AIR fixtures, proof_serde
 *        parser and rand-openings builder (no drift between the two tests).
 *
 * d4.d (2026-07-26) — CONSOLIDATION COMPLETE: test_batch_verify.c no longer
 * keeps its own copies; it includes this header. The two copies were diffed
 * line-by-line before the merge and were identical apart from the `inline`
 * qualifier (no behavioural divergence). Every function here is `static
 * inline` precisely so a consumer that uses only part of the fixture set (e.g.
 * test_batch_verify.c, which drives its own verifier-side loader and never
 * calls the prover-side load_pscenario) compiles warning-free under
 * -Wall -Wextra.
 *
 * Requires the including test to have "../batch_verify.h" +
 * "logup_test_util.h" available (both included below). All definitions have
 * internal linkage — each test gets its own copies.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_BATCH_TEST_UTIL_H
#define DNAC_BATCH_TEST_UTIL_H

#include <stdio.h>
#include <string.h>

#include "../batch_prover.h"
#include "../batch_verify.h"
#include "logup_test_util.h"

/* Parse/load failure with the line number — every fixture-builder bail-out
 * reports where it tripped (silent load failures cost debugging time). */
#define RF()                                                                  \
    do {                                                                      \
        fprintf(stderr, "  [fixture fail @ line %d]\n", __LINE__);            \
        return false;                                                         \
    } while (0)

/* ============================================================================
 * serde-JSON decoding ({"value":N} base / {"value":[{..},{..}]} fp2 /
 * {"cap":[[4 lanes]]} commitments)
 * ========================================================================== */
static inline bool sv_u64(const jv_t *v, uint64_t *out)
{
    if (!v) RF();
    if (v->kind == JV_OBJ) return jv_u64(jv_get(v, "value"), out);
    return jv_u64(v, out); /* raw JSON number */
}

static inline bool sv_fp(const jv_t *v, gold_fp_t *out)
{
    uint64_t u;
    if (!sv_u64(v, &u)) RF();
    *out = gold_fp_from_u64(u);
    return true;
}

static inline bool sv_fp2(const jv_t *v, gold_fp2_t *out)
{
    if (!v || v->kind != JV_OBJ) RF();
    const jv_t *arr = jv_get(v, "value");
    if (!arr || arr->kind != JV_ARR || arr->n != 2) RF();
    gold_fp_t a, b;
    if (!sv_fp(arr->items[0], &a) || !sv_fp(arr->items[1], &b)) RF();
    *out = gold_fp2_new(a, b);
    return true;
}

/* 64-hex-char commitment (fri_milestone_serialize_commitment: 4 lanes,
 * 8 LE bytes each) → gold_fp_t[4]. */
static inline bool hex_commit(const jv_t *v, gold_fp_t lanes[4])
{
    if (!v || v->kind != JV_STR || strlen(v->str) != 64) RF();
    for (size_t k = 0; k < 4; k++) {
        uint64_t u = 0;
        for (size_t b = 0; b < 8; b++) {
            unsigned hi, lo;
            char c1 = v->str[(k * 8 + b) * 2], c2 = v->str[(k * 8 + b) * 2 + 1];
            if (c1 >= '0' && c1 <= '9') hi = (unsigned)(c1 - '0');
            else if (c1 >= 'a' && c1 <= 'f') hi = (unsigned)(c1 - 'a' + 10);
            else RF();
            if (c2 >= '0' && c2 <= '9') lo = (unsigned)(c2 - '0');
            else if (c2 >= 'a' && c2 <= 'f') lo = (unsigned)(c2 - 'a' + 10);
            else RF();
            u |= ((uint64_t)(hi * 16 + lo)) << (8 * b); /* LE */
        }
        lanes[k] = gold_fp_from_u64(u);
    }
    return true;
}

/* friendly fp2 list ({"c0_decimal","c1_decimal"}) → array; JV_NULL → len 0. */
static inline bool fp2_list(const jv_t *v, gold_fp2_t *out, uint32_t cap,
                     uint32_t *len)
{
    *len = 0;
    if (!v || v->kind == JV_NULL) return true;
    if (v->kind != JV_ARR || v->n > cap) RF();
    for (size_t i = 0; i < v->n; i++) {
        if (!jv_fp2(v->items[i], &out[i])) RF();
    }
    *len = (uint32_t)v->n;
    return true;
}

/* ============================================================================
 * FRI proof construction from proof_serde.opening_proof
 * ========================================================================== */
#define MAX_CPC     8
#define MAX_QUERIES 4
#define MAX_BATCHES 6
#define MAX_MATS    24
#define MAX_COLS    16
#define MAX_SIBS    12
#define MAX_FP      8

typedef struct {
    dnac_p2_digest_t cpc[MAX_CPC];
    gold_fp_t        cpw[MAX_CPC];
    gold_fp2_t       final_poly[MAX_FP];
    gold_fp_t        qpw;
    dnac_fri_query_proof_t qps[MAX_QUERIES];
    /* per query per batch storage */
    dnac_fri_batch_opening_t bos[MAX_QUERIES][MAX_BATCHES];
    gold_fp_t        ov[MAX_QUERIES][MAX_BATCHES][MAX_MATS][MAX_COLS];
    const gold_fp_t *ovp[MAX_QUERIES][MAX_BATCHES][MAX_MATS];
    size_t           ovl[MAX_QUERIES][MAX_BATCHES][MAX_MATS];
    dnac_p2_digest_t ip_sibs[MAX_QUERIES][MAX_BATCHES][MAX_SIBS];
    dnac_fri_commit_phase_proof_step_t cpo[MAX_QUERIES][MAX_CPC];
    gold_fp2_t       cpo_sib_vals[MAX_QUERIES][MAX_CPC][4];
    dnac_p2_digest_t cpo_sibs[MAX_QUERIES][MAX_CPC][MAX_SIBS];
    dnac_fri_proof_t proof;
} fri_fixture_t;

static inline bool parse_digest_list(const jv_t *arr, dnac_p2_digest_t *out,
                                     size_t cap, size_t *n)
{
    *n = 0;
    if (!arr || arr->kind != JV_ARR || arr->n > cap) RF();
    for (size_t i = 0; i < arr->n; i++) {
        const jv_t *d = arr->items[i];
        if (!d || d->kind != JV_ARR || d->n != 4) RF();
        for (size_t k = 0; k < 4; k++) {
            if (!jv_u64(jv_get(d->items[k], "value") ? jv_get(d->items[k], "value")
                                                     : d->items[k],
                        &out[i].lanes[k])) {
                RF();
            }
        }
    }
    *n = arr->n;
    return true;
}

static inline bool build_fri_proof(const jv_t *op, fri_fixture_t *fx)
{
    memset(&fx->proof, 0, sizeof(fx->proof));

    const jv_t *cpc = jv_get(op, "commit_phase_commits");
    if (!cpc || cpc->kind != JV_ARR || cpc->n > MAX_CPC) RF();
    for (size_t i = 0; i < cpc->n; i++) {
        const jv_t *cap = jv_get(cpc->items[i], "cap");
        if (!cap || cap->kind != JV_ARR || cap->n != 1) RF();
        const jv_t *d = cap->items[0];
        if (!d || d->kind != JV_ARR || d->n != 4) RF();
        for (size_t k = 0; k < 4; k++) {
            if (!sv_u64(d->items[k], &fx->cpc[i].lanes[k])) RF();
        }
    }
    fx->proof.commit_phase_commits = fx->cpc;
    fx->proof.num_commit_phase_commits = cpc->n;

    const jv_t *cpw = jv_get(op, "commit_pow_witnesses");
    if (!cpw || cpw->kind != JV_ARR || cpw->n > MAX_CPC) RF();
    for (size_t i = 0; i < cpw->n; i++) {
        if (!sv_fp(cpw->items[i], &fx->cpw[i])) RF();
    }
    fx->proof.commit_pow_witnesses = fx->cpw;
    fx->proof.num_commit_pow_witnesses = cpw->n;

    const jv_t *fp = jv_get(op, "final_poly");
    if (!fp || fp->kind != JV_ARR || fp->n > MAX_FP) RF();
    for (size_t i = 0; i < fp->n; i++) {
        if (!sv_fp2(fp->items[i], &fx->final_poly[i])) RF();
    }
    fx->proof.final_poly = fx->final_poly;
    fx->proof.num_final_poly = fp->n;

    if (!sv_fp(jv_get(op, "query_pow_witness"), &fx->qpw)) RF();
    fx->proof.query_pow_witness = fx->qpw;

    const jv_t *qps = jv_get(op, "query_proofs");
    if (!qps || qps->kind != JV_ARR || qps->n > MAX_QUERIES) RF();
    for (size_t q = 0; q < qps->n; q++) {
        const jv_t *jq = qps->items[q];
        const jv_t *ip = jv_get(jq, "input_proof");
        if (!ip || ip->kind != JV_ARR || ip->n > MAX_BATCHES) RF();
        for (size_t b = 0; b < ip->n; b++) {
            const jv_t *jb = ip->items[b];
            const jv_t *ovs = jv_get(jb, "opened_values");
            if (!ovs || ovs->kind != JV_ARR || ovs->n > MAX_MATS) RF();
            for (size_t m = 0; m < ovs->n; m++) {
                const jv_t *row = ovs->items[m];
                if (!row || row->kind != JV_ARR || row->n > MAX_COLS) {
                    RF();
                }
                for (size_t c = 0; c < row->n; c++) {
                    if (!sv_fp(row->items[c], &fx->ov[q][b][m][c])) {
                        RF();
                    }
                }
                fx->ovp[q][b][m] = fx->ov[q][b][m];
                fx->ovl[q][b][m] = row->n;
            }
            size_t nsib;
            if (!parse_digest_list(jv_get(jb, "opening_proof"),
                                   fx->ip_sibs[q][b], MAX_SIBS, &nsib)) {
                RF();
            }
            dnac_fri_batch_opening_t *bo = &fx->bos[q][b];
            memset(bo, 0, sizeof(*bo));
            bo->opened_values = fx->ovp[q][b];
            bo->opened_values_lens = fx->ovl[q][b];
            bo->num_matrices = ovs->n;
            bo->opening_proof.siblings = fx->ip_sibs[q][b];
            bo->opening_proof.depth = (uint32_t)nsib;
            bo->salts = NULL;
            bo->salt_elems = 0;
        }
        const jv_t *cpo = jv_get(jq, "commit_phase_openings");
        if (!cpo || cpo->kind != JV_ARR || cpo->n > MAX_CPC) RF();
        for (size_t r = 0; r < cpo->n; r++) {
            const jv_t *js = cpo->items[r];
            uint64_t la;
            if (!jv_u64(jv_get(js, "log_arity"), &la)) RF();
            const jv_t *sv = jv_get(js, "sibling_values");
            if (!sv || sv->kind != JV_ARR || sv->n > 4) RF();
            for (size_t s = 0; s < sv->n; s++) {
                if (!sv_fp2(sv->items[s], &fx->cpo_sib_vals[q][r][s])) {
                    RF();
                }
            }
            size_t nsib;
            if (!parse_digest_list(jv_get(js, "opening_proof"),
                                   fx->cpo_sibs[q][r], MAX_SIBS, &nsib)) {
                RF();
            }
            dnac_fri_commit_phase_proof_step_t *st = &fx->cpo[q][r];
            memset(st, 0, sizeof(*st));
            st->log_arity = (uint8_t)la;
            st->sibling_values = fx->cpo_sib_vals[q][r];
            st->num_sibling_values = sv->n;
            st->opening_proof.siblings = fx->cpo_sibs[q][r];
            st->opening_proof.depth = (uint32_t)nsib;
            st->salts = NULL;
            st->salt_elems = 0;
        }
        fx->qps[q].input_proof = fx->bos[q];
        fx->qps[q].num_input_batches = ip->n;
        fx->qps[q].commit_phase_openings = fx->cpo[q];
        fx->qps[q].num_commit_phase_openings = cpo->n;
    }
    fx->proof.query_proofs = fx->qps;
    fx->proof.num_query_proofs = qps->n;
    return true;
}

/* rand-codeword openings ([round][mat][point] → flat entry list). */
#define MAX_RAND_ENTRIES 64
typedef struct {
    gold_fp2_t        store[MAX_RAND_ENTRIES][8];
    const gold_fp2_t *vals[MAX_RAND_ENTRIES];
    uint32_t          lens[MAX_RAND_ENTRIES];
    dnac_batch_rand_openings_t ro;
    /* S2'-d: dnac_batch_verify now REQUIRES the caller to state the hiding tail
     * length. A KAT fixture has no protocol constant to state — it replays
     * whatever the oracle emitted — so it derives the count as the MAX over the
     * loaded entries. That is exactly right here and NOT a pin: preprocessed
     * points carry 0 and every other point carries the same nrc, so the max IS
     * nrc; and if a vector ever disagreed with itself, the verify rejects,
     * which is the outcome a KAT should have. The real pin is the consensus
     * constant DNAC_SHIELDED_NUM_RANDOM, stated at the shielded entry. */
    uint32_t          nrc_derived;
} rand_fixture_t;

static inline bool build_rand_openings(const jv_t *rv, rand_fixture_t *rf)
{
    uint32_t k = 0;
    if (!rv || rv->kind != JV_ARR) RF();
    for (size_t r = 0; r < rv->n; r++) {
        const jv_t *round = rv->items[r];
        if (!round || round->kind != JV_ARR) RF();
        for (size_t m = 0; m < round->n; m++) {
            const jv_t *mat = round->items[m];
            if (!mat || mat->kind != JV_ARR) RF();
            for (size_t p = 0; p < mat->n; p++) {
                const jv_t *pt = mat->items[p];
                if (!pt || pt->kind != JV_ARR || pt->n > 8 ||
                    k >= MAX_RAND_ENTRIES) {
                    RF();
                }
                for (size_t e = 0; e < pt->n; e++) {
                    if (!sv_fp2(pt->items[e], &rf->store[k][e])) RF();
                }
                rf->vals[k] = rf->store[k];
                rf->lens[k] = (uint32_t)pt->n;
                k++;
            }
        }
    }
    rf->ro.vals = rf->vals;
    rf->ro.lens = rf->lens;
    rf->ro.num_entries = k;
    rf->nrc_derived = 0;
    for (uint32_t e = 0; e < k; e++) {
        if (rf->lens[e] > rf->nrc_derived) rf->nrc_derived = rf->lens[e];
    }
    return true;
}

/* ============================================================================
 * AIR fixtures
 * ========================================================================== */

/* FibonacciAir — fib_air.rs:44-72, EXACT emission order (5 constraints). */
static inline void fib_air_eval(dnac_stark_folder_t *f)
{
    const gold_fp2_t *l = f->trace_local;
    const gold_fp2_t *n = f->trace_next;
    const gold_fp2_t a = gold_fp2_from_base(f->public_values[0]);
    const gold_fp2_t b = gold_fp2_from_base(f->public_values[1]);
    const gold_fp2_t x = gold_fp2_from_base(f->public_values[2]);
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[0], a));
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[1], b));
    dnac_stark_folder_when(f, f->is_transition, gold_fp2_sub(l[1], n[0]));
    dnac_stark_folder_when(f, f->is_transition,
                           gold_fp2_sub(gold_fp2_add(l[0], l[1]), n[1]));
    dnac_stark_folder_when(f, f->is_last_row, gold_fp2_sub(l[1], x));
}

/* LogupAddAir — tests.rs:1100-1169: interactions ONLY, no base constraints
 * (push_interaction is a no-op on the verifier folder, folder.rs:226-244). */
static inline void add_air_eval(dnac_stark_folder_t *f) { (void)f; }

/* PrepEqAir — P2L-c fixture: v − t = 0 over (main[0], preprocessed[0]). */
static inline void prepeq_air_eval(dnac_stark_folder_t *f)
{
    dnac_stark_folder_assert_zero(
        f, gold_fp2_sub(f->trace_local[0], f->preprocessed_local[0]));
}

/* AddAir lookup declaration (mirrors the REAL Lookups::from_air output,
 * pinned in the P2L-a/b vectors: local at column 0, global "LUT" at column
 * 1; global tuple = the table triple, count = −1 send / +1 receive,
 * weight 1). Expression pool over the 7-wide window:
 *   [0..6] = main cols 0..6, [7] = const 1, [8] = −main[6], [9] = −1. */
static const dnac_logup_expr_t ADD_POOL[10] = {
    { DNAC_LOGUP_EXPR_MAIN, 0, 0, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 1, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 2, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 3, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 4, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 5, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_MAIN, 0, 6, {0}, -1, -1 },
    { DNAC_LOGUP_EXPR_CONST, 0, 0, {1}, -1, -1 },
    { DNAC_LOGUP_EXPR_NEG, 0, 0, {0}, 6, -1 },
    { DNAC_LOGUP_EXPR_NEG, 0, 0, {0}, 7, -1 },
};
static const uint32_t ADD_LOCAL_WIDTHS[2] = { 3, 3 };
static const int32_t  ADD_LOCAL_T0[3] = { 0, 1, 2 };
static const int32_t  ADD_LOCAL_T1[3] = { 3, 4, 5 };
static const int32_t *ADD_LOCAL_ELEMS[2] = { ADD_LOCAL_T0, ADD_LOCAL_T1 };
static const int32_t  ADD_LOCAL_MULTS[2] = { 7, 8 }; /* +1, −mult */
static const uint32_t ADD_GLOB_WIDTH[1] = { 3 };
static const int32_t *ADD_GLOB_ELEMS[1] = { ADD_LOCAL_T1 };
static const int32_t  ADD_GLOB_MULT_SEND[1] = { 9 }; /* −1 (send)    */
static const int32_t  ADD_GLOB_MULT_RECV[1] = { 7 }; /* +1 (receive) */

static const char *const ADD_BUS_NAMES[1] = { "LUT" };
static const uint32_t ADD_BUS_WEIGHTS[1] = { 1 };

static inline void make_add_lookups(dnac_logup_lookup_t lks[2], int is_send)
{
    memset(lks, 0, 2 * sizeof(*lks));
    lks[0].is_global = 0;
    lks[0].column = 0;
    lks[0].num_tuples = 2;
    lks[0].tuple_widths = ADD_LOCAL_WIDTHS;
    lks[0].tuple_elems = ADD_LOCAL_ELEMS;
    lks[0].multiplicities = ADD_LOCAL_MULTS;
    lks[1].is_global = 1;
    lks[1].column = 1;
    lks[1].num_tuples = 1;
    lks[1].tuple_widths = ADD_GLOB_WIDTH;
    lks[1].tuple_elems = ADD_GLOB_ELEMS;
    lks[1].multiplicities = is_send ? ADD_GLOB_MULT_SEND : ADD_GLOB_MULT_RECV;
}

/* ============================================================================
 * Witness builders + prover-side scenario loader (moved VERBATIM from
 * test_batch_prover.c at d4.b so the wire KAT (test_batch_wire.c) reuses the
 * SAME instance-geometry/witness fixtures — the logup_test_util extraction
 * precedent; test_batch_verify.c keeps its local copies until the d4.d
 * consolidation).
 * ========================================================================== */

/* fib_air.rs:74-92: row r = (left, right); (a,b) start, next = (r, l+r). */
static inline void fib_trace(uint64_t a, uint64_t b, size_t n, uint64_t *out)
{
    out[0] = a;
    out[1] = b;
    for (size_t i = 1; i < n; i++) {
        out[2 * i] = out[2 * i - 1];
        out[2 * i + 1] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(out[2 * i - 2]),
                        gold_fp_from_u64(out[2 * i - 1])));
    }
}

/* The P2L LUT fixtures (oracle dump_batch_proof sender/receiver tables). */
static const uint64_t SENDER_ROWS[4][7] = {
    { 0, 1, 1, 0, 1, 1, 2 },
    { 0, 1, 1, 0, 0, 0, 1 },
    { 1, 1, 2, 1, 0, 1, 0 },
    { 0, 0, 0, 1, 1, 2, 1 },
};
static const uint64_t RECEIVER_ROWS[4][7] = {
    { 0, 1, 1, 0, 0, 0, 1 },
    { 0, 1, 1, 0, 1, 1, 2 },
    { 1, 1, 2, 1, 1, 2, 1 },
    { 0, 0, 0, 1, 0, 1, 0 },
};

/* PrepEqAir ramp: v = t = 7 + 3i (both main and preprocessed). */
static inline void ramp_trace(size_t n, uint64_t *out)
{
    for (size_t i = 0; i < n; i++) out[i] = 7 + 3 * (uint64_t)i;
}

#define MAX_INST 4
#define MAX_TRACE_CELLS 256
#define MAX_DRAWS 2048

typedef struct {
    dnac_batch_vinstance_t insts[MAX_INST];
    dnac_batch_pwitness_t  wits[MAX_INST];
    dnac_logup_lookup_t    lks[MAX_INST][2];
    gold_fp_t              pubs[MAX_INST][4];
    uint64_t               main_store[MAX_INST][MAX_TRACE_CELLS];
    uint64_t               prep_store[MAX_INST][MAX_TRACE_CELLS];
    uint64_t               draws[MAX_DRAWS];
    size_t                 num_draws;
    uint32_t               n;
    int                    is_zk;
    uint32_t               nrc;
    dnac_fri_params_t      params;
} pscenario_t;

static inline bool load_pscenario(const jv_t *js, pscenario_t *sc)
{
    memset(sc, 0, sizeof(*sc));
    const jv_t *name = jv_get(js, "name");
    if (!name || name->kind != JV_STR) RF();
    uint64_t u;
    if (!sv_u64(jv_get(js, "is_zk"), &u)) RF();
    sc->is_zk = (int)u;
    if (!sv_u64(jv_get(js, "num_instances"), &u) || u == 0 || u > MAX_INST) {
        RF();
    }
    sc->n = (uint32_t)u;

    const jv_t *fpj = jv_get(js, "fri_params");
    if (!sv_u64(jv_get(fpj, "log_blowup"), &u)) RF();
    sc->params.log_blowup = u;
    if (!sv_u64(jv_get(fpj, "log_final_poly_len"), &u)) RF();
    sc->params.log_final_poly_len = u;
    if (!sv_u64(jv_get(fpj, "max_log_arity"), &u)) RF();
    sc->params.max_log_arity = u;
    if (!sv_u64(jv_get(fpj, "num_queries"), &u)) RF();
    sc->params.num_queries = u;
    if (!sv_u64(jv_get(fpj, "commit_proof_of_work_bits"), &u)) RF();
    sc->params.commit_proof_of_work_bits = u;
    if (!sv_u64(jv_get(fpj, "query_proof_of_work_bits"), &u)) RF();
    sc->params.query_proof_of_work_bits = u;
    if (sc->is_zk) {
        const jv_t *nr = jv_get(fpj, "num_random_codewords");
        if (!sv_u64(nr, &u)) RF();
        sc->nrc = (uint32_t)u;
    }

    const jv_t *insts = jv_get(js, "instances");
    if (!insts || insts->kind != JV_ARR || insts->n != sc->n) RF();
    for (uint32_t i = 0; i < sc->n; i++) {
        const jv_t *ji = insts->items[i];
        dnac_batch_vinstance_t *di = &sc->insts[i];
        uint64_t width, deg, nqcv, prew;
        if (!sv_u64(jv_get(ji, "width"), &width) ||
            !sv_u64(jv_get(ji, "log_ext_degree"), &deg) ||
            !sv_u64(jv_get(ji, "num_quotient_chunks"), &nqcv) ||
            !sv_u64(jv_get(ji, "preprocessed_width"), &prew)) {
            RF();
        }
        const jv_t *pn = jv_get(ji, "prep_next_used");
        di->degree_bits = (uint32_t)deg;
        di->preprocessed_width = (uint32_t)prew;
        di->prep_next = (pn && pn->kind == JV_BOOL && pn->bval) ? 1 : 0;
        uint32_t lq = 0;
        while ((1u << (lq + (uint32_t)sc->is_zk)) < nqcv) lq++;
        if ((1u << (lq + (uint32_t)sc->is_zk)) != nqcv) RF();
        di->log_num_qc = lq;

        const size_t base_h =
            (size_t)1 << (di->degree_bits - (uint32_t)sc->is_zk);
        if (base_h * width > MAX_TRACE_CELLS ||
            base_h * prew > MAX_TRACE_CELLS) {
            RF();
        }

        /* AIR selection + witness build, by scenario name (the oracle's
         * fixture choices). */
        if (!strncmp(name->str, "fib", 3)) {
            if (width != 2) RF();
            di->air.main_width = 2;
            di->air.num_public_values = 3;
            di->air.main_next = 1;
            di->air.air_eval = fib_air_eval;
            fib_trace(0, 1, base_h, sc->main_store[i]);
            sc->pubs[i][0] = gold_fp_from_u64(0);
            sc->pubs[i][1] = gold_fp_from_u64(1);
            sc->pubs[i][2] =
                gold_fp_from_u64(sc->main_store[i][2 * base_h - 1]);
            di->public_values = sc->pubs[i];
            di->num_publics = 3;
        } else if (!strncmp(name->str, "lut", 3)) {
            if (width != 7 || (base_h != 4 && base_h != 8)) RF();
            di->air.main_width = 7;
            di->air.num_public_values = 0;
            di->air.main_next = 1; /* all-columns default (air.rs:122-124) */
            di->air.air_eval = add_air_eval;
            make_add_lookups(sc->lks[i], i == 0 /* instance 0 = sender */);
            di->pool = ADD_POOL;
            di->pool_len = 10;
            di->lookups = sc->lks[i];
            di->num_lookups = 2;
            di->view.num_locals = 1;
            di->view.num_globals = 1;
            di->view.global_bus_names = ADD_BUS_NAMES;
            di->view.global_count_weights = ADD_BUS_WEIGHTS;
            /* sender h=8 = the 4-row block twice; h=4 = one block. */
            const uint64_t(*rows)[7] = i == 0 ? SENDER_ROWS : RECEIVER_ROWS;
            for (size_t r = 0; r < base_h; r++) {
                memcpy(&sc->main_store[i][r * 7], rows[r % 4],
                       7 * sizeof(uint64_t));
            }
            di->public_values = sc->pubs[i];
            di->num_publics = 0;
        } else if (!strncmp(name->str, "prep", 4)) {
            if (width != 1 || prew != 1) RF();
            di->air.main_width = 1;
            di->air.num_public_values = 0;
            di->air.main_next = 1; /* all-columns default */
            di->air.air_eval = prepeq_air_eval;
            ramp_trace(base_h, sc->main_store[i]);
            ramp_trace(base_h, sc->prep_store[i]);
            di->public_values = sc->pubs[i];
            di->num_publics = 0;
        } else {
            RF();
        }
        sc->wits[i].main_trace = sc->main_store[i];
        sc->wits[i].prep_trace = prew ? sc->prep_store[i] : NULL;

        /* publics cross-check vs the vector. */
        const jv_t *pv = jv_get(ji, "public_values");
        if (!pv || pv->kind != JV_ARR || pv->n != di->num_publics) RF();
        for (size_t p2 = 0; p2 < pv->n; p2++) {
            uint64_t x;
            if (!jv_u64(pv->items[p2], &x)) RF();
            if (x != gold_fp_to_u64(di->public_values[p2])) RF();
        }
    }

    /* zk draw stream (zk_rng.draws — the oracle's SmallRng(1) dump). */
    if (sc->is_zk) {
        const jv_t *zr = jv_get(js, "zk_rng");
        if (!zr) RF();
        uint64_t total;
        if (!sv_u64(jv_get(zr, "total_draws"), &total) || total > MAX_DRAWS) {
            RF();
        }
        const jv_t *dr = jv_get(zr, "draws");
        if (!dr || dr->kind != JV_ARR || dr->n != total) RF();
        for (size_t k = 0; k < dr->n; k++) {
            if (!jv_u64(dr->items[k], &sc->draws[k])) RF();
        }
        sc->num_draws = total;
    }
    return true;
}

#endif /* DNAC_BATCH_TEST_UTIL_H */
