/**
 * @file fri_proof_codec.c
 * @brief Deterministic FRI proof wire codec — implementation.
 *
 * Source of truth: docs/plans/2026-05-29-fri-proof-wire-codec-design.md,
 * fri_verifier.h, Plonky3 82cfad73 (fri/src/proof.rs field/struct order).
 *
 * Safety (design § M2):
 *   - every integer is byte-assembled little-endian (NO unaligned native casts;
 *     required for Windows/Android targets);
 *   - every read is bounds-checked against the remaining buffer BEFORE the read;
 *   - every length-prefixed vector checks count <= MAX and
 *     (u64)count*elem_size <= remaining BEFORE allocating;
 *   - Goldilocks limbs >= p are rejected (canonical-only);
 *   - decode registers every allocation immediately so any mid-decode error
 *     frees everything (no partial leak);
 *   - count == 0 is valid (NULL / zero-length), left for the verifier to judge.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_proof_codec.h"

#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h" /* GOLDILOCKS_P, gold_fp_to_u64/from_u64, gold_fp2_new */
#include "shielded_fri_params.h" /* pinned consensus FRI params (S0/C5) */

/* ============================================================================
 * Decoded package — owns all allocations via a registry.
 * ========================================================================== */
struct dnac_fri_wire_package_s {
    void   **allocs;
    size_t   n_allocs;
    size_t   cap_allocs;
    dnac_fri_params_t                          params;       /* embedded */
    dnac_fri_proof_t                           proof;        /* embedded */
    dnac_fri_commitment_with_opening_points_t *commitments;  /* registered */
    size_t                                     num_commitments;
};

/* Allocate (zeroed) and register; returns NULL for size==0 (a valid empty
 * vector) AND for OOM — callers distinguish via the dctx error field. */
static void *pkg_alloc(dnac_fri_wire_package_t *pkg, size_t size) {
    if (size == 0) return NULL;
    void *p = calloc(1, size);
    if (!p) return NULL;
    if (pkg->n_allocs == pkg->cap_allocs) {
        /* Registry-growth overflow guard (symmetry with wb_ensure). Unreachable
         * in practice — n_allocs <= len/4 <= 16M — but kept for defense. */
        if (pkg->cap_allocs > ((size_t)-1) / 2 ||
            (pkg->cap_allocs ? pkg->cap_allocs * 2 : 32) > ((size_t)-1) / sizeof(void *)) {
            free(p);
            return NULL;
        }
        size_t ncap = pkg->cap_allocs ? pkg->cap_allocs * 2 : 32;
        void **na = (void **)realloc(pkg->allocs, ncap * sizeof(void *));
        if (!na) { free(p); return NULL; }
        pkg->allocs = na;
        pkg->cap_allocs = ncap;
    }
    pkg->allocs[pkg->n_allocs++] = p;
    return p;
}

void dnac_fri_wire_free(dnac_fri_wire_package_t *pkg) {
    if (!pkg) return;
    for (size_t i = 0; i < pkg->n_allocs; ++i) free(pkg->allocs[i]);
    free(pkg->allocs);
    free(pkg);
}

/* ============================================================================
 * Writer (encode).
 * ========================================================================== */
typedef struct { uint8_t *buf; size_t len; size_t cap; int oom; } wbuf_t;

static void wb_ensure(wbuf_t *w, size_t n) {
    if (w->oom) return;
    if (w->len + n < w->len) { w->oom = 1; return; } /* size_t overflow guard */
    if (w->len + n > w->cap) {
        size_t ncap = w->cap ? w->cap : 256;
        while (ncap < w->len + n) {
            if (ncap > (size_t)-1 / 2) { w->oom = 1; return; }
            ncap *= 2;
        }
        uint8_t *nb = (uint8_t *)realloc(w->buf, ncap);
        if (!nb) { w->oom = 1; return; }
        w->buf = nb;
        w->cap = ncap;
    }
}
static void wb_bytes(wbuf_t *w, const uint8_t *p, size_t n) {
    wb_ensure(w, n);
    if (w->oom) return;
    memcpy(w->buf + w->len, p, n);
    w->len += n;
}
static void wb_u16(wbuf_t *w, uint16_t v) {
    uint8_t b[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    wb_bytes(w, b, 2);
}
static void wb_u32(wbuf_t *w, uint32_t v) {
    uint8_t b[4];
    for (int i = 0; i < 4; ++i) b[i] = (uint8_t)(v >> (8 * i));
    wb_bytes(w, b, 4);
}
static void wb_u64(wbuf_t *w, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; ++i) b[i] = (uint8_t)(v >> (8 * i));
    wb_bytes(w, b, 8);
}
static void wb_base(wbuf_t *w, gold_fp_t x) { wb_u64(w, gold_fp_to_u64(x)); }
static void wb_fp2(wbuf_t *w, gold_fp2_t x) { wb_base(w, x.a); wb_base(w, x.b); }
static void wb_digest(wbuf_t *w, const dnac_merkle_digest_t *d) {
    wb_bytes(w, d->bytes, DNAC_MERKLE_DIGEST_BYTES);
}

static void enc_batch_opening(wbuf_t *w, const dnac_fri_batch_opening_t *bo) {
    wb_u32(w, (uint32_t)bo->num_matrices);
    for (size_t m = 0; m < bo->num_matrices; ++m) {
        wb_u32(w, (uint32_t)bo->opened_values_lens[m]);
        for (size_t cidx = 0; cidx < bo->opened_values_lens[m]; ++cidx)
            wb_base(w, bo->opened_values[m][cidx]);
    }
    wb_u32(w, (uint32_t)bo->opening_proof.depth);
    for (uint32_t s = 0; s < bo->opening_proof.depth; ++s)
        wb_digest(w, &bo->opening_proof.siblings[s]);
}

static void enc_cpo(wbuf_t *w, const dnac_fri_commit_phase_proof_step_t *step) {
    wb_u32(w, (uint32_t)step->log_arity);
    wb_u32(w, (uint32_t)step->num_sibling_values);
    for (size_t s = 0; s < step->num_sibling_values; ++s)
        wb_fp2(w, step->sibling_values[s]);
    wb_u32(w, (uint32_t)step->opening_proof.depth);
    for (uint32_t s = 0; s < step->opening_proof.depth; ++s)
        wb_digest(w, &step->opening_proof.siblings[s]);
}

static void enc_query_proof(wbuf_t *w, const dnac_fri_query_proof_t *qp) {
    wb_u32(w, (uint32_t)qp->num_input_batches);
    for (size_t b = 0; b < qp->num_input_batches; ++b)
        enc_batch_opening(w, &qp->input_proof[b]);
    wb_u32(w, (uint32_t)qp->num_commit_phase_openings);
    for (size_t r = 0; r < qp->num_commit_phase_openings; ++r)
        enc_cpo(w, &qp->commit_phase_openings[r]);
}

static void enc_proof(wbuf_t *w, const dnac_fri_proof_t *p) {
    wb_u32(w, (uint32_t)p->num_commit_phase_commits);
    for (size_t i = 0; i < p->num_commit_phase_commits; ++i)
        wb_digest(w, &p->commit_phase_commits[i]);
    wb_u32(w, (uint32_t)p->num_commit_pow_witnesses);
    for (size_t i = 0; i < p->num_commit_pow_witnesses; ++i)
        wb_base(w, p->commit_pow_witnesses[i]);
    wb_u32(w, (uint32_t)p->num_final_poly);
    for (size_t i = 0; i < p->num_final_poly; ++i)
        wb_fp2(w, p->final_poly[i]);
    wb_base(w, p->query_pow_witness);
    wb_u32(w, (uint32_t)p->num_query_proofs);
    for (size_t i = 0; i < p->num_query_proofs; ++i)
        enc_query_proof(w, &p->query_proofs[i]);
}

static void enc_point(wbuf_t *w, const dnac_fri_opening_point_t *pt) {
    wb_fp2(w, pt->point);
    wb_u32(w, (uint32_t)pt->num_claimed_evals);
    for (size_t e = 0; e < pt->num_claimed_evals; ++e)
        wb_fp2(w, pt->claimed_evals[e]);
}

static void enc_matrix(wbuf_t *w, const dnac_fri_matrix_openings_t *mo) {
    wb_base(w, mo->domain.shift);
    wb_base(w, mo->domain.shift_inverse);
    wb_u32(w, (uint32_t)mo->domain.log_size);
    wb_u32(w, (uint32_t)mo->num_points);
    for (size_t p = 0; p < mo->num_points; ++p)
        enc_point(w, &mo->points[p]);
}

static void enc_commitment(wbuf_t *w, const dnac_fri_commitment_with_opening_points_t *cw) {
    wb_digest(w, &cw->commitment);
    wb_u32(w, (uint32_t)cw->num_matrices);
    for (size_t m = 0; m < cw->num_matrices; ++m)
        enc_matrix(w, &cw->matrices[m]);
}

dnac_fri_codec_status_t dnac_fri_proof_encode(
    const dnac_fri_params_t                         *params,
    const dnac_fri_proof_t                          *proof,
    const dnac_fri_commitment_with_opening_points_t *commitments,
    size_t                                           num_commitments,
    uint8_t                                        **out_buf,
    size_t                                          *out_len)
{
    if (!params || !proof || !out_buf || !out_len) return DNAC_FRI_CODEC_ERR_NULL;
    if (num_commitments > 0 && !commitments) return DNAC_FRI_CODEC_ERR_NULL;
    *out_buf = NULL;

    wbuf_t w; w.buf = NULL; w.len = 0; w.cap = 0; w.oom = 0;

    /* header */
    const uint8_t magic[4] = {
        DNAC_FRI_WIRE_MAGIC0, DNAC_FRI_WIRE_MAGIC1,
        DNAC_FRI_WIRE_MAGIC2, DNAC_FRI_WIRE_MAGIC3
    };
    wb_bytes(&w, magic, 4);
    wb_u16(&w, (uint16_t)DNAC_FRI_WIRE_VERSION);
    size_t total_len_off = w.len;
    wb_u32(&w, 0); /* total_len placeholder */

    /* params */
    wb_u32(&w, (uint32_t)params->log_blowup);
    wb_u32(&w, (uint32_t)params->log_final_poly_len);
    wb_u32(&w, (uint32_t)params->max_log_arity);
    wb_u32(&w, (uint32_t)params->num_queries);
    wb_u32(&w, (uint32_t)params->commit_proof_of_work_bits);
    wb_u32(&w, (uint32_t)params->query_proof_of_work_bits);

    /* proof + commitments */
    enc_proof(&w, proof);
    wb_u32(&w, (uint32_t)num_commitments);
    for (size_t i = 0; i < num_commitments; ++i)
        enc_commitment(&w, &commitments[i]);

    if (w.oom) { free(w.buf); return DNAC_FRI_CODEC_ERR_OOM; }
    if (w.len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) { free(w.buf); return DNAC_FRI_CODEC_ERR_TOO_LARGE; }

    /* patch total_len */
    uint32_t tl = (uint32_t)w.len;
    for (int i = 0; i < 4; ++i) w.buf[total_len_off + i] = (uint8_t)(tl >> (8 * i));

    *out_buf = w.buf;
    *out_len = w.len;
    return DNAC_FRI_CODEC_OK;
}

/* ============================================================================
 * Reader (decode).
 * ========================================================================== */
typedef struct {
    const uint8_t          *buf;
    size_t                  len;
    size_t                  pos;
    dnac_fri_wire_package_t *pkg;
    dnac_fri_codec_status_t err;
} dctx_t;

static int rd_avail(const dctx_t *c, size_t n) { return n <= c->len - c->pos; } /* len>=pos invariant */

static int rd_u16(dctx_t *c, uint16_t *v) {
    if (!rd_avail(c, 2)) { c->err = DNAC_FRI_CODEC_ERR_TRUNCATED; return 0; }
    const uint8_t *p = c->buf + c->pos;
    *v = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
    c->pos += 2;
    return 1;
}
static int rd_u32(dctx_t *c, uint32_t *v) {
    if (!rd_avail(c, 4)) { c->err = DNAC_FRI_CODEC_ERR_TRUNCATED; return 0; }
    const uint8_t *p = c->buf + c->pos;
    uint32_t x = 0;
    for (int i = 0; i < 4; ++i) x |= (uint32_t)p[i] << (8 * i);
    *v = x;
    c->pos += 4;
    return 1;
}
static int rd_u64(dctx_t *c, uint64_t *v) {
    if (!rd_avail(c, 8)) { c->err = DNAC_FRI_CODEC_ERR_TRUNCATED; return 0; }
    const uint8_t *p = c->buf + c->pos;
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i) x |= (uint64_t)p[i] << (8 * i);
    *v = x;
    c->pos += 8;
    return 1;
}
static int rd_base(dctx_t *c, gold_fp_t *v) {
    uint64_t u;
    if (!rd_u64(c, &u)) return 0;
    if (u >= GOLDILOCKS_P) { c->err = DNAC_FRI_CODEC_ERR_NONCANONICAL; return 0; }
    *v = gold_fp_from_u64(u);
    return 1;
}
static int rd_fp2(dctx_t *c, gold_fp2_t *v) {
    gold_fp_t a, b;
    if (!rd_base(c, &a)) return 0;
    if (!rd_base(c, &b)) return 0;
    *v = gold_fp2_new(a, b);
    return 1;
}
static int rd_digest(dctx_t *c, dnac_merkle_digest_t *d) {
    if (!rd_avail(c, DNAC_MERKLE_DIGEST_BYTES)) { c->err = DNAC_FRI_CODEC_ERR_TRUNCATED; return 0; }
    memcpy(d->bytes, c->buf + c->pos, DNAC_MERKLE_DIGEST_BYTES);
    c->pos += DNAC_MERKLE_DIGEST_BYTES;
    return 1;
}

/* Read a u32 count for a fixed-size-element vector: enforce count<=max and
 * (u64)count*elem <= remaining (the primary OOM guard) BEFORE returning. */
static int rd_count_fixed(dctx_t *c, uint32_t max, size_t elem, uint32_t *out) {
    uint32_t n;
    if (!rd_u32(c, &n)) return 0;
    if (n > max) { c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW; return 0; }
    uint64_t need = (uint64_t)n * (uint64_t)elem;
    if (need > (uint64_t)(c->len - c->pos)) { c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW; return 0; }
    *out = n;
    return 1;
}
/* Read a u32 count for a variable-size-element vector: cap at max; each element
 * read enforces its own bounds (so a too-large-for-buffer count fails fast on
 * the first element read). The alloc itself is bounded by max. */
static int rd_count_var(dctx_t *c, uint32_t max, uint32_t *out) {
    uint32_t n;
    if (!rd_u32(c, &n)) return 0;
    if (n > max) { c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW; return 0; }
    *out = n;
    return 1;
}
/* Read a Merkle-proof depth (u32): buffer-safety only — depth<=MAX_SIBLINGS and
 * depth*64 <= remaining. Does NOT check depth == verifier-derived height (that
 * is the verifier's pre-existing trust assumption; design § M2 out-of-scope). */
static int rd_depth(dctx_t *c, uint32_t *out) {
    uint32_t n;
    if (!rd_u32(c, &n)) return 0;
    if (n > DNAC_FRI_WIRE_MAX_SIBLINGS) { c->err = DNAC_FRI_CODEC_ERR_BAD_DEPTH; return 0; }
    uint64_t need = (uint64_t)n * (uint64_t)DNAC_MERKLE_DIGEST_BYTES;
    if (need > (uint64_t)(c->len - c->pos)) { c->err = DNAC_FRI_CODEC_ERR_BAD_DEPTH; return 0; }
    *out = n;
    return 1;
}
/* Allocate an array of count elems; count==0 -> NULL (valid). Sets err=OOM only
 * when count>0 and allocation fails. */
static void *rd_array(dctx_t *c, uint32_t count, size_t elem) {
    if (count == 0) return NULL;
    void *p = pkg_alloc(c->pkg, (size_t)count * elem);
    if (!p) c->err = DNAC_FRI_CODEC_ERR_OOM;
    return p;
}

static int dec_params(dctx_t *c, dnac_fri_params_t *params) {
    uint32_t v;
    if (!rd_u32(c, &v)) { return 0; }
    params->log_blowup = v;
    if (!rd_u32(c, &v)) { return 0; }
    params->log_final_poly_len = v;
    if (!rd_u32(c, &v)) { return 0; }
    params->max_log_arity = v;
    if (!rd_u32(c, &v)) { return 0; }
    params->num_queries = v;
    if (!rd_u32(c, &v)) { return 0; }
    params->commit_proof_of_work_bits = v;
    if (!rd_u32(c, &v)) { return 0; }
    params->query_proof_of_work_bits = v;
    return 1;
}

static int dec_batch_opening(dctx_t *c, dnac_fri_batch_opening_t *bo) {
    uint32_t m;
    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_MATRICES, &m)) return 0;
    gold_fp_t **rows = (gold_fp_t **)rd_array(c, m, sizeof(gold_fp_t *));
    if (c->err) return 0;
    size_t *lens = (size_t *)rd_array(c, m, sizeof(size_t));
    if (c->err) return 0;
    for (uint32_t mi = 0; mi < m; ++mi) {
        uint32_t cols;
        if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_COLS, 8, &cols)) return 0;
        gold_fp_t *row = (gold_fp_t *)rd_array(c, cols, sizeof(gold_fp_t));
        if (c->err) return 0;
        for (uint32_t ci = 0; ci < cols; ++ci)
            if (!rd_base(c, &row[ci])) return 0;
        rows[mi] = row;
        lens[mi] = cols;
    }
    bo->opened_values = (const gold_fp_t *const *)rows;
    bo->opened_values_lens = lens;
    bo->num_matrices = m;

    uint32_t depth;
    if (!rd_depth(c, &depth)) return 0;
    dnac_merkle_digest_t *sib = (dnac_merkle_digest_t *)rd_array(c, depth, sizeof(dnac_merkle_digest_t));
    if (c->err) return 0;
    for (uint32_t s = 0; s < depth; ++s)
        if (!rd_digest(c, &sib[s])) return 0;
    bo->opening_proof.leaf_index = 0;   /* verifier computes */
    bo->opening_proof.depth = depth;
    bo->opening_proof.num_matrices = m; /* verifier rebuilds; set for consistency */
    bo->opening_proof.siblings = sib;
    return 1;
}

static int dec_cpo(dctx_t *c, dnac_fri_commit_phase_proof_step_t *step) {
    uint32_t la;
    if (!rd_u32(c, &la)) return 0;
    if (la > 0xFFu) { c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW; return 0; } /* u8 field */
    step->log_arity = (uint8_t)la;

    uint32_t n;
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_SIBLING_VALUES, 16, &n)) return 0;
    gold_fp2_t *sv = (gold_fp2_t *)rd_array(c, n, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t s = 0; s < n; ++s)
        if (!rd_fp2(c, &sv[s])) return 0;
    step->sibling_values = sv;
    step->num_sibling_values = n;

    uint32_t depth;
    if (!rd_depth(c, &depth)) return 0;
    dnac_merkle_digest_t *sib = (dnac_merkle_digest_t *)rd_array(c, depth, sizeof(dnac_merkle_digest_t));
    if (c->err) return 0;
    for (uint32_t s = 0; s < depth; ++s)
        if (!rd_digest(c, &sib[s])) return 0;
    step->opening_proof.leaf_index = 0;
    step->opening_proof.depth = depth;
    step->opening_proof.num_matrices = 1;
    step->opening_proof.siblings = sib;
    return 1;
}

static int dec_query_proof(dctx_t *c, dnac_fri_query_proof_t *qp) {
    uint32_t n;
    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_BATCHES, &n)) return 0;
    dnac_fri_batch_opening_t *bo = (dnac_fri_batch_opening_t *)rd_array(c, n, sizeof(*bo));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!dec_batch_opening(c, &bo[i])) return 0;
    qp->input_proof = bo;
    qp->num_input_batches = n;

    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_ROUNDS, &n)) return 0;
    dnac_fri_commit_phase_proof_step_t *cpo =
        (dnac_fri_commit_phase_proof_step_t *)rd_array(c, n, sizeof(*cpo));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!dec_cpo(c, &cpo[i])) return 0;
    qp->commit_phase_openings = cpo;
    qp->num_commit_phase_openings = n;
    return 1;
}

static int dec_proof(dctx_t *c, dnac_fri_proof_t *p) {
    uint32_t n;
    /* commit_phase_commits */
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_ROUNDS, sizeof(dnac_merkle_digest_t), &n)) return 0;
    dnac_merkle_digest_t *commits = (dnac_merkle_digest_t *)rd_array(c, n, sizeof(dnac_merkle_digest_t));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!rd_digest(c, &commits[i])) return 0;
    p->commit_phase_commits = commits;
    p->num_commit_phase_commits = n;

    /* commit_pow_witnesses */
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_ROUNDS, 8, &n)) return 0;
    gold_fp_t *wits = (gold_fp_t *)rd_array(c, n, sizeof(gold_fp_t));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!rd_base(c, &wits[i])) return 0;
    p->commit_pow_witnesses = wits;
    p->num_commit_pow_witnesses = n;

    /* final_poly */
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_FINAL_POLY, 16, &n)) return 0;
    gold_fp2_t *fp = (gold_fp2_t *)rd_array(c, n, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!rd_fp2(c, &fp[i])) return 0;
    p->final_poly = fp;
    p->num_final_poly = n;

    /* query_pow_witness */
    if (!rd_base(c, &p->query_pow_witness)) return 0;

    /* query_proofs */
    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_QUERIES, &n)) return 0;
    dnac_fri_query_proof_t *qps = (dnac_fri_query_proof_t *)rd_array(c, n, sizeof(*qps));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!dec_query_proof(c, &qps[i])) return 0;
    p->query_proofs = qps;
    p->num_query_proofs = n;
    return 1;
}

static int dec_point(dctx_t *c, dnac_fri_opening_point_t *pt) {
    if (!rd_fp2(c, &pt->point)) return 0;
    uint32_t n;
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_CLAIMED, 16, &n)) return 0;
    gold_fp2_t *ev = (gold_fp2_t *)rd_array(c, n, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!rd_fp2(c, &ev[i])) return 0;
    pt->claimed_evals = ev;
    pt->num_claimed_evals = n;
    return 1;
}

static int dec_matrix(dctx_t *c, dnac_fri_matrix_openings_t *mo) {
    if (!rd_base(c, &mo->domain.shift)) return 0;
    if (!rd_base(c, &mo->domain.shift_inverse)) return 0;
    uint32_t ls;
    if (!rd_u32(c, &ls)) return 0;
    mo->domain.log_size = ls;
    uint32_t n;
    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_POINTS, &n)) return 0;
    dnac_fri_opening_point_t *pts = (dnac_fri_opening_point_t *)rd_array(c, n, sizeof(*pts));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!dec_point(c, &pts[i])) return 0;
    mo->points = pts;
    mo->num_points = n;
    return 1;
}

static int dec_commitment(dctx_t *c, dnac_fri_commitment_with_opening_points_t *cw) {
    if (!rd_digest(c, &cw->commitment)) return 0;
    uint32_t n;
    if (!rd_count_var(c, DNAC_FRI_WIRE_MAX_MATRICES, &n)) return 0;
    dnac_fri_matrix_openings_t *mo = (dnac_fri_matrix_openings_t *)rd_array(c, n, sizeof(*mo));
    if (c->err) return 0;
    for (uint32_t i = 0; i < n; ++i)
        if (!dec_matrix(c, &mo[i])) return 0;
    cw->matrices = mo;
    cw->num_matrices = n;
    return 1;
}

dnac_fri_codec_status_t dnac_fri_proof_decode(
    const uint8_t            *buf,
    size_t                    len,
    dnac_fri_wire_package_t **out_pkg)
{
    if (!buf || !out_pkg) return DNAC_FRI_CODEC_ERR_NULL;
    *out_pkg = NULL;
    if (len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) return DNAC_FRI_CODEC_ERR_TOO_LARGE;

    dnac_fri_wire_package_t *pkg = (dnac_fri_wire_package_t *)calloc(1, sizeof *pkg);
    if (!pkg) return DNAC_FRI_CODEC_ERR_OOM;

    dctx_t c;
    c.buf = buf; c.len = len; c.pos = 0; c.pkg = pkg; c.err = DNAC_FRI_CODEC_OK;

    /* header: magic + version + total_len */
    if (!rd_avail(&c, 6)) { c.err = DNAC_FRI_CODEC_ERR_TRUNCATED; goto fail; }
    if (buf[0] != DNAC_FRI_WIRE_MAGIC0 || buf[1] != DNAC_FRI_WIRE_MAGIC1 ||
        buf[2] != DNAC_FRI_WIRE_MAGIC2 || buf[3] != DNAC_FRI_WIRE_MAGIC3) {
        c.err = DNAC_FRI_CODEC_ERR_BAD_MAGIC; goto fail;
    }
    c.pos = 4;
    {
        uint16_t ver;
        if (!rd_u16(&c, &ver)) goto fail;
        if (ver != DNAC_FRI_WIRE_VERSION) { c.err = DNAC_FRI_CODEC_ERR_BAD_VERSION; goto fail; }
        uint32_t total_len;
        if (!rd_u32(&c, &total_len)) goto fail;
        if ((size_t)total_len != len) { c.err = DNAC_FRI_CODEC_ERR_INCONSISTENT_LENGTH; goto fail; }
    }

    if (!dec_params(&c, &pkg->params)) goto fail;
    if (!dec_proof(&c, &pkg->proof)) goto fail;

    {
        uint32_t ncom;
        if (!rd_count_var(&c, DNAC_FRI_WIRE_MAX_COMMITMENTS, &ncom)) goto fail;
        pkg->commitments = (dnac_fri_commitment_with_opening_points_t *)
            rd_array(&c, ncom, sizeof(*pkg->commitments));
        if (c.err) goto fail;
        for (uint32_t i = 0; i < ncom; ++i)
            if (!dec_commitment(&c, &pkg->commitments[i])) goto fail;
        pkg->num_commitments = ncom;
    }

    if (c.pos != len) { c.err = DNAC_FRI_CODEC_ERR_TRAILING; goto fail; }

    *out_pkg = pkg;
    return DNAC_FRI_CODEC_OK;

fail:
    dnac_fri_wire_free(pkg);
    return c.err;
}

/* ============================================================================
 * Accessors + verify wrapper.
 * ========================================================================== */
const dnac_fri_params_t *dnac_fri_wire_params(const dnac_fri_wire_package_t *pkg) {
    return pkg ? &pkg->params : NULL;
}
const dnac_fri_proof_t *dnac_fri_wire_proof(const dnac_fri_wire_package_t *pkg) {
    return pkg ? &pkg->proof : NULL;
}
const dnac_fri_commitment_with_opening_points_t *dnac_fri_wire_commitments(
    const dnac_fri_wire_package_t *pkg, size_t *out_num_commitments)
{
    if (!pkg) { if (out_num_commitments) *out_num_commitments = 0; return NULL; }
    if (out_num_commitments) *out_num_commitments = pkg->num_commitments;
    return pkg->commitments;
}

dnac_fri_codec_status_t dnac_fri_verify_wire(
    const uint8_t        *buf,
    size_t                len,
    dnac_transcript_t    *transcript,
    dnac_fri_status_t    *out_fri_status)
{
    dnac_fri_wire_package_t *pkg = NULL;
    dnac_fri_codec_status_t cs = dnac_fri_proof_decode(buf, len, &pkg);
    if (cs != DNAC_FRI_CODEC_OK) return cs;

    size_t n = 0;
    const dnac_fri_commitment_with_opening_points_t *com = dnac_fri_wire_commitments(pkg, &n);
    dnac_fri_status_t fs = dnac_fri_verify(dnac_fri_wire_params(pkg), dnac_fri_wire_proof(pkg),
                                           transcript, com, n);
    if (out_fri_status) *out_fri_status = fs;
    dnac_fri_wire_free(pkg);
    return DNAC_FRI_CODEC_OK;
}

dnac_fri_codec_status_t dnac_fri_verify_wire_shielded(
    const uint8_t        *buf,
    size_t                len,
    dnac_transcript_t    *transcript,
    dnac_fri_status_t    *out_fri_status)
{
    /* (0) Fail-closed contract (red-team S0-M4): a consensus caller MUST receive
     * the verdict — a NULL out slot would swallow it. Reject up front. */
    if (!out_fri_status) return DNAC_FRI_CODEC_ERR_NULL;
    *out_fri_status = DNAC_FRI_ERR_INVALID_POW_WITNESS; /* fail-closed default */

    dnac_fri_wire_package_t *pkg = NULL;
    dnac_fri_codec_status_t cs = dnac_fri_proof_decode(buf, len, &pkg);
    if (cs != DNAC_FRI_CODEC_OK) return cs;

    /* (1) Tamper detection: wire params MUST equal the pinned consensus set.
     * A shielded proof carrying anything else is rejected outright. */
    const dnac_fri_params_t *pinned = dnac_shielded_fri_params();
    if (!dnac_fri_params_eq(dnac_fri_wire_params(pkg), pinned)) {
        dnac_fri_wire_free(pkg);
        return DNAC_FRI_CODEC_ERR_SHIELDED_PARAM_MISMATCH;
    }

    /* (2) Trace-height pin (dm-c5 C5e): the largest committed matrix domain
     * height must equal the pinned shielded COMMITTED height, so a prover cannot
     * slide lgmh to weaken the low-degree test. The committed domain log_size is
     * base_degree_bits + is_zk (the is_zk hiding transform commits at base+1 — see
     * shielded_fri_params.h; grounded to conf_root_air_zk.json base_degree_bits+1),
     * so the pin is DNAC_SHIELDED_COMMITTED_LOG_HEIGHT == 11, NOT the physical 10. */
    size_t n = 0;
    const dnac_fri_commitment_with_opening_points_t *com =
        dnac_fri_wire_commitments(pkg, &n);
    size_t max_log_height = 0;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < com[i].num_matrices; j++) {
            size_t lh = com[i].matrices[j].domain.log_size;
            if (lh > max_log_height) max_log_height = lh;
        }
    }
    if (max_log_height != DNAC_SHIELDED_COMMITTED_LOG_HEIGHT) {
        dnac_fri_wire_free(pkg);
        return DNAC_FRI_CODEC_ERR_SHIELDED_HEIGHT_MISMATCH;
    }

    /* (3) SUBSTITUTE the pinned params — the verifier's own constant sets the
     * security level, never the wire pointer. */
    dnac_fri_status_t fs = dnac_fri_verify(pinned, dnac_fri_wire_proof(pkg),
                                           transcript, com, n);
    *out_fri_status = fs;
    dnac_fri_wire_free(pkg);
    /* (4) Fail-closed (M4): a non-OK verdict is a codec-level rejection, not a
     * silent CODEC_OK the caller might ignore. */
    if (fs != DNAC_FRI_OK) return DNAC_FRI_CODEC_ERR_SHIELDED_VERIFY_FAILED;
    return DNAC_FRI_CODEC_OK;
}
