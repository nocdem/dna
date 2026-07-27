/**
 * @file fri_proof_codec.c
 * @brief Deterministic batched-proof wire codec (DZKF v4) — implementation.
 *
 * Source of truth: docs/plans/2026-05-29-fri-proof-wire-codec-design.md,
 * fri_verifier.h, batch_verify.h, Plonky3 82cfad73 (fri/src/proof.rs,
 * batch-stark/src/proof.rs, lookup/src/types.rs field/struct order).
 *
 * d4.d (2026-07-26): v3 uni-stark retirement. The live surface is v4 ONLY
 * (dnac_batch_wire_{encode,decode} + accessors). The ENTIRE v3 surface is gone
 * — encoder, decoder, read accessors, opening-point structures and BOTH verify
 * wrappers; see the retirement note below dec_proof.
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

/* ============================================================================
 * Decoded package — owns all allocations via a registry.
 * ========================================================================== */
typedef struct {
    void   **allocs;
    size_t   n_allocs;
    size_t   cap_allocs;
} codec_reg_t;

/* v4 batched package — the decoded dnac_batch_verify input set. */
struct dnac_batch_wire_package_s {
    codec_reg_t reg;
    int                        is_zk;
    uint32_t                   num_instances;
    dnac_batch_vcommits_t      commits;       /* lane arrays registered      */
    dnac_batch_vopened_t      *opened;        /* [num_instances], registered */
    dnac_batch_rand_openings_t rand;          /* arrays registered           */
    dnac_fri_params_t          params;        /* embedded */
    dnac_fri_proof_t           proof;         /* embedded */
};

/* Allocate (zeroed) and register; returns NULL for size==0 (a valid empty
 * vector) AND for OOM — callers distinguish via the dctx error field. */
static void *reg_alloc(codec_reg_t *reg, size_t size) {
    if (size == 0) return NULL;
    void *p = calloc(1, size);
    if (!p) return NULL;
    if (reg->n_allocs == reg->cap_allocs) {
        /* Registry-growth overflow guard (symmetry with wb_ensure). Unreachable
         * in practice — n_allocs <= len/4 <= 16M — but kept for defense. */
        if (reg->cap_allocs > ((size_t)-1) / 2 ||
            (reg->cap_allocs ? reg->cap_allocs * 2 : 32) > ((size_t)-1) / sizeof(void *)) {
            free(p);
            return NULL;
        }
        size_t ncap = reg->cap_allocs ? reg->cap_allocs * 2 : 32;
        void **na = (void **)realloc(reg->allocs, ncap * sizeof(void *));
        if (!na) { free(p); return NULL; }
        reg->allocs = na;
        reg->cap_allocs = ncap;
    }
    reg->allocs[reg->n_allocs++] = p;
    return p;
}

static void reg_release(codec_reg_t *reg) {
    for (size_t i = 0; i < reg->n_allocs; ++i) free(reg->allocs[i]);
    free(reg->allocs);
}

void dnac_batch_wire_free(dnac_batch_wire_package_t *pkg) {
    if (!pkg) return;
    reg_release(&pkg->reg);
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
/* P1c: a digest is 4 canonical Goldilocks lanes = 32 bytes on the wire,
 * each lane u64-LE (wire v3). */
static void wb_digest(wbuf_t *w, const dnac_p2_digest_t *d) {
    for (size_t i = 0; i < DNAC_P2M_DIGEST_LANES; ++i) wb_u64(w, d->lanes[i]);
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
    /* v2: M3b leaf salts — salt_elems values PER MATRIX (fri_verifier.h
     * dnac_fri_batch_opening_t; salts==NULL <=> salt_elems==0). */
    wb_u32(w, (uint32_t)bo->salt_elems);
    if (bo->salt_elems > 0) {
        for (size_t m = 0; m < bo->num_matrices; ++m)
            for (size_t s = 0; s < bo->salt_elems; ++s)
                wb_base(w, bo->salts[m][s]);
    }
}

static void enc_cpo(wbuf_t *w, const dnac_fri_commit_phase_proof_step_t *step) {
    wb_u32(w, (uint32_t)step->log_arity);
    wb_u32(w, (uint32_t)step->num_sibling_values);
    for (size_t s = 0; s < step->num_sibling_values; ++s)
        wb_fp2(w, step->sibling_values[s]);
    wb_u32(w, (uint32_t)step->opening_proof.depth);
    for (uint32_t s = 0; s < step->opening_proof.depth; ++s)
        wb_digest(w, &step->opening_proof.siblings[s]);
    /* v2: M3b commit-phase leaf salts (BASE elements, extension_mmcs.rs:77-95
     * base-flattened convention — see fri_verifier.h). */
    wb_u32(w, (uint32_t)step->salt_elems);
    for (size_t s = 0; s < step->salt_elems; ++s)
        wb_base(w, step->salts[s]);
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

/* d4.d: the v3 ENCODER (dnac_fri_proof_encode) and its opening-point-only
 * helpers (enc_point / enc_matrix / enc_commitment) are RETIRED — nothing in
 * the tree produces a version-3 buffer. enc_proof above is retained: the v4
 * encoder reuses it verbatim for the FriProof section. */

/* ============================================================================
 * Reader (decode).
 * ========================================================================== */
typedef struct {
    const uint8_t          *buf;
    size_t                  len;
    size_t                  pos;
    codec_reg_t            *reg;
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
/* P1c: digest = 4 u64-LE lanes; every lane MUST be canonical (< p) — the NEW
 * G-DET-P1-5 guard (P1.0 F6). Poseidon2 digests are observed into the
 * DuplexChallenger as field elements, so a non-canonical lane has no defined
 * observation and is REJECTED at decode, fail-close (same rd_base policy as
 * every other field). */
static int rd_digest(dctx_t *c, dnac_p2_digest_t *d) {
    for (size_t i = 0; i < DNAC_P2M_DIGEST_LANES; ++i) {
        gold_fp_t lane;
        if (!rd_base(c, &lane)) return 0; /* rd_base: TRUNCATED / >= p reject */
        d->lanes[i] = gold_fp_to_u64(lane);
    }
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
    uint64_t need = (uint64_t)n * (uint64_t)(DNAC_P2M_DIGEST_LANES * 8u);
    if (need > (uint64_t)(c->len - c->pos)) { c->err = DNAC_FRI_CODEC_ERR_BAD_DEPTH; return 0; }
    *out = n;
    return 1;
}
/* Allocate an array of count elems; count==0 -> NULL (valid). Sets err=OOM only
 * when count>0 and allocation fails. */
static void *rd_array(dctx_t *c, uint32_t count, size_t elem) {
    if (count == 0) return NULL;
    void *p = reg_alloc(c->reg, (size_t)count * elem);
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
    dnac_p2_digest_t *sib = (dnac_p2_digest_t *)rd_array(c, depth, sizeof(dnac_p2_digest_t));
    if (c->err) return 0;
    for (uint32_t s = 0; s < depth; ++s)
        if (!rd_digest(c, &sib[s])) return 0;
    bo->opening_proof.leaf_index = 0;   /* verifier computes */
    bo->opening_proof.depth = depth;
    bo->opening_proof.num_matrices = m; /* verifier rebuilds; set for consistency */
    bo->opening_proof.siblings = sib;

    /* v2: M3b leaf salts — u32 salt_elems then salt_elems canonical base values
     * PER MATRIX. 0 => unsalted (salts NULL). The per-matrix count is pinned to
     * salt_elems by construction (SEC-M3b-1) and rd_base rejects non-canonical
     * salts (SEC-M3b-2). */
    {
        uint32_t se;
        if (!rd_u32(c, &se)) return 0;
        if (se > DNAC_FRI_WIRE_MAX_SALT_ELEMS) {
            c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW;
            return 0;
        }
        bo->salt_elems = se;
        bo->salts = NULL;
        if (se > 0) {
            gold_fp_t **saltp =
                (gold_fp_t **)rd_array(c, m, sizeof(gold_fp_t *));
            if (c->err) return 0;
            /* m == 0 with se > 0: no salt values follow; saltp stays NULL and
             * the verifier sees num_matrices==0 (nothing to salt). */
            for (uint32_t mi = 0; mi < m; ++mi) {
                gold_fp_t *sv =
                    (gold_fp_t *)rd_array(c, se, sizeof(gold_fp_t));
                if (c->err) return 0;
                for (uint32_t s = 0; s < se; ++s)
                    if (!rd_base(c, &sv[s])) return 0;
                saltp[mi] = sv;
            }
            bo->salts = (const gold_fp_t *const *)saltp;
        }
    }
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
    dnac_p2_digest_t *sib = (dnac_p2_digest_t *)rd_array(c, depth, sizeof(dnac_p2_digest_t));
    if (c->err) return 0;
    for (uint32_t s = 0; s < depth; ++s)
        if (!rd_digest(c, &sib[s])) return 0;
    step->opening_proof.leaf_index = 0;
    step->opening_proof.depth = depth;
    step->opening_proof.num_matrices = 1;
    step->opening_proof.siblings = sib;

    /* v2: M3b commit-phase salts — u32 salt_elems + salt_elems canonical base
     * values. 0 => unsalted (salts NULL). */
    {
        uint32_t se;
        if (!rd_u32(c, &se)) return 0;
        if (se > DNAC_FRI_WIRE_MAX_SALT_ELEMS) {
            c->err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW;
            return 0;
        }
        step->salt_elems = se;
        step->salts = NULL;
        if (se > 0) {
            gold_fp_t *sv = (gold_fp_t *)rd_array(c, se, sizeof(gold_fp_t));
            if (c->err) return 0;
            for (uint32_t s = 0; s < se; ++s)
                if (!rd_base(c, &sv[s])) return 0;
            step->salts = sv;
        }
    }
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
    if (!rd_count_fixed(c, DNAC_FRI_WIRE_MAX_ROUNDS, sizeof(dnac_p2_digest_t), &n)) return 0;
    dnac_p2_digest_t *commits = (dnac_p2_digest_t *)rd_array(c, n, sizeof(dnac_p2_digest_t));
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

/* d4.d (2026-07-26): the ENTIRE v3 single-instance wire is RETIRED — encoder,
 * decoder, read accessors, opening-point structures and BOTH verify wrappers.
 * Nothing in the tree produces or consumes a version-3 buffer.
 *
 *   - dnac_fri_verify_wire        — the unpinned, params-trusting TEST entry
 *                                   (M5 gate). No longer exists in ANY build,
 *                                   which is strictly stronger than the old
 *                                   "compiled out of consensus" guarantee.
 *   - dnac_fri_verify_wire_shielded — the pinned v3 consensus wrapper. Every
 *                                   pin it held now lives on the v4 path in
 *                                   dnac_shielded_verify_statement
 *                                   (shielded_verify.c: params-eq+substitute
 *                                   :188-204/:252, SALT_ELEMS :91-103/:221,
 *                                   height :243, is_zk/n :179-182, opened
 *                                   shape :210-216).
 *   - dnac_fri_proof_decode / dnac_fri_wire_free / dec_point / dec_matrix /
 *     dec_commitment — the v3 decode path. The opening-point encoding it read
 *     does not exist on the v4 wire at all (structural H2 closure), so the
 *     cross-version guard that matters is the LIVE one: the v4 decoder pins
 *     DNAC_BATCH_WIRE_VERSION and rejects a version-3 buffer
 *     (tests/test_batch_wire.c N2b).
 * ========================================================================== */

/* ============================================================================
 * DZKF v4 — batched proof wire (P2L-d d4.a).
 *
 * Layout (all integers LE; field conventions identical to v3 — canonical
 * u64-LE fail-close, fp2 c0‖c1, 4-lane digests, u32 counts, salt tails
 * inside the FriProof):
 *
 *   "DZKF" ‖ u16 version=4 ‖ u32 total_len ‖
 *   u32 is_zk (0/1) ‖ u32 num_instances ‖
 *   main_commit(4 lanes) ‖
 *   u32 has_prep ‖ [prep_commit] ‖ u32 has_perm ‖ [perm_commit] ‖
 *   quotient_commit(4 lanes) ‖ u32 has_random ‖ [random_commit] ‖
 *   per instance:
 *     fp2vec trace_local ‖ fp2vec trace_next ‖
 *     fp2vec preprocessed_local ‖ fp2vec preprocessed_next ‖
 *     u32 num_qc ‖ 2·num_qc fp2 (chunk pairs, stride 2) ‖
 *     fp2vec random ‖
 *     u32 permutation_len ‖ permutation_len fp2 (local) ‖
 *                           permutation_len fp2 (next) ‖
 *     u32 has_terminal (0 or 1) ‖ [fp2 terminal iff 1] ‖
 *   [iff is_zk] u32 num_rand_entries ‖ per entry: fp2vec vals ‖
 *   fri params (6 × u32, v3 order) ‖
 *   FriProof (v3 enc_proof encoding, incl. salt tails)
 *
 *   fp2vec := u32 len ‖ len fp2 values.
 *
 * NO opening points on the wire (structural H2 closure — see the header).
 * Presence flags are structural; the semantic gates (random iff is_zk,
 * perm-commit iff lookups, len-vs-width) belong to dnac_batch_verify.
 * ========================================================================== */

static void wb_lanes4(wbuf_t *w, const gold_fp_t *lanes) {
    for (size_t i = 0; i < DNAC_P2M_DIGEST_LANES; ++i) wb_base(w, lanes[i]);
}
/* len > 0 requires a non-NULL vector (encode-side fail-close). */
static int wb_fp2_vec(wbuf_t *w, const gold_fp2_t *v, uint32_t len) {
    if (len > 0 && !v) return 0;
    wb_u32(w, len);
    for (uint32_t i = 0; i < len; ++i) wb_fp2(w, v[i]);
    return 1;
}

dnac_fri_codec_status_t dnac_batch_wire_encode(
    int                               is_zk,
    uint32_t                          num_instances,
    const dnac_batch_vcommits_t      *commits,
    const dnac_batch_vopened_t       *opened,
    const dnac_batch_rand_openings_t *rand_openings,
    const dnac_fri_params_t          *params,
    const dnac_fri_proof_t           *proof,
    uint8_t                         **out_buf,
    size_t                           *out_len)
{
    if (!commits || !opened || !params || !proof || !out_buf || !out_len)
        return DNAC_FRI_CODEC_ERR_NULL;
    *out_buf = NULL;
    if (is_zk != 0 && is_zk != 1) return DNAC_FRI_CODEC_ERR_NONCANONICAL;
    if (num_instances == 0 || num_instances > DNAC_BATCH_WIRE_MAX_INSTANCES)
        return DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW;
    if (!commits->main_commit || !commits->quotient_commit)
        return DNAC_FRI_CODEC_ERR_NULL;
    /* rand-openings iff is_zk — mirror of the dnac_batch_verify contract. */
    if ((rand_openings != NULL) != (is_zk == 1)) return DNAC_FRI_CODEC_ERR_NULL;

    wbuf_t w; w.buf = NULL; w.len = 0; w.cap = 0; w.oom = 0;

    const uint8_t magic[4] = {
        DNAC_FRI_WIRE_MAGIC0, DNAC_FRI_WIRE_MAGIC1,
        DNAC_FRI_WIRE_MAGIC2, DNAC_FRI_WIRE_MAGIC3
    };
    wb_bytes(&w, magic, 4);
    wb_u16(&w, (uint16_t)DNAC_BATCH_WIRE_VERSION);
    size_t total_len_off = w.len;
    wb_u32(&w, 0); /* total_len placeholder */

    wb_u32(&w, (uint32_t)is_zk);
    wb_u32(&w, num_instances);

    /* commits */
    wb_lanes4(&w, commits->main_commit);
    wb_u32(&w, commits->preprocessed_commit ? 1u : 0u);
    if (commits->preprocessed_commit) wb_lanes4(&w, commits->preprocessed_commit);
    wb_u32(&w, commits->permutation_commit ? 1u : 0u);
    if (commits->permutation_commit) wb_lanes4(&w, commits->permutation_commit);
    wb_lanes4(&w, commits->quotient_commit);
    wb_u32(&w, commits->random_commit ? 1u : 0u);
    if (commits->random_commit) wb_lanes4(&w, commits->random_commit);

    /* per-instance opened values + global_lookup_data */
    for (uint32_t i = 0; i < num_instances; ++i) {
        const dnac_batch_vopened_t *o = &opened[i];
        if (!wb_fp2_vec(&w, o->trace_local, o->trace_local_len) ||
            !wb_fp2_vec(&w, o->trace_next, o->trace_next_len) ||
            !wb_fp2_vec(&w, o->preprocessed_local, o->preprocessed_local_len) ||
            !wb_fp2_vec(&w, o->preprocessed_next, o->preprocessed_next_len)) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_NULL;
        }
        if (o->num_quotient_chunks > 0 && !o->quotient_chunks) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_NULL;
        }
        if (o->num_quotient_chunks > DNAC_BATCH_WIRE_MAX_QC) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW;
        }
        wb_u32(&w, o->num_quotient_chunks);
        for (uint32_t k = 0; k < o->num_quotient_chunks * 2u; ++k)
            wb_fp2(&w, o->quotient_chunks[k]);
        if (!wb_fp2_vec(&w, o->random, o->random_len)) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_NULL;
        }
        if (o->permutation_len > 0 &&
            (!o->permutation_local || !o->permutation_next)) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_NULL;
        }
        wb_u32(&w, o->permutation_len);
        for (uint32_t k = 0; k < o->permutation_len; ++k)
            wb_fp2(&w, o->permutation_local[k]);
        for (uint32_t k = 0; k < o->permutation_len; ++k)
            wb_fp2(&w, o->permutation_next[k]);
        /* LookupTerminal — u32 count (0 or 1) then the fp2 when present
         * (oracle-pinned, main.rs:18194-18207). */
        wb_u32(&w, o->has_terminal ? 1u : 0u);
        if (o->has_terminal) {
            wb_fp2(&w, o->terminal);
        }
    }

    /* random-codeword openings iff is_zk */
    if (is_zk) {
        if (rand_openings->num_entries > DNAC_BATCH_WIRE_MAX_RAND_ENTRIES) {
            free(w.buf);
            return DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW;
        }
        wb_u32(&w, rand_openings->num_entries);
        for (uint32_t k = 0; k < rand_openings->num_entries; ++k) {
            if (!wb_fp2_vec(&w, rand_openings->vals[k],
                            rand_openings->lens[k])) {
                free(w.buf);
                return DNAC_FRI_CODEC_ERR_NULL;
            }
        }
    }

    /* params (v3 order) + FriProof (v3 encoding) */
    wb_u32(&w, (uint32_t)params->log_blowup);
    wb_u32(&w, (uint32_t)params->log_final_poly_len);
    wb_u32(&w, (uint32_t)params->max_log_arity);
    wb_u32(&w, (uint32_t)params->num_queries);
    wb_u32(&w, (uint32_t)params->commit_proof_of_work_bits);
    wb_u32(&w, (uint32_t)params->query_proof_of_work_bits);
    enc_proof(&w, proof);

    if (w.oom) { free(w.buf); return DNAC_FRI_CODEC_ERR_OOM; }
    if (w.len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) {
        free(w.buf);
        return DNAC_FRI_CODEC_ERR_TOO_LARGE;
    }

    uint32_t tl = (uint32_t)w.len;
    for (int i = 0; i < 4; ++i) w.buf[total_len_off + i] = (uint8_t)(tl >> (8 * i));

    *out_buf = w.buf;
    *out_len = w.len;
    return DNAC_FRI_CODEC_OK;
}

/* 4 canonical lanes into a registered gold_fp_t[4]. */
static int rd_lanes4(dctx_t *c, const gold_fp_t **out) {
    gold_fp_t *l = (gold_fp_t *)rd_array(c, DNAC_P2M_DIGEST_LANES,
                                         sizeof(gold_fp_t));
    if (c->err) return 0;
    for (size_t i = 0; i < DNAC_P2M_DIGEST_LANES; ++i)
        if (!rd_base(c, &l[i])) return 0;
    *out = l;
    return 1;
}
/* presence flag: 0 or 1 only (canonical wire — no third encoding of "absent"). */
static int rd_flag(dctx_t *c, uint32_t *out) {
    if (!rd_u32(c, out)) return 0;
    if (*out > 1u) { c->err = DNAC_FRI_CODEC_ERR_NONCANONICAL; return 0; }
    return 1;
}
/* fp2vec := u32 len + len fp2; len==0 -> NULL (the dnac_batch_vopened_t
 * absent-section convention). */
static int rd_fp2_vec(dctx_t *c, const gold_fp2_t **out, uint32_t *out_len,
                      uint32_t max) {
    uint32_t l;
    if (!rd_count_fixed(c, max, 16, &l)) return 0;
    gold_fp2_t *v = (gold_fp2_t *)rd_array(c, l, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t i = 0; i < l; ++i)
        if (!rd_fp2(c, &v[i])) return 0;
    *out = v;
    *out_len = l;
    return 1;
}

static int dec_batch_opened(dctx_t *c, dnac_batch_vopened_t *o) {
    if (!rd_fp2_vec(c, &o->trace_local, &o->trace_local_len,
                    DNAC_BATCH_WIRE_MAX_OPENED_VALS) ||
        !rd_fp2_vec(c, &o->trace_next, &o->trace_next_len,
                    DNAC_BATCH_WIRE_MAX_OPENED_VALS) ||
        !rd_fp2_vec(c, &o->preprocessed_local, &o->preprocessed_local_len,
                    DNAC_BATCH_WIRE_MAX_OPENED_VALS) ||
        !rd_fp2_vec(c, &o->preprocessed_next, &o->preprocessed_next_len,
                    DNAC_BATCH_WIRE_MAX_OPENED_VALS)) {
        return 0;
    }

    /* quotient chunk pairs: u32 num_qc + 2·num_qc fp2 (32 B per chunk). */
    uint32_t nqc;
    if (!rd_count_fixed(c, DNAC_BATCH_WIRE_MAX_QC, 32, &nqc)) return 0;
    gold_fp2_t *qc =
        (gold_fp2_t *)rd_array(c, nqc * 2u, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t k = 0; k < nqc * 2u; ++k)
        if (!rd_fp2(c, &qc[k])) return 0;
    o->quotient_chunks = qc;
    o->num_quotient_chunks = nqc;

    if (!rd_fp2_vec(c, &o->random, &o->random_len,
                    DNAC_BATCH_WIRE_MAX_OPENED_VALS)) {
        return 0;
    }

    /* permutation: ONE len, then local then next (each len fp2 = 32 B/pair). */
    uint32_t plen;
    if (!rd_count_fixed(c, DNAC_BATCH_WIRE_MAX_OPENED_VALS, 32, &plen)) return 0;
    gold_fp2_t *pl = (gold_fp2_t *)rd_array(c, plen, sizeof(gold_fp2_t));
    if (c->err) return 0;
    gold_fp2_t *pn = (gold_fp2_t *)rd_array(c, plen, sizeof(gold_fp2_t));
    if (c->err) return 0;
    for (uint32_t k = 0; k < plen; ++k)
        if (!rd_fp2(c, &pl[k])) return 0;
    for (uint32_t k = 0; k < plen; ++k)
        if (!rd_fp2(c, &pn[k])) return 0;
    o->permutation_local = pl;
    o->permutation_next = pn;
    o->permutation_len = plen;

    /* LookupTerminal — u32 count (0 or 1) then the fp2 when present.
     * Oracle-pinned layout (tools/plonky3_oracle/src/main.rs:18194-18207).
     * The count-then-entries shape is kept deliberately so the decoder loop
     * structure survives the v3 -> v0.6.2 change; the bus name and aux column
     * that used to follow it are gone from the wire entirely. */
    uint32_t nt;
    if (!rd_u32(c, &nt)) return 0;
    /* Exactly the Option discriminant: any other value is non-canonical.
     * Checked here rather than via a max bound so that 2..UINT32_MAX is
     * rejected as malformed rather than silently clamped. */
    if (nt > 1u) { c->err = DNAC_FRI_CODEC_ERR_NONCANONICAL; return 0; }
    if (nt == 1u) {
        if (!rd_fp2(c, &o->terminal)) return 0;
        o->has_terminal = 1;
    } else {
        o->terminal = gold_fp2_zero();
        o->has_terminal = 0;
    }
    return 1;
}

dnac_fri_codec_status_t dnac_batch_wire_decode(
    const uint8_t              *buf,
    size_t                      len,
    dnac_batch_wire_package_t **out_pkg)
{
    if (!buf || !out_pkg) return DNAC_FRI_CODEC_ERR_NULL;
    *out_pkg = NULL;
    if (len > DNAC_FRI_WIRE_MAX_TOTAL_LEN) return DNAC_FRI_CODEC_ERR_TOO_LARGE;

    dnac_batch_wire_package_t *pkg =
        (dnac_batch_wire_package_t *)calloc(1, sizeof *pkg);
    if (!pkg) return DNAC_FRI_CODEC_ERR_OOM;

    dctx_t c;
    c.buf = buf; c.len = len; c.pos = 0; c.reg = &pkg->reg;
    c.err = DNAC_FRI_CODEC_OK;

    /* header: magic + version(=4) + total_len */
    if (!rd_avail(&c, 6)) { c.err = DNAC_FRI_CODEC_ERR_TRUNCATED; goto fail; }
    if (buf[0] != DNAC_FRI_WIRE_MAGIC0 || buf[1] != DNAC_FRI_WIRE_MAGIC1 ||
        buf[2] != DNAC_FRI_WIRE_MAGIC2 || buf[3] != DNAC_FRI_WIRE_MAGIC3) {
        c.err = DNAC_FRI_CODEC_ERR_BAD_MAGIC; goto fail;
    }
    c.pos = 4;
    {
        uint16_t ver;
        if (!rd_u16(&c, &ver)) goto fail;
        if (ver != DNAC_BATCH_WIRE_VERSION) {
            c.err = DNAC_FRI_CODEC_ERR_BAD_VERSION; goto fail;
        }
        uint32_t total_len;
        if (!rd_u32(&c, &total_len)) goto fail;
        if ((size_t)total_len != len) {
            c.err = DNAC_FRI_CODEC_ERR_INCONSISTENT_LENGTH; goto fail;
        }
    }

    {
        uint32_t zk;
        if (!rd_flag(&c, &zk)) goto fail;
        pkg->is_zk = (int)zk;
    }
    {
        uint32_t n;
        if (!rd_u32(&c, &n)) goto fail;
        if (n == 0 || n > DNAC_BATCH_WIRE_MAX_INSTANCES) {
            c.err = DNAC_FRI_CODEC_ERR_LENGTH_OVERFLOW; goto fail;
        }
        pkg->num_instances = n;
    }

    /* commits */
    if (!rd_lanes4(&c, &pkg->commits.main_commit)) goto fail;
    {
        uint32_t f;
        if (!rd_flag(&c, &f)) goto fail;
        if (f && !rd_lanes4(&c, &pkg->commits.preprocessed_commit)) goto fail;
        if (!rd_flag(&c, &f)) goto fail;
        if (f && !rd_lanes4(&c, &pkg->commits.permutation_commit)) goto fail;
        if (!rd_lanes4(&c, &pkg->commits.quotient_commit)) goto fail;
        if (!rd_flag(&c, &f)) goto fail;
        if (f && !rd_lanes4(&c, &pkg->commits.random_commit)) goto fail;
    }

    /* per-instance opened values */
    pkg->opened = (dnac_batch_vopened_t *)rd_array(
        &c, pkg->num_instances, sizeof(dnac_batch_vopened_t));
    if (c.err) goto fail;
    for (uint32_t i = 0; i < pkg->num_instances; ++i)
        if (!dec_batch_opened(&c, &pkg->opened[i])) goto fail;

    /* random-codeword openings iff is_zk */
    if (pkg->is_zk) {
        uint32_t ne;
        if (!rd_count_var(&c, DNAC_BATCH_WIRE_MAX_RAND_ENTRIES, &ne)) goto fail;
        const gold_fp2_t **vals =
            (const gold_fp2_t **)rd_array(&c, ne, sizeof(gold_fp2_t *));
        if (c.err) goto fail;
        uint32_t *lens = (uint32_t *)rd_array(&c, ne, sizeof(uint32_t));
        if (c.err) goto fail;
        for (uint32_t k = 0; k < ne; ++k)
            if (!rd_fp2_vec(&c, &vals[k], &lens[k],
                            DNAC_BATCH_WIRE_MAX_OPENED_VALS)) {
                goto fail;
            }
        pkg->rand.vals = vals;
        pkg->rand.lens = lens;
        pkg->rand.num_entries = ne;
    }

    if (!dec_params(&c, &pkg->params)) goto fail;
    if (!dec_proof(&c, &pkg->proof)) goto fail;

    if (c.pos != len) { c.err = DNAC_FRI_CODEC_ERR_TRAILING; goto fail; }

    *out_pkg = pkg;
    return DNAC_FRI_CODEC_OK;

fail:
    dnac_batch_wire_free(pkg);
    return c.err;
}

/* ── v4 accessors (borrowed) ── */
int dnac_batch_wire_is_zk(const dnac_batch_wire_package_t *pkg) {
    return pkg ? pkg->is_zk : 0;
}
uint32_t dnac_batch_wire_num_instances(const dnac_batch_wire_package_t *pkg) {
    return pkg ? pkg->num_instances : 0;
}
const dnac_batch_vcommits_t *dnac_batch_wire_commits(
    const dnac_batch_wire_package_t *pkg) {
    return pkg ? &pkg->commits : NULL;
}
const dnac_batch_vopened_t *dnac_batch_wire_opened(
    const dnac_batch_wire_package_t *pkg) {
    return pkg ? pkg->opened : NULL;
}
const dnac_batch_rand_openings_t *dnac_batch_wire_rand_openings(
    const dnac_batch_wire_package_t *pkg) {
    return (pkg && pkg->is_zk) ? &pkg->rand : NULL;
}
const dnac_fri_params_t *dnac_batch_wire_params(
    const dnac_batch_wire_package_t *pkg) {
    return pkg ? &pkg->params : NULL;
}
const dnac_fri_proof_t *dnac_batch_wire_proof(
    const dnac_batch_wire_package_t *pkg) {
    return pkg ? &pkg->proof : NULL;
}

/* d4.d: dnac_fri_verify_wire_shielded lived here. Retired with the v3 wire —
 * its pins are enumerated in the retirement note above and are all enforced by
 * dnac_shielded_verify_statement (shielded_verify.c) on the v4 path. */
