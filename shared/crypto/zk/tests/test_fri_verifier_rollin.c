/**
 * @file test_fri_verifier_rollin.c
 * @brief F1.6 — multi-reduced-opening ROLL-IN replay (Plonky3 82cfad73).
 *
 * Consumes tools/vectors/fri_verifier_rollin.json (a REAL Plonky3 proof over
 * TWO single-matrix commitments at log_height 4 and 2, accepted by p3_verify_fri)
 * and proves the verify_query roll-in path (verifier.rs:477-480) is EXERCISED,
 * not merely present. V6 (single height) never reaches it.
 *
 * The vector carries its OWN primed transcript seed (input_buf_hex, 128 bytes:
 * 64 digest + 32 opened_A + 32 opened_B), so this test needs only one file.
 *
 * Assertions (per query unless noted):
 *   (1) PRODUCTION end-to-end: dnac_fri_verify(...) == DNAC_FRI_OK.
 *       With the lower-height reduced opening nonzero (asserted by the oracle at
 *       generation and pinned in the vector), DNAC_FRI_OK is mathematically
 *       impossible unless the production roll-in executed correctly — a skipped
 *       or wrong beta^arity·ro would diverge folded_eval from the prover's
 *       committed value and fail the terminal Horner check. So (1) IS the
 *       production roll-in-executed proof.
 *   (2) PRODUCTION capture (dnac_fri_test_verify_capture): query_index,
 *       sampled betas, and terminal folded_eval[q] match the vector.
 *   (3) INDEPENDENT fold trace: a local mirror of verify_query (verifier.rs:
 *       395-480) using the oracle-grounded fri_fold_row_fp2, seeded with the
 *       vector reduced openings + proof sibling values, recomputes
 *       folded_before / folded_after at every round and asserts they match the
 *       vector — deriving them from the proof, not echoing them.
 *   (4) ROLL-IN arithmetic (production gold_fp2 ops): beta^arity recomputed from
 *       beta by log_arity squarings; beta^arity·ro nonzero; folded_after ==
 *       folded_before + beta^arity·ro; folded_before != folded_after; roll-in at
 *       round 1 with round 0 a NO-roll-in round (next_if -> None then -> Some).
 *
 * dnac_fri_status_t is unchanged; fri_verifier.{c,h} are unchanged. The
 * independent trace is a second C implementation (mirrors verifier.rs), distinct
 * from the production verifier; both agree with the Plonky3-anchored vector.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define DNAC_FRI_TESTING 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_verifier.h"
#include "fri_fold.h" /* fri_fold_row_fp2 (independent trace) */

/* ===== Minimal JSON scanner (same idiom as tests/test_fri_verifier_valid.c) ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;

static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}
static bool js_peek(js_t *s, char c) { js_skip_ws(s); return s->pos < s->len && s->src[s->pos] == c; }
static bool js_match(js_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}
static char *js_read_string(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len || s->src[s->pos] != '"') return NULL;
    s->pos++;
    size_t start = s->pos;
    while (s->pos < s->len && s->src[s->pos] != '"') s->pos++;
    if (s->pos >= s->len) return NULL;
    size_t slen = s->pos - start;
    s->pos++;
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, s->src + start, slen);
    out[slen] = '\0';
    return out;
}
static bool js_read_u64(js_t *s, uint64_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}
static bool js_skip_value(js_t *s);
static bool js_skip_object(js_t *s) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) return false;
        free(k);
        if (!js_match(s, ':')) return false;
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_array(js_t *s) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_value(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '{') return js_skip_object(s);
    if (c == '[') return js_skip_array(s);
    if (c == '"') { char *t = js_read_string(s); if (!t) return false; free(t); return true; }
    if (c == 't') { s->pos += 4; return true; }
    if (c == 'f') { s->pos += 5; return true; }
    if (c == 'n') { s->pos += 4; return true; }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') s->pos++;
        else break;
    }
    return true;
}
static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex_decode(const char *hex, uint8_t *buf, size_t cap) {
    size_t hl = strlen(hex);
    if (hl % 2) return (size_t)-1;
    size_t n = hl / 2;
    if (n > cap) return (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(hex[2*i]), lo = hexnib(hex[2*i+1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* ===== value parsers for serde shapes (identical shapes to V6) ===== */
static void put_u64_le(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }

static int read_u64_array(js_t *s, uint64_t *out, int cap) {
    int n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        uint64_t v;
        if (!js_read_u64(s, &v)) return -1;
        if (n < cap) out[n] = v;
        n++;
    }
    return n;
}
/* bare [8 u64] digest -> 64 LE bytes */
static void parse_lanes_digest(js_t *s, uint8_t out[64]) {
    uint64_t lanes[8] = {0};
    read_u64_array(s, lanes, 8);
    for (int i = 0; i < 8; ++i) put_u64_le(out + i * 8, lanes[i]);
}
/* {_marker, cap:[[8 u64]]} -> 64 LE bytes */
static void parse_commit_digest(js_t *s, uint8_t out[64]) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "cap") == 0) {
            js_match(s, '[');
            parse_lanes_digest(s, out);
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}
/* {value:x} -> x */
static uint64_t parse_base_obj(js_t *s) {
    uint64_t r = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "value") == 0) js_read_u64(s, &r);
        else js_skip_value(s);
        free(k);
    }
    return r;
}
/* {_phantom, value:[{value:c0},{value:c1}]} -> fp2 (serde-wrapped) */
static gold_fp2_t parse_fp2_wrapped(js_t *s) {
    uint64_t comps[2] = {0, 0};
    int n = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "value") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                uint64_t bv = parse_base_obj(s);
                if (n < 2) comps[n] = bv;
                n++;
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    return gold_fp2_new(gold_fp_from_u64(comps[0]), gold_fp_from_u64(comps[1]));
}
/* {c0_decimal:"..", c1_decimal:".."} -> fp2 (diagnostic / zeta form) */
static gold_fp2_t parse_fp2_decimal(js_t *s) {
    uint64_t c0 = 0, c1 = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        char *v = js_peek(s, '"') ? js_read_string(s) : NULL;
        if (v && k && strcmp(k, "c0_decimal") == 0) c0 = strtoull(v, NULL, 10);
        else if (v && k && strcmp(k, "c1_decimal") == 0) c1 = strtoull(v, NULL, 10);
        else if (!v) js_skip_value(s);
        free(v);
        free(k);
    }
    return gold_fp2_new(gold_fp_from_u64(c0), gold_fp_from_u64(c1));
}

/* ===== fixture storage ===== */
#define MAXQ     2   /* num_queries                */
#define MAXBATCH 2   /* input batches per query    */
#define MAXR     8   /* commit-phase rounds        */
#define MAXCOL   8   /* matrix columns             */
#define MAXSIB   8   /* merkle depth               */

typedef struct {
    dnac_fri_params_t params;

    /* proof */
    dnac_merkle_digest_t commits[MAXR];
    gold_fp_t  witnesses[MAXR];
    gold_fp2_t final_poly[MAXCOL];
    size_t     num_final_poly;
    size_t     num_commits;
    gold_fp_t  qpow;

    /* per-query input batches (multi-batch, different depths) */
    gold_fp_t            inp_row[MAXQ][MAXBATCH][MAXCOL];
    const gold_fp_t     *inp_rowptr[MAXQ][MAXBATCH][1];
    size_t               inp_lens[MAXQ][MAXBATCH][1];
    size_t               inp_cols[MAXQ][MAXBATCH];
    dnac_merkle_digest_t inp_sib[MAXQ][MAXBATCH][MAXSIB];
    size_t               inp_depth[MAXQ][MAXBATCH];
    dnac_fri_batch_opening_t bo[MAXQ][MAXBATCH];
    size_t               num_batches[MAXQ];

    /* per-query commit-phase openings */
    gold_fp2_t           cpo_sib[MAXQ][MAXR][MAXSIB];
    size_t               cpo_nsib[MAXQ][MAXR];
    dnac_merkle_digest_t cpo_psib[MAXQ][MAXR][MAXSIB];
    size_t               cpo_depth[MAXQ][MAXR];
    dnac_fri_commit_phase_proof_step_t cpo[MAXQ][MAXR];
    size_t               cpo_n[MAXQ];
    dnac_fri_query_proof_t qp[MAXQ];
    size_t num_queries;

    dnac_fri_proof_t proof;

    /* commitments_with_opening_points (2 commitments, single matrix each) */
    dnac_merkle_digest_t commitment[MAXBATCH];
    gold_fp2_t           claimed[MAXBATCH][MAXCOL];
    size_t               num_claimed[MAXBATCH];
    dnac_fri_opening_point_t point[MAXBATCH];
    dnac_fri_matrix_openings_t matrix[MAXBATCH];
    dnac_fri_commitment_with_opening_points_t cwop[MAXBATCH];
    uint64_t domain_log_size[MAXBATCH]; /* = log_degree per commitment */
    size_t   num_commitments;
    gold_fp2_t zeta;

    /* primed transcript seed */
    uint8_t seed[256]; size_t seed_len;
    uint64_t query_indices[MAXQ]; size_t num_query_indices;
    size_t lgmh; /* log_global_max_height */

    /* rollin diagnostic */
    size_t     ro_lh[MAXQ][2];
    gold_fp2_t ro_val[MAXQ][2];
    gold_fp2_t betas_vec[MAXQ][MAXR];
    size_t     num_betas[MAXQ];
    gold_fp2_t term[MAXQ];
    size_t     roll_in_round[MAXQ];
    gold_fp2_t rd_folded_before[MAXQ][MAXR];
    gold_fp2_t rd_folded_after[MAXQ][MAXR];
    int        rd_rolled[MAXQ][MAXR];
    gold_fp2_t rd_ro[MAXQ][MAXR];
    gold_fp2_t rd_beta_pow_arity[MAXQ][MAXR];
    gold_fp2_t rd_beta_pow_ro[MAXQ][MAXR];
    size_t     rd_log_folded[MAXQ][MAXR];
    size_t     num_rounds_diag[MAXQ];
} fx_t;

/* parse one commit_phase_opening object into fx->cpo[q][r] */
static void parse_cpo(js_t *s, fx_t *fx, size_t q, size_t r) {
    size_t nsib = 0, npsib = 0;
    uint8_t la = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "log_arity") == 0) { uint64_t v; js_read_u64(s, &v); la = (uint8_t)v; }
        else if (k && strcmp(k, "sibling_values") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t fv = parse_fp2_wrapped(s);
                if (nsib < MAXSIB) fx->cpo_sib[q][r][nsib] = fv;
                nsib++;
            }
        } else if (k && strcmp(k, "opening_proof") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (npsib < MAXSIB) parse_lanes_digest(s, fx->cpo_psib[q][r][npsib].bytes);
                else js_skip_value(s);
                npsib++;
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    fx->cpo_nsib[q][r] = nsib;
    fx->cpo_depth[q][r] = npsib;
    fx->cpo[q][r].log_arity = la;
    fx->cpo[q][r].sibling_values = fx->cpo_sib[q][r];
    fx->cpo[q][r].num_sibling_values = nsib;
    fx->cpo[q][r].opening_proof.leaf_index = 0;
    fx->cpo[q][r].opening_proof.depth = (uint32_t)npsib;
    fx->cpo[q][r].opening_proof.num_matrices = 1;
    fx->cpo[q][r].opening_proof.siblings = fx->cpo_psib[q][r];
}

/* parse one input_proof batch (single matrix) into fx->bo[q][b] */
static void parse_input_batch(js_t *s, fx_t *fx, size_t q, size_t b) {
    size_t ncols = 0, nsib = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *bk = js_read_string(s);
        js_match(s, ':');
        if (bk && strcmp(bk, "opened_values") == 0) {
            js_match(s, '[');   /* per-matrix array */
            js_match(s, '[');   /* matrix 0 row     */
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                uint64_t bv = parse_base_obj(s);
                if (ncols < MAXCOL) fx->inp_row[q][b][ncols] = gold_fp_from_u64(bv);
                ncols++;
            }
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
        } else if (bk && strcmp(bk, "opening_proof") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (nsib < MAXSIB) parse_lanes_digest(s, fx->inp_sib[q][b][nsib].bytes);
                else js_skip_value(s);
                nsib++;
            }
        } else {
            js_skip_value(s);
        }
        free(bk);
    }
    fx->inp_cols[q][b] = ncols;
    fx->inp_depth[q][b] = nsib;
    fx->inp_rowptr[q][b][0] = fx->inp_row[q][b];
    fx->inp_lens[q][b][0] = ncols;
    fx->bo[q][b].opened_values = fx->inp_rowptr[q][b];
    fx->bo[q][b].opened_values_lens = fx->inp_lens[q][b];
    fx->bo[q][b].num_matrices = 1;
    fx->bo[q][b].opening_proof.leaf_index = 0;
    fx->bo[q][b].opening_proof.depth = (uint32_t)nsib;
    fx->bo[q][b].opening_proof.num_matrices = 1;
    fx->bo[q][b].opening_proof.siblings = fx->inp_sib[q][b];
}

/* parse one query_proof object into fx->qp[q] (multi-batch input_proof) */
static void parse_query_proof(js_t *s, fx_t *fx, size_t q) {
    size_t ncpo = 0, nbatch = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "input_proof") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (nbatch < MAXBATCH) { parse_input_batch(s, fx, q, nbatch); nbatch++; }
                else js_skip_value(s);
            }
        } else if (k && strcmp(k, "commit_phase_openings") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (ncpo < MAXR) { parse_cpo(s, fx, q, ncpo); ncpo++; }
                else js_skip_value(s);
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    fx->num_batches[q] = nbatch;
    fx->cpo_n[q] = ncpo;
    fx->qp[q].input_proof = fx->bo[q];
    fx->qp[q].num_input_batches = nbatch;
    fx->qp[q].commit_phase_openings = fx->cpo[q];
    fx->qp[q].num_commit_phase_openings = ncpo;
}

static void parse_params(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        uint64_t v = 0; js_read_u64(s, &v);
        if (k && strcmp(k, "log_blowup") == 0) fx->params.log_blowup = v;
        else if (k && strcmp(k, "log_final_poly_len") == 0) fx->params.log_final_poly_len = v;
        else if (k && strcmp(k, "max_log_arity") == 0) fx->params.max_log_arity = v;
        else if (k && strcmp(k, "num_queries") == 0) fx->params.num_queries = v;
        else if (k && strcmp(k, "commit_proof_of_work_bits") == 0) fx->params.commit_proof_of_work_bits = v;
        else if (k && strcmp(k, "query_proof_of_work_bits") == 0) fx->params.query_proof_of_work_bits = v;
        free(k);
    }
}

static void parse_proof(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "commit_phase_commits") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                if (n < MAXR) parse_commit_digest(s, fx->commits[n].bytes); else js_skip_value(s); n++; }
            fx->num_commits = n;
        } else if (k && strcmp(k, "commit_pow_witnesses") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                uint64_t bv = parse_base_obj(s); if (n < MAXR) fx->witnesses[n] = gold_fp_from_u64(bv); n++; }
        } else if (k && strcmp(k, "final_poly") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t fv = parse_fp2_wrapped(s); if (n < MAXCOL) fx->final_poly[n] = fv; n++; }
            fx->num_final_poly = n;
        } else if (k && strcmp(k, "query_pow_witness") == 0) {
            fx->qpow = gold_fp_from_u64(parse_base_obj(s));
        } else if (k && strcmp(k, "query_proofs") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                if (n < MAXQ) parse_query_proof(s, fx, n); else js_skip_value(s); n++; }
            fx->num_queries = n;
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* commitments_serde = [ {cap..}, {cap..} ] */
static void parse_commitments_serde(js_t *s, fx_t *fx) {
    size_t n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (n < MAXBATCH) parse_commit_digest(s, fx->commitment[n].bytes);
        else js_skip_value(s);
        n++;
    }
    fx->num_commitments = n;
}

/* opened_values_serde = [ batch0=[[ [fp2..] ]], batch1=[[ [fp2..] ]] ] */
static void parse_opened_values_serde(js_t *s, fx_t *fx) {
    size_t b = 0;
    js_match(s, '[');                 /* batches */
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        /* batch b = [ matrix0 = [ point0 = [fp2..] ] ] */
        js_match(s, '[');             /* matrices */
        js_match(s, '[');             /* points   */
        js_match(s, '[');             /* cols     */
        size_t nc = 0;
        while (!js_match(s, ']')) {
            if (js_peek(s, ',')) { s->pos++; continue; }
            gold_fp2_t fv = parse_fp2_wrapped(s);
            if (b < MAXBATCH && nc < MAXCOL) fx->claimed[b][nc] = fv;
            nc++;
        }
        if (b < MAXBATCH) fx->num_claimed[b] = nc;
        /* close points, matrices */
        while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
        while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
        b++;
    }
}

/* fixture.matrices = [ {commitment_index, log_degree, ...}, ... ] */
static void parse_fixture(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "matrices") == 0) {
            size_t mi = 0;
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                uint64_t log_degree = 0;
                js_match(s, '{');
                while (!js_match(s, '}')) {
                    if (js_peek(s, ',')) { s->pos++; continue; }
                    char *mk = js_read_string(s); js_match(s, ':');
                    if (mk && strcmp(mk, "log_degree") == 0) js_read_u64(s, &log_degree);
                    else js_skip_value(s);
                    free(mk);
                }
                if (mi < MAXBATCH) fx->domain_log_size[mi] = log_degree;
                mi++;
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* primed_transcript = { input_buf_hex, input_buf_len, ... } */
static void parse_primed(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "input_buf_hex") == 0) {
            char *h = js_read_string(s);
            if (h) { fx->seed_len = hex_decode(h, fx->seed, sizeof fx->seed); free(h); }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* top-level query_indices = [u64, ...] */
static void parse_query_indices(js_t *s, fx_t *fx) {
    uint64_t tmp[MAXQ] = {0};
    int n = read_u64_array(s, tmp, MAXQ);
    fx->num_query_indices = (n < 0) ? 0 : (size_t)n;
    for (size_t i = 0; i < fx->num_query_indices && i < MAXQ; ++i) fx->query_indices[i] = tmp[i];
}

/* parse one rollin.queries[q] round object */
static void parse_rollin_round(js_t *s, fx_t *fx, size_t q, size_t r) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "log_folded_height") == 0) {
            uint64_t v; js_read_u64(s, &v); if (r < MAXR) fx->rd_log_folded[q][r] = (size_t)v;
        } else if (k && strcmp(k, "folded_before_fp2") == 0) {
            gold_fp2_t v = parse_fp2_decimal(s); if (r < MAXR) fx->rd_folded_before[q][r] = v;
        } else if (k && strcmp(k, "folded_after_fp2") == 0) {
            gold_fp2_t v = parse_fp2_decimal(s); if (r < MAXR) fx->rd_folded_after[q][r] = v;
        } else if (k && strcmp(k, "rolled_in") == 0) {
            int b = js_peek(s, 't'); js_skip_value(s); if (r < MAXR) fx->rd_rolled[q][r] = b;
        } else if (k && strcmp(k, "ro_fp2") == 0) {
            gold_fp2_t v = parse_fp2_decimal(s); if (r < MAXR) fx->rd_ro[q][r] = v;
        } else if (k && strcmp(k, "beta_pow_arity_fp2") == 0) {
            gold_fp2_t v = parse_fp2_decimal(s); if (r < MAXR) fx->rd_beta_pow_arity[q][r] = v;
        } else if (k && strcmp(k, "beta_pow_ro_fp2") == 0) {
            gold_fp2_t v = parse_fp2_decimal(s); if (r < MAXR) fx->rd_beta_pow_ro[q][r] = v;
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* parse one rollin.queries[q] object */
static void parse_rollin_query(js_t *s, fx_t *fx, size_t q) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "reduced_openings_descending") == 0) {
            size_t i = 0;
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                /* {log_height, ro_fp2:{c0,c1}} */
                js_match(s, '{');
                uint64_t lh = 0; gold_fp2_t ro = gold_fp2_zero();
                while (!js_match(s, '}')) {
                    if (js_peek(s, ',')) { s->pos++; continue; }
                    char *ek = js_read_string(s); js_match(s, ':');
                    if (ek && strcmp(ek, "log_height") == 0) js_read_u64(s, &lh);
                    else if (ek && strcmp(ek, "ro_fp2") == 0) ro = parse_fp2_decimal(s);
                    else js_skip_value(s);
                    free(ek);
                }
                if (i < 2) { fx->ro_lh[q][i] = (size_t)lh; fx->ro_val[q][i] = ro; }
                i++;
            }
        } else if (k && strcmp(k, "betas_fp2") == 0) {
            size_t i = 0;
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t v = parse_fp2_decimal(s);
                if (i < MAXR) fx->betas_vec[q][i] = v;
                i++;
            }
            fx->num_betas[q] = i;
        } else if (k && strcmp(k, "terminal_folded_eval_fp2") == 0) {
            fx->term[q] = parse_fp2_decimal(s);
        } else if (k && strcmp(k, "roll_in_round") == 0) {
            uint64_t v; js_read_u64(s, &v); fx->roll_in_round[q] = (size_t)v;
        } else if (k && strcmp(k, "rounds") == 0) {
            size_t r = 0;
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                parse_rollin_round(s, fx, q, r);
                r++;
            }
            fx->num_rounds_diag[q] = r;
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* rollin = { roll_in_round, no_roll_in_round_before, queries:[...] } */
static void parse_rollin(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "queries") == 0) {
            size_t q = 0;
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (q < MAXQ) { parse_rollin_query(s, fx, q); q++; }
                else js_skip_value(s);
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* ===== independent verify_query fold trace (mirror of verifier.rs:395-480
 * using the oracle-grounded fri_fold_row_fp2). Recomputes folded_before/after
 * from the proof sibling values + vector reduced openings + vector betas.
 * Returns 0 on full agreement with the vector, else nonzero. ===== */
static int rollin_independent_trace(fx_t *fx, size_t q, int *out_rollin_round) {
    int fails = 0;
    gold_fp2_t folded = fx->ro_val[q][0];     /* seed = ro at log_global_max_height */
    size_t ro_i = 1;
    size_t log_cur = fx->lgmh;
    uint64_t idx = fx->query_indices[q];
    size_t log_final_height = fx->params.log_blowup + fx->params.log_final_poly_len;
    int rollin_round = -1;

    for (size_t round = 0; round < fx->cpo_n[q]; ++round) {
        size_t log_arity = fx->cpo[q][round].log_arity;
        size_t arity = (size_t)1u << log_arity;
        size_t iig = (size_t)(idx % (uint64_t)arity);
        gold_fp2_t evals[MAXSIB + 1];
        evals[iig] = folded;
        size_t sib = 0;
        for (size_t j = 0; j < arity; ++j) {
            if (j != iig) evals[j] = fx->cpo_sib[q][round][sib++];
        }
        size_t log_folded = log_cur - log_arity;
        idx >>= log_arity;
        gold_fp2_t folded_before =
            fri_fold_row_fp2((size_t)idx, (unsigned)log_folded, (unsigned)log_arity,
                             fx->betas_vec[q][round], evals, arity);
        gold_fp2_t folded_after = folded_before;
        int rolled = 0;
        if (ro_i < 2 && fx->ro_lh[q][ro_i] == log_folded) {
            gold_fp2_t beta_pow = fx->betas_vec[q][round];
            for (size_t s = 0; s < log_arity; ++s) beta_pow = gold_fp2_sqr(beta_pow);
            gold_fp2_t contrib = gold_fp2_mul(beta_pow, fx->ro_val[q][ro_i]);
            folded_after = gold_fp2_add(folded_before, contrib);
            rolled = 1;
            rollin_round = (int)round;
            /* (4) roll-in arithmetic vs vector, using production gold ops */
            if (!gold_fp2_eq(beta_pow, fx->rd_beta_pow_arity[q][round])) {
                printf("    [FAIL] q%zu r%zu beta^arity mismatch\n", q, round); fails++;
            }
            if (!gold_fp2_eq(contrib, fx->rd_beta_pow_ro[q][round])) {
                printf("    [FAIL] q%zu r%zu beta^arity*ro mismatch\n", q, round); fails++;
            }
            if (gold_fp2_eq(contrib, gold_fp2_zero())) {
                printf("    [FAIL] q%zu r%zu beta^arity*ro is ZERO (roll-in no-op)\n", q, round); fails++;
            }
            if (gold_fp2_eq(folded_before, folded_after)) {
                printf("    [FAIL] q%zu r%zu folded_eval unchanged across roll-in\n", q, round); fails++;
            }
            ro_i++;
        }
        /* (3) folded_before/after derived from proof must match the vector */
        if (!gold_fp2_eq(folded_before, fx->rd_folded_before[q][round])) {
            printf("    [FAIL] q%zu r%zu folded_before mismatch vs vector\n", q, round); fails++;
        }
        if (!gold_fp2_eq(folded_after, fx->rd_folded_after[q][round])) {
            printf("    [FAIL] q%zu r%zu folded_after mismatch vs vector\n", q, round); fails++;
        }
        if (rolled != fx->rd_rolled[q][round]) {
            printf("    [FAIL] q%zu r%zu rolled_in flag mismatch\n", q, round); fails++;
        }
        folded = folded_after;
        log_cur = log_folded;
    }

    if (log_cur != log_final_height) {
        printf("    [FAIL] q%zu final height %zu != %zu\n", q, log_cur, log_final_height); fails++;
    }
    if (ro_i != 2) {
        printf("    [FAIL] q%zu consumed %zu reduced openings (want 2)\n", q, ro_i); fails++;
    }
    if (!gold_fp2_eq(folded, fx->term[q])) {
        printf("    [FAIL] q%zu independent terminal != vector terminal\n", q); fails++;
    }
    *out_rollin_round = rollin_round;
    return fails;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fri_verifier_rollin.json>\n", argv[0]);
        return 2;
    }
    printf("============================================================\n");
    printf("F1.6 — FRI verifier multi-reduced-opening ROLL-IN (Plonky3 82cfad73)\n");
    printf("       2 commits @ log_height 4 + 2; roll-in at round 1\n");
    printf("============================================================\n");

    fx_t *fx = (fx_t *)calloc(1, sizeof *fx);
    if (!fx) return 2;

    size_t blen = 0; char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); free(fx); return 2; }
    js_t s = { blob, 0, blen };

    js_match(&s, '{');
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); js_match(&s, ':');
        if (k && strcmp(k, "fri_params") == 0) parse_params(&s, fx);
        else if (k && strcmp(k, "proof") == 0) parse_proof(&s, fx);
        else if (k && strcmp(k, "commitments_serde") == 0) parse_commitments_serde(&s, fx);
        else if (k && strcmp(k, "opened_values_serde") == 0) parse_opened_values_serde(&s, fx);
        else if (k && strcmp(k, "transcript_zeta_fp2") == 0) fx->zeta = parse_fp2_decimal(&s);
        else if (k && strcmp(k, "fixture") == 0) parse_fixture(&s, fx);
        else if (k && strcmp(k, "primed_transcript") == 0) parse_primed(&s, fx);
        else if (k && strcmp(k, "query_indices") == 0) parse_query_indices(&s, fx);
        else if (k && strcmp(k, "rollin") == 0) parse_rollin(&s, fx);
        else js_skip_value(&s);
        free(k);
    }
    free(blob);

    /* wire proof */
    fx->proof.commit_phase_commits = fx->commits;
    fx->proof.num_commit_phase_commits = fx->num_commits;
    fx->proof.commit_pow_witnesses = fx->witnesses;
    fx->proof.num_commit_pow_witnesses = fx->num_commits;
    fx->proof.query_proofs = fx->qp;
    fx->proof.num_query_proofs = fx->num_queries;
    fx->proof.final_poly = fx->final_poly;
    fx->proof.num_final_poly = fx->num_final_poly;
    fx->proof.query_pow_witness = fx->qpow;

    /* wire commitments_with_opening_points (2 commitments, single matrix each) */
    for (size_t b = 0; b < fx->num_commitments; ++b) {
        fx->point[b].point = fx->zeta;
        fx->point[b].claimed_evals = fx->claimed[b];
        fx->point[b].num_claimed_evals = fx->num_claimed[b];
        fx->matrix[b].domain.log_size = (size_t)fx->domain_log_size[b];
        fx->matrix[b].points = &fx->point[b];
        fx->matrix[b].num_points = 1;
        fx->cwop[b].commitment = fx->commitment[b];
        fx->cwop[b].matrices = &fx->matrix[b];
        fx->cwop[b].num_matrices = 1;
    }

    fx->lgmh = fx->params.log_blowup + fx->params.log_final_poly_len;
    for (size_t r = 0; r < fx->cpo_n[0]; ++r) fx->lgmh += fx->cpo[0][r].log_arity;

    /* ---- parse sanity ---- */
    int parse_ok = (fx->num_commits == 3) && (fx->num_queries == 2) &&
                   (fx->num_final_poly == 1) && (fx->num_commitments == 2) &&
                   (fx->seed_len == 128) && (fx->num_query_indices == 2) &&
                   (fx->num_batches[0] == 2) && (fx->num_batches[1] == 2) &&
                   (fx->cpo_n[0] == 3) && (fx->lgmh == 4) &&
                   (fx->domain_log_size[0] == 3) && (fx->domain_log_size[1] == 1) &&
                   (fx->num_claimed[0] == 2) && (fx->num_claimed[1] == 2) &&
                   (fx->inp_depth[0][0] == 4) && (fx->inp_depth[0][1] == 2);
    if (!parse_ok) {
        printf("FAIL parse: commits=%zu queries=%zu final=%zu cwop=%zu seed=%zu qi=%zu "
               "batches=[%zu,%zu] rounds=%zu lgmh=%zu dls=[%llu,%llu] depthsA=[%zu,%zu]\n",
               fx->num_commits, fx->num_queries, fx->num_final_poly, fx->num_commitments,
               fx->seed_len, fx->num_query_indices, fx->num_batches[0], fx->num_batches[1],
               fx->cpo_n[0], fx->lgmh,
               (unsigned long long)fx->domain_log_size[0], (unsigned long long)fx->domain_log_size[1],
               fx->inp_depth[0][0], fx->inp_depth[0][1]);
        free(fx); return 1;
    }
    printf("  parse OK: 2 commits (log_height 4 + 2), 2 batches/query "
           "(input depths %zu + %zu), 3 rounds, seed=%zu bytes\n",
           fx->inp_depth[0][0], fx->inp_depth[0][1], fx->seed_len);

    /* ---- (1) PRODUCTION end-to-end gate ---- */
    int fails = 0;
    {
        dnac_transcript_t *t = dnac_transcript_init(fx->seed, fx->seed_len);
        if (!t) { printf("  [FAIL] transcript init\n"); free(fx); return 1; }
        dnac_fri_status_t st = dnac_fri_verify(&fx->params, &fx->proof, t, fx->cwop, fx->num_commitments);
        dnac_transcript_free(t);
        printf("  (1) dnac_fri_verify -> %d (want %d=DNAC_FRI_OK)\n", (int)st, (int)DNAC_FRI_OK);
        if (st != DNAC_FRI_OK) fails++;
    }

    /* ---- (2) PRODUCTION capture cross-check ---- */
    dnac_fri_debug_t dbg;
    memset(&dbg, 0, sizeof dbg);
    {
        dnac_transcript_t *t = dnac_transcript_init(fx->seed, fx->seed_len);
        if (!t) { printf("  [FAIL] transcript init (capture)\n"); free(fx); return 1; }
        dnac_fri_status_t st = dnac_fri_test_verify_capture(&fx->params, &fx->proof, t,
                                                            fx->cwop, fx->num_commitments, &dbg);
        dnac_transcript_free(t);
        if (st != DNAC_FRI_OK) { printf("  [FAIL] capture verify -> %d\n", (int)st); fails++; }
        if (dbg.num_betas != fx->num_commits) { printf("  [FAIL] num_betas=%zu\n", dbg.num_betas); fails++; }
        for (size_t r = 0; r < dbg.num_betas && r < MAXR; ++r) {
            if (!gold_fp2_eq(dbg.betas[r], fx->betas_vec[0][r])) {
                printf("  [FAIL] production beta[%zu] != vector beta\n", r); fails++;
            }
        }
        for (size_t q = 0; q < fx->num_queries; ++q) {
            if (dbg.query_index[q] != fx->query_indices[q]) {
                printf("  [FAIL] q%zu production query_index %llu != vector %llu\n", q,
                       (unsigned long long)dbg.query_index[q], (unsigned long long)fx->query_indices[q]);
                fails++;
            }
            if (!gold_fp2_eq(dbg.folded_eval[q], fx->term[q])) {
                printf("  [FAIL] q%zu production terminal folded_eval != vector terminal\n", q); fails++;
            }
        }
        printf("  (2) production capture: query_index={%llu,%llu}, betas+terminal cross-checked\n",
               (unsigned long long)dbg.query_index[0], (unsigned long long)dbg.query_index[1]);
    }

    /* ---- (3)+(4) independent fold trace + roll-in arithmetic, per query ---- */
    for (size_t q = 0; q < fx->num_queries; ++q) {
        int rr = -1;
        int qf = rollin_independent_trace(fx, q, &rr);
        if (rr != 1) { printf("  [FAIL] q%zu roll-in round %d != 1\n", q, rr); qf++; }
        if (fx->roll_in_round[q] != 1) { printf("  [FAIL] q%zu vector roll_in_round %zu != 1\n", q, fx->roll_in_round[q]); qf++; }
        /* round 0 must be a NO-roll-in round (next_if -> None) */
        if (fx->rd_rolled[q][0] != 0) { printf("  [FAIL] q%zu round 0 unexpectedly rolled in\n", q); qf++; }
        if (qf == 0)
            printf("  (3)+(4) q%zu: independent trace matches vector; roll-in@round1 "
                   "(beta^arity*ro nonzero, folded changes); round0 no-roll-in\n", q);
        fails += qf;
    }

    printf("------------------------------------------------------------\n");
    if (fails == 0) {
        printf("F1.6 ROLL-IN GATE: GREEN — multi-reduced-opening roll-in EXERCISED end-to-end\n");
        printf("  production DNAC_FRI_OK + capture cross-check + independent fold trace\n");
        printf("============================================================\n");
        free(fx);
        return 0;
    }
    printf("F1.6 ROLL-IN GATE: RED (%d failures)\n", fails);
    free(fx);
    return 1;
}
