/**
 * @file test_fri_verifier_valid.c
 * @brief F7 integrated oracle test — V6 valid proof end-to-end acceptance.
 *
 * Plonky3 commit pin: v0.6.2 (11cc5849). The vectors were regenerated at S2'-f;
 * the 82cfad73 pin this header used to carry is historical.
 *
 * Parses the locked V6 valid proof + commitments_with_opening_points from
 * tools/vectors/fri_verifier_valid.json, seeds a transcript to the captured
 * "top of verify_fri" primed state (milestone 0 of
 * tools/vectors/fri_verifier_transcript_milestones.json — priming is the PCS
 * caller's job, out of FRI scope), then runs the full integrated verifier via
 * dnac_fri_test_verify_capture and asserts:
 *   - dnac_fri_verify returns DNAC_FRI_OK (V6 verifies end-to-end);
 *   - query indices == each sample_bits milestone's result.sampled_index,
 *     READ FROM THE VECTOR (they are challenger-derived, so S2'-b moved them
 *     from the P1c-era {8, 8}; a literal here would re-assert the OLD
 *     challenger and, in fx_query_x, silently stop reproducing z == x);
 *   - reduced_index == the same indices — this fixture's single matrix sits AT
 *     the global max height, so bits_reduced is 0 (verifier.rs:576-580);
 *   - folded_eval[q] == v6_honest_query_0.eval_fp2, READ from
 *     tools/vectors/fri_verifier_terminal_horner.json (oracle-gated by F6)
 * The intermediate cross-checks decompose a failure to a single stage.
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

/* ===== Minimal JSON scanner (same idiom as tests/test_merkle_mmcs.c) ===== */
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
    /* P1c: oracle snapshot/lane values are DECIMAL STRINGS — accept both
     * quoted and bare u64s. */
    bool quoted = (s->src[s->pos] == '"');
    if (quoted) s->pos++;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) { if (quoted) s->pos--; return false; }
    s->pos = (size_t)(endp - s->src);
    if (quoted) { if (s->pos < s->len && s->src[s->pos] == '"') s->pos++; else return false; }
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
/* (P1c: byte-hex helpers hexnib/hex_decode retired with the SHA3 seed format.) */

/* ===== value parsers for V6 serde shapes ===== */

/* read a bare [u64, ...] array into out[], return count */
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
/* P1c (regen-reconciled): a serde digest is `[ {"value": N} x4 ]` — each
 * lane a Goldilocks struct, NOT a bare u64. */
static uint64_t parse_base_obj(js_t *s); /* fwd */
static void parse_lanes_digest(js_t *s, dnac_p2_digest_t *out) {
    int n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        uint64_t v = parse_base_obj(s);
        if (n < 4) out->lanes[n] = v;
        n++;
    }
}
/* {_marker, cap:[[4 u64]]} -> 4-lane digest */
static void parse_commit_digest(js_t *s, dnac_p2_digest_t *out) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) return; /* fail-close on desync, never strcmp(NULL) */
        js_match(s, ':');
        if (strcmp(k, "cap") == 0) {
            js_match(s, '[');               /* outer cap array */
            parse_lanes_digest(s, out);     /* one digest (cap_height 0) */
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}
/* {value:x} -> x */
/* Goldilocks serde: v0.6.2 emits a BARE number where 82cfad73 emitted the
 * wrapped {"value": N}. Both forms are accepted so this parser reads either
 * vintage.
 *
 * Two guards, neither cosmetic. (1) No-progress: without it the bare-number
 * form makes this loop spin forever — nothing advances s->pos — and the test
 * emits nothing and looks exactly like a crypto hang. (2) NULL key: this copy
 * dereferenced js_read_string's result WITHOUT a NULL check, which the
 * bare-number form reaches directly (no leading '"', so js_read_string returns
 * NULL) — a segfault, not just a hang. Fixed here rather than left as a latent
 * trap for whoever regenerates the next vector. */
static uint64_t parse_base_obj(js_t *s) {
    uint64_t r = 0;
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] != '{') { js_read_u64(s, &r); return r; }
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        const size_t before = s->pos;
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "value") == 0) js_read_u64(s, &r);
        else js_skip_value(s);
        free(k);
        if (s->pos == before) break;   /* unparsable token: bail, never spin */
    }
    return r;
}
/* {_phantom, value:[{value:c0},{value:c1}]} -> fp2 */
static gold_fp2_t parse_fp2_wrapped(js_t *s) {
    uint64_t comps[2] = {0, 0};
    int n = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (strcmp(k, "value") == 0) {
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
/* {c0_decimal:"..", c1_decimal:".."} -> fp2 */
static gold_fp2_t parse_fp2_decimal(js_t *s) {
    uint64_t c0 = 0, c1 = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        char *v = js_peek(s, '"') ? js_read_string(s) : NULL;
        if (v && strcmp(k, "c0_decimal") == 0) c0 = strtoull(v, NULL, 10);
        else if (v && strcmp(k, "c1_decimal") == 0) c1 = strtoull(v, NULL, 10);
        else if (!v) js_skip_value(s);
        free(v);
        free(k);
    }
    return gold_fp2_new(gold_fp_from_u64(c0), gold_fp_from_u64(c1));
}

/* ===== V6 fixture storage ===== */
#define MAXQ 4
#define MAXR 8
#define MAXCOL 8
#define MAXSIB 8
typedef struct {
    dnac_fri_params_t params;
    dnac_p2_digest_t commits[MAXR];
    gold_fp_t  witnesses[MAXR];
    gold_fp2_t final_poly[MAXCOL];
    size_t     num_final_poly;
    size_t     num_commits;
    gold_fp_t  qpow;

    gold_fp_t  inp_row[MAXQ][MAXCOL];
    const gold_fp_t *inp_rowptr[MAXQ][1];
    size_t     inp_lens[MAXQ][1];
    dnac_p2_digest_t inp_sib[MAXQ][MAXSIB];
    dnac_fri_batch_opening_t bo[MAXQ];

    gold_fp2_t cpo_sib[MAXQ][MAXR][MAXSIB];
    dnac_p2_digest_t cpo_psib[MAXQ][MAXR][MAXSIB];
    dnac_fri_commit_phase_proof_step_t cpo[MAXQ][MAXR];
    dnac_fri_query_proof_t qp[MAXQ];
    size_t num_queries;

    dnac_fri_proof_t proof;

    gold_fp2_t claimed[MAXCOL]; size_t num_claimed;
    dnac_fri_opening_point_t point0;
    dnac_fri_matrix_openings_t matrix0;
    dnac_fri_commitment_with_opening_points_t cwop;
    uint64_t domain_log_size;

    /* P1c: milestone-0 primed DuplexChallenger state from the vector */
    dnac_duplex_t primed; int have_primed;
    uint64_t exp_qi[4]; int exp_qi_n;  /* oracle result.sampled_index values */
} fx_t;

/* P1c: rebuild a transcript at milestone 0. Requires the TESTING accessor —
 * the Makefile rule MUST define DNAC_TRANSCRIPT_TESTING (P1c-TODO). */
#ifdef DNAC_TRANSCRIPT_TESTING
static dnac_transcript_t *mk_primed(const fx_t *fx) {
    dnac_transcript_t *t = dnac_transcript_init_empty();
    if (!t) return NULL;
    *(dnac_duplex_t *)dnac_transcript_test_duplex(t) = fx->primed;
    return t;
}
#else
#error "P1c: test_fri_verifier_valid requires -DDNAC_TRANSCRIPT_TESTING=1 (primed-state injection)"
#endif

/* parse one commit_phase_opening object into fx->cpo[q][r] */
static void parse_cpo(js_t *s, fx_t *fx, size_t q, size_t r) {
    size_t nsib = 0, npsib = 0;
    uint8_t la = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (strcmp(k, "log_arity") == 0) { uint64_t v; js_read_u64(s, &v); la = (uint8_t)v; }
        else if (strcmp(k, "sibling_values") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t fv = parse_fp2_wrapped(s);
                if (nsib < MAXSIB) fx->cpo_sib[q][r][nsib] = fv;
                nsib++;
            }
        } else if (strcmp(k, "opening_proof") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (npsib < MAXSIB) parse_lanes_digest(s, &fx->cpo_psib[q][r][npsib]);
                else js_skip_value(s);
                npsib++;
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    fx->cpo[q][r].log_arity = la;
    fx->cpo[q][r].sibling_values = fx->cpo_sib[q][r];
    fx->cpo[q][r].num_sibling_values = nsib;
    fx->cpo[q][r].opening_proof.leaf_index = 0;
    fx->cpo[q][r].opening_proof.depth = (uint32_t)npsib;
    fx->cpo[q][r].opening_proof.num_matrices = 1;
    fx->cpo[q][r].opening_proof.siblings = fx->cpo_psib[q][r];
}

/* parse one query_proof object into fx->qp[q] */
static void parse_query_proof(js_t *s, fx_t *fx, size_t q) {
    size_t ncpo = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (strcmp(k, "input_proof") == 0) {
            js_match(s, '[');
            /* single batch */
            js_match(s, '{');
            size_t ncols = 0, nsib = 0;
            while (!js_match(s, '}')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *bk = js_read_string(s);
                js_match(s, ':');
                if (strcmp(bk, "opened_values") == 0) {
                    js_match(s, '[');          /* per-matrix */
                    js_match(s, '[');          /* matrix 0 row */
                    while (!js_match(s, ']')) {
                        if (js_peek(s, ',')) { s->pos++; continue; }
                        uint64_t bv = parse_base_obj(s);
                        if (ncols < MAXCOL) fx->inp_row[q][ncols] = gold_fp_from_u64(bv);
                        ncols++;
                    }
                    while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
                } else if (strcmp(bk, "opening_proof") == 0) {
                    js_match(s, '[');
                    while (!js_match(s, ']')) {
                        if (js_peek(s, ',')) { s->pos++; continue; }
                        if (nsib < MAXSIB) parse_lanes_digest(s, &fx->inp_sib[q][nsib]);
                        else js_skip_value(s);
                        nsib++;
                    }
                } else {
                    js_skip_value(s);
                }
                free(bk);
            }
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; } js_skip_value(s); }
            fx->inp_rowptr[q][0] = fx->inp_row[q];
            fx->inp_lens[q][0] = ncols;
            fx->bo[q].opened_values = fx->inp_rowptr[q];
            fx->bo[q].opened_values_lens = fx->inp_lens[q];
            fx->bo[q].num_matrices = 1;
            fx->bo[q].opening_proof.leaf_index = 0;
            fx->bo[q].opening_proof.depth = (uint32_t)nsib;
            fx->bo[q].opening_proof.num_matrices = 1;
            fx->bo[q].opening_proof.siblings = fx->inp_sib[q];
        } else if (strcmp(k, "commit_phase_openings") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                parse_cpo(s, fx, q, ncpo);
                ncpo++;
            }
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    fx->qp[q].input_proof = &fx->bo[q];
    fx->qp[q].num_input_batches = 1;
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
        if (strcmp(k, "log_blowup") == 0) fx->params.log_blowup = v;
        else if (strcmp(k, "log_final_poly_len") == 0) fx->params.log_final_poly_len = v;
        else if (strcmp(k, "max_log_arity") == 0) fx->params.max_log_arity = v;
        else if (strcmp(k, "num_queries") == 0) fx->params.num_queries = v;
        else if (strcmp(k, "commit_proof_of_work_bits") == 0) fx->params.commit_proof_of_work_bits = v;
        else if (strcmp(k, "query_proof_of_work_bits") == 0) fx->params.query_proof_of_work_bits = v;
        free(k);
    }
}

static void parse_proof(js_t *s, fx_t *fx) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (strcmp(k, "commit_phase_commits") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                if (n < MAXR) parse_commit_digest(s, &fx->commits[n]); else js_skip_value(s); n++; }
            fx->num_commits = n;
        } else if (strcmp(k, "commit_pow_witnesses") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                uint64_t bv = parse_base_obj(s); if (n < MAXR) fx->witnesses[n] = gold_fp_from_u64(bv); n++; }
        } else if (strcmp(k, "final_poly") == 0) {
            size_t n = 0; js_match(s, '[');
            while (!js_match(s, ']')) { if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t fv = parse_fp2_wrapped(s); if (n < MAXCOL) fx->final_poly[n] = fv; n++; }
            fx->num_final_poly = n;
        } else if (strcmp(k, "query_pow_witness") == 0) {
            fx->qpow = gold_fp_from_u64(parse_base_obj(s));
        } else if (strcmp(k, "query_proofs") == 0) {
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

/* opened_values_serde = [[[[ fp2, fp2 ]]]] -> claimed[] */
static void parse_opened_values_serde(js_t *s, fx_t *fx) {
    js_match(s, '['); js_match(s, '['); js_match(s, '['); /* batch, matrix, point */
    js_match(s, '[');                                     /* evals array */
    size_t n = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        gold_fp2_t fv = parse_fp2_wrapped(s);
        if (n < MAXCOL) fx->claimed[n] = fv;
        n++;
    }
    fx->num_claimed = n;
    js_match(s, ']'); js_match(s, ']'); js_match(s, ']');
}

static void load_seed(const char *path, fx_t *fx) {
    size_t blen = 0; char *blob = slurp(path, &blen);
    if (!blob) return;
    js_t s = { blob, 0, blen };
    js_match(&s, '{');
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); js_match(&s, ':');
        if (strcmp(k, "milestones") == 0) {
            js_match(&s, '[');
            /* milestone 0 only */
            js_match(&s, '{');
            while (!js_match(&s, '}')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                char *mk = js_read_string(&s); js_match(&s, ':');
                if (strcmp(mk, "transcript") == 0) {
                    /* P1c: duplex state triple (old byte-hex keys skipped). */
                    js_match(&s, '{');
                    while (!js_match(&s, '}')) {
                        if (js_peek(&s, ',')) { s.pos++; continue; }
                        char *tk = js_read_string(&s); js_match(&s, ':');
                        if (strcmp(tk, "sponge_state") == 0) {
                            uint64_t st[8] = {0};
                            if (read_u64_array(&s, st, 8) == 8) {
                                for (int i = 0; i < 8; ++i) fx->primed.sponge_state[i] = st[i];
                                fx->have_primed = 1;
                            }
                        } else if (strcmp(tk, "input_buffer") == 0) {
                            uint64_t ib[4] = {0};
                            int n = read_u64_array(&s, ib, 4);
                            if (n >= 0 && n <= 4) {
                                for (int i = 0; i < n; ++i) fx->primed.input_buffer[i] = ib[i];
                                fx->primed.input_len = (size_t)n;
                            }
                        } else if (strcmp(tk, "output_buffer") == 0) {
                            uint64_t ob[4] = {0};
                            int n = read_u64_array(&s, ob, 4);
                            if (n >= 0 && n <= 4) {
                                for (int i = 0; i < n; ++i) fx->primed.output_buffer[i] = ob[i];
                                fx->primed.output_len = (size_t)n;
                            }
                        } else js_skip_value(&s);
                        free(tk);
                    }
                } else js_skip_value(&s);
                free(mk);
            }
            /* The REST of the milestones: harvest each sample_bits milestone's
             * result.sampled_index. These are the oracle's query indices; they
             * are challenger-derived, so S2'-b moved them (they were {8,8}
             * against the P1c-era vector). Read them rather than hardcoding, so
             * this test keeps its OWN pin instead of trusting F4's. */
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (!js_peek(&s, '{')) { js_skip_value(&s); continue; }
                js_match(&s, '{');
                while (!js_match(&s, '}')) {
                    if (js_peek(&s, ',')) { s.pos++; continue; }
                    char *mk2 = js_read_string(&s); js_match(&s, ':');
                    if (mk2 && strcmp(mk2, "result") == 0 && js_peek(&s, '{')) {
                        js_match(&s, '{');
                        while (!js_match(&s, '}')) {
                            if (js_peek(&s, ',')) { s.pos++; continue; }
                            char *rk = js_read_string(&s); js_match(&s, ':');
                            if (rk && strcmp(rk, "sampled_index") == 0) {
                                uint64_t v = 0;
                                if (js_read_u64(&s, &v) && fx->exp_qi_n < 4)
                                    fx->exp_qi[fx->exp_qi_n++] = v;
                            } else js_skip_value(&s);
                            free(rk);
                        }
                    } else js_skip_value(&s);
                    free(mk2);
                }
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);
}


/* Read v6_honest_query_0.eval_fp2 from fri_verifier_terminal_horner.json, which
 * lives beside the milestones vector passed as argv[2]. Deliberately reads the
 * value instead of duplicating it: the same number is oracle-gated by F6
 * (test_fri_verifier_terminal_horner, 173/173), so there is exactly one source
 * of truth and a regeneration cannot leave this test asserting a stale one.
 *
 * ⚠ THE SEARCH RUNS BACKWARD ON PURPOSE. serde emits object keys in ALPHABETICAL
 * order, so within a case `"eval_fp2"` comes BEFORE `"name"`. Searching FORWARD
 * from the name landed 531 bytes later, inside the NEXT case object
 * (v6_honest_query_1, domain_index 14) — it only appeared to work because both
 * v6 honest queries carry the identical eval (this fixture's final_poly has a
 * single coefficient, so the Horner eval is constant in the terminal point).
 * With final_poly_len > 1 that would silently assert the wrong query's value.
 * So: find the name, then take the NEAREST PRECEDING "eval_fp2", which is the
 * one inside the same object. The leading quote also keeps this from matching
 * "corrupted_eval_fp2" (preceded by '_', not '"'). */
static bool load_v6_honest_eval(const char *milestones_path, gold_fp2_t *out) {
    const char *slash = strrchr(milestones_path, '/');
    const size_t dlen = slash ? (size_t)(slash - milestones_path) + 1 : 0;
    char path[1024];
    if (dlen + 40 >= sizeof path) return false;
    memcpy(path, milestones_path, dlen);
    memcpy(path + dlen, "fri_verifier_terminal_horner.json", 34);
    size_t blen = 0;
    char *blob = slurp(path, &blen);
    if (!blob) return false;
    bool ok = false;
    const char *name = strstr(blob, "\"v6_honest_query_0\"");
    if (name) {
        /* nearest "eval_fp2" strictly BEFORE the name => same object */
        const char *ev = NULL;
        for (const char *p = strstr(blob, "\"eval_fp2\"");
             p && p < name;
             p = strstr(p + 1, "\"eval_fp2\"")) {
            ev = p;
        }
        if (ev) {
            const char *c0 = strstr(ev, "\"c0_decimal\"");
            const char *c1 = c0 ? strstr(c0, "\"c1_decimal\"") : NULL;
            if (c0 && c1 && c0 < name && c1 < name) {
                const char *q0 = strchr(c0 + 12, '"');
                const char *q1 = strchr(c1 + 12, '"');
                if (q0 && q1) {
                    *out = gold_fp2_new(
                        gold_fp_from_u64((uint64_t)strtoull(q0 + 1, NULL, 10)),
                        gold_fp_from_u64((uint64_t)strtoull(q1 + 1, NULL, 10)));
                    ok = true;
                }
            }
        }
    }
    free(blob);
    return ok;
}

/* Run the integrated verifier on fx with a fresh transcript seeded to milestone-0. */
/* S2'-d: the query-domain point x the verifier derives for the fixture's single
 * matrix, re-derived here INDEPENDENTLY of fri_verifier.c (which keeps its own
 * static helpers) so that setting the opening point z := x reproduces the
 * degenerate `z == x` case upstream calls OpeningPointMatchesQueryPoint.
 *
 *   x = GENERATOR * two_adic_generator(log_height)^rev            [:614-615]
 *   rev = reverse_bits_len(index >> (lgmh - log_height), log_height)
 *
 * The V6 fixture has ONE matrix and both queries land on the same index (the
 * test prints query_index = {8, 8}), and that matrix sits at the global max
 * height, so bits_reduced is 0 and one x covers the whole run. */
static gold_fp2_t fx_query_x(const fx_t *fx) {
    size_t sum_la = 0;
    for (size_t r = 0; r < fx->qp[0].num_commit_phase_openings; ++r) {
        sum_la += (size_t)fx->qp[0].commit_phase_openings[r].log_arity;
    }
    const size_t lgmh = sum_la + fx->params.log_blowup +
                        fx->params.log_final_poly_len;
    const size_t log_height =
        (size_t)fx->matrix0.domain.log_size + fx->params.log_blowup;
    /* The fixture's query index, taken from the oracle's recorded
     * result.sampled_index rather than a literal — S2'-b moved it from 8 to 0,
     * and a stale literal here silently stops reproducing z == x, which turns
     * this ERRCHK into a false negative instead of a failure. */
    const uint64_t index = (fx->exp_qi_n > 0) ? fx->exp_qi[0] : 0;
    uint64_t v = index >> (lgmh - log_height);
    uint64_t rev = 0;
    for (unsigned b = 0; b < (unsigned)log_height; ++b) {
        rev = (rev << 1) | ((v >> b) & 1u);
    }
    gold_fp_t x = gold_fp_mul(
        gold_fp_from_u64(7), /* Goldilocks GENERATOR (fri_verifier.c) */
        gold_fp_pow(gold_fp_two_adic_generator((unsigned)log_height), rev));
    return gold_fp2_from_base(x);
}

static dnac_fri_status_t run_verify(fx_t *fx) {
    dnac_transcript_t *t = mk_primed(fx);
    if (!t) return (dnac_fri_status_t)0xBEEF;
    dnac_fri_status_t st = dnac_fri_verify(&fx->params, &fx->proof, t, &fx->cwop, 1);
    dnac_transcript_free(t);
    return st;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <fri_verifier_valid.json> <fri_verifier_transcript_milestones.json>\n", argv[0]);
        return 2;
    }
    printf("============================================================\n");
    printf("F7 — integrated FRI verifier, V6 valid proof (Plonky3 82cfad73)\n");
    printf("     verify_fri / open_input / verify_query / terminal Horner\n");
    printf("============================================================\n");

    fx_t *fx = (fx_t *)calloc(1, sizeof *fx);
    if (!fx) return 2;

    size_t blen = 0; char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    js_match(&s, '{');
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); js_match(&s, ':');
        if (strcmp(k, "fri_params") == 0) parse_params(&s, fx);
        else if (strcmp(k, "proof") == 0) parse_proof(&s, fx);
        else if (strcmp(k, "commitment_serde") == 0) parse_commit_digest(&s, &fx->cwop.commitment);
        else if (strcmp(k, "opened_values_serde") == 0) parse_opened_values_serde(&s, fx);
        else if (strcmp(k, "transcript_zeta_fp2") == 0) fx->point0.point = parse_fp2_decimal(&s);
        else if (strcmp(k, "fixture") == 0) {
            js_match(&s, '{');
            while (!js_match(&s, '}')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                char *fk = js_read_string(&s); js_match(&s, ':');
                if (strcmp(fk, "log_degree") == 0) js_read_u64(&s, &fx->domain_log_size);
                else js_skip_value(&s);
                free(fk);
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);

    load_seed(argv[2], fx);

    /* wire proof struct */
    fx->proof.commit_phase_commits = fx->commits;
    fx->proof.num_commit_phase_commits = fx->num_commits;
    fx->proof.commit_pow_witnesses = fx->witnesses;
    fx->proof.num_commit_pow_witnesses = fx->num_commits;
    fx->proof.query_proofs = fx->qp;
    fx->proof.num_query_proofs = fx->num_queries;
    fx->proof.final_poly = fx->final_poly;
    fx->proof.num_final_poly = fx->num_final_poly;
    fx->proof.query_pow_witness = fx->qpow;

    /* wire commitments_with_opening_points (1 batch, 1 matrix, 1 point) */
    fx->point0.claimed_evals = fx->claimed;
    fx->point0.num_claimed_evals = fx->num_claimed;
    fx->matrix0.domain.log_size = (size_t)fx->domain_log_size;
    fx->matrix0.points = &fx->point0;
    fx->matrix0.num_points = 1;
    fx->cwop.matrices = &fx->matrix0;
    fx->cwop.num_matrices = 1;

    /* sanity on parse */
    if (fx->num_commits != 3 || fx->num_queries != 2 || fx->num_final_poly != 1 ||
        fx->num_claimed != 2 || !fx->have_primed || fx->domain_log_size != 3) {
        printf("FAIL parse: commits=%zu queries=%zu final_poly=%zu claimed=%zu primed=%d domain_log=%llu\n",
               fx->num_commits, fx->num_queries, fx->num_final_poly, fx->num_claimed,
               fx->have_primed, (unsigned long long)fx->domain_log_size);
        free(fx); return 1;
    }

    /* seed transcript to milestone-0 primed state, run integrated verify */
    dnac_transcript_t *t = mk_primed(fx);
    if (!t) { printf("FAIL transcript init\n"); free(fx); return 1; }

    dnac_fri_debug_t dbg;
    memset(&dbg, 0, sizeof dbg);
    dnac_fri_status_t st = dnac_fri_test_verify_capture(&fx->params, &fx->proof, t,
                                                        &fx->cwop, 1, &dbg);
    dnac_transcript_free(t);

    /* The honest terminal folded eval, READ from the regenerated terminal-horner
     * fixture's v6_honest_query_0 eval_fp2 rather than pinned as a literal.
     * It is challenger-derived, so S2'-b moved it; a hardcoded pair silently
     * re-asserts the OLD challenger, which is exactly the trap the query-index
     * literals above turned out to be. Path is taken from argv[2]'s directory
     * so no CWD assumption and no Makefile change is needed.
     *
     * Both v6 queries share one value because this fixture's final_poly has a
     * single coefficient — the Horner eval is then constant in the terminal
     * point, so it does not depend on which index each query landed on. */
    gold_fp2_t want_folded;
    if (!load_v6_honest_eval(argv[2], &want_folded)) {
        fprintf(stderr, "cannot read v6_honest_query_0 eval_fp2 from the "
                        "terminal-horner vector beside %s\n", argv[2]);
        return 2;
    }

    printf("  dnac_fri_verify -> %d (want %d=DNAC_FRI_OK)\n", (int)st, (int)DNAC_FRI_OK);
    printf("  query_index   = {%llu, %llu} (want {%llu, %llu} — from the vector)\n",
           (unsigned long long)dbg.query_index[0], (unsigned long long)dbg.query_index[1],
           (unsigned long long)fx->exp_qi[0], (unsigned long long)fx->exp_qi[1]);
    printf("  reduced_index = {%llu, %llu} (want the same)\n",
           (unsigned long long)dbg.reduced_index[0], (unsigned long long)dbg.reduced_index[1]);
    printf("  folded_eval[0]==folded_eval[1]==honest: %s / %s\n",
           gold_fp2_eq(dbg.folded_eval[0], want_folded) ? "yes" : "no",
           gold_fp2_eq(dbg.folded_eval[1], want_folded) ? "yes" : "no");

    int v6_ok = (st == DNAC_FRI_OK)
          && (fx->exp_qi_n == 2)
          && (dbg.query_index[0] == fx->exp_qi[0])
          && (dbg.query_index[1] == fx->exp_qi[1])
          /* This fixture's single matrix sits AT the global max height, so
           * bits_reduced is 0 and reduced_index is the query index unchanged
           * (verifier.rs:576-580). Asserted as that invariant rather than as
           * the literal {8,8} the P1c-era vector happened to produce. */
          && (dbg.reduced_index[0] == fx->exp_qi[0])
          && (dbg.reduced_index[1] == fx->exp_qi[1])
          && gold_fp2_eq(dbg.folded_eval[0], want_folded)
          && gold_fp2_eq(dbg.folded_eval[1], want_folded);

    /* ---- Error replay: public verify_fri errors reachable through the
     * integrated path, driven by mutating the parsed V6 (each reverts after).
     * Names mirror tools/vectors/fri_verifier_errors.json public_verify_fri. ---- */
    printf("  --- integrated public error vectors ---\n");
    int errs_run = 0, errs_pass = 0;
    #define ERRCHK(label, mut, rev, want) do {                                  \
        mut; dnac_fri_status_t es = run_verify(fx); rev; errs_run++;            \
        if (es == (want)) { errs_pass++; printf("  [ERR OK ] %-34s -> %d\n", label, (int)es); } \
        else printf("  [ERR FAIL] %-33s got=%d want=%d\n", label, (int)es, (int)(want)); \
    } while (0)

    ERRCHK("InputProofBatchCountMismatch",
           fx->qp[0].num_input_batches = 2, fx->qp[0].num_input_batches = 1,
           DNAC_FRI_ERR_INPUT_PROOF_BATCH_COUNT_MISMATCH);
    /* S2'-d: the two guards added with the v0.6.2 variant mirror. Both were
     * fail-OPEN before — the first left an unauthenticated row width in the
     * flat MMCS leaf, the second silently dropped a matrix's whole claim
     * because gold_fp_inv(0) returns 0 rather than trapping. */
    ERRCHK("MatrixWithoutOpeningPoints",
           fx->matrix0.num_points = 0, fx->matrix0.num_points = 1,
           DNAC_FRI_ERR_MATRIX_WITHOUT_OPENING_POINTS);
    {
        const gold_fp2_t z_save = fx->point0.point;
        ERRCHK("OpeningPointMatchesQueryPoint",
               fx->point0.point = fx_query_x(fx), fx->point0.point = z_save,
               DNAC_FRI_ERR_OPENING_POINT_MATCHES_QUERY_POINT);
    }
    ERRCHK("BatchOpenedValuesCountMismatch",
           fx->bo[0].num_matrices = 2, fx->bo[0].num_matrices = 1,
           DNAC_FRI_ERR_BATCH_OPENED_VALUES_COUNT_MISMATCH);
    /* S2'-f (option A): this mutation now surfaces as the MMCS WrongWidth class
     * (InputError), NOT PointEvaluationCountMismatch. v0.6.2 pins the matrix
     * width to the FIRST opening point's claimed evaluation count
     * (fri/src/verifier.rs:695-712) and check_widths rejects BEFORE any hashing
     * (mmcs/geometry.rs:16-30, called at mmcs/batch.rs:184), so mismatching
     * point 0's count trips the width pin first. The regenerated
     * fri_verifier_errors.json case 10 records exactly this transition.
     * Both REJECT; only the variant moved.
     *
     * COVERAGE NOTE, stated rather than hidden: upstream KEEPS
     * PointEvaluationCountMismatch reachable for opening points 1..N-1, whose
     * counts do not pin the width (v0.6.2 verifier.rs:749-757). This fixture
     * has a SINGLE opening point and so can no longer express that path; the
     * variant is listed as deferred below rather than left looking tested. */
    ERRCHK("WrongWidth (width pin; was PointEvaluationCountMismatch)",
           fx->point0.num_claimed_evals = 3, fx->point0.num_claimed_evals = 2,
           DNAC_FRI_ERR_INPUT_ERROR);
    ERRCHK("SiblingValuesLengthMismatch",
           fx->cpo[0][0].num_sibling_values = 2, fx->cpo[0][0].num_sibling_values = 1,
           DNAC_FRI_ERR_SIBLING_VALUES_LENGTH_MISMATCH);
    ERRCHK("CommitPhaseMmcsError",
           fx->cpo_psib[0][0][0].lanes[0] ^= 1, fx->cpo_psib[0][0][0].lanes[0] ^= 1,
           DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR);
    ERRCHK("InputError",
           fx->inp_sib[0][0].lanes[0] ^= 1, fx->inp_sib[0][0].lanes[0] ^= 1,
           DNAC_FRI_ERR_INPUT_ERROR);
    #undef ERRCHK

    free(fx);
    int errs_ok = (errs_run == 8) && (errs_pass == 8);

    printf("------------------------------------------------------------\n");
    printf("  V6 end-to-end: %s | integrated error vectors: %d/%d\n",
           v6_ok ? "OK" : "FAIL", errs_pass, errs_run);
    printf("  error coverage: 8 integrated (here, incl. the 2 S2'-d guards) + 6 shape\n");
    printf("                  (F3) + 3 verify_query isolated (F5) + 1 FinalPolyMismatch\n");
    printf("                  horner (F6); deferred: InvalidPowWitness (V6 PoW=0),\n");
    printf("                  PointEvaluationCountMismatch (S2'-f: needs a matrix\n");
    printf("                  opened at >=2 points; point 0 trips the width pin),\n");
    printf("                  MissingInitialReducedOpening (needs empty input)\n");
    if (v6_ok && errs_ok) {
        printf("F7 INTEGRATED GATE: GREEN — V6 verifies end-to-end + 8/8 public errors\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F7 INTEGRATED GATE: RED\n");
    return 1;
}
