/**
 * @file test_fri_verifier_valid.c
 * @brief F7 integrated oracle test — V6 valid proof end-to-end acceptance.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Parses the locked V6 valid proof + commitments_with_opening_points from
 * tools/vectors/fri_verifier_valid.json, seeds a transcript to the captured
 * "top of verify_fri" primed state (milestone 0 of
 * tools/vectors/fri_verifier_transcript_milestones.json — priming is the PCS
 * caller's job, out of FRI scope), then runs the full integrated verifier via
 * dnac_fri_test_verify_capture and asserts:
 *   - dnac_fri_verify returns DNAC_FRI_OK (V6 verifies end-to-end);
 *   - query indices == {3, 12}        (F4 milestones / sample_bits)
 *   - reduced_index == {3, 12}        (F5 mmcs_calls input entries)
 *   - folded_eval[q] == {1177090699887663533, 15646686859640359525}
 *                                     (F6 honest eval == folded_eval)
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

/* ===== value parsers for V6 serde shapes ===== */
static void put_u64_le(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }

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
        if (strcmp(k, "cap") == 0) {
            js_match(s, '[');               /* outer cap array */
            parse_lanes_digest(s, out);     /* first row [8 u64] */
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
        if (strcmp(k, "value") == 0) js_read_u64(s, &r);
        else js_skip_value(s);
        free(k);
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
    dnac_merkle_digest_t commits[MAXR];
    gold_fp_t  witnesses[MAXR];
    gold_fp2_t final_poly[MAXCOL];
    size_t     num_final_poly;
    size_t     num_commits;
    gold_fp_t  qpow;

    gold_fp_t  inp_row[MAXQ][MAXCOL];
    const gold_fp_t *inp_rowptr[MAXQ][1];
    size_t     inp_lens[MAXQ][1];
    dnac_merkle_digest_t inp_sib[MAXQ][MAXSIB];
    dnac_fri_batch_opening_t bo[MAXQ];

    gold_fp2_t cpo_sib[MAXQ][MAXR][MAXSIB];
    dnac_merkle_digest_t cpo_psib[MAXQ][MAXR][MAXSIB];
    dnac_fri_commit_phase_proof_step_t cpo[MAXQ][MAXR];
    dnac_fri_query_proof_t qp[MAXQ];
    size_t num_queries;

    dnac_fri_proof_t proof;

    gold_fp2_t claimed[MAXCOL]; size_t num_claimed;
    dnac_fri_opening_point_t point0;
    dnac_fri_matrix_openings_t matrix0;
    dnac_fri_commitment_with_opening_points_t cwop;
    uint64_t domain_log_size;

    uint8_t seed[256]; size_t seed_len;
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
                if (npsib < MAXSIB) parse_lanes_digest(s, fx->cpo_psib[q][r][npsib].bytes);
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
                        if (nsib < MAXSIB) parse_lanes_digest(s, fx->inp_sib[q][nsib].bytes);
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
                if (n < MAXR) parse_commit_digest(s, fx->commits[n].bytes); else js_skip_value(s); n++; }
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
                    js_match(&s, '{');
                    while (!js_match(&s, '}')) {
                        if (js_peek(&s, ',')) { s.pos++; continue; }
                        char *tk = js_read_string(&s); js_match(&s, ':');
                        if (strcmp(tk, "input_buf_hex") == 0) {
                            char *h = js_read_string(&s);
                            if (h) { fx->seed_len = hex_decode(h, fx->seed, sizeof fx->seed); free(h); }
                        } else js_skip_value(&s);
                        free(tk);
                    }
                } else js_skip_value(&s);
                free(mk);
            }
            /* skip the rest of the milestones array */
            while (!js_match(&s, ']')) { if (js_peek(&s, ',')) { s.pos++; continue; } js_skip_value(&s); }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);
}

/* Run the integrated verifier on fx with a fresh transcript seeded to milestone-0. */
static dnac_fri_status_t run_verify(fx_t *fx) {
    dnac_transcript_t *t = dnac_transcript_init(fx->seed, fx->seed_len);
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
        else if (strcmp(k, "commitment_serde") == 0) parse_commit_digest(&s, fx->cwop.commitment.bytes);
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
        fx->num_claimed != 2 || fx->seed_len != 96 || fx->domain_log_size != 3) {
        printf("FAIL parse: commits=%zu queries=%zu final_poly=%zu claimed=%zu seed=%zu domain_log=%llu\n",
               fx->num_commits, fx->num_queries, fx->num_final_poly, fx->num_claimed,
               fx->seed_len, (unsigned long long)fx->domain_log_size);
        free(fx); return 1;
    }

    /* seed transcript to milestone-0 primed state, run integrated verify */
    dnac_transcript_t *t = dnac_transcript_init(fx->seed, fx->seed_len);
    if (!t) { printf("FAIL transcript init\n"); free(fx); return 1; }

    dnac_fri_debug_t dbg;
    memset(&dbg, 0, sizeof dbg);
    dnac_fri_status_t st = dnac_fri_test_verify_capture(&fx->params, &fx->proof, t,
                                                        &fx->cwop, 1, &dbg);
    dnac_transcript_free(t);

    gold_fp2_t want_folded = gold_fp2_new(gold_fp_from_u64(1177090699887663533ULL),
                                          gold_fp_from_u64(15646686859640359525ULL));

    printf("  dnac_fri_verify -> %d (want %d=DNAC_FRI_OK)\n", (int)st, (int)DNAC_FRI_OK);
    printf("  query_index   = {%llu, %llu} (want {3, 12})\n",
           (unsigned long long)dbg.query_index[0], (unsigned long long)dbg.query_index[1]);
    printf("  reduced_index = {%llu, %llu} (want {3, 12})\n",
           (unsigned long long)dbg.reduced_index[0], (unsigned long long)dbg.reduced_index[1]);
    printf("  folded_eval[0]==folded_eval[1]==honest: %s / %s\n",
           gold_fp2_eq(dbg.folded_eval[0], want_folded) ? "yes" : "no",
           gold_fp2_eq(dbg.folded_eval[1], want_folded) ? "yes" : "no");

    int v6_ok = (st == DNAC_FRI_OK)
          && (dbg.query_index[0] == 3) && (dbg.query_index[1] == 12)
          && (dbg.reduced_index[0] == 3) && (dbg.reduced_index[1] == 12)
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
    ERRCHK("BatchOpenedValuesCountMismatch",
           fx->bo[0].num_matrices = 2, fx->bo[0].num_matrices = 1,
           DNAC_FRI_ERR_BATCH_OPENED_VALUES_COUNT_MISMATCH);
    ERRCHK("PointEvaluationCountMismatch",
           fx->point0.num_claimed_evals = 3, fx->point0.num_claimed_evals = 2,
           DNAC_FRI_ERR_POINT_EVALUATION_COUNT_MISMATCH);
    ERRCHK("SiblingValuesLengthMismatch",
           fx->cpo[0][0].num_sibling_values = 2, fx->cpo[0][0].num_sibling_values = 1,
           DNAC_FRI_ERR_SIBLING_VALUES_LENGTH_MISMATCH);
    ERRCHK("CommitPhaseMmcsError",
           fx->cpo_psib[0][0][0].bytes[0] ^= 1, fx->cpo_psib[0][0][0].bytes[0] ^= 1,
           DNAC_FRI_ERR_COMMIT_PHASE_MMCS_ERROR);
    ERRCHK("InputError",
           fx->inp_sib[0][0].bytes[0] ^= 1, fx->inp_sib[0][0].bytes[0] ^= 1,
           DNAC_FRI_ERR_INPUT_ERROR);
    #undef ERRCHK

    free(fx);
    int errs_ok = (errs_run == 6) && (errs_pass == 6);

    printf("------------------------------------------------------------\n");
    printf("  V6 end-to-end: %s | integrated error vectors: %d/%d\n",
           v6_ok ? "OK" : "FAIL", errs_pass, errs_run);
    printf("  error coverage: 6 integrated (here) + 6 shape (F3) + 3 verify_query\n");
    printf("                  isolated (F5) + 1 FinalPolyMismatch horner (F6) = 16/19;\n");
    printf("                  deferred: InvalidPowWitness (V6 PoW=0), MissingInitialReducedOpening\n");
    printf("                  (needs empty input); not-reachable: InvalidProofShape (hiding-pcs)\n");
    if (v6_ok && errs_ok) {
        printf("F7 INTEGRATED GATE: GREEN — V6 verifies end-to-end + 6/6 public errors\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F7 INTEGRATED GATE: RED\n");
    return 1;
}
