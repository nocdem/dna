/**
 * @file test_fri_verifier_transcript.c
 * @brief F4 oracle test — verify_fri transcript-flow milestone replay.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Loads tools/vectors/fri_verifier_transcript_milestones.json (18 milestones),
 * seeds a transcript to the pre-primed milestone-0 state, then drives
 * dnac_fri_test_transcript_flow() and byte-compares the transcript buffer state
 * after every one of the 18 milestones (verifier.rs:143-268 Fiat-Shamir
 * sequence). The sampled-VALUE correctness of each primitive (sample_fp2,
 * sample_bits, observe_*) is already pinned by test_transcript_oracle; this test
 * pins the verify_fri SEQUENCE (which op, in what order, with what argument).
 *
 * Buffer-state alone cannot distinguish sample_bits(3) from sample_bits(4)
 * (same byte consumption, different mask), so we ALSO assert the flow's
 * log_global_max_height (== 4) and the masked query indices (== {3, 12}) — the
 * one value F5's open_input will consume.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define DNAC_FRI_TESTING 1        /* expose dnac_fri_test_transcript_flow */
#define DNAC_TRANSCRIPT_TESTING 1 /* expose transcript buffer snapshot hooks */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_verifier.h"   /* pulls transcript.h, field_goldilocks.h, merkle_smt.h */

/* ============================================================================
 * Minimal JSON scanner — same idiom as tests/test_merkle_mmcs.c.
 * ========================================================================== */

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
        char *k = js_read_string(s); if (!k) return false; free(k);
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
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp); buf[got] = '\0'; *out_len = got; return buf;
}

static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Decode hex string into buf (cap bytes). Returns byte length, or (size_t)-1. */
static size_t hex_decode(const char *hex, uint8_t *buf, size_t cap) {
    size_t hl = strlen(hex);
    if (hl % 2 != 0) return (size_t)-1;
    size_t n = hl / 2;
    if (n > cap) return (size_t)-1;
    for (size_t i = 0; i < n; ++i) {
        int hi = hexnib(hex[2*i]), lo = hexnib(hex[2*i+1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}
static void hex_print(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
}

/* ============================================================================
 * Parsed milestone + fixture data.
 * ========================================================================== */

#define BUFCAP 256
typedef struct {
    int     op_index;
    char    op_kind[48];
    uint8_t in[BUFCAP];  size_t in_len;
    uint8_t out[BUFCAP]; size_t out_len;
} ms_t;

#define MAX_COMMITS 8
typedef struct {
    ms_t     ms[18];
    int      ms_n;
    uint8_t  commits[MAX_COMMITS][DNAC_MERKLE_DIGEST_BYTES];
    int      commit_n;
    uint64_t fp_c0, fp_c1; int have_fp;
    /* fri_params */
    uint64_t log_blowup, log_final_poly_len, max_log_arity, num_queries,
             commit_pow, query_pow; int have_params;
} world_t;

/* Parse input_value_summary: pull commitment_bytes_hex / final_poly_fp2_decimal. */
static bool parse_ivs(js_t *s, world_t *w) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        if (strcmp(k, "commitment_bytes_hex") == 0) {
            char *h = js_read_string(s);
            if (h && w->commit_n < MAX_COMMITS) {
                hex_decode(h, w->commits[w->commit_n], DNAC_MERKLE_DIGEST_BYTES);
                w->commit_n++;
            }
            free(h);
        } else if (strcmp(k, "final_poly_fp2_decimal") == 0) {
            /* [ { "c0_decimal": "..", "c1_decimal": ".." } ] */
            js_match(s, '[');
            js_match(s, '{');
            while (!js_match(s, '}')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *fk = js_read_string(s); js_match(s, ':');
                char *fv = js_read_string(s);
                if (fv && strcmp(fk, "c0_decimal") == 0) { w->fp_c0 = strtoull(fv, NULL, 10); w->have_fp = 1; }
                else if (fv && strcmp(fk, "c1_decimal") == 0) { w->fp_c1 = strtoull(fv, NULL, 10); }
                free(fk); free(fv);
            }
            js_match(s, ']');
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

/* Parse transcript object: pull input_buf_hex / output_buf_remaining_hex. */
static bool parse_transcript(js_t *s, ms_t *m) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        if (strcmp(k, "input_buf_hex") == 0) {
            char *h = js_read_string(s);
            m->in_len = h ? hex_decode(h, m->in, BUFCAP) : 0;
            free(h);
        } else if (strcmp(k, "output_buf_remaining_hex") == 0) {
            char *h = js_read_string(s);
            m->out_len = h ? hex_decode(h, m->out, BUFCAP) : 0;
            free(h);
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}

static bool parse_milestone(js_t *s, world_t *w) {
    ms_t *m = &w->ms[w->ms_n];
    memset(m, 0, sizeof *m);
    m->op_index = w->ms_n;
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) { w->ms_n++; return true; }
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        if (strcmp(k, "op_index") == 0) { uint64_t v; js_read_u64(s, &v); m->op_index = (int)v; }
        else if (strcmp(k, "operation_kind") == 0) { char *v = js_read_string(s); if (v) { strncpy(m->op_kind, v, sizeof(m->op_kind)-1); free(v); } }
        else if (strcmp(k, "transcript") == 0) { if (!parse_transcript(s, m)) { free(k); return false; } }
        else if (strcmp(k, "input_value_summary") == 0) { if (!parse_ivs(s, w)) { free(k); return false; } }
        else js_skip_value(s);
        free(k);
    }
}

static bool parse_params(js_t *s, world_t *w) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) { w->have_params = 1; return true; }
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        uint64_t v = 0; js_read_u64(s, &v);
        if (strcmp(k, "log_blowup") == 0) w->log_blowup = v;
        else if (strcmp(k, "log_final_poly_len") == 0) w->log_final_poly_len = v;
        else if (strcmp(k, "max_log_arity") == 0) w->max_log_arity = v;
        else if (strcmp(k, "num_queries") == 0) w->num_queries = v;
        else if (strcmp(k, "commit_proof_of_work_bits") == 0) w->commit_pow = v;
        else if (strcmp(k, "query_proof_of_work_bits") == 0) w->query_pow = v;
        free(k);
    }
}

/* ============================================================================
 * Milestone-checking callback.
 * ========================================================================== */

typedef struct {
    world_t *w;
    int next;     /* next milestone op_index to check (starts at 1) */
    int fires;    /* callback fire count */
    int passed;   /* matched milestones (1..17) */
    int failed;
} cb_ctx_t;

static void check_snapshot(world_t *w, int i, const uint8_t *ib, size_t il,
                           const uint8_t *ob, size_t ol, int *passed, int *failed) {
    ms_t *m = &w->ms[i];
    bool ok = (il == m->in_len && memcmp(ib, m->in, il) == 0 &&
               ol == m->out_len && memcmp(ob, m->out, ol) == 0);
    if (ok) {
        (*passed)++;
        printf("  [%2d] %-34s OK\n", i, m->op_kind);
    } else {
        (*failed)++;
        const char *kind = (il != m->in_len || memcmp(ib, m->in, il < m->in_len ? il : m->in_len) != 0)
                           ? "input_buf (observe order/serialization)"
                           : "output_buf (sample order/consumption)";
        printf("  [%2d] %-34s MISMATCH (%s)\n", i, m->op_kind, kind);
        printf("       expected in[%zu]=", m->in_len); hex_print(m->in, m->in_len); printf("\n");
        printf("       actual   in[%zu]=", il);        hex_print(ib, il);          printf("\n");
        printf("       expected out[%zu]=", m->out_len); hex_print(m->out, m->out_len); printf("\n");
        printf("       actual   out[%zu]=", ol);          hex_print(ob, ol);            printf("\n");
    }
}

static void milestone_cb(void *vctx, dnac_transcript_t *t) {
    cb_ctx_t *c = (cb_ctx_t *)vctx;
    c->fires++;
    int i = c->next++;
    if (i >= c->w->ms_n) { c->failed++; return; }
    check_snapshot(c->w, i,
                   dnac_transcript_test_input_buf_ptr(t),
                   dnac_transcript_test_input_buf_len(t),
                   dnac_transcript_test_output_buf_ptr(t),
                   dnac_transcript_test_output_buf_remaining(t),
                   &c->passed, &c->failed);
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fri_verifier_transcript_milestones.json>\n", argv[0]);
        return 2;
    }
    printf("============================================================\n");
    printf("F4 — FRI verifier transcript flow (Plonky3 82cfad73)\n");
    printf("     verifier.rs:143-268 Fiat-Shamir sequence; MMCS/fold/\n");
    printf("     verify_query/Horner deferred to F5-F6\n");
    printf("============================================================\n");

    size_t blen = 0;
    char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    world_t *w = (world_t *)calloc(1, sizeof *w);
    if (!w) { return 2; }

    if (!js_match(&s, '{')) { fprintf(stderr, "bad json root\n"); return 2; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); if (!k) { fprintf(stderr, "bad key\n"); return 2; }
        if (!js_match(&s, ':')) { fprintf(stderr, "missing colon\n"); return 2; }
        if (strcmp(k, "fri_params") == 0) { if (!parse_params(&s, w)) return 2; }
        else if (strcmp(k, "milestones") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (w->ms_n >= 18) { fprintf(stderr, "too many milestones\n"); return 2; }
                if (!parse_milestone(&s, w)) { fprintf(stderr, "bad milestone\n"); return 2; }
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);

    /* Sanity: structure as expected. */
    if (w->ms_n != 18 || !w->have_params || w->commit_n != 3 || !w->have_fp) {
        printf("FAIL parse: ms_n=%d params=%d commits=%d have_fp=%d\n",
               w->ms_n, w->have_params, w->commit_n, w->have_fp);
        return 1;
    }

    /* Build the V6 proof fixture from parsed data (counts mirror fri_verifier_valid.json:
     * 3 commit rounds, 2 queries, 3 openings/query log_arity 1, final_poly len 1). */
    dnac_fri_params_t params;
    memset(&params, 0, sizeof params);
    params.log_blowup = (size_t)w->log_blowup;
    params.log_final_poly_len = (size_t)w->log_final_poly_len;
    params.max_log_arity = (size_t)w->max_log_arity;
    params.num_queries = (size_t)w->num_queries;
    params.commit_proof_of_work_bits = (size_t)w->commit_pow;
    params.query_proof_of_work_bits = (size_t)w->query_pow;

    dnac_merkle_digest_t commits[MAX_COMMITS];
    gold_fp_t witnesses[MAX_COMMITS];
    memset(commits, 0, sizeof commits);
    memset(witnesses, 0, sizeof witnesses);
    for (int r = 0; r < w->commit_n; ++r)
        memcpy(commits[r].bytes, w->commits[r], DNAC_MERKLE_DIGEST_BYTES);

    gold_fp2_t final_poly[1];
    final_poly[0] = gold_fp2_new(gold_fp_from_u64(w->fp_c0), gold_fp_from_u64(w->fp_c1));

    dnac_fri_commit_phase_proof_step_t openings[2][MAX_COMMITS];
    dnac_fri_query_proof_t qps[2];
    memset(openings, 0, sizeof openings);
    memset(qps, 0, sizeof qps);
    for (int q = 0; q < 2; ++q) {
        for (int r = 0; r < w->commit_n; ++r)
            openings[q][r].log_arity = 1; /* V6: log_arity 1 each (milestones 12-14) */
        qps[q].commit_phase_openings = openings[q];
        qps[q].num_commit_phase_openings = (size_t)w->commit_n;
    }

    dnac_fri_proof_t proof;
    memset(&proof, 0, sizeof proof);
    proof.commit_phase_commits = commits;
    proof.num_commit_phase_commits = (size_t)w->commit_n;
    proof.commit_pow_witnesses = witnesses;
    proof.num_commit_pow_witnesses = (size_t)w->commit_n;
    proof.query_proofs = qps;
    proof.num_query_proofs = 2;
    proof.final_poly = final_poly;
    proof.num_final_poly = 1;

    /* Seed the transcript to the pre-primed milestone-0 state. */
    dnac_transcript_t *t = dnac_transcript_init(w->ms[0].in, w->ms[0].in_len);
    if (!t) { printf("FAIL: transcript init\n"); return 1; }

    int passed = 0, failed = 0;
    /* Milestone 0 — verify the seed reproduces the primed state exactly. */
    check_snapshot(w, 0,
                   dnac_transcript_test_input_buf_ptr(t),
                   dnac_transcript_test_input_buf_len(t),
                   dnac_transcript_test_output_buf_ptr(t),
                   dnac_transcript_test_output_buf_remaining(t),
                   &passed, &failed);

    /* Run the verify_fri transcript flow; milestones 1..17 checked via callback. */
    cb_ctx_t ctx = { w, 1, 0, 0, 0 };
    dnac_fri_flow_out_t out;
    memset(&out, 0, sizeof out);
    dnac_fri_status_t err = (dnac_fri_status_t)0xDEAD; /* sentinel: must stay unset */
    bool completed = dnac_fri_test_transcript_flow(t, &params, &proof,
                                                   milestone_cb, &ctx, &out, &err);
    dnac_transcript_free(t);

    passed += ctx.passed;
    failed += ctx.failed;

    printf("------------------------------------------------------------\n");
    printf("  milestones matched: %d / 18 | callback fires: %d (want 17)\n",
           passed, ctx.fires);
    printf("  flow completed: %s | log_global_max_height: %zu (want 4)\n",
           completed ? "yes" : "no", out.log_global_max_height);
    printf("  query indices: ");
    for (size_t i = 0; i < out.num_query_indices; ++i) printf("%llu ", (unsigned long long)out.query_indices[i]);
    printf("(want 3 12)\n");

    int ok = (failed == 0)
          && (passed == 18)
          && (ctx.fires == 17)
          && completed
          && (err == (dnac_fri_status_t)0xDEAD)            /* no error path taken */
          && (out.log_global_max_height == 4)
          && (out.num_query_indices == 2)
          && (out.query_indices[0] == 3)
          && (out.query_indices[1] == 12);

    free(w);

    if (ok) {
        printf("F4 TRANSCRIPT GATE: GREEN — 18/18 milestones byte-match Plonky3,\n");
        printf("                    log_global_max_height + query indices pinned,\n");
        printf("                    no MMCS/fold/verify_query/Horner\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F4 TRANSCRIPT GATE: RED\n");
    return 1;
}
