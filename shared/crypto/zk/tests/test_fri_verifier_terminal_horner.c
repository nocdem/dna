/**
 * @file test_fri_verifier_terminal_horner.c
 * @brief F6 oracle test — terminal final-polynomial Horner evaluation.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Loads tools/vectors/fri_verifier_terminal_horner.json (173 cases) and replays
 * each through dnac_fri_test_terminal_horner_eval (mirror of verifier.rs:308-321):
 *   - 172 standard cases (v6_honest, v6_corrupted, deterministic_sweep): assert
 *     reverse_bits_len, x, and the Horner eval all byte-match the oracle.
 *   - 1 D7-trap case: call the helper twice — with log_global_max_height (correct)
 *     and with log_final_height (wrong) — and assert x_correct/eval_correct vs
 *     x_wrong/eval_wrong match AND differ. This pins design § M1 D7 (x must come
 *     from log_global_max_height, never log_final_height).
 *
 * Also exercises Part B (dnac_fri_test_terminal_horner_check): honest eval vs
 * itself -> OK; corrupted eval vs honest eval -> FinalPolyMismatch.
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
#include "zk_field_helpers.h"  /* reverse_bits_len_u64 (cross-check vs helper) */

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

/* ===== fp2 parsing ===== */
static uint64_t read_decimal_string(js_t *s) {
    char *v = js_read_string(s);
    uint64_t r = v ? strtoull(v, NULL, 10) : 0;
    free(v);
    return r;
}
/* { "c0_decimal":"..", "c1_decimal":".." } */
static gold_fp2_t parse_fp2(js_t *s) {
    uint64_t c0 = 0, c1 = 0;
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (js_peek(s, '"')) {
            uint64_t val = read_decimal_string(s);
            if (k && strcmp(k, "c0_decimal") == 0) c0 = val;
            else if (k && strcmp(k, "c1_decimal") == 0) c1 = val;
        } else {
            js_skip_value(s);
        }
        free(k);
    }
    return gold_fp2_new(gold_fp_from_u64(c0), gold_fp_from_u64(c1));
}
static size_t parse_fp2_array(js_t *s, gold_fp2_t *out, size_t cap) {
    size_t n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        gold_fp2_t v = parse_fp2(s);
        if (n < cap) out[n] = v;
        n++;
    }
    return n;
}

/* ===== Parsed case ===== */
#define MAXFP 64
typedef struct {
    char       category[40];
    char       name[64];
    uint64_t   domain_index;
    uint64_t   lgmh;
    uint64_t   log_final_height;     /* D7 only */
    gold_fp2_t final_poly[MAXFP];    size_t fp_len;
    /* standard */
    uint64_t   rbl_result;           uint64_t x_decimal;  gold_fp2_t eval;
    /* d7 */
    uint64_t   rbl_lgmh, rbl_lfh;    uint64_t x_correct, x_wrong;
    gold_fp2_t eval_correct, eval_wrong;
} hc_t;

static void parse_case(js_t *s, hc_t *c) {
    memset(c, 0, sizeof *c);
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (strcmp(k, "category") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->category, v, sizeof(c->category)-1); free(v);} }
        else if (strcmp(k, "name") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->name, v, sizeof(c->name)-1); free(v);} }
        else if (strcmp(k, "domain_index") == 0) js_read_u64(s, &c->domain_index);
        else if (strcmp(k, "log_global_max_height") == 0) js_read_u64(s, &c->lgmh);
        else if (strcmp(k, "log_final_height") == 0) js_read_u64(s, &c->log_final_height);
        else if (strcmp(k, "final_poly_len") == 0) { uint64_t t; js_read_u64(s, &t); }
        else if (strcmp(k, "reverse_bits_len_result") == 0) js_read_u64(s, &c->rbl_result);
        else if (strcmp(k, "reverse_bits_len_with_log_global_max_height") == 0) js_read_u64(s, &c->rbl_lgmh);
        else if (strcmp(k, "reverse_bits_len_with_log_final_height") == 0) js_read_u64(s, &c->rbl_lfh);
        else if (strcmp(k, "x_decimal") == 0) c->x_decimal = read_decimal_string(s);
        else if (strcmp(k, "x_correct_decimal") == 0) c->x_correct = read_decimal_string(s);
        else if (strcmp(k, "x_wrong_decimal") == 0) c->x_wrong = read_decimal_string(s);
        else if (strcmp(k, "final_poly_fp2") == 0) c->fp_len = parse_fp2_array(s, c->final_poly, MAXFP);
        else if (strcmp(k, "eval_fp2") == 0) c->eval = parse_fp2(s);
        else if (strcmp(k, "eval_correct_fp2") == 0) c->eval_correct = parse_fp2(s);
        else if (strcmp(k, "eval_wrong_fp2") == 0) c->eval_wrong = parse_fp2(s);
        else js_skip_value(s);
        free(k);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <fri_verifier_terminal_horner.json>\n", argv[0]); return 2; }
    printf("============================================================\n");
    printf("F6 — FRI terminal Horner / final-poly check (Plonky3 82cfad73)\n");
    printf("     verifier.rs:308-325\n");
    printf("============================================================\n");

    size_t blen = 0; char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    uint64_t h_total=0, h_honest=0, h_corrupt=0, h_d7=0, h_sweep=0; int saw=0;
    int parsed = 0, passed = 0, failed = 0, d7_done = 0;
    int have_honest = 0, have_corrupt = 0;
    gold_fp2_t honest_q0_eval = gold_fp2_zero(), corrupt_q0_eval = gold_fp2_zero();

    if (!js_match(&s, '{')) { fprintf(stderr, "bad json root\n"); return 2; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); if (!k) return 2;
        if (!js_match(&s, ':')) return 2;
        if (strcmp(k, "case_count_total") == 0) { js_read_u64(&s, &h_total); saw |= 1; }
        else if (strcmp(k, "case_count_v6_honest") == 0) { js_read_u64(&s, &h_honest); saw |= 2; }
        else if (strcmp(k, "case_count_v6_corrupted") == 0) { js_read_u64(&s, &h_corrupt); saw |= 4; }
        else if (strcmp(k, "case_count_d7_trap") == 0) { js_read_u64(&s, &h_d7); saw |= 8; }
        else if (strcmp(k, "case_count_deterministic_sweep") == 0) { js_read_u64(&s, &h_sweep); saw |= 16; }
        else if (strcmp(k, "cases") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                hc_t c; parse_case(&s, &c);
                parsed++;

                if (strcmp(c.category, "d7_trap_synthetic") == 0) {
                    /* correct path uses log_global_max_height */
                    gold_fp_t xc; gold_fp2_t ec = dnac_fri_test_terminal_horner_eval(
                        c.final_poly, c.fp_len, (size_t)c.lgmh, c.domain_index, &xc);
                    /* wrong path uses log_final_height (the D7 off-by-one) */
                    gold_fp_t xw; gold_fp2_t ew = dnac_fri_test_terminal_horner_eval(
                        c.final_poly, c.fp_len, (size_t)c.log_final_height, c.domain_index, &xw);
                    bool ok =
                        reverse_bits_len_u64(c.domain_index, (unsigned)c.lgmh) == c.rbl_lgmh &&
                        reverse_bits_len_u64(c.domain_index, (unsigned)c.log_final_height) == c.rbl_lfh &&
                        gold_fp_to_u64(xc) == c.x_correct &&
                        gold_fp_to_u64(xw) == c.x_wrong &&
                        gold_fp2_eq(ec, gold_fp2_new(gold_fp_from_u64(0),gold_fp_from_u64(0))) == false &&
                        gold_fp2_eq(ec, c.eval_correct) &&
                        gold_fp2_eq(ew, c.eval_wrong) &&
                        gold_fp_to_u64(xc) != gold_fp_to_u64(xw) &&     /* x_differs */
                        !gold_fp2_eq(ec, ew);                           /* eval_differs */
                    if (ok) { passed++; d7_done = 1; printf("  [OK ] %-34s D7 trap: x_correct(lgmh=%llu)!=x_wrong(lfh=%llu)\n", c.name, (unsigned long long)c.lgmh, (unsigned long long)c.log_final_height); }
                    else { failed++; printf("  [FAIL] %-34s D7 trap mismatch\n", c.name); }
                } else {
                    /* standard case */
                    gold_fp_t x; gold_fp2_t ev = dnac_fri_test_terminal_horner_eval(
                        c.final_poly, c.fp_len, (size_t)c.lgmh, c.domain_index, &x);
                    bool ok =
                        reverse_bits_len_u64(c.domain_index, (unsigned)c.lgmh) == c.rbl_result &&
                        gold_fp_to_u64(x) == c.x_decimal &&
                        gold_fp2_eq(ev, c.eval);
                    if (ok) {
                        passed++;
                        /* capture query_0 (domain_index 3) honest + corrupted evals for Part B */
                        if (strcmp(c.category, "v6_honest") == 0 && c.domain_index == 3) { honest_q0_eval = ev; have_honest = 1; }
                        if (strcmp(c.category, "v6_corrupted_final_poly_0") == 0 && c.domain_index == 3) { corrupt_q0_eval = ev; have_corrupt = 1; }
                    } else {
                        failed++;
                        printf("  [FAIL] %-34s rbl/x/eval mismatch (lgmh=%llu didx=%llu)\n",
                               c.name, (unsigned long long)c.lgmh, (unsigned long long)c.domain_index);
                    }
                }
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);

    /* Part B — FinalPolyMismatch comparison (verifier.rs:323-325). */
    int partB_ok = 0;
    if (have_honest && have_corrupt) {
        dnac_fri_status_t same = dnac_fri_test_terminal_horner_check(honest_q0_eval, honest_q0_eval);
        dnac_fri_status_t diff = dnac_fri_test_terminal_horner_check(corrupt_q0_eval, honest_q0_eval);
        partB_ok = (same == DNAC_FRI_OK) && (diff == DNAC_FRI_ERR_FINAL_POLY_MISMATCH);
        printf("  Part B: check(honest,honest)=%s  check(corrupt,honest)=%s\n",
               same == DNAC_FRI_OK ? "OK" : "ERR",
               diff == DNAC_FRI_ERR_FINAL_POLY_MISMATCH ? "FINAL_POLY_MISMATCH" : "??");
    }

    printf("------------------------------------------------------------\n");
    printf("  header: total=%llu honest=%llu corrupt=%llu d7=%llu sweep=%llu | parsed=%d passed=%d failed=%d\n",
           (unsigned long long)h_total, (unsigned long long)h_honest, (unsigned long long)h_corrupt,
           (unsigned long long)h_d7, (unsigned long long)h_sweep, parsed, passed, failed);

    int green = (saw == 31)
             && (h_total == 173) && (h_honest == 2) && (h_corrupt == 2) && (h_d7 == 1) && (h_sweep == 168)
             && (parsed == 173) && (passed == 173) && (failed == 0)
             && d7_done && partB_ok;
    if (green) {
        printf("F6 TERMINAL-HORNER GATE: GREEN — 173/173 cases byte-match Plonky3\n");
        printf("                         (D7 trap pins log_global_max_height; Part B mismatch OK)\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F6 TERMINAL-HORNER GATE: RED\n");
    return 1;
}
