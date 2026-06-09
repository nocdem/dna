/**
 * @file test_stark_verify_constraints.c
 * @brief S4: verify_constraints glue + FibonacciAir/SquareAir air_eval, end-to-end
 *        against the real-Plonky3 S2 vectors. FIRST C<->Plonky3 verify_constraints
 *        agreement.
 *
 *   argv[1] = stark_verify_constraints.json          (FibonacciAir, main_next=true)
 *   argv[2] = stark_verify_constraints_no_next.json  (SquareAir,    main_next=false)
 *
 * The two AIR callbacks are TEST fixtures (fib/square are not DNAC production AIRs);
 * the generic glue lives in stark_constraints.{c,h}. Per
 * docs/plans/2026-05-30-stark-constraint-check-implementation-design.md (S4).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "field_goldilocks.h"
#include "stark_constraints.h"

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
/* {c0_decimal:"..", c1_decimal:".."} -> fp2 */
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
static int parse_fp2_array(js_t *s, gold_fp2_t *out, int cap) {
    js_match(s, '[');
    int n = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        gold_fp2_t f = parse_fp2_decimal(s);
        if (n < cap) out[n] = f;
        n++;
    }
    return n;
}

/* ===== parsed vector ===== */
#define MAXW 256
#define MAXP 8
#define MAXC 16
typedef struct {
    uint64_t base_degree_bits, main_width, num_public_values;
    int main_next;
    int final_equal;
    gold_fp2_t zeta, alpha, quotient_zeta, folded;
    gold_fp2_t chunk0[2];
    int n_chunk0;
    gold_fp2_t trace_local[MAXW];
    int n_trace_local;
    gold_fp2_t trace_next[MAXW];
    int n_trace_next;
    int has_trace_next;
    gold_fp_t public_values[MAXP];
    int n_public;
    int n_constraints;
    gold_fp2_t applied[MAXC], acc_after[MAXC];
} vec_t;

static void parse_public_values(js_t *s, vec_t *v) {
    js_match(s, '[');
    int n = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *str = js_read_string(s);
        if (str && n < MAXP) v->public_values[n] = gold_fp_from_u64(strtoull(str, NULL, 10));
        free(str);
        n++;
    }
    v->n_public = n;
}
static void parse_fold_trace(js_t *s, vec_t *v) {
    js_match(s, '[');
    int i = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        js_match(s, '{');
        while (!js_match(s, '}')) {
            if (js_peek(s, ',')) { s->pos++; continue; }
            char *k = js_read_string(s);
            js_match(s, ':');
            if (k && strcmp(k, "selector_applied_value") == 0) {
                gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) v->applied[i] = f;
            } else if (k && strcmp(k, "accumulator_after") == 0) {
                gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) v->acc_after[i] = f;
            } else {
                js_skip_value(s);
            }
            free(k);
        }
        i++;
    }
    v->n_constraints = i;
}
static int parse_vector(const char *path, vec_t *v) {
    size_t len = 0;
    char *src = slurp(path, &len);
    if (!src) { fprintf(stderr, "cannot read %s\n", path); return -1; }
    memset(v, 0, sizeof *v);
    js_t s = { src, 0, len };
    if (!js_match(&s, '{')) { free(src); return -1; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s);
        if (!k) break;
        js_match(&s, ':');
        if (strcmp(k, "base_degree_bits") == 0) js_read_u64(&s, &v->base_degree_bits);
        else if (strcmp(k, "main_width") == 0) js_read_u64(&s, &v->main_width);
        else if (strcmp(k, "num_public_values") == 0) js_read_u64(&s, &v->num_public_values);
        else if (strcmp(k, "main_next") == 0) { v->main_next = js_peek(&s, 't') ? 1 : 0; js_skip_value(&s); }
        else if (strcmp(k, "final_equal") == 0) { v->final_equal = js_peek(&s, 't') ? 1 : 0; js_skip_value(&s); }
        else if (strcmp(k, "zeta") == 0) v->zeta = parse_fp2_decimal(&s);
        else if (strcmp(k, "alpha") == 0) v->alpha = parse_fp2_decimal(&s);
        else if (strcmp(k, "quotient_zeta") == 0) v->quotient_zeta = parse_fp2_decimal(&s);
        else if (strcmp(k, "folded_constraints") == 0) v->folded = parse_fp2_decimal(&s);
        else if (strcmp(k, "trace_local") == 0) v->n_trace_local = parse_fp2_array(&s, v->trace_local, MAXW);
        else if (strcmp(k, "trace_next") == 0) {
            if (js_peek(&s, 'n')) { js_skip_value(&s); v->has_trace_next = 0; v->n_trace_next = 0; }
            else { v->n_trace_next = parse_fp2_array(&s, v->trace_next, MAXW); v->has_trace_next = 1; }
        }
        else if (strcmp(k, "public_values") == 0) parse_public_values(&s, v);
        else if (strcmp(k, "quotient_chunks") == 0) {
            js_match(&s, '[');
            int ci = 0;
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (ci == 0) v->n_chunk0 = parse_fp2_array(&s, v->chunk0, 2);
                else js_skip_value(&s);
                ci++;
            }
        }
        else if (strcmp(k, "per_constraint_fold_trace") == 0) parse_fold_trace(&s, v);
        else js_skip_value(&s);
        free(k);
    }
    free(src);
    return 0;
}

/* ===== test AIR callbacks (fixtures; fib/square are not DNAC production AIRs) ===== */

/* FibonacciAir — fib_air.rs:44-72, emission order EXACT (5 constraints). */
static void fib_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *l = f->trace_local;
    const gold_fp2_t *n = f->trace_next;
    const gold_fp2_t a = gold_fp2_from_base(f->public_values[0]);
    const gold_fp2_t b = gold_fp2_from_base(f->public_values[1]);
    const gold_fp2_t x = gold_fp2_from_base(f->public_values[2]);
    /* when_first_row: local.left == a ; local.right == b */
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[0], a));
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[1], b));
    /* when_transition: local.right == next.left ; local.left+local.right == next.right */
    dnac_stark_folder_when(f, f->is_transition, gold_fp2_sub(l[1], n[0]));
    dnac_stark_folder_when(f, f->is_transition, gold_fp2_sub(gold_fp2_add(l[0], l[1]), n[1]));
    /* when_last_row: local.right == x */
    dnac_stark_folder_when(f, f->is_last_row, gold_fp2_sub(l[1], x));
}

/* SquareAir — no_next_row.rs:29-36, single unfiltered constraint. */
static void square_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *l = f->trace_local;
    dnac_stark_folder_assert_zero(f, gold_fp2_sub(gold_fp2_mul(l[0], l[0]), l[1]));
}

static const dnac_stark_air_t FIB_AIR = { 2, 3, 1, fib_air_eval };
static const dnac_stark_air_t SQUARE_AIR = { 2, 0, 0, square_air_eval };

/* ===== positive: verify_constraints OK + per-constraint capture ===== */
static int run_vector(const dnac_stark_air_t *air, const vec_t *v, const char *label, int expect_n) {
    int fail = 0;

    if ((size_t)v->main_width != air->main_width || v->main_next != air->main_next ||
        (size_t)v->num_public_values != air->num_public_values) {
        fprintf(stderr, "  %s: vector shape != AIR descriptor\n", label);
        fail++;
    }

    /* TEST 1 — production verify_constraints == OK. */
    const gold_fp2_t *tn = v->has_trace_next ? v->trace_next : NULL;
    size_t tn_len = v->has_trace_next ? (size_t)v->n_trace_next : 0;
    dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
        air, v->trace_local, (size_t)v->n_trace_local, tn, tn_len,
        v->public_values, (size_t)v->n_public, v->zeta, (size_t)v->base_degree_bits,
        v->alpha, v->chunk0);
    if (st != DNAC_STARK_VERIFY_OK) {
        fprintf(stderr, "  %s: verify_constraints = %d (want 0=OK)\n", label, (int)st);
        fail++;
    }

    /* TEST 2 — per-constraint capture via air_eval (localization). */
    dnac_stark_selectors_t sels = dnac_stark_selectors_at_point(v->zeta, (size_t)v->base_degree_bits);
    gold_fp2_t zeros[MAXW];
    for (size_t i = 0; i < air->main_width; i++) zeros[i] = gold_fp2_zero();
    dnac_stark_fold_step_t cap[MAXC];
    dnac_stark_folder_t f;
    f.trace_local = v->trace_local;
    f.trace_next = v->has_trace_next ? v->trace_next : zeros;
    f.main_width = air->main_width;
    f.public_values = v->public_values;
    f.num_public_values = (size_t)v->n_public;
    f.is_first_row = sels.is_first_row;
    f.is_last_row = sels.is_last_row;
    f.is_transition = sels.is_transition;
    dnac_stark_fold_init(&f.fold, v->alpha);
    f.capture = cap;
    f.capture_cap = MAXC;
    f.capture_len = 0;
    air->air_eval(&f);

    int trace_pass = 0;
    if ((int)f.capture_len != expect_n) {
        fprintf(stderr, "  %s: air_eval emitted %zu constraints != %d\n", label, f.capture_len, expect_n);
        fail++;
    }
    for (int i = 0; i < (int)f.capture_len && i < v->n_constraints; i++) {
        if (gold_fp2_eq(cap[i].received, v->applied[i]) && gold_fp2_eq(cap[i].after, v->acc_after[i])) {
            trace_pass++;
        } else {
            fail++;
            fprintf(stderr,
                    "  MISMATCH per-constraint trace\n    vector:    %s\n    constraint:%d\n"
                    "    expected received=(%llu,%llu) after=(%llu,%llu)\n"
                    "    actual   received=(%llu,%llu) after=(%llu,%llu)\n    plonky3:   folder.rs:216-218 + the AIR eval order\n",
                    label, i,
                    (unsigned long long)gold_fp_to_u64(v->applied[i].a), (unsigned long long)gold_fp_to_u64(v->applied[i].b),
                    (unsigned long long)gold_fp_to_u64(v->acc_after[i].a), (unsigned long long)gold_fp_to_u64(v->acc_after[i].b),
                    (unsigned long long)gold_fp_to_u64(cap[i].received.a), (unsigned long long)gold_fp_to_u64(cap[i].received.b),
                    (unsigned long long)gold_fp_to_u64(cap[i].after.a), (unsigned long long)gold_fp_to_u64(cap[i].after.b));
        }
    }
    /* cumulative folded == vector. */
    if (!gold_fp2_eq(f.fold.acc, v->folded)) {
        fprintf(stderr, "  %s: air_eval folded != vector folded_constraints\n", label);
        fail++;
    }
    /* final equality (verifier.rs:157). */
    gold_fp2_t lhs = gold_fp2_mul(v->folded, sels.inv_vanishing);
    if (!gold_fp2_eq(lhs, v->quotient_zeta)) {
        fprintf(stderr, "  %s: folded*inv_vanishing != quotient_zeta\n", label);
        fail++;
    }
    if (!v->final_equal) {
        fprintf(stderr, "  %s: vector final_equal != true\n", label);
        fail++;
    }

    printf("  [%s] %s: verify_constraints=OK | per-constraint trace %d/%d | cumulative==folded | final OK\n",
           fail ? "FAIL" : "OK  ", label, trace_pass, expect_n);
    return fail;
}

/* ===== negative cases ===== */
static int expect_status(const char *name, dnac_stark_verify_status_t got, dnac_stark_verify_status_t want) {
    if (got == want) { printf("  [OK  ] %-44s -> %d\n", name, (int)got); return 0; }
    fprintf(stderr, "  [FAIL] %-44s got %d want %d\n", name, (int)got, (int)want);
    return 1;
}
static int run_negatives(const vec_t *fv, const vec_t *sv) {
    int fail = 0;

    /* N1 — corrupt one trace_local value (fib) -> OOD_MISMATCH (folded changes,
     *      quotient unchanged). */
    {
        gold_fp2_t corrupt[MAXW];
        for (int i = 0; i < fv->n_trace_local; i++) corrupt[i] = fv->trace_local[i];
        corrupt[0] = gold_fp2_add(corrupt[0], gold_fp2_one());
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &FIB_AIR, corrupt, (size_t)fv->n_trace_local, fv->trace_next, (size_t)fv->n_trace_next,
            fv->public_values, (size_t)fv->n_public, fv->zeta, (size_t)fv->base_degree_bits,
            fv->alpha, fv->chunk0);
        fail += expect_status("N1 corrupt trace_local[0] (fib)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N2 — wrong trace width (fib): claim width-1 for a width-2 AIR -> SHAPE. */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &FIB_AIR, fv->trace_local, (size_t)fv->n_trace_local - 1, fv->trace_next, (size_t)fv->n_trace_next,
            fv->public_values, (size_t)fv->n_public, fv->zeta, (size_t)fv->base_degree_bits,
            fv->alpha, fv->chunk0);
        fail += expect_status("N2 wrong trace_local width (fib)", st, DNAC_STARK_VERIFY_ERR_SHAPE);
    }
    /* N3 — wrong public-value count (fib): claim 4 for a 3-public AIR -> SHAPE. */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &FIB_AIR, fv->trace_local, (size_t)fv->n_trace_local, fv->trace_next, (size_t)fv->n_trace_next,
            fv->public_values, (size_t)fv->n_public + 1, fv->zeta, (size_t)fv->base_degree_bits,
            fv->alpha, fv->chunk0);
        fail += expect_status("N3 wrong public_values count (fib)", st, DNAC_STARK_VERIFY_ERR_SHAPE);
    }
    /* N4 — SquareAir trace_next ABSENT (main_next=false) -> OK (zero-window). */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &SQUARE_AIR, sv->trace_local, (size_t)sv->n_trace_local, NULL, 0,
            sv->public_values, (size_t)sv->n_public, sv->zeta, (size_t)sv->base_degree_bits,
            sv->alpha, sv->chunk0);
        fail += expect_status("N4 SquareAir trace_next absent", st, DNAC_STARK_VERIFY_OK);
    }
    /* N5 — FibonacciAir missing trace_next (main_next=true) -> SHAPE. */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &FIB_AIR, fv->trace_local, (size_t)fv->n_trace_local, NULL, 0,
            fv->public_values, (size_t)fv->n_public, fv->zeta, (size_t)fv->base_degree_bits,
            fv->alpha, fv->chunk0);
        fail += expect_status("N5 FibonacciAir missing trace_next", st, DNAC_STARK_VERIFY_ERR_SHAPE);
    }
    return fail;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <stark_verify_constraints.json> <..._no_next.json>\n", argv[0]);
        return 2;
    }
    vec_t fv, sv;
    if (parse_vector(argv[1], &fv) != 0 || parse_vector(argv[2], &sv) != 0) return 1;

    printf("S4 — verify_constraints glue + FibonacciAir/SquareAir air_eval (vs real-Plonky3 S2)\n");
    int fail = 0;
    fail += run_vector(&FIB_AIR, &fv, "FibonacciAir (main_next=true)", 5);
    fail += run_vector(&SQUARE_AIR, &sv, "SquareAir (main_next=false)", 1);
    printf("  --- negative cases ---\n");
    fail += run_negatives(&fv, &sv);

    if (fail) {
        fprintf(stderr, "test_stark_verify_constraints: %d FAIL(s)\n", fail);
        return 1;
    }
    printf("test_stark_verify_constraints: PASS\n");
    printf("  FibonacciAir + SquareAir verify_constraints==OK; per-constraint trace 5/5 + 1/1;\n");
    printf("  5 negative cases reject/accept as expected (OOD/SHAPE/zero-window).\n");
    return 0;
}
