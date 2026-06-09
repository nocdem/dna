/**
 * @file test_stark_constraints_primitives.c
 * @brief S3 replay: generic STARK constraint-check primitives vs S2 oracle vectors.
 *
 * Byte-matches dnac_stark_selectors_at_point / recompose_quotient_1chunk / the
 * alpha-fold primitives / the final check against the real-Plonky3 verifier-side
 * vectors tools/vectors/stark_verify_constraints{,_no_next}.json (phase S2). Tests
 * ONLY generic primitives — NO AIR eval, NO full verify glue.
 *
 *   argv[1] = stark_verify_constraints.json          (FibonacciAir, 5 constraints)
 *   argv[2] = stark_verify_constraints_no_next.json  (SquareAir,    1 constraint)
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

/* ===== parsed vector ===== */
#define MAXC 16
typedef struct {
    uint64_t base_degree_bits;
    uint64_t main_width;
    int final_equal;
    gold_fp2_t zeta, alpha, quotient_zeta, folded;
    gold_fp2_t z_h, is_first, is_last, is_transition, inv_vanishing;
    gold_fp2_t chunk0[2];
    int n_chunk0;
    int n_constraints;
    char selector_name[MAXC][40];
    gold_fp2_t raw[MAXC], applied[MAXC], acc_before[MAXC], acc_after[MAXC];
} vec_t;

static void parse_selectors(js_t *s, vec_t *v) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        js_match(s, ':');
        if (k && strcmp(k, "z_h") == 0) v->z_h = parse_fp2_decimal(s);
        else if (k && strcmp(k, "is_first_row") == 0) v->is_first = parse_fp2_decimal(s);
        else if (k && strcmp(k, "is_last_row") == 0) v->is_last = parse_fp2_decimal(s);
        else if (k && strcmp(k, "is_transition") == 0) v->is_transition = parse_fp2_decimal(s);
        else if (k && strcmp(k, "inv_vanishing") == 0) v->inv_vanishing = parse_fp2_decimal(s);
        else js_skip_value(s);
        free(k);
    }
}

static void parse_quotient_chunks(js_t *s, vec_t *v) {
    js_match(s, '[');           /* outer array of chunks */
    int chunk_idx = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (chunk_idx == 0) {
            js_match(s, '[');   /* chunk0 = [fp2, fp2] */
            int n = 0;
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                gold_fp2_t f = parse_fp2_decimal(s);
                if (n < 2) v->chunk0[n] = f;
                n++;
            }
            v->n_chunk0 = n;
        } else {
            js_skip_value(s);
        }
        chunk_idx++;
    }
}

static void parse_fold_trace(js_t *s, vec_t *v) {
    js_match(s, '[');
    int i = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        js_match(s, '{');       /* one constraint object */
        while (!js_match(s, '}')) {
            if (js_peek(s, ',')) { s->pos++; continue; }
            char *k = js_read_string(s);
            js_match(s, ':');
            if (k && strcmp(k, "selector") == 0) {
                char *sv = js_read_string(s);
                if (i < MAXC && sv) { strncpy(v->selector_name[i], sv, 39); v->selector_name[i][39] = '\0'; }
                free(sv);
            } else if (k && strcmp(k, "raw_constraint_value") == 0) {
                gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) v->raw[i] = f;
            } else if (k && strcmp(k, "selector_applied_value") == 0) {
                gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) v->applied[i] = f;
            } else if (k && strcmp(k, "accumulator_before") == 0) {
                gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) v->acc_before[i] = f;
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
        else if (strcmp(k, "zeta") == 0) v->zeta = parse_fp2_decimal(&s);
        else if (strcmp(k, "alpha") == 0) v->alpha = parse_fp2_decimal(&s);
        else if (strcmp(k, "quotient_zeta") == 0) v->quotient_zeta = parse_fp2_decimal(&s);
        else if (strcmp(k, "folded_constraints") == 0) v->folded = parse_fp2_decimal(&s);
        else if (strcmp(k, "final_equal") == 0) { v->final_equal = js_peek(&s, 't') ? 1 : 0; js_skip_value(&s); }
        else if (strcmp(k, "selectors") == 0) parse_selectors(&s, v);
        else if (strcmp(k, "quotient_chunks") == 0) parse_quotient_chunks(&s, v);
        else if (strcmp(k, "per_constraint_fold_trace") == 0) parse_fold_trace(&s, v);
        else js_skip_value(&s);
        free(k);
    }
    free(src);
    return 0;
}

/* ===== helpers ===== */
static int chk(const char *path, const char *primitive, const char *p3ref,
               gold_fp2_t got, gold_fp2_t exp) {
    if (gold_fp2_eq(got, exp)) return 1;
    fprintf(stderr,
            "  MISMATCH\n    vector:   %s\n    primitive:%s\n    expected: (%llu, %llu)\n"
            "    actual:   (%llu, %llu)\n    plonky3:  %s\n",
            path, primitive,
            (unsigned long long)gold_fp_to_u64(exp.a), (unsigned long long)gold_fp_to_u64(exp.b),
            (unsigned long long)gold_fp_to_u64(got.a), (unsigned long long)gold_fp_to_u64(got.b),
            p3ref);
    return 0;
}
static gold_fp2_t sel_by_name(const char *name, const vec_t *v) {
    if (strcmp(name, "is_first_row") == 0) return v->is_first;
    if (strcmp(name, "is_last_row") == 0) return v->is_last;
    if (strcmp(name, "is_transition") == 0) return v->is_transition;
    return gold_fp2_one(); /* "one(unfiltered)" */
}

/* ===== per-vector replay ===== */
static int test_vector(const char *path, const char *label, int expect_constraints) {
    vec_t v;
    if (parse_vector(path, &v) != 0) return 1;
    int fail = 0;

    /* TEST 1 — selectors byte-match (domain.rs:262-271). */
    dnac_stark_selectors_t s = dnac_stark_selectors_at_point(v.zeta, (size_t)v.base_degree_bits);
    fail += !chk(path, "selectors_at_point.z_h", "domain.rs:251-253/264", s.z_h, v.z_h);
    fail += !chk(path, "selectors_at_point.is_first_row", "domain.rs:266", s.is_first_row, v.is_first);
    fail += !chk(path, "selectors_at_point.is_last_row", "domain.rs:267", s.is_last_row, v.is_last);
    fail += !chk(path, "selectors_at_point.is_transition", "domain.rs:268", s.is_transition, v.is_transition);
    fail += !chk(path, "selectors_at_point.inv_vanishing", "domain.rs:269", s.inv_vanishing, v.inv_vanishing);

    /* TEST 2 — recompose byte-match (verifier.rs:87-95). */
    if (v.n_chunk0 != 2) { fprintf(stderr, "  %s: quotient_chunks[0] len %d != 2\n", path, v.n_chunk0); fail++; }
    gold_fp2_t q = dnac_stark_recompose_quotient_1chunk(v.chunk0);
    fail += !chk(path, "recompose_quotient_1chunk", "verifier.rs:87-95", q, v.quotient_zeta);

    /* TEST 3 — per-constraint fold replay via fold_assert_zero (folder.rs:216-218). */
    if (v.n_constraints != expect_constraints) {
        fprintf(stderr, "  %s: constraint count %d != expected %d\n", path, v.n_constraints, expect_constraints);
        fail++;
    }
    int fold_pass = 0;
    for (int i = 0; i < v.n_constraints; i++) {
        dnac_stark_fold_t f;
        f.alpha = v.alpha;
        f.acc = v.acc_before[i];                    /* replay from the vector's before-state */
        dnac_stark_fold_assert_zero(&f, v.applied[i]);
        if (gold_fp2_eq(f.acc, v.acc_after[i])) fold_pass++;
        else fail += !chk(path, "fold_assert_zero (per-constraint)", "folder.rs:216-218", f.acc, v.acc_after[i]);
    }

    /* TEST 3b — per-constraint fold_when (filtered.rs:60-62): selector*raw -> after. */
    int when_pass = 0;
    for (int i = 0; i < v.n_constraints; i++) {
        gold_fp2_t sel = sel_by_name(v.selector_name[i], &v);
        dnac_stark_fold_t f;
        f.alpha = v.alpha;
        f.acc = v.acc_before[i];
        dnac_stark_fold_when(&f, sel, v.raw[i]);
        if (gold_fp2_eq(f.acc, v.acc_after[i])) when_pass++;
        else fail += !chk(path, "fold_when (selector*raw)", "filtered.rs:60-62", f.acc, v.acc_after[i]);
    }

    /* TEST 3c — cumulative fold from ZERO over the emission order == folded_constraints. */
    dnac_stark_fold_t fc;
    dnac_stark_fold_init(&fc, v.alpha);
    for (int i = 0; i < v.n_constraints; i++) dnac_stark_fold_assert_zero(&fc, v.applied[i]);
    fail += !chk(path, "cumulative fold == folded_constraints", "folder.rs:216-218 + verifier.rs:154", fc.acc, v.folded);

    /* TEST 4 — final OOD check (verifier.rs:157-159). */
    dnac_stark_verify_status_t st = dnac_stark_final_check(v.folded, v.inv_vanishing, v.quotient_zeta);
    if (st != DNAC_STARK_VERIFY_OK) { fprintf(stderr, "  %s: final_check = %d (want OK)\n", path, (int)st); fail++; }
    if (!v.final_equal) { fprintf(stderr, "  %s: vector final_equal != true\n", path); fail++; }
    gold_fp2_t lhs = gold_fp2_mul(v.folded, v.inv_vanishing);
    fail += !chk(path, "final_lhs == quotient_zeta", "verifier.rs:157", lhs, v.quotient_zeta);

    printf("  [%s] %s: selectors 5/5 | recompose OK | fold_assert_zero %d/%d | fold_when %d/%d | "
           "cumulative==folded | final_check=OK%s\n",
           fail ? "FAIL" : "OK  ", label, fold_pass, v.n_constraints, when_pass, v.n_constraints,
           fail ? " [SEE MISMATCH ABOVE]" : "");
    return fail;
}

/* ===== standalone primitive units (no vector) ===== */
static int test_standalone(void) {
    int fail = 0;
    const gold_fp2_t zero = gold_fp2_zero();
    const gold_fp2_t one = gold_fp2_one();
    const gold_fp2_t two = gold_fp2_from_base(gold_fp_from_u64(2));
    const gold_fp2_t three = gold_fp2_from_base(gold_fp_from_u64(3));
    const gold_fp2_t five = gold_fp2_from_base(gold_fp_from_u64(5));
    const gold_fp2_t seven = gold_fp2_from_base(gold_fp_from_u64(7));

    /* assert_zero: acc=0, alpha=3 -> assert_zero(5)=5 -> assert_zero(2)=5*3+2=17. */
    {
        dnac_stark_fold_t f; dnac_stark_fold_init(&f, three);
        dnac_stark_fold_assert_zero(&f, five);
        if (!gold_fp2_eq(f.acc, five)) { fprintf(stderr, "  assert_zero step1 != 5\n"); fail++; }
        dnac_stark_fold_assert_zero(&f, two);
        if (!gold_fp2_eq(f.acc, gold_fp2_from_base(gold_fp_from_u64(17)))) { fprintf(stderr, "  assert_zero step2 != 17\n"); fail++; }
    }
    /* assert_eq: a==b -> 0; a!=b (7,3) -> 4. */
    {
        dnac_stark_fold_t f; dnac_stark_fold_init(&f, three);
        dnac_stark_fold_assert_eq(&f, seven, seven);
        if (!gold_fp2_eq(f.acc, zero)) { fprintf(stderr, "  assert_eq(7,7) != 0\n"); fail++; }
        dnac_stark_fold_t g; dnac_stark_fold_init(&g, three);
        dnac_stark_fold_assert_eq(&g, seven, three);
        if (!gold_fp2_eq(g.acc, gold_fp2_from_base(gold_fp_from_u64(4)))) { fprintf(stderr, "  assert_eq(7,3) != 4\n"); fail++; }
    }
    /* fold_when: selector*x, acc=0 -> 3*5 = 15. */
    {
        dnac_stark_fold_t f; dnac_stark_fold_init(&f, two);
        dnac_stark_fold_when(&f, three, five);
        if (!gold_fp2_eq(f.acc, gold_fp2_from_base(gold_fp_from_u64(15)))) { fprintf(stderr, "  fold_when(3,5) != 15\n"); fail++; }
    }
    /* assert_bool (REQUIRED — fib/square never exercise it): x=0 ->0, x=1 ->0, x=2 -> 2. */
    {
        dnac_stark_fold_t f0; dnac_stark_fold_init(&f0, two);
        dnac_stark_fold_assert_bool(&f0, zero);
        if (!gold_fp2_eq(f0.acc, zero)) { fprintf(stderr, "  assert_bool(0): 0*(0-1) != 0\n"); fail++; }

        dnac_stark_fold_t f1; dnac_stark_fold_init(&f1, two);
        dnac_stark_fold_assert_bool(&f1, one);
        if (!gold_fp2_eq(f1.acc, zero)) { fprintf(stderr, "  assert_bool(1): 1*(1-1) != 0\n"); fail++; }

        dnac_stark_fold_t f2; dnac_stark_fold_init(&f2, two);
        dnac_stark_fold_assert_bool(&f2, two);
        if (gold_fp2_eq(f2.acc, zero)) { fprintf(stderr, "  assert_bool(2): 2*(2-1) must be NONZERO\n"); fail++; }
        if (!gold_fp2_eq(f2.acc, two)) { fprintf(stderr, "  assert_bool(2): 2*(2-1) != 2\n"); fail++; }
    }

    printf("  [%s] standalone primitives: assert_zero, assert_eq, fold_when, assert_bool(0/1/2)\n",
           fail ? "FAIL" : "OK  ");
    return fail;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <stark_verify_constraints.json> <..._no_next.json>\n", argv[0]);
        return 2;
    }
    printf("S3 — generic STARK constraint-check primitives (vs real-Plonky3 S2 vectors)\n");
    int fail = 0;
    fail += test_vector(argv[1], "FibonacciAir (main_next=true)", 5);
    fail += test_vector(argv[2], "SquareAir (main_next=false)", 1);
    fail += test_standalone();

    if (fail) {
        fprintf(stderr, "test_stark_constraints_primitives: %d FAIL(s)\n", fail);
        return 1;
    }
    printf("test_stark_constraints_primitives: PASS\n");
    printf("  selectors + recompose byte-match both vectors; fold trace FibonacciAir 5/5, SquareAir 1/1;\n");
    printf("  final OOD check OK both; assert_bool standalone unit OK.\n");
    return 0;
}
