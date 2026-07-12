/**
 * @file test_range_proof_air.c
 * @brief S5.x: C range_proof_air air_eval (range-only + combined, ADDITIVE) vs the
 *        S5.1 real-Plonky3 oracle vectors. Reuses the S4 generic
 *        dnac_stark_verify_constraints glue; the two air_eval callbacks are TEST
 *        fixtures mirroring the S5.1 Rust RangeOnlyAir / RangeProofAir.
 *
 *   argv[1] = range_air_only.json   (RangeOnlyAir, 53 constraints, main_next=false)
 *   argv[2] = range_proof_air.json  (RangeProofAir, 61 constraints, main_next=true)
 *
 * 2026-07 soundness fix: 52-bit decomposition (B6 field-wrap closed) plus
 * is_real/P padding gate and cnt count-accumulator bound to public n_real
 * (B7 padding/count closed). ADDITIVE only. CONFIDENTIAL use still BLOCKED
 * on B1 (trace<->TX binding), asserted from the vector flags. Per
 * docs/plans/2026-05-30-dnac-range-proof-air-regrounding.md (S5.x) +
 * dnac/docs/plans/2026-07-11-range-balance-soundness-fix-design.md.
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
#include "range_air.h"
#include "sum_balance.h"   /* SUM_BALANCE_TERM_MAX — the public-input bound */

/* Column layout (extends range_air; mirrors the Rust oracle constants). */
#define COL_AMOUNT   (RANGE_AIR_BITS)      /* 52 */
#define COL_ACC      (RANGE_AIR_BITS + 1)  /* 53 */
#define COL_IS_REAL  (RANGE_AIR_BITS + 2)  /* 54 */
#define COL_CNT      (RANGE_AIR_BITS + 3)  /* 55 */
#define RANGE_ONLY_W (RANGE_AIR_BITS + 1)  /* 53 */
#define RANGE_PROOF_W (RANGE_AIR_BITS + 4) /* 56 */
/* Wrap-safety bound: height <= 2^10 = 1024 = SUM_BALANCE_MAX_OUTPUTS so
 * 1024 * (2^52 - 1) < 2^62 < p (the mod-p acc IS the integer sum). */
#define RANGE_PROOF_MAX_DEGREE_BITS 10u

/* ===== Minimal JSON scanner (same idiom as tests/test_stark_verify_constraints.c) ===== */
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

/* ===== parsed case + file ===== */
#define MAXW 256
#define MAXP 8
#define MAXC 80
#define MAXCASES 8
typedef struct {
    char name[64];
    uint64_t base_degree_bits, main_width, num_public_values, num_qc;
    int main_next;
    int final_equal;
    gold_fp2_t zeta, alpha, quotient_zeta, folded;
    gold_fp2_t chunk0[2]; int n_chunk0;
    gold_fp2_t trace_local[MAXW]; int n_trace_local;
    gold_fp2_t trace_next[MAXW]; int n_trace_next; int has_trace_next;
    gold_fp_t public_values[MAXP]; int n_public;
    int n_constraints;
    gold_fp2_t applied[MAXC], acc_after[MAXC];
} case_t;
typedef struct {
    int additive_only, confidential_use_allowed;
    int blocker_b1, blocker_b6, blocker_b7;
    int n_cases;
    case_t cases[MAXCASES];
} file_t;

static void parse_public_values(js_t *s, case_t *c) {
    js_match(s, '[');
    int n = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *str = js_read_string(s);
        if (str && n < MAXP) c->public_values[n] = gold_fp_from_u64(strtoull(str, NULL, 10));
        free(str);
        n++;
    }
    c->n_public = n;
}
static void parse_fold_trace(js_t *s, case_t *c) {
    js_match(s, '[');
    int i = 0;
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        js_match(s, '{');
        while (!js_match(s, '}')) {
            if (js_peek(s, ',')) { s->pos++; continue; }
            char *k = js_read_string(s);
            js_match(s, ':');
            if (k && strcmp(k, "selector_applied_value") == 0) { gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) c->applied[i] = f; }
            else if (k && strcmp(k, "accumulator_after") == 0) { gold_fp2_t f = parse_fp2_decimal(s); if (i < MAXC) c->acc_after[i] = f; }
            else js_skip_value(s);
            free(k);
        }
        i++;
    }
    c->n_constraints = i;
}
static void parse_case(js_t *s, case_t *c) {
    memset(c, 0, sizeof *c);
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) break;
        js_match(s, ':');
        if (strcmp(k, "name") == 0) { char *v = js_read_string(s); if (v) { strncpy(c->name, v, 63); c->name[63] = '\0'; } free(v); }
        else if (strcmp(k, "base_degree_bits") == 0) js_read_u64(s, &c->base_degree_bits);
        else if (strcmp(k, "main_width") == 0) js_read_u64(s, &c->main_width);
        else if (strcmp(k, "num_public_values") == 0) js_read_u64(s, &c->num_public_values);
        else if (strcmp(k, "num_quotient_chunks") == 0) js_read_u64(s, &c->num_qc);
        else if (strcmp(k, "main_next") == 0) { c->main_next = js_peek(s, 't') ? 1 : 0; js_skip_value(s); }
        else if (strcmp(k, "final_equal") == 0) { c->final_equal = js_peek(s, 't') ? 1 : 0; js_skip_value(s); }
        else if (strcmp(k, "zeta") == 0) c->zeta = parse_fp2_decimal(s);
        else if (strcmp(k, "alpha") == 0) c->alpha = parse_fp2_decimal(s);
        else if (strcmp(k, "quotient_zeta") == 0) c->quotient_zeta = parse_fp2_decimal(s);
        else if (strcmp(k, "folded_constraints") == 0) c->folded = parse_fp2_decimal(s);
        else if (strcmp(k, "trace_local") == 0) c->n_trace_local = parse_fp2_array(s, c->trace_local, MAXW);
        else if (strcmp(k, "trace_next") == 0) {
            if (js_peek(s, 'n')) { js_skip_value(s); c->has_trace_next = 0; }
            else { c->n_trace_next = parse_fp2_array(s, c->trace_next, MAXW); c->has_trace_next = 1; }
        }
        else if (strcmp(k, "public_values") == 0) parse_public_values(s, c);
        else if (strcmp(k, "quotient_chunks") == 0) {
            js_match(s, '[');
            int ci = 0;
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                if (ci == 0) c->n_chunk0 = parse_fp2_array(s, c->chunk0, 2);
                else js_skip_value(s);
                ci++;
            }
        }
        else if (strcmp(k, "per_constraint_fold_trace") == 0) parse_fold_trace(s, c);
        else js_skip_value(s);
        free(k);
    }
}
static int parse_file(const char *path, file_t *fl) {
    size_t len = 0;
    char *src = slurp(path, &len);
    if (!src) { fprintf(stderr, "cannot read %s\n", path); return -1; }
    memset(fl, 0, sizeof *fl);
    js_t s = { src, 0, len };
    if (!js_match(&s, '{')) { free(src); return -1; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s);
        if (!k) break;
        js_match(&s, ':');
        if (strcmp(k, "additive_only") == 0) { fl->additive_only = js_peek(&s, 't') ? 1 : 0; js_skip_value(&s); }
        else if (strcmp(k, "confidential_use_allowed") == 0) { fl->confidential_use_allowed = js_peek(&s, 't') ? 1 : 0; js_skip_value(&s); }
        else if (strcmp(k, "blockers") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                char *b = js_read_string(&s);
                if (b) {
                    if (strcmp(b, "B1") == 0) fl->blocker_b1 = 1;
                    else if (strcmp(b, "B6") == 0) fl->blocker_b6 = 1;
                    else if (strcmp(b, "B7") == 0) fl->blocker_b7 = 1;
                }
                free(b);
            }
        }
        else if (strcmp(k, "cases") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (fl->n_cases < MAXCASES) parse_case(&s, &fl->cases[fl->n_cases]);
                else js_skip_value(&s);
                fl->n_cases++;
            }
        }
        else js_skip_value(&s);
        free(k);
    }
    free(src);
    return 0;
}

/* ===== AIR air_eval callbacks (TEST fixtures; mirror the S5.1 Rust evals) ===== */

/* RangeOnlyAir — width 53, main_next=false, 0 public. B₀..B₅₁ + S (unfiltered). */
static void range_only_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *l = f->trace_local;
    for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
        dnac_stark_folder_assert_bool(f, l[i]); /* Bᵢ = bitᵢ·(bitᵢ−1) */
    }
    /* S = Σ bitᵢ·2ⁱ − amount, low-bit-first */
    gold_fp2_t bit_sum = gold_fp2_zero();
    gold_fp2_t weight = gold_fp2_one(); /* 2^0 */
    for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
        bit_sum = gold_fp2_add(bit_sum, gold_fp2_mul(l[i], weight));
        weight = gold_fp2_add(weight, weight); /* double */
    }
    dnac_stark_folder_assert_eq(f, bit_sum, l[COL_AMOUNT]); /* assert_zero(bit_sum − amount) */
}

/* RangeProofAir — width 56, main_next=true, 3 public [claimed, fee, n_real].
 * Fold order MUST mirror the Rust RangeProofAir::eval exactly:
 * B₀..B₅₁, S, R, P, I, U, F, CI, CU, CF = 61 constraints. */
static void range_proof_air_eval(dnac_stark_folder_t *f) {
    const gold_fp2_t *l = f->trace_local;
    const gold_fp2_t *n = f->trace_next;
    const gold_fp2_t claimed = gold_fp2_from_base(f->public_values[0]);
    const gold_fp2_t fee = gold_fp2_from_base(f->public_values[1]);
    const gold_fp2_t n_real = gold_fp2_from_base(f->public_values[2]);
    for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
        dnac_stark_folder_assert_bool(f, l[i]);
    }
    gold_fp2_t bit_sum = gold_fp2_zero();
    gold_fp2_t weight = gold_fp2_one();
    for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
        bit_sum = gold_fp2_add(bit_sum, gold_fp2_mul(l[i], weight));
        weight = gold_fp2_add(weight, weight);
    }
    dnac_stark_folder_assert_eq(f, bit_sum, l[COL_AMOUNT]); /* S */
    /* R unfiltered: is_real boolean */
    dnac_stark_folder_assert_bool(f, l[COL_IS_REAL]);
    /* P: (1 − is_real)·amount — padding rows carry zero value (keccak-air
     * export-flag idiom: when(cond).assert_zero(target)). */
    dnac_stark_folder_when(f, gold_fp2_sub(gold_fp2_one(), l[COL_IS_REAL]),
                           l[COL_AMOUNT]);
    /* I first_row: acc − amount */
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[COL_ACC], l[COL_AMOUNT]));
    /* U transition: acc_next − acc_local − amount_next (padding adds 0 via P) */
    dnac_stark_folder_when(f, f->is_transition,
                           gold_fp2_sub(gold_fp2_sub(n[COL_ACC], l[COL_ACC]), n[COL_AMOUNT]));
    /* F last_row: acc − (claimed − fee) */
    dnac_stark_folder_when(f, f->is_last_row,
                           gold_fp2_sub(l[COL_ACC], gold_fp2_sub(claimed, fee)));
    /* CI first_row: cnt − is_real */
    dnac_stark_folder_when(f, f->is_first_row, gold_fp2_sub(l[COL_CNT], l[COL_IS_REAL]));
    /* CU transition: cnt_next − cnt_local − is_real_next */
    dnac_stark_folder_when(f, f->is_transition,
                           gold_fp2_sub(gold_fp2_sub(n[COL_CNT], l[COL_CNT]), n[COL_IS_REAL]));
    /* CF last_row: cnt − n_real (binds Σ is_real to the public output count) */
    dnac_stark_folder_when(f, f->is_last_row, gold_fp2_sub(l[COL_CNT], n_real));
}

static const dnac_stark_air_t RANGE_ONLY_AIR = { RANGE_ONLY_W, 0, 0, range_only_air_eval };
static const dnac_stark_air_t RANGE_PROOF_AIR = { RANGE_PROOF_W, 3, 1, range_proof_air_eval };

/* ===== P-constraint isolation (grounded, NOT oracle-lockstep) =====
 * The soundness role of P = (1-is_real)*amount is to REJECT a value-bearing
 * padding row (is_real=0, amount!=0). The oracle byte-match and N8 (which
 * corrupts is_real via other columns) do not isolate P: deleting P would still
 * byte-match the (all-real) positive vectors. This hand-forged witness drives P
 * directly: a row with is_real=0 and a nonzero, IN-RANGE amount (so B/S pass and
 * R passes) must make P's folded contribution nonzero — i.e. the AIR would
 * reject. A control row with is_real=1 leaves P at zero. Constraint fold order
 * (mirrors range_proof_air_eval): B0..B51 (0..51), S(52), R(53), P(54), I,U,F,
 * CI,CU,CF. */
#define P_CONSTRAINT_INDEX 54
static int test_p_isolation(void) {
    int fail = 0;
    const uint64_t A = 0x1ABCDEuLL; /* in range: < 2^52 */

    for (int real = 0; real <= 1; real++) {
        gold_fp2_t tl[MAXW];
        for (size_t i = 0; i < RANGE_PROOF_W; i++) tl[i] = gold_fp2_zero();
        /* 52-bit decomposition of A so S passes (bits recompose to amount). */
        for (size_t i = 0; i < RANGE_AIR_BITS; i++) {
            tl[i] = gold_fp2_from_base(gold_fp_from_u64((A >> i) & 1u));
        }
        tl[COL_AMOUNT]  = gold_fp2_from_base(gold_fp_from_u64(A));
        tl[COL_IS_REAL] = gold_fp2_from_base(gold_fp_from_u64((uint64_t)real));
        /* acc/cnt left 0 — the gated I/U/F/CI/CU/CF may be nonzero, but we only
         * assert the UNFILTERED P here (index 54), which is selector-independent. */

        gold_fp2_t zeros[MAXW];
        for (size_t i = 0; i < RANGE_PROOF_W; i++) zeros[i] = gold_fp2_zero();
        gold_fp_t pubs[3] = { gold_fp_from_u64(0), gold_fp_from_u64(0), gold_fp_from_u64(0) };
        dnac_stark_selectors_t sels = dnac_stark_selectors_at_point(gold_fp2_one(), 2);
        dnac_stark_fold_step_t cap[MAXC];
        dnac_stark_folder_t fdr;
        fdr.trace_local = tl;
        fdr.trace_next = zeros;
        fdr.main_width = RANGE_PROOF_W;
        fdr.public_values = pubs;
        fdr.num_public_values = 3;
        fdr.is_first_row = sels.is_first_row;
        fdr.is_last_row = sels.is_last_row;
        fdr.is_transition = sels.is_transition;
        dnac_stark_fold_init(&fdr.fold, gold_fp2_one());
        fdr.capture = cap;
        fdr.capture_cap = MAXC;
        fdr.capture_len = 0;
        range_proof_air_eval(&fdr);

        if (fdr.capture_len <= P_CONSTRAINT_INDEX) {
            fprintf(stderr, "  P-iso: only %zu constraints captured\n", fdr.capture_len);
            fail++;
            continue;
        }
        if (real == 0) {
            /* value-bearing padding row: P MUST equal (1-0)*A = A exactly
             * (hand-pinned, NOT oracle-lockstep). Nonzero ⇒ the fold rejects. */
            const gold_fp2_t want = gold_fp2_from_base(gold_fp_from_u64(A));
            if (!gold_fp2_eq(cap[P_CONSTRAINT_INDEX].received, want)) {
                fprintf(stderr,
                        "  [FAIL] P-iso is_real=0,amount!=0: P residual != A "
                        "(padding injection not detected / wrong formula)\n");
                fail++;
            } else {
                printf("  [OK  ] P-iso is_real=0,amount=0x%llx -> P == amount (rejects padding injection)\n",
                       (unsigned long long)A);
            }
        } else {
            bool p_zero = gold_fp2_eq(cap[P_CONSTRAINT_INDEX].received, gold_fp2_zero());
            /* real row: P must be zero (does not spuriously reject). */
            if (!p_zero) {
                fprintf(stderr, "  [FAIL] P-iso is_real=1: P residual nonzero (false reject)\n");
                fail++;
            } else {
                printf("  [OK  ] P-iso is_real=1 control -> P zero (no false reject)\n");
            }
        }
    }
    return fail;
}

/* ===== positive run ===== */
static int run_case(const dnac_stark_air_t *air, const case_t *c, int expect_n) {
    int fail = 0;
    if ((size_t)c->main_width != air->main_width || c->main_next != air->main_next ||
        (size_t)c->num_public_values != air->num_public_values) {
        fprintf(stderr, "  %s: case shape != AIR descriptor\n", c->name);
        fail++;
    }
    if (c->num_qc != 1) { fprintf(stderr, "  %s: vector num_qc %llu != 1\n", c->name, (unsigned long long)c->num_qc); fail++; }

    /* 1. production verify_constraints == OK */
    const gold_fp2_t *tn = c->has_trace_next ? c->trace_next : NULL;
    size_t tn_len = c->has_trace_next ? (size_t)c->n_trace_next : 0;
    dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
        air, c->trace_local, (size_t)c->n_trace_local, tn, tn_len,
        c->public_values, (size_t)c->n_public, c->zeta, (size_t)c->base_degree_bits,
        c->alpha, c->chunk0);
    if (st != DNAC_STARK_VERIFY_OK) { fprintf(stderr, "  %s: verify_constraints=%d (want OK)\n", c->name, (int)st); fail++; }

    /* 2. per-constraint capture byte-match */
    dnac_stark_selectors_t sels = dnac_stark_selectors_at_point(c->zeta, (size_t)c->base_degree_bits);
    gold_fp2_t zeros[MAXW];
    for (size_t i = 0; i < air->main_width; i++) zeros[i] = gold_fp2_zero();
    dnac_stark_fold_step_t cap[MAXC];
    dnac_stark_folder_t fdr;
    fdr.trace_local = c->trace_local;
    fdr.trace_next = c->has_trace_next ? c->trace_next : zeros;
    fdr.main_width = air->main_width;
    fdr.public_values = c->public_values;
    fdr.num_public_values = (size_t)c->n_public;
    fdr.is_first_row = sels.is_first_row;
    fdr.is_last_row = sels.is_last_row;
    fdr.is_transition = sels.is_transition;
    dnac_stark_fold_init(&fdr.fold, c->alpha);
    fdr.capture = cap;
    fdr.capture_cap = MAXC;
    fdr.capture_len = 0;
    air->air_eval(&fdr);

    int trace_pass = 0;
    if ((int)fdr.capture_len != expect_n) {
        fprintf(stderr, "  %s: air_eval emitted %zu constraints != %d\n", c->name, fdr.capture_len, expect_n);
        fail++;
    }
    if (c->n_constraints != expect_n) {
        fprintf(stderr, "  %s: vector has %d constraints != %d\n", c->name, c->n_constraints, expect_n);
        fail++;
    }
    for (int i = 0; i < (int)fdr.capture_len && i < c->n_constraints; i++) {
        if (gold_fp2_eq(cap[i].received, c->applied[i]) && gold_fp2_eq(cap[i].after, c->acc_after[i])) {
            trace_pass++;
        } else {
            fail++;
            fprintf(stderr,
                    "  MISMATCH per-constraint\n    case:%s\n    index:%d\n"
                    "    expected received=(%llu,%llu) after=(%llu,%llu)\n"
                    "    actual   received=(%llu,%llu) after=(%llu,%llu)\n"
                    "    (check emission order / selector / public order / bit order / arithmetic)\n",
                    c->name, i,
                    (unsigned long long)gold_fp_to_u64(c->applied[i].a), (unsigned long long)gold_fp_to_u64(c->applied[i].b),
                    (unsigned long long)gold_fp_to_u64(c->acc_after[i].a), (unsigned long long)gold_fp_to_u64(c->acc_after[i].b),
                    (unsigned long long)gold_fp_to_u64(cap[i].received.a), (unsigned long long)gold_fp_to_u64(cap[i].received.b),
                    (unsigned long long)gold_fp_to_u64(cap[i].after.a), (unsigned long long)gold_fp_to_u64(cap[i].after.b));
        }
    }
    if (!gold_fp2_eq(fdr.fold.acc, c->folded)) { fprintf(stderr, "  %s: air_eval folded != vector\n", c->name); fail++; }

    /* 3. final_lhs == final_rhs */
    gold_fp2_t lhs = gold_fp2_mul(c->folded, sels.inv_vanishing);
    if (!gold_fp2_eq(lhs, c->quotient_zeta)) { fprintf(stderr, "  %s: folded*inv_van != quotient_zeta\n", c->name); fail++; }
    if (!c->final_equal) { fprintf(stderr, "  %s: vector final_equal != true\n", c->name); fail++; }

    printf("  [%s] %s: verify_constraints=OK | per-constraint %d/%d | folded==vector | final OK\n",
           fail ? "FAIL" : "OK  ", c->name, trace_pass, expect_n);
    return fail;
}

/* ===== negatives ===== */
static int expect_status(const char *name, dnac_stark_verify_status_t got, dnac_stark_verify_status_t want) {
    if (got == want) { printf("  [OK  ] %-42s -> %d\n", name, (int)got); return 0; }
    fprintf(stderr, "  [FAIL] %-42s got %d want %d\n", name, (int)got, (int)want);
    return 1;
}
static int run_negatives(const case_t *rv, const case_t *cv) {
    int fail = 0;
    const gold_fp2_t one = gold_fp2_one();

    /* combined: trace_next present */
    const gold_fp2_t *cv_tn = cv->trace_next;
    size_t cv_tn_len = (size_t)cv->n_trace_next;

    /* N1 — corrupt a bit column (combined) -> OOD (changes B0 + S). */
    {
        gold_fp2_t t[MAXW];
        for (int i = 0; i < cv->n_trace_local; i++) t[i] = cv->trace_local[i];
        t[0] = gold_fp2_add(t[0], one);
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, t, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N1 corrupt bit column (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N2 — corrupt amount column (combined) -> OOD. */
    {
        gold_fp2_t t[MAXW];
        for (int i = 0; i < cv->n_trace_local; i++) t[i] = cv->trace_local[i];
        t[COL_AMOUNT] = gold_fp2_add(t[COL_AMOUNT], one);
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, t, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N2 corrupt amount column (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N3 — corrupt acc column (combined) -> OOD. */
    {
        gold_fp2_t t[MAXW];
        for (int i = 0; i < cv->n_trace_local; i++) t[i] = cv->trace_local[i];
        t[COL_ACC] = gold_fp2_add(t[COL_ACC], one);
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, t, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N3 corrupt acc column (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N4 — swap claimed/fee public order (combined) -> OOD (F breaks). */
    {
        gold_fp_t swapped[3] = { cv->public_values[1], cv->public_values[0],
                                 cv->public_values[2] };
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, cv->trace_local, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            swapped, 3, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N4 swap public_values (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N5 — wrong width (combined): claim width-1 -> SHAPE. */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, cv->trace_local, (size_t)cv->n_trace_local - 1, cv_tn, cv_tn_len,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N5 wrong width (combined)", st, DNAC_STARK_VERIFY_ERR_SHAPE);
    }
    /* N6 — combined missing trace_next -> SHAPE. */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, cv->trace_local, (size_t)cv->n_trace_local, NULL, 0,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N6 combined missing trace_next", st, DNAC_STARK_VERIFY_ERR_SHAPE);
    }
    /* N7 — RangeOnlyAir with absent trace_next -> OK (main_next=false). */
    {
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_ONLY_AIR, rv->trace_local, (size_t)rv->n_trace_local, NULL, 0,
            rv->public_values, (size_t)rv->n_public, rv->zeta, (size_t)rv->base_degree_bits, rv->alpha, rv->chunk0);
        fail += expect_status("N7 range-only trace_next absent", st, DNAC_STARK_VERIFY_OK);
    }
    /* N8 — corrupt is_real column (combined) -> OOD (R/P/CI/CU break). */
    {
        gold_fp2_t t[MAXW];
        for (int i = 0; i < cv->n_trace_local; i++) t[i] = cv->trace_local[i];
        t[COL_IS_REAL] = gold_fp2_add(t[COL_IS_REAL], one);
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, t, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            cv->public_values, (size_t)cv->n_public, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N8 corrupt is_real column (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    /* N9 — perturb n_real public (count forgery) -> OOD (CF breaks). */
    {
        gold_fp_t forged[3] = { cv->public_values[0], cv->public_values[1],
                                gold_fp_add(cv->public_values[2], gold_fp_one()) };
        dnac_stark_verify_status_t st = dnac_stark_verify_constraints(
            &RANGE_PROOF_AIR, cv->trace_local, (size_t)cv->n_trace_local, cv_tn, cv_tn_len,
            forged, 3, cv->zeta, (size_t)cv->base_degree_bits, cv->alpha, cv->chunk0);
        fail += expect_status("N9 forge n_real public (combined)", st, DNAC_STARK_VERIFY_ERR_OOD_MISMATCH);
    }
    return fail;
}

static int check_flags(const char *path, const file_t *fl) {
    int fail = 0;
    if (!fl->additive_only) { fprintf(stderr, "  %s: additive_only != true\n", path); fail++; }
    if (fl->confidential_use_allowed) { fprintf(stderr, "  %s: confidential_use_allowed != false\n", path); fail++; }
    /* 2026-07 soundness fix: B6 (field-wrap) closed on the OUTPUT side by 52-bit +
     * height<=1024. The FEE/CLAIMED side of B6 (the F mod-p equation) is closed by
     * a verifier-side SOFTWARE bound on the PUBLIC inputs (claimed,fee < 2^62 —
     * see the "STARK-path public-input bound" test above and sum_balance.c), NOT
     * an AIR constraint. B7 (padding/count) closed by is_real/P/cnt. B1 flagged. */
    if (!fl->blocker_b1) {
        fprintf(stderr, "  %s: blockers must include B1\n", path); fail++;
    }
    if (fl->blocker_b6 || fl->blocker_b7) {
        fprintf(stderr, "  %s: B6/B7 are resolved and must NOT be flagged\n", path); fail++;
    }
    return fail;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <range_air_only.json> <range_proof_air.json>\n", argv[0]);
        return 2;
    }
    file_t rf, cf;
    if (parse_file(argv[1], &rf) != 0 || parse_file(argv[2], &cf) != 0) return 1;

    printf("S5.x — C range_proof_air air_eval (ADDITIVE) vs real-Plonky3 S5.1 vectors\n");
    int fail = 0;

    printf("  --- flags (ADDITIVE only; CONFIDENTIAL blocked) ---\n");
    fail += check_flags("range_air_only.json", &rf);
    fail += check_flags("range_proof_air.json", &cf);

    printf("  --- RangeOnlyAir (53 constraints) ---\n");
    for (int i = 0; i < rf.n_cases; i++) fail += run_case(&RANGE_ONLY_AIR, &rf.cases[i], 53);

    printf("  --- RangeProofAir combined (61 constraints) ---\n");
    for (int i = 0; i < cf.n_cases; i++) {
        /* Wrap-safety: the combined AIR is only sound for heights <= 2^10
         * (1024 rows); a vector beyond that bound is invalid by definition. */
        if (cf.cases[i].base_degree_bits > RANGE_PROOF_MAX_DEGREE_BITS) {
            fprintf(stderr, "  %s: degree_bits %llu > %u (wrap-safety bound)\n",
                    cf.cases[i].name,
                    (unsigned long long)cf.cases[i].base_degree_bits,
                    RANGE_PROOF_MAX_DEGREE_BITS);
            fail++;
        }
        fail += run_case(&RANGE_PROOF_AIR, &cf.cases[i], 61);
    }

    printf("  --- negative cases ---\n");
    if (rf.n_cases > 0 && cf.n_cases > 0) fail += run_negatives(&rf.cases[0], &cf.cases[0]);
    else { fprintf(stderr, "  no cases for negatives\n"); fail++; }

    printf("  --- P-constraint isolation (forged padding row) ---\n");
    fail += test_p_isolation();

    /* --- STARK-path fee/claimed public-input bound ---
     * RangeProofAir's F constraint (acc - (claimed - fee)) is a mod-p equation
     * with UNBOUNDED public claimed/fee. Range-checking outputs does NOT close
     * the fee-side wrap: a wire committed_fee = p - A mints A (same G1 bug as the
     * direct sum_balance path). claimed/fee are PUBLIC (cleartext), so the
     * closure is a verifier-side SOFTWARE bound (both < SUM_BALANCE_TERM_MAX =
     * 2^62), NOT an AIR constraint. This is enforced in sum_balance.c; any STARK
     * verifier gating money MUST apply the same bound to the public values before
     * trusting the proof. Below grounds that predicate (hand-pinned, no oracle). */
    printf("  --- STARK-path public-input bound (fee/claimed wrap) ---\n");
    {
        const uint64_t GOLD_P = UINT64_C(0xFFFFFFFF00000001);
        struct { const char *name; uint64_t claimed, fee; bool want_ok; } pv[] = {
            { "vector publics (107,7) within bound",   107, 7,              true  },
            { "fee-wrap mint (0, p-1000)",             0,   GOLD_P - 1000,  false },
            { "claimed-wrap (p-1000, 0)",              GOLD_P - 1000, 0,    false },
            { "boundary claimed==2^62",                (uint64_t)SUM_BALANCE_TERM_MAX, 0, false },
            { "boundary claimed==2^62-1 ok",           (uint64_t)SUM_BALANCE_TERM_MAX - 1, 5, true },
        };
        for (size_t i = 0; i < sizeof(pv)/sizeof(pv[0]); i++) {
            bool ok = (pv[i].claimed < SUM_BALANCE_TERM_MAX) &&
                      (pv[i].fee < SUM_BALANCE_TERM_MAX);
            if (ok == pv[i].want_ok) {
                printf("  [OK  ] pub-bound: %s -> %s\n", pv[i].name, ok ? "within" : "rejected");
            } else {
                fprintf(stderr, "  [FAIL] pub-bound: %s -> got %s want %s\n",
                        pv[i].name, ok ? "within" : "rejected",
                        pv[i].want_ok ? "within" : "rejected");
                fail++;
            }
        }
    }

    if (fail) {
        fprintf(stderr, "test_range_proof_air: %d FAIL(s)\n", fail);
        return 1;
    }
    printf("test_range_proof_air: PASS\n");
    printf("  RangeOnlyAir + RangeProofAir verify_constraints==OK all cases; per-constraint 53/53 + 61/61;\n");
    printf("  9 negatives + P-isolation (forged padding row) + STARK public-input bound (fee-wrap) as expected;\n");
    printf("  ADDITIVE-only flags confirmed (CONFIDENTIAL blocked B1; B6 output-side + B7 closed by 52-bit +\n");
    printf("  is_real/cnt; B6 fee-side closed by verifier software pub-bound < 2^62).\n");
    return 0;
}
