/**
 * @file test_fri_fold_matrix_loga1_oracle.c
 * @brief Phase D.3 — byte-match gate for fri_fold_matrix_fp2 (log_arity == 1).
 *
 * Loads tools/vectors/fri_fold_matrix_loga1.json (~13MB, 330 cases) and asserts
 * exact u64 limb equality between C `fri_fold_matrix_fp2` output and Plonky3
 * `TwoAdicFriFolding::fold_matrix` log_arity==1 branch (commit 82cfad73,
 * fri/src/two_adic_pcs.rs:135-162).
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one byte-mismatch
 *   2  load / parse error
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../zk_field_helpers.h"
#include "../fri_fold.h"

/* ============================================================================
 * Minimal JSON scanner
 * ========================================================================== */
typedef struct {
    const char *src;
    size_t      pos;
    size_t      len;
} js_t;

static void js_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}

static bool js_match(js_t *s, char c) {
    js_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}

static bool js_key(js_t *s, const char *key) {
    js_ws(s);
    size_t klen = strlen(key);
    if (s->pos + klen + 2 > s->len) return false;
    if (s->src[s->pos] != '"') return false;
    if (memcmp(s->src + s->pos + 1, key, klen) != 0) return false;
    if (s->src[s->pos + 1 + klen] != '"') return false;
    s->pos += klen + 2;
    return true;
}

static char *js_str(js_t *s) {
    js_ws(s);
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

static bool js_str_u64(js_t *s, uint64_t *out) {
    char *str = js_str(s);
    if (!str) return false;
    char *endp = NULL;
    *out = strtoull(str, &endp, 10);
    bool ok = (endp != NULL && *endp == '\0');
    free(str);
    return ok;
}

static bool js_num_u64(js_t *s, uint64_t *out) {
    js_ws(s);
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}

static bool js_pair_u64(js_t *s, uint64_t *a_out, uint64_t *b_out) {
    if (!js_match(s, '[')) return false;
    if (!js_str_u64(s, a_out)) return false;
    js_match(s, ',');
    if (!js_str_u64(s, b_out)) return false;
    js_ws(s);
    return js_match(s, ']');
}

static bool js_pair_array(js_t *s,
                          uint64_t **a_out, uint64_t **b_out, size_t *n_out)
{
    if (!js_match(s, '[')) return false;
    size_t cap = 16, n = 0;
    uint64_t *a = (uint64_t *)malloc(cap * sizeof(uint64_t));
    uint64_t *b = (uint64_t *)malloc(cap * sizeof(uint64_t));
    if (!a || !b) { free(a); free(b); return false; }
    while (1) {
        js_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        uint64_t va, vb;
        if (!js_pair_u64(s, &va, &vb)) { free(a); free(b); return false; }
        if (n == cap) {
            cap *= 2;
            uint64_t *na = (uint64_t *)realloc(a, cap * sizeof(uint64_t));
            uint64_t *nb = (uint64_t *)realloc(b, cap * sizeof(uint64_t));
            if (!na || !nb) { free(na ? na : a); free(nb ? nb : b); return false; }
            a = na; b = nb;
        }
        a[n] = va; b[n] = vb; n++;
    }
    *a_out = a; *b_out = b; *n_out = n;
    return true;
}

static bool js_seek_cases(js_t *s) {
    s->pos = 0;
    const char *needle = "\"cases\"";
    size_t nlen = strlen(needle);
    while (s->pos + nlen + 4 < s->len) {
        if (memcmp(s->src + s->pos, needle, nlen) == 0) {
            s->pos += nlen;
            js_ws(s);
            if (s->pos < s->len && s->src[s->pos] == ':') {
                s->pos++;
                js_ws(s);
                if (s->pos < s->len && s->src[s->pos] == '[') {
                    s->pos++;
                    return true;
                }
            }
        }
        s->pos++;
    }
    return false;
}

static char *load_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *len_out = (size_t)sz;
    return buf;
}

/* ============================================================================
 * Case runner
 * ========================================================================== */

typedef struct {
    int       case_idx;
    uint64_t  log_arity;
    uint64_t  height;
    uint64_t  beta_a, beta_b;
    uint64_t *matrix_a; uint64_t *matrix_b; size_t matrix_n;
    uint64_t *exp_a;    uint64_t *exp_b;    size_t exp_n;
} matcase_t;

static void free_case(matcase_t *c) {
    free(c->matrix_a); free(c->matrix_b);
    free(c->exp_a);    free(c->exp_b);
    c->matrix_a = c->matrix_b = c->exp_a = c->exp_b = NULL;
}

static bool parse_case(js_t *s, matcase_t *c) {
    memset(c, 0, sizeof(*c));
    if (!js_match(s, '{')) return false;
    bool got_matrix = false, got_expected = false;

    while (1) {
        js_ws(s);
        if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }

        if (js_key(s, "log_arity")) {
            js_match(s, ':');
            if (!js_num_u64(s, &c->log_arity)) return false;
        } else if (js_key(s, "height")) {
            js_match(s, ':');
            if (!js_num_u64(s, &c->height)) return false;
        } else if (js_key(s, "beta")) {
            js_match(s, ':');
            if (!js_pair_u64(s, &c->beta_a, &c->beta_b)) return false;
        } else if (js_key(s, "matrix")) {
            js_match(s, ':');
            if (!js_pair_array(s, &c->matrix_a, &c->matrix_b, &c->matrix_n)) return false;
            got_matrix = true;
        } else if (js_key(s, "expected")) {
            js_match(s, ':');
            if (!js_pair_array(s, &c->exp_a, &c->exp_b, &c->exp_n)) return false;
            got_expected = true;
        } else {
            fprintf(stderr, "FAIL: unknown key in matrix case at pos %zu\n", s->pos);
            return false;
        }
    }
    return got_matrix && got_expected;
}

static void describe_case(const matcase_t *c, char *buf, size_t buflen) {
    snprintf(buf, buflen,
             "case=%d log_a=%" PRIu64 " height=%" PRIu64
             " beta=(%" PRIu64 ",%" PRIu64 ")",
             c->case_idx, c->log_arity, c->height, c->beta_a, c->beta_b);
}

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/fri_fold_matrix_loga1.json";

    size_t len;
    char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    js_t s = { buf, 0, len };
    if (!js_seek_cases(&s)) {
        fprintf(stderr, "FAIL: cannot locate \"cases\" array\n");
        free(buf);
        return 2;
    }

    int total = 0, passed = 0, failed = 0;
    int reported = 0;

    while (1) {
        js_ws(&s);
        if (s.pos < s.len && s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }

        matcase_t c;
        c.case_idx = total;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "FAIL: parse error near case_idx=%d pos=%zu\n",
                    total, s.pos);
            free(buf);
            return 2;
        }

        /* Layout sanity. */
        size_t height_sz = (size_t)c.height;
        size_t cols = (size_t)1u << c.log_arity;       /* = 2 for log_arity == 1 */
        if (c.matrix_n != height_sz * cols) {
            fprintf(stderr, "FAIL: matrix_n=%zu but height*cols=%zu (case %d)\n",
                    c.matrix_n, height_sz * cols, total);
            free_case(&c); free(buf); return 2;
        }
        if (c.exp_n != height_sz) {
            fprintf(stderr, "FAIL: exp_n=%zu but height=%zu (case %d)\n",
                    c.exp_n, height_sz, total);
            free_case(&c); free(buf); return 2;
        }

        /* Build C-side fp2 inputs. */
        gold_fp2_t *matrix_fp2 = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * c.matrix_n);
        gold_fp2_t *out_vec    = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * height_sz);
        if (!matrix_fp2 || !out_vec) {
            free(matrix_fp2); free(out_vec);
            free_case(&c); free(buf); return 2;
        }
        for (size_t i = 0; i < c.matrix_n; i++) {
            matrix_fp2[i] = gold_fp2_new(
                gold_fp_from_u64(c.matrix_a[i]),
                gold_fp_from_u64(c.matrix_b[i]));
        }
        gold_fp2_t beta = gold_fp2_new(
            gold_fp_from_u64(c.beta_a),
            gold_fp_from_u64(c.beta_b));

        fri_fold_matrix_fp2(beta, (unsigned)c.log_arity, height_sz,
                            matrix_fp2, out_vec);

        /* Byte-compare each output row. */
        int case_failed_row = -1;
        for (size_t i = 0; i < height_sz; i++) {
            uint64_t got_a = gold_fp_to_u64(out_vec[i].a);
            uint64_t got_b = gold_fp_to_u64(out_vec[i].b);
            if (got_a != c.exp_a[i] || got_b != c.exp_b[i]) {
                case_failed_row = (int)i;
                if (reported < 5) {
                    char desc[256];
                    describe_case(&c, desc, sizeof(desc));
                    fprintf(stderr, "MISMATCH %s row=%zu\n"
                                    "  expected=(%" PRIu64 ",%" PRIu64 ")\n"
                                    "  actual  =(%" PRIu64 ",%" PRIu64 ")\n"
                                    "  suspected source block:\n"
                                    "    Plonky3 two_adic_pcs.rs:149-154\n"
                                    "      (g_inv, halve_inv_powers, reverse_slice_index_bits)\n"
                                    "    or Plonky3 two_adic_pcs.rs:156-162\n"
                                    "      (fold loop: (lo+hi)/2 + (lo-hi)*beta*halve_inv_power)\n",
                            desc, i, c.exp_a[i], c.exp_b[i], got_a, got_b);
                    reported++;
                }
                break;
            }
        }
        if (case_failed_row < 0) passed++;
        else                     failed++;

        free(matrix_fp2);
        free(out_vec);
        free_case(&c);
        total++;
    }

    printf("\n%-40s  %5d cases\n", "fri_fold_matrix_loga1 total",  total);
    printf("%-40s  %5d\n",         "fri_fold_matrix_loga1 passed", passed);
    printf("%-40s  %5d\n",         "fri_fold_matrix_loga1 failed", failed);
    printf("\nPHASE D.3 ORACLE GATE: %s\n",
           failed == 0 ? "GREEN" : "RED");

    free(buf);
    return failed == 0 ? 0 : 1;
}
