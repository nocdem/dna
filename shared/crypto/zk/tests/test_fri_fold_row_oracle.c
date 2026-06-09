/**
 * @file test_fri_fold_row_oracle.c
 * @brief Phase D.2 — byte-match gate for fri_fold_row_fp2 vs Plonky3.
 *
 * Loads tools/vectors/fri_fold_row.json (~131k lines, 3000+ cases) and asserts
 * exact u64 limb equality between C `fri_fold_row_fp2` output and Plonky3
 * `TwoAdicFriFolding::fold_row` (commit 82cfad73, fri/src/two_adic_pcs.rs:109-132).
 *
 * Indirectly byte-verifies static `lagrange_interpolate_at_fp_fp2` since
 * fri_fold_row_fp2's only non-helper call is into lagrange.
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
 * Minimal JSON scanner (same shape as other Phase tests)
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

/* Read JSON number (no quotes). */
static bool js_num_u64(js_t *s, uint64_t *out) {
    js_ws(s);
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}

/* Read [a, b] string pair into (a_out, b_out). */
static bool js_pair_u64(js_t *s, uint64_t *a_out, uint64_t *b_out) {
    if (!js_match(s, '[')) return false;
    if (!js_str_u64(s, a_out)) return false;
    js_match(s, ',');
    if (!js_str_u64(s, b_out)) return false;
    js_ws(s);
    return js_match(s, ']');
}

/* Locate the "cases" array. */
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

/* ============================================================================
 * File loader
 * ========================================================================== */
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
    int      case_idx;
    uint64_t log_height;
    uint64_t log_arity;
    uint64_t index;
    uint64_t beta_a, beta_b;
    uint64_t *evals_a;
    uint64_t *evals_b;
    size_t    evals_n;
    uint64_t exp_a, exp_b;
} case_t;

static void free_case(case_t *c) {
    free(c->evals_a);
    free(c->evals_b);
    c->evals_a = NULL;
    c->evals_b = NULL;
}

/* Parse one case object from `{ ... }`. */
static bool parse_case(js_t *s, case_t *c) {
    memset(c, 0, sizeof(*c));
    if (!js_match(s, '{')) return false;
    bool got_evals = false;

    while (1) {
        js_ws(s);
        if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }

        if (js_key(s, "log_height")) {
            js_match(s, ':');
            if (!js_num_u64(s, &c->log_height)) return false;
        } else if (js_key(s, "log_arity")) {
            js_match(s, ':');
            if (!js_num_u64(s, &c->log_arity)) return false;
        } else if (js_key(s, "index")) {
            js_match(s, ':');
            if (!js_str_u64(s, &c->index)) return false;
        } else if (js_key(s, "beta")) {
            js_match(s, ':');
            if (!js_pair_u64(s, &c->beta_a, &c->beta_b)) return false;
        } else if (js_key(s, "evals")) {
            js_match(s, ':');
            if (!js_match(s, '[')) return false;
            size_t cap = 16, n = 0;
            uint64_t *ea = (uint64_t *)malloc(cap * sizeof(uint64_t));
            uint64_t *eb = (uint64_t *)malloc(cap * sizeof(uint64_t));
            if (!ea || !eb) { free(ea); free(eb); return false; }
            while (1) {
                js_ws(s);
                if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
                if (s->src[s->pos] == ',') { s->pos++; continue; }
                uint64_t va, vb;
                if (!js_pair_u64(s, &va, &vb)) { free(ea); free(eb); return false; }
                if (n == cap) {
                    cap *= 2;
                    uint64_t *na = (uint64_t *)realloc(ea, cap * sizeof(uint64_t));
                    uint64_t *nb = (uint64_t *)realloc(eb, cap * sizeof(uint64_t));
                    if (!na || !nb) {
                        free(na ? na : ea); free(nb ? nb : eb);
                        return false;
                    }
                    ea = na; eb = nb;
                }
                ea[n] = va; eb[n] = vb; n++;
            }
            c->evals_a = ea; c->evals_b = eb; c->evals_n = n;
            got_evals = true;
        } else if (js_key(s, "expected")) {
            js_match(s, ':');
            if (!js_pair_u64(s, &c->exp_a, &c->exp_b)) return false;
        } else {
            fprintf(stderr, "FAIL: unknown key in case object at pos %zu\n", s->pos);
            return false;
        }
    }
    if (!got_evals) return false;
    return true;
}

/* Format a short description of a case for mismatch reports. */
static void describe_case(const case_t *c, char *buf, size_t buflen) {
    snprintf(buf, buflen,
             "case=%d log_h=%" PRIu64 " log_a=%" PRIu64 " index=%" PRIu64
             " beta=(%" PRIu64 ",%" PRIu64 ") evals_n=%zu",
             c->case_idx, c->log_height, c->log_arity, c->index,
             c->beta_a, c->beta_b, c->evals_n);
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/fri_fold_row.json";

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

        case_t c;
        c.case_idx = total;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "FAIL: parse error near case_idx=%d pos=%zu\n",
                    total, s.pos);
            free(buf);
            return 2;
        }
        /* Verify evals_n == 1 << log_arity per oracle contract. */
        size_t expected_n = (size_t)1u << c.log_arity;
        if (c.evals_n != expected_n) {
            fprintf(stderr, "FAIL: case_idx=%d evals_n=%zu != 1<<log_arity=%zu\n",
                    total, c.evals_n, expected_n);
            free_case(&c);
            free(buf);
            return 2;
        }

        /* Build C-side fp2 arrays from parsed u64 limbs. */
        gold_fp2_t *evals_fp2 = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * c.evals_n);
        if (!evals_fp2) { free_case(&c); free(buf); return 2; }
        for (size_t i = 0; i < c.evals_n; i++) {
            evals_fp2[i] = gold_fp2_new(
                gold_fp_from_u64(c.evals_a[i]),
                gold_fp_from_u64(c.evals_b[i]));
        }
        gold_fp2_t beta = gold_fp2_new(
            gold_fp_from_u64(c.beta_a),
            gold_fp_from_u64(c.beta_b));

        /* Run C fold_row. */
        gold_fp2_t got = fri_fold_row_fp2(
            (size_t)c.index,
            (unsigned)c.log_height,
            (unsigned)c.log_arity,
            beta,
            evals_fp2,
            c.evals_n);

        uint64_t got_a = gold_fp_to_u64(got.a);
        uint64_t got_b = gold_fp_to_u64(got.b);

        if (got_a == c.exp_a && got_b == c.exp_b) {
            passed++;
        } else {
            failed++;
            if (reported < 5) {
                char desc[256];
                describe_case(&c, desc, sizeof(desc));
                fprintf(stderr, "MISMATCH %s\n"
                                "  expected=(%" PRIu64 ", %" PRIu64 ")\n"
                                "  actual  =(%" PRIu64 ", %" PRIu64 ")\n"
                                "  suspected source block:\n"
                                "    Plonky3 two_adic_pcs.rs:122-128 (xs construction:\n"
                                "      subgroup_start, shifted_powers, reverse_slice_index_bits)\n"
                                "    or Plonky3 two_adic_pcs.rs:220-260 (lagrange_interpolate_at)\n",
                        desc, c.exp_a, c.exp_b, got_a, got_b);
                reported++;
            }
        }

        free(evals_fp2);
        free_case(&c);
        total++;
    }

    printf("\n%-40s  %5d cases\n", "fri_fold_row total", total);
    printf("%-40s  %5d\n", "fri_fold_row passed", passed);
    printf("%-40s  %5d\n", "fri_fold_row failed", failed);
    printf("\nPHASE D.2 ORACLE GATE: %s\n",
           failed == 0 ? "GREEN" : "RED");

    free(buf);
    return failed == 0 ? 0 : 1;
}
