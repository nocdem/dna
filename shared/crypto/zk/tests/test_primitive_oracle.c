/**
 * @file test_primitive_oracle.c
 * @brief Phase C — byte-equivalence gate against Plonky3 primitive_ops oracle.
 *
 * Loads tools/vectors/primitive_ops.json (~14k lines) and asserts that:
 *   - reverse_slice_index_bits_fp  (C) byte-matches Plonky3 p3_util::reverse_slice_index_bits
 *   - reverse_slice_index_bits_fp2 (C) byte-matches Plonky3 (over Goldilocks²)
 *   - gold_fp_pow with large u64 exponents byte-matches Plonky3 Goldilocks::exp_u64
 *
 * Other Phase C primitives (gold_fp_inv, gold_fp_pow small-exponent,
 * gold_fp2_mul, gold_fp2_sqr, gold_fp2_inv, gold_fp_two_adic_generator)
 * are byte-verified by the existing tests:
 *   - test_field_goldilocks       → field_ops.json    (7142 cases GREEN)
 *   - test_field_goldilocks_ext   → field_ext.json    (6185 cases GREEN)
 *   - test_two_adic_gens          → two_adic_gens.json (33 cases GREEN)
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
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

/* ============================================================================
 * Minimal JSON scanner (same shape as test_field_goldilocks.c)
 * ========================================================================== */

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} json_scanner_t;

static void js_skip_ws(json_scanner_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            s->pos++;
        } else {
            return;
        }
    }
}

static bool js_match(json_scanner_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) {
        s->pos++;
        return true;
    }
    return false;
}

static bool js_match_key(json_scanner_t *s, const char *key) {
    js_skip_ws(s);
    size_t klen = strlen(key);
    if (s->pos + klen + 2 > s->len) return false;
    if (s->src[s->pos] != '"') return false;
    if (memcmp(s->src + s->pos + 1, key, klen) != 0) return false;
    if (s->src[s->pos + 1 + klen] != '"') return false;
    s->pos += klen + 2;
    return true;
}

static char *js_read_string(json_scanner_t *s) {
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

static bool js_read_u64_string(json_scanner_t *s, uint64_t *out) {
    char *str = js_read_string(s);
    if (!str) return false;
    char *endp = NULL;
    *out = strtoull(str, &endp, 10);
    bool ok = (endp != NULL && *endp == '\0');
    free(str);
    return ok;
}

/* Read a JSON number (raw integer) without quotes. Returns true on success. */
static bool js_read_size(json_scanner_t *s, size_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (size_t)v;
    return true;
}

/* Locate the named top-level array; leaves scanner just past `[`. */
static bool js_seek_array(json_scanner_t *s, const char *key) {
    s->pos = 0;
    size_t klen = strlen(key);
    while (s->pos + klen + 4 < s->len) {
        if (s->src[s->pos] == '"' &&
            memcmp(s->src + s->pos + 1, key, klen) == 0 &&
            s->src[s->pos + 1 + klen] == '"') {
            s->pos += klen + 2;
            js_skip_ws(s);
            if (s->pos < s->len && s->src[s->pos] == ':') {
                s->pos++;
                js_skip_ws(s);
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

/* Read array of decimal-string u64s into a malloc'd buffer. Caller frees. */
static uint64_t *js_read_string_u64_array(json_scanner_t *s, size_t *count_out) {
    if (!js_match(s, '[')) return NULL;
    size_t cap = 16, n = 0;
    uint64_t *buf = (uint64_t *)malloc(cap * sizeof(uint64_t));
    if (!buf) return NULL;
    while (1) {
        js_skip_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        uint64_t v;
        if (!js_read_u64_string(s, &v)) { free(buf); return NULL; }
        if (n == cap) {
            cap *= 2;
            uint64_t *nb = (uint64_t *)realloc(buf, cap * sizeof(uint64_t));
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        buf[n++] = v;
    }
    *count_out = n;
    return buf;
}

/* Read array of [decimal-string, decimal-string] pairs (fp2 components). */
static bool js_read_string_pair_array(json_scanner_t *s,
                                      uint64_t **a_out, uint64_t **b_out,
                                      size_t *count_out) {
    if (!js_match(s, '[')) return false;
    size_t cap = 16, n = 0;
    uint64_t *a = (uint64_t *)malloc(cap * sizeof(uint64_t));
    uint64_t *b = (uint64_t *)malloc(cap * sizeof(uint64_t));
    if (!a || !b) { free(a); free(b); return false; }
    while (1) {
        js_skip_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (!js_match(s, '[')) { free(a); free(b); return false; }
        uint64_t va, vb;
        if (!js_read_u64_string(s, &va)) { free(a); free(b); return false; }
        js_match(s, ',');
        if (!js_read_u64_string(s, &vb)) { free(a); free(b); return false; }
        js_skip_ws(s);
        if (!js_match(s, ']')) { free(a); free(b); return false; }
        if (n == cap) {
            cap *= 2;
            uint64_t *na = (uint64_t *)realloc(a, cap * sizeof(uint64_t));
            uint64_t *nb = (uint64_t *)realloc(b, cap * sizeof(uint64_t));
            if (!na || !nb) { free(na ? na : a); free(nb ? nb : b); return false; }
            a = na; b = nb;
        }
        a[n] = va; b[n] = vb; n++;
    }
    *a_out = a; *b_out = b; *count_out = n;
    return true;
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
 * Runners
 * ========================================================================== */

static int run_reverse_fp(json_scanner_t *s) {
    if (!js_seek_array(s, "reverse_slice_index_bits_fp")) {
        fprintf(stderr, "FAIL: locate reverse_slice_index_bits_fp\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (!js_match(s, '{')) { fprintf(stderr, "FAIL: expected '{' fp case\n"); return -1; }

        size_t n_case = 0;
        uint64_t *input = NULL, *output = NULL;
        size_t in_n = 0, out_n = 0;

        while (1) {
            js_skip_ws(s);
            if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "n")) {
                js_match(s, ':');
                if (!js_read_size(s, &n_case)) { fprintf(stderr, "FAIL n\n"); return -1; }
            } else if (js_match_key(s, "input")) {
                js_match(s, ':');
                input = js_read_string_u64_array(s, &in_n);
                if (!input) { fprintf(stderr, "FAIL input parse\n"); return -1; }
            } else if (js_match_key(s, "output")) {
                js_match(s, ':');
                output = js_read_string_u64_array(s, &out_n);
                if (!output) { fprintf(stderr, "FAIL output parse\n"); return -1; }
            } else {
                fprintf(stderr, "FAIL: unknown key fp case\n");
                free(input); free(output);
                return -1;
            }
        }
        if (!input || !output || in_n != n_case || out_n != n_case) {
            fprintf(stderr, "FAIL: missing/mismatched fields fp n=%zu\n", n_case);
            free(input); free(output);
            return -1;
        }

        /* Apply C reverse_slice_index_bits_fp to a fresh copy of input;
           compare result to oracle output byte-for-byte. */
        gold_fp_t *vals = (gold_fp_t *)malloc(sizeof(gold_fp_t) * n_case);
        if (!vals) { free(input); free(output); return -1; }
        for (size_t i = 0; i < n_case; i++) {
            vals[i] = gold_fp_from_u64(input[i]);
        }
        reverse_slice_index_bits_fp(vals, n_case);

        int case_failed = 0;
        for (size_t i = 0; i < n_case; i++) {
            uint64_t got = gold_fp_to_u64(vals[i]);
            if (got != output[i]) {
                if (failed < 5) {
                    fprintf(stderr,
                            "MISMATCH reverse_fp n=%zu i=%zu got=%" PRIu64
                            " want=%" PRIu64 "\n", n_case, i, got, output[i]);
                }
                case_failed = 1;
                break;
            }
        }
        if (case_failed) failed++; else passed++;

        free(vals); free(input); free(output);
    }
    printf("%-32s  %5d passed  %5d failed\n",
           "reverse_slice_index_bits_fp", passed, failed);
    return failed;
}

static int run_reverse_fp2(json_scanner_t *s) {
    if (!js_seek_array(s, "reverse_slice_index_bits_fp2")) {
        fprintf(stderr, "FAIL: locate reverse_slice_index_bits_fp2\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (!js_match(s, '{')) { fprintf(stderr, "FAIL: expected '{' fp2 case\n"); return -1; }

        size_t n_case = 0;
        uint64_t *in_a = NULL, *in_b = NULL, *out_a = NULL, *out_b = NULL;
        size_t in_n = 0, out_n = 0;

        while (1) {
            js_skip_ws(s);
            if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "n")) {
                js_match(s, ':');
                if (!js_read_size(s, &n_case)) return -1;
            } else if (js_match_key(s, "input")) {
                js_match(s, ':');
                if (!js_read_string_pair_array(s, &in_a, &in_b, &in_n)) {
                    fprintf(stderr, "FAIL fp2 input parse\n"); return -1;
                }
            } else if (js_match_key(s, "output")) {
                js_match(s, ':');
                if (!js_read_string_pair_array(s, &out_a, &out_b, &out_n)) {
                    fprintf(stderr, "FAIL fp2 output parse\n"); return -1;
                }
            } else {
                fprintf(stderr, "FAIL: unknown key fp2 case\n");
                free(in_a); free(in_b); free(out_a); free(out_b);
                return -1;
            }
        }
        if (!in_a || !out_a || in_n != n_case || out_n != n_case) {
            fprintf(stderr, "FAIL fp2 fields n=%zu\n", n_case);
            free(in_a); free(in_b); free(out_a); free(out_b);
            return -1;
        }

        gold_fp2_t *vals = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * n_case);
        if (!vals) {
            free(in_a); free(in_b); free(out_a); free(out_b);
            return -1;
        }
        for (size_t i = 0; i < n_case; i++) {
            vals[i] = gold_fp2_new(gold_fp_from_u64(in_a[i]),
                                   gold_fp_from_u64(in_b[i]));
        }
        reverse_slice_index_bits_fp2(vals, n_case);

        int case_failed = 0;
        for (size_t i = 0; i < n_case; i++) {
            uint64_t got_a = gold_fp_to_u64(vals[i].a);
            uint64_t got_b = gold_fp_to_u64(vals[i].b);
            if (got_a != out_a[i] || got_b != out_b[i]) {
                if (failed < 5) {
                    fprintf(stderr,
                            "MISMATCH reverse_fp2 n=%zu i=%zu got=(%" PRIu64
                            ",%" PRIu64 ") want=(%" PRIu64 ",%" PRIu64 ")\n",
                            n_case, i, got_a, got_b, out_a[i], out_b[i]);
                }
                case_failed = 1;
                break;
            }
        }
        if (case_failed) failed++; else passed++;

        free(vals); free(in_a); free(in_b); free(out_a); free(out_b);
    }
    printf("%-32s  %5d passed  %5d failed\n",
           "reverse_slice_index_bits_fp2", passed, failed);
    return failed;
}

static int run_extended_pow(json_scanner_t *s) {
    if (!js_seek_array(s, "extended_pow")) {
        fprintf(stderr, "FAIL: locate extended_pow\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos < s->len && s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (!js_match(s, '{')) return -1;

        uint64_t a = 0, k = 0, expected = 0;
        bool got_a = false, got_k = false, got_out = false;
        while (1) {
            js_skip_ws(s);
            if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "a")) {
                js_match(s, ':');
                got_a = js_read_u64_string(s, &a);
            } else if (js_match_key(s, "k")) {
                js_match(s, ':');
                got_k = js_read_u64_string(s, &k);
            } else if (js_match_key(s, "out")) {
                js_match(s, ':');
                got_out = js_read_u64_string(s, &expected);
            } else {
                fprintf(stderr, "FAIL: unknown key extended_pow\n");
                return -1;
            }
        }
        if (!got_a || !got_k || !got_out) {
            fprintf(stderr, "FAIL extended_pow fields\n");
            return -1;
        }
        gold_fp_t fa = gold_fp_from_u64(a);
        uint64_t actual = gold_fp_to_u64(gold_fp_pow(fa, k));
        if (actual != expected) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH extended_pow a=%" PRIu64
                                " k=%" PRIu64 " got=%" PRIu64
                                " want=%" PRIu64 "\n",
                        a, k, actual, expected);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-32s  %5d passed  %5d failed\n",
           "extended_pow", passed, failed);
    return failed;
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/primitive_ops.json";

    size_t len;
    char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    json_scanner_t s = { buf, 0, len };

    int total_failed = 0;
    printf("\n%-32s  %s\n", "op", "result");
    printf("--------------------------------  --------------\n");

    int r;
    r = run_reverse_fp(&s);        if (r < 0) { free(buf); return 2; } total_failed += r;
    r = run_reverse_fp2(&s);       if (r < 0) { free(buf); return 2; } total_failed += r;
    r = run_extended_pow(&s);      if (r < 0) { free(buf); return 2; } total_failed += r;

    printf("\nPHASE C ORACLE GATE: %s\n",
           total_failed == 0 ? "GREEN" : "RED");

    free(buf);
    return total_failed == 0 ? 0 : 1;
}
