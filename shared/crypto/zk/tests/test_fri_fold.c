/**
 * @file test_fri_fold.c
 * @brief Cross-validate fri_fold_arity2 against Plonky3 oracle (Sub-sprint 2.1).
 *
 * Loads tools/vectors/fri_fold.json — 7 cases covering log_h in {1,2,3,4,6,8,10}.
 * For each case: invokes fri_fold_arity2 with (input_values, halve_inv_powers,
 * beta, h) and asserts every output Goldilocks² element byte-matches.
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
#include "../fri_fold.h"

/* ---------- minimal JSON tokenizer (shared style) ---------- */
typedef struct { const char *src; size_t pos; size_t len; } json_scanner_t;
static void js_skip_ws(json_scanner_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}
static bool js_match(json_scanner_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
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
static bool js_read_u32(json_scanner_t *s, uint32_t *out) {
    js_skip_ws(s);
    uint64_t v = 0; bool any = false;
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint64_t)(c - '0'); s->pos++; any = true;
    }
    if (!any) return false;
    *out = (uint32_t)v;
    return true;
}
static bool js_read_u64_pair(json_scanner_t *s, uint64_t *a, uint64_t *b) {
    js_skip_ws(s);
    if (!js_match(s, '[')) return false;
    char *sa = js_read_string(s); if (!sa) return false;
    if (!js_match(s, ',')) { free(sa); return false; }
    char *sb = js_read_string(s); if (!sb) { free(sa); return false; }
    if (!js_match(s, ']')) { free(sa); free(sb); return false; }
    *a = strtoull(sa, NULL, 10);
    *b = strtoull(sb, NULL, 10);
    free(sa); free(sb);
    return true;
}

/* Read a [["a","b"], ...] array of fp2 pairs. Returns allocated array. */
static gold_fp2_t *read_fp2_array(json_scanner_t *s, size_t *out_count) {
    if (!js_match(s, '[')) return NULL;
    size_t cap = 8, count = 0;
    gold_fp2_t *arr = (gold_fp2_t *)malloc(cap * sizeof(gold_fp2_t));
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) { free(arr); return NULL; }
        if (s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        uint64_t a = 0, b = 0;
        if (!js_read_u64_pair(s, &a, &b)) { free(arr); return NULL; }
        if (count + 1 > cap) {
            cap *= 2;
            arr = (gold_fp2_t *)realloc(arr, cap * sizeof(gold_fp2_t));
        }
        arr[count++] = gold_fp2_new(gold_fp_from_u64(a), gold_fp_from_u64(b));
    }
    *out_count = count;
    return arr;
}

/* Read an ["d", "d", ...] array of decimal-string u64. Returns gold_fp_t array. */
static gold_fp_t *read_fp_array(json_scanner_t *s, size_t *out_count) {
    if (!js_match(s, '[')) return NULL;
    size_t cap = 8, count = 0;
    gold_fp_t *arr = (gold_fp_t *)malloc(cap * sizeof(gold_fp_t));
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) { free(arr); return NULL; }
        if (s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        char *str = js_read_string(s);
        if (!str) { free(arr); return NULL; }
        uint64_t v = strtoull(str, NULL, 10);
        free(str);
        if (count + 1 > cap) {
            cap *= 2;
            arr = (gold_fp_t *)realloc(arr, cap * sizeof(gold_fp_t));
        }
        arr[count++] = gold_fp_from_u64(v);
    }
    *out_count = count;
    return arr;
}

static void js_skip_value(json_scanner_t *s);
static void js_skip_array(json_scanner_t *s) {
    if (!js_match(s, '[')) return;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; return; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        js_skip_value(s);
    }
}
static void js_skip_object(json_scanner_t *s) {
    if (!js_match(s, '{')) return;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == '}') { s->pos++; return; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        char *k = js_read_string(s); if (k) free(k);
        js_match(s, ':');
        js_skip_value(s);
    }
}
static void js_skip_value(json_scanner_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return;
    char c = s->src[s->pos];
    if (c == '"') { char *v = js_read_string(s); if (v) free(v); return; }
    if (c == '[') { js_skip_array(s); return; }
    if (c == '{') { js_skip_object(s); return; }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\n' ||
            d == '\t' || d == '\r') break;
        s->pos++;
    }
}

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

int main(int argc, char **argv) {
    const char *path = "tools/vectors/fri_fold.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};
    /* Find "cases": [ */
    const char *needle = "\"cases\"";
    size_t nlen = strlen(needle);
    while (s.pos + nlen < s.len) {
        if (memcmp(s.src + s.pos, needle, nlen) == 0) {
            s.pos += nlen;
            js_skip_ws(&s);
            if (s.src[s.pos] == ':') s.pos++;
            js_skip_ws(&s);
            if (s.src[s.pos] == '[') { s.pos++; break; }
        }
        s.pos++;
    }

    int total_passed = 0, total_failed = 0;
    printf("log_h     h     pass    fail\n");
    printf("-----  -----  ------  ------\n");

    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len || s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }
        if (s.src[s.pos] != '{') { fprintf(stderr, "expected '{'\n"); return 2; }
        s.pos++;

        uint32_t log_h = 0, h_json = 0;
        gold_fp2_t *input_values = NULL; size_t n_input = 0;
        gold_fp2_t *expected = NULL;     size_t n_expected = 0;
        gold_fp_t *halve_inv_powers = NULL; size_t n_hip = 0;
        gold_fp_t *g_inv_powers = NULL;  size_t n_gip = 0; /* read but unused */
        uint64_t beta0 = 0, beta1 = 0;
        bool got_beta = false;

        while (1) {
            js_skip_ws(&s);
            if (s.src[s.pos] == '}') { s.pos++; break; }
            if (s.src[s.pos] == ',') { s.pos++; continue; }
            if (js_match_key(&s, "log_h")) { js_match(&s, ':'); js_read_u32(&s, &log_h); }
            else if (js_match_key(&s, "h")) { js_match(&s, ':'); js_read_u32(&s, &h_json); }
            else if (js_match_key(&s, "input_values")) { js_match(&s, ':'); input_values = read_fp2_array(&s, &n_input); }
            else if (js_match_key(&s, "beta")) { js_match(&s, ':'); got_beta = js_read_u64_pair(&s, &beta0, &beta1); }
            else if (js_match_key(&s, "g_inv_powers")) { js_match(&s, ':'); g_inv_powers = read_fp_array(&s, &n_gip); }
            else if (js_match_key(&s, "halve_inv_powers")) { js_match(&s, ':'); halve_inv_powers = read_fp_array(&s, &n_hip); }
            else if (js_match_key(&s, "expected_output")) { js_match(&s, ':'); expected = read_fp2_array(&s, &n_expected); }
            else { char *k = js_read_string(&s); if (k) free(k); js_match(&s, ':'); js_skip_value(&s); }
        }

        if (!input_values || !expected || !halve_inv_powers || !got_beta) {
            fprintf(stderr, "case log_h=%u missing field\n", log_h);
            return 2;
        }

        size_t h = (size_t)h_json;
        if (n_input != 2 * h || n_expected != h || n_hip != h) {
            fprintf(stderr, "case log_h=%u size mismatch: n_input=%zu (want %zu), n_expected=%zu (want %zu), n_hip=%zu (want %zu)\n",
                    log_h, n_input, 2 * h, n_expected, h, n_hip, h);
            return 2;
        }

        gold_fp2_t beta = gold_fp2_new(gold_fp_from_u64(beta0), gold_fp_from_u64(beta1));
        gold_fp2_t *out = (gold_fp2_t *)malloc(h * sizeof(gold_fp2_t));
        fri_fold_arity2(input_values, halve_inv_powers, beta, h, out);

        int passed = 0, failed = 0;
        for (size_t i = 0; i < h; i++) {
            if (gold_fp_to_u64(out[i].a) != gold_fp_to_u64(expected[i].a) ||
                gold_fp_to_u64(out[i].b) != gold_fp_to_u64(expected[i].b)) {
                if (failed < 3) {
                    fprintf(stderr, "  MISMATCH log_h=%u i=%zu: expected (%"PRIu64",%"PRIu64") got (%"PRIu64",%"PRIu64")\n",
                            log_h, i,
                            gold_fp_to_u64(expected[i].a), gold_fp_to_u64(expected[i].b),
                            gold_fp_to_u64(out[i].a), gold_fp_to_u64(out[i].b));
                }
                failed++;
            } else {
                passed++;
            }
        }
        printf("%5u  %5zu  %6d  %6d\n", log_h, h, passed, failed);
        total_passed += passed;
        total_failed += failed;

        free(out);
        free(input_values);
        free(expected);
        free(halve_inv_powers);
        free(g_inv_powers);
    }

    free(src);
    printf("\nTotal: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 2.1 (fri_fold) GATE: GREEN — arity-2 fold byte-matches Plonky3\n");
        return 0;
    } else {
        printf("SUB-SPRINT 2.1 (fri_fold) GATE: RED — %d mismatches\n", total_failed);
        return 1;
    }
}
