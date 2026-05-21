/**
 * @file test_field_goldilocks_ext.c
 * @brief Cross-validate gold_fp2_* against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/field_ext.json and runs each ext-field case through
 * gold_fp2_* in field_goldilocks.c. Asserts byte-identical output.
 *
 * Build:
 *   gcc -std=c99 -O2 -Wall -Wextra -I.. \
 *       tests/test_field_goldilocks_ext.c field_goldilocks.c \
 *       -o test_field_goldilocks_ext
 *   ./test_field_goldilocks_ext tools/vectors/field_ext.json
 *
 * Operations covered: add, sub, mul, neg, sqr, inv (6 ops).
 *
 * JSON schema:
 *   { "operations": {
 *       "add": [ {"a": ["d", "d"], "b": ["d", "d"], "out": ["d", "d"]}, ... ],
 *       ...
 *     }
 *   }
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

/* ============================================================================
 * Tiny JSON tokenizer (shared style with test_field_goldilocks.c).
 * ========================================================================== */

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} json_scanner_t;

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

static bool js_read_u64_string(json_scanner_t *s, uint64_t *out) {
    char *str = js_read_string(s);
    if (!str) return false;
    char *endp = NULL;
    *out = strtoull(str, &endp, 10);
    bool ok = (endp != NULL && *endp == '\0');
    free(str);
    return ok;
}

/* Read a [a, b] pair of decimal strings. Returns true on success. */
static bool js_read_u64_pair(json_scanner_t *s, uint64_t *out_a, uint64_t *out_b) {
    js_skip_ws(s);
    if (!js_match(s, '[')) return false;
    if (!js_read_u64_string(s, out_a)) return false;
    if (!js_match(s, ',')) return false;
    if (!js_read_u64_string(s, out_b)) return false;
    if (!js_match(s, ']')) return false;
    return true;
}

static bool js_seek_op_array(json_scanner_t *s, const char *op_name) {
    s->pos = 0;
    size_t klen = strlen(op_name);
    while (s->pos + klen + 4 < s->len) {
        if (s->src[s->pos] == '"' &&
            memcmp(s->src + s->pos + 1, op_name, klen) == 0 &&
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

/* ============================================================================
 * Per-op runners (ext field versions)
 * ========================================================================== */

typedef gold_fp2_t (*ext_binary_fn_t)(gold_fp2_t, gold_fp2_t);
typedef gold_fp2_t (*ext_unary_fn_t)(gold_fp2_t);

static int run_ext_binary_op(json_scanner_t *s,
                             const char *op_name,
                             ext_binary_fn_t fn) {
    if (!js_seek_op_array(s, op_name)) {
        fprintf(stderr, "FAIL: could not locate '%s' array\n", op_name);
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') {
            fprintf(stderr, "FAIL: expected '{' at pos %zu in '%s'\n", s->pos, op_name);
            return -1;
        }
        s->pos++;

        uint64_t a0=0, a1=0, b0=0, b1=0, out0=0, out1=0;
        bool got_a=false, got_b=false, got_out=false;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "a")) {
                js_match(s, ':');
                got_a = js_read_u64_pair(s, &a0, &a1);
            } else if (js_match_key(s, "b")) {
                js_match(s, ':');
                got_b = js_read_u64_pair(s, &b0, &b1);
            } else if (js_match_key(s, "out")) {
                js_match(s, ':');
                got_out = js_read_u64_pair(s, &out0, &out1);
            } else {
                fprintf(stderr, "FAIL: unexpected key in '%s'\n", op_name);
                return -1;
            }
        }
        if (!got_a || !got_b || !got_out) {
            fprintf(stderr, "FAIL: missing field in '%s'\n", op_name);
            return -1;
        }

        gold_fp2_t fa = gold_fp2_new(gold_fp_from_u64(a0), gold_fp_from_u64(a1));
        gold_fp2_t fb = gold_fp2_new(gold_fp_from_u64(b0), gold_fp_from_u64(b1));
        gold_fp2_t r = fn(fa, fb);
        uint64_t actual_0 = gold_fp_to_u64(r.a);
        uint64_t actual_1 = gold_fp_to_u64(r.b);
        if (actual_0 != out0 || actual_1 != out1) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH '%s'( (%"PRIu64",%"PRIu64"), (%"PRIu64",%"PRIu64") ): "
                                "expected (%"PRIu64",%"PRIu64"), got (%"PRIu64",%"PRIu64")\n",
                        op_name, a0, a1, b0, b1, out0, out1, actual_0, actual_1);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-6s  %5d passed  %5d failed\n", op_name, passed, failed);
    return failed;
}

static int run_ext_unary_op(json_scanner_t *s,
                            const char *op_name,
                            ext_unary_fn_t fn) {
    if (!js_seek_op_array(s, op_name)) {
        fprintf(stderr, "FAIL: could not locate '%s' array\n", op_name);
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') {
            fprintf(stderr, "FAIL: expected '{' in '%s'\n", op_name);
            return -1;
        }
        s->pos++;

        uint64_t a0=0, a1=0, out0=0, out1=0;
        bool got_a=false, got_out=false;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "a")) {
                js_match(s, ':');
                got_a = js_read_u64_pair(s, &a0, &a1);
            } else if (js_match_key(s, "out")) {
                js_match(s, ':');
                got_out = js_read_u64_pair(s, &out0, &out1);
            } else {
                fprintf(stderr, "FAIL: unexpected key in '%s'\n", op_name);
                return -1;
            }
        }
        if (!got_a || !got_out) {
            fprintf(stderr, "FAIL: missing field in '%s'\n", op_name);
            return -1;
        }

        gold_fp2_t fa = gold_fp2_new(gold_fp_from_u64(a0), gold_fp_from_u64(a1));
        gold_fp2_t r = fn(fa);
        uint64_t actual_0 = gold_fp_to_u64(r.a);
        uint64_t actual_1 = gold_fp_to_u64(r.b);
        if (actual_0 != out0 || actual_1 != out1) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH '%s'( (%"PRIu64",%"PRIu64") ): "
                                "expected (%"PRIu64",%"PRIu64"), got (%"PRIu64",%"PRIu64")\n",
                        op_name, a0, a1, out0, out1, actual_0, actual_1);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-6s  %5d passed  %5d failed\n", op_name, passed, failed);
    return failed;
}

/* ============================================================================
 * File loader
 * ========================================================================== */

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

/* ============================================================================
 * main
 * ========================================================================== */

int main(int argc, char **argv) {
    const char *path = "tools/vectors/field_ext.json";
    if (argc >= 2) path = argv[1];

    if (!gold_fp2_irreducible_consistency_check()) {
        fprintf(stderr, "FAIL: compile-time constant mismatch\n");
        return 2;
    }
    printf("compile-time consistency check: OK\n");

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) { return 2; }
    printf("loaded %s (%zu bytes)\n\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};

    printf("op      passed         failed\n");
    printf("------  -------------  -------------\n");

    int total_failed = 0;
    total_failed += run_ext_binary_op(&s, "add", gold_fp2_add);
    total_failed += run_ext_binary_op(&s, "sub", gold_fp2_sub);
    total_failed += run_ext_binary_op(&s, "mul", gold_fp2_mul);
    total_failed += run_ext_unary_op(&s,  "neg", gold_fp2_neg);
    total_failed += run_ext_unary_op(&s,  "sqr", gold_fp2_sqr);
    total_failed += run_ext_unary_op(&s,  "inv", gold_fp2_inv);

    free(src);

    printf("\n");
    if (total_failed == 0) {
        printf("SPRINT 1.3 GATE: GREEN — all ext-field test vectors byte-match Plonky3\n");
        return 0;
    } else {
        printf("SPRINT 1.3 GATE: RED — %d total mismatches\n", total_failed);
        return 1;
    }
}
