/**
 * @file test_field_goldilocks.c
 * @brief Cross-validate field_goldilocks.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/field_ops.json (~7,200 cases across 7 operations),
 * runs each case through our C impl, asserts byte-identical output.
 *
 * Build (standalone, no CMake yet):
 *   gcc -std=c99 -O2 -Wall -Wextra -I.. \
 *       tests/test_field_goldilocks.c field_goldilocks.c \
 *       -o test_field_goldilocks
 *   ./test_field_goldilocks tools/vectors/field_ops.json
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *   2  load / parse error
 *
 * Per Sprint 1.2 deliverable: cross-validation gate for all 7 base-field ops.
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
 * Tiny JSON tokenizer
 *
 * Recognizes only the subset of JSON our oracle emits:
 *   - whitespace (skip)
 *   - "..." string literals
 *   - { } [ ] , :
 *   - decimal numbers (we treat strings as the canonical form anyway)
 *
 * NOT a general parser. Designed to fail loudly on unexpected input.
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

/* Match a literal character (after skipping ws). Returns true on match. */
static bool js_match(json_scanner_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) {
        s->pos++;
        return true;
    }
    return false;
}

/* Match a literal string key (after skipping ws). e.g., js_match_key(s, "add"). */
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

/* Extract a string value as a NUL-terminated copy. Caller frees.
 *  Reads "..." up to closing quote. No escape handling — oracle output is
 *  pure ASCII decimal digits. */
static char *js_read_string(json_scanner_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len || s->src[s->pos] != '"') return NULL;
    s->pos++; /* opening quote */
    size_t start = s->pos;
    while (s->pos < s->len && s->src[s->pos] != '"') s->pos++;
    if (s->pos >= s->len) return NULL;
    size_t slen = s->pos - start;
    s->pos++; /* closing quote */
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, s->src + start, slen);
    out[slen] = '\0';
    return out;
}

/* Read a decimal u64 from a JSON string field (as oracle emits). */
static bool js_read_u64_string(json_scanner_t *s, uint64_t *out) {
    char *str = js_read_string(s);
    if (!str) return false;
    char *endp = NULL;
    *out = strtoull(str, &endp, 10);
    bool ok = (endp != NULL && *endp == '\0');
    free(str);
    return ok;
}

/* Skip until we land on the opening { of the named operation array.
 *   Looks for: "<op>": [   pattern.  Returns true on success. */
static bool js_seek_op_array(json_scanner_t *s, const char *op_name) {
    /* Reset to start; this is OK because file is tiny (~800KB) and we run
     * once per op. Simpler than maintaining cursor. */
    s->pos = 0;
    /* Find the key. */
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
 * Per-operation runners
 * ========================================================================== */

typedef enum {
    OP_BINARY,   /* fields: a, b, out */
    OP_UNARY,    /* fields: a, out */
    OP_POW       /* fields: a, k, out */
} op_kind_t;

typedef gold_fp_t (*binary_fn_t)(gold_fp_t, gold_fp_t);
typedef gold_fp_t (*unary_fn_t)(gold_fp_t);
typedef gold_fp_t (*pow_fn_t)(gold_fp_t, uint64_t);

static int run_binary_op(json_scanner_t *s,
                         const char *op_name,
                         binary_fn_t fn) {
    if (!js_seek_op_array(s, op_name)) {
        fprintf(stderr, "FAIL: could not locate '%s' array\n", op_name);
        return -1;
    }

    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') {
            s->pos++; /* consume ] */
            break;
        }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') {
            fprintf(stderr, "FAIL: expected '{' at pos %zu in '%s'\n", s->pos, op_name);
            return -1;
        }
        s->pos++; /* consume { */

        uint64_t a = 0, b = 0, expected = 0;
        bool got_a = false, got_b = false, got_out = false;
        while (1) {
            js_skip_ws(s);
            if (s->pos < s->len && s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "a")) {
                js_match(s, ':');
                got_a = js_read_u64_string(s, &a);
            } else if (js_match_key(s, "b")) {
                js_match(s, ':');
                got_b = js_read_u64_string(s, &b);
            } else if (js_match_key(s, "out")) {
                js_match(s, ':');
                got_out = js_read_u64_string(s, &expected);
            } else {
                fprintf(stderr, "FAIL: unexpected key at pos %zu in '%s'\n", s->pos, op_name);
                return -1;
            }
        }
        if (!got_a || !got_b || !got_out) {
            fprintf(stderr, "FAIL: missing field in '%s' case\n", op_name);
            return -1;
        }

        gold_fp_t fa = gold_fp_from_u64(a);
        gold_fp_t fb = gold_fp_from_u64(b);
        uint64_t actual = gold_fp_to_u64(fn(fa, fb));
        if (actual != expected) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH '%s'(%" PRIu64 ", %" PRIu64 "): "
                                "expected %" PRIu64 ", got %" PRIu64 "\n",
                        op_name, a, b, expected, actual);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-6s  %5d passed  %5d failed\n", op_name, passed, failed);
    return failed;
}

static int run_unary_op(json_scanner_t *s,
                        const char *op_name,
                        unary_fn_t fn) {
    if (!js_seek_op_array(s, op_name)) {
        fprintf(stderr, "FAIL: could not locate '%s' array\n", op_name);
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') { fprintf(stderr, "FAIL: expected '{'\n"); return -1; }
        s->pos++;

        uint64_t a = 0, expected = 0;
        bool got_a = false, got_out = false;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "a")) {
                js_match(s, ':');
                got_a = js_read_u64_string(s, &a);
            } else if (js_match_key(s, "out")) {
                js_match(s, ':');
                got_out = js_read_u64_string(s, &expected);
            } else {
                fprintf(stderr, "FAIL: unexpected key in '%s'\n", op_name);
                return -1;
            }
        }
        if (!got_a || !got_out) { fprintf(stderr, "FAIL: missing field\n"); return -1; }

        uint64_t actual = gold_fp_to_u64(fn(gold_fp_from_u64(a)));
        if (actual != expected) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH '%s'(%" PRIu64 "): expected %" PRIu64 ", got %" PRIu64 "\n",
                        op_name, a, expected, actual);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-6s  %5d passed  %5d failed\n", op_name, passed, failed);
    return failed;
}

static int run_pow_op(json_scanner_t *s) {
    if (!js_seek_op_array(s, "pow")) {
        fprintf(stderr, "FAIL: could not locate 'pow' array\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len || s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (s->src[s->pos] != '{') { fprintf(stderr, "FAIL: expected '{'\n"); return -1; }
        s->pos++;

        uint64_t a = 0, k = 0, expected = 0;
        bool got_a = false, got_k = false, got_out = false;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
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
                fprintf(stderr, "FAIL: unexpected key in 'pow'\n");
                return -1;
            }
        }
        if (!got_a || !got_k || !got_out) { fprintf(stderr, "FAIL: missing field\n"); return -1; }

        uint64_t actual = gold_fp_to_u64(gold_fp_pow(gold_fp_from_u64(a), k));
        if (actual != expected) {
            if (failed < 5) {
                fprintf(stderr, "MISMATCH pow(%" PRIu64 ", %" PRIu64 "): expected %" PRIu64 ", got %" PRIu64 "\n",
                        a, k, expected, actual);
            }
            failed++;
        } else {
            passed++;
        }
    }
    printf("%-6s  %5d passed  %5d failed\n", "pow", passed, failed);
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
    const char *path = "tools/vectors/field_ops.json";
    if (argc >= 2) path = argv[1];

    /* Self-check: compile-time constants. */
    if (!gold_fp2_irreducible_consistency_check()) {
        fprintf(stderr, "FAIL: compile-time constant mismatch\n");
        return 2;
    }
    printf("compile-time consistency check: OK\n");

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};

    printf("op      passed         failed\n");
    printf("------  -------------  -------------\n");

    int total_failed = 0;
    total_failed += run_binary_op(&s, "add", gold_fp_add);
    total_failed += run_binary_op(&s, "sub", gold_fp_sub);
    total_failed += run_binary_op(&s, "mul", gold_fp_mul);
    total_failed += run_unary_op(&s, "neg", gold_fp_neg);
    total_failed += run_unary_op(&s, "sqr", gold_fp_sqr);
    total_failed += run_unary_op(&s, "inv", gold_fp_inv);
    total_failed += run_pow_op(&s);

    free(src);

    printf("\n");
    if (total_failed == 0) {
        printf("SPRINT 1.2 GATE: GREEN — all field op test vectors byte-match Plonky3\n");
        return 0;
    } else {
        printf("SPRINT 1.2 GATE: RED — %d total mismatches\n", total_failed);
        return 1;
    }
}
