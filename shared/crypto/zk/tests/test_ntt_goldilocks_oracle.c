/**
 * @file test_ntt_goldilocks_oracle.c
 * @brief Cross-validate ntt_goldilocks.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/ntt_goldilocks.json (64 cases: 32 base + 32 ext across
 * log_n ∈ [1, 8] × {zero, delta_0, rand_a, rand_b}). For each case, calls
 * ntt_goldilocks_forward / ntt_goldilocks_ext_forward on a copy of the
 * input vector and asserts byte-identical output with the Plonky3
 * Radix2Dit reference.
 *
 * Closes the RESUME.md MEDIUM-confidence gap on ntt_goldilocks (previously
 * validated only against brute-force O(N²) DFT in test_ntt_goldilocks.c).
 * Plonky3 byte-match is a SECOND independent reference; the brute-force
 * test remains as the first.
 *
 * Build (Makefile):
 *   make build/test_ntt_goldilocks_oracle
 *
 * Run:
 *   ./build/test_ntt_goldilocks_oracle tools/vectors/ntt_goldilocks.json
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *   2  load / parse error
 *
 * Test-count honesty: every case byte-matched against Plonky3 Radix2Dit.
 * NO circular self-tests.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../ntt_goldilocks.h"

/* log_n max = 8 → 2^8 = 256 cells per vector. */
#define TEST_NTT_MAX_LOG_N 8
#define TEST_NTT_MAX_N (1u << TEST_NTT_MAX_LOG_N)

/* ============================================================================
 * Tiny JSON tokenizer (same shape as test_range_air.c / test_sum_balance.c)
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
    while (s->pos < s->len && s->src[s->pos] != '"') {
        if (s->src[s->pos] == '\\' && s->pos + 1 < s->len) s->pos++;
        s->pos++;
    }
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

static bool js_skip_value(json_scanner_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '"') {
        char *tmp = js_read_string(s);
        if (!tmp) return false;
        free(tmp);
        return true;
    }
    if (c == '{' || c == '[') {
        char open_c = c;
        char close_c = (c == '{') ? '}' : ']';
        int depth = 1;
        s->pos++;
        while (s->pos < s->len && depth > 0) {
            char cc = s->src[s->pos];
            if (cc == '"') {
                char *tmp = js_read_string(s);
                if (!tmp) return false;
                free(tmp);
                continue;
            }
            if (cc == open_c) depth++;
            else if (cc == close_c) depth--;
            s->pos++;
        }
        return depth == 0;
    }
    while (s->pos < s->len) {
        char cc = s->src[s->pos];
        if (cc == ',' || cc == '}' || cc == ']' ||
            cc == ' ' || cc == '\n' || cc == '\t' || cc == '\r') {
            break;
        }
        s->pos++;
    }
    return true;
}

static bool js_read_u64_string_array(json_scanner_t *s,
                                     uint64_t *out_buf,
                                     size_t capacity,
                                     size_t *out_actual) {
    if (!js_match(s, '[')) return false;
    size_t i = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) return false;
        if (s->src[s->pos] == ']') {
            s->pos++;
            if (out_actual) *out_actual = i;
            return true;
        }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (i >= capacity) return false;
        if (!js_read_u64_string(s, &out_buf[i])) return false;
        i++;
    }
}

/* Read `[[a0,a1],[a0,a1],...]` of u64 pairs into a flat row-major u64 buffer
 * of length 2 * out_pairs. */
static bool js_read_u64_pair_array(json_scanner_t *s,
                                   uint64_t *out_buf,
                                   size_t max_pairs,
                                   size_t *out_pairs) {
    if (!js_match(s, '[')) return false;
    size_t p = 0;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) return false;
        if (s->src[s->pos] == ']') {
            s->pos++;
            if (out_pairs) *out_pairs = p;
            return true;
        }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (p >= max_pairs) return false;
        size_t inner = 0;
        if (!js_read_u64_string_array(s, &out_buf[p * 2], 2, &inner)) {
            return false;
        }
        if (inner != 2) {
            fprintf(stderr, "FAIL: pair[%zu] has %zu entries (want 2)\n", p, inner);
            return false;
        }
        p++;
    }
}

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

/* ============================================================================
 * Per-case parsers
 * ========================================================================== */

typedef struct {
    char *name;
    uint32_t log_n;
    uint32_t n;
    uint64_t input[TEST_NTT_MAX_N];
    uint64_t ntt_output[TEST_NTT_MAX_N];
} ntt_base_case_t;

typedef struct {
    char *name;
    uint32_t log_n;
    uint32_t n;
    /* Each ext element = 2 consecutive u64s (a0, a1). */
    uint64_t input[TEST_NTT_MAX_N * 2];
    uint64_t ntt_output[TEST_NTT_MAX_N * 2];
} ntt_ext_case_t;

static void free_base(ntt_base_case_t *c) {
    if (c->name) { free(c->name); c->name = NULL; }
}

static void free_ext(ntt_ext_case_t *c) {
    if (c->name) { free(c->name); c->name = NULL; }
}

/* Read a JSON number (not a string) into u32. */
static bool js_read_u32_number(json_scanner_t *s, uint32_t *out) {
    js_skip_ws(s);
    char *endp = NULL;
    unsigned long v = strtoul(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint32_t)v;
    return true;
}

static bool parse_base_case(json_scanner_t *s, ntt_base_case_t *out) {
    memset(out, 0, sizeof *out);
    if (!js_match(s, '{')) return false;
    while (1) {
        js_skip_ws(s);
        if (js_match(s, '}')) return true;
        if (js_match(s, ',')) continue;

        if (js_match_key(s, "name")) {
            if (!js_match(s, ':')) return false;
            out->name = js_read_string(s);
            if (!out->name) return false;
        } else if (js_match_key(s, "log_n")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u32_number(s, &out->log_n)) return false;
        } else if (js_match_key(s, "n")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u32_number(s, &out->n)) return false;
        } else if (js_match_key(s, "input")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->input, TEST_NTT_MAX_N, &actual)) {
                return false;
            }
            if (out->n != 0 && actual != out->n) return false;
        } else if (js_match_key(s, "ntt_output")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->ntt_output, TEST_NTT_MAX_N, &actual)) {
                return false;
            }
            if (out->n != 0 && actual != out->n) return false;
        } else {
            char *k = js_read_string(s);
            if (!k) return false;
            free(k);
            if (!js_match(s, ':')) return false;
            if (!js_skip_value(s)) return false;
        }
    }
}

static bool parse_ext_case(json_scanner_t *s, ntt_ext_case_t *out) {
    memset(out, 0, sizeof *out);
    if (!js_match(s, '{')) return false;
    while (1) {
        js_skip_ws(s);
        if (js_match(s, '}')) return true;
        if (js_match(s, ',')) continue;

        if (js_match_key(s, "name")) {
            if (!js_match(s, ':')) return false;
            out->name = js_read_string(s);
            if (!out->name) return false;
        } else if (js_match_key(s, "log_n")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u32_number(s, &out->log_n)) return false;
        } else if (js_match_key(s, "n")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u32_number(s, &out->n)) return false;
        } else if (js_match_key(s, "input")) {
            if (!js_match(s, ':')) return false;
            size_t pairs = 0;
            if (!js_read_u64_pair_array(s, out->input, TEST_NTT_MAX_N, &pairs)) {
                return false;
            }
            if (out->n != 0 && pairs != out->n) return false;
        } else if (js_match_key(s, "ntt_output")) {
            if (!js_match(s, ':')) return false;
            size_t pairs = 0;
            if (!js_read_u64_pair_array(s, out->ntt_output, TEST_NTT_MAX_N, &pairs)) {
                return false;
            }
            if (out->n != 0 && pairs != out->n) return false;
        } else {
            char *k = js_read_string(s);
            if (!k) return false;
            free(k);
            if (!js_match(s, ':')) return false;
            if (!js_skip_value(s)) return false;
        }
    }
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
    const char *path = "tools/vectors/ntt_goldilocks.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    int base_pass = 0, base_fail = 0;
    int ext_pass = 0, ext_fail = 0;
    int base_cases = 0, ext_cases = 0;

    /* Walk base_cases array. */
    {
        json_scanner_t s = {.src = src, .pos = 0, .len = len};
        if (!js_seek_array(&s, "base_cases")) {
            fprintf(stderr, "FAIL: could not locate 'base_cases' array\n");
            free(src);
            return 2;
        }
        while (1) {
            js_skip_ws(&s);
            if (s.pos >= s.len) break;
            if (s.src[s.pos] == ']') { s.pos++; break; }
            if (s.src[s.pos] == ',') { s.pos++; continue; }

            ntt_base_case_t c;
            if (!parse_base_case(&s, &c)) {
                fprintf(stderr, "FAIL: parse base case at pos %zu\n", s.pos);
                free(src);
                return 2;
            }
            base_cases++;

            /* Copy input → field array → forward NTT → compare. */
            gold_fp_t arr[TEST_NTT_MAX_N];
            for (uint32_t i = 0; i < c.n; i++) {
                arr[i] = gold_fp_from_u64(c.input[i]);
            }
            ntt_goldilocks_forward(arr, (unsigned)c.log_n);

            bool ok = true;
            uint32_t first_bad = 0;
            for (uint32_t i = 0; i < c.n; i++) {
                if (gold_fp_to_u64(arr[i]) != c.ntt_output[i]) {
                    ok = false;
                    first_bad = i;
                    break;
                }
            }
            if (ok) {
                base_pass++;
            } else {
                base_fail++;
                if (base_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (base) case '%s' log_n=%u: "
                            "ntt[%u] oracle=%" PRIu64 " ours=%" PRIu64 "\n",
                            c.name ? c.name : "<unnamed>", c.log_n,
                            first_bad, c.ntt_output[first_bad],
                            gold_fp_to_u64(arr[first_bad]));
                }
            }
            free_base(&c);
        }
    }

    /* Walk ext_cases array. */
    {
        json_scanner_t s = {.src = src, .pos = 0, .len = len};
        if (!js_seek_array(&s, "ext_cases")) {
            fprintf(stderr, "FAIL: could not locate 'ext_cases' array\n");
            free(src);
            return 2;
        }
        while (1) {
            js_skip_ws(&s);
            if (s.pos >= s.len) break;
            if (s.src[s.pos] == ']') { s.pos++; break; }
            if (s.src[s.pos] == ',') { s.pos++; continue; }

            ntt_ext_case_t c;
            if (!parse_ext_case(&s, &c)) {
                fprintf(stderr, "FAIL: parse ext case at pos %zu\n", s.pos);
                free(src);
                return 2;
            }
            ext_cases++;

            gold_fp2_t arr[TEST_NTT_MAX_N];
            for (uint32_t i = 0; i < c.n; i++) {
                arr[i] = gold_fp2_new(
                    gold_fp_from_u64(c.input[i * 2]),
                    gold_fp_from_u64(c.input[i * 2 + 1]));
            }
            ntt_goldilocks_ext_forward(arr, (unsigned)c.log_n);

            bool ok = true;
            uint32_t first_bad = 0;
            for (uint32_t i = 0; i < c.n; i++) {
                uint64_t a0 = gold_fp_to_u64(arr[i].a);
                uint64_t a1 = gold_fp_to_u64(arr[i].b);
                if (a0 != c.ntt_output[i * 2] || a1 != c.ntt_output[i * 2 + 1]) {
                    ok = false;
                    first_bad = i;
                    break;
                }
            }
            if (ok) {
                ext_pass++;
            } else {
                ext_fail++;
                if (ext_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (ext) case '%s' log_n=%u: "
                            "ntt[%u] oracle=[%" PRIu64 ",%" PRIu64 "] "
                            "ours=[%" PRIu64 ",%" PRIu64 "]\n",
                            c.name ? c.name : "<unnamed>", c.log_n, first_bad,
                            c.ntt_output[first_bad * 2],
                            c.ntt_output[first_bad * 2 + 1],
                            gold_fp_to_u64(arr[first_bad].a),
                            gold_fp_to_u64(arr[first_bad].b));
                }
            }
            free_ext(&c);
        }
    }

    free(src);

    int total_fail = base_fail + ext_fail;

    printf("\n");
    printf("NTT_goldilocks oracle summary (byte-match against Plonky3 commit 82cfad73, Radix2Dit):\n");
    printf("  Base-field cases (log_n in [1,8]):  %d PASS / %d FAIL  (of %d)\n",
           base_pass, base_fail, base_cases);
    printf("  Ext-field cases (log_n in [1,8]):   %d PASS / %d FAIL  (of %d)\n",
           ext_pass, ext_fail, ext_cases);
    printf("  Circular self-tests:                0\n");
    printf("\n");

    if (total_fail == 0) {
        printf("NTT_GOLDILOCKS ORACLE GATE: GREEN — %d cases byte-match Plonky3 Radix2Dit, 0 circular\n",
               base_cases + ext_cases);
        return 0;
    }
    printf("NTT_GOLDILOCKS ORACLE GATE: RED — %d total mismatches\n", total_fail);
    return 1;
}
