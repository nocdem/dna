/**
 * @file test_range_air.c
 * @brief Cross-validate range_air.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/range_air.json (80 cases: 8 edge + 70 random + 2 tamper)
 * and runs two checks per case:
 *
 *   (A) Reconstruction byte-match (non-tamper cases only):
 *       range_air_build_trace(amount, ...) bytes  ==  JSON trace_row bytes.
 *       Verifies our C implementation produces the same trace as the oracle.
 *
 *   (B) Constraint outcome (all cases):
 *       range_air_check_constraints(JSON trace_row, ...) result  ==
 *           expected_valid from JSON.
 *       Valid cases must ACCEPT, tamper cases must REJECT.
 *
 * Build (Makefile):
 *   make build/test_range_air
 *
 * Run:
 *   ./build/test_range_air tools/vectors/range_air.json
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *   2  load / parse error
 *
 * Test-count honesty: every case here is byte-matched against the Plonky3
 * oracle (commit 82cfad73). NO circular self-tests are counted in the report.
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

#include "../range_air.h"

/* ============================================================================
 * Tiny JSON tokenizer (shape matches tests/test_field_goldilocks.c)
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

static bool js_read_bool(json_scanner_t *s, bool *out) {
    js_skip_ws(s);
    if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "true", 4) == 0) {
        s->pos += 4;
        *out = true;
        return true;
    }
    if (s->pos + 5 <= s->len && memcmp(s->src + s->pos, "false", 5) == 0) {
        s->pos += 5;
        *out = false;
        return true;
    }
    return false;
}

/* Skip exactly one JSON value (object/array/string/bool/null/number). */
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
    /* bool / null / number — consume until a structural char or whitespace. */
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

/* Read `[ "n1", "n2", ..., "nk" ]` of decimal u64 strings.
 * Returns true on success; *out_actual receives the count read. */
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
        if (s->src[s->pos] == ',') {
            s->pos++;
            continue;
        }
        if (i >= capacity) return false;
        if (!js_read_u64_string(s, &out_buf[i])) return false;
        i++;
    }
}

/* Seek to `"<key>": [` and consume the opening `[`. */
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
 * Per-case parser
 * ========================================================================== */

typedef struct {
    char *name;
    uint64_t amount_u64;
    uint64_t trace_row[RANGE_AIR_WIDTH];
    uint64_t bool_residuals[64];
    uint64_t recompose_residual;
    bool expected_valid;
    bool has_tamper;
} range_air_case_t;

static void free_case(range_air_case_t *c) {
    if (c->name) {
        free(c->name);
        c->name = NULL;
    }
}

static bool parse_case(json_scanner_t *s, range_air_case_t *out) {
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
        } else if (js_match_key(s, "amount_u64")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->amount_u64)) return false;
        } else if (js_match_key(s, "trace_row")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->trace_row,
                                          RANGE_AIR_WIDTH, &actual)) {
                return false;
            }
            if (actual != RANGE_AIR_WIDTH) {
                fprintf(stderr, "FAIL: trace_row has %zu entries (want %zu)\n",
                        actual, RANGE_AIR_WIDTH);
                return false;
            }
        } else if (js_match_key(s, "bool_residuals")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->bool_residuals,
                                          64, &actual)) {
                return false;
            }
            if (actual != 64) {
                fprintf(stderr,
                        "FAIL: bool_residuals has %zu entries (want 64)\n",
                        actual);
                return false;
            }
        } else if (js_match_key(s, "recompose_residual")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->recompose_residual)) return false;
        } else if (js_match_key(s, "expected_valid")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_bool(s, &out->expected_valid)) return false;
        } else if (js_match_key(s, "tamper_note")) {
            if (!js_match(s, ':')) return false;
            out->has_tamper = true;
            if (!js_skip_value(s)) return false;
        } else {
            /* Unknown key: read its string + colon + skip value. */
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
    const char *path = "tools/vectors/range_air.json";
    if (argc >= 2) path = argv[1];

    /* Pre-flight: column-binding constants are sane. (test #6 enforces this
     * formally; redundant check here helps debugging if test_air_column_layout
     * was never built.) */
    if (RANGE_AIR_WIDTH != 65 ||
        RANGE_AIR_AMOUNT_OFF != 64 ||
        RANGE_AIR_BIT_OFF(0) != 0 ||
        RANGE_AIR_BIT_OFF(63) != 63) {
        fprintf(stderr, "FAIL: column-binding contract violated\n");
        return 2;
    }

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};
    if (!js_seek_array(&s, "cases")) {
        fprintf(stderr, "FAIL: could not locate 'cases' array\n");
        free(src);
        return 2;
    }

    /* Honest counters — distinct categories, NEVER conflated. */
    int total_cases = 0;
    int reconstruct_pass = 0, reconstruct_fail = 0;
    int outcome_accept_pass = 0, outcome_accept_fail = 0;
    int outcome_reject_pass = 0, outcome_reject_fail = 0;
    int residual_pass = 0, residual_fail = 0;

    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len) break;
        if (s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }

        range_air_case_t c;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "FAIL: could not parse case at pos %zu\n", s.pos);
            free(src);
            return 2;
        }
        total_cases++;

        /* (A) Reconstruction byte-match — non-tamper cases only. */
        if (!c.has_tamper) {
            uint64_t my_trace[RANGE_AIR_WIDTH];
            range_air_build_trace(&c.amount_u64, 1, my_trace, RANGE_AIR_WIDTH);
            if (memcmp(my_trace, c.trace_row,
                       sizeof(uint64_t) * RANGE_AIR_WIDTH) == 0) {
                reconstruct_pass++;
            } else {
                reconstruct_fail++;
                if (reconstruct_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (reconstruction) case '%s' amount=%" PRIu64 ":\n",
                            c.name ? c.name : "<unnamed>", c.amount_u64);
                    for (size_t i = 0; i < RANGE_AIR_WIDTH; i++) {
                        if (my_trace[i] != c.trace_row[i]) {
                            fprintf(stderr,
                                    "  cell %zu: oracle=%" PRIu64
                                    " ours=%" PRIu64 "\n",
                                    i, c.trace_row[i], my_trace[i]);
                        }
                    }
                }
            }
        }

        /* (C) Residual byte-match — every per-bit boolean residual + the
         *     recomposition residual, byte-compared against the Plonky3 oracle.
         *     Covers the arithmetic that range_air_check_constraints would
         *     short-circuit on; ensures even tamper cases hit the same field
         *     values the oracle saw. */
        {
            uint64_t my_bool[64];
            uint64_t my_recomp = 0;
            range_air_compute_residuals(c.trace_row, my_bool, &my_recomp);
            bool ok = (my_recomp == c.recompose_residual) &&
                      (memcmp(my_bool, c.bool_residuals,
                              sizeof(uint64_t) * 64) == 0);
            if (ok) {
                residual_pass++;
            } else {
                residual_fail++;
                if (residual_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (residual) case '%s' amount=%" PRIu64 ":\n",
                            c.name ? c.name : "<unnamed>", c.amount_u64);
                    if (my_recomp != c.recompose_residual) {
                        fprintf(stderr,
                                "  recompose: oracle=%" PRIu64
                                " ours=%" PRIu64 "\n",
                                c.recompose_residual, my_recomp);
                    }
                    for (size_t i = 0; i < 64; i++) {
                        if (my_bool[i] != c.bool_residuals[i]) {
                            fprintf(stderr,
                                    "  bool[%zu]: oracle=%" PRIu64
                                    " ours=%" PRIu64 "\n",
                                    i, c.bool_residuals[i], my_bool[i]);
                        }
                    }
                }
            }
        }

        /* (B) Constraint outcome — all cases. */
        char fail_constraint = 0;
        size_t fail_row = 0, fail_bit = 0;
        bool accepted = range_air_check_constraints(
            c.trace_row, 1, RANGE_AIR_WIDTH,
            &fail_constraint, &fail_row, &fail_bit);

        if (c.expected_valid) {
            if (accepted) {
                outcome_accept_pass++;
            } else {
                outcome_accept_fail++;
                if (outcome_accept_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (outcome: expected ACCEPT, got REJECT) "
                            "case '%s' amount=%" PRIu64
                            " first_fail=%c row=%zu bit=%zu\n",
                            c.name ? c.name : "<unnamed>", c.amount_u64,
                            fail_constraint ? fail_constraint : '?',
                            fail_row, fail_bit);
                }
            }
        } else {
            if (!accepted) {
                outcome_reject_pass++;
            } else {
                outcome_reject_fail++;
                if (outcome_reject_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (outcome: expected REJECT, got ACCEPT) "
                            "case '%s' amount=%" PRIu64 "\n",
                            c.name ? c.name : "<unnamed>", c.amount_u64);
                }
            }
        }

        free_case(&c);
    }

    free(src);

    /* ============================================================================
     * Honest report — categories tabulated separately per
     * feedback_no_kafadan_crypto.md red flag: NEVER report "X tests, 0 fail"
     * without category breakdown.
     * ========================================================================== */
    int total_fail = reconstruct_fail + outcome_accept_fail +
                     outcome_reject_fail + residual_fail;

    printf("\n");
    printf("Range_air test summary (vectors byte-match against Plonky3 commit 82cfad73):\n");
    printf("  Total cases:                %d\n", total_cases);
    printf("  (A)  Reconstruction byte-match (non-tamper cases):  %d PASS / %d FAIL\n",
           reconstruct_pass, reconstruct_fail);
    printf("  (B1) Outcome ACCEPT for valid trace:                %d PASS / %d FAIL\n",
           outcome_accept_pass, outcome_accept_fail);
    printf("  (B2) Outcome REJECT for tampered trace:             %d PASS / %d FAIL\n",
           outcome_reject_pass, outcome_reject_fail);
    printf("  (C)  Residual byte-match (per-bit bool + recomp):   %d PASS / %d FAIL\n",
           residual_pass, residual_fail);
    printf("  Circular self-tests:                                0\n");
    printf("\n");

    if (total_fail == 0) {
        printf("RANGE_AIR GATE: GREEN — %d cases, all categories PASS, 0 circular tests\n",
               total_cases);
        return 0;
    }
    printf("RANGE_AIR GATE: RED — %d total mismatches\n", total_fail);
    return 1;
}
