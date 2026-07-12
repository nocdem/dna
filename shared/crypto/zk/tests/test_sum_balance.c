/**
 * @file test_sum_balance.c
 * @brief Cross-validate sum_balance.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/sum_balance.json (78 cases: 70 valid + 8 tamper across
 * n_outputs in {1, 2, 3, 4, 8}) and runs three checks per case:
 *
 *   (A) Reconstruction byte-match (non-tamper cases only):
 *       sum_balance_build_trace(amounts, ...) bytes  ==  JSON trace_rows bytes.
 *
 *   (B) Constraint outcome (all cases):
 *       sum_balance_check_constraints(JSON trace, ...) result  ==
 *           expected_valid from JSON.
 *
 *   (C) Residual byte-match (all cases):
 *       sum_balance_compute_residuals(JSON trace, ...) results  ==
 *           JSON init_residual / update_residuals / final_residual.
 *
 * Build (Makefile):
 *   make build/test_sum_balance
 *
 * Run:
 *   ./build/test_sum_balance tools/vectors/sum_balance.json
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *   2  load / parse error
 *
 * Test-count honesty: every case is byte-matched against the Plonky3 oracle
 * (commit 82cfad73). NO circular self-tests counted in the report.
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
#include "../sum_balance.h"

/* Max output count we serialize per case (oracle goes up to 8). */
#define TEST_MAX_OUTPUTS 16

/* ============================================================================
 * Tiny JSON tokenizer (same shape as test_range_air.c)
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
        if (s->src[s->pos] == ',') {
            s->pos++;
            continue;
        }
        if (i >= capacity) return false;
        if (!js_read_u64_string(s, &out_buf[i])) return false;
        i++;
    }
}

/* Read 2D array of decimal-u64 strings: [[...], [...], ...]
 * Writes row-major into out_buf of size max_rows * max_cols.
 * Sets *out_rows, *out_cols. If row widths differ, returns false. */
static bool js_read_u64_string_2d_array(json_scanner_t *s,
                                        uint64_t *out_buf,
                                        size_t max_rows,
                                        size_t max_cols,
                                        size_t *out_rows,
                                        size_t *out_cols) {
    if (!js_match(s, '[')) return false;
    size_t rows = 0;
    size_t cols = 0;
    bool cols_locked = false;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) return false;
        if (s->src[s->pos] == ']') {
            s->pos++;
            *out_rows = rows;
            *out_cols = cols;
            return true;
        }
        if (s->src[s->pos] == ',') {
            s->pos++;
            continue;
        }
        if (rows >= max_rows) return false;
        size_t this_cols = 0;
        if (!js_read_u64_string_array(s, &out_buf[rows * max_cols],
                                      max_cols, &this_cols)) {
            return false;
        }
        if (!cols_locked) {
            cols = this_cols;
            cols_locked = true;
        } else if (this_cols != cols) {
            fprintf(stderr, "FAIL: ragged 2D array row %zu has %zu cols, expected %zu\n",
                    rows, this_cols, cols);
            return false;
        }
        rows++;
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
 * Per-case parser
 * ========================================================================== */

typedef struct {
    char *name;
    size_t n_outputs;
    uint64_t amounts[TEST_MAX_OUTPUTS];
    uint64_t claimed_input_sum;
    uint64_t committed_fee;
    /* Row-major: row r col c at trace_rows[r * SUM_BALANCE_WIDTH + c]. */
    uint64_t trace_rows[TEST_MAX_OUTPUTS * SUM_BALANCE_WIDTH];
    uint64_t init_residual;
    uint64_t update_residuals[TEST_MAX_OUTPUTS]; /* n-1 valid */
    uint64_t final_residual;
    bool expected_valid;
    bool has_tamper;
} sum_balance_case_t;

static void free_case(sum_balance_case_t *c) {
    if (c->name) { free(c->name); c->name = NULL; }
}

static bool parse_case(json_scanner_t *s, sum_balance_case_t *out) {
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
        } else if (js_match_key(s, "n_outputs")) {
            if (!js_match(s, ':')) return false;
            /* n_outputs is emitted as a JSON number, not a string. Use a tiny
             * inline number parser since our js helpers expect strings. */
            js_skip_ws(s);
            char *endp = NULL;
            long val = strtol(s->src + s->pos, &endp, 10);
            if (endp == s->src + s->pos || val < 0 ||
                (size_t)val > TEST_MAX_OUTPUTS) {
                return false;
            }
            s->pos = (size_t)(endp - s->src);
            out->n_outputs = (size_t)val;
        } else if (js_match_key(s, "amounts")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->amounts,
                                          TEST_MAX_OUTPUTS, &actual)) {
                return false;
            }
            if (out->n_outputs != 0 && actual != out->n_outputs) {
                fprintf(stderr, "FAIL: amounts length %zu != n_outputs %zu\n",
                        actual, out->n_outputs);
                return false;
            }
            if (out->n_outputs == 0) out->n_outputs = actual;
        } else if (js_match_key(s, "claimed_input_sum")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->claimed_input_sum)) return false;
        } else if (js_match_key(s, "committed_fee")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->committed_fee)) return false;
        } else if (js_match_key(s, "trace_rows")) {
            if (!js_match(s, ':')) return false;
            size_t got_rows = 0, got_cols = 0;
            if (!js_read_u64_string_2d_array(s, out->trace_rows,
                                             TEST_MAX_OUTPUTS,
                                             SUM_BALANCE_WIDTH,
                                             &got_rows, &got_cols)) {
                return false;
            }
            if (got_cols != SUM_BALANCE_WIDTH) {
                fprintf(stderr, "FAIL: trace_rows cols=%zu, expected %zu\n",
                        got_cols, SUM_BALANCE_WIDTH);
                return false;
            }
            if (out->n_outputs != 0 && got_rows != out->n_outputs) {
                fprintf(stderr, "FAIL: trace_rows rows=%zu != n_outputs=%zu\n",
                        got_rows, out->n_outputs);
                return false;
            }
            if (out->n_outputs == 0) out->n_outputs = got_rows;
        } else if (js_match_key(s, "init_residual")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->init_residual)) return false;
        } else if (js_match_key(s, "update_residuals")) {
            if (!js_match(s, ':')) return false;
            size_t actual = 0;
            if (!js_read_u64_string_array(s, out->update_residuals,
                                          TEST_MAX_OUTPUTS, &actual)) {
                return false;
            }
            /* Should be n_outputs - 1 entries (or 0 for n_outputs == 1). */
            if (out->n_outputs != 0 &&
                actual != (out->n_outputs == 0 ? 0 : out->n_outputs - 1)) {
                fprintf(stderr,
                        "FAIL: update_residuals length %zu != n_outputs-1 %zu\n",
                        actual, out->n_outputs - 1);
                return false;
            }
        } else if (js_match_key(s, "final_residual")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u64_string(s, &out->final_residual)) return false;
        } else if (js_match_key(s, "expected_valid")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_bool(s, &out->expected_valid)) return false;
        } else if (js_match_key(s, "tamper_note")) {
            if (!js_match(s, ':')) return false;
            out->has_tamper = true;
            if (!js_skip_value(s)) return false;
        } else {
            /* Unknown key: skip its value. */
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
    const char *path = "tools/vectors/sum_balance.json";
    if (argc >= 2) path = argv[1];

    /* Pre-flight: column-binding constants are sane. */
    if (SUM_BALANCE_WIDTH != 54 ||
        SUM_BALANCE_ACC_OFF != 53 ||
        RANGE_AIR_AMOUNT_OFF != 52 ||
        RANGE_AIR_BIT_OFF(0) != 0 ||
        RANGE_AIR_BIT_OFF(51) != 51 ||
        SUM_BALANCE_MAX_OUTPUTS != 1024) {
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

    int total_cases = 0;
    int reconstruct_pass = 0, reconstruct_fail = 0;
    int outcome_accept_pass = 0, outcome_accept_fail = 0;
    int outcome_reject_pass = 0, outcome_reject_fail = 0;
    int residual_pass = 0, residual_fail = 0;
    int pi_perturb_pass = 0, pi_perturb_fail = 0;

    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len) break;
        if (s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }

        sum_balance_case_t c;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "FAIL: could not parse case at pos %zu\n", s.pos);
            free(src);
            return 2;
        }
        total_cases++;

        const size_t n = c.n_outputs;
        const sum_balance_public_t pub_in = {
            .claimed_input_sum = c.claimed_input_sum,
            .committed_fee = c.committed_fee,
        };

        /* (A) Reconstruction byte-match (non-tamper only). */
        if (!c.has_tamper) {
            uint64_t my_trace[TEST_MAX_OUTPUTS * SUM_BALANCE_WIDTH];
            memset(my_trace, 0, sizeof my_trace);
            sum_balance_build_trace(c.amounts, n, my_trace, SUM_BALANCE_WIDTH);
            const size_t total_cells = n * SUM_BALANCE_WIDTH;
            if (memcmp(my_trace, c.trace_rows,
                       sizeof(uint64_t) * total_cells) == 0) {
                reconstruct_pass++;
            } else {
                reconstruct_fail++;
                if (reconstruct_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (reconstruction) case '%s' n=%zu:\n",
                            c.name ? c.name : "<unnamed>", n);
                    for (size_t r = 0; r < n; r++) {
                        for (size_t col = 0; col < SUM_BALANCE_WIDTH; col++) {
                            size_t idx = r * SUM_BALANCE_WIDTH + col;
                            if (my_trace[idx] != c.trace_rows[idx]) {
                                fprintf(stderr,
                                        "  row %zu col %zu: oracle=%" PRIu64
                                        " ours=%" PRIu64 "\n",
                                        r, col, c.trace_rows[idx],
                                        my_trace[idx]);
                            }
                        }
                    }
                }
            }
        }

        /* (C) Residual byte-match — all cases. */
        {
            uint64_t my_init = 0, my_final = 0;
            uint64_t my_updates[TEST_MAX_OUTPUTS];
            memset(my_updates, 0, sizeof my_updates);
            sum_balance_compute_residuals(c.trace_rows, n, SUM_BALANCE_WIDTH,
                                          &pub_in, &my_init, my_updates,
                                          &my_final);
            const size_t n_updates = (n == 0 ? 0 : n - 1);
            bool ok = (my_init == c.init_residual) &&
                      (my_final == c.final_residual) &&
                      (memcmp(my_updates, c.update_residuals,
                              sizeof(uint64_t) * n_updates) == 0);
            if (ok) {
                residual_pass++;
            } else {
                residual_fail++;
                if (residual_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (residual) case '%s' n=%zu:\n",
                            c.name ? c.name : "<unnamed>", n);
                    if (my_init != c.init_residual) {
                        fprintf(stderr,
                                "  init: oracle=%" PRIu64 " ours=%" PRIu64 "\n",
                                c.init_residual, my_init);
                    }
                    if (my_final != c.final_residual) {
                        fprintf(stderr,
                                "  final: oracle=%" PRIu64 " ours=%" PRIu64 "\n",
                                c.final_residual, my_final);
                    }
                    for (size_t i = 0; i < n_updates; i++) {
                        if (my_updates[i] != c.update_residuals[i]) {
                            fprintf(stderr,
                                    "  update[%zu]: oracle=%" PRIu64
                                    " ours=%" PRIu64 "\n",
                                    i, c.update_residuals[i], my_updates[i]);
                        }
                    }
                }
            }
        }

        /* (B) Constraint outcome — all cases. */
        char fail_constraint = 0;
        size_t fail_row = 0;
        bool accepted = sum_balance_check_constraints(
            c.trace_rows, n, SUM_BALANCE_WIDTH, &pub_in,
            &fail_constraint, &fail_row);

        if (c.expected_valid) {
            if (accepted) {
                outcome_accept_pass++;
            } else {
                outcome_accept_fail++;
                if (outcome_accept_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (outcome: expected ACCEPT, got REJECT) "
                            "case '%s' first_fail=%c row=%zu\n",
                            c.name ? c.name : "<unnamed>",
                            fail_constraint ? fail_constraint : '?',
                            fail_row);
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
                            "case '%s'\n",
                            c.name ? c.name : "<unnamed>");
                }
            }
        }

        /* (D) Public-input binding — for VALID cases, perturbing either PI
         *     by XOR 1 (always changes the value, never overflows) must
         *     produce REJECT. If a perturbation still ACCEPTS, the C side
         *     is ignoring that public input — a bug byte-match can't catch
         *     because both sides would ignore it identically. */
        if (c.expected_valid) {
            const sum_balance_public_t perturb_claimed = {
                .claimed_input_sum = c.claimed_input_sum ^ UINT64_C(1),
                .committed_fee = c.committed_fee,
            };
            const sum_balance_public_t perturb_fee = {
                .claimed_input_sum = c.claimed_input_sum,
                .committed_fee = c.committed_fee ^ UINT64_C(1),
            };
            bool accepts_claimed_perturb = sum_balance_check_constraints(
                c.trace_rows, n, SUM_BALANCE_WIDTH, &perturb_claimed,
                NULL, NULL);
            bool accepts_fee_perturb = sum_balance_check_constraints(
                c.trace_rows, n, SUM_BALANCE_WIDTH, &perturb_fee,
                NULL, NULL);
            if (!accepts_claimed_perturb) {
                pi_perturb_pass++;
            } else {
                pi_perturb_fail++;
                if (pi_perturb_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (PI binding: claimed perturb still ACCEPTS) "
                            "case '%s'\n",
                            c.name ? c.name : "<unnamed>");
                }
            }
            if (!accepts_fee_perturb) {
                pi_perturb_pass++;
            } else {
                pi_perturb_fail++;
                if (pi_perturb_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (PI binding: fee perturb still ACCEPTS) "
                            "case '%s'\n",
                            c.name ? c.name : "<unnamed>");
                }
            }
        }

        free_case(&c);
    }

    free(src);

    /* ========================================================================
     * (E) Local soundness negatives (2026-07 mint-fix KATs — not oracle
     *     byte-match; these pin the ADVERSARIAL witnesses from the audit).
     * ====================================================================== */
    int soundness_pass = 0, soundness_fail = 0;

    /* (E1) Count bound: n = MAX_OUTPUTS is the last ACCEPT; n = MAX_OUTPUTS+1
     *      must REJECT with constraint 'N'. Heap-alloc (multi-hundred-KB
     *      fixture; stack would overflow). */
    {
        const size_t n_over = SUM_BALANCE_MAX_OUTPUTS + 1;
        uint64_t *amounts = (uint64_t *)calloc(n_over, sizeof(uint64_t));
        uint64_t *trace = (uint64_t *)calloc(n_over * SUM_BALANCE_WIDTH,
                                             sizeof(uint64_t));
        if (!amounts || !trace) {
            fprintf(stderr, "FAIL: E1 alloc\n");
            soundness_fail++;
        } else {
            for (size_t i = 0; i < n_over; i++) amounts[i] = 1;
            sum_balance_build_trace(amounts, n_over, trace, SUM_BALANCE_WIDTH);

            /* Boundary ACCEPT at exactly MAX_OUTPUTS. */
            const sum_balance_public_t pub_max = {
                .claimed_input_sum = (uint64_t)SUM_BALANCE_MAX_OUTPUTS + 5,
                .committed_fee = 5,
            };
            if (sum_balance_check_constraints(trace, SUM_BALANCE_MAX_OUTPUTS,
                                              SUM_BALANCE_WIDTH, &pub_max,
                                              NULL, NULL)) {
                soundness_pass++;
            } else {
                soundness_fail++;
                fprintf(stderr, "FAIL: E1 n=MAX_OUTPUTS boundary rejected\n");
            }

            /* MAX_OUTPUTS + 1 must REJECT via 'N' before any row math. */
            const sum_balance_public_t pub_over = {
                .claimed_input_sum = (uint64_t)n_over + 5,
                .committed_fee = 5,
            };
            char fc = 0;
            size_t fr = 0;
            bool acc_over = sum_balance_check_constraints(
                trace, n_over, SUM_BALANCE_WIDTH, &pub_over, &fc, &fr);
            if (!acc_over && fc == SUM_BALANCE_CONSTRAINT_COUNT) {
                soundness_pass++;
            } else {
                soundness_fail++;
                fprintf(stderr,
                        "FAIL: E1 n=MAX_OUTPUTS+1 accepted=%d constraint=%c\n",
                        (int)acc_over, fc ? fc : '?');
            }
        }
        free(amounts);
        free(trace);
    }

    /* (E2) The audit's concrete MINT witness: out1 = p-1, out2 = T+1 with
     *      claimed - fee = T. The mod-p balance alone ACCEPTS (acc wraps to
     *      T) — the composed range check MUST reject row 0 ('S': p-1 has no
     *      52-bit witness). This is exactly why range_air+sum_balance are
     *      only sound TOGETHER. */
    {
        const uint64_t GOLD_P = UINT64_C(0xFFFFFFFF00000001);
        const uint64_t fee = 5, t_val = 10;
        uint64_t amounts[2] = { GOLD_P - 1, t_val + 1 };
        uint64_t trace[2 * SUM_BALANCE_WIDTH];
        memset(trace, 0, sizeof trace);
        sum_balance_build_trace(amounts, 2, trace, SUM_BALANCE_WIDTH);
        const sum_balance_public_t pub_mint = {
            .claimed_input_sum = t_val + fee,
            .committed_fee = fee,
        };

        /* Balance alone accepts (documents the wraparound hole)... */
        bool balance_alone = sum_balance_check_constraints(
            trace, 2, SUM_BALANCE_WIDTH, &pub_mint, NULL, NULL);
        /* ...the composed range check is what kills the mint. */
        char fc = 0;
        size_t fr = 0, fb = 0;
        bool range_ok = range_air_check_constraints(trace, 2,
                                                    SUM_BALANCE_WIDTH,
                                                    &fc, &fr, &fb);
        if (balance_alone && !range_ok &&
            fc == RANGE_AIR_CONSTRAINT_RECOMP && fr == 0) {
            soundness_pass++;
        } else {
            soundness_fail++;
            fprintf(stderr,
                    "FAIL: E2 mint witness: balance_alone=%d range_ok=%d "
                    "constraint=%c row=%zu\n",
                    (int)balance_alone, (int)range_ok, fc ? fc : '?', fr);
        }
    }

    /* (E3) FEE-WRAP MINT (2026-07-12 red-team finding). The 07-11 fix bounded
     * outputs + count but left the F-equation publics unbounded. A prover sets
     * committed_fee = p - A (a valid canonical field element); then
     * (claimed - fee) mod p wraps to A, matched by a single in-range output of A,
     * minting A base units from claimed = 0. The public-input bound must REJECT
     * this with constraint 'P' (fee >= 2^62), BEFORE any row math. */
    {
        const uint64_t GOLD_P = UINT64_C(0xFFFFFFFF00000001);
        const uint64_t A = 1000;
        uint64_t amounts[1] = { A };            /* in range (< 2^52) */
        uint64_t trace[SUM_BALANCE_WIDTH];
        memset(trace, 0, sizeof trace);
        sum_balance_build_trace(amounts, 1, trace, SUM_BALANCE_WIDTH);
        const sum_balance_public_t pub_wrap = {
            .claimed_input_sum = 0,             /* declares zero input... */
            .committed_fee = GOLD_P - A,        /* ...via a near-p wrapping fee */
        };
        char fc = 0;
        size_t fr = 0;
        bool accepted = sum_balance_check_constraints(
            trace, 1, SUM_BALANCE_WIDTH, &pub_wrap, &fc, &fr);
        if (!accepted && fc == SUM_BALANCE_CONSTRAINT_PUBBOUND) {
            soundness_pass++;
        } else {
            soundness_fail++;
            fprintf(stderr,
                    "FAIL: E3 fee-wrap mint accepted=%d constraint=%c "
                    "(want reject 'P')\n",
                    (int)accepted, fc ? fc : '?');
        }
    }

    /* (E4) EMPTY TRACE fail-closed. n_rows == 0 leaves the F balance equation
     * unevaluated; a money check must reject (not vacuously accept) with 'P'. */
    {
        uint64_t dummy = 0;
        const sum_balance_public_t pub_zero = { .claimed_input_sum = 0,
                                                .committed_fee = 0 };
        char fc = 0;
        size_t fr = 0;
        bool accepted = sum_balance_check_constraints(
            &dummy, 0, SUM_BALANCE_WIDTH, &pub_zero, &fc, &fr);
        if (!accepted && fc == SUM_BALANCE_CONSTRAINT_PUBBOUND) {
            soundness_pass++;
        } else {
            soundness_fail++;
            fprintf(stderr,
                    "FAIL: E4 empty trace accepted=%d constraint=%c "
                    "(want reject 'P')\n",
                    (int)accepted, fc ? fc : '?');
        }
    }

    /* (E5) BOUNDARY: claimed/fee at exactly SUM_BALANCE_TERM_MAX must REJECT,
     * one below must be allowed through the pub-bound gate (a genuine valid
     * proof with claimed just below the ceiling still needs its F to hold, so we
     * only check the gate here via a claimed = TERM_MAX rejection). */
    {
        uint64_t amounts[1] = { 5 };
        uint64_t trace[SUM_BALANCE_WIDTH];
        memset(trace, 0, sizeof trace);
        sum_balance_build_trace(amounts, 1, trace, SUM_BALANCE_WIDTH);
        const sum_balance_public_t pub_at_max = {
            .claimed_input_sum = SUM_BALANCE_TERM_MAX,   /* == 2^62, out of bound */
            .committed_fee = 0,
        };
        char fc = 0;
        size_t fr = 0;
        bool accepted = sum_balance_check_constraints(
            trace, 1, SUM_BALANCE_WIDTH, &pub_at_max, &fc, &fr);
        if (!accepted && fc == SUM_BALANCE_CONSTRAINT_PUBBOUND) {
            soundness_pass++;
        } else {
            soundness_fail++;
            fprintf(stderr,
                    "FAIL: E5 claimed==TERM_MAX accepted=%d constraint=%c "
                    "(want reject 'P')\n",
                    (int)accepted, fc ? fc : '?');
        }
    }

    int total_fail = reconstruct_fail + outcome_accept_fail +
                     outcome_reject_fail + residual_fail + pi_perturb_fail +
                     soundness_fail;

    printf("\n");
    printf("Sum_balance test summary (byte-match against Plonky3 commit 82cfad73):\n");
    printf("  Total cases:                %d\n", total_cases);
    printf("  (A)  Reconstruction byte-match (non-tamper cases):  %d PASS / %d FAIL\n",
           reconstruct_pass, reconstruct_fail);
    printf("  (B1) Outcome ACCEPT for valid trace:                %d PASS / %d FAIL\n",
           outcome_accept_pass, outcome_accept_fail);
    printf("  (B2) Outcome REJECT for tampered trace:             %d PASS / %d FAIL\n",
           outcome_reject_pass, outcome_reject_fail);
    printf("  (C)  Residual byte-match (I + n-1 U + F per case):  %d PASS / %d FAIL\n",
           residual_pass, residual_fail);
    printf("  (D)  PI binding: perturbed claimed/fee → REJECT:   %d PASS / %d FAIL\n",
           pi_perturb_pass, pi_perturb_fail);
    printf("  (E)  Soundness KATs (N bound + mint witness):       %d PASS / %d FAIL\n",
           soundness_pass, soundness_fail);
    printf("  Circular self-tests:                                0\n");
    printf("\n");

    if (total_fail == 0) {
        printf("SUM_BALANCE GATE: GREEN — %d cases, all categories PASS, 0 circular tests\n",
               total_cases);
        return 0;
    }
    printf("SUM_BALANCE GATE: RED — %d total mismatches\n", total_fail);
    return 1;
}
