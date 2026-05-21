/**
 * @file test_fri_commit.c
 * @brief Cross-validate fri_commit_phase against Plonky3 oracle (Sub-sprint 2.2).
 *
 * Loads tools/vectors/fri_commit.json. For each case:
 *   1. Initialize transcript with case.transcript_init params.
 *   2. Verify pre-loop transcript state matches oracle.
 *   3. Run fri_commit_phase.
 *   4. For each layer, verify:
 *        - merkle_root_hex matches oracle's layer.merkle_root_hex
 *        - layer_beta matches oracle's layer.beta
 *   5. Verify final_layer_values matches oracle.
 *   6. Verify post-loop transcript state + counter match oracle.
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
#include "../merkle_smt.h"
#include "../transcript.h"
#include "../fri_commit.h"

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
static bool js_read_u64(json_scanner_t *s, uint64_t *out) {
    js_skip_ws(s);
    uint64_t v = 0; bool any = false;
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint64_t)(c - '0'); s->pos++; any = true;
    }
    if (!any) return false;
    *out = v;
    return true;
}
static bool js_read_u64_pair(json_scanner_t *s, uint64_t *a, uint64_t *b) {
    if (!js_match(s, '[')) return false;
    char *sa = js_read_string(s); if (!sa) return false;
    if (!js_match(s, ',')) { free(sa); return false; }
    char *sb = js_read_string(s); if (!sb) { free(sa); return false; }
    if (!js_match(s, ']')) { free(sa); free(sb); return false; }
    *a = strtoull(sa, NULL, 10); *b = strtoull(sb, NULL, 10);
    free(sa); free(sb);
    return true;
}
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}
static int hex_decode(const char *hex, uint8_t **out_buf) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t bytes = hlen / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes + 1);
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_buf = buf;
    return (int)bytes;
}
static bool hex_decode_fixed(const char *hex, uint8_t *out, size_t expected) {
    if (strlen(hex) != expected * 2) return false;
    for (size_t i = 0; i < expected; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

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

/* ============================================================================
 * Layer/case parsing
 * ========================================================================== */

typedef struct {
    uint32_t layer_index;
    uint32_t layer_log_size;
    uint8_t  merkle_root[64];
    uint64_t beta_a0, beta_a1;
} expected_layer_t;

typedef struct {
    char *name;
    uint32_t initial_log_size;
    uint32_t cap_height_log;
    /* transcript init */
    uint8_t chain_id[32];
    uint64_t block_height;
    uint32_t tx_index;
    uint8_t *public_input;
    size_t public_input_len;
    uint8_t transcript_state_pre_loop[64];
    uint32_t transcript_counter_pre_loop;
    uint8_t transcript_state_post_loop[64];
    uint32_t transcript_counter_post_loop;
    /* values */
    gold_fp2_t *initial_values; size_t n_initial;
    gold_fp2_t *final_layer_values; size_t n_final;
    /* expected layers */
    expected_layer_t *layers; size_t n_layers;
} case_data_t;

static void free_case(case_data_t *c) {
    free(c->name);
    free(c->public_input);
    free(c->initial_values);
    free(c->final_layer_values);
    free(c->layers);
    memset(c, 0, sizeof(*c));
}

static int parse_one_layer(json_scanner_t *s, expected_layer_t *L) {
    if (!js_match(s, '{')) return -1;
    char *root_hex = NULL;
    uint64_t b0 = 0, b1 = 0;
    bool got_beta = false;
    L->layer_index = 0xFFFFFFFF;
    L->layer_log_size = 0xFFFFFFFF;
    while (1) {
        js_skip_ws(s);
        if (s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (js_match_key(s, "layer_index")) { js_match(s, ':'); js_read_u32(s, &L->layer_index); }
        else if (js_match_key(s, "layer_log_size")) { js_match(s, ':'); js_read_u32(s, &L->layer_log_size); }
        else if (js_match_key(s, "merkle_root_hex")) { js_match(s, ':'); root_hex = js_read_string(s); }
        else if (js_match_key(s, "beta")) { js_match(s, ':'); got_beta = js_read_u64_pair(s, &b0, &b1); }
        else { char *k = js_read_string(s); if (k) free(k); js_match(s, ':'); js_skip_value(s); }
    }
    if (!root_hex || !got_beta) { free(root_hex); return -1; }
    if (!hex_decode_fixed(root_hex, L->merkle_root, 64)) { free(root_hex); return -1; }
    L->beta_a0 = b0; L->beta_a1 = b1;
    free(root_hex);
    return 0;
}

static int parse_layers_array(json_scanner_t *s, case_data_t *c) {
    if (!js_match(s, '[')) return -1;
    size_t cap = 4, n = 0;
    expected_layer_t *arr = (expected_layer_t *)malloc(cap * sizeof(expected_layer_t));
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) { free(arr); return -1; }
        if (s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (n + 1 > cap) {
            cap *= 2;
            arr = (expected_layer_t *)realloc(arr, cap * sizeof(expected_layer_t));
        }
        if (parse_one_layer(s, &arr[n]) != 0) { free(arr); return -1; }
        n++;
    }
    c->layers = arr;
    c->n_layers = n;
    return 0;
}

/* Parse a "transcript_init" object into case fields. */
static int parse_init(json_scanner_t *s, case_data_t *c) {
    if (!js_match(s, '{')) return -1;
    char *chain_id_hex = NULL, *public_input_hex = NULL, *initial_state_hex = NULL;
    while (1) {
        js_skip_ws(s);
        if (s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (js_match_key(s, "chain_id_hex")) { js_match(s, ':'); chain_id_hex = js_read_string(s); }
        else if (js_match_key(s, "block_height")) { js_match(s, ':'); js_read_u64(s, &c->block_height); }
        else if (js_match_key(s, "tx_index")) { js_match(s, ':'); js_read_u32(s, &c->tx_index); }
        else if (js_match_key(s, "public_input_hex")) { js_match(s, ':'); public_input_hex = js_read_string(s); }
        else if (js_match_key(s, "initial_state_hex")) { js_match(s, ':'); initial_state_hex = js_read_string(s); }
        else { char *k = js_read_string(s); if (k) free(k); js_match(s, ':'); js_skip_value(s); }
    }
    if (!chain_id_hex || !public_input_hex || !initial_state_hex) {
        free(chain_id_hex); free(public_input_hex); free(initial_state_hex);
        return -1;
    }
    if (!hex_decode_fixed(chain_id_hex, c->chain_id, 32)) {
        free(chain_id_hex); free(public_input_hex); free(initial_state_hex); return -1;
    }
    uint8_t *pubin = NULL;
    int pubin_len = hex_decode(public_input_hex, &pubin);
    if (pubin_len < 0) {
        free(chain_id_hex); free(public_input_hex); free(initial_state_hex); return -1;
    }
    c->public_input = pubin;
    c->public_input_len = (size_t)pubin_len;
    free(chain_id_hex); free(public_input_hex); free(initial_state_hex);
    return 0;
}

static int parse_case(json_scanner_t *s, case_data_t *c) {
    memset(c, 0, sizeof(*c));
    if (!js_match(s, '{')) return -1;
    while (1) {
        js_skip_ws(s);
        if (s->src[s->pos] == '}') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        if (js_match_key(s, "name")) { js_match(s, ':'); c->name = js_read_string(s); }
        else if (js_match_key(s, "initial_log_size")) { js_match(s, ':'); js_read_u32(s, &c->initial_log_size); }
        else if (js_match_key(s, "cap_height_log")) { js_match(s, ':'); js_read_u32(s, &c->cap_height_log); }
        else if (js_match_key(s, "transcript_init")) { js_match(s, ':'); if (parse_init(s, c) != 0) return -1; }
        else if (js_match_key(s, "initial_values")) { js_match(s, ':'); c->initial_values = read_fp2_array(s, &c->n_initial); }
        else if (js_match_key(s, "transcript_state_pre_loop_hex")) {
            js_match(s, ':');
            char *hex = js_read_string(s);
            if (!hex || !hex_decode_fixed(hex, c->transcript_state_pre_loop, 64)) { free(hex); return -1; }
            free(hex);
        }
        else if (js_match_key(s, "transcript_counter_pre_loop")) { js_match(s, ':'); js_read_u32(s, &c->transcript_counter_pre_loop); }
        else if (js_match_key(s, "layers")) { js_match(s, ':'); if (parse_layers_array(s, c) != 0) return -1; }
        else if (js_match_key(s, "final_layer_values")) { js_match(s, ':'); c->final_layer_values = read_fp2_array(s, &c->n_final); }
        else if (js_match_key(s, "transcript_state_post_loop_hex")) {
            js_match(s, ':');
            char *hex = js_read_string(s);
            if (!hex || !hex_decode_fixed(hex, c->transcript_state_post_loop, 64)) { free(hex); return -1; }
            free(hex);
        }
        else if (js_match_key(s, "transcript_counter_post_loop")) { js_match(s, ':'); js_read_u32(s, &c->transcript_counter_post_loop); }
        else { char *k = js_read_string(s); if (k) free(k); js_match(s, ':'); js_skip_value(s); }
    }
    return 0;
}

/* ============================================================================
 * Per-case runner
 * ========================================================================== */

static int run_case(const case_data_t *c, int *out_passed, int *out_failed) {
    int passed = 0, failed = 0;

    /* Initialize transcript. */
    transcript_t tr;
    transcript_init(&tr, c->chain_id, c->block_height, c->tx_index,
                    c->public_input, c->public_input_len);

    /* Verify pre-loop state. */
    if (memcmp(tr.state, c->transcript_state_pre_loop, 64) != 0) {
        fprintf(stderr, "  %s: pre-loop state MISMATCH\n", c->name);
        failed++;
    } else passed++;
    if (tr.challenge_counter != c->transcript_counter_pre_loop) {
        fprintf(stderr, "  %s: pre-loop counter MISMATCH (have=%u want=%u)\n",
                c->name, tr.challenge_counter, c->transcript_counter_pre_loop);
        failed++;
    } else passed++;

    /* Allocate scratch and output. */
    size_t initial_size = (size_t)1 << c->initial_log_size;
    size_t final_size = (size_t)1 << c->cap_height_log;
    gold_fp2_t *scratch = (gold_fp2_t *)malloc(initial_size * sizeof(gold_fp2_t));
    fri_commit_output_t out = {0};
    out.final_values = (gold_fp2_t *)malloc(final_size * sizeof(gold_fp2_t));
    if (!scratch || !out.final_values) {
        fprintf(stderr, "  %s: oom\n", c->name);
        free(scratch); free(out.final_values);
        *out_passed += passed; *out_failed += failed + 1;
        return -1;
    }

    /* Run commit phase. */
    if (fri_commit_phase(&tr, c->initial_values, c->initial_log_size,
                         c->cap_height_log, scratch, &out) != 0) {
        fprintf(stderr, "  %s: fri_commit_phase failed\n", c->name);
        free(scratch); free(out.final_values);
        *out_passed += passed; *out_failed += failed + 1;
        return -1;
    }

    /* Verify layer count. */
    if ((size_t)out.num_layers != c->n_layers) {
        fprintf(stderr, "  %s: layer count MISMATCH (have=%u want=%zu)\n",
                c->name, out.num_layers, c->n_layers);
        failed++;
    } else passed++;

    /* Verify each layer's root + beta. */
    for (size_t i = 0; i < c->n_layers && i < out.num_layers; i++) {
        if (memcmp(out.layer_roots[i], c->layers[i].merkle_root, 64) != 0) {
            if (failed < 3) fprintf(stderr, "  %s: layer[%zu] root MISMATCH\n", c->name, i);
            failed++;
        } else passed++;

        uint64_t got_a = gold_fp_to_u64(out.layer_betas[i].a);
        uint64_t got_b = gold_fp_to_u64(out.layer_betas[i].b);
        if (got_a != c->layers[i].beta_a0 || got_b != c->layers[i].beta_a1) {
            if (failed < 3) fprintf(stderr, "  %s: layer[%zu] beta MISMATCH (have (%"PRIu64",%"PRIu64") want (%"PRIu64",%"PRIu64"))\n",
                                    c->name, i, got_a, got_b, c->layers[i].beta_a0, c->layers[i].beta_a1);
            failed++;
        } else passed++;
    }

    /* Verify final layer values. */
    if ((size_t)((size_t)1 << out.final_log_size) != c->n_final) {
        fprintf(stderr, "  %s: final size MISMATCH (have=2^%u=%zu want=%zu)\n",
                c->name, out.final_log_size, (size_t)1 << out.final_log_size, c->n_final);
        failed++;
    } else {
        for (size_t i = 0; i < c->n_final; i++) {
            uint64_t exp_a = gold_fp_to_u64(c->final_layer_values[i].a);
            uint64_t exp_b = gold_fp_to_u64(c->final_layer_values[i].b);
            uint64_t got_a = gold_fp_to_u64(out.final_values[i].a);
            uint64_t got_b = gold_fp_to_u64(out.final_values[i].b);
            if (got_a != exp_a || got_b != exp_b) {
                if (failed < 3) fprintf(stderr, "  %s: final[%zu] MISMATCH\n", c->name, i);
                failed++;
            } else passed++;
        }
    }

    /* Verify post-loop transcript. */
    if (memcmp(tr.state, c->transcript_state_post_loop, 64) != 0) {
        fprintf(stderr, "  %s: post-loop state MISMATCH\n", c->name);
        failed++;
    } else passed++;
    if (tr.challenge_counter != c->transcript_counter_post_loop) {
        fprintf(stderr, "  %s: post-loop counter MISMATCH (have=%u want=%u)\n",
                c->name, tr.challenge_counter, c->transcript_counter_post_loop);
        failed++;
    } else passed++;

    free(scratch);
    free(out.final_values);
    *out_passed += passed; *out_failed += failed;
    return 0;
}

int main(int argc, char **argv) {
    const char *path = "tools/vectors/fri_commit.json";
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
    printf("case                    pass    fail\n");
    printf("---------------------  ------  ------\n");

    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len) break;
        if (s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }
        case_data_t c;
        if (parse_case(&s, &c) != 0) {
            fprintf(stderr, "parse error\n");
            free(src);
            return 2;
        }
        int p = total_passed, f = total_failed;
        run_case(&c, &total_passed, &total_failed);
        printf("%-21s  %6d  %6d\n", c.name ? c.name : "?",
               total_passed - p, total_failed - f);
        free_case(&c);
    }

    free(src);
    printf("\nTotal: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 2.2 (fri_commit) GATE: GREEN — multi-layer commit byte-matches Plonky3\n");
        return 0;
    } else {
        printf("SUB-SPRINT 2.2 (fri_commit) GATE: RED — %d mismatches\n", total_failed);
        return 1;
    }
}
