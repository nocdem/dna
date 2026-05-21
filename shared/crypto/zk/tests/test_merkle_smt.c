/**
 * @file test_merkle_smt.c
 * @brief Cross-validate merkle_smt.c against Plonky3 oracle JSON.
 *
 * Loads tools/vectors/merkle.json and runs 5 categories of cases:
 *   - leaf_hash   : merkle_smt_hash_leaf(index, value) → 64-byte hash
 *   - null_hash   : merkle_smt_hash_null(index) → 64-byte hash
 *   - node_hash   : merkle_smt_hash_node(left, right) → 64-byte hash
 *   - root        : merkle_smt_compute_root(leaves, depth) → 64-byte root
 *   - proof       : merkle_smt_build_proof + merkle_smt_verify_proof
 *
 * Build:
 *   gcc -std=c99 -O2 -Wall -Wextra -I.. -I../../.. \
 *       tests/test_merkle_smt.c merkle_smt.c \
 *       ../hash/qgp_sha3.c \
 *       -lcrypto -o test_merkle_smt
 *   ./test_merkle_smt tools/vectors/merkle.json
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

#include "../merkle_smt.h"

/* ============================================================================
 * Minimal JSON tokenizer (shared style with previous tests)
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

static bool js_read_u32(json_scanner_t *s, uint32_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    uint64_t v = 0;
    bool any = false;
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint64_t)(c - '0');
        s->pos++;
        any = true;
    }
    if (!any) return false;
    *out = (uint32_t)v;
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
 * Hex helpers
 * ========================================================================== */

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Decode hex string (NUL-terminated) into binary. Caller frees out_buf.
 * Returns length on success, -1 on parse error. */
static int hex_decode(const char *hex, uint8_t **out_buf) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t bytes = hlen / 2;
    uint8_t *buf = (uint8_t *)malloc(bytes + 1); /* +1 to avoid zero-malloc edge */
    if (!buf) return -1;
    for (size_t i = 0; i < bytes; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return -1; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_buf = buf;
    return (int)bytes;
}

/* Decode exactly N bytes from hex string. Returns true on success. */
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
 * Per-operation runners
 * ========================================================================== */

/* Skip whitespace + a single ',' between array elements (if present). */
static bool advance_array_elem(json_scanner_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    if (s->src[s->pos] == ']') { s->pos++; return false; }
    if (s->src[s->pos] == ',') { s->pos++; }
    js_skip_ws(s);
    return s->src[s->pos] == '{';
}

/* Helpers to skip arbitrary value (when we encounter an unwanted key). */
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
        /* skip key */
        char *k = js_read_string(s);
        if (k) free(k);
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
    /* Number or bool: read until separator. */
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if (d == ',' || d == '}' || d == ']' || d == ' ' || d == '\n' ||
            d == '\t' || d == '\r') break;
        s->pos++;
    }
}

/* ---------- leaf_hash ---------- */
static int run_leaf_hash(json_scanner_t *s) {
    if (!js_seek_op_array(s, "leaf_hash")) {
        fprintf(stderr, "FAIL: leaf_hash array not found\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (advance_array_elem(s)) {
        s->pos++; /* { */
        uint32_t index = 0;
        char *value_hex = NULL;
        char *hash_hex = NULL;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "index")) { js_match(s, ':'); js_read_u32(s, &index); }
            else if (js_match_key(s, "value_hex")) { js_match(s, ':'); value_hex = js_read_string(s); }
            else if (js_match_key(s, "hash_hex")) { js_match(s, ':'); hash_hex = js_read_string(s); }
            else { fprintf(stderr, "leaf_hash: bad key\n"); return -1; }
        }
        if (!value_hex || !hash_hex) { fprintf(stderr, "leaf_hash: missing field\n"); return -1; }

        uint8_t *value_buf = NULL;
        int value_len = hex_decode(value_hex, &value_buf);
        if (value_len < 0) { fprintf(stderr, "leaf_hash: hex decode fail\n"); return -1; }

        uint8_t expected[MERKLE_SMT_HASH_SIZE], actual[MERKLE_SMT_HASH_SIZE];
        if (!hex_decode_fixed(hash_hex, expected, MERKLE_SMT_HASH_SIZE)) {
            fprintf(stderr, "leaf_hash: bad expected hex\n"); return -1;
        }
        merkle_smt_hash_leaf(index, value_buf, (size_t)value_len, actual);

        if (memcmp(expected, actual, MERKLE_SMT_HASH_SIZE) != 0) {
            if (failed < 3) {
                fprintf(stderr, "MISMATCH leaf_hash(index=%u, value_len=%d)\n", index, value_len);
            }
            failed++;
        } else {
            passed++;
        }
        free(value_buf);
        free(value_hex);
        free(hash_hex);
    }
    printf("%-12s  %5d passed  %5d failed\n", "leaf_hash", passed, failed);
    return failed;
}

/* ---------- null_hash ---------- */
static int run_null_hash(json_scanner_t *s) {
    if (!js_seek_op_array(s, "null_hash")) {
        fprintf(stderr, "FAIL: null_hash array not found\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (advance_array_elem(s)) {
        s->pos++;
        uint32_t index = 0;
        char *hash_hex = NULL;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "index")) { js_match(s, ':'); js_read_u32(s, &index); }
            else if (js_match_key(s, "hash_hex")) { js_match(s, ':'); hash_hex = js_read_string(s); }
            else { fprintf(stderr, "null_hash: bad key\n"); return -1; }
        }
        if (!hash_hex) { fprintf(stderr, "null_hash: missing field\n"); return -1; }

        uint8_t expected[MERKLE_SMT_HASH_SIZE], actual[MERKLE_SMT_HASH_SIZE];
        if (!hex_decode_fixed(hash_hex, expected, MERKLE_SMT_HASH_SIZE)) {
            fprintf(stderr, "null_hash: bad expected hex\n"); return -1;
        }
        merkle_smt_hash_null(index, actual);

        if (memcmp(expected, actual, MERKLE_SMT_HASH_SIZE) != 0) {
            if (failed < 3) fprintf(stderr, "MISMATCH null_hash(index=%u)\n", index);
            failed++;
        } else {
            passed++;
        }
        free(hash_hex);
    }
    printf("%-12s  %5d passed  %5d failed\n", "null_hash", passed, failed);
    return failed;
}

/* ---------- node_hash ---------- */
static int run_node_hash(json_scanner_t *s) {
    if (!js_seek_op_array(s, "node_hash")) {
        fprintf(stderr, "FAIL: node_hash array not found\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (advance_array_elem(s)) {
        s->pos++;
        char *left_hex = NULL, *right_hex = NULL, *hash_hex = NULL;
        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "left_hex"))  { js_match(s, ':'); left_hex  = js_read_string(s); }
            else if (js_match_key(s, "right_hex")) { js_match(s, ':'); right_hex = js_read_string(s); }
            else if (js_match_key(s, "hash_hex"))  { js_match(s, ':'); hash_hex  = js_read_string(s); }
            else { fprintf(stderr, "node_hash: bad key\n"); return -1; }
        }
        if (!left_hex || !right_hex || !hash_hex) {
            fprintf(stderr, "node_hash: missing field\n"); return -1;
        }

        uint8_t left[MERKLE_SMT_HASH_SIZE], right[MERKLE_SMT_HASH_SIZE];
        uint8_t expected[MERKLE_SMT_HASH_SIZE], actual[MERKLE_SMT_HASH_SIZE];
        if (!hex_decode_fixed(left_hex,  left,     MERKLE_SMT_HASH_SIZE) ||
            !hex_decode_fixed(right_hex, right,    MERKLE_SMT_HASH_SIZE) ||
            !hex_decode_fixed(hash_hex,  expected, MERKLE_SMT_HASH_SIZE)) {
            fprintf(stderr, "node_hash: hex decode fail\n"); return -1;
        }
        merkle_smt_hash_node(left, right, actual);

        if (memcmp(expected, actual, MERKLE_SMT_HASH_SIZE) != 0) {
            if (failed < 3) fprintf(stderr, "MISMATCH node_hash\n");
            failed++;
        } else {
            passed++;
        }
        free(left_hex); free(right_hex); free(hash_hex);
    }
    printf("%-12s  %5d passed  %5d failed\n", "node_hash", passed, failed);
    return failed;
}

/* ---------- Helper: read string array. ---------- */
static char **read_string_array(json_scanner_t *s, size_t *out_count) {
    if (!js_match(s, '[')) return NULL;
    size_t cap = 8, count = 0;
    char **arr = (char **)malloc(cap * sizeof(char *));
    if (!arr) return NULL;
    while (1) {
        js_skip_ws(s);
        if (s->pos >= s->len) { /* fail */
            for (size_t i = 0; i < count; i++) free(arr[i]);
            free(arr); return NULL;
        }
        if (s->src[s->pos] == ']') { s->pos++; break; }
        if (s->src[s->pos] == ',') { s->pos++; continue; }
        char *str = js_read_string(s);
        if (!str) {
            for (size_t i = 0; i < count; i++) free(arr[i]);
            free(arr); return NULL;
        }
        if (count + 1 > cap) {
            cap *= 2;
            char **na = (char **)realloc(arr, cap * sizeof(char *));
            if (!na) {
                for (size_t i = 0; i < count; i++) free(arr[i]);
                free(arr); free(str); return NULL;
            }
            arr = na;
        }
        arr[count++] = str;
    }
    *out_count = count;
    return arr;
}

/* ---------- root ---------- */
static int run_root(json_scanner_t *s) {
    if (!js_seek_op_array(s, "root")) {
        fprintf(stderr, "FAIL: root array not found\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (advance_array_elem(s)) {
        s->pos++;
        uint32_t depth = 0, leaf_count_json = 0;
        char **leaves_hex = NULL;
        size_t leaves_n = 0;
        char *root_hex = NULL;

        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "depth")) { js_match(s, ':'); js_read_u32(s, &depth); }
            else if (js_match_key(s, "leaf_count")) { js_match(s, ':'); js_read_u32(s, &leaf_count_json); }
            else if (js_match_key(s, "leaves_hex")) {
                js_match(s, ':');
                leaves_hex = read_string_array(s, &leaves_n);
            }
            else if (js_match_key(s, "root_hex")) { js_match(s, ':'); root_hex = js_read_string(s); }
            else { fprintf(stderr, "root: bad key\n"); return -1; }
        }
        if (!leaves_hex || !root_hex) { fprintf(stderr, "root: missing field\n"); return -1; }

        /* Pack leaves into a flat buffer. */
        uint8_t *leaves_buf = (uint8_t *)malloc(leaves_n * MERKLE_SMT_HASH_SIZE + 1);
        if (!leaves_buf) { fprintf(stderr, "root: oom\n"); return -1; }
        for (size_t i = 0; i < leaves_n; i++) {
            if (!hex_decode_fixed(leaves_hex[i], leaves_buf + i * MERKLE_SMT_HASH_SIZE,
                                  MERKLE_SMT_HASH_SIZE)) {
                fprintf(stderr, "root: bad leaf hex at %zu\n", i); return -1;
            }
        }
        uint8_t expected[MERKLE_SMT_HASH_SIZE], actual[MERKLE_SMT_HASH_SIZE];
        if (!hex_decode_fixed(root_hex, expected, MERKLE_SMT_HASH_SIZE)) {
            fprintf(stderr, "root: bad expected hex\n"); return -1;
        }
        int rc = merkle_smt_compute_root(leaves_buf, leaves_n, depth, actual);
        if (rc != 0) {
            fprintf(stderr, "root: compute_root error rc=%d\n", rc);
            failed++;
        } else if (memcmp(expected, actual, MERKLE_SMT_HASH_SIZE) != 0) {
            if (failed < 3) fprintf(stderr, "MISMATCH root(depth=%u, leaves=%zu)\n", depth, leaves_n);
            failed++;
        } else {
            passed++;
        }
        free(leaves_buf);
        for (size_t i = 0; i < leaves_n; i++) free(leaves_hex[i]);
        free(leaves_hex);
        free(root_hex);
    }
    printf("%-12s  %5d passed  %5d failed\n", "root", passed, failed);
    return failed;
}

/* ---------- proof ---------- */
static int run_proof(json_scanner_t *s) {
    if (!js_seek_op_array(s, "proof")) {
        fprintf(stderr, "FAIL: proof array not found\n");
        return -1;
    }
    int passed = 0, failed = 0;
    while (advance_array_elem(s)) {
        s->pos++;
        uint32_t depth = 0, leaf_count_json = 0, target_index = 0;
        char **leaves_hex = NULL;  size_t leaves_n = 0;
        char **proof_hex = NULL;   size_t proof_n = 0;
        char *target_leaf_hex = NULL;
        char *expected_root_hex = NULL;

        while (1) {
            js_skip_ws(s);
            if (s->src[s->pos] == '}') { s->pos++; break; }
            if (s->src[s->pos] == ',') { s->pos++; continue; }
            if (js_match_key(s, "depth")) { js_match(s, ':'); js_read_u32(s, &depth); }
            else if (js_match_key(s, "leaf_count")) { js_match(s, ':'); js_read_u32(s, &leaf_count_json); }
            else if (js_match_key(s, "target_index")) { js_match(s, ':'); js_read_u32(s, &target_index); }
            else if (js_match_key(s, "leaves_hex")) { js_match(s, ':'); leaves_hex = read_string_array(s, &leaves_n); }
            else if (js_match_key(s, "target_leaf_hex")) { js_match(s, ':'); target_leaf_hex = js_read_string(s); }
            else if (js_match_key(s, "proof_hex")) { js_match(s, ':'); proof_hex = read_string_array(s, &proof_n); }
            else if (js_match_key(s, "expected_root_hex")) { js_match(s, ':'); expected_root_hex = js_read_string(s); }
            else { fprintf(stderr, "proof: bad key\n"); return -1; }
        }
        if (!leaves_hex || !proof_hex || !target_leaf_hex || !expected_root_hex) {
            fprintf(stderr, "proof: missing field\n"); return -1;
        }

        /* Pack leaves. */
        uint8_t *leaves_buf = (uint8_t *)malloc(leaves_n * MERKLE_SMT_HASH_SIZE + 1);
        if (!leaves_buf) { fprintf(stderr, "proof: oom\n"); return -1; }
        for (size_t i = 0; i < leaves_n; i++) {
            if (!hex_decode_fixed(leaves_hex[i], leaves_buf + i * MERKLE_SMT_HASH_SIZE,
                                  MERKLE_SMT_HASH_SIZE)) {
                fprintf(stderr, "proof: bad leaf hex\n"); return -1;
            }
        }

        /* Build proof via our impl. */
        merkle_smt_proof_t our_proof = {0};
        int rc = merkle_smt_build_proof(leaves_buf, leaves_n, depth, target_index, &our_proof);

        /* Check 1: target_leaf_hex matches our_proof.leaf_value (verifies leaves order). */
        uint8_t expected_leaf[MERKLE_SMT_HASH_SIZE];
        if (!hex_decode_fixed(target_leaf_hex, expected_leaf, MERKLE_SMT_HASH_SIZE)) {
            fprintf(stderr, "proof: bad target leaf hex\n"); return -1;
        }

        /* Check 2: proof path matches Plonky3-side proof_hex array. */
        if (rc != 0) {
            if (failed < 3) fprintf(stderr, "proof: build_proof rc=%d\n", rc);
            failed++;
        } else if (proof_n != depth) {
            fprintf(stderr, "proof: depth mismatch json=%zu local=%u\n", proof_n, depth);
            failed++;
        } else if (memcmp(our_proof.leaf_value, expected_leaf, MERKLE_SMT_HASH_SIZE) != 0) {
            if (failed < 3) fprintf(stderr, "proof: leaf value mismatch idx=%u\n", target_index);
            failed++;
        } else {
            bool path_ok = true;
            for (size_t i = 0; i < depth; i++) {
                uint8_t expected_sibling[MERKLE_SMT_HASH_SIZE];
                if (!hex_decode_fixed(proof_hex[i], expected_sibling, MERKLE_SMT_HASH_SIZE)) {
                    fprintf(stderr, "proof: bad sibling hex level=%zu\n", i); return -1;
                }
                if (memcmp(our_proof.path[i], expected_sibling, MERKLE_SMT_HASH_SIZE) != 0) {
                    if (failed < 3) {
                        fprintf(stderr, "proof: path mismatch idx=%u level=%zu\n",
                                target_index, i);
                    }
                    path_ok = false;
                    break;
                }
            }

            /* Check 3: verify against expected root using our verify function. */
            uint8_t expected_root[MERKLE_SMT_HASH_SIZE];
            if (!hex_decode_fixed(expected_root_hex, expected_root, MERKLE_SMT_HASH_SIZE)) {
                fprintf(stderr, "proof: bad expected root hex\n"); return -1;
            }
            bool verify_ok = merkle_smt_verify_proof(&our_proof, expected_root);

            if (path_ok && verify_ok) {
                passed++;
            } else {
                if (failed < 3) {
                    fprintf(stderr, "proof: idx=%u path_ok=%d verify_ok=%d\n",
                            target_index, (int)path_ok, (int)verify_ok);
                }
                failed++;
            }
        }

        free(leaves_buf);
        for (size_t i = 0; i < leaves_n; i++) free(leaves_hex[i]);
        free(leaves_hex);
        for (size_t i = 0; i < proof_n; i++) free(proof_hex[i]);
        free(proof_hex);
        free(target_leaf_hex);
        free(expected_root_hex);
    }
    printf("%-12s  %5d passed  %5d failed\n", "proof", passed, failed);
    return failed;
}

/* ============================================================================
 * main
 * ========================================================================== */

int main(int argc, char **argv) {
    const char *path = "tools/vectors/merkle.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};

    printf("op            passed         failed\n");
    printf("------------  -------------  -------------\n");

    int total_failed = 0;
    total_failed += run_leaf_hash(&s);
    total_failed += run_null_hash(&s);
    total_failed += run_node_hash(&s);
    total_failed += run_root(&s);
    total_failed += run_proof(&s);

    free(src);

    printf("\n");
    if (total_failed == 0) {
        printf("SPRINT 1.4 GATE: GREEN — merkle_smt byte-matches Plonky3 oracle\n");
        return 0;
    } else {
        printf("SPRINT 1.4 GATE: RED — %d total mismatches\n", total_failed);
        return 1;
    }
}
