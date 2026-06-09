/**
 * @file test_sponge_sha3_512.c
 * @brief Triple cross-validation of sponge_sha3_512 (Sprint 3.3b.7 rework).
 *
 * Loads tools/vectors/sha3_512_sponge.json and runs three checks per case:
 *
 *   (A) C sponge_sha3_512_oneshot output  ==  Plonky3 sha3 crate (oracle JSON)
 *   (B) C sponge_sha3_512_oneshot output  ==  keccak_ref_sha3_512 (existing
 *       OpenSSL-validated FIPS-202 SHA3-512)
 *   (C) Incremental absorb (chunked) == oneshot output
 *
 * Triple agreement means C, Plonky3, OpenSSL, AND the chunked-absorb path
 * all produce identical bytes for the same input.
 *
 * Build (Makefile):
 *   make build/test_sponge_sha3_512
 *
 * Run:
 *   ./build/test_sponge_sha3_512 tools/vectors/sha3_512_sponge.json
 *
 * Exit codes:
 *   0  all categories PASS
 *   1  at least one mismatch
 *   2  load / parse error
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

#include "../keccak_ref.h"
#include "../sponge_sha3_512.h"

#define TEST_MAX_INPUT_BYTES 4096

/* ============================================================================
 * Tiny JSON tokenizer (same shape as other oracle tests)
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

static bool js_read_u32_number(json_scanner_t *s, uint32_t *out) {
    js_skip_ws(s);
    char *endp = NULL;
    unsigned long v = strtoul(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint32_t)v;
    return true;
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
        char open_c = c, close_c = (c == '{') ? '}' : ']';
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
            cc == ' ' || cc == '\n' || cc == '\t' || cc == '\r') break;
        s->pos++;
    }
    return true;
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

/* Decode lowercase-hex string into bytes; len = strlen(hex)/2. */
static bool hex_decode(const char *hex, uint8_t *out, size_t *out_len, size_t max_bytes) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return false;
    size_t blen = hlen / 2;
    if (blen > max_bytes) return false;
    for (size_t i = 0; i < blen; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return false;
        out[i] = (uint8_t)b;
    }
    *out_len = blen;
    return true;
}

/* ============================================================================
 * Per-case
 * ========================================================================== */

typedef struct {
    char *name;
    uint32_t input_len;
    uint8_t input[TEST_MAX_INPUT_BYTES];
    size_t input_decoded_len;
    uint8_t expected[64];
} sha3_case_t;

static void free_case(sha3_case_t *c) {
    if (c->name) { free(c->name); c->name = NULL; }
}

static bool parse_case(json_scanner_t *s, sha3_case_t *out) {
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
        } else if (js_match_key(s, "input_len")) {
            if (!js_match(s, ':')) return false;
            if (!js_read_u32_number(s, &out->input_len)) return false;
        } else if (js_match_key(s, "input_hex")) {
            if (!js_match(s, ':')) return false;
            char *hex = js_read_string(s);
            if (!hex) return false;
            bool ok = hex_decode(hex, out->input,
                                 &out->input_decoded_len,
                                 TEST_MAX_INPUT_BYTES);
            free(hex);
            if (!ok) return false;
        } else if (js_match_key(s, "output_hex")) {
            if (!js_match(s, ':')) return false;
            char *hex = js_read_string(s);
            if (!hex) return false;
            size_t outlen = 0;
            bool ok = hex_decode(hex, out->expected, &outlen, 64);
            free(hex);
            if (!ok || outlen != 64) return false;
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
    const char *path = "tools/vectors/sha3_512_sponge.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) { fprintf(stderr, "FAIL: cannot load %s\n", path); return 2; }
    printf("loaded %s (%zu bytes)\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};
    if (!js_seek_array(&s, "cases")) {
        fprintf(stderr, "FAIL: could not locate 'cases' array\n");
        free(src); return 2;
    }

    int total = 0;
    int A_pass = 0, A_fail = 0;
    int B_pass = 0, B_fail = 0;
    int C_pass = 0, C_fail = 0;

    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len) break;
        if (s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }

        sha3_case_t c;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "FAIL: parse case at pos %zu\n", s.pos);
            free(src);
            return 2;
        }
        total++;

        if (c.input_decoded_len != (size_t)c.input_len) {
            fprintf(stderr,
                    "FAIL: case '%s' input_decoded_len=%zu != input_len=%u\n",
                    c.name ? c.name : "<unnamed>",
                    c.input_decoded_len, c.input_len);
            free_case(&c);
            continue;
        }

        /* (A) Plonky3 oracle byte-match. */
        {
            uint8_t ours[64];
            sha3_512_oneshot(c.input, c.input_decoded_len, ours);
            if (memcmp(ours, c.expected, 64) == 0) {
                A_pass++;
            } else {
                A_fail++;
                if (A_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (A: Plonky3 oracle) case '%s' len=%u:\n",
                            c.name ? c.name : "<unnamed>", c.input_len);
                    fprintf(stderr, "  oracle: ");
                    for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", c.expected[i]);
                    fprintf(stderr, "...\n  ours:   ");
                    for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", ours[i]);
                    fprintf(stderr, "...\n");
                }
            }
        }

        /* (B) keccak_ref (OpenSSL) byte-match. */
        {
            uint8_t ref[KECCAK_SHA3_512_OUT];
            keccak_ref_sha3_512(c.input, c.input_decoded_len, ref);
            uint8_t ours[64];
            sha3_512_oneshot(c.input, c.input_decoded_len, ours);
            if (memcmp(ours, ref, 64) == 0) {
                B_pass++;
            } else {
                B_fail++;
                if (B_fail <= 3) {
                    fprintf(stderr,
                            "MISMATCH (B: keccak_ref) case '%s' len=%u\n",
                            c.name ? c.name : "<unnamed>", c.input_len);
                }
            }
        }

        /* (C) Incremental absorb == oneshot. */
        {
            uint8_t oneshot[64];
            sha3_512_oneshot(c.input, c.input_decoded_len, oneshot);

            const size_t chunk_sizes[] = {1, 7, 17, 71, 72, 73};
            bool all_match = true;
            for (size_t ci = 0;
                 ci < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]);
                 ci++) {
                size_t chunk = chunk_sizes[ci];
                sha3_512_ctx_t ctx;
                sha3_512_init(&ctx);
                size_t off = 0;
                while (off < c.input_decoded_len) {
                    size_t step = (c.input_decoded_len - off < chunk)
                                      ? (c.input_decoded_len - off) : chunk;
                    sha3_512_absorb(&ctx, c.input + off, step);
                    off += step;
                }
                uint8_t inc[64];
                sha3_512_squeeze(&ctx, inc);
                if (memcmp(inc, oneshot, 64) != 0) {
                    all_match = false;
                    if (C_fail < 3) {
                        fprintf(stderr,
                                "MISMATCH (C: incremental chunk=%zu) case '%s' len=%u\n",
                                chunk, c.name ? c.name : "<unnamed>",
                                c.input_len);
                    }
                    break;
                }
            }
            if (all_match) C_pass++;
            else C_fail++;
        }

        free_case(&c);
    }

    free(src);

    int total_fail = A_fail + B_fail + C_fail;

    printf("\n");
    printf("SHA3-512 sponge triple cross-validation summary:\n");
    printf("  Total cases:                                  %d\n", total);
    printf("  (A) Plonky3 sha3 crate byte-match:            %d PASS / %d FAIL\n", A_pass, A_fail);
    printf("  (B) keccak_ref (OpenSSL FIPS-202) byte-match: %d PASS / %d FAIL\n", B_pass, B_fail);
    printf("  (C) Incremental absorb == oneshot:            %d PASS / %d FAIL\n", C_pass, C_fail);
    printf("  Circular self-tests:                          0\n");
    printf("\n");

    if (total_fail == 0) {
        printf("SPONGE_SHA3_512 GATE: GREEN — %d cases, triple agreement (Plonky3 = keccak_ref = ours), 0 circular\n",
               total);
        return 0;
    }
    printf("SPONGE_SHA3_512 GATE: RED — %d total mismatches\n", total_fail);
    return 1;
}
