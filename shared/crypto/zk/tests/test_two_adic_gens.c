/**
 * @file test_two_adic_gens.c
 * @brief Validate gold_fp_two_adic_generator against Plonky3 TWO_ADIC_GENERATORS.
 *
 * Loads tools/vectors/two_adic_gens.json, asserts every bits=[0..32] returns
 * the exact same u64 as Plonky3's pinned table.
 *
 * Build (via Makefile):
 *   make build/test_two_adic_gens
 *   ./build/test_two_adic_gens tools/vectors/two_adic_gens.json
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

/* ---------- minimal JSON tokenizer ---------- */
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
    const char *path = "tools/vectors/two_adic_gens.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n", path, len);

    json_scanner_t s = {.src = src, .pos = 0, .len = len};
    /* Find "generators": [ */
    const char *needle = "\"generators\"";
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

    int passed = 0, failed = 0;
    while (1) {
        js_skip_ws(&s);
        if (s.pos >= s.len || s.src[s.pos] == ']') { s.pos++; break; }
        if (s.src[s.pos] == ',') { s.pos++; continue; }
        if (s.src[s.pos] != '{') { fprintf(stderr, "expected '{'\n"); return 2; }
        s.pos++;

        uint32_t bits = 0xFFFFFFFF;
        char *gen_str = NULL;
        while (1) {
            js_skip_ws(&s);
            if (s.src[s.pos] == '}') { s.pos++; break; }
            if (s.src[s.pos] == ',') { s.pos++; continue; }
            if (js_match_key(&s, "bits")) { js_match(&s, ':'); js_read_u32(&s, &bits); }
            else if (js_match_key(&s, "generator")) { js_match(&s, ':'); gen_str = js_read_string(&s); }
            else { fprintf(stderr, "bad key\n"); return 2; }
        }
        if (bits == 0xFFFFFFFF || !gen_str) { fprintf(stderr, "missing field\n"); return 2; }

        uint64_t expected = strtoull(gen_str, NULL, 10);
        uint64_t actual   = gold_fp_to_u64(gold_fp_two_adic_generator(bits));
        if (expected != actual) {
            fprintf(stderr, "MISMATCH bits=%u: expected %" PRIu64 ", got %" PRIu64 "\n",
                    bits, expected, actual);
            failed++;
        } else {
            passed++;
        }
        free(gen_str);
    }

    free(src);
    printf("two_adic_gens  %d passed  %d failed\n", passed, failed);
    if (failed == 0) {
        printf("SUB-SPRINT 2.1 (two-adic gen) GATE: GREEN — all 33 generators match Plonky3\n");
        return 0;
    } else {
        printf("SUB-SPRINT 2.1 (two-adic gen) GATE: RED — %d mismatches\n", failed);
        return 1;
    }
}
