/**
 * @file test_fri_verifier_mmcs_calls.c
 * @brief F5 Part A oracle test — FRI MMCS verify_batch call replay.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Loads tools/vectors/fri_verifier_mmcs_calls.json (8 verify_batch calls Plonky3
 * issued while verifying the V6 proof) and replays each through DNAC's stateless
 * single-matrix merkle verify (dnac_fri_test_mmcs_verify_single -> dnac_merkle_verify).
 * Each call must ACCEPT (DNAC_MERKLE_OK), proving DNAC's independently-M3-grounded
 * SHA3-512 merkle agrees with Plonky3's MMCS on every captured opening.
 *
 * Load-bearing asserts (guard against false-green on this nested input):
 *   - header counts: total==8, input_mmcs==2, commit_phase==6; parsed exactly 8.
 *   - depth == log2(dimensions.height)   (makes "height" real, not decorative)
 *   - dnac_api_target == "dnac_merkle_verify" for all 8
 *   - width metadata: input_mmcs -> 0, params.mmcs -> arity (2)
 *
 * Accept-only: this proves the FRI->merkle call mapping on VALID openings; merkle
 * REJECTION soundness is covered independently by merkle_mmcs.json's reject cases.
 * V6 exercises only single-matrix MMCS (nov==1); the Phase-2A batch path is
 * covered by test_merkle_mmcs_batch, not here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define DNAC_FRI_TESTING 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_verifier.h"   /* pulls merkle_smt.h */

/* ===== Minimal JSON scanner (same idiom as tests/test_merkle_mmcs.c) ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;

static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}
static bool js_peek(js_t *s, char c) { js_skip_ws(s); return s->pos < s->len && s->src[s->pos] == c; }
static bool js_match(js_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}
static char *js_read_string(js_t *s) {
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
static bool js_read_u64(js_t *s, uint64_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}
static bool js_skip_value(js_t *s);
static bool js_skip_object(js_t *s) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s);
        if (!k) return false;
        free(k);
        if (!js_match(s, ':')) return false;
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_array(js_t *s) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (!js_skip_value(s)) return false;
    }
}
static bool js_skip_value(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '{') return js_skip_object(s);
    if (c == '[') return js_skip_array(s);
    if (c == '"') { char *t = js_read_string(s); if (!t) return false; free(t); return true; }
    if (c == 't') { s->pos += 4; return true; }
    if (c == 'f') { s->pos += 5; return true; }
    if (c == 'n') { s->pos += 4; return true; }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') s->pos++;
        else break;
    }
    return true;
}
static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t hex_decode(const char *hex, uint8_t *buf, size_t cap) {
    size_t hl = strlen(hex);
    if (hl % 2) return (size_t)-1;
    size_t n = hl / 2;
    if (n > cap) return (size_t)-1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(hex[2*i]), lo = hexnib(hex[2*i+1]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}
static int ilog2_u64(uint64_t h) {
    int l = 0;
    while (h > 1) { h >>= 1; l++; }
    return l;
}

/* ===== Per-call parsed data ===== */
#define MAX_SIB 16
typedef struct {
    char     call_site[40];
    char     api_target[40];
    char     expected_result[16];
    uint8_t  root[DNAC_MERKLE_DIGEST_BYTES];
    uint8_t  leaf[64];        size_t leaf_len;
    dnac_merkle_digest_t sib[MAX_SIB]; size_t nsib;
    uint64_t index;
    uint64_t height, width;
} call_t;

static bool parse_opened_values(js_t *s, call_t *c) {
    /* opened_values_hex = [ [ "hex", ... ]  ... ]  ; use first matrix only. */
    if (!js_match(s, '[')) return false;
    int mi = 0;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (mi == 0) {
            if (!js_match(s, '[')) return false;
            while (1) {
                if (js_match(s, ']')) break;
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *h = js_read_string(s); if (!h) return false;
                uint8_t tmp[32]; size_t n = hex_decode(h, tmp, sizeof tmp); free(h);
                if (n == (size_t)-1 || c->leaf_len + n > sizeof c->leaf) return false;
                memcpy(c->leaf + c->leaf_len, tmp, n); c->leaf_len += n;
            }
        } else {
            if (!js_skip_value(s)) return false; /* extra matrices (none for V6) */
        }
        mi++;
    }
}

static bool parse_siblings(js_t *s, call_t *c) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *h = js_read_string(s); if (!h) return false;
        if (c->nsib >= MAX_SIB) { free(h); return false; }
        size_t n = hex_decode(h, c->sib[c->nsib].bytes, DNAC_MERKLE_DIGEST_BYTES); free(h);
        if (n != DNAC_MERKLE_DIGEST_BYTES) return false;
        c->nsib++;
    }
}

static bool parse_dimensions(js_t *s, call_t *c) {
    if (!js_match(s, '[')) return false;
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        uint64_t v = 0; js_read_u64(s, &v);
        if (strcmp(k, "height") == 0) c->height = v;
        else if (strcmp(k, "width") == 0) c->width = v;
        free(k);
    }
    js_match(s, ']');
    return true;
}

static bool parse_call(js_t *s, call_t *c) {
    memset(c, 0, sizeof *c);
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        if (strcmp(k, "call_site") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->call_site, v, sizeof(c->call_site)-1); free(v);} }
        else if (strcmp(k, "dnac_api_target") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->api_target, v, sizeof(c->api_target)-1); free(v);} }
        else if (strcmp(k, "expected_result") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->expected_result, v, sizeof(c->expected_result)-1); free(v);} }
        else if (strcmp(k, "commit_hex") == 0) { char *v = js_read_string(s); if (v){ hex_decode(v, c->root, DNAC_MERKLE_DIGEST_BYTES); free(v);} }
        else if (strcmp(k, "index") == 0) { js_read_u64(s, &c->index); }
        else if (strcmp(k, "dimensions") == 0) { if (!parse_dimensions(s, c)) { free(k); return false; } }
        else if (strcmp(k, "opened_values_hex") == 0) { if (!parse_opened_values(s, c)) { free(k); return false; } }
        else if (strcmp(k, "opening_proof_siblings_hex") == 0) { if (!parse_siblings(s, c)) { free(k); return false; } }
        else js_skip_value(s);
        free(k);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <fri_verifier_mmcs_calls.json>\n", argv[0]); return 2; }
    printf("============================================================\n");
    printf("F5 Part A — FRI MMCS verify_batch call replay (Plonky3 82cfad73)\n");
    printf("            verifier.rs:446-455 (commit) + 589-597 (input)\n");
    printf("============================================================\n");

    size_t blen = 0; char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    uint64_t hdr_total = 0, hdr_input = 0, hdr_commit = 0; int saw_hdr = 0;
    int parsed = 0, ok = 0, fail = 0;

    if (!js_match(&s, '{')) { fprintf(stderr, "bad json root\n"); return 2; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); if (!k) return 2;
        if (!js_match(&s, ':')) return 2;
        if (strcmp(k, "call_count_total") == 0) { js_read_u64(&s, &hdr_total); saw_hdr |= 1; }
        else if (strcmp(k, "call_count_input_mmcs") == 0) { js_read_u64(&s, &hdr_input); saw_hdr |= 2; }
        else if (strcmp(k, "call_count_commit_phase_mmcs") == 0) { js_read_u64(&s, &hdr_commit); saw_hdr |= 4; }
        else if (strcmp(k, "calls") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                call_t c;
                if (!parse_call(&s, &c)) { fprintf(stderr, "bad call\n"); return 2; }
                parsed++;

                bool is_input  = (strstr(c.call_site, "input_mmcs") != NULL);
                int  exp_depth = ilog2_u64(c.height);
                uint64_t exp_width = is_input ? 0u : 2u; /* arity = 1<<log_arity = 2 (V6) */

                /* load-bearing structural asserts */
                if ((int)c.nsib != exp_depth) { fail++; printf("  [FAIL] %-26s depth=%zu != log2(height=%llu)=%d\n", c.call_site, c.nsib, (unsigned long long)c.height, exp_depth); continue; }
                if (strcmp(c.api_target, "dnac_merkle_verify") != 0) { fail++; printf("  [FAIL] %-26s api_target=%s\n", c.call_site, c.api_target); continue; }
                if (c.width != exp_width) { fail++; printf("  [FAIL] %-26s width=%llu != expected %llu\n", c.call_site, (unsigned long long)c.width, (unsigned long long)exp_width); continue; }
                if (strcmp(c.expected_result, "OK") != 0) { fail++; printf("  [FAIL] %-26s expected_result=%s (only OK supported in F5)\n", c.call_site, c.expected_result); continue; }

                dnac_merkle_digest_t root; memcpy(root.bytes, c.root, DNAC_MERKLE_DIGEST_BYTES);
                dnac_merkle_status_t st = dnac_fri_test_mmcs_verify_single(
                    &root, c.leaf, c.leaf_len, c.index, (uint32_t)c.nsib, c.sib);

                if (st == DNAC_MERKLE_OK) {
                    ok++;
                    printf("  [OK ] %-26s h=%2llu w=%llu idx=%2llu leaf=%2zuB depth=%zu\n",
                           c.call_site, (unsigned long long)c.height, (unsigned long long)c.width,
                           (unsigned long long)c.index, c.leaf_len, c.nsib);
                } else {
                    fail++;
                    printf("  [FAIL] %-26s dnac_merkle_verify -> %d (want DNAC_MERKLE_OK)\n", c.call_site, (int)st);
                }
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);

    printf("------------------------------------------------------------\n");
    printf("  header: total=%llu input=%llu commit=%llu | parsed=%d | OK=%d FAIL=%d\n",
           (unsigned long long)hdr_total, (unsigned long long)hdr_input,
           (unsigned long long)hdr_commit, parsed, ok, fail);

    int green = (saw_hdr == 7) && (hdr_total == 8) && (hdr_input == 2) && (hdr_commit == 6)
             && (parsed == 8) && (ok == 8) && (fail == 0);
    if (green) {
        printf("F5 MMCS-CALLS GATE: GREEN — 8/8 captured verify_batch calls accepted\n");
        printf("                    by DNAC merkle (2 input + 6 commit-phase)\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F5 MMCS-CALLS GATE: RED\n");
    return 1;
}
