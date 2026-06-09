/**
 * @file test_stark_proof_codec.c
 * @brief P5 replay — additive DZKS STARK/PCS wire wrapper roundtrip + negatives.
 *
 * Consumes tools/vectors/stark_proof_wire.json and asserts:
 *   POSITIVE (valid case):
 *     - dnac_stark_proof_decode == OK
 *     - decoded degree_bits / public_values / inner DZKF match the vector
 *     - dnac_stark_proof_encode(decoded) reproduces the wire byte-for-byte
 *     - the extracted inner DZKF decodes via dnac_fri_proof_decode == OK
 *       (existing DZKF wire unchanged + compatible)
 *   NEGATIVE (8 malformed wires):
 *     - dnac_stark_proof_decode returns the expected status, out == NULL.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_proof_codec.h"   /* dnac_fri_proof_decode (inner DZKF compat) */
#include "stark_proof_codec.h"

/* ===== Minimal JSON scanner (same idiom as tests/test_fri_verifier_valid.c) ===== */
typedef struct { const char *src; size_t pos; size_t len; } js_t;
static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++; else return;
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
    size_t slen = s->pos - start; s->pos++;
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, s->src + start, slen); out[slen] = '\0';
    return out;
}
static bool js_read_u64(js_t *s, uint64_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src); *out = (uint64_t)v;
    return true;
}
static bool js_skip_value(js_t *s);
static bool js_skip_object(js_t *s) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false; free(k);
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
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp); fclose(fp);
    buf[got] = '\0'; *out_len = got; return buf;
}
static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint8_t *hex_to_buf(const char *hex, size_t *out_len) {
    size_t hl = strlen(hex);
    if (hl % 2) return NULL;
    size_t n = hl / 2;
    uint8_t *b = (uint8_t *)malloc(n ? n : 1);
    if (!b) return NULL;
    for (size_t i = 0; i < n; i++) {
        int hi = hexnib(hex[2 * i]), lo = hexnib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(b); return NULL; }
        b[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n; return b;
}

/* ===== fixture ===== */
#define MAXPUB 64
#define MAXNEG 16
typedef struct {
    uint64_t degree_bits;
    uint64_t pub[MAXPUB];
    size_t   num_pub;
    uint8_t *inner; size_t inner_len;
    uint8_t *wire;  size_t wire_len;
} valid_t;
typedef struct {
    char     name[64];
    int      expect_status;
    uint8_t *wire; size_t wire_len;
} neg_t;

static void parse_valid(js_t *s, valid_t *v) {
    js_match(s, '{');
    while (!js_match(s, '}')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); js_match(s, ':');
        if (strcmp(k, "degree_bits") == 0) { js_read_u64(s, &v->degree_bits); }
        else if (strcmp(k, "public_values") == 0) {
            js_match(s, '[');
            while (!js_match(s, ']')) {
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *sv = js_read_string(s);
                if (sv && v->num_pub < MAXPUB) v->pub[v->num_pub++] = strtoull(sv, NULL, 10);
                free(sv);
            }
        } else if (strcmp(k, "inner_dzkf_hex") == 0) {
            char *h = js_read_string(s); v->inner = hex_to_buf(h, &v->inner_len); free(h);
        } else if (strcmp(k, "wire_hex") == 0) {
            char *h = js_read_string(s); v->wire = hex_to_buf(h, &v->wire_len); free(h);
        } else {
            js_skip_value(s);
        }
        free(k);
    }
}
static size_t parse_negatives(js_t *s, neg_t *out, size_t cap) {
    size_t n = 0;
    js_match(s, '[');
    while (!js_match(s, ']')) {
        if (js_peek(s, ',')) { s->pos++; continue; }
        neg_t c; memset(&c, 0, sizeof c);
        js_match(s, '{');
        while (!js_match(s, '}')) {
            if (js_peek(s, ',')) { s->pos++; continue; }
            char *k = js_read_string(s); js_match(s, ':');
            if (strcmp(k, "name") == 0) { char *nv = js_read_string(s); if (nv) { strncpy(c.name, nv, sizeof c.name - 1); free(nv); } }
            else if (strcmp(k, "expect_status") == 0) { uint64_t u = 0; js_read_u64(s, &u); c.expect_status = (int)u; }
            else if (strcmp(k, "wire_hex") == 0) { char *h = js_read_string(s); c.wire = hex_to_buf(h, &c.wire_len); free(h); }
            else js_skip_value(s);
            free(k);
        }
        if (n < cap) out[n++] = c; else free(c.wire);
    }
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <stark_proof_wire.json>\n", argv[0]); return 2; }
    size_t srclen = 0;
    char *src = slurp(argv[1], &srclen);
    if (!src) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }

    valid_t v; memset(&v, 0, sizeof v);
    neg_t negs[MAXNEG]; size_t nneg = 0;

    js_t s = { src, 0, srclen };
    js_match(&s, '{');
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); if (!k) break; js_match(&s, ':');
        if (strcmp(k, "valid") == 0) parse_valid(&s, &v);
        else if (strcmp(k, "negative") == 0) nneg = parse_negatives(&s, negs, MAXNEG);
        else js_skip_value(&s);
        free(k);
    }
    free(src);

    if (!v.wire || !v.inner) { fprintf(stderr, "vector missing valid wire/inner\n"); return 2; }

    int fails = 0;

    /* ---- POSITIVE: decode -> field checks -> re-encode == wire -> inner DZKF OK ---- */
    dnac_stark_wire_decoded_t *dec = NULL;
    dnac_stark_wire_status_t ds = dnac_stark_proof_decode(v.wire, v.wire_len, &dec);
    if (ds != DNAC_STARK_WIRE_OK || dec == NULL) {
        fprintf(stderr, "MISMATCH valid decode: status=%d (want 0), dec=%p\n", (int)ds, (void *)dec);
        fails++;
    } else {
        if (dec->degree_bits != v.degree_bits) {
            fprintf(stderr, "MISMATCH degree_bits: got %zu want %llu\n",
                    dec->degree_bits, (unsigned long long)v.degree_bits);
            fails++;
        }
        if (dec->num_public_values != v.num_pub) {
            fprintf(stderr, "MISMATCH num_public_values: got %zu want %zu\n",
                    dec->num_public_values, v.num_pub);
            fails++;
        } else {
            for (size_t i = 0; i < v.num_pub; i++) {
                if (gold_fp_to_u64(dec->public_values[i]) != v.pub[i]) {
                    fprintf(stderr, "MISMATCH public_values[%zu]: got %llu want %llu\n", i,
                            (unsigned long long)gold_fp_to_u64(dec->public_values[i]),
                            (unsigned long long)v.pub[i]);
                    fails++;
                }
            }
        }
        if (dec->inner_dzkf_len != v.inner_len ||
            (v.inner_len > 0 && memcmp(dec->inner_dzkf, v.inner, v.inner_len) != 0)) {
            fprintf(stderr, "MISMATCH inner_dzkf: got_len=%zu want_len=%zu (or bytes differ)\n",
                    dec->inner_dzkf_len, v.inner_len);
            fails++;
        }

        /* re-encode the decoded structure -> must reproduce the wire byte-for-byte */
        uint8_t *re = NULL; size_t rel = 0;
        dnac_stark_wire_status_t es = dnac_stark_proof_encode(
            dec->degree_bits, dec->public_values, dec->num_public_values,
            dec->inner_dzkf, dec->inner_dzkf_len, &re, &rel);
        if (es != DNAC_STARK_WIRE_OK || rel != v.wire_len || memcmp(re, v.wire, v.wire_len) != 0) {
            fprintf(stderr, "MISMATCH re-encode roundtrip: status=%d rel=%zu want=%zu\n",
                    (int)es, rel, v.wire_len);
            fails++;
        }
        free(re);

        /* inner DZKF must decode with the EXISTING fri_proof_codec (unchanged) */
        dnac_fri_wire_package_t *pkg = NULL;
        dnac_fri_codec_status_t cs = dnac_fri_proof_decode(dec->inner_dzkf, dec->inner_dzkf_len, &pkg);
        if (cs != DNAC_FRI_CODEC_OK || pkg == NULL) {
            fprintf(stderr, "MISMATCH inner DZKF decode: fri_codec_status=%d (want 0), pkg=%p\n",
                    (int)cs, (void *)pkg);
            fails++;
        }
        dnac_fri_wire_free(pkg);
    }
    dnac_stark_wire_free(dec);

    /* ---- NEGATIVE: each malformed wire -> expected status, out == NULL ---- */
    printf("  --- negative malformed cases ---\n");
    for (size_t i = 0; i < nneg; i++) {
        dnac_stark_wire_decoded_t *nd = NULL;
        dnac_stark_wire_status_t st = dnac_stark_proof_decode(negs[i].wire, negs[i].wire_len, &nd);
        if ((int)st != negs[i].expect_status || nd != NULL) {
            fprintf(stderr, "MISMATCH negative %-30s: status=%d (want %d), out=%p\n",
                    negs[i].name, (int)st, negs[i].expect_status, (void *)nd);
            fails++;
            dnac_stark_wire_free(nd);
        } else {
            printf("  [OK ] %-30s reject -> status %d\n", negs[i].name, (int)st);
        }
        free(negs[i].wire);
    }

    free(v.inner); free(v.wire);

    if (fails) { fprintf(stderr, "test_stark_proof_codec: %d FAIL(s)\n", fails); return 1; }

    printf("test_stark_proof_codec: PASS\n");
    printf("  DZKS valid: decode OK | degree_bits=%llu | %zu public_values | inner_dzkf=%zu bytes\n",
           (unsigned long long)v.degree_bits, v.num_pub, v.inner_len);
    printf("  roundtrip: re-encode == wire (%zu bytes); inner DZKF decodes via fri_proof_codec OK.\n",
           v.wire_len);
    printf("  %zu malformed cases all rejected with the expected status; existing DZKF wire unchanged.\n", nneg);
    return 0;
}
