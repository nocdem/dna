/**
 * @file test_fri_verifier_verify_query.c
 * @brief F5 Part B oracle test — verify_query isolated shape errors.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Loads tools/vectors/fri_verifier_verify_query.json (3 isolated cases) and
 * replays each through dnac_fri_test_verify_query_shape (mirror of
 * verifier.rs:378-398 + 483-497, zero fold rounds). Each must produce the
 * Plonky3 #[test]-asserted FriError variant:
 *   - InitialReducedOpeningHeightMismatch (verifier.rs:1335)
 *   - FinalFoldHeightMismatch             (verifier.rs:1381)
 *   - UnconsumedReducedOpenings           (verifier.rs:1428)
 *
 * These three are verify_query-private (the public verify_fri entry never
 * reaches them with naturally-shaped inputs); the eval values are irrelevant
 * with zero fold rounds, so only reduced-opening LOG-HEIGHTS are replayed.
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

#include "fri_verifier.h"

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

/* ===== Parsed case ===== */
#define MAX_RO 16
typedef struct {
    char     name[64];
    char     expected_error[48];
    uint64_t lgmh, lfh;
    size_t   ro_heights[MAX_RO]; size_t num_ro;
} vq_case_t;

/* reduced_openings_input = [ { "log_height": N, "fp2": {...}, ... }, ... ] */
static bool parse_reduced_openings(js_t *s, vq_case_t *c) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        /* one opening object */
        if (!js_match(s, '{')) return false;
        uint64_t lh = 0; int have = 0;
        while (1) {
            if (js_match(s, '}')) break;
            if (js_peek(s, ',')) { s->pos++; continue; }
            char *k = js_read_string(s); js_match(s, ':');
            if (strcmp(k, "log_height") == 0) { js_read_u64(s, &lh); have = 1; }
            else js_skip_value(s);
            free(k);
        }
        if (have && c->num_ro < MAX_RO) c->ro_heights[c->num_ro++] = (size_t)lh;
    }
}

static bool parse_case(js_t *s, vq_case_t *c) {
    memset(c, 0, sizeof *c);
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *k = js_read_string(s); if (!k) return false;
        if (!js_match(s, ':')) { free(k); return false; }
        if (strcmp(k, "name") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->name, v, sizeof(c->name)-1); free(v);} }
        else if (strcmp(k, "expected_error") == 0) { char *v = js_read_string(s); if (v){ strncpy(c->expected_error, v, sizeof(c->expected_error)-1); free(v);} }
        else if (strcmp(k, "log_global_max_height") == 0) { js_read_u64(s, &c->lgmh); }
        else if (strcmp(k, "log_final_height") == 0) { js_read_u64(s, &c->lfh); }
        else if (strcmp(k, "reduced_openings_input") == 0) { if (!parse_reduced_openings(s, c)) { free(k); return false; } }
        else js_skip_value(s);
        free(k);
    }
}

static int expected_enum(const char *e, dnac_fri_status_t *out) {
    if (strcmp(e, "InitialReducedOpeningHeightMismatch") == 0) { *out = DNAC_FRI_ERR_INITIAL_REDUCED_OPENING_HEIGHT_MISMATCH; return 1; }
    if (strcmp(e, "FinalFoldHeightMismatch") == 0) { *out = DNAC_FRI_ERR_FINAL_FOLD_HEIGHT_MISMATCH; return 1; }
    if (strcmp(e, "UnconsumedReducedOpenings") == 0) { *out = DNAC_FRI_ERR_UNCONSUMED_REDUCED_OPENINGS; return 1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <fri_verifier_verify_query.json>\n", argv[0]); return 2; }
    printf("============================================================\n");
    printf("F5 Part B — verify_query isolated shape errors (Plonky3 82cfad73)\n");
    printf("            verifier.rs:378-398 + 483-497, zero fold rounds\n");
    printf("============================================================\n");

    size_t blen = 0; char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    uint64_t hdr_total = 0; int saw_hdr = 0;
    int parsed = 0, passed = 0, failed = 0;

    if (!js_match(&s, '{')) { fprintf(stderr, "bad json root\n"); return 2; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *k = js_read_string(&s); if (!k) return 2;
        if (!js_match(&s, ':')) return 2;
        if (strcmp(k, "case_count_total") == 0) { js_read_u64(&s, &hdr_total); saw_hdr = 1; }
        else if (strcmp(k, "cases") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                vq_case_t c;
                if (!parse_case(&s, &c)) { fprintf(stderr, "bad case\n"); return 2; }
                parsed++;

                dnac_fri_status_t want;
                if (!expected_enum(c.expected_error, &want)) {
                    failed++; printf("  [FAIL] %-34s unknown expected_error %s\n", c.name, c.expected_error); continue;
                }
                dnac_fri_status_t got = dnac_fri_test_verify_query_shape(
                    c.ro_heights, c.num_ro, (size_t)c.lgmh, (size_t)c.lfh);
                if (got == want) {
                    passed++;
                    printf("  [OK ] %-34s lgmh=%llu lfh=%llu n_ro=%zu -> %s\n",
                           c.name, (unsigned long long)c.lgmh, (unsigned long long)c.lfh, c.num_ro, c.expected_error);
                } else {
                    failed++;
                    printf("  [FAIL] %-34s got=%d want=%d (%s)\n", c.name, (int)got, (int)want, c.expected_error);
                }
            }
        } else js_skip_value(&s);
        free(k);
    }
    free(blob);

    printf("------------------------------------------------------------\n");
    printf("  header total=%llu | parsed=%d | passed=%d failed=%d\n",
           (unsigned long long)hdr_total, parsed, passed, failed);

    int green = saw_hdr && (hdr_total == 3) && (parsed == 3) && (passed == 3) && (failed == 0);
    if (green) {
        printf("F5 VERIFY-QUERY GATE: GREEN — 3/3 isolated shape errors match Plonky3\n");
        printf("============================================================\n");
        return 0;
    }
    printf("F5 VERIFY-QUERY GATE: RED\n");
    return 1;
}
