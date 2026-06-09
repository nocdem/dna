/**
 * @file test_merkle_mmcs_batch.c
 * @brief Phase 2A Merkle/MMCS same-height multi-matrix byte-equivalence gate.
 *
 * Loads tools/vectors/merkle_mmcs_batch_same_height.json and, for every case,
 * replays the commit / open / verify cycle through the new C batch API
 * (dnac_merkle_batch_commit / dnac_merkle_batch_open / dnac_merkle_batch_verify)
 * and asserts byte identity with the Rust oracle for accept cases, and the
 * documented expected_error for reject cases.
 *
 * Acceptance gates:
 *   1. Parse all 511 cases (492 accept + 19 reject).
 *   2. Accept cases: byte-match commit root + per-matrix opened rows + proof
 *      siblings; dnac_merkle_batch_verify must return DNAC_MERKLE_OK.
 *   3. Reject cases: dnac_merkle_batch_verify must return the documented
 *      DNAC_MERKLE_ERR_* code matching expected_error.
 *   4. num_matrices == 1 regression: for every nm1_... case, the new batch
 *      API and the existing single-matrix API must produce byte-identical
 *      root + proof for the same input data.
 *   5. Height = 1 multi-matrix: proof_count == 0 and root recomputable from
 *      the concatenated single-row hash.
 *
 * Exit codes:
 *   0 — all gates passed
 *   1 — at least one failure
 *   2 — file load / parse error
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "crypto/hash/qgp_sha3.h"
#include "../merkle_smt.h"

/* ============================================================================
 * Minimal JSON scanner — same shape as test_merkle_mmcs.c / test_transcript_oracle.c.
 * ========================================================================== */

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} js_t;

static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}

static bool js_peek(js_t *s, char c) {
    js_skip_ws(s);
    return s->pos < s->len && s->src[s->pos] == c;
}

static bool js_match(js_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}

static bool js_match_key(js_t *s, const char *key) {
    js_skip_ws(s);
    size_t klen = strlen(key);
    if (s->pos + klen + 2 > s->len) return false;
    if (s->src[s->pos] != '"') return false;
    if (memcmp(s->src + s->pos + 1, key, klen) != 0) return false;
    if (s->src[s->pos + 1 + klen] != '"') return false;
    s->pos += klen + 2;
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == ':') s->pos++;
    return true;
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
        char *key = js_read_string(s);
        if (!key) return false;
        free(key);
        js_skip_ws(s);
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

static bool js_skip_string(js_t *s) {
    char *str = js_read_string(s);
    if (!str) return false;
    free(str);
    return true;
}

static bool js_skip_value(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '{') return js_skip_object(s);
    if (c == '[') return js_skip_array(s);
    if (c == '"') return js_skip_string(s);
    if (c == 't' || c == 'f') {
        if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "true", 4) == 0) {
            s->pos += 4; return true;
        }
        if (s->pos + 5 <= s->len && memcmp(s->src + s->pos, "false", 5) == 0) {
            s->pos += 5; return true;
        }
        return false;
    }
    if (c == 'n') {
        if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "null", 4) == 0) {
            s->pos += 4; return true;
        }
        return false;
    }
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' ||
            d == 'e' || d == 'E') {
            s->pos++;
        } else break;
    }
    return true;
}

/* ============================================================================
 * Hex codec
 * ========================================================================== */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return NULL;
    size_t blen = hlen / 2;
    uint8_t *out = (uint8_t *)malloc(blen == 0 ? 1 : blen);
    if (!out) return NULL;
    for (size_t i = 0; i < blen; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(out); return NULL; }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = blen;
    return out;
}

static void hex_encode(const uint8_t *bytes, size_t len, char *out) {
    static const char tab[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = tab[(bytes[i] >> 4) & 0x0F];
        out[2 * i + 1] = tab[bytes[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

/* ============================================================================
 * Data model
 * ========================================================================== */

typedef struct {
    /* Owned strings */
    char    *name;
    char    *expected_verify;       /* "accept" or "reject" */
    char    *tamper_type;           /* NULL on accept */
    char    *expected_error;        /* NULL on accept */
    /* Shape */
    uint64_t num_matrices;
    uint64_t height;
    uint64_t leaf_index;
    /* Per-matrix data (length num_matrices) */
    uint64_t *widths;               /* widths[m] */
    size_t   *row_byte_lens;        /* widths[m] * 8 */
    uint8_t **matrix_rows;          /* matrix_rows[m] = flat row-major bytes, length height * row_byte_lens[m] */
    /* Expected outputs */
    uint8_t  expected_root[64];
    uint8_t **expected_opened_rows; /* expected_opened_rows[m] = row_byte_lens[m] bytes */
    uint8_t  *expected_proof;       /* flat, length = depth * 64 */
    size_t    expected_proof_count;
    /* Optional caller-side num_matrices override (used by wrong_batch_size
     * reject vectors per Phase 2A oracle). When have_verifier_num_matrices_arg
     * is true, the test passes this value to dnac_merkle_batch_verify instead
     * of num_matrices, while proof->num_matrices is set to num_matrices
     * (the commit-time count). */
    bool      have_verifier_num_matrices_arg;
    uint32_t  verifier_num_matrices_arg;
} mb_case_t;

static void mb_case_free(mb_case_t *c) {
    free(c->name);
    free(c->expected_verify);
    free(c->tamper_type);
    free(c->expected_error);
    free(c->widths);
    free(c->row_byte_lens);
    if (c->matrix_rows) {
        for (size_t m = 0; m < c->num_matrices; m++) {
            free(c->matrix_rows[m]);
        }
        free(c->matrix_rows);
    }
    if (c->expected_opened_rows) {
        for (size_t m = 0; m < c->num_matrices; m++) {
            free(c->expected_opened_rows[m]);
        }
        free(c->expected_opened_rows);
    }
    free(c->expected_proof);
    memset(c, 0, sizeof(*c));
}

/* Parse a 2D array of hex strings: outer dim count = num_matrices, inner =
 * rows per matrix. Returns 2D array of malloc'd byte buffers; out_inner_lens
 * receives per-matrix byte length (height * row_byte_lens[m]). */
static bool parse_matrices_rows_hex(
    js_t       *s,
    uint64_t    expected_num_matrices,
    uint64_t    expected_height,
    const size_t *row_byte_lens,
    uint8_t  ***out_matrix_rows)
{
    *out_matrix_rows = NULL;
    if (!js_match(s, '[')) return false;
    uint8_t **arr = (uint8_t **)calloc(expected_num_matrices, sizeof(*arr));
    if (!arr) return false;
    size_t m_idx = 0;
    while (1) {
        if (js_match(s, ']')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (m_idx >= expected_num_matrices) goto fail;
        if (!js_match(s, '[')) goto fail;
        const size_t per_matrix_bytes = (size_t)expected_height * row_byte_lens[m_idx];
        arr[m_idx] = (uint8_t *)malloc(per_matrix_bytes == 0 ? 1 : per_matrix_bytes);
        if (!arr[m_idx]) goto fail;
        size_t row_idx = 0;
        while (1) {
            if (js_match(s, ']')) break;
            if (js_peek(s, ',')) { s->pos++; continue; }
            if (row_idx >= expected_height) goto fail;
            char *h = js_read_string(s);
            if (!h) goto fail;
            size_t rl = 0;
            uint8_t *rb = hex_decode(h, &rl);
            free(h);
            if (!rb || rl != row_byte_lens[m_idx]) { free(rb); goto fail; }
            memcpy(arr[m_idx] + row_idx * row_byte_lens[m_idx], rb, rl);
            free(rb);
            row_idx++;
        }
        if (row_idx != expected_height) goto fail;
        m_idx++;
    }
    if (m_idx != expected_num_matrices) goto fail;
    *out_matrix_rows = arr;
    return true;
fail:
    if (arr) {
        for (size_t i = 0; i < expected_num_matrices; i++) free(arr[i]);
        free(arr);
    }
    return false;
}

static bool parse_widths(js_t *s, uint64_t expected_num_matrices,
                         uint64_t **out_widths, size_t **out_row_byte_lens)
{
    *out_widths = NULL;
    *out_row_byte_lens = NULL;
    if (!js_match(s, '[')) return false;
    uint64_t *widths = (uint64_t *)calloc(expected_num_matrices, sizeof(*widths));
    size_t *rbls = (size_t *)calloc(expected_num_matrices, sizeof(*rbls));
    if (!widths || !rbls) { free(widths); free(rbls); return false; }
    size_t count = 0;
    while (1) {
        if (js_match(s, ']')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (count >= expected_num_matrices) { free(widths); free(rbls); return false; }
        uint64_t w;
        if (!js_read_u64(s, &w)) { free(widths); free(rbls); return false; }
        widths[count] = w;
        rbls[count] = (size_t)w * 8;
        count++;
    }
    if (count != expected_num_matrices) { free(widths); free(rbls); return false; }
    *out_widths = widths;
    *out_row_byte_lens = rbls;
    return true;
}

static bool parse_opened_rows_hex(
    js_t      *s,
    uint64_t   expected_num_matrices,
    const size_t *row_byte_lens,
    uint8_t ***out_opened_rows)
{
    *out_opened_rows = NULL;
    if (!js_match(s, '[')) return false;
    uint8_t **arr = (uint8_t **)calloc(expected_num_matrices, sizeof(*arr));
    if (!arr) return false;
    size_t count = 0;
    while (1) {
        if (js_match(s, ']')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (count >= expected_num_matrices) goto fail;
        char *h = js_read_string(s);
        if (!h) goto fail;
        size_t rl = 0;
        uint8_t *rb = hex_decode(h, &rl);
        free(h);
        if (!rb || rl != row_byte_lens[count]) { free(rb); goto fail; }
        arr[count] = rb;
        count++;
    }
    if (count != expected_num_matrices) goto fail;
    *out_opened_rows = arr;
    return true;
fail:
    if (arr) {
        for (size_t i = 0; i < expected_num_matrices; i++) free(arr[i]);
        free(arr);
    }
    return false;
}

/* Parse one case object from the JSON stream. */
static bool parse_case(js_t *s, mb_case_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    char  *root_hex = NULL;
    char **proof_hex = NULL;
    size_t proof_hex_count = 0;
    size_t proof_hex_cap   = 0;
    bool have_num_matrices = false, have_height = false, have_leaf_index = false;
    bool have_widths = false, have_matrices_rows = false, have_opened_rows = false;
    /* Defer parsing matrices_rows_hex and expected_opened_rows_hex until
     * after widths is parsed (we need row_byte_lens[]). We capture them as
     * raw spans and re-scan. */
    size_t matrices_rows_start = 0, matrices_rows_end = 0;
    size_t opened_rows_start = 0, opened_rows_end = 0;

    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }

        if (js_match_key(s, "name")) {
            out->name = js_read_string(s);
            if (!out->name) goto fail;
        } else if (js_match_key(s, "expected_verify")) {
            out->expected_verify = js_read_string(s);
            if (!out->expected_verify) goto fail;
        } else if (js_match_key(s, "tamper_type")) {
            out->tamper_type = js_read_string(s);
            if (!out->tamper_type) goto fail;
        } else if (js_match_key(s, "expected_error")) {
            out->expected_error = js_read_string(s);
            if (!out->expected_error) goto fail;
        } else if (js_match_key(s, "num_matrices")) {
            if (!js_read_u64(s, &out->num_matrices)) goto fail;
            have_num_matrices = true;
        } else if (js_match_key(s, "height")) {
            if (!js_read_u64(s, &out->height)) goto fail;
            have_height = true;
        } else if (js_match_key(s, "leaf_index")) {
            if (!js_read_u64(s, &out->leaf_index)) goto fail;
            have_leaf_index = true;
        } else if (js_match_key(s, "widths")) {
            if (!have_num_matrices) goto fail;
            if (!parse_widths(s, out->num_matrices, &out->widths, &out->row_byte_lens))
                goto fail;
            have_widths = true;
        } else if (js_match_key(s, "matrices_rows_hex")) {
            /* Capture span; parse later when widths is available. */
            js_skip_ws(s);
            matrices_rows_start = s->pos;
            if (!js_skip_value(s)) goto fail;
            matrices_rows_end = s->pos;
            have_matrices_rows = true;
        } else if (js_match_key(s, "expected_root_hex")) {
            root_hex = js_read_string(s);
            if (!root_hex) goto fail;
        } else if (js_match_key(s, "expected_opened_rows_hex")) {
            js_skip_ws(s);
            opened_rows_start = s->pos;
            if (!js_skip_value(s)) goto fail;
            opened_rows_end = s->pos;
            have_opened_rows = true;
        } else if (js_match_key(s, "expected_proof_hex")) {
            if (!js_match(s, '[')) goto fail;
            while (1) {
                if (js_match(s, ']')) break;
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *h = js_read_string(s);
                if (!h) goto fail;
                if (proof_hex_count == proof_hex_cap) {
                    size_t newcap = proof_hex_cap ? proof_hex_cap * 2 : 8;
                    char **g = (char **)realloc(proof_hex, newcap * sizeof(char *));
                    if (!g) { free(h); goto fail; }
                    proof_hex = g;
                    proof_hex_cap = newcap;
                }
                proof_hex[proof_hex_count++] = h;
            }
        } else if (js_match_key(s, "verifier_num_matrices_arg")) {
            uint64_t v = 0;
            if (!js_read_u64(s, &v)) goto fail;
            out->have_verifier_num_matrices_arg = true;
            out->verifier_num_matrices_arg = (uint32_t)v;
        } else {
            /* Skip unknown key:value */
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }

    if (!out->name || !out->expected_verify || !have_num_matrices ||
        !have_height || !have_leaf_index || !have_widths ||
        !have_matrices_rows || !have_opened_rows || !root_hex) goto fail;

    /* Decode root. */
    {
        size_t rlen = 0;
        uint8_t *rb = hex_decode(root_hex, &rlen);
        if (!rb || rlen != 64) { free(rb); goto fail; }
        memcpy(out->expected_root, rb, 64);
        free(rb);
    }

    /* Re-scan matrices_rows_hex span using row_byte_lens. */
    {
        js_t sub = { .src = s->src, .pos = matrices_rows_start, .len = matrices_rows_end };
        if (!parse_matrices_rows_hex(&sub, out->num_matrices, out->height,
                                     out->row_byte_lens, &out->matrix_rows))
            goto fail;
    }

    /* Re-scan expected_opened_rows_hex span. */
    {
        js_t sub = { .src = s->src, .pos = opened_rows_start, .len = opened_rows_end };
        if (!parse_opened_rows_hex(&sub, out->num_matrices,
                                   out->row_byte_lens, &out->expected_opened_rows))
            goto fail;
    }

    /* Decode proof siblings. */
    out->expected_proof_count = proof_hex_count;
    if (proof_hex_count > 0) {
        out->expected_proof = (uint8_t *)malloc(proof_hex_count * 64);
        if (!out->expected_proof) goto fail;
        for (size_t i = 0; i < proof_hex_count; i++) {
            size_t pl = 0;
            uint8_t *pb = hex_decode(proof_hex[i], &pl);
            if (!pb || pl != 64) { free(pb); goto fail; }
            memcpy(out->expected_proof + i * 64, pb, 64);
            free(pb);
        }
    }

    free(root_hex);
    for (size_t i = 0; i < proof_hex_count; i++) free(proof_hex[i]);
    free(proof_hex);
    return true;
fail:
    free(root_hex);
    if (proof_hex) {
        for (size_t i = 0; i < proof_hex_count; i++) free(proof_hex[i]);
        free(proof_hex);
    }
    mb_case_free(out);
    return false;
}

/* ============================================================================
 * Top-level loader
 * ========================================================================== */

static char *slurp_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    buf[n] = '\0';
    *out_len = (size_t)n;
    return buf;
}

static bool load_cases(const char *path, mb_case_t **out_cases, size_t *out_count) {
    size_t flen = 0;
    char *src = slurp_file(path, &flen);
    if (!src) {
        fprintf(stderr, "failed to open %s\n", path);
        return false;
    }
    js_t s = { .src = src, .pos = 0, .len = flen };

    if (!js_match(&s, '{')) { free(src); return false; }

    mb_case_t *cases = NULL;
    size_t count = 0, cap = 0;

    while (1) {
        if (js_match(&s, '}')) break;
        if (js_peek(&s, ',')) { s.pos++; continue; }
        if (js_match_key(&s, "cases")) {
            if (!js_match(&s, '[')) { free(src); return false; }
            while (1) {
                if (js_match(&s, ']')) break;
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (count == cap) {
                    size_t newcap = cap ? cap * 2 : 64;
                    mb_case_t *g = (mb_case_t *)realloc(cases, newcap * sizeof(*cases));
                    if (!g) { free(cases); free(src); return false; }
                    cases = g;
                    cap = newcap;
                }
                if (!parse_case(&s, &cases[count])) {
                    fprintf(stderr, "parse_case failed at index %zu\n", count);
                    free(src);
                    return false;
                }
                count++;
            }
        } else {
            char *unknown = js_read_string(&s);
            if (!unknown) { free(src); return false; }
            free(unknown);
            if (!js_match(&s, ':')) { free(src); return false; }
            if (!js_skip_value(&s)) { free(src); return false; }
        }
    }

    free(src);
    *out_cases = cases;
    *out_count = count;
    return true;
}

/* ============================================================================
 * Test runners
 * ========================================================================== */

static uint32_t log2_pow2_or_zero(uint64_t n) {
    if (n == 0) return 0;
    uint32_t k = 0;
    while ((n >> k) > 1) k++;
    return k;
}

static bool run_accept_case(const mb_case_t *c) {
    /* Stage A: dnac_merkle_batch_commit must produce expected_root. */
    dnac_merkle_batch_tree_t *tree = NULL;
    dnac_merkle_digest_t root;
    const uint8_t * const *mrows = (const uint8_t * const *)c->matrix_rows;
    dnac_merkle_status_t rc = dnac_merkle_batch_commit(
        mrows, c->row_byte_lens,
        (size_t)c->num_matrices, (size_t)c->height,
        &root, &tree);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] commit failed rc=%d\n", c->name, (int)rc);
        return false;
    }
    if (memcmp(root.bytes, c->expected_root, 64) != 0) {
        char got[129], want[129];
        hex_encode(root.bytes, 64, got);
        hex_encode(c->expected_root, 64, want);
        fprintf(stderr, "[%s] root mismatch\n  got : %s\n  want: %s\n",
                c->name, got, want);
        dnac_merkle_batch_tree_free(tree);
        return false;
    }

    /* Stage B: dnac_merkle_batch_open must produce expected proof + opened rows. */
    uint32_t depth = log2_pow2_or_zero(c->height);
    dnac_merkle_digest_t *siblings = NULL;
    if (depth > 0) {
        siblings = (dnac_merkle_digest_t *)calloc(depth, sizeof(*siblings));
        if (!siblings) {
            dnac_merkle_batch_tree_free(tree);
            return false;
        }
    }
    dnac_merkle_proof_t proof = { 0 };
    proof.leaf_index   = 0;
    proof.depth        = depth;
    proof.num_matrices = (uint32_t)c->num_matrices;
    proof.siblings     = siblings;

    const uint8_t **opened = (const uint8_t **)calloc(c->num_matrices, sizeof(*opened));
    if (!opened) {
        free(siblings);
        dnac_merkle_batch_tree_free(tree);
        return false;
    }
    rc = dnac_merkle_batch_open(tree, c->leaf_index, opened, &proof);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] open failed rc=%d\n", c->name, (int)rc);
        free(opened); free(siblings);
        dnac_merkle_batch_tree_free(tree);
        return false;
    }
    /* Verify per-matrix opened rows byte-match expected. */
    for (size_t m = 0; m < c->num_matrices; m++) {
        if (memcmp(opened[m], c->expected_opened_rows[m], c->row_byte_lens[m]) != 0) {
            fprintf(stderr, "[%s] opened row matrix %zu mismatch\n", c->name, m);
            free(opened); free(siblings);
            dnac_merkle_batch_tree_free(tree);
            return false;
        }
    }
    /* Verify proof siblings byte-match expected. */
    if (proof.depth != c->expected_proof_count) {
        fprintf(stderr, "[%s] proof depth mismatch: got %u want %zu\n",
                c->name, proof.depth, c->expected_proof_count);
        free(opened); free(siblings);
        dnac_merkle_batch_tree_free(tree);
        return false;
    }
    for (uint32_t i = 0; i < proof.depth; i++) {
        if (memcmp(proof.siblings[i].bytes,
                   c->expected_proof + i * 64, 64) != 0) {
            fprintf(stderr, "[%s] proof sibling %u mismatch\n", c->name, i);
            free(opened); free(siblings);
            dnac_merkle_batch_tree_free(tree);
            return false;
        }
    }

    /* Stage C: dnac_merkle_batch_verify must accept. */
    rc = dnac_merkle_batch_verify(
        &root, opened, c->row_byte_lens,
        (size_t)c->num_matrices, (size_t)c->height, &proof);
    free(opened); free(siblings);
    dnac_merkle_batch_tree_free(tree);

    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] verify rejected (rc=%d) but accept expected\n",
                c->name, (int)rc);
        return false;
    }
    return true;
}

/* Map an expected_error string to the dnac_merkle_status_t code. */
static dnac_merkle_status_t error_code_from_string(const char *s) {
    if (!s) return DNAC_MERKLE_OK;
    if (strcmp(s, "DNAC_MERKLE_OK") == 0)               return DNAC_MERKLE_OK;
    if (strcmp(s, "DNAC_MERKLE_ERR_NULL_ARG") == 0)     return DNAC_MERKLE_ERR_NULL_ARG;
    if (strcmp(s, "DNAC_MERKLE_ERR_BAD_HEIGHT") == 0)   return DNAC_MERKLE_ERR_BAD_HEIGHT;
    if (strcmp(s, "DNAC_MERKLE_ERR_BAD_INDEX") == 0)    return DNAC_MERKLE_ERR_BAD_INDEX;
    if (strcmp(s, "DNAC_MERKLE_ERR_BAD_DEPTH") == 0)    return DNAC_MERKLE_ERR_BAD_DEPTH;
    if (strcmp(s, "DNAC_MERKLE_ERR_ROOT_MISMATCH") == 0) return DNAC_MERKLE_ERR_ROOT_MISMATCH;
    if (strcmp(s, "DNAC_MERKLE_ERR_NONCANONICAL") == 0) return DNAC_MERKLE_ERR_NONCANONICAL;
    if (strcmp(s, "DNAC_MERKLE_ERR_OOM") == 0)          return DNAC_MERKLE_ERR_OOM;
    if (strcmp(s, "DNAC_MERKLE_ERR_WRONG_BATCH_SIZE") == 0) return DNAC_MERKLE_ERR_WRONG_BATCH_SIZE;
    return DNAC_MERKLE_OK;
}

/* Reject cases: each carries an expected_error that the verifier must report
 * when given the pre-tampered case data directly.
 *
 * The oracle records the case in its TAMPERED form (matrices_rows_hex,
 * expected_root, expected_opened_rows_hex, expected_proof_hex already
 * reflect the mutation). The test simply calls batch_verify() with these
 * tampered values and confirms the documented error code.
 *
 * For wrong_proof_length / wrong_batch_size / index_out_of_bounds the
 * tampering touches shape fields rather than data — the case's num_matrices
 * and expected_proof_count already reflect the mutated shape; the test
 * passes that mutated shape into batch_verify and confirms the error. */
static bool run_reject_case(const mb_case_t *c) {
    const dnac_merkle_status_t want = error_code_from_string(c->expected_error);

    /* Build a dnac_merkle_proof_t from the tampered fields. */
    dnac_merkle_digest_t *siblings = NULL;
    if (c->expected_proof_count > 0) {
        siblings = (dnac_merkle_digest_t *)calloc(
            c->expected_proof_count, sizeof(*siblings));
        if (!siblings) return false;
        for (size_t i = 0; i < c->expected_proof_count; i++) {
            memcpy(siblings[i].bytes, c->expected_proof + i * 64, 64);
        }
    }
    dnac_merkle_proof_t proof = { 0 };
    proof.leaf_index   = c->leaf_index;
    proof.depth        = (uint32_t)c->expected_proof_count;
    proof.num_matrices = (uint32_t)c->num_matrices;
    proof.siblings     = siblings;

    dnac_merkle_digest_t root;
    memcpy(root.bytes, c->expected_root, 64);

    const uint8_t **opened = (const uint8_t **)calloc(
        c->num_matrices, sizeof(*opened));
    if (!opened) { free(siblings); return false; }
    for (size_t m = 0; m < c->num_matrices; m++) {
        opened[m] = c->expected_opened_rows[m];
    }

    /* For wrong_batch_size reject vectors the case carries a separate
     * caller-side num_matrices override; for every other case the verifier's
     * num_matrices argument equals the commit-time count. */
    const size_t verifier_n =
        c->have_verifier_num_matrices_arg
            ? (size_t)c->verifier_num_matrices_arg
            : (size_t)c->num_matrices;

    dnac_merkle_status_t got = dnac_merkle_batch_verify(
        &root, opened, c->row_byte_lens,
        verifier_n, (size_t)c->height, &proof);
    free(opened);
    free(siblings);

    if (got != want) {
        fprintf(stderr, "[%s] reject mismatch: want=%d got=%d (expected_error=%s)\n",
                c->name, (int)want, (int)got, c->expected_error);
        return false;
    }
    return true;
}

/* ============================================================================
 * Cross-API regression: nm1 cases via batch API match single-matrix API.
 * ========================================================================== */

static bool run_nm1_regression(const mb_case_t *cases, size_t n_cases) {
    /* For every nm1_* accept case, also run the same data through the
     * existing dnac_merkle_commit / dnac_merkle_open / dnac_merkle_verify
     * and confirm byte identity on root + proof + leaf bytes. */
    size_t checked = 0, matched = 0;
    for (size_t i = 0; i < n_cases; i++) {
        const mb_case_t *c = &cases[i];
        if (strcmp(c->expected_verify, "accept") != 0) continue;
        if (c->num_matrices != 1) continue;
        if (strncmp(c->name, "nm1_", 4) != 0
            && strncmp(c->name, "tamper_anchor_nm1_", 18) != 0) continue;

        checked++;

        /* Drive the existing single-matrix API. */
        dnac_merkle_tree_t *st = NULL;
        dnac_merkle_digest_t sroot;
        dnac_merkle_status_t rc = dnac_merkle_commit(
            c->matrix_rows[0], c->row_byte_lens[0],
            (size_t)c->height, &sroot, &st);
        if (rc != DNAC_MERKLE_OK) {
            fprintf(stderr, "[nm1-regression %s] single-matrix commit rc=%d\n",
                    c->name, (int)rc);
            continue;
        }
        if (memcmp(sroot.bytes, c->expected_root, 64) != 0) {
            fprintf(stderr, "[nm1-regression %s] single-matrix root != oracle\n",
                    c->name);
            dnac_merkle_tree_free(st);
            continue;
        }

        uint32_t depth = log2_pow2_or_zero(c->height);
        dnac_merkle_digest_t *sibs = NULL;
        if (depth > 0) {
            sibs = (dnac_merkle_digest_t *)calloc(depth, sizeof(*sibs));
            if (!sibs) { dnac_merkle_tree_free(st); continue; }
        }
        dnac_merkle_proof_t sp = { .leaf_index = 0, .depth = depth, .siblings = sibs };
        const uint8_t *sleaf = NULL;
        size_t sleaf_len = 0;
        rc = dnac_merkle_open(st, c->leaf_index, &sleaf, &sleaf_len, &sp);
        if (rc != DNAC_MERKLE_OK) {
            fprintf(stderr, "[nm1-regression %s] single-matrix open rc=%d\n",
                    c->name, (int)rc);
            free(sibs); dnac_merkle_tree_free(st);
            continue;
        }
        /* Compare root, opened leaf, and proof to oracle. */
        bool ok = true;
        if (sleaf_len != c->row_byte_lens[0]
            || memcmp(sleaf, c->expected_opened_rows[0], sleaf_len) != 0) {
            fprintf(stderr, "[nm1-regression %s] leaf mismatch\n", c->name);
            ok = false;
        }
        if (sp.depth != c->expected_proof_count) {
            fprintf(stderr, "[nm1-regression %s] proof depth mismatch\n", c->name);
            ok = false;
        }
        for (uint32_t k = 0; ok && k < sp.depth; k++) {
            if (memcmp(sp.siblings[k].bytes,
                       c->expected_proof + k * 64, 64) != 0) {
                fprintf(stderr, "[nm1-regression %s] proof sibling %u mismatch\n",
                        c->name, k);
                ok = false;
            }
        }
        free(sibs);
        dnac_merkle_tree_free(st);
        if (ok) matched++;
    }
    fprintf(stderr, "[nm1-regression] checked=%zu matched=%zu\n", checked, matched);
    return checked > 0 && matched == checked;
}

/* ============================================================================
 * Height = 1 multi-matrix spot check.
 * ========================================================================== */

static bool run_height1_spot_check(const mb_case_t *cases, size_t n_cases) {
    /* Find at least one accept case with height==1 and num_matrices>=2,
     * verify that proof depth is 0 and the recomputed leaf hash equals root. */
    bool any_checked = false;
    for (size_t i = 0; i < n_cases; i++) {
        const mb_case_t *c = &cases[i];
        if (strcmp(c->expected_verify, "accept") != 0) continue;
        if (c->height != 1 || c->num_matrices < 2) continue;
        any_checked = true;
        if (c->expected_proof_count != 0) {
            fprintf(stderr, "[h1-spot %s] expected proof_count=0 got %zu\n",
                    c->name, c->expected_proof_count);
            return false;
        }
        /* Recompute SHA3-512(opened_row[0] || opened_row[1] || ...) and check
         * == expected_root. */
        size_t total = 0;
        for (size_t m = 0; m < c->num_matrices; m++) total += c->row_byte_lens[m];
        uint8_t *concat = (uint8_t *)malloc(total);
        if (!concat) return false;
        size_t off = 0;
        for (size_t m = 0; m < c->num_matrices; m++) {
            memcpy(concat + off, c->expected_opened_rows[m], c->row_byte_lens[m]);
            off += c->row_byte_lens[m];
        }
        uint8_t digest[64];
        if (qgp_sha3_512(concat, total, digest) != 0) {
            free(concat);
            return false;
        }
        free(concat);
        if (memcmp(digest, c->expected_root, 64) != 0) {
            fprintf(stderr, "[h1-spot %s] root != SHA3-512(concat)\n", c->name);
            return false;
        }
    }
    if (!any_checked) {
        fprintf(stderr, "[h1-spot] no height=1 multi-matrix case found\n");
        return false;
    }
    return true;
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    const char *path =
        (argc > 1) ? argv[1]
                   : "tools/vectors/merkle_mmcs_batch_same_height.json";

    mb_case_t *cases = NULL;
    size_t n_cases = 0;
    if (!load_cases(path, &cases, &n_cases)) {
        fprintf(stderr, "[merkle_mmcs_batch] load failed\n");
        return 2;
    }
    fprintf(stderr, "[merkle_mmcs_batch] loaded %zu cases from %s\n",
            n_cases, path);

    size_t n_accept = 0, n_reject = 0;
    size_t n_accept_pass = 0, n_reject_pass = 0;
    for (size_t i = 0; i < n_cases; i++) {
        const mb_case_t *c = &cases[i];
        if (strcmp(c->expected_verify, "accept") == 0) {
            n_accept++;
            if (run_accept_case(c)) n_accept_pass++;
        } else if (strcmp(c->expected_verify, "reject") == 0) {
            n_reject++;
            if (run_reject_case(c)) n_reject_pass++;
        } else {
            fprintf(stderr, "[%s] unknown expected_verify: %s\n",
                    c->name, c->expected_verify);
        }
    }
    fprintf(stderr, "[merkle_mmcs_batch] accept: %zu/%zu pass\n",
            n_accept_pass, n_accept);
    fprintf(stderr, "[merkle_mmcs_batch] reject: %zu/%zu pass\n",
            n_reject_pass, n_reject);

    fprintf(stderr, "[merkle_mmcs_batch] nm1 regression... ");
    bool nm1_ok = run_nm1_regression(cases, n_cases);
    fprintf(stderr, "%s\n", nm1_ok ? "PASS" : "FAIL");

    fprintf(stderr, "[merkle_mmcs_batch] height=1 spot check... ");
    bool h1_ok = run_height1_spot_check(cases, n_cases);
    fprintf(stderr, "%s\n", h1_ok ? "PASS" : "FAIL");

    for (size_t i = 0; i < n_cases; i++) mb_case_free(&cases[i]);
    free(cases);

    bool all_ok = (n_accept_pass == n_accept)
               && (n_reject_pass == n_reject)
               && nm1_ok && h1_ok;
    if (all_ok) {
        fprintf(stderr, "[merkle_mmcs_batch] ALL GATES GREEN — %zu cases passed\n",
                n_accept + n_reject);
        return 0;
    } else {
        fprintf(stderr, "[merkle_mmcs_batch] GATE FAILURE\n");
        return 1;
    }
}
