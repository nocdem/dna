/**
 * @file test_merkle_mmcs.c
 * @brief Stage M3 — DNAC C Merkle/MMCS byte-equivalence gate against the
 *        Plonky3-grounded merkle_mmcs.json oracle (Strategy C, 2026-05-27).
 *
 * Loads `tools/vectors/merkle_mmcs.json` and, for every case, replays the
 * commit / open / verify cycle through `merkle_smt.c` and asserts byte
 * identity with the Rust oracle's emitted root, leaf, and proof siblings.
 *
 * Acceptance gates (per the M3 task spec):
 *   1. Parse all cases (480 accept + 21 reject = 501 cases).
 *   2. Accept cases: byte-match commit root / opened leaf / opened proof,
 *      and verify must return DNAC_MERKLE_OK.
 *   3. Reject cases: route to the appropriate path and assert the documented
 *      error code (DNAC_MERKLE_ERR_ROOT_MISMATCH or _NONCANONICAL).
 *   4. Height=1 spot check: depth == 0, empty proof, root = SHA3-512(row).
 *   5. Determinism repeat: same input → byte-identical root × 100.
 *   6. Negative input validation cases (NULL, BAD_HEIGHT, BAD_INDEX, BAD_DEPTH).
 *   7. FIPS-202 SHA3-512 empty-string KAT cross-check on the C backend.
 *
 * Exit codes:
 *   0  all gates passed
 *   1  at least one mismatch / failure
 *   2  load / parse error
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
 * Minimal JSON scanner — same shape as test_transcript_oracle.c.
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
    /* number */
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
    /* Owned */
    char    *name;
    char    *expected_verify;       /* "accept" or "reject" */
    char    *tamper_type;           /* NULL on accept */
    char    *expected_error;        /* NULL on accept */
    /* Geometry */
    uint64_t height;
    uint64_t width;
    uint64_t leaf_index;
    /* Decoded vector data (owned). All sizes are byte counts. */
    uint8_t *rows_bytes;            /* flat row-major, length = height * row_byte_len */
    size_t   row_byte_len;          /* width * 8 */
    uint8_t  expected_root[64];     /* always 64 bytes */
    uint8_t *expected_leaf;
    size_t   expected_leaf_len;
    uint8_t *expected_proof;        /* flat, length = depth * 64 */
    size_t   expected_proof_count;  /* number of siblings */
} mc_case_t;

static void mc_case_free(mc_case_t *c) {
    free(c->name);
    free(c->expected_verify);
    free(c->tamper_type);
    free(c->expected_error);
    free(c->rows_bytes);
    free(c->expected_leaf);
    free(c->expected_proof);
    memset(c, 0, sizeof(*c));
}

/* Parse one case object from the JSON stream. */
static bool parse_case(js_t *s, mc_case_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    /* Staging — strings owned here; transferred to `out` on success. */
    char  **rows_hex = NULL;
    size_t  rows_hex_count = 0;
    size_t  rows_hex_cap   = 0;
    char  **proof_hex = NULL;
    size_t  proof_hex_count = 0;
    size_t  proof_hex_cap   = 0;
    char   *root_hex = NULL;
    char   *leaf_hex = NULL;
    bool    have_leaf_index = false;
    bool    have_height = false;
    bool    have_width = false;

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
        } else if (js_match_key(s, "height")) {
            if (!js_read_u64(s, &out->height)) goto fail;
            have_height = true;
        } else if (js_match_key(s, "width")) {
            if (!js_read_u64(s, &out->width)) goto fail;
            have_width = true;
        } else if (js_match_key(s, "leaf_index")) {
            if (!js_read_u64(s, &out->leaf_index)) goto fail;
            have_leaf_index = true;
        } else if (js_match_key(s, "rows_hex")) {
            if (!js_match(s, '[')) goto fail;
            while (1) {
                if (js_match(s, ']')) break;
                if (js_peek(s, ',')) { s->pos++; continue; }
                char *h = js_read_string(s);
                if (!h) goto fail;
                if (rows_hex_count == rows_hex_cap) {
                    size_t newcap = rows_hex_cap ? rows_hex_cap * 2 : 16;
                    char **g = (char **)realloc(rows_hex, newcap * sizeof(char *));
                    if (!g) { free(h); goto fail; }
                    rows_hex = g;
                    rows_hex_cap = newcap;
                }
                rows_hex[rows_hex_count++] = h;
            }
        } else if (js_match_key(s, "expected_root_hex")) {
            root_hex = js_read_string(s);
            if (!root_hex) goto fail;
        } else if (js_match_key(s, "expected_leaf_hex")) {
            leaf_hex = js_read_string(s);
            if (!leaf_hex) goto fail;
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
        } else {
            /* Skip unknown key:value pair. */
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }

    if (!out->name || !out->expected_verify || !have_height || !have_width ||
        !have_leaf_index || !root_hex || !leaf_hex || rows_hex_count == 0) {
        goto fail;
    }
    if (rows_hex_count != out->height) goto fail;

    /* Decode root (must be exactly 64 bytes). */
    {
        size_t rlen = 0;
        uint8_t *rb = hex_decode(root_hex, &rlen);
        if (!rb || rlen != 64) { free(rb); goto fail; }
        memcpy(out->expected_root, rb, 64);
        free(rb);
    }
    /* Decode leaf bytes. */
    out->expected_leaf = hex_decode(leaf_hex, &out->expected_leaf_len);
    if (!out->expected_leaf) goto fail;
    out->row_byte_len = out->expected_leaf_len;
    if (out->row_byte_len != out->width * 8) goto fail;

    /* Decode rows flat-buffer. */
    {
        size_t total = out->height * out->row_byte_len;
        out->rows_bytes = (uint8_t *)malloc(total == 0 ? 1 : total);
        if (!out->rows_bytes) goto fail;
        for (size_t i = 0; i < rows_hex_count; i++) {
            size_t rl = 0;
            uint8_t *rb = hex_decode(rows_hex[i], &rl);
            if (!rb || rl != out->row_byte_len) { free(rb); goto fail; }
            memcpy(out->rows_bytes + i * out->row_byte_len, rb, rl);
            free(rb);
        }
    }

    /* Decode proof siblings. Each must be 64 bytes. */
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

    /* Free staging arrays (contents already consumed). */
    for (size_t i = 0; i < rows_hex_count; i++) free(rows_hex[i]);
    free(rows_hex);
    for (size_t i = 0; i < proof_hex_count; i++) free(proof_hex[i]);
    free(proof_hex);
    free(root_hex);
    free(leaf_hex);
    return true;

fail:
    for (size_t i = 0; i < rows_hex_count; i++) free(rows_hex[i]);
    free(rows_hex);
    for (size_t i = 0; i < proof_hex_count; i++) free(proof_hex[i]);
    free(proof_hex);
    free(root_hex);
    free(leaf_hex);
    mc_case_free(out);
    return false;
}

/* ============================================================================
 * File slurp
 * ========================================================================== */

static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return NULL; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return NULL; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

/* ============================================================================
 * log2 helper (for proof depth)
 * ========================================================================== */

static uint32_t log2_pow2_u64(uint64_t n) {
    uint32_t k = 0;
    while ((n >> k) > 1) k++;
    return k;
}

/* ============================================================================
 * SHA3-512 KAT
 * ========================================================================== */

static const uint8_t SHA3_512_KAT_EMPTY[64] = {
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
    0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
    0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
    0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
    0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
    0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
    0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
};

static bool run_sha3_kat(void) {
    uint8_t out[64];
    if (qgp_sha3_512((const uint8_t *)"", 0, out) != 0) {
        fprintf(stderr, "FAIL: qgp_sha3_512 returned non-zero on empty input\n");
        return false;
    }
    if (memcmp(out, SHA3_512_KAT_EMPTY, 64) != 0) {
        char actual[129], expected[129];
        hex_encode(out, 64, actual);
        hex_encode(SHA3_512_KAT_EMPTY, 64, expected);
        fprintf(stderr, "FAIL: SHA3-512 empty-string KAT mismatch\n");
        fprintf(stderr, "  expected = %s\n", expected);
        fprintf(stderr, "  actual   = %s\n", actual);
        return false;
    }
    return true;
}

/* ============================================================================
 * Case runner
 * ========================================================================== */

static void print_hex_diff(const char *label, const uint8_t *a, const uint8_t *b, size_t n) {
    char *ah = (char *)malloc(2 * n + 1);
    char *bh = (char *)malloc(2 * n + 1);
    if (!ah || !bh) { free(ah); free(bh); return; }
    hex_encode(a, n, ah);
    hex_encode(b, n, bh);
    fprintf(stderr, "    %s expected: %s\n", label, ah);
    fprintf(stderr, "    %s actual:   %s\n", label, bh);
    free(ah);
    free(bh);
}

/* Run an accept case end-to-end. Returns true on success. */
static bool run_accept_case(const mc_case_t *c) {
    dnac_merkle_digest_t root;
    dnac_merkle_tree_t  *tree = NULL;

    dnac_merkle_status_t rc = dnac_merkle_commit(
        c->rows_bytes, c->row_byte_len, (size_t)c->height, &root, &tree);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] commit failed with status=%d\n", c->name, rc);
        return false;
    }

    /* Compare root byte-for-byte. */
    if (memcmp(root.bytes, c->expected_root, 64) != 0) {
        fprintf(stderr, "[%s] root mismatch\n", c->name);
        print_hex_diff("root", c->expected_root, root.bytes, 64);
        dnac_merkle_tree_free(tree);
        return false;
    }

    /* Prepare proof buffer. */
    uint32_t depth = log2_pow2_u64(c->height);
    dnac_merkle_proof_t proof = {0};
    proof.depth = depth;
    proof.siblings = (depth == 0) ? NULL
        : (dnac_merkle_digest_t *)calloc(depth, sizeof(dnac_merkle_digest_t));
    if (depth > 0 && !proof.siblings) {
        fprintf(stderr, "[%s] OOM allocating proof siblings\n", c->name);
        dnac_merkle_tree_free(tree);
        return false;
    }

    const uint8_t *leaf_ptr = NULL;
    size_t leaf_len = 0;
    rc = dnac_merkle_open(tree, c->leaf_index, &leaf_ptr, &leaf_len, &proof);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] open failed with status=%d\n", c->name, rc);
        free(proof.siblings);
        dnac_merkle_tree_free(tree);
        return false;
    }

    /* Compare leaf bytes. */
    if (leaf_len != c->expected_leaf_len ||
        memcmp(leaf_ptr, c->expected_leaf, leaf_len) != 0) {
        fprintf(stderr, "[%s] leaf mismatch (len got=%zu expected=%zu)\n",
                c->name, leaf_len, c->expected_leaf_len);
        free(proof.siblings);
        dnac_merkle_tree_free(tree);
        return false;
    }

    /* Compare proof siblings. */
    if ((size_t)depth != c->expected_proof_count) {
        fprintf(stderr, "[%s] proof depth mismatch: got %u, expected %zu\n",
                c->name, depth, c->expected_proof_count);
        free(proof.siblings);
        dnac_merkle_tree_free(tree);
        return false;
    }
    for (uint32_t i = 0; i < depth; i++) {
        if (memcmp(proof.siblings[i].bytes,
                   c->expected_proof + i * 64, 64) != 0) {
            fprintf(stderr, "[%s] proof sibling[%u] mismatch\n", c->name, i);
            print_hex_diff("sibling", c->expected_proof + i * 64,
                           proof.siblings[i].bytes, 64);
            free(proof.siblings);
            dnac_merkle_tree_free(tree);
            return false;
        }
    }

    /* Verify against the committed root. */
    rc = dnac_merkle_verify(&root, leaf_ptr, leaf_len, &proof);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "[%s] verify failed with status=%d\n", c->name, rc);
        free(proof.siblings);
        dnac_merkle_tree_free(tree);
        return false;
    }

    free(proof.siblings);
    dnac_merkle_tree_free(tree);
    return true;
}

/* Run a reject case. Returns true if the expected error code is produced. */
static bool run_reject_case(const mc_case_t *c) {
    if (!c->tamper_type || !c->expected_error) {
        fprintf(stderr, "[%s] reject case missing tamper_type / expected_error\n",
                c->name);
        return false;
    }

    /* noncanonical_row → commit-time rejection BEFORE any hashing. */
    if (strcmp(c->tamper_type, "noncanonical_row") == 0) {
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t  *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(
            c->rows_bytes, c->row_byte_len, (size_t)c->height, &root, &tree);
        if (rc != DNAC_MERKLE_ERR_NONCANONICAL) {
            fprintf(stderr, "[%s] expected DNAC_MERKLE_ERR_NONCANONICAL, got %d\n",
                    c->name, rc);
            dnac_merkle_tree_free(tree);
            return false;
        }
        if (strcmp(c->expected_error, "DNAC_MERKLE_ERR_NONCANONICAL") != 0) {
            fprintf(stderr, "[%s] expected_error string mismatch: %s\n",
                    c->name, c->expected_error);
            return false;
        }
        return true;
    }

    /* All other tamper variants → use the JSON-recorded root/leaf/proof
     * directly through verify and expect ROOT_MISMATCH. */
    dnac_merkle_digest_t root;
    memcpy(root.bytes, c->expected_root, 64);

    uint32_t depth = log2_pow2_u64(c->height);
    if ((size_t)depth != c->expected_proof_count) {
        fprintf(stderr, "[%s] reject proof_count != log2(height): %zu vs %u\n",
                c->name, c->expected_proof_count, depth);
        return false;
    }

    dnac_merkle_proof_t proof = {0};
    proof.leaf_index = c->leaf_index;
    proof.depth      = depth;
    proof.siblings = (depth == 0) ? NULL
        : (dnac_merkle_digest_t *)calloc(depth, sizeof(dnac_merkle_digest_t));
    if (depth > 0 && !proof.siblings) {
        fprintf(stderr, "[%s] OOM allocating proof siblings\n", c->name);
        return false;
    }
    for (uint32_t i = 0; i < depth; i++) {
        memcpy(proof.siblings[i].bytes, c->expected_proof + i * 64, 64);
    }

    dnac_merkle_status_t rc = dnac_merkle_verify(
        &root, c->expected_leaf, c->expected_leaf_len, &proof);

    bool ok = false;
    if (rc == DNAC_MERKLE_ERR_ROOT_MISMATCH &&
        strcmp(c->expected_error, "DNAC_MERKLE_ERR_ROOT_MISMATCH") == 0) {
        ok = true;
    } else {
        fprintf(stderr, "[%s] expected %s, got status=%d\n",
                c->name, c->expected_error, rc);
    }

    free(proof.siblings);
    return ok;
}

/* ============================================================================
 * Determinism repeat — same input → byte-identical root × 100.
 * Picks a deterministic representative subset of the cases.
 * ========================================================================== */

static bool run_determinism_repeat(const mc_case_t *cases, size_t n_cases) {
    /* Pick at most 5 accept cases evenly spaced through the array. */
    size_t picked = 0;
    size_t indices[5] = {0};
    size_t step = (n_cases > 0) ? (n_cases / 5) : 0;
    if (step == 0) step = 1;
    for (size_t i = 0; i < n_cases && picked < 5; i += step) {
        if (strcmp(cases[i].expected_verify, "accept") == 0) {
            indices[picked++] = i;
        }
    }
    if (picked == 0) {
        fprintf(stderr, "WARN: no accept case found for determinism repeat\n");
        return true;
    }

    for (size_t k = 0; k < picked; k++) {
        const mc_case_t *c = &cases[indices[k]];
        dnac_merkle_digest_t baseline;
        bool baseline_set = false;
        for (int rep = 0; rep < 100; rep++) {
            dnac_merkle_digest_t root;
            dnac_merkle_tree_t  *tree = NULL;
            dnac_merkle_status_t rc = dnac_merkle_commit(
                c->rows_bytes, c->row_byte_len, (size_t)c->height,
                &root, &tree);
            if (rc != DNAC_MERKLE_OK) {
                fprintf(stderr, "[determinism %s rep %d] commit status=%d\n",
                        c->name, rep, rc);
                dnac_merkle_tree_free(tree);
                return false;
            }
            if (!baseline_set) {
                memcpy(baseline.bytes, root.bytes, 64);
                baseline_set = true;
            } else if (memcmp(baseline.bytes, root.bytes, 64) != 0) {
                fprintf(stderr, "[determinism %s rep %d] ROOT DIVERGED\n",
                        c->name, rep);
                dnac_merkle_tree_free(tree);
                return false;
            }
            dnac_merkle_tree_free(tree);
        }
    }
    return true;
}

/* ============================================================================
 * Negative input validation
 * ========================================================================== */

static bool run_negative_cases(void) {
    bool all_ok = true;

    /* (a) commit with NULL rows. */
    {
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(NULL, 8, 4, &root, &tree);
        if (rc != DNAC_MERKLE_ERR_NULL_ARG) {
            fprintf(stderr, "  neg[commit NULL rows]: expected NULL_ARG, got %d\n", rc);
            all_ok = false;
        }
    }
    /* (b) num_rows == 0. */
    {
        uint8_t junk[8] = {0};
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(junk, 8, 0, &root, &tree);
        if (rc != DNAC_MERKLE_ERR_BAD_HEIGHT) {
            fprintf(stderr, "  neg[commit num_rows=0]: expected BAD_HEIGHT, got %d\n", rc);
            all_ok = false;
        }
    }
    /* (c) num_rows not power of two. */
    {
        uint8_t junk[24] = {0}; /* 3 rows of 8 bytes */
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(junk, 8, 3, &root, &tree);
        if (rc != DNAC_MERKLE_ERR_BAD_HEIGHT) {
            fprintf(stderr, "  neg[commit num_rows=3]: expected BAD_HEIGHT, got %d\n", rc);
            all_ok = false;
        }
    }
    /* (d) row_byte_len not multiple of 8. */
    {
        uint8_t junk[12] = {0}; /* 4 rows of 3 bytes */
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(junk, 3, 4, &root, &tree);
        if (rc != DNAC_MERKLE_ERR_BAD_HEIGHT) {
            fprintf(stderr, "  neg[commit row_byte_len=3]: expected BAD_HEIGHT, got %d\n", rc);
            all_ok = false;
        }
    }
    /* (e) open with leaf_index >= num_rows. */
    {
        /* Build a valid 4-row tree first. */
        uint8_t rows[32] = {0};  /* 4 × 8 zero bytes — all canonical */
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        dnac_merkle_status_t rc = dnac_merkle_commit(rows, 8, 4, &root, &tree);
        if (rc != DNAC_MERKLE_OK) {
            fprintf(stderr, "  neg[setup for BAD_INDEX]: commit failed %d\n", rc);
            all_ok = false;
        } else {
            dnac_merkle_proof_t proof = {0};
            proof.depth = 2;
            dnac_merkle_digest_t sibs[2] = {{{0}}, {{0}}};
            proof.siblings = sibs;
            const uint8_t *lp = NULL;
            size_t ll = 0;
            rc = dnac_merkle_open(tree, 4, &lp, &ll, &proof);
            if (rc != DNAC_MERKLE_ERR_BAD_INDEX) {
                fprintf(stderr, "  neg[open leaf_index=4 of 4]: expected BAD_INDEX, got %d\n", rc);
                all_ok = false;
            }
            dnac_merkle_tree_free(tree);
        }
    }
    /* (f) verify with mismatched proof->depth. */
    {
        uint8_t rows[32] = {0};
        dnac_merkle_digest_t root;
        dnac_merkle_tree_t *tree = NULL;
        if (dnac_merkle_commit(rows, 8, 4, &root, &tree) == DNAC_MERKLE_OK) {
            dnac_merkle_proof_t proof = {0};
            proof.depth = 99;
            const uint8_t *lp = NULL;
            size_t ll = 0;
            dnac_merkle_status_t rc = dnac_merkle_open(tree, 0, &lp, &ll, &proof);
            if (rc != DNAC_MERKLE_ERR_BAD_DEPTH) {
                fprintf(stderr, "  neg[open depth=99]: expected BAD_DEPTH, got %d\n", rc);
                all_ok = false;
            }
            dnac_merkle_tree_free(tree);
        }
    }
    /* (g) verify NULL args. */
    {
        uint8_t leaf[8] = {0};
        dnac_merkle_proof_t proof = {0};
        proof.depth = 0;
        dnac_merkle_status_t rc = dnac_merkle_verify(NULL, leaf, 8, &proof);
        if (rc != DNAC_MERKLE_ERR_NULL_ARG) {
            fprintf(stderr, "  neg[verify NULL root]: expected NULL_ARG, got %d\n", rc);
            all_ok = false;
        }
    }
    /* (h) tree_free(NULL) — must not crash. */
    dnac_merkle_tree_free(NULL);

    return all_ok;
}

/* ============================================================================
 * Height=1 spot check — root == SHA3-512(row), proof empty.
 * ========================================================================== */

static bool run_height_one_check(const mc_case_t *cases, size_t n) {
    const mc_case_t *picked = NULL;
    for (size_t i = 0; i < n; i++) {
        if (cases[i].height == 1 &&
            strcmp(cases[i].expected_verify, "accept") == 0) {
            picked = &cases[i];
            break;
        }
    }
    if (!picked) {
        fprintf(stderr, "FAIL: no height=1 accept case in vector file\n");
        return false;
    }

    uint8_t direct[64];
    if (qgp_sha3_512(picked->rows_bytes, picked->row_byte_len, direct) != 0) {
        fprintf(stderr, "FAIL: qgp_sha3_512 on height=1 row returned non-zero\n");
        return false;
    }
    if (memcmp(direct, picked->expected_root, 64) != 0) {
        fprintf(stderr, "FAIL: height=1 root != SHA3-512(row) (oracle bug?)\n");
        return false;
    }
    if (picked->expected_proof_count != 0) {
        fprintf(stderr, "FAIL: height=1 proof not empty (got %zu siblings)\n",
                picked->expected_proof_count);
        return false;
    }

    /* Round-trip through merkle_smt and verify byte-match. */
    dnac_merkle_digest_t root;
    dnac_merkle_tree_t  *tree = NULL;
    dnac_merkle_status_t rc = dnac_merkle_commit(
        picked->rows_bytes, picked->row_byte_len, 1, &root, &tree);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "FAIL: height=1 commit returned %d\n", rc);
        return false;
    }
    if (memcmp(root.bytes, picked->expected_root, 64) != 0) {
        fprintf(stderr, "FAIL: height=1 commit root mismatch\n");
        dnac_merkle_tree_free(tree);
        return false;
    }
    dnac_merkle_proof_t proof = {0};
    proof.depth = 0;
    proof.siblings = NULL;
    const uint8_t *lp = NULL;
    size_t ll = 0;
    rc = dnac_merkle_open(tree, 0, &lp, &ll, &proof);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "FAIL: height=1 open returned %d\n", rc);
        dnac_merkle_tree_free(tree);
        return false;
    }
    rc = dnac_merkle_verify(&root, lp, ll, &proof);
    if (rc != DNAC_MERKLE_OK) {
        fprintf(stderr, "FAIL: height=1 verify returned %d\n", rc);
        dnac_merkle_tree_free(tree);
        return false;
    }
    dnac_merkle_tree_free(tree);
    return true;
}

/* ============================================================================
 * main
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <merkle_mmcs.json>\n", argv[0]);
        return 2;
    }

    /* (1) SHA3-512 KAT first. If the hash backend is wrong, nothing else
     *     is meaningful. */
    fprintf(stderr, "[merkle_mmcs] SHA3-512 empty-string KAT... ");
    if (!run_sha3_kat()) {
        fprintf(stderr, "FAIL\n");
        return 1;
    }
    fprintf(stderr, "PASS\n");

    /* (2) Slurp + parse JSON. */
    size_t blen = 0;
    char *blob = slurp(argv[1], &blen);
    if (!blob) return 2;

    js_t s = { blob, 0, blen };
    if (!js_match(&s, '{')) {
        fprintf(stderr, "FAIL: top-level not an object\n");
        free(blob);
        return 2;
    }
    /* Skip top-level metadata until we hit "cases": [ ... ]. */
    mc_case_t *cases = NULL;
    size_t n_cases = 0, cap_cases = 0;
    bool found_cases = false;
    while (1) {
        if (js_match(&s, '}')) break;
        if (js_peek(&s, ',')) { s.pos++; continue; }
        if (js_match_key(&s, "cases")) {
            if (!js_match(&s, '[')) {
                fprintf(stderr, "FAIL: cases not an array\n");
                free(blob);
                return 2;
            }
            found_cases = true;
            while (1) {
                if (js_match(&s, ']')) break;
                if (js_peek(&s, ',')) { s.pos++; continue; }
                if (n_cases == cap_cases) {
                    size_t newcap = cap_cases ? cap_cases * 2 : 128;
                    mc_case_t *g = (mc_case_t *)realloc(cases, newcap * sizeof(*cases));
                    if (!g) { fprintf(stderr, "OOM\n"); free(blob); return 2; }
                    cases = g;
                    cap_cases = newcap;
                }
                if (!parse_case(&s, &cases[n_cases])) {
                    fprintf(stderr, "FAIL: case parse error at index %zu\n", n_cases);
                    free(blob);
                    return 2;
                }
                n_cases++;
            }
        } else {
            /* unknown top-level field — skip its value. */
            char *key = js_read_string(&s);
            if (!key) { fprintf(stderr, "FAIL: top-level key parse\n"); free(blob); return 2; }
            free(key);
            if (!js_match(&s, ':')) { fprintf(stderr, "FAIL: top-level colon\n"); free(blob); return 2; }
            if (!js_skip_value(&s)) { fprintf(stderr, "FAIL: top-level value skip\n"); free(blob); return 2; }
        }
    }
    free(blob);
    if (!found_cases) {
        fprintf(stderr, "FAIL: no 'cases' field\n");
        return 2;
    }

    fprintf(stderr, "[merkle_mmcs] parsed %zu cases from %s\n", n_cases, argv[1]);

    /* (3) Iterate accept + reject. */
    size_t n_accept = 0, n_reject = 0;
    size_t n_accept_pass = 0, n_reject_pass = 0;
    for (size_t i = 0; i < n_cases; i++) {
        const mc_case_t *c = &cases[i];
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
    fprintf(stderr, "[merkle_mmcs] accept: %zu/%zu pass\n", n_accept_pass, n_accept);
    fprintf(stderr, "[merkle_mmcs] reject: %zu/%zu pass\n", n_reject_pass, n_reject);

    /* (4) Height=1 spot check. */
    fprintf(stderr, "[merkle_mmcs] height=1 spot check... ");
    bool h1_ok = run_height_one_check(cases, n_cases);
    fprintf(stderr, "%s\n", h1_ok ? "PASS" : "FAIL");

    /* (5) Determinism repeat × 100 across representative cases. */
    fprintf(stderr, "[merkle_mmcs] determinism repeat (5 cases × 100x)... ");
    bool det_ok = run_determinism_repeat(cases, n_cases);
    fprintf(stderr, "%s\n", det_ok ? "PASS" : "FAIL");

    /* (6) Negative input validation. */
    fprintf(stderr, "[merkle_mmcs] negative input validation... ");
    bool neg_ok = run_negative_cases();
    fprintf(stderr, "%s\n", neg_ok ? "PASS" : "FAIL");

    /* Cleanup. */
    for (size_t i = 0; i < n_cases; i++) mc_case_free(&cases[i]);
    free(cases);

    bool all_ok = (n_accept_pass == n_accept)
               && (n_reject_pass == n_reject)
               && h1_ok && det_ok && neg_ok;

    if (all_ok) {
        fprintf(stderr, "[merkle_mmcs] ALL GATES GREEN — %zu cases passed\n",
                n_accept + n_reject);
        return 0;
    } else {
        fprintf(stderr, "[merkle_mmcs] GATE FAILURE\n");
        return 1;
    }
}
