/**
 * @file test_transcript_oracle.c
 * @brief Phase T3 — DNAC C transcript byte-equivalence gate against
 *        the Plonky3-grounded transcript.json oracle.
 *
 * Loads `tools/vectors/transcript.json` and, for every case, replays the
 * op stream against `dnac_transcript_t`. After each op, compares the
 * snapshot triple (input_buf, output_buf_remaining, result) against the
 * JSON-recorded values byte-for-byte. After the last op, also compares
 * the case-level `final_input_buf` and `final_output_buf_remaining`.
 *
 * Compile with -DDNAC_TRANSCRIPT_TESTING=1 to enable the transcript
 * state-inspection helpers used here.
 *
 * Exit codes:
 *   0  all cases passed
 *   1  at least one mismatch
 *   2  load / parse error
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define DNAC_TRANSCRIPT_TESTING 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "../transcript.h"

/* ============================================================================
 * Minimal JSON scanner — same shape as test_primitive_oracle.c.
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

/** Read a "..." string into a newly malloc'd zero-terminated buffer. */
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

static bool js_read_u64_string(js_t *s, uint64_t *out) {
    char *str = js_read_string(s);
    if (!str) return false;
    char *endp = NULL;
    *out = strtoull(str, &endp, 10);
    bool ok = (endp != NULL && *endp == '\0');
    free(str);
    return ok;
}

/** Read an unquoted JSON number into size_t. */
static bool js_read_size(js_t *s, size_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (size_t)v;
    return true;
}

/** Read true / false. */
static bool js_read_bool(js_t *s, bool *out) {
    js_skip_ws(s);
    if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "true", 4) == 0) {
        s->pos += 4; *out = true; return true;
    }
    if (s->pos + 5 <= s->len && memcmp(s->src + s->pos, "false", 5) == 0) {
        s->pos += 5; *out = false; return true;
    }
    return false;
}

/** Skip a single JSON value of any shape (used to skip uninteresting fields). */
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
    if (c == 't' || c == 'f') { bool b; return js_read_bool(s, &b); }
    if (c == 'n') {
        if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "null", 4) == 0) {
            s->pos += 4; return true;
        }
        return false;
    }
    /* number */
    while (s->pos < s->len) {
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' || d == 'e' || d == 'E') {
            s->pos++;
        } else break;
    }
    return true;
}

/* ============================================================================
 * Hex decoder
 * ========================================================================== */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Hex-decode `hex` into a newly malloc'd buffer; sets *out_len.
 *  Returns NULL on parse failure. Empty hex string → out_len=0 and a
 *  malloc(1) zero-byte buffer (so caller can always free). */
static uint8_t *hex_decode(const char *hex, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return NULL;
    size_t blen = hlen / 2;
    uint8_t *out = (uint8_t *)malloc(blen + 1);
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

/* ============================================================================
 * Data model
 * ========================================================================== */

typedef enum {
    OP_OBSERVE_BYTES,
    OP_OBSERVE_FP,
    OP_OBSERVE_FP2,
    OP_SAMPLE_FP,
    OP_SAMPLE_FP2,
    OP_SAMPLE_BITS,
    OP_CHECK_WITNESS,
} op_kind_t;

typedef struct {
    op_kind_t kind;
    uint8_t  *bytes;      /* observe_bytes */
    size_t    bytes_len;
    uint64_t  value_u64;  /* observe_fp */
    uint64_t  c0_u64;     /* observe_fp2 */
    uint64_t  c1_u64;
    size_t    bits;       /* sample_bits / check_witness */
    uint64_t  witness_u64;/* check_witness */
} op_t;

typedef enum {
    R_NONE = 0, R_FP, R_FP2, R_BITS, R_BOOL,
} result_kind_t;

typedef struct {
    result_kind_t kind;
    uint64_t u64_value;
    uint64_t c0_u64;
    uint64_t c1_u64;
    bool     boolean;
} result_t;

typedef struct {
    size_t   after_op;
    uint8_t *input_buf;            size_t input_buf_len;
    uint8_t *output_buf_remaining; size_t output_remaining_len;
    result_t result;               bool    has_result;
} snapshot_t;

typedef struct {
    char    *name;
    uint8_t *init_state;                   size_t init_state_len;
    op_t    *ops;                          size_t n_ops;
    snapshot_t *snapshots;                 size_t n_snapshots;
    uint8_t *final_input_buf;              size_t final_input_buf_len;
    uint8_t *final_output_buf_remaining;   size_t final_output_remaining_len;
} case_t;

static void op_free(op_t *o) { free(o->bytes); o->bytes = NULL; }
static void snapshot_free(snapshot_t *s) {
    free(s->input_buf);
    free(s->output_buf_remaining);
    s->input_buf = NULL;
    s->output_buf_remaining = NULL;
}
static void case_free(case_t *c) {
    free(c->name);
    free(c->init_state);
    for (size_t i = 0; i < c->n_ops; i++) op_free(&c->ops[i]);
    free(c->ops);
    for (size_t i = 0; i < c->n_snapshots; i++) snapshot_free(&c->snapshots[i]);
    free(c->snapshots);
    free(c->final_input_buf);
    free(c->final_output_buf_remaining);
    memset(c, 0, sizeof(*c));
}

/* ============================================================================
 * Parsers
 * ========================================================================== */

/** Parse one op object: { "op": "...", ... }. Returns true on success. */
static bool parse_op(js_t *s, op_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    char *op_name = NULL;
    /* Variant field staging. */
    char *bytes_hex = NULL;
    uint64_t value_u64 = 0;     bool has_value_u64 = false;
    uint64_t c0_u64 = 0;        bool has_c0 = false;
    uint64_t c1_u64 = 0;        bool has_c1 = false;
    size_t   bits = 0;          bool has_bits = false;
    uint64_t witness_u64 = 0;   bool has_witness = false;

    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }

        if (js_match_key(s, "op")) {
            op_name = js_read_string(s);
            if (!op_name) goto fail;
        } else if (js_match_key(s, "bytes")) {
            bytes_hex = js_read_string(s);
            if (!bytes_hex) goto fail;
        } else if (js_match_key(s, "value_u64")) {
            if (!js_read_u64_string(s, &value_u64)) goto fail;
            has_value_u64 = true;
        } else if (js_match_key(s, "c0_u64")) {
            if (!js_read_u64_string(s, &c0_u64)) goto fail;
            has_c0 = true;
        } else if (js_match_key(s, "c1_u64")) {
            if (!js_read_u64_string(s, &c1_u64)) goto fail;
            has_c1 = true;
        } else if (js_match_key(s, "bits")) {
            if (!js_read_size(s, &bits)) goto fail;
            has_bits = true;
        } else if (js_match_key(s, "witness_u64")) {
            if (!js_read_u64_string(s, &witness_u64)) goto fail;
            has_witness = true;
        } else {
            /* Unknown field — consume key, colon, value to stay forward-compatible. */
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }

    if (!op_name) goto fail;

    if (strcmp(op_name, "observe_bytes") == 0) {
        out->kind = OP_OBSERVE_BYTES;
        if (!bytes_hex) goto fail;
        out->bytes = hex_decode(bytes_hex, &out->bytes_len);
        if (!out->bytes) goto fail;
    } else if (strcmp(op_name, "observe_fp") == 0) {
        out->kind = OP_OBSERVE_FP;
        if (!has_value_u64) goto fail;
        out->value_u64 = value_u64;
    } else if (strcmp(op_name, "observe_fp2") == 0) {
        out->kind = OP_OBSERVE_FP2;
        if (!has_c0 || !has_c1) goto fail;
        out->c0_u64 = c0_u64;
        out->c1_u64 = c1_u64;
    } else if (strcmp(op_name, "sample_fp") == 0) {
        out->kind = OP_SAMPLE_FP;
    } else if (strcmp(op_name, "sample_fp2") == 0) {
        out->kind = OP_SAMPLE_FP2;
    } else if (strcmp(op_name, "sample_bits") == 0) {
        out->kind = OP_SAMPLE_BITS;
        if (!has_bits) goto fail;
        out->bits = bits;
    } else if (strcmp(op_name, "check_witness") == 0) {
        out->kind = OP_CHECK_WITNESS;
        if (!has_bits || !has_witness) goto fail;
        out->bits = bits;
        out->witness_u64 = witness_u64;
    } else {
        fprintf(stderr, "unknown op kind: %s\n", op_name);
        goto fail;
    }

    free(op_name);
    free(bytes_hex);
    return true;

fail:
    free(op_name);
    free(bytes_hex);
    op_free(out);
    return false;
}

/** Parse one result object: { "kind": "...", ... }. */
static bool parse_result(js_t *s, result_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    char *kind = NULL;
    uint64_t u64_value = 0;  bool has_u64_value = false;
    uint64_t c0_u64 = 0;     bool has_c0 = false;
    uint64_t c1_u64 = 0;     bool has_c1 = false;
    bool boolean = false;    bool has_boolean = false;

    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }

        if (js_match_key(s, "kind")) {
            kind = js_read_string(s);
            if (!kind) goto fail;
        } else if (js_match_key(s, "u64_value")) {
            if (!js_read_u64_string(s, &u64_value)) goto fail;
            has_u64_value = true;
        } else if (js_match_key(s, "c0_u64")) {
            if (!js_read_u64_string(s, &c0_u64)) goto fail;
            has_c0 = true;
        } else if (js_match_key(s, "c1_u64")) {
            if (!js_read_u64_string(s, &c1_u64)) goto fail;
            has_c1 = true;
        } else if (js_match_key(s, "value")) {
            if (!js_read_bool(s, &boolean)) goto fail;
            has_boolean = true;
        } else {
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }
    if (!kind) goto fail;

    if (strcmp(kind, "fp") == 0) {
        if (!has_u64_value) goto fail;
        out->kind = R_FP; out->u64_value = u64_value;
    } else if (strcmp(kind, "fp2") == 0) {
        if (!has_c0 || !has_c1) goto fail;
        out->kind = R_FP2; out->c0_u64 = c0_u64; out->c1_u64 = c1_u64;
    } else if (strcmp(kind, "bits") == 0) {
        if (!has_u64_value) goto fail;
        out->kind = R_BITS; out->u64_value = u64_value;
    } else if (strcmp(kind, "bool") == 0) {
        if (!has_boolean) goto fail;
        out->kind = R_BOOL; out->boolean = boolean;
    } else {
        fprintf(stderr, "unknown result kind: %s\n", kind);
        goto fail;
    }
    free(kind);
    return true;
fail:
    free(kind);
    return false;
}

/** Parse one snapshot object. */
static bool parse_snapshot(js_t *s, snapshot_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    char *input_buf_hex = NULL;
    char *output_buf_hex = NULL;

    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }

        if (js_match_key(s, "after_op")) {
            if (!js_read_size(s, &out->after_op)) goto fail;
        } else if (js_match_key(s, "input_buf")) {
            input_buf_hex = js_read_string(s);
            if (!input_buf_hex) goto fail;
        } else if (js_match_key(s, "output_buf_remaining")) {
            output_buf_hex = js_read_string(s);
            if (!output_buf_hex) goto fail;
        } else if (js_match_key(s, "result")) {
            /* `null` or { ... }. */
            js_skip_ws(s);
            if (s->pos + 4 <= s->len && memcmp(s->src + s->pos, "null", 4) == 0) {
                s->pos += 4;
                out->has_result = false;
            } else {
                if (!parse_result(s, &out->result)) goto fail;
                out->has_result = true;
            }
        } else {
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }

    if (!input_buf_hex || !output_buf_hex) goto fail;
    out->input_buf = hex_decode(input_buf_hex, &out->input_buf_len);
    out->output_buf_remaining = hex_decode(output_buf_hex, &out->output_remaining_len);
    if (!out->input_buf || !out->output_buf_remaining) goto fail;

    free(input_buf_hex);
    free(output_buf_hex);
    return true;
fail:
    free(input_buf_hex);
    free(output_buf_hex);
    snapshot_free(out);
    return false;
}

/** Append-grow utility for op arrays. */
static op_t *append_op(op_t *arr, size_t *n, size_t *cap, const op_t *new_op) {
    if (*n == *cap) {
        size_t nc = (*cap == 0) ? 8 : (*cap * 2);
        op_t *na = (op_t *)realloc(arr, nc * sizeof(op_t));
        if (!na) return NULL;
        arr = na; *cap = nc;
    }
    arr[*n] = *new_op;
    (*n)++;
    return arr;
}

static snapshot_t *append_snapshot(snapshot_t *arr, size_t *n, size_t *cap, const snapshot_t *snap) {
    if (*n == *cap) {
        size_t nc = (*cap == 0) ? 8 : (*cap * 2);
        snapshot_t *na = (snapshot_t *)realloc(arr, nc * sizeof(snapshot_t));
        if (!na) return NULL;
        arr = na; *cap = nc;
    }
    arr[*n] = *snap;
    (*n)++;
    return arr;
}

/** Parse one case object. */
static bool parse_case(js_t *s, case_t *out) {
    memset(out, 0, sizeof(*out));
    if (!js_match(s, '{')) return false;

    char *init_hex = NULL;
    char *final_in_hex = NULL;
    char *final_out_hex = NULL;

    while (1) {
        if (js_match(s, '}')) break;
        if (js_peek(s, ',')) { s->pos++; continue; }

        if (js_match_key(s, "name")) {
            out->name = js_read_string(s);
            if (!out->name) goto fail;
        } else if (js_match_key(s, "init_state")) {
            init_hex = js_read_string(s);
            if (!init_hex) goto fail;
        } else if (js_match_key(s, "ops")) {
            if (!js_match(s, '[')) goto fail;
            size_t cap = 0;
            while (1) {
                if (js_match(s, ']')) break;
                if (js_peek(s, ',')) { s->pos++; continue; }
                op_t op_local;
                if (!parse_op(s, &op_local)) goto fail;
                op_t *na = append_op(out->ops, &out->n_ops, &cap, &op_local);
                if (!na) { op_free(&op_local); goto fail; }
                out->ops = na;
            }
        } else if (js_match_key(s, "snapshots")) {
            if (!js_match(s, '[')) goto fail;
            size_t cap = 0;
            while (1) {
                if (js_match(s, ']')) break;
                if (js_peek(s, ',')) { s->pos++; continue; }
                snapshot_t snap_local;
                if (!parse_snapshot(s, &snap_local)) goto fail;
                snapshot_t *na = append_snapshot(out->snapshots, &out->n_snapshots, &cap, &snap_local);
                if (!na) { snapshot_free(&snap_local); goto fail; }
                out->snapshots = na;
            }
        } else if (js_match_key(s, "final_input_buf")) {
            final_in_hex = js_read_string(s);
            if (!final_in_hex) goto fail;
        } else if (js_match_key(s, "final_output_buf_remaining")) {
            final_out_hex = js_read_string(s);
            if (!final_out_hex) goto fail;
        } else {
            /* description and any other future fields — consume key+colon+value. */
            char *unknown = js_read_string(s);
            if (!unknown) goto fail;
            free(unknown);
            if (!js_match(s, ':')) goto fail;
            if (!js_skip_value(s)) goto fail;
        }
    }

    if (!out->name) goto fail;
    if (!init_hex) goto fail;
    out->init_state = hex_decode(init_hex, &out->init_state_len);
    if (!out->init_state) goto fail;

    if (final_in_hex) {
        out->final_input_buf = hex_decode(final_in_hex, &out->final_input_buf_len);
        if (!out->final_input_buf) goto fail;
    }
    if (final_out_hex) {
        out->final_output_buf_remaining = hex_decode(final_out_hex, &out->final_output_remaining_len);
        if (!out->final_output_buf_remaining) goto fail;
    }

    free(init_hex);
    free(final_in_hex);
    free(final_out_hex);
    return true;
fail:
    free(init_hex);
    free(final_in_hex);
    free(final_out_hex);
    case_free(out);
    return false;
}

/* ============================================================================
 * File loader
 * ========================================================================== */

static char *load_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
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
    *len_out = (size_t)sz;
    return buf;
}

/* ============================================================================
 * Reporters — print mismatch diagnostics in a consistent shape.
 * ========================================================================== */

static void print_hex_prefix(const uint8_t *b, size_t len, size_t limit) {
    size_t cap = (len < limit) ? len : limit;
    for (size_t i = 0; i < cap; i++) printf("%02x", b[i]);
    if (len > cap) printf("…(+%zu)", len - cap);
}

static void report_bytes_mismatch(const char *case_name, size_t op_idx,
                                  const char *field,
                                  const uint8_t *expected, size_t expected_len,
                                  const uint8_t *actual,   size_t actual_len) {
    printf("\n  MISMATCH: case=%s op=%zu field=%s\n", case_name, op_idx, field);
    printf("    expected (%zu bytes): ", expected_len);
    print_hex_prefix(expected, expected_len, 64);
    printf("\n");
    printf("    actual   (%zu bytes): ", actual_len);
    print_hex_prefix(actual, actual_len, 64);
    printf("\n");
    /* Find first diverging byte */
    size_t lim = (expected_len < actual_len) ? expected_len : actual_len;
    for (size_t i = 0; i < lim; i++) {
        if (expected[i] != actual[i]) {
            printf("    first diff at byte %zu: expected=%02x actual=%02x\n",
                   i, expected[i], actual[i]);
            return;
        }
    }
    if (expected_len != actual_len) {
        printf("    length differs: expected=%zu actual=%zu\n", expected_len, actual_len);
    }
}

static const char *result_kind_name(result_kind_t k) {
    switch (k) {
        case R_NONE: return "none";
        case R_FP:   return "fp";
        case R_FP2:  return "fp2";
        case R_BITS: return "bits";
        case R_BOOL: return "bool";
    }
    return "?";
}

static void report_result_mismatch(const char *case_name, size_t op_idx,
                                   const result_t *expected, bool has_expected,
                                   const result_t *actual,   bool has_actual) {
    printf("\n  MISMATCH: case=%s op=%zu field=result\n", case_name, op_idx);
    if (has_expected) {
        printf("    expected kind=%s", result_kind_name(expected->kind));
        switch (expected->kind) {
            case R_FP:   case R_BITS: printf(" u64=%" PRIu64, expected->u64_value); break;
            case R_FP2:  printf(" c0=%" PRIu64 " c1=%" PRIu64, expected->c0_u64, expected->c1_u64); break;
            case R_BOOL: printf(" value=%s", expected->boolean ? "true" : "false"); break;
            case R_NONE: break;
        }
        printf("\n");
    } else {
        printf("    expected: <no result>\n");
    }
    if (has_actual) {
        printf("    actual   kind=%s", result_kind_name(actual->kind));
        switch (actual->kind) {
            case R_FP:   case R_BITS: printf(" u64=%" PRIu64, actual->u64_value); break;
            case R_FP2:  printf(" c0=%" PRIu64 " c1=%" PRIu64, actual->c0_u64, actual->c1_u64); break;
            case R_BOOL: printf(" value=%s", actual->boolean ? "true" : "false"); break;
            case R_NONE: break;
        }
        printf("\n");
    } else {
        printf("    actual:   <no result>\n");
    }
}

static bool results_match(const result_t *a, const result_t *b) {
    if (a->kind != b->kind) return false;
    switch (a->kind) {
        case R_FP:   case R_BITS: return a->u64_value == b->u64_value;
        case R_FP2:  return a->c0_u64 == b->c0_u64 && a->c1_u64 == b->c1_u64;
        case R_BOOL: return a->boolean == b->boolean;
        case R_NONE: return true;
    }
    return false;
}

/* ============================================================================
 * Op runner
 * ========================================================================== */

/** Run one op against `t`, capture any result. Returns true if op produced a result. */
static bool run_op(dnac_transcript_t *t, const op_t *op, result_t *got) {
    memset(got, 0, sizeof(*got));
    got->kind = R_NONE;
    switch (op->kind) {
        case OP_OBSERVE_BYTES:
            dnac_transcript_observe_bytes(t, op->bytes, op->bytes_len);
            return false;
        case OP_OBSERVE_FP: {
            fp_t v; v.v = op->value_u64;
            dnac_transcript_observe_fp(t, v);
            return false;
        }
        case OP_OBSERVE_FP2: {
            fp2_t v;
            v.a.v = op->c0_u64;
            v.b.v = op->c1_u64;
            dnac_transcript_observe_fp2(t, v);
            return false;
        }
        case OP_SAMPLE_FP: {
            fp_t v = dnac_transcript_sample_fp(t);
            got->kind = R_FP;
            got->u64_value = v.v;
            return true;
        }
        case OP_SAMPLE_FP2: {
            fp2_t v = dnac_transcript_sample_fp2(t);
            got->kind = R_FP2;
            got->c0_u64 = v.a.v;
            got->c1_u64 = v.b.v;
            return true;
        }
        case OP_SAMPLE_BITS: {
            uint64_t b = dnac_transcript_sample_bits(t, op->bits);
            got->kind = R_BITS;
            got->u64_value = b;
            return true;
        }
        case OP_CHECK_WITNESS: {
            fp_t w; w.v = op->witness_u64;
            bool ok = dnac_transcript_check_witness(t, op->bits, w);
            got->kind = R_BOOL;
            got->boolean = ok;
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Case runner
 * ========================================================================== */

static int run_case(const case_t *c) {
    dnac_transcript_t *t = dnac_transcript_init(c->init_state, c->init_state_len);
    if (!t) {
        fprintf(stderr, "case %s: dnac_transcript_init failed\n", c->name);
        return -1;
    }

    int errors = 0;
    if (c->n_snapshots != c->n_ops) {
        printf("\n  case=%s: snapshot/op count mismatch (snap=%zu ops=%zu)\n",
               c->name, c->n_snapshots, c->n_ops);
        errors++;
    }

    for (size_t i = 0; i < c->n_ops; i++) {
        const op_t       *op   = &c->ops[i];
        const snapshot_t *snap = (i < c->n_snapshots) ? &c->snapshots[i] : NULL;

        result_t got;
        bool has_got = run_op(t, op, &got);

        if (!snap) continue;

        /* Compare input_buf. */
        const uint8_t *got_input     = dnac_transcript_test_input_buf_ptr(t);
        size_t         got_input_len = dnac_transcript_test_input_buf_len(t);
        if (got_input_len != snap->input_buf_len ||
            (got_input_len > 0 && memcmp(got_input, snap->input_buf, got_input_len) != 0)) {
            report_bytes_mismatch(c->name, i, "input_buf",
                                  snap->input_buf, snap->input_buf_len,
                                  got_input, got_input_len);
            errors++;
        }

        /* Compare output_buf_remaining. */
        const uint8_t *got_out     = dnac_transcript_test_output_buf_ptr(t);
        size_t         got_out_len = dnac_transcript_test_output_buf_remaining(t);
        if (got_out_len != snap->output_remaining_len ||
            (got_out_len > 0 && memcmp(got_out, snap->output_buf_remaining, got_out_len) != 0)) {
            report_bytes_mismatch(c->name, i, "output_buf_remaining",
                                  snap->output_buf_remaining, snap->output_remaining_len,
                                  got_out, got_out_len);
            errors++;
        }

        /* Compare result. */
        if (has_got != snap->has_result ||
            (has_got && !results_match(&got, &snap->result))) {
            report_result_mismatch(c->name, i,
                                   &snap->result, snap->has_result,
                                   &got,          has_got);
            errors++;
        }
    }

    /* Compare final_input_buf. */
    if (c->final_input_buf) {
        const uint8_t *got_input     = dnac_transcript_test_input_buf_ptr(t);
        size_t         got_input_len = dnac_transcript_test_input_buf_len(t);
        if (got_input_len != c->final_input_buf_len ||
            (got_input_len > 0 && memcmp(got_input, c->final_input_buf, got_input_len) != 0)) {
            report_bytes_mismatch(c->name, c->n_ops, "final_input_buf",
                                  c->final_input_buf, c->final_input_buf_len,
                                  got_input, got_input_len);
            errors++;
        }
    }

    /* Compare final_output_buf_remaining. */
    if (c->final_output_buf_remaining) {
        const uint8_t *got_out     = dnac_transcript_test_output_buf_ptr(t);
        size_t         got_out_len = dnac_transcript_test_output_buf_remaining(t);
        if (got_out_len != c->final_output_remaining_len ||
            (got_out_len > 0 && memcmp(got_out, c->final_output_buf_remaining, got_out_len) != 0)) {
            report_bytes_mismatch(c->name, c->n_ops, "final_output_buf_remaining",
                                  c->final_output_buf_remaining, c->final_output_remaining_len,
                                  got_out, got_out_len);
            errors++;
        }
    }

    dnac_transcript_free(t);
    return errors;
}

/* ============================================================================
 * Top-level scanner: locate "cases": [ ... ] and iterate.
 * ========================================================================== */

static bool seek_cases_array(js_t *s) {
    /* Linear scan for `"cases"` followed by `:` `[`. */
    const char *key = "\"cases\"";
    size_t klen = strlen(key);
    s->pos = 0;
    while (s->pos + klen < s->len) {
        if (memcmp(s->src + s->pos, key, klen) == 0) {
            s->pos += klen;
            js_skip_ws(s);
            if (!js_match(s, ':')) continue;
            js_skip_ws(s);
            if (!js_match(s, '[')) continue;
            return true;
        }
        s->pos++;
    }
    return false;
}

/* ============================================================================
 * main
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <transcript.json>\n", argv[0]);
        return 2;
    }

    size_t flen = 0;
    char *src = load_file(argv[1], &flen);
    if (!src) {
        fprintf(stderr, "load_file failed: %s\n", argv[1]);
        return 2;
    }

    js_t s = { .src = src, .pos = 0, .len = flen };
    if (!seek_cases_array(&s)) {
        fprintf(stderr, "failed to locate \"cases\" array\n");
        free(src);
        return 2;
    }

    printf("============================================================\n");
    printf("Phase T3 — DNAC transcript C oracle replay (Plonky3 commit 82cfad73)\n");
    printf("           %s\n", argv[1]);
    printf("============================================================\n");

    int total_cases = 0;
    int passed = 0;
    int failed = 0;
    int total_ops_checked = 0;

    while (1) {
        if (js_match(&s, ']')) break;
        if (js_peek(&s, ',')) { s.pos++; continue; }

        case_t c;
        if (!parse_case(&s, &c)) {
            fprintf(stderr, "parse_case failed at pos %zu\n", s.pos);
            free(src);
            return 2;
        }

        int errs = run_case(&c);
        total_cases++;
        total_ops_checked += (int)c.n_ops;
        if (errs == 0) {
            printf("  %-44s PASS  (%zu ops)\n", c.name, c.n_ops);
            passed++;
        } else {
            printf("  %-44s FAIL  (%d mismatches)\n", c.name, errs);
            failed++;
        }
        case_free(&c);
    }

    free(src);

    printf("\nTotal: %d cases (%d ops), %d passed, %d failed\n",
           total_cases, total_ops_checked, passed, failed);
    if (failed > 0) {
        printf("PHASE T3 ORACLE GATE: RED\n");
        return 1;
    }
    printf("PHASE T3 ORACLE GATE: GREEN\n");
    return 0;
}
