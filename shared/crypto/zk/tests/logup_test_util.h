/**
 * @file logup_test_util.h
 * @brief Shared test-only helpers for the LogUp KATs (test_logup,
 *        test_logup_bus): a minimal JSON DOM parser, fp2 decoding, file
 *        loading, and expression-pool building from the oracle expr JSON.
 *
 * Test-local header — NOT part of the zk library surface. All functions are
 * `static inline` so unused ones in a given test TU do not warn.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_LOGUP_TEST_UTIL_H
#define DNAC_LOGUP_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../logup.h"

/* ============================================================================
 * Minimal JSON DOM (order-agnostic; enough for the logup vectors: no float
 * semantics needed, strings without escape decoding — escaped chars are
 * skipped verbatim)
 * ========================================================================== */
typedef enum { JV_NULL, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ } jv_kind_t;

typedef struct jv {
    jv_kind_t kind;
    bool bval;
    char *str; /* NUM: raw token; STR: contents */
    struct jv **items;
    size_t n;
    char **keys;
    struct jv **vals;
    size_t nk;
} jv_t;

typedef struct {
    const char *s;
    size_t pos, len;
} jp_t;

static inline void jp_ws(jp_t *p)
{
    while (p->pos < p->len) {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p->pos++;
        else return;
    }
}

static inline jv_t *jv_alloc(jv_kind_t k)
{
    jv_t *v = (jv_t *)calloc(1, sizeof(jv_t));
    if (v) v->kind = k;
    return v;
}

static inline void jv_free(jv_t *v)
{
    if (!v) return;
    free(v->str);
    for (size_t i = 0; i < v->n; i++) jv_free(v->items[i]);
    free(v->items);
    for (size_t i = 0; i < v->nk; i++) {
        free(v->keys[i]);
        jv_free(v->vals[i]);
    }
    free(v->keys);
    free(v->vals);
    free(v);
}

static inline char *jp_string(jp_t *p)
{
    if (p->s[p->pos] != '"') return NULL;
    p->pos++;
    size_t start = p->pos;
    while (p->pos < p->len && p->s[p->pos] != '"') {
        if (p->s[p->pos] == '\\') p->pos++; /* skip escaped char verbatim */
        p->pos++;
    }
    if (p->pos >= p->len) return NULL;
    size_t slen = p->pos - start;
    p->pos++;
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, p->s + start, slen);
    out[slen] = '\0';
    return out;
}

static inline jv_t *jp_value(jp_t *p);

static inline jv_t *jp_array(jp_t *p)
{
    jv_t *v = jv_alloc(JV_ARR);
    if (!v) return NULL;
    p->pos++; /* '[' */
    jp_ws(p);
    if (p->pos < p->len && p->s[p->pos] == ']') { p->pos++; return v; }
    size_t cap = 8;
    v->items = (jv_t **)malloc(cap * sizeof(jv_t *));
    if (!v->items) { jv_free(v); return NULL; }
    while (1) {
        jv_t *it = jp_value(p);
        if (!it) { jv_free(v); return NULL; }
        if (v->n == cap) {
            cap *= 2;
            jv_t **ni = (jv_t **)realloc(v->items, cap * sizeof(jv_t *));
            if (!ni) { jv_free(it); jv_free(v); return NULL; }
            v->items = ni;
        }
        v->items[v->n++] = it;
        jp_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
        if (p->pos < p->len && p->s[p->pos] == ']') { p->pos++; return v; }
        jv_free(v);
        return NULL;
    }
}

static inline jv_t *jp_object(jp_t *p)
{
    jv_t *v = jv_alloc(JV_OBJ);
    if (!v) return NULL;
    p->pos++; /* '{' */
    jp_ws(p);
    if (p->pos < p->len && p->s[p->pos] == '}') { p->pos++; return v; }
    size_t cap = 8;
    v->keys = (char **)malloc(cap * sizeof(char *));
    v->vals = (jv_t **)malloc(cap * sizeof(jv_t *));
    if (!v->keys || !v->vals) { jv_free(v); return NULL; }
    while (1) {
        jp_ws(p);
        char *k = jp_string(p);
        if (!k) { jv_free(v); return NULL; }
        jp_ws(p);
        if (p->pos >= p->len || p->s[p->pos] != ':') { free(k); jv_free(v); return NULL; }
        p->pos++;
        jv_t *val = jp_value(p);
        if (!val) { free(k); jv_free(v); return NULL; }
        if (v->nk == cap) {
            cap *= 2;
            char **nk = (char **)realloc(v->keys, cap * sizeof(char *));
            jv_t **nv = (jv_t **)realloc(v->vals, cap * sizeof(jv_t *));
            if (!nk || !nv) {
                if (nk) v->keys = nk;
                if (nv) v->vals = nv;
                free(k); jv_free(val); jv_free(v);
                return NULL;
            }
            v->keys = nk;
            v->vals = nv;
        }
        v->keys[v->nk] = k;
        v->vals[v->nk] = val;
        v->nk++;
        jp_ws(p);
        if (p->pos < p->len && p->s[p->pos] == ',') { p->pos++; continue; }
        if (p->pos < p->len && p->s[p->pos] == '}') { p->pos++; return v; }
        jv_free(v);
        return NULL;
    }
}

static inline jv_t *jp_value(jp_t *p)
{
    jp_ws(p);
    if (p->pos >= p->len) return NULL;
    char c = p->s[p->pos];
    if (c == '{') return jp_object(p);
    if (c == '[') return jp_array(p);
    if (c == '"') {
        jv_t *v = jv_alloc(JV_STR);
        if (!v) return NULL;
        v->str = jp_string(p);
        if (!v->str) { jv_free(v); return NULL; }
        return v;
    }
    if (!strncmp(p->s + p->pos, "null", 4)) { p->pos += 4; return jv_alloc(JV_NULL); }
    if (!strncmp(p->s + p->pos, "true", 4)) {
        p->pos += 4;
        jv_t *v = jv_alloc(JV_BOOL);
        if (v) v->bval = true;
        return v;
    }
    if (!strncmp(p->s + p->pos, "false", 5)) {
        p->pos += 5;
        jv_t *v = jv_alloc(JV_BOOL);
        if (v) v->bval = false;
        return v;
    }
    /* number */
    size_t start = p->pos;
    if (c == '-') p->pos++;
    while (p->pos < p->len &&
           ((p->s[p->pos] >= '0' && p->s[p->pos] <= '9') || p->s[p->pos] == '.' ||
            p->s[p->pos] == 'e' || p->s[p->pos] == 'E' || p->s[p->pos] == '+' ||
            p->s[p->pos] == '-')) {
        p->pos++;
    }
    if (p->pos == start) return NULL;
    jv_t *v = jv_alloc(JV_NUM);
    if (!v) return NULL;
    v->str = (char *)malloc(p->pos - start + 1);
    if (!v->str) { jv_free(v); return NULL; }
    memcpy(v->str, p->s + start, p->pos - start);
    v->str[p->pos - start] = '\0';
    return v;
}

static inline const jv_t *jv_get(const jv_t *obj, const char *key)
{
    if (!obj || obj->kind != JV_OBJ) return NULL;
    for (size_t i = 0; i < obj->nk; i++) {
        if (!strcmp(obj->keys[i], key)) return obj->vals[i];
    }
    return NULL;
}

static inline bool jv_u64(const jv_t *v, uint64_t *out)
{
    if (!v || (v->kind != JV_NUM && v->kind != JV_STR) || !v->str) return false;
    char *end = NULL;
    *out = strtoull(v->str, &end, 10);
    return end && *end == '\0';
}

static inline bool jv_fp2(const jv_t *v, gold_fp2_t *out)
{
    uint64_t a, b;
    if (!v || v->kind != JV_OBJ) return false;
    if (!jv_u64(jv_get(v, "c0_decimal"), &a)) return false;
    if (!jv_u64(jv_get(v, "c1_decimal"), &b)) return false;
    *out = gold_fp2_new(gold_fp_from_u64(a), gold_fp_from_u64(b));
    return true;
}

static inline char *load_file(const char *path, size_t *len_out)
{
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
 * Expression pool building from the oracle expr JSON
 * ========================================================================== */
typedef struct {
    dnac_logup_expr_t *nodes;
    uint32_t len, cap;
} pool_t;

static inline int32_t pool_push(pool_t *p, dnac_logup_expr_t node)
{
    if (p->len == p->cap) {
        uint32_t nc = p->cap ? p->cap * 2 : 32;
        dnac_logup_expr_t *nn =
            (dnac_logup_expr_t *)realloc(p->nodes, nc * sizeof(*nn));
        if (!nn) return -1;
        p->nodes = nn;
        p->cap = nc;
    }
    p->nodes[p->len] = node;
    return (int32_t)p->len++;
}

/* Children pushed first => topological order holds by construction. */
static inline int32_t build_expr(pool_t *p, const jv_t *e)
{
    const jv_t *op = jv_get(e, "op");
    if (!op || op->kind != JV_STR) return -1;
    dnac_logup_expr_t node;
    memset(&node, 0, sizeof(node));
    node.x = node.y = -1;

    if (!strcmp(op->str, "const")) {
        uint64_t v;
        if (!jv_u64(jv_get(e, "val"), &v)) return -1;
        node.kind = DNAC_LOGUP_EXPR_CONST;
        node.cval = gold_fp_from_u64(v);
        return pool_push(p, node);
    }
    if (!strcmp(op->str, "main") || !strcmp(op->str, "prep")) {
        uint64_t col, next;
        if (!jv_u64(jv_get(e, "col"), &col)) return -1;
        if (!jv_u64(jv_get(e, "next"), &next)) return -1;
        node.kind = strcmp(op->str, "main") ? DNAC_LOGUP_EXPR_PREP
                                            : DNAC_LOGUP_EXPR_MAIN;
        node.index = (uint32_t)col;
        node.next = (uint8_t)next;
        return pool_push(p, node);
    }
    if (!strcmp(op->str, "public")) {
        uint64_t idx;
        if (!jv_u64(jv_get(e, "idx"), &idx)) return -1;
        node.kind = DNAC_LOGUP_EXPR_PUBLIC;
        node.index = (uint32_t)idx;
        return pool_push(p, node);
    }
    if (!strcmp(op->str, "neg")) {
        int32_t x = build_expr(p, jv_get(e, "x"));
        if (x < 0) return -1;
        node.kind = DNAC_LOGUP_EXPR_NEG;
        node.x = x;
        return pool_push(p, node);
    }
    if (!strcmp(op->str, "add") || !strcmp(op->str, "sub") ||
        !strcmp(op->str, "mul")) {
        int32_t x = build_expr(p, jv_get(e, "x"));
        if (x < 0) return -1;
        int32_t y = build_expr(p, jv_get(e, "y"));
        if (y < 0) return -1;
        node.kind = !strcmp(op->str, "add")   ? DNAC_LOGUP_EXPR_ADD
                    : !strcmp(op->str, "sub") ? DNAC_LOGUP_EXPR_SUB
                                              : DNAC_LOGUP_EXPR_MUL;
        node.x = x;
        node.y = y;
        return pool_push(p, node);
    }
    return -1;
}

static inline bool fp2_eq_limbs(gold_fp2_t got, gold_fp2_t exp)
{
    return gold_fp_to_u64(got.a) == gold_fp_to_u64(exp.a) &&
           gold_fp_to_u64(got.b) == gold_fp_to_u64(exp.b);
}

#endif /* DNAC_LOGUP_TEST_UTIL_H */
