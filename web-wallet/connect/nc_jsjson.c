/* Nodus Connect core — JavaScript-compatible helpers (nc_jsjson.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_jsjson.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── growable byte buffer ───────────────────────────────────────────── */

void nc_sb_init(nc_sb_t *b) { b->p = NULL; b->len = 0; b->cap = 0; b->oom = 0; }

void nc_sb_free(nc_sb_t *b) {
    free(b->p);
    nc_sb_init(b);
}

void nc_sb_reset(nc_sb_t *b) {
    b->len = 0;
    if (b->p) b->p[0] = '\0';
}

int nc_sb_put(nc_sb_t *b, const void *p, size_t n) {
    if (b->oom) return -1;
    if (n > (size_t)-1 - b->len - 1) { b->oom = 1; return -1; }
    size_t need = b->len + n + 1;
    if (need > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < need) {
            if (cap > (size_t)-1 / 2) { cap = need; break; }
            cap *= 2;
        }
        char *q = realloc(b->p, cap);
        if (!q) { b->oom = 1; return -1; }
        b->p = q;
        b->cap = cap;
    }
    if (n) memcpy(b->p + b->len, p, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

int nc_sb_putc(nc_sb_t *b, char c) { return nc_sb_put(b, &c, 1); }

int nc_sb_puts(nc_sb_t *b, const char *s) { return nc_sb_put(b, s, strlen(s)); }

char *nc_sb_take(nc_sb_t *b, size_t *len) {
    if (b->oom) { nc_sb_free(b); if (len) *len = 0; return NULL; }
    if (!b->p && nc_sb_put(b, "", 0) != 0) { nc_sb_free(b); if (len) *len = 0; return NULL; }
    char *p = b->p;
    if (len) *len = b->len;
    nc_sb_init(b);
    return p;
}

/* ── JSON.parse (ECMA-262 §25.5.1 over the RFC 8259 grammar) ─────────── */

typedef struct {
    const unsigned char *s;
    size_t n;
    size_t i;
} vctx_t;

static int is_jws(unsigned char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
static int is_digit(unsigned char c) { return c >= '0' && c <= '9'; }

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void v_ws(vctx_t *v) { while (v->i < v->n && is_jws(v->s[v->i])) v->i++; }

/* Four hex digits at s[i]; -1 if not. */
static long v_hex4(const vctx_t *v, size_t i) {
    if (i > v->n || v->n - i < 4) return -1;
    long cu = 0;
    for (size_t k = 0; k < 4; k++) {
        int h = hexval(v->s[i + k]);
        if (h < 0) return -1;
        cu = (cu << 4) | h;
    }
    return cu;
}

/* Strict UTF-8 (no overlong form, no surrogate, <= U+10FFFF) at s[i];
 * the sequence length, or 0. */
static size_t v_utf8(const vctx_t *v, size_t i) {
    const unsigned char *s = v->s + i;
    size_t left = v->n - i;
    unsigned char c = s[0];
#define CONT(k) (left > (k) && (s[k] & 0xC0) == 0x80)
    if (c >= 0xC2 && c <= 0xDF) return CONT(1) ? 2 : 0;
    if (c == 0xE0) return (left > 2 && s[1] >= 0xA0 && s[1] <= 0xBF && CONT(2)) ? 3 : 0;
    if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) return (CONT(1) && CONT(2)) ? 3 : 0;
    if (c == 0xED) return (left > 2 && s[1] >= 0x80 && s[1] <= 0x9F && CONT(2)) ? 3 : 0;
    if (c == 0xF0) return (left > 3 && s[1] >= 0x90 && s[1] <= 0xBF && CONT(2) && CONT(3)) ? 4 : 0;
    if (c >= 0xF1 && c <= 0xF3) return (CONT(1) && CONT(2) && CONT(3)) ? 4 : 0;
    if (c == 0xF4) return (left > 3 && s[1] >= 0x80 && s[1] <= 0x8F && CONT(2) && CONT(3)) ? 4 : 0;
#undef CONT
    return 0;
}

/* One code point as UTF-8; a surrogate code unit (only a lone one reaches
 * here: pairs are joined first) as its 3-byte WTF-8 form ED A0..BF xx. */
static void put_cp(nc_sb_t *b, uint32_t cp) {
    unsigned char t[4];
    size_t k;
    if (cp < 0x80) { t[0] = (unsigned char)cp; k = 1; }
    else if (cp < 0x800) {
        t[0] = (unsigned char)(0xC0 | (cp >> 6));
        t[1] = (unsigned char)(0x80 | (cp & 0x3F));
        k = 2;
    } else if (cp < 0x10000) {
        t[0] = (unsigned char)(0xE0 | (cp >> 12));
        t[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        t[2] = (unsigned char)(0x80 | (cp & 0x3F));
        k = 3;
    } else {
        t[0] = (unsigned char)(0xF0 | (cp >> 18));
        t[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
        t[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
        t[3] = (unsigned char)(0x80 | (cp & 0x3F));
        k = 4;
    }
    nc_sb_put(b, t, k);
}

/* A string at s[i] == '"', decoded into `out` (WTF-8). 0, or -1 (syntax).
 * As JSON.parse: every escape decoded, \u0000 kept as a NUL byte, an
 * escaped pair (😀) joined into one code point, an unpaired
 * escaped surrogate kept as that lone code unit; a raw byte < 0x20 or
 * malformed UTF-8 (which no JS string can hold) is an error. */
static int p_string(vctx_t *v, nc_sb_t *out) {
    v->i++;
    size_t run = v->i;
    for (;;) {
        if (v->i >= v->n) return -1;
        unsigned char c = v->s[v->i];
        if (c == '"') {
            nc_sb_put(out, v->s + run, v->i - run);
            nc_sb_put(out, "", 0);               /* a buffer even when empty */
            v->i++;
            return 0;
        }
        if (c < 0x20) return -1;
        if (c == '\\') {
            nc_sb_put(out, v->s + run, v->i - run);
            if (v->i + 1 >= v->n) return -1;
            unsigned char e = v->s[v->i + 1];
            char one = 0;
            switch (e) {
            case '"': one = '"'; break;
            case '\\': one = '\\'; break;
            case '/': one = '/'; break;
            case 'b': one = '\b'; break;
            case 'f': one = '\f'; break;
            case 'n': one = '\n'; break;
            case 'r': one = '\r'; break;
            case 't': one = '\t'; break;
            case 'u': break;
            default: return -1;
            }
            if (e != 'u') {
                nc_sb_putc(out, one);
                v->i += 2;
            } else {
                long cu = v_hex4(v, v->i + 2);
                if (cu < 0) return -1;
                v->i += 6;
                if (cu >= 0xD800 && cu <= 0xDBFF) {
                    long lo = (v->i + 1 < v->n && v->s[v->i] == '\\' && v->s[v->i + 1] == 'u')
                              ? v_hex4(v, v->i + 2) : -1;
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        v->i += 6;
                        put_cp(out, 0x10000u + (((uint32_t)cu - 0xD800u) << 10) + ((uint32_t)lo - 0xDC00u));
                    } else {
                        put_cp(out, (uint32_t)cu);          /* lone high surrogate */
                    }
                } else {
                    put_cp(out, (uint32_t)cu);              /* incl. a lone low, NUL */
                }
            }
            run = v->i;
            continue;
        }
        if (c < 0x80) { v->i++; continue; }
        size_t k = v_utf8(v, v->i);
        if (!k) return -1;
        v->i += k;
    }
}

/* A number at s[i]: the JSON grammar, then the double JSON.parse reads
 * (strtod is correctly rounded, as ECMAScript's StringToNumber; a literal
 * of any size or exponent becomes the nearest double, or ±Infinity). */
static int p_number(vctx_t *v, double *out) {
    size_t start = v->i;
    if (v->s[v->i] == '-') v->i++;
    if (v->i >= v->n) return -1;
    if (v->s[v->i] == '0') v->i++;
    else if (v->s[v->i] >= '1' && v->s[v->i] <= '9') {
        while (v->i < v->n && is_digit(v->s[v->i])) v->i++;
    } else return -1;
    if (v->i < v->n && v->s[v->i] == '.') {
        v->i++;
        if (v->i >= v->n || !is_digit(v->s[v->i])) return -1;
        while (v->i < v->n && is_digit(v->s[v->i])) v->i++;
    }
    if (v->i < v->n && (v->s[v->i] == 'e' || v->s[v->i] == 'E')) {
        v->i++;
        if (v->i < v->n && (v->s[v->i] == '+' || v->s[v->i] == '-')) v->i++;
        if (v->i >= v->n || !is_digit(v->s[v->i])) return -1;
        while (v->i < v->n && is_digit(v->s[v->i])) v->i++;
    }
    size_t len = v->i - start;
    char small[64];
    char *lit = len < sizeof(small) ? small : malloc(len + 1);
    if (!lit) return -2;
    memcpy(lit, v->s + start, len);
    lit[len] = '\0';
    *out = strtod(lit, NULL);
    if (lit != small) free(lit);
    return 0;
}

static int p_literal(vctx_t *v, const char *lit) {
    size_t k = strlen(lit);
    if (v->n - v->i < k || memcmp(v->s + v->i, lit, k) != 0) return -1;
    v->i += k;
    return 0;
}

/* ── the value tree ─────────────────────────────────────────────────── */

void nc_jv_free(nc_jv_t *o) {
    if (!o) return;
    free(o->s);
    for (size_t i = 0; i < o->len; i++) {
        nc_jv_free(o->v[i]);
        if (o->k) free(o->k[i]);
    }
    free(o->v);
    free(o->k);
    free(o->kn);
    free(o->dead);
    free(o);
}

static nc_jv_t *jv_new(nc_jvkind_t kind) {
    nc_jv_t *o = calloc(1, sizeof(*o));
    if (o) o->kind = kind;
    return o;
}

/* Append (key, val) to an object or val to an array; key ownership moves. */
static int jv_push(nc_jv_t *c, char *key, size_t kn, nc_jv_t *val) {
    if (c->len == c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 4;
        if (cap > ((size_t)-1) / sizeof(void *)) return -1;
        nc_jv_t **v = realloc(c->v, cap * sizeof(*v));
        if (!v) return -1;
        c->v = v;
        if (c->kind == NC_JV_OBJ) {
            char **k = realloc(c->k, cap * sizeof(*k));
            if (!k) return -1;
            c->k = k;
            size_t *n = realloc(c->kn, cap * sizeof(*n));
            if (!n) return -1;
            c->kn = n;
        }
        c->cap = cap;
    }
    c->v[c->len] = val;
    if (c->kind == NC_JV_OBJ) { c->k[c->len] = key; c->kn[c->len] = kn; }
    c->len++;
    return 0;
}

static int key_cmp(const nc_jv_t *o, size_t a, size_t b) {
    size_t na = o->kn[a], nb = o->kn[b];
    int c = memcmp(o->k[a], o->k[b], na < nb ? na : nb);
    if (c) return c;
    return na < nb ? -1 : na > nb ? 1 : 0;
}

static void key_msort(const nc_jv_t *o, size_t *idx, size_t *tmp, size_t n) {
    if (n < 2) return;
    size_t h = n / 2;
    key_msort(o, idx, tmp, h);
    key_msort(o, idx + h, tmp, n - h);
    size_t i = 0, j = h, k = 0;
    while (i < h && j < n) tmp[k++] = key_cmp(o, idx[j], idx[i]) < 0 ? idx[j++] : idx[i++];
    while (i < h) tmp[k++] = idx[i++];
    while (j < n) tmp[k++] = idx[j++];
    memcpy(idx, tmp, n * sizeof(size_t));
}

/* A closed object: a pair whose key appears again later is dead (JSON.parse
 * keeps the LAST value of a repeated key). O(n log n): an object of many
 * keys is attacker-sized. */
static int jv_close_object(nc_jv_t *o) {
    if (o->len < 2) return 0;
    o->dead = calloc(o->len, 1);
    size_t *idx = malloc(o->len * sizeof(size_t));
    size_t *tmp = malloc(o->len * sizeof(size_t));
    if (!o->dead || !idx || !tmp) { free(idx); free(tmp); return -1; }
    for (size_t i = 0; i < o->len; i++) idx[i] = i;
    key_msort(o, idx, tmp, o->len);          /* stable: equal keys in input order */
    for (size_t i = 0; i + 1 < o->len; i++)
        if (key_cmp(o, idx[i], idx[i + 1]) == 0) o->dead[idx[i]] = 1;
    free(idx);
    free(tmp);
    return 0;
}

const nc_jv_t *nc_jv_get(const nc_jv_t *o, const char *key) {
    if (!o || o->kind != NC_JV_OBJ) return NULL;
    size_t n = strlen(key);
    for (size_t i = o->len; i-- > 0;)
        if (o->kn[i] == n && (n == 0 || memcmp(o->k[i], key, n) == 0)) return o->v[i];
    return NULL;
}

typedef struct { nc_jv_t *c; char *key; size_t kn; } frame_t;

nc_js_parse_t nc_js_parse(const char *text, size_t len, nc_jv_t **out) {
    *out = NULL;
    if (!text) return NC_JS_SYNTAX;
    vctx_t vc = { (const unsigned char *)text, len, 0 };
    vctx_t *v = &vc;
    frame_t *st = calloc(NC_JS_MAX_NEST, sizeof(*st));
    if (!st) return NC_JS_NOMEM;
    size_t depth = 0;
    nc_jv_t *root = NULL, *node = NULL;
    nc_js_parse_t rc = NC_JS_SYNTAX;
    nc_sb_t sb;
    nc_sb_init(&sb);

    v_ws(v);
value:
    if (v->i >= v->n) goto fail;
    node = NULL;
    switch (v->s[v->i]) {
    case '{':
    case '[': {
        int obj = v->s[v->i] == '{';
        if (depth == NC_JS_MAX_NEST) { rc = NC_JS_DEPTH; goto fail; }
        node = jv_new(obj ? NC_JV_OBJ : NC_JV_ARR);
        if (!node) goto nomem;
        goto attach_container;
    }
    case '"': {
        nc_sb_reset(&sb);
        if (p_string(v, &sb) != 0) goto fail;
        node = jv_new(NC_JV_STR);
        if (!node) goto nomem;
        node->s = nc_sb_take(&sb, &node->n);
        if (!node->s) goto nomem_node;
        goto attach;
    }
    case 't': if (p_literal(v, "true") != 0) goto fail;  node = jv_new(NC_JV_TRUE);  break;
    case 'f': if (p_literal(v, "false") != 0) goto fail; node = jv_new(NC_JV_FALSE); break;
    case 'n': if (p_literal(v, "null") != 0) goto fail;  node = jv_new(NC_JV_NULL);  break;
    default: {
        if (v->s[v->i] != '-' && !is_digit(v->s[v->i])) goto fail;
        double d;
        int r = p_number(v, &d);
        if (r == -2) goto nomem;
        if (r != 0) goto fail;
        node = jv_new(NC_JV_NUM);
        if (node) node->num = d;
        break;
    }
    }
    if (!node) goto nomem;
attach:
    if (depth == 0) root = node;
    else if (jv_push(st[depth - 1].c, st[depth - 1].key, st[depth - 1].kn, node) != 0) goto nomem_node;
    else st[depth - 1].key = NULL;
    node = NULL;
    goto after;
attach_container:
    if (depth == 0) root = node;
    else if (jv_push(st[depth - 1].c, st[depth - 1].key, st[depth - 1].kn, node) != 0) goto nomem_node;
    else st[depth - 1].key = NULL;
    st[depth].c = node;
    st[depth].key = NULL;
    depth++;
    node = NULL;
    v->i++;
    v_ws(v);
    if (st[depth - 1].c->kind == NC_JV_OBJ) {
        if (v->i < v->n && v->s[v->i] == '}') { v->i++; depth--; goto after; }
        goto key;
    }
    if (v->i < v->n && v->s[v->i] == ']') { v->i++; depth--; goto after; }
    goto value;
key:
    if (v->i >= v->n || v->s[v->i] != '"') goto fail;
    nc_sb_reset(&sb);
    if (p_string(v, &sb) != 0) goto fail;
    st[depth - 1].key = nc_sb_take(&sb, &st[depth - 1].kn);
    if (!st[depth - 1].key) goto nomem;
    v_ws(v);
    if (v->i >= v->n || v->s[v->i] != ':') goto fail;
    v->i++;
    v_ws(v);
    goto value;
after:
    if (depth == 0) {
        v_ws(v);
        if (v->i != v->n) goto fail;
        *out = root;
        root = NULL;
        rc = NC_JS_OK;
        goto done;
    }
    v_ws(v);
    if (v->i >= v->n) goto fail;
    if (v->s[v->i] == ',') {
        v->i++;
        v_ws(v);
        if (st[depth - 1].c->kind == NC_JV_OBJ) goto key;
        goto value;
    }
    if ((st[depth - 1].c->kind == NC_JV_OBJ && v->s[v->i] == '}') ||
        (st[depth - 1].c->kind == NC_JV_ARR && v->s[v->i] == ']')) {
        v->i++;
        if (st[depth - 1].c->kind == NC_JV_OBJ && jv_close_object(st[depth - 1].c) != 0) goto nomem;
        depth--;
        goto after;
    }
    goto fail;

nomem_node:
    nc_jv_free(node);
    node = NULL;
nomem:
    rc = NC_JS_NOMEM;
fail:
done:
    nc_jv_free(node);
    nc_jv_free(root);                 /* every attached node hangs off root */
    for (size_t i = 0; i < depth; i++) free(st[i].key);
    free(st);
    nc_sb_free(&sb);
    return rc;
}

/* ── JSON.stringify ─────────────────────────────────────────────────── */

static const char HEXL[] = "0123456789abcdef";

void nc_js_write_string(nc_sb_t *b, const char *str, size_t n) {
    const unsigned char *s = (const unsigned char *)str;
    nc_sb_putc(b, '"');
    size_t run = 0;                      /* start of the raw run          */
    for (size_t i = 0; i < n;) {
        unsigned char c = s[i];
        char esc[8];
        size_t elen = 0, adv = 1;
        if (c == '"') { esc[0] = '\\'; esc[1] = '"'; elen = 2; }
        else if (c == '\\') { esc[0] = '\\'; esc[1] = '\\'; elen = 2; }
        else if (c == '\b') { esc[0] = '\\'; esc[1] = 'b'; elen = 2; }
        else if (c == '\t') { esc[0] = '\\'; esc[1] = 't'; elen = 2; }
        else if (c == '\n') { esc[0] = '\\'; esc[1] = 'n'; elen = 2; }
        else if (c == '\f') { esc[0] = '\\'; esc[1] = 'f'; elen = 2; }
        else if (c == '\r') { esc[0] = '\\'; esc[1] = 'r'; elen = 2; }
        else if (c < 0x20) {
            memcpy(esc, "\\u00", 4);
            esc[4] = HEXL[c >> 4];
            esc[5] = HEXL[c & 15];
            elen = 6;
        } else if (c == 0xED && n - i >= 3 && s[i + 1] >= 0xA0 && s[i + 1] <= 0xBF) {
            /* WTF-8 lone surrogate: JSON.stringify writes \udxxx */
            unsigned cu = 0xD000u | ((unsigned)(s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F);
            esc[0] = '\\'; esc[1] = 'u';
            esc[2] = HEXL[(cu >> 12) & 15]; esc[3] = HEXL[(cu >> 8) & 15];
            esc[4] = HEXL[(cu >> 4) & 15];  esc[5] = HEXL[cu & 15];
            elen = 6;
            adv = 3;
        }
        if (elen) {
            if (i > run) nc_sb_put(b, s + run, i - run);
            nc_sb_put(b, esc, elen);
            i += adv;
            run = i;
        } else {
            i++;
        }
    }
    if (n > run) nc_sb_put(b, s + run, n - run);
    nc_sb_putc(b, '"');
}

/* The k-digit decimal significand of `d` (> 0, finite) whose value is the
 * nearest to d among those that round-trip, if any; digits in dig[], the
 * decimal exponent of the first digit in *e10. */
static int digits_at(double d, int k, char dig[24], int *e10) {
    char buf[48];
    snprintf(buf, sizeof(buf), "%.*e", k - 1, d);
    /* buf = "d[.ddd]e[+-]X" */
    int nd = 0;
    const char *p = buf;
    for (; *p && *p != 'e'; p++) if (*p >= '0' && *p <= '9') dig[nd++] = *p;
    dig[nd] = '\0';
    int ex = atoi(p + 1);
    if (strtod(buf, NULL) == d) { *e10 = ex; return 1; }
    /* the nearest k-digit value does not round-trip; at a power of two
     * the interval is asymmetric and a neighbour may (ECMA-262 picks the
     * smallest k with ANY round-tripping significand). */
    for (int dir = -1; dir <= 1; dir += 2) {
        char cand[24];
        memcpy(cand, dig, (size_t)nd + 1);
        int cex = ex;
        int i = nd - 1;
        if (dir > 0) {
            while (i >= 0 && cand[i] == '9') cand[i--] = '0';
            if (i < 0) { cand[0] = '1'; for (int j = 1; j < nd; j++) cand[j] = '0'; cex++; }
            else cand[i]++;
        } else {
            while (i >= 0 && cand[i] == '0') cand[i--] = '9';
            if (i < 0) continue;
            cand[i]--;
            if (cand[0] == '0') {
                if (nd == 1) continue;
                /* 1000 - 1 = 0999 -> 9.99e(ex-1) with k digits: 9999 */
                memmove(cand, cand + 1, (size_t)nd - 1);
                cand[nd - 1] = '9';
                cex--;
            }
        }
        char tb[48];
        int w = snprintf(tb, sizeof(tb), "%c.%se%d", cand[0], cand + 1, cex);
        if (nd == 1) w = snprintf(tb, sizeof(tb), "%ce%d", cand[0], cex);
        (void)w;
        if (strtod(tb, NULL) == d) { memcpy(dig, cand, (size_t)nd + 1); *e10 = cex; return 1; }
    }
    return 0;
}

void nc_js_number_to_string(double d, char out[NC_JS_NUMSTR_MAX]) {
    if (isnan(d)) { strcpy(out, "NaN"); return; }
    if (d == 0) { strcpy(out, "0"); return; }
    if (isinf(d)) { strcpy(out, d > 0 ? "Infinity" : "-Infinity"); return; }
    char *o = out;
    if (d < 0) { *o++ = '-'; d = -d; }
    char dig[24];
    int e10 = 0, k = 0;
    for (k = 1; k <= 17; k++) if (digits_at(d, k, dig, &e10)) break;
    if (k > 17) { k = 17; digits_at(d, 17, dig, &e10); }
    k = (int)strlen(dig);
    while (k > 1 && dig[k - 1] == '0') dig[--k] = '\0';
    int n = e10 + 1;                     /* ECMA-262 n                    */
    if (k <= n && n <= 21) {
        memcpy(o, dig, (size_t)k); o += k;
        for (int i = 0; i < n - k; i++) *o++ = '0';
    } else if (0 < n && n <= 21) {
        memcpy(o, dig, (size_t)n); o += n;
        *o++ = '.';
        memcpy(o, dig + n, (size_t)(k - n)); o += k - n;
    } else if (-6 < n && n <= 0) {
        *o++ = '0'; *o++ = '.';
        for (int i = 0; i < -n; i++) *o++ = '0';
        memcpy(o, dig, (size_t)k); o += k;
    } else {
        *o++ = dig[0];
        if (k > 1) { *o++ = '.'; memcpy(o, dig + 1, (size_t)k - 1); o += k - 1; }
        o += snprintf(o, 8, "e%c%d", n - 1 >= 0 ? '+' : '-', abs(n - 1));
    }
    *o = '\0';
}

void nc_js_write_number(nc_sb_t *b, double d) {
    if (!isfinite(d)) { nc_sb_puts(b, "null"); return; }
    char t[NC_JS_NUMSTR_MAX];
    nc_js_number_to_string(d, t);
    nc_sb_puts(b, t);
}

/* ── JS scalar values ───────────────────────────────────────────────── */

nc_val_t nc_val_undef(void) { nc_val_t v; memset(&v, 0, sizeof(v)); v.kind = NC_V_UNDEF; return v; }

nc_val_t nc_val_str(const char *s, size_t n) {
    nc_val_t v = nc_val_undef();
    v.kind = NC_V_STR;
    v.s = s;
    v.n = n;
    return v;
}

int nc_val_from_jv(const nc_jv_t *o, nc_val_t *out) {
    *out = nc_val_undef();
    if (!o) return 0;                                  /* absent: undefined */
    switch (o->kind) {
    case NC_JV_NULL:  out->kind = NC_V_NULL; return 0;
    case NC_JV_FALSE: out->kind = NC_V_FALSE; return 0;
    case NC_JV_TRUE:  out->kind = NC_V_TRUE; return 0;
    case NC_JV_NUM:   out->kind = NC_V_NUM; out->num = o->num; return 0;
    case NC_JV_STR:   out->kind = NC_V_STR; out->s = o->s; out->n = o->n; return 0;
    default:          return -1;
    }
}

void nc_val_tostring(const nc_val_t *v, nc_sb_t *b) {
    switch (v->kind) {
    case NC_V_UNDEF: nc_sb_puts(b, "undefined"); break;
    case NC_V_NULL:  nc_sb_puts(b, "null"); break;
    case NC_V_FALSE: nc_sb_puts(b, "false"); break;
    case NC_V_TRUE:  nc_sb_puts(b, "true"); break;
    case NC_V_NUM: {
        char t[NC_JS_NUMSTR_MAX];
        nc_js_number_to_string(v->num, t);
        nc_sb_puts(b, t);
        break;
    }
    case NC_V_STR:   nc_sb_put(b, v->s, v->n); break;
    }
}

int nc_val_truthy(const nc_val_t *v) {
    switch (v->kind) {
    case NC_V_TRUE: return 1;
    case NC_V_NUM:  return !(v->num == 0 || isnan(v->num));
    case NC_V_STR:  return v->n > 0;
    default:        return 0;
    }
}

int nc_val_strict_eq(const nc_val_t *a, const nc_val_t *b) {
    if (a->kind != b->kind) return 0;
    if (a->kind == NC_V_NUM) return a->num == b->num;
    if (a->kind == NC_V_STR) return a->n == b->n && (a->n == 0 || memcmp(a->s, b->s, a->n) == 0);
    return 1;
}

int nc_js_str_eq(const char *s, size_t n, const char *lit) {
    size_t k = strlen(lit);
    return n == k && (k == 0 || memcmp(s, lit, k) == 0);
}

int nc_val_is(const nc_val_t *v, const char *lit) {
    return v->kind == NC_V_STR && nc_js_str_eq(v->s, v->n, lit);
}

int nc_js_is_integer(double d) { return isfinite(d) && trunc(d) == d; }

/* ── strings ────────────────────────────────────────────────────────── */

size_t nc_utf8_char_len(const unsigned char *s, size_t n) {
    if (!n) return 0;
    size_t k = 1;
    if (s[0] >= 0xF0 && s[0] <= 0xF7) k = 4;
    else if (s[0] >= 0xE0) k = (s[0] <= 0xEF) ? 3 : 1;
    else if (s[0] >= 0xC0) k = 2;
    return k > n ? n : k;
}

int nc_utf8_is_lone_high(const unsigned char *s, size_t n) {
    return n >= 3 && s[0] == 0xED && s[1] >= 0xA0 && s[1] <= 0xAF;
}

size_t nc_js_utf16_len(const char *str, size_t n) {
    const unsigned char *s = (const unsigned char *)str;
    size_t units = 0;
    for (size_t i = 0; i < n;) {
        size_t k = nc_utf8_char_len(s + i, n - i);
        units += (k == 4) ? 2 : 1;
        i += k;
    }
    return units;
}

size_t nc_js_code_points(const char *str, size_t n) {
    const unsigned char *s = (const unsigned char *)str;
    size_t cps = 0;
    for (size_t i = 0; i < n; cps++) i += nc_utf8_char_len(s + i, n - i);
    return cps;
}

static uint32_t decode_cp(const unsigned char *s, size_t k) {
    switch (k) {
    case 1: return s[0];
    case 2: return ((uint32_t)(s[0] & 0x1F) << 6) | (s[1] & 0x3F);
    case 3: return ((uint32_t)(s[0] & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
    default: return ((uint32_t)(s[0] & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
                    ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
    }
}

static int is_js_ws_cp(uint32_t c) {
    switch (c) {
    case 0x09: case 0x0B: case 0x0C: case 0x20: case 0xA0: case 0xFEFF:   /* WhiteSpace */
    case 0x1680: case 0x202F: case 0x205F: case 0x3000:                    /* Zs */
    case 0x0A: case 0x0D: case 0x2028: case 0x2029:                        /* LineTerminator */
        return 1;
    default:
        return c >= 0x2000 && c <= 0x200A;                                 /* Zs */
    }
}

size_t nc_js_ws_at(const char *str, size_t n) {
    const unsigned char *s = (const unsigned char *)str;
    size_t k = nc_utf8_char_len(s, n);
    if (!k) return 0;
    return is_js_ws_cp(decode_cp(s, k)) ? k : 0;
}

void nc_js_trim(const char *str, size_t n, size_t *start, size_t *end) {
    const unsigned char *s = (const unsigned char *)str;
    size_t a = 0, z = n;
    while (a < z) {
        size_t k = nc_js_ws_at(str + a, z - a);
        if (!k) break;
        a += k;
    }
    while (z > a) {
        size_t p = z - 1;
        while (p > a && (s[p] & 0xC0) == 0x80 && z - p < 4) p--;
        size_t k = nc_utf8_char_len(s + p, z - p);
        if (p + k != z || !is_js_ws_cp(decode_cp(s + p, k))) break;
        z = p;
    }
    *start = a;
    *end = z;
}

void nc_js_lower_ascii(nc_sb_t *b, const char *s, size_t n) {
    size_t at = b->len;
    if (nc_sb_put(b, s, n) != 0) return;
    for (size_t i = 0; i < n; i++) {
        char c = b->p[at + i];
        if (c >= 'A' && c <= 'Z') b->p[at + i] = (char)(c - 'A' + 'a');
    }
}

void nc_js_to_utf8(nc_sb_t *b, const char *str, size_t n) {
    const unsigned char *s = (const unsigned char *)str;
    size_t run = 0;
    for (size_t i = 0; i < n;) {
        if (s[i] == 0xED && n - i >= 3 && s[i + 1] >= 0xA0 && s[i + 1] <= 0xBF) {
            if (i > run) nc_sb_put(b, s + run, i - run);
            nc_sb_put(b, "\xEF\xBF\xBD", 3);
            i += 3;
            run = i;
        } else {
            i++;
        }
    }
    if (n > run) nc_sb_put(b, s + run, n - run);
}

/* ── BigInt ─────────────────────────────────────────────────────────── */

#define BIG_BASE 1000000000u

void nc_big_init(nc_big_t *a) { a->neg = 0; a->limb = NULL; a->n = 0; a->cap = 0; }

void nc_big_free(nc_big_t *a) { free(a->limb); nc_big_init(a); }

static int big_reserve(nc_big_t *a, size_t cap) {
    if (cap <= a->cap) return 0;
    if (cap > ((size_t)-1) / sizeof(uint32_t)) return -1;
    uint32_t *q = realloc(a->limb, cap * sizeof(uint32_t));
    if (!q) return -1;
    a->limb = q;
    a->cap = cap;
    return 0;
}

static void big_norm(nc_big_t *a) {
    while (a->n && a->limb[a->n - 1] == 0) a->n--;
    if (!a->n) a->neg = 0;
}

/* a = a * m + add (m, add < 2^32, a >= 0 magnitude) */
static int big_muladd(nc_big_t *a, uint32_t m, uint32_t add) {
    uint64_t carry = add;
    for (size_t i = 0; i < a->n; i++) {
        uint64_t t = (uint64_t)a->limb[i] * m + carry;
        a->limb[i] = (uint32_t)(t % BIG_BASE);
        carry = t / BIG_BASE;
    }
    while (carry) {
        if (big_reserve(a, a->n + 1) != 0) return -1;
        a->limb[a->n++] = (uint32_t)(carry % BIG_BASE);
        carry /= BIG_BASE;
    }
    return 0;
}

nc_big_rc_t nc_big_from_u128(nc_big_t *a, unsigned __int128 v) {
    a->n = 0;
    a->neg = 0;
    while (v) {
        if (big_reserve(a, a->n + 1) != 0) return NC_BIG_NOMEM;
        a->limb[a->n++] = (uint32_t)(v % BIG_BASE);
        v /= BIG_BASE;
    }
    return NC_BIG_OK;
}

static nc_big_rc_t big_from_double(nc_big_t *a, double d) {
    if (!nc_js_is_integer(d)) return NC_BIG_RANGE;
    int neg = d < 0;
    double m = fabs(d);
    if (m < 18446744073709551616.0) {
        if (nc_big_from_u128(a, (unsigned __int128)(uint64_t)m) != NC_BIG_OK) return NC_BIG_NOMEM;
    } else {
        int e;
        double f = frexp(m, &e);                 /* m = f * 2^e, f in [0.5,1) */
        uint64_t mant = (uint64_t)ldexp(f, 53);  /* exact: m has <= 53 bits  */
        e -= 53;                                 /* m = mant * 2^e, e > 0    */
        if (nc_big_from_u128(a, mant) != NC_BIG_OK) return NC_BIG_NOMEM;
        while (e > 0) {
            int s = e > 29 ? 29 : e;
            if (big_muladd(a, (uint32_t)1u << s, 0) != 0) return NC_BIG_NOMEM;
            e -= s;
        }
    }
    a->neg = neg;
    big_norm(a);
    return NC_BIG_OK;
}

/* StringToBigInt (ECMA-262 §7.1.14). */
static nc_big_rc_t big_from_string(nc_big_t *a, const char *str, size_t len) {
    size_t st, en;
    nc_js_trim(str, len, &st, &en);
    const unsigned char *s = (const unsigned char *)str + st;
    size_t n = en - st;
    a->n = 0;
    a->neg = 0;
    if (n == 0) return NC_BIG_OK;
    if (n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X' || s[1] == 'o' || s[1] == 'O' ||
                                  s[1] == 'b' || s[1] == 'B')) {
        uint32_t radix = (s[1] == 'x' || s[1] == 'X') ? 16 : (s[1] == 'o' || s[1] == 'O') ? 8 : 2;
        if (n == 2) return NC_BIG_SYNTAX;
        for (size_t i = 2; i < n; i++) {
            int h = hexval(s[i]);
            if (h < 0 || (uint32_t)h >= radix) return NC_BIG_SYNTAX;
        }
        if (n - 2 > NC_BIG_RADIX_MAX) return NC_BIG_UNSUPPORTED;
        for (size_t i = 2; i < n; i++)
            if (big_muladd(a, radix, (uint32_t)hexval(s[i])) != 0) return NC_BIG_NOMEM;
        big_norm(a);
        return NC_BIG_OK;
    }
    int neg = 0;
    size_t i = 0;
    if (s[0] == '+' || s[0] == '-') { neg = s[0] == '-'; i = 1; }
    if (i == n) return NC_BIG_SYNTAX;
    for (size_t j = i; j < n; j++) if (!is_digit(s[j])) return NC_BIG_SYNTAX;
    while (i < n - 1 && s[i] == '0') i++;
    size_t nd = n - i;
    if (big_reserve(a, nd / 9 + 1) != 0) return NC_BIG_NOMEM;
    /* 9-digit groups from the least significant end */
    size_t end = n;
    while (end > i) {
        size_t beg = end >= i + 9 ? end - 9 : i;
        uint32_t limb = 0;
        for (size_t j = beg; j < end; j++) limb = limb * 10 + (uint32_t)(s[j] - '0');
        a->limb[a->n++] = limb;
        end = beg;
    }
    a->neg = neg;
    big_norm(a);
    return NC_BIG_OK;
}

nc_big_rc_t nc_big_from_val(nc_big_t *a, const nc_val_t *v) {
    a->n = 0;
    a->neg = 0;
    switch (v->kind) {
    case NC_V_UNDEF:
    case NC_V_NULL:  return NC_BIG_TYPE;
    case NC_V_FALSE: return NC_BIG_OK;
    case NC_V_TRUE:  return nc_big_from_u128(a, 1);
    case NC_V_NUM:   return big_from_double(a, v->num);
    case NC_V_STR:   return big_from_string(a, v->s, v->n);
    }
    return NC_BIG_TYPE;
}

static int mag_cmp(const nc_big_t *a, const nc_big_t *b) {
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (size_t i = a->n; i-- > 0;)
        if (a->limb[i] != b->limb[i]) return a->limb[i] < b->limb[i] ? -1 : 1;
    return 0;
}

int nc_big_cmp(const nc_big_t *a, const nc_big_t *b) {
    if (a->neg != b->neg) return a->neg ? -1 : 1;
    int m = mag_cmp(a, b);
    return a->neg ? -m : m;
}

nc_big_rc_t nc_big_add(nc_big_t *acc, const nc_big_t *b) {
    if (!b->n) return NC_BIG_OK;
    size_t n = (acc->n > b->n ? acc->n : b->n) + 1;
    if (big_reserve(acc, n) != 0) return NC_BIG_NOMEM;
    for (size_t i = acc->n; i < n; i++) acc->limb[i] = 0;
    size_t an = acc->n;
    acc->n = n;
    if (acc->neg == b->neg || an == 0) {
        if (an == 0) acc->neg = b->neg;
        uint32_t carry = 0;
        for (size_t i = 0; i < n; i++) {
            uint32_t t = acc->limb[i] + (i < b->n ? b->limb[i] : 0) + carry;
            carry = t >= BIG_BASE;
            acc->limb[i] = carry ? t - BIG_BASE : t;
        }
    } else {
        /* different signs: |acc| - |b| or |b| - |acc| */
        nc_big_t tmp = *acc;
        tmp.n = an;
        int c = mag_cmp(&tmp, b);
        if (c == 0) { acc->n = 0; acc->neg = 0; return NC_BIG_OK; }
        uint32_t borrow = 0;
        for (size_t i = 0; i < n; i++) {
            int64_t x = (int64_t)(c > 0 ? acc->limb[i] : (i < b->n ? b->limb[i] : 0));
            int64_t y = (int64_t)(c > 0 ? (i < b->n ? b->limb[i] : 0) : acc->limb[i]);
            int64_t t = x - y - borrow;
            borrow = t < 0;
            acc->limb[i] = (uint32_t)(borrow ? t + BIG_BASE : t);
        }
        if (c < 0) acc->neg = b->neg;
    }
    big_norm(acc);
    return NC_BIG_OK;
}

void nc_big_to_string(const nc_big_t *a, nc_sb_t *b) {
    if (!a->n) { nc_sb_putc(b, '0'); return; }
    char t[16];
    if (a->neg) nc_sb_putc(b, '-');
    snprintf(t, sizeof(t), "%u", (unsigned)a->limb[a->n - 1]);
    nc_sb_puts(b, t);
    for (size_t i = a->n - 1; i-- > 0;) {
        snprintf(t, sizeof(t), "%09u", (unsigned)a->limb[i]);
        nc_sb_puts(b, t);
    }
}

void nc_u128_to_string(unsigned __int128 v, nc_sb_t *b) {
    char t[48];
    size_t i = sizeof(t);
    t[--i] = '\0';
    do { t[--i] = (char)('0' + (int)(v % 10)); v /= 10; } while (v);
    nc_sb_puts(b, t + i);
}
