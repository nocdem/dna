/**
 * @file test_rlp_conformity.c
 * @brief HF-9 review T-2: evm_trie_rlp.c (encode and decode) against vectors
 *        produced by the pinned ethereum-rlp 0.1.6.
 *
 * Plan: docs/plans/approved/2026-11-04-hf9.md section 12 row T-2, section 3.3.
 *
 * REFERENCE: ethereum-rlp 0.1.6 sdist (sha256 ede36f53b53c8da21f19259a676eed8790950d47f0b42cb928ac8a3c562282f3),
 * src/ethereum_rlp/rlp.py encode :66-130, decode :143-159, :387-543. The
 * vectors are written by trie/rlp_conformity_oracle.py (a separate script;
 * it holds no RLP rule, every expected value is what rlp.py returned or
 * raised), from the sdist and the three pinned wheels of execution-specs
 * a87891f7 uv.lock (ethereum_types 0.4.1, typing_extensions 4.15.0,
 * mypy_extensions 1.1.0).
 *
 * VECTOR FILE: trie/rlp_vectors_0_1_6.json, sha256
 *   0b5c25b1be5e9e83e054483a604ff2ba614d3b2aae037e16d6b5dfdf80195897
 * (696 vectors: 332 encode, 338 decode accepted and 26 decode rejected by
 * the reference; the oracle run twice gives identical bytes). The test computes the file's sha256 and
 * refuses to run on any other content, so an edited or stale file cannot
 * pass; regenerating needs `make rlp-vectors RLP_SDIST=... RLP_DEPS=...`
 * and a new sha256 here.
 *
 * WHAT IT PROVES, for every vector:
 *   encode: the tree built with evm_trie_rlp_put_bytes / _wrap_list yields
 *           exactly the reference's bytes;
 *   decode accepted by the reference: evm_trie_rlp_decode_item accepts the
 *           whole buffer (rc 0 and total == length: the C decoder permits
 *           trailing bytes by contract, rlp.decode rejects them, so
 *           trailing bytes are a C reject here) and, recursing into every
 *           list payload, yields the reference's tree;
 *   decode rejected by the reference (non-canonical, truncated, trailing,
 *           empty): the C decoder rejects it at the top or in some nested
 *           item. The C decoder's verdict equals the reference's on every
 *           vector.
 *
 * COMPILE FLAGS: none; environment: none. Run from shared/evm
 * (`make test_rlp_conformity` builds, `make test` runs it); the vector path
 * may be given as argv[1].
 *
 * LEAVES BEHIND: nothing (reads one file).
 *
 * HOW IT CAN FALSELY PASS OR SKIP: a missing or changed vector file FAILS
 * (sha256), it is not skipped; the vectors prove conformity only on the
 * inputs listed (boundary lengths 0, 1, 55, 56, 57, 255-257, 1024, 65536 for
 * strings; payload 55 / 56 / 57 / 256 for lists; 300 seeded random trees; 32
 * hand-chosen decode inputs) - an input class not in the file is not
 * covered; the oracle ran on one interpreter (python 3.11.2) and a vector
 * set regenerated with different dependency pins would need the pins
 * re-checked. The file parser is a minimal reader for the oracle's exact
 * layout (one vector per line); it is not a general JSON parser.
 */
#include "evm_trie_rlp.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTORS_SHA256 \
    "0b5c25b1be5e9e83e054483a604ff2ba614d3b2aae037e16d6b5dfdf80195897"

static int g_fail;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
            g_fail++;                                                       \
        }                                                                   \
    } while (0)

/* ── minimal JSON subset: strings (no escapes), arrays, objects, true /
 *    false, non-negative integers ──────────────────────────────────── */

enum { J_STR, J_ARR, J_OBJ, J_BOOL, J_NUM };

typedef struct jv {
    int          kind;
    char        *str;        /* J_STR (NUL-terminated copy)                */
    int          b;          /* J_BOOL                                      */
    size_t       n;          /* J_ARR: items; J_OBJ: members                */
    struct jv  **items;      /* J_ARR items, or J_OBJ values                */
    char       **keys;       /* J_OBJ                                       */
} jv;

static void jv_free(jv *v)
{
    if (!v) return;
    for (size_t i = 0; i < v->n; i++) {
        jv_free(v->items[i]);
        if (v->keys) free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->str);
    free(v);
}

static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static char *parse_raw_string(const char **pp)
{
    const char *p = *pp;
    if (*p != '"') return NULL;
    p++;
    const char *s = p;
    while (*p && *p != '"') {
        if (*p == '\\') return NULL;           /* no escapes in the file */
        p++;
    }
    if (*p != '"') return NULL;
    size_t n = (size_t)(p - s);
    char *r = malloc(n + 1);
    if (!r) return NULL;
    memcpy(r, s, n);
    r[n] = 0;
    *pp = p + 1;
    return r;
}

static jv *parse_value(const char **pp, int depth);

static jv *jv_new(int kind)
{
    jv *v = calloc(1, sizeof(jv));
    if (v) v->kind = kind;
    return v;
}

static int push(jv *c, char *key, jv *val)
{
    jv **ni = realloc(c->items, (c->n + 1) * sizeof(*ni));
    if (!ni) return -1;
    c->items = ni;
    if (c->kind == J_OBJ) {
        char **nk = realloc(c->keys, (c->n + 1) * sizeof(*nk));
        if (!nk) return -1;
        c->keys = nk;
        c->keys[c->n] = key;
    }
    c->items[c->n++] = val;
    return 0;
}

static jv *parse_value(const char **pp, int depth)
{
    const char *p = skip_ws(*pp);
    jv *v = NULL;
    if (depth > 64) return NULL;
    if (*p == '"') {
        v = jv_new(J_STR);
        if (!v) return NULL;
        v->kind = J_STR;
        v->str = parse_raw_string(&p);
        if (!v->str) { jv_free(v); return NULL; }
    } else if (*p == '[' || *p == '{') {
        int obj = *p == '{';
        char close = obj ? '}' : ']';
        v = jv_new(obj ? J_OBJ : J_ARR);
        if (!v) return NULL;
        v->kind = obj ? J_OBJ : J_ARR;
        p = skip_ws(p + 1);
        if (*p == close) {
            p++;
        } else {
            for (;;) {
                char *key = NULL;
                p = skip_ws(p);
                if (obj) {
                    key = parse_raw_string(&p);
                    p = skip_ws(p);
                    if (!key || *p != ':') { free(key); jv_free(v); return NULL; }
                    p++;
                }
                jv *e = parse_value(&p, depth + 1);
                if (!e || push(v, key, e) != 0) {
                    free(key);
                    jv_free(e);
                    jv_free(v);
                    return NULL;
                }
                p = skip_ws(p);
                if (*p == ',') { p++; continue; }
                if (*p == close) { p++; break; }
                jv_free(v);
                return NULL;
            }
        }
    } else if (strncmp(p, "true", 4) == 0 || strncmp(p, "false", 5) == 0) {
        v = jv_new(J_BOOL);
        if (!v) return NULL;
        v->kind = J_BOOL;
        v->b = (*p == 't');
        p += v->b ? 4 : 5;
    } else if (*p >= '0' && *p <= '9') {
        v = jv_new(J_NUM);
        if (!v) return NULL;
        v->kind = J_NUM;
        while (*p >= '0' && *p <= '9') v->b = v->b * 10 + (*p++ - '0');
    } else {
        return NULL;
    }
    *pp = p;
    return v;
}

static const jv *jv_get(const jv *o, const char *key)
{
    if (!o || o->kind != J_OBJ) return NULL;
    for (size_t i = 0; i < o->n; i++)
        if (strcmp(o->keys[i], key) == 0) return o->items[i];
    return NULL;
}

/* ── hex ───────────────────────────────────────────────────────────── */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* @return malloc'd bytes (non-NULL even for 0 bytes) or NULL */
static uint8_t *unhex(const char *s, size_t *len)
{
    size_t n = strlen(s);
    if (n % 2) return NULL;
    uint8_t *r = malloc(n / 2 + 1);
    if (!r) return NULL;
    for (size_t i = 0; i < n / 2; i++) {
        int a = hexval(s[2 * i]), b = hexval(s[2 * i + 1]);
        if (a < 0 || b < 0) { free(r); return NULL; }
        r[i] = (uint8_t)(a << 4 | b);
    }
    *len = n / 2;
    return r;
}

/* ── tree <-> C RLP ────────────────────────────────────────────────── */

/* a TREE is {"b":HEX} (object, one member) or an array of TREEs */
static int enc_tree(evm_trie_rlp_buf *out, const jv *t)
{
    if (t->kind == J_OBJ) {
        const jv *h = jv_get(t, "b");
        size_t n = 0;
        if (!h || h->kind != J_STR) return -1;
        uint8_t *d = unhex(h->str, &n);
        if (!d) return -1;
        int rc = evm_trie_rlp_put_bytes(out, d, n);
        free(d);
        return rc;
    }
    if (t->kind != J_ARR) return -1;
    size_t start = out->len;
    for (size_t i = 0; i < t->n; i++)
        if (enc_tree(out, t->items[i]) != 0) return -1;
    return evm_trie_rlp_wrap_list(out, start);
}

/* Decode exactly the span [p, p+len) as one item (no trailing bytes),
 * recursing into list payloads, and compare with `exp` (NULL = no
 * comparison). @return 0 accepted (and equal when exp), -1 rejected,
 * 1 accepted but different from exp. */
static int dec_span(const uint8_t *p, size_t len, const jv *exp)
{
    evm_trie_rlp_item it;
    if (evm_trie_rlp_decode_item(p, len, &it) != 0) return -1;
    if (it.total != len) return -1;
    if (!it.is_list) {
        if (exp) {
            const jv *h = exp->kind == J_OBJ ? jv_get(exp, "b") : NULL;
            size_t n = 0;
            uint8_t *d = h && h->kind == J_STR ? unhex(h->str, &n) : NULL;
            int same = d && n == it.len &&
                       (n == 0 || memcmp(d, it.payload, n) == 0);
            free(d);
            if (!same) return 1;
        }
        return 0;
    }
    /* an expected non-list is reported after the payload is validated */
    const uint8_t *q = it.payload;
    size_t rem = it.len, idx = 0;
    int result = 0;
    while (rem > 0) {
        evm_trie_rlp_item sub;
        if (evm_trie_rlp_decode_item(q, rem, &sub) != 0) return -1;
        const jv *child = (exp && exp->kind == J_ARR && idx < exp->n)
                              ? exp->items[idx] : NULL;
        int rc = dec_span(q, sub.total, child);
        if (rc < 0) return -1;
        if (rc > 0) result = 1;
        q += sub.total;
        rem -= sub.total;
        idx++;
    }
    if (exp && (exp->kind != J_ARR || exp->n != idx)) result = 1;
    return result;
}

/* ── driver ────────────────────────────────────────────────────────── */

static void hex_of(const uint8_t *p, size_t n, char *out, size_t cap)
{
    static const char *h = "0123456789abcdef";
    size_t k = 0;
    for (size_t i = 0; i < n && k + 3 < cap; i++) {
        out[k++] = h[p[i] >> 4];
        out[k++] = h[p[i] & 15];
    }
    out[k] = 0;
}

static void run_vector(const jv *v, size_t *n_enc, size_t *n_acc,
                       size_t *n_rej)
{
    const jv *id = jv_get(v, "id"), *op = jv_get(v, "op"),
             *in = jv_get(v, "in");
    const char *name = id && id->kind == J_STR ? id->str : "?";
    if (!id || !op || !in || op->kind != J_STR) {
        CHECK(0, "malformed vector line");
        return;
    }
    if (strcmp(op->str, "encode") == 0) {
        const jv *out = jv_get(v, "out");
        evm_trie_rlp_buf b = {0};
        size_t wl = 0;
        uint8_t *want = out && out->kind == J_STR ? unhex(out->str, &wl) : NULL;
        int rc = enc_tree(&b, in);
        CHECK(want && rc == 0 && b.len == wl &&
              (wl == 0 || memcmp(b.p, want, wl) == 0),
              "%s: encode differs from the reference (rc %d, len %zu vs %zu)",
              name, rc, b.len, wl);
        if (want && rc == 0 && b.len > 0 && b.len != wl) {
            char hx[64];
            hex_of(b.p, b.len, hx, sizeof(hx));
            printf("     C head: %s\n", hx);
        }
        evm_trie_rlp_buf_free(&b);
        free(want);
        (*n_enc)++;
        return;
    }
    if (strcmp(op->str, "decode") == 0) {
        const jv *ok = jv_get(v, "ok");
        size_t n = 0;
        uint8_t *d = in->kind == J_STR ? unhex(in->str, &n) : NULL;
        if (!d || !ok || ok->kind != J_BOOL) {
            CHECK(0, "%s: malformed decode vector", name);
            free(d);
            return;
        }
        if (ok->b) {
            const jv *tree = jv_get(v, "tree");
            int rc = tree ? dec_span(d, n, tree) : -1;
            CHECK(rc == 0, "%s: reference accepts; C %s", name,
                  rc < 0 ? "rejects" : "decodes a different tree");
            (*n_acc)++;
        } else {
            int rc = dec_span(d, n, NULL);
            CHECK(rc < 0, "%s: reference rejects (%s); C accepts", name,
                  jv_get(v, "error") && jv_get(v, "error")->kind == J_STR
                      ? jv_get(v, "error")->str : "?");
            (*n_rej)++;
        }
        free(d);
        return;
    }
    CHECK(0, "%s: unknown op %s", name, op->str);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "trie/rlp_vectors_0_1_6.json";
    FILE *f = fopen(path, "rb");
    if (!f) { printf("FAIL cannot open %s\n", path); return 1; }
    size_t cap = 1 << 20, len = 0;
    char *buf = malloc(cap + 1);
    size_t got;
    while (buf && (got = fread(buf + len, 1, cap - len, f)) > 0) {
        len += got;
        if (len == cap) {
            char *nb = realloc(buf, cap * 2 + 1);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (!buf) { printf("FAIL out of memory\n"); return 1; }
    buf[len] = 0;

    uint8_t md[SHA256_DIGEST_LENGTH];
    char hx[2 * SHA256_DIGEST_LENGTH + 1];
    SHA256((const unsigned char *)buf, len, md);
    hex_of(md, sizeof(md), hx, sizeof(hx));
    if (strcmp(hx, VECTORS_SHA256) != 0) {
        printf("FAIL %s sha256 %s, expected %s\n", path, hx, VECTORS_SHA256);
        free(buf);
        return 1;
    }

    /* line 1: header with the vector count; then one vector per line */
    char *line = buf;
    char *nl = strchr(line, '\n');
    size_t count = 0, seen = 0, n_enc = 0, n_acc = 0, n_rej = 0;
    {
        const char *c = nl ? strstr(line, "\"count\": ") : NULL;
        if (!c || c > nl) { printf("FAIL header without count\n"); free(buf); return 1; }
        count = (size_t)strtoul(c + 9, NULL, 10);
    }
    line = nl + 1;
    while (*line) {
        nl = strchr(line, '\n');
        if (!nl) { CHECK(0, "last line without newline"); break; }
        *nl = 0;
        const char *p = line;
        jv *v = parse_value(&p, 0);
        CHECK(v && v->kind == J_OBJ && *skip_ws(p) == 0,
              "vector %zu does not parse", seen);
        if (v) run_vector(v, &n_enc, &n_acc, &n_rej);
        jv_free(v);
        seen++;
        line = nl + 1;
    }
    CHECK(seen == count, "vector lines %zu, header says %zu", seen, count);
    CHECK(n_enc > 0 && n_acc > 0 && n_rej > 0,
          "every class present: encode %zu, accept %zu, reject %zu", n_enc,
          n_acc, n_rej);
    printf("ok   %zu vectors: %zu encode, %zu decode-accept, %zu "
           "decode-reject\n", seen, n_enc, n_acc, n_rej);
    printf("%s: %d failure(s)\n", g_fail ? "FAILED" : "PASSED", g_fail);
    free(buf);
    return g_fail ? 1 : 0;
}
