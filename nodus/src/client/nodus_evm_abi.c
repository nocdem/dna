/**
 * @file nodus/src/client/nodus_evm_abi.c
 * @brief The Nodus EVM contract-ABI text layer (see nodus_evm_abi.h) —
 *        moved from tools/nodus-cli.c's `ABI` block, I/O-free; the parser
 *        is made strictly canonical (Kurultay #40, Astra finding A1).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_evm_abi.h"

#include "crypto/hash/keccak256.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
__attribute__((format(printf, 3, 4)))
#endif
static void abi_err(char *err, size_t cap, const char *fmt, ...) {
    if (!err || cap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, cap, fmt, ap);
    va_end(ap);
}

/* ── 256-bit big-endian integers ─────────────────────────────────────── */

int nodus_evm_u256_dec(const char *s, uint8_t out[32]) {
    memset(out, 0, 32);
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        unsigned carry = (unsigned)(*p - '0');
        for (int i = 31; i >= 0; i--) {
            unsigned v = (unsigned)out[i] * 10u + carry;
            out[i] = (uint8_t)v;
            carry = v >> 8;
        }
        if (carry) return -1;
    }
    return 0;
}

/* out = "0x"-prefixed hex (1..64 digits), right-aligned. @return 0 / -1. */
static int evm_u256_hexnum(const char *s, uint8_t out[32]) {
    memset(out, 0, 32);
    if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    s += 2;
    size_t n = strlen(s);
    if (n == 0 || n > 64) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[n - 1 - i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        out[31 - i / 2] |= (uint8_t)(d << ((i % 2) * 4));
    }
    return 0;
}

void nodus_evm_u256_to_dec(const uint8_t in[32], char *out) {
    uint8_t v[32];
    char tmp[80];
    size_t n = 0;
    memcpy(v, in, 32);
    for (;;) {
        unsigned rem = 0;
        int zero = 1;
        for (int i = 0; i < 32; i++) {
            unsigned cur = (rem << 8) | v[i];
            v[i] = (uint8_t)(cur / 10u);
            rem = cur % 10u;
            if (v[i]) zero = 0;
        }
        tmp[n++] = (char)('0' + rem);
        if (zero) break;
    }
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = '\0';
}

int nodus_evm_hex_bytes(const char *hex, uint8_t *out, size_t cap,
                        size_t *len) {
    if (!hex) return -1;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return -1;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 0;
}

int nodus_evm_addr_parse(const char *s, uint8_t out[32]) {
    if (!s) return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (strlen(s) != 64) return -1;
    int lower = 0, upper = 0;
    char low[64];
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'F') { upper = 1; c = (char)(c - 'A' + 'a'); }
        else if (c >= 'a' && c <= 'f') lower = 1;
        else if (!(c >= '0' && c <= '9')) return -1;
        low[i] = c;
    }
    if (lower && upper) {
        uint8_t h[32];
        if (keccak256((const uint8_t *)low, 64, h) != 0) return -1;
        for (int i = 0; i < 64; i++) {
            if (low[i] < 'a') continue;            /* a digit */
            int nib = (h[i / 2] >> (i % 2 ? 0 : 4)) & 0x0F;
            int want_upper = nib >= 8;
            int is_upper = s[i] >= 'A' && s[i] <= 'F';
            if (want_upper != is_upper) return -1;
        }
    }
    size_t n = 0;
    char buf[65];
    memcpy(buf, low, 64);
    buf[64] = '\0';
    return nodus_evm_hex_bytes(buf, out, 32, &n) == 0 && n == 32 ? 0 : -1;
}

int nodus_evm_addr_of_pk(const uint8_t *pk, uint8_t out[32]) {
    uint8_t fp[64];
    if (!pk || qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0) return -1;
    memcpy(out, fp, 32);
    return 0;
}

/* ── ABI ─────────────────────────────────────────────────────────────── */

static int evm_abi_dynamic(const nodus_evm_abi_type_t *t) {
    return t->arr || t->k == NODUS_EVM_ABI_BYTES ||
           t->k == NODUS_EVM_ABI_STRING;
}

/* A width / size written as text: 1..3 decimal digits, the first not '0',
 * nothing else (no sign, no space, no 0x) — so the value is known to be
 * below 1000 before any narrowing. @return 0 / -1. */
static int abi_num(const char *s, unsigned *v) {
    size_t n = strlen(s);
    if (n == 0 || n > 3 || s[0] == '0') return -1;
    unsigned x = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        x = x * 10u + (unsigned)(s[i] - '0');
    }
    *v = x;
    return 0;
}

/* One type name (n chars) → type + its canonical text. A one-dimensional
 * dynamic array T[] of a static T is accepted when `allow_arr`; T[k],
 * nested arrays, string[] / bytes[] and tuples are refused with a message.
 * @return 0 / -1. */
static int evm_abi_type(const char *s, size_t n, nodus_evm_abi_type_t *t,
                        char *canon, size_t cap, int allow_arr,
                        char *err, size_t errcap) {
    char name[32];
    if (n == 0 || n >= sizeof(name)) return -1;
    memcpy(name, s, n);
    name[n] = '\0';
    memset(t, 0, sizeof(*t));
    if (strchr(name, '(') || strchr(name, ')')) {
        abi_err(err, errcap, "%s: tuples are not supported", name);
        return -1;
    }
    char *lb = strchr(name, '[');
    if (lb) {
        if (!allow_arr) {
            abi_err(err, errcap, "%s: arrays are not supported in a return "
                    "list (they are not decoded)", name);
            return -1;
        }
        if (strchr(lb + 1, '[')) {
            abi_err(err, errcap, "%s: nested arrays are not supported", name);
            return -1;
        }
        if (strcmp(lb, "[]") != 0) {
            abi_err(err, errcap, "%s: only the dynamic array T[] is "
                    "supported (no fixed-size T[k])", name);
            return -1;
        }
        *lb = '\0';
        t->arr = 1;
    }
    if (!strcmp(name, "address")) t->k = NODUS_EVM_ABI_ADDR;
    else if (!strcmp(name, "bool")) t->k = NODUS_EVM_ABI_BOOL;
    else if (!strcmp(name, "string")) t->k = NODUS_EVM_ABI_STRING;
    else if (!strcmp(name, "bytes")) t->k = NODUS_EVM_ABI_BYTES;
    else if (!strncmp(name, "uint", 4) || !strncmp(name, "int", 3)) {
        int is_u = name[0] == 'u';
        const char *num = name + (is_u ? 4 : 3);
        unsigned bits = 256;
        if (*num && abi_num(num, &bits) != 0) return -1;
        if (bits < 8 || bits > 256 || bits % 8) return -1;
        t->k = is_u ? NODUS_EVM_ABI_UINT : NODUS_EVM_ABI_INT;
        t->bits = bits;
        /* rebuilt from the validated number ("uint" -> "uint256") */
        snprintf(name, sizeof(name), "%s%u", is_u ? "uint" : "int", bits);
    } else if (!strncmp(name, "bytes", 5)) {
        unsigned m = 0;
        if (abi_num(name + 5, &m) != 0 || m < 1 || m > 32) return -1;
        t->k = NODUS_EVM_ABI_FBYTES;
        t->size = m;
        snprintf(name, sizeof(name), "bytes%u", m);
    } else {
        return -1;                              /* function, unknown: refused */
    }
    if (t->arr && (t->k == NODUS_EVM_ABI_BYTES ||
                   t->k == NODUS_EVM_ABI_STRING)) {
        abi_err(err, errcap, "%s[]: arrays of a dynamic type are not "
                "supported", name);
        return -1;
    }
    /* the canonical text, as the selector hashes it */
    if (snprintf(canon, cap, "%s%s", name, t->arr ? "[]" : "") >= (int)cap)
        return -1;
    return 0;
}

/* "t1,t2" (n chars, may be empty) → types; appends the canonical list to
 * `canon`. @return the count, or -1. */
static int evm_abi_list(const char *s, size_t n, nodus_evm_abi_type_t *ts,
                        char *canon, size_t cap, int allow_arr,
                        char *err, size_t errcap) {
    int cnt = 0;
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && s[j] != ',') j++;
        size_t a = i, b = j;
        while (a < b && s[a] == ' ') a++;
        while (b > a && s[b - 1] == ' ') b--;
        char one[40];
        if (cnt >= NODUS_EVM_ABI_MAX_ARGS ||
            evm_abi_type(s + a, b - a, &ts[cnt], one, sizeof(one),
                         allow_arr, err, errcap) != 0)
            return -1;
        size_t cl = strlen(canon);
        if (snprintf(canon + cl, cap - cl, "%s%s", cnt ? "," : "", one) >=
            (int)(cap - cl))
            return -1;
        cnt++;
        if (j == n) break;
        i = j + 1;
        if (i == n) return -1;          /* a trailing comma */
    }
    return cnt;
}

int nodus_evm_abi_sig(const char *sig, nodus_evm_abi_sig_t *g,
                      char *err, size_t errcap) {
    memset(g, 0, sizeof(*g));
    if (err && errcap) err[0] = '\0';
    const char *lp = strchr(sig, '(');
    if (!lp) return -1;
    const char *rp = strchr(lp, ')');
    if (!rp) return -1;
    size_t nl = (size_t)(lp - sig);
    /* a Solidity identifier: a letter, '_' or '$' first, then letters,
     * digits, '_' or '$'; empty only for a constructor */
    for (size_t i = 0; i < nl; i++) {
        char c = sig[i];
        int alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    c == '_' || c == '$';
        int digit = c >= '0' && c <= '9';
        if (!(alpha || (digit && i > 0))) return -1;
    }
    if (nl >= 128) return -1;
    memcpy(g->canon, sig, nl);
    g->canon[nl] = '(';
    g->canon[nl + 1] = '\0';
    g->is_ctor = nl == 0;
    int n = evm_abi_list(lp + 1, (size_t)(rp - lp - 1), g->in, g->canon,
                         sizeof(g->canon), 1, err, errcap);
    if (n < 0) return -1;
    g->n_in = n;
    size_t cl = strlen(g->canon);
    if (cl + 2 > sizeof(g->canon)) return -1;
    g->canon[cl] = ')';
    g->canon[cl + 1] = '\0';
    const char *rest = rp + 1;
    if (*rest == '\0') return 0;
    if (*rest != '(') return -1;
    const char *rp2 = strchr(rest, ')');
    if (!rp2 || rp2[1] != '\0') return -1;
    char scratch[512] = "";
    /* evm_abi_print has no array case: a return list refuses arrays */
    n = evm_abi_list(rest + 1, (size_t)(rp2 - rest - 1), g->out, scratch,
                     sizeof(scratch), 0, err, errcap);
    if (n < 0) return -1;
    g->n_out = n;
    g->has_out = 1;
    return 0;
}

int nodus_evm_abi_selector(const char *canon, uint8_t sel[4]) {
    uint8_t h[32];
    if (keccak256((const uint8_t *)canon, strlen(canon), h) != 0) return -1;
    memcpy(sel, h, 4);
    return 0;
}

/* One static word of `t` from text `v`. @return 0 / -1. */
static int evm_abi_word(const nodus_evm_abi_type_t *t, const char *v,
                        uint8_t w[32]) {
    memset(w, 0, 32);
    switch (t->k) {
    case NODUS_EVM_ABI_ADDR:
        return nodus_evm_addr_parse(v, w);
    case NODUS_EVM_ABI_BOOL:
        if (!strcmp(v, "true") || !strcmp(v, "1")) { w[31] = 1; return 0; }
        if (!strcmp(v, "false") || !strcmp(v, "0")) return 0;
        return -1;
    case NODUS_EVM_ABI_UINT: {
        if ((v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
                ? evm_u256_hexnum(v, w) != 0 : nodus_evm_u256_dec(v, w) != 0)
            return -1;
        for (unsigned i = 0; i < (256u - t->bits) / 8u; i++)
            if (w[i]) return -1;                       /* out of range */
        return 0;
    }
    case NODUS_EVM_ABI_INT: {
        int neg = v[0] == '-';
        uint8_t m[32];
        if (nodus_evm_u256_dec(v + neg, m) != 0) return -1;
        /* |v| < 2^(bits-1), or == 2^(bits-1) when negative */
        uint8_t lim[32];
        memset(lim, 0, sizeof(lim));
        unsigned bit = t->bits - 1u;
        lim[31 - bit / 8] = (uint8_t)(1u << (bit % 8));
        int c = memcmp(m, lim, 32);
        if (c > 0 || (c == 0 && !neg)) return -1;
        if (!neg) { memcpy(w, m, 32); return 0; }
        /* two's complement: ~m + 1 */
        unsigned carry = 1;
        for (int i = 31; i >= 0; i--) {
            unsigned x = (unsigned)(uint8_t)~m[i] + carry;
            w[i] = (uint8_t)x;
            carry = x >> 8;
        }
        return 0;
    }
    case NODUS_EVM_ABI_FBYTES: {
        size_t n = 0;
        if (nodus_evm_hex_bytes(v, w, 32, &n) != 0 || n != t->size) return -1;
        return 0;
    }
    default:
        return -1;
    }
}

/* enc(T[] value) — one argv element "[v1,v2,...]" ("[]" = empty) → the
 * array's tail: its length word, then one static word per element
 * (abi-spec "Formal Specification of the Encoding", T[k] / T[]). *out heap.
 * @return 0 / -1 (message in err). */
static int evm_abi_array(const nodus_evm_abi_type_t *t, const char *v,
                         int argn, uint8_t **out, size_t *out_len,
                         char *err, size_t errcap) {
    *out = NULL;
    *out_len = 0;
    size_t vl = strlen(v);
    if (vl < 2 || v[0] != '[' || v[vl - 1] != ']') {
        abi_err(err, errcap, "argument %d: an array is written "
                "[v1,v2,...] ([] = empty), as one argument", argn);
        return -1;
    }
    char *body = malloc(vl - 1);
    if (!body) return -1;
    memcpy(body, v + 1, vl - 2);
    body[vl - 2] = '\0';
    size_t cnt = 0;
    for (const char *c = body; *c; c++) {
        if (*c != ' ') { cnt = 1; break; }
    }
    if (cnt)
        for (const char *c = body; *c; c++)
            if (*c == ',') cnt++;
    uint8_t *buf = calloc(1, 32 + cnt * 32);
    if (!buf) { free(body); return -1; }
    for (int k = 0; k < 8; k++)
        buf[31 - k] = (uint8_t)((uint64_t)cnt >> (8 * k));
    char *p = body;
    for (size_t e = 0; e < cnt; e++) {
        char *comma = strchr(p, ',');
        if (comma) *comma = '\0';
        while (*p == ' ') p++;
        size_t el = strlen(p);
        while (el && p[el - 1] == ' ') p[--el] = '\0';
        if (!*p || strchr(p, '[') || strchr(p, ']') ||
            evm_abi_word(t, p, buf + 32 + e * 32) != 0) {
            abi_err(err, errcap, "argument %d element %zu (%s) is not a "
                    "valid value of its type", argn, e + 1, p);
            free(buf);
            free(body);
            return -1;
        }
        if (comma) p = comma + 1;
    }
    free(body);
    *out = buf;
    *out_len = 32 + cnt * 32;
    return 0;
}

int nodus_evm_abi_encode(const nodus_evm_abi_type_t *ts, int n, char **vals,
                         uint8_t **out, size_t *out_len,
                         char *err, size_t errcap) {
    *out = NULL;
    *out_len = 0;
    if (err && errcap) err[0] = '\0';
    if (n < 0 || n > NODUS_EVM_ABI_MAX_ARGS) return -1;
    size_t head = (size_t)n * 32, tail = 0;
    uint8_t *dyn[NODUS_EVM_ABI_MAX_ARGS];
    size_t   dyn_len[NODUS_EVM_ABI_MAX_ARGS];
    memset(dyn, 0, sizeof(dyn));
    memset(dyn_len, 0, sizeof(dyn_len));
    int rc = -1;
    for (int i = 0; i < n; i++) {
        if (!evm_abi_dynamic(&ts[i])) continue;
        if (ts[i].arr) {
            if (evm_abi_array(&ts[i], vals[i], i + 1, &dyn[i],
                              &dyn_len[i], err, errcap) != 0)
                goto done;
            tail += dyn_len[i];
            continue;
        }
        size_t blen = 0;
        uint8_t *b = NULL;
        if (ts[i].k == NODUS_EVM_ABI_STRING) {
            blen = strlen(vals[i]);
            b = malloc(blen ? blen : 1);
            if (!b) goto done;
            memcpy(b, vals[i], blen);
        } else {
            size_t hl = strlen(vals[i]);
            b = malloc(hl / 2 + 1);
            if (!b || nodus_evm_hex_bytes(vals[i], b, hl / 2 + 1,
                                          &blen) != 0) {
                free(b);
                abi_err(err, errcap, "argument %d: bytes must be hex", i + 1);
                goto done;
            }
        }
        size_t padded = (blen + 31) / 32 * 32;
        dyn[i] = calloc(1, 32 + padded + 1);
        if (!dyn[i]) { free(b); goto done; }
        for (int k = 0; k < 8; k++)
            dyn[i][31 - k] = (uint8_t)((uint64_t)blen >> (8 * k));
        if (blen) memcpy(dyn[i] + 32, b, blen);
        free(b);
        dyn_len[i] = 32 + padded;
        tail += dyn_len[i];
    }
    uint8_t *buf = calloc(1, head + tail + 1);
    if (!buf) goto done;
    size_t toff = head;
    for (int i = 0; i < n; i++) {
        uint8_t *w = buf + (size_t)i * 32;
        if (evm_abi_dynamic(&ts[i])) {
            for (int k = 0; k < 8; k++)
                w[31 - k] = (uint8_t)((uint64_t)toff >> (8 * k));
            memcpy(buf + toff, dyn[i], dyn_len[i]);
            toff += dyn_len[i];
        } else if (evm_abi_word(&ts[i], vals[i], w) != 0) {
            abi_err(err, errcap, "argument %d (%s) is not a valid value of "
                    "its type", i + 1, vals[i]);
            free(buf);
            goto done;
        }
    }
    *out = buf;
    *out_len = head + tail;
    rc = 0;
done:
    for (int i = 0; i < n; i++) free(dyn[i]);
    return rc;
}
