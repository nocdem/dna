/* Nodus Connect core — P1a: the contact-request, delivery, check-scheduling
 * and contact-state rules (nc_rules.h), ported from src/connect/ui/text.js
 * and src/connect/core.js (web 0.1.101). Each function cites the JS line
 * it copies.
 *
 * The small accept-set / sort helpers below repeat nc_payload.c's private
 * ones (static there; that file is not part of this package's change).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_rules.h"

#include <stdlib.h>
#include <string.h>

#define NONE ((size_t)-1)

/* ── accept sets (text.js:8-9) ──────────────────────────────────────── */

static int is_dig(char c)  { return c >= '0' && c <= '9'; }
static int is_lhex(char c) { return is_dig(c) || (c >= 'a' && c <= 'f'); }

/* /^[0-9a-f]{128}$/ */
static int re_hex128(const char *s, size_t n) {
    if (n != 128) return 0;
    for (size_t i = 0; i < n; i++) if (!is_lhex(s[i])) return 0;
    return 1;
}
/* /^(0|[1-9]\d{0,19})$/ */
static int re_u64(const char *s, size_t n) {
    if (n < 1 || n > 20) return 0;
    for (size_t i = 0; i < n; i++) if (!is_dig(s[i])) return 0;
    return n == 1 || s[0] != '0';
}
static nc_u128_t dec(const char *s, size_t n) {
    nc_u128_t v = 0;
    for (size_t i = 0; i < n; i++) v = v * 10 + (unsigned)(s[i] - '0');
    return v;
}

/* String(v) without allocating: the string's own bytes, a number's
 * Number::toString in tmp, or the literal. */
static void str_view(const nc_val_t *v, char tmp[NC_JS_NUMSTR_MAX], const char **s, size_t *n) {
    switch (v->kind) {
    case NC_V_STR:   *s = v->n ? v->s : ""; *n = v->n; return;
    case NC_V_NUM:   nc_js_number_to_string(v->num, tmp); *s = tmp; *n = strlen(tmp); return;
    case NC_V_NULL:  *s = "null"; break;
    case NC_V_TRUE:  *s = "true"; break;
    case NC_V_FALSE: *s = "false"; break;
    default:         *s = "undefined"; break;
    }
    *n = strlen(*s);
}

/* U64.test(String(v)). *of_string = BigInt(String(v)); *exact = BigInt(v)
 * (for a Number the double's own value: an integer below 1e21, which
 * String() writes without an exponent, cast exactly). */
static int u64_of(const nc_val_t *v, nc_u128_t *of_string, nc_u128_t *exact) {
    char t[NC_JS_NUMSTR_MAX];
    const char *s;
    size_t n;
    if (v->kind != NC_V_STR && v->kind != NC_V_NUM) return 0;
    str_view(v, t, &s, &n);
    if (!re_u64(s, n)) return 0;
    nc_u128_t d = dec(s, n);
    if (of_string) *of_string = d;
    if (exact) *exact = v->kind == NC_V_NUM ? (nc_u128_t)v->num : d;
    return 1;
}
/* typeof v === 'string' && U64.test(v) */
static int u64_str(const nc_val_t *v, nc_u128_t *out) {
    if (v->kind != NC_V_STR || !re_u64(v->s, v->n)) return 0;
    if (out) *out = dec(v->s, v->n);
    return 1;
}
/* u64OrNull (text.js:314): BigInt(String(v)) when U64.test(String(v)) and
 * v is neither undefined nor null. */
static int u64_or_null(const nc_val_t *v, nc_u128_t *out) {
    if (v->kind == NC_V_UNDEF || v->kind == NC_V_NULL) return 0;
    return u64_of(v, out, NULL);
}

static int big_rc(nc_big_rc_t r) {
    switch (r) {
    case NC_BIG_OK:          return NC_P_OK;
    case NC_BIG_SYNTAX:      return NC_P_SYNTAX_ERROR;
    case NC_BIG_RANGE:       return NC_P_RANGE_ERROR;
    case NC_BIG_TYPE:        return NC_P_TYPE_ERROR;
    case NC_BIG_UNSUPPORTED: return NC_P_UNSUPPORTED;
    default:                 return NC_P_NOMEM;
    }
}

/* BigInt(m.<field>) where m is an element: reading a field of null throws
 * TypeError; a non-object element reads undefined (TypeError too). */
static int big_field(const nc_rmsg_t *m, const nc_val_t *field, nc_big_t *out) {
    if (m->elem != NC_ELEM_OBJECT) return NC_P_TYPE_ERROR;
    return big_rc(nc_big_from_val(out, field));
}

/* ── strings as values: views, sets ────────────────────────────────── */

typedef struct { const char *s; size_t n; } sv_t;

static int sv_cmp(const sv_t *a, const sv_t *b) {
    size_t m = a->n < b->n ? a->n : b->n;
    int c = m ? memcmp(a->s, b->s, m) : 0;
    if (c) return c < 0 ? -1 : 1;
    return a->n < b->n ? -1 : a->n > b->n ? 1 : 0;
}

/* ── a stable sort (JS Array.prototype.sort is stable) ──────────────── */

typedef int (*idx_cmp_fn)(const void *ctx, size_t a, size_t b);

static void msort(size_t *idx, size_t *tmp, size_t n, idx_cmp_fn cmp, const void *ctx) {
    if (n < 2) return;
    size_t h = n / 2;
    msort(idx, tmp, h, cmp, ctx);
    msort(idx + h, tmp, n - h, cmp, ctx);
    size_t i = 0, j = h, k = 0;
    while (i < h && j < n) tmp[k++] = (cmp(ctx, idx[j], idx[i]) < 0) ? idx[j++] : idx[i++];
    while (i < h) tmp[k++] = idx[i++];
    while (j < n) tmp[k++] = idx[j++];
    memcpy(idx, tmp, n * sizeof(size_t));
}
static int stable_sort(size_t *idx, size_t n, idx_cmp_fn cmp, const void *ctx) {
    if (n < 2) return 0;
    size_t *tmp = malloc(n * sizeof(size_t));
    if (!tmp) return -1;
    msort(idx, tmp, n, cmp, ctx);
    free(tmp);
    return 0;
}
int nc_stable_sort(size_t *idx, size_t n, int (*cmp)(const void *ctx, size_t a, size_t b), const void *ctx) {
    return stable_sort(idx, n, cmp, ctx);
}
static size_t *iota(size_t n) {
    size_t *p = malloc((n ? n : 1) * sizeof(size_t));
    if (p) for (size_t i = 0; i < n; i++) p[i] = i;
    return p;
}

/* A sorted set of string views; Set.prototype.has of a string. */
typedef struct { sv_t *v; size_t n; } svset_t;
static int sv_idx_cmp(const void *ctx, size_t a, size_t b) {
    const sv_t *v = ctx;
    return sv_cmp(&v[a], &v[b]);
}
static int svset_build(svset_t *set, const sv_t *items, size_t n) {
    set->v = NULL;
    set->n = 0;
    size_t *idx = iota(n);
    sv_t *v = malloc((n ? n : 1) * sizeof(sv_t));
    if (!idx || !v || stable_sort(idx, n, sv_idx_cmp, items) != 0) { free(idx); free(v); return -1; }
    for (size_t i = 0; i < n; i++) v[i] = items[idx[i]];
    free(idx);
    set->v = v;
    set->n = n;
    return 0;
}
static int svset_has(const svset_t *set, const char *s, size_t n) {
    sv_t key = { s, n };
    size_t lo = 0, hi = set->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = sv_cmp(&set->v[mid], &key);
        if (c == 0) return 1;
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* String() of a list of values, kept in one arena (offsets, then views). */
typedef struct { nc_sb_t arena; size_t *off, *len; size_t n; } strlist_t;
static void strlist_free(strlist_t *l) { nc_sb_free(&l->arena); free(l->off); free(l->len); }
static int strlist_init(strlist_t *l, size_t n) {
    nc_sb_init(&l->arena);
    l->n = 0;
    l->off = malloc((n ? n : 1) * sizeof(size_t));
    l->len = malloc((n ? n : 1) * sizeof(size_t));
    return l->off && l->len ? 0 : -1;
}
static void strlist_add(strlist_t *l, const nc_val_t *v) {
    char t[NC_JS_NUMSTR_MAX];
    const char *s;
    size_t n;
    str_view(v, t, &s, &n);
    l->off[l->n] = l->arena.len;
    l->len[l->n] = n;
    nc_sb_put(&l->arena, s, n);
    l->n++;
}
static sv_t strlist_at(const strlist_t *l, size_t i) {
    sv_t v = { l->arena.p ? l->arena.p + l->off[i] : "", l->len[i] };
    return v;
}

/* ── maps: own keys, then Object.prototype ──────────────────────────── */

/* Object.getOwnPropertyNames(Object.prototype) in V8 (node 22). */
static const char *const OBJ_PROTO[] = {
    "constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty",
    "__lookupGetter__", "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable",
    "toString", "valueOf", "__proto__", "toLocaleString"
};

int nc_rmap_get(const nc_rmap_t *m, const char *key, size_t key_n, nc_val_t *v, int *compound) {
    *v = nc_val_undef();
    if (compound) *compound = 0;
    if (!m->object) return 0;
    for (size_t i = 0; i < m->n; i++) {
        if (m->key_n[i] == key_n && (key_n == 0 || memcmp(m->key[i], key, key_n) == 0)) {
            *v = m->val[i];
            if (compound) *compound = m->compound ? m->compound[i] : 0;
            return 1;
        }
    }
    for (size_t i = 0; i < sizeof(OBJ_PROTO) / sizeof(OBJ_PROTO[0]); i++)
        if (nc_js_str_eq(key, key_n, OBJ_PROTO[i])) return 2;
    return 0;
}

/* obj[String(key)] for a map lookup. */
static int map_get_val(const nc_rmap_t *m, const nc_val_t *key, nc_val_t *v, int *compound) {
    char t[NC_JS_NUMSTR_MAX];
    const char *s;
    size_t n;
    str_view(key, t, &s, &n);
    return nc_rmap_get(m, s, n, v, compound);
}

/* A map's own keys sorted, for many lookups (checkOrder, needFullSync). */
typedef struct { const nc_rmap_t *m; size_t *idx; } mapidx_t;
static int map_key_cmp(const void *ctx, size_t a, size_t b) {
    const nc_rmap_t *m = ctx;
    sv_t x = { m->key[a], m->key_n[a] }, y = { m->key[b], m->key_n[b] };
    return sv_cmp(&x, &y);
}
static int mapidx_build(mapidx_t *mi, const nc_rmap_t *m) {
    mi->m = m;
    mi->idx = NULL;
    if (!m->object) return 0;
    mi->idx = iota(m->n);
    if (!mi->idx || stable_sort(mi->idx, m->n, map_key_cmp, m) != 0) { free(mi->idx); mi->idx = NULL; return -1; }
    return 0;
}
/* dmSync?.[key] as u64OrNull reads it: an inherited Object.prototype value
 * (a function, or the prototype object) is never a U64. */
static int mapidx_u64(const mapidx_t *mi, const nc_val_t *key, nc_u128_t *out) {
    if (!mi->m->object) return 0;
    char t[NC_JS_NUMSTR_MAX];
    const char *s;
    size_t n;
    str_view(key, t, &s, &n);
    sv_t k = { s, n };
    size_t lo = 0, hi = mi->m->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2, i = mi->idx[mid];
        sv_t x = { mi->m->key[i], mi->m->key_n[i] };
        int c = sv_cmp(&x, &k);
        if (c == 0) {
            if (mi->m->compound && mi->m->compound[i]) return 0;
            return u64_or_null(&mi->m->val[i], out);
        }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* ── requests (text.js:20-67) ───────────────────────────────────────── */

/* declinedFp (text.js:22): typeof d === 'string' ? d : d?.fp */
static nc_val_t declined_fp(const nc_decl_t *d) {
    if (d->is_str) return d->str;
    if (d->elem == NC_ELEM_OBJECT) return d->fp;
    return nc_val_undef();
}

/* A kept candidate of declinedNow: the element's position, its fp and at. */
typedef struct { size_t pos; const char *fp; nc_u128_t at; char as[24]; size_t an; } decl_cand_t;
static int decl_fp_cmp(const void *ctx, size_t a, size_t b) {
    const decl_cand_t *c = ctx;
    return memcmp(c[a].fp, c[b].fp, 128);
}
/* the result order: BigInt(at) ascending, ties in Map insertion order
 * (the stable sort of [...byFp.values()]) */
static int decl_out_cmp(const void *ctx, size_t a, size_t b) {
    const decl_cand_t *c = ctx;
    if (c[a].at != c[b].at) return c[a].at < c[b].at ? -1 : 1;
    return c[a].pos < c[b].pos ? -1 : c[a].pos > c[b].pos ? 1 : 0;
}

/* declinedNow over the elements, with one optional extra element appended
 * ({ fp: extra_fp, at: nowSeconds }, addDeclined).
 * byFp (text.js:25-33): a Map from fp; `byFp.set` on an existing key keeps
 * its insertion place, and replaces the value only for a strictly greater
 * at. So each fp ends at the place of its FIRST kept element with the
 * greatest at (equal values of a U64 string are equal strings). */
static int declined_core(const nc_decl_t *list, size_t n, const nc_decl_t *extra,
                         const nc_val_t *now_seconds, nc_decl_out_t **out, size_t *n_out,
                         const char **msg) {
    *out = NULL;
    *n_out = 0;
    nc_u128_t now;
    if (!u64_str(now_seconds, &now)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    size_t total = n + (extra ? 1 : 0);
    decl_cand_t *c = malloc((total ? total : 1) * sizeof(*c));
    if (!c) return NC_P_NOMEM;
    size_t nc = 0;
    for (size_t i = 0; i < total; i++) {
        const nc_decl_t *d = i < n ? &list[i] : extra;
        nc_val_t fp = declined_fp(d);
        if (fp.kind != NC_V_STR || !re_hex128(fp.s, fp.n)) continue;
        /* at = typeof d === 'string' ? nowSeconds : String(d.at) */
        char t[NC_JS_NUMSTR_MAX];
        const char *as;
        size_t an;
        if (d->is_str) { as = now_seconds->s; an = now_seconds->n; }
        else str_view(&d->at, t, &as, &an);
        if (!re_u64(as, an)) continue;
        nc_u128_t at = dec(as, an);
        if (now > at + NC_DECLINE_KEEP_SECONDS) continue;             /* now - at > KEEP */
        c[nc].pos = i;
        c[nc].fp = fp.s;
        c[nc].at = at;
        memcpy(c[nc].as, as, an);
        c[nc].as[an] = '\0';
        c[nc].an = an;
        nc++;
    }
    /* one per fp: place of the first, value of the first greatest at */
    size_t *idx = iota(nc);
    decl_cand_t *g = malloc((nc ? nc : 1) * sizeof(*g));
    if (!idx || !g || stable_sort(idx, nc, decl_fp_cmp, c) != 0) {
        free(idx); free(g); free(c);
        return NC_P_NOMEM;
    }
    size_t ng = 0;
    for (size_t i = 0; i < nc; i++) {
        const decl_cand_t *x = &c[idx[i]];
        if (ng && memcmp(g[ng - 1].fp, x->fp, 128) == 0) {
            if (x->at > g[ng - 1].at) {                               /* the value; the place stays */
                size_t pos = g[ng - 1].pos;
                g[ng - 1] = *x;
                g[ng - 1].pos = pos;
            }
        } else {
            g[ng++] = *x;                                             /* stable: the first by position */
        }
    }
    free(c);
    for (size_t i = 0; i < ng; i++) idx[i] = i;
    if (stable_sort(idx, ng, decl_out_cmp, g) != 0) { free(idx); free(g); return NC_P_NOMEM; }
    size_t from = ng > NC_DECLINE_MAX ? ng - NC_DECLINE_MAX : 0;          /* .slice(-DECLINE_MAX) */
    nc_decl_out_t *res = malloc(((ng - from) ? (ng - from) : 1) * sizeof(*res));
    if (!res) { free(idx); free(g); return NC_P_NOMEM; }
    for (size_t i = from; i < ng; i++) {
        const decl_cand_t *x = &g[idx[i]];
        res[i - from].fp = x->fp;
        memcpy(res[i - from].at, x->as, x->an + 1);
        res[i - from].at_n = x->an;
    }
    free(idx);
    free(g);
    *out = res;
    *n_out = ng - from;
    return NC_P_OK;
}

int nc_declined_now(const nc_decl_t *list, size_t n, const nc_val_t *now_seconds,
                    nc_decl_out_t **out, size_t *n_out, const char **msg) {
    return declined_core(list, n, NULL, now_seconds, out, n_out, msg);
}

int nc_is_declined(const nc_decl_t *list, size_t n, const nc_val_t *fp) {
    for (size_t i = 0; i < n; i++) {
        nc_val_t d = declined_fp(&list[i]);
        if (nc_val_strict_eq(&d, fp)) return 1;
    }
    return 0;
}

int nc_undecline(const nc_decl_t *list, size_t n, const nc_val_t *fp, size_t **keep, size_t *n_keep) {
    size_t *k = malloc((n ? n : 1) * sizeof(size_t));
    *keep = NULL;
    *n_keep = 0;
    if (!k) return NC_P_NOMEM;
    size_t nk = 0;
    for (size_t i = 0; i < n; i++) {
        nc_val_t d = declined_fp(&list[i]);
        if (!nc_val_strict_eq(&d, fp)) k[nk++] = i;
    }
    *keep = k;
    *n_keep = nk;
    return NC_P_OK;
}

int nc_add_declined(const nc_decl_t *list, size_t n, const nc_val_t *fp, const nc_val_t *now_seconds,
                    nc_decl_out_t **out, size_t *n_out, const char **msg) {
    /* declinedNow([...list.filter(d => declinedFp(d) !== fp), { fp, at: nowSeconds }], nowSeconds) */
    nc_decl_t *f = malloc((n + 1) * sizeof(*f));
    if (!f) { *out = NULL; *n_out = 0; return NC_P_NOMEM; }
    size_t nf = 0;
    for (size_t i = 0; i < n; i++) {
        nc_val_t d = declined_fp(&list[i]);
        if (!nc_val_strict_eq(&d, fp)) f[nf++] = list[i];
    }
    nc_decl_t extra;
    memset(&extra, 0, sizeof(extra));
    extra.elem = NC_ELEM_OBJECT;
    extra.fp = *fp;
    extra.at = *now_seconds;
    int rc = declined_core(f, nf, &extra, now_seconds, out, n_out, msg);
    free(f);
    return rc;
}

int nc_parse_contact_id(const nc_val_t *value, char out[129], const char **msg) {
    /* typeof value === 'string' ? value.replace(/\s+/g, '').toLowerCase() : '' */
    size_t k = 0;
    int ok = value->kind == NC_V_STR;
    for (size_t i = 0; ok && i < value->n;) {
        size_t w = nc_js_ws_at(value->s + i, value->n - i);
        if (w) { i += w; continue; }
        char c = value->s[i];
        if ((unsigned char)c >= 0x80 || k == 128) { ok = 0; break; }   /* see nc_rules.h */
        out[k++] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
        i++;
    }
    if (!ok || !re_hex128(out, k)) { *msg = NC_R_MSG_ID; return NC_P_THROW; }
    out[128] = '\0';
    return NC_P_OK;
}

int nc_request_refusal(const nc_val_t *fp, const nc_refusal_opts_t *o, const char **text) {
    nc_val_t own = nc_val_undef(), contact = nc_val_undef(), requested = nc_val_undef();
    if (!o->absent) {
        if (o->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;          /* destructuring null */
        if (o->elem == NC_ELEM_OBJECT) { own = o->own_fp; contact = o->is_contact; requested = o->is_requested; }
    }
    /* isContact = false / isRequested = false: an undefined reads false either way */
    if (nc_val_strict_eq(fp, &own)) *text = NC_R_REFUSE_OWN;
    else if (nc_val_truthy(&contact)) *text = NC_R_REFUSE_CONTACT;
    else if (nc_val_truthy(&requested)) *text = NC_R_REFUSE_REQUESTED;
    else *text = "";
    return NC_P_OK;
}

int nc_acceptance_may_auto_approve(const nc_accept_req_t *r, int pending_is_set,
                                   const nc_val_t *pending, size_t n_pending) {
    /* !!request && request.acceptance === true && request.message === MSG &&
     * typeof request.sender === 'string' && HEX128.test(request.sender) &&
     * pendingOutgoing instanceof Set && pendingOutgoing.has(request.sender) */
    if (r->elem != NC_ELEM_OBJECT) return 0;      /* null, or a scalar: its fields are undefined */
    if (r->acceptance.kind != NC_V_TRUE) return 0;
    if (!nc_val_is(&r->message, NC_CONTACT_ACCEPTED_MSG)) return 0;
    if (r->sender.kind != NC_V_STR || !re_hex128(r->sender.s, r->sender.n)) return 0;
    if (!pending_is_set) return 0;
    for (size_t i = 0; i < n_pending; i++)
        if (nc_val_strict_eq(&pending[i], &r->sender)) return 1;
    return 0;
}

int nc_accepted_salt(const nc_salt_of_t *mine, const nc_salt_of_t *request, nc_val_t *out) {
    /* mine?.salt || request.salt || null */
    if (mine->elem == NC_ELEM_OBJECT && nc_val_truthy(&mine->salt)) { *out = mine->salt; return NC_P_OK; }
    if (request->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    if (request->elem == NC_ELEM_OBJECT && nc_val_truthy(&request->salt)) { *out = request->salt; return NC_P_OK; }
    *out = nc_val_undef();
    out->kind = NC_V_NULL;
    return NC_P_OK;
}

/* ── delivery (text.js:349-486) ─────────────────────────────────────── */

int nc_is_delivered(const nc_rmsg_t *m) {
    return m->elem == NC_ELEM_OBJECT && m->delivered.kind == NC_V_TRUE;
}

const char *nc_message_status(const nc_rmsg_t *m) {
    if (nc_is_delivered(m)) return "delivered";
    if (m->elem == NC_ELEM_OBJECT && m->published.kind == NC_V_TRUE) return "sent";
    return "waiting to send";
}

/* m.dir === 'out' && m.fp === fp, after the null check (TypeError). */
static int own_to(const nc_rmsg_t *m, const nc_val_t *fp) {
    return m->elem == NC_ELEM_OBJECT && nc_val_is(&m->dir, "out") && nc_val_strict_eq(&m->fp, fp);
}

int nc_published_seqs(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      size_t **first, size_t *n_first) {
    *first = NULL;
    *n_first = 0;
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;                /* messages.filter */
    for (size_t i = 0; i < n; i++) if (m[i].elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    strlist_t sl;
    int sl_bad = strlist_init(&sl, n);                                /* always initialised */
    size_t *pick = malloc((n ? n : 1) * sizeof(size_t));
    if (!pick || sl_bad) { free(pick); strlist_free(&sl); return NC_P_NOMEM; }
    size_t np = 0;
    for (size_t i = 0; i < n; i++) {
        if (!own_to(&m[i], fp) || m[i].published.kind != NC_V_TRUE) continue;
        pick[np++] = i;
        strlist_add(&sl, &m[i].seq);                                   /* String(m.seq) */
    }
    if (sl.arena.oom) { free(pick); strlist_free(&sl); return NC_P_NOMEM; }
    /* new Set(...): the first of each distinct string, in order */
    sv_t *v = malloc((np ? np : 1) * sizeof(sv_t));
    size_t *idx = iota(np);
    if (!v || !idx) { free(v); free(idx); free(pick); strlist_free(&sl); return NC_P_NOMEM; }
    for (size_t i = 0; i < np; i++) v[i] = strlist_at(&sl, i);
    if (stable_sort(idx, np, sv_idx_cmp, v) != 0) { free(v); free(idx); free(pick); strlist_free(&sl); return NC_P_NOMEM; }
    unsigned char *dup = calloc(np ? np : 1, 1);
    if (!dup) { free(v); free(idx); free(pick); strlist_free(&sl); return NC_P_NOMEM; }
    for (size_t i = 1; i < np; i++)
        if (sv_cmp(&v[idx[i - 1]], &v[idx[i]]) == 0) dup[idx[i]] = 1;    /* stable: the first stays */
    size_t nf = 0;
    for (size_t i = 0; i < np; i++) if (!dup[i]) pick[nf++] = pick[i];
    free(dup);
    free(v);
    free(idx);
    strlist_free(&sl);
    *first = pick;
    *n_first = nf;
    return NC_P_OK;
}

int nc_mark_published(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      nc_list_t set_kind, const nc_rmsg_t *set, size_t n_set,
                      size_t **idx, size_t *n_idx) {
    *idx = NULL;
    *n_idx = 0;
    /* const sent = new Set(set.map(m => String(m.seq))) — first */
    if (set_kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;
    for (size_t i = 0; i < n_set; i++) if (set[i].elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;
    for (size_t i = 0; i < n; i++) if (m[i].elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    strlist_t sl;
    sv_t *items = malloc((n_set ? n_set : 1) * sizeof(sv_t));
    size_t *out = malloc((n ? n : 1) * sizeof(size_t));
    svset_t sent = { NULL, 0 };
    int rc = NC_P_NOMEM;
    if (strlist_init(&sl, n_set) != 0 || !items || !out) goto done;
    for (size_t i = 0; i < n_set; i++) {
        nc_val_t seq = set[i].elem == NC_ELEM_OBJECT ? set[i].seq : nc_val_undef();
        strlist_add(&sl, &seq);
    }
    if (sl.arena.oom) goto done;
    for (size_t i = 0; i < n_set; i++) items[i] = strlist_at(&sl, i);
    if (svset_build(&sent, items, n_set) != 0) goto done;
    size_t no = 0;
    for (size_t i = 0; i < n; i++) {
        if (!own_to(&m[i], fp) || m[i].published.kind == NC_V_TRUE) continue;
        char t[NC_JS_NUMSTR_MAX];
        const char *s;
        size_t sn;
        str_view(&m[i].seq, t, &s, &sn);
        if (svset_has(&sent, s, sn)) out[no++] = i;
    }
    *idx = out;
    *n_idx = no;
    out = NULL;
    rc = NC_P_OK;
done:
    free(out);
    free(items);
    free(sent.v);
    strlist_free(&sl);
    return rc;
}

/* publishedBefore.has(String(m.seq)): a Set of JSON scalars; only a string
 * element can equal a string (SameValueZero). */
static int scalar_set_build(svset_t *set, const nc_val_t *v, size_t n) {
    sv_t *items = malloc((n ? n : 1) * sizeof(sv_t));
    if (!items) return -1;
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (v[i].kind == NC_V_STR) { items[k].s = v[i].n ? v[i].s : ""; items[k].n = v[i].n; k++; }
    int rc = svset_build(set, items, k);
    free(items);
    return rc;
}

int nc_mark_delivered(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      const nc_val_t *ack_ts, int before_is_set, const nc_val_t *before, size_t n_before,
                      const nc_val_t *now_seconds, size_t **idx, size_t *n_idx, const char **msg) {
    *idx = NULL;
    *n_idx = 0;
    nc_u128_t ack;
    if (!u64_str(ack_ts, &ack) || nc_val_is(ack_ts, "0") || !before_is_set) return NC_P_OK;   /* [] */
    if (!u64_str(now_seconds, NULL)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;
    for (size_t i = 0; i < n; i++) if (m[i].elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    svset_t set;
    if (scalar_set_build(&set, before, n_before) != 0) return NC_P_NOMEM;
    size_t *out = malloc((n ? n : 1) * sizeof(size_t));
    if (!out) { free(set.v); return NC_P_NOMEM; }
    size_t no = 0;
    for (size_t i = 0; i < n; i++) {
        if (!own_to(&m[i], fp) || nc_is_delivered(&m[i])) continue;
        char t[NC_JS_NUMSTR_MAX];
        const char *s;
        size_t sn;
        str_view(&m[i].seq, t, &s, &sn);
        if (!svset_has(&set, s, sn)) continue;
        nc_u128_t ts;
        /* U64.test(String(m.ts)) && BigInt(m.ts) < ack */
        if (!u64_of(&m[i].ts, NULL, &ts) || !(ts < ack)) continue;
        out[no++] = i;
    }
    free(set.v);
    *idx = out;
    *n_idx = no;
    return NC_P_OK;
}

int nc_ack_to_send(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                   const nc_val_t *last_sent, int *has, nc_u128_t *value) {
    *has = 0;
    *value = 0;
    if (kind == NC_LIST_BAD) return NC_P_TYPE_ERROR;                  /* for…of a non-iterable */
    nc_u128_t newest = 0;
    for (size_t i = 0; kind == NC_LIST_ARRAY && i < n; i++) {
        if (m[i].elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
        if (m[i].elem != NC_ELEM_OBJECT || !nc_val_is(&m[i].dir, "in") || !nc_val_strict_eq(&m[i].fp, fp)) continue;
        nc_u128_t ts;
        if (!u64_of(&m[i].sender_ts, NULL, &ts)) continue;             /* BigInt(m.senderTs) */
        if (ts > newest) newest = ts;
    }
    if (newest == 0) return NC_P_OK;
    nc_u128_t last;
    if (u64_str(last_sent, &last) && newest <= last) return NC_P_OK;
    *has = 1;
    *value = newest;
    return NC_P_OK;
}

int nc_ack_allowed(const nc_ack_flags_t *f, int *allowed) {
    *allowed = 0;
    if (f->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    if (f->elem != NC_ELEM_OBJECT) return NC_P_OK;
    *allowed = f->persistent.kind == NC_V_TRUE && f->complete.kind == NC_V_TRUE && !nc_val_truthy(&f->lost);
    return NC_P_OK;
}

/* inGrace (text.js:385): isDelivered(m) && U64.test(String(m.deliveredAt))
 * && BigInt(m.deliveredAt) + DELIVERED_GRACE_SECONDS > now */
static int in_grace(const nc_rmsg_t *m, nc_u128_t now) {
    nc_u128_t at;
    return nc_is_delivered(m) && u64_of(&m->delivered_at, NULL, &at) &&
           at + NC_DELIVERED_GRACE_SECONDS > now;
}

/* BigInt(m.ts) > now - OUTBOX_LIFETIME_SECONDS (oldest may be negative):
 * BigInt(m.ts) + LIFETIME > now. *rc: a BigInt throw. */
static int within_lifetime(const nc_rmsg_t *m, const nc_big_t *now_big, nc_big_t *ts, int *rc) {
    *rc = big_field(m, &m->ts, ts);
    if (*rc != NC_P_OK) return 0;
    nc_big_t t;
    nc_big_init(&t);
    nc_big_rc_t b = nc_big_from_u128(&t, NC_OUTBOX_LIFETIME_SECONDS);
    if (b == NC_BIG_OK) {
        nc_big_t sum;
        nc_big_init(&sum);
        b = nc_big_add(&sum, ts);
        if (b == NC_BIG_OK) b = nc_big_add(&sum, &t);
        int r = b == NC_BIG_OK && nc_big_cmp(&sum, now_big) > 0;
        nc_big_free(&sum);
        nc_big_free(&t);
        if (b != NC_BIG_OK) { *rc = NC_P_NOMEM; return 0; }
        return r;
    }
    nc_big_free(&t);
    *rc = NC_P_NOMEM;
    return 0;
}

/* compareLocal's keys and V8's comparator order (nc_rules.h). */
static int bigkey_cmp(const void *ctx, size_t a, size_t b) {
    const nc_big_t *k = ctx;
    return nc_big_cmp(&k[a], &k[b]);
}
static size_t v8_min_run(size_t n) {
    size_t r = 0;
    while (n >= 64) { r |= n & 1; n >>= 1; }
    return n + r;
}
/* The first element (by V8 TimSort's first comparator call on it) whose key
 * throws; NONE if none does or n < 2 (no comparator call). Comparisons
 * before it only involve valid keys; ok[] = 1 for a valid key. *nomem on
 * allocation failure. */
static size_t v8_first_throw(size_t n, const int *ok, idx_cmp_fn cmp, const void *ctx, int *nomem) {
    *nomem = 0;
    if (n < 2) return NONE;
    int any = 0;
    for (size_t i = 0; i < n; i++) if (!ok[i]) { any = 1; break; }
    if (!any) return NONE;
    unsigned char *seen = calloc(n, 1);
    if (!seen) { *nomem = 1; return NONE; }
    size_t bad = NONE;
#define TOUCH(i) do { size_t t_ = (i); if (!seen[t_]) { seen[t_] = 1; if (!ok[t_]) { bad = t_; goto done; } } } while (0)
    size_t min_run = v8_min_run(n), low = 0;
    while (low < n) {
        size_t rem = n - low, run;
        if (rem == 1) { TOUCH(low); break; }
        /* CountAndMakeRun: Compare(a[low+1], a[low]), then forward */
        TOUCH(low + 1);
        TOUCH(low);
        int desc = cmp(ctx, low + 1, low) < 0;
        run = 2;
        for (size_t i = low + 2; i < n; i++) {
            TOUCH(i);
            int o = cmp(ctx, i, i - 1);
            if (desc ? o >= 0 : o < 0) break;
            run++;
        }
        if (run < min_run) {
            /* BinaryInsertionSort: each pivot is the first argument */
            size_t forced = min_run < rem ? min_run : rem;
            for (size_t s = low + run; s < low + forced; s++) TOUCH(s);
            run = forced;
        }
        low += run;
    }
#undef TOUCH
done:
    free(seen);
    return bad;
}

/* The replay order of the outbox trim (text.js:456): newest first by
 * sender time, then seq. */
typedef struct { size_t msg; const nc_big_t *ts, *seq; char key[64 + 1 + 8]; size_t key_n; } replay_t;
static int replay_cmp(const void *ctx, size_t a, size_t b) {
    const replay_t *r = ctx;
    int t = nc_big_cmp(r[a].ts, r[b].ts);
    if (t == 0) {
        int s = nc_big_cmp(r[a].seq, r[b].seq);
        return s < 0 ? 1 : s > 0 ? -1 : 0;
    }
    return t < 0 ? 1 : -1;
}
static int replay_key_cmp(const void *ctx, size_t a, size_t b) {
    const replay_t *r = ctx;
    sv_t x = { r[a].key, r[a].key_n }, y = { r[b].key, r[b].key_n };
    return sv_cmp(&x, &y);
}

int nc_pending_outbox(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                      const nc_val_t *now_seconds, size_t **out, size_t *n_out, const char **msg) {
    *out = NULL;
    *n_out = 0;
    nc_u128_t now;
    if (!u64_str(now_seconds, &now)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;                /* messages.filter */

    int rc = NC_P_OK;
    nc_big_t now_big, *ts = NULL, *seq = NULL;
    size_t *list = NULL, *idx = NULL, *kept = NULL, *ridx = NULL;
    int *ok = NULL;
    replay_t *rp = NULL;
    unsigned char *moot = NULL;
    size_t nl = 0;
    nc_big_init(&now_big);
    if (nc_big_from_u128(&now_big, now) != NC_BIG_OK) return NC_P_NOMEM;
    ts = calloc(n ? n : 1, sizeof(*ts));
    list = malloc((n ? n : 1) * sizeof(size_t));
    if (!ts || !list) { rc = NC_P_NOMEM; goto done; }
    for (size_t i = 0; i < n; i++) nc_big_init(&ts[i]);

    /* .filter(m => m.dir === 'out' && m.fp === fp && BigInt(m.ts) > oldest &&
     *              (!isDelivered(m) || inGrace(m, now))) */
    for (size_t i = 0; i < n; i++) {
        if (m[i].elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; goto done; }
        if (!own_to(&m[i], fp)) continue;
        int r;
        int live = within_lifetime(&m[i], &now_big, &ts[i], &r);
        if (r != NC_P_OK) { rc = r; goto done; }
        if (!live) continue;
        if (nc_is_delivered(&m[i]) && !in_grace(&m[i], now)) continue;
        list[nl++] = i;
    }

    /* .sort(compareLocal): BigInt(seq) of each element the comparator sees */
    seq = calloc(nl ? nl : 1, sizeof(*seq));
    ok = calloc(nl ? nl : 1, sizeof(*ok));
    int *err = calloc(nl ? nl : 1, sizeof(*err));
    if (!seq || !ok || !err) { free(err); rc = NC_P_NOMEM; goto done; }
    for (size_t i = 0; i < nl; i++) {
        nc_big_init(&seq[i]);
        err[i] = big_field(&m[list[i]], &m[list[i]].seq, &seq[i]);
        if (err[i] == NC_P_NOMEM) { free(err); rc = NC_P_NOMEM; goto done; }
        ok[i] = err[i] == NC_P_OK;
    }
    {
        int nomem;
        size_t bad = v8_first_throw(nl, ok, bigkey_cmp, seq, &nomem);
        if (nomem) { free(err); rc = NC_P_NOMEM; goto done; }
        if (bad != NONE) { rc = err[bad]; free(err); goto done; }
    }
    free(err);
    idx = iota(nl);
    if (!idx || stable_sort(idx, nl, bigkey_cmp, seq) != 0) { rc = NC_P_NOMEM; goto done; }

    /* kept: positions p into list (idx[p] = the list entry) */
    kept = malloc((nl ? nl : 1) * sizeof(size_t));
    if (!kept) { rc = NC_P_NOMEM; goto done; }
    size_t nk = nl;
    for (size_t p = 0; p < nl; p++) kept[p] = idx[p];

    if (nk > NC_OUTBOX_MAX) {
        /* replay: the reactions parseReaction accepts, newest first */
        rp = malloc(nk * sizeof(*rp));
        moot = calloc(nl, 1);
        if (!rp || !moot) { rc = NC_P_NOMEM; goto done; }
        size_t nr = 0;
        nc_sb_t txt;
        nc_sb_init(&txt);
        for (size_t p = 0; p < nk; p++) {
            size_t e = kept[p];
            const nc_rmsg_t *x = &m[list[e]];
            if (!nc_val_is(&x->kind, "reaction")) continue;
            nc_sb_reset(&txt);
            nc_val_tostring(&x->text, &txt);                           /* parseReaction: String(text) */
            nc_sb_put(&txt, "", 0);
            if (txt.oom) { nc_sb_free(&txt); rc = NC_P_NOMEM; goto done; }
            nc_reaction_t r;
            if (nc_parse_reaction(txt.p, txt.len, &r) != NC_P_OK) continue;
            replay_t *q = &rp[nr++];
            q->msg = e;
            q->ts = &ts[list[e]];
            q->seq = &seq[e];
            /* `${r.target.toLowerCase()} ${r.emoji}`: target is 64 hex */
            for (size_t k = 0; k < 64; k++) {
                char c = r.target[k];
                q->key[k] = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
            }
            q->key[64] = ' ';
            memcpy(q->key + 65, r.emoji, r.emoji_n);
            q->key_n = 65 + r.emoji_n;
        }
        nc_sb_free(&txt);
        ridx = iota(nr);
        if (!ridx || stable_sort(ridx, nr, replay_cmp, rp) != 0) { rc = NC_P_NOMEM; goto done; }
        /* later / moot: in replay order the first of a key is kept */
        replay_t *rs = malloc((nr ? nr : 1) * sizeof(*rs));
        size_t *kidx = iota(nr);
        if (!rs || !kidx) { free(rs); free(kidx); rc = NC_P_NOMEM; goto done; }
        for (size_t i = 0; i < nr; i++) rs[i] = rp[ridx[i]];
        if (stable_sort(kidx, nr, replay_key_cmp, rs) != 0) { free(rs); free(kidx); rc = NC_P_NOMEM; goto done; }
        for (size_t i = 1; i < nr; i++)
            if (replay_key_cmp(rs, kidx[i - 1], kidx[i]) == 0) moot[rs[kidx[i]].msg] = 1;
        free(rs);
        free(kidx);
        size_t w = 0;
        for (size_t p = 0; p < nk; p++) if (!moot[kept[p]]) kept[w++] = kept[p];
        nk = w;
        if (nk > NC_OUTBOX_MAX) {
            /* kept.filter(m => m.kind !== 'reaction' || extra-- <= 0) */
            size_t extra = nk - NC_OUTBOX_MAX;
            w = 0;
            for (size_t p = 0; p < nk; p++) {
                if (nc_val_is(&m[list[kept[p]]].kind, "reaction") && extra > 0) { extra--; continue; }
                kept[w++] = kept[p];
            }
            nk = w;
        }
        if (nk > NC_OUTBOX_MAX) {                                      /* .slice(-OUTBOX_MAX) */
            size_t from = nk - NC_OUTBOX_MAX;
            memmove(kept, kept + from, NC_OUTBOX_MAX * sizeof(size_t));
            nk = NC_OUTBOX_MAX;
        }
    }
    for (size_t p = 0; p < nk; p++) kept[p] = list[kept[p]];
    *out = kept;
    *n_out = nk;
    kept = NULL;
done:
    nc_big_free(&now_big);
    if (ts) for (size_t i = 0; i < n; i++) nc_big_free(&ts[i]);
    if (seq) for (size_t i = 0; i < nl; i++) nc_big_free(&seq[i]);
    free(ts);
    free(seq);
    free(ok);
    free(list);
    free(idx);
    free(kept);
    free(rp);
    free(ridx);
    free(moot);
    return rc;
}

int nc_has_undelivered(nc_list_t kind, const nc_rmsg_t *m, size_t n, const nc_val_t *fp,
                       const nc_val_t *now_seconds, int *has, const char **msg) {
    *has = 0;
    nc_u128_t now;
    if (!u64_str(now_seconds, &now)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;                /* messages.some */
    nc_big_t now_big;
    nc_big_init(&now_big);
    if (nc_big_from_u128(&now_big, now) != NC_BIG_OK) return NC_P_NOMEM;
    int rc = NC_P_OK;
    for (size_t i = 0; i < n; i++) {
        if (m[i].elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; break; }
        if (!own_to(&m[i], fp)) continue;
        nc_big_t ts;
        nc_big_init(&ts);
        int r;
        int live = within_lifetime(&m[i], &now_big, &ts, &r);
        nc_big_free(&ts);
        if (r != NC_P_OK) { rc = r; break; }
        if (live && !nc_is_delivered(&m[i])) { *has = 1; break; }    /* .some stops here */
    }
    nc_big_free(&now_big);
    return rc;
}

int nc_compare_local(const nc_rmsg_t *a, const nc_rmsg_t *b, int *order) {
    *order = 0;
    nc_big_t x, y;
    nc_big_init(&x);
    nc_big_init(&y);
    int rc = big_field(a, &a->seq, &x);                               /* BigInt(a.seq) first */
    if (rc == NC_P_OK) rc = big_field(b, &b->seq, &y);
    if (rc == NC_P_OK) *order = nc_big_cmp(&x, &y);
    nc_big_free(&x);
    nc_big_free(&y);
    return rc;
}

/* A JSON array element as JSON.stringify writes it (undefined -> null). */
static void w_elem(nc_sb_t *b, const nc_val_t *v) {
    switch (v->kind) {
    case NC_V_STR:   nc_js_write_string(b, v->n ? v->s : "", v->n); break;
    case NC_V_NUM:   nc_js_write_number(b, v->num); break;
    case NC_V_TRUE:  nc_sb_puts(b, "true"); break;
    case NC_V_FALSE: nc_sb_puts(b, "false"); break;
    default:         nc_sb_puts(b, "null"); break;
    }
}

int nc_received_key(const nc_val_t *fp, const nc_rmsg_t *m, nc_sb_t *out) {
    if (m->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    nc_val_t seq = nc_val_undef(), sts = nc_val_undef(), text = nc_val_undef();
    if (m->elem == NC_ELEM_OBJECT) { seq = m->seq; sts = m->sender_ts; text = m->text; }
    nc_sb_t s;
    nc_sb_init(&s);
    nc_sb_putc(out, '[');
    w_elem(out, fp);
    nc_sb_putc(out, ',');
    nc_val_tostring(&seq, &s);
    nc_js_write_string(out, s.p ? s.p : "", s.len);
    nc_sb_putc(out, ',');
    nc_sb_reset(&s);
    nc_val_tostring(&sts, &s);
    nc_js_write_string(out, s.p ? s.p : "", s.len);
    nc_sb_putc(out, ',');
    w_elem(out, &text);
    nc_sb_putc(out, ']');
    int oom = s.oom || out->oom;
    nc_sb_free(&s);
    return oom ? NC_P_NOMEM : NC_P_OK;
}

/* ── check scheduling (text.js:256-329) ─────────────────────────────── */

int nc_contact_needs_full_sync(const nc_val_t *fp, const nc_rmap_t *dm_sync, const nc_val_t *now,
                               int *full, const char **msg) {
    nc_u128_t t, last;
    if (!u64_or_null(now, &t)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    nc_val_t v;
    int compound = 0;
    int got = map_get_val(dm_sync, fp, &v, &compound) == 1 && !compound && u64_or_null(&v, &last);
    /* last === null || last === 0n || t - last > SMART_SYNC_FULL_SECONDS */
    *full = !got || last == 0 || t > last + NC_SMART_SYNC_FULL_SECONDS;
    return NC_P_OK;
}

int nc_need_full_sync(nc_list_t kind, const nc_val_t *fps, size_t n, const nc_rmap_t *dm_sync,
                      const nc_val_t *now, int *full, const char **msg) {
    *full = 0;
    nc_u128_t t;
    if (!u64_or_null(now, &t)) { *msg = NC_R_MSG_TIME; return NC_P_THROW; }
    if (kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;                /* contactFps.some */
    mapidx_t mi;
    if (mapidx_build(&mi, dm_sync) != 0) return NC_P_NOMEM;
    for (size_t i = 0; i < n; i++) {
        nc_u128_t last;
        if (!mapidx_u64(&mi, &fps[i], &last) || last == 0 || t > last + NC_SMART_SYNC_FULL_SECONDS) {
            *full = 1;
            break;
        }
    }
    free(mi.idx);
    return NC_P_OK;
}

int nc_full_days(const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg) {
    nc_u128_t d;
    *n_days = 0;
    if (!u64_str(today, &d)) { *msg = NC_R_MSG_DAY; return NC_P_THROW; }
    /* for k = -6 .. 1: d + k >= 0 */
    for (int k = -6; k <= 1; k++) {
        if (k < 0 && d < (nc_u128_t)(-k)) continue;
        days[(*n_days)++] = k < 0 ? d - (nc_u128_t)(-k) : d + (nc_u128_t)k;
    }
    return NC_P_OK;
}

int nc_recent_days(const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg) {
    nc_u128_t d;
    *n_days = 0;
    if (!u64_str(today, &d)) { *msg = NC_R_MSG_DAY; return NC_P_THROW; }
    if (d > 0) days[(*n_days)++] = d - 1;
    days[(*n_days)++] = d;
    days[(*n_days)++] = d + 1;
    return NC_P_OK;
}

int nc_contact_days(const nc_val_t *fp, const nc_rmap_t *dm_sync, const nc_val_t *now,
                    const nc_val_t *today, nc_u128_t days[8], size_t *n_days, const char **msg) {
    int full;
    *n_days = 0;
    int rc = nc_contact_needs_full_sync(fp, dm_sync, now, &full, msg);
    if (rc != NC_P_OK) return rc;
    return full ? nc_full_days(today, days, n_days, msg) : nc_recent_days(today, days, n_days, msg);
}

/* checkOrder's newest map: (fp string, newest seq) of the messages. */
typedef struct { sv_t fp; nc_u128_t seq; } newest_t;
static int newest_cmp(const void *ctx, size_t a, size_t b) {
    const newest_t *v = ctx;
    return sv_cmp(&v[a].fp, &v[b].fp);
}
typedef struct { size_t index; int rank; nc_u128_t seq; } ord_t;
static int ord_cmp(const void *ctx, size_t a, size_t b) {
    const ord_t *o = ctx;
    if (o[a].rank != o[b].rank) return o[a].rank - o[b].rank;
    if (o[a].rank == 1 && o[a].seq != o[b].seq) return o[a].seq > o[b].seq ? -1 : 1;
    return o[a].index < o[b].index ? -1 : o[a].index > o[b].index ? 1 : 0;
}

int nc_check_order(nc_list_t kind, const nc_rmsg_t *contacts, size_t n,
                   const nc_rmap_t *dm_sync, nc_list_t msg_kind, const nc_rmsg_t *msgs, size_t n_msgs,
                   size_t **order) {
    *order = NULL;
    /* for (const m of messages || []) — first */
    if (msg_kind == NC_LIST_BAD) return NC_P_TYPE_ERROR;
    size_t nm = msg_kind == NC_LIST_ARRAY ? n_msgs : 0;
    newest_t *nw = malloc((nm ? nm : 1) * sizeof(*nw));
    if (!nw) return NC_P_NOMEM;
    size_t nn = 0;
    for (size_t i = 0; i < nm; i++) {
        const nc_rmsg_t *x = &msgs[i];
        /* !m || typeof m.fp !== 'string' || !U64.test(String(m.seq)) */
        if (x->elem != NC_ELEM_OBJECT || x->fp.kind != NC_V_STR) continue;
        nc_u128_t s;
        if (!u64_of(&x->seq, &s, NULL)) continue;                     /* BigInt(String(m.seq)) */
        nw[nn].fp.s = x->fp.n ? x->fp.s : "";
        nw[nn].fp.n = x->fp.n;
        nw[nn].seq = s;
        nn++;
    }
    size_t *ni = iota(nn);
    if (!ni || stable_sort(ni, nn, newest_cmp, nw) != 0) { free(ni); free(nw); return NC_P_NOMEM; }
    /* collapse to one (fp, max seq) per fp, sorted by fp */
    newest_t *grp = malloc((nn ? nn : 1) * sizeof(*grp));
    if (!grp) { free(ni); free(nw); return NC_P_NOMEM; }
    size_t ng = 0;
    for (size_t i = 0; i < nn; i++) {
        const newest_t *x = &nw[ni[i]];
        if (ng && sv_cmp(&grp[ng - 1].fp, &x->fp) == 0) {
            if (x->seq > grp[ng - 1].seq) grp[ng - 1].seq = x->seq;
        } else {
            grp[ng++] = *x;
        }
    }
    free(ni);
    free(nw);

    if (kind != NC_LIST_ARRAY) { free(grp); return NC_P_TYPE_ERROR; }  /* contacts.map */
    mapidx_t mi;
    ord_t *o = malloc((n ? n : 1) * sizeof(*o));
    if (!o || mapidx_build(&mi, dm_sync) != 0) { free(o); free(grp); return NC_P_NOMEM; }
    int rc = NC_P_OK;
    for (size_t i = 0; i < n; i++) {
        const nc_rmsg_t *c = &contacts[i];
        if (c->elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; break; } /* contact.fp */
        nc_val_t cfp = c->elem == NC_ELEM_OBJECT ? c->fp : nc_val_undef();
        o[i].index = i;
        o[i].seq = 0;
        nc_u128_t last;
        if (!mapidx_u64(&mi, &cfp, &last) || last == 0) { o[i].rank = 0; continue; }
        o[i].rank = 2;
        if (cfp.kind != NC_V_STR) continue;                           /* newest.has: string keys */
        sv_t k = { cfp.n ? cfp.s : "", cfp.n };
        size_t lo = 0, hi = ng;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int cmp = sv_cmp(&grp[mid].fp, &k);
            if (cmp == 0) { o[i].rank = 1; o[i].seq = grp[mid].seq; break; }
            if (cmp < 0) lo = mid + 1; else hi = mid;
        }
    }
    free(mi.idx);
    free(grp);
    if (rc != NC_P_OK) { free(o); return rc; }
    size_t *idx = iota(n);
    if (!idx || stable_sort(idx, n, ord_cmp, o) != 0) { free(idx); free(o); return NC_P_NOMEM; }
    free(o);
    *order = idx;
    return NC_P_OK;
}

int nc_profile_fresh(const nc_rmsg_t *entry, const nc_val_t *entry_at, const nc_val_t *now) {
    nc_u128_t at, t;
    /* entry?.at: a non-object entry reads undefined (or, for a string or an
     * array, the method `at`, which is not a U64 either) */
    nc_val_t a = entry->elem == NC_ELEM_OBJECT ? *entry_at : nc_val_undef();
    if (!u64_or_null(&a, &at) || !u64_or_null(now, &t)) return 0;
    return t >= at && t - at < NC_PROFILE_CACHE_SECONDS;
}

/* ── contact state (text.js:494-565) ─────────────────────────────────── */

int nc_merge_listed_contacts(const nc_rstate_t *st, nc_list_t entries_kind,
                             const nc_rcontact_t *entries, size_t n_entries, const nc_val_t *own_fp,
                             nc_contact_edit_t **edits, size_t *n_edits, int *changed) {
    *edits = NULL;
    *n_edits = 0;
    *changed = 0;
    /* const removed = new Set(state.removed) */
    if (st->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
    svset_t removed = { NULL, 0 };
    if (st->elem == NC_ELEM_OBJECT && st->removed_array &&
        scalar_set_build(&removed, st->removed, st->n_removed) != 0) return NC_P_NOMEM;
    /* for (const entry of entries || []) */
    if (entries_kind == NC_LIST_BAD) { free(removed.v); return NC_P_TYPE_ERROR; }
    size_t ne = entries_kind == NC_LIST_ARRAY ? n_entries : 0;

    /* the working copy of state.contacts: the elements, then the pushed ones */
    size_t nc = st->contacts_kind == NC_LIST_ARRAY ? st->n_contacts : 0;
    nc_rcontact_t *c = malloc((nc + ne + 1) * sizeof(*c));
    nc_contact_edit_t *ed = malloc((2 * ne + 1) * sizeof(*ed));
    if (!c || !ed) { free(c); free(ed); free(removed.v); return NC_P_NOMEM; }
    if (nc) memcpy(c, st->contacts, nc * sizeof(*c));
    size_t ned = 0;
    int rc = NC_P_OK;
    for (size_t i = 0; i < ne; i++) {
        const nc_rcontact_t *e = &entries[i];
        /* !entry || !HEX128.test(entry.fp) || entry.fp === ownFp || removed.has(entry.fp)
         * (HEX128.test(String(x)): only a string can be 128 hex) */
        if (e->elem != NC_ELEM_OBJECT || e->fp.kind != NC_V_STR || !re_hex128(e->fp.s, e->fp.n)) continue;
        if (nc_val_strict_eq(&e->fp, own_fp) || svset_has(&removed, e->fp.s, e->fp.n)) continue;
        if (st->contacts_kind != NC_LIST_ARRAY) { rc = NC_P_TYPE_ERROR; break; }   /* state.contacts.find */
        size_t local = NONE;
        for (size_t k = 0; k < nc; k++) {
            if (c[k].elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; break; }        /* c.fp */
            if (c[k].elem == NC_ELEM_OBJECT && nc_val_strict_eq(&c[k].fp, &e->fp)) { local = k; break; }
        }
        if (rc != NC_P_OK) break;
        if (local == NONE) {
            /* state.contacts.push({ fp: entry.fp, salt: entry.salt || null, listed: true }) */
            memset(&c[nc], 0, sizeof(c[nc]));
            c[nc].elem = NC_ELEM_OBJECT;
            c[nc].fp = e->fp;
            if (nc_val_truthy(&e->salt)) c[nc].salt = e->salt;
            else { c[nc].salt = nc_val_undef(); c[nc].salt.kind = NC_V_NULL; }
            c[nc].listed = nc_val_undef();
            c[nc].listed.kind = NC_V_TRUE;
            ed[ned].kind = NC_EDIT_PUSH; ed[ned].contact = nc; ed[ned].entry = i; ned++;
            nc++;
            *changed = 1;
        } else {
            if (!nc_val_truthy(&c[local].salt) && nc_val_truthy(&e->salt)) {
                c[local].salt = e->salt;
                ed[ned].kind = NC_EDIT_SALT; ed[ned].contact = local; ed[ned].entry = i; ned++;
                *changed = 1;
            }
            if (!nc_val_truthy(&c[local].listed)) {
                c[local].listed = nc_val_undef();
                c[local].listed.kind = NC_V_TRUE;
                ed[ned].kind = NC_EDIT_LISTED; ed[ned].contact = local; ed[ned].entry = i; ned++;
                *changed = 1;
            }
        }
    }
    free(c);
    free(removed.v);
    if (rc != NC_P_OK) { free(ed); *changed = 0; return rc; }
    *edits = ed;
    *n_edits = ned;
    return NC_P_OK;
}

int nc_remove_contact(const nc_rstate_t *st, const nc_val_t *fp, nc_remove_out_t *out) {
    memset(out, 0, sizeof(*out));
    /* const index = state.contacts.findIndex(c => c.fp === fp) */
    if (st->elem != NC_ELEM_OBJECT || st->contacts_kind != NC_LIST_ARRAY) return NC_P_TYPE_ERROR;
    size_t index = NONE;
    for (size_t k = 0; k < st->n_contacts; k++) {
        const nc_rcontact_t *c = &st->contacts[k];
        if (c->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
        nc_val_t cfp = c->elem == NC_ELEM_OBJECT ? c->fp : nc_val_undef();
        if (nc_val_strict_eq(&cfp, fp)) { index = k; break; }
    }
    if (index == NONE) return NC_P_OK;                                /* false */
    /* if (!state.removed.includes(fp)) state.removed.push(fp) */
    if (!st->removed_array) return NC_P_TYPE_ERROR;
    int has = 0;
    for (size_t k = 0; k < st->n_removed; k++)
        if (nc_val_strict_eq(&st->removed[k], fp)) { has = 1; break; }   /* SameValueZero on JSON scalars */
    /* delete state.dmSync[fp], profileCache[fp], chainNames[fp] */
    if (!st->dm_sync.object || !st->profile_cache.object || !st->chain_names.object) return NC_P_TYPE_ERROR;
    out->removed = 1;
    out->index = index;
    out->push_removed = !has;
    out->del_no_name = st->chain_no_name.object;                      /* if (state.chainNoName) */
    return NC_P_OK;
}

int nc_unremove_contact(const nc_rstate_t *st, const nc_val_t *fp, size_t **keep, size_t *n_keep) {
    *keep = NULL;
    *n_keep = 0;
    /* state.removed = state.removed.filter(r => r !== fp) */
    if (st->elem != NC_ELEM_OBJECT || !st->removed_array) return NC_P_TYPE_ERROR;
    size_t *k = malloc((st->n_removed ? st->n_removed : 1) * sizeof(size_t));
    if (!k) return NC_P_NOMEM;
    size_t nk = 0;
    for (size_t i = 0; i < st->n_removed; i++)
        if (!nc_val_strict_eq(&st->removed[i], fp)) k[nk++] = i;
    *keep = k;
    *n_keep = nk;
    return NC_P_OK;
}

int nc_own_record_seen(const nc_rstate_t *st, const nc_val_t *own_fp, const nc_val_t *kind) {
    if (st->falsy) return 1;                                          /* if (!state) return true */
    if (st->elem != NC_ELEM_OBJECT) {
        /* a truthy scalar: every field undefined */
        if (nc_val_is(kind, "profile") || nc_val_is(kind, "list")) return 0;
        return 1;
    }
    nc_val_t v;
    int compound;
    /* state.seenOwn && state.seenOwn[kind] !== undefined */
    if (st->seen_own.object && map_get_val(&st->seen_own, kind, &v, &compound) != 0) return 1;
    if (nc_val_is(kind, "profile")) {
        /* !!(state.profileCache && ownFp && state.profileCache[ownFp]) */
        if (!st->profile_cache.object || !nc_val_truthy(own_fp)) return 0;
        int got = map_get_val(&st->profile_cache, own_fp, &v, &compound);
        if (got == 2) return 1;                                       /* inherited: truthy */
        return got == 1 && (compound || nc_val_truthy(&v));
    }
    if (nc_val_is(kind, "list")) {
        /* Array.isArray(state.contacts) && state.contacts.some(c => c && c.listed === true) */
        if (st->contacts_kind != NC_LIST_ARRAY) return 0;
        for (size_t i = 0; i < st->n_contacts; i++)
            if (st->contacts[i].elem == NC_ELEM_OBJECT && st->contacts[i].listed.kind == NC_V_TRUE) return 1;
        return 0;
    }
    return 1;                                                         /* an unknown kind */
}

int nc_first_record_allowed(const nc_rstate_t *st, const nc_val_t *own_fp, const nc_val_t *kind) {
    return !nc_own_record_seen(st, own_fp, kind);
}

int nc_mark_own_record_seen(const nc_rstate_t *st, const nc_val_t *kind, nc_mark_seen_out_t *out) {
    memset(out, 0, sizeof(*out));
    /* if (!state || (kind !== 'profile' && kind !== 'list')) return false */
    if (st->falsy || !(nc_val_is(kind, "profile") || nc_val_is(kind, "list"))) return NC_P_OK;
    /* a truthy scalar: state.seenOwn = {} assigns a property to a primitive */
    if (st->elem != NC_ELEM_OBJECT) return NC_P_TYPE_ERROR;
    if (st->seen_own.object) {
        nc_val_t v;
        if (map_get_val(&st->seen_own, kind, &v, NULL) != 0) return NC_P_OK;    /* already seen */
    } else {
        out->create_seen_own = 1;                                     /* if (!state.seenOwn) state.seenOwn = {} */
    }
    out->result = 1;
    return NC_P_OK;
}
