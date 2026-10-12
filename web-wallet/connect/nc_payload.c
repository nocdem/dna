/* Nodus Connect core — P1b: the app's payload forms (nc_payload.h), ported
 * from src/connect/ui/actions.js (web 0.1.101). Each function cites the JS
 * line it copies.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_payload.h"

#include "crypto/hash/qgp_sha3.h"

#include <stdlib.h>
#include <string.h>

const char *const nc_reaction_emojis[NC_REACTION_EMOJIS] = {
    "\xE2\x9D\xA4\xEF\xB8\x8F",   /* ❤️ U+2764 U+FE0F */
    "\xF0\x9F\x91\x8D",           /* 👍 */
    "\xF0\x9F\x98\x82",           /* 😂 */
    "\xF0\x9F\x98\xAE",           /* 😮 */
    "\xF0\x9F\x98\xA2",           /* 😢 */
    "\xF0\x9F\x99\x8F",           /* 🙏 */
    "\xF0\x9F\x94\xA5",           /* 🔥 */
    "\xF0\x9F\x8E\x89"            /* 🎉 */
};

/* "↩ Re: " (actions.js:250), 6 UTF-16 units = 8 bytes */
static const char REPLY_PREFIX[] = "\xE2\x86\xA9 Re: ";
#define REPLY_PREFIX_LEN 8

/* ── accept sets (actions.js:28-30, :167) ───────────────────────────── */

static int is_lhex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
static int is_xhex(char c) { return is_lhex(c) || (c >= 'A' && c <= 'F'); }
static int is_dig(char c)  { return c >= '0' && c <= '9'; }

/* /^[0-9a-f]{128}$/ */
static int re_hex128(const char *s, size_t n) {
    if (n != 128) return 0;
    for (size_t i = 0; i < n; i++) if (!is_lhex(s[i])) return 0;
    return 1;
}
/* /^[0-9a-fA-F]{64}$/ */
static int re_hex64(const char *s, size_t n) {
    if (n != 64) return 0;
    for (size_t i = 0; i < n; i++) if (!is_xhex(s[i])) return 0;
    return 1;
}
/* /^(0|[1-9]\d{0,19})$/ */
static int re_u64(const char *s, size_t n) {
    if (n < 1 || n > 20) return 0;
    for (size_t i = 0; i < n; i++) if (!is_dig(s[i])) return 0;
    return n == 1 || s[0] != '0';
}
/* /^(0|[1-9]\d{0,11})(\.\d{1,8})?$/ ; *dot = index of '.', or n */
static int re_amount(const char *s, size_t n, size_t *dot) {
    size_t i = 0;
    if (n == 0 || !is_dig(s[0])) return 0;
    if (s[0] == '0') i = 1;
    else { while (i < n && is_dig(s[i])) i++; if (i > 12) return 0; }
    *dot = i;
    if (i == n) return 1;
    if (s[i] != '.') return 0;
    size_t f = n - i - 1;
    if (f < 1 || f > 8) return 0;
    for (size_t j = i + 1; j < n; j++) if (!is_dig(s[j])) return 0;
    return 1;
}

/* String(v) tested against a RegExp: v as a string in `b` (reset). */
static void str_of(const nc_val_t *v, nc_sb_t *b) {
    nc_sb_reset(b);
    nc_val_tostring(v, b);
}
static int val_hex128(const nc_val_t *v, nc_sb_t *tmp) { str_of(v, tmp); return !tmp->oom && re_hex128(tmp->p, tmp->len); }
static int val_hex64(const nc_val_t *v, nc_sb_t *tmp)  { str_of(v, tmp); return !tmp->oom && re_hex64(tmp->p, tmp->len); }

/* cString (actions.js:37): up to the first NUL. */
static size_t cstring_len(const char *s, size_t n) {
    const char *z = n ? memchr(s, '\0', n) : NULL;
    return z ? (size_t)(z - s) : n;
}

static size_t find(const char *s, size_t n, const char *pat, size_t pn, size_t from) {
    if (pn > n) return (size_t)-1;
    for (size_t i = from; i + pn <= n; i++)
        if (memcmp(s + i, pat, pn) == 0) return i;
    return (size_t)-1;
}

static unsigned __int128 u128_dec(const char *s, size_t n) {
    unsigned __int128 v = 0;
    for (size_t i = 0; i < n; i++) v = v * 10 + (unsigned)(s[i] - '0');
    return v;
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

/* ── content hash (actions.js:39-51) ────────────────────────────────── */

int nc_content_hash(const nc_val_t *sender_fp, const nc_val_t *recipient_fp,
                    const nc_val_t *text, const nc_val_t *ts, char out[65]) {
    nc_sb_t s1, s2, t, pre, enc;
    nc_sb_init(&s1); nc_sb_init(&s2); nc_sb_init(&t); nc_sb_init(&pre); nc_sb_init(&enc);
    int rc = NC_P_NULL;
    str_of(sender_fp, &s1);
    str_of(recipient_fp, &s2);
    str_of(ts, &t);
    if (s1.oom || s2.oom || t.oom) { rc = NC_P_NOMEM; goto out; }
    if (!re_hex128(s1.p, s1.len) || !re_hex128(s2.p, s2.len) || !re_u64(t.p, t.len)) goto out;
    nc_sb_put(&pre, s1.p, s1.len);
    nc_sb_put(&pre, s2.p, s2.len);
    {
        nc_sb_t tx;
        nc_sb_init(&tx);
        nc_val_tostring(text, &tx);                          /* String(text) */
        if (!tx.oom) nc_sb_put(&pre, tx.p, cstring_len(tx.p, tx.len));
        else pre.oom = 1;
        nc_sb_free(&tx);
    }
    /* String(BigInt(ts)): a string that passed U64 is already canonical;
     * a Number that did is an integer below 1e21 (no exponent form), whose
     * BigInt is its exact value (which may differ from String(ts) above
     * 2^53, e.g. 2^64 = "18446744073709552000" vs 18446744073709551616). */
    if (ts->kind == NC_V_NUM) nc_u128_to_string((unsigned __int128)ts->num, &pre);
    else nc_sb_put(&pre, t.p, t.len);
    nc_js_to_utf8(&enc, pre.p ? pre.p : "", pre.len);         /* TextEncoder */
    if (pre.oom || enc.oom) { rc = NC_P_NOMEM; goto out; }
    uint8_t h[32];
    if (qgp_sha3_256((const uint8_t *)enc.p, enc.len, h) != 0) { rc = NC_P_NOMEM; goto out; }
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = hx[h[i] >> 4]; out[2 * i + 1] = hx[h[i] & 15]; }
    out[64] = '\0';
    rc = NC_P_OK;
out:
    nc_sb_free(&s1); nc_sb_free(&s2); nc_sb_free(&t); nc_sb_free(&pre); nc_sb_free(&enc);
    return rc;
}

int nc_message_hash(const nc_msg_t *m, const nc_val_t *own_fp, char out[65]) {
    if (m->elem != NC_ELEM_OBJECT) return NC_P_NULL;      /* !m, or m.dir undefined */
    if (nc_val_is(&m->dir, "out")) return nc_content_hash(own_fp, &m->fp, &m->text, &m->ts, out);
    if (nc_val_is(&m->dir, "in"))  return nc_content_hash(&m->fp, own_fp, &m->text, &m->sender_ts, out);
    return NC_P_NULL;
}

/* ── reactions (actions.js:54-118) ──────────────────────────────────── */

static int emoji_index(const char *s, size_t n) {
    for (int i = 0; i < NC_REACTION_EMOJIS; i++)
        if (nc_js_str_eq(s, n, nc_reaction_emojis[i])) return i;
    return -1;
}

int nc_build_reaction(const nc_val_t *target, const nc_val_t *emoji,
                      const nc_val_t *op, nc_sb_t *out) {
    nc_sb_t t;
    nc_sb_init(&t);
    int ok = val_hex64(target, &t) && emoji->kind == NC_V_STR && emoji_index(emoji->s, emoji->n) >= 0 &&
             (nc_val_is(op, "add") || nc_val_is(op, "remove"));
    if (!ok) { int oom = t.oom; nc_sb_free(&t); return oom ? NC_P_NOMEM : NC_P_THROW; }
    nc_sb_puts(out, "{\"target\":\"");
    nc_sb_put(out, t.p, t.len);
    nc_sb_puts(out, "\",\"emoji\":\"");
    nc_sb_put(out, emoji->s, emoji->n);
    nc_sb_puts(out, "\",\"op\":\"");
    nc_sb_put(out, op->s, op->n);
    nc_sb_puts(out, "\"}");
    nc_sb_free(&t);
    return out->oom ? NC_P_NOMEM : NC_P_OK;
}

/* field (actions.js:60): the value after `"<name>":"` up to the next '"'. */
static int field(const char *s, size_t n, const char *name, const char **v, size_t *vn) {
    char pat[16];
    size_t nl = strlen(name);
    pat[0] = '"';
    memcpy(pat + 1, name, nl);
    memcpy(pat + 1 + nl, "\":\"", 3);
    size_t pn = nl + 4;
    size_t at = find(s, n, pat, pn, 0);
    if (at == (size_t)-1) return 0;
    size_t start = at + pn;
    const char *e = memchr(s + start, '"', n - start);
    if (!e) return 0;
    *v = s + start;
    *vn = (size_t)(e - (s + start));
    return 1;
}

int nc_parse_reaction(const char *s0, size_t n0, nc_reaction_t *out) {
    size_t n = cstring_len(s0, n0);
    const char *t = NULL, *e = NULL, *o = NULL;
    size_t tn = 0, en = 0, on = 0;
    int ht = field(s0, n, "target", &t, &tn);
    int he = field(s0, n, "emoji", &e, &en);
    int ho = field(s0, n, "op", &o, &on);
    /* !target || !HEX64 || op not add/remove || !emoji || bytes(emoji) > 7 */
    if (!ht || tn == 0 || !re_hex64(t, tn)) return NC_P_NULL;
    if (!ho || !(nc_js_str_eq(o, on, "add") || nc_js_str_eq(o, on, "remove"))) return NC_P_NULL;
    if (!he || en == 0 || en > 7) return NC_P_NULL;   /* a lone surrogate is 3 bytes in
                                                         * WTF-8 and in TextEncoder's U+FFFD */
    out->target = t; out->target_n = tn;
    out->emoji = e;  out->emoji_n = en;
    out->op = o;     out->op_n = on;
    return NC_P_OK;
}

typedef struct {
    char      target[65];          /* lowercased (the Map key)           */
    char      emoji[8];
    size_t    emoji_n;
    int       add;
    nc_val_t  reactor;
    unsigned __int128 ts;
    nc_big_t  seq;
} react_row_t;

static int row_cmp(const react_row_t *a, const react_row_t *b) {
    if (a->ts != b->ts) return a->ts < b->ts ? -1 : 1;
    return nc_big_cmp(&a->seq, &b->seq);
}

/* Stable merge sort of indices (JS Array.prototype.sort is stable). */
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
static int rows_cmp(const void *ctx, size_t a, size_t b) {
    const react_row_t *r = ctx;
    return row_cmp(&r[a], &r[b]);
}
static int emoji_order(const char *e, size_t n) {
    int i = emoji_index(e, n);
    return i < 0 ? NC_REACTION_EMOJIS : i;
}
static int items_cmp(const void *ctx, size_t a, size_t b) {
    const nc_react_item_t *it = ctx;
    return emoji_order(it[a].emoji, it[a].emoji_n) - emoji_order(it[b].emoji, it[b].emoji_n);
}

typedef struct { nc_val_t reactor; int on; } who_t;
typedef struct { char emoji[8]; size_t emoji_n; who_t *who; size_t n_who; } by_emoji_t;
typedef struct { char key[65]; by_emoji_t *em; size_t n_em; } by_target_t;

static void *grow(void *p, size_t n, size_t sz) {
    /* room for element n (0-based) in an array of n elements */
    if (n > ((size_t)-1) / sz - 1) return NULL;
    return realloc(p, (n + 1) * sz);
}

void nc_react_summary_free(nc_react_summary_t *s) {
    for (size_t i = 0; i < s->n; i++) free(s->t[i].items);
    free(s->t);
    s->t = NULL;
    s->n = 0;
}

int nc_reaction_summary(const nc_msg_t *recs, size_t n, const nc_val_t *own_fp,
                        nc_react_summary_t *out) {
    out->t = NULL;
    out->n = 0;
    react_row_t *rows = NULL;
    size_t nrows = 0;
    by_target_t *st = NULL;
    size_t nst = 0;
    size_t *idx = NULL;
    int rc = NC_P_OK;
    nc_sb_t txt, tss;
    nc_sb_init(&txt);
    nc_sb_init(&tss);

    for (size_t i = 0; i < n; i++) {
        const nc_msg_t *m = &recs[i];
        if (m->elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; goto out; }   /* m.kind */
        if (m->elem != NC_ELEM_OBJECT || !nc_val_is(&m->kind, "reaction")) continue;
        str_of(&m->text, &txt);
        if (txt.oom) { rc = NC_P_NOMEM; goto out; }
        nc_reaction_t r;
        if (nc_parse_reaction(txt.p, txt.len, &r) != NC_P_OK) continue;
        int out_dir = nc_val_is(&m->dir, "out");
        const nc_val_t *ts = out_dir ? &m->ts : &m->sender_ts;
        str_of(ts, &tss);
        if (tss.oom) { rc = NC_P_NOMEM; goto out; }
        if (!re_u64(tss.p, tss.len)) continue;
        react_row_t *nr = grow(rows, nrows, sizeof(*rows));
        if (!nr) { rc = NC_P_NOMEM; goto out; }
        rows = nr;
        react_row_t *row = &rows[nrows];
        memset(row, 0, sizeof(*row));
        nc_big_init(&row->seq);
        nrows++;
        for (size_t k = 0; k < 64; k++) {
            char c = r.target[k];
            row->target[k] = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
        }
        row->target[64] = '\0';
        memcpy(row->emoji, r.emoji, r.emoji_n);
        row->emoji_n = r.emoji_n;
        row->add = nc_js_str_eq(r.op, r.op_n, "add");
        row->reactor = out_dir ? *own_fp : m->fp;
        row->ts = (ts->kind == NC_V_NUM) ? (unsigned __int128)ts->num : u128_dec(tss.p, tss.len);
        /* BigInt(m.seq ?? 0) */
        nc_val_t seq = m->seq;
        if (seq.kind == NC_V_UNDEF || seq.kind == NC_V_NULL) { seq = nc_val_undef(); seq.kind = NC_V_NUM; seq.num = 0; }
        int b = big_rc(nc_big_from_val(&row->seq, &seq));
        if (b != NC_P_OK) { rc = b; goto out; }
    }

    idx = malloc((nrows ? nrows : 1) * sizeof(size_t));
    if (!idx) { rc = NC_P_NOMEM; goto out; }
    for (size_t i = 0; i < nrows; i++) idx[i] = i;
    if (stable_sort(idx, nrows, rows_cmp, rows) != 0) { rc = NC_P_NOMEM; goto out; }

    for (size_t q = 0; q < nrows; q++) {
        const react_row_t *r = &rows[idx[q]];
        size_t ti;
        for (ti = 0; ti < nst; ti++) if (memcmp(st[ti].key, r->target, 64) == 0) break;
        if (ti == nst) {
            by_target_t *ns = grow(st, nst, sizeof(*st));
            if (!ns) { rc = NC_P_NOMEM; goto out; }
            st = ns;
            memset(&st[nst], 0, sizeof(st[nst]));
            memcpy(st[nst].key, r->target, 65);
            nst++;
        }
        by_target_t *T = &st[ti];
        size_t ei;
        for (ei = 0; ei < T->n_em; ei++)
            if (T->em[ei].emoji_n == r->emoji_n && memcmp(T->em[ei].emoji, r->emoji, r->emoji_n) == 0) break;
        if (ei == T->n_em) {
            by_emoji_t *ne = grow(T->em, T->n_em, sizeof(*T->em));
            if (!ne) { rc = NC_P_NOMEM; goto out; }
            T->em = ne;
            memset(&T->em[T->n_em], 0, sizeof(T->em[T->n_em]));
            memcpy(T->em[T->n_em].emoji, r->emoji, r->emoji_n);
            T->em[T->n_em].emoji_n = r->emoji_n;
            T->n_em++;
        }
        by_emoji_t *E = &T->em[ei];
        size_t wi;
        for (wi = 0; wi < E->n_who; wi++) if (nc_val_strict_eq(&E->who[wi].reactor, &r->reactor)) break;
        if (wi == E->n_who) {
            who_t *nw = grow(E->who, E->n_who, sizeof(*E->who));
            if (!nw) { rc = NC_P_NOMEM; goto out; }
            E->who = nw;
            E->who[E->n_who].reactor = r->reactor;
            E->n_who++;
        }
        E->who[wi].on = r->add;
    }

    for (size_t ti = 0; ti < nst; ti++) {
        by_target_t *T = &st[ti];
        nc_react_item_t *list = malloc((T->n_em ? T->n_em : 1) * sizeof(*list));
        if (!list) { rc = NC_P_NOMEM; goto out; }
        size_t nl = 0;
        for (size_t ei = 0; ei < T->n_em; ei++) {
            size_t on = 0;
            int mine = 0;
            for (size_t wi = 0; wi < T->em[ei].n_who; wi++) {
                if (!T->em[ei].who[wi].on) continue;
                on++;
                if (nc_val_strict_eq(&T->em[ei].who[wi].reactor, own_fp)) mine = 1;
            }
            if (!on) continue;
            memcpy(list[nl].emoji, T->em[ei].emoji, T->em[ei].emoji_n);
            list[nl].emoji_n = T->em[ei].emoji_n;
            list[nl].count = on;
            list[nl].mine = mine;
            nl++;
        }
        if (!nl) { free(list); continue; }
        size_t *li = malloc(nl * sizeof(size_t));
        nc_react_item_t *sorted = malloc(nl * sizeof(*sorted));
        if (!li || !sorted) { free(li); free(sorted); free(list); rc = NC_P_NOMEM; goto out; }
        for (size_t k = 0; k < nl; k++) li[k] = k;
        if (stable_sort(li, nl, items_cmp, list) != 0) { free(li); free(sorted); free(list); rc = NC_P_NOMEM; goto out; }
        for (size_t k = 0; k < nl; k++) sorted[k] = list[li[k]];
        free(li);
        free(list);
        nc_react_target_t *nt = grow(out->t, out->n, sizeof(*out->t));
        if (!nt) { free(sorted); rc = NC_P_NOMEM; goto out; }
        out->t = nt;
        memcpy(out->t[out->n].target, T->key, 65);
        out->t[out->n].items = sorted;
        out->t[out->n].n_items = nl;
        out->n++;
    }

out:
    if (rc != NC_P_OK) nc_react_summary_free(out);
    for (size_t i = 0; i < nrows; i++) nc_big_free(&rows[i].seq);
    free(rows);
    for (size_t ti = 0; ti < nst; ti++) {
        for (size_t ei = 0; ei < st[ti].n_em; ei++) free(st[ti].em[ei].who);
        free(st[ti].em);
    }
    free(st);
    free(idx);
    nc_sb_free(&txt);
    nc_sb_free(&tss);
    return rc;
}

int nc_own_reaction_on(const nc_react_in_pair_t *pairs, size_t n,
                       const nc_val_t *target, const nc_val_t *emoji, int *on) {
    *on = 0;
    nc_sb_t t, k;
    nc_sb_init(&t);
    nc_sb_init(&k);
    nc_val_tostring(target, &t);
    nc_js_lower_ascii(&k, t.p ? t.p : "", t.len);
    if (t.oom || k.oom) { nc_sb_free(&t); nc_sb_free(&k); return NC_P_NOMEM; }
    const nc_react_in_pair_t *hit = NULL;
    for (size_t i = 0; i < n; i++)                     /* Map: the last set value */
        if (pairs[i].key_n == k.len && (k.len == 0 || memcmp(pairs[i].key, k.p, k.len) == 0)) hit = &pairs[i];
    nc_sb_free(&t);
    nc_sb_free(&k);
    if (!hit) return NC_P_OK;
    for (size_t i = 0; i < hit->n_items; i++) {        /* .some(), in order */
        const nc_react_in_item_t *r = &hit->items[i];
        if (r->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;
        nc_val_t re = r->elem == NC_ELEM_OBJECT ? r->emoji : nc_val_undef();
        nc_val_t rm = r->elem == NC_ELEM_OBJECT ? r->mine : nc_val_undef();
        if (nc_val_strict_eq(&re, emoji) && nc_val_truthy(&rm)) { *on = 1; return NC_P_OK; }
    }
    return NC_P_OK;
}

/* ── delete notices (actions.js:121-159) ────────────────────────────── */

int nc_build_delete(int is_array, const nc_val_t *hashes, size_t n, nc_sb_t *out) {
    if (!is_array || n == 0 || n > NC_DELETE_HASHES_MAX) return NC_P_THROW;
    nc_sb_t t;
    nc_sb_init(&t);
    for (size_t i = 0; i < n; i++)
        if (!val_hex64(&hashes[i], &t)) { int oom = t.oom; nc_sb_free(&t); return oom ? NC_P_NOMEM : NC_P_THROW; }
    nc_sb_free(&t);
    /* JSON.stringify({ type: 'delete', action: 0, hashes }): every element
     * passed the hex test, so it is a string (no Number prints 64 hex). */
    nc_sb_puts(out, "{\"type\":\"delete\",\"action\":0,\"hashes\":[");
    for (size_t i = 0; i < n; i++) {
        if (i) nc_sb_putc(out, ',');
        nc_js_write_string(out, hashes[i].s, hashes[i].n);
    }
    nc_sb_puts(out, "]}");
    return out->oom ? NC_P_NOMEM : NC_P_OK;
}

/* JSON.parse(cString(text)) as an object: NC_P_OK with *j (an object, or
 * an array when allow_array), NC_P_NULL (throws -> caught, or not an
 * object), NC_P_NOMEM. */
static int parse_object(const char *s, size_t n, int allow_array, nc_jv_t **j) {
    *j = NULL;
    nc_js_parse_t pr = nc_js_parse(s, cstring_len(s, n), j);
    if (pr == NC_JS_NOMEM) return NC_P_NOMEM;
    /* SYNTAX: JSON.parse throws (caught). DEPTH: JSON.parse would go on —
     * the documented nesting difference (nc_jsjson.h), "not a payload". */
    if (pr != NC_JS_OK) return NC_P_NULL;
    /* !j || typeof j !== 'object' (null and every scalar) */
    if (!((*j)->kind == NC_JV_OBJ || (allow_array && (*j)->kind == NC_JV_ARR))) {
        nc_jv_free(*j);
        *j = NULL;
        return NC_P_NULL;
    }
    return NC_P_OK;
}

static int jstr_is(const nc_jv_t *o, const char *lit) {
    return o && o->kind == NC_JV_STR && nc_js_str_eq(o->s, o->n, lit);
}

int nc_parse_delete(const char *s, size_t n, nc_delete_t *out) {
    nc_jv_t *j;
    const nc_jv_t *v;
    int rc = parse_object(s, n, 1, &j);
    if (rc != NC_P_OK) return rc;
    /* an array is an object to typeof; its .type is undefined */
    if (j->kind != NC_JV_OBJ || !jstr_is(nc_jv_get(j, "type"), "delete")) {
        nc_jv_free(j);
        return NC_P_NULL;
    }
    out->action = 0;
    v = nc_jv_get(j, "action");
    if (v && v->kind == NC_JV_NUM && nc_js_is_integer(v->num)) out->action = v->num;
    out->n = 0;
    v = nc_jv_get(j, "hashes");
    if (v && v->kind == NC_JV_ARR) {
        for (size_t i = 0; i < v->len && out->n < NC_DELETE_HASHES_MAX; i++) {
            const nc_jv_t *h = v->v[i];
            if (h->kind != NC_JV_STR) continue;
            const char *hs = h->s;
            size_t hn = h->n;
            if (!re_hex64(hs, hn)) continue;
            for (size_t k = 0; k < 64; k++) {
                char c = hs[k];
                out->hashes[out->n][k] = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
            }
            out->hashes[out->n][64] = '\0';
            out->n++;
        }
    }
    nc_jv_free(j);
    return NC_P_OK;
}

void nc_hashset_free(nc_hashset_t *s) { free(s->h); s->h = NULL; s->n = 0; s->cap = 0; }

static int hashset_add(nc_hashset_t *s, const char h[65]) {
    for (size_t i = 0; i < s->n; i++) if (memcmp(s->h[i], h, 64) == 0) return 0;
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 8;
        char (*q)[65] = realloc(s->h, cap * sizeof(*q));
        if (!q) return -1;
        s->h = q;
        s->cap = cap;
    }
    memcpy(s->h[s->n], h, 65);
    s->n++;
    return 0;
}

typedef struct { const char *h; size_t hn; nc_val_t sender; } by_sender_t;

int nc_deletions(const nc_msg_t *recs, size_t n, const nc_val_t *own_fp,
                 const nc_val_t *hash_of, nc_hashset_t *deleted, nc_hashset_t *hidden) {
    memset(deleted, 0, sizeof(*deleted));
    memset(hidden, 0, sizeof(*hidden));
    by_sender_t *bs = NULL;
    size_t nbs = 0;
    int rc = NC_P_OK;
    nc_sb_t txt;
    nc_sb_init(&txt);
    nc_delete_t *notice = malloc(sizeof(*notice));
    if (!notice) return NC_P_NOMEM;

    for (size_t i = 0; i < n; i++) {
        const nc_msg_t *m = &recs[i];
        if (m->elem == NC_ELEM_NULL) { rc = NC_P_TYPE_ERROR; goto out; }   /* m.kind */
        if (m->elem != NC_ELEM_OBJECT) continue;                          /* dir undefined */
        if (nc_val_truthy(&m->kind) && !nc_val_is(&m->kind, "chat")) continue;
        int out_dir = nc_val_is(&m->dir, "out");
        if (!out_dir && !nc_val_is(&m->dir, "in")) continue;
        const nc_val_t *h = &hash_of[i];
        if (!nc_val_truthy(h) || h->kind != NC_V_STR) continue;
        size_t k;
        for (k = 0; k < nbs; k++)
            if (bs[k].hn == h->n && memcmp(bs[k].h, h->s, h->n) == 0) break;
        if (k == nbs) {
            by_sender_t *nb = grow(bs, nbs, sizeof(*bs));
            if (!nb) { rc = NC_P_NOMEM; goto out; }
            bs = nb;
            bs[nbs].h = h->s;
            bs[nbs].hn = h->n;
            nbs++;
        }
        bs[k].sender = out_dir ? *own_fp : m->fp;
    }
    for (size_t i = 0; i < n; i++) {
        const nc_msg_t *m = &recs[i];
        if (m->elem != NC_ELEM_OBJECT) continue;   /* null threw above */
        if (nc_val_is(&m->kind, "hide") && m->target.kind == NC_V_STR && re_hex64(m->target.s, m->target.n)) {
            char low[65];
            for (size_t c = 0; c < 64; c++) {
                char ch = m->target.s[c];
                low[c] = (ch >= 'A' && ch <= 'F') ? (char)(ch - 'A' + 'a') : ch;
            }
            low[64] = '\0';
            if (hashset_add(hidden, low) != 0) { rc = NC_P_NOMEM; goto out; }
            continue;
        }
        if (!nc_val_is(&m->kind, "delete")) continue;
        str_of(&m->text, &txt);
        if (txt.oom) { rc = NC_P_NOMEM; goto out; }
        int pr = nc_parse_delete(txt.p, txt.len, notice);
        if (pr == NC_P_NOMEM) { rc = NC_P_NOMEM; goto out; }
        if (pr != NC_P_OK || notice->action != 0) continue;   /* -0 !== 0 is false */
        nc_val_t deleter = nc_val_is(&m->dir, "out") ? *own_fp : m->fp;
        for (size_t q = 0; q < notice->n; q++) {
            nc_val_t got = nc_val_undef();               /* bySender.get(h) */
            for (size_t k = 0; k < nbs; k++)
                if (bs[k].hn == 64 && memcmp(bs[k].h, notice->hashes[q], 64) == 0) { got = bs[k].sender; break; }
            if (nc_val_strict_eq(&got, &deleter) && hashset_add(deleted, notice->hashes[q]) != 0) {
                rc = NC_P_NOMEM;
                goto out;
            }
        }
    }
out:
    if (rc != NC_P_OK) { nc_hashset_free(deleted); nc_hashset_free(hidden); }
    free(bs);
    free(notice);
    nc_sb_free(&txt);
    return rc;
}

/* ── payment cards (actions.js:165-240) ─────────────────────────────── */

static const char NATIVE_TOKEN[] =
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000";

int nc_nodus_units(const nc_val_t *amount, unsigned __int128 *units) {
    size_t dot;
    if (amount->kind != NC_V_STR || !re_amount(amount->s, amount->n, &dot)) return NC_P_NULL;
    unsigned __int128 whole = u128_dec(amount->s, dot), frac = 0;
    size_t fn = dot < amount->n ? amount->n - dot - 1 : 0;
    for (size_t i = 0; i < 8; i++)                    /* frac.padEnd(8, '0') */
        frac = frac * 10 + (i < fn ? (unsigned)(amount->s[dot + 1 + i] - '0') : 0);
    *units = whole * 100000000u + frac;
    return NC_P_OK;
}

/* cardName (actions.js:182): the first 64 UTF-16 units; a cut that ends on
 * a high surrogate drops it. */
static void card_name(const char *str, size_t n, nc_sb_t *out) {
    const unsigned char *s = (const unsigned char *)str;
    size_t units = 0, i = 0, last = (size_t)-1;
    int straddle = 0;
    while (i < n) {
        size_t k = nc_utf8_char_len(s + i, n - i);
        size_t u = (k == 4) ? 2 : 1;
        if (units + u > NC_CARD_NAME_UNITS) { straddle = (units < NC_CARD_NAME_UNITS); break; }
        units += u;
        last = i;
        i += k;
    }
    size_t end = i;
    /* a pair split by the cut: .slice leaves its high half, which the
     * regex drops — the characters before it stay as they are. Otherwise
     * the cut ends on a whole character: a lone high surrogate there goes. */
    if (!straddle && last != (size_t)-1 && nc_utf8_is_lone_high(s + last, n - last)) end = last;
    nc_sb_put(out, str, end);
}

int nc_build_transfer(const nc_transfer_in_t *d, nc_sb_t *out) {
    if (d->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;      /* destructuring */
    nc_val_t u = nc_val_undef();
    const nc_val_t *amount = d->elem == NC_ELEM_OBJECT ? &d->amount : &u;
    const nc_val_t *wire   = d->elem == NC_ELEM_OBJECT ? &d->wire : &u;
    const nc_val_t *to     = d->elem == NC_ELEM_OBJECT ? &d->to : &u;
    const nc_val_t *name   = d->elem == NC_ELEM_OBJECT ? &d->name : &u;
    unsigned __int128 units;
    nc_sb_t w, t, nm;
    nc_sb_init(&w); nc_sb_init(&t); nc_sb_init(&nm);
    int rc = NC_P_THROW;
    if (nc_nodus_units(amount, &units) != NC_P_OK || units == 0) goto out;
    if (!val_hex128(wire, &w) || !val_hex128(to, &t)) { if (w.oom || t.oom) rc = NC_P_NOMEM; goto out; }
    if (name->kind == NC_V_UNDEF) nc_sb_put(&nm, "", 0);       /* name = '' */
    else nc_val_tostring(name, &nm);
    if (nm.oom) { rc = NC_P_NOMEM; goto out; }
    nc_sb_puts(out, "{\"type\":\"token_transfer\",\"amount\":");
    nc_js_write_string(out, amount->s, amount->n);
    nc_sb_puts(out, ",\"token\":\"NODUS\",\"network\":\"Nodus\",\"chain\":\"nodus\",\"txHash\":");
    nc_js_write_string(out, w.p, w.len);
    nc_sb_puts(out, ",\"recipientAddress\":");
    nc_js_write_string(out, t.p, t.len);
    nc_sb_puts(out, ",\"recipientName\":");
    {
        nc_sb_t cut;
        nc_sb_init(&cut);
        card_name(nm.p ? nm.p : "", nm.len, &cut);
        nc_js_write_string(out, cut.p ? cut.p : "", cut.len);
        if (cut.oom) out->oom = 1;
        nc_sb_free(&cut);
    }
    nc_sb_putc(out, '}');
    rc = out->oom ? NC_P_NOMEM : NC_P_OK;
out:
    nc_sb_free(&w); nc_sb_free(&t); nc_sb_free(&nm);
    return rc;
}

void nc_transfer_init(nc_transfer_t *t) {
    nc_sb_init(&t->chain); nc_sb_init(&t->amount); nc_sb_init(&t->token);
    nc_sb_init(&t->wire);  nc_sb_init(&t->to);     nc_sb_init(&t->name);
}

void nc_transfer_free(nc_transfer_t *t) {
    nc_sb_free(&t->chain); nc_sb_free(&t->amount); nc_sb_free(&t->token);
    nc_sb_free(&t->wire);  nc_sb_free(&t->to);     nc_sb_free(&t->name);
}

/* str (actions.js:192): the property if it is a string, else ''. */
static void jfield_str(const nc_jv_t *j, const char *key, int lower, nc_sb_t *out) {
    const nc_jv_t *v = nc_jv_get(j, key);
    nc_sb_put(out, "", 0);
    if (!v || v->kind != NC_JV_STR) return;
    if (lower) nc_js_lower_ascii(out, v->s, v->n);
    else nc_sb_put(out, v->s, v->n);
}

int nc_parse_transfer(const char *s, size_t n, nc_transfer_t *out) {
    nc_jv_t *j;
    int rc = parse_object(s, n, 0, &j);
    if (rc != NC_P_OK) return rc;
    if (!jstr_is(nc_jv_get(j, "type"), "token_transfer")) {
        nc_jv_free(j);
        return NC_P_NULL;
    }
    jfield_str(j, "chain", 1, &out->chain);
    jfield_str(j, "amount", 0, &out->amount);
    jfield_str(j, "token", 0, &out->token);
    jfield_str(j, "txHash", 1, &out->wire);
    jfield_str(j, "recipientAddress", 1, &out->to);
    jfield_str(j, "recipientName", 0, &out->name);
    nc_jv_free(j);
    if (out->chain.oom || out->amount.oom || out->token.oom || out->wire.oom || out->to.oom || out->name.oom)
        return NC_P_NOMEM;
    return NC_P_OK;
}

int nc_valid_nodus_card(const nc_card_t *c) {
    if (c->elem != NC_ELEM_OBJECT) return 0;         /* !!card, or card.chain undefined */
    if (!nc_val_is(&c->chain, "nodus") || !nc_val_is(&c->token, "NODUS")) return 0;
    nc_sb_t t;
    nc_sb_init(&t);
    int ok = val_hex128(&c->wire, &t) && val_hex128(&c->to, &t);
    nc_sb_free(&t);
    unsigned __int128 u;
    return ok && nc_nodus_units(&c->amount, &u) == NC_P_OK;
}

void nc_verdict_init(nc_verdict_t *v) {
    v->state = NC_VERDICT_PENDING;
    nc_sb_init(&v->height);
    v->chain = nc_val_str("", 0);
}

void nc_verdict_free(nc_verdict_t *v) { nc_sb_free(&v->height); }

int nc_transfer_verdict(const nc_card_t *card, nc_list_t entries_kind,
                        const nc_entry_t *entries, size_t n,
                        const nc_verdict_opts_t *opts, nc_verdict_t *out) {
    if (opts->elem == NC_ELEM_NULL) return NC_P_TYPE_ERROR;   /* destructuring */
    nc_val_t u = nc_val_undef();
    const nc_val_t *incoming     = opts->elem == NC_ELEM_OBJECT ? &opts->incoming : &u;
    const nc_val_t *counterparty = opts->elem == NC_ELEM_OBJECT ? &opts->counterparty : &u;
    const nc_val_t *own_fp       = opts->elem == NC_ELEM_OBJECT ? &opts->own_fp : &u;

    unsigned __int128 want;
    nc_sb_t t;
    nc_sb_init(&t);
    int valid = card->elem == NC_ELEM_OBJECT && nc_val_is(&card->chain, "nodus") &&
                nc_val_is(&card->token, "NODUS") && val_hex128(&card->wire, &t) &&
                nc_nodus_units(&card->amount, &want) == NC_P_OK;
    int oom = t.oom;
    nc_sb_free(&t);
    if (oom) return NC_P_NOMEM;
    if (!valid) {
        out->state = NC_VERDICT_UNVERIFIABLE;
        /* card?.chain || '' */
        out->chain = (card->elem == NC_ELEM_OBJECT && nc_val_truthy(&card->chain)) ? card->chain
                                                                                   : nc_val_str("", 0);
        return NC_P_OK;
    }
    if (!nc_val_strict_eq(&card->to, nc_val_truthy(incoming) ? own_fp : counterparty)) {
        out->state = NC_VERDICT_MISMATCH;
        return NC_P_OK;
    }
    if (entries_kind == NC_LIST_BAD) return NC_P_TYPE_ERROR;  /* (entries || []).filter */
    size_t nrows = 0;
    const char *kind = nc_val_truthy(incoming) ? "spend_in" : "spend_out";
    size_t n_own = 0, first_own = 0;
    int bad_token = 0;
    for (size_t i = 0; entries_kind == NC_LIST_ARRAY && i < n; i++) {
        const nc_entry_t *e = &entries[i];
        if (e->elem != NC_ELEM_OBJECT || !nc_val_strict_eq(&e->wire, &card->wire)) continue;
        nrows++;
        if (!nc_val_is(&e->kind, kind) || !nc_val_strict_eq(&e->peer, counterparty)) continue;
        if (!n_own) first_own = i;
        n_own++;
        if (!nc_val_is(&e->token, NATIVE_TOKEN)) bad_token = 1;
    }
    if (!nrows) { out->state = NC_VERDICT_PENDING; return NC_P_OK; }
    if (!n_own || bad_token) { out->state = NC_VERDICT_MISMATCH; return NC_P_OK; }

    nc_big_t total, x, w;
    nc_big_init(&total); nc_big_init(&x); nc_big_init(&w);
    int rc = NC_P_OK;
    for (size_t i = 0; i < n; i++) {
        const nc_entry_t *e = &entries[i];
        if (e->elem != NC_ELEM_OBJECT || !nc_val_strict_eq(&e->wire, &card->wire) ||
            !nc_val_is(&e->kind, kind) || !nc_val_strict_eq(&e->peer, counterparty)) continue;
        rc = big_rc(nc_big_from_val(&x, &e->amount));           /* BigInt(e.amount) */
        if (rc != NC_P_OK) goto done;
        if (nc_big_add(&total, &x) != NC_BIG_OK) { rc = NC_P_NOMEM; goto done; }
    }
    if (nc_big_from_u128(&w, want) != NC_BIG_OK) { rc = NC_P_NOMEM; goto done; }
    if (nc_big_cmp(&total, &w) == 0) {
        out->state = NC_VERDICT_CONFIRMED;
        nc_val_tostring(&entries[first_own].h, &out->height);      /* String(own[0].h) */
        if (out->height.oom) rc = NC_P_NOMEM;
    } else {
        out->state = NC_VERDICT_MISMATCH;
    }
done:
    nc_big_free(&total); nc_big_free(&x); nc_big_free(&w);
    return rc;
}

static int cards_cmp(const void *ctx, size_t a, size_t b) {
    const nc_copy_card_t *c = ctx;
    return nc_big_cmp(c[a].order, c[b].order);
}

int nc_copy_cards(nc_list_t kind, const nc_copy_card_t *cards, size_t n,
                  size_t **copies, size_t *n_copies) {
    *copies = NULL;
    *n_copies = 0;
    if (kind == NC_LIST_BAD) return NC_P_TYPE_ERROR;          /* (cards || []).filter */
    if (kind == NC_LIST_EMPTY) n = 0;
    size_t *idx = malloc((n ? n : 1) * sizeof(size_t));
    size_t *res = malloc((n ? n : 1) * sizeof(size_t));
    char  **keys = calloc(n ? n : 1, sizeof(char *));
    size_t *klen = calloc(n ? n : 1, sizeof(size_t));
    int rc = NC_P_OK;
    size_t m = 0, nkeys = 0, nres = 0;
    if (!idx || !res || !keys || !klen) { rc = NC_P_NOMEM; goto out; }
    for (size_t i = 0; i < n; i++)
        if (cards[i].elem == NC_ELEM_OBJECT && nc_val_is(&cards[i].state, "confirmed")) idx[m++] = i;
    if (stable_sort(idx, m, cards_cmp, cards) != 0) { rc = NC_P_NOMEM; goto out; }
    for (size_t q = 0; q < m; q++) {
        const nc_copy_card_t *c = &cards[idx[q]];
        nc_sb_t k;
        nc_sb_init(&k);
        nc_val_tostring(&c->dir, &k);                        /* `${c.dir}|${c.wire}` */
        nc_sb_putc(&k, '|');
        nc_val_tostring(&c->wire, &k);
        if (k.oom) { nc_sb_free(&k); rc = NC_P_NOMEM; goto out; }
        size_t f;
        for (f = 0; f < nkeys; f++) if (klen[f] == k.len && memcmp(keys[f], k.p, k.len) == 0) break;
        if (f == nkeys) {
            size_t kl;
            keys[nkeys] = nc_sb_take(&k, &kl);
            if (!keys[nkeys]) { rc = NC_P_NOMEM; goto out; }
            klen[nkeys++] = kl;
        } else {
            nc_sb_free(&k);
            res[nres++] = idx[q];
        }
    }
out:
    for (size_t i = 0; keys && i < nkeys; i++) free(keys[i]);
    free(keys);
    free(klen);
    free(idx);
    if (rc != NC_P_OK) { free(res); return rc; }
    *copies = res;
    *n_copies = nres;
    return NC_P_OK;
}

/* ── replies (actions.js:243-262) ───────────────────────────────────── */

/* .replace(/[\r\n]+/g, ' ') */
static void crlf_to_space(const char *s, size_t n, nc_sb_t *out) {
    size_t i = 0;
    while (i < n) {
        if (s[i] == '\r' || s[i] == '\n') {
            while (i < n && (s[i] == '\r' || s[i] == '\n')) i++;
            nc_sb_putc(out, ' ');
        } else {
            size_t j = i;
            while (j < n && s[j] != '\r' && s[j] != '\n') j++;
            nc_sb_put(out, s + i, j - i);
            i = j;
        }
    }
}

int nc_build_reply(const char *sender, size_t sender_n, const char *quoted, size_t quoted_n,
                   const char *text, size_t text_n, nc_sb_t *out) {
    nc_sb_t who, q;
    nc_sb_init(&who);
    nc_sb_init(&q);
    crlf_to_space(sender, sender_n, &who);
    crlf_to_space(quoted, quoted_n, &q);
    nc_sb_put(&who, "", 0);
    nc_sb_put(&q, "", 0);
    if (who.oom || q.oom) { nc_sb_free(&who); nc_sb_free(&q); return NC_P_NOMEM; }
    size_t a, z;
    nc_js_trim(who.p, who.len, &a, &z);
    nc_sb_put(out, REPLY_PREFIX, REPLY_PREFIX_LEN);
    if (z > a) nc_sb_put(out, who.p + a, z - a);
    else nc_sb_puts(out, "them");
    nc_sb_puts(out, "\n> ");
    if (nc_js_code_points(q.p, q.len) > NC_QUOTE_MAX) {
        const unsigned char *s = (const unsigned char *)q.p;
        size_t i = 0;
        for (size_t c = 0; c < NC_QUOTE_MAX; c++) i += nc_utf8_char_len(s + i, q.len - i);
        nc_sb_put(out, q.p, i);
        nc_sb_puts(out, "...");
    } else {
        nc_sb_put(out, q.p, q.len);
    }
    nc_sb_putc(out, '\n');
    nc_sb_put(out, text, text_n);
    nc_sb_free(&who);
    nc_sb_free(&q);
    return out->oom ? NC_P_NOMEM : NC_P_OK;
}

int nc_parse_reply(const char *s, size_t n, nc_reply_t *out) {
    if (n < REPLY_PREFIX_LEN || memcmp(s, REPLY_PREFIX, REPLY_PREFIX_LEN) != 0) return NC_P_NULL;
    const char *nl = memchr(s, '\n', n);
    if (!nl) return NC_P_NULL;
    size_t first = (size_t)(nl - s);
    const char *after = s + first + 1;
    size_t an = n - first - 1;
    if (an < 2 || after[0] != '>' || after[1] != ' ') return NC_P_NULL;
    const char *nl2 = memchr(after, '\n', an);
    if (!nl2) return NC_P_NULL;
    size_t second = (size_t)(nl2 - after);
    out->sender = s + REPLY_PREFIX_LEN;
    out->sender_n = first - REPLY_PREFIX_LEN;
    out->quoted = after + 2;
    out->quoted_n = second - 2;
    out->text = after + second + 1;
    out->text_n = an - second - 1;
    return NC_P_OK;
}
