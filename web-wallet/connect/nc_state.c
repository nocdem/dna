/* Nodus Connect core — P7 stage 1: the state schema v2 codec (nc_state.h;
 * design docs/plans/2026-10-13-connect-core-p7-state-design.md rev 2).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_state.h"
#include "nc_jsjson.h"

#include "dnac/dnac.h"          /* dnac_name_bytes_ok: the chain-name byte rule */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned __int128 u128;

#define FP_LEN    128            /* a fingerprint: 128 lowercase hex      */
#define SALT_LEN  64             /* a 1:1 salt: 64 lowercase hex          */
#define GID_LEN   64             /* a group id (store.js HEX64_KEY)       */
#define ID_DIGITS 20             /* 'c' / 'p' / 'v' / 'g' + 20 digits     */

/* 10^20 - 1: the largest value the U64 regex accepts (20 digits). */
static u128 u64_regex_max(void) {
    u128 v = 0;
    for (int i = 0; i < ID_DIGITS; i++) v = v * 10 + 9;
    return v;
}

/* ── small readers ──────────────────────────────────────────────────── */

static int live(const nc_jv_t *o, size_t i) { return !(o->dead && o->dead[i]); }
static int is_obj(const nc_jv_t *v) { return v && v->kind == NC_JV_OBJ; }
static int is_arr(const nc_jv_t *v) { return v && v->kind == NC_JV_ARR; }
static int is_str(const nc_jv_t *v) { return v && v->kind == NC_JV_STR; }
static int is_bool(const nc_jv_t *v) { return v && (v->kind == NC_JV_TRUE || v->kind == NC_JV_FALSE); }
static int is_num(const nc_jv_t *v, double d) { return v && v->kind == NC_JV_NUM && v->num == d; }

static int hex_n(const char *s, size_t n, size_t want) {
    if (n != want) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}
static int str_hex(const nc_jv_t *v, size_t want) { return is_str(v) && hex_n(v->s, v->n, want); }

/* /^(0|[1-9]\d{0,19})$/ on bytes (store.js:66 U64). */
static int u64_text(const char *s, size_t n) {
    if (n == 0 || n > ID_DIGITS) return 0;
    if (s[0] == '0') return n == 1;
    for (size_t i = 0; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

/* <prefix> + exactly 20 digits (store.js PROFILE_RECORD_ID, VAULT_RECORD_ID,
 * the /^g\d{20}$/ of checkState; 'c' for a known ID). */
static int rec_id(const char *s, size_t n, char prefix) {
    if (n != 1 + ID_DIGITS || s[0] != prefix) return 0;
    for (size_t i = 1; i < n; i++) if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}
static int str_rec_id(const nc_jv_t *v, char prefix) { return is_str(v) && rec_id(v->s, v->n, prefix); }

/* Digits (already checked) -> value. */
static u128 digits_value(const char *s, size_t n) {
    u128 v = 0;
    for (size_t i = 0; i < n; i++) v = v * 10 + (u128)(s[i] - '0');
    return v;
}

/* JavaScript String(v) of a parsed JSON value, appended: a scalar as
 * nc_val_tostring (Number::toString for a number); an array as
 * Array.prototype.join(",") — null elements give "", nested arrays join
 * again; an object "[object Object]" (Object.prototype.toString; an object
 * with its own "toString" key makes JavaScript throw instead — a refusal
 * either way, as "[object Object]" never passes U64). */
static void js_string(nc_sb_t *b, const nc_jv_t *v) {
    switch (v->kind) {
    case NC_JV_NULL:  nc_sb_puts(b, "null"); return;
    case NC_JV_FALSE: nc_sb_puts(b, "false"); return;
    case NC_JV_TRUE:  nc_sb_puts(b, "true"); return;
    case NC_JV_NUM: {
        char t[NC_JS_NUMSTR_MAX];
        nc_js_number_to_string(v->num, t);
        nc_sb_puts(b, t);
        return;
    }
    case NC_JV_STR:   nc_sb_put(b, v->s, v->n); return;
    case NC_JV_ARR:
        for (size_t i = 0; i < v->len; i++) {
            if (i) nc_sb_putc(b, ',');
            if (v->v[i]->kind != NC_JV_NULL) js_string(b, v->v[i]);
        }
        return;
    case NC_JV_OBJ:   nc_sb_puts(b, "[object Object]"); return;
    }
}

/* ── the working context ────────────────────────────────────────────── */

typedef struct {
    const char    *fp;               /* FP_LEN bytes inside the state tree   */
    int            contact;          /* kept in contacts[] (first wins)      */
    size_t         c_rank;
    const nc_jv_t *c_salt;           /* string, or NULL                      */
    int            c_listed;
    int            pending;          /* kept in outgoing[] (Map form)        */
    size_t         o_rank;
    const nc_jv_t *o_salt, *o_at;    /* the LAST entry's                     */
    const nc_jv_t *ack, *ack_sent, *dm_sync, *profile, *chain_name, *chain_no_name;
    u128           seq;
    int            has_id;
} ent_t;

typedef struct {
    char   id[1 + ID_DIGITS + 1];
    char   fp[FP_LEN + 1];
    char  *json;
    size_t json_len;
} prec_t;

/* One projection's outcome. why != NULL: refused (the reason). */
typedef struct {
    const char *why;
    u128        next;
    char       *header;
    size_t      header_len;
    prec_t     *rec;
    size_t      n_rec;
    char      **drop;                /* the dropped paths, sorted, distinct  */
    size_t     *drop_len;
    size_t      n_drop;
} proj_t;

static void proj_free(proj_t *p) {
    free(p->header);
    for (size_t i = 0; i < p->n_rec; i++) free(p->rec[i].json);
    free(p->rec);
    for (size_t i = 0; i < p->n_drop; i++) free(p->drop[i]);
    free(p->drop);
    free(p->drop_len);
    memset(p, 0, sizeof(*p));
}

/* U64.test(String(v)) — v NULL (absent) is String(undefined), which fails.
 * `t` is scratch; its oom flag is checked by the caller at the end. */
static int u64_of(nc_sb_t *t, const nc_jv_t *v) {
    if (!v) return 0;
    nc_sb_reset(t);
    js_string(t, v);
    return !t->oom && t->p && u64_text(t->p, t->len);
}

/* isMap(value[key]) after checkState's defaults (store.js:250, :252): an
 * absent key of this list reads as {} (removed as []). */
static const nc_jv_t EMPTY_OBJ = { .kind = NC_JV_OBJ };
static const nc_jv_t EMPTY_ARR = { .kind = NC_JV_ARR };
static const char *const DEFAULT_MAPS[] = {
    "ackSent", "profileCache", "dmSync", "chainNames", "chainNoName", "vaults", "groups", "seenOwn"
};
static const nc_jv_t *field(const nc_jv_t *root, const char *key) {
    const nc_jv_t *v = nc_jv_get(root, key);
    if (v) return v;
    for (size_t i = 0; i < sizeof(DEFAULT_MAPS) / sizeof(DEFAULT_MAPS[0]); i++)
        if (strcmp(key, DEFAULT_MAPS[i]) == 0) return &EMPTY_OBJ;
    if (strcmp(key, "removed") == 0) return &EMPTY_ARR;
    return NULL;
}

/* names.js chainNameOk: a string, 3..36 of a-z0-9, not all-hex from 8 on.
 * Non-ASCII fails both the JavaScript (char code > 'z') and the byte rule,
 * so UTF-16 length and byte length agree on every string that can pass. */
static int chain_name_ok(const nc_jv_t *v) {
    return is_str(v) && dnac_name_bytes_ok((const uint8_t *)v->s, v->n);
}

static int key_is(const nc_jv_t *o, size_t i, const char *lit) { return nc_js_str_eq(o->k[i], o->kn[i], lit); }

/* ── 1. the v1 gate: store.js checkState (:246-269), exactly ─────────── */

static int check_state(nc_sb_t *t, const nc_jv_t *root) {
    /* !value || value.version !== 1: only an object can carry "version". */
    if (!is_obj(root) || !is_num(nc_jv_get(root, "version"), 1.0)) return 0;
    if (!u64_of(t, nc_jv_get(root, "nextSeq"))) return 0;
    const nc_jv_t *contacts = nc_jv_get(root, "contacts"), *outgoing = nc_jv_get(root, "outgoing");
    const nc_jv_t *declined = nc_jv_get(root, "declined");
    if (!is_arr(contacts) || !is_arr(outgoing) || !is_arr(declined)) return 0;
    /* a bare ID (before 0.1.96) or { fp, at } */
    for (size_t i = 0; i < declined->len; i++) {
        const nc_jv_t *d = declined->v[i];
        if (d->kind == NC_JV_STR) { if (!hex_n(d->s, d->n, FP_LEN)) return 0; continue; }
        if (!is_obj(d) || !str_hex(nc_jv_get(d, "fp"), FP_LEN) || !u64_of(t, nc_jv_get(d, "at"))) return 0;
    }
    const nc_jv_t *removed = field(root, "removed");
    if (!is_arr(removed)) return 0;
    for (size_t i = 0; i < removed->len; i++) if (!str_hex(removed->v[i], FP_LEN)) return 0;
    /* !value.acks || typeof value.acks !== 'object': an object or an array */
    const nc_jv_t *acks = nc_jv_get(root, "acks");
    if (!is_obj(acks) && !is_arr(acks)) return 0;
    const nc_jv_t *ack_sent = field(root, "ackSent"), *pc = field(root, "profileCache");
    const nc_jv_t *dm = field(root, "dmSync"), *cn = field(root, "chainNames");
    const nc_jv_t *cnn = field(root, "chainNoName"), *vaults = field(root, "vaults");
    const nc_jv_t *groups = field(root, "groups"), *seen = field(root, "seenOwn");
    if (!is_obj(ack_sent) || !is_obj(pc) || !is_obj(dm) || !is_obj(cn) || !is_obj(cnn) ||
        !is_obj(vaults) || !is_obj(groups) || !is_obj(seen)) return 0;
    for (size_t i = 0; i < seen->len; i++) {
        if (!live(seen, i)) continue;
        if (!(key_is(seen, i, "profile") || key_is(seen, i, "list")) || !u64_of(t, seen->v[i])) return 0;
    }
    for (size_t i = 0; i < groups->len; i++) {
        if (!live(groups, i)) continue;
        const nc_jv_t *e = groups->v[i];
        if (!hex_n(groups->k[i], groups->kn[i], GID_LEN) || !is_obj(e) ||
            !str_rec_id(nc_jv_get(e, "id"), 'g') || !u64_of(t, nc_jv_get(e, "at"))) return 0;
    }
    for (size_t i = 0; i < pc->len; i++) {
        if (!live(pc, i)) continue;
        const nc_jv_t *e = pc->v[i];
        if (!is_obj(e) || !str_rec_id(nc_jv_get(e, "id"), 'p') || !u64_of(t, nc_jv_get(e, "at")) ||
            !is_str(nc_jv_get(e, "name"))) return 0;
    }
    for (size_t i = 0; i < dm->len; i++)
        if (live(dm, i) && !u64_of(t, dm->v[i])) return 0;
    for (size_t i = 0; i < cn->len; i++) {
        if (!live(cn, i)) continue;
        const nc_jv_t *e = cn->v[i];
        if (!hex_n(cn->k[i], cn->kn[i], FP_LEN) || !is_obj(e) || !chain_name_ok(nc_jv_get(e, "name")) ||
            !u64_of(t, nc_jv_get(e, "at"))) return 0;
    }
    for (size_t i = 0; i < cnn->len; i++) {
        if (!live(cnn, i)) continue;
        if (!hex_n(cnn->k[i], cnn->kn[i], FP_LEN) || !u64_of(t, cnn->v[i])) return 0;
    }
    for (size_t i = 0; i < vaults->len; i++) {
        if (!live(vaults, i)) continue;
        const nc_jv_t *e = vaults->v[i];
        if (!hex_n(vaults->k[i], vaults->kn[i], FP_LEN) || !is_obj(e) ||
            !str_rec_id(nc_jv_get(e, "id"), 'v') || !u64_of(t, nc_jv_get(e, "at"))) return 0;
    }
    return 1;
}

/* ── 2. what v2 cannot represent: dropped and listed (nc_state.h) ────── */

/* The paths of what the projection left out (design rev 2.1 item 1). */
typedef struct {
    char  **s;
    size_t *n;
    size_t  len, cap;
    int     oom;
} drops_t;

static void drops_free(drops_t *d) {
    for (size_t i = 0; i < d->len; i++) free(d->s[i]);
    free(d->s);
    free(d->n);
    memset(d, 0, sizeof(*d));
}

/* Appends <base>[<idx>].<key> — the index only when has_idx, the key only
 * when key != NULL. */
static void drop_add(drops_t *d, const char *base, size_t bn, int has_idx, size_t idx,
                     const char *key, size_t kn) {
    if (d->oom) return;
    if (d->len == d->cap) {
        size_t cap = d->cap ? d->cap * 2 : 8;
        char **s = realloc(d->s, cap * sizeof(*s));
        if (s) d->s = s;
        size_t *n = s ? realloc(d->n, cap * sizeof(*n)) : NULL;
        if (n) d->n = n;
        if (!s || !n) { d->oom = 1; return; }
        d->cap = cap;
    }
    nc_sb_t b;
    nc_sb_init(&b);
    nc_sb_put(&b, base, bn);
    if (has_idx) { nc_sb_putc(&b, '['); nc_u128_to_string((u128)idx, &b); nc_sb_putc(&b, ']'); }
    if (key) { nc_sb_putc(&b, '.'); nc_sb_put(&b, key, kn); }
    size_t len = 0;
    char *s = nc_sb_take(&b, &len);
    if (!s) { d->oom = 1; return; }
    d->s[d->len] = s;
    d->n[d->len] = len;
    d->len++;
}
#define DROP(d, lit, has_idx, idx, key, kn) drop_add((d), (lit), strlen(lit), (has_idx), (idx), (key), (kn))

/* Whether `key` (kn bytes) is one of `keys`. */
static int key_in(const char *key, size_t kn, const char *const *keys, size_t nk) {
    for (size_t j = 0; j < nk; j++) if (nc_js_str_eq(key, kn, keys[j])) return 1;
    return 0;
}
#define N_OF(a) (sizeof(a) / sizeof((a)[0]))

/* Every live key of entry `o` not in `keys`: <base>[idx].<key>. */
static void drop_extra_keys(drops_t *d, const char *base, size_t idx, const nc_jv_t *o,
                            const char *const *keys, size_t nk) {
    for (size_t i = 0; i < o->len; i++)
        if (live(o, i) && !key_in(o->k[i], o->kn[i], keys, nk)) DROP(d, base, 1, idx, o->k[i], o->kn[i]);
}

/* A contacts[] / outgoing[] entry v2 can hold: an object with a 128-hex fp.
 * Any other is dropped whole (no default exists for an ID). */
static int entry_ok(const nc_jv_t *e) { return is_obj(e) && str_hex(nc_jv_get(e, "fp"), FP_LEN); }

/* the salt kept: 64 lowercase hex, else none (the default, null) */
static const nc_jv_t *salt_of(const nc_jv_t *v) { return str_hex(v, SALT_LEN) ? v : NULL; }

/* The six per-ID maps of v1 (§2.2 item 3), in a fixed order. */
#define N_ID_MAPS 6
static const char *const ID_MAPS[N_ID_MAPS] = {
    "acks", "ackSent", "profileCache", "dmSync", "chainNames", "chainNoName"
};
/* Their values are U64 by String() (acks, ackSent: checkState does not look
 * at them; messages.js:1003, :1084 write U64 strings). The others' values
 * are checked by checkState. */
static int id_map_u64(int m) { return m == 0 || m == 1; }

/* Entry i of per-ID map m is kept: a live 128-hex key and, for acks /
 * ackSent, a U64 value. A dropped one is absent — the default. */
static int id_entry_ok(nc_sb_t *t, int m, const nc_jv_t *map, size_t i) {
    return live(map, i) && hex_n(map->k[i], map->kn[i], FP_LEN) && (!id_map_u64(m) || u64_of(t, map->v[i]));
}

/* The per-ID maps after checkState's defaults; acks as an array (which
 * checkState lets through) reads as {} — dropped when it is not empty. */
static void id_maps(const nc_jv_t *root, const nc_jv_t *maps[N_ID_MAPS]) {
    for (int m = 0; m < N_ID_MAPS; m++) {
        maps[m] = field(root, ID_MAPS[m]);
        if (is_arr(maps[m])) maps[m] = &EMPTY_OBJ;
    }
}

static const char *const V1_KEYS[] = {
    "version", "nextSeq", "contacts", "outgoing", "declined", "removed", "acks", "ackSent",
    "profileCache", "dmSync", "chainNames", "chainNoName", "vaults", "groups", "seenOwn", "listTaken"
};
static const char *const CONTACT_KEYS[] = { "fp", "salt", "listed" };
static const char *const OUTGOING_KEYS[] = { "fp", "salt", "at" };
static const char *const DECLINED_KEYS[] = { "fp", "at" };
static const char *const PROFILE_KEYS[] = { "id", "at", "name" };
static const char *const CHAIN_NAME_KEYS[] = { "name", "at" };
static const char *const INDEX_KEYS[] = { "id", "at" };

/* Lists every path the projection leaves out or replaces by its default
 * (nc_state.h "DROPPED"). Runs after the v1 gate, so every shape
 * checkState tests is already known good. Never refuses. */
static void scan_drops(nc_sb_t *t, const nc_jv_t *root, drops_t *d) {
    for (size_t i = 0; i < root->len; i++)
        if (live(root, i) && !key_in(root->k[i], root->kn[i], V1_KEYS, N_OF(V1_KEYS)))
            drop_add(d, root->k[i], root->kn[i], 0, 0, NULL, 0);
    const nc_jv_t *contacts = nc_jv_get(root, "contacts");
    for (size_t i = 0; i < contacts->len; i++) {
        const nc_jv_t *c = contacts->v[i], *listed;
        if (!entry_ok(c)) { DROP(d, "contacts", 1, i, NULL, 0); continue; }
        drop_extra_keys(d, "contacts", i, c, CONTACT_KEYS, N_OF(CONTACT_KEYS));
        const nc_jv_t *s = nc_jv_get(c, "salt");
        if (s && s->kind != NC_JV_NULL && !salt_of(s)) DROP(d, "contacts", 1, i, "salt", 4);
        if ((listed = nc_jv_get(c, "listed")) != NULL && !is_bool(listed)) DROP(d, "contacts", 1, i, "listed", 6);
    }
    const nc_jv_t *outgoing = nc_jv_get(root, "outgoing");
    for (size_t i = 0; i < outgoing->len; i++) {
        const nc_jv_t *o = outgoing->v[i];
        if (!entry_ok(o)) { DROP(d, "outgoing", 1, i, NULL, 0); continue; }
        drop_extra_keys(d, "outgoing", i, o, OUTGOING_KEYS, N_OF(OUTGOING_KEYS));
        const nc_jv_t *s = nc_jv_get(o, "salt");
        if (s && s->kind != NC_JV_NULL && !salt_of(s)) DROP(d, "outgoing", 1, i, "salt", 4);
        if (!u64_of(t, nc_jv_get(o, "at"))) DROP(d, "outgoing", 1, i, "at", 2);
    }
    const nc_jv_t *declined = nc_jv_get(root, "declined");
    for (size_t i = 0; i < declined->len; i++)
        if (is_obj(declined->v[i])) drop_extra_keys(d, "declined", i, declined->v[i], DECLINED_KEYS, N_OF(DECLINED_KEYS));
    const nc_jv_t *acks = nc_jv_get(root, "acks");
    if (is_arr(acks) && acks->len != 0) DROP(d, "acks", 0, 0, NULL, 0);
    const nc_jv_t *maps[N_ID_MAPS];
    id_maps(root, maps);
    for (int m = 0; m < N_ID_MAPS; m++) {
        size_t j = 0;                                /* the live entry's position */
        for (size_t i = 0; i < maps[m]->len; i++) {
            if (!live(maps[m], i)) continue;
            if (!id_entry_ok(t, m, maps[m], i)) DROP(d, ID_MAPS[m], 1, j, NULL, 0);
            else if (m == 2) drop_extra_keys(d, ID_MAPS[m], j, maps[m]->v[i], PROFILE_KEYS, N_OF(PROFILE_KEYS));
            else if (m == 4) drop_extra_keys(d, ID_MAPS[m], j, maps[m]->v[i], CHAIN_NAME_KEYS, N_OF(CHAIN_NAME_KEYS));
            j++;
        }
    }
    static const char *const INDEX_MAPS[] = { "vaults", "groups" };
    for (size_t k = 0; k < N_OF(INDEX_MAPS); k++) {
        const nc_jv_t *m = field(root, INDEX_MAPS[k]);
        size_t j = 0;
        for (size_t i = 0; i < m->len; i++) {
            if (!live(m, i)) continue;
            drop_extra_keys(d, INDEX_MAPS[k], j++, m->v[i], INDEX_KEYS, N_OF(INDEX_KEYS));
        }
    }
    const nc_jv_t *lt = nc_jv_get(root, "listTaken");
    if (lt && !is_bool(lt)) DROP(d, "listTaken", 0, 0, NULL, 0);
}

/* ── sorting (stable merge sort over indices; never qsort) ──────────── */

typedef int (*cmp_fn)(const void *ctx, size_t a, size_t b);

static void msort(size_t *idx, size_t *tmp, size_t n, cmp_fn cmp, const void *ctx) {
    if (n < 2) return;
    size_t h = n / 2;
    msort(idx, tmp, h, cmp, ctx);
    msort(idx + h, tmp, n - h, cmp, ctx);
    size_t i = 0, j = h, k = 0;
    while (i < h && j < n) tmp[k++] = cmp(ctx, idx[j], idx[i]) < 0 ? idx[j++] : idx[i++];
    while (i < h) tmp[k++] = idx[i++];
    while (j < n) tmp[k++] = idx[j++];
    memcpy(idx, tmp, n * sizeof(size_t));
}

/* Sorted index of n items; NULL when out of memory (n == 0: a valid
 * one-element allocation). */
static size_t *sorted_index(size_t n, cmp_fn cmp, const void *ctx) {
    size_t *idx = malloc((n ? n : 1) * sizeof(size_t));
    size_t *tmp = malloc((n ? n : 1) * sizeof(size_t));
    if (!idx || !tmp) { free(idx); free(tmp); return NULL; }
    for (size_t i = 0; i < n; i++) idx[i] = i;
    msort(idx, tmp, n, cmp, ctx);
    free(tmp);
    return idx;
}

static int cmp_fp_ptr(const void *ctx, size_t a, size_t b) {
    const char *const *p = ctx;
    return memcmp(p[a], p[b], FP_LEN);
}

static int cmp_bytes(const char *a, size_t an, const char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    if (c) return c;
    return an < bn ? -1 : an > bn ? 1 : 0;
}

/* the live keys of an object, by key bytes */
static int cmp_obj_key(const void *ctx, size_t a, size_t b) {
    const nc_jv_t *o = ctx;
    return cmp_bytes(o->k[a], o->kn[a], o->k[b], o->kn[b]);
}

static int cmp_ent_seq(const void *ctx, size_t a, size_t b) {
    const ent_t *e = ctx;
    return e[a].seq < e[b].seq ? -1 : e[a].seq > e[b].seq ? 1 : 0;
}

static int cmp_u128(const void *ctx, size_t a, size_t b) {
    const u128 *v = ctx;
    return v[a] < v[b] ? -1 : v[a] > v[b] ? 1 : 0;
}

static ent_t *ent_find(ent_t *e, size_t n, const char *fp) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(e[mid].fp, fp, FP_LEN);
        if (c == 0) return &e[mid];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* ── writers (JSON.stringify form, no whitespace) ───────────────────── */

static void w_str(nc_sb_t *b, const nc_jv_t *v) { nc_js_write_string(b, v->s, v->n); }
static void w_key(nc_sb_t *b, const char *lit) { nc_js_write_string(b, lit, strlen(lit)); nc_sb_putc(b, ':'); }
/* a u64 field: the decimal text String(v) as a JSON string (digits only) */
static void w_u64(nc_sb_t *b, const nc_jv_t *v) { nc_sb_putc(b, '"'); js_string(b, v); nc_sb_putc(b, '"'); }

static void w_id(nc_sb_t *b, char prefix, u128 seq) {
    char t[1 + ID_DIGITS + 1];
    t[0] = prefix;
    for (int i = ID_DIGITS; i >= 1; i--) { t[i] = (char)('0' + (int)(seq % 10)); seq /= 10; }
    t[1 + ID_DIGITS] = '\0';
    nc_sb_put(b, t, 1 + ID_DIGITS);
}

/* Any parsed value, compact, live pairs in input order. */
static void jv_write(nc_sb_t *b, const nc_jv_t *v) {
    switch (v->kind) {
    case NC_JV_NULL:  nc_sb_puts(b, "null"); return;
    case NC_JV_FALSE: nc_sb_puts(b, "false"); return;
    case NC_JV_TRUE:  nc_sb_puts(b, "true"); return;
    case NC_JV_NUM:   nc_js_write_number(b, v->num); return;
    case NC_JV_STR:   w_str(b, v); return;
    case NC_JV_ARR:
        nc_sb_putc(b, '[');
        for (size_t i = 0; i < v->len; i++) { if (i) nc_sb_putc(b, ','); jv_write(b, v->v[i]); }
        nc_sb_putc(b, ']');
        return;
    case NC_JV_OBJ: {
        nc_sb_putc(b, '{');
        int first = 1;
        for (size_t i = 0; i < v->len; i++) {
            if (!live(v, i)) continue;
            if (!first) nc_sb_putc(b, ',');
            first = 0;
            nc_js_write_string(b, v->k[i], v->kn[i]);
            nc_sb_putc(b, ':');
            jv_write(b, v->v[i]);
        }
        nc_sb_putc(b, '}');
        return;
    }
    }
}

/* vaults / groups: {"<key>":{"id":…,"at":"N"},…} ascending by key. */
static int w_index_map(nc_sb_t *b, const nc_jv_t *m) {
    size_t *idx = sorted_index(m->len, cmp_obj_key, m);
    if (!idx) return -1;
    nc_sb_putc(b, '{');
    int first = 1;
    for (size_t j = 0; j < m->len; j++) {
        size_t i = idx[j];
        if (!live(m, i)) continue;
        if (!first) nc_sb_putc(b, ',');
        first = 0;
        nc_js_write_string(b, m->k[i], m->kn[i]);
        nc_sb_putc(b, ':');
        nc_sb_putc(b, '{');
        w_key(b, "id"); w_str(b, nc_jv_get(m->v[i], "id"));
        nc_sb_putc(b, ',');
        w_key(b, "at"); w_u64(b, nc_jv_get(m->v[i], "at"));
        nc_sb_putc(b, '}');
    }
    nc_sb_putc(b, '}');
    free(idx);
    return 0;
}

static int w_header(nc_sb_t *b, const nc_jv_t *root, const ent_t *e, const size_t *by_seq, size_t n, u128 next) {
    nc_sb_puts(b, "{\"version\":2,\"nextSeq\":\"");
    nc_u128_to_string(next, b);
    nc_sb_puts(b, "\",\"ids\":[");
    for (size_t j = 0; j < n; j++) {
        if (j) nc_sb_putc(b, ',');
        nc_sb_putc(b, '"');
        w_id(b, 'c', e[by_seq[j]].seq);
        nc_sb_putc(b, '"');
    }
    nc_sb_puts(b, "],\"removed\":[");
    const nc_jv_t *removed = field(root, "removed");
    size_t from = removed->len > NC_STATE_REMOVED_MAX ? removed->len - NC_STATE_REMOVED_MAX : 0;
    for (size_t i = from; i < removed->len; i++) {
        if (i > from) nc_sb_putc(b, ',');
        w_str(b, removed->v[i]);
    }
    nc_sb_puts(b, "],\"declined\":[");
    const nc_jv_t *declined = nc_jv_get(root, "declined");
    for (size_t i = 0; i < declined->len; i++) {
        const nc_jv_t *d = declined->v[i];
        if (i) nc_sb_putc(b, ',');
        if (is_str(d)) { w_str(b, d); continue; }
        nc_sb_putc(b, '{');
        w_key(b, "fp"); w_str(b, nc_jv_get(d, "fp"));
        nc_sb_putc(b, ',');
        w_key(b, "at"); w_u64(b, nc_jv_get(d, "at"));
        nc_sb_putc(b, '}');
    }
    nc_sb_puts(b, "],\"vaults\":");
    if (w_index_map(b, field(root, "vaults")) != 0) return -1;
    nc_sb_puts(b, ",\"groups\":");
    if (w_index_map(b, field(root, "groups")) != 0) return -1;
    nc_sb_puts(b, ",\"net\":{\"v\":1");
    const nc_jv_t *seen = field(root, "seenOwn");
    const nc_jv_t *sp = nc_jv_get(seen, "profile"), *sl = nc_jv_get(seen, "list");
    if (sp || sl) {
        nc_sb_puts(b, ",\"seenOwn\":{");
        if (sp) { w_key(b, "profile"); w_u64(b, sp); }
        if (sl) { if (sp) nc_sb_putc(b, ','); w_key(b, "list"); w_u64(b, sl); }
        nc_sb_putc(b, '}');
    }
    const nc_jv_t *lt = nc_jv_get(root, "listTaken");
    if (lt && lt->kind == NC_JV_TRUE) nc_sb_puts(b, ",\"listTaken\":true");
    nc_sb_puts(b, "}}");
    return 0;
}

static void w_record(nc_sb_t *b, const ent_t *x) {
    nc_sb_putc(b, '{');
    w_key(b, "fp"); nc_js_write_string(b, x->fp, FP_LEN);
    if (x->contact) nc_sb_puts(b, ",\"contact\":{}");
    if (x->pending) {
        nc_sb_puts(b, ",\"pending\":{");
        w_key(b, "at");
        if (x->o_at) w_u64(b, x->o_at); else nc_sb_puts(b, "\"0\"");   /* dropped: the default */
        nc_sb_putc(b, '}');
    }
    if (x->profile) {
        nc_sb_puts(b, ",\"profile\":{");
        w_key(b, "id"); w_str(b, nc_jv_get(x->profile, "id"));
        nc_sb_putc(b, ',');
        w_key(b, "at"); w_u64(b, nc_jv_get(x->profile, "at"));
        nc_sb_putc(b, ',');
        w_key(b, "name"); w_str(b, nc_jv_get(x->profile, "name"));
        nc_sb_putc(b, '}');
    }
    if (x->chain_name) {
        nc_sb_puts(b, ",\"chainName\":{");
        w_key(b, "name"); w_str(b, nc_jv_get(x->chain_name, "name"));
        nc_sb_putc(b, ',');
        w_key(b, "at"); w_u64(b, nc_jv_get(x->chain_name, "at"));
        nc_sb_putc(b, '}');
    }
    if (x->chain_no_name) { nc_sb_puts(b, ",\"chainNoName\":"); w_u64(b, x->chain_no_name); }
    const nc_jv_t *salt = x->contact ? x->c_salt : NULL, *psalt = x->pending ? x->o_salt : NULL;
    int listed = x->contact && x->c_listed;
    if (salt || psalt || listed || x->ack || x->ack_sent || x->dm_sync) {
        nc_sb_puts(b, ",\"net\":{\"v\":1");
        if (salt) { nc_sb_putc(b, ','); w_key(b, "salt"); w_str(b, salt); }
        if (psalt) { nc_sb_putc(b, ','); w_key(b, "pendingSalt"); w_str(b, psalt); }
        if (listed) nc_sb_puts(b, ",\"listed\":true");
        if (x->ack) { nc_sb_putc(b, ','); w_key(b, "ack"); w_u64(b, x->ack); }
        if (x->ack_sent) { nc_sb_putc(b, ','); w_key(b, "ackSent"); w_u64(b, x->ack_sent); }
        if (x->dm_sync) { nc_sb_putc(b, ','); w_key(b, "dmSync"); w_u64(b, x->dm_sync); }
        nc_sb_putc(b, '}');
    }
    nc_sb_putc(b, '}');
}

/* ── 3-5. the projection ────────────────────────────────────────────── */

static int cmp_drop(const void *ctx, size_t a, size_t b) {
    const drops_t *d = ctx;
    return cmp_bytes(d->s[a], d->n[a], d->s[b], d->n[b]);
}

/* The dropped paths into p, ascending by bytes, each once. 0, or -1 when
 * out of memory. */
static int take_drops(drops_t *d, proj_t *p) {
    if (d->oom) return -1;
    size_t *idx = sorted_index(d->len, cmp_drop, d);
    p->drop = malloc((d->len ? d->len : 1) * sizeof(*p->drop));
    p->drop_len = malloc((d->len ? d->len : 1) * sizeof(*p->drop_len));
    if (!idx || !p->drop || !p->drop_len) { free(idx); return -1; }
    for (size_t j = 0; j < d->len; j++) {
        size_t i = idx[j];
        if (p->n_drop && cmp_bytes(p->drop[p->n_drop - 1], p->drop_len[p->n_drop - 1], d->s[i], d->n[i]) == 0) {
            free(d->s[i]);
        } else {
            p->drop[p->n_drop] = d->s[i];
            p->drop_len[p->n_drop] = d->n[i];
            p->n_drop++;
        }
        d->s[i] = NULL;
    }
    free(idx);
    return 0;
}

static int project_tree(const nc_jv_t *root, const nc_jv_t *map, proj_t *p) {
    memset(p, 0, sizeof(*p));
    nc_sb_t t;
    nc_sb_init(&t);
    drops_t d;
    memset(&d, 0, sizeof(d));
    ent_t *e = NULL;
    const char **all = NULL;
    size_t *idx = NULL, *order = NULL, *by_seq = NULL, *pos = NULL;
    u128 *seqs = NULL;
    int rc = -1;

    if (!check_state(&t, root)) { p->why = t.oom ? NULL : "checkState"; rc = t.oom ? -1 : 0; goto out; }
    scan_drops(&t, root, &d);
    if (t.oom || d.oom) goto out;

    /* Below, every entry scan_drops dropped whole is skipped by the same
     * tests (entry_ok, id_entry_ok), in both passes. */
    const nc_jv_t *contacts = nc_jv_get(root, "contacts"), *outgoing = nc_jv_get(root, "outgoing");
    const nc_jv_t *maps[N_ID_MAPS];
    id_maps(root, maps);

    /* every fp, then the distinct ones ascending */
    size_t cap = contacts->len + outgoing->len, k = 0;
    for (int m = 0; m < N_ID_MAPS; m++) cap += maps[m]->len;
    all = malloc((cap ? cap : 1) * sizeof(*all));
    if (!all) goto out;
    for (size_t i = 0; i < contacts->len; i++)
        if (entry_ok(contacts->v[i])) all[k++] = nc_jv_get(contacts->v[i], "fp")->s;
    for (size_t i = 0; i < outgoing->len; i++)
        if (entry_ok(outgoing->v[i])) all[k++] = nc_jv_get(outgoing->v[i], "fp")->s;
    for (int m = 0; m < N_ID_MAPS; m++)
        for (size_t i = 0; i < maps[m]->len; i++) if (id_entry_ok(&t, m, maps[m], i)) all[k++] = maps[m]->k[i];
    if (t.oom) goto out;
    idx = sorted_index(k, cmp_fp_ptr, all);
    e = calloc(k ? k : 1, sizeof(*e));
    if (!idx || !e) goto out;
    size_t n = 0;
    for (size_t j = 0; j < k; j++)
        if (n == 0 || memcmp(e[n - 1].fp, all[idx[j]], FP_LEN) != 0) e[n++].fp = all[idx[j]];

    /* contacts: the first entry of an fp wins (messages.js:469) */
    size_t n_c = 0, n_o = 0;
    for (size_t i = 0; i < contacts->len; i++) {
        const nc_jv_t *c = contacts->v[i];
        if (!entry_ok(c)) continue;
        ent_t *x = ent_find(e, n, nc_jv_get(c, "fp")->s);
        if (x->contact) continue;
        const nc_jv_t *listed = nc_jv_get(c, "listed");
        x->contact = 1;
        x->c_rank = n_c++;
        x->c_salt = salt_of(nc_jv_get(c, "salt"));
        x->c_listed = listed && listed->kind == NC_JV_TRUE;
    }
    /* outgoing: the Map of messages.js:317 — first position, last value */
    for (size_t i = 0; i < outgoing->len; i++) {
        const nc_jv_t *o = outgoing->v[i];
        if (!entry_ok(o)) continue;
        ent_t *x = ent_find(e, n, nc_jv_get(o, "fp")->s);
        if (!x->pending) { x->pending = 1; x->o_rank = n_o++; }
        x->o_salt = salt_of(nc_jv_get(o, "salt"));
        x->o_at = u64_of(&t, nc_jv_get(o, "at")) ? nc_jv_get(o, "at") : NULL;   /* NULL: "0" */
    }
    for (int m = 0; m < N_ID_MAPS; m++)
        for (size_t i = 0; i < maps[m]->len; i++) {
            if (!id_entry_ok(&t, m, maps[m], i)) continue;
            ent_t *x = ent_find(e, n, maps[m]->k[i]);
            const nc_jv_t *v = maps[m]->v[i];
            switch (m) {
            case 0: x->ack = v; break;
            case 1: x->ack_sent = v; break;
            case 2: x->profile = v; break;
            case 3: x->dm_sync = v; break;
            case 4: x->chain_name = v; break;
            default: x->chain_no_name = v; break;
            }
        }

    /* nextSeq (U64 by String(), checked by the gate) */
    nc_sb_reset(&t);
    js_string(&t, nc_jv_get(root, "nextSeq"));
    if (t.oom) goto out;
    u128 next = digits_value(t.p, t.len);

    /* the previous fp -> id map */
    if (!is_obj(map)) { p->why = "map"; rc = 0; goto out; }
    seqs = malloc((map->len ? map->len : 1) * sizeof(*seqs));
    if (!seqs) goto out;
    size_t ns = 0;
    for (size_t i = 0; i < map->len; i++) {
        if (!live(map, i)) continue;
        const nc_jv_t *v = map->v[i];
        if (!hex_n(map->k[i], map->kn[i], FP_LEN) || !str_rec_id(v, 'c')) { p->why = "map"; rc = 0; goto out; }
        u128 s = digits_value(v->s + 1, ID_DIGITS);
        if (s >= next) { p->why = "map"; rc = 0; goto out; }
        seqs[ns++] = s;
    }
    {
        size_t *si = sorted_index(ns, cmp_u128, seqs);
        if (!si) goto out;
        int dup = 0;
        for (size_t j = 1; j < ns; j++) if (seqs[si[j]] == seqs[si[j - 1]]) dup = 1;
        free(si);
        if (dup) { p->why = "map"; rc = 0; goto out; }
    }
    for (size_t i = 0; i < map->len; i++) {
        if (!live(map, i)) continue;
        ent_t *x = ent_find(e, n, map->k[i]);
        if (!x) continue;                                  /* no field left: dropped */
        x->seq = digits_value(map->v[i]->s + 1, ID_DIGITS);
        x->has_id = 1;
    }

    /* allocation order (§2.2 item 3) */
    order = malloc((n ? n : 1) * sizeof(*order));
    pos = malloc(((n_c > n_o ? n_c : n_o) ? (n_c > n_o ? n_c : n_o) : 1) * sizeof(*pos));
    if (!order || !pos) goto out;
    size_t no = 0;
    for (size_t i = 0; i < n; i++) if (e[i].contact) pos[e[i].c_rank] = i;
    for (size_t r = 0; r < n_c; r++) order[no++] = pos[r];
    for (size_t i = 0; i < n; i++) if (e[i].pending) pos[e[i].o_rank] = i;
    for (size_t r = 0; r < n_o; r++) if (!e[pos[r]].contact) order[no++] = pos[r];
    for (size_t i = 0; i < n; i++) if (!e[i].contact && !e[i].pending) order[no++] = i;
    const u128 max = u64_regex_max();
    for (size_t j = 0; j < no; j++) {
        ent_t *x = &e[order[j]];
        if (x->has_id) continue;
        if (next >= max) { p->why = "nextSeq"; rc = 0; goto out; }
        x->seq = next++;
    }

    /* the bytes */
    by_seq = sorted_index(n, cmp_ent_seq, e);
    p->rec = calloc(n ? n : 1, sizeof(*p->rec));
    if (!by_seq || !p->rec) goto out;
    nc_sb_t b;
    nc_sb_init(&b);
    if (w_header(&b, root, e, by_seq, n, next) != 0) { nc_sb_free(&b); goto out; }
    p->header = nc_sb_take(&b, &p->header_len);
    if (!p->header) goto out;
    for (size_t j = 0; j < n; j++) {
        const ent_t *x = &e[by_seq[j]];
        prec_t *r = &p->rec[p->n_rec];
        nc_sb_init(&b);
        w_record(&b, x);
        r->json = nc_sb_take(&b, &r->json_len);
        if (!r->json) goto out;
        nc_sb_init(&b);
        w_id(&b, 'c', x->seq);
        if (b.oom || b.len != sizeof(r->id) - 1) { nc_sb_free(&b); free(r->json); r->json = NULL; goto out; }
        memcpy(r->id, b.p, b.len + 1);
        nc_sb_free(&b);
        memcpy(r->fp, x->fp, FP_LEN);
        r->fp[FP_LEN] = '\0';
        p->n_rec++;
    }
    p->next = next;
    if (take_drops(&d, p) != 0) goto out;
    rc = 0;
out:
    if (t.oom) rc = -1;
    if (rc != 0 || p->why) {
        const char *why = p->why;
        proj_free(p);
        p->why = rc == 0 ? why : NULL;
    }
    drops_free(&d);
    nc_sb_free(&t);
    free(e);
    free(all);
    free(idx);
    free(order);
    free(by_seq);
    free(pos);
    free(seqs);
    return rc;
}

/* {"status":"<s>","reason":"<r>"} */
static int w_refusal(const char *status, const char *reason, char **out, size_t *out_len) {
    nc_sb_t b;
    nc_sb_init(&b);
    nc_sb_putc(&b, '{');
    w_key(&b, "status");
    nc_js_write_string(&b, status, strlen(status));
    nc_sb_putc(&b, ',');
    w_key(&b, "reason");
    nc_js_write_string(&b, reason, strlen(reason));
    nc_sb_putc(&b, '}');
    *out = nc_sb_take(&b, out_len);
    return *out ? 0 : -1;
}

int nc_state_project_json(const char *state, size_t state_len,
                          const char *map, size_t map_len,
                          char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (!state || !map) return -1;
    nc_jv_t *root = NULL, *mtree = NULL;
    nc_js_parse_t pr = nc_js_parse(state, state_len, &root);
    if (pr == NC_JS_NOMEM) return -1;
    if (pr != NC_JS_OK) return w_refusal("invalid", "json", out, out_len);
    pr = nc_js_parse(map, map_len, &mtree);         /* a failed parse: NULL -> "map" */
    if (pr == NC_JS_NOMEM) { nc_jv_free(root); return -1; }
    proj_t p;
    int rc = project_tree(root, mtree, &p);
    nc_jv_free(root);
    nc_jv_free(mtree);
    if (rc != 0) return -1;
    if (p.why) return w_refusal("invalid", p.why, out, out_len);
    nc_sb_t b;
    nc_sb_init(&b);
    nc_sb_puts(&b, "{\"status\":\"ok\",\"nextSeq\":\"");
    nc_u128_to_string(p.next, &b);
    nc_sb_puts(&b, "\",\"header\":");
    nc_js_write_string(&b, p.header, p.header_len);
    nc_sb_puts(&b, ",\"records\":[");
    for (size_t i = 0; i < p.n_rec; i++) {
        if (i) nc_sb_putc(&b, ',');
        nc_sb_putc(&b, '{');
        w_key(&b, "id"); nc_js_write_string(&b, p.rec[i].id, 1 + ID_DIGITS);
        nc_sb_putc(&b, ',');
        w_key(&b, "fp"); nc_js_write_string(&b, p.rec[i].fp, FP_LEN);
        nc_sb_putc(&b, ',');
        w_key(&b, "json"); nc_js_write_string(&b, p.rec[i].json, p.rec[i].json_len);
        nc_sb_putc(&b, '}');
    }
    nc_sb_puts(&b, "],\"dropped\":[");
    for (size_t i = 0; i < p.n_drop; i++) {
        if (i) nc_sb_putc(&b, ',');
        nc_js_write_string(&b, p.drop[i], p.drop_len[i]);
    }
    nc_sb_puts(&b, "]}");
    proj_free(&p);
    *out = nc_sb_take(&b, out_len);
    return *out ? 0 : -1;
}

int nc_state_project_wrapped_json(const char *in, size_t in_len, char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (!in) return -1;
    nc_jv_t *w = NULL;
    nc_js_parse_t pr = nc_js_parse(in, in_len, &w);
    if (pr == NC_JS_NOMEM) return -1;
    const nc_jv_t *st = pr == NC_JS_OK ? nc_jv_get(w, "state") : NULL;
    const nc_jv_t *mp = pr == NC_JS_OK ? nc_jv_get(w, "map") : NULL;
    int rc;
    if (!is_obj(w) || !is_str(st)) rc = w_refusal("invalid", "json", out, out_len);
    else if (!is_str(mp)) rc = w_refusal("invalid", "map", out, out_len);
    else rc = nc_state_project_json(st->s, st->n, mp->s, mp->n, out, out_len);
    nc_jv_free(w);
    return rc;
}

/* ── LOAD ───────────────────────────────────────────────────────────── */

/* the input records (validated: objects with a string "id"), by id bytes */
static int cmp_in_id(const void *ctx, size_t a, size_t b) {
    const nc_jv_t *list = ctx;
    const nc_jv_t *x = nc_jv_get(list->v[a], "id"), *y = nc_jv_get(list->v[b], "id");
    return cmp_bytes(x->s, x->n, y->s, y->n);
}

/* The input record with this id (idx: the records sorted by id), or NULL. */
static const nc_jv_t *in_find(const nc_jv_t *list, const size_t *idx, const nc_jv_t *id) {
    size_t lo = 0, hi = list->len;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const nc_jv_t *m = nc_jv_get(list->v[idx[mid]], "id");
        int c = cmp_bytes(m->s, m->n, id->s, id->n);
        if (c == 0) return list->v[idx[mid]];
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

/* net.v, when net is an object holding "v": must be the number 1. */
static int net_version_ok(const nc_jv_t *holder) {
    const nc_jv_t *net = nc_jv_get(holder, "net");
    const nc_jv_t *v = is_obj(net) ? nc_jv_get(net, "v") : NULL;
    return !v || is_num(v, (double)NC_STATE_NET_V);
}

/* `"<key>":{ "<fp>": <net[field] or holder[field]>, … }` over the records
 * that carry it (in id order). in_net: the field is inside record.net. */
static void w_v1_map(nc_sb_t *b, const char *key, nc_jv_t *const *recs, size_t n, const char *fld, int in_net) {
    nc_sb_putc(b, ',');
    w_key(b, key);
    nc_sb_putc(b, '{');
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        const nc_jv_t *v = nc_jv_get(in_net ? nc_jv_get(recs[i], "net") : recs[i], fld);
        if (!v) continue;
        if (!first) nc_sb_putc(b, ',');
        first = 0;
        w_str(b, nc_jv_get(recs[i], "fp"));
        nc_sb_putc(b, ':');
        jv_write(b, v);
    }
    nc_sb_putc(b, '}');
}

/* The v1 object the records describe (nc_state.h "The canonical v1
 * object"); a value that is not there is left out, so the re-projection
 * (checkState's defaults included) decides. */
static void w_v1(nc_sb_t *b, const nc_jv_t *h, nc_jv_t *const *recs, size_t n) {
    const nc_jv_t *v, *hnet = nc_jv_get(h, "net");
    nc_sb_puts(b, "{\"version\":1");
    if ((v = nc_jv_get(h, "nextSeq")) != NULL) { nc_sb_putc(b, ','); w_key(b, "nextSeq"); jv_write(b, v); }
    nc_sb_puts(b, ",\"contacts\":[");
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        if (!nc_jv_get(recs[i], "contact")) continue;
        const nc_jv_t *net = nc_jv_get(recs[i], "net");
        const nc_jv_t *salt = nc_jv_get(net, "salt"), *listed = nc_jv_get(net, "listed");
        if (!first) nc_sb_putc(b, ',');
        first = 0;
        nc_sb_putc(b, '{');
        w_key(b, "fp"); w_str(b, nc_jv_get(recs[i], "fp"));
        nc_sb_putc(b, ',');
        w_key(b, "salt"); if (salt) jv_write(b, salt); else nc_sb_puts(b, "null");
        nc_sb_putc(b, ',');
        w_key(b, "listed"); if (listed) jv_write(b, listed); else nc_sb_puts(b, "false");
        nc_sb_putc(b, '}');
    }
    nc_sb_puts(b, "],\"outgoing\":[");
    first = 1;
    for (size_t i = 0; i < n; i++) {
        const nc_jv_t *pend = nc_jv_get(recs[i], "pending");
        if (!pend) continue;
        const nc_jv_t *salt = nc_jv_get(nc_jv_get(recs[i], "net"), "pendingSalt");
        const nc_jv_t *at = nc_jv_get(pend, "at");
        if (!first) nc_sb_putc(b, ',');
        first = 0;
        nc_sb_putc(b, '{');
        w_key(b, "fp"); w_str(b, nc_jv_get(recs[i], "fp"));
        nc_sb_putc(b, ',');
        w_key(b, "salt"); if (salt) jv_write(b, salt); else nc_sb_puts(b, "null");
        if (at) { nc_sb_putc(b, ','); w_key(b, "at"); jv_write(b, at); }
        nc_sb_putc(b, '}');
    }
    nc_sb_putc(b, ']');
    if ((v = nc_jv_get(h, "declined")) != NULL) { nc_sb_putc(b, ','); w_key(b, "declined"); jv_write(b, v); }
    if ((v = nc_jv_get(h, "removed")) != NULL) { nc_sb_putc(b, ','); w_key(b, "removed"); jv_write(b, v); }
    w_v1_map(b, "acks", recs, n, "ack", 1);
    w_v1_map(b, "ackSent", recs, n, "ackSent", 1);
    w_v1_map(b, "profileCache", recs, n, "profile", 0);
    w_v1_map(b, "dmSync", recs, n, "dmSync", 1);
    w_v1_map(b, "chainNames", recs, n, "chainName", 0);
    w_v1_map(b, "chainNoName", recs, n, "chainNoName", 0);
    if ((v = nc_jv_get(h, "vaults")) != NULL) { nc_sb_putc(b, ','); w_key(b, "vaults"); jv_write(b, v); }
    if ((v = nc_jv_get(h, "groups")) != NULL) { nc_sb_putc(b, ','); w_key(b, "groups"); jv_write(b, v); }
    nc_sb_putc(b, ',');
    w_key(b, "seenOwn");
    if ((v = nc_jv_get(hnet, "seenOwn")) != NULL) jv_write(b, v); else nc_sb_puts(b, "{}");
    if ((v = nc_jv_get(hnet, "listTaken")) != NULL) { nc_sb_putc(b, ','); w_key(b, "listTaken"); jv_write(b, v); }
    nc_sb_putc(b, '}');
}

static int cmp_rec_fp(const void *ctx, size_t a, size_t b) {
    nc_jv_t *const *recs = ctx;
    return memcmp(nc_jv_get(recs[a], "fp")->s, nc_jv_get(recs[b], "fp")->s, FP_LEN);
}

int nc_state_load_json(const char *in, size_t in_len, char **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (!in) return -1;
    nc_jv_t *w = NULL, *h = NULL, *v1 = NULL, *mtree = NULL;
    nc_jv_t **recs = NULL;
    size_t *idx = NULL, *fpi = NULL, n = 0;
    nc_sb_t s1, sm;
    nc_sb_init(&s1);
    nc_sb_init(&sm);
    proj_t p;
    memset(&p, 0, sizeof(p));
    const char *why = NULL;
    int rc = -1;

    nc_js_parse_t pr = nc_js_parse(in, in_len, &w);
    if (pr == NC_JS_NOMEM) goto out;
    const nc_jv_t *hs = pr == NC_JS_OK ? nc_jv_get(w, "header") : NULL;
    const nc_jv_t *list = pr == NC_JS_OK ? nc_jv_get(w, "records") : NULL;
    if (!is_obj(w) || !is_str(hs) || !is_arr(list)) { why = "input"; goto refuse; }
    for (size_t i = 0; i < list->len; i++) {
        const nc_jv_t *r = list->v[i];
        if (!is_obj(r) || !is_str(nc_jv_get(r, "id")) || !is_str(nc_jv_get(r, "json"))) { why = "input"; goto refuse; }
    }
    idx = sorted_index(list->len, cmp_in_id, list);
    if (!idx) goto out;
    for (size_t j = 1; j < list->len; j++)
        if (cmp_in_id(list, idx[j - 1], idx[j]) == 0) { why = "input"; goto refuse; }

    pr = nc_js_parse(hs->s, hs->n, &h);
    if (pr == NC_JS_NOMEM) goto out;
    if (pr != NC_JS_OK || !is_obj(h)) { why = "header"; goto refuse; }
    if (!is_num(nc_jv_get(h, "version"), (double)NC_STATE_VERSION) || !net_version_ok(h)) { why = "version"; goto refuse; }
    const nc_jv_t *ids = nc_jv_get(h, "ids");
    if (!is_arr(ids)) { why = "header"; goto refuse; }
    for (size_t i = 0; i < ids->len; i++) if (!str_rec_id(ids->v[i], 'c')) { why = "header"; goto refuse; }

    recs = calloc(ids->len ? ids->len : 1, sizeof(*recs));
    if (!recs) goto out;
    for (n = 0; n < ids->len; n++) {
        const nc_jv_t *r = in_find(list, idx, ids->v[n]);
        if (!r) { why = "missing record"; goto refuse; }
        const nc_jv_t *js = nc_jv_get(r, "json");
        pr = nc_js_parse(js->s, js->n, &recs[n]);
        if (pr == NC_JS_NOMEM) goto out;
        if (pr != NC_JS_OK || !is_obj(recs[n]) || !str_hex(nc_jv_get(recs[n], "fp"), FP_LEN)) {
            n++;                                     /* recs[n] (maybe NULL) is freed below */
            why = "bad record";
            goto refuse;
        }
        if (!net_version_ok(recs[n])) { n++; why = "version"; goto refuse; }
    }
    fpi = sorted_index(n, cmp_rec_fp, recs);
    if (!fpi) goto out;
    for (size_t j = 1; j < n; j++)
        if (cmp_rec_fp(recs, fpi[j - 1], fpi[j]) == 0) { why = "duplicate fp"; goto refuse; }

    /* the v1 object and the map, then the re-projection must give the same bytes */
    w_v1(&s1, h, recs, n);
    nc_sb_putc(&sm, '{');
    for (size_t i = 0; i < n; i++) {
        if (i) nc_sb_putc(&sm, ',');
        w_str(&sm, nc_jv_get(recs[i], "fp"));
        nc_sb_putc(&sm, ':');
        w_str(&sm, ids->v[i]);
    }
    nc_sb_putc(&sm, '}');
    if (s1.oom || sm.oom) goto out;
    pr = nc_js_parse(s1.p, s1.len, &v1);
    if (pr == NC_JS_NOMEM) goto out;
    if (pr != NC_JS_OK) { why = "not canonical"; goto refuse; }
    pr = nc_js_parse(sm.p, sm.len, &mtree);
    if (pr == NC_JS_NOMEM) goto out;
    if (pr != NC_JS_OK) { why = "not canonical"; goto refuse; }
    if (project_tree(v1, mtree, &p) != 0) goto out;
    /* nothing dropped: a stored record holds only what v2 represents */
    int same = !p.why && p.n_drop == 0 && p.header_len == hs->n && memcmp(p.header, hs->s, hs->n) == 0 && p.n_rec == n;
    for (size_t i = 0; same && i < n; i++) {
        const nc_jv_t *js = nc_jv_get(in_find(list, idx, ids->v[i]), "json");
        same = memcmp(p.rec[i].id, ids->v[i]->s, 1 + ID_DIGITS) == 0 &&
               p.rec[i].json_len == js->n && memcmp(p.rec[i].json, js->s, js->n) == 0;
    }
    if (!same) { why = "not canonical"; goto refuse; }

    {
        nc_sb_t b;
        nc_sb_init(&b);
        nc_sb_puts(&b, "{\"status\":\"ok\",\"state\":");
        nc_sb_put(&b, s1.p, s1.len);
        nc_sb_puts(&b, ",\"map\":");
        nc_sb_put(&b, sm.p, sm.len);
        nc_sb_putc(&b, '}');
        *out = nc_sb_take(&b, out_len);
        rc = *out ? 0 : -1;
    }
    goto out;
refuse:
    rc = w_refusal("damaged", why, out, out_len);
out:
    proj_free(&p);
    nc_jv_free(w);
    nc_jv_free(h);
    nc_jv_free(v1);
    nc_jv_free(mtree);
    if (recs) for (size_t i = 0; i < n; i++) nc_jv_free(recs[i]);
    free(recs);
    free(idx);
    free(fpi);
    nc_sb_free(&s1);
    nc_sb_free(&sm);
    return rc;
}
