/* Nodus Connect core — the P1 rules' JSON dispatcher (nc_rules_json.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_rules_json.h"
#include "nc_jsjson.h"
#include "nc_payload.h"
#include "nc_rules.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RJ_OK    0
#define RJ_BAD   1      /* outside the argument contract */
#define RJ_NOMEM (-1)

/* ── reading the arguments ──────────────────────────────────────────── */

/* args[key]: *present = 0 when absent (JSON null is a NC_JV_NULL node). */
static const nc_jv_t *arg(const nc_jv_t *args, const char *key, int *present) {
    const nc_jv_t *o = nc_jv_get(args, key);
    *present = o != NULL;
    return o;
}

static int is_compound(const nc_jv_t *o) {
    return o && (o->kind == NC_JV_OBJ || o->kind == NC_JV_ARR);
}

/* A scalar argument (absent = undefined). */
static int scalar_arg(const nc_jv_t *args, const char *key, nc_val_t *v) {
    return nc_val_from_jv(nc_jv_get(args, key), v) == 0 ? RJ_OK : RJ_BAD;
}

/* A field of a flat object (checked by elem_of). */
static nc_val_t fld(const nc_jv_t *obj, const char *key) {
    nc_val_t v = nc_val_undef();
    if (obj && obj->kind == NC_JV_OBJ) (void)nc_val_from_jv(nc_jv_get(obj, key), &v);
    return v;
}

/* What `o` is as an object argument / list element. present = 0 (an
 * absent argument = undefined) reads like null. A JSON object must be flat:
 * every value JSON.parse keeps (a repeated key's earlier, dead values do
 * not count, as in Object.values) is a scalar. */
static int elem_of(const nc_jv_t *o, int present, nc_elem_t *elem) {
    if (!present || !o || o->kind == NC_JV_NULL) { *elem = NC_ELEM_NULL; return RJ_OK; }
    if (o->kind == NC_JV_OBJ) {
        for (size_t i = 0; i < o->len; i++)
            if (!(o->dead && o->dead[i]) && is_compound(o->v[i])) return RJ_BAD;
        *elem = NC_ELEM_OBJECT;
        return RJ_OK;
    }
    *elem = NC_ELEM_OTHER;
    return RJ_OK;
}

/* `x || []` (nc_payload.h nc_list_t). */
static nc_list_t list_of(const nc_jv_t *o, int present) {
    if (!present || !o) return NC_LIST_EMPTY;
    if (o->kind == NC_JV_ARR) return NC_LIST_ARRAY;
    if (o->kind == NC_JV_OBJ) return NC_LIST_BAD;
    nc_val_t v;
    (void)nc_val_from_jv(o, &v);
    return nc_val_truthy(&v) ? NC_LIST_BAD : NC_LIST_EMPTY;
}

static int msg_of(const nc_jv_t *o, nc_msg_t *m) {
    memset(m, 0, sizeof(*m));
    if (elem_of(o, 1, &m->elem) != RJ_OK) return RJ_BAD;
    if (m->elem != NC_ELEM_OBJECT) return RJ_OK;
    m->dir = fld(o, "dir");
    m->fp = fld(o, "fp");
    m->text = fld(o, "text");
    m->ts = fld(o, "ts");
    m->sender_ts = fld(o, "senderTs");
    m->seq = fld(o, "seq");
    m->kind = fld(o, "kind");
    m->target = fld(o, "target");
    return RJ_OK;
}

/* records: an array of message records -> *out (malloc'd). */
static int records_of(const nc_jv_t *args, nc_msg_t **out, size_t *n) {
    int present;
    const nc_jv_t *a = arg(args, "records", &present);
    *out = NULL;
    *n = 0;
    if (!present || a->kind != NC_JV_ARR) return RJ_BAD;
    size_t len = a->len;
    nc_msg_t *m = calloc(len ? len : 1, sizeof(*m));
    if (!m) return RJ_NOMEM;
    for (size_t i = 0; i < len; i++)
        if (msg_of(a->v[i], &m[i]) != RJ_OK) { free(m); return RJ_BAD; }
    *out = m;
    *n = len;
    return RJ_OK;
}

/* ── writing the result ─────────────────────────────────────────────── */

static void w_str(nc_sb_t *o, const char *s, size_t n) { nc_js_write_string(o, s ? s : "", n); }

/* A scalar as JSON.stringify writes it; undefined (an array element) as null. */
static void w_val(nc_sb_t *o, const nc_val_t *v) {
    switch (v->kind) {
    case NC_V_STR:   w_str(o, v->s, v->n); break;
    case NC_V_NUM:   nc_js_write_number(o, v->num); break;
    case NC_V_TRUE:  nc_sb_puts(o, "true"); break;
    case NC_V_FALSE: nc_sb_puts(o, "false"); break;
    default:         nc_sb_puts(o, "null"); break;
    }
}

static void w_size(nc_sb_t *o, size_t n) { nc_u128_to_string((unsigned __int128)n, o); }

static void w_error(nc_sb_t *o, const char *msg) {
    nc_sb_reset(o);
    nc_sb_puts(o, "{\"error\":");
    w_str(o, msg, strlen(msg));
    nc_sb_putc(o, '}');
}

/* A function's throw / null as the result; RJ_OK unless out of memory. */
static int w_rc(nc_sb_t *o, int rc, const char *throw_msg) {
    switch (rc) {
    case NC_P_NULL:         nc_sb_puts(o, "null"); return RJ_OK;
    case NC_P_THROW:        w_error(o, throw_msg ? throw_msg : "Error"); return RJ_OK;
    case NC_P_TYPE_ERROR:   w_error(o, "TypeError"); return RJ_OK;
    case NC_P_RANGE_ERROR:  w_error(o, "RangeError"); return RJ_OK;
    case NC_P_SYNTAX_ERROR: w_error(o, "SyntaxError"); return RJ_OK;
    case NC_P_UNSUPPORTED:  w_error(o, "nc_rule: unsupported BigInt literal"); return RJ_OK;
    default:                return RJ_NOMEM;
    }
}

/* ── the rules ──────────────────────────────────────────────────────── */

static int r_content_hash(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t s, r, t, ts;
    if (scalar_arg(a, "senderFp", &s) || scalar_arg(a, "recipientFp", &r) ||
        scalar_arg(a, "text", &t) || scalar_arg(a, "ts", &ts)) return RJ_BAD;
    char h[65];
    int rc = nc_content_hash(&s, &r, &t, &ts, h);
    if (rc != NC_P_OK) return w_rc(o, rc, NULL);
    w_str(o, h, 64);
    return RJ_OK;
}

static int r_message_hash(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *mo = arg(a, "m", &present);
    nc_msg_t m;
    nc_val_t own;
    memset(&m, 0, sizeof(m));
    if (scalar_arg(a, "ownFp", &own)) return RJ_BAD;
    if (!present) m.elem = NC_ELEM_NULL;
    else if (msg_of(mo, &m) != RJ_OK) return RJ_BAD;
    char h[65];
    int rc = nc_message_hash(&m, &own, h);
    if (rc != NC_P_OK) return w_rc(o, rc, NULL);
    w_str(o, h, 64);
    return RJ_OK;
}

static int r_build_reaction(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t t, e, op;
    if (scalar_arg(a, "target", &t) || scalar_arg(a, "emoji", &e) || scalar_arg(a, "op", &op)) return RJ_BAD;
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = nc_build_reaction(&t, &e, &op, &s);
    if (rc == NC_P_OK) w_str(o, s.p, s.len);
    nc_sb_free(&s);
    return rc == NC_P_OK ? RJ_OK : w_rc(o, rc, NC_P_MSG_REACTION);
}

/* String(args.text) into `b`. */
static int text_arg(const nc_jv_t *a, const char *key, nc_sb_t *b) {
    nc_val_t v;
    if (scalar_arg(a, key, &v)) return RJ_BAD;
    nc_val_tostring(&v, b);
    nc_sb_put(b, "", 0);
    return b->oom ? RJ_NOMEM : RJ_OK;
}

static int r_parse_reaction(const nc_jv_t *a, nc_sb_t *o) {
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = text_arg(a, "text", &s);
    if (rc == RJ_OK) {
        nc_reaction_t r;
        if (nc_parse_reaction(s.p, s.len, &r) == NC_P_OK) {
            nc_sb_puts(o, "{\"target\":");
            w_str(o, r.target, r.target_n);
            nc_sb_puts(o, ",\"emoji\":");
            w_str(o, r.emoji, r.emoji_n);
            nc_sb_puts(o, ",\"op\":");
            w_str(o, r.op, r.op_n);
            nc_sb_putc(o, '}');
        } else {
            nc_sb_puts(o, "null");
        }
    }
    nc_sb_free(&s);
    return rc;
}

static int r_reaction_summary(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t own;
    if (scalar_arg(a, "ownFp", &own)) return RJ_BAD;
    nc_msg_t *recs;
    size_t n;
    int rc = records_of(a, &recs, &n);
    if (rc != RJ_OK) return rc;
    nc_react_summary_t s;
    int p = nc_reaction_summary(recs, n, &own, &s);
    free(recs);
    if (p != NC_P_OK) return w_rc(o, p, NULL);
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < s.n; i++) {
        if (i) nc_sb_putc(o, ',');
        nc_sb_putc(o, '[');
        w_str(o, s.t[i].target, 64);
        nc_sb_puts(o, ",[");
        for (size_t k = 0; k < s.t[i].n_items; k++) {
            const nc_react_item_t *it = &s.t[i].items[k];
            if (k) nc_sb_putc(o, ',');
            nc_sb_puts(o, "{\"emoji\":");
            w_str(o, it->emoji, it->emoji_n);
            nc_sb_puts(o, ",\"count\":");
            w_size(o, it->count);
            nc_sb_puts(o, it->mine ? ",\"mine\":true}" : ",\"mine\":false}");
        }
        nc_sb_puts(o, "]]");
    }
    nc_sb_putc(o, ']');
    nc_react_summary_free(&s);
    return RJ_OK;
}

static int r_own_reaction_on(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t t, e;
    if (scalar_arg(a, "target", &t) || scalar_arg(a, "emoji", &e)) return RJ_BAD;
    int present;
    const nc_jv_t *sm = arg(a, "summary", &present);
    if (!present || sm->kind != NC_JV_ARR) return RJ_BAD;
    size_t np = sm->len, total = 0;
    for (size_t i = 0; i < np; i++) {
        const nc_jv_t *pr = sm->v[i];
        if (pr->kind != NC_JV_ARR || pr->len != 2) return RJ_BAD;
        if (pr->v[0]->kind != NC_JV_STR || pr->v[1]->kind != NC_JV_ARR) return RJ_BAD;
        total += pr->v[1]->len;
    }
    nc_react_in_pair_t *pairs = calloc(np ? np : 1, sizeof(*pairs));
    nc_react_in_item_t *items = calloc(total ? total : 1, sizeof(*items));
    if (!pairs || !items) { free(pairs); free(items); return RJ_NOMEM; }
    size_t at = 0;
    int rc = RJ_OK;
    for (size_t i = 0; i < np && rc == RJ_OK; i++) {
        const nc_jv_t *k = sm->v[i]->v[0], *l = sm->v[i]->v[1];
        pairs[i].key = k->s;
        pairs[i].key_n = k->n;
        pairs[i].items = items + at;
        pairs[i].n_items = l->len;
        for (size_t q = 0; q < pairs[i].n_items; q++) {
            const nc_jv_t *it = l->v[q];
            nc_react_in_item_t *x = &items[at + q];
            if (elem_of(it, 1, &x->elem) != RJ_OK) { rc = RJ_BAD; break; }
            x->emoji = fld(it, "emoji");
            x->mine = fld(it, "mine");
        }
        at += pairs[i].n_items;
    }
    if (rc == RJ_OK) {
        int on = 0;
        int p = nc_own_reaction_on(pairs, np, &t, &e, &on);
        if (p == NC_P_OK) nc_sb_puts(o, on ? "true" : "false");
        else rc = w_rc(o, p, NULL);
    }
    free(pairs);
    free(items);
    return rc;
}

static int r_build_delete(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *h = arg(a, "hashes", &present);
    int is_array = present && h->kind == NC_JV_ARR;
    size_t n = is_array ? h->len : 0;
    nc_val_t *v = calloc(n ? n : 1, sizeof(*v));
    if (!v) return RJ_NOMEM;
    for (size_t i = 0; i < n; i++)
        if (nc_val_from_jv(h->v[i], &v[i]) != 0) { free(v); return RJ_BAD; }
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = nc_build_delete(is_array, v, n, &s);
    free(v);
    if (rc == NC_P_OK) w_str(o, s.p, s.len);
    nc_sb_free(&s);
    return rc == NC_P_OK ? RJ_OK : w_rc(o, rc, NC_P_MSG_DELETE);
}

static int r_parse_delete(const nc_jv_t *a, nc_sb_t *o) {
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = text_arg(a, "text", &s);
    nc_delete_t *d = rc == RJ_OK ? malloc(sizeof(*d)) : NULL;
    if (rc == RJ_OK && !d) rc = RJ_NOMEM;
    if (rc == RJ_OK) {
        int p = nc_parse_delete(s.p, s.len, d);
        if (p == NC_P_OK) {
            nc_sb_puts(o, "{\"action\":");
            nc_js_write_number(o, d->action);
            nc_sb_puts(o, ",\"hashes\":[");
            for (size_t i = 0; i < d->n; i++) {
                if (i) nc_sb_putc(o, ',');
                w_str(o, d->hashes[i], 64);
            }
            nc_sb_puts(o, "]}");
        } else {
            rc = w_rc(o, p, NULL);
        }
    }
    free(d);
    nc_sb_free(&s);
    return rc;
}

static void w_hashset(nc_sb_t *o, const nc_hashset_t *h) {
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < h->n; i++) {
        if (i) nc_sb_putc(o, ',');
        w_str(o, h->h[i], 64);
    }
    nc_sb_putc(o, ']');
}

static int r_deletions(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t own;
    if (scalar_arg(a, "ownFp", &own)) return RJ_BAD;
    nc_msg_t *recs;
    size_t n;
    int rc = records_of(a, &recs, &n);
    if (rc != RJ_OK) return rc;
    int present;
    const nc_jv_t *ha = arg(a, "hashes", &present);
    if (!present || ha->kind != NC_JV_ARR || ha->len != n) {
        free(recs);
        return RJ_BAD;
    }
    nc_val_t *hv = calloc(n ? n : 1, sizeof(*hv));
    if (!hv) { free(recs); return RJ_NOMEM; }
    for (size_t i = 0; i < n; i++) {
        const nc_jv_t *h = ha->v[i];
        if (h->kind != NC_JV_NULL && h->kind != NC_JV_STR) { free(recs); free(hv); return RJ_BAD; }
        (void)nc_val_from_jv(h, &hv[i]);
    }
    nc_hashset_t del, hid;
    int p = nc_deletions(recs, n, &own, hv, &del, &hid);
    free(recs);
    free(hv);
    if (p != NC_P_OK) return w_rc(o, p, NULL);
    nc_sb_puts(o, "{\"deleted\":");
    w_hashset(o, &del);
    nc_sb_puts(o, ",\"hidden\":");
    w_hashset(o, &hid);
    nc_sb_putc(o, '}');
    nc_hashset_free(&del);
    nc_hashset_free(&hid);
    return RJ_OK;
}

static int r_nodus_units(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t v;
    if (scalar_arg(a, "amount", &v)) return RJ_BAD;
    unsigned __int128 u;
    if (nc_nodus_units(&v, &u) != NC_P_OK) { nc_sb_puts(o, "null"); return RJ_OK; }
    nc_sb_putc(o, '"');                       /* a BigInt: its decimal string */
    nc_u128_to_string(u, o);
    nc_sb_putc(o, '"');
    return RJ_OK;
}

static int r_build_transfer(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *d = arg(a, "detail", &present);
    nc_transfer_in_t in;
    memset(&in, 0, sizeof(in));
    if (elem_of(d, present, &in.elem) != RJ_OK) return RJ_BAD;
    if (in.elem == NC_ELEM_OBJECT) {
        in.amount = fld(d, "amount");
        in.wire = fld(d, "wire");
        in.to = fld(d, "to");
        in.name = fld(d, "name");
    }
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = nc_build_transfer(&in, &s);
    if (rc == NC_P_OK) w_str(o, s.p, s.len);
    nc_sb_free(&s);
    return rc == NC_P_OK ? RJ_OK : w_rc(o, rc, NC_P_MSG_CARD);
}

static int r_parse_transfer(const nc_jv_t *a, nc_sb_t *o) {
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = text_arg(a, "text", &s);
    if (rc == RJ_OK) {
        nc_transfer_t t;
        nc_transfer_init(&t);
        int p = nc_parse_transfer(s.p, s.len, &t);
        if (p == NC_P_OK) {
            nc_sb_puts(o, "{\"chain\":");  w_str(o, t.chain.p, t.chain.len);
            nc_sb_puts(o, ",\"amount\":"); w_str(o, t.amount.p, t.amount.len);
            nc_sb_puts(o, ",\"token\":");  w_str(o, t.token.p, t.token.len);
            nc_sb_puts(o, ",\"wire\":");   w_str(o, t.wire.p, t.wire.len);
            nc_sb_puts(o, ",\"to\":");     w_str(o, t.to.p, t.to.len);
            nc_sb_puts(o, ",\"name\":");   w_str(o, t.name.p, t.name.len);
            nc_sb_putc(o, '}');
        } else {
            rc = w_rc(o, p, NULL);
        }
        nc_transfer_free(&t);
    }
    nc_sb_free(&s);
    return rc;
}

static int card_of(const nc_jv_t *c, int present, nc_card_t *card) {
    memset(card, 0, sizeof(*card));
    if (elem_of(c, present, &card->elem) != RJ_OK) return RJ_BAD;
    if (card->elem == NC_ELEM_OBJECT) {
        card->chain = fld(c, "chain");
        card->amount = fld(c, "amount");
        card->token = fld(c, "token");
        card->wire = fld(c, "wire");
        card->to = fld(c, "to");
    }
    return RJ_OK;
}

static int r_valid_nodus_card(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *c = arg(a, "card", &present);
    nc_card_t card;
    if (card_of(c, present, &card) != RJ_OK) return RJ_BAD;
    nc_sb_puts(o, nc_valid_nodus_card(&card) ? "true" : "false");
    return RJ_OK;
}

static int r_transfer_verdict(const nc_jv_t *a, nc_sb_t *o) {
    int pc, pe, po;
    const nc_jv_t *c = arg(a, "card", &pc);
    const nc_jv_t *el = arg(a, "entries", &pe);
    const nc_jv_t *op = arg(a, "opts", &po);
    nc_card_t card;
    nc_verdict_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    if (card_of(c, pc, &card) != RJ_OK) return RJ_BAD;
    if (elem_of(op, po, &opts.elem) != RJ_OK) return RJ_BAD;
    if (opts.elem == NC_ELEM_OBJECT) {
        opts.incoming = fld(op, "incoming");
        opts.counterparty = fld(op, "counterparty");
        opts.own_fp = fld(op, "ownFp");
    }
    nc_list_t kind = list_of(el, pe);
    size_t n = kind == NC_LIST_ARRAY ? el->len : 0;
    nc_entry_t *e = calloc(n ? n : 1, sizeof(*e));
    if (!e) return RJ_NOMEM;
    for (size_t i = 0; i < n; i++) {
        const nc_jv_t *x = el->v[i];
        if (elem_of(x, 1, &e[i].elem) != RJ_OK) { free(e); return RJ_BAD; }
        e[i].wire = fld(x, "wire");
        e[i].kind = fld(x, "kind");
        e[i].peer = fld(x, "peer");
        e[i].token = fld(x, "token");
        e[i].amount = fld(x, "amount");
        e[i].h = fld(x, "h");
    }
    nc_verdict_t v;
    nc_verdict_init(&v);
    int p = nc_transfer_verdict(&card, kind, e, n, &opts, &v);
    free(e);
    int rc = RJ_OK;
    if (p != NC_P_OK) {
        rc = w_rc(o, p, NULL);
    } else {
        switch (v.state) {
        case NC_VERDICT_CONFIRMED:
            nc_sb_puts(o, "{\"state\":\"confirmed\",\"height\":");
            w_str(o, v.height.p, v.height.len);
            nc_sb_putc(o, '}');
            break;
        case NC_VERDICT_MISMATCH: nc_sb_puts(o, "{\"state\":\"mismatch\"}"); break;
        case NC_VERDICT_PENDING:  nc_sb_puts(o, "{\"state\":\"pending\"}"); break;
        default:
            nc_sb_puts(o, "{\"state\":\"unverifiable\",\"chain\":");
            w_val(o, &v.chain);
            nc_sb_putc(o, '}');
            break;
        }
    }
    nc_verdict_free(&v);
    return rc;
}

/* /^(0|-?[1-9][0-9]*)$/ — a BigInt's own decimal string. */
static int canonical_bigint(const nc_val_t *v) {
    if (v->kind != NC_V_STR || v->n == 0) return 0;
    size_t i = v->s[0] == '-' ? 1 : 0;
    if (i == v->n) return 0;
    if (v->s[i] == '0') return i == 0 && v->n == 1;
    for (; i < v->n; i++) if (v->s[i] < '0' || v->s[i] > '9') return 0;
    return 1;
}

static int r_copy_cards(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *cl = arg(a, "cards", &present);
    nc_list_t kind = list_of(cl, present);
    size_t n = kind == NC_LIST_ARRAY ? cl->len : 0;
    nc_copy_card_t *c = calloc(n ? n : 1, sizeof(*c));
    nc_big_t *ord = calloc(n ? n : 1, sizeof(*ord));
    int rc = RJ_OK;
    if (!c || !ord) { free(c); free(ord); return RJ_NOMEM; }
    for (size_t i = 0; i < n; i++) nc_big_init(&ord[i]);
    for (size_t i = 0; i < n && rc == RJ_OK; i++) {
        const nc_jv_t *x = cl->v[i];
        if (elem_of(x, 1, &c[i].elem) != RJ_OK) { rc = RJ_BAD; break; }
        if (c[i].elem != NC_ELEM_OBJECT) continue;
        c[i].key = fld(x, "key");
        c[i].dir = fld(x, "dir");
        c[i].wire = fld(x, "wire");
        c[i].state = fld(x, "state");
        if (!nc_val_is(&c[i].state, "confirmed")) continue;
        nc_val_t ov = fld(x, "order");
        if (!canonical_bigint(&ov)) { rc = RJ_BAD; break; }
        nc_big_rc_t b = nc_big_from_val(&ord[i], &ov);
        if (b == NC_BIG_NOMEM) rc = RJ_NOMEM;
        else if (b != NC_BIG_OK) rc = RJ_BAD;
        c[i].order = &ord[i];
    }
    if (rc == RJ_OK) {
        size_t *copies = NULL, nc = 0;
        int p = nc_copy_cards(kind, c, n, &copies, &nc);
        if (p != NC_P_OK) {
            rc = w_rc(o, p, NULL);
        } else {
            nc_sb_putc(o, '[');
            for (size_t i = 0; i < nc; i++) {
                if (i) nc_sb_putc(o, ',');
                w_val(o, &c[copies[i]].key);
            }
            nc_sb_putc(o, ']');
        }
        free(copies);
    }
    for (size_t i = 0; i < n; i++) nc_big_free(&ord[i]);
    free(ord);
    free(c);
    return rc;
}

static int r_build_reply(const nc_jv_t *a, nc_sb_t *o) {
    nc_sb_t s, q, t, out;
    nc_sb_init(&s); nc_sb_init(&q); nc_sb_init(&t); nc_sb_init(&out);
    int rc = text_arg(a, "senderLabel", &s);
    if (rc == RJ_OK) rc = text_arg(a, "quoted", &q);
    if (rc == RJ_OK) rc = text_arg(a, "text", &t);
    if (rc == RJ_OK) {
        int p = nc_build_reply(s.p, s.len, q.p, q.len, t.p, t.len, &out);
        if (p == NC_P_OK) w_str(o, out.p, out.len);
        else rc = RJ_NOMEM;
    }
    nc_sb_free(&s); nc_sb_free(&q); nc_sb_free(&t); nc_sb_free(&out);
    return rc;
}

static int r_parse_reply(const nc_jv_t *a, nc_sb_t *o) {
    nc_sb_t s;
    nc_sb_init(&s);
    int rc = text_arg(a, "text", &s);
    if (rc == RJ_OK) {
        nc_reply_t r;
        if (nc_parse_reply(s.p, s.len, &r) == NC_P_OK) {
            nc_sb_puts(o, "{\"sender\":");
            w_str(o, r.sender, r.sender_n);
            nc_sb_puts(o, ",\"quoted\":");
            w_str(o, r.quoted, r.quoted_n);
            nc_sb_puts(o, ",\"text\":");
            w_str(o, r.text, r.text_n);
            nc_sb_putc(o, '}');
        } else {
            nc_sb_puts(o, "null");
        }
    }
    nc_sb_free(&s);
    return rc;
}

/* ══ P1a: text.js / core.js rules (nc_rules.h) ════════════════════════ */

/* ── JS values echoed: a JSON.parse'd tree, changed and written back ── */

/* A node of the argument tree. The dispatcher owns the tree (it frees it
 * after the rule), so the mutators below change it in place and write it:
 * that is the JS function's own object after the call. */
static nc_jv_t *jv_node(nc_jvkind_t kind) {
    nc_jv_t *o = calloc(1, sizeof(*o));
    if (o) o->kind = kind;
    return o;
}
static nc_jv_t *jv_str_node(const char *s, size_t n) {
    nc_jv_t *o = jv_node(NC_JV_STR);
    if (!o) return NULL;
    o->s = malloc(n + 1);
    if (!o->s) { free(o); return NULL; }
    if (n) memcpy(o->s, s, n);
    o->s[n] = '\0';
    o->n = n;
    return o;
}
/* A scalar as a node; undefined as null (an array element, as
 * JSON.stringify writes it). */
static nc_jv_t *jv_val_node(const nc_val_t *v) {
    nc_jv_t *o;
    switch (v->kind) {
    case NC_V_STR:   return jv_str_node(v->s, v->n);
    case NC_V_NUM:   o = jv_node(NC_JV_NUM); if (o) o->num = v->num; return o;
    case NC_V_TRUE:  return jv_node(NC_JV_TRUE);
    case NC_V_FALSE: return jv_node(NC_JV_FALSE);
    default:         return jv_node(NC_JV_NULL);
    }
}
static int jv_grow(nc_jv_t *c) {
    if (c->len < c->cap) return 0;
    size_t cap = c->cap ? c->cap * 2 : 4;
    if (cap > ((size_t)-1) / sizeof(void *)) return -1;
    nc_jv_t **v = realloc(c->v, cap * sizeof(*v));
    if (!v) return -1;
    c->v = v;
    if (c->kind == NC_JV_OBJ) {
        char **k = realloc(c->k, cap * sizeof(*k));
        if (!k) return -1;
        c->k = k;
        size_t *kn = realloc(c->kn, cap * sizeof(*kn));
        if (!kn) return -1;
        c->kn = kn;
    }
    c->cap = cap;
    return 0;
}
/* array.push(node); takes node. */
static int jv_arr_push(nc_jv_t *a, nc_jv_t *node) {
    if (!node) return -1;
    if (jv_grow(a) != 0) { nc_jv_free(node); return -1; }
    a->v[a->len++] = node;
    return 0;
}
/* array.splice(i, 1) */
static void jv_arr_del(nc_jv_t *a, size_t i) {
    nc_jv_free(a->v[i]);
    memmove(&a->v[i], &a->v[i + 1], (a->len - i - 1) * sizeof(a->v[0]));
    a->len--;
}
static int jv_key_eq(const nc_jv_t *o, size_t i, const char *k, size_t kn) {
    return o->kn[i] == kn && (kn == 0 || memcmp(o->k[i], k, kn) == 0);
}
/* obj[key] = node: the value of the live pair (the LAST one with the key,
 * nc_jsjson.c jv_close_object) replaced — the key keeps its place — or a
 * new pair at the end. Takes node. */
static int jv_obj_set(nc_jv_t *o, const char *k, size_t kn, nc_jv_t *node) {
    if (!node) return -1;
    for (size_t i = o->len; i-- > 0;)
        if (jv_key_eq(o, i, k, kn)) { nc_jv_free(o->v[i]); o->v[i] = node; return 0; }
    if (jv_grow(o) != 0) { nc_jv_free(node); return -1; }
    char *key = malloc(kn + 1);
    if (!key) { nc_jv_free(node); return -1; }
    if (kn) memcpy(key, k, kn);
    key[kn] = '\0';
    if (o->dead) {
        unsigned char *d = realloc(o->dead, o->len + 1);
        if (!d) { free(key); nc_jv_free(node); return -1; }
        o->dead = d;
        d[o->len] = 0;
    }
    o->k[o->len] = key;
    o->kn[o->len] = kn;
    o->v[o->len] = node;
    o->len++;
    return 0;
}
/* delete obj[key]: every pair of that key goes. */
static void jv_obj_del(nc_jv_t *o, const char *k, size_t kn) {
    size_t w = 0;
    for (size_t i = 0; i < o->len; i++) {
        if (jv_key_eq(o, i, k, kn)) { nc_jv_free(o->v[i]); free(o->k[i]); continue; }
        o->v[w] = o->v[i];
        o->k[w] = o->k[i];
        o->kn[w] = o->kn[i];
        if (o->dead) o->dead[w] = o->dead[i];
        w++;
    }
    o->len = w;
}
/* A live value of the tree (nc_jv_get) as a changeable node. */
static nc_jv_t *jv_get_mut(nc_jv_t *o, const char *key) { return (nc_jv_t *)nc_jv_get(o, key); }

/* JSON.stringify of a JSON.parse'd object: its own keys in
 * OrdinaryOwnPropertyKeys order — the array-index keys (canonical decimal,
 * at most 2^32 - 2) ascending, then the others in creation order; a key
 * JSON.parse saw twice sits at its FIRST place with its LAST value. */
static int index_key(const char *k, size_t n, uint32_t *v) {
    if (n == 0 || n > 10 || (n > 1 && k[0] == '0')) return 0;
    uint64_t x = 0;
    for (size_t i = 0; i < n; i++) {
        if (k[i] < '0' || k[i] > '9') return 0;
        x = x * 10 + (uint64_t)(k[i] - '0');
    }
    if (x > 4294967294u) return 0;
    *v = (uint32_t)x;
    return 1;
}
static int pair_key_cmp(const void *ctx, size_t a, size_t b) {
    const nc_jv_t *o = ctx;
    size_t na = o->kn[a], nb = o->kn[b];
    int c = (na < nb ? na : nb) ? memcmp(o->k[a], o->k[b], na < nb ? na : nb) : 0;
    if (c) return c < 0 ? -1 : 1;
    return na < nb ? -1 : na > nb ? 1 : 0;
}
typedef struct { size_t first, live; int is_index; uint32_t index; } okey_t;
static int okey_cmp(const void *ctx, size_t a, size_t b) {
    const okey_t *e = ctx;
    if (e[a].is_index != e[b].is_index) return e[a].is_index ? -1 : 1;
    if (e[a].is_index) return e[a].index < e[b].index ? -1 : e[a].index > e[b].index ? 1 : 0;
    return e[a].first < e[b].first ? -1 : e[a].first > e[b].first ? 1 : 0;
}
static void w_jv(nc_sb_t *b, const nc_jv_t *v);
static void w_jv_object(nc_sb_t *b, const nc_jv_t *o) {
    size_t n = o->len, ne = 0;
    size_t *idx = malloc((n ? n : 1) * sizeof(size_t));
    size_t *ord = malloc((n ? n : 1) * sizeof(size_t));
    okey_t *e = malloc((n ? n : 1) * sizeof(okey_t));
    if (!idx || !ord || !e) { b->oom = 1; goto out; }
    for (size_t i = 0; i < n; i++) idx[i] = i;
    if (nc_stable_sort(idx, n, pair_key_cmp, o) != 0) { b->oom = 1; goto out; }
    for (size_t i = 0; i < n;) {
        size_t j = i, live = (size_t)-1;
        for (; j < n && pair_key_cmp(o, idx[i], idx[j]) == 0; j++)
            if (!(o->dead && o->dead[idx[j]])) live = idx[j];
        if (live != (size_t)-1) {
            e[ne].first = idx[i];                                  /* stable: the smallest place */
            e[ne].live = live;
            e[ne].is_index = index_key(o->k[live], o->kn[live], &e[ne].index);
            ne++;
        }
        i = j;
    }
    for (size_t i = 0; i < ne; i++) ord[i] = i;
    if (nc_stable_sort(ord, ne, okey_cmp, e) != 0) { b->oom = 1; goto out; }
    nc_sb_putc(b, '{');
    for (size_t i = 0; i < ne; i++) {
        size_t p = e[ord[i]].live;
        if (i) nc_sb_putc(b, ',');
        w_str(b, o->k[p], o->kn[p]);
        nc_sb_putc(b, ':');
        w_jv(b, o->v[p]);
    }
    nc_sb_putc(b, '}');
out:
    free(idx);
    free(ord);
    free(e);
}
static void w_jv(nc_sb_t *b, const nc_jv_t *v) {
    switch (v->kind) {
    case NC_JV_NULL:  nc_sb_puts(b, "null"); break;
    case NC_JV_FALSE: nc_sb_puts(b, "false"); break;
    case NC_JV_TRUE:  nc_sb_puts(b, "true"); break;
    case NC_JV_NUM:   nc_js_write_number(b, v->num); break;
    case NC_JV_STR:   w_str(b, v->s, v->n); break;
    case NC_JV_ARR:
        nc_sb_putc(b, '[');
        for (size_t i = 0; i < v->len; i++) {
            if (i) nc_sb_putc(b, ',');
            w_jv(b, v->v[i]);
        }
        nc_sb_putc(b, ']');
        break;
    case NC_JV_OBJ:   w_jv_object(b, v); break;
    }
}

/* ── P1a argument readers (the contract: nc_rules_json.h) ───────────── */

static int rmsg_of(const nc_jv_t *o, int present, nc_rmsg_t *m) {
    memset(m, 0, sizeof(*m));
    if (elem_of(o, present, &m->elem) != RJ_OK) return RJ_BAD;
    if (m->elem != NC_ELEM_OBJECT) return RJ_OK;
    m->dir = fld(o, "dir");
    m->fp = fld(o, "fp");
    m->ts = fld(o, "ts");
    m->sender_ts = fld(o, "senderTs");
    m->seq = fld(o, "seq");
    m->kind = fld(o, "kind");
    m->text = fld(o, "text");
    m->published = fld(o, "published");
    m->delivered = fld(o, "delivered");
    m->delivered_at = fld(o, "deliveredAt");
    return RJ_OK;
}

static int contact_of(const nc_jv_t *o, nc_rcontact_t *c) {
    memset(c, 0, sizeof(*c));
    if (elem_of(o, 1, &c->elem) != RJ_OK) return RJ_BAD;
    if (c->elem == NC_ELEM_OBJECT) {
        c->fp = fld(o, "fp");
        c->salt = fld(o, "salt");
        c->listed = fld(o, "listed");
    }
    return RJ_OK;
}

/* How a non-array list argument behaves:
 *   LM_METHOD     x.filter / .some / .map / .find: TypeError;
 *   LM_FOR_OF     for (… of x): a string iterates one-character strings
 *                 (no field any rule reads: as no element); anything else
 *                 TypeError;
 *   LM_OR_FOR_OF  for (… of x || []): falsy -> none; a string as above;
 *                 any other truthy value TypeError. */
typedef enum { LM_METHOD, LM_FOR_OF, LM_OR_FOR_OF } lmode_t;
static nc_list_t nonarray_kind(const nc_jv_t *o, int present, lmode_t mode) {
    if (mode == LM_METHOD) return NC_LIST_BAD;
    if (!present || o->kind == NC_JV_NULL) return mode == LM_OR_FOR_OF ? NC_LIST_EMPTY : NC_LIST_BAD;
    if (o->kind == NC_JV_STR) return NC_LIST_EMPTY;
    if (mode == LM_OR_FOR_OF && !is_compound(o)) {
        nc_val_t v;
        (void)nc_val_from_jv(o, &v);
        if (!nc_val_truthy(&v)) return NC_LIST_EMPTY;
    }
    return NC_LIST_BAD;
}

/* A list of message records (or contacts read as records: fp, seq). */
static int rmsgs_arg(const nc_jv_t *args, const char *key, lmode_t mode, nc_list_t *kind,
                     nc_rmsg_t **out, size_t *n) {
    int present;
    const nc_jv_t *a = arg(args, key, &present);
    *out = NULL;
    *n = 0;
    if (!present || a->kind != NC_JV_ARR) { *kind = nonarray_kind(a, present, mode); return RJ_OK; }
    nc_rmsg_t *m = calloc(a->len ? a->len : 1, sizeof(*m));
    if (!m) return RJ_NOMEM;
    for (size_t i = 0; i < a->len; i++)
        if (rmsg_of(a->v[i], 1, &m[i]) != RJ_OK) { free(m); return RJ_BAD; }
    *kind = NC_LIST_ARRAY;
    *out = m;
    *n = a->len;
    return RJ_OK;
}

/* An array whose elements must be scalars (a Set's elements, contactFps):
 * *is_array = 0 for anything else (passed on as it is). */
static int scalars_arg(const nc_jv_t *args, const char *key, int *is_array, nc_val_t **out, size_t *n) {
    int present;
    const nc_jv_t *a = arg(args, key, &present);
    *is_array = 0;
    *out = NULL;
    *n = 0;
    if (!present || a->kind != NC_JV_ARR) return RJ_OK;
    nc_val_t *v = calloc(a->len ? a->len : 1, sizeof(*v));
    if (!v) return RJ_NOMEM;
    for (size_t i = 0; i < a->len; i++)
        if (nc_val_from_jv(a->v[i], &v[i]) != 0) { free(v); return RJ_BAD; }
    *is_array = 1;
    *out = v;
    *n = a->len;
    return RJ_OK;
}

/* The declined list: Array.isArray(list) ? list : []. */
static int decls_arg(const nc_jv_t *args, nc_decl_t **out, size_t *n, const nc_jv_t **list) {
    int present;
    const nc_jv_t *a = arg(args, "list", &present);
    *out = NULL;
    *n = 0;
    *list = NULL;
    if (!present || a->kind != NC_JV_ARR) return RJ_OK;
    nc_decl_t *d = calloc(a->len ? a->len : 1, sizeof(*d));
    if (!d) return RJ_NOMEM;
    for (size_t i = 0; i < a->len; i++) {
        const nc_jv_t *x = a->v[i];
        if (elem_of(x, 1, &d[i].elem) != RJ_OK) { free(d); return RJ_BAD; }
        if (x->kind == NC_JV_STR) { d[i].is_str = 1; (void)nc_val_from_jv(x, &d[i].str); }
        if (d[i].elem == NC_ELEM_OBJECT) { d[i].fp = fld(x, "fp"); d[i].at = fld(x, "at"); }
    }
    *out = d;
    *n = a->len;
    *list = a;
    return RJ_OK;
}

/* A map's own keys and values (storage freed by mapbuf_free). */
typedef struct { const char **k; size_t *kn; nc_val_t *v; unsigned char *c; } mapbuf_t;
static void mapbuf_free(mapbuf_t *b) { free(b->k); free(b->kn); free(b->v); free(b->c); memset(b, 0, sizeof(*b)); }
/* `o`: absent (NULL) or null -> undefined; a non-array object -> its own
 * pairs (flat = 1: every value a scalar); anything else outside the
 * contract. */
static int map_of(const nc_jv_t *o, int flat, nc_rmap_t *m, mapbuf_t *b) {
    memset(m, 0, sizeof(*m));
    memset(b, 0, sizeof(*b));
    if (!o || o->kind == NC_JV_NULL) return RJ_OK;
    if (o->kind != NC_JV_OBJ) return RJ_BAD;
    size_t n = o->len;
    b->k = malloc((n ? n : 1) * sizeof(*b->k));
    b->kn = malloc((n ? n : 1) * sizeof(*b->kn));
    b->v = calloc(n ? n : 1, sizeof(*b->v));
    b->c = calloc(n ? n : 1, 1);
    if (!b->k || !b->kn || !b->v || !b->c) { mapbuf_free(b); return RJ_NOMEM; }
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (o->dead && o->dead[i]) continue;                         /* a repeated key: the last */
        b->k[w] = o->k[i];
        b->kn[w] = o->kn[i];
        if (nc_val_from_jv(o->v[i], &b->v[w]) != 0) {
            if (flat) { mapbuf_free(b); return RJ_BAD; }
            b->c[w] = 1;
        }
        w++;
    }
    m->object = 1;
    m->n = w;
    m->key = b->k;
    m->key_n = b->kn;
    m->val = b->v;
    m->compound = b->c;
    return RJ_OK;
}
static int flat_map_arg(const nc_jv_t *args, const char *key, nc_rmap_t *m, mapbuf_t *b) {
    return map_of(nc_jv_get(args, key), 1, m, b);
}

/* The Messages state (mergeListedContacts, removeContact, unremoveContact,
 * ownRecordSeen, firstRecordAllowed, markOwnRecordSeen). */
#define STATE_MAPS 5
static const char *const STATE_MAP_NAMES[STATE_MAPS] = { "dmSync", "profileCache", "chainNames", "chainNoName", "seenOwn" };
typedef struct {
    nc_rstate_t    st;
    nc_rcontact_t *contacts;
    nc_val_t      *removed;
    mapbuf_t       mb[STATE_MAPS];
    nc_jv_t       *node;          /* the state value (NULL when absent) */
} statebuf_t;
static void statebuf_free(statebuf_t *s) {
    free(s->contacts);
    free(s->removed);
    for (int i = 0; i < STATE_MAPS; i++) mapbuf_free(&s->mb[i]);
}
static int state_arg(const nc_jv_t *args, statebuf_t *s) {
    memset(s, 0, sizeof(*s));
    s->st.contacts_kind = NC_LIST_BAD;
    int present;
    const nc_jv_t *o = arg(args, "state", &present);
    if (!present) { s->st.elem = NC_ELEM_NULL; s->st.falsy = 1; return RJ_OK; }
    if (o->kind == NC_JV_ARR) return RJ_BAD;
    s->node = (nc_jv_t *)o;                                           /* the dispatcher's own tree */
    if (o->kind != NC_JV_OBJ) {
        nc_val_t v;
        (void)nc_val_from_jv(o, &v);
        s->st.elem = o->kind == NC_JV_NULL ? NC_ELEM_NULL : NC_ELEM_OTHER;
        s->st.falsy = !nc_val_truthy(&v);
        return RJ_OK;
    }
    s->st.elem = NC_ELEM_OBJECT;
    const nc_jv_t *c = nc_jv_get(o, "contacts");
    if (c && c->kind == NC_JV_ARR) {
        s->contacts = calloc(c->len ? c->len : 1, sizeof(*s->contacts));
        if (!s->contacts) return RJ_NOMEM;
        for (size_t i = 0; i < c->len; i++)
            if (contact_of(c->v[i], &s->contacts[i]) != RJ_OK) return RJ_BAD;
        s->st.contacts_kind = NC_LIST_ARRAY;
        s->st.contacts = s->contacts;
        s->st.n_contacts = c->len;
    }
    const nc_jv_t *r = nc_jv_get(o, "removed");
    if (r && r->kind != NC_JV_NULL) {
        if (r->kind != NC_JV_ARR) return RJ_BAD;
        s->removed = calloc(r->len ? r->len : 1, sizeof(*s->removed));
        if (!s->removed) return RJ_NOMEM;
        for (size_t i = 0; i < r->len; i++)
            if (nc_val_from_jv(r->v[i], &s->removed[i]) != 0) return RJ_BAD;
        s->st.removed_array = 1;
        s->st.removed = s->removed;
        s->st.n_removed = r->len;
    }
    nc_rmap_t *maps[STATE_MAPS] = { &s->st.dm_sync, &s->st.profile_cache, &s->st.chain_names,
                                    &s->st.chain_no_name, &s->st.seen_own };
    for (int i = 0; i < STATE_MAPS; i++) {
        int rc = map_of(nc_jv_get(o, STATE_MAP_NAMES[i]), 0, maps[i], &s->mb[i]);
        if (rc != RJ_OK) return rc;
    }
    return RJ_OK;
}

/* A mutator's result: { result, state } as JSON.stringify writes it (an
 * undefined result or state is left out). */
static void w_mutated(nc_sb_t *o, int has_result, int result, const nc_jv_t *state) {
    nc_sb_putc(o, '{');
    if (has_result) nc_sb_puts(o, result ? "\"result\":true" : "\"result\":false");
    if (state) {
        if (has_result) nc_sb_putc(o, ',');
        nc_sb_puts(o, "\"state\":");
        w_jv(o, state);
    }
    nc_sb_putc(o, '}');
}

static void w_bool(nc_sb_t *o, int b) { nc_sb_puts(o, b ? "true" : "false"); }
static void w_days(nc_sb_t *o, const nc_u128_t *d, size_t n) {
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < n; i++) {
        if (i) nc_sb_putc(o, ',');
        nc_sb_putc(o, '"');
        nc_u128_to_string(d[i], o);
        nc_sb_putc(o, '"');
    }
    nc_sb_putc(o, ']');
}
static int w_p(nc_sb_t *o, int rc, const char *msg) { return w_rc(o, rc, msg); }

/* ── P1a rules ──────────────────────────────────────────────────────── */

static void w_decls(nc_sb_t *o, const nc_decl_out_t *d, size_t n) {
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < n; i++) {
        if (i) nc_sb_putc(o, ',');
        nc_sb_puts(o, "{\"fp\":");
        w_str(o, d[i].fp, 128);
        nc_sb_puts(o, ",\"at\":");
        w_str(o, d[i].at, d[i].at_n);
        nc_sb_putc(o, '}');
    }
    nc_sb_putc(o, ']');
}

static int r_declined_now(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t now;
    if (scalar_arg(a, "nowSeconds", &now)) return RJ_BAD;
    nc_decl_t *d;
    size_t n;
    const nc_jv_t *list;
    int rc = decls_arg(a, &d, &n, &list);
    if (rc != RJ_OK) return rc;
    nc_decl_out_t *out;
    size_t no;
    const char *msg = NULL;
    int p = nc_declined_now(d, n, &now, &out, &no, &msg);
    free(d);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_decls(o, out, no);
    free(out);
    return RJ_OK;
}

static int r_is_declined(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    nc_decl_t *d;
    size_t n;
    const nc_jv_t *list;
    int rc = decls_arg(a, &d, &n, &list);
    if (rc != RJ_OK) return rc;
    w_bool(o, nc_is_declined(d, n, &fp));
    free(d);
    return RJ_OK;
}

static int r_add_declined(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, now;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "nowSeconds", &now)) return RJ_BAD;
    nc_decl_t *d;
    size_t n;
    const nc_jv_t *list;
    int rc = decls_arg(a, &d, &n, &list);
    if (rc != RJ_OK) return rc;
    nc_decl_out_t *out;
    size_t no;
    const char *msg = NULL;
    int p = nc_add_declined(d, n, &fp, &now, &out, &no, &msg);
    free(d);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_decls(o, out, no);
    free(out);
    return RJ_OK;
}

static int r_undecline(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    nc_decl_t *d;
    size_t n;
    const nc_jv_t *list;
    int rc = decls_arg(a, &d, &n, &list);
    if (rc != RJ_OK) return rc;
    size_t *keep, nk;
    int p = nc_undecline(d, n, &fp, &keep, &nk);
    free(d);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < nk; i++) {
        if (i) nc_sb_putc(o, ',');
        w_jv(o, list->v[keep[i]]);                                    /* the elements themselves */
    }
    nc_sb_putc(o, ']');
    free(keep);
    return RJ_OK;
}

static int r_parse_contact_id(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t v;
    if (scalar_arg(a, "value", &v)) return RJ_BAD;
    char id[129];
    const char *msg = NULL;
    int p = nc_parse_contact_id(&v, id, &msg);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_str(o, id, 128);
    return RJ_OK;
}

static int r_request_refusal(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    int present;
    const nc_jv_t *x = arg(a, "opts", &present);
    nc_refusal_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.absent = !present;
    if (present) {
        if (elem_of(x, 1, &opts.elem) != RJ_OK) return RJ_BAD;
        if (opts.elem == NC_ELEM_OBJECT) {
            opts.own_fp = fld(x, "ownFp");
            opts.is_contact = fld(x, "isContact");
            opts.is_requested = fld(x, "isRequested");
        }
    }
    const char *text = "";
    int p = nc_request_refusal(&fp, &opts, &text);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    w_str(o, text, strlen(text));
    return RJ_OK;
}

static int r_acceptance_may_auto_approve(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *x = arg(a, "request", &present);
    nc_accept_req_t r;
    memset(&r, 0, sizeof(r));
    if (elem_of(x, present, &r.elem) != RJ_OK) return RJ_BAD;
    if (r.elem == NC_ELEM_OBJECT) {
        r.acceptance = fld(x, "acceptance");
        r.message = fld(x, "message");
        r.sender = fld(x, "sender");
    }
    int is_set;
    nc_val_t *pending;
    size_t np;
    int rc = scalars_arg(a, "pendingOutgoing", &is_set, &pending, &np);
    if (rc != RJ_OK) return rc;
    w_bool(o, nc_acceptance_may_auto_approve(&r, is_set, pending, np));
    free(pending);
    return RJ_OK;
}

static int salt_of(const nc_jv_t *a, const char *key, nc_salt_of_t *s) {
    int present;
    const nc_jv_t *x = arg(a, key, &present);
    memset(s, 0, sizeof(*s));
    if (elem_of(x, present, &s->elem) != RJ_OK) return RJ_BAD;
    if (s->elem == NC_ELEM_OBJECT) s->salt = fld(x, "salt");
    return RJ_OK;
}

static int r_accepted_salt(const nc_jv_t *a, nc_sb_t *o) {
    nc_salt_of_t mine, request;
    if (salt_of(a, "mine", &mine) != RJ_OK || salt_of(a, "request", &request) != RJ_OK) return RJ_BAD;
    nc_val_t v;
    int p = nc_accepted_salt(&mine, &request, &v);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    w_val(o, &v);
    return RJ_OK;
}

static int r_is_delivered(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *x = arg(a, "message", &present);
    nc_rmsg_t m;
    if (rmsg_of(x, present, &m) != RJ_OK) return RJ_BAD;
    w_bool(o, nc_is_delivered(&m));
    return RJ_OK;
}

static int r_message_status(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *x = arg(a, "message", &present);
    nc_rmsg_t m;
    if (rmsg_of(x, present, &m) != RJ_OK) return RJ_BAD;
    const char *s = nc_message_status(&m);
    w_str(o, s, strlen(s));
    return RJ_OK;
}

static int r_published_seqs(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    nc_list_t kind;
    nc_rmsg_t *m;
    size_t n;
    int rc = rmsgs_arg(a, "messages", LM_METHOD, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    size_t *first, nf;
    int p = nc_published_seqs(kind, m, n, &fp, &first, &nf);
    if (p != NC_P_OK) { free(m); return w_p(o, p, NULL); }
    nc_sb_t s;
    nc_sb_init(&s);
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < nf; i++) {
        if (i) nc_sb_putc(o, ',');
        nc_sb_reset(&s);
        nc_val_tostring(&m[first[i]].seq, &s);                        /* String(m.seq) */
        w_str(o, s.p, s.len);
    }
    nc_sb_putc(o, ']');
    if (s.oom) o->oom = 1;
    nc_sb_free(&s);
    free(first);
    free(m);
    return RJ_OK;
}

/* Writes { ...m, <key>: <node> [, <key2>: <node2>] } for each picked
 * message: the record node itself, changed (the tree is the dispatcher's). */
static int r_mark_published(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    nc_list_t kind, set_kind;
    nc_rmsg_t *m, *set;
    size_t n, ns;
    int rc = rmsgs_arg(a, "messages", LM_METHOD, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    rc = rmsgs_arg(a, "set", LM_METHOD, &set_kind, &set, &ns);
    if (rc != RJ_OK) { free(m); return rc; }
    size_t *idx, ni;
    int p = nc_mark_published(kind, m, n, &fp, set_kind, set, ns, &idx, &ni);
    free(m);
    free(set);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    nc_jv_t *msgs = jv_get_mut((nc_jv_t *)a, "messages");
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < ni && rc == RJ_OK; i++) {
        nc_jv_t *rec = msgs->v[idx[i]];
        if (jv_obj_set(rec, "published", 9, jv_node(NC_JV_TRUE)) != 0) { rc = RJ_NOMEM; break; }
        if (i) nc_sb_putc(o, ',');
        w_jv(o, rec);
    }
    nc_sb_putc(o, ']');
    free(idx);
    return rc;
}

static int r_mark_delivered(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, ack, now;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "ackTs", &ack) || scalar_arg(a, "nowSeconds", &now)) return RJ_BAD;
    nc_list_t kind;
    nc_rmsg_t *m;
    size_t n;
    int rc = rmsgs_arg(a, "messages", LM_METHOD, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    int is_set;
    nc_val_t *before;
    size_t nb;
    rc = scalars_arg(a, "publishedBefore", &is_set, &before, &nb);
    if (rc != RJ_OK) { free(m); return rc; }
    size_t *idx, ni;
    const char *msg = NULL;
    int p = nc_mark_delivered(kind, m, n, &fp, &ack, is_set, before, nb, &now, &idx, &ni, &msg);
    free(m);
    free(before);
    if (p != NC_P_OK) return w_p(o, p, msg);
    nc_jv_t *msgs = jv_get_mut((nc_jv_t *)a, "messages");
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < ni && rc == RJ_OK; i++) {
        nc_jv_t *rec = msgs->v[idx[i]];
        /* { ...m, delivered: true, deliveredAt: nowSeconds } (a string here) */
        if (jv_obj_set(rec, "delivered", 9, jv_node(NC_JV_TRUE)) != 0 ||
            jv_obj_set(rec, "deliveredAt", 11, jv_str_node(now.s, now.n)) != 0) { rc = RJ_NOMEM; break; }
        if (i) nc_sb_putc(o, ',');
        w_jv(o, rec);
    }
    nc_sb_putc(o, ']');
    free(idx);
    return rc;
}

static int r_ack_to_send(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, last;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "lastSent", &last)) return RJ_BAD;
    nc_list_t kind;
    nc_rmsg_t *m;
    size_t n;
    int rc = rmsgs_arg(a, "messages", LM_FOR_OF, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    int has;
    nc_u128_t v;
    int p = nc_ack_to_send(kind, m, n, &fp, &last, &has, &v);
    free(m);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    if (!has) { nc_sb_puts(o, "null"); return RJ_OK; }
    nc_sb_putc(o, '"');
    nc_u128_to_string(v, o);
    nc_sb_putc(o, '"');
    return RJ_OK;
}

static int r_ack_allowed(const nc_jv_t *a, nc_sb_t *o) {
    int present;
    const nc_jv_t *x = arg(a, "flags", &present);
    nc_ack_flags_t f;
    memset(&f, 0, sizeof(f));
    if (elem_of(x, present, &f.elem) != RJ_OK) return RJ_BAD;
    if (f.elem == NC_ELEM_OBJECT) {
        f.persistent = fld(x, "persistent");
        f.complete = fld(x, "complete");
        f.lost = fld(x, "lost");
    }
    int ok;
    int p = nc_ack_allowed(&f, &ok);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    w_bool(o, ok);
    return RJ_OK;
}

/* { seq: m.seq, ts: m.ts, text: m.text } — an undefined field left out,
 * as JSON.stringify does. */
static void w_outbox_entry(nc_sb_t *o, const nc_rmsg_t *m) {
    const char *names[3] = { "seq", "ts", "text" };
    const nc_val_t *vals[3] = { &m->seq, &m->ts, &m->text };
    int first = 1;
    nc_sb_putc(o, '{');
    for (int i = 0; i < 3; i++) {
        if (vals[i]->kind == NC_V_UNDEF) continue;
        if (!first) nc_sb_putc(o, ',');
        first = 0;
        w_str(o, names[i], strlen(names[i]));
        nc_sb_putc(o, ':');
        w_val(o, vals[i]);
    }
    nc_sb_putc(o, '}');
}

static int r_pending_outbox(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, now;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "nowSeconds", &now)) return RJ_BAD;
    nc_list_t kind;
    nc_rmsg_t *m;
    size_t n;
    int rc = rmsgs_arg(a, "messages", LM_METHOD, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    size_t *idx, ni;
    const char *msg = NULL;
    int p = nc_pending_outbox(kind, m, n, &fp, &now, &idx, &ni, &msg);
    if (p != NC_P_OK) { free(m); return w_p(o, p, msg); }
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < ni; i++) {
        if (i) nc_sb_putc(o, ',');
        w_outbox_entry(o, &m[idx[i]]);
    }
    nc_sb_putc(o, ']');
    free(idx);
    free(m);
    return RJ_OK;
}

static int r_has_undelivered(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, now;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "nowSeconds", &now)) return RJ_BAD;
    nc_list_t kind;
    nc_rmsg_t *m;
    size_t n;
    int rc = rmsgs_arg(a, "messages", LM_METHOD, &kind, &m, &n);
    if (rc != RJ_OK) return rc;
    int has;
    const char *msg = NULL;
    int p = nc_has_undelivered(kind, m, n, &fp, &now, &has, &msg);
    free(m);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_bool(o, has);
    return RJ_OK;
}

static int r_compare_local(const nc_jv_t *a, nc_sb_t *o) {
    int pa, pb;
    const nc_jv_t *xa = arg(a, "a", &pa), *xb = arg(a, "b", &pb);
    nc_rmsg_t ma, mb;
    if (rmsg_of(xa, pa, &ma) != RJ_OK || rmsg_of(xb, pb, &mb) != RJ_OK) return RJ_BAD;
    int order;
    int p = nc_compare_local(&ma, &mb, &order);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    nc_js_write_number(o, (double)order);
    return RJ_OK;
}

static int r_received_key(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    int present;
    const nc_jv_t *x = arg(a, "message", &present);
    nc_rmsg_t m;
    if (rmsg_of(x, present, &m) != RJ_OK) return RJ_BAD;
    nc_sb_t s;
    nc_sb_init(&s);
    int p = nc_received_key(&fp, &m, &s);
    if (p == NC_P_OK) w_str(o, s.p, s.len);
    nc_sb_free(&s);
    return p == NC_P_OK ? RJ_OK : w_p(o, p, NULL);
}

static int r_contact_needs_full_sync(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, now;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "now", &now)) return RJ_BAD;
    nc_rmap_t dm;
    mapbuf_t mb;
    int rc = flat_map_arg(a, "dmSync", &dm, &mb);
    if (rc != RJ_OK) return rc;
    int full;
    const char *msg = NULL;
    int p = nc_contact_needs_full_sync(&fp, &dm, &now, &full, &msg);
    mapbuf_free(&mb);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_bool(o, full);
    return RJ_OK;
}

static int r_need_full_sync(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t now;
    if (scalar_arg(a, "now", &now)) return RJ_BAD;
    int is_array;
    nc_val_t *fps;
    size_t n;
    int rc = scalars_arg(a, "contactFps", &is_array, &fps, &n);
    if (rc != RJ_OK) return rc;
    nc_rmap_t dm;
    mapbuf_t mb;
    rc = flat_map_arg(a, "dmSync", &dm, &mb);
    if (rc != RJ_OK) { free(fps); return rc; }
    int full;
    const char *msg = NULL;
    int p = nc_need_full_sync(is_array ? NC_LIST_ARRAY : NC_LIST_BAD, fps, n, &dm, &now, &full, &msg);
    free(fps);
    mapbuf_free(&mb);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_bool(o, full);
    return RJ_OK;
}

static int r_contact_days(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp, now, today;
    if (scalar_arg(a, "fp", &fp) || scalar_arg(a, "now", &now) || scalar_arg(a, "today", &today)) return RJ_BAD;
    nc_rmap_t dm;
    mapbuf_t mb;
    int rc = flat_map_arg(a, "dmSync", &dm, &mb);
    if (rc != RJ_OK) return rc;
    nc_u128_t d[8];
    size_t nd;
    const char *msg = NULL;
    int p = nc_contact_days(&fp, &dm, &now, &today, d, &nd, &msg);
    mapbuf_free(&mb);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_days(o, d, nd);
    return RJ_OK;
}

static int r_full_days(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t today;
    if (scalar_arg(a, "today", &today)) return RJ_BAD;
    nc_u128_t d[8];
    size_t nd;
    const char *msg = NULL;
    int p = nc_full_days(&today, d, &nd, &msg);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_days(o, d, nd);
    return RJ_OK;
}

static int r_recent_days(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t today;
    if (scalar_arg(a, "today", &today)) return RJ_BAD;
    nc_u128_t d[8];
    size_t nd;
    const char *msg = NULL;
    int p = nc_recent_days(&today, d, &nd, &msg);
    if (p != NC_P_OK) return w_p(o, p, msg);
    w_days(o, d, nd);
    return RJ_OK;
}

static int r_check_order(const nc_jv_t *a, nc_sb_t *o) {
    nc_list_t ck, mk;
    nc_rmsg_t *c, *m;
    size_t nc, nm;
    int rc = rmsgs_arg(a, "contacts", LM_METHOD, &ck, &c, &nc);
    if (rc != RJ_OK) return rc;
    rc = rmsgs_arg(a, "messages", LM_OR_FOR_OF, &mk, &m, &nm);
    if (rc != RJ_OK) { free(c); return rc; }
    nc_rmap_t dm;
    mapbuf_t mb;
    rc = flat_map_arg(a, "dmSync", &dm, &mb);
    if (rc != RJ_OK) { free(c); free(m); return rc; }
    size_t *order;
    int p = nc_check_order(ck, c, nc, &dm, mk, m, nm, &order);
    free(c);
    free(m);
    mapbuf_free(&mb);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    const nc_jv_t *contacts = nc_jv_get(a, "contacts");
    nc_sb_putc(o, '[');
    for (size_t i = 0; i < nc; i++) {
        if (i) nc_sb_putc(o, ',');
        w_jv(o, contacts->v[order[i]]);                               /* the same objects (§R R3) */
    }
    nc_sb_putc(o, ']');
    free(order);
    return RJ_OK;
}

static int r_profile_fresh(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t now;
    if (scalar_arg(a, "now", &now)) return RJ_BAD;
    int present;
    const nc_jv_t *x = arg(a, "entry", &present);
    nc_rmsg_t e;
    if (rmsg_of(x, present, &e) != RJ_OK) return RJ_BAD;
    nc_val_t at = e.elem == NC_ELEM_OBJECT ? fld(x, "at") : nc_val_undef();
    w_bool(o, nc_profile_fresh(&e, &at, &now));
    return RJ_OK;
}

static int r_merge_listed_contacts(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t own;
    if (scalar_arg(a, "ownFp", &own)) return RJ_BAD;
    statebuf_t sb;
    int rc = state_arg(a, &sb);
    if (rc != RJ_OK) { statebuf_free(&sb); return rc; }
    int present;
    const nc_jv_t *ea = arg(a, "entries", &present);
    nc_list_t ek;
    nc_rcontact_t *ents = NULL;
    size_t ne = 0;
    if (present && ea->kind == NC_JV_ARR) {
        ents = calloc(ea->len ? ea->len : 1, sizeof(*ents));
        if (!ents) { statebuf_free(&sb); return RJ_NOMEM; }
        for (size_t i = 0; i < ea->len; i++)
            if (contact_of(ea->v[i], &ents[i]) != RJ_OK) { free(ents); statebuf_free(&sb); return RJ_BAD; }
        ek = NC_LIST_ARRAY;
        ne = ea->len;
    } else {
        ek = nonarray_kind(ea, present, LM_OR_FOR_OF);
    }
    nc_contact_edit_t *ed;
    size_t ned;
    int changed;
    int p = nc_merge_listed_contacts(&sb.st, ek, ents, ne, &own, &ed, &ned, &changed);
    if (p != NC_P_OK) { free(ents); statebuf_free(&sb); return w_p(o, p, NULL); }
    nc_jv_t *contacts = ned ? jv_get_mut(sb.node, "contacts") : NULL;
    for (size_t i = 0; i < ned && rc == RJ_OK; i++) {
        const nc_rcontact_t *e = &ents[ed[i].entry];
        if (ed[i].kind == NC_EDIT_PUSH) {
            /* { fp: entry.fp, salt: entry.salt || null, listed: true } */
            nc_val_t null_v = nc_val_undef();
            null_v.kind = NC_V_NULL;
            nc_jv_t *c = jv_node(NC_JV_OBJ);
            if (!c) {
                rc = RJ_NOMEM;
            } else if (jv_obj_set(c, "fp", 2, jv_val_node(&e->fp)) != 0 ||
                       jv_obj_set(c, "salt", 4, jv_val_node(nc_val_truthy(&e->salt) ? &e->salt : &null_v)) != 0 ||
                       jv_obj_set(c, "listed", 6, jv_node(NC_JV_TRUE)) != 0) {
                nc_jv_free(c);
                rc = RJ_NOMEM;
            } else if (jv_arr_push(contacts, c) != 0) {               /* frees c */
                rc = RJ_NOMEM;
            }
        } else if (ed[i].kind == NC_EDIT_SALT) {
            if (jv_obj_set(contacts->v[ed[i].contact], "salt", 4, jv_val_node(&e->salt)) != 0) rc = RJ_NOMEM;
        } else {
            if (jv_obj_set(contacts->v[ed[i].contact], "listed", 6, jv_node(NC_JV_TRUE)) != 0) rc = RJ_NOMEM;
        }
    }
    free(ed);
    free(ents);
    statebuf_free(&sb);
    if (rc == RJ_OK) w_mutated(o, 1, changed, sb.node);
    return rc;
}

/* String(fp) as an object key. */
static void key_of(const nc_val_t *v, nc_sb_t *b) {
    nc_sb_reset(b);
    nc_val_tostring(v, b);
    nc_sb_put(b, "", 0);
}

static int r_remove_contact(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    statebuf_t sb;
    int rc = state_arg(a, &sb);
    if (rc != RJ_OK) { statebuf_free(&sb); return rc; }
    nc_remove_out_t r;
    int p = nc_remove_contact(&sb.st, &fp, &r);
    statebuf_free(&sb);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    if (r.removed) {
        nc_jv_t *st = sb.node;
        jv_arr_del(jv_get_mut(st, "contacts"), r.index);
        if (r.push_removed && jv_arr_push(jv_get_mut(st, "removed"), jv_val_node(&fp)) != 0) return RJ_NOMEM;
        nc_sb_t k;
        nc_sb_init(&k);
        key_of(&fp, &k);
        if (k.oom) { nc_sb_free(&k); return RJ_NOMEM; }
        jv_obj_del(jv_get_mut(st, "dmSync"), k.p, k.len);
        jv_obj_del(jv_get_mut(st, "profileCache"), k.p, k.len);
        jv_obj_del(jv_get_mut(st, "chainNames"), k.p, k.len);
        if (r.del_no_name) jv_obj_del(jv_get_mut(st, "chainNoName"), k.p, k.len);
        nc_sb_free(&k);
    }
    w_mutated(o, 1, r.removed, sb.node);
    return RJ_OK;
}

static int r_unremove_contact(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t fp;
    if (scalar_arg(a, "fp", &fp)) return RJ_BAD;
    statebuf_t sb;
    int rc = state_arg(a, &sb);
    if (rc != RJ_OK) { statebuf_free(&sb); return rc; }
    size_t *keep, nk;
    int p = nc_unremove_contact(&sb.st, &fp, &keep, &nk);
    statebuf_free(&sb);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    /* state.removed = state.removed.filter(r => r !== fp): the same place,
     * the kept elements */
    nc_jv_t *removed = jv_get_mut(sb.node, "removed");
    size_t w = 0, q = 0;
    for (size_t i = 0; i < removed->len; i++) {
        if (q < nk && keep[q] == i) { removed->v[w++] = removed->v[i]; q++; }
        else nc_jv_free(removed->v[i]);
    }
    removed->len = w;
    free(keep);
    w_mutated(o, 0, 0, sb.node);                                      /* returns undefined */
    return RJ_OK;
}

static int r_own_record_seen_common(const nc_jv_t *a, nc_sb_t *o, int first_allowed) {
    nc_val_t own, kind;
    if (scalar_arg(a, "ownFp", &own) || scalar_arg(a, "kind", &kind)) return RJ_BAD;
    statebuf_t sb;
    int rc = state_arg(a, &sb);
    if (rc == RJ_OK)
        w_bool(o, first_allowed ? nc_first_record_allowed(&sb.st, &own, &kind)
                                : nc_own_record_seen(&sb.st, &own, &kind));
    statebuf_free(&sb);
    return rc;
}
static int r_own_record_seen(const nc_jv_t *a, nc_sb_t *o) { return r_own_record_seen_common(a, o, 0); }
static int r_first_record_allowed(const nc_jv_t *a, nc_sb_t *o) { return r_own_record_seen_common(a, o, 1); }

static int r_mark_own_record_seen(const nc_jv_t *a, nc_sb_t *o) {
    nc_val_t kind, now;
    if (scalar_arg(a, "kind", &kind) || scalar_arg(a, "nowSec", &now)) return RJ_BAD;
    statebuf_t sb;
    int rc = state_arg(a, &sb);
    if (rc != RJ_OK) { statebuf_free(&sb); return rc; }
    nc_mark_seen_out_t r;
    int p = nc_mark_own_record_seen(&sb.st, &kind, &r);
    statebuf_free(&sb);
    if (p != NC_P_OK) return w_p(o, p, NULL);
    if (r.result) {
        if (r.create_seen_own && jv_obj_set(sb.node, "seenOwn", 7, jv_node(NC_JV_OBJ)) != 0) return RJ_NOMEM;
        nc_sb_t s;
        nc_sb_init(&s);
        nc_val_tostring(&now, &s);                                    /* String(nowSec) */
        nc_sb_put(&s, "", 0);
        int bad = s.oom || jv_obj_set(jv_get_mut(sb.node, "seenOwn"), kind.s, kind.n,
                                      jv_str_node(s.p, s.len)) != 0;
        nc_sb_free(&s);
        if (bad) return RJ_NOMEM;
    }
    w_mutated(o, 1, r.result, sb.node);
    return RJ_OK;
}

/* ── the dispatcher ─────────────────────────────────────────────────── */

typedef int (*rule_fn)(const nc_jv_t *args, nc_sb_t *out);
static const struct { const char *name; rule_fn fn; } RULES[] = {
    { "contentHash",     r_content_hash },
    { "messageHash",     r_message_hash },
    { "buildReaction",   r_build_reaction },
    { "parseReaction",   r_parse_reaction },
    { "reactionSummary", r_reaction_summary },
    { "ownReactionOn",   r_own_reaction_on },
    { "buildDelete",     r_build_delete },
    { "parseDelete",     r_parse_delete },
    { "deletions",       r_deletions },
    { "nodusUnits",      r_nodus_units },
    { "buildTransfer",   r_build_transfer },
    { "parseTransfer",   r_parse_transfer },
    { "validNodusCard",  r_valid_nodus_card },
    { "transferVerdict", r_transfer_verdict },
    { "copyCards",       r_copy_cards },
    { "buildReply",      r_build_reply },
    { "parseReply",      r_parse_reply },
    /* P1a: text.js / core.js (nc_rules.h) */
    { "declinedNow",              r_declined_now },
    { "isDeclined",               r_is_declined },
    { "addDeclined",              r_add_declined },
    { "undecline",                r_undecline },
    { "parseContactId",           r_parse_contact_id },
    { "requestRefusal",           r_request_refusal },
    { "acceptanceMayAutoApprove", r_acceptance_may_auto_approve },
    { "acceptedSalt",             r_accepted_salt },
    { "isDelivered",              r_is_delivered },
    { "messageStatus",            r_message_status },
    { "publishedSeqs",            r_published_seqs },
    { "markPublished",            r_mark_published },
    { "markDelivered",            r_mark_delivered },
    { "ackToSend",                r_ack_to_send },
    { "ackAllowed",               r_ack_allowed },
    { "pendingOutbox",            r_pending_outbox },
    { "hasUndelivered",           r_has_undelivered },
    { "compareLocal",             r_compare_local },
    { "receivedKey",              r_received_key },
    { "contactNeedsFullSync",     r_contact_needs_full_sync },
    { "needFullSync",             r_need_full_sync },
    { "contactDays",              r_contact_days },
    { "fullDays",                 r_full_days },
    { "recentDays",               r_recent_days },
    { "checkOrder",               r_check_order },
    { "profileFresh",             r_profile_fresh },
    { "mergeListedContacts",      r_merge_listed_contacts },
    { "removeContact",            r_remove_contact },
    { "unremoveContact",          r_unremove_contact },
    { "ownRecordSeen",            r_own_record_seen },
    { "firstRecordAllowed",       r_first_record_allowed },
    { "markOwnRecordSeen",        r_mark_own_record_seen },
};

/* The rule names are short identifiers: anything longer is unknown. */
#define RULE_NAME_MAX 64

int nc_rule_call(const char *name, const char *args_json, size_t args_len, char **out_json) {
    nc_sb_t o;
    nc_sb_init(&o);
    *out_json = NULL;
    rule_fn fn = NULL;
    size_t nl = 0;
    if (name) while (nl <= RULE_NAME_MAX && name[nl]) nl++;
    for (size_t i = 0; name && nl <= RULE_NAME_MAX && i < sizeof(RULES) / sizeof(RULES[0]); i++)
        if (nc_js_str_eq(name, nl, RULES[i].name)) { fn = RULES[i].fn; break; }

    if (args_len > NC_RULE_IN_MAX) {
        w_error(&o, "nc_rule: input too large");
    } else if (!fn) {
        w_error(&o, "nc_rule: unknown rule");
    } else {
        nc_jv_t *args = NULL;
        nc_js_parse_t pr = args_json ? nc_js_parse(args_json, args_len, &args) : NC_JS_SYNTAX;
        switch (pr) {
        case NC_JS_OK:
            if (args->kind != NC_JV_OBJ) {
                w_error(&o, "nc_rule: bad arguments");
            } else {
                int rc = fn(args, &o);
                if (rc == RJ_BAD) w_error(&o, "nc_rule: bad arguments");
                else if (rc == RJ_NOMEM) o.oom = 1;
            }
            nc_jv_free(args);
            break;
        case NC_JS_DEPTH: w_error(&o, "nc_rule: nesting too deep"); break;
        case NC_JS_NOMEM: o.oom = 1; break;
        default:          w_error(&o, "nc_rule: invalid JSON"); break;
        }
    }
    size_t len;
    *out_json = nc_sb_take(&o, &len);
    return *out_json ? 0 : -1;
}
