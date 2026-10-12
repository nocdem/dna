/* Nodus Connect core — the P1 rules' JSON dispatcher (nc_rules_json.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */
#include "nc_rules_json.h"
#include "nc_jsjson.h"
#include "nc_payload.h"

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
