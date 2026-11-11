/**
 * @file amm_http.c
 * @brief nodus-amm HTTP API (see amm_http.h). Parser and server pattern:
 *        tools/faucet/faucet_http.c, with a runtime body bound.
 */
#define _GNU_SOURCE
#include "amm_http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_HTTP"

/* ── request parser ───────────────────────────────────────────────────── */

static const char *find_crlfcrlf(const char *buf, size_t len) {
    if (len < 4) return NULL;
    for (size_t i = 0; i + 4 <= len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
            buf[i + 3] == '\n') return buf + i;
    return NULL;
}

int amm_http_parse(const char *buf, size_t len, size_t max_body, amm_http_req_t *req) {
    memset(req, 0, sizeof(*req));
    size_t scan = len < AMM_HTTP_MAX_HEADER_BLOCK + 4 ? len : AMM_HTTP_MAX_HEADER_BLOCK + 4;
    const char *end = find_crlfcrlf(buf, scan);
    if (!end) return len > AMM_HTTP_MAX_HEADER_BLOCK ? -431 : 0;
    size_t head_len = (size_t)(end - buf);
    if (head_len > AMM_HTTP_MAX_HEADER_BLOCK) return -431;

    for (size_t i = 0; i < head_len; i++) {
        if (buf[i] == '\0') return -400;
        if (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) return -400;
        if (buf[i] == '\r' && buf[i + 1] != '\n') return -400;
    }

    const char *p = buf;
    const char *eol = memchr(p, '\r', head_len);
    size_t line_len = eol ? (size_t)(eol - p) : head_len;
    if (line_len > AMM_HTTP_MAX_REQUEST_LINE) return -400;
    char line[AMM_HTTP_MAX_REQUEST_LINE + 1];
    memcpy(line, p, line_len);
    line[line_len] = '\0';
    char *sp1 = strchr(line, ' ');
    if (!sp1) return -400;
    *sp1 = '\0';
    char *path = sp1 + 1;
    char *sp2 = strchr(path, ' ');
    if (!sp2) return -400;
    *sp2 = '\0';
    char *ver = sp2 + 1;
    if (strcmp(ver, "HTTP/1.1") && strcmp(ver, "HTTP/1.0")) return -400;
    int is_get = !strcmp(line, "GET"), is_post = !strcmp(line, "POST");
    if (!is_get && !is_post) return -405;
    size_t plen = strlen(path);
    if (plen == 0 || plen >= AMM_HTTP_MAX_PATH || path[0] != '/') return -400;
    for (size_t i = 0; i < plen; i++) {
        unsigned char ch = (unsigned char)path[i];
        if (ch < 0x21 || ch > 0x7e || ch == '?' || ch == '#') return -400;
    }
    snprintf(req->method, sizeof(req->method), "%s", is_get ? "GET" : "POST");
    snprintf(req->path, sizeof(req->path), "%s", path);

    long long clen = -1;
    int nhdr = 0;
    const char *cur = eol ? eol + 2 : buf + head_len;
    while (cur < buf + head_len) {
        const char *le = memchr(cur, '\r', (size_t)(buf + head_len - cur));
        size_t hl = le ? (size_t)(le - cur) : (size_t)(buf + head_len - cur);
        if (hl > AMM_HTTP_MAX_HEADER_LINE) return -431;
        if (++nhdr > AMM_HTTP_MAX_HEADERS) return -431;
        const char *colon = memchr(cur, ':', hl);
        if (!colon || colon == cur) return -400;
        size_t nlen = (size_t)(colon - cur);
        if (nlen == 14 && !strncasecmp(cur, "content-length", 14)) {
            if (clen >= 0) return -400;                 /* duplicate          */
            const char *v = colon + 1;
            const char *ve = cur + hl;
            while (v < ve && (*v == ' ' || *v == '\t')) v++;
            if (v == ve || ve - v > 9) return -400;
            long long n = 0;
            for (; v < ve; v++) {
                if (*v < '0' || *v > '9') return -400;
                n = n * 10 + (*v - '0');
            }
            if ((unsigned long long)n > max_body) return -413;
            clen = n;
        } else if (nlen == 17 && !strncasecmp(cur, "transfer-encoding", 17)) {
            return -501;
        }
        cur = le ? le + 2 : buf + head_len;
    }
    if (is_get && clen > 0) return -400;
    if (is_post && clen < 0) return -411;
    if (clen < 0) clen = 0;

    size_t body_off = head_len + 4;
    if (len < body_off + (size_t)clen) return 0;        /* body still coming  */
    req->body = buf + body_off;
    req->body_len = (size_t)clen;
    return 1;
}

/* ── JSON: one flat object of string values ──────────────────────────── */

static const char *jws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    return p;
}

/* "...": printable ASCII without an escape. Returns the byte after the closing
 * quote, or NULL. */
static const char *jstr(const char *p, const char *end, const char **s, size_t *n) {
    if (p >= end || *p != '"') return NULL;
    const char *q = p + 1;
    while (q < end && *q != '"') {
        unsigned char c = (unsigned char)*q;
        if (c < 0x20 || c > 0x7e || c == '\\') return NULL;
        q++;
    }
    if (q >= end) return NULL;
    *s = p + 1;
    *n = (size_t)(q - p - 1);
    return q + 1;
}

int amm_json_parse(const char *body, size_t len, amm_json_t *out) {
    memset(out, 0, sizeof(*out));
    const char *p = body, *end = body + len;
    p = jws(p, end);
    if (p >= end || *p++ != '{') return -1;
    p = jws(p, end);
    if (p < end && *p == '}') { p++; p = jws(p, end); return p == end ? 0 : -1; }
    for (;;) {
        if (out->n >= AMM_HTTP_MAX_KEYS) return -1;
        const char *k, *v;
        size_t kn, vn;
        p = jws(p, end);
        p = jstr(p, end, &k, &kn);
        if (!p) return -1;
        p = jws(p, end);
        if (p >= end || *p++ != ':') return -1;
        p = jws(p, end);
        p = jstr(p, end, &v, &vn);
        if (!p) return -1;
        for (int i = 0; i < out->n; i++)
            if (out->key_len[i] == kn && !memcmp(out->key[i], k, kn)) return -1;
        out->key[out->n] = k; out->key_len[out->n] = kn;
        out->val[out->n] = v; out->val_len[out->n] = vn;
        out->n++;
        p = jws(p, end);
        if (p >= end) return -1;
        if (*p == ',') { p++; continue; }
        if (*p == '}') { p++; break; }
        return -1;
    }
    p = jws(p, end);
    return p == end ? 0 : -1;
}

int amm_json_get(const amm_json_t *j, const char *key, const char **v, size_t *n) {
    size_t kl = strlen(key);
    for (int i = 0; i < j->n; i++)
        if (j->key_len[i] == kl && !memcmp(j->key[i], key, kl)) {
            *v = j->val[i]; *n = j->val_len[i];
            return 1;
        }
    return 0;
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int amm_http_hex0x(const char *s, size_t len, uint8_t *out, size_t n) {
    if (len != 2 + 2 * n || s[0] != '0' || s[1] != 'x') return -1;
    for (size_t i = 0; i < n; i++) {
        int a = hexv(s[2 + 2 * i]), b = hexv(s[3 + 2 * i]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return 0;
}

/* a decimal u64 text without sign or leading zero ("0" alone), <= INT64_MAX */
static int dec_u64(const char *s, size_t n, uint64_t *out) {
    if (n == 0 || n > 19 || (n > 1 && s[0] == '0')) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v > (uint64_t)INT64_MAX) return -1;
    *out = v;
    return 0;
}

/* ── answers ──────────────────────────────────────────────────────────── */

typedef struct { char *out; size_t cap, n; int bad; } jb_t;

static void jraw(jb_t *j, const char *s) {
    size_t l = strlen(s);
    if (j->n + l + 1 > j->cap) { j->bad = 1; return; }
    memcpy(j->out + j->n, s, l + 1);
    j->n += l;
}

static void jstr_out(jb_t *j, const char *s) {
    jraw(j, "\"");
    for (; *s; s++) {
        char t[8];
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') { t[0] = '\\'; t[1] = (char)ch; t[2] = 0; }
        else if (ch < 0x20 || ch >= 0x7f) snprintf(t, sizeof(t), "\\u%04x", ch);
        else { t[0] = (char)ch; t[1] = 0; }
        jraw(j, t);
    }
    jraw(j, "\"");
}

static void jnum_str(jb_t *j, uint64_t v) {
    char t[32];
    snprintf(t, sizeof(t), "\"%llu\"", (unsigned long long)v);
    jraw(j, t);
}

static void jkey(jb_t *j, const char *k, int first) {
    if (!first) jraw(j, ",");
    jstr_out(j, k);
    jraw(j, ":");
}

static void hex_of(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = H[b[i] >> 4]; out[2 * i + 1] = H[b[i] & 15]; }
    out[2 * n] = '\0';
}

static const char *dir_word(amm_dir_t d) {
    return d == AMM_USDT_TO_NODUS ? "usdt_to_nodus" : "nodus_to_usdt";
}

static int finish(jb_t *j, int *status, int ok_status, char *body, size_t cap) {
    if (j->bad) {
        *status = 500;
        snprintf(body, cap, "{}");
        return -1;
    }
    *status = ok_status;
    return 0;
}

static void refusal(int *status, char *body, size_t cap, int code, const char *okkey,
                    const char *word) {
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, okkey, 1); jraw(&j, "false");
    jkey(&j, "reason", 0); jstr_out(&j, word);
    jraw(&j, "}");
    finish(&j, status, code, body, cap);
}

static const char *q_word(int rc) {
    switch (rc) {
    case AMM_Q_PAUSED:       return "paused";
    case AMM_Q_STOPPED:      return "stopped";
    case AMM_Q_BELOW_MIN:    return "below_minimum";
    case AMM_Q_ABOVE_MAX:    return "above_maximum";
    case AMM_Q_INFLIGHT:     return "inflight_full";
    case AMM_Q_NO_LIQUIDITY: return "no_liquidity";
    case AMM_Q_CANNOT_PAY:   return "cannot_pay";
    case AMM_Q_UNAVAILABLE:  return "unavailable";
    case AMM_Q_BUSY:         return "busy";     /* givens item 98: try again later */
    case AMM_Q_BAD:          return "bad_request";
    default:                 return "internal";
    }
}

static const char *s_word(int rc) {
    switch (rc) {
    case AMM_HS_FORMAT:     return "bad_format";
    case AMM_HS_CHAIN:      return "bad_chain";
    case AMM_HS_ADDRESS:    return "bad_address";
    case AMM_HS_SIGNATURE:  return "bad_signature";
    case AMM_HS_REUSED:     return "number_reused";
    case AMM_HS_NO_NUMBER:  return "unknown_number";
    case AMM_HS_AMOUNT:     return "amount_mismatch";
    case AMM_HS_USED:       return "number_used";
    case AMM_HS_OPEN:       return "open_approval";
    case AMM_HS_EXPIRED:    return "approval_expired";
    case AMM_HS_PAUSED:     return "paused";
    case AMM_HS_NO_POSITION: return "no_position";
    case AMM_HS_UNAVAILABLE: return "unavailable";
    default:                return "internal";
    }
}

/* ── routes ───────────────────────────────────────────────────────────── */

static void route_quote(amm_http_ctx_t *c, const amm_http_req_t *req, uint64_t dl, int *status,
                        char *body, size_t cap) {
    amm_json_t js;
    const char *dv, *av;
    size_t dn, an;
    uint64_t amount = 0;
    if (amm_json_parse(req->body, req->body_len, &js) != 0 || js.n != 2 ||
        !amm_json_get(&js, "direction", &dv, &dn) || !amm_json_get(&js, "amount", &av, &an) ||
        dec_u64(av, an, &amount) != 0 || amount == 0) {
        refusal(status, body, cap, 400, "approved", "bad_request");
        return;
    }
    amm_dir_t dir;
    if (dn == 13 && !memcmp(dv, "usdt_to_nodus", 13)) dir = AMM_USDT_TO_NODUS;
    else if (dn == 13 && !memcmp(dv, "nodus_to_usdt", 13)) dir = AMM_NODUS_TO_USDT;
    else { refusal(status, body, cap, 400, "approved", "bad_request"); return; }

    amm_quote_answer_t a;
    memset(&a, 0, sizeof(a));
    int rc = c->be.quote(c->be.ctx, dir, amount, dl, &a);
    if (rc != AMM_Q_OK) {
        refusal(status, body, cap, rc == AMM_Q_ERR ? 500 : 200, "approved", q_word(rc));
        return;
    }
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "approved", 1); jraw(&j, "true");
    jkey(&j, "direction", 0); jstr_out(&j, dir_word(a.dir));
    jkey(&j, "amount", 0); jnum_str(&j, a.amount);
    jkey(&j, "number", 0); jnum_str(&j, a.number);
    jkey(&j, "estimatedFee", 0); jnum_str(&j, a.est_fee);
    jkey(&j, "requestNumber", 0); jnum_str(&j, a.request_number);
    jkey(&j, "validUntil", 0); jnum_str(&j, a.valid_until);
    jkey(&j, "payTo", 0); jstr_out(&j, a.pay_to);
    jraw(&j, "}");
    finish(&j, status, 200, body, cap);
}

static void swap_answer(int rc, uint32_t req_no, uint32_t open_req, int *status, char *body,
                        size_t cap) {
    if (rc == AMM_HS_RECEIVED) {
        jb_t j = { body, cap, 0, 0 };
        if (cap) body[0] = '\0';
        jraw(&j, "{");
        jkey(&j, "received", 1); jraw(&j, "true");
        jkey(&j, "requestNumber", 0); jnum_str(&j, req_no);
        jraw(&j, "}");
        finish(&j, status, 200, body, cap);
        return;
    }
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "received", 1); jraw(&j, "false");
    jkey(&j, "reason", 0); jstr_out(&j, s_word(rc));
    if (rc == AMM_HS_OPEN) { jkey(&j, "openRequestNumber", 0); jnum_str(&j, open_req); }
    jraw(&j, "}");
    finish(&j, status, rc == AMM_HS_ERR ? 500 : 200, body, cap);
}

static void route_swap(amm_http_ctx_t *c, const amm_http_req_t *req, int *status, char *body,
                       size_t cap) {
    amm_json_t js;
    const char *kv;
    size_t kn;
    if (amm_json_parse(req->body, req->body_len, &js) != 0 ||
        !amm_json_get(&js, "kind", &kv, &kn)) {
        refusal(status, body, cap, 400, "received", "bad_request");
        return;
    }
    uint32_t req_no = 0, open_req = 0;
    if (kn == 13 && !memcmp(kv, "usdt_to_nodus", 13)) {
        const char *sv, *dv, *av, *mv, *rv, *gv;
        size_t sn, dn, an, mn, rn, gn;
        if (js.n != 7 || !amm_json_get(&js, "sender", &sv, &sn) ||
            !amm_json_get(&js, "destination", &dv, &dn) ||
            !amm_json_get(&js, "amount", &av, &an) ||
            !amm_json_get(&js, "minimumToReceive", &mv, &mn) ||
            !amm_json_get(&js, "requestNumber", &rv, &rn) ||
            !amm_json_get(&js, "signature", &gv, &gn) ||
            sn != 42 || dn != 128 || an > 20 || mn > 20 || rn > 20) {
            refusal(status, body, cap, 400, "received", "bad_request");
            return;
        }
        char sender[43], dest[129], amt[21], mnm[21], rno[21];
        memcpy(sender, sv, sn); sender[sn] = '\0';
        memcpy(dest, dv, dn); dest[dn] = '\0';
        memcpy(amt, av, an); amt[an] = '\0';
        memcpy(mnm, mv, mn); mnm[mn] = '\0';
        memcpy(rno, rv, rn); rno[rn] = '\0';
        amm_req_usdt_in_t in;
        memset(&in, 0, sizeof(in));
        in.sender = sender; in.destination = dest; in.amount = amt;
        in.minimum_to_receive = mnm; in.request_number = rno;
        if (amm_http_hex0x(gv, gn, in.signature, 65) != 0) {
            refusal(status, body, cap, 400, "received", "bad_request");
            return;
        }
        int rc = c->be.swap_usdt(c->be.ctx, &in, &req_no, &open_req);
        swap_answer(rc, req_no, open_req, status, body, cap);
        return;
    }
    if (kn == 13 && !memcmp(kv, "nodus_to_usdt", 13)) {
        const char *tv, *pv, *gv;
        size_t tn, pn, gn;
        if (js.n != 4 || !amm_json_get(&js, "text", &tv, &tn) ||
            !amm_json_get(&js, "publicKey", &pv, &pn) ||
            !amm_json_get(&js, "signature", &gv, &gn) ||
            tn < 2 || tn % 2 != 0 || (tn - 2) / 2 > AMM_REQ_TEXT_MAX) {
            refusal(status, body, cap, 400, "received", "bad_request");
            return;
        }
        const size_t text_len = (tn - 2) / 2;
        uint8_t text[AMM_REQ_TEXT_MAX];
        nodus_pubkey_t *pk = calloc(1, sizeof(*pk));
        nodus_sig_t *sg = calloc(1, sizeof(*sg));
        if (!pk || !sg) { free(pk); free(sg); refusal(status, body, cap, 500, "received", "internal"); return; }
        if (amm_http_hex0x(tv, tn, text, text_len) != 0 ||
            amm_http_hex0x(pv, pn, pk->bytes, NODUS_PK_BYTES) != 0 ||
            amm_http_hex0x(gv, gn, sg->bytes, NODUS_SIG_BYTES) != 0) {
            free(pk); free(sg);
            refusal(status, body, cap, 400, "received", "bad_request");
            return;
        }
        amm_req_nodus_in_t in = { text, text_len, pk, sg };
        int rc = c->be.swap_nodus(c->be.ctx, &in, &req_no, &open_req);
        free(pk); free(sg);
        swap_answer(rc, req_no, open_req, status, body, cap);
        return;
    }
    refusal(status, body, cap, 400, "received", "bad_request");
}

static const char *aq_word(int rc) {
    switch (rc) {
    case AMM_AQ_PAUSED:       return "paused";
    case AMM_AQ_STOPPED:      return "stopped";
    case AMM_AQ_BELOW_MIN:    return "below_minimum";
    case AMM_AQ_BAD:          return "bad_request";
    case AMM_AQ_UNAVAILABLE:  return "unavailable";
    case AMM_AQ_BUSY:         return "busy";    /* givens item 98: try again later */
    default:                  return "internal";
    }
}

/* The add question (the path is the build's choice, amm_http.h). */
static void route_add_quote(amm_http_ctx_t *c, const amm_http_req_t *req, uint64_t dl, int *status,
                            char *body, size_t cap) {
    amm_json_t js;
    const char *sv, *av;
    size_t sn, an;
    uint64_t amount = 0;
    if (!c->be.add_question || amm_json_parse(req->body, req->body_len, &js) != 0 || js.n != 2 ||
        !amm_json_get(&js, "side", &sv, &sn) || !amm_json_get(&js, "amount", &av, &an) ||
        dec_u64(av, an, &amount) != 0 || amount == 0) {
        refusal(status, body, cap, 400, "approved", "bad_request");
        return;
    }
    amm_side_t side;
    if (sn == 4 && !memcmp(sv, "usdt", 4)) side = AMM_SIDE_USDT;
    else if (sn == 5 && !memcmp(sv, "nodus", 5)) side = AMM_SIDE_NODUS;
    else { refusal(status, body, cap, 400, "approved", "bad_request"); return; }

    amm_add_answer_t a;
    memset(&a, 0, sizeof(a));
    int rc = c->be.add_question(c->be.ctx, side, amount, dl, &a);
    if (rc != AMM_AQ_OK) {
        refusal(status, body, cap, rc == AMM_AQ_ERR ? 500 : 200, "approved", aq_word(rc));
        return;
    }
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "approved", 1); jraw(&j, "true");
    jkey(&j, "usdtAmount", 0); jnum_str(&j, a.usdt_amount);
    jkey(&j, "nodusAmount", 0); jnum_str(&j, a.nodus_amount);
    jkey(&j, "requestNumber", 0); jnum_str(&j, a.request_number);
    jkey(&j, "validUntil", 0); jnum_str(&j, a.valid_until);
    jkey(&j, "payEthereum", 0); jstr_out(&j, a.pay_eth);
    jkey(&j, "payNodus", 0); jstr_out(&j, a.pay_nodus);
    jraw(&j, "}");
    finish(&j, status, 200, body, cap);
}

/* The two signed halves of a liquidity add (flat body, amm_http.h). */
static void route_add(amm_http_ctx_t *c, const amm_http_req_t *req, int *status, char *body,
                      size_t cap) {
    amm_json_t js;
    const char *ev, *nv, *uv, *mv, *rv, *gv, *tv, *pv, *sv;
    size_t en, nn, un, mn, rn, gn, tn, pn, sn;
    if (!c->be.add_accept || amm_json_parse(req->body, req->body_len, &js) != 0 || js.n != 9 ||
        !amm_json_get(&js, "ethereumAddress", &ev, &en) ||
        !amm_json_get(&js, "nodusAddress", &nv, &nn) ||
        !amm_json_get(&js, "usdtAmount", &uv, &un) ||
        !amm_json_get(&js, "nodusAmount", &mv, &mn) ||
        !amm_json_get(&js, "requestNumber", &rv, &rn) ||
        !amm_json_get(&js, "ethSignature", &gv, &gn) ||
        !amm_json_get(&js, "text", &tv, &tn) ||
        !amm_json_get(&js, "publicKey", &pv, &pn) ||
        !amm_json_get(&js, "nodusSignature", &sv, &sn) ||
        en != 42 || nn != 128 || un > 20 || mn > 20 || rn > 20 ||
        tn < 2 || tn % 2 != 0 || (tn - 2) / 2 > AMM_REQ_TEXT_MAX) {
        refusal(status, body, cap, 400, "received", "bad_request");
        return;
    }
    char eth[43], nod[129], usd[21], nds[21], rno[21];
    memcpy(eth, ev, en); eth[en] = '\0';
    memcpy(nod, nv, nn); nod[nn] = '\0';
    memcpy(usd, uv, un); usd[un] = '\0';
    memcpy(nds, mv, mn); nds[mn] = '\0';
    memcpy(rno, rv, rn); rno[rn] = '\0';
    amm_req_liq_eth_in_t ei;
    memset(&ei, 0, sizeof(ei));
    ei.ethereum_address = eth; ei.nodus_address = nod; ei.usdt_amount = usd;
    ei.nodus_amount = nds; ei.request_number = rno;
    const size_t text_len = (tn - 2) / 2;
    uint8_t text[AMM_REQ_TEXT_MAX];
    nodus_pubkey_t *pk = calloc(1, sizeof(*pk));
    nodus_sig_t *sg = calloc(1, sizeof(*sg));
    if (!pk || !sg) { free(pk); free(sg); refusal(status, body, cap, 500, "received", "internal"); return; }
    if (amm_http_hex0x(gv, gn, ei.signature, 65) != 0 ||
        amm_http_hex0x(tv, tn, text, text_len) != 0 ||
        amm_http_hex0x(pv, pn, pk->bytes, NODUS_PK_BYTES) != 0 ||
        amm_http_hex0x(sv, sn, sg->bytes, NODUS_SIG_BYTES) != 0) {
        free(pk); free(sg);
        refusal(status, body, cap, 400, "received", "bad_request");
        return;
    }
    amm_req_nodus_in_t ni = { text, text_len, pk, sg };
    uint32_t req_no = 0, open_req = 0;
    int rc = c->be.add_accept(c->be.ctx, &ei, &ni, &req_no, &open_req);
    free(pk); free(sg);
    swap_answer(rc, req_no, open_req, status, body, cap);
}

/* The signed withdrawal (plan 6.4.7: text, publicKey, signature; the Nodus key
 * only). The answer carries the signed request number, a u64. */
static void route_withdraw(amm_http_ctx_t *c, const amm_http_req_t *req, int *status, char *body,
                           size_t cap) {
    amm_json_t js;
    const char *tv, *pv, *gv;
    size_t tn, pn, gn;
    if (!c->be.withdraw || amm_json_parse(req->body, req->body_len, &js) != 0 || js.n != 3 ||
        !amm_json_get(&js, "text", &tv, &tn) || !amm_json_get(&js, "publicKey", &pv, &pn) ||
        !amm_json_get(&js, "signature", &gv, &gn) ||
        tn < 2 || tn % 2 != 0 || (tn - 2) / 2 > AMM_REQ_TEXT_MAX) {
        refusal(status, body, cap, 400, "received", "bad_request");
        return;
    }
    const size_t text_len = (tn - 2) / 2;
    uint8_t text[AMM_REQ_TEXT_MAX];
    nodus_pubkey_t *pk = calloc(1, sizeof(*pk));
    nodus_sig_t *sg = calloc(1, sizeof(*sg));
    if (!pk || !sg) { free(pk); free(sg); refusal(status, body, cap, 500, "received", "internal"); return; }
    if (amm_http_hex0x(tv, tn, text, text_len) != 0 ||
        amm_http_hex0x(pv, pn, pk->bytes, NODUS_PK_BYTES) != 0 ||
        amm_http_hex0x(gv, gn, sg->bytes, NODUS_SIG_BYTES) != 0) {
        free(pk); free(sg);
        refusal(status, body, cap, 400, "received", "bad_request");
        return;
    }
    amm_req_nodus_in_t in = { text, text_len, pk, sg };
    uint64_t req_no = 0;
    int rc = c->be.withdraw(c->be.ctx, &in, &req_no);
    free(pk); free(sg);
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "received", 1);
    if (rc == AMM_HS_RECEIVED) {
        jraw(&j, "true");
        jkey(&j, "requestNumber", 0); jnum_str(&j, req_no);
    } else {
        jraw(&j, "false");
        jkey(&j, "reason", 0); jstr_out(&j, s_word(rc));
    }
    jraw(&j, "}");
    finish(&j, status, rc == AMM_HS_ERR ? 500 : 200, body, cap);
}

static void route_get_swap(amm_http_ctx_t *c, const char *num, int *status, char *body, size_t cap) {
    uint64_t n = 0;
    if (dec_u64(num, strlen(num), &n) != 0 || n == 0 || n > UINT32_MAX) {
        refusal(status, body, cap, 404, "found", "unknown_number");
        return;
    }
    amm_swap_t s;
    int g = c->be.get_swap(c->be.ctx, (uint32_t)n, &s);
    if (g == 1) { refusal(status, body, cap, 404, "found", "unknown_number"); return; }
    if (g < 0) { refusal(status, body, cap, 500, "found", "internal"); return; }
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "requestNumber", 1); jnum_str(&j, s.req_no_bot);
    jkey(&j, "state", 0); jstr_out(&j, s.state);
    jkey(&j, "direction", 0); jstr_out(&j, dir_word(s.dir));
    jkey(&j, "amount", 0); jnum_str(&j, s.amount);
    jkey(&j, "number", 0); jnum_str(&j, s.quote_out);
    jkey(&j, "estimatedFee", 0); jnum_str(&j, s.est_fee);
    jkey(&j, "validUntil", 0); jnum_str(&j, s.expiry);
    /* plan 6.4.7: a payment waiting for room shows that it waits (givens item
     * 94); once the swap is decided, the output computed then, the network fee
     * deducted and the amount paid (givens items 93, 95) and, for a refund, its
     * reason */
    const int waiting = !strcmp(s.state, AMM_S_PAID_WAITING) && !s.room;
    jkey(&j, "waitingForRoom", 0); jraw(&j, waiting ? "true" : "false");
    if (!strcmp(s.state, AMM_S_PAYOUT_PENDING) || !strcmp(s.state, AMM_S_PAID)) {
        jkey(&j, "output", 0); jnum_str(&j, s.out_amount);
        jkey(&j, "networkFee", 0); jnum_str(&j, s.out_fee);
        jkey(&j, "paid", 0); jnum_str(&j, s.out_paid);
    }
    if (!strcmp(s.state, AMM_S_REFUND_PENDING) || !strcmp(s.state, AMM_S_REFUNDED) ||
        !strcmp(s.state, AMM_S_DROPPED)) {
        jkey(&j, "reason", 0); jstr_out(&j, s.message);
    }
    jraw(&j, "}");
    finish(&j, status, 200, body, cap);
}

static void u256_dec(const evm_u256 *v, char *out, size_t cap) {
    uint64_t u = 0;
    if (amm_to_u64(&u, v) == AMM_OK) snprintf(out, cap, "%llu", (unsigned long long)u);
    else snprintf(out, cap, "above_2_64");
}

static void route_status(amm_http_ctx_t *c, int *status, char *body, size_t cap) {
    amm_engine_status_t st;
    if (c->be.status(c->be.ctx, &st) != 0) {
        refusal(status, body, cap, 500, "ok", "internal");
        return;
    }
    const amm_cfg_t *g = c->cfg;
    char t[32], hx[2 * 32 + 1], ea[2 * 20 + 1];
    jb_t j = { body, cap, 0, 0 };
    if (cap) body[0] = '\0';
    jraw(&j, "{");
    jkey(&j, "swapsPaused", 1); jraw(&j, st.swaps_paused ? "true" : "false");
    jkey(&j, "liquidityPaused", 0); jraw(&j, st.liquidity_paused ? "true" : "false");
    jkey(&j, "payoutsPaused", 0); jraw(&j, st.payouts_paused ? "true" : "false");
    jkey(&j, "stopped", 0); jraw(&j, st.stopped ? "true" : "false");
    jkey(&j, "inflightUsdt", 0); jnum_str(&j, st.inflight_usdt);
    jkey(&j, "roomUsdt", 0); jnum_str(&j, st.room_usdt);
    jkey(&j, "reserves", 0);
    if (st.have_pool) {
        jraw(&j, "{");
        jkey(&j, "nodus", 1); u256_dec(&st.pool.depth_n, t, sizeof(t)); jstr_out(&j, t);
        jkey(&j, "usdt", 0); u256_dec(&st.pool.depth_u, t, sizeof(t)); jstr_out(&j, t);
        jraw(&j, "}");
    } else {
        jraw(&j, "null");
    }
    jkey(&j, "settings", 0);
    jraw(&j, "{");
    jkey(&j, "swapMinUsdt", 1); jnum_str(&j, g->swap_min_usdt);
    jkey(&j, "swapMaxUsdt", 0); jnum_str(&j, g->swap_max_usdt);
    jkey(&j, "inflightMaxUsdt", 0); jnum_str(&j, g->inflight_max_usdt);
    jkey(&j, "approvalValidSeconds", 0); jnum_str(&j, g->approval_valid_seconds);
    jkey(&j, "commission", 0); jnum_str(&j, g->commission);
    jkey(&j, "ethChainId", 0); jnum_str(&j, g->eth_chain_id);
    jkey(&j, "eip712Name", 0); jstr_out(&j, g->eip712_name);
    jkey(&j, "expectedOrigin", 0); jstr_out(&j, g->expected_origin);
    /* the USDT contract the extension's USDT payment names as `token`, and the
     * smallest liquidity add (givens item 96), written as foundationEthereum is */
    jkey(&j, "usdtContract", 0);
    hex_of(g->usdt_contract, 20, ea);
    jraw(&j, "\"0x"); jraw(&j, ea); jraw(&j, "\"");
    jkey(&j, "liquidityMinNodus", 0); jnum_str(&j, g->liquidity_min_nodus);
    jraw(&j, "}");
    jkey(&j, "foundationEthereum", 0);
    hex_of(g->foundation_eth, 20, ea);
    jraw(&j, "\"0x"); jraw(&j, ea); jraw(&j, "\"");
    jkey(&j, "foundationNodus", 0); jstr_out(&j, g->foundation_nodus);
    jkey(&j, "nodusChainId", 0);
    hex_of(g->chain_id, 32, hx);
    jstr_out(&j, hx);
    jraw(&j, "}");
    finish(&j, status, 200, body, cap);
}

void amm_http_route(amm_http_ctx_t *c, const amm_http_req_t *req, uint64_t deadline_ms,
                    int *status, char *body, size_t cap) {
    const int get = !strcmp(req->method, "GET");
    if (!strcmp(req->path, "/amm/quote")) {
        if (get) { refusal(status, body, cap, 405, "approved", "bad_request"); return; }
        route_quote(c, req, deadline_ms, status, body, cap);
    } else if (!strcmp(req->path, "/amm/swap")) {
        if (get) { refusal(status, body, cap, 405, "received", "bad_request"); return; }
        route_swap(c, req, status, body, cap);
    } else if (!strcmp(req->path, "/amm/liquidity/quote")) {
        if (get) { refusal(status, body, cap, 405, "approved", "bad_request"); return; }
        route_add_quote(c, req, deadline_ms, status, body, cap);
    } else if (!strcmp(req->path, "/amm/liquidity/add")) {
        if (get) { refusal(status, body, cap, 405, "received", "bad_request"); return; }
        route_add(c, req, status, body, cap);
    } else if (!strcmp(req->path, "/amm/liquidity/withdraw")) {
        if (get) { refusal(status, body, cap, 405, "received", "bad_request"); return; }
        route_withdraw(c, req, status, body, cap);
    } else if (!strncmp(req->path, "/amm/swap/", 10)) {
        if (!get) { refusal(status, body, cap, 405, "found", "bad_request"); return; }
        route_get_swap(c, req->path + 10, status, body, cap);
    } else if (!strcmp(req->path, "/amm/status")) {
        if (!get) { refusal(status, body, cap, 405, "ok", "bad_request"); return; }
        route_status(c, status, body, cap);
    } else {
        refusal(status, body, cap, 404, "ok", "not_found");
    }
}

/* ── the server ───────────────────────────────────────────────────────── */

typedef struct {
    int      fd;
    char    *buf;
    size_t   len;
    uint64_t deadline_ms;
    int      writing;
    char    *resp;
    size_t   resp_len, resp_off;
} conn_t;

struct amm_http {
    int       lfd, conn_cap, timeout_ms, nconn;
    size_t    max_body, max_response, buf_cap, resp_cap;
    amm_http_handler_fn handler;
    void     *ctx;
    conn_t   *conns[AMM_HTTP_CONN_HARD_MAX];
};

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static const char *reason(int s) {
    switch (s) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Internal Server Error";
    }
}

static size_t format_response(char *out, size_t cap, int status, const char *body) {
    size_t bl = body ? strlen(body) : 0;
    int n = snprintf(out, cap,
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nCache-Control: no-store\r\n"
                     "Connection: close\r\n\r\n%s",
                     status, reason(status), bl, body ? body : "");
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

static void send_once(int fd, int status, const char *word) {
    char body[128], resp[512];
    snprintf(body, sizeof(body), "{\"approved\":false,\"reason\":\"%s\"}", word);
    size_t n = format_response(resp, sizeof(resp), status, body);
    if (n) (void)send(fd, resp, n, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static void conn_free(conn_t *c) {
    close(c->fd);
    free(c->buf);
    free(c->resp);
    free(c);
}

static void drop(amm_http_t *h, int idx) {
    conn_free(h->conns[idx]);
    h->conns[idx] = h->conns[--h->nconn];
    h->conns[h->nconn] = NULL;
}

static int flush_conn(conn_t *c) {
    while (c->resp_off < c->resp_len) {
        ssize_t r = send(c->fd, c->resp + c->resp_off, c->resp_len - c->resp_off,
                         MSG_NOSIGNAL | MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        c->resp_off += (size_t)r;
    }
    return 1;
}

static void answer_conn(amm_http_t *h, int idx, int status, const char *body) {
    conn_t *c = h->conns[idx];
    size_t n = format_response(c->resp, h->resp_cap, status, body);
    if (!n) n = format_response(c->resp, h->resp_cap, 500, "{}");
    c->resp_len = n;
    c->resp_off = 0;
    c->writing = 1;
    if (flush_conn(c) != 0) drop(h, idx);
}

int amm_http_open(uint16_t port, int conn_cap, int timeout_ms, size_t max_body,
                  size_t max_response, amm_http_handler_fn handler, void *ctx,
                  amm_http_t **out, uint16_t *bound) {
    if (!handler || !out || conn_cap < 1 || conn_cap > AMM_HTTP_CONN_HARD_MAX ||
        timeout_ms < 1 || max_body < 1 || max_response < 64 ||
        max_body > (64u << 20) || max_response > (64u << 20)) return -1;
    *out = NULL;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);        /* 127.0.0.1 ONLY */
    sa.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 32) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot listen on 127.0.0.1:%u: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    if (bound) {
        socklen_t sl = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) { close(fd); return -1; }
        *bound = ntohs(sa.sin_port);
    }
    amm_http_t *h = calloc(1, sizeof(*h));
    if (!h) { close(fd); return -1; }
    h->lfd = fd; h->conn_cap = conn_cap; h->timeout_ms = timeout_ms;
    h->max_body = max_body; h->max_response = max_response;
    h->buf_cap = AMM_HTTP_MAX_HEADER_BLOCK + 4 + max_body;
    h->resp_cap = max_response + 256;
    h->handler = handler; h->ctx = ctx;
    *out = h;
    return 0;
}

int amm_http_connections(const amm_http_t *h) { return h->nconn; }

static void serve_conn(amm_http_t *h, int idx) {
    conn_t *c = h->conns[idx];
    if (c->writing) {
        if (flush_conn(c) != 0) drop(h, idx);
        return;
    }
    ssize_t r = recv(c->fd, c->buf + c->len, h->buf_cap - c->len, 0);
    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        drop(h, idx);
        return;
    }
    if (r < 0) return;
    c->len += (size_t)r;

    amm_http_req_t req;
    int pr = amm_http_parse(c->buf, c->len, h->max_body, &req);
    if (pr == 0) {
        if (c->len >= h->buf_cap) answer_conn(h, idx, 413, "{\"reason\":\"bad_request\"}");
        return;
    }
    if (pr < 0) {
        answer_conn(h, idx, -pr, "{\"reason\":\"bad_request\"}");
        return;
    }
    char *body = malloc(h->max_response + 1);
    if (!body) { answer_conn(h, idx, 500, "{}"); return; }
    int status = 500;
    body[0] = '\0';
    h->handler(h->ctx, &req, c->deadline_ms, &status, body, h->max_response + 1);
    answer_conn(h, idx, status, body);
    free(body);
}

int amm_http_poll(amm_http_t *h, int wait_ms) {
    struct pollfd pfd[AMM_HTTP_CONN_HARD_MAX + 1];
    const int nold = h->nconn;
    pfd[0].fd = h->lfd;
    pfd[0].events = POLLIN;
    for (int i = 0; i < h->nconn; i++) {
        pfd[i + 1].fd = h->conns[i]->fd;
        pfd[i + 1].events = h->conns[i]->writing ? POLLOUT : POLLIN;
    }
    int n = poll(pfd, (nfds_t)(h->nconn + 1), wait_ms);
    if (n < 0 && errno != EINTR) return -1;

    if (n > 0 && (pfd[0].revents & POLLIN)) {
        for (int k = 0; k < 16; k++) {
            int cfd = accept4(h->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0) break;
            if (h->nconn >= h->conn_cap) {
                send_once(cfd, 503, "unavailable");
                close(cfd);
                continue;
            }
            conn_t *c = calloc(1, sizeof(*c));
            if (c) { c->buf = malloc(h->buf_cap); c->resp = malloc(h->resp_cap); }
            if (!c || !c->buf || !c->resp) {
                if (c) { free(c->buf); free(c->resp); free(c); }
                close(cfd);
                continue;
            }
            c->fd = cfd;
            c->deadline_ms = now_ms() + (uint64_t)h->timeout_ms;
            h->conns[h->nconn++] = c;
        }
    }
    if (n > 0)
        for (int i = nold - 1; i >= 0; i--)
            if (pfd[i + 1].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR))
                serve_conn(h, i);

    uint64_t now = now_ms();
    for (int i = h->nconn - 1; i >= 0; i--) {
        if (now >= h->conns[i]->deadline_ms) {
            if (!h->conns[i]->writing) send_once(h->conns[i]->fd, 408, "request_timeout");
            drop(h, i);
        }
    }
    return 0;
}

void amm_http_close(amm_http_t *h) {
    if (!h) return;
    while (h->nconn > 0) drop(h, h->nconn - 1);
    close(h->lfd);
    free(h);
}
