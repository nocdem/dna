/**
 * @file amm_eth_rpc.c
 * @brief nodus-amm Ethereum JSON-RPC provider (see amm_eth_rpc.h for the
 *        references, the mapping rule and the bounds).
 */
#include "amm_eth_rpc.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "amm_cfg.h"
#include "client/nodus_evm_abi.h"
#include "crypto/hash/keccak256.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_RPC"
#define AMM_RPC_OBJ_MEMBERS 64

/* ═══ strict bounded JSON ═════════════════════════════════════════════ */

typedef enum { J_NULL, J_BOOL, J_INT, J_STR, J_ARR, J_OBJ } jt_t;

typedef struct {
    jt_t        t;
    const char *s;          /* J_STR: the text between the quotes            */
    size_t      len;
    int64_t     i;          /* J_INT value, J_BOOL 0/1                       */
    int         first, last, next, nchild;
    const char *key;        /* the key this value has in its object          */
    size_t      klen;
} jn_t;

typedef struct {
    const char *p, *end;
    jn_t       *nodes;
    int         cap, n;
} jp_t;

static void skip_ws(jp_t *j) {
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r')) j->p++;
}

static int new_node(jp_t *j, jt_t t) {
    if (j->n >= j->cap) return -1;
    jn_t *n = &j->nodes[j->n];
    memset(n, 0, sizeof(*n));
    n->t = t;
    n->first = n->last = n->next = -1;
    return j->n++;
}

/* A string with no escape and only printable ASCII. */
static int parse_string(jp_t *j, const char **s, size_t *len) {
    if (j->p >= j->end || *j->p != '"') return -1;
    const char *b = ++j->p;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p;
        if (c < 0x20 || c > 0x7e || c == '\\') return -1;
        j->p++;
    }
    if (j->p >= j->end) return -1;
    *s = b;
    *len = (size_t)(j->p - b);
    j->p++;
    return 0;
}

static int lit(jp_t *j, const char *w) {
    size_t n = strlen(w);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, w, n) != 0) return -1;
    j->p += n;
    return 0;
}

static int parse_value(jp_t *j, int depth);

static int link_child(jp_t *j, int parent, int child) {
    jn_t *p = &j->nodes[parent];
    /* At most AMM_RPC_OBJ_MEMBERS members per object: the duplicate-key scan
     * below is linear per member, so the cap bounds it per object (the widest
     * schema answer read here, a block, has fewer than 32 fields). */
    if (p->t == J_OBJ && p->nchild >= AMM_RPC_OBJ_MEMBERS) return -1;
    if (p->t == J_OBJ) {                       /* no duplicate key           */
        for (int c = p->first; c >= 0; c = j->nodes[c].next)
            if (j->nodes[c].klen == j->nodes[child].klen &&
                !memcmp(j->nodes[c].key, j->nodes[child].key, j->nodes[c].klen))
                return -1;
    }
    if (p->last < 0) p->first = child; else j->nodes[p->last].next = child;
    p->last = child;
    p->nchild++;
    return 0;
}

static int parse_container(jp_t *j, int depth, int is_obj) {
    if (depth + 1 > AMM_RPC_JSON_DEPTH) return -1;
    int me = new_node(j, is_obj ? J_OBJ : J_ARR);
    if (me < 0) return -1;
    j->p++;                                    /* '{' or '['                  */
    skip_ws(j);
    const char close = is_obj ? '}' : ']';
    if (j->p < j->end && *j->p == close) { j->p++; return me; }
    for (;;) {
        const char *k = NULL;
        size_t kl = 0;
        skip_ws(j);
        if (is_obj) {
            if (parse_string(j, &k, &kl) != 0) return -1;
            skip_ws(j);
            if (j->p >= j->end || *j->p != ':') return -1;
            j->p++;
            skip_ws(j);
        }
        int c = parse_value(j, depth + 1);
        if (c < 0) return -1;
        j->nodes[c].key = k;
        j->nodes[c].klen = kl;
        if (link_child(j, me, c) != 0) return -1;
        skip_ws(j);
        if (j->p >= j->end) return -1;
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == close) { j->p++; return me; }
        return -1;
    }
}

static int parse_value(jp_t *j, int depth) {
    if (j->p >= j->end) return -1;
    char c = *j->p;
    if (c == '{') return parse_container(j, depth, 1);
    if (c == '[') return parse_container(j, depth, 0);
    if (c == '"') {
        int n = new_node(j, J_STR);
        if (n < 0 || parse_string(j, &j->nodes[n].s, &j->nodes[n].len) != 0) return -1;
        return n;
    }
    if (c == 't' || c == 'f') {
        int n = new_node(j, J_BOOL);
        if (n < 0 || lit(j, c == 't' ? "true" : "false") != 0) return -1;
        j->nodes[n].i = (c == 't');
        return n;
    }
    if (c == 'n') {
        int n = new_node(j, J_NULL);
        if (n < 0 || lit(j, "null") != 0) return -1;
        return n;
    }
    if (c == '-' || (c >= '0' && c <= '9')) {      /* integers only          */
        const char *b = j->p;
        int neg = (c == '-');
        if (neg) j->p++;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9') return -1;
        const char *d0 = j->p;
        if (*j->p == '0') {
            j->p++;
        } else {
            while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
        }
        if (j->p - d0 > 15) return -1;
        if (j->p < j->end && ((*j->p >= '0' && *j->p <= '9') || *j->p == '.' ||
                              *j->p == 'e' || *j->p == 'E')) return -1;
        int64_t v = 0;
        for (const char *q = d0; q < j->p; q++) v = v * 10 + (*q - '0');
        int n = new_node(j, J_INT);
        if (n < 0) return -1;
        j->nodes[n].i = neg ? -v : v;
        (void)b;
        return n;
    }
    return -1;
}

/* Parse the whole text. @return the root index (0) or -1. */
static int json_parse(const char *buf, size_t len, jn_t *nodes, int cap) {
    jp_t j = { buf, buf + len, nodes, cap, 0 };
    skip_ws(&j);
    int root = parse_value(&j, 0);
    if (root < 0) return -1;
    skip_ws(&j);
    return j.p == j.end ? root : -1;
}

static int obj_get(const jn_t *nd, int obj, const char *key) {
    if (nd[obj].t != J_OBJ) return -1;
    size_t kl = strlen(key);
    for (int c = nd[obj].first; c >= 0; c = nd[c].next)
        if (nd[c].klen == kl && !memcmp(nd[c].key, key, kl)) return c;
    return -1;
}

/* ═══ value formats (base-types.yaml) ═════════════════════════════════ */

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* `uint`: ^0x(0|[1-9a-f][0-9a-f]*)$ -- the digit text, or NULL. */
static const char *uint_digits(const jn_t *n, size_t *nd) {
    if (n->t != J_STR || n->len < 3 || n->s[0] != '0' || n->s[1] != 'x') return NULL;
    const char *d = n->s + 2;
    size_t k = n->len - 2;
    if (k == 1 && d[0] == '0') { *nd = 1; return d; }
    if (hexv(d[0]) <= 0) return NULL;                  /* no leading zero    */
    for (size_t i = 0; i < k; i++) if (hexv(d[i]) < 0) return NULL;
    *nd = k;
    return d;
}

static int q_u64(const jn_t *n, uint64_t *out) {
    size_t nd;
    const char *d = uint_digits(n, &nd);
    if (!d || nd > 16) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < nd; i++) v = (v << 4) | (uint64_t)hexv(d[i]);
    *out = v;
    return 0;
}

static int q_be32(const jn_t *n, uint8_t out[32]) {
    size_t nd;
    const char *d = uint_digits(n, &nd);
    if (!d || nd > 64) return -1;
    memset(out, 0, 32);
    for (size_t i = 0; i < nd; i++) {                   /* from the right      */
        size_t pos = nd - 1 - i;                        /* nibble index        */
        uint8_t v = (uint8_t)hexv(d[pos]);
        size_t byte = 31 - i / 2;
        out[byte] |= (uint8_t)((i % 2) ? (v << 4) : v);
    }
    return 0;
}

/* `bytes`: ^0x[0-9a-f]*$ with an even number of digits (a byte string). */
static int bytes_text(const jn_t *n, const char **d, size_t *nbytes) {
    if (n->t != J_STR || n->len < 2 || n->s[0] != '0' || n->s[1] != 'x') return -1;
    size_t k = n->len - 2;
    if (k % 2) return -1;
    for (size_t i = 0; i < k; i++) if (hexv(n->s[2 + i]) < 0) return -1;
    *d = n->s + 2;
    *nbytes = k / 2;
    return 0;
}

static void bytes_copy(const char *d, size_t nbytes, uint8_t *out) {
    for (size_t i = 0; i < nbytes; i++)
        out[i] = (uint8_t)(hexv(d[2 * i]) * 16 + hexv(d[2 * i + 1]));
}

static int h_fixed(const jn_t *n, uint8_t *out, size_t want) {   /* hash32 / bytes32 */
    const char *d;
    size_t nb;
    if (bytes_text(n, &d, &nb) != 0 || nb != want) return -1;
    bytes_copy(d, nb, out);
    return 0;
}

static int h_hash32(const jn_t *n, uint8_t out[32]) { return h_fixed(n, out, 32); }

/* `address`: ^0x[0-9a-fA-F]{40}$ (mixed case allowed by the schema). */
static int h_addr(const jn_t *n, uint8_t out[20]) {
    if (n->t != J_STR || n->len != 42 || n->s[0] != '0' || n->s[1] != 'x') return -1;
    for (int i = 0; i < 20; i++) {
        char a = n->s[2 + 2 * i], b = n->s[3 + 2 * i];
        if (a >= 'A' && a <= 'F') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'F') b = (char)(b - 'A' + 'a');
        int x = hexv(a), y = hexv(b);
        if (x < 0 || y < 0) return -1;
        out[i] = (uint8_t)(x * 16 + y);
    }
    return 0;
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* ═══ the provider object and one call ════════════════════════════════ */

struct amm_eth_rpc {
    char            url[AMM_URL_MAX];
    char            name[AMM_RPC_NAME_MAX];
    amm_rpc_post_fn post;
    void           *post_ctx;
    size_t          max_response;
    /* the chain id rule (amm_eth_rpc.h CHAIN ID): all read and written only
     * under `mu`, inside rpc_call */
    uint64_t        chain_id;        /* the eth_chain_id setting                       */
    pthread_mutex_t mu;              /* one call and its check are one unit on the handle */
    int64_t         verified_sock;   /* descriptor of the connection that last reported
                                      * the setting, AMM_RPC_SOCK_NONE if none          */
    int             drop_next;       /* 1: the next POST re-creates the handle          */
};

amm_eth_rpc_t *amm_eth_rpc_new(const amm_eth_rpc_cfg_t *cfg) {
    if (!cfg || !cfg->url || !cfg->post || cfg->chain_id == 0 ||
        cfg->max_response < AMM_RPC_RESP_MIN || cfg->max_response > AMM_RPC_RESP_CEIL)
        return NULL;
    size_t ul = strlen(cfg->url);
    if (ul < 9 || ul >= AMM_URL_MAX || strncmp(cfg->url, "https://", 8) != 0)
        return NULL;
    for (size_t i = 0; i < ul; i++)
        if ((unsigned char)cfg->url[i] < 0x21 || (unsigned char)cfg->url[i] > 0x7e)
            return NULL;
    amm_eth_rpc_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    memcpy(r->url, cfg->url, ul + 1);
    snprintf(r->name, sizeof(r->name), "%s", cfg->name ? cfg->name : "provider");
    r->post = cfg->post;
    r->post_ctx = cfg->post_ctx;
    r->max_response = cfg->max_response;
    r->chain_id = cfg->chain_id;
    r->verified_sock = AMM_RPC_SOCK_NONE;
    r->drop_next = 0;
    if (pthread_mutex_init(&r->mu, NULL) != 0) { free(r); return NULL; }
    return r;
}

void amm_eth_rpc_free(amm_eth_rpc_t *r) {
    if (!r) return;
    pthread_mutex_destroy(&r->mu);
    free(r);
}

typedef struct {
    uint8_t *resp;
    jn_t    *nodes;
    int      result;      /* index of the `result` value                      */
} doc_t;

static void doc_free(doc_t *d) {
    free(d->resp);
    free(d->nodes);
    memset(d, 0, sizeof(*d));
}

#define REQ_ID 1

/* The longest provider message the log line carries, in bytes (operator
 * 2026-11-11); a longer one is cut and marked with "...". */
#define ERR_MSG_MAX 200

/* The provider's own words in the log line: at most ERR_MSG_MAX bytes of `s`,
 * every byte outside printable ASCII 0x20-0x7E written as '?', so provider
 * text cannot put a newline or another control byte into the log. `out` needs
 * ERR_MSG_MAX + 4 bytes. (The strict parser already refuses such bytes; this
 * keeps the line safe on its own.) */
static void sanitize_err_msg(const char *s, size_t len, char *out) {
    size_t n = len < ERR_MSG_MAX ? len : ERR_MSG_MAX;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        out[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    if (len > ERR_MSG_MAX) { memcpy(out + n, "...", 3); n += 3; }
    out[n] = '\0';
}

/* What replaces the provider's URL inside its message. */
#define URL_MARKER     "[url]"
#define URL_MARKER_LEN 5

static int at_needle(const char *s, size_t rem, const char *nd, size_t nl) {
    return nl > 0 && nl <= rem && memcmp(s, nd, nl) == 0;
}

/* The provider's message with its configured URL taken out, so a key that the
 * provider echoes back never reaches the log. Every occurrence of the whole URL
 * and of its path+query part (from the first '/' or '?' after the authority;
 * only when longer than one byte) becomes URL_MARKER. The scan reads the WHOLE
 * message, not just the first ERR_MSG_MAX bytes, so a URL that straddles the cut
 * cannot leave its prefix; it stops once the result is past ERR_MSG_MAX (the
 * caller cuts there). `out` needs ERR_MSG_MAX + 1 + URL_MARKER_LEN bytes;
 * returns the result length. */
static size_t redact_url(const char *s, size_t len, const char *url, char *out) {
    size_t ul = url ? strlen(url) : 0;
    const char *au = url ? strstr(url, "://") : NULL;
    au = au ? au + 3 : url;
    const char *tail = au ? au + strcspn(au, "/?") : NULL;
    size_t tl = tail ? strlen(tail) : 0;
    if (tl < 2) tl = 0;
    size_t i = 0, o = 0;
    while (i < len && o <= ERR_MSG_MAX) {
        if (at_needle(s + i, len - i, url, ul)) {
            memcpy(out + o, URL_MARKER, URL_MARKER_LEN); o += URL_MARKER_LEN; i += ul;
        } else if (at_needle(s + i, len - i, tail, tl)) {
            memcpy(out + o, URL_MARKER, URL_MARKER_LEN); o += URL_MARKER_LEN; i += tl;
        } else {
            out[o++] = s[i++];
        }
    }
    return o;
}

/* Warn about an error answer: the provider's NAME (never its URL, which may
 * carry a key, and never the URL or its path/query inside the provider's own
 * message: redact_url), the error's integer `code` and string `message` when it
 * has them. `er` is the index of the `error` value. */
static void log_rpc_error(const char *name, const char *url, const char *method,
                          const jn_t *nd, int er) {
    int code = nd[er].t == J_OBJ ? obj_get(nd, er, "code") : -1;
    int msg = nd[er].t == J_OBJ ? obj_get(nd, er, "message") : -1;
    int has_code = code >= 0 && nd[code].t == J_INT;
    int has_msg = msg >= 0 && nd[msg].t == J_STR;
    char text[ERR_MSG_MAX + 4];
    char red[ERR_MSG_MAX + 1 + URL_MARKER_LEN];
    if (has_msg) {
        size_t rl = redact_url(nd[msg].s, nd[msg].len, url, red);
        sanitize_err_msg(red, rl, text);
    }
    if (has_code && has_msg)
        QGP_LOG_WARN(LOG_TAG, "%s: %s: provider error %lld: %s", name, method,
                     (long long)nd[code].i, text);
    else if (has_code)
        QGP_LOG_WARN(LOG_TAG, "%s: %s: provider error %lld", name, method,
                     (long long)nd[code].i);
    else if (has_msg)
        QGP_LOG_WARN(LOG_TAG, "%s: %s: provider error: %s", name, method, text);
    else
        QGP_LOG_WARN(LOG_TAG, "%s: %s: the provider answered with an error", name, method);
}

/* One JSON-RPC call. `params` is the JSON text of the params array. 0 and
 * `d` filled, or -1 (every failure, including an error object). */
static uint64_t mono_ms(void);

/* A provider call that takes this long is written to the log. */
#define RPC_SLOW_MS 3000

static int rpc_once(amm_eth_rpc_t *r, const char *method, const char *params,
                    uint64_t deadline_ms, doc_t *d, amm_rpc_xfer_t *xf) {
    memset(d, 0, sizeof(*d));
    xf->new_conns = 0;
    xf->sock = AMM_RPC_SOCK_NONE;
    size_t bl = strlen(method) + strlen(params) + 64;
    char *body = malloc(bl);
    if (!body) return -1;
    int n = snprintf(body, bl, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"method\":\"%s\","
                     "\"params\":%s}", REQ_ID, method, params);
    if (n < 0 || (size_t)n >= bl) { free(body); return -1; }
    d->resp = malloc(r->max_response);
    if (!d->resp) { free(body); return -1; }
    size_t rl = 0;
    uint64_t t0 = mono_ms();
    int pr = r->post(r->post_ctx, r->url, (const uint8_t *)body, (size_t)n,
                     d->resp, r->max_response, &rl, deadline_ms, r->drop_next, xf);
    r->drop_next = 0;                       /* the request has been posted with it (under r->mu) */
    uint64_t took = mono_ms() - t0;
    free(body);
    /* The keep rule, after EVERY post whatever its result: the verification
     * stays only if this transfer made no connection and left the verified
     * connection in the cache. A new connection can receive the number of a
     * closed verified one, and its transfer can still fail at the bot's level
     * (HTTP status, not JSON, an id that does not parse): without this reset
     * the next call over that never-checked connection would pass. */
    if (!(xf->new_conns == 0 && xf->sock != AMM_RPC_SOCK_NONE &&
          xf->sock == r->verified_sock))
        r->verified_sock = AMM_RPC_SOCK_NONE;
    if (took >= RPC_SLOW_MS)
        QGP_LOG_WARN(LOG_TAG, "%s: %s: the answer took %llu ms", r->name, method,
                     (unsigned long long)took);
    if (pr != AMM_ETH_OK || rl == 0 || rl > r->max_response) {
        QGP_LOG_WARN(LOG_TAG, "%s: %s: no usable answer (after %llu ms)", r->name, method,
                     (unsigned long long)took);
        doc_free(d);
        return -1;
    }
    int cap = rl + 1 < (size_t)AMM_RPC_JSON_NODES ? (int)(rl + 1) : AMM_RPC_JSON_NODES;
    d->nodes = malloc((size_t)cap * sizeof(jn_t));
    if (!d->nodes) { doc_free(d); return -1; }
    int root = json_parse((const char *)d->resp, rl, d->nodes, cap);
    if (root != 0 || d->nodes[0].t != J_OBJ) {
        QGP_LOG_WARN(LOG_TAG, "%s: %s: the answer is not strict JSON (after %llu ms)",
                     r->name, method, (unsigned long long)took);
        doc_free(d);
        return -1;
    }
    /* envelope: only jsonrpc, id, result, error; exactly one of result/error */
    int jr = -1, id = -1, res = -1, er = -1;
    for (int c = d->nodes[0].first; c >= 0; c = d->nodes[c].next) {
        const jn_t *k = &d->nodes[c];
        if (k->klen == 7 && !memcmp(k->key, "jsonrpc", 7)) jr = c;
        else if (k->klen == 2 && !memcmp(k->key, "id", 2)) id = c;
        else if (k->klen == 6 && !memcmp(k->key, "result", 6)) res = c;
        else if (k->klen == 5 && !memcmp(k->key, "error", 5)) er = c;
        else { jr = -2; break; }                        /* unknown top-level key */
    }
    if (jr < 0 || id < 0 || d->nodes[jr].t != J_STR || d->nodes[jr].len != 3 ||
        memcmp(d->nodes[jr].s, "2.0", 3) != 0 || d->nodes[id].t != J_INT ||
        d->nodes[id].i != REQ_ID || (res >= 0) == (er >= 0)) {
        QGP_LOG_WARN(LOG_TAG, "%s: %s: not a valid JSON-RPC answer (after %llu ms)",
                     r->name, method, (unsigned long long)took);
        doc_free(d);
        return -1;
    }
    if (er >= 0) {
        /* the call line (operator order 2026-11-12: full diagnostic log); the
         * params are never written: eth_sendRawTransaction carries the signed
         * transaction in them */
        int ec = d->nodes[er].t == J_OBJ ? obj_get(d->nodes, er, "code") : -1;
        if (ec >= 0 && d->nodes[ec].t == J_INT)
            QGP_LOG_INFO(LOG_TAG, "%s: %s: answered in %llu ms with the JSON-RPC error %lld",
                         r->name, method, (unsigned long long)took,
                         (long long)d->nodes[ec].i);
        else
            QGP_LOG_INFO(LOG_TAG, "%s: %s: answered in %llu ms with a JSON-RPC error "
                         "without a code", r->name, method, (unsigned long long)took);
        log_rpc_error(r->name, r->url, method, d->nodes, er);
        doc_free(d);
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "%s: %s: answered in %llu ms with a result", r->name, method,
                 (unsigned long long)took);
    d->result = res;
    return 0;
}

/* The chain id rule (amm_eth_rpc.h CHAIN ID; plan 6.1 item 7 (f)). Holds the
 * RPC object's mutex for the whole call, so the call, its check and the field
 * updates are one unit on the provider's handle. `n` and `s` below are the
 * request's xt.new_conns and xt.sock. */
static void chain_warn(const amm_eth_rpc_t *r, const char *method, const char *why) {
    QGP_LOG_WARN(LOG_TAG, "%s: %s: the answer does not count: %s", r->name, method, why);
}

static int rpc_call_locked(amm_eth_rpc_t *r, const char *method, const char *params,
                           uint64_t deadline_ms, doc_t *d) {
    doc_t t;
    amm_rpc_xfer_t xt;
    int rc = rpc_once(r, method, params, deadline_ms, &t, &xt);
    if (strcmp(method, "eth_chainId") == 0) {
        /* a chain-id request checks the connection it arrived on itself */
        uint64_t id;
        if (rc == 0 && q_u64(&t.nodes[t.result], &id) == 0) {
            if (id == r->chain_id) {
                r->verified_sock = xt.sock;            /* NONE when not kept */
            } else {
                r->verified_sock = AMM_RPC_SOCK_NONE;
                r->drop_next = 1;
            }
        }
        if (rc == 0) *d = t;
        return rc;
    }
    if (rc != 0) return -1;                            /* nothing to count; t is freed */
    if (r->verified_sock != AMM_RPC_SOCK_NONE) {       /* ran over the verified connection */
        *d = t;
        return 0;
    }
    if (xt.sock == AMM_RPC_SOCK_NONE) {                /* not kept: nothing can verify it */
        chain_warn(r, method, "its connection was not kept");
        doc_free(&t);
        return -1;
    }
    if (deadline_ms != 0 && mono_ms() >= deadline_ms) {
        chain_warn(r, method, "the deadline passed before the chain-id check");
        doc_free(&t);
        return -1;
    }
    /* hold T's answer; one check on the same handle, never a loop */
    doc_t p;
    amm_rpc_xfer_t xp;
    int pc = rpc_once(r, "eth_chainId", "[]", deadline_ms, &p, &xp);
    int have = 0;
    uint64_t pid = 0;
    if (pc == 0) {
        have = q_u64(&p.nodes[p.result], &pid) == 0;
        doc_free(&p);
    }
    if (have) {
        if (pid == r->chain_id) {
            r->verified_sock = xp.sock;                /* the connection the check ran on */
        } else {
            r->verified_sock = AMM_RPC_SOCK_NONE;
            r->drop_next = 1;
        }
    }
    int ok = 0;
    if (!have) {
        chain_warn(r, method, "the chain id could not be read on this connection");
    } else if (pid != r->chain_id) {
        char w[96];
        snprintf(w, sizeof(w), "the connection reports chain id %llu, the setting is %llu",
                 (unsigned long long)pid, (unsigned long long)r->chain_id);
        chain_warn(r, method, w);
    } else if (xp.new_conns != 0) {
        chain_warn(r, method, "the chain-id check needed another new connection");
    } else if (xp.sock != xt.sock) {
        chain_warn(r, method, "the chain-id check ran on another connection");
    } else {
        ok = 1;
    }
    if (!ok) {
        doc_free(&t);
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "%s: %s: chain id %llu checked on this connection: the answer counts",
                 r->name, method, (unsigned long long)pid);
    *d = t;
    return 0;
}

static int rpc_call(amm_eth_rpc_t *r, const char *method, const char *params,
                    uint64_t deadline_ms, doc_t *d) {
    memset(d, 0, sizeof(*d));
    pthread_mutex_lock(&r->mu);
    int rc = rpc_call_locked(r, method, params, deadline_ms, d);
    pthread_mutex_unlock(&r->mu);
    return rc;
}

/* ═══ the calls ═══════════════════════════════════════════════════════ */

static int call_u64(void *ctx, const char *method, const char *params,
                    uint64_t dl, uint64_t *out) {
    doc_t d;
    if (!out || rpc_call(ctx, method, params, dl, &d) != 0) return AMM_ETH_ERR;
    uint64_t v;
    int ok = q_u64(&d.nodes[d.result], &v) == 0;
    if (ok) *out = v;
    doc_free(&d);
    return ok ? AMM_ETH_OK : AMM_ETH_ERR;
}

/* eth_chainId: client.yaml:1 */
static int m_chain_id(void *ctx, uint64_t *out, uint64_t dl) {
    return call_u64(ctx, "eth_chainId", "[]", dl, out);
}
/* eth_blockNumber: client.yaml:60 */
static int m_block_number(void *ctx, uint64_t *out, uint64_t dl) {
    return call_u64(ctx, "eth_blockNumber", "[]", dl, out);
}
/* eth_gasPrice: fee_market.yaml:1 */
static int m_gas_price(void *ctx, uint64_t *out, uint64_t dl) {
    return call_u64(ctx, "eth_gasPrice", "[]", dl, out);
}
/* eth_maxPriorityFeePerGas: fee_market.yaml:43 */
static int m_max_priority_fee(void *ctx, uint64_t *out, uint64_t dl) {
    return call_u64(ctx, "eth_maxPriorityFeePerGas", "[]", dl, out);
}

/* Required-field checks of an object `o`: the field must be present and match
 * its base-types.yaml pattern. */
static int f_uint(const jn_t *nd, int o, const char *k) {
    int i = obj_get(nd, o, k);
    size_t n;
    return i >= 0 && uint_digits(&nd[i], &n) != NULL && n <= 64;
}
static int f_hash(const jn_t *nd, int o, const char *k) {
    uint8_t b[32];
    int i = obj_get(nd, o, k);
    return i >= 0 && h_hash32(&nd[i], b) == 0;
}
static int f_addr(const jn_t *nd, int o, const char *k) {
    uint8_t b[20];
    int i = obj_get(nd, o, k);
    return i >= 0 && h_addr(&nd[i], b) == 0;
}
static int f_bytes(const jn_t *nd, int o, const char *k) {
    const char *d;
    size_t n;
    int i = obj_get(nd, o, k);
    return i >= 0 && bytes_text(&nd[i], &d, &n) == 0;
}
/* bytesN: exactly `nbytes` bytes of lower-case hex (bytes8, bytes256) */
static int f_fixed(const jn_t *nd, int o, const char *k, size_t nbytes) {
    const char *d;
    size_t n;
    int i = obj_get(nd, o, k);
    return i >= 0 && bytes_text(&nd[i], &d, &n) == 0 && n == nbytes;
}
/* `byte`: ^0x[0-9a-f]{1,2}$ */
static int f_byte(const jn_t *nd, int o, const char *k) {
    int i = obj_get(nd, o, k);
    if (i < 0 || nd[i].t != J_STR || nd[i].len < 3 || nd[i].len > 4 ||
        nd[i].s[0] != '0' || nd[i].s[1] != 'x') return 0;
    for (size_t x = 2; x < nd[i].len; x++) if (hexv(nd[i].s[x]) < 0) return 0;
    return 1;
}
static int f_arr(const jn_t *nd, int o, const char *k) {
    int i = obj_get(nd, o, k);
    return i >= 0 && nd[i].t == J_ARR;
}
/* optional, but null or an address when present (to, contractAddress) */
static int opt_addr_or_null(const jn_t *nd, int o, const char *k) {
    uint8_t b[20];
    int i = obj_get(nd, o, k);
    return i < 0 || nd[i].t == J_NULL || h_addr(&nd[i], b) == 0;
}

static int tx_required_ok(const jn_t *nd, int o);

/* A list of hash32 (blobVersionedHashes, transaction.yaml:148-153). */
static int f_hashes(const jn_t *nd, int o, const char *k) {
    uint8_t h[32];
    int i = obj_get(nd, o, k);
    if (i < 0 || nd[i].t != J_ARR) return 0;
    for (int c = nd[i].first; c >= 0; c = nd[c].next)
        if (h_hash32(&nd[c], h) != 0) return 0;
    return 1;
}

/* AccessList (transaction.yaml:186-204): every entry an object with `address`
 * and `storageKeys` (an array of hash32). */
static int f_acl(const jn_t *nd, int o) {
    int i = obj_get(nd, o, "accessList");
    if (i < 0 || nd[i].t != J_ARR) return 0;
    for (int c = nd[i].first; c >= 0; c = nd[c].next)
        if (nd[c].t != J_OBJ || !f_addr(nd, c, "address") || !f_hashes(nd, c, "storageKeys"))
            return 0;
    return 1;
}

/* AuthorizationList (transaction.yaml:59-91): every entry an object with
 * chainId, nonce, address, yParity, r, s. */
static int f_authlist(const jn_t *nd, int o) {
    int i = obj_get(nd, o, "authorizationList");
    if (i < 0 || nd[i].t != J_ARR) return 0;
    for (int c = nd[i].first; c >= 0; c = nd[c].next)
        if (nd[c].t != J_OBJ || !f_uint(nd, c, "chainId") || !f_uint(nd, c, "nonce") ||
            !f_addr(nd, c, "address") || !f_byte(nd, c, "yParity") ||
            !f_uint(nd, c, "r") || !f_uint(nd, c, "s")) return 0;
    return 1;
}

/* Block required (schemas/block.yaml:1-23): hash, parentHash, sha3Uncles,
 * miner, stateRoot, transactionsRoot, receiptsRoot, logsBloom, number,
 * gasLimit, gasUsed, timestamp, extraData, mixHash, nonce, size,
 * transactions, uncles; types :24-110. `transactions` holds hash32 items
 * (hydrated = false) or transaction objects (anyOf, :89-98). */
static int block_required_ok(const jn_t *nd, int o) {
    if (!f_hash(nd, o, "hash") || !f_hash(nd, o, "parentHash") ||
        !f_hash(nd, o, "sha3Uncles") || !f_addr(nd, o, "miner") ||
        !f_hash(nd, o, "stateRoot") || !f_hash(nd, o, "transactionsRoot") ||
        !f_hash(nd, o, "receiptsRoot") || !f_fixed(nd, o, "logsBloom", 256) ||
        !f_uint(nd, o, "number") || !f_uint(nd, o, "gasLimit") ||
        !f_uint(nd, o, "gasUsed") || !f_uint(nd, o, "timestamp") ||
        !f_bytes(nd, o, "extraData") || !f_hash(nd, o, "mixHash") ||
        !f_fixed(nd, o, "nonce", 8) || !f_uint(nd, o, "size") ||
        !f_arr(nd, o, "transactions") || !f_arr(nd, o, "uncles")) return 0;
    uint8_t h[32];
    int tx = obj_get(nd, o, "transactions"), un = obj_get(nd, o, "uncles");
    for (int c = nd[tx].first; c >= 0; c = nd[c].next)
        if (nd[c].t == J_OBJ ? !tx_required_ok(nd, c) : h_hash32(&nd[c], h) != 0) return 0;
    for (int c = nd[un].first; c >= 0; c = nd[c].next)
        if (h_hash32(&nd[c], h) != 0) return 0;
    return 1;
}

/* eth_getBlockByNumber: block.yaml:63; result oneOf [notFound, Block] */
static int m_get_block(void *ctx, uint64_t number, amm_eth_block_t *out, uint64_t dl) {
    char params[64];
    snprintf(params, sizeof(params), "[\"0x%llx\",false]", (unsigned long long)number);
    doc_t d;
    if (!out || rpc_call(ctx, "eth_getBlockByNumber", params, dl, &d) != 0)
        return AMM_ETH_ERR;
    const jn_t *nd = d.nodes;
    int rc = AMM_ETH_ERR;
    if (nd[d.result].t == J_NULL) {
        rc = AMM_ETH_NOT_FOUND;
    } else if (nd[d.result].t == J_OBJ) {
        int in = obj_get(nd, d.result, "number"), ih = obj_get(nd, d.result, "hash"),
            ip = obj_get(nd, d.result, "parentHash"),
            it = obj_get(nd, d.result, "timestamp");
        amm_eth_block_t b;
        memset(&b, 0, sizeof(b));
        if (in >= 0 && ih >= 0 && ip >= 0 && it >= 0 && block_required_ok(nd, d.result) &&
            q_u64(&nd[in], &b.number) == 0 && b.number == number &&
            h_hash32(&nd[ih], b.hash) == 0 && h_hash32(&nd[ip], b.parent) == 0 &&
            q_u64(&nd[it], &b.timestamp) == 0) {
            *out = b;
            rc = AMM_ETH_OK;
        }
    }
    doc_free(&d);
    return rc;
}

/* One Log object (receipt.yaml:1-40) of block `block` with hash `bhash`. The
 * schema requires only transactionHash; the seam needs more, so every field it
 * reads is required here (a stricter reading, ERR when absent). `removed` must
 * be false when present; the log must carry exactly that block number AND
 * that block hash. @return 0 / -1. */
static int parse_log(const jn_t *nd, int c, uint64_t block, const uint8_t bhash[32],
                     amm_eth_log_t *l) {
    if (nd[c].t != J_OBJ) return -1;
    int iL = obj_get(nd, c, "logIndex"), iT = obj_get(nd, c, "transactionHash"),
        iH = obj_get(nd, c, "blockHash"), iN = obj_get(nd, c, "blockNumber"),
        iA = obj_get(nd, c, "address"), iP = obj_get(nd, c, "topics"),
        iD = obj_get(nd, c, "data"), iR = obj_get(nd, c, "removed");
    memset(l, 0, sizeof(*l));
    uint64_t li = 0;
    const char *dh = NULL;
    size_t dn = 0;
    if (iL < 0 || iT < 0 || iH < 0 || iN < 0 || iA < 0 || iP < 0 || iD < 0 ||
        (iR >= 0 && (nd[iR].t != J_BOOL || nd[iR].i != 0)) ||
        q_u64(&nd[iL], &li) != 0 || li > UINT32_MAX ||
        h_hash32(&nd[iT], l->tx) != 0 || h_hash32(&nd[iH], l->block_hash) != 0 ||
        q_u64(&nd[iN], &l->block_number) != 0 || l->block_number != block ||
        memcmp(l->block_hash, bhash, 32) != 0 ||
        h_addr(&nd[iA], l->address) != 0 || nd[iP].t != J_ARR ||
        nd[iP].nchild > 4 || bytes_text(&nd[iD], &dh, &dn) != 0 ||
        dn > (size_t)INT32_MAX) return -1;
    l->log_index = (uint32_t)li;
    for (int t = nd[iP].first; t >= 0; t = nd[t].next) {
        if (h_fixed(&nd[t], l->topics[l->n_topics], 32) != 0) return -1;
        l->n_topics++;
    }
    l->data_len = (int)dn;                 /* the true length; the first 32 bytes */
    bytes_copy(dh, dn < 32 ? dn : 32, l->data);
    {   /* the digest of the whole data (a tail beyond 32 bytes is not lost) */
        uint8_t *all = malloc(dn ? dn : 1);
        if (!all) return -1;
        bytes_copy(dh, dn, all);
        int kr = keccak256(all, dn, l->data_digest);
        free(all);
        if (kr != 0) return -1;
    }
    return 0;
}

/* eth_getLogs: filter.yaml:151 with "Filter by block hash" (filter.yaml:40-59:
 * blockHash, address, topics; no fromBlock/toBlock), so the answer is about
 * exactly the asked block and a provider that does not hold it answers with an
 * error (go-ethereum v1.17.8 eth/filters/filter.go:83-97, an unknown hash is
 * errUnknownBlock); topics [topic0, null, recipient] (FilterTopics,
 * filter.yaml:61-80) */
static int m_get_logs(void *ctx, uint64_t block, const uint8_t block_hash[32],
                      const uint8_t contract[20],
                      const uint8_t topic0[32], const uint8_t to[20],
                      amm_eth_log_t *out, int cap, int *n, uint64_t dl) {
    if (!out || !n || cap < 1 || !block_hash) return AMM_ETH_ERR;
    char hb[65], hc[41], ht[65], hr[41];
    to_hex(block_hash, 32, hb);
    to_hex(contract, 20, hc);
    to_hex(topic0, 32, ht);
    to_hex(to, 20, hr);
    char params[480];
    snprintf(params, sizeof(params),
             "[{\"blockHash\":\"0x%s\",\"address\":\"0x%s\","
             "\"topics\":[\"0x%s\",null,\"0x000000000000000000000000%s\"]}]",
             hb, hc, ht, hr);
    doc_t d;
    if (rpc_call(ctx, "eth_getLogs", params, dl, &d) != 0) return AMM_ETH_ERR;
    const jn_t *nd = d.nodes;
    int rc = AMM_ETH_ERR;
    if (nd[d.result].t != J_ARR || nd[d.result].nchild > cap) goto done;
    int cnt = 0, ok = 1;
    for (int c = nd[d.result].first; c >= 0 && ok; c = nd[c].next) {
        if (parse_log(nd, c, block, block_hash, &out[cnt]) != 0) { ok = 0; break; }
        cnt++;
    }
    if (ok) { *n = cnt; rc = AMM_ETH_OK; }
done:
    doc_free(&d);
    return rc;
}

/* Required fields of TransactionInfo (transaction.yaml:487-518): the
 * contextual ones (blockHash, blockNumber, from, hash, transactionIndex) and,
 * by `type`, the required fields of the signed type
 * (TransactionSigned, :480-486; the Unsigned schemas' required lists and the
 * signature properties :364-479): all types need type, nonce, gas, value,
 * input, r, s. `to` is required to be present here (the seam reads it; the
 * schema lets types 0-2 omit it, a stricter reading that is ERR). An unknown
 * type is ERR. The schema's contextual blockTimestamp is not read: the bot
 * never uses it, live providers leave it out (rpc.sepolia.ethpandaops.io and
 * ethereum-sepolia-rpc.blockreq.com, 2026-11-12), and the client THORChain's
 * bifrost reads transactions with (shared/evm/eth_rpc.go:134) takes only
 * blockNumber, blockHash and from besides the transaction: op-geth
 * v1.101503.1 ethclient/ethclient.go:254-258 (the go-ethereum replacement of
 * thornode go.mod:20), as go-ethereum v1.17.8 ethclient/ethclient.go:268-272. */
static int tx_required_ok(const jn_t *nd, int o) {
    int it = obj_get(nd, o, "type");
    if (it < 0 || nd[it].t != J_STR) return 0;
    if (!f_hash(nd, o, "blockHash") || !f_uint(nd, o, "blockNumber") ||
        !f_addr(nd, o, "from") ||
        !f_hash(nd, o, "hash") || !f_uint(nd, o, "transactionIndex") ||
        !f_byte(nd, o, "type") || !f_uint(nd, o, "nonce") || !f_uint(nd, o, "gas") ||
        !f_uint(nd, o, "value") || !f_bytes(nd, o, "input") || !f_uint(nd, o, "r") ||
        !f_uint(nd, o, "s")) return 0;
    const char *ty = nd[it].s;
    size_t tl = nd[it].len;
    if (tl != 3) return 0;
    switch (ty[2]) {
    case '0':   /* legacy: gasPrice, v */
        return f_uint(nd, o, "gasPrice") && f_uint(nd, o, "v");
    case '1':   /* 2930: gasPrice, chainId, accessList, yParity */
        return f_uint(nd, o, "gasPrice") && f_uint(nd, o, "chainId") &&
               f_acl(nd, o) && f_byte(nd, o, "yParity");
    case '2':   /* 1559 */
        return f_uint(nd, o, "maxFeePerGas") && f_uint(nd, o, "maxPriorityFeePerGas") &&
               f_uint(nd, o, "gasPrice") && f_uint(nd, o, "chainId") &&
               f_acl(nd, o) && f_byte(nd, o, "yParity");
    case '3':   /* 4844: to, fees, maxFeePerBlobGas, accessList, blobVersionedHashes */
        return f_addr(nd, o, "to") && f_uint(nd, o, "maxFeePerGas") &&
               f_uint(nd, o, "maxPriorityFeePerGas") && f_uint(nd, o, "maxFeePerBlobGas") &&
               f_acl(nd, o) && f_hashes(nd, o, "blobVersionedHashes") &&
               f_uint(nd, o, "chainId") && f_byte(nd, o, "yParity");
    case '4':   /* 7702: to, fees, accessList, chainId, authorizationList */
        return f_addr(nd, o, "to") && f_uint(nd, o, "maxFeePerGas") &&
               f_uint(nd, o, "maxPriorityFeePerGas") && f_acl(nd, o) &&
               f_uint(nd, o, "chainId") && f_authlist(nd, o) &&
               f_byte(nd, o, "yParity");
    default:
        return 0;
    }
}

/* eth_getTransactionByHash: transaction.yaml:1; TransactionInfo
 * (transaction.yaml:487-517); `input` (:519-548) */
static int m_get_tx(void *ctx, const uint8_t hash[32], amm_eth_tx_t *out, uint64_t dl) {
    char hh[65], params[96];
    to_hex(hash, 32, hh);
    snprintf(params, sizeof(params), "[\"0x%s\"]", hh);
    doc_t d;
    if (!out || rpc_call(ctx, "eth_getTransactionByHash", params, dl, &d) != 0)
        return AMM_ETH_ERR;
    const jn_t *nd = d.nodes;
    int rc = AMM_ETH_ERR;
    if (nd[d.result].t == J_NULL) {
        rc = AMM_ETH_NOT_FOUND;
    } else if (nd[d.result].t == J_OBJ) {
        int ih = obj_get(nd, d.result, "hash"), ifr = obj_get(nd, d.result, "from"),
            ito = obj_get(nd, d.result, "to"), iin = obj_get(nd, d.result, "input");
        amm_eth_tx_t t;
        memset(&t, 0, sizeof(t));
        uint8_t hh2[32];
        const char *dh = NULL;
        size_t dn = 0;
        if (ih >= 0 && ifr >= 0 && ito >= 0 && iin >= 0 &&
            tx_required_ok(nd, d.result) &&
            h_hash32(&nd[ih], hh2) == 0 && !memcmp(hh2, hash, 32) &&
            h_addr(&nd[ifr], t.from) == 0 && bytes_text(&nd[iin], &dh, &dn) == 0 &&
            dn <= UINT32_MAX &&
            (nd[ito].t == J_NULL || h_addr(&nd[ito], t.to) == 0)) {
            t.has_to = nd[ito].t != J_NULL;
            t.input_len = (uint32_t)dn;
            bytes_copy(dh, dn < 4 ? dn : 4, t.input_head);
            *out = t;
            rc = AMM_ETH_OK;
        }
    }
    if (rc == AMM_ETH_ERR)
        QGP_LOG_WARN(LOG_TAG, "%s: eth_getTransactionByHash 0x%s: the answer is not a valid "
                     "transaction (a required field is missing or malformed)",
                     ((amm_eth_rpc_t *)ctx)->name, hh);
    doc_free(&d);
    return rc;
}

/* eth_getTransactionReceipt: transaction.yaml:127; ReceiptInfo
 * (receipt.yaml:40-140): status is 0 or 1 (:111-114) */
static int m_get_receipt(void *ctx, const uint8_t hash[32], amm_eth_receipt_t *out,
                         uint64_t dl) {
    char hh[65], params[96];
    to_hex(hash, 32, hh);
    snprintf(params, sizeof(params), "[\"0x%s\"]", hh);
    doc_t d;
    if (!out || rpc_call(ctx, "eth_getTransactionReceipt", params, dl, &d) != 0)
        return AMM_ETH_ERR;
    const jn_t *nd = d.nodes;
    int rc = AMM_ETH_ERR;
    if (nd[d.result].t == J_NULL) {
        rc = AMM_ETH_NOT_FOUND;
    } else if (nd[d.result].t == J_OBJ) {
        const int o = d.result;
        int ih = obj_get(nd, o, "transactionHash"),
            is = obj_get(nd, o, "status"), ib = obj_get(nd, o, "blockNumber"),
            ibh = obj_get(nd, o, "blockHash"), il = obj_get(nd, o, "logs");
        amm_eth_receipt_t *r = calloc(1, sizeof(*r));
        uint8_t hh2[32];
        uint64_t st = 2;
        /* ReceiptInfo required (receipt.yaml:43-54): blockHash, blockNumber,
         * from, cumulativeGasUsed, gasUsed, logs, logsBloom, transactionHash,
         * transactionIndex, effectiveGasPrice; `status` is the seam's field
         * (receipt.yaml:107-111, 0 or 1) */
        if (r && ih >= 0 && is >= 0 && ib >= 0 && ibh >= 0 && il >= 0 &&
            h_hash32(&nd[ih], hh2) == 0 && !memcmp(hh2, hash, 32) &&
            q_u64(&nd[is], &st) == 0 && st <= 1 &&
            q_u64(&nd[ib], &r->block_number) == 0 &&
            h_hash32(&nd[ibh], r->block_hash) == 0 &&
            f_addr(nd, o, "from") && f_uint(nd, o, "cumulativeGasUsed") &&
            f_uint(nd, o, "gasUsed") && f_fixed(nd, o, "logsBloom", 256) &&
            f_uint(nd, o, "transactionIndex") && f_uint(nd, o, "effectiveGasPrice") &&
            opt_addr_or_null(nd, o, "to") && opt_addr_or_null(nd, o, "contractAddress") &&
            nd[il].t == J_ARR) {
            /* every log of the receipt is checked like an eth_getLogs log
             * (receipt.yaml:101-105, Log :1-40) and must name the receipt's
             * own block; the first AMM_ETH_RCPT_LOGS are kept */
            int ok = 1, total = 0;
            for (int c = nd[il].first; c >= 0 && ok; c = nd[c].next) {
                amm_eth_log_t lg;
                if (parse_log(nd, c, r->block_number, r->block_hash, &lg) != 0 ||
                    memcmp(lg.tx, hash, 32) != 0) { ok = 0; break; }
                if (total < AMM_ETH_RCPT_LOGS) r->logs[total] = lg;
                total++;
            }
            if (ok) {
                r->status = (int)st;
                r->logs_total = total;
                r->n_logs = total < AMM_ETH_RCPT_LOGS ? total : AMM_ETH_RCPT_LOGS;
                *out = *r;
                rc = AMM_ETH_OK;
            }
        }
        free(r);
    }
    if (rc == AMM_ETH_ERR)
        QGP_LOG_WARN(LOG_TAG, "%s: eth_getTransactionReceipt 0x%s: the answer is not a valid "
                     "receipt (a required field is missing or malformed)",
                     ((amm_eth_rpc_t *)ctx)->name, hh);
    doc_free(&d);
    return rc;
}

/* eth_getBalance: state.yaml:1, block `latest` */
static int m_get_balance(void *ctx, const uint8_t addr[20], uint8_t out[32], uint64_t dl) {
    char ha[41], params[96];
    to_hex(addr, 20, ha);
    snprintf(params, sizeof(params), "[\"0x%s\",\"latest\"]", ha);
    doc_t d;
    if (!out || rpc_call(ctx, "eth_getBalance", params, dl, &d) != 0) return AMM_ETH_ERR;
    uint8_t v[32];
    int ok = q_be32(&d.nodes[d.result], v) == 0;
    if (ok) memcpy(out, v, 32);
    doc_free(&d);
    return ok ? AMM_ETH_OK : AMM_ETH_ERR;
}

/* eth_call: execute.yaml:1, GenericTransaction `to` + `input`, block
 * `latest`; the result is `bytes` and must be one 32-byte word */
static int m_erc20_balance(void *ctx, const uint8_t token[20], const uint8_t owner[20],
                           uint8_t out[32], uint64_t dl) {
    uint8_t sel[4];
    /* ERC-20 balanceOf(address): erc-20.md:85-90 */
    if (!out || nodus_evm_abi_selector("balanceOf(address)", sel) != 0) return AMM_ETH_ERR;
    char ht[41], hs[9], ho[41], params[240];
    to_hex(token, 20, ht);
    to_hex(sel, 4, hs);
    to_hex(owner, 20, ho);
    snprintf(params, sizeof(params),
             "[{\"to\":\"0x%s\",\"input\":\"0x%s000000000000000000000000%s\"},\"latest\"]",
             ht, hs, ho);
    doc_t d;
    if (rpc_call(ctx, "eth_call", params, dl, &d) != 0) return AMM_ETH_ERR;
    uint8_t v[32];
    int ok = h_fixed(&d.nodes[d.result], v, 32) == 0;
    if (ok) memcpy(out, v, 32);
    doc_free(&d);
    return ok ? AMM_ETH_OK : AMM_ETH_ERR;
}

/* eth_getTransactionCount: state.yaml:109, block `pending` | `latest`
 * (BlockTag, schemas/block.yaml:213-222) */
static int m_tx_count(void *ctx, const uint8_t addr[20], int pending, uint64_t *out,
                      uint64_t dl) {
    char ha[41], params[96];
    to_hex(addr, 20, ha);
    snprintf(params, sizeof(params), "[\"0x%s\",\"%s\"]", ha, pending ? "pending" : "latest");
    return call_u64(ctx, "eth_getTransactionCount", params, dl, out);
}

#define EST_INPUT_MAX 4096u

/* eth_estimateGas: execute.yaml:43, GenericTransaction from / to / input */
static int m_estimate_gas(void *ctx, const uint8_t from[20], const uint8_t to[20],
                          const uint8_t *input, size_t input_len, uint64_t *out,
                          uint64_t dl) {
    if (!out || (input_len > 0 && !input) || input_len > EST_INPUT_MAX) return AMM_ETH_ERR;
    size_t pl = input_len * 2 + 200;
    char *params = malloc(pl);
    if (!params) return AMM_ETH_ERR;
    char hf[41], ht[41];
    to_hex(from, 20, hf);
    to_hex(to, 20, ht);
    int n = snprintf(params, pl, "[{\"from\":\"0x%s\",\"to\":\"0x%s\",\"input\":\"0x", hf, ht);
    to_hex(input, input_len, params + n);
    n += (int)(input_len * 2);
    snprintf(params + n, pl - (size_t)n, "\"},\"latest\"]");
    int rc = call_u64(ctx, "eth_estimateGas", params, dl, out);
    free(params);
    return rc;
}

#define SEND_RAW_MAX (64u * 1024u)

/* eth_sendRawTransaction: submit.yaml:32; the result is the hash32 */
static int m_send_raw(void *ctx, const uint8_t *raw, size_t raw_len, uint8_t hash_out[32],
                      uint64_t dl) {
    if (!raw || raw_len == 0 || raw_len > SEND_RAW_MAX || !hash_out) return AMM_ETH_ERR;
    size_t pl = raw_len * 2 + 16;
    char *params = malloc(pl);
    if (!params) return AMM_ETH_ERR;
    int n = snprintf(params, pl, "[\"0x");
    to_hex(raw, raw_len, params + n);
    n += (int)(raw_len * 2);
    snprintf(params + n, pl - (size_t)n, "\"]");
    doc_t d;
    int rc = rpc_call(ctx, "eth_sendRawTransaction", params, dl, &d);
    free(params);
    if (rc != 0) return AMM_ETH_ERR;
    uint8_t h[32];
    int ok = h_hash32(&d.nodes[d.result], h) == 0;
    if (ok) memcpy(hash_out, h, 32);
    doc_free(&d);
    return ok ? AMM_ETH_OK : AMM_ETH_ERR;
}

void amm_eth_rpc_provider(amm_eth_rpc_t *r, amm_eth_provider_t *out) {
    memset(out, 0, sizeof(*out));
    out->ctx = r;
    out->name = r->name;
    out->chain_id = m_chain_id;
    out->block_number = m_block_number;
    out->get_block = m_get_block;
    out->get_logs = m_get_logs;
    out->get_tx = m_get_tx;
    out->get_receipt = m_get_receipt;
    out->get_balance = m_get_balance;
    out->erc20_balance = m_erc20_balance;
    out->tx_count = m_tx_count;
    out->estimate_gas = m_estimate_gas;
    out->gas_price = m_gas_price;
    out->max_priority_fee = m_max_priority_fee;
    out->send_raw = m_send_raw;
}

/* ═══ the libcurl transport ═══════════════════════════════════════════ */

/* One transport per provider: ONE easy handle for its whole life (so libcurl
 * re-uses the provider's open connection), re-created only when a POST asks
 * for it (drop_pool) and after every failed transfer; one header list, one
 * mutex that serialises the POSTs (libcurl-thread(3)), and counters. */
struct amm_rpc_curl {
    uint32_t           cap_ms;
    char               label[AMM_RPC_NAME_MAX];   /* the provider's log name, never the URL */
    CURL              *h;                         /* NULL only after a re-creation whose init failed */
    struct curl_slist *hdr;
    pthread_mutex_t    mu;
    uint64_t           performs, new_conns, failures, drops;
};

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

int amm_rpc_curl_global_init(void) {
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

/* (Re)create the easy handle; CURLOPT_MAXCONNECTS = 1 is a bound on the
 * connections (so the descriptors) one provider's handle keeps. mu held (or
 * the object not yet shared). 0 / -1, c->h NULL on -1. */
static int curl_handle_make(amm_rpc_curl_t *c) {
    c->h = curl_easy_init();
    if (!c->h) return -1;
    if (curl_easy_setopt(c->h, CURLOPT_MAXCONNECTS, 1L) != CURLE_OK) {
        curl_easy_cleanup(c->h);
        c->h = NULL;
        return -1;
    }
    return 0;
}

/* Close every connection of the old handle (curl_easy_cleanup) and make a new
 * one; counted in `drops`. mu held. 0 / -1. */
static int curl_handle_recreate(amm_rpc_curl_t *c) {
    if (c->h) curl_easy_cleanup(c->h);
    c->h = NULL;
    c->drops++;
    return curl_handle_make(c);
}

amm_rpc_curl_t *amm_rpc_curl_new(uint32_t timeout_cap_ms, const char *label) {
    if (timeout_cap_ms == 0 || !label || !*label || strlen(label) >= AMM_RPC_NAME_MAX)
        return NULL;
    amm_rpc_curl_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->cap_ms = timeout_cap_ms;
    snprintf(c->label, sizeof(c->label), "%s", label);
    c->hdr = curl_slist_append(NULL, "Content-Type: application/json");
    if (!c->hdr || pthread_mutex_init(&c->mu, NULL) != 0) {
        if (c->hdr) curl_slist_free_all(c->hdr);
        free(c);
        return NULL;
    }
    if (curl_handle_make(c) != 0) {
        pthread_mutex_destroy(&c->mu);
        curl_slist_free_all(c->hdr);
        free(c);
        return NULL;
    }
    return c;
}

void amm_rpc_curl_free(amm_rpc_curl_t *c) {
    if (!c) return;
    if (c->h) curl_easy_cleanup(c->h);
    curl_slist_free_all(c->hdr);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

void amm_rpc_curl_counts(amm_rpc_curl_t *c, uint64_t *performs, uint64_t *new_conns,
                         uint64_t *failures, uint64_t *drops) {
    if (!c) return;
    pthread_mutex_lock(&c->mu);
    if (performs) *performs = c->performs;
    if (new_conns) *new_conns = c->new_conns;
    if (failures) *failures = c->failures;
    if (drops) *drops = c->drops;
    pthread_mutex_unlock(&c->mu);
}

typedef struct {
    uint8_t *buf;
    size_t   cap, len;
} wr_t;

/* The size bound is enforced HERE, while receiving: a chunked or lying
 * response cannot grow past it (returning less than was offered aborts the
 * transfer with CURLE_WRITE_ERROR). */
static size_t wr_cb(char *p, size_t sz, size_t nm, void *u) {
    wr_t *w = u;
    if (sz != 0 && nm > SIZE_MAX / sz) return 0;
    size_t n = sz * nm;
    if (n > w->cap - w->len) return 0;
    memcpy(w->buf + w->len, p, n);
    w->len += n;
    return n;
}

/* The log lines of one post, composed under the transport's mutex and written
 * after it is released (no log call under mu). All carry the label; the URL
 * never. */
#define POST_LINES 4
typedef struct {
    int  n;
    int  warn[POST_LINES];
    char txt[POST_LINES][400];
} post_lines_t;

static void pl_add(post_lines_t *l, int warn, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void pl_add(post_lines_t *l, int warn, const char *fmt, ...) {
    if (l->n >= POST_LINES) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(l->txt[l->n], sizeof(l->txt[l->n]), fmt, ap);
    va_end(ap);
    l->warn[l->n++] = warn;
}

int amm_rpc_curl_post(void *ctx, const char *url, const uint8_t *body, size_t body_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len,
                      uint64_t deadline_ms, int drop_pool, amm_rpc_xfer_t *xf) {
    amm_rpc_curl_t *c = ctx;
    if (xf) {                                  /* written on every return, a refusal included */
        xf->new_conns = 0;
        xf->sock = AMM_RPC_SOCK_NONE;
    }
    if (!c || !url || !body || !resp || !resp_len || !xf || strncmp(url, "https://", 8) != 0)
        return AMM_ETH_ERR;
    post_lines_t pl;
    pl.n = 0;
    int result = AMM_ETH_ERR;
    wr_t w = { resp, resp_cap, 0 };

    pthread_mutex_lock(&c->mu);
    /* a re-creation asked for is done whenever it is asked, also when the
     * deadline has already passed, so no wrong-chain connection survives a
     * post that is refused for its deadline */
    if (drop_pool) {
        if (curl_handle_recreate(c) == 0)
            pl_add(&pl, 0, "%s: every connection dropped, the handle re-created (%llu since start)",
                   c->label, (unsigned long long)c->drops);
        else {
            /* this post fails; c->h stays NULL and the NEXT post that finds it
             * NULL tries curl_easy_init again */
            pl_add(&pl, 1, "%s: post: the handle could not be created", c->label);
            goto out;
        }
    }
    if (!c->h && curl_handle_make(c) != 0) {
        pl_add(&pl, 1, "%s: post: the handle could not be created", c->label);
        goto out;
    }
    uint64_t tmo = c->cap_ms;
    if (deadline_ms != 0) {
        uint64_t now = mono_ms();
        if (now >= deadline_ms) goto out;
        if (deadline_ms - now < tmo) tmo = deadline_ms - now;
    }
    {
        /* every option today's transport sets, on every call: options are
         * sticky, so a call never inherits the previous call's body, buffer
         * or timeout. CURLOPT_FRESH_CONNECT is never set. */
        CURL *h = c->h;
        CURLcode rc = CURLE_OK;
        rc |= curl_easy_setopt(h, CURLOPT_URL, url);
        rc |= curl_easy_setopt(h, CURLOPT_POST, 1L);
        rc |= curl_easy_setopt(h, CURLOPT_POSTFIELDS, (const char *)body);
        rc |= curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
        rc |= curl_easy_setopt(h, CURLOPT_HTTPHEADER, c->hdr);
        rc |= curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr_cb);
        rc |= curl_easy_setopt(h, CURLOPT_WRITEDATA, &w);
        /* TLS: peer and host verification ON, stated, never left to a default */
        rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
        rc |= curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
        /* https only, no redirect */
        rc |= curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
        rc |= curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "https");
        rc |= curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
        rc |= curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        rc |= curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, (long)tmo);
        rc |= curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, (long)tmo);
        if (rc != CURLE_OK) goto out;                 /* no perform started: nothing re-created */

        c->performs++;
        uint64_t t0 = mono_ms();
        CURLcode pr = curl_easy_perform(h);
        uint64_t took = mono_ms() - t0;
        long code = 0;
        int have_code = curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code) == CURLE_OK;
        /* read on the handle that made the transfer, before any re-creation */
        long nc = 0;
        if (curl_easy_getinfo(h, CURLINFO_NUM_CONNECTS, &nc) != CURLE_OK) nc = 1;   /* unknown: new */
        xf->new_conns = nc;
        c->new_conns += (uint64_t)nc;
        curl_off_t t_dns = 0, t_conn = 0, t_tls = 0, t_first = 0, t_tot = 0;
        (void)curl_easy_getinfo(h, CURLINFO_NAMELOOKUP_TIME_T, &t_dns);
        (void)curl_easy_getinfo(h, CURLINFO_CONNECT_TIME_T, &t_conn);
        (void)curl_easy_getinfo(h, CURLINFO_APPCONNECT_TIME_T, &t_tls);
        (void)curl_easy_getinfo(h, CURLINFO_STARTTRANSFER_TIME_T, &t_first);
        (void)curl_easy_getinfo(h, CURLINFO_TOTAL_TIME_T, &t_tot);
        char ph[160];
        snprintf(ph, sizeof(ph), "name lookup / connect / TLS / first byte / total %lld / %lld / %lld / %lld / %lld ms",
                 (long long)(t_dns / 1000), (long long)(t_conn / 1000), (long long)(t_tls / 1000),
                 (long long)(t_first / 1000), (long long)(t_tot / 1000));
        if (pr != CURLE_OK) {
            /* the cause, without the address (it may carry a key). The handle is
             * re-created at once: over HTTP/2 libcurl keeps a timed-out
             * connection, so the provider's next call would run on it again;
             * today's sequence closes it when the failed call returns. */
            c->failures++;
            int rec = curl_handle_recreate(c);
            if (rec == 0)
                pl_add(&pl, 1, "%s: post: transfer failed: %s (new connections for this request: %ld; %s); "
                       "the handle re-created after the failure (%llu re-creations since start)",
                       c->label, curl_easy_strerror(pr), nc, ph, (unsigned long long)c->drops);
            else
                pl_add(&pl, 1, "%s: post: transfer failed: %s (new connections for this request: %ld; %s); "
                       "the handle could not be re-created", c->label, curl_easy_strerror(pr), nc, ph);
            goto out;                                  /* xf->sock stays NONE: nothing cached */
        }
        curl_socket_t as = CURL_SOCKET_BAD;
        if (curl_easy_getinfo(h, CURLINFO_ACTIVESOCKET, &as) == CURLE_OK && as != CURL_SOCKET_BAD)
            xf->sock = (int64_t)as;                    /* else NONE: an unknown connection is never a verified one */
        if (took >= RPC_SLOW_MS)
            pl_add(&pl, 1, "%s: post: took %llu ms (%s)", c->label, (unsigned long long)took, ph);
        if (!have_code || code != 200) {
            pl_add(&pl, 1, "%s: post: HTTP status %ld", c->label, have_code ? code : 0L);
            goto out;
        }
        if (nc >= 1)
            pl_add(&pl, 0, "%s: a new connection was made for this request (%llu since start)",
                   c->label, (unsigned long long)c->new_conns);
        *resp_len = w.len;
        result = AMM_ETH_OK;
    }
out:
    pthread_mutex_unlock(&c->mu);
    for (int i = 0; i < pl.n; i++) {
        if (pl.warn[i]) QGP_LOG_WARN(LOG_TAG, "%s", pl.txt[i]);
        else QGP_LOG_INFO(LOG_TAG, "%s", pl.txt[i]);
    }
    return result;
}
