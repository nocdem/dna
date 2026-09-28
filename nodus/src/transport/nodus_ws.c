/**
 * Nodus — WebSocket entry: pure handshake + frame codec (RFC 6455)
 *
 * No sockets, no I/O, no logging: every function works on caller buffers
 * and reports through return values, so the transport glue (nodus_tcp.c)
 * decides what to log and the module can be fuzzed in isolation.
 * See nodus_ws.h for the contract of each function.
 */

#include "transport/nodus_ws.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* RFC 6455 §1.3: the GUID concatenated to Sec-WebSocket-Key. */
static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/* ── Small helpers ───────────────────────────────────────────────── */

static int ascii_lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/* Case-insensitive equality of a (ptr,len) field with a NUL-terminated
 * lowercase literal. */
static bool ci_eq(const char *s, size_t n, const char *lit) {
    size_t l = strlen(lit);
    if (n != l) return false;
    for (size_t i = 0; i < n; i++)
        if (ascii_lower((unsigned char)s[i]) != lit[i]) return false;
    return true;
}

static bool is_ows(char c) { return c == ' ' || c == '\t'; }

static void trim_ows(const char **s, size_t *n) {
    while (*n > 0 && is_ows(**s)) { (*s)++; (*n)--; }
    while (*n > 0 && is_ows((*s)[*n - 1])) (*n)--;
}

/* RFC 7230 §3.2.6 tchar. */
static bool is_tchar(unsigned char c) {
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        return true;
    return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* Does the comma-separated list value contain `token`? Elements are trimmed
 * of OWS; `ci` selects case-insensitive comparison (token must then be
 * lowercase). */
static bool list_has(const char *v, size_t n, const char *token, bool ci) {
    size_t tl = strlen(token);
    size_t i = 0;
    while (i <= n) {
        size_t j = i;
        while (j < n && v[j] != ',') j++;
        const char *e = v + i;
        size_t el = j - i;
        trim_ows(&e, &el);
        if (ci ? ci_eq(e, el, token) : (el == tl && memcmp(e, token, tl) == 0))
            return true;
        i = j + 1;
    }
    return false;
}

static int b64_val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* §4.2.1 item 5: base64 of exactly 16 bytes → 24 chars, "==" padding, and
 * the canonical form (the unused low 4 bits of the 22nd char are zero). */
static bool key_valid(const char *k, size_t n) {
    if (n != 24 || k[22] != '=' || k[23] != '=') return false;
    for (size_t i = 0; i < 22; i++)
        if (b64_val((unsigned char)k[i]) < 0) return false;
    return (b64_val((unsigned char)k[21]) & 0x0F) == 0;
}

/* ── Origins ─────────────────────────────────────────────────────── */

int nodus_ws_origins_add(nodus_ws_origins_t *o, const char *origin) {
    if (!o || !origin) return -1;
    if (o->count < 0 || o->count >= NODUS_WS_MAX_ORIGINS) return -1;
    size_t n = strlen(origin);
    if (n == 0 || n >= NODUS_WS_ORIGIN_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)origin[i];
        if (c <= 0x20 || c == 0x7F) return -1;
    }
    memcpy(o->origin[o->count], origin, n + 1);
    o->count++;
    return 0;
}

void nodus_ws_origins_default(nodus_ws_origins_t *o) {
    if (!o) return;
    memset(o, 0, sizeof(*o));
    (void)nodus_ws_origins_add(o, NODUS_WS_DEFAULT_ORIGIN);
}

static bool origin_allowed(const nodus_ws_origins_t *o, const char *v, size_t n) {
    if (!o) return false;
    for (int i = 0; i < o->count && i < NODUS_WS_MAX_ORIGINS; i++) {
        size_t l = strlen(o->origin[i]);
        if (l == n && memcmp(o->origin[i], v, n) == 0) return true;
    }
    return false;
}

/* ── Accept key / real IP ────────────────────────────────────────── */

int nodus_ws_accept_key(const char *key, size_t key_len,
                        char out[NODUS_WS_ACCEPT_LEN + 1]) {
    if (!key || !out || key_len > 64) return -1;
    unsigned char in[64 + sizeof(WS_GUID)];
    memcpy(in, key, key_len);
    memcpy(in + key_len, WS_GUID, sizeof(WS_GUID) - 1);

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_Digest(in, key_len + sizeof(WS_GUID) - 1, md, &md_len,
                   EVP_sha1(), NULL) != 1 || md_len != 20)
        return -1;
    /* 20 bytes → 28 base64 characters + NUL. */
    if (EVP_EncodeBlock((unsigned char *)out, md, 20) != NODUS_WS_ACCEPT_LEN)
        return -1;
    out[NODUS_WS_ACCEPT_LEN] = '\0';
    return 0;
}

int nodus_ws_real_ip(const char *sock_ip, const char *xff, size_t xff_len,
                     char out[64]) {
    if (!sock_ip || !out) return -1;
    if (strcmp(sock_ip, "127.0.0.1") != 0) {
        /* Not the local proxy: the socket address is the client. */
        int w = snprintf(out, 64, "%s", sock_ip);
        return (w > 0 && w < 64) ? 0 : -1;
    }
    if (!xff) return -1;

    /* LAST comma-separated element: the value the local proxy appended. */
    size_t start = xff_len;
    while (start > 0 && xff[start - 1] != ',') start--;
    const char *e = xff + start;
    size_t el = xff_len - start;
    trim_ows(&e, &el);
    if (el == 0 || el >= 64) return -1;

    char tmp[64];
    memcpy(tmp, e, el);
    tmp[el] = '\0';

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, tmp, &a4) == 1)
        return inet_ntop(AF_INET, &a4, out, 64) ? 0 : -1;
    if (inet_pton(AF_INET6, tmp, &a6) == 1)
        return inet_ntop(AF_INET6, &a6, out, 64) ? 0 : -1;
    return -1;
}

int nodus_ws_ip_bucket(const char *ip, nodus_ws_ip_bucket_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!ip) return -1;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip, &a4) == 1) {
        out->family = 4;
        memcpy(out->key, &a4.s_addr, 4);
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &a6) == 1) {
        if (IN6_IS_ADDR_V4MAPPED(&a6)) {
            out->family = 4;
            memcpy(out->key, a6.s6_addr + 12, 4);
        } else {
            out->family = 6;
            memcpy(out->key, a6.s6_addr, 8);
        }
        return 0;
    }
    return -1;
}

/* ── UTF-8 (RFC 3629 §4) ─────────────────────────────────────────── */

bool nodus_ws_utf8_valid(const uint8_t *s, size_t n) {
    if (!s) return n == 0;
    size_t i = 0;
    while (i < n) {
        uint8_t b = s[i];
        if (b < 0x80) { i++; continue; }

        size_t need;          /* continuation bytes after the lead */
        uint8_t lo = 0x80;    /* allowed range of the FIRST continuation */
        uint8_t hi = 0xBF;
        if (b >= 0xC2 && b <= 0xDF) {
            need = 1;
        } else if (b == 0xE0) {
            need = 2; lo = 0xA0;              /* no overlong 3-byte */
        } else if (b == 0xED) {
            need = 2; hi = 0x9F;              /* no surrogates */
        } else if (b >= 0xE1 && b <= 0xEF) {
            need = 2;
        } else if (b == 0xF0) {
            need = 3; lo = 0x90;              /* no overlong 4-byte */
        } else if (b >= 0xF1 && b <= 0xF3) {
            need = 3;
        } else if (b == 0xF4) {
            need = 3; hi = 0x8F;              /* nothing above U+10FFFF */
        } else {
            return false;     /* 0x80-0xC1 lead, or 0xF5-0xFF */
        }
        if (n - i - 1 < need) return false;   /* truncated */
        if (s[i + 1] < lo || s[i + 1] > hi) return false;
        for (size_t k = 2; k <= need; k++)
            if (s[i + k] < 0x80 || s[i + k] > 0xBF) return false;
        i += need + 1;
    }
    return true;
}

/* ── Opening handshake ───────────────────────────────────────────── */

static int hs_reject(nodus_ws_hs_result_t *res, int status, const char *reason) {
    res->status = status;
    res->reason = reason;
    return NODUS_WS_HS_REJECT;
}

int nodus_ws_handshake_parse(const uint8_t *buf, size_t len,
                             const char *sock_ip,
                             const nodus_ws_origins_t *origins,
                             nodus_ws_hs_result_t *res) {
    if (!res) return NODUS_WS_HS_REJECT;
    memset(res, 0, sizeof(*res));
    if (!buf || !sock_ip)
        return hs_reject(res, 0, "internal: null argument");

    /* 1. Find the end of the head within the first NODUS_WS_HS_MAX bytes. */
    size_t lim = len < NODUS_WS_HS_MAX ? len : NODUS_WS_HS_MAX;
    size_t head_len = 0;
    for (size_t i = 3; i < lim; i++) {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' &&
            buf[i - 1] == '\r' && buf[i] == '\n') {
            head_len = i + 1;
            break;
        }
    }
    if (head_len == 0) {
        if (len >= NODUS_WS_HS_MAX)
            return hs_reject(res, 0, "request head over 8 KiB");
        return NODUS_WS_HS_NEED_MORE;
    }

    /* 2. Byte hygiene: CR only before LF, LF only after CR, no controls. */
    for (size_t i = 0; i < head_len; i++) {
        uint8_t b = buf[i];
        if (b == '\n') {
            if (i == 0 || buf[i - 1] != '\r')
                return hs_reject(res, 400, "bare LF in request head");
        } else if (b == '\r') {
            if (i + 1 >= head_len || buf[i + 1] != '\n')
                return hs_reject(res, 400, "bare CR in request head");
        } else if ((b < 0x20 && b != '\t') || b == 0x7F) {
            return hs_reject(res, 400, "control byte in request head");
        }
    }

    const char *h = (const char *)buf;

    /* 3. Request line: GET <origin-form target> HTTP/1.1 */
    size_t pos = 0;
    size_t eol = pos;
    while (eol + 1 < head_len && !(h[eol] == '\r' && h[eol + 1] == '\n')) eol++;
    {
        const char *l = h;
        size_t ll = eol;
        static const char suffix[] = " HTTP/1.1";
        size_t sl = sizeof(suffix) - 1;
        if (ll < 4 + 1 + sl || memcmp(l, "GET ", 4) != 0 ||
            memcmp(l + ll - sl, suffix, sl) != 0)
            return hs_reject(res, 400, "request line is not GET ... HTTP/1.1");
        const char *t = l + 4;
        size_t tl = ll - 4 - sl;
        if (tl == 0 || t[0] != '/')
            return hs_reject(res, 400, "request target not origin-form");
        for (size_t i = 0; i < tl; i++)
            if (t[i] == ' ' || t[i] == '\t')
                return hs_reject(res, 400, "whitespace in request target");
    }
    pos = eol + 2;

    /* 4. Header fields. */
    int n_host = 0, n_key = 0, n_ver = 0, n_origin = 0;
    bool upgrade_ok = false, conn_ok = false, proto_binary = false;
    const char *key = NULL, *ver = NULL, *org = NULL, *xff = NULL;
    size_t key_n = 0, ver_n = 0, org_n = 0, xff_n = 0;
    bool host_empty = false;

    while (pos + 1 < head_len) {
        eol = pos;
        while (eol + 1 < head_len && !(h[eol] == '\r' && h[eol + 1] == '\n')) eol++;
        size_t ll = eol - pos;
        if (ll == 0) break;                          /* the empty line: end */
        const char *l = h + pos;
        pos = eol + 2;

        if (is_ows(l[0]))
            return hs_reject(res, 400, "obsolete header line folding");
        const char *colon = memchr(l, ':', ll);
        if (!colon || colon == l)
            return hs_reject(res, 400, "malformed header line");
        size_t nl = (size_t)(colon - l);
        for (size_t i = 0; i < nl; i++)
            if (!is_tchar((unsigned char)l[i]))
                return hs_reject(res, 400, "invalid header name");
        const char *v = colon + 1;
        size_t vn = ll - nl - 1;
        trim_ows(&v, &vn);

        if (ci_eq(l, nl, "host")) {
            n_host++;
            host_empty = (vn == 0);
        } else if (ci_eq(l, nl, "upgrade")) {
            if (list_has(v, vn, "websocket", true)) upgrade_ok = true;
        } else if (ci_eq(l, nl, "connection")) {
            if (list_has(v, vn, "upgrade", true)) conn_ok = true;
        } else if (ci_eq(l, nl, "sec-websocket-key")) {
            n_key++; key = v; key_n = vn;
        } else if (ci_eq(l, nl, "sec-websocket-version")) {
            n_ver++; ver = v; ver_n = vn;
        } else if (ci_eq(l, nl, "origin")) {
            n_origin++; org = v; org_n = vn;
        } else if (ci_eq(l, nl, "sec-websocket-protocol")) {
            if (list_has(v, vn, "binary", false)) proto_binary = true;
        } else if (ci_eq(l, nl, "x-forwarded-for")) {
            xff = v; xff_n = vn;                     /* the last line wins */
        }
    }

    /* 5. The §4.2.1 requirements, then this entry's own. */
    if (n_host != 1 || host_empty)
        return hs_reject(res, 400, "Host missing or repeated");
    if (!upgrade_ok)
        return hs_reject(res, 400, "Upgrade: websocket missing");
    if (!conn_ok)
        return hs_reject(res, 400, "Connection: Upgrade missing");
    if (n_ver != 1 || ver_n != 2 || memcmp(ver, "13", 2) != 0)
        return hs_reject(res, 426, "Sec-WebSocket-Version is not 13");
    if (n_key != 1 || !key_valid(key, key_n))
        return hs_reject(res, 400, "Sec-WebSocket-Key missing or invalid");
    if (n_origin != 1 || !origin_allowed(origins, org, org_n))
        return hs_reject(res, 403, "Origin missing or not allowed");
    if (nodus_ws_real_ip(sock_ip, xff, xff_n, res->real_ip) != 0)
        return hs_reject(res, 400, "X-Forwarded-For missing or malformed");
    if (nodus_ws_accept_key(key, key_n, res->accept) != 0)
        return hs_reject(res, 0, "internal: accept digest failed");

    res->proto_binary = proto_binary;
    res->consumed = head_len;
    return NODUS_WS_HS_OK;
}

size_t nodus_ws_handshake_response(const nodus_ws_hs_result_t *res,
                                   char *out, size_t cap) {
    if (!res || !out || cap == 0) return 0;
    int w = snprintf(out, cap,
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n"
                     "%s"
                     "\r\n",
                     res->accept,
                     res->proto_binary ? "Sec-WebSocket-Protocol: binary\r\n" : "");
    if (w <= 0 || (size_t)w >= cap) return 0;
    return (size_t)w;
}

size_t nodus_ws_reject_response(int status, char *out, size_t cap) {
    if (!out || cap == 0) return 0;
    const char *line;
    const char *extra = "";
    switch (status) {
    case 400: line = "400 Bad Request"; break;
    case 403: line = "403 Forbidden"; break;
    case 426: line = "426 Upgrade Required";
              extra = "Sec-WebSocket-Version: 13\r\n"; break;
    default:  return 0;
    }
    int w = snprintf(out, cap,
                     "HTTP/1.1 %s\r\n%sConnection: close\r\n"
                     "Content-Length: 0\r\n\r\n", line, extra);
    if (w <= 0 || (size_t)w >= cap) return 0;
    return (size_t)w;
}

/* ── Frame parser ────────────────────────────────────────────────── */

void nodus_ws_parser_init(nodus_ws_parser_t *p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    p->hdr_need = 2;
}

static int feed_fail(nodus_ws_parser_t *p, uint16_t *code, uint16_t c,
                     const char *reason) {
    p->closed = true;
    p->reason = reason;
    *code = c;
    return NODUS_WS_FEED_ERROR;
}

static bool is_control(uint8_t op) { return (op & 0x08) != 0; }

/* §7.4.1 / §7.4.2 plus the IANA-registered 1012-1014: codes a peer may put
 * in a close frame. 1004-1006 and 1015 are never sent. */
static bool close_code_valid(uint16_t c) {
    return (c >= 1000 && c <= 1003) || (c >= 1007 && c <= 1014) ||
           (c >= 3000 && c <= 4999);
}

/* Validate the first two header bytes; set hdr_need. 0 = ok. */
static int check_first_two(nodus_ws_parser_t *p, uint16_t *code) {
    uint8_t b0 = p->hdr[0], b1 = p->hdr[1];
    p->fin = (b0 & 0x80) != 0;
    p->opcode = b0 & 0x0F;
    if (b0 & 0x70)
        return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "RSV bit set");
    if (!(b1 & 0x80))
        return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "unmasked client frame");
    uint8_t len7 = b1 & 0x7F;

    switch (p->opcode) {
    case NODUS_WS_OP_TEXT:
        return feed_fail(p, code, NODUS_WS_CLOSE_UNSUPPORTED, "text frame");
    case NODUS_WS_OP_CONT:
        if (!p->in_message)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL,
                             "continuation without open message");
        break;
    case NODUS_WS_OP_BINARY:
        if (p->in_message)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL,
                             "new data frame inside open message");
        break;
    case NODUS_WS_OP_CLOSE:
    case NODUS_WS_OP_PING:
    case NODUS_WS_OP_PONG:
        if (!p->fin)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "fragmented control frame");
        if (len7 > NODUS_WS_CTRL_MAX)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "control frame over 125 bytes");
        break;
    default:
        return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "unknown opcode");
    }

    p->hdr_need = (uint8_t)(2 + (len7 == 126 ? 2 : (len7 == 127 ? 8 : 0)) + 4);
    return 0;
}

/* Header complete: decode length + mask. 0 = ok. */
static int finish_header(nodus_ws_parser_t *p, uint16_t *code) {
    uint8_t len7 = p->hdr[1] & 0x7F;
    uint64_t plen;
    size_t moff;
    if (len7 < 126) {
        plen = len7;
        moff = 2;
    } else if (len7 == 126) {
        plen = ((uint64_t)p->hdr[2] << 8) | p->hdr[3];
        if (plen < 126)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "non-minimal 16-bit length");
        moff = 4;
    } else {
        if (p->hdr[2] & 0x80)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "64-bit length MSB set");
        plen = 0;
        for (int i = 0; i < 8; i++)
            plen = (plen << 8) | p->hdr[2 + i];
        if (plen <= 0xFFFF)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "non-minimal 64-bit length");
        moff = 10;
    }
    /* Decided here, before a single payload byte is looked at. */
    if (!is_control(p->opcode) && plen > NODUS_WS_MAX_PAYLOAD)
        return feed_fail(p, code, NODUS_WS_CLOSE_TOO_BIG, "frame payload too large");

    memcpy(p->mask, p->hdr + moff, 4);
    p->mask_pos = 0;
    p->remaining = plen;
    p->ctrl_len = 0;
    p->in_payload = true;

    if (p->opcode == NODUS_WS_OP_BINARY && !p->fin)
        p->in_message = true;
    else if (p->opcode == NODUS_WS_OP_CONT && p->fin)
        p->in_message = false;
    return 0;
}

/* Payload complete: act on control frames, reset for the next header.
 * Returns a NODUS_WS_FEED_* value. */
static int finish_frame(nodus_ws_parser_t *p, const nodus_ws_sink_t *sink,
                        uint16_t *code) {
    p->in_payload = false;
    p->hdr_len = 0;
    p->hdr_need = 2;

    switch (p->opcode) {
    case NODUS_WS_OP_PING:
        if (sink && sink->on_ping &&
            sink->on_ping(sink->ctx, p->ctrl, p->ctrl_len) != 0)
            return feed_fail(p, code, NODUS_WS_CLOSE_INTERNAL, "pong could not be queued");
        return NODUS_WS_FEED_OK;
    case NODUS_WS_OP_CLOSE:
        if (p->ctrl_len == 0) {
            p->closed = true;
            p->reason = "peer close";
            *code = NODUS_WS_CLOSE_NO_STATUS;
            return NODUS_WS_FEED_PEER_CLOSE;
        }
        if (p->ctrl_len < 2)
            return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "close body of 1 byte");
        {
            uint16_t c = (uint16_t)(((uint16_t)p->ctrl[0] << 8) | p->ctrl[1]);
            if (!close_code_valid(c))
                return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "invalid close code");
            /* §5.5.1: the reason after the code is UTF-8; §8.1: invalid
             * UTF-8 fails the connection with 1007. */
            if (!nodus_ws_utf8_valid(p->ctrl + 2, (size_t)p->ctrl_len - 2))
                return feed_fail(p, code, NODUS_WS_CLOSE_INVALID_DATA,
                                 "close reason not UTF-8");
            p->closed = true;
            p->reason = "peer close";
            *code = c;
            return NODUS_WS_FEED_PEER_CLOSE;
        }
    default:
        return NODUS_WS_FEED_OK;     /* data frame end, or pong (ignored) */
    }
}

int nodus_ws_feed(nodus_ws_parser_t *p, uint8_t *in, size_t len,
                  const nodus_ws_sink_t *sink, uint16_t *code) {
    uint16_t dummy = 0;
    if (!code) code = &dummy;
    if (!p) return NODUS_WS_FEED_ERROR;
    if (p->closed)
        return feed_fail(p, code, NODUS_WS_CLOSE_PROTOCOL, "input after close");
    if (!in && len) return feed_fail(p, code, NODUS_WS_CLOSE_INTERNAL, "null input");

    size_t i = 0;
    while (i < len) {
        if (!p->in_payload) {
            p->hdr[p->hdr_len++] = in[i++];
            if (p->hdr_len == 2) {
                if (check_first_two(p, code) != 0) return NODUS_WS_FEED_ERROR;
            }
            if (p->hdr_len >= 2 && p->hdr_len == p->hdr_need) {
                if (finish_header(p, code) != 0) return NODUS_WS_FEED_ERROR;
                if (p->remaining == 0) {
                    int rc = finish_frame(p, sink, code);
                    if (rc != NODUS_WS_FEED_OK) return rc;
                }
            }
            continue;
        }

        size_t avail = len - i;
        size_t take = (p->remaining < (uint64_t)avail) ? (size_t)p->remaining : avail;
        uint8_t *d = in + i;
        for (size_t k = 0; k < take; k++)
            d[k] ^= p->mask[(p->mask_pos + k) & 3];
        p->mask_pos = (uint8_t)((p->mask_pos + take) & 3);

        if (is_control(p->opcode)) {
            /* ≤ 125 bytes total, enforced at the header. */
            memcpy(p->ctrl + p->ctrl_len, d, take);
            p->ctrl_len = (uint8_t)(p->ctrl_len + take);
        } else if (take > 0) {
            if (!sink || !sink->on_data || sink->on_data(sink->ctx, d, take) != 0)
                return feed_fail(p, code, NODUS_WS_CLOSE_TOO_BIG,
                                 "read buffer cannot take payload");
        }
        i += take;
        p->remaining -= take;
        if (p->remaining == 0) {
            int rc = finish_frame(p, sink, code);
            if (rc != NODUS_WS_FEED_OK) return rc;
        }
    }
    return NODUS_WS_FEED_OK;
}

/* ── Server → client frames ──────────────────────────────────────── */

size_t nodus_ws_frame_header_len(uint64_t payload_len) {
    if (payload_len < 126) return 2;
    if (payload_len <= 0xFFFF) return 4;
    return 10;
}

size_t nodus_ws_frame_header(uint8_t opcode, uint64_t payload_len,
                             uint8_t *out, size_t cap) {
    size_t hl = nodus_ws_frame_header_len(payload_len);
    if (!out || cap < hl) return 0;
    out[0] = (uint8_t)(0x80 | (opcode & 0x0F));
    if (hl == 2) {
        out[1] = (uint8_t)payload_len;
    } else if (hl == 4) {
        out[1] = 126;
        out[2] = (uint8_t)(payload_len >> 8);
        out[3] = (uint8_t)payload_len;
    } else {
        out[1] = 127;
        for (int i = 0; i < 8; i++)
            out[2 + i] = (uint8_t)(payload_len >> (8 * (7 - i)));
    }
    return hl;
}

size_t nodus_ws_close_frame(uint16_t code, uint8_t *out, size_t cap) {
    if (!out) return 0;
    if (code == NODUS_WS_CLOSE_NO_STATUS) {
        if (cap < 2) return 0;
        out[0] = 0x80 | NODUS_WS_OP_CLOSE;
        out[1] = 0;
        return 2;
    }
    if (cap < 4) return 0;
    out[0] = 0x80 | NODUS_WS_OP_CLOSE;
    out[1] = 2;
    out[2] = (uint8_t)(code >> 8);
    out[3] = (uint8_t)code;
    return 4;
}
