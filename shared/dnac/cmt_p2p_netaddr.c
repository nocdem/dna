/**
 * @file shared/dnac/cmt_p2p_netaddr.c
 * @brief cometbft @709fd12b `p2p/netaddress.go` + `p2p/key.go` (ID) +
 *        `p2p/errors.go` in C, with the Go standard library pieces they
 *        stand on (net.ParseIP / IP.String / SplitHostPort / JoinHostPort /
 *        IPNet.Contains, strconv.ParseUint, encoding/hex).
 *
 * Contract and deviations: cmt_p2p_netaddr.h. Functions in the
 * reference's order; each names its Go lines. Go standard library lines
 * are Go 1.21.5 (/usr/local/go/src — the local toolchain; the reference's
 * go.mod names 1.22.11).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_wire.h"      /* the NetAddress proto codec (F4) */
#include "dnac/cmt_validator_set.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ══ errors.go ════════════════════════════════════════════════════════ */

bool cmt_p2p_err_is_rejected(int err)
{
    switch (err) {
    case CMT_P2P_ERR_REJECTED_AUTH_FAILURE:
    case CMT_P2P_ERR_REJECTED_DUPLICATE:
    case CMT_P2P_ERR_REJECTED_FILTERED:
    case CMT_P2P_ERR_REJECTED_INCOMPATIBLE:
    case CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID:
    case CMT_P2P_ERR_REJECTED_SELF:
    case CMT_P2P_ERR_REJECTED_TIMEOUT:
        return true;
    default:
        return false;
    }
}

const char *cmt_p2p_err_str(int err)
{
    switch (err) {
    case CMT_P2P_ERR_NONE:                       return "ok";
    case CMT_P2P_ERR_FILTER_TIMEOUT:             return "filter timed out";
    case CMT_P2P_ERR_REJECTED_AUTH_FAILURE:      return "auth failure";
    case CMT_P2P_ERR_REJECTED_DUPLICATE:         return "duplicate";
    case CMT_P2P_ERR_REJECTED_FILTERED:          return "filtered";
    case CMT_P2P_ERR_REJECTED_INCOMPATIBLE:      return "incompatible";
    case CMT_P2P_ERR_REJECTED_NODE_INFO_INVALID: return "invalid NodeInfo";
    case CMT_P2P_ERR_REJECTED_SELF:              return "self";
    case CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_ID:   return "duplicate peer ID";
    case CMT_P2P_ERR_SWITCH_DUPLICATE_PEER_IP:   return "duplicate peer IP";
    case CMT_P2P_ERR_SWITCH_CONNECT_TO_SELF:     return "connect to self";
    case CMT_P2P_ERR_SWITCH_AUTH_FAILURE:        return "failed to authenticate peer";
    case CMT_P2P_ERR_TRANSPORT_CLOSED:           return "transport has been closed";
    case CMT_P2P_ERR_PEER_REMOVAL:               return "peer removal failed";
    case CMT_P2P_ERR_NETADDR_NO_ID:              return "address does not contain ID";
    case CMT_P2P_ERR_NETADDR_INVALID:            return "invalid address";
    case CMT_P2P_ERR_NETADDR_LOOKUP:             return "error looking up host";
    case CMT_P2P_ERR_CURRENTLY_DIALING_OR_EXISTING:
        return "connection has been established or dialed";
    case CMT_P2P_ERR_NET:                        return "network error";
    case CMT_P2P_ERR_REJECTED_TIMEOUT:           return "auth failure: handshake timeout";
    case CMT_P2P_ERR_NOT_RUNNING:                return "not running";
    case CMT_P2P_ERR_LIMIT:                      return "inbound connection limit reached";
    case CMT_P2P_ERR_BUSY:                       return "handshake job queue full";
    case CMT_FAULT:                              return "local fault";
    default:                                     return "unknown error";
    }
}

/* ══ key.go ═══════════════════════════════════════════════════════════ */

/* key.go:44 `PubKeyToID` = hex.EncodeToString(pubKey.Address()). The
 * address is the port's ONE derivation, cmt_pub_key_address
 * (cmt_validator_set.c:356 → cmt_address_hash). */
int cmt_p2p_pubkey_to_id(const uint8_t pk[CMT_P2P_NODE_PK_SIZE],
                         char out[CMT_P2P_ID_CAP])
{
    static const char hexd[] = "0123456789abcdef";
    cmt_pb_public_key_t *key;
    uint8_t addr[CMT_PB_ADDRESS_MAX];
    int rc;
    size_t i;

    if (pk == NULL || out == NULL) {
        return CMT_FAULT;
    }
    _Static_assert(CMT_PB_ADDRESS_MAX == CMT_P2P_ID_BYTE_LENGTH,
                   "the ID is the hex of one address");
    _Static_assert(CMT_PB_PUBKEY_LEN == CMT_P2P_NODE_PK_SIZE,
                   "the node key is the ML-DSA-87 key");
    key = (cmt_pb_public_key_t *)calloc(1, sizeof(*key));
    if (key == NULL) {
        return CMT_FAULT;
    }
    key->present = true;
    memcpy(key->key, pk, CMT_P2P_NODE_PK_SIZE);
    rc = cmt_pub_key_address(key, addr);
    free(key);
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    for (i = 0; i < CMT_P2P_ID_BYTE_LENGTH; i++) {
        out[2 * i]     = hexd[addr[i] >> 4];
        out[2 * i + 1] = hexd[addr[i] & 0x0Fu];
    }
    out[CMT_P2P_ID_HEX_LEN] = '\0';
    return CMT_OK;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* netaddress.go:407-419 `validateID`. hex.DecodeString refuses an odd
 * length or a non-hex byte (Go src/encoding/hex/hex.go:90-110); the
 * decoded length must be IDByteLength. */
int cmt_p2p_validate_id(const char *id, size_t len)
{
    size_t i;

    if (id == NULL || len == 0) {
        return CMT_P2P_ERR_NETADDR_INVALID;        /* :408-410 "no ID" */
    }
    for (i = 0; i < len; i++) {
        if (hex_val(id[i]) < 0) {
            return CMT_P2P_ERR_NETADDR_INVALID;    /* :411-414 */
        }
    }
    if (len % 2 != 0) {
        return CMT_P2P_ERR_NETADDR_INVALID;        /* ErrLength */
    }
    if (len / 2 != CMT_P2P_ID_BYTE_LENGTH) {
        return CMT_P2P_ERR_NETADDR_INVALID;        /* :415-417 */
    }
    return CMT_P2P_ERR_NONE;
}

/* ══ Go net.IP ════════════════════════════════════════════════════════ */

static const uint8_t V4_IN_V6_PREFIX[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0xff, 0xff };     /* ip.go:62 */

/* ip.go:52-60 `IPv4`. */
cmt_p2p_ip_t cmt_p2p_ip_v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    cmt_p2p_ip_t ip;

    memset(&ip, 0, sizeof(ip));
    memcpy(ip.b, V4_IN_V6_PREFIX, sizeof(V4_IN_V6_PREFIX));
    ip.b[12] = a;
    ip.b[13] = b;
    ip.b[14] = c;
    ip.b[15] = d;
    ip.len = CMT_P2P_IPV6_LEN;
    return ip;
}

/* ip.go:212-224 `To4`. */
bool cmt_p2p_ip_to4(const cmt_p2p_ip_t *ip, uint8_t out4[4])
{
    if (ip == NULL) {
        return false;
    }
    if (ip->len == CMT_P2P_IPV4_LEN) {
        if (out4 != NULL) {
            memcpy(out4, ip->b, 4);
        }
        return true;
    }
    if (ip->len == CMT_P2P_IPV6_LEN &&
        memcmp(ip->b, V4_IN_V6_PREFIX, sizeof(V4_IN_V6_PREFIX)) == 0) {
        if (out4 != NULL) {
            memcpy(out4, ip->b + 12, 4);
        }
        return true;
    }
    return false;
}

/* ip.go:359-370 `Equal`. */
bool cmt_p2p_ip_equal(const cmt_p2p_ip_t *a, const cmt_p2p_ip_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->len == b->len) {
        return memcmp(a->b, b->b, a->len) == 0;
    }
    if (a->len == CMT_P2P_IPV4_LEN && b->len == CMT_P2P_IPV6_LEN) {
        return memcmp(b->b, V4_IN_V6_PREFIX, 12) == 0 &&
               memcmp(a->b, b->b + 12, 4) == 0;
    }
    if (a->len == CMT_P2P_IPV6_LEN && b->len == CMT_P2P_IPV4_LEN) {
        return memcmp(a->b, V4_IN_V6_PREFIX, 12) == 0 &&
               memcmp(a->b + 12, b->b, 4) == 0;
    }
    return false;
}

/* ip.go:120-122 `IsUnspecified` — Equal(IPv4zero) || Equal(IPv6unspecified). */
bool cmt_p2p_ip_is_unspecified(const cmt_p2p_ip_t *ip)
{
    cmt_p2p_ip_t v4zero = cmt_p2p_ip_v4(0, 0, 0, 0);
    cmt_p2p_ip_t v6zero;

    memset(&v6zero, 0, sizeof(v6zero));
    v6zero.len = CMT_P2P_IPV6_LEN;
    return cmt_p2p_ip_equal(ip, &v4zero) || cmt_p2p_ip_equal(ip, &v6zero);
}

/* ip.go:125-130 `IsLoopback`. */
bool cmt_p2p_ip_is_loopback(const cmt_p2p_ip_t *ip)
{
    uint8_t v4[4];
    cmt_p2p_ip_t v6lo;

    if (cmt_p2p_ip_to4(ip, v4)) {
        return v4[0] == 127;
    }
    memset(&v6lo, 0, sizeof(v6lo));
    v6lo.b[15] = 1;
    v6lo.len = CMT_P2P_IPV6_LEN;
    return cmt_p2p_ip_equal(ip, &v6lo);
}

/* netip.go:155-194 `parseIPv4`. */
static bool parse_ipv4(const char *s, size_t len, uint8_t out[4])
{
    uint8_t fields[4] = { 0, 0, 0, 0 };
    int val = 0, pos = 0, dig_len = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        char c = s[i];

        if (c >= '0' && c <= '9') {
            if (dig_len == 1 && val == 0) {
                return false;                      /* :162-164 leading zero */
            }
            val = val * 10 + (c - '0');
            dig_len++;
            if (val > 255) {
                return false;                      /* :167-169 */
            }
        } else if (c == '.') {
            if (i == 0 || i == len - 1 || s[i - 1] == '.') {
                return false;                      /* :174-176 */
            }
            if (pos == 3) {
                return false;                      /* :178-180 */
            }
            fields[pos] = (uint8_t)val;
            pos++;
            val = 0;
            dig_len = 0;
        } else {
            return false;                          /* :185-187 */
        }
    }
    if (pos < 3) {
        return false;                              /* :189-191 */
    }
    fields[3] = (uint8_t)val;
    memcpy(out, fields, 4);
    return true;
}

/* netip.go:196-333 `parseIPv6`. A zone ('%') is refused outright: net's
 * parseIP (ip.go:501-507) refuses any address that has one. */
static bool parse_ipv6(const char *s, size_t len, uint8_t ip[16])
{
    int ellipsis = -1;
    int i = 0;
    size_t k;

    for (k = 0; k < len; k++) {
        if (s[k] == '%') {
            return false;
        }
    }
    memset(ip, 0, 16);
    if (len >= 2 && s[0] == ':' && s[1] == ':') {            /* :217-225 */
        ellipsis = 0;
        s += 2;
        len -= 2;
        if (len == 0) {
            return true;                            /* "::" */
        }
    }
    while (i < 16) {                                          /* :228 */
        size_t off = 0;
        uint32_t acc = 0;

        for (; off < len; off++) {
            char c = s[off];

            if (c >= '0' && c <= '9') {
                acc = (acc << 4) + (uint32_t)(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                acc = (acc << 4) + (uint32_t)(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                acc = (acc << 4) + (uint32_t)(c - 'A' + 10);
            } else {
                break;
            }
            if (acc > 0xFFFFu) {
                return false;                       /* :244-247 */
            }
        }
        if (off == 0) {
            return false;                           /* :249-252 */
        }
        if (off < len && s[off] == '.') {                     /* :255 */
            uint8_t v4[4];

            if (ellipsis < 0 && i != 12) {
                return false;                       /* :256-259 */
            }
            if (i + 4 > 16) {
                return false;                       /* :260-263 */
            }
            if (!parse_ipv4(s, len, v4)) {
                return false;                       /* :267-270 */
            }
            memcpy(ip + i, v4, 4);
            len = 0;
            i += 4;
            break;
        }
        ip[i] = (uint8_t)(acc >> 8);                          /* :281-283 */
        ip[i + 1] = (uint8_t)acc;
        i += 2;
        s += off;
        len -= off;
        if (len == 0) {
            break;                                            /* :286-289 */
        }
        if (s[0] != ':') {
            return false;                           /* :292-293 */
        } else if (len == 1) {
            return false;                           /* :294-295 */
        }
        s += 1;
        len -= 1;
        if (s[0] == ':') {                                    /* :300 */
            if (ellipsis >= 0) {
                return false;                       /* :301-303 */
            }
            ellipsis = i;
            s += 1;
            len -= 1;
            if (len == 0) {
                break;
            }
        }
    }
    if (len != 0) {
        return false;                               /* :312-314 */
    }
    if (i < 16) {                                             /* :317 */
        int n, j;

        if (ellipsis < 0) {
            return false;
        }
        n = 16 - i;
        for (j = i - 1; j >= ellipsis; j--) {
            ip[j + n] = ip[j];
        }
        for (j = ellipsis + n - 1; j >= ellipsis; j--) {
            ip[j] = 0;
        }
    } else if (ellipsis >= 0) {
        return false;                               /* :327-330 */
    }
    return true;
}

/* ip.go:494-507 `ParseIP` → netip.go:114-127 `ParseAddr`: the first '.'
 * or ':' decides the family; a '%' before either is refused. */
bool cmt_p2p_ip_parse(const char *s, size_t len, cmt_p2p_ip_t *out)
{
    size_t i;

    if (s == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            uint8_t v4[4];

            if (!parse_ipv4(s, len, v4)) {
                return false;
            }
            *out = cmt_p2p_ip_v4(v4[0], v4[1], v4[2], v4[3]);  /* As16 */
            return true;
        }
        if (s[i] == ':') {
            if (!parse_ipv6(s, len, out->b)) {
                memset(out, 0, sizeof(*out));
                return false;
            }
            out->len = CMT_P2P_IPV6_LEN;
            return true;
        }
        if (s[i] == '%') {
            return false;
        }
    }
    return false;
}

/* A bounded appender. */
typedef struct {
    char  *out;
    size_t cap;
    size_t n;
    bool   ok;
} sbuf_t;

static void sb_init(sbuf_t *b, char *out, size_t cap)
{
    b->out = out;
    b->cap = cap;
    b->n = 0;
    b->ok = (out != NULL && cap > 0);
    if (b->ok) {
        out[0] = '\0';
    }
}

static void sb_put(sbuf_t *b, const char *s, size_t len)
{
    if (!b->ok) {
        return;
    }
    if (len >= b->cap - b->n) {
        b->ok = false;
        return;
    }
    memcpy(b->out + b->n, s, len);
    b->n += len;
    b->out[b->n] = '\0';
}

static void sb_str(sbuf_t *b, const char *s)
{
    sb_put(b, s, strlen(s));
}

static size_t sb_done(sbuf_t *b)
{
    if (!b->ok) {
        if (b->out != NULL && b->cap > 0) {
            b->out[0] = '\0';
        }
        return 0;
    }
    return b->n;
}

/* netip.go:799-829 appendDecimal / appendHex. */
static void sb_dec8(sbuf_t *b, uint8_t x)
{
    char t[3];
    size_t n = 0;

    if (x >= 100) {
        t[n++] = (char)('0' + x / 100);
    }
    if (x >= 10) {
        t[n++] = (char)('0' + (x / 10) % 10);
    }
    t[n++] = (char)('0' + x % 10);
    sb_put(b, t, n);
}

static void sb_hex16(sbuf_t *b, uint16_t x)
{
    static const char d[] = "0123456789abcdef";
    char t[4];
    size_t n = 0;

    if (x >= 0x1000) {
        t[n++] = d[x >> 12];
    }
    if (x >= 0x100) {
        t[n++] = d[(x >> 8) & 0xF];
    }
    if (x >= 0x10) {
        t[n++] = d[(x >> 4) & 0xF];
    }
    t[n++] = d[x & 0xF];
    sb_put(b, t, n);
}

static void sb_ip(sbuf_t *b, const cmt_p2p_ip_t *ip)
{
    uint8_t v4[4];
    int i, zs = 255, ze = 255;

    if (ip->len == 0) {
        sb_str(b, "<nil>");                                 /* ip.go:296-298 */
        return;
    }
    if (ip->len != CMT_P2P_IPV4_LEN && ip->len != CMT_P2P_IPV6_LEN) {
        sb_str(b, "?");                                     /* unreachable */
        return;
    }
    if (cmt_p2p_ip_to4(ip, v4)) {                           /* ip.go:304-306 */
        sb_dec8(b, v4[0]);
        sb_str(b, ".");
        sb_dec8(b, v4[1]);
        sb_str(b, ".");
        sb_dec8(b, v4[2]);
        sb_str(b, ".");
        sb_dec8(b, v4[3]);
        return;
    }
    /* netip.go:873-906 appendTo6 — the longest run (>= 2) of zero groups,
     * the first on ties, becomes "::". */
    for (i = 0; i < 8; i++) {
        int j = i;

        while (j < 8 && ip->b[2 * j] == 0 && ip->b[2 * j + 1] == 0) {
            j++;
        }
        if (j - i >= 2 && j - i > ze - zs) {
            zs = i;
            ze = j;
        }
    }
    for (i = 0; i < 8; i++) {
        if (i == zs) {
            sb_str(b, "::");
            i = ze;
            if (i >= 8) {
                break;
            }
        } else if (i > 0) {
            sb_str(b, ":");
        }
        sb_hex16(b, (uint16_t)((ip->b[2 * i] << 8) | ip->b[2 * i + 1]));
    }
}

size_t cmt_p2p_ip_string(const cmt_p2p_ip_t *ip, char *out, size_t cap)
{
    sbuf_t b;

    sb_init(&b, out, cap);
    if (ip == NULL) {
        b.ok = false;
        return sb_done(&b);
    }
    sb_ip(&b, ip);
    return sb_done(&b);
}

/* ══ ipsock.go:164-219 SplitHostPort ═══════════════════════════════════ */

static const char *mem_chr(const char *s, size_t len, char c)
{
    return (const char *)memchr(s, c, len);
}

bool cmt_p2p_split_host_port(const char *s, size_t len,
                             const char **host, size_t *host_len,
                             const char **port, size_t *port_len)
{
    size_t i, j = 0, k = 0;
    bool found = false;

    if (s == NULL || host == NULL || host_len == NULL || port == NULL ||
        port_len == NULL) {
        return false;
    }
    /* :174-178 the port starts after the LAST colon */
    for (i = len; i > 0; i--) {
        if (s[i - 1] == ':') {
            found = true;
            break;
        }
    }
    if (!found) {
        return false;                              /* missing port */
    }
    i -= 1;                                        /* index of that ':' */
    if (s[0] == '[') {                                        /* :180 */
        const char *e = mem_chr(s, len, ']');
        size_t end;

        if (e == NULL) {
            return false;                          /* missing ']' */
        }
        end = (size_t)(e - s);
        if (end + 1 == len) {
            return false;                          /* missing port */
        } else if (end + 1 != i) {
            return false;                          /* too many colons / missing port */
        }
        *host = s + 1;
        *host_len = end - 1;
        j = 1;
        k = end + 1;
    } else {
        *host = s;
        *host_len = i;
        if (mem_chr(s, i, ':') != NULL) {
            return false;                          /* too many colons */
        }
    }
    if (mem_chr(s + j, len - j, '[') != NULL) {
        return false;                              /* :209-211 */
    }
    if (mem_chr(s + k, len - k, ']') != NULL) {
        return false;                              /* :212-214 */
    }
    *port = s + i + 1;
    *port_len = len - i - 1;
    return true;
}

/* ipsock.go:235-243 JoinHostPort. */
static void sb_join_host_port(sbuf_t *b, const char *host, const char *port)
{
    if (strchr(host, ':') != NULL) {
        sb_str(b, "[");
        sb_str(b, host);
        sb_str(b, "]:");
    } else {
        sb_str(b, host);
        sb_str(b, ":");
    }
    sb_str(b, port);
}

/* strconv.ParseUint(s, 10, 16) (Go src/strconv/atoi.go:77-160): digits
 * only — no sign, no prefix, no underscore at base 10 — non-empty, and
 * <= 65535. Leading zeros are accepted. */
static bool parse_port(const char *s, size_t len, uint16_t *out)
{
    uint32_t v = 0;
    size_t i;

    if (len == 0) {
        return false;
    }
    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10 + (uint32_t)(s[i] - '0');
        if (v > 0xFFFFu) {
            return false;
        }
    }
    *out = (uint16_t)v;
    return true;
}

/* ══ netaddress.go ════════════════════════════════════════════════════ */

/* netaddress.go:399-405 `removeProtocolIfDefined`: if "://" occurs, the
 * text between the first and the second occurrence (strings.Split(…)[1]). */
static void remove_protocol(const char *s, size_t len, const char **o,
                            size_t *olen)
{
    size_t i;

    for (i = 0; i + 3 <= len; i++) {
        if (s[i] == ':' && s[i + 1] == '/' && s[i + 2] == '/') {
            size_t start = i + 3, e;

            for (e = start; e + 3 <= len; e++) {
                if (s[e] == ':' && s[e + 1] == '/' && s[e + 2] == '/') {
                    break;
                }
            }
            if (e + 3 > len) {
                e = len;
            }
            *o = s + start;
            *olen = e - start;
            return;
        }
    }
    *o = s;
    *olen = len;
}

/* netaddress.go:33-36 */
size_t cmt_p2p_id_address_string(const char *id, const char *proto_host_port,
                                 size_t proto_host_port_len,
                                 char *out, size_t cap)
{
    sbuf_t b;
    const char *hp;
    size_t hp_len;

    sb_init(&b, out, cap);
    if (id == NULL || (proto_host_port == NULL && proto_host_port_len != 0)) {
        b.ok = false;
        return sb_done(&b);
    }
    remove_protocol(proto_host_port != NULL ? proto_host_port : "",
                    proto_host_port_len, &hp, &hp_len);
    sb_str(&b, id);
    sb_str(&b, "@");
    sb_put(&b, hp, hp_len);
    return sb_done(&b);
}

/* netaddress.go:43-64 */
int cmt_p2p_netaddr_new(const char *id, const cmt_p2p_ip_t *ip, uint16_t port,
                        cmt_p2p_netaddr_t *out)
{
    size_t idlen;

    if (id == NULL || ip == NULL || out == NULL) {
        return CMT_FAULT;
    }
    idlen = strlen(id);
    if (cmt_p2p_validate_id(id, idlen) != CMT_P2P_ERR_NONE) {
        return CMT_FAULT;                                  /* :55-57 panic */
    }
    *out = cmt_p2p_netaddr_new_ip_port(ip, port);          /* :59-61 */
    memcpy(out->id, id, idlen + 1);                        /* :62 */
    return CMT_OK;
}

/* netaddress.go:70-112 */
int cmt_p2p_netaddr_new_string(const char *s, size_t len,
                               cmt_p2p_netaddr_t *out)
{
    const char *a, *at, *host, *port;
    size_t alen, idlen, rest_len, host_len, port_len;
    cmt_p2p_ip_t ip;
    uint16_t p;

    if (s == NULL || out == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    remove_protocol(s, len, &a, &alen);                    /* :71 */
    /* :72-75 strings.Split(…, "@") must yield exactly two parts */
    at = mem_chr(a, alen, '@');
    if (at == NULL || mem_chr(at + 1, alen - (size_t)(at - a) - 1, '@') != NULL) {
        return CMT_P2P_ERR_NETADDR_NO_ID;
    }
    idlen = (size_t)(at - a);
    if (cmt_p2p_validate_id(a, idlen) != CMT_P2P_ERR_NONE) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :78-80 */
    }
    rest_len = alen - idlen - 1;
    if (!cmt_p2p_split_host_port(at + 1, rest_len, &host, &host_len,
                                 &port, &port_len)) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :85-88 */
    }
    if (host_len == 0) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :89-93 */
    }
    if (!cmt_p2p_ip_parse(host, host_len, &ip)) {
        /* :95-102 net.LookupIP — not done here (R-P2P-24). */
        return CMT_P2P_ERR_NETADDR_LOOKUP;
    }
    if (!parse_port(port, port_len, &p)) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :104-107 */
    }
    *out = cmt_p2p_netaddr_new_ip_port(&ip, p);            /* :109 */
    memcpy(out->id, a, idlen);                             /* :110 */
    out->id[idlen] = '\0';
    return CMT_P2P_ERR_NONE;
}

/* netaddress.go:132-137 */
cmt_p2p_netaddr_t cmt_p2p_netaddr_new_ip_port(const cmt_p2p_ip_t *ip,
                                              uint16_t port)
{
    cmt_p2p_netaddr_t na;

    memset(&na, 0, sizeof(na));
    if (ip != NULL) {
        na.ip = *ip;
    }
    na.port = port;
    return na;
}

/* ══ netaddress.go:139-186 — the proto conversions (phase F4) ═════════ */

/* types.pb.go `NetAddress.Unmarshal`. */
int cmt_p2p_netaddr_pb_unmarshal(const uint8_t *in, size_t len,
                                 cmt_p2p_netaddr_pb_t *pb)
{
    size_t off = 0;

    if ((in == NULL && len > 0) || pb == NULL) {
        return CMT_FAULT;
    }
    memset(pb, 0, sizeof(*pb));
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        if (fn == 1 || fn == 2) {                          /* ID, IP */
            const uint8_t *p;
            size_t n;

            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fn == 1) {
                pb->id = p;
                pb->id_len = n;
            } else {
                pb->ip = p;
                pb->ip_len = n;
            }
        } else if (fn == 3) {                              /* Port */
            uint64_t v;

            if (wt != 0 || cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            pb->port = (uint32_t)v;                        /* uint32 truncation */
        } else {
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* types.pb.go:357-382, written backward. */
int cmt_p2p_netaddr_pb_marshal(const cmt_p2p_netaddr_pb_t *pb, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    pb_w_t w;

    if (pb == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    w_init(&w, out, cap);
    wf_varint(&w, 3, pb->port);                            /* :362-366 */
    wf_bytes(&w, 2, pb->ip, pb->ip_len);                   /* :367-373 */
    wf_bytes(&w, 1, pb->id, pb->id_len);                   /* :374-380 */
    return w_finish(&w, out_len);
}

/* netaddress.go:139-153 */
int cmt_p2p_netaddr_from_proto(const cmt_p2p_netaddr_pb_t *pb,
                               cmt_p2p_netaddr_t *out)
{
    cmt_p2p_ip_t ip;

    if (pb == NULL || out == NULL || (pb->ip == NULL && pb->ip_len > 0) ||
        (pb->id == NULL && pb->id_len > 0)) {
        return CMT_FAULT;
    }
    if (!cmt_p2p_ip_parse((const char *)pb->ip, pb->ip_len, &ip)) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :141-143 */
    }
    if (pb->port >= (1u << 16)) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :144-146 */
    }
    *out = cmt_p2p_netaddr_new_ip_port(&ip, (uint16_t)pb->port);
    if (pb->id_len > CMT_P2P_ID_HEX_LEN) {                 /* file header */
        memcpy(out->id, CMT_P2P_NETADDR_OVERLONG_ID,
               sizeof(CMT_P2P_NETADDR_OVERLONG_ID));
    } else {
        if (pb->id_len > 0) {
            memcpy(out->id, pb->id, pb->id_len);           /* :148 ID(pb.ID) */
        }
        out->id[pb->id_len] = '\0';
    }
    return CMT_P2P_ERR_NONE;
}

/* netaddress.go:155-165 */
int cmt_p2p_netaddrs_from_proto(const cmt_p2p_netaddr_pb_t *pbs, int n,
                                cmt_p2p_netaddr_t *out)
{
    int i;

    if (n < 0 || (n > 0 && (pbs == NULL || out == NULL))) {
        return CMT_FAULT;
    }
    for (i = 0; i < n; i++) {
        int rc = cmt_p2p_netaddr_from_proto(&pbs[i], &out[i]);

        if (rc != CMT_P2P_ERR_NONE) {
            return rc;                                     /* :159-161 */
        }
    }
    return CMT_P2P_ERR_NONE;
}

/* netaddress.go:177-186 */
int cmt_p2p_netaddr_to_proto(const cmt_p2p_netaddr_t *na,
                             char ip_buf[CMT_P2P_IP_STR_MAX],
                             cmt_p2p_netaddr_pb_t *pb)
{
    size_t n;

    if (na == NULL || ip_buf == NULL || pb == NULL) {
        return CMT_FAULT;
    }
    n = cmt_p2p_ip_string(&na->ip, ip_buf, CMT_P2P_IP_STR_MAX);
    pb->id = (const uint8_t *)na->id;                      /* :180 */
    pb->id_len = strlen(na->id);
    pb->ip = (const uint8_t *)ip_buf;                      /* :181 IP.String() */
    pb->ip_len = n;
    pb->port = na->port;                                   /* :182 */
    return CMT_OK;
}

/* netaddress.go:167-175 */
int cmt_p2p_netaddrs_to_proto(const cmt_p2p_netaddr_t *const *nas, int n,
                              char (*ip_bufs)[CMT_P2P_IP_STR_MAX],
                              cmt_p2p_netaddr_pb_t *pbs)
{
    int i, k = 0;

    if (nas == NULL || ip_bufs == NULL || pbs == NULL) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (nas[i] != NULL &&                              /* :170 */
            cmt_p2p_netaddr_to_proto(nas[i], ip_bufs[k], &pbs[k]) == CMT_OK) {
            k++;
        }
    }
    return k;
}

static void sb_dial_string(sbuf_t *b, const cmt_p2p_netaddr_t *na)
{
    char ips[CMT_P2P_IP_STR_MAX];
    char ports[8];

    (void)cmt_p2p_ip_string(&na->ip, ips, sizeof(ips));
    (void)snprintf(ports, sizeof(ports), "%u", (unsigned)na->port);
    sb_join_host_port(b, ips, ports);
}

/* netaddress.go:211-222 */
size_t cmt_p2p_netaddr_string(const cmt_p2p_netaddr_t *na, char *out,
                              size_t cap)
{
    sbuf_t b;

    sb_init(&b, out, cap);
    if (na == NULL) {
        sb_str(&b, CMT_P2P_EMPTY_NET_ADDRESS);
        return sb_done(&b);
    }
    if (na->id[0] != '\0') {
        sb_str(&b, na->id);
        sb_str(&b, "@");
    }
    sb_dial_string(&b, na);
    return sb_done(&b);
}

/* netaddress.go:224-232 */
size_t cmt_p2p_netaddr_dial_string(const cmt_p2p_netaddr_t *na, char *out,
                                   size_t cap)
{
    sbuf_t b;

    sb_init(&b, out, cap);
    if (na == NULL) {
        sb_str(&b, CMT_P2P_EMPTY_NET_ADDRESS);
        return sb_done(&b);
    }
    sb_dial_string(&b, na);
    return sb_done(&b);
}

/* netaddress.go:190-195 */
bool cmt_p2p_netaddr_equals(const cmt_p2p_netaddr_t *a,
                            const cmt_p2p_netaddr_t *b)
{
    char sa[CMT_P2P_NETADDR_STR_MAX], sb[CMT_P2P_NETADDR_STR_MAX];

    if (a == NULL || b == NULL) {
        return false;
    }
    (void)cmt_p2p_netaddr_string(a, sa, sizeof(sa));
    (void)cmt_p2p_netaddr_string(b, sb, sizeof(sb));
    return strcmp(sa, sb) == 0;
}

/* netaddress.go:198-208 */
bool cmt_p2p_netaddr_same(const cmt_p2p_netaddr_t *a,
                          const cmt_p2p_netaddr_t *b)
{
    char sa[CMT_P2P_NETADDR_STR_MAX], sb[CMT_P2P_NETADDR_STR_MAX];

    if (a == NULL || b == NULL) {
        return false;
    }
    (void)cmt_p2p_netaddr_dial_string(a, sa, sizeof(sa));
    (void)cmt_p2p_netaddr_dial_string(b, sb, sizeof(sb));
    if (strcmp(sa, sb) == 0) {
        return true;
    }
    return a->id[0] != '\0' && strcmp(a->id, b->id) == 0;
}

/* IPNet.Contains (ip.go:424-462) for the networks below. */
typedef struct {
    uint8_t ip[16];
    uint8_t ones;
    bool    v4;          /* the network is IPv4 (4-byte number and mask) */
} ipnet_t;

static bool ipnet_contains(const ipnet_t *n, const cmt_p2p_ip_t *ip)
{
    uint8_t v4[4];
    const uint8_t *x;
    size_t l, i;
    unsigned ones = n->ones;

    if (cmt_p2p_ip_to4(ip, v4)) {
        x = v4;
        l = 4;
    } else {
        x = ip->b;
        l = ip->len;
    }
    if (l != (n->v4 ? 4u : 16u)) {
        return false;
    }
    for (i = 0; i < l; i++) {
        uint8_t m;

        if (ones >= 8) {
            m = 0xff;
            ones -= 8;
        } else {
            m = (uint8_t)~(0xffu >> ones);
            ones = 0;
        }
        if ((n->ip[i] & m) != (x[i] & m)) {
            return false;
        }
    }
    return true;
}

/* netaddress.go:348-360, :373 — the networks, as ParseIP + CIDRMask. */
static const ipnet_t RFC1918_10  = { { 10 }, 8, true };
static const ipnet_t RFC1918_192 = { { 192, 168 }, 16, true };
static const ipnet_t RFC1918_172 = { { 172, 16 }, 12, true };
static const ipnet_t RFC3849     = { { 0x20, 0x01, 0x0d, 0xb8 }, 32, false };
static const ipnet_t RFC3927     = { { 169, 254 }, 16, true };
static const ipnet_t RFC3964     = { { 0x20, 0x02 }, 16, false };
static const ipnet_t RFC4193     = { { 0xfc }, 7, false };
static const ipnet_t RFC4380     = { { 0x20, 0x01 }, 32, false };
static const ipnet_t RFC4843     = { { 0x20, 0x01, 0x00, 0x10 }, 28, false };
static const ipnet_t RFC4862     = { { 0xfe, 0x80 }, 64, false };
static const ipnet_t RFC6052     = { { 0x00, 0x64, 0xff, 0x9b }, 96, false };
static const ipnet_t RFC6145     = { { 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }, 96, false };
static const ipnet_t ZERO4       = { { 0 }, 8, true };
static const ipnet_t ONION_CAT   = { { 0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43 }, 48, false };

/* netaddress.go:383-397 */
bool cmt_p2p_netaddr_rfc1918(const cmt_p2p_netaddr_t *na)
{
    return na != NULL && (ipnet_contains(&RFC1918_10, &na->ip) ||
                          ipnet_contains(&RFC1918_192, &na->ip) ||
                          ipnet_contains(&RFC1918_172, &na->ip));
}
bool cmt_p2p_netaddr_rfc3849(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC3849, &na->ip); }
bool cmt_p2p_netaddr_rfc3927(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC3927, &na->ip); }
bool cmt_p2p_netaddr_rfc3964(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC3964, &na->ip); }
bool cmt_p2p_netaddr_rfc4193(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC4193, &na->ip); }
bool cmt_p2p_netaddr_rfc4380(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC4380, &na->ip); }
bool cmt_p2p_netaddr_rfc4843(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC4843, &na->ip); }
bool cmt_p2p_netaddr_rfc4862(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC4862, &na->ip); }
bool cmt_p2p_netaddr_rfc6052(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC6052, &na->ip); }
bool cmt_p2p_netaddr_rfc6145(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&RFC6145, &na->ip); }
bool cmt_p2p_netaddr_onion_cat_tor(const cmt_p2p_netaddr_t *na)
{ return na != NULL && ipnet_contains(&ONION_CAT, &na->ip); }

/* netaddress.go:263-275 */
int cmt_p2p_netaddr_valid(const cmt_p2p_netaddr_t *na)
{
    cmt_p2p_ip_t bcast = cmt_p2p_ip_v4(255, 255, 255, 255);

    if (na == NULL) {
        return CMT_P2P_ERR_NETADDR_INVALID;
    }
    if (cmt_p2p_validate_id(na->id, strlen(na->id)) != CMT_P2P_ERR_NONE) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :264-266 */
    }
    if (na->ip.len == 0) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :268-270 "no IP" */
    }
    if (cmt_p2p_ip_is_unspecified(&na->ip) || cmt_p2p_netaddr_rfc3849(na) ||
        cmt_p2p_ip_equal(&na->ip, &bcast)) {
        return CMT_P2P_ERR_NETADDR_INVALID;                /* :271-273 */
    }
    return CMT_P2P_ERR_NONE;
}

/* netaddress.go:278-281 */
bool cmt_p2p_netaddr_has_id(const cmt_p2p_netaddr_t *na)
{
    return na != NULL && na->id[0] != '\0';
}

/* netaddress.go:284-286 */
bool cmt_p2p_netaddr_local(const cmt_p2p_netaddr_t *na)
{
    return na != NULL && (cmt_p2p_ip_is_loopback(&na->ip) ||
                          ipnet_contains(&ZERO4, &na->ip));
}

/* netaddress.go:253-259 */
bool cmt_p2p_netaddr_routable(const cmt_p2p_netaddr_t *na)
{
    if (cmt_p2p_netaddr_valid(na) != CMT_P2P_ERR_NONE) {
        return false;
    }
    return !cmt_p2p_netaddr_rfc1918(na) && !cmt_p2p_netaddr_rfc3927(na) &&
           !cmt_p2p_netaddr_rfc4862(na) && !cmt_p2p_netaddr_rfc4193(na) &&
           !cmt_p2p_netaddr_rfc4843(na) && !cmt_p2p_netaddr_local(na);
}

/* netaddress.go:289-336. The constants (:290-297): Unreachable = 0, then
 * iota continues at 1 — Default 1, Teredo 2, Ipv6Weak 3, Ipv4 4,
 * Ipv6Strong 5. */
int cmt_p2p_netaddr_reachability_to(const cmt_p2p_netaddr_t *na,
                                    const cmt_p2p_netaddr_t *o)
{
    enum { UNREACHABLE = 0, DEFAULT = 1, TEREDO = 2, IPV6_WEAK = 3,
           IPV4 = 4, IPV6_STRONG = 5 };
    bool tunneled;

    if (na == NULL || o == NULL) {
        return UNREACHABLE;
    }
    if (!cmt_p2p_netaddr_routable(na)) {
        return UNREACHABLE;
    }
    if (cmt_p2p_netaddr_rfc4380(na)) {
        if (!cmt_p2p_netaddr_routable(o)) {
            return DEFAULT;
        }
        if (cmt_p2p_netaddr_rfc4380(o)) {
            return TEREDO;
        }
        if (cmt_p2p_ip_to4(&o->ip, NULL)) {
            return IPV4;
        }
        return IPV6_WEAK;
    }
    if (cmt_p2p_ip_to4(&na->ip, NULL)) {
        if (cmt_p2p_netaddr_routable(o) && cmt_p2p_ip_to4(&o->ip, NULL)) {
            return IPV4;
        }
        return DEFAULT;
    }
    tunneled = cmt_p2p_netaddr_rfc3964(o) || cmt_p2p_netaddr_rfc6052(o) ||
               cmt_p2p_netaddr_rfc6145(o);
    if (!cmt_p2p_netaddr_routable(o)) {
        return DEFAULT;
    }
    if (cmt_p2p_netaddr_rfc4380(o)) {
        return TEREDO;
    }
    if (cmt_p2p_ip_to4(&o->ip, NULL)) {
        return IPV4;
    }
    if (tunneled) {
        return IPV6_WEAK;
    }
    return IPV6_STRONG;
}
