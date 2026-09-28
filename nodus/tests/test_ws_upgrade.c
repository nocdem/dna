/**
 * Nodus — WebSocket opening handshake tests (RFC 6455 §4.2.1 / §4.2.2)
 *
 * Pure-module tests for nodus_ws_handshake_parse / _response / _real_ip.
 * Pins down:
 *   - a valid request yields 101 with the RFC 6455 §1.3 accept value, and
 *     "Sec-WebSocket-Protocol: binary" only when the client offered it;
 *   - an incomplete head asks for more (every prefix of a valid request);
 *   - missing / wrong Upgrade, Connection, Version (426), Key, Host,
 *     Origin (403), method, HTTP version, bare-LF line ends, a bare CR
 *     inside a header line → refused;
 *   - a repeated Host (400), Origin (403), Sec-WebSocket-Version (426) or
 *     Sec-WebSocket-Key (400) is refused even when both values are valid;
 *   - a head over 8 KiB without its end → refused with no response, and so
 *     is a COMPLETE head of 8193 bytes (a head of exactly 8192 parses);
 *   - the real client IP is the LAST X-Forwarded-For value when the socket
 *     peer is 127.0.0.1; missing or malformed XFF from loopback → refused;
 *   - a non-loopback socket peer keeps its own address and XFF is ignored;
 *   - nodus_ws_ip_bucket (the per-IP limit key): IPv6 by /64, IPv4 whole,
 *     IPv4-mapped IPv6 as its IPv4, families never equal, junk → -1.
 *
 * Requires: a default build, no environment.
 *
 * Test-runner output uses printf like every other nodus unit test.
 */

#include "transport/nodus_ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-60s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

static nodus_ws_origins_t g_origins;

#define ORIGIN_OK  "https://wallet.nodusnetwork.io"
#define KEY_RFC    "dGhlIHNhbXBsZSBub25jZQ=="
#define ACCEPT_RFC "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

/* A request assembled from parts; any part may be replaced or dropped. */
typedef struct {
    const char *request_line;
    const char *host;
    const char *upgrade;
    const char *connection;
    const char *key;
    const char *version;
    const char *origin;
    const char *protocol;
    const char *xff;
    const char *extra;      /* raw extra header lines, CRLF-terminated */
} req_t;

static req_t req_default(void) {
    req_t r = {
        "GET /ws HTTP/1.1", "203.0.113.1", "websocket", "keep-alive, Upgrade",
        KEY_RFC, "13", ORIGIN_OK, NULL, "198.51.100.23", NULL
    };
    return r;
}

static size_t req_build(const req_t *r, char *out, size_t cap) {
    size_t o = 0;
#define ADD(...) do { int w_ = snprintf(out + o, cap - o, __VA_ARGS__); \
                      if (w_ > 0) o += (size_t)w_; } while (0)
    ADD("%s\r\n", r->request_line);
    if (r->host)       ADD("Host: %s\r\n", r->host);
    if (r->upgrade)    ADD("Upgrade: %s\r\n", r->upgrade);
    if (r->connection) ADD("Connection: %s\r\n", r->connection);
    if (r->key)        ADD("Sec-WebSocket-Key: %s\r\n", r->key);
    if (r->version)    ADD("Sec-WebSocket-Version: %s\r\n", r->version);
    if (r->origin)     ADD("Origin: %s\r\n", r->origin);
    if (r->protocol)   ADD("Sec-WebSocket-Protocol: %s\r\n", r->protocol);
    if (r->xff)        ADD("X-Forwarded-For: %s\r\n", r->xff);
    if (r->extra)      ADD("%s", r->extra);
    ADD("\r\n");
#undef ADD
    return o;
}

static int parse(const req_t *r, const char *sock_ip, nodus_ws_hs_result_t *res) {
    char buf[4096];
    size_t n = req_build(r, buf, sizeof(buf));
    memset(res, 0, sizeof(*res));
    return nodus_ws_handshake_parse((const uint8_t *)buf, n, sock_ip,
                                    &g_origins, res);
}

static void expect_reject(const char *name, const req_t *r, const char *sock_ip,
                          int want_status) {
    TEST(name);
    nodus_ws_hs_result_t res;
    int rc = parse(r, sock_ip, &res);
    if (rc == NODUS_WS_HS_REJECT && res.status == want_status && res.reason)
        PASS();
    else {
        char msg[96];
        snprintf(msg, sizeof(msg), "rc=%d status=%d", rc, res.status);
        FAIL(msg);
    }
}

static void test_valid(void) {
    TEST("valid request → OK, RFC accept, real IP from XFF");
    req_t r = req_default();
    nodus_ws_hs_result_t res;
    char buf[4096];
    size_t n = req_build(&r, buf, sizeof(buf));
    memset(&res, 0, sizeof(res));
    int rc = nodus_ws_handshake_parse((const uint8_t *)buf, n, "127.0.0.1",
                                      &g_origins, &res);
    if (rc == NODUS_WS_HS_OK && res.consumed == n &&
        strcmp(res.accept, ACCEPT_RFC) == 0 && !res.proto_binary &&
        strcmp(res.real_ip, "198.51.100.23") == 0)
        PASS();
    else
        FAIL("valid request");

    TEST("101 response carries the accept, no protocol header");
    char resp[512];
    size_t rl = nodus_ws_handshake_response(&res, resp, sizeof(resp));
    resp[rl < sizeof(resp) ? rl : sizeof(resp) - 1] = '\0';
    if (rl > 0 &&
        strncmp(resp, "HTTP/1.1 101 Switching Protocols\r\n", 34) == 0 &&
        strstr(resp, "\r\nSec-WebSocket-Accept: " ACCEPT_RFC "\r\n") &&
        strstr(resp, "\r\nUpgrade: websocket\r\n") &&
        strstr(resp, "\r\nConnection: Upgrade\r\n") &&
        !strstr(resp, "Sec-WebSocket-Protocol") &&
        rl >= 4 && memcmp(resp + rl - 4, "\r\n\r\n", 4) == 0)
        PASS();
    else
        FAIL("101 response");

    TEST("\"binary\" subprotocol offered → echoed in 101");
    r.protocol = "chat, binary";
    rc = parse(&r, "127.0.0.1", &res);
    rl = nodus_ws_handshake_response(&res, resp, sizeof(resp));
    resp[rl < sizeof(resp) ? rl : sizeof(resp) - 1] = '\0';
    if (rc == NODUS_WS_HS_OK && res.proto_binary &&
        strstr(resp, "\r\nSec-WebSocket-Protocol: binary\r\n"))
        PASS();
    else
        FAIL("binary protocol");

    TEST("header names and Upgrade/Connection tokens case-insensitive");
    char raw[1024];
    int w = snprintf(raw, sizeof(raw),
        "GET / HTTP/1.1\r\nhOsT: x\r\nUPGRADE: WebSocket\r\n"
        "connection: UPGRADE\r\nsec-websocket-key: %s\r\n"
        "SEC-WEBSOCKET-VERSION: 13\r\norigin: %s\r\n"
        "x-forwarded-for: 192.0.2.9\r\n\r\n", KEY_RFC, ORIGIN_OK);
    memset(&res, 0, sizeof(res));
    rc = nodus_ws_handshake_parse((const uint8_t *)raw, (size_t)w, "127.0.0.1",
                                  &g_origins, &res);
    if (rc == NODUS_WS_HS_OK && strcmp(res.real_ip, "192.0.2.9") == 0)
        PASS();
    else
        FAIL("case-insensitive");

    TEST("bytes after the head are not consumed");
    n = req_build(&r, buf, sizeof(buf));
    memcpy(buf + n, "\x82\x80", 2);
    memset(&res, 0, sizeof(res));
    rc = nodus_ws_handshake_parse((const uint8_t *)buf, n + 2, "127.0.0.1",
                                  &g_origins, &res);
    if (rc == NODUS_WS_HS_OK && res.consumed == n) PASS();
    else FAIL("consumed");
}

static void test_need_more(void) {
    TEST("every strict prefix of a valid head → NEED_MORE");
    req_t r = req_default();
    char buf[4096];
    size_t n = req_build(&r, buf, sizeof(buf));
    int bad = 0;
    for (size_t i = 0; i < n && !bad; i++) {
        nodus_ws_hs_result_t res;
        memset(&res, 0, sizeof(res));
        int rc = nodus_ws_handshake_parse((const uint8_t *)buf, i, "127.0.0.1",
                                          &g_origins, &res);
        if (rc != NODUS_WS_HS_NEED_MORE) bad = 1;
    }
    if (!bad) PASS(); else FAIL("prefix not NEED_MORE");
}

static void test_rejects(void) {
    req_t r;

    r = req_default(); r.version = NULL;
    expect_reject("missing Sec-WebSocket-Version → 426", &r, "127.0.0.1", 426);
    r = req_default(); r.version = "8";
    expect_reject("Sec-WebSocket-Version 8 → 426", &r, "127.0.0.1", 426);

    r = req_default(); r.key = NULL;
    expect_reject("missing Sec-WebSocket-Key → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.key = "c2hvcnQ=";                     /* 5 bytes */
    expect_reject("key not 16 bytes → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.key = "dGhlIHNhbXBsZSBub25jZQ!!";
    expect_reject("key not base64 → 400", &r, "127.0.0.1", 400);
    r = req_default();
    r.extra = "Sec-WebSocket-Key: " KEY_RFC "\r\n";
    expect_reject("duplicate Sec-WebSocket-Key → 400", &r, "127.0.0.1", 400);

    r = req_default(); r.origin = NULL;
    expect_reject("missing Origin → 403", &r, "127.0.0.1", 403);
    r = req_default(); r.origin = "https://evil.example";
    expect_reject("Origin not in list → 403", &r, "127.0.0.1", 403);
    r = req_default(); r.origin = ORIGIN_OK "/";
    expect_reject("Origin with trailing slash → 403 (exact match)", &r,
                  "127.0.0.1", 403);

    r = req_default(); r.upgrade = NULL;
    expect_reject("missing Upgrade → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.upgrade = "h2c";
    expect_reject("Upgrade not websocket → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.connection = "keep-alive";
    expect_reject("Connection without Upgrade token → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.connection = "Upgraded";
    expect_reject("Connection token must match whole → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.host = NULL;
    expect_reject("missing Host → 400", &r, "127.0.0.1", 400);

    r = req_default(); r.request_line = "POST /ws HTTP/1.1";
    expect_reject("method POST → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.request_line = "GET /ws HTTP/1.0";
    expect_reject("HTTP/1.0 → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.request_line = "GET ws HTTP/1.1";
    expect_reject("request target not origin-form → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.extra = "Bad Header: x\r\n";
    expect_reject("space in header name → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.extra = " folded\r\n";
    expect_reject("obsolete line folding → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.extra = "X-A: a\nX-B: b\r\n";
    expect_reject("bare LF line end → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.extra = "X-A: a\rb\r\n";
    expect_reject("bare CR inside a header line → 400", &r, "127.0.0.1", 400);

    /* Exactly one of each (RFC 6455 §4.2.1); the status is the one the
     * failed check answers with. */
    r = req_default(); r.extra = "Host: 203.0.113.2\r\n";
    expect_reject("duplicate Host → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.extra = "Origin: " ORIGIN_OK "\r\n";
    expect_reject("duplicate Origin (same value) → 403", &r, "127.0.0.1", 403);
    r = req_default(); r.extra = "Sec-WebSocket-Version: 13\r\n";
    expect_reject("duplicate Sec-WebSocket-Version (13) → 426", &r,
                  "127.0.0.1", 426);

    TEST("NUL byte in the head → 400");
    {
        req_t d = req_default();
        char buf[4096];
        size_t n = req_build(&d, buf, sizeof(buf));
        char *p = strstr(buf, "Host: ");
        p[6] = '\0';
        nodus_ws_hs_result_t res;
        memset(&res, 0, sizeof(res));
        int rc = nodus_ws_handshake_parse((const uint8_t *)buf, n, "127.0.0.1",
                                          &g_origins, &res);
        if (rc == NODUS_WS_HS_REJECT && res.status == 400) PASS();
        else FAIL("NUL accepted");
    }
}

static void test_oversize(void) {
    TEST("head exceeding 8 KiB without end → REJECT, no response");
    size_t n = NODUS_WS_HS_MAX + 16;
    char *buf = malloc(n);
    if (!buf) { FAIL("alloc"); return; }
    int w = snprintf(buf, n, "GET / HTTP/1.1\r\nX-Pad: ");
    memset(buf + w, 'a', n - (size_t)w);
    nodus_ws_hs_result_t res;
    memset(&res, 0, sizeof(res));
    int rc = nodus_ws_handshake_parse((const uint8_t *)buf, n, "127.0.0.1",
                                      &g_origins, &res);
    char out[256];
    if (rc == NODUS_WS_HS_REJECT && res.status == 0 &&
        nodus_ws_reject_response(res.status, out, sizeof(out)) == 0)
        PASS();
    else
        FAIL("oversize");

    TEST("head of exactly 8 KiB still parses");
    free(buf);
    buf = malloc(NODUS_WS_HS_MAX + 1);
    if (!buf) { FAIL("alloc"); return; }
    req_t r = req_default();
    size_t base = req_build(&r, buf, NODUS_WS_HS_MAX + 1);
    /* Rebuild with an X-Pad header sized so the head ends at 8192 bytes. */
    size_t pad = NODUS_WS_HS_MAX - base - strlen("X-Pad: \r\n");
    char *extra = malloc(pad + 16);
    if (!extra) { FAIL("alloc"); free(buf); return; }
    memcpy(extra, "X-Pad: ", 7);
    memset(extra + 7, 'b', pad);
    memcpy(extra + 7 + pad, "\r\n", 3);
    r.extra = extra;
    n = req_build(&r, buf, NODUS_WS_HS_MAX + 1);
    memset(&res, 0, sizeof(res));
    rc = nodus_ws_handshake_parse((const uint8_t *)buf, n, "127.0.0.1",
                                  &g_origins, &res);
    if (n == NODUS_WS_HS_MAX && rc == NODUS_WS_HS_OK) PASS();
    else FAIL("8 KiB head refused");
    free(extra);
    free(buf);

    /* The same head one byte longer: COMPLETE (it ends in CRLF CRLF), but
     * its end lies past the limit, so it must be refused like an endless
     * one — the limit is on the head, not on "a head without its end". */
    TEST("complete head of 8193 bytes → REJECT, no response");
    buf = malloc(NODUS_WS_HS_MAX + 2);
    extra = malloc(pad + 17);
    if (!buf || !extra) { FAIL("alloc"); free(buf); free(extra); return; }
    memcpy(extra, "X-Pad: ", 7);
    memset(extra + 7, 'b', pad + 1);
    memcpy(extra + 7 + pad + 1, "\r\n", 3);
    r.extra = extra;
    n = req_build(&r, buf, NODUS_WS_HS_MAX + 2);
    memset(&res, 0, sizeof(res));
    rc = nodus_ws_handshake_parse((const uint8_t *)buf, n, "127.0.0.1",
                                  &g_origins, &res);
    if (n == NODUS_WS_HS_MAX + 1 &&
        memcmp(buf + n - 4, "\r\n\r\n", 4) == 0 &&
        rc == NODUS_WS_HS_REJECT && res.status == 0 &&
        nodus_ws_reject_response(res.status, out, sizeof(out)) == 0)
        PASS();
    else
        FAIL("8193-byte head accepted");
    free(extra);
    free(buf);
}

static void test_ip_bucket(void) {
    nodus_ws_ip_bucket_t a, b;

    TEST("bucket: IPv6 in the same /64 → equal");
    int ok = nodus_ws_ip_bucket("2001:db8:1:2::1", &a) == 0 &&
             nodus_ws_ip_bucket("2001:db8:1:2:ffff:ffff:ffff:ffff", &b) == 0 &&
             a.family == 6 && memcmp(&a, &b, sizeof(a)) == 0;
    if (ok) PASS(); else FAIL("same /64 differs");

    TEST("bucket: IPv6 in another /64 → different");
    ok = nodus_ws_ip_bucket("2001:db8:1:2::1", &a) == 0 &&
         nodus_ws_ip_bucket("2001:db8:1:3::1", &b) == 0 &&
         memcmp(&a, &b, sizeof(a)) != 0;
    if (ok) PASS(); else FAIL("other /64 equal");

    TEST("bucket: IPv4 is the whole address");
    ok = nodus_ws_ip_bucket("198.51.100.7", &a) == 0 &&
         nodus_ws_ip_bucket("198.51.100.8", &b) == 0 &&
         a.family == 4 && memcmp(&a, &b, sizeof(a)) != 0 &&
         nodus_ws_ip_bucket("198.51.100.7", &b) == 0 &&
         memcmp(&a, &b, sizeof(a)) == 0;
    if (ok) PASS(); else FAIL("ipv4 key");

    TEST("bucket: IPv4-mapped IPv6 keyed as its IPv4");
    ok = nodus_ws_ip_bucket("::ffff:198.51.100.7", &a) == 0 &&
         nodus_ws_ip_bucket("198.51.100.7", &b) == 0 &&
         memcmp(&a, &b, sizeof(a)) == 0 &&
         nodus_ws_ip_bucket("::ffff:198.51.100.8", &b) == 0 &&
         memcmp(&a, &b, sizeof(a)) != 0;
    if (ok) PASS(); else FAIL("v4-mapped");

    TEST("bucket: IPv4 never equals an IPv6 bucket");
    ok = nodus_ws_ip_bucket("0.0.0.1", &a) == 0 &&
         nodus_ws_ip_bucket("::1", &b) == 0 &&
         memcmp(&a, &b, sizeof(a)) != 0;
    if (ok) PASS(); else FAIL("families collide");

    TEST("bucket: unparsable address → -1");
    ok = nodus_ws_ip_bucket("999.1.1.1", &a) == -1 &&
         nodus_ws_ip_bucket("garbage", &a) == -1 &&
         nodus_ws_ip_bucket(NULL, &a) == -1;
    if (ok) PASS(); else FAIL("bad address accepted");
}

static void test_real_ip(void) {
    req_t r;
    nodus_ws_hs_result_t res;

    TEST("XFF list → LAST value used");
    r = req_default(); r.xff = "10.0.0.1, 192.0.2.44";
    if (parse(&r, "127.0.0.1", &res) == NODUS_WS_HS_OK &&
        strcmp(res.real_ip, "192.0.2.44") == 0)
        PASS();
    else
        FAIL("last value");

    TEST("two XFF lines → last value of the last line");
    r = req_default(); r.xff = "10.0.0.1";
    r.extra = "X-Forwarded-For: 10.0.0.2, 192.0.2.45\r\n";
    if (parse(&r, "127.0.0.1", &res) == NODUS_WS_HS_OK &&
        strcmp(res.real_ip, "192.0.2.45") == 0)
        PASS();
    else
        FAIL("multi-line");

    TEST("IPv6 XFF value accepted");
    r = req_default(); r.xff = "2001:db8::1";
    if (parse(&r, "127.0.0.1", &res) == NODUS_WS_HS_OK &&
        strcmp(res.real_ip, "2001:db8::1") == 0)
        PASS();
    else
        FAIL("ipv6");

    r = req_default(); r.xff = NULL;
    expect_reject("loopback peer, no XFF → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.xff = "999.1.1.1";
    expect_reject("malformed XFF → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.xff = "192.0.2.1, ";
    expect_reject("empty last XFF element → 400", &r, "127.0.0.1", 400);
    r = req_default(); r.xff = "192.0.2.1:443";
    expect_reject("XFF with port → 400", &r, "127.0.0.1", 400);

    TEST("non-loopback peer: XFF ignored, socket IP kept");
    r = req_default(); r.xff = "192.0.2.77";
    if (parse(&r, "10.9.8.7", &res) == NODUS_WS_HS_OK &&
        strcmp(res.real_ip, "10.9.8.7") == 0)
        PASS();
    else
        FAIL("non-loopback");

    TEST("non-loopback peer: malformed XFF does not matter");
    r = req_default(); r.xff = "garbage";
    if (parse(&r, "10.9.8.7", &res) == NODUS_WS_HS_OK &&
        strcmp(res.real_ip, "10.9.8.7") == 0)
        PASS();
    else
        FAIL("non-loopback garbage");

    TEST("nodus_ws_real_ip direct: trims spaces, normalises");
    char out[64];
    const char *x = " 192.0.2.5 ,  192.0.2.6  ";
    if (nodus_ws_real_ip("127.0.0.1", x, strlen(x), out) == 0 &&
        strcmp(out, "192.0.2.6") == 0 &&
        nodus_ws_real_ip("127.0.0.1", NULL, 0, out) == -1)
        PASS();
    else
        FAIL("real_ip");
}

static void test_reject_responses(void) {
    TEST("reject responses: 400 / 403 / 426 (+Version: 13)");
    char out[256];
    size_t a = nodus_ws_reject_response(400, out, sizeof(out));
    int ok = a > 0 && strncmp(out, "HTTP/1.1 400 ", 13) == 0;
    size_t b = nodus_ws_reject_response(403, out, sizeof(out));
    ok = ok && b > 0 && strncmp(out, "HTTP/1.1 403 ", 13) == 0;
    size_t c = nodus_ws_reject_response(426, out, sizeof(out));
    out[c < sizeof(out) ? c : sizeof(out) - 1] = '\0';
    ok = ok && c > 0 && strncmp(out, "HTTP/1.1 426 ", 13) == 0 &&
         strstr(out, "\r\nSec-WebSocket-Version: 13\r\n") != NULL;
    if (ok) PASS(); else FAIL("responses");
}

static void test_origins_api(void) {
    TEST("origins: default, add, refuse bad entries");
    nodus_ws_origins_t o;
    nodus_ws_origins_default(&o);
    int ok = o.count == 1 && strcmp(o.origin[0], NODUS_WS_DEFAULT_ORIGIN) == 0;
    ok = ok && nodus_ws_origins_add(&o, "http://localhost:8080") == 0 && o.count == 2;
    ok = ok && nodus_ws_origins_add(&o, "") == -1;
    ok = ok && nodus_ws_origins_add(&o, "https://a b") == -1;
    ok = ok && nodus_ws_origins_add(&o, "https://x\r\n") == -1;
    for (int i = o.count; i < NODUS_WS_MAX_ORIGINS; i++)
        ok = ok && nodus_ws_origins_add(&o, "https://fill.example") == 0;
    ok = ok && nodus_ws_origins_add(&o, "https://overflow.example") == -1;
    if (ok) PASS(); else FAIL("origins");
}

int main(void) {
    printf("nodus WebSocket upgrade tests\n");
    nodus_ws_origins_default(&g_origins);
    test_valid();
    test_need_more();
    test_rejects();
    test_oversize();
    test_real_ip();
    test_ip_bucket();
    test_reject_responses();
    test_origins_api();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
