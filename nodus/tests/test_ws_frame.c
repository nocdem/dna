/**
 * Nodus — WebSocket frame codec tests (RFC 6455 §5)
 *
 * Pure-module tests for src/transport/nodus_ws.c: no socket, no server.
 * Pins down:
 *   - the RFC 6455 §1.3 Sec-WebSocket-Accept vector (SHA-1 via libcrypto);
 *   - unmasking against the RFC 6455 §5.7 masked "Hello" sample (with the
 *     opcode set to binary, since text frames are refused here);
 *   - 7-, 16- and 64-bit payload lengths;
 *   - streaming: the same frame stream fed whole and one byte at a time
 *     yields identical data and ping events;
 *   - fragmentation with an interleaved ping (§5.4, §5.5);
 *   - every refusal the entry relies on: unmasked, RSV bits, unknown opcode,
 *     text, control > 125, fragmented control, stray continuation, a new
 *     data frame inside an open message, non-minimal lengths, 64-bit MSB;
 *   - oversize length → 1009 decided at header completion, BEFORE any
 *     payload byte reaches the sink;
 *   - ping → pong frame bytes, peer close → echoed code, server frame
 *     headers for every length form.
 *
 * Test-runner output uses printf like every other nodus unit test; the
 * module under test logs nothing.
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

/* ── Capture sink ────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
    size_t   data_calls;
    int      pings;
    uint8_t  ping_payload[NODUS_WS_CTRL_MAX];
    size_t   ping_len;
    int      refuse_data;   /* on_data returns -1 when set */
} cap_t;

static int cap_on_data(void *ctx, const uint8_t *d, size_t n) {
    cap_t *c = (cap_t *)ctx;
    c->data_calls++;
    if (c->refuse_data) return -1;
    if (c->len + n > c->cap) {
        size_t nc = c->cap ? c->cap : 256;
        while (nc < c->len + n) nc *= 2;
        uint8_t *nb = realloc(c->data, nc);
        if (!nb) return -1;
        c->data = nb;
        c->cap = nc;
    }
    memcpy(c->data + c->len, d, n);
    c->len += n;
    return 0;
}

static int cap_on_ping(void *ctx, const uint8_t *p, size_t n) {
    cap_t *c = (cap_t *)ctx;
    c->pings++;
    memcpy(c->ping_payload, p, n);
    c->ping_len = n;
    return 0;
}

static void cap_reset(cap_t *c) {
    free(c->data);
    memset(c, 0, sizeof(*c));
}

static nodus_ws_sink_t sink_for(cap_t *c) {
    nodus_ws_sink_t s = { cap_on_data, cap_on_ping, c };
    return s;
}

/* ── Client frame builder (masked, §5.3) ─────────────────────────── */

/* Writes one client frame into out; returns its size. `len_form` forces the
 * length encoding: 0 = minimal, 126 / 127 = that form regardless of size. */
static size_t build_frame(uint8_t *out, uint8_t first_byte, int masked,
                          const uint8_t *payload, uint64_t plen,
                          int len_form) {
    static const uint8_t key[4] = { 0x37, 0xfa, 0x21, 0x3d };
    size_t o = 0;
    out[o++] = first_byte;
    uint8_t mbit = masked ? 0x80 : 0x00;
    int form = len_form;
    if (form == 0)
        form = plen < 126 ? 0 : (plen <= 0xFFFF ? 126 : 127);
    if (form == 0) {
        out[o++] = (uint8_t)(mbit | plen);
    } else if (form == 126) {
        out[o++] = (uint8_t)(mbit | 126);
        out[o++] = (uint8_t)(plen >> 8);
        out[o++] = (uint8_t)(plen);
    } else {
        out[o++] = (uint8_t)(mbit | 127);
        for (int i = 7; i >= 0; i--)
            out[o++] = (uint8_t)(plen >> (8 * i));
    }
    if (masked) {
        memcpy(out + o, key, 4);
        o += 4;
    }
    if (payload) {
        for (uint64_t i = 0; i < plen; i++)
            out[o + i] = masked ? (uint8_t)(payload[i] ^ key[i & 3]) : payload[i];
        o += (size_t)plen;
    }
    return o;
}

/* Feed all at once; returns the feed rc. */
static int feed_all(nodus_ws_parser_t *p, uint8_t *buf, size_t n,
                    cap_t *c, uint16_t *code) {
    nodus_ws_sink_t s = sink_for(c);
    return nodus_ws_feed(p, buf, n, &s, code);
}

/* Expect the stream to be refused with `want_code`. */
static void expect_error(const char *name, uint8_t *buf, size_t n,
                         uint16_t want_code) {
    TEST(name);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    uint16_t code = 0;
    int rc = feed_all(&p, buf, n, &c, &code);
    if (rc == NODUS_WS_FEED_ERROR && code == want_code && c.len == 0)
        PASS();
    else {
        char msg[96];
        snprintf(msg, sizeof(msg), "rc=%d code=%u data=%zu", rc,
                 (unsigned)code, c.len);
        FAIL(msg);
    }
    cap_reset(&c);
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_accept_vector(void) {
    TEST("RFC 6455 §1.3 Sec-WebSocket-Accept vector");
    char acc[NODUS_WS_ACCEPT_LEN + 1];
    const char *key = "dGhlIHNhbXBsZSBub25jZQ==";
    if (nodus_ws_accept_key(key, strlen(key), acc) == 0 &&
        strcmp(acc, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0)
        PASS();
    else
        FAIL("accept mismatch");
}

static void test_rfc_masked_hello(void) {
    TEST("RFC 6455 §5.7 masked \"Hello\" (binary opcode)");
    /* §5.7: 0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 — opcode
     * changed 0x1 → 0x2; mask and masked bytes unchanged. */
    uint8_t f[] = { 0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d,
                    0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    uint16_t code = 0;
    int rc = feed_all(&p, f, sizeof(f), &c, &code);
    if (rc == NODUS_WS_FEED_OK && c.len == 5 && memcmp(c.data, "Hello", 5) == 0)
        PASS();
    else
        FAIL("unmask");
    cap_reset(&c);
}

static void test_lengths(void) {
    static const uint64_t sizes[] = { 0, 1, 125, 126, 300, 65535, 65536, 70000 };
    for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
        char name[64];
        snprintf(name, sizeof(name), "length %llu decodes",
                 (unsigned long long)sizes[k]);
        TEST(name);
        uint64_t n = sizes[k];
        uint8_t *pl = malloc(n ? n : 1);
        uint8_t *fr = malloc(n + 16);
        if (!pl || !fr) { FAIL("alloc"); free(pl); free(fr); continue; }
        for (uint64_t i = 0; i < n; i++) pl[i] = (uint8_t)(i * 7 + 3);
        size_t fl = build_frame(fr, 0x82, 1, pl, n, 0);
        nodus_ws_parser_t p;
        nodus_ws_parser_init(&p);
        cap_t c;
        memset(&c, 0, sizeof(c));
        uint16_t code = 0;
        int rc = feed_all(&p, fr, fl, &c, &code);
        if (rc == NODUS_WS_FEED_OK && c.len == n &&
            (n == 0 || memcmp(c.data, pl, n) == 0) && !p.in_payload)
            PASS();
        else
            FAIL("mismatch");
        cap_reset(&c);
        free(pl);
        free(fr);
    }
}

/* Builds: binary FIN=0 "Hel" | ping "p!" | continuation FIN=0 "" |
 *         continuation FIN=1 "lo" | binary FIN=1 (300 bytes, 16-bit len) */
static size_t build_stream(uint8_t *out, uint8_t *tail_payload) {
    size_t o = 0;
    o += build_frame(out + o, 0x02, 1, (const uint8_t *)"Hel", 3, 0);
    o += build_frame(out + o, 0x89, 1, (const uint8_t *)"p!", 2, 0);
    o += build_frame(out + o, 0x00, 1, NULL, 0, 0);
    o += build_frame(out + o, 0x80, 1, (const uint8_t *)"lo", 2, 0);
    for (int i = 0; i < 300; i++) tail_payload[i] = (uint8_t)(0xA0 + i);
    o += build_frame(out + o, 0x82, 1, tail_payload, 300, 0);
    return o;
}

static void test_fragmented_with_ping(void) {
    TEST("fragmented message + interleaved ping");
    uint8_t buf[1024], tail[300];
    size_t n = build_stream(buf, tail);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    uint16_t code = 0;
    int rc = feed_all(&p, buf, n, &c, &code);
    if (rc == NODUS_WS_FEED_OK && c.len == 305 &&
        memcmp(c.data, "Hello", 5) == 0 && memcmp(c.data + 5, tail, 300) == 0 &&
        c.pings == 1 && c.ping_len == 2 && memcmp(c.ping_payload, "p!", 2) == 0 &&
        !p.in_message)
        PASS();
    else
        FAIL("stream mismatch");
    cap_reset(&c);
}

static void test_byte_at_a_time(void) {
    TEST("same stream fed one byte at a time");
    uint8_t buf[1024], tail[300];
    size_t n = build_stream(buf, tail);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    nodus_ws_sink_t s = sink_for(&c);
    int rc = NODUS_WS_FEED_OK;
    for (size_t i = 0; i < n && rc == NODUS_WS_FEED_OK; i++) {
        uint16_t code = 0;
        rc = nodus_ws_feed(&p, buf + i, 1, &s, &code);
    }
    if (rc == NODUS_WS_FEED_OK && c.len == 305 &&
        memcmp(c.data, "Hello", 5) == 0 && memcmp(c.data + 5, tail, 300) == 0 &&
        c.pings == 1 && memcmp(c.ping_payload, "p!", 2) == 0)
        PASS();
    else
        FAIL("byte-wise mismatch");
    cap_reset(&c);
}

static void test_split_points(void) {
    TEST("stream split at every offset in two calls");
    uint8_t ref[1024], tail[300];
    size_t n = build_stream(ref, tail);
    int bad = 0;
    for (size_t cut = 0; cut <= n && !bad; cut++) {
        uint8_t buf[1024];
        memcpy(buf, ref, n);
        nodus_ws_parser_t p;
        nodus_ws_parser_init(&p);
        cap_t c;
        memset(&c, 0, sizeof(c));
        nodus_ws_sink_t s = sink_for(&c);
        uint16_t code = 0;
        int rc = nodus_ws_feed(&p, buf, cut, &s, &code);
        if (rc == NODUS_WS_FEED_OK)
            rc = nodus_ws_feed(&p, buf + cut, n - cut, &s, &code);
        if (rc != NODUS_WS_FEED_OK || c.len != 305 || c.pings != 1 ||
            memcmp(c.data, "Hello", 5) != 0)
            bad = 1;
        cap_reset(&c);
    }
    if (!bad) PASS(); else FAIL("a split point diverged");
}

static void test_refusals(void) {
    uint8_t b[64];
    size_t n;

    n = build_frame(b, 0x82, 0, (const uint8_t *)"abc", 3, 0);
    expect_error("unmasked client frame → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x82 | 0x40, 1, (const uint8_t *)"abc", 3, 0);
    expect_error("RSV1 set → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x82 | 0x10, 1, (const uint8_t *)"abc", 3, 0);
    expect_error("RSV3 set → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x83, 1, (const uint8_t *)"abc", 3, 0);
    expect_error("unknown data opcode 0x3 → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x8B, 1, NULL, 0, 0);
    expect_error("unknown control opcode 0xB → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x81, 1, (const uint8_t *)"abc", 3, 0);
    expect_error("text frame → 1003", b, n, NODUS_WS_CLOSE_UNSUPPORTED);

    n = build_frame(b, 0x80, 1, (const uint8_t *)"abc", 3, 0);
    expect_error("continuation with no open message → 1002", b, n,
                 NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x09, 1, NULL, 0, 0);
    expect_error("fragmented ping (FIN=0) → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    /* Control frame announcing 126 bytes: refused at the second header byte. */
    b[0] = 0x89; b[1] = 0x80 | 126; b[2] = 0; b[3] = 126;
    expect_error("ping with 126-byte length → 1002", b, 4, NODUS_WS_CLOSE_PROTOCOL);

    /* ORCHESTRATOR repair: the stream model (spec item 6) hands each
     * fragment's payload to the sink as it arrives, so the first,
     * VALID fragment "a" is legitimately delivered before the second
     * header is seen; the violation is the second frame. Assert the
     * close code AND that only the valid fragment reached the sink. */
    n  = build_frame(b, 0x02, 1, (const uint8_t *)"a", 1, 0);
    n += build_frame(b + n, 0x82, 1, (const uint8_t *)"b", 1, 0);
    {
        TEST("new binary frame inside open message → 1002");
        nodus_ws_parser_t p;
        nodus_ws_parser_init(&p);
        cap_t c;
        memset(&c, 0, sizeof(c));
        uint16_t code = 0;
        int rc = feed_all(&p, b, n, &c, &code);
        if (rc == NODUS_WS_FEED_ERROR && code == NODUS_WS_CLOSE_PROTOCOL &&
            c.len == 1 && c.data[0] == 'a')
            PASS();
        else {
            char msg[96];
            snprintf(msg, sizeof(msg), "rc=%d code=%u data=%zu", rc,
                     (unsigned)code, c.len);
            FAIL(msg);
        }
        cap_reset(&c);
    }
}

static void test_refusals_lengths(void) {
    uint8_t b[64];
    size_t n;

    /* 16-bit form carrying 5 bytes: not minimal (§5.2 MUST). Only the header
     * is fed — the refusal must not need the payload. */
    n = build_frame(b, 0x82, 1, NULL, 5, 126);
    expect_error("non-minimal 16-bit length → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x82, 1, NULL, 300, 127);
    expect_error("non-minimal 64-bit length → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    n = build_frame(b, 0x82, 1, NULL, 0x8000000000000000ULL, 127);
    expect_error("64-bit length with MSB set → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);
}

static void test_oversize_no_touch(void) {
    TEST("oversize length → 1009 at header, sink never called");
    uint8_t b[32];
    size_t n = build_frame(b, 0x82, 1, NULL, NODUS_WS_MAX_PAYLOAD + 1, 0);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    uint16_t code = 0;
    int rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_ERROR && code == NODUS_WS_CLOSE_TOO_BIG &&
        c.data_calls == 0 && c.data == NULL)
        PASS();
    else
        FAIL("oversize not refused at header");
    cap_reset(&c);

    TEST("exactly NODUS_WS_MAX_PAYLOAD header is accepted");
    n = build_frame(b, 0x82, 1, NULL, NODUS_WS_MAX_PAYLOAD, 0);
    nodus_ws_parser_init(&p);
    memset(&c, 0, sizeof(c));
    rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_OK && p.in_payload &&
        p.remaining == NODUS_WS_MAX_PAYLOAD)
        PASS();
    else
        FAIL("max-size header refused");
    cap_reset(&c);
}

static void test_sink_refusal(void) {
    TEST("sink refusing data (buffer full) → 1009");
    uint8_t b[32];
    size_t n = build_frame(b, 0x82, 1, (const uint8_t *)"abc", 3, 0);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    c.refuse_data = 1;
    uint16_t code = 0;
    int rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_ERROR && code == NODUS_WS_CLOSE_TOO_BIG)
        PASS();
    else
        FAIL("refusal not propagated");
    cap_reset(&c);
}

static void test_ping_pong_bytes(void) {
    TEST("ping payload → pong frame bytes");
    uint8_t b[64];
    size_t n = build_frame(b, 0x89, 1, (const uint8_t *)"xyz", 3, 0);
    nodus_ws_parser_t p;
    nodus_ws_parser_init(&p);
    cap_t c;
    memset(&c, 0, sizeof(c));
    uint16_t code = 0;
    int rc = feed_all(&p, b, n, &c, &code);
    uint8_t pong[16];
    size_t h = nodus_ws_frame_header(NODUS_WS_OP_PONG, c.ping_len, pong, sizeof(pong));
    if (rc == NODUS_WS_FEED_OK && c.pings == 1 && c.ping_len == 3 &&
        memcmp(c.ping_payload, "xyz", 3) == 0 && c.len == 0 &&
        h == 2 && pong[0] == 0x8A && pong[1] == 0x03)
        PASS();
    else
        FAIL("pong");
    cap_reset(&c);

    TEST("pong from client is ignored");
    n = build_frame(b, 0x8A, 1, (const uint8_t *)"q", 1, 0);
    nodus_ws_parser_init(&p);
    memset(&c, 0, sizeof(c));
    rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_OK && c.pings == 0 && c.len == 0)
        PASS();
    else
        FAIL("pong handling");
    cap_reset(&c);
}

static void test_close(void) {
    uint8_t b[64];
    nodus_ws_parser_t p;
    cap_t c;
    uint16_t code = 0;
    int rc;
    size_t n;

    TEST("close 1000 → PEER_CLOSE echoing 1000");
    uint8_t body[2] = { 0x03, 0xE8 };
    n = build_frame(b, 0x88, 1, body, 2, 0);
    nodus_ws_parser_init(&p);
    memset(&c, 0, sizeof(c));
    rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_PEER_CLOSE && code == 1000 && p.closed) PASS();
    else FAIL("close 1000");
    cap_reset(&c);

    TEST("empty close → PEER_CLOSE with empty reply");
    n = build_frame(b, 0x88, 1, NULL, 0, 0);
    nodus_ws_parser_init(&p);
    memset(&c, 0, sizeof(c));
    rc = feed_all(&p, b, n, &c, &code);
    if (rc == NODUS_WS_FEED_PEER_CLOSE && code == NODUS_WS_CLOSE_NO_STATUS) PASS();
    else FAIL("empty close");
    cap_reset(&c);

    uint8_t one[1] = { 0x03 };
    n = build_frame(b, 0x88, 1, one, 1, 0);
    expect_error("close with 1-byte body → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    uint8_t bad[2] = { 0x03, 0xED };   /* 1005 must never be sent (§7.4.1) */
    n = build_frame(b, 0x88, 1, bad, 2, 0);
    expect_error("close carrying 1005 → 1002", b, n, NODUS_WS_CLOSE_PROTOCOL);

    TEST("input after close is refused");
    nodus_ws_parser_init(&p);
    memset(&c, 0, sizeof(c));
    n = build_frame(b, 0x88, 1, NULL, 0, 0);
    n += build_frame(b + n, 0x82, 1, (const uint8_t *)"z", 1, 0);
    rc = feed_all(&p, b, n, &c, &code);
    uint16_t code2 = 0;
    int rc2 = feed_all(&p, b, 1, &c, &code2);
    if (rc == NODUS_WS_FEED_PEER_CLOSE && c.len == 0 &&
        rc2 == NODUS_WS_FEED_ERROR)
        PASS();
    else
        FAIL("post-close input");
    cap_reset(&c);

    TEST("close frame bytes");
    uint8_t cf[8];
    size_t l1 = nodus_ws_close_frame(1002, cf, sizeof(cf));
    int ok = (l1 == 4 && cf[0] == 0x88 && cf[1] == 0x02 && cf[2] == 0x03 && cf[3] == 0xEA);
    size_t l2 = nodus_ws_close_frame(NODUS_WS_CLOSE_NO_STATUS, cf, sizeof(cf));
    ok = ok && (l2 == 2 && cf[0] == 0x88 && cf[1] == 0x00);
    if (ok) PASS(); else FAIL("close bytes");
}

static void test_server_headers(void) {
    TEST("server frame header: 7/16/64-bit forms, unmasked");
    uint8_t h[NODUS_WS_SERVER_HDR_MAX];
    int ok = 1;
    ok &= nodus_ws_frame_header(0x2, 125, h, sizeof(h)) == 2 && h[0] == 0x82 && h[1] == 125;
    ok &= nodus_ws_frame_header(0x2, 126, h, sizeof(h)) == 4 && h[1] == 126 &&
          h[2] == 0 && h[3] == 126;
    ok &= nodus_ws_frame_header(0x2, 65535, h, sizeof(h)) == 4 && h[2] == 0xFF && h[3] == 0xFF;
    ok &= nodus_ws_frame_header(0x2, 65536, h, sizeof(h)) == 10 && h[1] == 127 &&
          h[2] == 0 && h[7] == 1 && h[8] == 0 && h[9] == 0;
    ok &= nodus_ws_frame_header_len(125) == 2;
    ok &= nodus_ws_frame_header_len(126) == 4;
    ok &= nodus_ws_frame_header_len(65536) == 10;
    ok &= nodus_ws_frame_header(0x2, 65536, h, 9) == 0;   /* cap too small */
    if (ok) PASS(); else FAIL("header encoding");
}

int main(void) {
    printf("nodus WebSocket frame tests\n");
    test_accept_vector();
    test_rfc_masked_hello();
    test_lengths();
    test_fragmented_with_ping();
    test_byte_at_a_time();
    test_split_points();
    test_refusals();
    test_refusals_lengths();
    test_oversize_no_touch();
    test_sink_refusal();
    test_ping_pong_bytes();
    test_close();
    test_server_headers();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
