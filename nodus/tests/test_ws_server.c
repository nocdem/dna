/**
 * Nodus — WebSocket entry end-to-end test
 *
 * Starts a real nodus_server with ws_port set and drives its client
 * transport from THIS thread (nodus_tcp_poll on srv.tcp — no server thread),
 * so calling the handshake-timeout sweep with a synthetic clock cannot race
 * the event loop. A plain C client connects over loopback.
 *
 * What it proves (each would be false if it failed):
 *   1. An Upgrade with an allowed Origin and an X-Forwarded-For gets 101 with
 *      the correct Sec-WebSocket-Accept and the "binary" subprotocol echo.
 *   2. After the Upgrade the connection is an ordinary tier-2 client
 *      connection: a nodus "hello" frame carried in a masked binary WS frame
 *      is answered with a "challenge", itself carried in one unmasked binary
 *      WS frame — i.e. inbound bytes reach the nodus frame decoder and
 *      outbound nodus frames are wrapped.
 *   3. ping → pong with the same payload.
 *   4. A disallowed Origin gets 403 and the connection is closed.
 *   5. The per-real-IP limit counts WS connections by X-Forwarded-For:
 *      20 open connections with one XFF address are served, the 21st is
 *      closed without a 101.
 *   6. An Upgrade that never completes is closed by nodus_tcp_ws_sweep once
 *      NODUS_WS_HANDSHAKE_TIMEOUT_S has passed (clock passed in), and not
 *      before; open connections are never swept.
 *   7. A text frame on an open connection is answered with close 1003 and
 *      the connection is closed (the read-path teardown).
 *
 * Requires: a default build (no compile flags, no environment). Uses the
 * test-unique ports 15300-15305 (see nodus/CMakeLists.txt parallel-safety
 * note) and a /tmp data dir removed at the end.
 * How it can lie: the liveness bound on each wait is a ROUND count of
 * nodus_tcp_poll calls, not a timing claim; if the server never answers,
 * the check fails — it never passes by waiting.
 *
 * Test-runner output uses printf like every other nodus unit test.
 */

#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "transport/nodus_ws.h"
#include "protocol/nodus_wire.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define WS_PORT      15305
#define KEY_RFC      "dGhlIHNhbXBsZSBub25jZQ=="
#define ACCEPT_RFC   "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
#define XFF_IP       "198.51.100.7"
/* Upper bound on nodus_tcp_poll rounds per wait. A liveness bound only:
 * every wait below returns as soon as its condition holds. */
#define MAX_ROUNDS   400

static nodus_server_t g_srv;   /* static: far too large for the stack */

static void pump_once(void) {
    nodus_tcp_poll(&g_srv.tcp, 5);
}

/* ── Client helpers ──────────────────────────────────────────────── */

static int client_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(WS_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

typedef struct {
    uint8_t buf[65536];
    size_t  len;
    int     eof;       /* peer closed (0-byte read or reset) */
} rx_t;

/* Pull whatever the server has sent, pumping the server between reads. */
static void rx_poll(int fd, rx_t *rx) {
    pump_once();
    for (;;) {
        if (rx->len >= sizeof(rx->buf)) return;
        ssize_t r = recv(fd, rx->buf + rx->len, sizeof(rx->buf) - rx->len,
                         MSG_DONTWAIT);
        if (r > 0) { rx->len += (size_t)r; continue; }
        if (r == 0) { rx->eof = 1; return; }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) rx->eof = 1;
        return;
    }
}

static const uint8_t *find_seq(const uint8_t *b, size_t n, const char *s) {
    size_t sl = strlen(s);
    for (size_t i = 0; i + sl <= n; i++)
        if (memcmp(b + i, s, sl) == 0) return b + i;
    return NULL;
}

/* Wait for the end of the HTTP response head (or EOF). */
static int rx_http_head(int fd, rx_t *rx) {
    for (int i = 0; i < MAX_ROUNDS; i++) {
        rx_poll(fd, rx);
        if (find_seq(rx->buf, rx->len, "\r\n\r\n")) return 0;
        if (rx->eof) return -1;
    }
    return -1;
}

/* Wait until the server closes the connection. Returns 1 when it did. */
static int rx_until_eof(int fd, rx_t *rx) {
    for (int i = 0; i < MAX_ROUNDS; i++) {
        rx_poll(fd, rx);
        if (rx->eof) return 1;
    }
    return 0;
}

/* Parse one server→client frame at rx->buf[off]. Returns the total frame
 * size, 0 if incomplete, -1 if it is masked (server frames never are). */
static long server_frame_at(const rx_t *rx, size_t off, uint8_t *opcode,
                            const uint8_t **payload, uint64_t *plen) {
    if (rx->len < off + 2) return 0;
    const uint8_t *b = rx->buf + off;
    if (b[1] & 0x80) return -1;
    uint64_t l = b[1] & 0x7F;
    size_t h = 2;
    if (l == 126) {
        if (rx->len < off + 4) return 0;
        l = ((uint64_t)b[2] << 8) | b[3];
        h = 4;
    } else if (l == 127) {
        if (rx->len < off + 10) return 0;
        l = 0;
        for (int i = 0; i < 8; i++) l = (l << 8) | b[2 + i];
        h = 10;
    }
    if (rx->len < off + h + l) return 0;
    *opcode = b[0] & 0x0F;
    *payload = b + h;
    *plen = l;
    return (long)(h + l);
}

/* Wait for one complete server frame starting at `off`. */
static long rx_frame(int fd, rx_t *rx, size_t off, uint8_t *opcode,
                     const uint8_t **payload, uint64_t *plen) {
    for (int i = 0; i < MAX_ROUNDS; i++) {
        long n = server_frame_at(rx, off, opcode, payload, plen);
        if (n != 0) return n;
        if (rx->eof) return 0;
        rx_poll(fd, rx);
    }
    return 0;
}

/* Masked client frame (RFC 6455 §5.3). */
static size_t client_frame(uint8_t *out, uint8_t first, const uint8_t *p,
                           size_t n) {
    static const uint8_t key[4] = { 0x11, 0x22, 0x33, 0x44 };
    size_t o = 0;
    out[o++] = first;
    if (n < 126) {
        out[o++] = (uint8_t)(0x80 | n);
    } else {
        out[o++] = 0x80 | 126;
        out[o++] = (uint8_t)(n >> 8);
        out[o++] = (uint8_t)n;
    }
    memcpy(out + o, key, 4);
    o += 4;
    for (size_t i = 0; i < n; i++) out[o + i] = (uint8_t)(p[i] ^ key[i & 3]);
    return o + n;
}

static size_t upgrade_request(char *out, size_t cap, const char *origin,
                              const char *xff, int binary) {
    int w = snprintf(out, cap,
        "GET /ws HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " KEY_RFC "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: %s\r\n"
        "%s"
        "X-Forwarded-For: %s\r\n"
        "\r\n",
        WS_PORT, origin, binary ? "Sec-WebSocket-Protocol: binary\r\n" : "", xff);
    return (w > 0 && (size_t)w < cap) ? (size_t)w : 0;
}

/* Open a connection and complete the Upgrade. Returns fd, or -1. The 101
 * response is consumed; rx is left empty. */
static int ws_open_conn(const char *xff, rx_t *rx, int *got_101) {
    *got_101 = 0;
    int fd = client_connect();
    if (fd < 0) return -1;
    char req[1024];
    size_t n = upgrade_request(req, sizeof(req), NODUS_WS_DEFAULT_ORIGIN, xff, 1);
    memset(rx, 0, sizeof(*rx));
    if (n == 0 || send_all(fd, req, n) != 0 || rx_http_head(fd, rx) != 0)
        return fd;
    if (rx->len >= 12 && memcmp(rx->buf, "HTTP/1.1 101", 12) == 0) {
        *got_101 = 1;
        const uint8_t *end = find_seq(rx->buf, rx->len, "\r\n\r\n");
        size_t head = (size_t)(end - rx->buf) + 4;
        memmove(rx->buf, rx->buf + head, rx->len - head);
        rx->len -= head;
    }
    return fd;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static int  g_open_fds[NODUS_WS_MAX_CONNS_PER_IP + 1];
static int  g_open_count = 0;

static void test_upgrade_and_hello(nodus_identity_t *id) {
    rx_t *rx = calloc(1, sizeof(*rx));
    if (!rx) { TEST("upgrade"); FAIL("alloc"); return; }

    TEST("Upgrade → 101, RFC accept, binary echoed");
    int fd = client_connect();
    char req[1024];
    size_t n = upgrade_request(req, sizeof(req), NODUS_WS_DEFAULT_ORIGIN, XFF_IP, 1);
    int ok = fd >= 0 && n > 0 && send_all(fd, req, n) == 0 &&
             rx_http_head(fd, rx) == 0 &&
             rx->len >= 12 && memcmp(rx->buf, "HTTP/1.1 101", 12) == 0 &&
             find_seq(rx->buf, rx->len, "\r\nSec-WebSocket-Accept: " ACCEPT_RFC "\r\n") &&
             find_seq(rx->buf, rx->len, "\r\nSec-WebSocket-Protocol: binary\r\n");
    if (ok) PASS(); else { FAIL("no valid 101"); if (fd >= 0) close(fd); free(rx); return; }

    const uint8_t *end = find_seq(rx->buf, rx->len, "\r\n\r\n");
    size_t head = (size_t)(end - rx->buf) + 4;
    memmove(rx->buf, rx->buf + head, rx->len - head);
    rx->len -= head;

    TEST("conn->ip is the X-Forwarded-For address");
    {
        int found = 0;
        for (int i = 0; i < NODUS_TCP_MAX_CONNS; i++) {
            nodus_tcp_conn_t *c = g_srv.tcp.pool[i];
            if (c && c->is_ws && c->ws_open && strcmp(c->ip, XFF_IP) == 0) found++;
        }
        if (found == 1) PASS(); else FAIL("conn->ip is not the XFF address");
    }

    TEST("tier-2 hello in WS frame → challenge in WS frame");
    uint8_t *t2 = malloc(16384);
    uint8_t *nf = malloc(16384 + NODUS_FRAME_HEADER_SIZE);
    uint8_t *wf = malloc(16384 + NODUS_FRAME_HEADER_SIZE + 16);
    ok = 0;
    if (t2 && nf && wf) {
        size_t t2_len = 0;
        if (nodus_t2_hello(7, &id->pk, &id->node_id, t2, 16384, &t2_len) == 0) {
            size_t nf_len = nodus_frame_encode(nf, 16384 + NODUS_FRAME_HEADER_SIZE,
                                               t2, (uint32_t)t2_len);
            size_t wf_len = client_frame(wf, 0x82, nf, nf_len);
            if (nf_len > 0 && send_all(fd, wf, wf_len) == 0) {
                uint8_t op = 0;
                const uint8_t *pl = NULL;
                uint64_t pln = 0;
                long fl = rx_frame(fd, rx, 0, &op, &pl, &pln);
                nodus_frame_t fr;
                if (fl > 0 && op == NODUS_WS_OP_BINARY &&
                    nodus_frame_decode(pl, (size_t)pln, &fr) == (int)pln) {
                    nodus_tier2_msg_t msg;
                    memset(&msg, 0, sizeof(msg));
                    if (nodus_t2_decode(fr.payload, fr.payload_len, &msg) == 0 &&
                        strcmp(msg.method, "challenge") == 0 && msg.txn_id == 7)
                        ok = 1;
                    nodus_t2_msg_free(&msg);
                    memmove(rx->buf, rx->buf + fl, rx->len - (size_t)fl);
                    rx->len -= (size_t)fl;
                }
            }
        }
    }
    if (ok) PASS(); else FAIL("no challenge");
    free(t2); free(nf); free(wf);

    TEST("ping → pong with the same payload");
    uint8_t pf[16];
    size_t pfl = client_frame(pf, 0x89, (const uint8_t *)"hi", 2);
    ok = 0;
    if (send_all(fd, pf, pfl) == 0) {
        uint8_t op = 0;
        const uint8_t *pl = NULL;
        uint64_t pln = 0;
        long fl = rx_frame(fd, rx, 0, &op, &pl, &pln);
        if (fl > 0 && op == NODUS_WS_OP_PONG && pln == 2 && memcmp(pl, "hi", 2) == 0)
            ok = 1;
        if (fl > 0) {
            memmove(rx->buf, rx->buf + fl, rx->len - (size_t)fl);
            rx->len -= (size_t)fl;
        }
    }
    if (ok) PASS(); else FAIL("no pong");

    g_open_fds[g_open_count++] = fd;   /* stays open: counts toward the IP limit */
    free(rx);
}

static void test_origin_refused(void) {
    TEST("disallowed Origin → 403 and close");
    rx_t *rx = calloc(1, sizeof(*rx));
    int fd = client_connect();
    char req[1024];
    size_t n = upgrade_request(req, sizeof(req), "https://evil.example", XFF_IP, 0);
    int ok = rx && fd >= 0 && n > 0 && send_all(fd, req, n) == 0 &&
             rx_http_head(fd, rx) == 0 &&
             rx->len >= 12 && memcmp(rx->buf, "HTTP/1.1 403", 12) == 0 &&
             rx_until_eof(fd, rx) == 1;
    if (ok) PASS(); else FAIL("not refused");
    if (fd >= 0) close(fd);
    free(rx);
}

static void test_per_ip_limit(void) {
    TEST("20 WS conns from one XFF address are served");
    rx_t *rx = calloc(1, sizeof(*rx));
    if (!rx) { FAIL("alloc"); return; }
    int ok = 1;
    while (g_open_count < NODUS_WS_MAX_CONNS_PER_IP) {
        int got = 0;
        int fd = ws_open_conn(XFF_IP, rx, &got);
        if (fd < 0 || !got) { ok = 0; if (fd >= 0) close(fd); break; }
        g_open_fds[g_open_count++] = fd;
    }
    if (ok && g_open_count == NODUS_WS_MAX_CONNS_PER_IP) PASS();
    else FAIL("a connection under the limit was refused");

    TEST("21st WS conn from the same XFF address is closed");
    int got = 0;
    int fd = ws_open_conn(XFF_IP, rx, &got);
    ok = fd >= 0 && !got && rx_until_eof(fd, rx) == 1;
    if (ok) PASS(); else FAIL("limit not enforced");
    if (fd >= 0) close(fd);

    TEST("another XFF address is still served");
    fd = ws_open_conn("198.51.100.8", rx, &got);
    if (fd >= 0 && got) PASS(); else FAIL("other address refused");
    if (fd >= 0) close(fd);
    for (int i = 0; i < 20; i++) pump_once();   /* let the server see the close */
    free(rx);
}

static void test_handshake_timeout(void) {
    TEST("unfinished Upgrade: not swept before the timeout");
    rx_t *rx = calloc(1, sizeof(*rx));
    int fd = client_connect();
    int ok = rx && fd >= 0 && send_all(fd, "GET /ws HT", 10) == 0;
    for (int i = 0; ok && i < 20; i++) rx_poll(fd, rx);   /* accept + read */
    uint64_t now = nodus_time_now();
    int swept_early = ok ? nodus_tcp_ws_sweep(&g_srv.tcp, now) : -1;
    if (ok && swept_early == 0 && !rx->eof) PASS(); else FAIL("swept early");

    TEST("unfinished Upgrade: closed once the timeout passed");
    int swept = nodus_tcp_ws_sweep(&g_srv.tcp,
                                   now + NODUS_WS_HANDSHAKE_TIMEOUT_S + 1);
    /* Exactly one: the open connections of the earlier tests are never
     * swept, only the unfinished Upgrade. */
    ok = ok && swept == 1 && rx_until_eof(fd, rx) == 1;
    if (ok) PASS(); else FAIL("not closed by the sweep");
    if (fd >= 0) close(fd);
    free(rx);
}

static void test_text_frame_closes(void) {
    TEST("text frame on open conn → close 1003, then closed");
    if (g_open_count == 0) { FAIL("no open connection"); return; }
    rx_t *rx = calloc(1, sizeof(*rx));
    if (!rx) { FAIL("alloc"); return; }
    int fd = g_open_fds[--g_open_count];
    uint8_t tf[16];
    size_t tfl = client_frame(tf, 0x81, (const uint8_t *)"x", 1);
    int ok = 0;
    if (send_all(fd, tf, tfl) == 0) {
        uint8_t op = 0;
        const uint8_t *pl = NULL;
        uint64_t pln = 0;
        long fl = rx_frame(fd, rx, 0, &op, &pl, &pln);
        if (fl > 0 && op == NODUS_WS_OP_CLOSE && pln == 2 &&
            pl[0] == 0x03 && pl[1] == 0xEB && rx_until_eof(fd, rx) == 1)
            ok = 1;
    }
    if (ok) PASS(); else FAIL("no close 1003");
    close(fd);
    free(rx);
}

int main(void) {
    printf("nodus WebSocket entry end-to-end test\n");

    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));
    snprintf(config.bind_ip, sizeof(config.bind_ip), "127.0.0.1");
    config.udp_port     = 15300;
    config.tcp_port     = 15301;
    config.peer_port    = 15302;
    config.ch_port      = 15303;
    config.witness_port = 15304;
    config.ws_port      = WS_PORT;      /* origins left empty → default */
    snprintf(config.data_path, sizeof(config.data_path),
             "/tmp/nodus_ws_server_test_%d", (int)getpid());

    char cmd[320];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", config.data_path);
    if (system(cmd) != 0) {
        printf("cannot create %s\n", config.data_path);
        return 1;
    }

    if (nodus_server_init(&g_srv, &config) != 0) {
        printf("server init failed\n");
        nodus_server_close(&g_srv);
        snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
        if (system(cmd) != 0) printf("cleanup of %s failed\n", config.data_path);
        return 1;
    }

    TEST("WS entry listens on 127.0.0.1 with the default origin");
    if (g_srv.tcp.ws_listen_fd >= 0 && g_srv.tcp.ws_port == WS_PORT &&
        g_srv.config.ws_origins.count == 1 &&
        strcmp(g_srv.config.ws_origins.origin[0], NODUS_WS_DEFAULT_ORIGIN) == 0)
        PASS();
    else
        FAIL("listener / default origin");

    nodus_identity_t *id = calloc(1, sizeof(*id));
    if (!id || nodus_identity_generate(id) != 0) {
        printf("identity generation failed\n");
        failed++;
    } else {
        test_upgrade_and_hello(id);
        test_origin_refused();
        test_per_ip_limit();
        test_handshake_timeout();
        test_text_frame_closes();
    }

    for (int i = 0; i < g_open_count; i++) close(g_open_fds[i]);
    for (int i = 0; i < 20; i++) pump_once();
    if (id) {
        nodus_identity_clear(id);
        free(id);
    }
    nodus_server_close(&g_srv);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
    if (system(cmd) != 0) printf("cleanup of %s failed\n", config.data_path);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
