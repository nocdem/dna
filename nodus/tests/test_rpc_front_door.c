/**
 * Nodus — client-port front door (simple version, operator 2026-10-14;
 * decision docs/plans/decisions/2026-10-14-kurultay-20-summary.md)
 *
 * What it proves (each would be false if it failed):
 *   1. SPEND COST: nodus_chain_spend_units(len) = ceil(len / 4627), at
 *      least 1 — 0 and 1 → 1, 4627 → 1, 4628 → 2, 1 MiB → 227 — and the
 *      1 MiB cost fits NODUS_CHAIN_RATE_BUDGET.
 *   2. CHAIN BUDGET: nodus_session_chain_charge, driven with an injected
 *      monotonic time, admits exactly NODUS_CHAIN_RATE_BUDGET units in one
 *      window, refuses the next unit without charging it, still refuses one
 *      ms before the window ends, and starts over at exactly
 *      NODUS_CHAIN_RATE_WINDOW_MS; a refused multi-unit charge leaves room
 *      for a smaller one; a zeroed session (what session_clear leaves)
 *      starts with the full budget.
 *   3. EARLY FRAME LENGTH (conn->max_payload): on a real nodus_tcp_t, a
 *      connection whose cap is 64 is closed as soon as a 7-byte header
 *      declaring 65 arrives — no payload byte sent, no frame dispatched,
 *      on_disconnect once, and the client reads EOF; a complete over-cap
 *      frame in one write is closed the same way (never dispatched); a
 *      frame of exactly the cap is dispatched; with max_payload 0 the cap is
 *      NODUS_MAX_FRAME_TCP (a header declaring one more byte closes).
 *   4. PER-TRANSPORT READ BUDGET (nodus_tcp_t.read_budget_frames): with 8
 *      set, one nodus_tcp_poll call dispatches EXACTLY 8 frames of a
 *      connection whose 3 x 8 + 17 frames are all in the kernel, and later
 *      calls deliver the rest 8 at a time.
 *
 * Not covered here: dispatch_t2 itself (static; the auth-failure close
 * (D-18), the RATE_LIMITED reply and the dnac_cc_collect own-identity
 * refusal run only inside a full server) and session_clear (static — the
 * zeroed-session case stands in for it).
 *
 * Requires: a default build (no compile flags, no environment). Uses
 * 127.0.0.1:0 (kernel-chosen port), no fixed port.
 * Leaves behind: nothing (sockets and transports closed).
 * How it can lie: case 4's first-call count is meaningful only when the
 * whole burst is in the kernel receive queue before that call; the test
 * waits for it with FIONREAD and requires EXACTLY 8, so an early-EAGAIN
 * stop fails instead of passing. Case 3's "before the payload" is shown by
 * never sending a payload byte at all.
 *
 * Test-runner output uses printf like every other nodus unit test.
 */

#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "protocol/nodus_wire.h"
#include "nodus/nodus_types.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* Upper bound on poll rounds per wait. A liveness bound only: every wait
 * returns as soon as its condition holds. */
#define MAX_ROUNDS 200

/* ── 1. Spend cost ───────────────────────────────────────────────── */

static void test_spend_units(void) {
    TEST("dnac_spend cost = ceil(len / 4627), min 1");
    struct { size_t len; uint32_t want; } v[] = {
        { 0, 1 }, { 1, 1 }, { 4627, 1 }, { 4628, 2 }, { 9254, 2 },
        { 9255, 3 }, { 1048576, 227 },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint32_t got = nodus_chain_spend_units(v[i].len);
        if (got != v[i].want) {
            char m[96];
            snprintf(m, sizeof(m), "len %zu cost %u, want %u",
                     v[i].len, got, v[i].want);
            FAIL(m);
            return;
        }
    }
    if (nodus_chain_spend_units(1048576) > NODUS_CHAIN_RATE_BUDGET) {
        FAIL("a 1 MiB spend does not fit the budget");
        return;
    }
    PASS();
}

/* ── 2. Chain budget ─────────────────────────────────────────────── */

static void test_budget_window(void) {
    TEST("budget: exactly BUDGET units per window, reset at WINDOW");
    nodus_session_t s;
    memset(&s, 0, sizeof(s));
    const uint64_t t0 = 50000;

    for (uint32_t i = 0; i < NODUS_CHAIN_RATE_BUDGET; i++) {
        if (!nodus_session_chain_charge(&s, 1, t0 + i % 7)) {
            FAIL("refused within the budget");
            return;
        }
    }
    if (nodus_session_chain_charge(&s, 1, t0 + 10)) {
        FAIL("unit BUDGET+1 admitted");
        return;
    }
    if (s.chain_units_used != NODUS_CHAIN_RATE_BUDGET) {
        FAIL("a refused unit was charged");
        return;
    }
    if (nodus_session_chain_charge(&s, 1, t0 + NODUS_CHAIN_RATE_WINDOW_MS - 1)) {
        FAIL("admitted 1 ms before the window ends");
        return;
    }
    if (!nodus_session_chain_charge(&s, 1, t0 + NODUS_CHAIN_RATE_WINDOW_MS)) {
        FAIL("not reset at the window boundary");
        return;
    }
    if (s.chain_units_used != 1 ||
        s.chain_window_start_ms != t0 + NODUS_CHAIN_RATE_WINDOW_MS) {
        FAIL("new window not started at the charging time");
        return;
    }
    PASS();
}

static void test_budget_multi_unit(void) {
    TEST("budget: refused big charge costs nothing; smaller still fits");
    nodus_session_t s;
    memset(&s, 0, sizeof(s));
    const uint64_t t0 = 123456;

    uint32_t big = nodus_chain_spend_units(1048576);          /* 227 */
    if (!nodus_session_chain_charge(&s, big, t0)) {
        FAIL("a 1 MiB spend refused on a fresh window");
        return;
    }
    uint32_t left = NODUS_CHAIN_RATE_BUDGET - big;              /* 73 */
    if (nodus_session_chain_charge(&s, left + 1, t0 + 1)) {
        FAIL("charge one over what is left admitted");
        return;
    }
    if (s.chain_units_used != big) {
        FAIL("refused multi-unit charge was charged");
        return;
    }
    if (!nodus_session_chain_charge(&s, left, t0 + 2)) {
        FAIL("exactly what is left refused");
        return;
    }
    if (nodus_session_chain_charge(&s, 1, t0 + 3)) {
        FAIL("admitted past a full budget");
        return;
    }
    PASS();
}

static void test_budget_zeroed_session(void) {
    TEST("budget: zeroed session starts with the full budget");
    nodus_session_t s;
    memset(&s, 0, sizeof(s));          /* what session_clear leaves */
    /* Early monotonic time (now - 0 < WINDOW: no reset) and late time
     * (reset) must both start from a full budget. */
    if (!nodus_session_chain_charge(&s, NODUS_CHAIN_RATE_BUDGET, 5)) {
        FAIL("full budget refused at an early monotonic time");
        return;
    }
    memset(&s, 0, sizeof(s));
    if (!nodus_session_chain_charge(&s, NODUS_CHAIN_RATE_BUDGET,
                                    (uint64_t)1 << 40)) {
        FAIL("full budget refused at a late monotonic time");
        return;
    }
    PASS();
}

/* ── Transport fixture (3, 4) ────────────────────────────────────── */

static uint32_t g_cap;              /* max_payload set on accept */
static nodus_tcp_conn_t *g_conn;    /* the one accepted connection */
static int g_accepted;
static int g_frames;
static size_t g_last_len;
static int g_disc;

static void reset_state(uint32_t cap) {
    g_cap = cap;
    g_conn = NULL;
    g_accepted = 0;
    g_frames = 0;
    g_last_len = 0;
    g_disc = 0;
}

static void on_accept_cb(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    conn->max_payload = g_cap;
    g_conn = conn;
    g_accepted++;
}

static void on_frame_cb(nodus_tcp_conn_t *conn, const uint8_t *payload,
                        size_t len, void *ctx) {
    (void)conn; (void)payload; (void)ctx;
    g_frames++;
    g_last_len = len;
}

static void on_disconnect_cb(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_disc++;
}

static nodus_tcp_t *transport_open(int read_budget_frames) {
    nodus_tcp_t *tcp = calloc(1, sizeof(*tcp));
    if (!tcp) return NULL;
    if (nodus_tcp_init(tcp, -1) != 0 ||
        nodus_tcp_listen(tcp, "127.0.0.1", 0) != 0) {
        nodus_tcp_close(tcp);
        free(tcp);
        return NULL;
    }
    tcp->on_accept     = on_accept_cb;
    tcp->on_frame      = on_frame_cb;
    tcp->on_disconnect = on_disconnect_cb;
    tcp->read_budget_frames = read_budget_frames;
    return tcp;
}

static void transport_close(nodus_tcp_t *tcp) {
    if (!tcp) return;
    nodus_tcp_close(tcp);
    free(tcp);
}

static int client_connect(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int wait_accepted(nodus_tcp_t *tcp) {
    for (int r = 0; r < MAX_ROUNDS && g_accepted < 1; r++)
        nodus_tcp_poll(tcp, 10);
    return g_accepted >= 1 ? 0 : -1;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* A valid nodus frame header declaring `declared` payload bytes. */
static void header_for(uint8_t hdr[NODUS_FRAME_HEADER_SIZE], uint32_t declared) {
    hdr[0] = (uint8_t)(NODUS_FRAME_MAGIC >> 8);
    hdr[1] = (uint8_t)(NODUS_FRAME_MAGIC & 0xFF);
    hdr[2] = NODUS_FRAME_VERSION;
    hdr[3] = (uint8_t)declared;
    hdr[4] = (uint8_t)(declared >> 8);
    hdr[5] = (uint8_t)(declared >> 16);
    hdr[6] = (uint8_t)(declared >> 24);
}

static int wait_disconnect(nodus_tcp_t *tcp) {
    for (int r = 0; r < MAX_ROUNDS && g_disc == 0; r++)
        nodus_tcp_poll(tcp, 10);
    return g_disc > 0 ? 0 : -1;
}

static int wait_frames(nodus_tcp_t *tcp, int want) {
    for (int r = 0; r < MAX_ROUNDS && g_frames < want && g_disc == 0; r++)
        nodus_tcp_poll(tcp, 10);
    return g_frames >= want ? 0 : -1;
}

/* Client side sees the server's close: recv returns 0 (EOF) or a reset. */
static int client_sees_close(int fd) {
    for (int r = 0; r < MAX_ROUNDS; r++) {
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, 10) < 0 && errno != EINTR) return -1;
        if (!(p.revents & (POLLIN | POLLHUP | POLLERR))) continue;
        uint8_t b[64];
        ssize_t n = recv(fd, b, sizeof(b), MSG_DONTWAIT);
        if (n == 0) return 0;
        if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) return 0;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    }
    return -1;
}

/* ── 3. Early frame length ───────────────────────────────────────── */

static void test_header_over_cap_closes(void) {
    TEST("max_payload: header over cap closes before any payload");
    reset_state(64);
    nodus_tcp_t *tcp = transport_open(0);
    if (!tcp) { FAIL("transport open"); return; }
    int fd = client_connect(tcp->port);
    if (fd < 0 || wait_accepted(tcp) != 0) { FAIL("not accepted"); goto out; }

    uint8_t hdr[NODUS_FRAME_HEADER_SIZE];
    header_for(hdr, 65);
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { FAIL("client send"); goto out; }
    if (wait_disconnect(tcp) != 0)  { FAIL("not closed on the header"); goto out; }
    if (g_disc != 1)                { FAIL("on_disconnect not exactly once"); goto out; }
    if (g_frames != 0)              { FAIL("a frame was dispatched"); goto out; }
    if (tcp->count != 0)            { FAIL("connection still in the pool"); goto out; }
    if (client_sees_close(fd) != 0) { FAIL("client did not see the close"); goto out; }
    PASS();
out:
    if (fd >= 0) close(fd);
    transport_close(tcp);
}

static void test_complete_over_cap_closes(void) {
    TEST("max_payload: complete over-cap frame closes, never dispatched");
    reset_state(64);
    nodus_tcp_t *tcp = transport_open(0);
    if (!tcp) { FAIL("transport open"); return; }
    int fd = client_connect(tcp->port);
    if (fd < 0 || wait_accepted(tcp) != 0) { FAIL("not accepted"); goto out; }

    uint8_t p[65];
    memset(p, 0xA5, sizeof(p));
    uint8_t buf[NODUS_FRAME_HEADER_SIZE + sizeof(p)];
    size_t w = nodus_frame_encode(buf, sizeof(buf), p, sizeof(p));
    if (w != sizeof(buf) || send_all(fd, buf, w) != 0) { FAIL("client send"); goto out; }
    if (wait_disconnect(tcp) != 0) { FAIL("not closed"); goto out; }
    if (g_frames != 0)             { FAIL("over-cap frame dispatched"); goto out; }
    PASS();
out:
    if (fd >= 0) close(fd);
    transport_close(tcp);
}

static void test_frame_at_cap_dispatched(void) {
    TEST("max_payload: frame of exactly the cap is dispatched");
    reset_state(64);
    nodus_tcp_t *tcp = transport_open(0);
    if (!tcp) { FAIL("transport open"); return; }
    int fd = client_connect(tcp->port);
    if (fd < 0 || wait_accepted(tcp) != 0) { FAIL("not accepted"); goto out; }

    uint8_t p[64];
    memset(p, 0x5A, sizeof(p));
    uint8_t buf[NODUS_FRAME_HEADER_SIZE + sizeof(p)];
    size_t w = nodus_frame_encode(buf, sizeof(buf), p, sizeof(p));
    if (w != sizeof(buf) || send_all(fd, buf, w) != 0) { FAIL("client send"); goto out; }
    if (wait_frames(tcp, 1) != 0) { FAIL("frame at the cap not dispatched"); goto out; }
    if (g_disc != 0 || g_last_len != sizeof(p)) { FAIL("wrong frame / closed"); goto out; }

    /* The owner clears the cap (auth success): a bigger frame now passes. */
    g_conn->max_payload = 0;
    uint8_t big[1000];
    memset(big, 0x11, sizeof(big));
    uint8_t buf2[NODUS_FRAME_HEADER_SIZE + sizeof(big)];
    w = nodus_frame_encode(buf2, sizeof(buf2), big, sizeof(big));
    if (w != sizeof(buf2) || send_all(fd, buf2, w) != 0) { FAIL("client send 2"); goto out; }
    if (wait_frames(tcp, 2) != 0 || g_last_len != sizeof(big)) {
        FAIL("frame after clearing the cap not dispatched");
        goto out;
    }
    PASS();
out:
    if (fd >= 0) close(fd);
    transport_close(tcp);
}

static void test_default_cap_is_max_frame(void) {
    TEST("max_payload 0: header over NODUS_MAX_FRAME_TCP closes");
    reset_state(0);
    nodus_tcp_t *tcp = transport_open(0);
    if (!tcp) { FAIL("transport open"); return; }
    int fd = client_connect(tcp->port);
    if (fd < 0 || wait_accepted(tcp) != 0) { FAIL("not accepted"); goto out; }

    uint8_t hdr[NODUS_FRAME_HEADER_SIZE];
    header_for(hdr, (uint32_t)NODUS_MAX_FRAME_TCP + 1);
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { FAIL("client send"); goto out; }
    if (wait_disconnect(tcp) != 0) { FAIL("not closed on the header"); goto out; }
    if (g_frames != 0)             { FAIL("a frame was dispatched"); goto out; }
    PASS();
out:
    if (fd >= 0) close(fd);
    transport_close(tcp);
}

/* ── 4. Per-transport read budget ────────────────────────────────── */

#define IPC_BUDGET   8
#define BURST_FRAMES (3 * IPC_BUDGET + 17)
#define SEQ_LEN      4

static int wait_queued(int sfd, size_t bytes) {
    for (int r = 0; r < MAX_ROUNDS; r++) {
        int q = 0;
        if (ioctl(sfd, FIONREAD, &q) != 0) return -1;
        if (q >= 0 && (size_t)q >= bytes) return 0;
        struct pollfd p = { .fd = sfd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, 10) < 0 && errno != EINTR) return -1;
    }
    return -1;
}

static void test_transport_read_budget(void) {
    TEST("read_budget_frames 8: exactly 8 frames per poll call");
    reset_state(0);
    nodus_tcp_t *tcp = transport_open(IPC_BUDGET);
    if (!tcp) { FAIL("transport open"); return; }
    uint8_t *buf = NULL;
    int fd = client_connect(tcp->port);
    if (fd < 0 || wait_accepted(tcp) != 0) { FAIL("not accepted"); goto out; }
    nodus_tcp_poll(tcp, 0);   /* accept already did the immediate read */

    size_t fw = NODUS_FRAME_HEADER_SIZE + SEQ_LEN;
    size_t total = (size_t)BURST_FRAMES * fw;
    buf = malloc(total);
    if (!buf) { FAIL("alloc"); goto out; }
    for (int i = 0; i < BURST_FRAMES; i++) {
        uint8_t p[SEQ_LEN] = { 0, 0, (uint8_t)(i >> 8), (uint8_t)i };
        if (nodus_frame_encode(buf + (size_t)i * fw, fw, p, SEQ_LEN) != fw) {
            FAIL("encode");
            goto out;
        }
    }
    if (send_all(fd, buf, total) != 0) { FAIL("client send"); goto out; }
    if (wait_queued(g_conn->fd, total) != 0) {
        FAIL("burst never fully queued in the kernel (case not exercised)");
        goto out;
    }

    int calls = 0;
    while (g_frames < BURST_FRAMES && calls < MAX_ROUNDS) {
        int before = g_frames;
        int remaining = BURST_FRAMES - before;
        int expect = remaining < IPC_BUDGET ? remaining : IPC_BUDGET;
        nodus_tcp_poll(tcp, 0);
        calls++;
        if (g_frames - before != expect) {
            char m[96];
            snprintf(m, sizeof(m), "call %d delivered %d frames, want %d",
                     calls, g_frames - before, expect);
            FAIL(m);
            goto out;
        }
    }
    if (g_frames != BURST_FRAMES || g_disc != 0) { FAIL("burst not delivered"); goto out; }
    PASS();
out:
    free(buf);
    if (fd >= 0) close(fd);
    transport_close(tcp);
}

int main(void) {
    printf("test_rpc_front_door\n");
    test_spend_units();
    test_budget_window();
    test_budget_multi_unit();
    test_budget_zeroed_session();
    test_header_over_cap_closes();
    test_complete_over_cap_closes();
    test_frame_at_cap_dispatched();
    test_default_cap_is_max_frame();
    test_transport_read_budget();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
