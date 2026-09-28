/**
 * Nodus — deferred connection close (nodus_tcp_disconnect inside a poll)
 *
 * A real nodus_tcp_t listening on 127.0.0.1:0 (kernel-chosen port, so no
 * fixed port and no ctest -j collision), driven from this thread, with
 * plain loopback client sockets writing nodus frames.
 *
 * What it proves (each would be false if it failed):
 *   1. CROSS-CLOSE IN ONE BATCH: two connections each have one frame ready
 *      in the SAME epoll batch; the frame callback of whichever is handled
 *      first disconnects the other. The other's pending event is skipped —
 *      its frame is never dispatched (on_frame total == 1) — and the
 *      transport never touches its memory after the close. on_disconnect
 *      runs exactly once for the victim (a second nodus_tcp_disconnect on
 *      it inside the callback is a no-op) and never for the survivor.
 *      This is the shape of the session eviction in nodus_auth.c.
 *   2. SELF-CLOSE: two frames arrive in one read; the callback disconnects
 *      its own connection on the first. try_parse_frames stops — the
 *      second frame is never dispatched — and on_disconnect runs once.
 *      This is the shape of dispatch_inter's AUTH_OK !bind_ok branch.
 *   3. After each of those batches returns, nothing is left parked
 *      (close_list empty, poll_depth 0): the deferred memory was released
 *      at the end of the batch, not leaked.
 *   4. OUTSIDE A POLL nodus_tcp_disconnect behaves as before: the slot is
 *      empty and the memory released before it returns (nothing parked).
 *
 * Requires: a default build (no compile flags, no environment). To make
 * "no access after free" a hard failure rather than a silent read of
 * freed memory, build it with AddressSanitizer, e.g. a separate build dir
 * configured with -DCMAKE_C_FLAGS=-fsanitize=address
 * -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address. The transport allocates and
 * frees every connection on the heap, so ASan sees any use after free.
 * Leaves behind: nothing (sockets closed, transport closed).
 * How it can lie: scenario 1 is only meaningful if both frames land in ONE
 * nodus_tcp_poll batch. The test waits (poll(2) on the server-side fds,
 * which does not consume epoll events) until both are readable, then
 * requires that single nodus_tcp_poll call to report 2 events; if it does
 * not, the scenario FAILS instead of passing without exercising the case.
 * Without ASan a regression may read freed memory without crashing; the
 * frame / disconnect counts still catch the dispatch of a closed conn.
 *
 * Test-runner output uses printf like every other nodus unit test.
 */

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
#define MAX_TRACKED 4

typedef enum { MODE_NONE = 0, MODE_CROSS, MODE_SELF } cb_mode_t;

/* Callback bookkeeping. A connection is identified by the 1-based id the
 * on_accept callback stores in user_data — never by its pointer, which the
 * test must not dereference after the close. */
static nodus_tcp_t      *g_tcp;
static cb_mode_t          g_mode;
static nodus_tcp_conn_t  *g_conns[MAX_TRACKED];   /* by id-1; for disconnect only */
static int                g_accepted;
static int                g_frames;
static int                g_frames_by_id[MAX_TRACKED + 1];
static int                g_disc_by_id[MAX_TRACKED + 1];
static int                g_acted;
static int                g_victim_id;

static int conn_id(const nodus_tcp_conn_t *conn) {
    return (int)(intptr_t)conn->user_data;
}

static void reset_state(void) {
    g_mode = MODE_NONE;
    memset(g_conns, 0, sizeof(g_conns));
    g_accepted = 0;
    g_frames = 0;
    memset(g_frames_by_id, 0, sizeof(g_frames_by_id));
    memset(g_disc_by_id, 0, sizeof(g_disc_by_id));
    g_acted = 0;
    g_victim_id = 0;
}

static void on_accept_cb(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    if (g_accepted >= MAX_TRACKED) return;
    g_conns[g_accepted] = conn;
    g_accepted++;
    conn->user_data = (void *)(intptr_t)g_accepted;
}

static void on_frame_cb(nodus_tcp_conn_t *conn, const uint8_t *payload,
                        size_t len, void *ctx) {
    (void)payload; (void)len; (void)ctx;
    int id = conn_id(conn);
    g_frames++;
    if (id >= 1 && id <= MAX_TRACKED) g_frames_by_id[id]++;
    if (g_acted) return;

    if (g_mode == MODE_CROSS) {
        /* Close the OTHER connection — whichever event epoll delivered
         * first. Twice: the second call must not run on_disconnect again. */
        int other = (id == 1) ? 2 : 1;
        nodus_tcp_conn_t *victim = g_conns[other - 1];
        g_acted = 1;
        g_victim_id = other;
        nodus_tcp_disconnect(g_tcp, victim);
        nodus_tcp_disconnect(g_tcp, victim);
    } else if (g_mode == MODE_SELF) {
        g_acted = 1;
        g_victim_id = id;
        nodus_tcp_disconnect(g_tcp, conn);
        nodus_tcp_disconnect(g_tcp, conn);
    }
}

static void on_disconnect_cb(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    int id = conn_id(conn);
    if (id >= 1 && id <= MAX_TRACKED) g_disc_by_id[id]++;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static nodus_tcp_t *transport_open(void) {
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
    g_tcp = tcp;
    return tcp;
}

static void transport_close(nodus_tcp_t *tcp) {
    if (!tcp) return;
    nodus_tcp_close(tcp);
    free(tcp);
    g_tcp = NULL;
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

/* Poll the transport until `want` connections have been accepted. */
static int wait_accepted(nodus_tcp_t *tcp, int want) {
    for (int r = 0; r < MAX_ROUNDS && g_accepted < want; r++)
        nodus_tcp_poll(tcp, 10);
    return g_accepted >= want ? 0 : -1;
}

/* Write `count` nodus frames (payload "f<i>") in ONE send, so they reach
 * the transport in one read. */
static int client_send_frames(int fd, int count) {
    uint8_t buf[256];
    size_t off = 0;
    for (int i = 0; i < count; i++) {
        uint8_t payload[2] = { 'f', (uint8_t)('0' + i) };
        size_t w = nodus_frame_encode(buf + off, sizeof(buf) - off,
                                      payload, (uint32_t)sizeof(payload));
        if (w == 0) return -1;
        off += w;
    }
    size_t sent = 0;
    while (sent < off) {
        ssize_t n = send(fd, buf + sent, off - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

/* Wait (poll(2), which does not consume epoll events) until every server
 * side fd in `fds` is readable. */
static int wait_readable(const int *fds, int nfds) {
    struct pollfd p[MAX_TRACKED];
    for (int r = 0; r < MAX_ROUNDS; r++) {
        int ready = 0;
        for (int i = 0; i < nfds; i++) {
            p[i].fd = fds[i];
            p[i].events = POLLIN;
            p[i].revents = 0;
        }
        if (poll(p, (nfds_t)nfds, 10) < 0 && errno != EINTR) return -1;
        for (int i = 0; i < nfds; i++)
            if (p[i].revents & POLLIN) ready++;
        if (ready == nfds) return 0;
    }
    return -1;
}

/* The client side of a connection the server closed reads EOF or a reset. */
static int client_sees_close(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    for (int r = 0; r < MAX_ROUNDS; r++) {
        if (poll(&p, 1, 10) > 0) {
            uint8_t b[64];
            ssize_t n = recv(fd, b, sizeof(b), 0);
            if (n == 0) return 1;
            if (n < 0 && (errno == ECONNRESET || errno == EPIPE)) return 1;
            if (n < 0 && errno != EINTR && errno != EAGAIN) return 1;
            if (n > 0) return 0;   /* data, not a close */
        }
    }
    return 0;
}

static int nothing_parked(const nodus_tcp_t *tcp) {
    return tcp->close_list == NULL && tcp->poll_depth == 0;
}

/* ── Scenario 1: the frame callback closes ANOTHER conn in the batch ─ */

static void test_cross_close_same_batch(void) {
    TEST("callback closes another conn with an event in the same batch");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int sfd[2];
    int n, survivor;
    int c1 = client_connect(tcp->port);
    int c2 = client_connect(tcp->port);
    if (c1 < 0 || c2 < 0 || wait_accepted(tcp, 2) != 0) {
        FAIL("two connections not accepted");
        goto out;
    }
    /* Nothing else is pending: accept already did the ET immediate read. */
    nodus_tcp_poll(tcp, 0);

    sfd[0] = g_conns[0]->fd;
    sfd[1] = g_conns[1]->fd;
    g_mode = MODE_CROSS;
    if (client_send_frames(c1, 1) != 0 || client_send_frames(c2, 1) != 0) {
        FAIL("client send");
        goto out;
    }
    if (wait_readable(sfd, 2) != 0) {
        FAIL("server fds never became readable");
        goto out;
    }

    n = nodus_tcp_poll(tcp, 0);
    if (n != 2) {
        char m[96];
        snprintf(m, sizeof(m), "batch had %d events, need 2 (case not exercised)", n);
        FAIL(m);
        goto out;
    }
    survivor = (g_victim_id == 1) ? 2 : 1;
    if (!g_acted || g_victim_id == 0) { FAIL("callback never closed a conn"); goto out; }
    if (g_frames != 1)                { FAIL("closed conn's frame was dispatched"); goto out; }
    if (g_frames_by_id[g_victim_id] != 0) { FAIL("victim got a frame"); goto out; }
    if (g_disc_by_id[g_victim_id] != 1) { FAIL("victim on_disconnect != 1"); goto out; }
    if (g_disc_by_id[survivor] != 0)  { FAIL("survivor was disconnected"); goto out; }
    if (tcp->count != 1)              { FAIL("pool count != 1"); goto out; }
    if (!nothing_parked(tcp))         { FAIL("deferred conn not released at batch end"); goto out; }
    if (!client_sees_close(g_victim_id == 1 ? c1 : c2)) {
        FAIL("victim's client did not see the close");
        goto out;
    }
    PASS();
out:
    if (c1 >= 0) close(c1);
    if (c2 >= 0) close(c2);
    transport_close(tcp);
}

/* ── Scenario 2: the frame callback closes ITS OWN conn ────────────── */

static void test_self_close_stops_parsing(void) {
    TEST("callback closes its own conn: no further frame dispatched");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int sfd[1];
    int n;
    int c1 = client_connect(tcp->port);
    if (c1 < 0 || wait_accepted(tcp, 1) != 0) {
        FAIL("connection not accepted");
        goto out;
    }
    nodus_tcp_poll(tcp, 0);

    sfd[0] = g_conns[0]->fd;
    g_mode = MODE_SELF;
    if (client_send_frames(c1, 2) != 0) { FAIL("client send"); goto out; }
    if (wait_readable(sfd, 1) != 0)      { FAIL("server fd never readable"); goto out; }

    n = nodus_tcp_poll(tcp, 0);
    if (n != 1)                  { FAIL("expected one event"); goto out; }
    if (!g_acted)                { FAIL("callback never ran"); goto out; }
    if (g_frames != 1)           { FAIL("frame after self-close was dispatched"); goto out; }
    if (g_disc_by_id[1] != 1)    { FAIL("on_disconnect != 1"); goto out; }
    if (tcp->count != 0)         { FAIL("pool count != 0"); goto out; }
    if (!nothing_parked(tcp))    { FAIL("deferred conn not released at batch end"); goto out; }
    if (!client_sees_close(c1))  { FAIL("client did not see the close"); goto out; }
    PASS();
out:
    if (c1 >= 0) close(c1);
    transport_close(tcp);
}

/* ── Scenario 3: outside a poll, close is immediate as before ─────── */

static void test_disconnect_outside_poll(void) {
    TEST("disconnect outside a poll frees immediately");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int slot;
    int c1 = client_connect(tcp->port);
    if (c1 < 0 || wait_accepted(tcp, 1) != 0) {
        FAIL("connection not accepted");
        goto out;
    }
    slot = g_conns[0]->slot;
    nodus_tcp_disconnect(tcp, g_conns[0]);
    g_conns[0] = NULL;
    if (g_disc_by_id[1] != 1)        { FAIL("on_disconnect != 1"); goto out; }
    if (tcp->pool[slot] != NULL)     { FAIL("slot not emptied"); goto out; }
    if (tcp->count != 0)             { FAIL("pool count != 0"); goto out; }
    if (!nothing_parked(tcp))        { FAIL("close was deferred outside a poll"); goto out; }
    if (!client_sees_close(c1))      { FAIL("client did not see the close"); goto out; }
    PASS();
out:
    if (c1 >= 0) close(c1);
    transport_close(tcp);
}

int main(void) {
    printf("TCP deferred close tests\n");
    printf("========================\n");

    test_cross_close_same_batch();
    test_self_close_stops_parsing();
    test_disconnect_outside_poll();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
