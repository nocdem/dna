/**
 * Nodus — per-connection read budget (NODUS_TCP_READ_BUDGET_*)
 *
 * A real nodus_tcp_t listening on 127.0.0.1:0 (kernel-chosen port, so no
 * fixed port and no ctest -j collision), driven from this thread, with
 * plain loopback client sockets writing nodus frames whose 4-byte payload
 * is a big-endian sequence number.
 *
 * What it proves (each would be false if it failed):
 *   1. BUDGET + FAIRNESS: connection A has BURST_FRAMES (> 3 x the frame
 *      budget) frames queued in the kernel and connection B has one. A
 *      single nodus_tcp_poll call dispatches EXACTLY
 *      NODUS_TCP_READ_BUDGET_FRAMES frames of A — not all of them — and
 *      B's frame is dispatched in that call or the next. A is then on the
 *      pending-read list.
 *   2. NOTHING IS LOST UNDER EPOLLET: A's remaining frames are already in
 *      user space (rbuf) after the first call, so epoll will never report
 *      A again. Further nodus_tcp_poll calls still deliver them — each call
 *      exactly min(budget, remaining) — in order and without gaps, and
 *      afterwards the pending-read list is empty.
 *   3. CLOSE WHILE PENDING (another conn's callback): A is on the pending
 *      list when B's frame callback disconnects A. A is dropped from the
 *      list (read_count 0), none of its leftover frames is dispatched,
 *      on_disconnect runs once for A and never for B, and nothing stays
 *      parked after the call.
 *   4. CLOSE WHILE PENDING (its own callback): A disconnects itself from
 *      on_frame while being serviced from the pending list. Dispatch stops
 *      at that frame, on_disconnect runs once, the list is empty and
 *      nothing stays parked.
 *   5. CLOSE WHILE PENDING, OUTSIDE A POLL: nodus_tcp_disconnect on a
 *      pending connection between two polls frees it at once; the list
 *      must not keep the freed pointer (the next poll would touch freed
 *      memory — a hard failure under ASan) and read_count is 0.
 *
 * Requires: a default build (no compile flags, no environment). As with
 * test_tcp_deferred_close, build it with AddressSanitizer
 * (-DCMAKE_C_FLAGS=-fsanitize=address -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address
 * in a separate build dir) to make a use-after-free of a closed pending
 * connection a hard failure instead of a silent read.
 * Leaves behind: nothing (sockets closed, transport closed).
 * How it can lie: the first-call assertion is only meaningful if A's whole
 * burst is in the kernel receive queue before that call — otherwise a read
 * that hit EAGAIN early would also stop short of the burst. The test waits
 * until ioctl(FIONREAD) on the server-side fds reports every byte, and
 * requires EXACTLY the budget (not "at most"), so an early-EAGAIN stop
 * fails instead of passing. The byte budget is not exercised here: a
 * deterministic > 256 KiB loopback burst depends on socket buffer sizes
 * this test does not control.
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
#define MAX_TRACKED 4

#define BUDGET        NODUS_TCP_READ_BUDGET_FRAMES
#define BURST_FRAMES  (3 * BUDGET + 17)
#define SEQ_LEN       4

typedef enum {
    MODE_NONE = 0,
    MODE_B_KILLS_A,     /* B's frame callback disconnects A */
    MODE_A_SELF_AT      /* A's callback disconnects A at frame g_self_at */
} cb_mode_t;

/* A connection is identified by the 1-based id the on_accept callback
 * stores in user_data — never by its pointer after a close. */
static nodus_tcp_t      *g_tcp;
static cb_mode_t          g_mode;
static nodus_tcp_conn_t  *g_conns[MAX_TRACKED];
static int                g_accepted;
static int                g_frames_by_id[MAX_TRACKED + 1];
static uint32_t           g_next_seq[MAX_TRACKED + 1];
static int                g_order_err;
static int                g_disc_by_id[MAX_TRACKED + 1];
static int                g_self_at;

static int conn_id(const nodus_tcp_conn_t *conn) {
    return (int)(intptr_t)conn->user_data;
}

static void reset_state(void) {
    g_mode = MODE_NONE;
    memset(g_conns, 0, sizeof(g_conns));
    g_accepted = 0;
    memset(g_frames_by_id, 0, sizeof(g_frames_by_id));
    memset(g_next_seq, 0, sizeof(g_next_seq));
    g_order_err = 0;
    memset(g_disc_by_id, 0, sizeof(g_disc_by_id));
    g_self_at = 0;
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
    (void)ctx;
    int id = conn_id(conn);
    if (id < 1 || id > MAX_TRACKED) return;
    if (len != SEQ_LEN) {
        g_order_err++;
    } else {
        uint32_t seq = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                       ((uint32_t)payload[2] << 8)  |  (uint32_t)payload[3];
        if (seq != g_next_seq[id]) g_order_err++;
        g_next_seq[id] = seq + 1;
    }
    g_frames_by_id[id]++;

    if (g_mode == MODE_B_KILLS_A && id == 2) {
        g_mode = MODE_NONE;
        nodus_tcp_disconnect(g_tcp, g_conns[0]);
    } else if (g_mode == MODE_A_SELF_AT && id == 1 &&
               g_frames_by_id[1] == g_self_at) {
        g_mode = MODE_NONE;
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

static int wait_accepted(nodus_tcp_t *tcp, int want) {
    for (int r = 0; r < MAX_ROUNDS && g_accepted < want; r++)
        nodus_tcp_poll(tcp, 10);
    return g_accepted >= want ? 0 : -1;
}

/* Bytes one frame of this test takes on the wire. */
static size_t frame_wire_size(void) {
    return NODUS_FRAME_HEADER_SIZE + SEQ_LEN;
}

/* Write `count` frames with sequence numbers 0..count-1 in one burst.
 * Returns the number of bytes written, or 0 on failure. */
static size_t client_send_seq(int fd, int count) {
    size_t cap = (size_t)count * frame_wire_size();
    uint8_t *buf = malloc(cap);
    if (!buf) return 0;
    size_t off = 0;
    for (int i = 0; i < count; i++) {
        uint8_t p[SEQ_LEN] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16),
                               (uint8_t)(i >> 8),  (uint8_t)i };
        size_t w = nodus_frame_encode(buf + off, cap - off, p, SEQ_LEN);
        if (w == 0) { free(buf); return 0; }
        off += w;
    }
    size_t sent = 0;
    while (sent < off) {
        ssize_t n = send(fd, buf + sent, off - sent, MSG_NOSIGNAL);
        if (n <= 0) { free(buf); return 0; }
        sent += (size_t)n;
    }
    free(buf);
    return off;
}

/* Wait (without consuming any epoll event) until the kernel receive queue
 * of server-side fd `sfd` holds at least `bytes`. */
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

static int list_clean(const nodus_tcp_t *tcp) {
    return tcp->read_head == NULL && tcp->read_tail == NULL &&
           tcp->read_count == 0;
}

static int nothing_parked(const nodus_tcp_t *tcp) {
    return tcp->close_list == NULL && tcp->poll_depth == 0;
}

/* Common setup: accept A (id 1) and B (id 2), queue A's burst and B's one
 * frame in the kernel, and run the first nodus_tcp_poll call. On success
 * A has exactly BUDGET frames and is on the pending-read list. */
static int setup_first_call(nodus_tcp_t *tcp, int *ca, int *cb,
                            const char **why) {
    *ca = client_connect(tcp->port);
    *cb = client_connect(tcp->port);
    if (*ca < 0 || *cb < 0 || wait_accepted(tcp, 2) != 0) {
        *why = "two connections not accepted";
        return -1;
    }
    nodus_tcp_poll(tcp, 0);   /* accept already did the immediate read */

    int sa = g_conns[0]->fd, sb = g_conns[1]->fd;
    size_t ba = client_send_seq(*ca, BURST_FRAMES);
    size_t bb = client_send_seq(*cb, 1);
    if (ba == 0 || bb == 0) { *why = "client send"; return -1; }
    if (wait_queued(sa, ba) != 0 || wait_queued(sb, bb) != 0) {
        *why = "burst never fully queued in the kernel (case not exercised)";
        return -1;
    }

    nodus_tcp_poll(tcp, 0);
    if (g_frames_by_id[1] != BUDGET) {
        static char m[96];
        snprintf(m, sizeof(m), "first call dispatched %d frames of A, want %d",
                 g_frames_by_id[1], BUDGET);
        *why = m;
        return -1;
    }
    if (!g_conns[0]->read_pending || tcp->read_count != 1) {
        *why = "A not on the pending-read list after its budget";
        return -1;
    }
    return 0;
}

/* ── Scenario 1+2: budget, fairness, eventual in-order delivery ──── */

static void test_budget_fair_and_complete(void) {
    TEST("one call reads <= budget; rest delivered in order later");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int ca = -1, cb = -1;
    const char *why = NULL;
    int calls = 1;
    if (setup_first_call(tcp, &ca, &cb, &why) != 0) { FAIL(why); goto out; }

    /* B: served in the same call, or at the latest in the next. */
    if (g_frames_by_id[2] != 1) {
        nodus_tcp_poll(tcp, 0);
        calls++;
        if (g_frames_by_id[2] != 1) { FAIL("B starved past the next call"); goto out; }
        if (g_frames_by_id[1] > 2 * BUDGET) { FAIL("A exceeded budget in call 2"); goto out; }
    }

    /* The rest of A is in rbuf; epoll will not report A again. A generous
     * timeout proves nothing sleeps on it: each call must still deliver. */
    for (int r = 0; r < MAX_ROUNDS && g_frames_by_id[1] < BURST_FRAMES; r++) {
        int before = g_frames_by_id[1];
        int remaining = BURST_FRAMES - before;
        int expect = remaining < BUDGET ? remaining : BUDGET;
        nodus_tcp_poll(tcp, 50);
        calls++;
        int got = g_frames_by_id[1] - before;
        if (got != expect) {
            char m[96];
            snprintf(m, sizeof(m), "call %d delivered %d frames of A, want %d",
                     calls, got, expect);
            FAIL(m);
            goto out;
        }
    }
    if (g_frames_by_id[1] != BURST_FRAMES) { FAIL("A's frames never all delivered"); goto out; }
    if (g_order_err != 0)                  { FAIL("frames out of order / gap"); goto out; }
    if (g_frames_by_id[2] != 1)            { FAIL("B frame count != 1"); goto out; }
    if (!list_clean(tcp))                  { FAIL("pending-read list not empty at the end"); goto out; }
    if (!nothing_parked(tcp))              { FAIL("poll left state behind"); goto out; }
    if (g_disc_by_id[1] || g_disc_by_id[2]) { FAIL("unexpected disconnect"); goto out; }
    PASS();
out:
    if (ca >= 0) close(ca);
    if (cb >= 0) close(cb);
    transport_close(tcp);
}

/* ── Scenario 3: another conn's callback closes a pending conn ────── */

static void test_pending_closed_by_other(void) {
    TEST("pending conn closed by another conn's callback is dropped");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int ca = -1, cb = -1;
    const char *why = NULL;
    int sb;
    size_t bb;
    if (setup_first_call(tcp, &ca, &cb, &why) != 0) { FAIL(why); goto out; }
    if (g_frames_by_id[2] != 1) nodus_tcp_poll(tcp, 0);   /* B's first frame */
    if (g_frames_by_id[2] != 1) { FAIL("B's first frame not delivered"); goto out; }
    if (!g_conns[0]->read_pending) { FAIL("A left the pending list early"); goto out; }

    /* B sends one more frame; its callback closes A (still pending). This
     * call handles B's event first, then the pending list — which must no
     * longer hold A. */
    {
        int a_before = g_frames_by_id[1];
        sb = g_conns[1]->fd;
        g_next_seq[2] = 0;           /* B's second burst restarts at 0 */
        bb = client_send_seq(cb, 1);
        if (bb == 0 || wait_queued(sb, bb) != 0) { FAIL("B second frame not queued"); goto out; }
        g_mode = MODE_B_KILLS_A;
        nodus_tcp_poll(tcp, 0);
        if (g_mode != MODE_NONE)          { FAIL("B's callback never ran"); goto out; }
        if (g_frames_by_id[1] != a_before) { FAIL("closed pending conn got a frame"); goto out; }
    }
    if (g_disc_by_id[1] != 1)  { FAIL("A on_disconnect != 1"); goto out; }
    if (g_disc_by_id[2] != 0)  { FAIL("B was disconnected"); goto out; }
    if (!list_clean(tcp))      { FAIL("closed conn still on the pending list"); goto out; }
    if (!nothing_parked(tcp))  { FAIL("deferred conn not released at call end"); goto out; }
    if (tcp->count != 1)       { FAIL("pool count != 1"); goto out; }
    nodus_tcp_poll(tcp, 0);    /* nothing to service; must not touch A */
    if (g_order_err != 0)      { FAIL("frames out of order / gap"); goto out; }
    PASS();
out:
    if (ca >= 0) close(ca);
    if (cb >= 0) close(cb);
    transport_close(tcp);
}

/* ── Scenario 4: a pending conn closes itself while serviced ─────── */

static void test_pending_self_close(void) {
    TEST("pending conn closing itself stops dispatch, leaves list");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int ca = -1, cb = -1;
    const char *why = NULL;
    if (setup_first_call(tcp, &ca, &cb, &why) != 0) { FAIL(why); goto out; }

    g_self_at = BUDGET + BUDGET / 2;   /* inside the second call's service */
    g_mode = MODE_A_SELF_AT;
    nodus_tcp_poll(tcp, 0);
    if (g_mode != MODE_NONE)              { FAIL("self-close never ran"); goto out; }
    if (g_frames_by_id[1] != g_self_at)   { FAIL("frame dispatched after self-close"); goto out; }
    if (g_disc_by_id[1] != 1)             { FAIL("A on_disconnect != 1"); goto out; }
    if (!list_clean(tcp))                 { FAIL("closed conn still on the pending list"); goto out; }
    if (!nothing_parked(tcp))             { FAIL("deferred conn not released at call end"); goto out; }
    nodus_tcp_poll(tcp, 0);
    if (g_frames_by_id[1] != g_self_at)   { FAIL("closed conn serviced later"); goto out; }
    if (g_order_err != 0)                 { FAIL("frames out of order / gap"); goto out; }
    PASS();
out:
    if (ca >= 0) close(ca);
    if (cb >= 0) close(cb);
    transport_close(tcp);
}

/* ── Scenario 5: a pending conn closed between two polls ─────────── */

static void test_pending_closed_outside_poll(void) {
    TEST("pending conn disconnected outside a poll leaves the list");
    reset_state();
    nodus_tcp_t *tcp = transport_open();
    if (!tcp) { FAIL("transport open"); return; }

    int ca = -1, cb = -1;
    const char *why = NULL;
    int a_before;
    if (setup_first_call(tcp, &ca, &cb, &why) != 0) { FAIL(why); goto out; }

    a_before = g_frames_by_id[1];
    nodus_tcp_disconnect(tcp, g_conns[0]);   /* freed at once: no poll running */
    g_conns[0] = NULL;
    if (g_disc_by_id[1] != 1)   { FAIL("A on_disconnect != 1"); goto out; }
    if (!list_clean(tcp))       { FAIL("freed conn still on the pending list"); goto out; }
    if (!nothing_parked(tcp))   { FAIL("close deferred outside a poll"); goto out; }
    nodus_tcp_poll(tcp, 0);     /* would touch freed memory if still listed */
    nodus_tcp_poll(tcp, 0);
    if (g_frames_by_id[1] != a_before) { FAIL("freed conn got a frame"); goto out; }
    if (g_frames_by_id[2] != 1)        { FAIL("B's frame not delivered"); goto out; }
    PASS();
out:
    if (ca >= 0) close(ca);
    if (cb >= 0) close(cb);
    transport_close(tcp);
}

int main(void) {
    printf("TCP read budget tests\n");
    printf("=====================\n");

    test_budget_fair_and_complete();
    test_pending_closed_by_other();
    test_pending_self_close();
    test_pending_closed_outside_poll();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
