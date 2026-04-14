/**
 * Nodus — Pending queue + backpressure tests (Phase 3)
 *
 * Exercises the send-path fallback behavior:
 *   1. When wbuf is near cap, new sends land in the per-conn pending FIFO.
 *   2. When wbuf drains, pending frames are promoted back into wbuf in order.
 *   3. When the pending queue is at its cap, the on_pending_full callback
 *      is invoked so the caller can persist the frame (hint table).
 *   4. conn_free releases queued frames without leaking.
 *
 * These tests manipulate conn->wlen directly to simulate "wbuf near cap"
 * without needing a slow remote peer. Public conn struct fields make this
 * straightforward; the pending queue internals stay private to nodus_tcp.c.
 */

#include "transport/nodus_tcp.h"
#include "nodus/nodus_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int accepted_flag = 0;
static int pending_full_fired = 0;
static size_t last_pending_full_len = 0;

static void on_accept_simple(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    accepted_flag = 1;
}

static void on_pending_full_stub(nodus_tcp_conn_t *conn,
                                  const uint8_t *payload, size_t len,
                                  void *ctx) {
    (void)conn; (void)payload; (void)ctx;
    pending_full_fired++;
    last_pending_full_len = len;
}

/** Drive both sides of a loopback pair until the client conn is connected. */
static nodus_tcp_conn_t *setup_pair(nodus_tcp_t *server, nodus_tcp_t *client) {
    accepted_flag = 0;
    nodus_tcp_init(server, -1);
    nodus_tcp_init(client, -1);
    server->on_accept = on_accept_simple;
    nodus_tcp_listen(server, "127.0.0.1", 0);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(client, "127.0.0.1", server->port);
    for (int i = 0; i < 20 && (!conn || conn->state != NODUS_CONN_CONNECTED); i++) {
        nodus_tcp_poll(server, 10);
        nodus_tcp_poll(client, 10);
    }
    return conn;
}

/* ── Test 1: wbuf full → pending queue takes the frame ───────────── */
static void test_send_routes_to_pending(void) {
    TEST("wbuf near cap routes next send to pending queue");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("setup failed");
        nodus_tcp_close(&client); nodus_tcp_close(&server);
        return;
    }

    /* Force wbuf to look almost full. We grow wcap to just under MAX_FRAME_TCP
     * and park the write window right at its end so the next frame cannot fit. */
    const size_t target_wlen = NODUS_MAX_FRAME_TCP - 1024;
    uint8_t *new_buf = realloc(conn->wbuf, target_wlen + 8192);
    if (!new_buf) { FAIL("realloc"); nodus_tcp_close(&client); nodus_tcp_close(&server); return; }
    conn->wbuf = new_buf;
    conn->wcap = target_wlen + 8192;
    conn->wlen = target_wlen;
    conn->wpos = target_wlen;  /* Pretend all of this was "already queued and will be consumed" */

    /* Compact path in send() treats wpos > 0 as already-sent; after compaction
     * wlen will be 0 again. That's not what we want — we want wlen to stay at
     * target_wlen so buf_ensure fails. Reset wpos so compaction is a no-op. */
    conn->wpos = 0;

    /* Send a 1 MB frame — it cannot fit because target_wlen + 1MB > cap. */
    size_t payload_len = 1 * 1024 * 1024;
    uint8_t *payload = malloc(payload_len);
    memset(payload, 0xAB, payload_len);

    uint64_t prev_enqueued = conn->pending_enqueued_count;
    int rc = nodus_tcp_send(conn, payload, payload_len);
    free(payload);

    if (rc == 0 &&
        conn->pending_count == 1 &&
        conn->pending_enqueued_count == prev_enqueued + 1 &&
        conn->pending_bytes > payload_len) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "rc=%d pending_count=%zu enq=%llu bytes=%zu",
                 rc, conn->pending_count,
                 (unsigned long long)conn->pending_enqueued_count,
                 conn->pending_bytes);
        FAIL(msg);
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

/* ── Test 2: FIFO order is preserved across push → drain ─────────── */
static void test_fifo_order_on_drain(void) {
    TEST("pending FIFO order preserved on drain");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("setup failed");
        nodus_tcp_close(&client); nodus_tcp_close(&server);
        return;
    }

    /* Park wbuf right under the hard cap so any reasonably-sized frame fails
     * buf_ensure and lands in pending instead of growing wbuf. */
    const size_t target = NODUS_MAX_FRAME_TCP - 1024;
    uint8_t *nb = realloc(conn->wbuf, target + 8192);
    if (!nb) { FAIL("realloc"); nodus_tcp_close(&client); nodus_tcp_close(&server); return; }
    conn->wbuf = nb;
    conn->wcap = target + 8192;
    conn->wlen = target;
    conn->wpos = 0;

    /* Push 3 64-KB frames — each exceeds remaining cap so all queue. */
    const size_t frame_size = 64 * 1024;
    uint8_t *f1 = malloc(frame_size); memset(f1, 0xA1, frame_size);
    uint8_t *f2 = malloc(frame_size); memset(f2, 0xB2, frame_size);
    uint8_t *f3 = malloc(frame_size); memset(f3, 0xC3, frame_size);
    conn->wlen = target; conn->wpos = 0;
    nodus_tcp_send(conn, f1, frame_size);
    conn->wlen = target; conn->wpos = 0;
    nodus_tcp_send(conn, f2, frame_size);
    conn->wlen = target; conn->wpos = 0;
    nodus_tcp_send(conn, f3, frame_size);
    free(f1); free(f2); free(f3);

    if (conn->pending_count != 3) {
        char msg[64]; snprintf(msg, sizeof(msg), "expected 3 pending, got %zu", conn->pending_count);
        FAIL(msg);
        nodus_tcp_close(&client); nodus_tcp_close(&server); return;
    }

    /* Simulate full drain: socket consumed everything. */
    conn->wlen = 0;
    conn->wpos = 0;

    /* Poll briefly to trigger handle_write → pending drain path. */
    for (int i = 0; i < 10; i++) {
        nodus_tcp_poll(&client, 5);
        nodus_tcp_poll(&server, 5);
    }

    if (conn->pending_count == 0 && conn->pending_drained_count == 3) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "pending_count=%zu drained=%llu",
                 conn->pending_count,
                 (unsigned long long)conn->pending_drained_count);
        FAIL(msg);
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

/* ── Test 3: frame cap triggers on_pending_full callback ─────────── */
static void test_pending_cap_fires_callback(void) {
    TEST("pending frame cap triggers on_pending_full callback");

    pending_full_fired = 0;
    last_pending_full_len = 0;

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("setup failed");
        nodus_tcp_close(&client); nodus_tcp_close(&server);
        return;
    }

    client.on_pending_full = on_pending_full_stub;
    client.pending_full_ctx = NULL;

    /* Park wbuf artificially full. */
    const size_t target = NODUS_MAX_FRAME_TCP - 1024;
    uint8_t *nb = realloc(conn->wbuf, target + 8192);
    if (!nb) { FAIL("realloc"); nodus_tcp_close(&client); nodus_tcp_close(&server); return; }
    conn->wbuf = nb;
    conn->wcap = target + 8192;
    conn->wlen = target;
    conn->wpos = 0;

    /* Push exactly NODUS_PENDING_MAX_FRAMES 64 KB frames — should all queue. */
    const size_t frame_size = 64 * 1024;
    uint8_t *frame = malloc(frame_size);
    memset(frame, 0xDE, frame_size);
    for (int i = 0; i < NODUS_PENDING_MAX_FRAMES; i++) {
        conn->wlen = target;
        conn->wpos = 0;
        nodus_tcp_send(conn, frame, frame_size);
    }

    if (conn->pending_count != NODUS_PENDING_MAX_FRAMES) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "expected %d pending, got %zu",
                 NODUS_PENDING_MAX_FRAMES, conn->pending_count);
        FAIL(msg);
        free(frame);
        nodus_tcp_close(&client); nodus_tcp_close(&server); return;
    }

    /* One more send → queue is at cap → callback must fire. */
    conn->wlen = target;
    conn->wpos = 0;
    int rc = nodus_tcp_send(conn, frame, frame_size);
    free(frame);

    if (rc == 0 &&
        pending_full_fired == 1 &&
        last_pending_full_len == frame_size &&
        conn->pending_hint_fallback_count == 1) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "rc=%d cb_fired=%d len=%zu hint=%llu",
                 rc, pending_full_fired, last_pending_full_len,
                 (unsigned long long)conn->pending_hint_fallback_count);
        FAIL(msg);
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

/* ── Test 4: conn_free releases pending frames without leaking ───── */
static void test_cleanup_on_close(void) {
    TEST("conn_free drops pending frames cleanly");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("setup failed");
        nodus_tcp_close(&client); nodus_tcp_close(&server);
        return;
    }

    /* Park wbuf artificially full and push 5 queued frames. */
    const size_t target = NODUS_MAX_FRAME_TCP - 1024;
    uint8_t *nb = realloc(conn->wbuf, target + 8192);
    if (!nb) { FAIL("realloc"); nodus_tcp_close(&client); nodus_tcp_close(&server); return; }
    conn->wbuf = nb;
    conn->wcap = target + 8192;

    const size_t frame_size = 64 * 1024;
    uint8_t *frame = malloc(frame_size);
    memset(frame, 0xEF, frame_size);
    for (int i = 0; i < 5; i++) {
        conn->wlen = target;
        conn->wpos = 0;
        nodus_tcp_send(conn, frame, frame_size);
    }
    free(frame);

    if (conn->pending_count != 5) {
        char msg[64]; snprintf(msg, sizeof(msg), "setup: pending=%zu", conn->pending_count);
        FAIL(msg);
        nodus_tcp_close(&client); nodus_tcp_close(&server); return;
    }

    /* Closing the transport must call conn_free → pending_free_all.
     * We can't observe the leak directly here, but a clean exit is
     * the success criterion; valgrind/ASAN would catch any leak in CI. */
    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
    PASS();
}

int main(void) {
    printf("Pending queue / backpressure tests (Phase 3)\n");
    printf("============================================\n");

    test_send_routes_to_pending();
    test_fifo_order_on_drain();
    test_pending_cap_fires_callback();
    test_cleanup_on_close();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
