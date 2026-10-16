/**
 * Nodus — portable TCP listener test (Linux/Android and Windows)
 *
 * What it proves: the server half of nodus_tcp.c — nodus_tcp_listen,
 * accept through nodus_tcp_poll, frame I/O on an accepted connection, close —
 * works through the public API alone, and the plain listener's per-IP
 * admission limit (NODUS_MAX_CONNS_PER_IP, CRIT-5) refuses the connection
 * past the limit. Nothing here is platform-specific: the same source is
 * meant to build on Linux (epoll loop) and with mingw (select loop), so the
 * Windows build of the transport is held to the same behaviour.
 *
 * Cases:
 *   1. listen on 127.0.0.1 port 0, the bound port is read back (> 0)
 *   2. connect + accept, one frame client -> server and one server -> client,
 *      client closes, the server sees on_disconnect for its connection
 *   3. NODUS_MAX_CONNS_PER_IP + 1 connections from 127.0.0.1: the server
 *      runs on_accept exactly NODUS_MAX_CONNS_PER_IP times, and exactly one
 *      client connection is closed by the server
 *
 * Requires: a default build; no environment, no fixed port (the kernel
 * picks it), no files. Leaves nothing behind.
 *
 * How it can lie: every wait is bounded by a count of poll rounds
 * (MAX_ROUNDS), not by time; if a round count is exhausted the case FAILS,
 * it never passes silently. Case 3 counts connections by callbacks, so it
 * does not prove WHICH connection was refused — only that the limit held.
 */

#include "transport/nodus_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

/* Upper bound on poll rounds for any one wait. Each round polls both
 * transports with a 10 ms wait; a wait ends as soon as its condition holds. */
#define MAX_ROUNDS 2000

static int passed = 0;
static int failed = 0;

/* One record per transport, passed as cb_ctx. */
typedef struct {
    int               accepted;
    int               connected;
    int               disconnected;
    int               frames;
    uint8_t           last[64];
    size_t            last_len;
    nodus_tcp_conn_t *last_accepted;
} side_t;

static void on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    side_t *s = (side_t *)ctx;
    s->accepted++;
    s->last_accepted = conn;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn;
    ((side_t *)ctx)->connected++;
}

static void on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    side_t *s = (side_t *)ctx;
    if (s->last_accepted == conn)
        s->last_accepted = NULL;
    s->disconnected++;
}

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                     size_t len, void *ctx) {
    (void)conn;
    side_t *s = (side_t *)ctx;
    if (len <= sizeof(s->last)) {
        memcpy(s->last, payload, len);
        s->last_len = len;
    }
    s->frames++;
}

static void setup(nodus_tcp_t *tcp, side_t *s) {
    memset(s, 0, sizeof(*s));
    nodus_tcp_init(tcp, -1);
    tcp->on_accept     = on_accept;
    tcp->on_connect    = on_connect;
    tcp->on_disconnect = on_disconnect;
    tcp->on_frame      = on_frame;
    tcp->cb_ctx        = s;
}

static void pump(nodus_tcp_t *a, nodus_tcp_t *b) {
    nodus_tcp_poll(a, 10);
    nodus_tcp_poll(b, 10);
}

/* 1 — listen on an ephemeral port */
static void test_listen_ephemeral(void) {
    TEST("listen on 127.0.0.1:0, bound port read back");
    nodus_tcp_t srv;
    side_t ss;
    setup(&srv, &ss);
    int rc = nodus_tcp_listen(&srv, "127.0.0.1", 0);
    if (rc == 0 && srv.port > 0 && srv.listen_fd >= 0)
        PASS();
    else
        FAIL("nodus_tcp_listen failed or port not read back");
    nodus_tcp_close(&srv);
}

/* 2 — accept, frame both ways, close */
static void test_accept_frames_close(void) {
    TEST("accept, frame client->server and server->client, close");
    nodus_tcp_t srv, cli;
    side_t ss, cs;
    setup(&srv, &ss);
    setup(&cli, &cs);

    if (nodus_tcp_listen(&srv, "127.0.0.1", 0) != 0) {
        FAIL("listen");
        nodus_tcp_close(&srv);
        nodus_tcp_close(&cli);
        return;
    }

    nodus_tcp_conn_t *c = nodus_tcp_connect(&cli, "127.0.0.1", srv.port);
    if (!c) {
        FAIL("connect");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }

    int r;
    for (r = 0; r < MAX_ROUNDS &&
                (ss.accepted == 0 || c->state != NODUS_CONN_CONNECTED); r++)
        pump(&srv, &cli);
    if (ss.accepted != 1 || !ss.last_accepted || c->state != NODUS_CONN_CONNECTED) {
        FAIL("no accept / connect");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }

    const uint8_t up[] = "ping-from-client";
    if (nodus_tcp_send(c, up, sizeof(up) - 1) != 0) {
        FAIL("client send");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }
    for (r = 0; r < MAX_ROUNDS && ss.frames == 0; r++)
        pump(&cli, &srv);
    if (ss.frames != 1 || ss.last_len != sizeof(up) - 1 ||
        memcmp(ss.last, up, sizeof(up) - 1) != 0) {
        FAIL("server did not receive the client frame");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }

    const uint8_t down[] = "pong-from-server";
    if (nodus_tcp_send(ss.last_accepted, down, sizeof(down) - 1) != 0) {
        FAIL("server send");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }
    for (r = 0; r < MAX_ROUNDS && cs.frames == 0; r++)
        pump(&srv, &cli);
    if (cs.frames != 1 || cs.last_len != sizeof(down) - 1 ||
        memcmp(cs.last, down, sizeof(down) - 1) != 0) {
        FAIL("client did not receive the server frame");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }

    /* Client closes; the server must notice and release its connection. */
    nodus_tcp_disconnect(&cli, c);
    for (r = 0; r < MAX_ROUNDS && ss.disconnected == 0; r++)
        nodus_tcp_poll(&srv, 10);
    if (ss.disconnected == 1 && ss.last_accepted == NULL && srv.count == 0)
        PASS();
    else
        FAIL("server did not see the close");

    nodus_tcp_close(&cli);
    nodus_tcp_close(&srv);
}

/* 3 — per-IP admission limit of the plain listener */
static void test_per_ip_limit(void) {
    TEST("per-IP limit: NODUS_MAX_CONNS_PER_IP admitted, one more refused");
    nodus_tcp_t srv, cli;
    side_t ss, cs;
    setup(&srv, &ss);
    setup(&cli, &cs);

    if (nodus_tcp_listen(&srv, "127.0.0.1", 0) != 0) {
        FAIL("listen");
        nodus_tcp_close(&srv);
        nodus_tcp_close(&cli);
        return;
    }

    const int want = NODUS_MAX_CONNS_PER_IP + 1;
    int opened = 0;
    for (int i = 0; i < want; i++)
        if (nodus_tcp_connect(&cli, "127.0.0.1", srv.port)) opened++;
    if (opened != want) {
        FAIL("could not open the client connections");
        nodus_tcp_close(&cli);
        nodus_tcp_close(&srv);
        return;
    }

    /* The server accepts one connection per poll; the refused one is closed
     * by the server right after accept and the client reads EOF. */
    int r;
    for (r = 0; r < MAX_ROUNDS &&
                (ss.accepted < NODUS_MAX_CONNS_PER_IP || cs.disconnected < 1); r++)
        pump(&srv, &cli);
    /* A few more rounds: a second refusal or an over-limit on_accept would
     * show up here. Bounded by count, not time. */
    for (int extra = 0; extra < 20; extra++)
        pump(&srv, &cli);

    if (ss.accepted == NODUS_MAX_CONNS_PER_IP &&
        srv.count == NODUS_MAX_CONNS_PER_IP &&
        cs.disconnected == 1 &&
        cli.count == NODUS_MAX_CONNS_PER_IP) {
        PASS();
    } else {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "accepted=%d srv.count=%d client_disconnects=%d cli.count=%d",
                 ss.accepted, srv.count, cs.disconnected, cli.count);
        FAIL(msg);
    }

    nodus_tcp_close(&cli);
    nodus_tcp_close(&srv);
}

int main(void) {
    printf("Nodus portable TCP listener tests\n");
    test_listen_ephemeral();
    test_accept_frames_close();
    test_per_ip_limit();
    printf("\n  %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
