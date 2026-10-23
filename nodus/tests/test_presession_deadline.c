/**
 * Nodus — the pre-session deadline of accepting transports (DHT v2 3b-2,
 * Kurultay #43 O-5): 15 s after the last socket byte, 30 s after connect,
 * whichever comes first, on the MONOTONIC clock; an authenticated session is
 * never touched.
 *
 * PROVES (nodus_tcp_sc_presession_sweep, nodus_server.h NODUS_PRESESSION_*):
 *   D1  an accepted connection that never completes the handshake survives
 *       idle-1 ms and is closed at idle ms after its last activity;
 *   D2  a connection that keeps trickling (activity just before every look)
 *       is still closed at the 30 s absolute bound from connect;
 *   D3  a connection whose SecretConnection became AUTHENTICATED is never
 *       closed by the sweep, however late the look;
 *   D4  the deadline reads the monotonic stamps, not the wall-clock ones:
 *       moving connected_at / last_activity (the wall-clock fields) far into
 *       the past changes nothing.
 *
 * HOW: a transport that accepts with the layer enabled (the th_ helper), the
 * time handed to the sweep is injected (connected_mono_ms + n) — no sleeps,
 * no clock reads in the assertions. D3 runs a real handshake between two
 * transports in this thread (bounded polls).
 *
 * REQUIRES: default build, loopback. LEAVES: nothing.
 * HOW IT CAN LIE: the injected times prove the thresholds, not that the
 * server loop calls the sweep once a second (nodus_server.c presession_tick);
 * D3's "authenticated" depends on the handshake completing inside its
 * bounded poll — otherwise the case FAILs (never passes vacuously).
 */

#include "test_session_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDLE_MS 15000u
#define ABS_MS  30000u

static int passed = 0, failed = 0;
#define CHECK(c, name) do { if (c) { printf("  PASS %s\n", name); passed++; } \
                            else { printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); failed++; } } while (0)

static nodus_tcp_t g_srv, g_cli;
static th_node_t g_node;
static nodus_tcp_conn_t *g_accepted;
static int g_sessions;

static void on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)ctx;
    g_accepted = conn;
    if (th_node_accept(&g_srv, conn, &g_node) != 0) nodus_tcp_disconnect(&g_srv, conn);
}

static void on_session(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    g_sessions++;
}

static void pump(int n) {
    for (int i = 0; i < n; i++) {
        nodus_tcp_poll(&g_srv, 2);
        nodus_tcp_poll(&g_cli, 2);
    }
}

/* a plain TCP client that connects and says nothing */
static nodus_tcp_conn_t *silent_client(void) {
    g_accepted = NULL;
    nodus_tcp_conn_t *c = nodus_tcp_connect(&g_cli, "127.0.0.1", g_srv.port);
    for (int i = 0; c && i < 400 && !g_accepted; i++) pump(1);
    return g_accepted ? c : NULL;
}

int main(void) {
    printf("=== pre-session deadline (monotonic, injected time) ===\n");
    if (th_node_init(&g_node, 0x44) != 0 ||
        nodus_tcp_init(&g_srv, -1) != 0 || nodus_tcp_init(&g_cli, -1) != 0) {
        printf("FATAL: setup\n");
        return 1;
    }
    g_srv.on_accept = on_accept;
    g_srv.on_session = on_session;
    if (nodus_tcp_listen(&g_srv, "127.0.0.1", 0) != 0) { printf("FATAL: listen\n"); return 1; }

    /* D1 idle */
    {
        nodus_tcp_conn_t *c = silent_client();
        CHECK(c && g_accepted, "D1 connection accepted");
        uint64_t t0 = g_accepted->last_activity_mono_ms;
        CHECK(nodus_tcp_sc_presession_sweep(&g_srv, t0 + IDLE_MS - 1, IDLE_MS, ABS_MS) == 0,
              "D1 idle-1 ms: kept");
        CHECK(nodus_tcp_sc_presession_sweep(&g_srv, t0 + IDLE_MS, IDLE_MS, ABS_MS) == 1,
              "D1 idle ms: closed");
    }

    /* D2 absolute (trickle) */
    {
        nodus_tcp_conn_t *c = silent_client();
        CHECK(c && g_accepted, "D2 connection accepted");
        uint64_t t0 = g_accepted->connected_mono_ms;
        nodus_tcp_conn_t *acc = g_accepted;
        acc->last_activity_mono_ms = t0 + ABS_MS - 1;    /* active right now */
        CHECK(nodus_tcp_sc_presession_sweep(&g_srv, t0 + ABS_MS - 1, IDLE_MS, ABS_MS) == 0,
              "D2 absolute-1 ms with fresh activity: kept");
        acc->last_activity_mono_ms = t0 + ABS_MS;        /* still trickling */
        CHECK(nodus_tcp_sc_presession_sweep(&g_srv, t0 + ABS_MS, IDLE_MS, ABS_MS) == 1,
              "D2 absolute ms: closed although never idle");
    }

    /* D4 wall-clock fields are not read */
    {
        nodus_tcp_conn_t *c = silent_client();
        CHECK(c && g_accepted, "D4 connection accepted");
        g_accepted->connected_at = 1;           /* 1970 */
        g_accepted->last_activity = 1;
        uint64_t t0 = g_accepted->last_activity_mono_ms;
        CHECK(nodus_tcp_sc_presession_sweep(&g_srv, t0 + 1000, IDLE_MS, ABS_MS) == 0,
              "D4 ancient wall-clock stamps do not close a fresh connection");
        nodus_tcp_sc_presession_sweep(&g_srv, t0 + ABS_MS, IDLE_MS, ABS_MS);
    }

    /* D3 authenticated: a real handshake */
    {
        g_accepted = NULL;
        g_sessions = 0;
        nodus_tcp_conn_t *c = nodus_tcp_connect(&g_cli, "127.0.0.1", g_srv.port);
        nodus_identity_t client_id;
        nodus_tcp_sc_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        bool ok = c && nodus_identity_generate(&client_id) == 0;
        if (ok) {
            cfg.role = CMT_P2P_SC_ROLE_INITIATOR;
            cfg.profile = &CMT_P2P_SC_PROFILE_CLIENT;
            cfg.id = &client_id;
            cfg.proto_ver = NODUS_CSESS_PROTO_VERSION;
            memcpy(cfg.chain_id, g_node.chain_id, sizeof(cfg.chain_id));
            cfg.expected_peer = &g_node.pin;
            ok = nodus_tcp_sc_enable(&g_cli, c, &cfg) == 0;
        }
        for (int i = 0; ok && i < 1500 && g_sessions < 1; i++) pump(1);
        CHECK(ok && g_sessions == 1 && g_accepted && nodus_tcp_sc_authenticated(g_accepted),
              "D3 handshake completes");
        int closed = nodus_tcp_sc_presession_sweep(&g_srv, g_accepted ? g_accepted->connected_mono_ms + 3600000u : 0,
                                                   IDLE_MS, ABS_MS);
        CHECK(closed == 0, "D3 an authenticated session is never closed by the sweep");
        nodus_identity_clear(&client_id);
    }

    nodus_tcp_close(&g_cli);
    nodus_tcp_close(&g_srv);
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
