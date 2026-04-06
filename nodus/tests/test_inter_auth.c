/**
 * Nodus -- Inter-node Auth State Machine Tests
 *
 * Tests the auth gate in nodus_tcp_send(), pending queue, and send_raw bypass.
 */

#include "transport/nodus_tcp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Shared state for callbacks */
static int accepted_count = 0;
static int connected_count = 0;

static void on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    accepted_count++;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    connected_count++;
}

static void reset_counters(void) {
    accepted_count = 0;
    connected_count = 0;
}

/**
 * Helper: set up a server+client pair, wait for connection.
 * Returns the client-side connection (outbound conn).
 */
static nodus_tcp_conn_t *setup_pair(nodus_tcp_t *server, nodus_tcp_t *client,
                                     uint16_t port) {
    reset_counters();
    nodus_tcp_init(server, -1);
    nodus_tcp_init(client, -1);

    server->on_accept = on_accept;
    nodus_tcp_listen(server, "127.0.0.1", port);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(client, "127.0.0.1", server->port);

    for (int i = 0; i < 20 && (accepted_count == 0 ||
         (conn && conn->state != NODUS_CONN_CONNECTED)); i++) {
        nodus_tcp_poll(server, 10);
        nodus_tcp_poll(client, 10);
    }
    return conn;
}

static void cleanup_pair(nodus_tcp_t *server, nodus_tcp_t *client) {
    nodus_tcp_close(client);
    nodus_tcp_close(server);
}

/* ------------------------------------------------------------------ */

/**
 * Test 1: auth_required=false -> send goes directly to wbuf
 */
static void test_send_bypass_no_auth(void) {
    TEST("send bypasses gate when auth not required");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19800);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    /* auth_required defaults to false (calloc) */
    conn->auth_required = false;

    const uint8_t payload[] = "no-auth-test";
    int rc = nodus_tcp_send(conn, payload, sizeof(payload) - 1);

    /* rc==0 means it went to wbuf (possibly already flushed), not pending */
    if (rc == 0 && conn->pending_len == 0) {
        PASS();
    } else {
        FAIL("send should go to wbuf directly");
    }

    cleanup_pair(&server, &client);
}

/**
 * Test 2: auth_required=true, auth_state=HELLO_SENT -> queued to pending
 */
static void test_send_queues_during_auth(void) {
    TEST("send queues to pending during auth handshake");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19801);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    conn->auth_required = true;
    conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;

    const uint8_t payload[] = "queued-msg";
    size_t wlen_before = conn->wlen;
    int rc = nodus_tcp_send(conn, payload, sizeof(payload) - 1);

    if (rc == 0 && conn->pending_len > 0 && conn->wlen == wlen_before) {
        PASS();
    } else {
        FAIL("send should queue to pending_buf, not wbuf");
    }

    cleanup_pair(&server, &client);
}

/**
 * Test 3: auth_required=true, auth_state=AUTH_OK -> direct to wbuf
 */
static void test_send_direct_when_authed(void) {
    TEST("send goes to wbuf when auth completed");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19802);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    conn->auth_required = true;
    conn->auth_state = NODUS_CONN_AUTH_OK;

    const uint8_t payload[] = "authed-msg";
    int rc = nodus_tcp_send(conn, payload, sizeof(payload) - 1);

    /* rc==0 means it went through send_progress (wbuf path), not pending */
    if (rc == 0 && conn->pending_len == 0) {
        PASS();
    } else {
        FAIL("send should go to wbuf when AUTH_OK");
    }

    cleanup_pair(&server, &client);
}

/**
 * Test 4: auth_required=true, auth_state=FAILED -> returns -1
 */
static void test_send_fails_when_auth_failed(void) {
    TEST("send returns -1 when auth failed");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19803);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    conn->auth_required = true;
    conn->auth_state = NODUS_CONN_AUTH_FAILED;

    const uint8_t payload[] = "fail-msg";
    int rc = nodus_tcp_send(conn, payload, sizeof(payload) - 1);

    if (rc == -1) {
        PASS();
    } else {
        FAIL("send should return -1 on AUTH_FAILED");
    }

    cleanup_pair(&server, &client);
}

/**
 * Test 5: fill pending queue past 5MB cap -> returns -1
 */
static void test_pending_queue_cap(void) {
    TEST("pending queue rejects when 5MB cap exceeded");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19804);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    conn->auth_required = true;
    conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;

    /* Fill with 1MB chunks (each chunk + 7-byte frame header) */
    size_t chunk_sz = 1024 * 1024;
    uint8_t *chunk = malloc(chunk_sz);
    if (!chunk) {
        FAIL("malloc failed");
        cleanup_pair(&server, &client);
        return;
    }
    memset(chunk, 'X', chunk_sz);

    int last_rc = 0;
    int filled = 0;
    for (int i = 0; i < 10; i++) {
        last_rc = nodus_tcp_send(conn, chunk, chunk_sz);
        if (last_rc != 0) break;
        filled++;
    }

    free(chunk);

    /* Should have fit ~4 chunks (4MB + headers < 5MB) then failed on 5th or 6th */
    if (last_rc == -1 && filled >= 4 && filled <= 5) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "filled=%d, last_rc=%d (expected 4-5 fills then -1)",
                 filled, last_rc);
        FAIL(msg);
    }

    cleanup_pair(&server, &client);
}

/**
 * Test 6: send_raw bypasses auth gate
 */
static void test_send_raw_bypasses_gate(void) {
    TEST("send_raw bypasses auth gate");

    nodus_tcp_t server, client;
    nodus_tcp_conn_t *conn = setup_pair(&server, &client, 19805);
    if (!conn || conn->state != NODUS_CONN_CONNECTED) {
        FAIL("connection not established");
        cleanup_pair(&server, &client);
        return;
    }

    conn->auth_required = true;
    conn->auth_state = NODUS_CONN_AUTH_HELLO_SENT;

    const uint8_t payload[] = "raw-bypass";
    int rc = nodus_tcp_send_raw(conn, payload, sizeof(payload) - 1);

    /* rc==0 means it went through send_progress (wbuf path), not pending */
    if (rc == 0 && conn->pending_len == 0) {
        PASS();
    } else {
        FAIL("send_raw should go to wbuf directly, bypassing auth gate");
    }

    cleanup_pair(&server, &client);
}

/* ------------------------------------------------------------------ */

int main(void) {
    printf("=== Nodus Inter-node Auth State Machine Tests ===\n");

    test_send_bypass_no_auth();
    test_send_queues_during_auth();
    test_send_direct_when_authed();
    test_send_fails_when_auth_failed();
    test_pending_queue_cap();
    test_send_raw_bypasses_gate();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
