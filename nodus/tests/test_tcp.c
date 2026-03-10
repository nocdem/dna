/**
 * Nodus — TCP Transport Tests
 *
 * Tests loopback connect, frame send/receive, disconnect.
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
static int disconnected_count = 0;
static uint8_t received_payload[4096];
static size_t received_len = 0;
static int frame_count = 0;

static void on_accept(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    accepted_count++;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    connected_count++;
}

static void on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    disconnected_count++;
}

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                      size_t len, void *ctx) {
    (void)conn; (void)ctx;
    if (len <= sizeof(received_payload)) {
        memcpy(received_payload, payload, len);
        received_len = len;
    }
    frame_count++;
}

static void reset_counters(void) {
    accepted_count = 0;
    connected_count = 0;
    disconnected_count = 0;
    received_len = 0;
    frame_count = 0;
    memset(received_payload, 0, sizeof(received_payload));
}

static void test_init(void) {
    TEST("tcp init and close");
    nodus_tcp_t tcp;
    int rc = nodus_tcp_init(&tcp, -1);
    if (rc == 0 && tcp.epoll_fd >= 0 && tcp.owns_epoll) {
        nodus_tcp_close(&tcp);
        PASS();
    } else {
        nodus_tcp_close(&tcp);
        FAIL("init failed");
    }
}

static void test_listen(void) {
    TEST("tcp listen on port 0 (random)");
    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);

    int rc = nodus_tcp_listen(&tcp, "127.0.0.1", 0);
    if (rc == 0 && tcp.port > 0) {
        nodus_tcp_close(&tcp);
        PASS();
    } else {
        nodus_tcp_close(&tcp);
        FAIL("listen failed");
    }
}

static void test_connect_accept(void) {
    TEST("tcp connect and accept loopback");
    reset_counters();

    nodus_tcp_t server, client;
    nodus_tcp_init(&server, -1);
    nodus_tcp_init(&client, -1);

    server.on_accept = on_accept;
    nodus_tcp_listen(&server, "127.0.0.1", 0);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", server.port);

    /* Poll both sides */
    for (int i = 0; i < 10 && accepted_count == 0; i++) {
        nodus_tcp_poll(&server, 10);
        nodus_tcp_poll(&client, 10);
    }

    if (conn && conn->state == NODUS_CONN_CONNECTED && accepted_count == 1) {
        PASS();
    } else {
        FAIL("connect/accept failed");
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

static void test_send_receive_frame(void) {
    TEST("tcp send and receive frame");
    reset_counters();

    nodus_tcp_t server, client;
    nodus_tcp_init(&server, -1);
    nodus_tcp_init(&client, -1);

    server.on_accept = on_accept;
    server.on_frame = on_frame;
    nodus_tcp_listen(&server, "127.0.0.1", 0);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", server.port);

    /* Wait for connection */
    for (int i = 0; i < 10 && accepted_count == 0; i++) {
        nodus_tcp_poll(&server, 10);
        nodus_tcp_poll(&client, 10);
    }

    /* Send a payload */
    const uint8_t payload[] = "hello nodus";
    nodus_tcp_send(conn, payload, sizeof(payload) - 1);

    /* Poll until frame arrives */
    for (int i = 0; i < 10 && frame_count == 0; i++) {
        nodus_tcp_poll(&client, 10);
        nodus_tcp_poll(&server, 10);
    }

    if (frame_count == 1 && received_len == 11 &&
        memcmp(received_payload, "hello nodus", 11) == 0) {
        PASS();
    } else {
        FAIL("frame not received correctly");
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

static void test_multiple_frames(void) {
    TEST("tcp multiple frames in sequence");
    reset_counters();

    nodus_tcp_t server, client;
    nodus_tcp_init(&server, -1);
    nodus_tcp_init(&client, -1);

    server.on_accept = on_accept;
    server.on_frame = on_frame;
    nodus_tcp_listen(&server, "127.0.0.1", 0);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", server.port);

    for (int i = 0; i < 10 && accepted_count == 0; i++) {
        nodus_tcp_poll(&server, 10);
        nodus_tcp_poll(&client, 10);
    }

    /* Send 5 frames */
    for (int i = 0; i < 5; i++) {
        uint8_t msg[32];
        int len = snprintf((char *)msg, sizeof(msg), "msg-%d", i);
        nodus_tcp_send(conn, msg, (size_t)len);
    }

    /* Poll until all frames arrive */
    for (int i = 0; i < 50 && frame_count < 5; i++) {
        nodus_tcp_poll(&client, 10);
        nodus_tcp_poll(&server, 10);
    }

    if (frame_count == 5) {
        PASS();
    } else {
        FAIL("not all frames received");
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&server);
}

static void test_disconnect_callback(void) {
    TEST("tcp disconnect callback");
    reset_counters();

    nodus_tcp_t server, client;
    nodus_tcp_init(&server, -1);
    nodus_tcp_init(&client, -1);

    server.on_accept = on_accept;
    server.on_disconnect = on_disconnect;
    nodus_tcp_listen(&server, "127.0.0.1", 0);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", server.port);
    (void)conn;

    for (int i = 0; i < 10 && accepted_count == 0; i++) {
        nodus_tcp_poll(&server, 10);
        nodus_tcp_poll(&client, 10);
    }

    /* Close client — server should detect disconnect */
    nodus_tcp_close(&client);

    for (int i = 0; i < 10 && disconnected_count == 0; i++) {
        nodus_tcp_poll(&server, 10);
    }

    if (disconnected_count == 1) {
        PASS();
    } else {
        FAIL("disconnect not detected");
    }

    nodus_tcp_close(&server);
}

static void test_find_by_addr(void) {
    TEST("tcp find connection by address");
    reset_counters();

    nodus_tcp_t tcp;
    nodus_tcp_init(&tcp, -1);
    nodus_tcp_listen(&tcp, "127.0.0.1", 0);

    nodus_tcp_t client;
    nodus_tcp_init(&client, -1);
    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", tcp.port);

    for (int i = 0; i < 10 && tcp.count == 0; i++) {
        nodus_tcp_poll(&tcp, 10);
        nodus_tcp_poll(&client, 10);
    }

    /* Find the accepted connection on server side */
    nodus_tcp_conn_t *found = nodus_tcp_find_by_addr(&client, "127.0.0.1", tcp.port);

    if (found == conn) {
        PASS();
    } else {
        FAIL("find_by_addr failed");
    }

    nodus_tcp_close(&client);
    nodus_tcp_close(&tcp);
}

static void test_time_now(void) {
    TEST("nodus_time_now returns reasonable value");
    uint64_t t = nodus_time_now();
    /* Should be after 2026-01-01 (1735689600) */
    if (t > 1735689600ULL) {
        PASS();
    } else {
        FAIL("timestamp too old");
    }
}

int main(void) {
    printf("=== Nodus TCP Transport Tests ===\n");

    test_init();
    test_listen();
    test_connect_accept();
    test_send_receive_frame();
    test_multiple_frames();
    test_disconnect_callback();
    test_find_by_addr();
    test_time_now();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
