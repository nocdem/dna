/**
 * Nodus — transport diagnostics must go through QGP_LOG, not stderr (D-22)
 *
 * nodus_tcp.c used to print nine fixed-format lines straight to stderr
 * (TCP_CONN: ALLOC / FREE / FD_SET, TCP_SEND_FIRST, TX_ENCRYPT_FIRST,
 * ENCRYPT_CALL, PENDING_DRAIN, FIND_DUP). They ignored the log level and
 * reached every user's console (nodus-light, nodus-cli) on each connection.
 *
 * Proves: a full loopback life cycle (listen, connect, accept, one frame,
 *   find-by-address, close) writes none of those markers to file
 *   descriptor 2, with the default log level.
 * Flags/env: none (no QGP_LOG_LEVEL override; stderr is redirected to a
 *   temporary file for the duration of the case and restored).
 * Leaves behind: nothing (the temporary file is unlinked).
 * How it can falsely pass: only the markers listed below are searched, so
 *   a new unlisted stderr line is not caught; and a marker line removed
 *   together with its code path would also pass. FIND_DUP needs two
 *   connections to the same address and is not provoked here; it is
 *   covered by the source change, not by this case. Before the fix the
 *   ALLOC / FD_SET / FREE markers are present and the case fails.
 */

#include "transport/nodus_tcp.h"
#include "nodus/nodus_types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static const char *const MARKERS[] = {
    "TCP_CONN:", "TCP_SEND_FIRST", "TX_ENCRYPT_FIRST", "ENCRYPT_CALL",
    "PENDING_DRAIN", "FIND_DUP",
};

static void on_accept_stub(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

int main(void) {
    char path[] = "/tmp/test_tcp_no_stderr_XXXXXX";
    int tmp = mkstemp(path);
    if (tmp < 0) { printf("FAIL: mkstemp\n"); return 1; }

    fflush(stderr);
    int saved = dup(2);
    if (saved < 0 || dup2(tmp, 2) < 0) {
        printf("FAIL: redirect stderr\n");
        unlink(path);
        return 1;
    }

    nodus_tcp_t server, client;
    nodus_tcp_init(&server, -1);
    nodus_tcp_init(&client, -1);
    server.on_accept = on_accept_stub;
    nodus_tcp_listen(&server, "127.0.0.1", 0);
    nodus_tcp_conn_t *conn = nodus_tcp_connect(&client, "127.0.0.1", server.port);
    for (int i = 0; i < 20 && (!conn || conn->state != NODUS_CONN_CONNECTED); i++) {
        nodus_tcp_poll(&server, 10);
        nodus_tcp_poll(&client, 10);
    }
    int connected = conn && conn->state == NODUS_CONN_CONNECTED;
    if (connected) {
        const uint8_t payload[16] = { 0 };
        nodus_tcp_send(conn, payload, sizeof(payload));
        for (int i = 0; i < 5; i++) {
            nodus_tcp_poll(&client, 5);
            nodus_tcp_poll(&server, 5);
        }
        (void)nodus_tcp_find_by_addr(&client, "127.0.0.1", server.port);
    }
    nodus_tcp_close(&client);
    nodus_tcp_close(&server);

    fflush(stderr);
    dup2(saved, 2);
    close(saved);

    int bad = 0;
    char buf[4096];
    lseek(tmp, 0, SEEK_SET);
    ssize_t n;
    size_t total = 0;
    static char all[1 << 16];
    while ((n = read(tmp, buf, sizeof(buf))) > 0 && total + (size_t)n < sizeof(all)) {
        memcpy(all + total, buf, (size_t)n);
        total += (size_t)n;
    }
    all[total] = '\0';
    close(tmp);
    unlink(path);

    for (size_t i = 0; i < sizeof(MARKERS) / sizeof(MARKERS[0]); i++) {
        if (strstr(all, MARKERS[i])) {
            printf("FAIL: stderr carries '%s'\n", MARKERS[i]);
            bad++;
        }
    }
    if (!connected) { printf("FAIL: loopback connect did not complete\n"); bad++; }

    if (bad == 0) printf("PASS: no transport diagnostics on stderr\n");
    return bad ? 1 : 0;
}
