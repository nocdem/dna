/**
 * Nodus — server-init partial-failure cleanup regression (2026-07-21).
 *
 * Pins the fd-leak fix in nodus_server_init: when init fails MIDWAY (here:
 * the inter-node TCP bind loses its port to another process), every
 * resource acquired BEFORE the failure — most importantly the already-bound
 * client TCP listen socket — must be RELEASED, not leaked for the life of
 * the process.
 *
 * Observed bug (pre-fix, under `ctest -j`): a test's in-process server lost
 * a port race, init returned -1 after binding TCP, and the leaked LISTEN
 * socket held the port hostage, poisoning later runs.
 *
 *   T1  occupy the peer port (15202) with a dummy listener
 *       -> nodus_server_init(tcp=15201, peer=15202, ...) MUST fail
 *   T2  after the failure, binding tcp_port 15201 ourselves MUST succeed
 *       (pre-fix: EADDRINUSE — the leaked socket still held it)
 *   T3  control: with the dummy listener closed, the same config inits OK
 *       (proves T1 failed for the intended reason) and is torn down cleanly.
 *
 * Ports 152xx are unique to this test (ctest -j safe).
 */

#include "server/nodus_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int bind_listener(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void build_config(nodus_server_config_t *config) {
    memset(config, 0, sizeof(*config));
    snprintf(config->bind_ip, sizeof(config->bind_ip), "127.0.0.1");
    config->udp_port = 15200;
    config->tcp_port = 15201;
    config->peer_port = 15202;
    config->ch_port = 15203;
    config->witness_port = 15204;
    snprintf(config->data_path, sizeof(config->data_path),
             "/tmp/nodus_initfail_test_%d", (int)getpid());
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", config->data_path);
    if (system(cmd) != 0) { /* best-effort; storage open reports failure */ }
}

int main(void) {
    int fails = 0;
    printf("=== server-init partial-failure cleanup regression ===\n");

    nodus_server_config_t config;
    build_config(&config);

    /* Heap-alloc: nodus_server_t is multi-MB — stack alloc segfaults. */
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) { fprintf(stderr, "calloc failed\n"); return 2; }

    /* T1: peer port occupied -> init must fail. */
    int blocker = bind_listener(15202);
    if (blocker < 0) {
        fprintf(stderr, "cannot set up blocker listener\n");
        free(srv);
        return 2;
    }
    {
        int rc = nodus_server_init(srv, &config);
        int ok = rc != 0;
        printf("  T1 init FAILS while peer port is occupied         %s\n",
               ok ? "PASS" : "FAIL");
        if (!ok) {
            fails++;
            nodus_server_close(srv); /* it unexpectedly succeeded */
        }
    }

    /* T2: the client TCP port bound before the failure must be FREE now. */
    {
        int probe = bind_listener(15201);
        int ok = probe >= 0;
        printf("  T2 tcp_port released after failed init (no leak)  %s\n",
               ok ? "PASS" : "FAIL");
        if (ok) close(probe);
        else fails++;
    }

    close(blocker);

    /* T3: control — same config with the blocker gone inits OK. */
    {
        memset(srv, 0, sizeof(*srv));
        int rc = nodus_server_init(srv, &config);
        int ok = rc == 0;
        printf("  T3 control: init OK once the port is free         %s\n",
               ok ? "PASS" : "FAIL");
        if (ok) nodus_server_close(srv);
        else fails++;
    }

    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", config.data_path);
        if (system(cmd) != 0) { /* best-effort cleanup */ }
    }
    free(srv);

    if (fails == 0) {
        printf("SERVER INIT CLEANUP GATE: GREEN\n");
        return 0;
    }
    printf("SERVER INIT CLEANUP GATE: RED (%d failures)\n", fails);
    return 1;
}
