/**
 * Nodus — Server Entry Point
 *
 * Start a Nodus DHT server with optional config file.
 *
 * Usage:
 *   nodus-server [-c <config.json>] [-b <bind_ip>] [-u <udp_port>]
 *                [-t <tcp_port>] [-i <identity_dir>] [-d <data_dir>]
 *                [-s <seed_ip:port>] [-h]
 *
 * The options, the JSON config keys, the network file and the
 * --derive-v2-genesis one-shot live in nodus_node_config.c, shared with
 * nodus-witness (component split S3); this file only runs the server.
 */

#include "nodus_node_config.h"
#include "server/nodus_server.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>

static nodus_server_t server;

static void sighandler(int sig) {
    (void)sig;
    nodus_server_stop(&server);
}

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    int exit_code = nodus_node_config_load(argc, argv, "Nodus Server",
                                           &config);
    if (exit_code >= 0)
        return exit_code;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    memset(&server, 0, sizeof(server));

    if (nodus_server_init(&server, &config) != 0) {
        fprintf(stderr, "Server init failed\n");
        nodus_server_close(&server);
        return 1;
    }

    int rc = nodus_server_run(&server);
    nodus_server_close(&server);
    return rc;
}
