/**
 * Nodus — Core process entry point (component split S6)
 *
 * The server's core roles as their own process, decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md: UDP 4000
 * (Kademlia ping/pong + cluster), TCP 4001 client sessions, the one 4002
 * inter-node listener, presence, circuits, the partial-wipe gate (items
 * 2, 3, 4, 6, 9). It is the only process that creates and writes the
 * identity files (item 10). It reaches its DHT / storage half
 * (nodus-storage, <data_path>/storage.sock) and its witness
 * (nodus-witness, <data_path>/witness.sock) over IPC only — it links no
 * in-process DHT or witness object (tests/core_linked.cmake).
 *
 * BOTH storage_external and witness_external are REQUIRED ("..._external":
 * true or --storage-external --witness-external): this binary carries
 * neither half in-process, so a config without them describes a node it
 * cannot be. The process refuses to start (exit 1). A combined or
 * half-split node runs nodus-server (decision item 8: it stays).
 *
 * Same command line and config file as nodus-server (nodus_node_config.c,
 * item 18), WITHOUT the witness-side parts (nodus_node_config_load_storage):
 * the 4004 p2p section, the network file and its pin are nodus-witness's
 * to read, and --derive-v2-genesis is refused here (run it with
 * nodus-server or nodus-witness). `--v2-genesis-pin` is parsed and not
 * used — the joiner is the witness.
 *
 * Usage:
 *   nodus-core -c <config.json> --storage-external --witness-external
 *              [-b <bind_ip>] [-u <udp_port>] [-t <tcp_port>]
 *              [-p <peer_port>] [-i <identity_dir>] [-d <data_dir>]
 *              [-s <seed_ip:port>] [-h]
 */

#include "nodus_node_config.h"
#include "server/nodus_server.h"
#include "crypto/utils/qgp_log.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "NODUS_CORE"

static nodus_server_t server;

static void sighandler(int sig) {
    (void)sig;
    nodus_server_stop(&server);
}

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    /* The parse without the witness-side parts: this binary links no
     * witness object (tests/core_linked.cmake). */
    int exit_code = nodus_node_config_load_storage(argc, argv, "Nodus Core",
                                                   &config);
    if (exit_code >= 0)
        return exit_code;

    /* The misconfiguration guard (nodus_server_backends_ipc's admit says
     * the same thing; refusing here keeps the signal handlers and the
     * server untouched). */
    if (!config.storage_external || !config.witness_external) {
        QGP_LOG_ERROR(LOG_TAG, "the loaded config does not set both "
                      "storage_external and witness_external "
                      "(storage_external=%s, witness_external=%s). "
                      "nodus-core runs only beside a nodus-storage and a "
                      "nodus-witness on the same data directory; a combined "
                      "or half-split node runs nodus-server. Not starting.",
                      config.storage_external ? "true" : "false",
                      config.witness_external ? "true" : "false");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    memset(&server, 0, sizeof(server));

    if (nodus_server_init_ex(&server, &config, &nodus_server_backends_ipc) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "core init failed (the lines above say "
                      "why) — exiting");
        nodus_server_close(&server);
        return 1;
    }

    int rc = nodus_server_run(&server);
    nodus_server_close(&server);
    return rc;
}
