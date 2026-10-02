/**
 * Nodus — Witness process entry point (component split S3)
 *
 * The witness module (port 4004 p2p host + the Comet consensus lane) as
 * its own process, decision docs/plans/decisions/2026-10-01-nodus-
 * component-split.md: consensus runs independently of core (item 5); core
 * reaches it over <data_path>/witness.sock (items 7, 19 — the IPC listener,
 * witness/nodus_witness_ipc.h); identity files are only READ here and a
 * missing one refuses the start (item 10); an init failure exits non-zero
 * so the unit's Restart=on-failure takes over (item 11).
 *
 * Same command line and same config file as nodus-server
 * (nodus_node_config.c, item 18); the DHT/core-only settings (UDP/TCP/peer
 * ports, seeds as DHT seeds, ws_*, require_peer_auth, witness_external)
 * are read and not used. --derive-v2-genesis works here too — the same
 * one-shot, compiled with this binary's own chain constants.
 *
 * Usage:
 *   nodus-witness -c <config.json> [-i <identity_dir>] [-d <data_dir>]
 *                 [-W <witness_port>] [-s id@<ip:port>]
 *                 [--v2-genesis-pin <64hex>] [--network-file <path>] [-h]
 */

#include "nodus_node_config.h"
#include "server/nodus_server.h"            /* nodus_server_config_t, the
                                               witness config subset (inline) */
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_host.h"
#include "witness/nodus_witness_ipc.h"
#include "witness/nodus_witness_p2p.h"
#include "witness/nodus_witness_network_file.h"
#include "crypto/nodus_identity.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_stop = 0;

static void sighandler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* The partial-wipe gate's marker (NODUS_PARTIAL_WIPE_GENESIS_MARKER): this
 * node completed a normal start with a chain. The combined binary writes
 * it at the end of nodus_server_init when its witness has a chain open
 * (see the O16A comment there); a node whose witness runs here gets it
 * from here, under the same condition. The gate itself stays in core
 * (decision item 9). Not fatal, but loud. */
static void write_genesis_marker(const char *data_path) {
    char marker[640];
    int mk = snprintf(marker, sizeof(marker), "%s/%s",
                      data_path[0] ? data_path : "/tmp",
                      NODUS_PARTIAL_WIPE_GENESIS_MARKER);
    if (mk < 0 || (size_t)mk >= sizeof(marker)) {
        fprintf(stderr,
            "NODUS_WITNESS: WARNING data path too long to form %s — the "
            "partial-wipe gate stays OPEN on this node\n",
            NODUS_PARTIAL_WIPE_GENESIS_MARKER);
        return;
    }
    FILE *mf = fopen(marker, "w");
    if (mf) {
        fclose(mf);
    } else {
        fprintf(stderr,
            "NODUS_WITNESS: WARNING failed to write %s: %s — the "
            "partial-wipe gate stays OPEN on this node's next boot\n",
            marker, strerror(errno));
    }
}

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    int exit_code = nodus_node_config_load(argc, argv, "Nodus Witness",
                                           &config);
    if (exit_code >= 0)
        return exit_code;

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    /* Decision item 10: only core creates identity files; this process
     * reads them and refuses to start without them. */
    if (!config.identity_path[0]) {
        fprintf(stderr, "NODUS_WITNESS: no identity directory (-i / "
                "\"identity_path\") — the witness never creates an "
                "identity; start nodus-server first. Not starting.\n");
        return 1;
    }

    /* The network file's pin-at-start check, against the chain this
     * process is about to open (nodus_server_init runs the same check in
     * the combined binary). */
    if (config.has_network_pin &&
        nodus_witness_check_chain_pin(config.data_path,
                                      config.network_pin) != 0) {
        fprintf(stderr, "NODUS_WITNESS: the network file's pin does not "
                "match the chain in %s — not starting\n", config.data_path);
        return 1;
    }

    char sock_path[NODUS_TCP_UNIX_PATH_MAX];
    if (nodus_witness_ipc_sock_path(config.data_path, sock_path,
                                    sizeof(sock_path)) != 0) {
        fprintf(stderr, "NODUS_WITNESS: the IPC socket path under \"%s\" "
                "does not fit %d bytes — not starting\n", config.data_path,
                NODUS_TCP_UNIX_PATH_MAX - 1);
        return 1;
    }

    nodus_identity_t identity;
    if (nodus_identity_load_readonly(config.identity_path, &identity) != 0) {
        fprintf(stderr, "NODUS_WITNESS: identity at %s is missing or "
                "incomplete — the witness only reads it (start nodus-server "
                "first to create it). Not starting.\n", config.identity_path);
        return 1;
    }

    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) {
        fprintf(stderr, "NODUS_WITNESS: failed to allocate the witness "
                "context\n");
        nodus_identity_clear(&identity);
        return 1;
    }

    nodus_witness_ipc_handlers_t handlers;
    nodus_witness_ipc_handlers_for(w, &handlers);
    nodus_witness_ipc_t *ipc = nodus_witness_ipc_new(&handlers);
    if (!ipc) {
        fprintf(stderr, "NODUS_WITNESS: failed to create the IPC "
                "transport\n");
        free(w);
        nodus_identity_clear(&identity);
        return 1;
    }

    /* The host view: the same config subset the combined binary gives
     * its witness (nodus_server_witness_host_config — seq_dir =
     * identity_path), this process's read-only identity, and the IPC
     * session table as the session lookup. */
    nodus_witness_host_t host;
    memset(&host, 0, sizeof(host));
    host.identity = &identity;
    nodus_server_witness_host_config(&config, &host.config);
    host.find_session_conn = nodus_witness_ipc_find_session_conn;
    host.ctx = ipc;

    if (nodus_witness_init(w, &host, &config.witness) != 0) {
        /* Decision item 11: exit non-zero; systemd restarts the unit.
         * The witness stops its own p2p host on this path, so it is
         * freed without nodus_witness_close (as the in-process backend
         * does). */
        fprintf(stderr,
            "ERROR: WITNESS MODULE INIT FAILED — nodus-witness EXITS (code "
            "1)\n");
        fprintf(stderr,
            "ERROR:   cause:     named in the WITNESS lines above — a chain "
            "database that is\n"
            "ERROR:              PRESENT but unusable (with its sqlite "
            "fault), a refused startup\n"
            "ERROR:              gate, or an unmet bootstrap "
            "precondition.\n");
        fprintf(stderr,
            "ERROR:   DHT / clients: unaffected — they run in nodus-server; "
            "dnac_* requests are\n"
            "ERROR:              answered \"" NODUS_CHAIN_NO_WITNESS_MSG
            "\" until this process is back.\n");
        nodus_witness_ipc_free(ipc);
        free(w);
        nodus_identity_clear(&identity);
        return 1;
    }

    if (w->db)
        write_genesis_marker(config.data_path);

    if (nodus_witness_ipc_listen(ipc, sock_path) != 0) {
        fprintf(stderr, "NODUS_WITNESS: cannot listen on %s (the lines above "
                "say why) — exiting\n", sock_path);
        nodus_witness_close(w);
        nodus_witness_ipc_free(ipc);
        free(w);
        nodus_identity_clear(&identity);
        return 1;
    }

    fprintf(stderr, "Nodus witness v%s running\n", NODUS_VERSION_STRING);
    fprintf(stderr, "  Identity: %s\n", identity.fingerprint);
    fprintf(stderr, "  Witness port: %d%s\n",
            (int)nodus_witness_p2p_listen_port(w->p2p),
            w->p2p ? "" : " (not opened)");
    fprintf(stderr, "  IPC socket: %s\n", sock_path);

    /* nodus_witness_tick waits up to 50 ms in the 4004 poll — but only
     * while it runs and its p2p host exists. Without a p2p host (no
     * chain, no pin), or once the witness has stopped itself (a CMT_FAULT
     * ends consensus participation: `running` false, the process stays
     * up exactly as the combined binary's witness half does), the tick
     * returns at once, so the IPC poll does the waiting instead — never
     * a busy loop. */
    while (!g_stop) {
        nodus_witness_tick(w);
        nodus_witness_ipc_poll(ipc, (w->running && w->p2p) ? 0 : 50);
    }

    fprintf(stderr, "Nodus witness: stopping\n");
    nodus_witness_close(w);
    nodus_witness_ipc_free(ipc);
    free(w);
    nodus_identity_clear(&identity);
    return 0;
}
