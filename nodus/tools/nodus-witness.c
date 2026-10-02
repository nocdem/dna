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
 * ports, seeds as DHT seeds, ws_*, require_peer_auth) are read and not
 * used. --derive-v2-genesis works here too — the same one-shot, compiled
 * with this binary's own chain constants.
 *
 * witness_external is REQUIRED ("witness_external": true or
 * --witness-external): without it the same config would make a
 * nodus-server beside this process run its own witness in-process — a
 * second witness with the same validator key on the same data_path. The
 * process refuses to start (exit 1) unless the loaded config has it, and
 * holds an exclusive lock on <data_path>/NODUS_WITNESS_LOCK_NAME for its
 * lifetime, so a second nodus-witness on one data_path refuses too. (The
 * combined binary does not take that lock: doing so would change what it
 * does today — e.g. two of them on one data_path would newly refuse.)
 *
 * The p2p address-record sequence file (nodus.addr_seq) is written in
 * the DATA directory here, never in the identity directory: only core
 * writes the identity directory (item 10). Moving an existing host's
 * file from the identity directory is the installer's job (item 21);
 * this process only WARNs, once at start, when it sees the old file and
 * no new one — it never touches the identity directory. (Without the
 * file the witness numbers its next record from the highest own record
 * its address book — in the data directory — has seen:
 * nodus_witness_p2p.c own_record_start.)
 *
 * Usage:
 *   nodus-witness -c <config.json> --witness-external [-i <identity_dir>]
 *                 [-d <data_dir>] [-W <witness_port>] [-s id@<ip:port>]
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
#include "crypto/utils/qgp_log.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "NODUS_WITNESS"

/* The lock file under data_path ("/tmp" when empty, as the IPC socket).
 * Its name matches none of the patterns the data directory's scans look
 * for (witness_<hex>.db*, nodus.db, channels.db). */
#define NODUS_WITNESS_LOCK_NAME  "nodus-witness.lock"

/* The p2p address-record sequence file's name — NODUS_P2P_ADDR_SEQ_FILE,
 * defined in witness/nodus_witness_p2p.c (not exported); used here only
 * for the read-only "not migrated" check. */
#define NODUS_WITNESS_ADDR_SEQ_NAME  "nodus.addr_seq"

static volatile sig_atomic_t g_stop = 0;

static void sighandler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* The partial-wipe gate's marker (NODUS_PARTIAL_WIPE_GENESIS_MARKER): this
 * node completed a normal start with a chain. The combined binary writes
 * it at the END of nodus_server_init, when its witness has a chain open —
 * and, by then, nodus.db and channels.db exist too (see the O16A comment
 * there: the gate demands all three DBs or none, and a marker armed while
 * only the chain DB exists refuses the next start of a freshly derived
 * host). This process does not open those two, and may start before core
 * has created them; so it writes the marker only when the chain is open
 * AND both core databases are already present — the same "all three are
 * real" condition. Otherwise core arms it (nodus_server_run, external
 * mode). The gate itself stays in core (decision item 9). */
static bool core_dbs_present(const char *data_path) {
    static const char *const names[] = { "nodus.db", "channels.db" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char p[640];
        struct stat st;
        int n = snprintf(p, sizeof(p), "%s/%s",
                         data_path[0] ? data_path : "/tmp", names[i]);
        if (n < 0 || (size_t)n >= sizeof(p) || stat(p, &st) != 0)
            return false;
    }
    return true;
}

/* Not fatal, but loud (the combined binary's rule). */
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

/* An exclusive lock on <data_path>/NODUS_WITNESS_LOCK_NAME, held until the
 * process exits (the fd is never closed; the kernel releases the lock with
 * the process). @return the fd, or -1 (logged) — another nodus-witness
 * holds it, or the file cannot be opened. */
static int take_data_lock(const char *data_path) {
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/%s",
                     data_path[0] ? data_path : "/tmp",
                     NODUS_WITNESS_LOCK_NAME);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        QGP_LOG_ERROR(LOG_TAG, "data path too long to form %s — not "
                      "starting", NODUS_WITNESS_LOCK_NAME);
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot open %s: %s — not starting",
                      path, strerror(errno));
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK)
            QGP_LOG_ERROR(LOG_TAG, "%s is held by another nodus-witness on "
                          "this data directory — not starting a second "
                          "witness with the same validator key", path);
        else
            QGP_LOG_ERROR(LOG_TAG, "cannot lock %s: %s — not starting",
                          path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* Decisions 10 / 21: this process keeps nodus.addr_seq in the data
 * directory; moving an existing host's file out of the identity directory
 * is the installer's step. If that step has not run, say so once — the
 * witness then starts a NEW sequence in the data directory. Read-only:
 * two stat calls, nothing in either directory is touched. */
static void warn_addr_seq_not_migrated(const char *identity_path,
                                       const char *data_path) {
    char old_p[640], new_p[640];
    struct stat st;
    int a = snprintf(old_p, sizeof(old_p), "%s/%s", identity_path,
                     NODUS_WITNESS_ADDR_SEQ_NAME);
    /* The witness's own path for it (seq_dir "" → its data_path as
     * given, nodus_witness.c). */
    int b = snprintf(new_p, sizeof(new_p), "%s/%s", data_path,
                     NODUS_WITNESS_ADDR_SEQ_NAME);
    if (a < 0 || (size_t)a >= sizeof(old_p) ||
        b < 0 || (size_t)b >= sizeof(new_p))
        return;
    if (stat(old_p, &st) == 0 && stat(new_p, &st) != 0 && errno == ENOENT)
        QGP_LOG_WARN(LOG_TAG, "%s exists but %s does not — the address-"
                     "record sequence file was not migrated to the data "
                     "directory (installer step, decision 2026-10-01-"
                     "nodus-component-split item 21). This witness numbers "
                     "its next address record from the highest of its own "
                     "records its address book has seen, not from that "
                     "file, and keeps the sequence in %s; the old file is "
                     "left untouched", old_p, new_p, data_path);
}

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    int exit_code = nodus_node_config_load(argc, argv, "Nodus Witness",
                                           &config);
    if (exit_code >= 0)
        return exit_code;

    /* The misconfiguration guard: a config without witness_external is
     * one a nodus-server would read as "run the witness in-process" — a
     * second witness with this validator key on this data_path. */
    if (!config.witness_external) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the loaded config does not set "
                      "witness_external (\"witness_external\": true or "
                      "--witness-external). nodus-witness runs only beside "
                      "a nodus-server that has it too — otherwise that "
                      "server runs its own witness with the same validator "
                      "key. Not starting.");
        return 1;
    }

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

    /* One nodus-witness per data directory, for the process lifetime —
     * taken before anything in the data directory is opened. */
    /* Held, never closed: the kernel releases it with the process. */
    if (take_data_lock(config.data_path) < 0)
        return 1;

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
     * its witness (nodus_server_witness_host_config) except seq_dir,
     * this process's read-only identity, and the IPC session table as the
     * session lookup. seq_dir is emptied: the witness then keeps
     * nodus.addr_seq in data_path (nodus_witness.c), never in the
     * identity directory only core writes (decision item 10). */
    nodus_witness_host_t host;
    memset(&host, 0, sizeof(host));
    host.identity = &identity;
    nodus_server_witness_host_config(&config, &host.config);
    host.config.seq_dir[0] = '\0';
    warn_addr_seq_not_migrated(config.identity_path, config.data_path);
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

    if (w->db && core_dbs_present(config.data_path))
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
     * a busy loop. The IPC poll itself waits 0 ms while its own
     * pending-read list is non-empty (nodus_tcp_poll); the tick's 4004
     * wait is computed inside nodus_witness_tick and is not shortened
     * for it, so leftover IPC input can wait up to that 50 ms. */
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
