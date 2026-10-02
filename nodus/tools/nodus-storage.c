/**
 * Nodus — Storage process entry point (component split S5b)
 *
 * The DHT / storage half (Kademlia routing, the iterative lookup engine,
 * replication, republish, hinted handoff, listen subscriptions, batch
 * forward, nodus.db with media, channels.db) as its own process, decision
 * docs/plans/decisions/2026-10-01-nodus-component-split.md:
 *   - core (nodus-server with "storage_external") reaches it over
 *     <data_path>/storage.sock (items 7, 19; dht/nodus_dht_ipc.h) and keeps
 *     4000 / 4001 / 4002, sessions, cluster and presence (items 3, 4);
 *   - this process dials the peers' 4002 itself — replication, republish,
 *     hinted retry, listen forwarding, batch forward — on its own pool,
 *     with the shared pinned dialer (items 16, 28); it listens on no
 *     network port;
 *   - identity files are only READ here and a missing one refuses the
 *     start (item 10); the 4002 handshake signs with the identity's key;
 *   - the partial-wipe gate stays in core (item 9).
 *
 * Same command line and same config file as nodus-server
 * (nodus_node_config.c, item 18). Read here: data_path, identity_path,
 * require_peer_auth (the 4002 handshake of the dialed connections),
 * external_ip / bind_ip and peer_port (this node's own entry in the hash
 * ring, as nodus_server_init gives the in-process DHT). Everything else is
 * read and not used.
 *
 * storage_external is REQUIRED ("storage_external": true or
 * --storage-external): without it the same config would make a
 * nodus-server beside this process open nodus.db and channels.db itself —
 * two DHTs with one identity on one data_path. The process refuses to
 * start (exit 1) unless the loaded config has it, and holds an exclusive
 * lock on <data_path>/NODUS_STORAGE_LOCK_NAME for its lifetime, so a
 * second nodus-storage on one data_path refuses too.
 *
 * Loop: the IPC socket and the outbound pool (nodus_dht_ipc_poll, up to
 * 50 ms while idle), the runtime's own periodic work (nodus_dht_ipc_tick),
 * then ping-before-evict BEFORE the DHT's tick (Fable S5 g10: core ran the
 * evict sweep right after its cluster tick, ahead of the DHT tick; there
 * is no cluster tick here), then the DHT's tick (hinted retry,
 * subscriptions, lookups, batch forward, bucket refresh, cleanup,
 * republish, WAL checkpoint, vacuum).
 *
 * Usage:
 *   nodus-storage -c <config.json> --storage-external [-i <identity_dir>]
 *                 [-d <data_dir>] [-b <bind_ip>] [-p <peer_port>] [-h]
 */

#include "nodus_node_config.h"
#include "server/nodus_server.h"          /* nodus_server_config_t (type) */
#include "dht/nodus_dht.h"
#include "dht/nodus_dht_ipc.h"
#include "crypto/nodus_identity.h"
#include "crypto/utils/qgp_log.h"

#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "NODUS_STORAGE"

/* The lock file under data_path ("/tmp" when empty, as the IPC socket).
 * Its name matches none of the patterns the data directory's scans look
 * for (witness_<hex>.db*, nodus.db, channels.db). */
#define NODUS_STORAGE_LOCK_NAME  "nodus-storage.lock"

static volatile sig_atomic_t g_stop = 0;

static void sighandler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* An exclusive lock on <data_path>/NODUS_STORAGE_LOCK_NAME, held until the
 * process exits (the fd is never closed; the kernel releases the lock with
 * the process). @return the fd, or -1 (logged). */
static int take_data_lock(const char *data_path) {
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/%s",
                     data_path[0] ? data_path : "/tmp",
                     NODUS_STORAGE_LOCK_NAME);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        QGP_LOG_ERROR(LOG_TAG, "data path too long to form %s — not "
                      "starting", NODUS_STORAGE_LOCK_NAME);
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
            QGP_LOG_ERROR(LOG_TAG, "%s is held by another nodus-storage on "
                          "this data directory — not starting a second "
                          "DHT on the same databases", path);
        else
            QGP_LOG_ERROR(LOG_TAG, "cannot lock %s: %s — not starting",
                          path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    nodus_server_config_t config;
    memset(&config, 0, sizeof(config));

    int exit_code = nodus_node_config_load(argc, argv, "Nodus Storage",
                                           &config);
    if (exit_code >= 0)
        return exit_code;

    /* The misconfiguration guard: a config without storage_external is one
     * a nodus-server would read as "run the DHT in-process" — a second DHT
     * with this identity on these databases. */
    if (!config.storage_external) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the loaded config does not set "
                      "storage_external (\"storage_external\": true or "
                      "--storage-external). nodus-storage runs only beside a "
                      "nodus-server that has it too — otherwise that server "
                      "opens nodus.db and channels.db itself. Not starting.");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    /* Decision item 10: only core creates identity files. */
    if (!config.identity_path[0]) {
        fprintf(stderr, "NODUS_STORAGE: no identity directory (-i / "
                "\"identity_path\") — the storage process never creates an "
                "identity; start nodus-server first. Not starting.\n");
        return 1;
    }

    /* One nodus-storage per data directory, for the process lifetime —
     * taken before anything in the data directory is opened. Held, never
     * closed: the kernel releases it with the process. */
    if (take_data_lock(config.data_path) < 0)
        return 1;

    char sock_path[NODUS_TCP_UNIX_PATH_MAX];
    if (nodus_dht_ipc_sock_path(config.data_path, sock_path,
                                sizeof(sock_path)) != 0) {
        fprintf(stderr, "NODUS_STORAGE: the IPC socket path under \"%s\" "
                "does not fit %d bytes — not starting\n", config.data_path,
                NODUS_TCP_UNIX_PATH_MAX - 1);
        return 1;
    }

    nodus_identity_t identity;
    if (nodus_identity_load_readonly(config.identity_path, &identity) != 0) {
        fprintf(stderr, "NODUS_STORAGE: identity at %s is missing or "
                "incomplete — the storage process only reads it (start "
                "nodus-server first to create it). Not starting.\n",
                config.identity_path);
        return 1;
    }

    nodus_dht_ipc_t *ipc = nodus_dht_ipc_new(&identity,
                                             config.require_peer_auth);
    nodus_dht_t *dht = calloc(1, sizeof(*dht));
    if (!ipc || !dht) {
        fprintf(stderr, "NODUS_STORAGE: failed to allocate the storage "
                "runtime\n");
        nodus_dht_ipc_free(ipc);
        free(dht);
        nodus_identity_clear(&identity);
        return 1;
    }

    /* The DHT, with this process's host view (dht/nodus_dht_ipc.h): phase
     * one, then the databases, the routing table and the hash ring with
     * this node at its advertised address — the values nodus_server_init
     * gives the in-process DHT. */
    nodus_dht_host_t host;
    nodus_dht_ipc_host(ipc, &host);
    if (nodus_dht_init(dht, &host) != 0) {
        fprintf(stderr, "NODUS_STORAGE: DHT init failed (batch-forward epoll) "
                "— exiting\n");
        nodus_dht_ipc_free(ipc);
        free(dht);
        nodus_identity_clear(&identity);
        return 1;
    }
    uint16_t self_peer_port = config.peer_port ? config.peer_port
                                               : NODUS_DEFAULT_PEER_PORT;
    const char *self_ip = config.external_ip[0] ? config.external_ip
                                                : config.bind_ip;
    if (nodus_dht_open(dht, config.data_path, self_ip, self_peer_port) != 0) {
        fprintf(stderr, "NODUS_STORAGE: a database under \"%s\" did not open "
                "(the lines above say which) — exiting\n",
                config.data_path[0] ? config.data_path : "/tmp");
        nodus_dht_stop(dht);
        nodus_dht_close(dht);
        nodus_dht_ipc_free(ipc);
        free(dht);
        nodus_identity_clear(&identity);
        return 1;
    }
    nodus_dht_ipc_attach(ipc, dht);

    if (nodus_dht_ipc_listen(ipc, sock_path) != 0) {
        fprintf(stderr, "NODUS_STORAGE: cannot listen on %s (the lines above "
                "say why) — exiting\n", sock_path);
        nodus_dht_stop(dht);
        nodus_dht_close(dht);
        nodus_dht_ipc_free(ipc);
        free(dht);
        nodus_identity_clear(&identity);
        return 1;
    }

    fprintf(stderr, "Nodus storage v%s running\n", NODUS_VERSION_STRING);
    fprintf(stderr, "  Identity: %s\n", identity.fingerprint);
    fprintf(stderr, "  Data: %s\n", config.data_path[0] ? config.data_path
                                                         : "/tmp");
    fprintf(stderr, "  IPC socket: %s\n", sock_path);
    fprintf(stderr, "  4002 dials: %s\n", config.require_peer_auth
            ? "authenticated (require_peer_auth)" : "plaintext");

    while (!g_stop) {
        nodus_dht_ipc_poll(ipc, 50);
        nodus_dht_ipc_tick(ipc);
        nodus_dht_evict_tick(dht);
        nodus_dht_tick(dht);
    }

    fprintf(stderr, "Nodus storage: stopping\n");
    nodus_dht_stop(dht);
    nodus_dht_ipc_free(ipc);
    nodus_dht_close(dht);
    free(dht);
    nodus_identity_clear(&identity);
    return 0;
}
