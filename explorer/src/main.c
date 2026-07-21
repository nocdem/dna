/* dna-explorerd — read-only DNAC chain indexer + JSON API (scan.cpunk.io)
 *
 * CLI:
 *   --config PATH    witness server list, "host port" per line (default
 *                     /etc/dna-explorer.conf; see exp_chain_config_load)
 *   --db PATH        sqlite index db path (default /var/lib/dna-explorer/index.db)
 *   --port N         JSON API listen port (default 8390), 127.0.0.1 only
 *   --once           run a single exp_sync_tick() and exit (smoke tests)
 *   --verify-index   run exp_db_verify_addr_stats() against --db and exit
 *                     0 (OK) / 1 (mismatch), no network involved
 *   --version        print version and exit
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "exp_chain.h"
#include "exp_db.h"
#include "exp_http.h"
#include "exp_sync.h"

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXPLORER"

#define EXPLORERD_VERSION "0.1.0"

#define EXPLORERD_DEFAULT_CONFIG "/etc/dna-explorer.conf"
#define EXPLORERD_DEFAULT_DB     "/var/lib/dna-explorer/index.db"
#define EXPLORERD_DEFAULT_PORT   8390

/* Set from a SIGINT/SIGTERM handler; polled by exp_sync_thread (once per
 * second) and by main's own join. A single-word flag write from a signal
 * handler is the standard async-signal-safe shutdown pattern — no
 * consensus/determinism path touches it (daemon lifecycle only). */
static volatile int g_stop = 0;

static void handle_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--config PATH] [--db PATH] [--port N] [--once] [--verify-index] [--version]\n",
        prog);
}

int main(int argc, char **argv) {
    const char *config_path = EXPLORERD_DEFAULT_CONFIG;
    const char *db_path = EXPLORERD_DEFAULT_DB;
    int port = EXPLORERD_DEFAULT_PORT;
    int once = 0;
    int verify_index = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("dna-explorerd %s\n", EXPLORERD_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--once") == 0) {
            once = 1;
        } else if (strcmp(argv[i], "--verify-index") == 0) {
            verify_index = 1;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (verify_index) {
        exp_db_t *db = NULL;
        if (exp_db_open(db_path, &db) != 0) {
            printf("verify-index: FAILED to open db %s\n", db_path);
            return 1;
        }
        int rc = exp_db_verify_addr_stats(db);
        printf("verify-index: %s\n", rc == 0 ? "OK (addr_stats matches tx_io derivation)" : "MISMATCH");
        exp_db_close(db);
        return rc == 0 ? 0 : 1;
    }

    QGP_LOG_INFO(LOG_TAG, "dna-explorerd %s starting (config=%s db=%s port=%d)",
                 EXPLORERD_VERSION, config_path, db_path, port);

    exp_server_t servers[EXP_CHAIN_MAX_SERVERS];
    int server_count = 0;
    if (exp_chain_config_load(config_path, servers, EXP_CHAIN_MAX_SERVERS, &server_count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to load witness server list from %s", config_path);
        return 1;
    }

    exp_chain_t *chain = NULL;
    if (exp_chain_open(&chain, servers, server_count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to connect to any configured witness server");
        return 1;
    }

    exp_db_t *db = NULL;
    if (exp_db_open(db_path, &db) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to open index db %s", db_path);
        exp_chain_close(chain);
        return 1;
    }

    if (once) {
        exp_reset_fsm_t fsm;
        memset(&fsm, 0, sizeof(fsm));
        exp_sync_preseed(db, &fsm);

        /* Single-shot, single-threaded: no concurrent HTTP reader exists,
         * so no db_lock is needed (Task 7). */
        int rc = exp_sync_tick(chain, &db, db_path, &fsm, NULL);

        exp_db_close(db);
        exp_chain_close(chain);
        return rc == 0 ? 0 : 1;
    }

    /* Daemon mode: sync thread + JSON API on the main thread + signal-driven
     * shutdown. Both share g_stop: a SIGINT/SIGTERM sets it once, the sync
     * thread notices within 1s (its own sleep loop), and exp_http_serve's
     * poll() loop notices within its own 1s timeout. */
    signal(SIGINT, handle_stop_signal);
    signal(SIGTERM, handle_stop_signal);

    /* Task 7 (chain-client-sharing race): the HTTP thread's ?utxos=1
     * passthrough gets its OWN exp_chain_t, opened against the same server
     * list, rather than sharing `chain` with the sync thread. Sharing meant
     * a failing HTTP utxo query could exp_chain_rotate -> nodus_client_close
     * a connection the sync thread was mid-call on (remotely triggerable
     * UAF). A failed open here is non-fatal — the utxos section already has
     * a "witness-live unavailable" degrade path (exp_http.c route_address)
     * for ctx->chain == NULL. */
    exp_chain_t *http_chain = NULL;
    if (exp_chain_open(&http_chain, servers, server_count) != 0) {
        QGP_LOG_WARN(LOG_TAG, "failed to open dedicated HTTP chain client — ?utxos=1 will report unavailable");
        http_chain = NULL;
    }

    /* Task 7 (db-swap race): guards *db against the sync thread's
     * confirmed-chain-reset close/rename/reopen swap racing an in-flight
     * HTTP request on the old handle. */
    pthread_rwlock_t db_lock;
    if (pthread_rwlock_init(&db_lock, NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to init db_lock");
        exp_chain_close(http_chain);
        exp_db_close(db);
        exp_chain_close(chain);
        return 1;
    }

    exp_sync_args_t sync_args;
    sync_args.chain = chain;
    sync_args.db = &db;
    sync_args.db_path = db_path;
    sync_args.stop = &g_stop;
    sync_args.db_lock = &db_lock;

    pthread_t sync_tid;
    if (pthread_create(&sync_tid, NULL, exp_sync_thread, &sync_args) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "failed to spawn sync thread");
        pthread_rwlock_destroy(&db_lock);
        exp_chain_close(http_chain);
        exp_db_close(db);
        exp_chain_close(chain);
        return 1;
    }

    exp_http_ctx_t http_ctx;
    /* Fix round 1, C1: &db, not db — the same location sync_args.db points
     * at, so the HTTP thread observes handle_confirmed_reset's swap
     * instead of dereferencing a copy that goes stale the moment the swap
     * happens. */
    http_ctx.db = &db;
    http_ctx.chain = http_chain;
    http_ctx.port = (uint16_t)port;
    http_ctx.stop = &g_stop;
    http_ctx.db_lock = &db_lock;

    if (exp_http_serve(&http_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_http_serve failed — requesting shutdown");
        g_stop = 1;
    }

    pthread_join(sync_tid, NULL);

    pthread_rwlock_destroy(&db_lock);
    exp_db_close(db);
    exp_chain_close(chain);
    exp_chain_close(http_chain);
    QGP_LOG_INFO(LOG_TAG, "dna-explorerd shutting down");
    return 0;
}
