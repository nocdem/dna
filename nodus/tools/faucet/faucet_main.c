/**
 * @file faucet_main.c
 * @brief nodus-faucet — the testnet faucet service (NODUS + tUSDT).
 *
 * Governing records: docs/plans/decisions/2026-10-22-testnet-test-tokens-
 * faucet-dex.md and docs/plans/2026-10-22-testnet-faucet-design.md section 6.
 * Operation, config and API: nodus/docs/FAUCET.md.
 *
 *   nodus-faucet --config <file>                 run the service
 *   nodus-faucet --config <file> --print-address print the faucet's address
 *                                                (creates the key on first use)
 *
 * Threads: the main thread serves HTTP (decide + journal + answer); ONE
 * worker thread drives the oldest open claim. Both share the journal and the
 * node session through their own mutexes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "faucet_cfg.h"
#include "faucet_core.h"
#include "faucet_http.h"
#include "faucet_node_real.h"

#define LOG_TAG "FAUCET_MAIN"

static atomic_int g_stop = 0;
static void on_signal(int sig) { (void)sig; atomic_store(&g_stop, 1); }

static int rand_cb(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    return nodus_random(buf, len);
}

static void route_cb(void *ctx, const faucet_http_req_t *req, int *status,
                     char *body, size_t cap) {
    faucet_http_route((faucet_core_t *)ctx, req, status, body, cap);
}

static void sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *worker_main(void *arg) {
    faucet_core_t *core = arg;
    while (!atomic_load(&g_stop)) {
        int r = faucet_worker_step(core);
        if (r == 1) { sleep_ms(50); continue; }        /* progress: go on   */
        for (int waited = 0; waited < core->cfg->poll_ms && !atomic_load(&g_stop);
             waited += 100)
            sleep_ms(100);
    }
    return NULL;
}

/* The faucet's own identity: created on first use, loaded afterwards. */
static int load_or_create_identity(const char *dir, nodus_identity_t *id,
                                   int *created) {
    char pk_path[FAUCET_PATH_MAX + 16];
    snprintf(pk_path, sizeof(pk_path), "%s/nodus.pk", dir);
    *created = 0;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        QGP_LOG_ERROR(LOG_TAG, "cannot create key directory %s: %s", dir, strerror(errno));
        return -1;
    }
    chmod(dir, 0700);
    if (access(pk_path, F_OK) != 0) {
        nodus_identity_t fresh;
        if (nodus_identity_generate(&fresh) != 0 || nodus_identity_save(&fresh, dir) != 0) {
            nodus_identity_clear(&fresh);
            QGP_LOG_ERROR(LOG_TAG, "cannot create the faucet identity in %s", dir);
            return -1;
        }
        nodus_identity_clear(&fresh);
        *created = 1;
    }
    if (nodus_identity_load(dir, id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot load the faucet identity from %s", dir);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *cfg_path = NULL;
    int print_only = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) cfg_path = argv[++i];
        else if (!strcmp(argv[i], "--print-address")) print_only = 1;
        else {
            fprintf(stderr, "usage: %s --config <file> [--print-address]\n", argv[0]);
            return 2;
        }
    }
    if (!cfg_path) {
        fprintf(stderr, "usage: %s --config <file> [--print-address]\n", argv[0]);
        return 2;
    }
    umask(077);

    faucet_cfg_t cfg;
    char err[160];
    if (faucet_cfg_load(cfg_path, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "config refused: %s\n", err);
        return 1;
    }

    nodus_identity_t id;
    int created = 0;
    if (load_or_create_identity(cfg.key_dir, &id, &created) != 0) return 1;
    uint8_t fpraw[64];
    char self_hex[129];
    if (qgp_sha3_512(id.pk.bytes, NODUS_PK_BYTES, fpraw) != 0) return 1;
    qgp_fp_raw_to_hex(fpraw, self_hex);
    if (print_only) {
        printf("%s\n", self_hex);
        nodus_identity_clear(&id);
        return 0;
    }
    QGP_LOG_INFO(LOG_TAG, "faucet address%s: %s — fund this address with NODUS and tUSDT",
                 created ? " (NEW key created)" : "", self_hex);

    /* one instance only: the journal is the single source of "already paid" */
    char lock_path[FAUCET_PATH_MAX + 8];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", cfg.journal_path);
    int lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "another nodus-faucet holds %s (or it cannot be opened) — "
                      "refusing to start", lock_path);
        nodus_identity_clear(&id);
        return 1;
    }

    faucet_journal_t *journal = NULL;
    if (faucet_journal_open(cfg.journal_path, cfg.storage_ceiling, &journal) != 0) {
        nodus_identity_clear(&id);
        return 1;
    }
    faucet_node_t node;
    faucet_node_real_t *real = NULL;
    if (faucet_node_real_open(&cfg, &id, &real, &node) != 0) return 1;

    faucet_core_t core;
    if (faucet_core_init(&core, &cfg, &node, journal, id.pk.bytes, id.sk.bytes,
                         rand_cb, NULL) != 0) return 1;
    /* refuse to run on another chain (design 6 "Chain guard") */
    if (!faucet_core_check_chain(&core)) {
        QGP_LOG_ERROR(LOG_TAG, "the node did not confirm the configured chain id — "
                      "refusing to start");
        faucet_node_real_close(real);
        faucet_journal_close(journal);
        nodus_identity_clear(&id);
        return 1;
    }

    faucet_http_t *http = NULL;
    uint16_t bound = 0;
    if (faucet_http_open(cfg.listen_port, cfg.conn_cap, cfg.request_timeout_ms,
                         route_cb, &core, &http, &bound) != 0) return 1;
    QGP_LOG_INFO(LOG_TAG, "listening on 127.0.0.1:%u", bound);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    pthread_t worker;
    if (pthread_create(&worker, NULL, worker_main, &core) != 0) return 1;
    while (!atomic_load(&g_stop)) faucet_http_poll(http, 500);
    pthread_join(worker, NULL);

    faucet_http_close(http);
    faucet_node_real_close(real);
    faucet_journal_close(journal);
    nodus_identity_clear(&id);
    close(lock_fd);
    return 0;
}
