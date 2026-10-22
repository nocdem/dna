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
 *                                                (creates the key on first use;
 *                                                the service must be stopped:
 *                                                it takes the same lock)
 *
 * Order of start: config -> the single-instance lock -> the identity (create
 * or load) -> journal -> node session -> chain guard -> HTTP -> worker. The
 * lock comes BEFORE any identity access, so two first starts can never both
 * generate a key and disagree about which one the funds belong to.
 *
 * Threads: the main thread serves HTTP (decide + journal + answer); ONE
 * worker thread drives the oldest open claim and keeps the funds cache
 * /status reads. Both share the journal and the node session through their
 * own mutexes.
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

static void route_cb(void *ctx, const faucet_http_req_t *req,
                     uint64_t deadline_ms, int *status, char *body, size_t cap) {
    faucet_http_route((faucet_core_t *)ctx, req, deadline_ms, status, body, cap);
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

/* ── the faucet's own identity ──────────────────────────────────────── */

/* The six files nodus_identity_load_readonly() requires. nodus.pk is the
 * "exists" signal and is written LAST. */
typedef struct { const char *name; const uint8_t *bytes; size_t len; } id_file_t;

static int fsync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

/* temp file (O_EXCL, 0600) -> write -> fsync -> rename -> fsync(dir). A
 * crash or error at any point leaves either no file at the final path or a
 * complete one; secret bytes go through write(2), never a stdio buffer. */
static int write_file_atomic(const char *dir, const char *name,
                             const uint8_t *bytes, size_t len) {
    char tmp[FAUCET_PATH_MAX + 64], fin[FAUCET_PATH_MAX + 64];
    int n1 = snprintf(tmp, sizeof(tmp), "%s/%s.tmp", dir, name);
    int n2 = snprintf(fin, sizeof(fin), "%s/%s", dir, name);
    if (n1 < 0 || (size_t)n1 >= sizeof(tmp) || n2 < 0 || (size_t)n2 >= sizeof(fin))
        return -1;
    unlink(tmp);                       /* a leftover of a crashed creation */
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, bytes + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, fin) != 0) { unlink(tmp); return -1; }
    return fsync_dir(dir);
}

/* How many of the six identity files exist (any kind of entry counts: a
 * present but unreadable file is not "absent"). */
static int count_identity_files(const char *dir, const id_file_t *f, int n) {
    int have = 0;
    for (int i = 0; i < n; i++) {
        char p[FAUCET_PATH_MAX + 64];
        snprintf(p, sizeof(p), "%s/%s", dir, f[i].name);
        struct stat sb;
        if (lstat(p, &sb) == 0) have++;
        else if (errno != ENOENT) return -1;
    }
    return have;
}

/* Create a fresh identity in `dir` atomically and durably. Nothing is left
 * behind on failure (the address is unknown to anyone until nodus.pk
 * exists, so undoing our own renames is safe). */
static int create_identity(const char *dir) {
    nodus_identity_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    int rc = -1;
    char fp_text[NODUS_KEY_HEX_LEN + 2];
    if (nodus_identity_generate(&fresh) != 0 || !fresh.has_kyber || !fresh.has_mlkem) {
        QGP_LOG_ERROR(LOG_TAG, "identity generation failed");
        goto out;
    }
    snprintf(fp_text, sizeof(fp_text), "%s\n", fresh.fingerprint);
    const id_file_t files[] = {
        { "nodus.kyber_pk",  fresh.kyber_pk,  NODUS_KYBER_PK_BYTES },
        { "nodus.kyber_sk",  fresh.kyber_sk,  NODUS_KYBER_SK_BYTES },
        { "nodus.mlkem_pk",  fresh.mlkem_pk,  NODUS_MLKEM_PK_BYTES },
        { "nodus.mlkem_sk",  fresh.mlkem_sk,  NODUS_MLKEM_SK_BYTES },
        { "nodus.sk",        fresh.sk.bytes,  NODUS_SK_BYTES },
        { "nodus.fp",        (const uint8_t *)fp_text, strlen(fp_text) },
        { "nodus.pk",        fresh.pk.bytes,  NODUS_PK_BYTES },   /* LAST */
    };
    const int nfiles = (int)(sizeof(files) / sizeof(files[0]));
    int written = 0;
    for (; written < nfiles; written++)
        if (write_file_atomic(dir, files[written].name, files[written].bytes,
                              files[written].len) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "cannot write %s/%s: %s", dir,
                          files[written].name, strerror(errno));
            break;
        }
    if (written == nfiles) { rc = 0; goto out; }
    for (int i = 0; i < nfiles; i++) {                 /* undo, pk first   */
        char p[FAUCET_PATH_MAX + 64];
        snprintf(p, sizeof(p), "%s/%s", dir, files[nfiles - 1 - i].name);
        unlink(p);
        snprintf(p, sizeof(p), "%s/%s.tmp", dir, files[nfiles - 1 - i].name);
        unlink(p);
    }
out:
    nodus_identity_clear(&fresh);
    return rc;
}

/* The faucet's identity: loaded when complete, created atomically when the
 * key directory holds none of it, REFUSED when it holds only part. The
 * single-instance lock is held by the caller. @return 0 / -1. */
static int load_or_create_identity(const char *dir, nodus_identity_t *id,
                                   int *created) {
    static const id_file_t names[] = {
        { "nodus.pk", NULL, 0 }, { "nodus.sk", NULL, 0 },
        { "nodus.kyber_pk", NULL, 0 }, { "nodus.kyber_sk", NULL, 0 },
        { "nodus.mlkem_pk", NULL, 0 }, { "nodus.mlkem_sk", NULL, 0 },
    };
    const int n = (int)(sizeof(names) / sizeof(names[0]));
    *created = 0;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        QGP_LOG_ERROR(LOG_TAG, "cannot create key directory %s: %s", dir, strerror(errno));
        return -1;
    }
    if (chmod(dir, 0700) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot restrict key directory %s: %s", dir, strerror(errno));
        return -1;
    }
    int have = count_identity_files(dir, names, n);
    if (have < 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot inspect the identity in %s: %s", dir, strerror(errno));
        return -1;
    }
    if (have != 0 && have != n) {
        QGP_LOG_ERROR(LOG_TAG, "the identity in %s is PARTIAL (%d of %d files) — "
                      "refusing to start or to create another key over it; "
                      "restore the missing files or move the directory away",
                      dir, have, n);
        return -1;
    }
    if (have == 0) {
        if (create_identity(dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "cannot create the faucet identity in %s", dir);
            return -1;
        }
        *created = 1;
    }
    /* read-only loader: never writes, never regenerates, refuses a short or
     * mismatched file; clears `id` itself on error */
    if (nodus_identity_load_readonly(dir, id) != 0) {
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

    /* Every resource below is released by the ONE cleanup path at `done`;
     * the identity is zero-initialised so that path may always wipe it. */
    int rc = 1;
    int lock_fd = -1;
    nodus_identity_t id;
    memset(&id, 0, sizeof(id));
    faucet_journal_t *journal = NULL;
    faucet_node_real_t *real = NULL;
    faucet_http_t *http = NULL;
    int worker_started = 0;
    pthread_t worker;
    faucet_core_t core;
    faucet_node_t node;

    /* one instance only: the journal is the single source of "already
     * paid" and the key directory has one owner — taken BEFORE the identity
     * is touched (also for --print-address) */
    char lock_path[FAUCET_PATH_MAX + 8];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", cfg.journal_path);
    lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "another nodus-faucet holds %s (or it cannot be opened) — "
                      "refusing to start", lock_path);
        goto done;
    }

    int created = 0;
    if (load_or_create_identity(cfg.key_dir, &id, &created) != 0) goto done;
    uint8_t fpraw[64];
    char self_hex[129];
    if (qgp_sha3_512(id.pk.bytes, NODUS_PK_BYTES, fpraw) != 0) goto done;
    qgp_fp_raw_to_hex(fpraw, self_hex);
    if (print_only) {
        printf("%s\n", self_hex);
        rc = 0;
        goto done;
    }
    QGP_LOG_INFO(LOG_TAG, "faucet address%s: %s — fund this address with NODUS and tUSDT",
                 created ? " (NEW key created)" : "", self_hex);

    if (faucet_journal_open(cfg.journal_path, cfg.storage_ceiling, &journal) != 0)
        goto done;
    if (faucet_node_real_open(&cfg, &id, &real, &node) != 0) goto done;
    if (faucet_core_init(&core, &cfg, &node, journal, id.pk.bytes, id.sk.bytes,
                         rand_cb, NULL) != 0) goto done;
    /* refuse to run on another chain (design 6 "Chain guard") */
    if (!faucet_core_check_chain(&core)) {
        QGP_LOG_ERROR(LOG_TAG, "the node did not confirm the configured chain id — "
                      "refusing to start");
        goto done;
    }

    uint16_t bound = 0;
    if (faucet_http_open(cfg.listen_port, cfg.conn_cap, cfg.request_timeout_ms,
                         route_cb, &core, &http, &bound) != 0) goto done;
    QGP_LOG_INFO(LOG_TAG, "listening on 127.0.0.1:%u", bound);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (pthread_create(&worker, NULL, worker_main, &core) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot start the worker thread");
        goto done;
    }
    worker_started = 1;
    while (!atomic_load(&g_stop)) faucet_http_poll(http, 500);
    rc = 0;

done:
    atomic_store(&g_stop, 1);
    if (worker_started) pthread_join(worker, NULL);
    faucet_http_close(http);
    faucet_node_real_close(real);
    faucet_journal_close(journal);
    nodus_identity_clear(&id);
    if (lock_fd >= 0) close(lock_fd);
    return rc;
}
