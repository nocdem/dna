/**
 * Phase 4 — concurrent cluster TPS bench.
 *
 * Drives N worker threads against a running Stage F cluster (or any
 * live nodus cluster), each submitting SPEND TXs via dna-connect-cli.
 * Measures submit TPS and commit latency histogram.
 *
 * Design notes:
 *  - Each worker owns a dedicated funded wallet (--wallet-dir lists
 *    paths; one per worker). This avoids nullifier collisions on
 *    parallel spends from the same wallet.
 *  - TX submission path is the real production CLI (fork/execve).
 *    The CLI `dna send` exits on success or timeout; exit code 0
 *    means TX submitted + committed.
 *  - Commit latency = wall time from fork() to child exit. This
 *    bundles submit + propagation + BFT round + DB commit.
 *
 * Not in scope (Phase 5 handles):
 *  - Cluster bring-up (stagef_up.sh)
 *  - Wallet funding (bench_run.sh calls stagef_mk_funded_user)
 *  - Per-layer QGP_BENCH counter dump (separate orchestration call)
 *
 * Output: single-line JSON matching the shape documented in
 * nodus/docs/plans/2026-04-24-perf-harness-design.md section 5/Phase 4.
 */

#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>

#define MAX_WORKERS      64
#define MAX_WALLETS      256
#define MAX_PATH_LEN     512
#define SPEND_AMOUNT_RAW 100ULL    /* minimal send, raw units */

typedef struct {
    int id;
    const char *wallet_home;   /* HOME for this worker's CLI calls */
    const char *recipient_fp;  /* destination fingerprint */
    const char *cli_bin;
    int duration_s;
    bench_histogram_t *hist;   /* shared; per-record via mutex-free atomic */
    _Atomic uint64_t *submitted;
    _Atomic uint64_t *committed;
    _Atomic uint64_t *failed;
    volatile int *stop;
} worker_ctx_t;

/* Shared histogram lock — simpler than lock-free push for 64-bit
 * arrays. Contention is low (one add per spend per worker). */
static pthread_mutex_t g_hist_lock = PTHREAD_MUTEX_INITIALIZER;

/* Fork-exec `cli_bin -q dna send <fp> <amount> <memo>` under the
 * worker's HOME. Returns wall ns of the child run, or 0 on fork fail.
 * Success (exit 0) -> *ok_out = 1; failure -> 0.
 *
 * NOTE on stdout/stderr: silence by redirecting to /dev/null so the
 * bench doesn't spray CLI output. Callers can re-enable for debugging. */
static uint64_t spend_one(const worker_ctx_t *w, int iter, int *ok_out) {
    *ok_out = 0;

    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%llu",
             (unsigned long long)SPEND_AMOUNT_RAW);
    char memo[64];
    snprintf(memo, sizeof(memo), "bench_w%d_i%d", w->id, iter);

    uint64_t t0 = bench_now_ns();
    pid_t pid = fork();
    if (pid < 0) return 0;

    if (pid == 0) {
        /* Child. Redirect stdout/stderr to /dev/null. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            close(devnull);
        }
        setenv("HOME", w->wallet_home, 1);
        setenv("DNA_NO_FALLBACK", "1", 1);
        /* argv: cli -q dna send fp amount memo */
        char *argv[] = {
            (char *)w->cli_bin, (char *)"-q", (char *)"dna", (char *)"send",
            (char *)w->recipient_fp, amount_str, memo, NULL
        };
        execv(w->cli_bin, argv);
        _exit(127);
    }

    /* Parent. Wait for child. */
    int status = 0;
    waitpid(pid, &status, 0);
    uint64_t dt = bench_now_ns() - t0;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        *ok_out = 1;
    }
    return dt;
}

static void *worker_main(void *arg) {
    worker_ctx_t *w = (worker_ctx_t *)arg;
    uint64_t deadline_ns = bench_now_ns()
        + (uint64_t)w->duration_s * 1000000000ULL;

    int iter = 0;
    while (!*w->stop && bench_now_ns() < deadline_ns) {
        int ok = 0;
        uint64_t dt = spend_one(w, iter++, &ok);
        atomic_fetch_add(w->submitted, 1);
        if (ok) {
            atomic_fetch_add(w->committed, 1);
            pthread_mutex_lock(&g_hist_lock);
            bench_histogram_record(w->hist, dt);
            pthread_mutex_unlock(&g_hist_lock);
        } else {
            atomic_fetch_add(w->failed, 1);
        }
    }
    return NULL;
}

/* ── Arg parsing ────────────────────────────────────────────────── */

typedef struct {
    const char *cli_bin;
    const char *wallets_file;   /* newline-separated wallet HOME dirs */
    const char *recipient_fp;
    int concurrency;
    int duration_s;
    const char *output_path;    /* stdout if NULL */
    const char *nodus_version;  /* for JSON metadata */
} config_t;

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s \\\n"
        "    --cli /path/to/dna-connect-cli \\\n"
        "    --wallets /path/to/wallets.txt  (newline-separated HOME dirs)\\\n"
        "    --recipient <129-hex fingerprint> \\\n"
        "    --concurrency N \\\n"
        "    --duration SECONDS \\\n"
        "    [--output FILE] [--version X.Y.Z]\n",
        p);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->concurrency = 4;
    cfg->duration_s = 30;
    cfg->nodus_version = "unknown";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cli") == 0 && i + 1 < argc) {
            cfg->cli_bin = argv[++i];
        } else if (strcmp(argv[i], "--wallets") == 0 && i + 1 < argc) {
            cfg->wallets_file = argv[++i];
        } else if (strcmp(argv[i], "--recipient") == 0 && i + 1 < argc) {
            cfg->recipient_fp = argv[++i];
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            cfg->concurrency = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            cfg->duration_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            cfg->output_path = argv[++i];
        } else if (strcmp(argv[i], "--version") == 0 && i + 1 < argc) {
            cfg->nodus_version = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return -1;
        }
    }
    if (!cfg->cli_bin || !cfg->wallets_file || !cfg->recipient_fp) {
        usage(argv[0]);
        return -1;
    }
    if (cfg->concurrency < 1 || cfg->concurrency > MAX_WORKERS) {
        fprintf(stderr, "concurrency must be 1..%d\n", MAX_WORKERS);
        return -1;
    }
    if (cfg->duration_s < 1) {
        fprintf(stderr, "duration must be >= 1\n");
        return -1;
    }
    return 0;
}

/* Read wallets file into a static-capacity array of strings. Returns
 * count, or -1 on error. Caller frees with free_wallets. */
static char *g_wallets[MAX_WALLETS];
static int g_wallet_count = 0;

static int load_wallets(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen wallets"); return -1; }
    char line[MAX_PATH_LEN];
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' ||
                         line[n-1] == ' '  || line[n-1] == '\t')) {
            line[--n] = '\0';
        }
        if (n == 0) continue;
        if (g_wallet_count >= MAX_WALLETS) break;
        g_wallets[g_wallet_count] = strdup(line);
        if (!g_wallets[g_wallet_count]) { fclose(f); return -1; }
        g_wallet_count++;
    }
    fclose(f);
    return g_wallet_count;
}

static void free_wallets(void) {
    for (int i = 0; i < g_wallet_count; i++) free(g_wallets[i]);
    g_wallet_count = 0;
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    config_t cfg;
    if (parse_args(argc, argv, &cfg) != 0) return 1;

    if (load_wallets(cfg.wallets_file) < 0) {
        fprintf(stderr, "failed to load wallets from %s\n", cfg.wallets_file);
        return 1;
    }
    if (g_wallet_count < cfg.concurrency) {
        fprintf(stderr,
            "need at least %d wallets (got %d) for concurrency=%d\n",
            cfg.concurrency, g_wallet_count, cfg.concurrency);
        free_wallets();
        return 1;
    }

    bench_histogram_t hist;
    if (bench_histogram_init(&hist,
            (size_t)cfg.concurrency * (size_t)cfg.duration_s * 64) != 0) {
        fprintf(stderr, "histogram init failed\n");
        free_wallets();
        return 1;
    }

    _Atomic uint64_t submitted = 0;
    _Atomic uint64_t committed = 0;
    _Atomic uint64_t failed    = 0;
    volatile int stop = 0;

    pthread_t threads[MAX_WORKERS];
    worker_ctx_t ctxs[MAX_WORKERS];
    for (int i = 0; i < cfg.concurrency; i++) {
        ctxs[i].id            = i;
        ctxs[i].wallet_home   = g_wallets[i];
        ctxs[i].recipient_fp  = cfg.recipient_fp;
        ctxs[i].cli_bin       = cfg.cli_bin;
        ctxs[i].duration_s    = cfg.duration_s;
        ctxs[i].hist          = &hist;
        ctxs[i].submitted     = &submitted;
        ctxs[i].committed     = &committed;
        ctxs[i].failed        = &failed;
        ctxs[i].stop          = &stop;
    }

    uint64_t bench_start = bench_now_ns();
    for (int i = 0; i < cfg.concurrency; i++) {
        if (pthread_create(&threads[i], NULL, worker_main, &ctxs[i]) != 0) {
            fprintf(stderr, "pthread_create failed for worker %d\n", i);
            stop = 1;
            break;
        }
    }
    for (int i = 0; i < cfg.concurrency; i++) {
        pthread_join(threads[i], NULL);
    }
    uint64_t bench_total_ns = bench_now_ns() - bench_start;

    /* Stats */
    uint64_t s = atomic_load(&submitted);
    uint64_t c = atomic_load(&committed);
    uint64_t f = atomic_load(&failed);
    double dur_s = (double)bench_total_ns / 1e9;
    double tps_submit = dur_s > 0 ? (double)s / dur_s : 0;
    double tps_commit = dur_s > 0 ? (double)c / dur_s : 0;
    double success_rate = s > 0 ? (double)c / (double)s : 0;

    /* Build extra JSON fragment. */
    char extra[512];
    snprintf(extra, sizeof(extra),
        "\"concurrency\":%d,\"duration_s\":%d,"
        "\"tx_submitted\":%llu,\"tx_committed\":%llu,\"tx_failed\":%llu,"
        "\"tps_submit\":%.3f,\"tps_commit\":%.3f,"
        "\"submit_success_rate\":%.4f,"
        "\"nodus_version\":\"%s\",\"wallets_available\":%d",
        cfg.concurrency, cfg.duration_s,
        (unsigned long long)s, (unsigned long long)c, (unsigned long long)f,
        tps_submit, tps_commit, success_rate,
        cfg.nodus_version, g_wallet_count);

    /* Redirect stdout if requested. */
    FILE *saved_stdout = NULL;
    if (cfg.output_path) {
        FILE *out = fopen(cfg.output_path, "w");
        if (!out) { perror("fopen output"); bench_histogram_free(&hist);
                    free_wallets(); return 1; }
        saved_stdout = stdout;
        stdout = out;
    }

    bench_emit_json("cluster_tps", c, bench_total_ns,
                    c > 0 ? &hist : NULL, extra);

    if (saved_stdout) {
        fclose(stdout);
        stdout = saved_stdout;
    }

    bench_histogram_free(&hist);
    free_wallets();
    return 0;
}
