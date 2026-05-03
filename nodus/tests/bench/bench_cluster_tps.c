/**
 * Phase 4/6 — concurrent cluster TPS bench (burst mode).
 *
 * Drives a pool of funded wallets against a running Stage F cluster
 * to measure **cluster** commit throughput, not per-client latency.
 *
 * Model: each round fires one dna-connect-cli `dna send` process per
 * wallet IN PARALLEL (not sequentially), then waits for all children
 * with a timeout cap. This saturates the mempool to expose the true
 * BFT commit cadence — limited by min(batch cap / block interval,
 * mempool depth / block interval).
 *
 * Wallet-per-process is mandatory: two parallel spends from the same
 * wallet pick the same UTXO/nullifier -> one commits, the other fails.
 *
 * Output: single-line JSON with cluster-level TPS metrics:
 *   tps_commit      — committed TX / wall time
 *   blocks_observed — full rounds that completed in the window
 *   batch_fill_pct  — committed / (rounds * NODUS_W_MAX_BLOCK_TXS)
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE        /* for usleep() */

#include "bench_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define MAX_WALLETS      256
#define MAX_PATH_LEN     512
#define SPEND_AMOUNT_RAW 100ULL    /* minimal send, raw units */
#define CHILD_TIMEOUT_S  60        /* kill any CLI stuck longer */

typedef struct {
    const char *cli_bin;
    const char *wallets_file;
    const char *recipient_fp;
    int duration_s;
    int burst_size;              /* wallets to fire per round; 0 = all */
    const char *output_path;
    const char *nodus_version;
} config_t;

static char *g_wallets[MAX_WALLETS];
static int g_wallet_count = 0;

/* ── Child launcher ─────────────────────────────────────────────── */

static pid_t launch_spend(const config_t *cfg, const char *wallet_home,
                          int round, int widx) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) return pid;

    /* Child. Redirect noisy stdout/stderr to /dev/null. */
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, 1);
        dup2(devnull, 2);
        close(devnull);
    }
    setenv("HOME", wallet_home, 1);
    setenv("DNA_NO_FALLBACK", "1", 1);

    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%llu",
             (unsigned long long)SPEND_AMOUNT_RAW);
    char memo[64];
    snprintf(memo, sizeof(memo), "burst_r%d_w%d", round, widx);

    char *argv[] = {
        (char *)cfg->cli_bin, (char *)"-q", (char *)"dna", (char *)"send",
        (char *)cfg->recipient_fp, amount_str, memo, NULL
    };
    execv(cfg->cli_bin, argv);
    _exit(127);
}

/* Collect all children with timeout. Records per-child (ok, ns_elapsed).
 * Kills any still running after timeout_s from round_t0. */
typedef struct {
    pid_t pid;
    uint64_t t0_ns;
    uint64_t dt_ns;
    int ok;
    int done;
} child_t;

static void reap_all(child_t *ch, int n, uint64_t deadline_ns) {
    int remaining = n;
    while (remaining > 0) {
        int status = 0;
        pid_t pid;
        uint64_t now = bench_now_ns();
        if (now >= deadline_ns) {
            /* Timeout: SIGKILL any not yet done, then non-blocking reap. */
            for (int i = 0; i < n; i++) {
                if (!ch[i].done && ch[i].pid > 0) {
                    kill(ch[i].pid, SIGKILL);
                }
            }
            /* Brief spin to harvest zombies. */
            for (int spin = 0; spin < 200 && remaining > 0; spin++) {
                pid = waitpid(-1, &status, WNOHANG);
                if (pid <= 0) { usleep(50 * 1000); continue; }
                for (int i = 0; i < n; i++) {
                    if (!ch[i].done && ch[i].pid == pid) {
                        ch[i].done = 1;
                        ch[i].dt_ns = bench_now_ns() - ch[i].t0_ns;
                        ch[i].ok = 0;  /* timed out */
                        remaining--;
                        break;
                    }
                }
            }
            /* Anything still unreaped: mark as timed out to avoid hang. */
            for (int i = 0; i < n; i++) {
                if (!ch[i].done) {
                    ch[i].done = 1;
                    ch[i].dt_ns = bench_now_ns() - ch[i].t0_ns;
                    ch[i].ok = 0;
                    remaining--;
                }
            }
            break;
        }
        pid = waitpid(-1, &status, 0);
        if (pid < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            if (!ch[i].done && ch[i].pid == pid) {
                ch[i].done = 1;
                ch[i].dt_ns = bench_now_ns() - ch[i].t0_ns;
                ch[i].ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                remaining--;
                break;
            }
        }
    }
}

/* ── Wallets file ───────────────────────────────────────────────── */

static int load_wallets(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("fopen wallets"); return -1; }
    char line[MAX_PATH_LEN];
    while (fgets(line, sizeof(line), f) && g_wallet_count < MAX_WALLETS) {
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r' ||
                         line[n-1] == ' '  || line[n-1] == '\t')) {
            line[--n] = '\0';
        }
        if (n == 0) continue;
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

/* ── Arg parsing ────────────────────────────────────────────────── */

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s \\\n"
        "    --cli /path/to/dna-connect-cli \\\n"
        "    --wallets /path/to/wallets.txt \\\n"
        "    --recipient <129-hex fingerprint> \\\n"
        "    --duration SECONDS \\\n"
        "    [--burst-size N]     (default: all wallets per round)\\\n"
        "    [--output FILE] [--version X.Y.Z]\n"
        "\n"
        "Each round fires `burst_size` parallel dna-connect-cli `dna send`\n"
        "processes (one per wallet) and waits for all to complete or\n"
        "timeout (%d s cap). Repeats until duration elapses.\n",
        p, CHILD_TIMEOUT_S);
}

static int parse_args(int argc, char **argv, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->duration_s = 30;
    cfg->burst_size = 0;  /* 0 = all */
    cfg->nodus_version = "unknown";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cli") == 0 && i + 1 < argc) {
            cfg->cli_bin = argv[++i];
        } else if (strcmp(argv[i], "--wallets") == 0 && i + 1 < argc) {
            cfg->wallets_file = argv[++i];
        } else if (strcmp(argv[i], "--recipient") == 0 && i + 1 < argc) {
            cfg->recipient_fp = argv[++i];
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            cfg->duration_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--burst-size") == 0 && i + 1 < argc) {
            cfg->burst_size = atoi(argv[++i]);
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
    if (cfg->duration_s < 1) {
        fprintf(stderr, "duration must be >= 1\n");
        return -1;
    }
    return 0;
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    config_t cfg;
    if (parse_args(argc, argv, &cfg) != 0) return 1;

    if (load_wallets(cfg.wallets_file) < 0) {
        fprintf(stderr, "failed to load wallets from %s\n", cfg.wallets_file);
        return 1;
    }
    int burst = (cfg.burst_size > 0 && cfg.burst_size < g_wallet_count)
                ? cfg.burst_size : g_wallet_count;
    if (burst < 1) {
        fprintf(stderr, "no wallets to spend with\n");
        free_wallets();
        return 1;
    }

    /* Histogram sized generously: assume up to 1 round per second. */
    bench_histogram_t hist;
    size_t hist_cap = (size_t)burst * (size_t)cfg.duration_s;
    if (hist_cap < 16) hist_cap = 16;
    if (bench_histogram_init(&hist, hist_cap) != 0) {
        fprintf(stderr, "histogram init failed\n");
        free_wallets();
        return 1;
    }

    uint64_t bench_t0 = bench_now_ns();
    uint64_t deadline = bench_t0 + (uint64_t)cfg.duration_s * 1000000000ULL;

    uint64_t submitted = 0, committed = 0, failed = 0;
    uint64_t rounds = 0;

    child_t *ch = calloc((size_t)burst, sizeof(child_t));
    if (!ch) {
        fprintf(stderr, "calloc failed\n");
        bench_histogram_free(&hist);
        free_wallets();
        return 1;
    }

    while (bench_now_ns() < deadline) {
        /* Launch burst. */
        uint64_t round_t0 = bench_now_ns();
        memset(ch, 0, (size_t)burst * sizeof(child_t));
        for (int i = 0; i < burst; i++) {
            ch[i].t0_ns = bench_now_ns();
            ch[i].pid = launch_spend(&cfg, g_wallets[i],
                                      (int)rounds, i);
            if (ch[i].pid > 0) {
                submitted++;
            } else {
                ch[i].done = 1;
                ch[i].ok = 0;
                failed++;
            }
        }
        /* Wait all children with per-child timeout cap. */
        uint64_t round_deadline = round_t0
            + (uint64_t)CHILD_TIMEOUT_S * 1000000000ULL;
        reap_all(ch, burst, round_deadline);

        for (int i = 0; i < burst; i++) {
            if (!ch[i].done) continue;  /* shouldn't happen */
            if (ch[i].pid > 0) {
                if (ch[i].ok) {
                    committed++;
                    bench_histogram_record(&hist, ch[i].dt_ns);
                } else {
                    failed++;
                }
            }
        }
        rounds++;
    }

    uint64_t bench_total_ns = bench_now_ns() - bench_t0;
    double dur_s = (double)bench_total_ns / 1e9;
    double tps_submit = dur_s > 0 ? (double)submitted / dur_s : 0;
    double tps_commit = dur_s > 0 ? (double)committed / dur_s : 0;
    double success_rate = submitted > 0
        ? (double)committed / (double)submitted : 0;

    /* Heuristic block accounting: NODUS_W_MAX_BLOCK_TXS is the compile
     * cap (10); batch_fill_pct assumes every round fills at most one
     * block. Real block count would require per-node dump — until
     * Phase 7 (SIGUSR1 handler) lands, this is best-effort. */
    double batch_fill_pct = 0.0;
    if (rounds > 0) {
        double expected_cap = (double)rounds * 10.0;
        if (expected_cap > 0) {
            batch_fill_pct = (double)committed / expected_cap * 100.0;
        }
    }

    char extra[640];
    snprintf(extra, sizeof(extra),
        "\"mode\":\"burst\","
        "\"burst_size\":%d,"
        "\"wallet_pool\":%d,"
        "\"duration_s\":%d,"
        "\"rounds\":%llu,"
        "\"tx_submitted\":%llu,"
        "\"tx_committed\":%llu,"
        "\"tx_failed\":%llu,"
        "\"tps_submit\":%.3f,"
        "\"tps_commit\":%.3f,"
        "\"submit_success_rate\":%.4f,"
        "\"batch_fill_pct_heuristic\":%.2f,"
        "\"nodus_version\":\"%s\"",
        burst, g_wallet_count, cfg.duration_s,
        (unsigned long long)rounds,
        (unsigned long long)submitted,
        (unsigned long long)committed,
        (unsigned long long)failed,
        tps_submit, tps_commit, success_rate,
        batch_fill_pct, cfg.nodus_version);

    /* Redirect stdout if requested. */
    FILE *saved_stdout = NULL;
    if (cfg.output_path) {
        FILE *out = fopen(cfg.output_path, "w");
        if (!out) { perror("fopen output"); goto cleanup; }
        saved_stdout = stdout;
        stdout = out;
    }
    bench_emit_json("cluster_tps_burst", committed, bench_total_ns,
                    committed > 0 ? &hist : NULL, extra);
    if (saved_stdout) {
        fclose(stdout);
        stdout = saved_stdout;
    }

cleanup:
    free(ch);
    bench_histogram_free(&hist);
    free_wallets();
    return 0;
}
