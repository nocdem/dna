/* dna_bench_run.c — `run` subcommand (burst / sustained / rampup / soak).
 *
 * Each round:
 *   - For each wallet i (parallel): fork dna-connect-cli -d <wi>/.dna dna
 *     send <target_fp> <amount> <memo> --bench. Capture stdout pipe.
 *     Parse single-line JSON {"tx_hash":..., "submit_ms":...}. Append
 *     tx_hash to tx_hashes.txt.
 *   - Wait for all children with CHILD_TIMEOUT_S cap; record per-child
 *     wall latency (fork→exit).
 *
 * Mesh recipient: target = wallets[(i+1 + rng()%(N-1)) % N]; never self.
 *
 * sustained: round_budget_us = 1e6 * pool / tps_target; sleep remainder.
 * burst:     no pacing, capped at --max-tps unless --allow-stress.
 * rampup:    iterate (start..end step) calling sustained(tps,hold).
 * soak:      pure alias for sustained (default --duration 24h).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EX_OOM_OR_INTERNAL 71
#define MAX_POOL 1024
#define MAX_STDOUT_BUF (16 * 1024)

static char *xstrdup_r(const char *s) {
    char *r = strdup(s ? s : "");
    if (!r) { perror("strdup"); exit(EX_OOM_OR_INTERNAL); }
    return r;
}

/* ── Time helpers ──────────────────────────────────────────────── */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int parse_duration_strict(const char *s, int *out_s) {
    /* Accept N{s,m,h,d} or bare integer (seconds). Reject anything else. */
    if (!s || !*s) return -1;
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || v <= 0) return -1;
    int mult = 1;
    if (*end == '\0' || *end == 's' || *end == 'S') mult = 1;
    else if (*end == 'm' || *end == 'M') mult = 60;
    else if (*end == 'h' || *end == 'H') mult = 3600;
    else if (*end == 'd' || *end == 'D') mult = 86400;
    else return -1;
    if (*end != '\0' && *(end + 1) != '\0') return -1;
    long total = v * mult;
    if (total > 2147483647L) return -1;
    *out_s = (int)total;
    return 0;
}

/* ── Pool loader ───────────────────────────────────────────────── */

struct pool_entry {
    int idx;
    char fp[160];        /* 128 hex + nul */
    char data_dir[1024]; /* ~/.dna_bench/wallets/wXX/.dna */
};

static int load_pool(struct pool_entry *out, int max,
                     struct dna_bench_pool *meta) {
    int rc = dna_bench_pool_load(meta);
    if (rc != 0) {
        fprintf(stderr, "[dna-bench] no pool found (run `wallets create N`)\n");
        return -1;
    }
    if (meta->count > max) meta->count = max;
    int n = 0;
    for (int i = 0; i < meta->count; i++) {
        char *fp_path = dna_bench_wallet_fp_path(i);
        char *fp = dna_bench_read_first_line(fp_path);
        char *wdir = dna_bench_wallet_dir(i);
        free(fp_path);
        if (!fp || strlen(fp) != 128) {
            fprintf(stderr, "[dna-bench] w%02d: missing/invalid fp.txt\n", i);
            free(fp); free(wdir);
            continue;
        }
        out[n].idx = i;
        snprintf(out[n].fp, sizeof(out[n].fp), "%s", fp);
        snprintf(out[n].data_dir, sizeof(out[n].data_dir), "%s/.dna", wdir);
        free(fp); free(wdir);
        n++;
    }
    return n;
}

/* ── Send-child fork/wait ──────────────────────────────────────── */

struct child_slot {
    pid_t   pid;
    int     stdout_fd;
    char    stdout_buf[MAX_STDOUT_BUF];
    size_t  stdout_len;
    uint64_t fork_ns;
    uint64_t exit_ns;
    int     wallet_idx;
    int     status;
    int     reaped;
};

/* Fork dna-connect-cli; on success returns pid, slot populated. */
static int fork_send(struct child_slot *slot,
                     const struct pool_entry *src,
                     const char *target_fp,
                     const char *memo) {
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return -1; }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        const char *cli = dna_bench_cli_bin();
        char amount_str[32];
        snprintf(amount_str, sizeof(amount_str), "%llu",
                 (unsigned long long)DNA_BENCH_SPEND_AMOUNT_RAW);
        const char *argv[] = {
            cli, "-q", "-d", src->data_dir,
            "dna", "send", target_fp, amount_str, memo, "--bench", NULL
        };
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    slot->pid = pid;
    slot->stdout_fd = pipefd[0];
    slot->stdout_len = 0;
    slot->fork_ns = now_ns();
    slot->exit_ns = 0;
    slot->status = 0;
    slot->reaped = 0;
    return 0;
}

/* Drain non-blocking pipe; tolerate EAGAIN. */
static void slot_drain(struct child_slot *s) {
    while (1) {
        if (s->stdout_len + 1 >= sizeof(s->stdout_buf)) return;
        ssize_t n = read(s->stdout_fd,
                         s->stdout_buf + s->stdout_len,
                         sizeof(s->stdout_buf) - 1 - s->stdout_len);
        if (n > 0) { s->stdout_len += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return;
    }
}

/* Reap N children with deadline. Drains stdout repeatedly. */
static void reap_round(struct child_slot *slots, int n,
                       uint64_t deadline_ns) {
    int alive = n;
    while (alive > 0) {
        int progress = 0;
        for (int i = 0; i < n; i++) {
            if (slots[i].reaped) continue;
            slot_drain(&slots[i]);
            int status = 0;
            pid_t r = waitpid(slots[i].pid, &status, WNOHANG);
            if (r == slots[i].pid) {
                slots[i].exit_ns = now_ns();
                slots[i].status = status;
                slots[i].reaped = 1;
                slot_drain(&slots[i]);
                close(slots[i].stdout_fd);
                slots[i].stdout_fd = -1;
                slots[i].stdout_buf[slots[i].stdout_len] = '\0';
                alive--;
                progress = 1;
            }
        }
        if (!progress) {
            uint64_t t = now_ns();
            if (t > deadline_ns || g_dna_bench_shutdown) {
                /* Force-kill survivors */
                for (int i = 0; i < n; i++) {
                    if (slots[i].reaped) continue;
                    kill(slots[i].pid, SIGTERM);
                }
                struct timespec ts = {1, 0};
                nanosleep(&ts, NULL);
                for (int i = 0; i < n; i++) {
                    if (slots[i].reaped) continue;
                    kill(slots[i].pid, SIGKILL);
                    int status = 0;
                    waitpid(slots[i].pid, &status, 0);
                    slots[i].exit_ns = now_ns();
                    slots[i].status = -1;
                    slots[i].reaped = 1;
                    if (slots[i].stdout_fd >= 0) close(slots[i].stdout_fd);
                    slots[i].stdout_fd = -1;
                }
                return;
            }
            struct timespec ts = {0, 50 * 1000000L}; /* 50ms */
            nanosleep(&ts, NULL);
        }
    }
}

/* ── Output: tx_hashes file + stats ─────────────────────────────── */

static int parse_tx_hash(const char *buf, char *out, size_t n) {
    const char *p = strstr(buf, "\"tx_hash\":\"");
    if (!p) return -1;
    p += strlen("\"tx_hash\":\"");
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < n) out[i++] = *p++;
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

static int parse_error_field(const char *buf, char *out, size_t n) {
    const char *p = strstr(buf, "\"error\":\"");
    if (!p) return -1;
    p += strlen("\"error\":\"");
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < n) out[i++] = *p++;
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

/* ── Percentile helpers ────────────────────────────────────────── */

static int u64_cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y);
}

static uint64_t pct(uint64_t *arr, int n, double p) {
    if (n <= 0) return 0;
    int idx = (int)(p * n);
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return arr[idx];
}

/* ── Final JSON ────────────────────────────────────────────────── */

static void iso_utc(char *buf, size_t n, time_t t) {
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void emit_final_json(FILE *out,
                            const struct dna_bench_run_cfg *cfg,
                            const char *started_at,
                            const char *ended_at,
                            int rounds, int submit, int commit_h, int fail,
                            int rate_limited,
                            uint64_t *latencies_us, int latency_n,
                            int actual_duration_s, bool interrupted,
                            int pool_size, uint64_t fund_per_wallet_raw) {
    qsort(latencies_us, latency_n, sizeof(uint64_t), u64_cmp);
    uint64_t lmin = latency_n > 0 ? latencies_us[0] : 0;
    uint64_t lmax = latency_n > 0 ? latencies_us[latency_n - 1] : 0;
    uint64_t l50 = pct(latencies_us, latency_n, 0.50);
    uint64_t l95 = pct(latencies_us, latency_n, 0.95);
    uint64_t l99 = pct(latencies_us, latency_n, 0.99);

    double secs = (double)(actual_duration_s > 0 ? actual_duration_s : 1);
    double tps_submit = submit / secs;
    double tps_commit = commit_h / secs;
    double success_rate = submit > 0 ? (double)commit_h / (double)submit : 0.0;

    const char *mode_str =
        cfg->mode == DNA_BENCH_MODE_BURST     ? "burst" :
        cfg->mode == DNA_BENCH_MODE_SUSTAINED ? "sustained" :
        cfg->mode == DNA_BENCH_MODE_RAMPUP    ? "rampup" :
        cfg->mode == DNA_BENCH_MODE_SOAK      ? "soak" : "?";

    fprintf(out,
"{\"schema_version\":%d,\"tool_version\":\"%s\","
"\"started_at\":\"%s\",\"ended_at\":\"%s\","
"\"config\":{\"mode\":\"%s\",\"tps_target\":%d,\"duration_s\":%d,"
"\"wallets\":%d,\"recipient\":\"%s\",\"fund_per_wallet_raw\":%llu},"
"\"totals\":{\"rounds\":%d,\"submit\":%d,\"commit_h\":%d,\"fail\":%d,"
"\"rate_limited\":%d,\"tps_submit\":%.3f,\"tps_commit_h\":%.3f,"
"\"submit_success_rate\":%.4f},"
"\"latency_us_h\":{\"p50\":%llu,\"p95\":%llu,\"p99\":%llu,\"min\":%llu,\"max\":%llu},"
"\"interrupted\":%s,\"actual_duration_s\":%d,\"reconciled\":false}\n",
        DNA_BENCH_SCHEMA_VERSION, DNA_BENCH_TOOL_VERSION,
        started_at, ended_at,
        mode_str, cfg->tps_target, cfg->duration_s,
        pool_size, cfg->fixed_recipient ? "fixed" : "mesh",
        (unsigned long long)fund_per_wallet_raw,
        rounds, submit, commit_h, fail, rate_limited,
        tps_submit, tps_commit, success_rate,
        (unsigned long long)l50, (unsigned long long)l95,
        (unsigned long long)l99, (unsigned long long)lmin,
        (unsigned long long)lmax,
        interrupted ? "true" : "false",
        actual_duration_s);
    fflush(out);
}

/* ── Sustained / burst inner loop ──────────────────────────────── */

static unsigned int g_rng_state = 0;
static unsigned int rand_step(void) {
    g_rng_state = g_rng_state * 1664525u + 1013904223u;
    return g_rng_state;
}

struct run_state {
    struct pool_entry *pool;
    int pool_size;
    struct dna_bench_run_cfg *cfg;
    uint64_t fund_per_wallet_raw;
    char run_dir[1024];
    FILE *txhashes;
    FILE *streamf;
    int   submit, commit_h, fail, rate_limited, rounds;
    uint64_t *latencies_us;
    int    latency_n, latency_cap;
    uint64_t started_ns;
};

static void run_state_record_latency(struct run_state *st, uint64_t us) {
    if (st->latency_n >= st->latency_cap) {
        int newcap = st->latency_cap ? st->latency_cap * 2 : 1024;
        uint64_t *p = realloc(st->latencies_us, newcap * sizeof(uint64_t));
        if (!p) return;
        st->latencies_us = p;
        st->latency_cap = newcap;
    }
    st->latencies_us[st->latency_n++] = us;
}

/* Run one round at given target TPS; sleep slack if sustained. */
static void run_one_round(struct run_state *st, int target_tps,
                          const char *phase) {
    int N = st->pool_size;
    if (N <= 0) return;
    struct child_slot *slots = calloc(N, sizeof(*slots));
    if (!slots) return;

    char memo[64];
    snprintf(memo, sizeof(memo), "bench-%s-r%d", phase, st->rounds + 1);

    uint64_t round_start = now_ns();
    /* ROOT CAUSE FIX: rc237's pre-flight UTXO sync is in
     * dnac_provider.sendPayment (Flutter), NOT in the C CLI's
     * dna_chain_cmd_send. So a fresh `dna-connect-cli dna send` runs
     * with whatever state the wallet's SQLite DB had on disk. After a
     * commit, local DB doesn't auto-refresh — the next round's send
     * tries to rebuild from stale UTXO state and fails with
     * "Insufficient funds" (coin selection sees the initial UTXO
     * still marked unspent + the freshly-created change UTXO as
     * pending, neither selectable for another send).
     *
     * Workaround: explicit sync per wallet BEFORE its send each round.
     * This is what the Flutter wallet does. It costs ~5-10s per
     * wallet but takes the round-loop fail rate from ~33-90% to
     * near-zero. Sync runs in parallel via fork (output discarded).
     */
    pid_t sync_pids[MAX_POOL];
    int sync_count = 0;
    for (int i = 0; i < N; i++) {
        const char *cli = dna_bench_cli_bin();
        const char *sync_argv[] = {
            cli, "-q", "-d", st->pool[i].data_dir, "dna", "sync", NULL,
        };
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDOUT_FILENO); dup2(dn, STDERR_FILENO); close(dn); }
            int dni = open("/dev/null", O_RDONLY);
            if (dni >= 0) { dup2(dni, STDIN_FILENO); close(dni); }
            execv(sync_argv[0], (char *const *)sync_argv);
            _exit(127);
        }
        if (pid > 0) {
            sync_pids[sync_count++] = pid;
        }
    }
    for (int i = 0; i < sync_count; i++) {
        int status;
        waitpid(sync_pids[i], &status, 0);
    }

    /* PARALLEL send fire — all wallets at once. With per-attempt
     * retry: after first parallel pass, identify wallets that failed
     * with transient errors (Network error / send_fail without
     * "Insufficient funds"), re-sync them, fire the failed ones again
     * in parallel. Up to 3 attempts total. */
    char targets[MAX_POOL][160];
    for (int i = 0; i < N; i++) {
        if (st->cfg->fixed_recipient) {
            snprintf(targets[i], sizeof(targets[i]), "%s",
                     st->cfg->recipient_fp);
        } else {
            int j;
            if (N == 1) j = 0;
            else {
                j = (i + 1 + (rand_step() % (N - 1))) % N;
                if (j == i) j = (j + 1) % N;
            }
            snprintf(targets[i], sizeof(targets[i]), "%s", st->pool[j].fp);
        }
        slots[i].wallet_idx = st->pool[i].idx;
    }

    const int MAX_SEND_ATTEMPTS = 3;
    bool need[MAX_POOL];
    for (int i = 0; i < N; i++) need[i] = true;

    for (int attempt = 0; attempt < MAX_SEND_ATTEMPTS; attempt++) {
        /* Fire all wallets that still need a send (parallel). */
        for (int i = 0; i < N; i++) {
            if (!need[i]) continue;
            slots[i].pid = 0;
            slots[i].stdout_len = 0;
            slots[i].stdout_buf[0] = '\0';
            slots[i].reaped = 0;
            slots[i].fork_ns = 0;
            slots[i].exit_ns = 0;
            slots[i].status = 0;
            if (fork_send(&slots[i], &st->pool[i], targets[i], memo) != 0) {
                slots[i].reaped = 1;
                slots[i].pid = -1;
                slots[i].status = -1;
            }
        }
        uint64_t deadline = now_ns() + (uint64_t)DNA_BENCH_CHILD_TIMEOUT_S
                                     * 1000000000ULL;
        reap_round(slots, N, deadline);

        /* Classify each wallet: success, retryable, or final fail. */
        int retry_count = 0;
        for (int i = 0; i < N; i++) {
            if (!need[i]) continue;
            char tx[160];
            if (slots[i].pid > 0 &&
                parse_tx_hash(slots[i].stdout_buf, tx, sizeof(tx)) == 0) {
                need[i] = false;
                continue;
            }
            if (slots[i].pid <= 0) { need[i] = false; continue; }
            if (attempt + 1 >= MAX_SEND_ATTEMPTS) { need[i] = false; continue; }
            const char *body = slots[i].stdout_buf;
            bool transient =
                (strstr(body, "Network error") != NULL) ||
                (strstr(body, "Insufficient funds") != NULL);
            if (!transient) { need[i] = false; continue; }
            retry_count++;
        }
        if (retry_count == 0) break;

        /* Re-sync only the wallets we'll retry, in parallel. */
        pid_t resync_pids[MAX_POOL];
        int resync_count = 0;
        for (int i = 0; i < N; i++) {
            if (!need[i]) continue;
            const char *cli2 = dna_bench_cli_bin();
            const char *resync_argv[] = {
                cli2, "-q", "-d", st->pool[i].data_dir, "dna", "sync", NULL,
            };
            pid_t rs_pid = fork();
            if (rs_pid == 0) {
                int dn = open("/dev/null", O_WRONLY);
                if (dn >= 0) { dup2(dn, STDOUT_FILENO); dup2(dn, STDERR_FILENO); close(dn); }
                int dni = open("/dev/null", O_RDONLY);
                if (dni >= 0) { dup2(dni, STDIN_FILENO); close(dni); }
                execv(resync_argv[0], (char *const *)resync_argv);
                _exit(127);
            }
            if (rs_pid > 0) resync_pids[resync_count++] = rs_pid;
        }
        for (int i = 0; i < resync_count; i++) {
            int rs_status;
            waitpid(resync_pids[i], &rs_status, 0);
        }
        struct timespec ts = { 1, 0 };
        nanosleep(&ts, NULL);
    }

    int round_submit = 0, round_commit = 0, round_fail = 0, round_rl = 0;
    uint64_t lat_min = UINT64_MAX, lat_max = 0;
    uint64_t round_lats[1024];
    int round_lat_n = 0;

    char first_err[1024] = {0};
    for (int i = 0; i < N; i++) {
        if (slots[i].pid <= 0) { round_fail++; st->fail++; continue; }
        round_submit++;
        st->submit++;
        char tx[160];
        if (parse_tx_hash(slots[i].stdout_buf, tx, sizeof(tx)) == 0) {
            round_commit++;
            st->commit_h++;
            if (st->txhashes) {
                fprintf(st->txhashes, "%s\n", tx);
                fflush(st->txhashes);
            }
        } else {
            char err[64] = {0};
            (void)parse_error_field(slots[i].stdout_buf, err, sizeof(err));
            if (strcmp(err, "rate_limited") == 0) {
                round_rl++; st->rate_limited++;
            }
            round_fail++; st->fail++;
            if (first_err[0] == '\0') {
                /* Capture first child's stdout snippet for diagnosis. */
                size_t len = slots[i].stdout_len;
                if (len > sizeof(first_err) - 1) len = sizeof(first_err) - 1;
                memcpy(first_err, slots[i].stdout_buf, len);
                first_err[len] = '\0';
                /* Strip trailing whitespace */
                while (len > 0 && (first_err[len - 1] == '\n' ||
                                   first_err[len - 1] == ' ')) {
                    first_err[--len] = '\0';
                }
            }
        }
        if (slots[i].exit_ns > slots[i].fork_ns) {
            uint64_t lat_us = (slots[i].exit_ns - slots[i].fork_ns) / 1000;
            if (lat_us < lat_min) lat_min = lat_us;
            if (lat_us > lat_max) lat_max = lat_us;
            run_state_record_latency(st, lat_us);
            if (round_lat_n < (int)(sizeof(round_lats) / sizeof(round_lats[0]))) {
                round_lats[round_lat_n++] = lat_us;
            }
        }
    }
    free(slots);

    uint64_t round_dt_ns = now_ns() - round_start;
    st->rounds++;

    if (round_fail > 0 && first_err[0]) {
        fprintf(stderr,
            "[dna-bench] round %d: %d/%d failed; first child stdout (full):\n"
            "----- BEGIN -----\n%s\n----- END -----\n",
            st->rounds, round_fail, round_submit, first_err);
    }

    /* Sustained / soak: pace the round */
    if (st->cfg->mode == DNA_BENCH_MODE_SUSTAINED ||
        st->cfg->mode == DNA_BENCH_MODE_SOAK ||
        (st->cfg->mode == DNA_BENCH_MODE_RAMPUP && target_tps > 0)) {
        if (target_tps > 0) {
            uint64_t budget_ns = (uint64_t)(1e9 * (double)N / (double)target_tps);
            if (round_dt_ns < budget_ns && !g_dna_bench_shutdown) {
                uint64_t slack_ns = budget_ns - round_dt_ns;
                struct timespec ts;
                ts.tv_sec  = slack_ns / 1000000000ULL;
                ts.tv_nsec = slack_ns % 1000000000ULL;
                nanosleep(&ts, NULL);
            }
        }
    }

    /* Stream JSONL line for this round */
    if (st->streamf) {
        qsort(round_lats, round_lat_n, sizeof(uint64_t), u64_cmp);
        uint64_t r_min = round_lat_n ? round_lats[0] : 0;
        uint64_t r_max = round_lat_n ? round_lats[round_lat_n - 1] : 0;
        uint64_t r_50  = pct(round_lats, round_lat_n, 0.50);
        uint64_t r_95  = pct(round_lats, round_lat_n, 0.95);
        char ts[32];
        iso_utc(ts, sizeof(ts), time(NULL));
        fprintf(st->streamf,
            "{\"ts\":\"%s\",\"round\":%d,\"phase\":\"%s\",\"tps_target\":%d,"
            "\"submit\":%d,\"commit_h\":%d,\"fail\":%d,"
            "\"round_dt_ms\":%llu,\"min_dt_ms\":%llu,\"p50_dt_ms\":%llu,"
            "\"p95_dt_ms\":%llu,\"max_dt_ms\":%llu}\n",
            ts, st->rounds, phase, target_tps,
            round_submit, round_commit, round_fail,
            (unsigned long long)(round_dt_ns / 1000000ULL),
            (unsigned long long)(r_min / 1000ULL),
            (unsigned long long)(r_50 / 1000ULL),
            (unsigned long long)(r_95 / 1000ULL),
            (unsigned long long)(r_max / 1000ULL));
        fflush(st->streamf);
    }
}

/* ── Live tick thread ──────────────────────────────────────────── */

static struct {
    pthread_t t;
    int running;
    int interval_s;
    pthread_mutex_t lock;
    struct run_state *st;
    const char *phase;
    int target_tps;
} g_tick;

static void *tick_thread(void *arg) {
    (void)arg;
    /* Sleep in 200ms steps so tick_stop() can return promptly without
     * needing pthread_kill (SIGUSR2 default action is process-terminate;
     * installing a handler in a multi-threaded program is fragile). */
    while (1) {
        for (int slept = 0; slept < g_tick.interval_s * 1000; slept += 200) {
            pthread_mutex_lock(&g_tick.lock);
            int running = g_tick.running;
            pthread_mutex_unlock(&g_tick.lock);
            if (!running) return NULL;
            struct timespec ts = { 0, 200 * 1000 * 1000L };
            nanosleep(&ts, NULL);
        }
        pthread_mutex_lock(&g_tick.lock);
        if (!g_tick.running) { pthread_mutex_unlock(&g_tick.lock); break; }
        struct run_state *st = g_tick.st;
        if (st && st->started_ns) {
            uint64_t elapsed_ns = now_ns() - st->started_ns;
            double secs = (double)elapsed_ns / 1.0e9;
            if (secs < 1) secs = 1;
            double tps_s = st->submit / secs;
            double tps_c = st->commit_h / secs;
            fprintf(stderr,
                "[dna-bench %4ds] phase=%s submit=%d commit_h=%d fail=%d "
                "tps_submit=%.2f tps_commit_h=%.2f rl=%d\n",
                (int)secs, g_tick.phase ? g_tick.phase : "?",
                st->submit, st->commit_h, st->fail, tps_s, tps_c,
                st->rate_limited);
        }
        pthread_mutex_unlock(&g_tick.lock);
    }
    return NULL;
}

static void tick_start(struct run_state *st, const char *phase, int target_tps,
                       int interval_s) {
    if (interval_s <= 0) interval_s = 5;
    pthread_mutex_init(&g_tick.lock, NULL);
    g_tick.interval_s = interval_s;
    g_tick.running = 1;
    g_tick.st = st;
    g_tick.phase = phase;
    g_tick.target_tps = target_tps;
    pthread_create(&g_tick.t, NULL, tick_thread, NULL);
}

static void tick_stop(void) {
    pthread_mutex_lock(&g_tick.lock);
    g_tick.running = 0;
    pthread_mutex_unlock(&g_tick.lock);
    /* Tick thread polls running flag every 200ms; will exit on its
     * next iteration. Worst case we wait ~200ms in pthread_join. */
    pthread_join(g_tick.t, NULL);
    pthread_mutex_destroy(&g_tick.lock);
}

/* ── Mode runners ──────────────────────────────────────────────── */

static void run_loop_until_deadline(struct run_state *st, int target_tps,
                                    int duration_s, const char *phase) {
    if (duration_s <= 0) duration_s = 30;
    uint64_t deadline_ns = now_ns() + (uint64_t)duration_s * 1000000000ULL;
    while (!g_dna_bench_shutdown && now_ns() < deadline_ns) {
        run_one_round(st, target_tps, phase);
        if (st->cfg->abort_on_fail_rate > 0.0 && st->submit > 0) {
            double rate = (double)st->fail / (double)st->submit;
            if (rate > st->cfg->abort_on_fail_rate) {
                fprintf(stderr,
                    "[dna-bench] abort: fail rate %.3f > threshold %.3f\n",
                    rate, st->cfg->abort_on_fail_rate);
                g_dna_bench_shutdown = 1;
                break;
            }
        }
    }
}

/* ── Argument parsing ──────────────────────────────────────────── */

static enum dna_bench_mode parse_mode(const char *s) {
    if (strcmp(s, "burst")     == 0) return DNA_BENCH_MODE_BURST;
    if (strcmp(s, "sustained") == 0) return DNA_BENCH_MODE_SUSTAINED;
    if (strcmp(s, "rampup")    == 0) return DNA_BENCH_MODE_RAMPUP;
    if (strcmp(s, "soak")      == 0) return DNA_BENCH_MODE_SOAK;
    return DNA_BENCH_MODE_INVALID;
}

static void usage_run(void) {
    fprintf(stderr,
"usage: dna_bench run --mode <burst|sustained|rampup|soak> [opts]\n"
"  burst:     [--max-tps N|--allow-stress]\n"
"  sustained: --tps N --duration T\n"
"  rampup:    --start A --end B --step S --hold H\n"
"  soak:      --tps N (default 1) --duration T (default 24h)\n"
"  common:    --recipient mesh|fixed:<FP>\n"
"             --status-interval N (default 5s)\n"
"             --stream FILE.jsonl\n"
"             --output FILE.json (default <run-dir>/run.json)\n"
"             --abort-on-fail-rate <fraction>\n"
"             --allow-long  (bypass 48h cap)\n");
}

int cmd_run(int argc, char **argv) {
    struct dna_bench_run_cfg cfg = {0};
    cfg.status_interval_s = 5;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--mode") == 0 && i + 1 < argc) {
            cfg.mode = parse_mode(argv[++i]);
        } else if (strcmp(a, "--tps") == 0 && i + 1 < argc) {
            cfg.tps_target = atoi(argv[++i]);
        } else if (strcmp(a, "--duration") == 0 && i + 1 < argc) {
            if (parse_duration_strict(argv[++i], &cfg.duration_s) != 0) {
                fprintf(stderr, "[dna-bench] invalid --duration\n");
                return DNA_BENCH_EXIT_USAGE;
            }
        } else if (strcmp(a, "--start") == 0 && i + 1 < argc) {
            cfg.ramp_start = atoi(argv[++i]);
        } else if (strcmp(a, "--end") == 0 && i + 1 < argc) {
            cfg.ramp_end = atoi(argv[++i]);
        } else if (strcmp(a, "--step") == 0 && i + 1 < argc) {
            cfg.ramp_step = atoi(argv[++i]);
        } else if (strcmp(a, "--hold") == 0 && i + 1 < argc) {
            if (parse_duration_strict(argv[++i], &cfg.ramp_hold_s) != 0) {
                fprintf(stderr, "[dna-bench] invalid --hold\n");
                return DNA_BENCH_EXIT_USAGE;
            }
        } else if (strcmp(a, "--max-tps") == 0 && i + 1 < argc) {
            cfg.max_tps_cap = atoi(argv[++i]);
        } else if (strcmp(a, "--allow-stress") == 0) {
            cfg.allow_stress = true;
        } else if (strcmp(a, "--allow-long") == 0) {
            cfg.allow_long = true;
        } else if (strcmp(a, "--status-interval") == 0 && i + 1 < argc) {
            cfg.status_interval_s = atoi(argv[++i]);
        } else if (strcmp(a, "--stream") == 0 && i + 1 < argc) {
            snprintf(cfg.stream_path, sizeof(cfg.stream_path), "%s", argv[++i]);
        } else if (strcmp(a, "--output") == 0 && i + 1 < argc) {
            snprintf(cfg.output_path, sizeof(cfg.output_path), "%s", argv[++i]);
        } else if (strcmp(a, "--recipient") == 0 && i + 1 < argc) {
            const char *r = argv[++i];
            if (strncmp(r, "fixed:", 6) == 0) {
                cfg.fixed_recipient = true;
                snprintf(cfg.recipient_fp, sizeof(cfg.recipient_fp),
                         "%s", r + 6);
            } else if (strcmp(r, "mesh") == 0) {
                cfg.fixed_recipient = false;
            } else {
                fprintf(stderr, "[dna-bench] invalid --recipient: %s\n", r);
                return DNA_BENCH_EXIT_USAGE;
            }
        } else if (strcmp(a, "--abort-on-fail-rate") == 0 && i + 1 < argc) {
            cfg.abort_on_fail_rate = strtod(argv[++i], NULL);
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage_run();
            return 0;
        } else {
            fprintf(stderr, "[dna-bench] unknown flag: %s\n", a);
            usage_run();
            return DNA_BENCH_EXIT_USAGE;
        }
    }

    if (cfg.mode == DNA_BENCH_MODE_INVALID) {
        usage_run();
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Mode-specific defaults / validation */
    if (cfg.mode == DNA_BENCH_MODE_SOAK) {
        if (cfg.tps_target <= 0) cfg.tps_target = 1;
        if (cfg.duration_s <= 0) cfg.duration_s = 24 * 3600;
    }
    if (cfg.mode == DNA_BENCH_MODE_BURST) {
        if (cfg.max_tps_cap <= 0 && !cfg.allow_stress) {
            cfg.max_tps_cap = DNA_BENCH_BURST_DEFAULT_TPS;
        }
        if (cfg.duration_s <= 0) cfg.duration_s = 30;
    }
    if (cfg.mode == DNA_BENCH_MODE_SUSTAINED) {
        if (cfg.tps_target <= 0 || cfg.duration_s <= 0) {
            fprintf(stderr, "[dna-bench] sustained needs --tps N --duration T\n");
            return DNA_BENCH_EXIT_USAGE;
        }
    }
    if (cfg.mode == DNA_BENCH_MODE_RAMPUP) {
        if (cfg.ramp_start <= 0 || cfg.ramp_end <= 0 ||
            cfg.ramp_step <= 0 || cfg.ramp_hold_s <= 0) {
            fprintf(stderr,
                "[dna-bench] rampup needs --start --end --step --hold\n");
            return DNA_BENCH_EXIT_USAGE;
        }
        cfg.duration_s = ((cfg.ramp_end - cfg.ramp_start) / cfg.ramp_step + 1)
                         * cfg.ramp_hold_s;
    }
    if (!cfg.allow_long && cfg.duration_s > DNA_BENCH_MAX_DURATION_S) {
        fprintf(stderr,
            "[dna-bench] --duration %ds exceeds 48h cap; pass --allow-long\n",
            cfg.duration_s);
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Load pool */
    struct pool_entry *pool = calloc(MAX_POOL, sizeof(*pool));
    if (!pool) return EX_OOM_OR_INTERNAL;
    struct dna_bench_pool meta = {0};
    int pool_size = load_pool(pool, MAX_POOL, &meta);
    if (pool_size <= 0) {
        fprintf(stderr, "[dna-bench] pool empty (rc=%d)\n", pool_size);
        free(pool);
        return 1;
    }

    /* Run dir + tx_hashes + stream */
    char *run_dir = dna_bench_run_dir_new();
    char tx_path[1280], default_out[1280];
    snprintf(tx_path,    sizeof(tx_path),    "%s/tx_hashes.txt", run_dir);
    snprintf(default_out, sizeof(default_out), "%s/run.json",     run_dir);
    if (cfg.output_path[0] == '\0') {
        snprintf(cfg.output_path, sizeof(cfg.output_path), "%s", default_out);
    }
    if (cfg.stream_path[0] == '\0') {
        snprintf(cfg.stream_path, sizeof(cfg.stream_path),
                 "%s/stream.jsonl", run_dir);
    }

    g_rng_state = (unsigned)(time(NULL) ^ getpid());

    /* Pre-run warm sync: parallel fork ALL wallets at once; wait for
     * all. Sequential here scales O(N × 15s) which becomes 6+ minutes
     * for N=27 — longer than the entire test duration. Parallel scales
     * to ~30s regardless of N. */
    fprintf(stderr, "[dna-bench] warm-sync %d wallet(s) (parallel)...\n",
            pool_size);
    pid_t warm_pids[MAX_POOL];
    int warm_count = 0;
    for (int i = 0; i < pool_size; i++) {
        const char *cli = dna_bench_cli_bin();
        const char *sync_argv[] = {
            cli, "-q", "-d", pool[i].data_dir, "dna", "sync", NULL,
        };
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            int dni = open("/dev/null", O_RDONLY);
            if (dni >= 0) { dup2(dni, STDIN_FILENO); close(dni); }
            execv(sync_argv[0], (char *const *)sync_argv);
            _exit(127);
        }
        if (pid > 0) warm_pids[warm_count++] = pid;
    }
    for (int i = 0; i < warm_count; i++) {
        int status;
        waitpid(warm_pids[i], &status, 0);
    }
    fprintf(stderr, "[dna-bench] warm-sync done.\n");

    struct run_state st = {0};
    st.pool = pool;
    st.pool_size = pool_size;
    st.cfg = &cfg;
    st.fund_per_wallet_raw = meta.fund_per_wallet_raw;
    st.txhashes = fopen(tx_path, "w");
    if (!st.txhashes) {
        fprintf(stderr, "[dna-bench] cannot open %s: %s\n",
                tx_path, strerror(errno));
    }
    st.streamf = fopen(cfg.stream_path, "a");
    snprintf(st.run_dir, sizeof(st.run_dir), "%s", run_dir);

    char started_at[32];
    iso_utc(started_at, sizeof(started_at), time(NULL));
    st.started_ns = now_ns();

    fprintf(stderr,
        "[dna-bench] mode=%s tps=%d duration=%ds wallets=%d recipient=%s "
        "run_dir=%s\n",
        cfg.mode == DNA_BENCH_MODE_BURST     ? "burst" :
        cfg.mode == DNA_BENCH_MODE_SUSTAINED ? "sustained" :
        cfg.mode == DNA_BENCH_MODE_RAMPUP    ? "rampup" :
        cfg.mode == DNA_BENCH_MODE_SOAK      ? "soak"    : "?",
        cfg.tps_target, cfg.duration_s, pool_size,
        cfg.fixed_recipient ? "fixed" : "mesh",
        run_dir);

    tick_start(&st,
        cfg.mode == DNA_BENCH_MODE_BURST     ? "burst" :
        cfg.mode == DNA_BENCH_MODE_SUSTAINED ? "sustained" :
        cfg.mode == DNA_BENCH_MODE_RAMPUP    ? "rampup" :
        cfg.mode == DNA_BENCH_MODE_SOAK      ? "soak"    : "?",
        cfg.tps_target, cfg.status_interval_s);

    /* Dispatch */
    if (cfg.mode == DNA_BENCH_MODE_RAMPUP) {
        for (int t = cfg.ramp_start; t <= cfg.ramp_end && !g_dna_bench_shutdown;
             t += cfg.ramp_step) {
            fprintf(stderr, "[dna-bench] rampup_step tps=%d hold=%ds\n",
                    t, cfg.ramp_hold_s);
            run_loop_until_deadline(&st, t, cfg.ramp_hold_s, "rampup_step");
        }
    } else if (cfg.mode == DNA_BENCH_MODE_BURST) {
        int eff = cfg.allow_stress ? 0 : cfg.max_tps_cap;
        run_loop_until_deadline(&st, eff, cfg.duration_s, "burst");
    } else { /* sustained / soak */
        run_loop_until_deadline(&st, cfg.tps_target, cfg.duration_s,
            cfg.mode == DNA_BENCH_MODE_SOAK ? "soak" : "sustained");
    }

    tick_stop();

    char ended_at[32];
    iso_utc(ended_at, sizeof(ended_at), time(NULL));
    int actual = (int)((now_ns() - st.started_ns) / 1000000000ULL);

    if (st.txhashes) fclose(st.txhashes);
    if (st.streamf) fclose(st.streamf);

    /* Final JSON to stdout AND --output */
    bool interrupted = (g_dna_bench_shutdown != 0);

    emit_final_json(stdout, &cfg, started_at, ended_at,
                    st.rounds, st.submit, st.commit_h, st.fail,
                    st.rate_limited,
                    st.latencies_us, st.latency_n,
                    actual, interrupted, pool_size,
                    st.fund_per_wallet_raw);
    FILE *of = fopen(cfg.output_path, "w");
    if (of) {
        emit_final_json(of, &cfg, started_at, ended_at,
                        st.rounds, st.submit, st.commit_h, st.fail,
                        st.rate_limited,
                        st.latencies_us, st.latency_n,
                        actual, interrupted, pool_size,
                        st.fund_per_wallet_raw);
        fclose(of);
    }

    free(st.latencies_us);
    free(pool);
    free(run_dir);
    return interrupted ? DNA_BENCH_EXIT_INTERRUPTED : 0;
}

int dna_bench_run_main(struct dna_bench_run_cfg *cfg) {
    (void)cfg;
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}
