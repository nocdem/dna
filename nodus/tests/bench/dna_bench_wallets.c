/* dna_bench_wallets.c — wallets {create,list,reset,drain}.
 *
 * Architecture: every wallet operation forks dna-connect-cli (resolved
 * via $BENCH_CLI_BIN) so the parent process never loads libdna/ASan.
 *
 * Per-wallet layout (mode 0700 throughout):
 *   ~/.dna_bench/wallets/wNN/.dna/    CLI's data dir (--data-dir target)
 *   ~/.dna_bench/wallets/wNN/fp.txt   128-hex fingerprint cache
 *
 * Mnemonics are NEVER persisted (red-team B1/B2/B3). cmd_create's
 * stdout (which contains the mnemonic display) is read into a heap
 * buffer, parsed for the "Fingerprint:" line, and freed. Buffer
 * memset-zeroed before free() to reduce window where memory dumps /
 * swap could leak the mnemonic.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define EX_OOM_OR_INTERNAL 71
#define MAX_STDOUT_BUF (256 * 1024)  /* 256 KiB; mnemonic + identity output */

static char *xstrdup_w(const char *s) {
    char *r = strdup(s ? s : "");
    if (!r) { perror("strdup"); exit(EX_OOM_OR_INTERNAL); }
    return r;
}

/* ── Subprocess helpers ────────────────────────────────────────── */

/* Run argv[] with stdin closed, capture stdout into a heap buffer (caller
 * frees), discard stderr. Returns child exit status (0 on success).
 * Sets *out_buf to NULL/0 on fork or pipe failure. */
static int run_capture_stdout(const char *const argv[], char **out_buf,
                              size_t *out_len, int timeout_s) {
    *out_buf = NULL;
    *out_len = 0;

    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return -1; }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        /* child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        /* stdin from /dev/null so init / register can't block on read */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        /* stderr inherited so the operator sees diagnostics live */
        execv(argv[0], (char *const *)argv);
        fprintf(stderr, "[dna-bench] execv %s failed: %s\n",
                argv[0], strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);

    /* Read with a soft timeout. If the deadline passes, kill the child. */
    char *buf = calloc(1, MAX_STDOUT_BUF + 1);
    if (!buf) { close(pipefd[0]); waitpid(pid, NULL, 0); return -1; }
    size_t total = 0;
    time_t deadline = time(NULL) + (timeout_s > 0 ? timeout_s : 600);

    while (1) {
        if (g_dna_bench_shutdown) {
            kill(pid, SIGTERM);
            break;
        }
        if (time(NULL) > deadline) {
            fprintf(stderr, "[dna-bench] child %d timed out after %ds\n",
                    (int)pid, timeout_s);
            kill(pid, SIGTERM);
            sleep(1);
            kill(pid, SIGKILL);
            break;
        }
        ssize_t n = read(pipefd[0], buf + total, MAX_STDOUT_BUF - total);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        total += (size_t)n;
        if (total >= MAX_STDOUT_BUF) break;
    }
    close(pipefd[0]);
    buf[total] = '\0';

    int status = 0;
    waitpid(pid, &status, 0);

    *out_buf = buf;
    *out_len = total;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

/* Locate "Fingerprint: <hex>" anywhere in buf; copy hex into out (max
 * 128 chars). Returns 0 ok, -1 not found / malformed. */
static int parse_fingerprint_from_text(const char *buf, char *out,
                                       size_t out_n) {
    const char *p = strstr(buf, "Fingerprint:");
    if (!p) return -1;
    p += strlen("Fingerprint:");
    while (*p == ' ' || *p == '\t') p++;
    size_t i = 0;
    while (*p && i + 1 < out_n) {
        char c = *p;
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            out[i++] = c;
            p++;
        } else {
            break;
        }
    }
    out[i] = '\0';
    return (i == 128) ? 0 : -1;
}

/* Look for { "tx_hash": "<hex>", ... } single-line JSON. Returns 0 ok. */
static int parse_tx_hash_json(const char *buf, char *out, size_t out_n) {
    const char *p = strstr(buf, "\"tx_hash\":\"");
    if (!p) return -1;
    p += strlen("\"tx_hash\":\"");
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_n) out[i++] = *p++;
    out[i] = '\0';
    return (i > 0) ? 0 : -1;
}

/* ── Recursive rmdir (~/.dna_bench cleanup) ────────────────────── */

static int rmtree_visit(const char *path, const struct stat *sb,
                        int type, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (type == FTW_DP) {
        if (rmdir(path) != 0 && errno != ENOENT) {
            fprintf(stderr, "[dna-bench] rmdir %s: %s\n", path, strerror(errno));
        }
    } else {
        if (unlink(path) != 0 && errno != ENOENT) {
            fprintf(stderr, "[dna-bench] unlink %s: %s\n", path, strerror(errno));
        }
    }
    return 0;
}

static int rmtree_secure(const char *root) {
    /* Refuse to delete suspicious paths. */
    if (!root || !*root || strstr(root, "..") || strcmp(root, "/") == 0) {
        fprintf(stderr, "[dna-bench] refusing to rmtree %s\n",
                root ? root : "(null)");
        return -1;
    }
    return nftw(root, rmtree_visit, 16, FTW_DEPTH | FTW_PHYS);
}

/* ── Subcommands ───────────────────────────────────────────────── */

static int cmd_wallets_reset(int argc, char **argv);
static int cmd_wallets_create(int argc, char **argv);
static int cmd_wallets_list(int argc, char **argv);
static int cmd_wallets_drain(int argc, char **argv);
static int cmd_wallets_refund(int argc, char **argv);
static int cmd_wallets_extend(int argc, char **argv);

int cmd_wallets(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: dna_bench wallets "
            "{create|list|reset|drain|refund|extend} ...\n");
        return DNA_BENCH_EXIT_USAGE;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "create") == 0) return cmd_wallets_create(argc - 1, argv + 1);
    if (strcmp(sub, "list")   == 0) return cmd_wallets_list(argc - 1, argv + 1);
    if (strcmp(sub, "reset")  == 0) return cmd_wallets_reset(argc - 1, argv + 1);
    if (strcmp(sub, "drain")  == 0) return cmd_wallets_drain(argc - 1, argv + 1);
    if (strcmp(sub, "refund") == 0) return cmd_wallets_refund(argc - 1, argv + 1);
    if (strcmp(sub, "extend") == 0) return cmd_wallets_extend(argc - 1, argv + 1);
    fprintf(stderr, "wallets: unknown subcommand '%s'\n", sub);
    return DNA_BENCH_EXIT_USAGE;
}

static int cmd_wallets_reset(int argc, char **argv) {
    (void)argc; (void)argv;
    char *root = dna_bench_root();
    struct stat st;
    if (stat(root, &st) != 0) {
        fprintf(stderr, "[dna-bench] reset: %s does not exist (nothing to do)\n", root);
        free(root);
        return 0;
    }
    fprintf(stderr, "[dna-bench] reset: removing %s\n", root);
    int rc = rmtree_secure(root);
    free(root);
    return (rc == 0) ? 0 : 1;
}

/* ── wallets create ────────────────────────────────────────────── */

static void random_hex6(char *out) {
    /* 6 hex chars from urandom; non-crypto purpose (name suffix). */
    unsigned char b[3];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, b, 3); close(fd); }
    else { srand((unsigned)(time(NULL) ^ getpid())); for (int i=0;i<3;i++) b[i]=rand()&0xFF; }
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 3; i++) {
        out[i*2]   = hex[(b[i] >> 4) & 0xF];
        out[i*2+1] = hex[b[i] & 0xF];
    }
    out[6] = '\0';
}

/* Create wallet idx: data dir + identity create + cache fp.txt.
 *
 * IDEMPOTENT: if fp.txt already exists with a valid 128-hex
 * fingerprint, skip identity creation (no DHT keyserver pollution,
 * no fresh Dilithium keypair). Returns 0 immediately, populating
 * fp_out from the cached file. Bench wallets are persistent and
 * re-used across sessions per design. */
int dna_bench_wallet_init(int idx, char *fp_out, size_t fp_n) {
    char *wdir = dna_bench_wallet_dir(idx);
    char data_dir[1280];
    snprintf(data_dir, sizeof(data_dir), "%s/.dna", wdir);

    /* Fast path: existing wallet — skip identity create. */
    char *cached_fp_path = dna_bench_wallet_fp_path(idx);
    char *cached_fp = dna_bench_read_first_line(cached_fp_path);
    free(cached_fp_path);
    if (cached_fp && strlen(cached_fp) == 128) {
        fprintf(stderr, "[dna-bench] w%02d: REUSING existing identity %.16s...\n",
                idx, cached_fp);
        if (fp_out && fp_n) snprintf(fp_out, fp_n, "%s", cached_fp);
        free(cached_fp);
        free(wdir);
        return 0;
    }
    if (cached_fp) free(cached_fp);

    if (dna_bench_mkdir_p_secure(data_dir) != 0) {
        fprintf(stderr, "[dna-bench] mkdir %s: %s\n", data_dir, strerror(errno));
        free(wdir);
        return -1;
    }
    char name[32];
    snprintf(name, sizeof(name), "stress_");
    random_hex6(name + 7);

    const char *cli = dna_bench_cli_bin();
    const char *argv[] = {
        cli, "-q", "-d", data_dir,
        "identity", "create", name, NULL,
    };
    fprintf(stderr, "[dna-bench] w%02d: identity create %s ...\n", idx, name);

    char *out = NULL;
    size_t out_len = 0;
    int rc = run_capture_stdout(argv, &out, &out_len, 90);
    /* `identity create` exits 1 with "Internal error" when the optional
     * DHT name-registration step fails, even though the local identity
     * (keys/identity.{dsa,kem}, mnemonic.enc) is fully written and
     * loadable via `identity whoami`. The bench only needs the
     * fingerprint, so accept whichever exit code as long as the
     * Fingerprint: line is in stdout. */
    char fp[160] = {0};
    int fp_ok = (out && parse_fingerprint_from_text(out, fp, sizeof(fp)) == 0);
    if (!fp_ok) {
        fprintf(stderr,
            "[dna-bench] w%02d: identity create exit=%d, no Fingerprint parsed\n",
            idx, rc);
        if (out) { memset(out, 0, out_len); free(out); }
        free(wdir);
        return -1;
    }
    if (rc != 0) {
        fprintf(stderr,
            "[dna-bench] w%02d: identity create exit=%d "
            "(local identity OK, DHT registration likely failed — proceeding)\n",
            idx, rc);
    }
    /* zero captured stdout BEFORE free (mnemonic was in there) */
    memset(out, 0, out_len);
    free(out);

    /* Write fp.txt */
    char *fp_path = dna_bench_wallet_fp_path(idx);
    int fd = open(fp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "[dna-bench] w%02d: open %s: %s\n", idx, fp_path,
                strerror(errno));
        free(fp_path); free(wdir);
        return -1;
    }
    dprintf(fd, "%s\n", fp);
    close(fd);
    free(fp_path);
    free(wdir);

    if (fp_out && fp_n) {
        snprintf(fp_out, fp_n, "%s", fp);
    }
    fprintf(stderr, "[dna-bench] w%02d: created %.16s...\n", idx, fp);
    return 0;
}

/* Send `amount_raw` from punk master (HOME=~/) to wallet idx's fp via
 * `dna send <fp> <amount> bench-fund --bench`. Returns 0 on success.
 *
 * Retries up to 3 times on transient DHT errors ("Network error" or
 * "Insufficient funds" caused by a failed pre-flight sync that leaves
 * the local UTXO cache stale). 3-second backoff between attempts to
 * give DHT clients time to reconnect to a healthy peer.
 */
int dna_bench_wallet_fund(int idx, const char *fp, uint64_t amount_raw) {
    const char *cli = dna_bench_cli_bin();
    char amount_str[32];
    snprintf(amount_str, sizeof(amount_str), "%llu",
             (unsigned long long)amount_raw);

    const char *argv[] = {
        cli, "-q", "dna", "send", fp, amount_str, "bench-fund", "--bench", NULL,
    };

    int max_attempts = 3;
    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        /* Pre-sync punk's local UTXO cache. The internal pre-flight sync
         * inside `dna send` (rc237) sometimes fails with "Network error"
         * and leaves the cache in a stale state, which then causes
         * "Insufficient funds" on subsequent attempts. Running an
         * explicit sync first reduces that window — and on retry it
         * re-populates whatever the broken send left empty. */
        const char *sync_argv[] = {
            cli, "-q", "dna", "sync", NULL,
        };
        char *sync_out = NULL;
        size_t sync_len = 0;
        (void)run_capture_stdout(sync_argv, &sync_out, &sync_len, 30);
        if (sync_out) free(sync_out);

        char *out = NULL;
        size_t out_len = 0;
        int rc = run_capture_stdout(argv, &out, &out_len,
                                    DNA_BENCH_FUND_TIMEOUT_S);
        char tx_hash[160] = {0};
        if (out && parse_tx_hash_json(out, tx_hash, sizeof(tx_hash)) == 0) {
            free(out);
            fprintf(stderr,
                "[dna-bench] w%02d: funded tx=%.16s... amount=%llu (attempt %d)\n",
                idx, tx_hash, (unsigned long long)amount_raw, attempt);
            return 0;
        }
        /* Failure path: log + decide whether to retry. */
        const char *body = out ? out : "(no stdout)";
        bool transient =
            (out && (strstr(out, "Network error") ||
                     strstr(out, "Insufficient funds") ||
                     strstr(out, "send_fail")));
        fprintf(stderr,
            "[dna-bench] w%02d: fund attempt %d/%d failed exit=%d "
            "(transient=%d):\n%s",
            idx, attempt, max_attempts, rc, transient ? 1 : 0, body);
        if (out) free(out);
        if (!transient || attempt == max_attempts) {
            return -1;
        }
        /* Backoff to let DHT clients re-elect a healthy peer. */
        sleep(3);
    }
    return -1;
}

/* Read `dna balance` confirmed line; convert "X.YY DNAC" -> raw (×10^8). */
int dna_bench_wallet_balance(int idx, uint64_t *raw_out) {
    *raw_out = 0;
    char *wdir = dna_bench_wallet_dir(idx);
    char data_dir[1280];
    snprintf(data_dir, sizeof(data_dir), "%s/.dna", wdir);

    const char *cli = dna_bench_cli_bin();
    const char *argv[] = { cli, "-q", "-d", data_dir, "dna", "balance", NULL };

    char *out = NULL;
    size_t out_len = 0;
    int rc = run_capture_stdout(argv, &out, &out_len, 30);
    free(wdir);
    if (rc != 0 || !out) {
        if (out) free(out);
        return -1;
    }

    /* Parse "Confirmed:    X.YY DNAC" */
    const char *p = strstr(out, "Confirmed:");
    if (!p) { free(out); return -1; }
    p += strlen("Confirmed:");
    while (*p == ' ' || *p == '\t') p++;
    /* Read floating value */
    char *end = NULL;
    double dnac = strtod(p, &end);
    if (end == p) { free(out); return -1; }
    free(out);
    *raw_out = (uint64_t)(dnac * 1.0e8 + 0.5);
    return 0;
}

static void usage_create(void) {
    fprintf(stderr,
        "usage: dna_bench wallets create <N> [--fund <amount-raw>]\n"
        "                                    [--fresh] [--allow-large]\n");
}

static int cmd_wallets_create(int argc, char **argv) {
    int n = -1;
    uint64_t fund_raw = DNA_BENCH_DEFAULT_FUND_RAW;
    bool fresh = false;
    bool allow_large = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-') {
            if (n < 0) {
                char *end;
                long v = strtol(a, &end, 10);
                if (*end != '\0' || v <= 0) {
                    fprintf(stderr, "[dna-bench] invalid N: %s\n", a);
                    return DNA_BENCH_EXIT_USAGE;
                }
                n = (int)v;
            } else {
                fprintf(stderr, "[dna-bench] unexpected arg: %s\n", a);
                return DNA_BENCH_EXIT_USAGE;
            }
        } else if (strcmp(a, "--fund") == 0 && i + 1 < argc) {
            fund_raw = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(a, "--fresh") == 0) {
            fresh = true;
        } else if (strcmp(a, "--allow-large") == 0) {
            allow_large = true;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage_create();
            return 0;
        } else {
            fprintf(stderr, "[dna-bench] unknown flag: %s\n", a);
            usage_create();
            return DNA_BENCH_EXIT_USAGE;
        }
    }
    if (n <= 0) { usage_create(); return DNA_BENCH_EXIT_USAGE; }

    /* Operator safety caps (red-team C3, B10). */
    if (n > DNA_BENCH_MAX_WALLETS_DEFAULT && !allow_large) {
        fprintf(stderr,
                "[dna-bench] N=%d exceeds default cap %d; pass --allow-large to bypass\n",
                n, DNA_BENCH_MAX_WALLETS_DEFAULT);
        return DNA_BENCH_EXIT_USAGE;
    }
    if (n > DNA_BENCH_MAX_WALLETS_HARD) {
        fprintf(stderr, "[dna-bench] N=%d exceeds hard cap %d (no override)\n",
                n, DNA_BENCH_MAX_WALLETS_HARD);
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Pool exists? */
    if (dna_bench_pool_exists() && !fresh) {
        fprintf(stderr, "[dna-bench] pool already exists; pass --fresh or run "
                        "'wallets reset'\n");
        return 1;
    }
    if (fresh) {
        fprintf(stderr, "[dna-bench] --fresh: removing existing pool\n");
        cmd_wallets_reset(0, NULL);
    }

    /* Punk identity lock: refuse if dna-punk-debug-inbox is up (red-team C2). */
    int sysrc = system("systemctl is-active --quiet dna-punk-debug-inbox 2>/dev/null");
    if (WIFEXITED(sysrc) && WEXITSTATUS(sysrc) == 0) {
        fprintf(stderr,
            "[dna-bench] WARN: dna-punk-debug-inbox.service is active; punk "
            "identity is locked.\n"
            "           Stop it first:  sudo systemctl stop dna-punk-debug-inbox\n");
        return DNA_BENCH_EXIT_PUNK_LOCKED;
    }

    char *root = dna_bench_root();
    if (dna_bench_mkdir_p_secure(root) != 0) {
        fprintf(stderr, "[dna-bench] mkdir %s: %s\n", root, strerror(errno));
        free(root);
        return 1;
    }
    free(root);

    fprintf(stderr, "[dna-bench] creating %d wallets, fund=%llu raw each\n",
            n, (unsigned long long)fund_raw);

    int funded = 0;
    int created = 0;
    for (int i = 0; i < n && !g_dna_bench_shutdown; i++) {
        char fp[160] = {0};
        if (dna_bench_wallet_init(i, fp, sizeof(fp)) != 0) {
            fprintf(stderr, "[dna-bench] w%02d: init FAILED\n", i);
            continue;
        }
        created++;
        if (dna_bench_wallet_fund(i, fp, fund_raw) != 0) {
            fprintf(stderr, "[dna-bench] w%02d: fund FAILED\n", i);
            continue;
        }
        funded++;
    }

    int min_required = (n / 2 < 5) ? 5 : (n / 2);
    if (n < 5) min_required = n;  /* small smoke pool */
    if (funded < min_required) {
        fprintf(stderr,
            "[dna-bench] only %d/%d funded (min required %d) — aborting; "
            "check punk balance and DHT connectivity\n",
            funded, n, min_required);
        return 1;
    }

    /* Persist pool.json */
    struct dna_bench_pool p = {0};
    p.count = funded;
    p.fund_per_wallet_raw = fund_raw;
    if (dna_bench_pool_save(&p) != 0) {
        fprintf(stderr, "[dna-bench] failed to persist pool.json\n");
        return 1;
    }
    fprintf(stderr, "[dna-bench] pool created: %d/%d wallets funded (created=%d)\n",
            funded, n, created);
    return 0;
}

/* ── wallets list ──────────────────────────────────────────────── */

static int cmd_wallets_list(int argc, char **argv) {
    (void)argc; (void)argv;
    struct dna_bench_pool p = {0};
    int rc = dna_bench_pool_load(&p);
    if (rc != 0) {
        fprintf(stderr, "[dna-bench] no pool found (rc=%d)\n", rc);
        return 1;
    }
    fprintf(stderr, "[dna-bench] pool: count=%d fund_per_wallet=%llu created=%s\n",
            p.count, (unsigned long long)p.fund_per_wallet_raw, p.created_at);
    printf("idx  fp_short          balance_raw   balance_dnac\n");
    for (int i = 0; i < p.count; i++) {
        char *fp_path = dna_bench_wallet_fp_path(i);
        char *fp = dna_bench_read_first_line(fp_path);
        free(fp_path);
        uint64_t bal = 0;
        (void)dna_bench_wallet_balance(i, &bal);
        char fp_short[32] = "?";
        if (fp) { snprintf(fp_short, sizeof(fp_short), "%.16s", fp); free(fp); }
        printf("%-3d  %-17s %12llu  %.4f DNAC\n",
               i, fp_short, (unsigned long long)bal, bal / 1.0e8);
    }
    return 0;
}

/* ── wallets drain ─ deferred (not on smoke path) ──────────────── */

static int cmd_wallets_drain(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr,
        "[dna-bench] drain: deferred. For now, send remaining balances "
        "manually with `dna-connect-cli -d <wallet>/.dna dna send <to> ...` "
        "or run `wallets reset` to discard the pool.\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

/* ── wallets refund ────────────────────────────────────────────── */
/*
 * Re-fund every wallet in an existing pool from punk WITHOUT
 * touching identity files. Use this after a chain wipe leaves the
 * pool's on-chain UTXOs invalid: pool.json + wallets/wNN/{fp.txt,
 * .dna/} stay intact, only fresh fund TXs are sent on the current
 * chain.
 *
 * `wallets reset` would regenerate Dilithium5 identities → DHT
 * keyserver pollution + wallet-FP churn. `wallets refund` reuses
 * the cached fingerprints (verified via fp.txt at 128 hex chars).
 *
 * Optional flags:
 *   --fund X      override fund_per_wallet_raw for this top-up
 *                 (default: pool.json's fund_per_wallet_raw)
 *
 * Side effects: pool.json is rewritten with the refunded count and
 * (if --fund passed) the new fund_per_wallet_raw. created_at is
 * preserved so the pool's identity/age semantics are unchanged.
 */
static void usage_refund(void) {
    fprintf(stderr,
"usage: dna_bench wallets refund [--fund X]\n"
"\n"
"Re-fund every wallet in the existing pool from punk WITHOUT\n"
"regenerating identities. Use after a chain wipe drains UTXOs.\n"
"\n"
"  --fund X    raw units per wallet (default: pool.json value)\n"
"\n"
"Identity files in wallets/wNN/.dna/ + fp.txt are preserved.\n");
}

static int cmd_wallets_refund(int argc, char **argv) {
    uint64_t fund_override = 0;
    bool have_override = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--fund") == 0 && i + 1 < argc) {
            fund_override = strtoull(argv[++i], NULL, 10);
            have_override = true;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage_refund();
            return 0;
        } else {
            fprintf(stderr, "[dna-bench] refund: unknown arg: %s\n", a);
            usage_refund();
            return DNA_BENCH_EXIT_USAGE;
        }
    }

    struct dna_bench_pool meta = {0};
    int rc = dna_bench_pool_load(&meta);
    if (rc != 0) {
        fprintf(stderr,
            "[dna-bench] refund: no pool found (rc=%d). "
            "Run `wallets create N` first.\n", rc);
        return 1;
    }
    if (meta.count <= 0) {
        fprintf(stderr, "[dna-bench] refund: pool has count=0\n");
        return 1;
    }

    uint64_t fund_raw = have_override ? fund_override : meta.fund_per_wallet_raw;
    if (fund_raw == 0) {
        fprintf(stderr,
            "[dna-bench] refund: fund amount is 0 "
            "(pool default missing and no --fund given)\n");
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Same punk-locked guard as `wallets create`: refund TXs come from
     * the punk identity, so the listener service must be down. */
    int sysrc = system("systemctl is-active --quiet dna-punk-debug-inbox 2>/dev/null");
    if (WIFEXITED(sysrc) && WEXITSTATUS(sysrc) == 0) {
        fprintf(stderr,
            "[dna-bench] refund: dna-punk-debug-inbox.service is active; "
            "punk identity is locked.\n"
            "           Stop it first:  sudo systemctl stop dna-punk-debug-inbox\n");
        return DNA_BENCH_EXIT_PUNK_LOCKED;
    }

    fprintf(stderr,
        "[dna-bench] refund: %d wallets, fund=%llu raw each "
        "(pool created %s)\n",
        meta.count, (unsigned long long)fund_raw, meta.created_at);

    int funded = 0;
    int missing_fp = 0;
    for (int i = 0; i < meta.count && !g_dna_bench_shutdown; i++) {
        char *fp_path = dna_bench_wallet_fp_path(i);
        char *fp = dna_bench_read_first_line(fp_path);
        free(fp_path);
        if (!fp || strlen(fp) != 128) {
            fprintf(stderr,
                "[dna-bench] w%02d: no cached fp (skip — run `wallets reset` "
                "if pool is corrupted)\n", i);
            if (fp) free(fp);
            missing_fp++;
            continue;
        }
        fprintf(stderr,
            "[dna-bench] w%02d: refund %.16s... <- punk\n", i, fp);
        if (dna_bench_wallet_fund(i, fp, fund_raw) != 0) {
            fprintf(stderr, "[dna-bench] w%02d: fund FAILED\n", i);
        } else {
            funded++;
        }
        free(fp);
    }

    if (missing_fp == meta.count) {
        fprintf(stderr,
            "[dna-bench] refund: every wallet missing fp.txt — pool "
            "is corrupted; run `wallets reset` then `wallets create`.\n");
        return 1;
    }

    int min_required = (meta.count / 2 < 5) ? 5 : (meta.count / 2);
    if (meta.count < 5) min_required = meta.count;
    if (funded < min_required) {
        fprintf(stderr,
            "[dna-bench] refund: only %d/%d funded (min required %d) — "
            "check punk balance and DHT connectivity\n",
            funded, meta.count, min_required);
        return 1;
    }

    /* Persist updated pool.json: count = funded, fund_per_wallet_raw =
     * what we actually paid, created_at preserved (pool age unchanged). */
    struct dna_bench_pool out = {0};
    out.count = funded;
    out.fund_per_wallet_raw = fund_raw;
    snprintf(out.created_at, sizeof(out.created_at), "%s", meta.created_at);
    snprintf(out.chain_genesis_id, sizeof(out.chain_genesis_id), "%s",
             meta.chain_genesis_id);
    if (dna_bench_pool_save(&out) != 0) {
        fprintf(stderr, "[dna-bench] refund: failed to persist pool.json\n");
        return 1;
    }

    fprintf(stderr,
        "[dna-bench] refund: %d/%d wallets re-funded "
        "(missing fp=%d). Pool ready for `dna_bench --tps ...`.\n",
        funded, meta.count, missing_fp);
    return 0;
}

/* ── wallets extend ────────────────────────────────────────────── */
/*
 * Grow an existing pool from current count C to a target N (N > C),
 * keeping wallets/wNN/.dna/ + fp.txt for every existing index. Only
 * indices [C, N) get fresh Dilithium5 identities.
 *
 * The complementary subcommand to `wallets refund`: refund tops up
 * existing wallets without identity churn; extend adds new wallets
 * without touching existing ones.
 *
 * pool.json's count is bumped to N on success, so subsequent
 * `dna_bench --tps ...` runs see all N wallets, and `wallets refund`
 * tops up all of them.
 *
 * Flags:
 *   N         (positional) target pool size (1 < N <= MAX_HARD)
 *   --fund X  raw units per new wallet (default: pool.json's
 *             fund_per_wallet_raw, falling back to
 *             DNA_BENCH_DEFAULT_FUND_RAW if pool default is 0)
 *
 * Existing wallet balances and pool's fund_per_wallet_raw are NOT
 * changed by this command. Use `wallets refund [--fund X]` to top
 * up the whole pool to X.
 */
static void usage_extend(void) {
    fprintf(stderr,
"usage: dna_bench wallets extend N [--fund X]\n"
"\n"
"Grow an existing pool from its current count to N (N > current).\n"
"Existing identities + funds are preserved.\n"
"\n"
"  N          target pool size (must be larger than current count)\n"
"  --fund X   raw units per NEW wallet (default: pool's existing\n"
"             fund_per_wallet_raw, or %llu if unset)\n",
        (unsigned long long)DNA_BENCH_DEFAULT_FUND_RAW);
}

static int cmd_wallets_extend(int argc, char **argv) {
    int target = -1;
    uint64_t fund_override = 0;
    bool have_override = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] != '-') {
            if (target < 0) {
                char *end;
                long v = strtol(a, &end, 10);
                if (*end != '\0' || v <= 1) {
                    fprintf(stderr,
                        "[dna-bench] extend: invalid target N: %s\n", a);
                    return DNA_BENCH_EXIT_USAGE;
                }
                target = (int)v;
            } else {
                fprintf(stderr, "[dna-bench] extend: unexpected arg: %s\n", a);
                return DNA_BENCH_EXIT_USAGE;
            }
        } else if (strcmp(a, "--fund") == 0 && i + 1 < argc) {
            fund_override = strtoull(argv[++i], NULL, 10);
            have_override = true;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage_extend();
            return 0;
        } else {
            fprintf(stderr, "[dna-bench] extend: unknown flag: %s\n", a);
            usage_extend();
            return DNA_BENCH_EXIT_USAGE;
        }
    }
    if (target < 0) { usage_extend(); return DNA_BENCH_EXIT_USAGE; }
    if (target > DNA_BENCH_MAX_WALLETS_HARD) {
        fprintf(stderr, "[dna-bench] extend: N=%d exceeds hard cap %d\n",
                target, DNA_BENCH_MAX_WALLETS_HARD);
        return DNA_BENCH_EXIT_USAGE;
    }

    struct dna_bench_pool meta = {0};
    int rc = dna_bench_pool_load(&meta);
    if (rc != 0) {
        fprintf(stderr,
            "[dna-bench] extend: no pool found (rc=%d). "
            "Run `wallets create N` first.\n", rc);
        return 1;
    }
    if (target <= meta.count) {
        fprintf(stderr,
            "[dna-bench] extend: target %d <= current %d. "
            "Nothing to do; pass a strictly larger N.\n",
            target, meta.count);
        return DNA_BENCH_EXIT_USAGE;
    }

    uint64_t fund_raw = have_override
        ? fund_override
        : (meta.fund_per_wallet_raw ? meta.fund_per_wallet_raw
                                    : DNA_BENCH_DEFAULT_FUND_RAW);
    if (fund_raw == 0) {
        fprintf(stderr,
            "[dna-bench] extend: fund amount is 0; pass --fund X\n");
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Same punk lock guard as create / refund. */
    int sysrc = system("systemctl is-active --quiet dna-punk-debug-inbox 2>/dev/null");
    if (WIFEXITED(sysrc) && WEXITSTATUS(sysrc) == 0) {
        fprintf(stderr,
            "[dna-bench] extend: dna-punk-debug-inbox.service is active; "
            "punk identity is locked.\n"
            "           Stop it first:  sudo systemctl stop dna-punk-debug-inbox\n");
        return DNA_BENCH_EXIT_PUNK_LOCKED;
    }

    int new_count = target - meta.count;
    fprintf(stderr,
        "[dna-bench] extend: %d -> %d (%d new wallets, fund=%llu raw each)\n",
        meta.count, target, new_count, (unsigned long long)fund_raw);

    int created = 0;
    int funded = 0;
    for (int i = meta.count; i < target && !g_dna_bench_shutdown; i++) {
        char fp[160] = {0};
        if (dna_bench_wallet_init(i, fp, sizeof(fp)) != 0) {
            fprintf(stderr, "[dna-bench] w%02d: init FAILED\n", i);
            continue;
        }
        created++;
        if (dna_bench_wallet_fund(i, fp, fund_raw) != 0) {
            fprintf(stderr, "[dna-bench] w%02d: fund FAILED\n", i);
            continue;
        }
        funded++;
    }

    if (funded == 0) {
        fprintf(stderr,
            "[dna-bench] extend: 0 new wallets funded; pool unchanged\n");
        return 1;
    }

    /* Persist pool.json: count = old + funded (don't bump for unfunded
     * wallets — they have no on-chain UTXO so a later refund can't
     * salvage them, but `extend` can be re-run to retry). */
    struct dna_bench_pool out = {0};
    out.count = meta.count + funded;
    out.fund_per_wallet_raw = meta.fund_per_wallet_raw
        ? meta.fund_per_wallet_raw : fund_raw;
    snprintf(out.created_at, sizeof(out.created_at), "%s", meta.created_at);
    snprintf(out.chain_genesis_id, sizeof(out.chain_genesis_id), "%s",
             meta.chain_genesis_id);
    if (dna_bench_pool_save(&out) != 0) {
        fprintf(stderr, "[dna-bench] extend: failed to persist pool.json\n");
        return 1;
    }

    fprintf(stderr,
        "[dna-bench] extend: %d/%d new wallets funded, pool now %d "
        "(created=%d, fund_failed=%d)\n",
        funded, new_count, out.count, created, created - funded);
    return 0;
}
