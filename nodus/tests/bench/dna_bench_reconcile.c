/* dna_bench_reconcile.c — post-bench chain reconciliation.
 *
 * Per design 2026-04-27 "dna-bench reconcile <run.json>":
 * - Read tx_hashes.txt next to <run.json>.
 * - For each hash, fork `dna-connect-cli dna chain tx <hash>` (NOT
 *   `dna tx <hash>` — note the chain prefix; the verb is in the same
 *   group as `genesis-create` etc; aliased here as `dna tx`).
 * - Parse "Block:" line from output -> committed.
 * - "Tx not found" / non-zero exit / no Block line -> dropped.
 * - Write run.reconciled.json next to run.json with discrepancy fields.
 *
 * Phase 1.F ships the per-hash path (N × ~50ms RTT). The Phase 2
 * batch-range optimization is captured in the design doc; not needed
 * for typical N≤100 reconciles.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_HASHES   100000
#define HASH_BUF_LEN 160
#define CLI_OUT_LEN  4096

static int run_capture(const char *const argv[], char *out, size_t n) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
        int dni = open("/dev/null", O_RDONLY);
        if (dni >= 0) { dup2(dni, STDIN_FILENO); close(dni); }
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t total = 0;
    while (total + 1 < n) {
        ssize_t r = read(pipefd[0], out + total, n - 1 - total);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            break;
        }
        total += (size_t)r;
    }
    out[total] = '\0';
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* In-flight retry pause: one block_interval (NODUS_W_BLOCK_INTERVAL_MS = 5s).
 * Used when lookup-tx returns exit 1 ("not found") for a hash that may still
 * be in the BFT-commit → ledger-insert window (red-team F-D3). One retry. */
#define RETRY_PAUSE_S 5

int cmd_reconcile(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: dna_bench reconcile <run.json>\n");
        return DNA_BENCH_EXIT_USAGE;
    }
    return dna_bench_reconcile_main(argv[1]);
}

int dna_bench_reconcile_main(const char *run_json_path) {
    if (!run_json_path) return DNA_BENCH_EXIT_USAGE;

    /* Locate tx_hashes.txt next to run.json. */
    char dir_buf[1280];
    snprintf(dir_buf, sizeof(dir_buf), "%s", run_json_path);
    char *slash = strrchr(dir_buf, '/');
    char tx_path[1280];
    if (slash) {
        *slash = '\0';
        snprintf(tx_path, sizeof(tx_path), "%s/tx_hashes.txt", dir_buf);
    } else {
        snprintf(tx_path, sizeof(tx_path), "tx_hashes.txt");
    }

    FILE *fh = fopen(tx_path, "r");
    if (!fh) {
        fprintf(stderr,
            "[dna-bench] reconcile: cannot open %s: %s\n"
            "  (looked next to %s)\n",
            tx_path, strerror(errno), run_json_path);
        return 1;
    }

    /* Slurp the original run.json so we can echo its body into the
     * reconciled JSON (minus its trailing brace + reconciled:false).
     * For simplicity we just parse the schema we know. */
    FILE *rj = fopen(run_json_path, "r");
    char *orig = NULL;
    size_t orig_len = 0;
    if (rj) {
        char buf[8192];
        size_t n = fread(buf, 1, sizeof(buf), rj);
        fclose(rj);
        orig = malloc(n + 1);
        if (orig) { memcpy(orig, buf, n); orig[n] = '\0'; orig_len = n; }
    }

    const char *cli = dna_bench_cli_bin();

    char hash[HASH_BUF_LEN];
    int found = 0, dropped = 0, harness_errors = 0, total = 0;

    fprintf(stderr, "[dna-bench] reconcile: querying %s via lookup-tx ...\n",
            tx_path);

    /* Per-hash query: dna chain lookup-tx <hash>
     * Distinct exit codes (design 2026-05-09-cli-lookup-tx-design.md §5.2):
     *   0 = found on chain
     *   1 = not-found (legitimate; may be in-flight → retry once after 5s)
     *   2 = usage/hex error (harness bug, should never happen here)
     *   3 = transport/witness error (witness offline, network drop)
     */
    while (fgets(hash, sizeof(hash), fh)) {
        size_t hl = strlen(hash);
        while (hl > 0 && (hash[hl-1] == '\n' || hash[hl-1] == '\r' ||
                          hash[hl-1] == ' '  || hash[hl-1] == '\t')) {
            hash[--hl] = '\0';
        }
        if (hl == 0) continue;
        total++;

        const char *q_argv[] = {
            cli, "-q", "dna", "lookup-tx", hash, NULL,
        };
        char out[CLI_OUT_LEN];
        out[0] = '\0';
        int rc = run_capture(q_argv, out, sizeof(out));

        if (rc == 0) {
            found++;
        } else if (rc == 1) {
            /* In-flight window retry: sleep one block_interval, re-query. */
            struct timespec ts = { RETRY_PAUSE_S, 0 };
            nanosleep(&ts, NULL);
            out[0] = '\0';
            int rc2 = run_capture(q_argv, out, sizeof(out));
            if (rc2 == 0) {
                found++;
            } else if (rc2 == 1) {
                dropped++;
            } else {
                harness_errors++;
                fprintf(stderr,
                    "[dna-bench] reconcile: harness error rc=%d on hash %.16s... (retry)\n",
                    rc2, hash);
            }
        } else {
            harness_errors++;
            fprintf(stderr,
                "[dna-bench] reconcile: harness error rc=%d on hash %.16s...\n",
                rc, hash);
        }

        if (total % 10 == 0) {
            fprintf(stderr,
                "[dna-bench] reconcile: %d (found=%d dropped=%d errors=%d)\n",
                total, found, dropped, harness_errors);
        }
    }
    fclose(fh);

    /* Write run.reconciled.json next to run.json. */
    char out_path[1280];
    snprintf(out_path, sizeof(out_path), "%s.reconciled.json", run_json_path);
    /* Replace .json suffix if present */
    char *p = strstr(out_path, ".json.reconciled.json");
    if (p) {
        memmove(p, ".reconciled.json", strlen(".reconciled.json") + 1);
    }
    FILE *of = fopen(out_path, "w");
    if (!of) {
        fprintf(stderr, "[dna-bench] reconcile: cannot write %s: %s\n",
                out_path, strerror(errno));
        free(orig);
        return 1;
    }

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    /* If we have orig JSON, strip trailing newline + closing brace and
     * append the reconciled fields before re-closing. Simpler approach:
     * a small wrapper. */
    if (orig && orig_len > 2) {
        /* Find last '}' */
        char *last_brace = NULL;
        for (size_t i = orig_len; i > 0; i--) {
            if (orig[i - 1] == '}') { last_brace = &orig[i - 1]; break; }
        }
        if (last_brace) *last_brace = '\0';
        fprintf(of,
            "%s,\"reconciled_at\":\"%s\",\"reconciled\":true,"
            "\"actuals\":{\"commit_actual\":%d,"
            "\"dropped_or_uncommitted\":%d,\"harness_errors\":%d,"
            "\"queries\":%d}}\n",
            orig, ts, found, dropped, harness_errors, total);
    } else {
        fprintf(of,
            "{\"reconciled_at\":\"%s\",\"reconciled\":true,"
            "\"actuals\":{\"commit_actual\":%d,"
            "\"dropped_or_uncommitted\":%d,\"harness_errors\":%d,"
            "\"queries\":%d}}\n",
            ts, found, dropped, harness_errors, total);
    }
    fclose(of);
    free(orig);

    fprintf(stderr,
        "[dna-bench] reconcile DONE: queries=%d found=%d dropped=%d errors=%d\n"
        "[dna-bench] wrote %s\n",
        total, found, dropped, harness_errors, out_path);
    return harness_errors > 0 ? 1 : 0;
}
