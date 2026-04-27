/* dna_bench — main + subcommand dispatch.
 *
 * Replaces bench_cluster_tps.c (kept side-by-side until Phase 1.H).
 * See nodus/docs/plans/2026-04-27-dna-bench-design.md (local-only).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "dna_bench_internal.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile int g_dna_bench_shutdown = 0;

static void on_signal(int sig) {
    (void)sig;
    g_dna_bench_shutdown = 1;
}

static void install_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: let waitpid/poll return EINTR */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    /* Children are reaped explicitly; ignore SIGPIPE so a broken pipe
     * doesn't kill the parent during stream writes. */
    signal(SIGPIPE, SIG_IGN);
}

static void print_usage(void) {
    fprintf(stderr,
"dna-bench %s — load generator + meter for the prod 7-node cluster.\n"
"\n"
"Usage:\n"
"  dna_bench wallets create <N> [--fund <amount-raw>] [--fresh] [--allow-large]\n"
"  dna_bench wallets list\n"
"  dna_bench wallets reset\n"
"  dna_bench wallets drain --to <FP> --confirm-name <name> [--yes]\n"
"  dna_bench run --mode <burst|sustained|rampup|soak> [opts]\n"
"  dna_bench reconcile <run.json>\n"
"  dna_bench observe [--duration T]\n"
"\n"
"Run modes:\n"
"  --mode burst                            (max load, no pace; capped at\n"
"                                           %d tps unless --allow-stress)\n"
"  --mode sustained --tps N --duration T   (paced)\n"
"  --mode rampup --start A --end B --step S --hold H\n"
"  --mode soak --tps 1 --duration 24h      (alias for sustained)\n"
"\n"
"Common opts:\n"
"  --recipient mesh|fixed:<FP>      default mesh\n"
"  --status-interval N              live stderr tick (s); default 5\n"
"  --stream FILE.jsonl              round-by-round JSONL append\n"
"  --output FILE.json               final summary; default <run-dir>/run.json\n"
"  --abort-on-fail-rate <fraction>  optional early-exit guard\n"
"  --allow-stress                   uncap burst max-tps\n"
"  --allow-long                     bypass 48h duration cap\n"
"\n"
"Env:\n"
"  BENCH_HOME       Override pool root (default ~/.dna_bench)\n"
"  BENCH_CLI_BIN    Override dna-connect-cli path\n"
"\n"
"Pool location: ~/.dna_bench/ (mode 0700).\n"
            , DNA_BENCH_TOOL_VERSION
            , DNA_BENCH_BURST_DEFAULT_TPS);
}

int main(int argc, char **argv) {
    install_signal_handlers();

    if (argc < 2) {
        print_usage();
        return DNA_BENCH_EXIT_USAGE;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        print_usage();
        return DNA_BENCH_EXIT_OK;
    }
    if (strcmp(cmd, "--version") == 0) {
        printf("dna-bench %s\n", DNA_BENCH_TOOL_VERSION);
        return DNA_BENCH_EXIT_OK;
    }
    if (strcmp(cmd, "wallets") == 0) {
        return cmd_wallets(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "run") == 0) {
        return cmd_run(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "reconcile") == 0) {
        return cmd_reconcile(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "observe") == 0) {
        return cmd_observe(argc - 1, argv + 1);
    }

    fprintf(stderr, "unknown subcommand: %s\n", cmd);
    print_usage();
    return DNA_BENCH_EXIT_USAGE;
}
