/* dna_bench — single-binary TPS bench against the prod 7-node cluster.
 *
 * Usage:
 *   dna_bench --tps N --duration T [--wallets N] [--fund X] [--reset]
 *
 * Pool is auto-created at ~/.dna_bench/ on first run. Reset with --reset.
 * Optional advanced verbs (`reconcile <run.json>`) preserved.
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
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
}

static void print_usage(void) {
    fprintf(stderr,
"dna-bench %s — single-binary TPS bench against the prod 7-node cluster.\n"
"\n"
"Run a TPS test:\n"
"  dna_bench --tps N --duration T            sustained @ N tps for duration T\n"
"\n"
"Pool management (auto-creates if missing):\n"
"  --wallets N                               pool size (default 27, max 200)\n"
"  --fund X                                  raw units per wallet (default %llu)\n"
"  --reset                                   wipe pool before run (DESTROYS\n"
"                                            wallet identities; use\n"
"                                            `wallets refund` to re-fund\n"
"                                            existing pool after a chain wipe)\n"
"\n"
"Output options:\n"
"  --output FILE.json                        final summary (default <run-dir>/run.json)\n"
"  --stream FILE.jsonl                       round-by-round JSONL append\n"
"  --status-interval N                       live stderr tick (s); default 5\n"
"  --abort-on-fail-rate <fraction>           optional early-exit guard\n"
"  --allow-long                              bypass 48h duration cap\n"
"\n"
"Advanced verbs:\n"
"  dna_bench reconcile <run.json>            verify tx_hashes on chain\n"
"\n"
"Examples:\n"
"  dna_bench --tps 1 --duration 1h\n"
"  dna_bench --tps 10 --duration 5m --wallets 50\n"
"  dna_bench --reset --wallets 30 --tps 1 --duration 1h\n"
"\n"
"Env:\n"
"  BENCH_HOME       Override pool root (default ~/.dna_bench)\n"
"  BENCH_CLI_BIN    Override dna-connect-cli path\n"
            , DNA_BENCH_TOOL_VERSION
            , (unsigned long long)DNA_BENCH_DEFAULT_FUND_RAW);
}

/* run_with_autopool — top-level entry point: parse flags, ensure pool
 * exists (create if --reset or pool missing), invoke run loop. */
int dna_bench_main(int argc, char **argv);

int main(int argc, char **argv) {
    install_signal_handlers();

    if (argc < 2) {
        print_usage();
        return DNA_BENCH_EXIT_USAGE;
    }

    /* Help / version */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return DNA_BENCH_EXIT_OK;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("dna-bench %s\n", DNA_BENCH_TOOL_VERSION);
            return DNA_BENCH_EXIT_OK;
        }
    }

    /* Advanced: reconcile is a separate verb. */
    if (strcmp(argv[1], "reconcile") == 0) {
        return cmd_reconcile(argc - 1, argv + 1);
    }

    /* Pool management verb: `dna_bench wallets {create|list|reset|drain|refund} ...`
     * Used directly when the operator wants to refund/inspect/reset the pool
     * without touching the run loop. The internal --reset flag in the run
     * path still calls cmd_wallets() programmatically. */
    if (strcmp(argv[1], "wallets") == 0) {
        return cmd_wallets(argc - 1, argv + 1);
    }

    /* Default path: --tps / --duration etc. parsed in dna_bench_main. */
    return dna_bench_main(argc, argv);
}
