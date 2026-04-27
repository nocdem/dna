/* dna_bench_wallets.c — wallets {create,list,reset,drain} subcommand.
 *
 * Phase 1.A scaffolding: dispatch + stub returns. Real impl in 1.B.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmd_wallets_create(int argc, char **argv);
static int cmd_wallets_list(int argc, char **argv);
static int cmd_wallets_reset(int argc, char **argv);
static int cmd_wallets_drain(int argc, char **argv);

int cmd_wallets(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: dna_bench wallets {create|list|reset|drain} ...\n");
        return DNA_BENCH_EXIT_USAGE;
    }
    const char *sub = argv[1];
    if (strcmp(sub, "create") == 0) return cmd_wallets_create(argc - 1, argv + 1);
    if (strcmp(sub, "list")   == 0) return cmd_wallets_list(argc - 1, argv + 1);
    if (strcmp(sub, "reset")  == 0) return cmd_wallets_reset(argc - 1, argv + 1);
    if (strcmp(sub, "drain")  == 0) return cmd_wallets_drain(argc - 1, argv + 1);
    fprintf(stderr, "wallets: unknown subcommand '%s'\n", sub);
    return DNA_BENCH_EXIT_USAGE;
}

static int cmd_wallets_create(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] wallets create: not yet implemented (Phase 1.B)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

static int cmd_wallets_list(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] wallets list: not yet implemented (Phase 1.B)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

static int cmd_wallets_reset(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] wallets reset: not yet implemented (Phase 1.B)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

static int cmd_wallets_drain(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] wallets drain: not yet implemented (Phase 1.B)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

/* Wallet ops — Phase 1.B implementations live here too. Stubs for now. */
int dna_bench_wallet_init(int idx, char *fp_out, size_t fp_n) {
    (void)idx; (void)fp_out; (void)fp_n;
    return -1;
}
int dna_bench_wallet_fund(int idx, const char *fp, uint64_t amount_raw) {
    (void)idx; (void)fp; (void)amount_raw;
    return -1;
}
int dna_bench_wallet_balance(int idx, uint64_t *raw_out) {
    (void)idx; (void)raw_out;
    return -1;
}
