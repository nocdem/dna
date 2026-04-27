/* dna_bench_run.c — run subcommand (burst/sustained/rampup/soak).
 *
 * Phase 1.A scaffolding: arg dispatch + stub. Real impl in 1.C.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cmd_run(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] run: not yet implemented (Phase 1.C)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}

int dna_bench_run_main(struct dna_bench_run_cfg *cfg) {
    (void)cfg;
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}
