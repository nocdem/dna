/* dna_bench_reconcile.c — reconcile run.json against on-chain TX history.
 * Phase 1.A scaffolding.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "dna_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cmd_reconcile(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: dna_bench reconcile <run.json>\n");
        return DNA_BENCH_EXIT_USAGE;
    }
    return dna_bench_reconcile_main(argv[1]);
}

int dna_bench_reconcile_main(const char *run_json_path) {
    (void)run_json_path;
    fprintf(stderr, "[dna-bench] reconcile: not yet implemented (Phase 1.F)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}
