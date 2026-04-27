/* dna_bench_observe.c — generator-less chain observer.
 *
 * DEFERRED to Phase 2 per implementation plan 1.G.2: requires Tier-2
 * streaming verb that does not yet exist; not on the critical path for
 * the prod TPS measurement bench.
 */

#define _POSIX_C_SOURCE 200809L

#include "dna_bench_internal.h"

#include <stdio.h>

int cmd_observe(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "[dna-bench] observe: deferred to Phase 2 (no T2 streaming verb yet)\n");
    return DNA_BENCH_EXIT_NOT_IMPLEMENTED;
}
