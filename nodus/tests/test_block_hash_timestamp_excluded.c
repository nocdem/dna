/**
 * Nodus — PR 2: nodus block_hash must NOT depend on timestamp
 *
 * See docs/plans/2026-05-03-pr2-timestamp-determinism-impl.md.
 *
 * Pre-PR-2 (RED): nodus_witness_compute_block_hash_ex took a
 * `uint64_t timestamp` parameter, included it in the SHA3 preimage,
 * and produced different hashes for different timestamps.
 *
 * Post-PR-2 (GREEN): timestamp parameter REMOVED from the signature
 * entirely. This test now serves a structural role: if any future
 * change re-introduces a timestamp parameter, this test will FAIL to
 * compile (function arity mismatch). That compile error IS the
 * regression catch — the deeper property (timestamp independence) is
 * now enforced by the type system itself.
 *
 * For the dnac-side equivalent (which keeps timestamp as a struct
 * field but excludes it from preimage), see
 * dnac/tests/test_block_hash_timestamp_excluded.c — that test stays
 * as a runtime check because the field can't be deleted from the
 * dnac_block_t struct (used for storage/display).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_db.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

static void fill_seed(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(seed + i);
}

int main(void) {
    printf("\nPR 2 — nodus block_hash signature regression guard\n");

    uint64_t       height       = 42;
    uint8_t        prev_hash[64];
    uint8_t        state_root[64];
    uint8_t        tx_root[64];
    uint32_t       tx_count     = 5;
    uint8_t        proposer[32];

    fill_seed(prev_hash,  64, 0xA1);
    fill_seed(state_root, 64, 0xA2);
    fill_seed(tx_root,    64, 0xA3);
    fill_seed(proposer,   32, 0xA4);

    /* If a future change re-introduces a timestamp parameter to either
     * function, these calls will fail to compile (arity mismatch). */
    uint8_t out_a[64], out_b[64];
    nodus_witness_compute_block_hash_ex(height, prev_hash, state_root,
                                          tx_root, tx_count,
                                          proposer, NULL, 0, out_a);
    nodus_witness_compute_block_hash_ex(height, prev_hash, state_root,
                                          tx_root, tx_count,
                                          proposer, NULL, 0, out_b);
    CHECK(memcmp(out_a, out_b, 64) == 0);

    /* Same for the non-extended variant. */
    nodus_witness_compute_block_hash(height, prev_hash, state_root,
                                       tx_root, tx_count,
                                       proposer, out_a);
    nodus_witness_compute_block_hash(height, prev_hash, state_root,
                                       tx_root, tx_count,
                                       proposer, out_b);
    CHECK(memcmp(out_a, out_b, 64) == 0);

    printf("PR 2 (nodus signature guard) PASS\n");
    return 0;
}
