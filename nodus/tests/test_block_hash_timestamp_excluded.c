/**
 * Nodus — PR 2: nodus block_hash must NOT depend on timestamp
 *
 * Regression test for the timestamp determinism fix
 * (docs/plans/2026-05-03-witness-auto-bootstrap-design.md PR 2).
 *
 * Bug recap: leader's `time(NULL)` at start_round differs from broadcast
 * `hdr.timestamp`; followers store `hdr.timestamp`, leader stores its
 * own time(NULL). With timestamp in the block_hash preimage, this
 * produces divergent block_hashes → cascading prev_hash divergence
 * (observed live: EU-4 chain `e154cff9` block 193+ corruption).
 *
 * Fix (Option C + belt-and-suspenders): drop timestamp from BOTH hash
 * preimages entirely (this test) AND make leader/follower use the same
 * timestamp value so stored values match.
 *
 * Test asserts: with all OTHER fields identical, two different
 * timestamps produce the SAME hash.
 *
 * Pre-fix RED: hashes differ → memcmp != 0 → assertion FAILS.
 * Post-fix GREEN: hashes identical → memcmp == 0 → PASS.
 *
 * Companion test for the dnac-side implementation
 * (dnac_block_compute_hash) lives in dnac/tests/.
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
    printf("\nPR 2 — nodus block_hash timestamp independence\n");

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

    uint8_t out_a[64], out_b[64];
    nodus_witness_compute_block_hash_ex(height, prev_hash, state_root,
                                          tx_root, tx_count,
                                          /*timestamp=*/ 1700000000,
                                          proposer, NULL, 0, out_a);
    nodus_witness_compute_block_hash_ex(height, prev_hash, state_root,
                                          tx_root, tx_count,
                                          /*timestamp=*/ 1700009999,
                                          proposer, NULL, 0, out_b);

    /* RED on main: timestamp in preimage → out_a != out_b. */
    /* GREEN post-PR-2: timestamp dropped from preimage → out_a == out_b. */
    CHECK(memcmp(out_a, out_b, 64) == 0);

    printf("PR 2 (nodus) PASS\n");
    return 0;
}
