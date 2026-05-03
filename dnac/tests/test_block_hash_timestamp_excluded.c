/**
 * DNAC — PR 2: dnac_block_compute_hash must NOT depend on timestamp
 *
 * Companion to nodus/tests/test_block_hash_timestamp_excluded.c.
 * Both code paths (nodus_witness_compute_block_hash_ex AND
 * dnac_block_compute_hash) must produce identical hashes for the same
 * block — and after PR 2, neither depends on timestamp.
 *
 * See docs/plans/2026-05-03-pr2-timestamp-determinism-impl.md.
 *
 * Pre-fix RED: hashes differ → memcmp != 0 → assertion FAILS.
 * Post-fix GREEN: hashes identical → memcmp == 0 → PASS.
 */

#include "dnac/block.h"

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
    printf("\nPR 2 — dnac_block_compute_hash timestamp independence\n");

    dnac_block_t blk_a, blk_b;
    memset(&blk_a, 0, sizeof(blk_a));
    memset(&blk_b, 0, sizeof(blk_b));

    /* Identical fields except timestamp. Non-genesis path: is_genesis
     * stays false, chain_def excluded from preimage. */
    blk_a.block_height = 42;
    blk_b.block_height = 42;
    fill_seed(blk_a.prev_block_hash, 64, 0xB1);
    fill_seed(blk_b.prev_block_hash, 64, 0xB1);
    fill_seed(blk_a.state_root, 64, 0xB2);
    fill_seed(blk_b.state_root, 64, 0xB2);
    fill_seed(blk_a.tx_root, 64, 0xB3);
    fill_seed(blk_b.tx_root, 64, 0xB3);
    blk_a.tx_count = 5;
    blk_b.tx_count = 5;
    fill_seed(blk_a.proposer_id, 32, 0xB4);
    fill_seed(blk_b.proposer_id, 32, 0xB4);

    blk_a.timestamp = 1700000000;
    blk_b.timestamp = 1700009999;

    CHECK(dnac_block_compute_hash(&blk_a) == 0);
    CHECK(dnac_block_compute_hash(&blk_b) == 0);

    /* RED: timestamp in preimage → block_hash differs. */
    /* GREEN post-PR-2: timestamp dropped → block_hash identical. */
    CHECK(memcmp(blk_a.block_hash, blk_b.block_hash, 64) == 0);

    printf("PR 2 (dnac) PASS\n");
    return 0;
}
