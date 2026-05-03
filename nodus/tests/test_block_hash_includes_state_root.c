/**
 * Nodus — Faz 1.5 — block_hash binds state_root (B-1 invariant, concrete)
 *
 * compute_block_hash 244-byte preimage includes state_root: changing
 * state_root MUST change the resulting block_hash. This invariant is
 * the underlying defense for B-1 (Byzantine leader cannot mutate
 * state_root post-PRECOMMIT and keep certs valid — block_hash
 * recompute diverges).
 *
 * Note: full B-1 mitigation also requires the PRECOMMIT sign side
 * to feed compute_block_hash output (not raw tx_root) into
 * compute_cert_preimage. That sign-side migration is a separate
 * audit task; this test locks down the helper invariant the future
 * fix will lean on.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_db.h"
#include "nodus/nodus_types.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

int main(void) {
    printf("\nFaz 1.5 — block_hash includes state_root\n");

    uint8_t prev_hash[64], tx_root[64], proposer[32];
    uint8_t state_root_A[64], state_root_B[64];
    memset(prev_hash, 0x11, 64);
    memset(tx_root,   0x22, 64);
    memset(proposer,  0x33, 32);
    memset(state_root_A, 0xAA, 64);
    memset(state_root_B, 0xBB, 64);

    uint8_t hash_A[64], hash_B[64];
    nodus_witness_compute_block_hash(5, prev_hash, state_root_A, tx_root,
                                       1, proposer, hash_A);
    nodus_witness_compute_block_hash(5, prev_hash, state_root_B, tx_root,
                                       1, proposer, hash_B);

    CHECK(memcmp(hash_A, hash_B, 64) != 0);
    printf("  state_root_A vs state_root_B → distinct block_hash ✓\n");

    /* Sanity: same inputs reproduce same hash */
    uint8_t hash_A2[64];
    nodus_witness_compute_block_hash(5, prev_hash, state_root_A, tx_root,
                                       1, proposer, hash_A2);
    CHECK(memcmp(hash_A, hash_A2, 64) == 0);
    printf("  determinism preserved ✓\n");

    printf("Faz 1.5 PASS (B-1 helper invariant; sign-side migration "
        "tracked separately)\n");
    return 0;
}
