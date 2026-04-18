/* Verifies Task 14 — TX hash preimage binds chain_id (F-CRYPTO-10).
 *
 * Two TXs identical except for chain_id MUST produce different hashes.
 * A zeroed chain_id MUST produce a different hash than a non-zero one.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

int main(void) {
    /* Build a minimal SPEND-shaped TX (just populate fields manually — no
     * ctx required for dnac_tx_compute_hash).
     *
     * NOTE: because chain_id is now hashed, build two identical TXs
     * differing only in chain_id, verify their hashes diverge.
     */

    dnac_transaction_t tx_a, tx_b;
    memset(&tx_a, 0, sizeof(tx_a));
    memset(&tx_b, 0, sizeof(tx_b));

    tx_a.version = 1;
    tx_a.type = DNAC_TX_SPEND;
    tx_a.timestamp = 1744812345ULL;

    /* Clone into tx_b */
    tx_b = tx_a;

    /* Diverge only chain_id */
    for (int i = 0; i < 32; i++) tx_a.chain_id[i] = 0xAA;
    for (int i = 0; i < 32; i++) tx_b.chain_id[i] = 0xBB;

    uint8_t hash_a[DNAC_TX_HASH_SIZE];
    uint8_t hash_b[DNAC_TX_HASH_SIZE];

    CHECK(dnac_tx_compute_hash(&tx_a, hash_a) == DNAC_SUCCESS);
    CHECK(dnac_tx_compute_hash(&tx_b, hash_b) == DNAC_SUCCESS);

    CHECK(memcmp(hash_a, hash_b, DNAC_TX_HASH_SIZE) != 0);

    /* Also: a zeroed chain_id is distinct from a non-zero one */
    dnac_transaction_t tx_zero;
    tx_zero = tx_a;
    memset(tx_zero.chain_id, 0, 32);

    uint8_t hash_zero[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_zero, hash_zero) == DNAC_SUCCESS);
    CHECK(memcmp(hash_a, hash_zero, DNAC_TX_HASH_SIZE) != 0);

    /* Determinism: same TX hashes identically */
    uint8_t hash_a2[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_a, hash_a2) == DNAC_SUCCESS);
    CHECK(memcmp(hash_a, hash_a2, DNAC_TX_HASH_SIZE) == 0);

    printf("test_preimage_binding: ALL CHECKS PASSED\n");
    return 0;
}
