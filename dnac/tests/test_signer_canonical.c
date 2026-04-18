/* Verifies F-CRYPTO-06 — TX hash + wire bytes MUST be invariant under
 * mutation of unused signer slots (signers[signer_count..DNAC_TX_MAX_SIGNERS]).
 *
 * Attack model: adversary post-construction mutates trailing signer bytes
 * hoping to alter tx_hash or wire bytes while keeping the valid signature
 * on the first slot. If the signer array were hashed full-width, this
 * would produce hash malleability.
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
    dnac_transaction_t tx_a;
    memset(&tx_a, 0, sizeof(tx_a));

    tx_a.version = 1;
    tx_a.type = DNAC_TX_SPEND;
    tx_a.timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx_a.chain_id[i] = 0xC1;

    /* One signer with well-known pubkey/sig bytes */
    tx_a.signer_count = 1;
    memset(tx_a.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx_a.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    /* Clone, then mutate unused slots 1..N-1 */
    dnac_transaction_t tx_b = tx_a;
    for (int i = 1; i < DNAC_TX_MAX_SIGNERS; i++) {
        memset(tx_b.signers[i].pubkey,    0xFF, DNAC_PUBKEY_SIZE);
        memset(tx_b.signers[i].signature, 0xFE, DNAC_SIGNATURE_SIZE);
    }

    /* Invariant 1: compute_hash identical */
    uint8_t hash_a[DNAC_TX_HASH_SIZE];
    uint8_t hash_b[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_a, hash_a) == DNAC_SUCCESS);
    CHECK(dnac_tx_compute_hash(&tx_b, hash_b) == DNAC_SUCCESS);
    CHECK(memcmp(hash_a, hash_b, DNAC_TX_HASH_SIZE) == 0);

    /* Invariant 2: serialized wire bytes identical */
    /* Populate tx_hash field (serialize writes it into the header). */
    memcpy(tx_a.tx_hash, hash_a, DNAC_TX_HASH_SIZE);
    memcpy(tx_b.tx_hash, hash_b, DNAC_TX_HASH_SIZE);

    uint8_t buf_a[8192];
    uint8_t buf_b[8192];
    size_t  len_a = 0, len_b = 0;
    CHECK(dnac_tx_serialize(&tx_a, buf_a, sizeof(buf_a), &len_a) == DNAC_SUCCESS);
    CHECK(dnac_tx_serialize(&tx_b, buf_b, sizeof(buf_b), &len_b) == DNAC_SUCCESS);
    CHECK(len_a == len_b);
    CHECK(memcmp(buf_a, buf_b, len_a) == 0);

    /* Invariant 3: deserialize of either form yields signer_count=1 and
     * ignores bytes beyond the first slot. */
    dnac_transaction_t *round_a = NULL;
    dnac_transaction_t *round_b = NULL;
    CHECK(dnac_tx_deserialize(buf_a, len_a, &round_a) == DNAC_SUCCESS);
    CHECK(dnac_tx_deserialize(buf_b, len_b, &round_b) == DNAC_SUCCESS);
    CHECK(round_a->signer_count == 1);
    CHECK(round_b->signer_count == 1);

    /* Un-populated signer slots in the deserialized struct must be zeroed
     * (calloc semantics in dnac_tx_deserialize). */
    uint8_t zero_pk[DNAC_PUBKEY_SIZE] = {0};
    uint8_t zero_sig[DNAC_SIGNATURE_SIZE] = {0};
    for (int i = 1; i < DNAC_TX_MAX_SIGNERS; i++) {
        CHECK(memcmp(round_a->signers[i].pubkey,    zero_pk,  DNAC_PUBKEY_SIZE)    == 0);
        CHECK(memcmp(round_a->signers[i].signature, zero_sig, DNAC_SIGNATURE_SIZE) == 0);
        CHECK(memcmp(round_b->signers[i].pubkey,    zero_pk,  DNAC_PUBKEY_SIZE)    == 0);
        CHECK(memcmp(round_b->signers[i].signature, zero_sig, DNAC_SIGNATURE_SIZE) == 0);
    }

    dnac_free_transaction(round_a);
    dnac_free_transaction(round_b);

    printf("test_signer_canonical: ALL CHECKS PASSED\n");
    return 0;
}
