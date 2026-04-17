/* Verifies Task 17 — DELEGATE TX appended-field serialization.
 *
 * - Round-trip: serialize -> deserialize preserves validator_pubkey exactly.
 * - KAT byte layout: wire bytes at appended offset match validator_pubkey.
 * - Hash binds validator_pubkey: mutating one byte changes tx_hash.
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
    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.type = DNAC_TX_DELEGATE;
    tx.timestamp = 1744812346ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC2;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    /* Populate validator_pubkey with a recognizable pattern. */
    for (size_t i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        tx.delegate_fields.validator_pubkey[i] = (uint8_t)(i & 0xff);
    }

    /* Compute hash (binds appended fields). */
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    /* Serialize. */
    uint8_t buf[16384];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    /* Deserialize. */
    dnac_transaction_t *round = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &round) == DNAC_SUCCESS);

    /* Field-by-field round-trip. */
    CHECK(round->type == DNAC_TX_DELEGATE);
    CHECK(memcmp(round->delegate_fields.validator_pubkey,
                 tx.delegate_fields.validator_pubkey,
                 DNAC_PUBKEY_SIZE) == 0);

    /* KAT: validator_pubkey appended block sits immediately before the
     * trailing chain_def flag byte (1, has_chain_def=false). */
    size_t appended_start = len - 1 - DNAC_PUBKEY_SIZE;
    for (size_t i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        CHECK(buf[appended_start + i] == (uint8_t)(i & 0xff));
    }

    /* Hash binds validator_pubkey. */
    dnac_transaction_t tx_mutated = tx;
    tx_mutated.delegate_fields.validator_pubkey[0] ^= 0x01;
    uint8_t hash_orig[DNAC_TX_HASH_SIZE];
    uint8_t hash_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx, hash_orig) == DNAC_SUCCESS);
    CHECK(dnac_tx_compute_hash(&tx_mutated, hash_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_mut, DNAC_TX_HASH_SIZE) != 0);

    /* Also bind a mid-array and a tail byte to catch short-hash bugs. */
    dnac_transaction_t tx_mid = tx;
    tx_mid.delegate_fields.validator_pubkey[DNAC_PUBKEY_SIZE / 2] ^= 0xFF;
    uint8_t hash_mid[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_mid, hash_mid) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_mid, DNAC_TX_HASH_SIZE) != 0);

    dnac_transaction_t tx_tail = tx;
    tx_tail.delegate_fields.validator_pubkey[DNAC_PUBKEY_SIZE - 1] ^= 0x80;
    uint8_t hash_tail[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_tail, hash_tail) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_tail, DNAC_TX_HASH_SIZE) != 0);

    dnac_free_transaction(round);
    printf("test_delegate_serialize: ALL CHECKS PASSED\n");
    return 0;
}
