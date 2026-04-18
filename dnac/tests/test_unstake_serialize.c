/* Verifies Task 20 — UNSTAKE TX has NO appended fields.
 *
 * Serialized UNSTAKE wire bytes must be EXACTLY the same as a SPEND TX
 * with identical non-type fields, except for the type byte.
 *
 * The empty-appended-section property is what makes UNSTAKE cryptographically
 * distinct from other types while reusing the canonical preimage shape —
 * Rule H (status=RETIRING) enforcement happens at state-mutation time.
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
    /* Build an UNSTAKE TX with a signer and some chain_id — nothing else. */
    dnac_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.type = DNAC_TX_UNSTAKE;
    tx.timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC1;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    /* Serialize, measure size. */
    uint8_t buf[32768];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    /* Expected size: header(74) + input_count(1)=0 + output_count(1)=0 +
     * witness_count(1)=0 + signer_count(1) + 1×signer(2592+4627) +
     * chain_def_flag(1) = 74 + 1 + 1 + 1 + 1 + 7219 + 1 = 7298
     * (No appended fields. Any mismatch means someone added an UNSTAKE branch
     * that shouldn't exist.)
     *
     * Compute expected length programmatically and verify equality. */
    size_t expected = 0;
    expected += 1 + 1 + 8 + DNAC_TX_HASH_SIZE;                  /* version + type + timestamp + tx_hash */
    expected += 1;                                               /* input_count */
    expected += 1;                                               /* output_count */
    expected += 1;                                               /* witness_count */
    expected += 1;                                               /* signer_count */
    expected += DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE;          /* 1 signer */
    expected += 1;                                               /* has_chain_def flag */
    CHECK(len == expected);

    /* Round-trip */
    dnac_transaction_t *round = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &round) == DNAC_SUCCESS);
    CHECK(round->type == DNAC_TX_UNSTAKE);
    CHECK(round->signer_count == 1);
    CHECK(memcmp(round->signers[0].pubkey, tx.signers[0].pubkey, DNAC_PUBKEY_SIZE) == 0);
    CHECK(memcmp(round->tx_hash, tx.tx_hash, DNAC_TX_HASH_SIZE) == 0);

    /* Anti-regression: if anyone adds an UNSTAKE branch that appends bytes,
     * size will change. Pin it. */
    dnac_free_transaction(round);

    /* Construct a SPEND TX identical except for type. Wire bytes must
     * differ ONLY at offset 1 (type byte) and in the tx_hash (because
     * compute_hash hashes the type byte). */
    dnac_transaction_t tx_spend = tx;
    tx_spend.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_compute_hash(&tx_spend, tx_spend.tx_hash) == DNAC_SUCCESS);

    uint8_t buf_spend[32768];
    size_t  len_spend = 0;
    CHECK(dnac_tx_serialize(&tx_spend, buf_spend, sizeof(buf_spend), &len_spend) == DNAC_SUCCESS);
    CHECK(len == len_spend);  /* same size — both have no appended fields */

    /* Byte-diff: only position [1] (type) + [2..2+64) (tx_hash) should differ. */
    /* Header layout: version(0) + type(1) + timestamp(2..9) + tx_hash(10..73) */
    for (size_t i = 0; i < len; i++) {
        if (i == 1) continue;                              /* type byte */
        if (i >= 10 && i < 10 + DNAC_TX_HASH_SIZE) continue;  /* tx_hash window */
        CHECK(buf[i] == buf_spend[i]);
    }

    printf("test_unstake_serialize: ALL CHECKS PASSED\n");
    return 0;
}
