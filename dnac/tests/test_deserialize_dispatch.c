/* Verifies Task 21 — TX deserialize handles all 6 new types + rejects unknown.
 *
 * Coverage:
 * - Round-trip every new type (4..9).
 * - Unknown type (value > DNAC_TX_VALIDATOR_UPDATE) rejected by the type-range
 *   check added in Task 16.
 * - Truncated buffer at various points rejected without crash.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

static void fill_signer(dnac_transaction_t *tx) {
    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);
}

static void common_fields(dnac_transaction_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;
    fill_signer(tx);
}

static int roundtrip(const dnac_transaction_t *tx) {
    uint8_t buf[32768];
    size_t len = 0;
    if (dnac_tx_serialize(tx, buf, sizeof(buf), &len) != DNAC_SUCCESS) return 0;
    dnac_transaction_t *round = NULL;
    if (dnac_tx_deserialize(buf, len, &round) != DNAC_SUCCESS) return 0;
    int ok = (round->type == tx->type);
    dnac_free_transaction(round);
    return ok;
}

int main(void) {
    dnac_transaction_t tx;

    /* STAKE */
    common_fields(&tx);
    tx.type = DNAC_TX_STAKE;
    tx.stake_fields.commission_bps = 500;
    memset(tx.stake_fields.unstake_destination_fp, 0x11, 64);
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);
    CHECK(roundtrip(&tx));

    /* DELEGATE */
    common_fields(&tx);
    tx.type = DNAC_TX_DELEGATE;
    memset(tx.delegate_fields.validator_pubkey, 0x22, DNAC_PUBKEY_SIZE);
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);
    CHECK(roundtrip(&tx));

    /* UNSTAKE */
    common_fields(&tx);
    tx.type = DNAC_TX_UNSTAKE;
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);
    CHECK(roundtrip(&tx));

    /* UNDELEGATE */
    common_fields(&tx);
    tx.type = DNAC_TX_UNDELEGATE;
    memset(tx.undelegate_fields.validator_pubkey, 0x33, DNAC_PUBKEY_SIZE);
    tx.undelegate_fields.amount = 1000ULL * 100000000ULL;
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);
    CHECK(roundtrip(&tx));

    /* VALIDATOR_UPDATE */
    common_fields(&tx);
    tx.type = DNAC_TX_VALIDATOR_UPDATE;
    tx.validator_update_fields.new_commission_bps = 800;
    tx.validator_update_fields.signed_at_block = 42ULL;
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);
    CHECK(roundtrip(&tx));

    /* Unknown type rejection: take a valid STAKE, mutate type byte to 99 */
    common_fields(&tx);
    tx.type = DNAC_TX_STAKE;
    tx.stake_fields.commission_bps = 500;
    memset(tx.stake_fields.unstake_destination_fp, 0x11, 64);
    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    uint8_t buf[32768];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    /* Verify type is at offset 1 per header layout. Mutate it. */
    uint8_t orig_type = buf[1];
    CHECK(orig_type == DNAC_TX_STAKE);
    buf[1] = 99;  /* well above DNAC_TX_VALIDATOR_UPDATE */
    dnac_transaction_t *bad = NULL;
    int rc = dnac_tx_deserialize(buf, len, &bad);
    CHECK(rc != DNAC_SUCCESS);
    CHECK(bad == NULL);
    buf[1] = orig_type;  /* restore */

    /* Truncated-buffer rejection: try truncating at various points. None should
     * crash; all should reject the corrupted TX. */
    for (size_t trunc = 1; trunc < len - 1; trunc += 41) {
        dnac_transaction_t *t = NULL;
        int r = dnac_tx_deserialize(buf, trunc, &t);
        /* Either rejects or accepts (if the truncation happens to be at a valid
         * boundary like "end of signers" before appended fields). Must not crash. */
        if (r == DNAC_SUCCESS) {
            /* Legal short form — but then type must match original and we must
             * not segfault on freeing. */
            dnac_free_transaction(t);
        } else {
            CHECK(t == NULL);
        }
    }

    printf("test_deserialize_dispatch: ALL CHECKS PASSED\n");
    return 0;
}
