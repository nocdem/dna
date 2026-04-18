/* Verifies Task 18 — UNDELEGATE TX appended-field serialization.
 *
 * - Round-trip: serialize -> deserialize preserves validator_pubkey + amount.
 * - KAT byte layout: amount is big-endian 8 bytes at expected offset.
 * - Hash binds both fields: mutating either changes tx_hash.
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
    tx.type = DNAC_TX_UNDELEGATE;
    tx.timestamp = 1744812347ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC3;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    /* validator_pubkey: recognizable pattern. */
    for (size_t i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        tx.undelegate_fields.validator_pubkey[i] = (uint8_t)((i * 7) & 0xff);
    }
    /* amount: 0x0102030405060708 so BE wire must read 01 02 03 04 05 06 07 08. */
    tx.undelegate_fields.amount = 0x0102030405060708ULL;

    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    uint8_t buf[16384];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    dnac_transaction_t *round = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &round) == DNAC_SUCCESS);

    CHECK(round->type == DNAC_TX_UNDELEGATE);
    CHECK(memcmp(round->undelegate_fields.validator_pubkey,
                 tx.undelegate_fields.validator_pubkey,
                 DNAC_PUBKEY_SIZE) == 0);
    CHECK(round->undelegate_fields.amount == 0x0102030405060708ULL);

    /* KAT: appended block starts (len - 1 [chain_def flag] - 8 [amount]
     * - 2592 [pubkey]). Amount sits at appended_start + 2592. */
    size_t appended_start = len - 1 - 8 - DNAC_PUBKEY_SIZE;
    /* Pubkey first byte matches pattern i=0 -> 0. */
    CHECK(buf[appended_start] == 0x00);
    /* Pubkey byte 5 = (5*7)&0xff = 35 = 0x23. */
    CHECK(buf[appended_start + 5] == 0x23);
    /* Amount BE bytes. */
    size_t amt_off = appended_start + DNAC_PUBKEY_SIZE;
    CHECK(buf[amt_off + 0] == 0x01);
    CHECK(buf[amt_off + 1] == 0x02);
    CHECK(buf[amt_off + 2] == 0x03);
    CHECK(buf[amt_off + 3] == 0x04);
    CHECK(buf[amt_off + 4] == 0x05);
    CHECK(buf[amt_off + 5] == 0x06);
    CHECK(buf[amt_off + 6] == 0x07);
    CHECK(buf[amt_off + 7] == 0x08);

    /* Hash binds validator_pubkey. */
    uint8_t hash_orig[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx, hash_orig) == DNAC_SUCCESS);

    dnac_transaction_t tx_pk_mut = tx;
    tx_pk_mut.undelegate_fields.validator_pubkey[DNAC_PUBKEY_SIZE / 2] ^= 0x01;
    uint8_t hash_pk_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_pk_mut, hash_pk_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_pk_mut, DNAC_TX_HASH_SIZE) != 0);

    /* Hash binds amount. */
    dnac_transaction_t tx_amt_mut = tx;
    tx_amt_mut.undelegate_fields.amount ^= 0x01ULL;
    uint8_t hash_amt_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_amt_mut, hash_amt_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_amt_mut, DNAC_TX_HASH_SIZE) != 0);

    /* Also high-byte mutation of amount. */
    dnac_transaction_t tx_amt_hi = tx;
    tx_amt_hi.undelegate_fields.amount ^= (0x01ULL << 56);
    uint8_t hash_amt_hi[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_amt_hi, hash_amt_hi) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_amt_hi, DNAC_TX_HASH_SIZE) != 0);

    dnac_free_transaction(round);
    printf("test_undelegate_serialize: ALL CHECKS PASSED\n");
    return 0;
}
