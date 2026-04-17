/* Verifies Task 19 — VALIDATOR_UPDATE TX appended-field serialization.
 *
 * - Round-trip: serialize -> deserialize preserves both fields.
 * - KAT byte layout: u16 BE commission, u64 BE signed_at_block at exact offsets.
 * - Hash binds both fields.
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
    tx.type = DNAC_TX_VALIDATOR_UPDATE;
    tx.timestamp = 1744812349ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC5;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    /* 0x0BB8 = 3000 (= 30.00% commission), 0x123456789ABCDEF0 block. */
    tx.validator_update_fields.new_commission_bps = 0x0BB8;
    tx.validator_update_fields.signed_at_block    = 0x123456789ABCDEF0ULL;

    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    uint8_t buf[16384];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    dnac_transaction_t *round = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &round) == DNAC_SUCCESS);

    CHECK(round->type == DNAC_TX_VALIDATOR_UPDATE);
    CHECK(round->validator_update_fields.new_commission_bps == 0x0BB8);
    CHECK(round->validator_update_fields.signed_at_block    == 0x123456789ABCDEF0ULL);

    /* KAT: appended block sits at (len - 1 [chain_def flag] - 8 [u64] - 2 [u16]). */
    size_t appended_start = len - 1 - 8 - 2;
    /* commission BE: 0x0B 0xB8. */
    CHECK(buf[appended_start + 0] == 0x0B);
    CHECK(buf[appended_start + 1] == 0xB8);
    /* signed_at_block BE. */
    size_t blk_off = appended_start + 2;
    CHECK(buf[blk_off + 0] == 0x12);
    CHECK(buf[blk_off + 1] == 0x34);
    CHECK(buf[blk_off + 2] == 0x56);
    CHECK(buf[blk_off + 3] == 0x78);
    CHECK(buf[blk_off + 4] == 0x9A);
    CHECK(buf[blk_off + 5] == 0xBC);
    CHECK(buf[blk_off + 6] == 0xDE);
    CHECK(buf[blk_off + 7] == 0xF0);

    /* Hash binds commission. */
    uint8_t hash_orig[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx, hash_orig) == DNAC_SUCCESS);

    dnac_transaction_t tx_c = tx;
    tx_c.validator_update_fields.new_commission_bps ^= 0x0001;
    uint8_t hash_c[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_c, hash_c) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_c, DNAC_TX_HASH_SIZE) != 0);

    /* High-byte mutation of commission. */
    dnac_transaction_t tx_c_hi = tx;
    tx_c_hi.validator_update_fields.new_commission_bps ^= 0x0100;
    uint8_t hash_c_hi[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_c_hi, hash_c_hi) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_c_hi, DNAC_TX_HASH_SIZE) != 0);

    /* Hash binds signed_at_block (low byte). */
    dnac_transaction_t tx_b_lo = tx;
    tx_b_lo.validator_update_fields.signed_at_block ^= 1ULL;
    uint8_t hash_b_lo[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_b_lo, hash_b_lo) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_b_lo, DNAC_TX_HASH_SIZE) != 0);

    /* High byte of signed_at_block. */
    dnac_transaction_t tx_b_hi = tx;
    tx_b_hi.validator_update_fields.signed_at_block ^= (1ULL << 56);
    uint8_t hash_b_hi[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_b_hi, hash_b_hi) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_b_hi, DNAC_TX_HASH_SIZE) != 0);

    dnac_free_transaction(round);
    printf("test_validator_update_serialize: ALL CHECKS PASSED\n");
    return 0;
}
