/* Verifies Task 18 — CLAIM_REWARD TX appended-field serialization.
 *
 * - Round-trip preserves target_validator + max_pending_amount + valid_before_block.
 * - KAT byte layout: both u64s encoded big-endian at expected offsets.
 * - Hash binds all three fields.
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
    tx.type = DNAC_TX_CLAIM_REWARD;
    tx.timestamp = 1744812348ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC4;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    for (size_t i = 0; i < DNAC_PUBKEY_SIZE; i++) {
        tx.claim_reward_fields.target_validator[i] = (uint8_t)((i * 3 + 11) & 0xff);
    }
    tx.claim_reward_fields.max_pending_amount = 0x1122334455667788ULL;
    tx.claim_reward_fields.valid_before_block = 0xDEADBEEFCAFEF00DULL;

    CHECK(dnac_tx_compute_hash(&tx, tx.tx_hash) == DNAC_SUCCESS);

    uint8_t buf[16384];
    size_t  len = 0;
    CHECK(dnac_tx_serialize(&tx, buf, sizeof(buf), &len) == DNAC_SUCCESS);

    dnac_transaction_t *round = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &round) == DNAC_SUCCESS);

    CHECK(round->type == DNAC_TX_CLAIM_REWARD);
    CHECK(memcmp(round->claim_reward_fields.target_validator,
                 tx.claim_reward_fields.target_validator,
                 DNAC_PUBKEY_SIZE) == 0);
    CHECK(round->claim_reward_fields.max_pending_amount == 0x1122334455667788ULL);
    CHECK(round->claim_reward_fields.valid_before_block == 0xDEADBEEFCAFEF00DULL);

    /* KAT: appended block sits at (len - 1 [flag] - 16 [two u64s] - 2592 [pubkey]). */
    size_t appended_start = len - 1 - 16 - DNAC_PUBKEY_SIZE;
    /* target_validator[0] = (0*3+11) = 11 = 0x0B. */
    CHECK(buf[appended_start] == 0x0B);
    /* target_validator[10] = (30+11) = 41 = 0x29. */
    CHECK(buf[appended_start + 10] == 0x29);
    /* max_pending_amount BE. */
    size_t max_off = appended_start + DNAC_PUBKEY_SIZE;
    CHECK(buf[max_off + 0] == 0x11);
    CHECK(buf[max_off + 1] == 0x22);
    CHECK(buf[max_off + 2] == 0x33);
    CHECK(buf[max_off + 3] == 0x44);
    CHECK(buf[max_off + 4] == 0x55);
    CHECK(buf[max_off + 5] == 0x66);
    CHECK(buf[max_off + 6] == 0x77);
    CHECK(buf[max_off + 7] == 0x88);
    /* valid_before_block BE. */
    size_t valid_off = max_off + 8;
    CHECK(buf[valid_off + 0] == 0xDE);
    CHECK(buf[valid_off + 1] == 0xAD);
    CHECK(buf[valid_off + 2] == 0xBE);
    CHECK(buf[valid_off + 3] == 0xEF);
    CHECK(buf[valid_off + 4] == 0xCA);
    CHECK(buf[valid_off + 5] == 0xFE);
    CHECK(buf[valid_off + 6] == 0xF0);
    CHECK(buf[valid_off + 7] == 0x0D);

    /* Hash binds each field. */
    uint8_t hash_orig[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx, hash_orig) == DNAC_SUCCESS);

    dnac_transaction_t tx_mut = tx;
    tx_mut.claim_reward_fields.target_validator[0] ^= 0x01;
    uint8_t hash_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_mut, hash_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_mut, DNAC_TX_HASH_SIZE) != 0);

    dnac_transaction_t tx_max_mut = tx;
    tx_max_mut.claim_reward_fields.max_pending_amount ^= 1ULL;
    uint8_t hash_max[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_max_mut, hash_max) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_max, DNAC_TX_HASH_SIZE) != 0);

    dnac_transaction_t tx_valid_mut = tx;
    tx_valid_mut.claim_reward_fields.valid_before_block ^= 1ULL;
    uint8_t hash_valid[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_valid_mut, hash_valid) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_valid, DNAC_TX_HASH_SIZE) != 0);

    /* Ensure max vs valid_before fields are independent in the hash
     * (i.e. swapping values does change the digest). */
    dnac_transaction_t tx_swap = tx;
    tx_swap.claim_reward_fields.max_pending_amount = 0xDEADBEEFCAFEF00DULL;
    tx_swap.claim_reward_fields.valid_before_block = 0x1122334455667788ULL;
    uint8_t hash_swap[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_swap, hash_swap) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_swap, DNAC_TX_HASH_SIZE) != 0);

    dnac_free_transaction(round);
    printf("test_claim_reward_serialize: ALL CHECKS PASSED\n");
    return 0;
}
