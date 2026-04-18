/* Verifies Task 16 — STAKE TX appended-field serialization.
 *
 * - Round-trip: serialize -> deserialize produces byte-identical fields.
 * - KAT byte layout: a known STAKE TX produces a specific wire suffix.
 * - Purpose tag mismatch: deserialize rejects a mutated tag.
 * - Hash binds appended fields: mutating commission_bps changes tx_hash.
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
    tx.type = DNAC_TX_STAKE;
    tx.timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xC1;
    tx.signer_count = 1;
    memset(tx.signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx.signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    tx.stake_fields.commission_bps = 0x1234;
    memset(tx.stake_fields.unstake_destination_fp, 0xEF,
           DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);

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
    CHECK(round->type == DNAC_TX_STAKE);
    CHECK(round->stake_fields.commission_bps == 0x1234);
    CHECK(memcmp(round->stake_fields.unstake_destination_fp,
                 tx.stake_fields.unstake_destination_fp,
                 DNAC_STAKE_UNSTAKE_DEST_FP_SIZE) == 0);

    /* KAT: commission_bps = 0x1234 -> bytes [0x12, 0x34] at the appended
     * offset. Reverse-calculate position: whole size minus trailing
     * chain_def flag (1 byte, has_chain_def=false) minus 17 (purpose_tag)
     * minus 64 (fp) minus 2 (commission) = start of appended block. */
    size_t appended_start = len - 1 - DNAC_STAKE_PURPOSE_TAG_LEN
                          - DNAC_STAKE_UNSTAKE_DEST_FP_SIZE - 2;
    CHECK(buf[appended_start + 0] == 0x12);
    CHECK(buf[appended_start + 1] == 0x34);
    /* First byte of unstake_destination_fp */
    CHECK(buf[appended_start + 2] == 0xEF);
    /* First byte of purpose tag "D" */
    CHECK(buf[appended_start + 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE] == 'D');

    /* Purpose tag tamper detection: mutate the 'D' -> 'X' in the wire. */
    size_t tag_off = appended_start + 2 + DNAC_STAKE_UNSTAKE_DEST_FP_SIZE;
    buf[tag_off] = 'X';
    dnac_transaction_t *bad = NULL;
    int rc = dnac_tx_deserialize(buf, len, &bad);
    CHECK(rc != DNAC_SUCCESS);
    CHECK(bad == NULL);

    /* Restore and confirm re-parse works. */
    buf[tag_off] = 'D';
    dnac_transaction_t *good = NULL;
    CHECK(dnac_tx_deserialize(buf, len, &good) == DNAC_SUCCESS);

    /* Hash binds commission_bps. */
    dnac_transaction_t tx_mutated = tx;
    tx_mutated.stake_fields.commission_bps = 0x5678;
    uint8_t hash_orig[DNAC_TX_HASH_SIZE];
    uint8_t hash_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx, hash_orig) == DNAC_SUCCESS);
    CHECK(dnac_tx_compute_hash(&tx_mutated, hash_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_mut, DNAC_TX_HASH_SIZE) != 0);

    /* Hash also binds unstake_destination_fp. */
    dnac_transaction_t tx_fp_mut = tx;
    tx_fp_mut.stake_fields.unstake_destination_fp[0] ^= 0x01;
    uint8_t hash_fp_mut[DNAC_TX_HASH_SIZE];
    CHECK(dnac_tx_compute_hash(&tx_fp_mut, hash_fp_mut) == DNAC_SUCCESS);
    CHECK(memcmp(hash_orig, hash_fp_mut, DNAC_TX_HASH_SIZE) != 0);

    dnac_free_transaction(round);
    dnac_free_transaction(good);
    printf("test_stake_serialize: ALL CHECKS PASSED\n");
    return 0;
}
