/* Verifies Task 33 - F-CRYPTO-05 cross-protocol purpose-tag defense.
 *
 * A Dilithium5 signature captured from a SPEND TX MUST NOT verify as
 * a STAKE TX. The defense is Task 16 / design section 2.3: the STAKE
 * preimage includes the 17-byte literal "DNAC_VALIDATOR_v1"
 * (DNAC_STAKE_PURPOSE_TAG) AND the commission_bps +
 * unstake_destination_fp. SPEND has no type-specific preimage
 * section. So even with every OTHER field identical (version,
 * timestamp, chain_id, signer pubkey, inputs, outputs), the two
 * preimages differ and a SPEND-bound signature cannot pass a STAKE
 * signature-verify.
 *
 * Test flow:
 *   1. Generate a real Dilithium5 keypair.
 *   2. Build a SPEND TX (type = DNAC_TX_SPEND), populate signer,
 *      inputs, outputs, chain_id, timestamp.
 *   3. Compute SPEND tx_hash, sign it - record the signature.
 *   4. Sanity: verify_signers() passes for the SPEND.
 *   5. Flip tx.type to DNAC_TX_STAKE; populate stake_fields with
 *      chosen commission + unstake_destination_fp. Keep the captured
 *      SPEND signature in signers[0].signature.
 *   6. Recompute tx_hash (now includes commission_bps + unstake_fp +
 *      "DNAC_VALIDATOR_v1" suffix - entirely new preimage).
 *   7. verify_signers must FAIL - the SPEND signature cannot cover
 *      the STAKE preimage.
 *   8. Double-check: the two hashes differ.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while (0)

#define CHECK_OK(expr) do { \
    int _rc = (expr); \
    if (_rc != DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_OK fail at %s:%d: %s -> %d\n", \
            __FILE__, __LINE__, #expr, _rc); exit(1); } } while (0)

#define CHECK_ERR(expr) do { \
    int _rc = (expr); \
    if (_rc == DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_ERR fail at %s:%d: %s returned SUCCESS\n", \
            __FILE__, __LINE__, #expr); exit(1); } } while (0)

/* verify_signers is defined non-static in dnac/src/transaction/verify.c
 * but not declared in any public header - it's an internal primitive
 * only useful to tests. Local prototype keeps the linker happy. */
int verify_signers(const dnac_transaction_t *tx);

/* Build a SPEND TX. All fields chosen so the same fields (inputs,
 * outputs, timestamp, chain_id, signer) remain valid when we later
 * retype it to STAKE - only the type-specific appended section
 * changes. */
static void build_spend_tx(dnac_transaction_t *tx,
                            const uint8_t *signer_pubkey) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_SPEND;
    tx->timestamp = 1744999999ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xD0;

    tx->input_count = 1;
    tx->inputs[0].amount = 2000000000ULL;
    memset(tx->inputs[0].nullifier, 0xE0, DNAC_NULLIFIER_SIZE);

    tx->output_count = 1;
    tx->outputs[0].version = 1;
    memset(tx->outputs[0].owner_fingerprint, 'z', DNAC_FINGERPRINT_SIZE - 1);
    tx->outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx->outputs[0].amount = 2000000000ULL;

    tx->signer_count = 1;
    memcpy(tx->signers[0].pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0, DNAC_SIGNATURE_SIZE);
}

int main(void) {
    printf("test_purpose_tag_reuse: Task 33 / F-CRYPTO-05\n");

    /* 1. Real Dilithium5 keypair. */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t seckey[QGP_DSA87_SECRETKEYBYTES];
    int rc = qgp_dsa87_keypair(pubkey, seckey);
    CHECK(rc == 0);

    /* 2. Build SPEND TX. */
    dnac_transaction_t tx;
    build_spend_tx(&tx, pubkey);

    /* 3. Compute SPEND preimage hash and sign. */
    CHECK_OK(dnac_tx_compute_hash(&tx, tx.tx_hash));

    uint8_t spend_hash[DNAC_TX_HASH_SIZE];
    memcpy(spend_hash, tx.tx_hash, DNAC_TX_HASH_SIZE);

    size_t sig_len = 0;
    int sign_rc = qgp_dsa87_sign(tx.signers[0].signature, &sig_len,
                                   tx.tx_hash, DNAC_TX_HASH_SIZE, seckey);
    CHECK(sign_rc == 0);
    CHECK(sig_len == DNAC_SIGNATURE_SIZE);

    /* Capture the SPEND signature verbatim. */
    uint8_t captured_sig[DNAC_SIGNATURE_SIZE];
    memcpy(captured_sig, tx.signers[0].signature, DNAC_SIGNATURE_SIZE);

    /* 4. Sanity: SPEND signature verifies against SPEND preimage. */
    CHECK_OK(verify_signers(&tx));

    /* 5. Retype to STAKE - attacker claims the SPEND signature also
     *    authorizes a validator self-stake. Populate stake_fields so
     *    the preimage has real content. Keep captured signature. */
    tx.type = DNAC_TX_STAKE;
    tx.stake_fields.commission_bps = 500;   /* 5% */
    memset(tx.stake_fields.unstake_destination_fp, 0x7A,
           DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);
    memcpy(tx.signers[0].signature, captured_sig, DNAC_SIGNATURE_SIZE);

    /* 6. Recompute tx_hash - now includes commission_bps +
     *    unstake_fp + "DNAC_VALIDATOR_v1" purpose_tag. */
    CHECK_OK(dnac_tx_compute_hash(&tx, tx.tx_hash));

    uint8_t stake_hash[DNAC_TX_HASH_SIZE];
    memcpy(stake_hash, tx.tx_hash, DNAC_TX_HASH_SIZE);

    /* 8. The two preimage hashes MUST differ - STAKE appended
     *    commission + unstake_fp + 17-byte purpose_tag to what was
     *    hashed for SPEND. */
    CHECK(memcmp(spend_hash, stake_hash, DNAC_TX_HASH_SIZE) != 0);

    /* 7. Verify: SPEND-bound signature cannot cover STAKE preimage. */
    CHECK_ERR(verify_signers(&tx));

    /* Additional hardening check: if an attacker tries to spoof the
     * STAKE preimage by stuffing signers[0].signature with the SPEND
     * signature but manually copying tx.tx_hash back to the SPEND
     * hash (so Dilithium5 sees a hash its signature covers),
     * verify_signers still passes - but dnac_tx_compute_hash shows
     * the mismatch. In a real ingest path the witness recomputes the
     * hash from the preimage, so this attack is rejected at that
     * recomputation step. We assert the mismatch here to document the
     * defense. */
    memcpy(tx.tx_hash, spend_hash, DNAC_TX_HASH_SIZE);
    /* verify_signers over tx.tx_hash=spend_hash with captured_sig
     * passes trivially - but no honest caller accepts a STAKE TX
     * whose stored tx_hash doesn't match its preimage. */
    CHECK_OK(verify_signers(&tx));

    uint8_t recomputed[DNAC_TX_HASH_SIZE];
    CHECK_OK(dnac_tx_compute_hash(&tx, recomputed));
    CHECK(memcmp(recomputed, tx.tx_hash, DNAC_TX_HASH_SIZE) != 0);

    printf("test_purpose_tag_reuse: ALL CHECKS PASSED\n");
    return 0;
}
