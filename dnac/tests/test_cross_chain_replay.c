/* Verifies Task 32 — F-CRYPTO-10 cross-chain replay defense.
 *
 * A DELEGATE TX signed on chain A (chain_id = 0xAA..AA) MUST NOT
 * verify as a DELEGATE on chain B (chain_id = 0xBB..BB). The defense
 * is design §2.3 / Task 14: chain_id is in the TX preimage
 * (transaction.c:315 feeds tx->chain_id into the SHA3-512 of the
 * tx_hash) so mutating chain_id changes the hash, and the signature
 * bound to the original hash no longer verifies.
 *
 * Test flow:
 *   1. Generate a real Dilithium5 keypair.
 *   2. Build a DELEGATE TX on chain A, fill signers[0].pubkey.
 *   3. Compute tx_hash, sign it — store sig into signers[0].signature.
 *   4. Sanity: verify_signers(&tx) returns DNAC_SUCCESS.
 *   5. Mutate tx.chain_id to chain B; recompute tx_hash.
 *   6. Do NOT re-sign. verify_signers must now fail.
 *
 * The test does NOT exercise the full dnac_tx_verify_full path (that
 * path pulls in witness attestations + balance checks that are not
 * the subject of this test). verify_signers is the narrowest,
 * highest-signal primitive for this specific defense.
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

/* verify_signers lives in dnac/src/transaction/verify.c without a
 * public header declaration. Declared here locally so the test can
 * call it directly. */
int verify_signers(const dnac_transaction_t *tx);

/* Build a minimal DELEGATE TX that satisfies structure (not the
 * business rules — we don't call dnac_tx_verify_delegate_rules here).
 * All we need is a fully-populated tx suitable for tx_hash + sign. */
static void build_delegate_tx(dnac_transaction_t *tx,
                               const uint8_t *signer_pubkey,
                               const uint8_t chain_id_byte) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_DELEGATE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = chain_id_byte;

    /* validator_pubkey: distinct from signer. Just use a pattern. */
    memset(tx->delegate_fields.validator_pubkey, 0xBB, DNAC_PUBKEY_SIZE);

    /* 1 native DNAC input (nullifier/amount/token_id). */
    tx->input_count = 1;
    tx->inputs[0].amount = 1000000000ULL;
    memset(tx->inputs[0].nullifier, 0xCC, DNAC_NULLIFIER_SIZE);

    /* 1 native DNAC output (change). */
    tx->output_count = 1;
    tx->outputs[0].version = 1;
    memset(tx->outputs[0].owner_fingerprint, 'x', DNAC_FINGERPRINT_SIZE - 1);
    tx->outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx->outputs[0].amount = 100000000ULL;

    /* Populate signer[0].pubkey — needed BEFORE tx_hash because the
     * compute_hash binding includes signer pubkeys. */
    tx->signer_count = 1;
    memcpy(tx->signers[0].pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0, DNAC_SIGNATURE_SIZE);
}

int main(void) {
    printf("test_cross_chain_replay: Task 32 / F-CRYPTO-10\n");

    /* 1. Real Dilithium5 keypair. */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    uint8_t seckey[QGP_DSA87_SECRETKEYBYTES];
    int rc = qgp_dsa87_keypair(pubkey, seckey);
    CHECK(rc == 0);

    /* 2. Build DELEGATE TX on chain A (all 0xAA). */
    dnac_transaction_t tx;
    build_delegate_tx(&tx, pubkey, 0xAA);

    /* 3. Compute tx_hash (binds chain_id via preimage, transaction.c:315). */
    CHECK_OK(dnac_tx_compute_hash(&tx, tx.tx_hash));

    /* Record the chain-A hash for assertion later. */
    uint8_t chain_a_hash[DNAC_TX_HASH_SIZE];
    memcpy(chain_a_hash, tx.tx_hash, DNAC_TX_HASH_SIZE);

    /* 4. Sign the hash with Dilithium5. */
    size_t sig_len = 0;
    int sign_rc = qgp_dsa87_sign(tx.signers[0].signature, &sig_len,
                                   tx.tx_hash, DNAC_TX_HASH_SIZE, seckey);
    CHECK(sign_rc == 0);
    CHECK(sig_len == DNAC_SIGNATURE_SIZE);

    /* 5. Sanity: signature valid against the chain-A preimage. */
    CHECK_OK(verify_signers(&tx));

    /* 6. Mutate chain_id to chain B (all 0xBB) — attacker replay attempt.
     *    The captured signature is unchanged; only chain_id is swapped. */
    for (int i = 0; i < 32; i++) tx.chain_id[i] = 0xBB;

    /* Recompute tx_hash on the mutated TX. chain_id is part of the
     * preimage, so the new hash MUST differ from chain_a_hash. */
    CHECK_OK(dnac_tx_compute_hash(&tx, tx.tx_hash));

    uint8_t chain_b_hash[DNAC_TX_HASH_SIZE];
    memcpy(chain_b_hash, tx.tx_hash, DNAC_TX_HASH_SIZE);
    CHECK(memcmp(chain_a_hash, chain_b_hash, DNAC_TX_HASH_SIZE) != 0);

    /* 7. Verify: the chain-A signature cannot match the chain-B hash. */
    CHECK_ERR(verify_signers(&tx));

    /* 8. Belt-and-braces: do the same check but keep the tx_hash field
     *    stale (= chain_a_hash) while chain_id says chain B. This models
     *    an attacker who forgot to recompute the hash. verify_signers
     *    only checks signature vs tx.tx_hash vs tx.signers[i].pubkey —
     *    in this case the signature IS against chain_a_hash, which
     *    still lives in tx.tx_hash, so the signature would verify
     *    mathematically. But any honest caller would recompute the
     *    hash from the preimage first and catch the mismatch. We
     *    demonstrate that — the recomputed hash differs from the
     *    stale tx.tx_hash. */
    memcpy(tx.tx_hash, chain_a_hash, DNAC_TX_HASH_SIZE);
    uint8_t recomputed[DNAC_TX_HASH_SIZE];
    CHECK_OK(dnac_tx_compute_hash(&tx, recomputed));
    CHECK(memcmp(recomputed, tx.tx_hash, DNAC_TX_HASH_SIZE) != 0);

    printf("test_cross_chain_replay: ALL CHECKS PASSED\n");
    return 0;
}
