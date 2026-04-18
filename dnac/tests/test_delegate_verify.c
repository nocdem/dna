/* Verifies Task 23 — DELEGATE TX verify rules (local subset).
 *
 * Rules covered here (client-side, no DB access):
 *   - signer_count == 1
 *   - signer[0].pubkey != validator_pubkey (Rule S)
 *   - Σ DNAC inputs − Σ DNAC outputs >= DNAC_MIN_DELEGATION (Rule J)
 *
 * Rules B (validator ACTIVE in validator_tree) and G (<64 delegations
 * per delegator) are witness-side — deferred to Phase 8 Task 41.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_OK(expr) do { \
    int _rc = (expr); \
    if (_rc != DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_OK fail at %s:%d: %s -> %d (expected DNAC_SUCCESS)\n", \
            __FILE__, __LINE__, #expr, _rc); exit(1); } } while(0)

#define CHECK_ERR(expr) do { \
    int _rc = (expr); \
    if (_rc == DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_ERR fail at %s:%d: %s returned DNAC_SUCCESS (expected error)\n", \
            __FILE__, __LINE__, #expr); exit(1); } } while(0)

/* Build a minimally-valid DELEGATE TX:
 *   - signer_count = 1 with pubkey = 0xAA...
 *   - validator_pubkey = 0xBB... (distinct from signer to pass Rule S)
 *   - 1 native DNAC input of (net_delegation_amount + fee_slack)
 *   - 1 native DNAC output of fee_slack
 *   (so Σin − Σout = net_delegation_amount)
 *
 * `fee_slack` is a small positive amount representing the change
 * returned after delegation + fee; keeping it nonzero exercises the
 * output-branch of the accounting loop. */
static void build_valid_delegate(dnac_transaction_t *tx, uint64_t net_delegation_amount) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_DELEGATE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    /* validator_pubkey distinct from signer pubkey → Rule S passes */
    memset(tx->delegate_fields.validator_pubkey, 0xBB, DNAC_PUBKEY_SIZE);

    const uint64_t fee_slack = 1000ULL;
    tx->input_count = 1;
    tx->inputs[0].amount = net_delegation_amount + fee_slack;
    memset(tx->inputs[0].nullifier, 0xCC, DNAC_NULLIFIER_SIZE);
    /* token_id already zeros = native DNAC */

    tx->output_count = 1;
    tx->outputs[0].version = 1;
    memset(tx->outputs[0].owner_fingerprint, 'x', DNAC_FINGERPRINT_SIZE - 1);
    tx->outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx->outputs[0].amount = fee_slack;
    /* token_id already zeros = native DNAC */
}

int main(void) {
    dnac_transaction_t tx;
    const uint64_t min = DNAC_MIN_DELEGATION;

    /* ──────────────────────────────────────────────────────────────
     * 1. Valid baseline: net delegation = 100 DNAC (boundary).
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min);
    CHECK_OK(dnac_tx_verify_delegate_rules(&tx));

    /* 1b. Valid: delegation > 100 DNAC. */
    build_valid_delegate(&tx, min + 1000000000ULL);  /* +10 DNAC */
    CHECK_OK(dnac_tx_verify_delegate_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 2. Rule J: net < 100 DNAC → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min - 1ULL);
    CHECK_ERR(dnac_tx_verify_delegate_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 3. Rule S: signer == validator → reject self-delegation.
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min);
    memset(tx.delegate_fields.validator_pubkey, 0xAA, DNAC_PUBKEY_SIZE);  /* match signer */
    CHECK_ERR(dnac_tx_verify_delegate_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 4. signer_count != 1 → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_delegate_rules(&tx));

    build_valid_delegate(&tx, min);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_delegate_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 5. Non-DNAC tokens don't count toward delegation. Put a huge
     *    non-native input alongside an insufficient native one → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min - 1ULL);
    tx.input_count = 2;
    tx.inputs[1].amount = 999999999999ULL;
    memset(tx.inputs[1].nullifier, 0xDD, DNAC_NULLIFIER_SIZE);
    memset(tx.inputs[1].token_id,  0xEE, DNAC_TOKEN_ID_SIZE);  /* non-native */
    CHECK_ERR(dnac_tx_verify_delegate_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 6. Non-DELEGATE TX routed to the helper returns INVALID_TX_TYPE.
     * ────────────────────────────────────────────────────────────── */
    build_valid_delegate(&tx, min);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_delegate_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 7. NULL tx → reject. */
    CHECK(dnac_tx_verify_delegate_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_delegate_verify: ALL CHECKS PASSED\n");
    return 0;
}
