/* Verifies Task 25 — UNDELEGATE TX verify rules (local subset).
 *
 * Local rules covered here (client-side, no DB access):
 *   - signer_count == 1
 *   - undelegate_fields.amount > 0
 *
 * Rule O (hold duration current_block − delegated_at_block >=
 * EPOCH_LENGTH), delegation-existence and amount-cap checks require
 * witness-side DB access — deferred to Phase 8 Task 43.
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

static void build_valid_undelegate(dnac_transaction_t *tx, uint64_t amount) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_UNDELEGATE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    memset(tx->undelegate_fields.validator_pubkey, 0xBB, DNAC_PUBKEY_SIZE);
    tx->undelegate_fields.amount = amount;
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Valid baseline: amount > 0, signer_count == 1 */
    build_valid_undelegate(&tx, 500ULL * 100000000ULL);  /* 500 DNAC */
    CHECK_OK(dnac_tx_verify_undelegate_rules(&tx));

    /* 1b. Valid: minimum nonzero amount (1 raw unit) */
    build_valid_undelegate(&tx, 1ULL);
    CHECK_OK(dnac_tx_verify_undelegate_rules(&tx));

    /* 1c. Valid: max uint64 amount (rule O / cap are witness-side) */
    build_valid_undelegate(&tx, UINT64_MAX);
    CHECK_OK(dnac_tx_verify_undelegate_rules(&tx));

    /* 2. amount == 0 → reject */
    build_valid_undelegate(&tx, 0ULL);
    CHECK_ERR(dnac_tx_verify_undelegate_rules(&tx));

    /* 3. signer_count != 1 → reject */
    build_valid_undelegate(&tx, 100ULL * 100000000ULL);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_undelegate_rules(&tx));

    build_valid_undelegate(&tx, 100ULL * 100000000ULL);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_undelegate_rules(&tx));

    /* 4. Non-UNDELEGATE TX routed to helper → INVALID_TX_TYPE */
    build_valid_undelegate(&tx, 100ULL * 100000000ULL);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_undelegate_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    build_valid_undelegate(&tx, 100ULL * 100000000ULL);
    tx.type = DNAC_TX_DELEGATE;
    CHECK(dnac_tx_verify_undelegate_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 5. NULL tx → reject */
    CHECK(dnac_tx_verify_undelegate_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_undelegate_verify: ALL CHECKS PASSED\n");
    return 0;
}
