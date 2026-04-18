/* Verifies Task 27 — VALIDATOR_UPDATE TX verify rules (local subset).
 *
 * Local rules covered here (client-side, no DB access):
 *   - signer_count == 1
 *   - new_commission_bps <= DNAC_COMMISSION_BPS_MAX (10000)
 *   - signed_at_block > 0
 *
 * Rule K (freshness current_block − signed_at_block < 32), validator
 * status, cooldown, and pending-commission logic are witness-side —
 * deferred to Phase 8 Task 45.
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

static void build_valid_update(dnac_transaction_t *tx,
                               uint16_t commission_bps,
                               uint64_t signed_at_block) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_VALIDATOR_UPDATE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    tx->validator_update_fields.new_commission_bps = commission_bps;
    tx->validator_update_fields.signed_at_block = signed_at_block;
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Valid baseline: commission 500 (5%), signed_at=10000 */
    build_valid_update(&tx, 500, 10000ULL);
    CHECK_OK(dnac_tx_verify_validator_update_rules(&tx));

    /* 2. Commission boundaries */
    /* 2a. commission == 0 → accept */
    build_valid_update(&tx, 0, 10000ULL);
    CHECK_OK(dnac_tx_verify_validator_update_rules(&tx));

    /* 2b. commission == 10000 (100%, boundary) → accept */
    build_valid_update(&tx, 10000, 10000ULL);
    CHECK_OK(dnac_tx_verify_validator_update_rules(&tx));

    /* 2c. commission == 10001 → reject */
    build_valid_update(&tx, 10001, 10000ULL);
    CHECK_ERR(dnac_tx_verify_validator_update_rules(&tx));

    /* 2d. commission == UINT16_MAX → reject */
    build_valid_update(&tx, 65535, 10000ULL);
    CHECK_ERR(dnac_tx_verify_validator_update_rules(&tx));

    /* 3. signed_at_block == 0 → reject */
    build_valid_update(&tx, 500, 0ULL);
    CHECK_ERR(dnac_tx_verify_validator_update_rules(&tx));

    /* 3b. signed_at_block == 1 (boundary nonzero) → accept */
    build_valid_update(&tx, 500, 1ULL);
    CHECK_OK(dnac_tx_verify_validator_update_rules(&tx));

    /* 4. signer_count != 1 → reject */
    build_valid_update(&tx, 500, 10000ULL);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_validator_update_rules(&tx));

    build_valid_update(&tx, 500, 10000ULL);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_validator_update_rules(&tx));

    /* 5. Wrong tx_type → INVALID_TX_TYPE */
    build_valid_update(&tx, 500, 10000ULL);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_validator_update_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    build_valid_update(&tx, 500, 10000ULL);
    tx.type = DNAC_TX_STAKE;
    CHECK(dnac_tx_verify_validator_update_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 6. NULL tx → reject */
    CHECK(dnac_tx_verify_validator_update_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_validator_update_verify: ALL CHECKS PASSED\n");
    return 0;
}
