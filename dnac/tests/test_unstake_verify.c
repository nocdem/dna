/* Verifies Task 24 — UNSTAKE TX verify rules (local subset).
 *
 * UNSTAKE has no appended fields, no amount fields, no commission.
 * The single locally-verifiable rule is signer_count == 1; everything
 * substantive (Rule A drain-before-exit, validator status gate, fee)
 * runs witness-side at state-apply time (Phase 8 Task 42).
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

static void build_valid_unstake(dnac_transaction_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_UNSTAKE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);
    /* No appended fields, no inputs/outputs required for local verify */
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Valid baseline: signer_count == 1 */
    build_valid_unstake(&tx);
    CHECK_OK(dnac_tx_verify_unstake_rules(&tx));

    /* 2. signer_count == 0 → reject */
    build_valid_unstake(&tx);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_unstake_rules(&tx));

    /* 3. signer_count > 1 → reject */
    build_valid_unstake(&tx);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_unstake_rules(&tx));

    build_valid_unstake(&tx);
    tx.signer_count = 4;
    CHECK_ERR(dnac_tx_verify_unstake_rules(&tx));

    /* 4. Non-UNSTAKE TX routed to helper → INVALID_TX_TYPE */
    build_valid_unstake(&tx);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_unstake_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    build_valid_unstake(&tx);
    tx.type = DNAC_TX_STAKE;
    CHECK(dnac_tx_verify_unstake_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 5. NULL tx → reject */
    CHECK(dnac_tx_verify_unstake_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_unstake_verify: ALL CHECKS PASSED\n");
    return 0;
}
