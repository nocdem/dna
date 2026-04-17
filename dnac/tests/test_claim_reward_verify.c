/* Verifies Task 26 — CLAIM_REWARD TX verify rules (local subset).
 *
 * Local rules covered here (client-side, no DB access):
 *   - signer_count == 1
 *   - claim_reward_fields.max_pending_amount > 0
 *   - claim_reward_fields.valid_before_block > 0
 *
 * Rules requiring chain state (freshness current_block <=
 * valid_before_block, pending-reward computation, cap check, Rule L
 * dynamic dust threshold) are witness-side — deferred to Phase 8
 * Task 44.
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

static void build_valid_claim(dnac_transaction_t *tx,
                              uint64_t max_pending,
                              uint64_t valid_before) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_CLAIM_REWARD;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    memset(tx->claim_reward_fields.target_validator, 0xBB, DNAC_PUBKEY_SIZE);
    tx->claim_reward_fields.max_pending_amount = max_pending;
    tx->claim_reward_fields.valid_before_block = valid_before;
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Valid baseline: cap=500 DNAC, expiry=block 100000 */
    build_valid_claim(&tx, 500ULL * 100000000ULL, 100000ULL);
    CHECK_OK(dnac_tx_verify_claim_reward_rules(&tx));

    /* 1b. Valid: both fields at 1 (minimum nonzero) */
    build_valid_claim(&tx, 1ULL, 1ULL);
    CHECK_OK(dnac_tx_verify_claim_reward_rules(&tx));

    /* 1c. Valid: UINT64_MAX (witness-side cap check handles semantics) */
    build_valid_claim(&tx, UINT64_MAX, UINT64_MAX);
    CHECK_OK(dnac_tx_verify_claim_reward_rules(&tx));

    /* 2. max_pending_amount == 0 → reject */
    build_valid_claim(&tx, 0ULL, 100000ULL);
    CHECK_ERR(dnac_tx_verify_claim_reward_rules(&tx));

    /* 3. valid_before_block == 0 → reject */
    build_valid_claim(&tx, 500ULL * 100000000ULL, 0ULL);
    CHECK_ERR(dnac_tx_verify_claim_reward_rules(&tx));

    /* 4. Both zero → reject (first rule hit wins) */
    build_valid_claim(&tx, 0ULL, 0ULL);
    CHECK_ERR(dnac_tx_verify_claim_reward_rules(&tx));

    /* 5. signer_count != 1 → reject */
    build_valid_claim(&tx, 500ULL * 100000000ULL, 100000ULL);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_claim_reward_rules(&tx));

    build_valid_claim(&tx, 500ULL * 100000000ULL, 100000ULL);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_claim_reward_rules(&tx));

    /* 6. Wrong tx_type → INVALID_TX_TYPE */
    build_valid_claim(&tx, 500ULL * 100000000ULL, 100000ULL);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_claim_reward_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    build_valid_claim(&tx, 500ULL * 100000000ULL, 100000ULL);
    tx.type = DNAC_TX_DELEGATE;
    CHECK(dnac_tx_verify_claim_reward_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 7. NULL tx → reject */
    CHECK(dnac_tx_verify_claim_reward_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_claim_reward_verify: ALL CHECKS PASSED\n");
    return 0;
}
