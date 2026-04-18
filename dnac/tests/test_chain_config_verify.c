/* Hard-Fork v1 — CHAIN_CONFIG TX verify-rule tests (design §6.3).
 *
 * Local rules covered (client-side, no DB):
 *   - signer_count == 1
 *   - param_id in {1..DNAC_CFG_PARAM_MAX_ID}
 *   - new_value in per-param range
 *   - signed_at_block > 0
 *   - valid_before_block > effective_block_height
 *   - valid_before_block > signed_at_block
 *   - committee_sig_count in [5, 7]
 *   - committee_votes[].witness_id pairwise distinct
 *
 * Witness-side rules (committee membership, sig verify against pubkeys,
 * epoch grace, freshness, monotonicity, exclusive block) are Stage B and
 * NOT exercised here.
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
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

static void build_valid_chain_config(dnac_transaction_t *tx,
                                      uint8_t param_id,
                                      uint64_t new_value) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_CHAIN_CONFIG;
    tx->timestamp = 1745000000ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
    cc->param_id               = param_id;
    cc->new_value              = new_value;
    cc->effective_block_height = 5000ULL;
    cc->proposal_nonce         = 0xDEADBEEFCAFEBABEULL;
    cc->signed_at_block        = 4800ULL;
    cc->valid_before_block     = 5100ULL;
    cc->committee_sig_count    = 5;
    for (int i = 0; i < 5; i++) {
        /* Distinct witness_ids per slot. */
        memset(cc->committee_votes[i].witness_id, 0x10 + i, 32);
        memset(cc->committee_votes[i].signature, 0x80 + i, DNAC_SIGNATURE_SIZE);
    }
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Baseline: valid MAX_TXS_PER_BLOCK proposal, 5 sigs. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));

    /* 2. Wrong tx_type → INVALID_TX_TYPE. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_chain_config_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* 3. NULL tx → INVALID_PARAM. */
    CHECK(dnac_tx_verify_chain_config_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    /* 4. signer_count != 1. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 5. param_id bounds — 0 and >MAX_ID rejected, all three defined IDs accepted. */
    build_valid_chain_config(&tx, 0, 5);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_PARAM_MAX_ID + 1, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    /* All 3 defined IDs with valid values. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 1);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 5);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK, 12345);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));

    /* 6. MAX_TXS_PER_BLOCK range [1, 10]. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 1);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, DNAC_CFG_MAX_TXS_HARD_CAP);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, DNAC_CFG_MAX_TXS_HARD_CAP + 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 7. BLOCK_INTERVAL_SEC range [1, 15]. Default Q6 tightened from 60. */
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 0);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 1);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 15);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 16);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_BLOCK_INTERVAL_SEC, 60);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 8. INFLATION_START_BLOCK upper bound 2^48. */
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK, 0);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));  /* 0 allowed at client layer */
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK,
                             DNAC_CFG_MAX_INFLATION_START_BLOCK);
    CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_INFLATION_START_BLOCK,
                             DNAC_CFG_MAX_INFLATION_START_BLOCK + 1);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 9. signed_at_block == 0 rejected (CC-AUDIT-008). */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.chain_config_fields.signed_at_block = 0;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 10. valid_before <= effective rejected. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.chain_config_fields.valid_before_block = tx.chain_config_fields.effective_block_height;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.chain_config_fields.valid_before_block =
        tx.chain_config_fields.effective_block_height - 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 11. valid_before <= signed_at rejected. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.chain_config_fields.signed_at_block = tx.chain_config_fields.valid_before_block + 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 12. committee_sig_count boundaries. */
    for (uint8_t n = 0; n < DNAC_CHAIN_CONFIG_MIN_SIGS; n++) {
        build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
        tx.chain_config_fields.committee_sig_count = n;
        CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));
    }
    /* Accepted: 5, 6, 7. */
    for (uint8_t n = DNAC_CHAIN_CONFIG_MIN_SIGS; n <= DNAC_CHAIN_CONFIG_MAX_SIGS; n++) {
        build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
        tx.chain_config_fields.committee_sig_count = n;
        /* Extend distinct witness_ids up to n. */
        for (uint8_t i = 0; i < n; i++) {
            memset(tx.chain_config_fields.committee_votes[i].witness_id, 0x10 + i, 32);
        }
        CHECK_OK(dnac_tx_verify_chain_config_rules(&tx));
    }
    /* n > 7 rejected. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    tx.chain_config_fields.committee_sig_count = DNAC_CHAIN_CONFIG_MAX_SIGS + 1;
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    /* 13. Duplicate witness_ids rejected. */
    build_valid_chain_config(&tx, DNAC_CFG_MAX_TXS_PER_BLOCK, 5);
    /* Make votes[0] and votes[3] collide. */
    memcpy(tx.chain_config_fields.committee_votes[3].witness_id,
           tx.chain_config_fields.committee_votes[0].witness_id, 32);
    CHECK_ERR(dnac_tx_verify_chain_config_rules(&tx));

    printf("test_chain_config_verify: ALL CHECKS PASSED\n");
    return 0;
}
