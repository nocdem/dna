/**
 * @file test_genesis_verify_rule_p_extended.c
 * @brief Phase 12 Task 56 — full Rule P (has_chain_def path).
 *
 * Rule P per design §5.2 F-STATE-04:
 *   (1) chain_def.initial_validator_count == 7
 *   (2) Σ outputs + 7 × DNAC_SELF_STAKE_AMOUNT == DNAC_DEFAULT_TOTAL_SUPPLY
 *   (3) initial_validators[i].pubkey pairwise distinct
 *
 * Exercises dnac_tx_verify_genesis_rules with has_chain_def=true. The legacy
 * path is covered by test_genesis_verify_rule_p.c.
 */

#include "dnac/transaction.h"
#include "dnac/dnac.h"
#include "dnac/block.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_OK(expr) do { \
    int _rc = (expr); \
    if (_rc != DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_OK fail at %s:%d: %s -> %d\n", \
            __FILE__, __LINE__, #expr, _rc); exit(1); } } while(0)

#define CHECK_ERR(expr) do { \
    int _rc = (expr); \
    if (_rc == DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_ERR fail at %s:%d: %s returned DNAC_SUCCESS\n", \
            __FILE__, __LINE__, #expr); exit(1); } } while(0)

/* Populate a valid post-Task-56 genesis TX:
 *   - has_chain_def = true
 *   - 7 distinct initial_validators
 *   - outputs sum to DNAC_DEFAULT_TOTAL_SUPPLY − 7 × DNAC_SELF_STAKE_AMOUNT. */
static void build_valid_genesis(dnac_transaction_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_GENESIS;
    tx->timestamp = 1744820000ULL;
    tx->input_count = 0;

    /* chain_def trailer with 7 distinct pubkeys. */
    tx->has_chain_def = true;
    tx->chain_def.initial_validator_count = DNAC_COMMITTEE_SIZE;
    for (int i = 0; i < DNAC_COMMITTEE_SIZE; i++) {
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
            tx->chain_def.initial_validators[i].pubkey[b] =
                (uint8_t)((b + 31 * (i + 1)) & 0xff);
        }
        tx->chain_def.initial_validators[i].commission_bps = (uint16_t)(i * 100);
    }

    /* Outputs: sum = total − 7 × 10M. Split across 7 outputs. */
    uint64_t total_locked = DNAC_SELF_STAKE_AMOUNT * (uint64_t)DNAC_COMMITTEE_SIZE;
    uint64_t outs_sum = DNAC_DEFAULT_TOTAL_SUPPLY - total_locked;
    uint64_t per = outs_sum / 7ULL;
    uint64_t running = 0;
    for (int i = 0; i < 7; i++) {
        tx->outputs[i].version = 1;
        memset(tx->outputs[i].owner_fingerprint, 'a' + (char)i,
               DNAC_FINGERPRINT_SIZE - 1);
        tx->outputs[i].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
        uint64_t amt = (i == 6) ? (outs_sum - running) : per;
        tx->outputs[i].amount = amt;
        running += amt;
        /* token_id zeros = native DNAC. */
    }
    tx->output_count = 7;
}

int main(void) {
    dnac_transaction_t tx;

    /* 1. Valid post-Task-56 genesis → PASS. */
    build_valid_genesis(&tx);
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    /* 2. initial_validator_count != 7 → Rule P.1 reject. */
    build_valid_genesis(&tx);
    tx.chain_def.initial_validator_count = 6;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    build_valid_genesis(&tx);
    tx.chain_def.initial_validator_count = 0;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 3. Duplicate pubkeys (i=0 == i=5) → Rule P.3 reject. */
    build_valid_genesis(&tx);
    memcpy(tx.chain_def.initial_validators[5].pubkey,
           tx.chain_def.initial_validators[0].pubkey,
           DNAC_PUBKEY_SIZE);
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 4. Output sum off by +1 → Rule P.2 reject. */
    build_valid_genesis(&tx);
    tx.outputs[3].amount += 1ULL;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 5. Output sum off by -1 → Rule P.2 reject. */
    build_valid_genesis(&tx);
    tx.outputs[3].amount -= 1ULL;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 6. Input present → reject (genesis creates coins only). */
    build_valid_genesis(&tx);
    tx.input_count = 1;
    memset(tx.inputs[0].nullifier, 0xCC, DNAC_NULLIFIER_SIZE);
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 7. Legacy path preserved: has_chain_def=false + outputs==total → PASS. */
    memset(&tx, 0, sizeof(tx));
    tx.version = 1;
    tx.type = DNAC_TX_GENESIS;
    tx.input_count = 0;
    tx.has_chain_def = false;
    tx.output_count = 1;
    tx.outputs[0].version = 1;
    memset(tx.outputs[0].owner_fingerprint, 'x', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[0].amount = DNAC_DEFAULT_TOTAL_SUPPLY;
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    printf("test_genesis_verify_rule_p_extended: ALL CHECKS PASSED\n");
    return 0;
}
