/* Verifies Task 28 — GENESIS TX verify rules (Rule P, design §5.2 F-STATE-04).
 *
 * Rule P per design §5.2:
 *   (1) chain_def.initial_validator_count == 7
 *   (2) Σ outputs.amount + Σ initial_validators[i].self_stake == DNAC_TOTAL_SUPPLY
 *   (3) all 7 initial_validators[i].pubkey pairwise distinct
 *
 * Scope today: dnac_chain_definition_t has no initial_validators[] yet —
 * that field ships in Task 56 (Phase 12). Until then we enforce the
 * pre-stake supply invariant: Σ DNAC outputs == DNAC_DEFAULT_TOTAL_SUPPLY.
 *
 * The test exercises the rule layer directly via
 * dnac_tx_verify_genesis_rules() so we don't need real Dilithium5 signer
 * sigs or witness attestations just to validate the rule code.
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

/* Build a genesis TX with N native DNAC outputs summing to `total`.
 *
 * Output amount distribution:
 *   - The first n-1 outputs get total / n
 *   - The last output absorbs the remainder so the sum is exact
 * Caller can tweak outputs[i].amount / token_id afterward to test cases.
 */
static void build_genesis_tx(dnac_transaction_t *tx,
                              uint64_t total,
                              int n_outputs) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_GENESIS;
    tx->timestamp = 1744812345ULL;
    tx->input_count = 0;

    if (n_outputs <= 0) {
        tx->output_count = 0;
        return;
    }
    if (n_outputs > DNAC_TX_MAX_OUTPUTS) n_outputs = DNAC_TX_MAX_OUTPUTS;

    uint64_t per = total / (uint64_t)n_outputs;
    uint64_t sum = 0;
    for (int i = 0; i < n_outputs; i++) {
        tx->outputs[i].version = 1;
        memset(tx->outputs[i].owner_fingerprint, 'a' + (char)i,
               DNAC_FINGERPRINT_SIZE - 1);
        tx->outputs[i].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
        uint64_t amt = (i == n_outputs - 1) ? (total - sum) : per;
        tx->outputs[i].amount = amt;
        sum += amt;
        /* token_id already zero = native DNAC */
    }
    tx->output_count = n_outputs;
}

int main(void) {
    dnac_transaction_t tx;
    const uint64_t total = DNAC_DEFAULT_TOTAL_SUPPLY;

    /* ──────────────────────────────────────────────────────────────
     * 1. Valid genesis: sum of native outputs == DNAC_DEFAULT_TOTAL_SUPPLY.
     *    Must PASS.
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, total, 7);
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    /* 1b. Single-output genesis with full supply → PASS. */
    build_genesis_tx(&tx, total, 1);
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    /* 1c. Many outputs (spread the supply across 16) → PASS. */
    build_genesis_tx(&tx, total, DNAC_TX_MAX_OUTPUTS);
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 2. Wrong sum: outputs sum < DNAC_DEFAULT_TOTAL_SUPPLY → reject.
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, total, 7);
    /* Subtract 1 from the last output → sum is total-1 */
    tx.outputs[6].amount -= 1ULL;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 2b. outputs sum > DNAC_DEFAULT_TOTAL_SUPPLY → reject. */
    build_genesis_tx(&tx, total, 7);
    tx.outputs[6].amount += 1ULL;
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 2c. Zero outputs → sum == 0 != DNAC_DEFAULT_TOTAL_SUPPLY → reject. */
    build_genesis_tx(&tx, 0, 0);
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 3. Non-native token outputs DO NOT count toward supply invariant.
     *
     *    Seed a valid native-sum (7 × native outputs summing to total),
     *    then flip output[3].token_id to a foreign token: that output is
     *    removed from the accounting → native sum drops → reject.
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, total, 7);
    memset(tx.outputs[3].token_id, 0xFE, DNAC_TOKEN_ID_SIZE);  /* non-native */
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* 3b. Counter-positive: native 7-output sum == total PLUS an extra
     *     foreign-token output → native-only accounting still balances. */
    build_genesis_tx(&tx, total, 7);
    tx.output_count = 8;
    tx.outputs[7].version = 1;
    memset(tx.outputs[7].owner_fingerprint, 'z', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[7].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[7].amount = 999999999ULL;
    memset(tx.outputs[7].token_id, 0xFE, DNAC_TOKEN_ID_SIZE);  /* non-native */
    CHECK_OK(dnac_tx_verify_genesis_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 4. Overflow attempt — outputs individually huge but summing to
     *    exact total should STILL pass (no overflow because intermediate
     *    partial sums ≤ total).
     *
     *    A wrap overflow attempt: two outputs at UINT64_MAX/2 and
     *    UINT64_MAX/2 + 2 would wrap to 1 if unchecked → safe_add_u64
     *    must detect.
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, 0, 0);
    tx.output_count = 2;
    tx.outputs[0].version = 1;
    memset(tx.outputs[0].owner_fingerprint, 'a', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[0].amount = (uint64_t)(UINT64_MAX / 2ULL);
    tx.outputs[1].version = 1;
    memset(tx.outputs[1].owner_fingerprint, 'b', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[1].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[1].amount = (uint64_t)(UINT64_MAX / 2ULL) + 2ULL;
    /* Both native. Sum would overflow → verify must return ERROR_OVERFLOW. */
    int rc_overflow = dnac_tx_verify_genesis_rules(&tx);
    CHECK(rc_overflow == DNAC_ERROR_OVERFLOW);

    /* ──────────────────────────────────────────────────────────────
     * 5. input_count != 0 → reject (genesis creates coins, never spends).
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, total, 7);
    tx.input_count = 1;  /* forbid any input */
    memset(tx.inputs[0].nullifier, 0xCC, DNAC_NULLIFIER_SIZE);
    CHECK_ERR(dnac_tx_verify_genesis_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 6. Non-GENESIS TX routed to the helper returns INVALID_TX_TYPE.
     * ────────────────────────────────────────────────────────────── */
    build_genesis_tx(&tx, total, 7);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_genesis_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* ──────────────────────────────────────────────────────────────
     * 7. NULL tx → reject.
     * ────────────────────────────────────────────────────────────── */
    CHECK(dnac_tx_verify_genesis_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_genesis_verify_rule_p: ALL CHECKS PASSED\n");
    return 0;
}
