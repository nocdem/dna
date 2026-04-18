/* Verifies Task 22 — STAKE TX verify rules (local subset).
 *
 * Rules covered here (client-side, no DB access):
 *   - signer_count == 1
 *   - commission_bps <= 10000
 *   - Σ DNAC input >= 10M + Σ DNAC output
 *
 * Rules I (pubkey NOT in validator_tree) and M (|validator_tree| < 128)
 * are witness-side — deferred to Phase 8 Task 40.
 *
 * The test exercises the rule layer directly via
 * dnac_tx_verify_stake_rules() so we don't need real Dilithium5 signer
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

/* Build a minimally-valid STAKE TX skeleton.
 *
 * - signer_count = 1 (required)
 * - commission_bps = 500 (valid)
 * - One native DNAC input with `input_amount`
 * - Zero outputs (so the balance rule reduces to input_amount >= 10M)
 *
 * The caller can mutate any single field to exercise a specific rule. */
static void build_valid_stake_tx(dnac_transaction_t *tx, uint64_t input_amount) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_STAKE;
    tx->timestamp = 1744812345ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    memset(tx->signers[0].pubkey,    0xAA, DNAC_PUBKEY_SIZE);
    memset(tx->signers[0].signature, 0xBB, DNAC_SIGNATURE_SIZE);

    tx->stake_fields.commission_bps = 500;  /* 5% */
    memset(tx->stake_fields.unstake_destination_fp, 0x11,
           DNAC_STAKE_UNSTAKE_DEST_FP_SIZE);

    tx->input_count = 1;
    tx->inputs[0].amount = input_amount;
    memset(tx->inputs[0].nullifier, 0xCC, DNAC_NULLIFIER_SIZE);
    /* token_id = zeros (calloc-equivalent via memset above) = native DNAC */
}

int main(void) {
    dnac_transaction_t tx;
    const uint64_t ten_m_raw = DNAC_SELF_STAKE_AMOUNT;
    const uint64_t ten_dnac  = 10ULL * 100000000ULL;

    /* ──────────────────────────────────────────────────────────────
     * 1. Valid baseline: inputs = 10M + 10 DNAC (10 DNAC is implicit fee
     *    since output_count=0). Must PASS.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    CHECK_OK(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 2. Commission > 10000 → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.stake_fields.commission_bps = 10001;
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    /* 2b. Commission = 10000 (boundary) → accept. */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.stake_fields.commission_bps = 10000;
    CHECK_OK(dnac_tx_verify_stake_rules(&tx));

    /* 2c. Commission = 0 (boundary) → accept. */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.stake_fields.commission_bps = 0;
    CHECK_OK(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 3. signer_count != 1 → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.signer_count = 0;
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.signer_count = 2;
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 4. inputs < 10M → reject.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw - 1ULL);
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    /* 4b. inputs = 10M exactly, zero output, zero fee → accept (boundary). */
    build_valid_stake_tx(&tx, ten_m_raw);
    CHECK_OK(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 5. inputs − outputs < 10M → reject.
     *    inputs = 10M + 10 DNAC, outputs = 5M+10 DNAC → diff = 5M < 10M.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.output_count = 1;
    tx.outputs[0].version = 1;
    memset(tx.outputs[0].owner_fingerprint, 'x', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[0].amount = (ten_m_raw / 2ULL) + ten_dnac;  /* leaves only 5M for stake */
    /* token_id already zeros = native DNAC */
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    /* 5b. inputs − outputs == 10M (zero fee) → accept (boundary). */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.output_count = 1;
    tx.outputs[0].version = 1;
    memset(tx.outputs[0].owner_fingerprint, 'x', DNAC_FINGERPRINT_SIZE - 1);
    tx.outputs[0].owner_fingerprint[DNAC_FINGERPRINT_SIZE - 1] = '\0';
    tx.outputs[0].amount = ten_dnac;  /* inputs − outputs = 10M exactly */
    CHECK_OK(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 6. Non-DNAC inputs/outputs don't count toward the 10M stake.
     *    All DNAC comes from input[0]; input[1] is a foreign token
     *    that must NOT be credited against the 10M requirement.
     *
     *    inputs[0] (DNAC) = 10M − 1 (insufficient)
     *    inputs[1] (token X) = huge irrelevant amount
     *    → reject (DNAC-only accounting fails).
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw - 1ULL);  /* DNAC input insufficient */
    tx.input_count = 2;
    tx.inputs[1].amount = 999999999999ULL;
    memset(tx.inputs[1].nullifier, 0xDD, DNAC_NULLIFIER_SIZE);
    memset(tx.inputs[1].token_id,  0xEE, DNAC_TOKEN_ID_SIZE);  /* non-native */
    CHECK_ERR(dnac_tx_verify_stake_rules(&tx));

    /* ──────────────────────────────────────────────────────────────
     * 7. Non-STAKE TX routed to the helper returns INVALID_TX_TYPE.
     * ────────────────────────────────────────────────────────────── */
    build_valid_stake_tx(&tx, ten_m_raw + ten_dnac);
    tx.type = DNAC_TX_SPEND;
    CHECK(dnac_tx_verify_stake_rules(&tx) == DNAC_ERROR_INVALID_TX_TYPE);

    /* ──────────────────────────────────────────────────────────────
     * 8. NULL tx → reject.
     * ────────────────────────────────────────────────────────────── */
    CHECK(dnac_tx_verify_stake_rules(NULL) == DNAC_ERROR_INVALID_PARAM);

    printf("test_stake_verify: ALL CHECKS PASSED\n");
    return 0;
}
