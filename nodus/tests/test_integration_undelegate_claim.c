/* Task 54 — UNDELEGATE auto-claim E2E regression test.
 *
 * Exercises the full lifecycle through apply_tx_to_state primitives:
 *     STAKE   → DELEGATE → (simulated accumulator accrual) → UNDELEGATE
 *
 * The reward-accrual step is simulated by a direct reward-record mutation
 * (set validator.accumulator to a known non-zero u128) rather than running
 * 120 real blocks through the accumulator pipeline. The Phase 8 unit
 * tests already cover each apply_* helper individually; this test pins
 * the *end-to-end* invariants that must hold across all three
 * type-specific helpers once stitched together:
 *
 *   (a) delegation.amount decremented by the UNDELEGATE amount.
 *   (b) delegation.reward_snapshot advanced to the current validator
 *       accumulator value (BE-serialized u128).
 *   (c) two synthetic UTXOs emitted for the delegator — principal
 *       (output_index 100) and pending-reward (output_index 101).
 *   (d) Validator totals (total_delegated / external_delegated) track
 *       the post-undelegate delegation amount.
 *
 * See:
 *   - Task 41 (apply_delegate)     commit 06c76e08
 *   - Task 43 (apply_undelegate)   commit 35bff4c4
 *   - Task 49 (accumulator update) commit d229f142
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_bft_internal.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/transaction.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_u128.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

static const uint8_t LOCAL_PURPOSE_TAG[DNAC_STAKE_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','V','A','L','I','D','A','T','O','R','_','v','1'
};

/* ──────────────────────────────────────────────────────────────────────
 * TX buffer helpers — identical shape to Phase 8 test_apply_*.c files.
 * Each builds a minimal valid wire-format TX for the witness's
 * deserializer, populating only the fields the state-apply helpers
 * actually read.
 * ──────────────────────────────────────────────────────────────────── */

static uint8_t *build_stake_tx(const uint8_t *signer_pubkey,
                                const uint8_t *unstake_fp_raw,
                                uint16_t commission_bps,
                                uint8_t nul_fill,
                                size_t *len_out) {
    const size_t appended = 2 + 64 + DNAC_STAKE_PURPOSE_TAG_LEN;
    const size_t tx_len =
        74 +
        1 + (64 + 8 + 64) +
        1 +
        1 +
        1 + (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE) +
        appended +
        1;

    uint8_t *buf = calloc(1, tx_len);
    CHECK(buf != NULL);

    size_t off = 0;
    buf[off++] = 1;
    buf[off++] = 4;                   /* STAKE */
    off += 8 + 64;

    buf[off++] = 1;
    memset(buf + off, nul_fill, 64); off += 64;
    uint64_t input_amt = DNAC_SELF_STAKE_AMOUNT + 100;
    memcpy(buf + off, &input_amt, 8); off += 8;
    off += 64;

    buf[off++] = 0;
    buf[off++] = 0;

    buf[off++] = 1;
    memcpy(buf + off, signer_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    off += DNAC_SIGNATURE_SIZE;

    buf[off++] = (uint8_t)((commission_bps >> 8) & 0xff);
    buf[off++] = (uint8_t)(commission_bps & 0xff);
    memcpy(buf + off, unstake_fp_raw, 64); off += 64;
    memcpy(buf + off, LOCAL_PURPOSE_TAG, DNAC_STAKE_PURPOSE_TAG_LEN);
    off += DNAC_STAKE_PURPOSE_TAG_LEN;

    buf[off++] = 0;
    CHECK(off == tx_len);
    *len_out = tx_len;
    return buf;
}

static uint8_t *build_delegate_tx(const uint8_t *signer_pubkey,
                                    const uint8_t *validator_pubkey,
                                    uint8_t nul_fill,
                                    uint64_t input_amount,
                                    uint64_t change_amount,
                                    const char *change_fp,
                                    size_t *len_out) {
    const size_t appended = DNAC_PUBKEY_SIZE;
    const size_t output_size = 1 + 129 + 8 + 64 + 32 + 1;

    const size_t tx_len =
        74 +
        1 + (64 + 8 + 64) +
        1 + output_size +
        1 +
        1 + (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE) +
        appended +
        1;

    uint8_t *buf = calloc(1, tx_len);
    CHECK(buf != NULL);

    size_t off = 0;
    buf[off++] = 1;
    buf[off++] = 5;                   /* DELEGATE */
    off += 8 + 64;

    buf[off++] = 1;
    memset(buf + off, nul_fill, 64); off += 64;
    memcpy(buf + off, &input_amount, 8); off += 8;
    off += 64;

    buf[off++] = 1;
    buf[off++] = 1;
    memcpy(buf + off, change_fp, 128); buf[off + 128] = 0; off += 129;
    memcpy(buf + off, &change_amount, 8); off += 8;
    off += 64;
    memset(buf + off, 0xEE, 32); off += 32;
    buf[off++] = 0;

    buf[off++] = 0;

    buf[off++] = 1;
    memcpy(buf + off, signer_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    off += DNAC_SIGNATURE_SIZE;

    memcpy(buf + off, validator_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;

    buf[off++] = 0;
    CHECK(off == tx_len);
    *len_out = tx_len;
    return buf;
}

/* UNDELEGATE appended layout: validator_pubkey[2592] + amount[8 BE]. */
static uint8_t *build_undelegate_tx(const uint8_t *signer_pubkey,
                                      const uint8_t *validator_pubkey,
                                      uint64_t undelegate_amount,
                                      uint8_t nul_fill,
                                      const uint8_t *tx_hash,
                                      size_t *len_out) {
    const size_t appended = DNAC_PUBKEY_SIZE + 8;
    const size_t tx_len =
        74 +
        1 + (64 + 8 + 64) +
        1 +
        1 +
        1 + (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE) +
        appended +
        1;

    uint8_t *buf = calloc(1, tx_len);
    CHECK(buf != NULL);

    size_t off = 0;
    buf[off++] = 1;
    buf[off++] = 7;                   /* UNDELEGATE */
    off += 8;
    memcpy(buf + off, tx_hash, 64); off += 64;

    buf[off++] = 1;
    memset(buf + off, nul_fill, 64); off += 64;
    uint64_t input_amt = 100;
    memcpy(buf + off, &input_amt, 8); off += 8;
    off += 64;

    buf[off++] = 0;
    buf[off++] = 0;

    buf[off++] = 1;
    memcpy(buf + off, signer_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    off += DNAC_SIGNATURE_SIZE;

    memcpy(buf + off, validator_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    /* amount big-endian */
    for (int i = 7; i >= 0; i--) {
        buf[off++] = (uint8_t)((undelegate_amount >> (i*8)) & 0xff);
    }

    buf[off++] = 0;
    CHECK(off == tx_len);
    *len_out = tx_len;
    return buf;
}

/* Matches emit_synthetic_utxo() nullifier derivation in nodus_witness_bft.c. */
static void compute_synthetic_nullifier(const uint8_t *tx_hash,
                                          uint8_t kind,
                                          uint32_t index,
                                          uint8_t out[64]) {
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind;
    preimage[65] = (uint8_t)((index >> 24) & 0xff);
    preimage[66] = (uint8_t)((index >> 16) & 0xff);
    preimage[67] = (uint8_t)((index >> 8) & 0xff);
    preimage[68] = (uint8_t)(index & 0xff);
    qgp_sha3_512(preimage, sizeof(preimage), out);
}

int main(void) {
    char data_path[] = "/tmp/test_integration_undelegate_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xF0, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK(rc == 0);

    /* ── Phase 1: STAKE a validator ─────────────────────────────────── */
    uint8_t validator_pk[DNAC_PUBKEY_SIZE];
    memset(validator_pk, 0xA1, DNAC_PUBKEY_SIZE);
    uint8_t validator_fp_raw[64];
    qgp_sha3_512(validator_pk, DNAC_PUBKEY_SIZE, validator_fp_raw);

    uint8_t delegator_pk[DNAC_PUBKEY_SIZE];
    memset(delegator_pk, 0xB2, DNAC_PUBKEY_SIZE);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(validator_pk, validator_fp_raw,
                                         /*commission_bps=*/500, 0xA1,
                                         &stake_len);
    const uint8_t *nul_stake[1];
    uint8_t nul_stake_buf[64]; memset(nul_stake_buf, 0xA1, 64);
    nul_stake[0] = nul_stake_buf;
    uint8_t stake_hash[64] = {0};
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_STAKE,
                            nul_stake, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/1, NULL, NULL, NULL);
    CHECK(rc == 0);
    free(stake_tx);

    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, validator_pk, &v);
    CHECK(rc == 0);
    CHECK(v.status == DNAC_VALIDATOR_ACTIVE);
    CHECK(v.self_stake == DNAC_SELF_STAKE_AMOUNT);
    CHECK(v.total_delegated == 0);
    CHECK(v.external_delegated == 0);

    /* ── Phase 2: DELEGATE 1000 DNAC (net, via input-minus-change) ──── */
    char change_fp[129];
    memset(change_fp, 'c', 128); change_fp[128] = 0;

    /* delegation.amount is recorded as (input_sum - output_sum). Pick
     * numbers so the net delegation is a clean amount: input 1000 DNAC,
     * change 0 → delegation = 1000 DNAC. */
    const uint64_t deleg_input  = 1000ULL * 100000000ULL;   /* 1000 DNAC */
    const uint64_t deleg_change = 0ULL;
    const uint64_t delegation_amount = deleg_input - deleg_change;

    size_t deleg_len = 0;
    uint8_t *deleg_tx = build_delegate_tx(delegator_pk, validator_pk,
                                           /*nul_fill=*/0xB1,
                                           deleg_input, deleg_change,
                                           change_fp, &deleg_len);
    const uint8_t *nul_deleg[1];
    uint8_t nul_deleg_buf[64]; memset(nul_deleg_buf, 0xB1, 64);
    nul_deleg[0] = nul_deleg_buf;
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_DELEGATE,
                            nul_deleg, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/2, NULL, NULL, NULL);
    CHECK(rc == 0);
    free(deleg_tx);

    /* Delegation row created with snapshot = 0 (validator.accumulator
     * is still zero at this point). */
    dnac_delegation_record_t d;
    rc = nodus_delegation_get(&w, delegator_pk, validator_pk, &d);
    CHECK(rc == 0);
    CHECK(d.amount == delegation_amount);
    uint8_t zero16[16] = {0};
    CHECK(memcmp(d.reward_snapshot, zero16, 16) == 0);

    /* Validator totals reflect the new delegation. */
    rc = nodus_validator_get(&w, validator_pk, &v);
    CHECK(rc == 0);
    CHECK(v.total_delegated == delegation_amount);
    CHECK(v.external_delegated == delegation_amount);

    /* ── Phase 3: Simulate accumulator accrual ──────────────────────── *
     *
     * Instead of running the full 120-block accumulator pipeline (Task
     * 49), we directly mutate the reward row's accumulator to a known
     * u128 value. This pins the mathematical contract that UNDELEGATE
     * uses:
     *
     *     diff     = (V.accumulator − D.reward_snapshot)        (u128)
     *     pending  = (diff * D.amount) >> 64                    (u64)
     *
     * Pick accumulator = (hi=0, lo=0x1_0000_0000) → diff = 2^32.
     * For D.amount = 1000_DNAC_raw (100_000_000_000),
     *   pending = (2^32 * 100_000_000_000) >> 64
     *           = 429_496_729_600_000_000_000 >> 64
     *           = 23 (the hi-limb of the 128-bit product).
     * That matches what the unit test in test_apply_undelegate uses.
     */
    dnac_reward_record_t r;
    rc = nodus_reward_get(&w, validator_pk, &r);
    CHECK(rc == 0);
    qgp_u128_t acc_seed = qgp_u128_from_limbs(0, 0x100000000ULL);
    qgp_u128_serialize_be(acc_seed, r.accumulator);
    r.last_update_block = 120;   /* pretend one epoch passed */
    rc = nodus_reward_upsert(&w, &r);
    CHECK(rc == 0);

    /* Compute the expected pending value the witness will emit. Mirrors
     * the apply_undelegate code in nodus_witness_bft.c exactly. */
    qgp_u128_t snap_before = qgp_u128_deserialize_be(d.reward_snapshot);
    qgp_u128_t diff        = qgp_u128_sub(acc_seed, snap_before);
    qgp_u128_t pending_wide = qgp_u128_mul_u64(diff, d.amount);
    uint64_t expected_pending = pending_wide.hi;
    CHECK(expected_pending > 0);

    /* ── Phase 4: UNDELEGATE 500 DNAC ───────────────────────────────── */
    const uint64_t undelegate_amount = 500ULL * 100000000ULL;
    uint8_t undeleg_hash[64];
    memset(undeleg_hash, 0x7C, 64);

    size_t undeleg_len = 0;
    uint8_t *undeleg_tx = build_undelegate_tx(delegator_pk, validator_pk,
                                                undelegate_amount,
                                                /*nul_fill=*/0xC1,
                                                undeleg_hash, &undeleg_len);
    const uint8_t *nul_undeleg[1];
    uint8_t nul_undeleg_buf[64]; memset(nul_undeleg_buf, 0xC1, 64);
    nul_undeleg[0] = nul_undeleg_buf;
    rc = apply_tx_to_state(&w, undeleg_hash, NODUS_W_TX_UNDELEGATE,
                            nul_undeleg, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/121, NULL, NULL, NULL);
    CHECK(rc == 0);
    free(undeleg_tx);

    /* ── Assertion (a): delegation.amount decremented. ──────────────── */
    rc = nodus_delegation_get(&w, delegator_pk, validator_pk, &d);
    CHECK(rc == 0);
    CHECK(d.amount == delegation_amount - undelegate_amount);

    /* ── Assertion (b): reward_snapshot advanced to validator.accumulator. */
    qgp_u128_t snap_after = qgp_u128_deserialize_be(d.reward_snapshot);
    CHECK(qgp_u128_cmp(snap_after, acc_seed) == 0);
    CHECK(memcmp(d.reward_snapshot, r.accumulator, 16) == 0);

    /* ── Assertion (c): two synthetic UTXOs emitted ─ principal + pending. */
    uint8_t principal_null[64];
    uint8_t pending_null[64];
    compute_synthetic_nullifier(undeleg_hash, 0x01, 100, principal_null);
    compute_synthetic_nullifier(undeleg_hash, 0x02, 101, pending_null);

    uint64_t principal_amt = 0;
    uint64_t pending_amt   = 0;
    uint8_t unused_tid[64];
    rc = nodus_witness_utxo_lookup_ex(&w, principal_null,
                                        &principal_amt, NULL, unused_tid, NULL);
    CHECK(rc == 0);
    CHECK(principal_amt == undelegate_amount);

    rc = nodus_witness_utxo_lookup_ex(&w, pending_null,
                                        &pending_amt, NULL, unused_tid, NULL);
    CHECK(rc == 0);
    CHECK(pending_amt == expected_pending);

    /* ── Assertion (d): Validator totals track post-undelegate amount. */
    rc = nodus_validator_get(&w, validator_pk, &v);
    CHECK(rc == 0);
    CHECK(v.total_delegated    == delegation_amount - undelegate_amount);
    CHECK(v.external_delegated == delegation_amount - undelegate_amount);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_integration_undelegate_claim: ALL CHECKS PASSED\n");
    return 0;
}
