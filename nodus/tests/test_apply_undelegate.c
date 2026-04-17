/**
 * Nodus — Task 43 apply_undelegate state mutation test
 *
 * Exercises apply_tx_to_state for NODUS_W_TX_UNDELEGATE:
 *  1. Happy path (partial undelegate w/ nonzero pending): principal +
 *     pending-reward UTXOs emitted, delegation amount decremented,
 *     reward_snapshot advanced to V.accumulator.
 *  2. Full-drain undelegate: delegation row deleted.
 *  3. Zero-pending (acc == snap): pending UTXO still emitted (Rule Q).
 *  4. Insufficient delegation amount rejected.
 *  5. Missing delegation rejected.
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

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define CHECK_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK_TRUE fail at %s:%d: %s\n", \
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
    CHECK_TRUE(buf != NULL);

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
    CHECK_EQ(off, tx_len);
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
    CHECK_TRUE(buf != NULL);

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
    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

/* Build an UNDELEGATE TX. Appended: validator_pubkey[2592] + amount[8 BE]. */
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
    CHECK_TRUE(buf != NULL);

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
    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

/* Compute the synthetic-UTXO nullifier used by emit_synthetic_utxo
 * (must match the formula in nodus_witness_bft.c). */
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
    char data_path[] = "/tmp/test_apply_undeleg_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xD1, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    /* Bootstrap validator + delegation. */
    uint8_t val_pubkey[DNAC_PUBKEY_SIZE];
    memset(val_pubkey, 0x42, DNAC_PUBKEY_SIZE);
    uint8_t val_fp_raw[64];
    qgp_sha3_512(val_pubkey, DNAC_PUBKEY_SIZE, val_fp_raw);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(val_pubkey, val_fp_raw, 500,
                                         0xA1, &stake_len);
    const uint8_t *nul_stake[1];
    uint8_t nul_stake_buf[64]; memset(nul_stake_buf, 0xA1, 64);
    nul_stake[0] = nul_stake_buf;
    uint8_t stake_hash[64] = {0};
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_STAKE,
                            nul_stake, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    uint8_t dlg_pubkey[DNAC_PUBKEY_SIZE];
    memset(dlg_pubkey, 0x55, DNAC_PUBKEY_SIZE);

    char change_fp[129];
    memset(change_fp, 'b', 128); change_fp[128] = 0;

    size_t deleg_len = 0;
    const uint64_t deleg_input   = 100000000000ULL;   /* 1000 DNAC */
    const uint64_t deleg_change  =  40000000000ULL;   /*  400 DNAC change */
    uint8_t *deleg_tx = build_delegate_tx(dlg_pubkey, val_pubkey, 0xA3,
                                            deleg_input, deleg_change,
                                            change_fp, &deleg_len);
    const uint8_t *nul_deleg[1];
    uint8_t nul_deleg_buf[64]; memset(nul_deleg_buf, 0xA3, 64);
    nul_deleg[0] = nul_deleg_buf;
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_DELEGATE,
                            nul_deleg, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/2, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(deleg_tx);

    /* Verify delegation amount (input - output includes fee as noise per
     * Phase 8 known gap). */
    dnac_delegation_record_t d;
    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    const uint64_t deleg_amount_recorded = deleg_input - deleg_change;
    CHECK_EQ(d.amount, deleg_amount_recorded);

    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.total_delegated, deleg_amount_recorded);
    CHECK_EQ(v.external_delegated, deleg_amount_recorded);

    /* ── Scenario 1: Happy path partial undelegate w/ nonzero pending ──
     *
     * Manually seed V.accumulator = (hi=0, lo=0x1_0000_0000). Pending
     * per unit = 2^32 / 2^64 = 2^-32. For d.amount = deleg_amount_recorded,
     * pending = (2^32 × deleg_amount_recorded) >> 64.
     *
     * We use a smaller accumulator for predictable math:
     *   acc = 0 || 2^32 (hi=0, lo=0x100000000)
     *   pending = (2^32 × d.amount) >> 64
     *           = (uint128)(0x100000000 * amount) >> 64
     */
    dnac_reward_record_t r;
    rc = nodus_reward_get(&w, val_pubkey, &r);
    CHECK_EQ(rc, 0);
    qgp_u128_t acc_seed = qgp_u128_from_limbs(0, 0x100000000ULL);
    qgp_u128_serialize_be(acc_seed, r.accumulator);
    rc = nodus_reward_upsert(&w, &r);
    CHECK_EQ(rc, 0);

    /* Compute expected pending. */
    qgp_u128_t snap = qgp_u128_deserialize_be(d.reward_snapshot);
    qgp_u128_t diff = qgp_u128_sub(acc_seed, snap);
    qgp_u128_t pending_wide = qgp_u128_mul_u64(diff, d.amount);
    uint64_t expected_pending = pending_wide.hi;
    CHECK_TRUE(expected_pending > 0);

    const uint64_t partial_amount = 20000000000ULL;   /* 200 DNAC */
    uint8_t undeleg_hash[64];
    memset(undeleg_hash, 0x11, 64);
    size_t undeleg_len = 0;
    uint8_t *undeleg_tx = build_undelegate_tx(dlg_pubkey, val_pubkey,
                                                 partial_amount, 0xB1,
                                                 undeleg_hash, &undeleg_len);
    const uint8_t *nul_undeleg[1];
    uint8_t nul_undeleg_buf[64]; memset(nul_undeleg_buf, 0xB1, 64);
    nul_undeleg[0] = nul_undeleg_buf;
    rc = apply_tx_to_state(&w, undeleg_hash, NODUS_W_TX_UNDELEGATE,
                            nul_undeleg, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/3, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(undeleg_tx);

    /* Verify delegation amount decremented + snapshot advanced. */
    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    CHECK_EQ(d.amount, deleg_amount_recorded - partial_amount);
    qgp_u128_t new_snap = qgp_u128_deserialize_be(d.reward_snapshot);
    CHECK_EQ(qgp_u128_cmp(new_snap, acc_seed), 0);

    /* Verify validator totals decremented. */
    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.total_delegated, deleg_amount_recorded - partial_amount);
    CHECK_EQ(v.external_delegated, deleg_amount_recorded - partial_amount);

    /* Verify synthetic UTXOs exist with expected amounts. */
    uint8_t principal_null[64];
    uint8_t pending_null[64];
    compute_synthetic_nullifier(undeleg_hash, 0x01, 100, principal_null);
    compute_synthetic_nullifier(undeleg_hash, 0x02, 101, pending_null);

    uint64_t principal_amt = 0, pending_amt = 0;
    uint8_t unused_tid[64];
    rc = nodus_witness_utxo_lookup_ex(&w, principal_null,
                                        &principal_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(principal_amt, partial_amount);

    rc = nodus_witness_utxo_lookup_ex(&w, pending_null,
                                        &pending_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(pending_amt, expected_pending);

    /* ── Scenario 2: Full drain — delegation row deleted ──────────── */
    uint64_t remaining = d.amount;
    uint8_t undeleg2_hash[64];
    memset(undeleg2_hash, 0x22, 64);
    undeleg_tx = build_undelegate_tx(dlg_pubkey, val_pubkey,
                                        remaining, 0xB2,
                                        undeleg2_hash, &undeleg_len);
    const uint8_t *nul_undeleg2[1];
    uint8_t nul_undeleg2_buf[64]; memset(nul_undeleg2_buf, 0xB2, 64);
    nul_undeleg2[0] = nul_undeleg2_buf;
    rc = apply_tx_to_state(&w, undeleg2_hash, NODUS_W_TX_UNDELEGATE,
                            nul_undeleg2, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/4, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(undeleg_tx);

    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 1);   /* not found */

    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.total_delegated, 0);
    CHECK_EQ(v.external_delegated, 0);

    /* ── Scenario 3: Zero-pending (acc == snap) still emits pending UTXO.
     *
     * Bootstrap a second validator + delegation and immediately UNDELEGATE
     * (no accumulator movement). snapshot == 0 == accumulator.
     */
    uint8_t val2_pubkey[DNAC_PUBKEY_SIZE];
    memset(val2_pubkey, 0x77, DNAC_PUBKEY_SIZE);
    uint8_t val2_fp[64];
    qgp_sha3_512(val2_pubkey, DNAC_PUBKEY_SIZE, val2_fp);

    stake_tx = build_stake_tx(val2_pubkey, val2_fp, 1000, 0xA4, &stake_len);
    const uint8_t *nul_s2[1];
    uint8_t nul_s2_buf[64]; memset(nul_s2_buf, 0xA4, 64);
    nul_s2[0] = nul_s2_buf;
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_STAKE,
                            nul_s2, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/5, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    deleg_tx = build_delegate_tx(dlg_pubkey, val2_pubkey, 0xA5,
                                   deleg_input, deleg_change,
                                   change_fp, &deleg_len);
    const uint8_t *nul_d2[1];
    uint8_t nul_d2_buf[64]; memset(nul_d2_buf, 0xA5, 64);
    nul_d2[0] = nul_d2_buf;
    rc = apply_tx_to_state(&w, stake_hash, NODUS_W_TX_DELEGATE,
                            nul_d2, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/6, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(deleg_tx);

    uint8_t undeleg3_hash[64];
    memset(undeleg3_hash, 0x33, 64);
    undeleg_tx = build_undelegate_tx(dlg_pubkey, val2_pubkey,
                                        partial_amount, 0xB3,
                                        undeleg3_hash, &undeleg_len);
    const uint8_t *nul_u3[1];
    uint8_t nul_u3_buf[64]; memset(nul_u3_buf, 0xB3, 64);
    nul_u3[0] = nul_u3_buf;
    rc = apply_tx_to_state(&w, undeleg3_hash, NODUS_W_TX_UNDELEGATE,
                            nul_u3, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/7, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(undeleg_tx);

    /* Both UTXOs emitted; pending UTXO exists with amount=0. */
    uint8_t p2_null[64], pend2_null[64];
    compute_synthetic_nullifier(undeleg3_hash, 0x01, 100, p2_null);
    compute_synthetic_nullifier(undeleg3_hash, 0x02, 101, pend2_null);

    rc = nodus_witness_utxo_lookup_ex(&w, p2_null,
                                        &principal_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(principal_amt, partial_amount);
    rc = nodus_witness_utxo_lookup_ex(&w, pend2_null,
                                        &pending_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(pending_amt, 0);

    /* ── Scenario 4: Insufficient delegation amount ───────────────── */
    uint8_t undeleg4_hash[64];
    memset(undeleg4_hash, 0x44, 64);
    undeleg_tx = build_undelegate_tx(dlg_pubkey, val2_pubkey,
                                        /*amount too high*/ 1000000000000ULL,
                                        0xB4, undeleg4_hash, &undeleg_len);
    const uint8_t *nul_u4[1];
    uint8_t nul_u4_buf[64]; memset(nul_u4_buf, 0xB4, 64);
    nul_u4[0] = nul_u4_buf;
    rc = apply_tx_to_state(&w, undeleg4_hash, NODUS_W_TX_UNDELEGATE,
                            nul_u4, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/8, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(undeleg_tx);

    /* ── Scenario 5: No delegation ────────────────────────────────── */
    uint8_t ghost[DNAC_PUBKEY_SIZE];
    memset(ghost, 0x99, DNAC_PUBKEY_SIZE);
    uint8_t undeleg5_hash[64];
    memset(undeleg5_hash, 0x55, 64);
    undeleg_tx = build_undelegate_tx(ghost, val2_pubkey,
                                        10000000, 0xB5,
                                        undeleg5_hash, &undeleg_len);
    const uint8_t *nul_u5[1];
    uint8_t nul_u5_buf[64]; memset(nul_u5_buf, 0xB5, 64);
    nul_u5[0] = nul_u5_buf;
    rc = apply_tx_to_state(&w, undeleg5_hash, NODUS_W_TX_UNDELEGATE,
                            nul_u5, 1, undeleg_tx, (uint32_t)undeleg_len,
                            /*block_height=*/9, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(undeleg_tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_undelegate: ALL CHECKS PASSED\n");
    return 0;
}
