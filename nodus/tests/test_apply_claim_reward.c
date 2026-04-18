/**
 * Nodus — Task 44 apply_claim_reward state mutation test
 *
 * Exercises apply_tx_to_state for NODUS_W_TX_CLAIM_REWARD:
 *  1. VALIDATOR path — signer == target_validator. validator_unclaimed
 *     is drained into a single synthetic UTXO; reward row's
 *     validator_unclaimed zeroed.
 *  2. DELEGATOR path — pending computed from accumulator diff × amount
 *     >> 64 and emitted as a UTXO; D.reward_snapshot advanced.
 *  3. pending > max_pending → rejected.
 *  4. DELEGATOR path with no delegation row → rejected.
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
    buf[off++] = 4;
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
    buf[off++] = 5;
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

/* CLAIM_REWARD appended: target_validator[2592] + max_pending[8 BE] + valid_before[8 BE]. */
static uint8_t *build_claim_reward_tx(const uint8_t *signer_pubkey,
                                         const uint8_t *target_pubkey,
                                         uint64_t max_pending,
                                         uint64_t valid_before,
                                         uint8_t nul_fill,
                                         const uint8_t *tx_hash,
                                         size_t *len_out) {
    const size_t appended = DNAC_PUBKEY_SIZE + 8 + 8;
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
    buf[off++] = 8;                  /* CLAIM_REWARD */
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

    memcpy(buf + off, target_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    for (int i = 7; i >= 0; i--) {
        buf[off++] = (uint8_t)((max_pending >> (i*8)) & 0xff);
    }
    for (int i = 7; i >= 0; i--) {
        buf[off++] = (uint8_t)((valid_before >> (i*8)) & 0xff);
    }

    buf[off++] = 0;
    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

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
    char data_path[] = "/tmp/test_apply_claim_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    /* Bootstrap validator. */
    uint8_t val_pubkey[DNAC_PUBKEY_SIZE];
    memset(val_pubkey, 0x42, DNAC_PUBKEY_SIZE);
    uint8_t val_fp[64];
    qgp_sha3_512(val_pubkey, DNAC_PUBKEY_SIZE, val_fp);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(val_pubkey, val_fp, 500, 0xA1, &stake_len);
    const uint8_t *nul_s[1];
    uint8_t nul_s_buf[64]; memset(nul_s_buf, 0xA1, 64);
    nul_s[0] = nul_s_buf;
    uint8_t dummy_hash[64] = {0};
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_STAKE,
                            nul_s, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    /* ── Scenario 1: VALIDATOR path ──────────────────────────────── */
    /* Seed V.validator_unclaimed = 500. */
    dnac_reward_record_t r;
    rc = nodus_reward_get(&w, val_pubkey, &r);
    CHECK_EQ(rc, 0);
    r.validator_unclaimed = 500;
    rc = nodus_reward_upsert(&w, &r);
    CHECK_EQ(rc, 0);

    uint8_t claim1_hash[64];
    memset(claim1_hash, 0x11, 64);
    size_t claim_len = 0;
    uint8_t *claim_tx = build_claim_reward_tx(val_pubkey, val_pubkey,
                                                 /*max_pending=*/1000,
                                                 /*valid_before=*/999999,
                                                 0xC1,
                                                 claim1_hash, &claim_len);
    const uint8_t *nul_c1[1];
    uint8_t nul_c1_buf[64]; memset(nul_c1_buf, 0xC1, 64);
    nul_c1[0] = nul_c1_buf;
    rc = apply_tx_to_state(&w, claim1_hash, NODUS_W_TX_CLAIM_REWARD,
                            nul_c1, 1, claim_tx, (uint32_t)claim_len,
                            /*block_height=*/2, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(claim_tx);

    /* validator_unclaimed drained to 0. */
    rc = nodus_reward_get(&w, val_pubkey, &r);
    CHECK_EQ(rc, 0);
    CHECK_EQ(r.validator_unclaimed, 0);
    CHECK_EQ(r.last_update_block, 2);

    /* Synthetic UTXO emitted with amount=500. */
    uint8_t utxo_null[64];
    compute_synthetic_nullifier(claim1_hash, 0x03, 100, utxo_null);
    uint64_t utxo_amt = 0;
    uint8_t unused_tid[64];
    rc = nodus_witness_utxo_lookup_ex(&w, utxo_null,
                                        &utxo_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(utxo_amt, 500);

    /* ── Scenario 2: DELEGATOR path ──────────────────────────────── */
    uint8_t dlg_pubkey[DNAC_PUBKEY_SIZE];
    memset(dlg_pubkey, 0x55, DNAC_PUBKEY_SIZE);

    char change_fp[129];
    memset(change_fp, 'b', 128); change_fp[128] = 0;

    size_t deleg_len = 0;
    const uint64_t deleg_input  = 100000000000ULL;
    const uint64_t deleg_change =  40000000000ULL;
    uint8_t *deleg_tx = build_delegate_tx(dlg_pubkey, val_pubkey, 0xA3,
                                            deleg_input, deleg_change,
                                            change_fp, &deleg_len);
    const uint8_t *nul_d[1];
    uint8_t nul_d_buf[64]; memset(nul_d_buf, 0xA3, 64);
    nul_d[0] = nul_d_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_DELEGATE,
                            nul_d, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/3, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(deleg_tx);

    dnac_delegation_record_t d;
    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    const uint64_t amt = d.amount;

    /* Seed V.accumulator = (hi=0, lo=0x100000000) to give nonzero pending. */
    qgp_u128_t acc_seed = qgp_u128_from_limbs(0, 0x100000000ULL);
    qgp_u128_serialize_be(acc_seed, r.accumulator);
    rc = nodus_reward_upsert(&w, &r);
    CHECK_EQ(rc, 0);

    qgp_u128_t snap_u = qgp_u128_deserialize_be(d.reward_snapshot);
    qgp_u128_t diff = qgp_u128_sub(acc_seed, snap_u);
    qgp_u128_t wide = qgp_u128_mul_u64(diff, amt);
    uint64_t expected_pending = wide.hi;
    CHECK_TRUE(expected_pending > 0);

    uint8_t claim2_hash[64];
    memset(claim2_hash, 0x22, 64);
    claim_tx = build_claim_reward_tx(dlg_pubkey, val_pubkey,
                                        /*max_pending=*/expected_pending + 1000,
                                        /*valid_before=*/999999,
                                        0xC2,
                                        claim2_hash, &claim_len);
    const uint8_t *nul_c2[1];
    uint8_t nul_c2_buf[64]; memset(nul_c2_buf, 0xC2, 64);
    nul_c2[0] = nul_c2_buf;
    rc = apply_tx_to_state(&w, claim2_hash, NODUS_W_TX_CLAIM_REWARD,
                            nul_c2, 1, claim_tx, (uint32_t)claim_len,
                            /*block_height=*/4, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(claim_tx);

    /* snapshot advanced. */
    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    qgp_u128_t new_snap = qgp_u128_deserialize_be(d.reward_snapshot);
    CHECK_EQ(qgp_u128_cmp(new_snap, acc_seed), 0);
    CHECK_EQ(d.amount, amt);      /* amount unchanged — CLAIM doesn't touch principal */

    /* UTXO at expected pending. */
    compute_synthetic_nullifier(claim2_hash, 0x03, 100, utxo_null);
    rc = nodus_witness_utxo_lookup_ex(&w, utxo_null,
                                        &utxo_amt, NULL, unused_tid, NULL);
    CHECK_EQ(rc, 0);
    CHECK_EQ(utxo_amt, expected_pending);

    /* ── Scenario 3: pending > max_pending → rejected ─────────────── */
    /* Advance V.accumulator further so another claim would produce
     * nonzero pending; set low max_pending. */
    acc_seed = qgp_u128_from_limbs(0, 0x200000000ULL);
    qgp_u128_serialize_be(acc_seed, r.accumulator);
    rc = nodus_reward_upsert(&w, &r);
    CHECK_EQ(rc, 0);

    uint8_t claim3_hash[64];
    memset(claim3_hash, 0x33, 64);
    claim_tx = build_claim_reward_tx(dlg_pubkey, val_pubkey,
                                        /*max_pending=*/1,  /* way too low */
                                        /*valid_before=*/999999,
                                        0xC3,
                                        claim3_hash, &claim_len);
    const uint8_t *nul_c3[1];
    uint8_t nul_c3_buf[64]; memset(nul_c3_buf, 0xC3, 64);
    nul_c3[0] = nul_c3_buf;
    rc = apply_tx_to_state(&w, claim3_hash, NODUS_W_TX_CLAIM_REWARD,
                            nul_c3, 1, claim_tx, (uint32_t)claim_len,
                            /*block_height=*/5, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(claim_tx);

    /* ── Scenario 4: DELEGATOR path with no delegation row ────────── */
    uint8_t ghost[DNAC_PUBKEY_SIZE];
    memset(ghost, 0x99, DNAC_PUBKEY_SIZE);
    uint8_t claim4_hash[64];
    memset(claim4_hash, 0x44, 64);
    claim_tx = build_claim_reward_tx(ghost, val_pubkey,
                                        /*max_pending=*/1000000000ULL,
                                        /*valid_before=*/999999,
                                        0xC4,
                                        claim4_hash, &claim_len);
    const uint8_t *nul_c4[1];
    uint8_t nul_c4_buf[64]; memset(nul_c4_buf, 0xC4, 64);
    nul_c4[0] = nul_c4_buf;
    rc = apply_tx_to_state(&w, claim4_hash, NODUS_W_TX_CLAIM_REWARD,
                            nul_c4, 1, claim_tx, (uint32_t)claim_len,
                            /*block_height=*/6, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(claim_tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_claim_reward: ALL CHECKS PASSED\n");
    return 0;
}
