/**
 * Nodus — Task 41 apply_delegate state mutation test
 *
 * Exercises apply_tx_to_state for NODUS_W_TX_DELEGATE. Bootstraps a
 * validator via apply_stake first, then submits DELEGATE TX(s) and
 * verifies the delegation row + validator totals + reward snapshot.
 *
 * NOTE: delegation_amount in Phase 8 = input_sum - output_sum (the
 * fee is included as noise until Phase 9 splits it out). Tests account
 * for that imprecision.
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
#include "dnac/transaction.h"    /* DNAC_STAKE_PURPOSE_TAG_LEN */

#include "crypto/hash/qgp_sha3.h"

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

/* Build a DELEGATE TX.
 *   input_amount - change_amount = delegation_amount + fee (Phase 8 lumps
 *   these together as Task 41's approximate delegation_amount).
 */
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

    buf[off++] = 1;                   /* 1 output (change) */
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

int main(void) {
    char data_path[] = "/tmp/test_apply_delegate_XXXXXX";
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

    /* ── Bootstrap: STAKE a validator ─────────────────────────────── */
    uint8_t val_pubkey[DNAC_PUBKEY_SIZE];
    memset(val_pubkey, 0x42, DNAC_PUBKEY_SIZE);
    uint8_t val_fp_raw[64];
    qgp_sha3_512(val_pubkey, DNAC_PUBKEY_SIZE, val_fp_raw);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(val_pubkey, val_fp_raw, 500,
                                         0xA1, &stake_len);
    const uint8_t *nul0[1];
    uint8_t nul0_buf[64]; memset(nul0_buf, 0xA1, 64); nul0[0] = nul0_buf;
    uint8_t tx_hash[64] = {0};
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_STAKE,
                            nul0, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    /* ── Scenario 1: Happy path DELEGATE ────────────────────────────
     * input=1000 DNAC, change=400 DNAC => delegation_amount=600 DNAC
     * (includes fee as noise in Phase 8). */
    uint8_t dlg_pubkey[DNAC_PUBKEY_SIZE];
    memset(dlg_pubkey, 0x55, DNAC_PUBKEY_SIZE);

    char change_fp[129];
    memset(change_fp, 'a', 128); change_fp[128] = 0;

    const uint64_t input_amt   = 100000000000ULL;  /* 1000 DNAC */
    const uint64_t change_amt  =  40000000000ULL;  /*  400 DNAC */
    const uint64_t expected_amount = input_amt - change_amt;  /* 600 DNAC */

    size_t deleg_len = 0;
    uint8_t *deleg_tx = build_delegate_tx(dlg_pubkey, val_pubkey, 0xB1,
                                            input_amt, change_amt,
                                            change_fp, &deleg_len);
    const uint8_t *nul1[1];
    uint8_t nul1_buf[64]; memset(nul1_buf, 0xB1, 64); nul1[0] = nul1_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul1, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/2, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);

    /* Delegation row exists with expected amount + block + snapshot. */
    dnac_delegation_record_t d;
    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    CHECK_EQ(d.amount, expected_amount);
    CHECK_EQ(d.delegated_at_block, 2);
    /* Reward snapshot == validator's current accumulator (zero at this
     * point, no blocks have rewarded yet). */
    uint8_t zero_acc[16] = {0};
    CHECK_TRUE(memcmp(d.reward_snapshot, zero_acc, 16) == 0);

    /* Validator totals bumped. */
    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.total_delegated,    expected_amount);
    CHECK_EQ(v.external_delegated, expected_amount);
    free(deleg_tx);

    /* ── Scenario 2: Top-up delegation from same delegator ────────── */
    const uint64_t input2 = 50000000000ULL;  /* 500 DNAC */
    const uint64_t change2 = 20000000000ULL; /* 200 DNAC */
    const uint64_t expected_amount2 = input2 - change2;  /* 300 */
    deleg_tx = build_delegate_tx(dlg_pubkey, val_pubkey, 0xB2,
                                   input2, change2, change_fp, &deleg_len);
    const uint8_t *nul2[1];
    uint8_t nul2_buf[64]; memset(nul2_buf, 0xB2, 64); nul2[0] = nul2_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul2, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/3, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);

    rc = nodus_delegation_get(&w, dlg_pubkey, val_pubkey, &d);
    CHECK_EQ(rc, 0);
    CHECK_EQ(d.amount, expected_amount + expected_amount2);
    CHECK_EQ(d.delegated_at_block, 3);   /* Rule O restart */

    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.total_delegated,    expected_amount + expected_amount2);
    CHECK_EQ(v.external_delegated, expected_amount + expected_amount2);
    free(deleg_tx);

    /* ── Scenario 3: self-delegation rejected (Rule S) ───────────── */
    deleg_tx = build_delegate_tx(val_pubkey, val_pubkey, 0xB3,
                                   input_amt, change_amt,
                                   change_fp, &deleg_len);
    const uint8_t *nul3[1];
    uint8_t nul3_buf[64]; memset(nul3_buf, 0xB3, 64); nul3[0] = nul3_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul3, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/4, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(deleg_tx);

    /* ── Scenario 4: DELEGATE to non-existent validator ──────────── */
    uint8_t ghost_val[DNAC_PUBKEY_SIZE];
    memset(ghost_val, 0x99, DNAC_PUBKEY_SIZE);
    deleg_tx = build_delegate_tx(dlg_pubkey, ghost_val, 0xB4,
                                   input_amt, change_amt,
                                   change_fp, &deleg_len);
    const uint8_t *nul4[1];
    uint8_t nul4_buf[64]; memset(nul4_buf, 0xB4, 64); nul4[0] = nul4_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul4, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/5, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(deleg_tx);

    /* ── Scenario 5: DELEGATE to non-ACTIVE validator (Rule B) ──── */
    dnac_validator_record_t vrec;
    rc = nodus_validator_get(&w, val_pubkey, &vrec);
    CHECK_EQ(rc, 0);
    vrec.status = DNAC_VALIDATOR_RETIRING;
    rc = nodus_validator_update(&w, &vrec);
    CHECK_EQ(rc, 0);

    uint8_t dlg2[DNAC_PUBKEY_SIZE];
    memset(dlg2, 0x66, DNAC_PUBKEY_SIZE);
    deleg_tx = build_delegate_tx(dlg2, val_pubkey, 0xB5,
                                   input_amt, change_amt,
                                   change_fp, &deleg_len);
    const uint8_t *nul5[1];
    uint8_t nul5_buf[64]; memset(nul5_buf, 0xB5, 64); nul5[0] = nul5_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul5, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/6, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(deleg_tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_delegate: ALL CHECKS PASSED\n");
    return 0;
}
