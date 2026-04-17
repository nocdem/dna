/**
 * Nodus — Task 42 apply_unstake state mutation test
 *
 * Exercises apply_tx_to_state for NODUS_W_TX_UNSTAKE. Verifies status
 * transitions to RETIRING, unstake_commit_block is set, and Rule A
 * (no delegations) is enforced.
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

/* Build an UNSTAKE TX (no appended fields). */
static uint8_t *build_unstake_tx(const uint8_t *signer_pubkey,
                                   uint8_t nul_fill,
                                   uint64_t input_amount,
                                   uint64_t change_amount,
                                   const char *change_fp,
                                   size_t *len_out) {
    const size_t output_size = 1 + 129 + 8 + 64 + 32 + 1;

    const size_t tx_len =
        74 +
        1 + (64 + 8 + 64) +
        1 + output_size +
        1 +
        1 + (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE) +
        /* no appended */
        1;

    uint8_t *buf = calloc(1, tx_len);
    CHECK_TRUE(buf != NULL);

    size_t off = 0;
    buf[off++] = 1;
    buf[off++] = 6;                   /* UNSTAKE */
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
    memset(buf + off, 0xDD, 32); off += 32;
    buf[off++] = 0;

    buf[off++] = 0;

    buf[off++] = 1;
    memcpy(buf + off, signer_pubkey, DNAC_PUBKEY_SIZE); off += DNAC_PUBKEY_SIZE;
    off += DNAC_SIGNATURE_SIZE;

    buf[off++] = 0;
    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

int main(void) {
    char data_path[] = "/tmp/test_apply_unstake_XXXXXX";
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

    /* ── Scenario 1: Happy path UNSTAKE (no delegators) ───────────── */
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

    /* Issue UNSTAKE. */
    char change_fp[129];
    memset(change_fp, 'b', 128); change_fp[128] = 0;

    size_t unstake_len = 0;
    uint8_t *unstake_tx = build_unstake_tx(val_pubkey, 0xC1,
                                             1000000000ULL,   /* 10 DNAC */
                                              999900000ULL,   /* change */
                                             change_fp,
                                             &unstake_len);
    const uint8_t *nul1[1];
    uint8_t nul1_buf[64]; memset(nul1_buf, 0xC1, 64); nul1[0] = nul1_buf;
    const uint64_t unstake_block = 5;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_UNSTAKE,
                            nul1, 1, unstake_tx, (uint32_t)unstake_len,
                            unstake_block, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(unstake_tx);

    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.status, DNAC_VALIDATOR_RETIRING);
    CHECK_EQ(v.unstake_commit_block, unstake_block);
    /* self_stake not cleared yet — that happens at phase 2 epoch graduation. */
    CHECK_EQ(v.self_stake, DNAC_SELF_STAKE_AMOUNT);

    /* ── Scenario 2: UNSTAKE when status != ACTIVE (already RETIRING) */
    unstake_tx = build_unstake_tx(val_pubkey, 0xC2,
                                    1000000000ULL, 999900000ULL,
                                    change_fp, &unstake_len);
    const uint8_t *nul2[1];
    uint8_t nul2_buf[64]; memset(nul2_buf, 0xC2, 64); nul2[0] = nul2_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_UNSTAKE,
                            nul2, 1, unstake_tx, (uint32_t)unstake_len,
                            /*block_height=*/6, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(unstake_tx);

    /* ── Scenario 3: UNSTAKE when delegators exist (Rule A) ──────── */
    /* Bootstrap a second validator, delegate to it, then try UNSTAKE. */
    uint8_t val2_pubkey[DNAC_PUBKEY_SIZE];
    memset(val2_pubkey, 0x77, DNAC_PUBKEY_SIZE);
    uint8_t val2_fp_raw[64];
    qgp_sha3_512(val2_pubkey, DNAC_PUBKEY_SIZE, val2_fp_raw);

    stake_tx = build_stake_tx(val2_pubkey, val2_fp_raw, 1000, 0xA2, &stake_len);
    const uint8_t *nul3[1];
    uint8_t nul3_buf[64]; memset(nul3_buf, 0xA2, 64); nul3[0] = nul3_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_STAKE,
                            nul3, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/7, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    /* Delegate from another pubkey. */
    uint8_t dlg_pubkey[DNAC_PUBKEY_SIZE];
    memset(dlg_pubkey, 0x55, DNAC_PUBKEY_SIZE);

    size_t deleg_len = 0;
    uint8_t *deleg_tx = build_delegate_tx(dlg_pubkey, val2_pubkey, 0xA3,
                                            100000000000ULL,   /* 1000 DNAC */
                                             40000000000ULL,   /*  400 DNAC change */
                                            change_fp, &deleg_len);
    const uint8_t *nul4[1];
    uint8_t nul4_buf[64]; memset(nul4_buf, 0xA3, 64); nul4[0] = nul4_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_DELEGATE,
                            nul4, 1, deleg_tx, (uint32_t)deleg_len,
                            /*block_height=*/8, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(deleg_tx);

    /* Now try UNSTAKE on val2 — must fail (Rule A). */
    unstake_tx = build_unstake_tx(val2_pubkey, 0xC3,
                                    1000000000ULL, 999900000ULL,
                                    change_fp, &unstake_len);
    const uint8_t *nul5[1];
    uint8_t nul5_buf[64]; memset(nul5_buf, 0xC3, 64); nul5[0] = nul5_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_UNSTAKE,
                            nul5, 1, unstake_tx, (uint32_t)unstake_len,
                            /*block_height=*/9, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);

    /* val2 still ACTIVE. */
    rc = nodus_validator_get(&w, val2_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.status, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(v.unstake_commit_block, 0);
    free(unstake_tx);

    /* ── Scenario 4: UNSTAKE on non-existent validator ───────────── */
    uint8_t ghost[DNAC_PUBKEY_SIZE];
    memset(ghost, 0x99, DNAC_PUBKEY_SIZE);
    unstake_tx = build_unstake_tx(ghost, 0xC4,
                                    1000000000ULL, 999900000ULL,
                                    change_fp, &unstake_len);
    const uint8_t *nul6[1];
    uint8_t nul6_buf[64]; memset(nul6_buf, 0xC4, 64); nul6[0] = nul6_buf;
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_UNSTAKE,
                            nul6, 1, unstake_tx, (uint32_t)unstake_len,
                            /*block_height=*/10, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(unstake_tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_unstake: ALL CHECKS PASSED\n");
    return 0;
}
