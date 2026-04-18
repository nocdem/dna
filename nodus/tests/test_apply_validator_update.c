/**
 * Nodus — Task 45 apply_validator_update state mutation test
 *
 * Exercises apply_tx_to_state for NODUS_W_TX_VALIDATOR_UPDATE:
 *  1. Increase commission → pending fields set, current unchanged,
 *     effective_block = max(next_epoch_boundary, current + EPOCH_LENGTH).
 *  2. Decrease commission → current set immediately, pending fields
 *     cleared.
 *  3. Non-ACTIVE / non-RETIRING status → rejected.
 *  4. Non-existent validator → rejected.
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

/* VALIDATOR_UPDATE appended: new_commission_bps[2 BE] + signed_at_block[8 BE]. */
static uint8_t *build_val_update_tx(const uint8_t *signer_pubkey,
                                      uint16_t new_bps,
                                      uint64_t signed_at,
                                      uint8_t nul_fill,
                                      size_t *len_out) {
    const size_t appended = 2 + 8;
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
    buf[off++] = 9;                  /* VALIDATOR_UPDATE */
    off += 8 + 64;

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

    buf[off++] = (uint8_t)((new_bps >> 8) & 0xff);
    buf[off++] = (uint8_t)(new_bps & 0xff);
    for (int i = 7; i >= 0; i--) {
        buf[off++] = (uint8_t)((signed_at >> (i*8)) & 0xff);
    }

    buf[off++] = 0;
    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

int main(void) {
    char data_path[] = "/tmp/test_apply_valupd_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xE1, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    uint8_t val_pubkey[DNAC_PUBKEY_SIZE];
    memset(val_pubkey, 0x42, DNAC_PUBKEY_SIZE);
    uint8_t val_fp[64];
    qgp_sha3_512(val_pubkey, DNAC_PUBKEY_SIZE, val_fp);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(val_pubkey, val_fp, /*commission=*/500,
                                          0xA1, &stake_len);
    const uint8_t *nul_s[1];
    uint8_t nul_s_buf[64]; memset(nul_s_buf, 0xA1, 64);
    nul_s[0] = nul_s_buf;
    uint8_t dummy_hash[64] = {0};
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_STAKE,
                            nul_s, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/1, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    /* ── Scenario 1: Increase commission (500 -> 800) ─────────────── */
    const uint64_t increase_block = 10;
    size_t up_len = 0;
    uint8_t *up_tx = build_val_update_tx(val_pubkey, /*new_bps=*/800,
                                           /*signed_at=*/increase_block,
                                           0xB1, &up_len);
    const uint8_t *nul_u1[1];
    uint8_t nul_u1_buf[64]; memset(nul_u1_buf, 0xB1, 64);
    nul_u1[0] = nul_u1_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_VALIDATOR_UPDATE,
                            nul_u1, 1, up_tx, (uint32_t)up_len,
                            increase_block, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(up_tx);

    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, val_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.commission_bps, 500);           /* unchanged */
    CHECK_EQ(v.pending_commission_bps, 800);   /* pending set */
    CHECK_EQ(v.last_validator_update_block, increase_block);

    /* pending_effective_block = max(next_epoch_boundary, block + EPOCH_LENGTH). */
    uint64_t next_boundary = ((increase_block / DNAC_EPOCH_LENGTH) + 1) * DNAC_EPOCH_LENGTH;
    uint64_t plus_epoch = increase_block + DNAC_EPOCH_LENGTH;
    uint64_t expected = next_boundary > plus_epoch ? next_boundary : plus_epoch;
    CHECK_EQ(v.pending_effective_block, expected);

    /* ── Scenario 2: Decrease commission (500 -> 300) ─────────────── */
    /* Fresh validator to start from 500. */
    uint8_t val2_pubkey[DNAC_PUBKEY_SIZE];
    memset(val2_pubkey, 0x77, DNAC_PUBKEY_SIZE);
    uint8_t val2_fp[64];
    qgp_sha3_512(val2_pubkey, DNAC_PUBKEY_SIZE, val2_fp);
    stake_tx = build_stake_tx(val2_pubkey, val2_fp, 500, 0xA2, &stake_len);
    const uint8_t *nul_s2[1];
    uint8_t nul_s2_buf[64]; memset(nul_s2_buf, 0xA2, 64);
    nul_s2[0] = nul_s2_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_STAKE,
                            nul_s2, 1, stake_tx, (uint32_t)stake_len,
                            /*block_height=*/2, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(stake_tx);

    const uint64_t decrease_block = 20;
    up_tx = build_val_update_tx(val2_pubkey, /*new_bps=*/300,
                                  /*signed_at=*/decrease_block,
                                  0xB2, &up_len);
    const uint8_t *nul_u2[1];
    uint8_t nul_u2_buf[64]; memset(nul_u2_buf, 0xB2, 64);
    nul_u2[0] = nul_u2_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_VALIDATOR_UPDATE,
                            nul_u2, 1, up_tx, (uint32_t)up_len,
                            decrease_block, NULL, NULL, NULL);
    CHECK_EQ(rc, 0);
    free(up_tx);

    rc = nodus_validator_get(&w, val2_pubkey, &v);
    CHECK_EQ(rc, 0);
    CHECK_EQ(v.commission_bps, 300);          /* immediate */
    CHECK_EQ(v.pending_commission_bps, 0);    /* cleared */
    CHECK_EQ(v.pending_effective_block, 0);
    CHECK_EQ(v.last_validator_update_block, decrease_block);

    /* ── Scenario 3: Non-ACTIVE/RETIRING status → rejected ────────── */
    /* Force val2 to UNSTAKED directly via validator_update. */
    v.status = DNAC_VALIDATOR_UNSTAKED;
    rc = nodus_validator_update(&w, &v);
    CHECK_EQ(rc, 0);

    up_tx = build_val_update_tx(val2_pubkey, 400, 30, 0xB3, &up_len);
    const uint8_t *nul_u3[1];
    uint8_t nul_u3_buf[64]; memset(nul_u3_buf, 0xB3, 64);
    nul_u3[0] = nul_u3_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_VALIDATOR_UPDATE,
                            nul_u3, 1, up_tx, (uint32_t)up_len,
                            /*block_height=*/30, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(up_tx);

    /* ── Scenario 4: Non-existent validator → rejected ────────────── */
    uint8_t ghost[DNAC_PUBKEY_SIZE];
    memset(ghost, 0x99, DNAC_PUBKEY_SIZE);
    up_tx = build_val_update_tx(ghost, 600, 40, 0xB4, &up_len);
    const uint8_t *nul_u4[1];
    uint8_t nul_u4_buf[64]; memset(nul_u4_buf, 0xB4, 64);
    nul_u4[0] = nul_u4_buf;
    rc = apply_tx_to_state(&w, dummy_hash, NODUS_W_TX_VALIDATOR_UPDATE,
                            nul_u4, 1, up_tx, (uint32_t)up_len,
                            /*block_height=*/40, NULL, NULL, NULL);
    CHECK_TRUE(rc != 0);
    free(up_tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_validator_update: ALL CHECKS PASSED\n");
    return 0;
}
