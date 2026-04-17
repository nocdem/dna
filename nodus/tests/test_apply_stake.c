/**
 * Nodus — Task 40 apply_stake state mutation test
 *
 * Constructs a minimal STAKE TX buffer by hand (design §2.3) and
 * invokes apply_tx_to_state with tx_type = NODUS_W_TX_STAKE. Asserts
 * that the helper inserts a validator row, seeds an empty reward row,
 * and bumps validator_stats.active_count. Also covers the malformed
 * case (truncated appended fields).
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_bft_internal.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/transaction.h"    /* DNAC_STAKE_PURPOSE_TAG_LEN */

/* DNAC_STAKE_PURPOSE_TAG is defined in dnac/src/transaction/constants.c and
 * is not linked into the nodus test binaries. Hardcode the 17-byte
 * "DNAC_VALIDATOR_v1" value locally — apply_stake does NOT verify the
 * tag content (Phase 7 STAKE verify is the source of truth), so this
 * is just test scaffolding. */
static const uint8_t LOCAL_PURPOSE_TAG[DNAC_STAKE_PURPOSE_TAG_LEN] = {
    'D','N','A','C','_','V','A','L','I','D','A','T','O','R','_','v','1'
};

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

/* Build a minimal STAKE TX buffer.
 *
 * Wire layout:
 *   header(74)
 *   + input_count(1=1) + 1 input (nullifier[64] + amount[8] + token_id[64])
 *   + output_count(1=0)
 *   + witness_count(1=0)
 *   + signer_count(1=1) + 1 signer (pubkey[2592] + sig[4627])
 *   + appended: commission_bps(2) + unstake_destination_fp[64] + purpose_tag[17]
 *   + has_chain_def(1=0)
 *
 * The caller supplies the signer pubkey (so tests can reuse the same
 * pubkey across operations), the raw 64-byte unstake destination fp,
 * and commission_bps. The flags `truncate_appended` cuts off the tail
 * to exercise the malformed-input branch. Returns a malloc'd buffer —
 * caller frees. *len_out set on return.
 */
static uint8_t *build_stake_tx(const uint8_t *signer_pubkey,
                                const uint8_t *unstake_fp_raw,
                                uint16_t commission_bps,
                                int truncate_appended,
                                size_t *len_out) {
    const size_t appended_full = 2 + 64 + DNAC_STAKE_PURPOSE_TAG_LEN;
    const size_t appended = truncate_appended ? 10 : appended_full;

    const size_t tx_len =
        74 +                                  /* header */
        1 + (64 + 8 + 64) +                   /* 1 input */
        1 +                                   /* 0 outputs */
        1 +                                   /* 0 witnesses */
        1 + (DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE) +  /* 1 signer */
        appended +
        1;                                    /* has_chain_def flag */

    uint8_t *buf = calloc(1, tx_len);
    CHECK_TRUE(buf != NULL);

    size_t off = 0;
    buf[off++] = 1;   /* version */
    buf[off++] = 4;   /* type = DNAC_TX_STAKE */
    /* timestamp(8) — leave zero */
    off += 8;
    /* tx_hash(64) — leave zero (apply doesn't verify hash) */
    off += 64;

    /* input_count=1 */
    buf[off++] = 1;
    /* nullifier: 0xAA fill */
    memset(buf + off, 0xAA, 64); off += 64;
    /* amount: arbitrary (e.g. 10M+fee) stored little-endian */
    uint64_t input_amt = DNAC_SELF_STAKE_AMOUNT + 100;
    memcpy(buf + off, &input_amt, 8); off += 8;
    /* token_id: zeros (native DNAC) */
    off += 64;

    /* output_count=0 */
    buf[off++] = 0;
    /* witness_count=0 */
    buf[off++] = 0;

    /* signer_count=1 */
    buf[off++] = 1;
    memcpy(buf + off, signer_pubkey, DNAC_PUBKEY_SIZE);
    off += DNAC_PUBKEY_SIZE;
    /* signature[4627] — zero-filled (apply_stake doesn't verify it) */
    off += DNAC_SIGNATURE_SIZE;

    /* Appended fields */
    if (truncate_appended) {
        /* Just 10 junk bytes so the offset parser doesn't choke but the
         * 83-byte required block is definitely short. */
        memset(buf + off, 0x7E, appended);
        off += appended;
    } else {
        buf[off++] = (uint8_t)((commission_bps >> 8) & 0xff);
        buf[off++] = (uint8_t)(commission_bps & 0xff);
        memcpy(buf + off, unstake_fp_raw, 64);
        off += 64;
        memcpy(buf + off, LOCAL_PURPOSE_TAG, DNAC_STAKE_PURPOSE_TAG_LEN);
        off += DNAC_STAKE_PURPOSE_TAG_LEN;
    }

    /* has_chain_def=0 */
    buf[off++] = 0;

    CHECK_EQ(off, tx_len);
    *len_out = tx_len;
    return buf;
}

int main(void) {
    char data_path[] = "/tmp/test_apply_stake_XXXXXX";
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
    CHECK_TRUE(w.db != NULL);

    /* ── Scenario 1: STAKE happy path — signer fp == unstake fp ───── */
    uint8_t signer_pubkey[DNAC_PUBKEY_SIZE];
    memset(signer_pubkey, 0x42, DNAC_PUBKEY_SIZE);

    uint8_t signer_fp_raw[64];
    qgp_sha3_512(signer_pubkey, DNAC_PUBKEY_SIZE, signer_fp_raw);

    uint16_t commission = 500;   /* 5% */
    const uint64_t block_height = 7;

    size_t tx_len = 0;
    uint8_t *tx = build_stake_tx(signer_pubkey, signer_fp_raw, commission,
                                  /*truncate_appended=*/0, &tx_len);

    /* Verify active_count starts at 0 */
    int active = -1;
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 0);

    /* Compute nullifier blob pointer for apply_tx_to_state */
    const uint8_t *nullifiers[1];
    uint8_t nul[64];
    memset(nul, 0xAA, 64);
    nullifiers[0] = nul;

    uint8_t tx_hash[64] = {0};

    /* Invoke apply_tx_to_state with STAKE type */
    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_STAKE,
                            nullifiers, 1,
                            tx, (uint32_t)tx_len,
                            block_height,
                            /*batch_ctx=*/NULL,
                            /*client_pubkey=*/NULL,
                            /*client_sig=*/NULL);
    CHECK_EQ(rc, 0);

    /* Verify validator row */
    dnac_validator_record_t got;
    rc = nodus_validator_get(&w, signer_pubkey, &got);
    CHECK_EQ(rc, 0);
    CHECK_EQ(got.self_stake, DNAC_SELF_STAKE_AMOUNT);
    CHECK_EQ(got.total_delegated, 0);
    CHECK_EQ(got.external_delegated, 0);
    CHECK_EQ(got.commission_bps, commission);
    CHECK_EQ(got.status, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(got.active_since_block, block_height);
    CHECK_TRUE(memcmp(got.pubkey, signer_pubkey, DNAC_PUBKEY_SIZE) == 0);

    /* Unstake destination pubkey should be the signer's (fp matches) */
    CHECK_TRUE(memcmp(got.unstake_destination_pubkey, signer_pubkey,
                      DNAC_PUBKEY_SIZE) == 0);

    /* Unstake destination fp should be the hex-encoding of signer_fp_raw */
    static const char hex_digits[] = "0123456789abcdef";
    char expected_fp[129];
    for (int i = 0; i < 64; i++) {
        expected_fp[2*i]     = hex_digits[signer_fp_raw[i] >> 4];
        expected_fp[2*i + 1] = hex_digits[signer_fp_raw[i] & 0xf];
    }
    expected_fp[128] = '\0';
    CHECK_EQ(strcmp((const char *)got.unstake_destination_fp, expected_fp), 0);

    /* Verify active_count bumped to 1 */
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 1);

    /* Verify empty reward row was seeded */
    dnac_reward_record_t r;
    rc = nodus_reward_get(&w, signer_pubkey, &r);
    CHECK_EQ(rc, 0);
    CHECK_EQ(r.validator_unclaimed, 0);
    CHECK_EQ(r.residual_dust, 0);
    CHECK_EQ(r.last_update_block, block_height);
    uint8_t zero_acc[16] = {0};
    CHECK_TRUE(memcmp(r.accumulator, zero_acc, 16) == 0);

    free(tx);

    /* ── Scenario 2: STAKE with third-party unstake destination ───── */
    uint8_t other_pubkey[DNAC_PUBKEY_SIZE];
    memset(other_pubkey, 0x55, DNAC_PUBKEY_SIZE);

    uint8_t other_fp_raw[64];
    memset(other_fp_raw, 0xBE, 64);   /* arbitrary (not signer's real fp) */

    tx = build_stake_tx(other_pubkey, other_fp_raw, 1000,
                        /*truncate_appended=*/0, &tx_len);

    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_STAKE,
                            nullifiers, 1,
                            tx, (uint32_t)tx_len,
                            block_height + 1,
                            NULL, NULL, NULL);
    CHECK_EQ(rc, 0);

    rc = nodus_validator_get(&w, other_pubkey, &got);
    CHECK_EQ(rc, 0);

    /* Destination pubkey MUST be zero since fp != SHA3-512(signer) */
    uint8_t zero_pk[DNAC_PUBKEY_SIZE] = {0};
    CHECK_TRUE(memcmp(got.unstake_destination_pubkey, zero_pk,
                      DNAC_PUBKEY_SIZE) == 0);

    /* active_count should now be 2 */
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 2);

    free(tx);

    /* ── Scenario 3: Malformed TX (truncated appended fields) ──────── */
    uint8_t third_pubkey[DNAC_PUBKEY_SIZE];
    memset(third_pubkey, 0x66, DNAC_PUBKEY_SIZE);
    tx = build_stake_tx(third_pubkey, other_fp_raw, 0,
                        /*truncate_appended=*/1, &tx_len);

    rc = apply_tx_to_state(&w, tx_hash, NODUS_W_TX_STAKE,
                            nullifiers, 1,
                            tx, (uint32_t)tx_len,
                            block_height + 2,
                            NULL, NULL, NULL);
    /* Expected to fail: truncated appended fields. */
    CHECK_TRUE(rc != 0);

    /* And no third validator row was inserted. */
    rc = nodus_validator_get(&w, third_pubkey, &got);
    CHECK_EQ(rc, 1);

    /* active_count should STILL be 2 (the failing attempt didn't commit).
     * NOTE: apply_tx_to_state itself doesn't roll back (the outer TX
     * wrapper does) — the nullifier/UTXO mutations prior to apply_stake
     * may have persisted, but the active_count bump is gated on
     * apply_stake's success so it stayed at 2. */
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 2);

    free(tx);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_stake: ALL CHECKS PASSED\n");
    return 0;
}
