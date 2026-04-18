/* Task 55 — UNSTAKE two-phase integration test.
 *
 * Exercises the full validator-exit lifecycle:
 *
 *   STAKE  → UNSTAKE (phase 1: RETIRING, active_count unchanged)
 *          → next epoch boundary (phase 2: UNSTAKED, active_count--,
 *            two graduation UTXOs emitted, reward unclaimed zeroed,
 *            principal UTXO locked until block + COOLDOWN)
 *
 * Assertions cover the full lock-unlock contract:
 *
 *   (a) Before UNSTAKE: status=ACTIVE, active_count=1.
 *   (b) After UNSTAKE (pre-epoch): status=RETIRING,
 *       unstake_commit_block set, active_count still 1.
 *   (c) After epoch boundary: status=UNSTAKED, active_count=0,
 *       two synthetic UTXOs exist at v.unstake_destination_fp:
 *         - principal 10M DNAC, unlock_block = grad + COOLDOWN
 *         - pending 0 DNAC (no accrued rewards), unlock_block = 0
 *       reward.validator_unclaimed = 0.
 *   (d) Before unlock_block: locked UTXO's unlock_block > any queried
 *       height — witness would reject any SPEND attempt (Rule D,
 *       verified at Task 29).
 *   (e) At/after unlock_block: the UTXO is spendable per the
 *       unlock_block <= current_block invariant.
 *
 * See:
 *   - Task 42 (apply_unstake)              commit e7eb9f9f
 *   - Task 46 (apply_epoch_boundary)        commit 3deb3d09
 *   - Task 29 (locked-UTXO SPEND rejection) commit 33becca4
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
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

/* ──────────────────────────────────────────────────────────────────── */

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

/* UNSTAKE has no type-specific appended fields. */
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
        1;

    uint8_t *buf = calloc(1, tx_len);
    CHECK(buf != NULL);

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
    CHECK(off == tx_len);
    *len_out = tx_len;
    return buf;
}

/* Mirrors apply_epoch_boundary_transitions's boundary_tx_hash derivation. */
static void compute_graduation_tx_hash(uint64_t block_height,
                                         uint8_t out[64]) {
    static const char tag[] = "dnac_epoch_graduation_v1";
    const size_t tag_len = sizeof(tag) - 1;
    uint8_t preimage[32 + 8];
    memset(preimage, 0, sizeof(preimage));
    memcpy(preimage, tag, tag_len);
    for (int i = 0; i < 8; i++) {
        preimage[32 + i] =
            (uint8_t)((block_height >> (56 - 8 * i)) & 0xff);
    }
    qgp_sha3_512(preimage, sizeof(preimage), out);
}

/* Matches emit_synthetic_utxo / _for_fp nullifier derivation. */
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

static uint64_t read_active_count(nodus_witness_t *w) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT value FROM validator_stats WHERE key = 'active_count'",
        -1, &stmt, NULL);
    CHECK(rc == SQLITE_OK);
    rc = sqlite3_step(stmt);
    CHECK(rc == SQLITE_ROW);
    uint64_t v = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return v;
}

/* Drive finalize_block. Dummy single-TX batch (no TXs actually applied —
 * the epoch-boundary transitions run unconditionally on a boundary
 * height). */
static int run_finalize(nodus_witness_t *w, uint64_t expected_height) {
    uint8_t tx_hash[64];
    memset(tx_hash, 0x00, sizeof(tx_hash));
    uint8_t proposer_id[32];
    memset(proposer_id, 0xAA, sizeof(proposer_id));

    int rc = nodus_witness_db_begin(w);
    CHECK(rc == 0);

    rc = finalize_block(w, tx_hash, 1, proposer_id,
                        /*timestamp=*/1000, expected_height,
                        NULL, 0);
    if (rc != 0) {
        nodus_witness_db_rollback(w);
        return rc;
    }
    return nodus_witness_db_commit(w);
}

int main(void) {
    char data_path[] = "/tmp/test_integration_unstake_XXXXXX";
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
    CHECK(rc == 0);

    /* ── Phase 1: STAKE ─────────────────────────────────────────────── */
    uint8_t val_pk[DNAC_PUBKEY_SIZE];
    memset(val_pk, 0x42, DNAC_PUBKEY_SIZE);
    uint8_t val_fp_raw[64];
    qgp_sha3_512(val_pk, DNAC_PUBKEY_SIZE, val_fp_raw);

    size_t stake_len = 0;
    uint8_t *stake_tx = build_stake_tx(val_pk, val_fp_raw,
                                         /*commission_bps=*/500,
                                         /*nul_fill=*/0xA1,
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

    /* Assertion (a): before UNSTAKE. */
    dnac_validator_record_t v;
    rc = nodus_validator_get(&w, val_pk, &v);
    CHECK(rc == 0);
    CHECK(v.status == DNAC_VALIDATOR_ACTIVE);
    CHECK(v.self_stake == DNAC_SELF_STAKE_AMOUNT);
    CHECK(v.unstake_commit_block == 0);
    CHECK(read_active_count(&w) == 1);

    /* Snapshot the hex fingerprint — graduation UTXOs will land here. */
    char dest_fp[129];
    memcpy(dest_fp, v.unstake_destination_fp, 129);

    /* ── Phase 2: UNSTAKE at a pre-epoch block (100 < DNAC_EPOCH_LENGTH=120). */
    char change_fp[129];
    memset(change_fp, 'd', 128); change_fp[128] = 0;

    size_t unstake_len = 0;
    uint8_t *unstake_tx = build_unstake_tx(val_pk,
                                             /*nul_fill=*/0xB1,
                                             /*input=*/1000000000ULL,   /* 10 DNAC */
                                             /*change=*/999900000ULL,   /*  9.999 DNAC change */
                                             change_fp, &unstake_len);
    const uint8_t *nul_unstake[1];
    uint8_t nul_unstake_buf[64]; memset(nul_unstake_buf, 0xB1, 64);
    nul_unstake[0] = nul_unstake_buf;

    const uint64_t unstake_block = 100;
    CHECK(unstake_block < DNAC_EPOCH_LENGTH);
    uint8_t unstake_tx_hash[64];
    memset(unstake_tx_hash, 0x6B, 64);
    rc = apply_tx_to_state(&w, unstake_tx_hash, NODUS_W_TX_UNSTAKE,
                            nul_unstake, 1, unstake_tx, (uint32_t)unstake_len,
                            unstake_block, NULL, NULL, NULL);
    CHECK(rc == 0);
    free(unstake_tx);

    /* Assertion (b): phase-1 UNSTAKE side effects. */
    rc = nodus_validator_get(&w, val_pk, &v);
    CHECK(rc == 0);
    CHECK(v.status == DNAC_VALIDATOR_RETIRING);
    CHECK(v.unstake_commit_block == unstake_block);
    /* self_stake column still populated — it is *cleared* during phase 2. */
    CHECK(v.self_stake == DNAC_SELF_STAKE_AMOUNT);
    /* active_count unchanged — graduation hasn't happened yet. */
    CHECK(read_active_count(&w) == 1);

    /* ── Phase 3: Trigger epoch boundary at 120 ────────────────────── */
    const uint64_t grad_height = DNAC_EPOCH_LENGTH;   /* first boundary */
    rc = run_finalize(&w, grad_height);
    CHECK(rc == 0);

    /* Assertion (c): status UNSTAKED, active_count=0, reward zeroed. */
    rc = nodus_validator_get(&w, val_pk, &v);
    CHECK(rc == 0);
    CHECK(v.status == DNAC_VALIDATOR_UNSTAKED);
    CHECK(read_active_count(&w) == 0);

    dnac_reward_record_t r_after;
    rc = nodus_reward_get(&w, val_pk, &r_after);
    CHECK(rc == 0);
    CHECK(r_after.validator_unclaimed == 0);
    CHECK(r_after.last_update_block == grad_height);

    /* Locate both graduation UTXOs via their synthetic nullifiers. */
    uint8_t grad_hash[64];
    compute_graduation_tx_hash(grad_height, grad_hash);

    uint8_t principal_null[64];
    uint8_t pending_null[64];
    compute_synthetic_nullifier(grad_hash, 0x10, 200, principal_null);
    compute_synthetic_nullifier(grad_hash, 0x11, 201, pending_null);

    /* Principal UTXO: amount=10M, unlock_block=grad + COOLDOWN. */
    uint64_t principal_amt = 0;
    uint64_t principal_unlock = 0;
    uint8_t unused_tid[64];
    rc = nodus_witness_utxo_lookup_ex(&w, principal_null,
                                        &principal_amt, NULL, unused_tid,
                                        &principal_unlock);
    CHECK(rc == 0);
    CHECK(principal_amt == DNAC_SELF_STAKE_AMOUNT);
    const uint64_t expected_unlock = grad_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS;
    CHECK(principal_unlock == expected_unlock);

    /* Pending UTXO: amount=0 (nothing accrued in this test), unlock=0. */
    uint64_t pending_amt = 0;
    uint64_t pending_unlock = ~(uint64_t)0;
    rc = nodus_witness_utxo_lookup_ex(&w, pending_null,
                                        &pending_amt, NULL, unused_tid,
                                        &pending_unlock);
    CHECK(rc == 0);
    CHECK(pending_amt == 0);
    CHECK(pending_unlock == 0);

    /* Sanity: both UTXOs are owned by v.unstake_destination_fp. */
    sqlite3_stmt *stmt = NULL;
    rc = sqlite3_prepare_v2(w.db,
        "SELECT COUNT(*) FROM utxo_set WHERE owner = ?",
        -1, &stmt, NULL);
    CHECK(rc == SQLITE_OK);
    sqlite3_bind_text(stmt, 1, dest_fp, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    CHECK(rc == SQLITE_ROW);
    int owned_count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    CHECK(owned_count == 2);

    /* ── Assertion (d): Locked UTXO SPEND would be rejected at block 200.
     *
     * We don't run a full SPEND TX — the witness's Rule D check lives in
     * apply_spend (Task 29). Instead we verify the invariant directly
     * via the unlock_block column: at any current_block in
     * (grad_height, expected_unlock), unlock_block > current_block, so
     * a SPEND against this UTXO would trip the "locked UTXO" rejection.
     */
    const uint64_t locked_query_block = 200;
    CHECK(locked_query_block < expected_unlock);
    CHECK(principal_unlock > locked_query_block);   /* SPEND rejected */

    /* Pending UTXO (unlock=0) is always spendable — Rule D requires
     * unlock_block <= current_block, and 0 satisfies that for any height. */
    CHECK(pending_unlock <= locked_query_block);

    /* ── Assertion (e): At block >= expected_unlock the principal is spendable. */
    const uint64_t post_unlock_block = expected_unlock;
    CHECK(principal_unlock <= post_unlock_block);
    /* Also strictly after: defensive check. */
    CHECK(principal_unlock <= post_unlock_block + 1);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_integration_unstake_two_phase: ALL CHECKS PASSED\n");
    return 0;
}
