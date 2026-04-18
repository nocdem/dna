/**
 * Nodus — Task 46 apply_epoch_boundary_transitions test
 *
 * Exercises the time-driven state transitions that run at every epoch
 * boundary inside finalize_block (after per-TX apply_tx_to_state calls,
 * before state_root recompute). Covers:
 *
 *   Scenario 1: Non-boundary block   (block_height % EPOCH_LENGTH != 0)
 *               -> no state changes; validators untouched.
 *   Scenario 2: Pending commission activation at the boundary where
 *               pending_effective_block matches current block. Another
 *               validator with a mismatching pending_effective_block
 *               stays pending.
 *   Scenario 3: RETIRING -> UNSTAKED graduation emits two locked+unlocked
 *               UTXOs, zeros validator_unclaimed, transitions status,
 *               decrements active_count.
 *   Scenario 4: Graduation emits both UTXOs even when unclaimed == 0
 *               (Rule Q supply symmetry).
 *
 * We call the internal `finalize_block` function so the test exercises
 * the real hook wiring (apply_epoch_boundary_transitions is static and
 * called from within finalize_block).
 *
 * The test bypasses STAKE/UNSTAKE TX submission and manipulates
 * validator/reward records directly via the CRUD helpers. This keeps
 * setup fast while still driving the actual production transition code
 * path end-to-end.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_bft_internal.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

/* Recursive remove using opendir/unlink — avoids invoking a shell. */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/* Build a minimal validator record. Caller fills in pubkey/status/
 * commission_bps/pending_* as needed. */
static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = DNAC_SELF_STAKE_AMOUNT;
    v->total_delegated         = 0;
    v->external_delegated      = 0;
    v->commission_bps          = 500;
    v->pending_commission_bps  = 0;
    v->pending_effective_block = 0;
    v->status                  = DNAC_VALIDATOR_ACTIVE;
    v->active_since_block      = 1;
    v->unstake_commit_block    = 0;
    /* Owner fingerprint derived from the pubkey, so we can look up the
     * graduation UTXOs by the same fp value the production code uses. */
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->last_validator_update_block = 0;
    v->consecutive_missed_epochs   = 0;
    v->last_signed_block           = 0;
}

/* Bump validator_stats.active_count by +1 so graduation decrement has
 * something to subtract from. */
static void bump_active_count(nodus_witness_t *w) {
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "UPDATE validator_stats SET value = value + 1 WHERE key = 'active_count'",
        NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "bump_active_count failed: %s\n", err ? err : "(null)");
        if (err) sqlite3_free(err);
        exit(1);
    }
}

static uint64_t read_active_count(nodus_witness_t *w) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT value FROM validator_stats WHERE key = 'active_count'",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    rc = sqlite3_step(stmt);
    CHECK_EQ(rc, SQLITE_ROW);
    uint64_t v = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return v;
}

/* Count UTXOs owned by the given fingerprint (hex, 128 chars). */
static int count_utxos_by_fp(nodus_witness_t *w, const char *fp) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM utxo_set WHERE owner = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_text(stmt, 1, fp, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    CHECK_EQ(rc, SQLITE_ROW);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

/* Sum of UTXO amounts owned by fp with unlock_block == expected_unlock. */
static uint64_t sum_utxos_by_fp_and_unlock(nodus_witness_t *w,
                                             const char *fp,
                                             uint64_t expected_unlock) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COALESCE(SUM(amount), 0) FROM utxo_set "
        "WHERE owner = ? AND unlock_block = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_text(stmt, 1, fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)expected_unlock);
    rc = sqlite3_step(stmt);
    CHECK_EQ(rc, SQLITE_ROW);
    uint64_t s = (uint64_t)sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return s;
}

/* Drive finalize_block via the internal API. We need a real tx_hash buffer
 * even though no TXs are applied (tx_count>=1 asserted). Caller passes
 * expected_height = block being committed. */
static int run_finalize(nodus_witness_t *w, uint64_t expected_height) {
    /* Dummy 1-TX batch: tx_hashes = 64 zero bytes; proposer_id = 32
     * bytes of 0xAA. finalize_block will write a block row — that is
     * fine, we never read it back. */
    uint8_t tx_hash[64];
    memset(tx_hash, 0x00, sizeof(tx_hash));
    uint8_t proposer_id[32];
    memset(proposer_id, 0xAA, sizeof(proposer_id));

    int rc = nodus_witness_db_begin(w);
    CHECK_EQ(rc, 0);

    rc = finalize_block(w, tx_hash, 1, proposer_id,
                        /*timestamp=*/1000, expected_height,
                        NULL, 0);
    if (rc != 0) {
        nodus_witness_db_rollback(w);
        return rc;
    }
    rc = nodus_witness_db_commit(w);
    return rc;
}

int main(void) {
    char data_path[] = "/tmp/test_apply_epoch_boundary_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xE0, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    /* ─────── Scenario 1: Non-boundary block — no state changes ─────── */

    /* Seed validator A with pending commission that SHOULD activate later. */
    dnac_validator_record_t va;
    init_validator(&va, /*pub_fill=*/0x11);
    va.commission_bps          = 500;
    va.pending_commission_bps  = 800;
    va.pending_effective_block = DNAC_EPOCH_LENGTH;   /* first boundary */
    rc = nodus_validator_insert(&w, &va);
    CHECK_EQ(rc, 0);
    bump_active_count(&w);

    /* Seed reward row for A (STAKE normally does this; we replicate
     * minimally). Validators don't strictly need one for this scenario
     * but lets later boundary runs be safely idempotent if A ever
     * transitions to RETIRING in a future test. */
    dnac_reward_record_t ra;
    memset(&ra, 0, sizeof(ra));
    memcpy(ra.validator_pubkey, va.pubkey, DNAC_PUBKEY_SIZE);
    rc = nodus_reward_upsert(&w, &ra);
    CHECK_EQ(rc, 0);

    /* Call finalize_block on a non-boundary block. EPOCH_LENGTH = 120; 50 is
     * safely non-boundary. */
    rc = run_finalize(&w, /*expected_height=*/50);
    CHECK_EQ(rc, 0);

    dnac_validator_record_t check;
    rc = nodus_validator_get(&w, va.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.commission_bps, 500);
    CHECK_EQ(check.pending_commission_bps, 800);
    CHECK_EQ(check.pending_effective_block, DNAC_EPOCH_LENGTH);
    CHECK_EQ(check.status, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(read_active_count(&w), 1);

    /* ─────── Scenario 2: Pending commission activation at boundary ─────── */

    /* Seed validator B with pending effective at DIFFERENT epoch (240).
     * At block_height=120 only validator A should promote; B stays pending. */
    dnac_validator_record_t vb;
    init_validator(&vb, /*pub_fill=*/0x22);
    vb.commission_bps          = 300;
    vb.pending_commission_bps  = 450;
    vb.pending_effective_block = DNAC_EPOCH_LENGTH * 2;   /* 240 */
    rc = nodus_validator_insert(&w, &vb);
    CHECK_EQ(rc, 0);
    bump_active_count(&w);

    rc = run_finalize(&w, /*expected_height=*/DNAC_EPOCH_LENGTH);  /* 120 */
    CHECK_EQ(rc, 0);

    /* A promoted. */
    rc = nodus_validator_get(&w, va.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.commission_bps, 800);
    CHECK_EQ(check.pending_commission_bps, 0);
    CHECK_EQ(check.pending_effective_block, 0);
    CHECK_EQ(check.status, DNAC_VALIDATOR_ACTIVE);

    /* B unchanged — its pending effective is at 240, not 120. */
    rc = nodus_validator_get(&w, vb.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.commission_bps, 300);
    CHECK_EQ(check.pending_commission_bps, 450);
    CHECK_EQ(check.pending_effective_block, DNAC_EPOCH_LENGTH * 2);
    CHECK_EQ(check.status, DNAC_VALIDATOR_ACTIVE);

    /* active_count untouched by commission activation. */
    CHECK_EQ(read_active_count(&w), 2);

    /* ─────── Scenario 3: RETIRING -> UNSTAKED graduation ─────── */

    /* Seed validator C in RETIRING status with a non-zero unclaimed
     * reward so we can verify both graduation UTXOs populate correctly. */
    dnac_validator_record_t vc;
    init_validator(&vc, /*pub_fill=*/0x33);
    vc.status               = DNAC_VALIDATOR_RETIRING;
    vc.unstake_commit_block = 130;   /* sometime after epoch 1 */
    rc = nodus_validator_insert(&w, &vc);
    CHECK_EQ(rc, 0);
    bump_active_count(&w);

    dnac_reward_record_t rc_rec;
    memset(&rc_rec, 0, sizeof(rc_rec));
    memcpy(rc_rec.validator_pubkey, vc.pubkey, DNAC_PUBKEY_SIZE);
    rc_rec.validator_unclaimed = 7777ULL;   /* some pending reward */
    rc_rec.last_update_block   = 130;
    rc = nodus_reward_upsert(&w, &rc_rec);
    CHECK_EQ(rc, 0);

    uint64_t before_active = read_active_count(&w);
    CHECK_EQ(before_active, 3);

    /* Save the fp hex so we can query UTXOs post-graduation. */
    char c_fp[129];
    memcpy(c_fp, vc.unstake_destination_fp, 129);

    /* Run at next epoch boundary (240). */
    const uint64_t grad_height = DNAC_EPOCH_LENGTH * 2;
    rc = run_finalize(&w, /*expected_height=*/grad_height);
    CHECK_EQ(rc, 0);

    /* Validator C flipped to UNSTAKED. */
    rc = nodus_validator_get(&w, vc.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.status, DNAC_VALIDATOR_UNSTAKED);

    /* Reward row's validator_unclaimed zeroed. */
    dnac_reward_record_t r_after;
    rc = nodus_reward_get(&w, vc.pubkey, &r_after);
    CHECK_EQ(rc, 0);
    CHECK_EQ(r_after.validator_unclaimed, 0);
    CHECK_EQ(r_after.last_update_block, grad_height);

    /* active_count decremented by 1. */
    CHECK_EQ(read_active_count(&w), before_active - 1);

    /* Two UTXOs emitted for vc's unstake_destination_fp:
     *   (a) locked 10M with unlock_block = grad_height + COOLDOWN
     *   (b) unlocked 7777 with unlock_block = 0
     */
    int utxo_count = count_utxos_by_fp(&w, c_fp);
    CHECK_EQ(utxo_count, 2);

    uint64_t locked_sum = sum_utxos_by_fp_and_unlock(
        &w, c_fp, grad_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS);
    CHECK_EQ(locked_sum, DNAC_SELF_STAKE_AMOUNT);

    uint64_t unlocked_sum = sum_utxos_by_fp_and_unlock(&w, c_fp, 0);
    CHECK_EQ(unlocked_sum, 7777ULL);

    /* Validator B's pending activation check (completeness — block 240 hits
     * its pending_effective_block=240, so it should have promoted as part
     * of Scenario 3's run_finalize). */
    rc = nodus_validator_get(&w, vb.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.commission_bps, 450);
    CHECK_EQ(check.pending_commission_bps, 0);
    CHECK_EQ(check.pending_effective_block, 0);

    /* ─────── Scenario 4: Graduation with zero validator_unclaimed ─────── */
    /* A second graduate whose unclaimed reward is 0 still emits two
     * UTXOs (Rule Q supply symmetry). */
    dnac_validator_record_t vd;
    init_validator(&vd, /*pub_fill=*/0x44);
    vd.status               = DNAC_VALIDATOR_RETIRING;
    vd.unstake_commit_block = 250;
    rc = nodus_validator_insert(&w, &vd);
    CHECK_EQ(rc, 0);
    bump_active_count(&w);

    dnac_reward_record_t rd;
    memset(&rd, 0, sizeof(rd));
    memcpy(rd.validator_pubkey, vd.pubkey, DNAC_PUBKEY_SIZE);
    rd.validator_unclaimed = 0;   /* no accrued reward */
    rc = nodus_reward_upsert(&w, &rd);
    CHECK_EQ(rc, 0);

    char d_fp[129];
    memcpy(d_fp, vd.unstake_destination_fp, 129);

    const uint64_t grad2_height = DNAC_EPOCH_LENGTH * 3;   /* 360 */
    rc = run_finalize(&w, /*expected_height=*/grad2_height);
    CHECK_EQ(rc, 0);

    rc = nodus_validator_get(&w, vd.pubkey, &check);
    CHECK_EQ(rc, 0);
    CHECK_EQ(check.status, DNAC_VALIDATOR_UNSTAKED);

    /* Two UTXOs even when unclaimed == 0. */
    CHECK_EQ(count_utxos_by_fp(&w, d_fp), 2);
    uint64_t d_locked = sum_utxos_by_fp_and_unlock(
        &w, d_fp, grad2_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS);
    CHECK_EQ(d_locked, DNAC_SELF_STAKE_AMOUNT);
    uint64_t d_unlocked = sum_utxos_by_fp_and_unlock(&w, d_fp, 0);
    CHECK_EQ(d_unlocked, 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_apply_epoch_boundary: ALL CHECKS PASSED\n");
    return 0;
}
