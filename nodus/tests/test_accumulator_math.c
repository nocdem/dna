/**
 * Nodus - Task 49 accumulator update + liveness gate tests.
 *
 * Scenarios:
 *   (1) Single committee, no delegators: per_member -> validator_unclaimed.
 *   (2) Delegators + commission: piece-sum exact, dust carries.
 *   (3) Liveness gate drops stale signer; share goes to attenders.
 *   (4) All offline -> pool rolls forward.
 *   (5) Residual dust carries across two blocks.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_bft_internal.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_u128.h"

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
    unsigned long long _a = (unsigned long long)(a), \
                       _b = (unsigned long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %llu != %llu\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

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

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                            uint64_t active_since,
                            uint64_t total_delegated,
                            uint16_t commission_bps) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = DNAC_SELF_STAKE_AMOUNT;
    v->total_delegated         = total_delegated;
    v->external_delegated      = total_delegated;
    v->commission_bps          = commission_bps;
    v->status                  = DNAC_VALIDATOR_ACTIVE;
    v->active_since_block      = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2*i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2*i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

static int run_finalize(nodus_witness_t *w, uint64_t expected_height) {
    uint8_t tx_hash[64];
    memset(tx_hash, 0x00, sizeof(tx_hash));
    uint8_t proposer_id[32];
    memset(proposer_id, 0xAA, sizeof(proposer_id));

    int rc = nodus_witness_db_begin(w);
    CHECK_EQ(rc, 0);

    rc = finalize_block(w, tx_hash, 1, proposer_id, 1000, expected_height,
                        NULL, 0);
    if (rc != 0) {
        nodus_witness_db_rollback(w);
        return rc;
    }
    return nodus_witness_db_commit(w);
}

/* Phase 10 / Task 53 — tests add validators dynamically across
 * scenarios within the same epoch; committee is frozen per epoch by
 * design, but for test pedagogy we invalidate the cache after each
 * insert so that the new validator becomes visible on the next
 * finalize. Production paths never invalidate mid-epoch. */
static void invalidate_committee_cache(nodus_witness_t *w) {
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;
}

static void bump_active_count(nodus_witness_t *w) {
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "UPDATE validator_stats SET value = value + 1 WHERE key = 'active_count'",
        NULL, NULL, &err);
    CHECK(rc == SQLITE_OK);
    if (err) sqlite3_free(err);
}

/* Directly set last_signed_block via SQL so we don't have to simulate
 * a full BFT round. The production path is covered by Task 48. */
static void set_last_signed(nodus_witness_t *w, const uint8_t *pubkey,
                             uint64_t val) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET last_signed_block = ? WHERE pubkey = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, (int64_t)val);
    sqlite3_bind_blob(stmt, 2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

/* Override self_stake + total_delegated (STAKE normally enforces these
 * tight; we want to craft them for math scenarios). */
static void force_stake(nodus_witness_t *w, const uint8_t *pubkey,
                         uint64_t self_stake,
                         uint64_t total_delegated) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET self_stake = ?, total_delegated = ?, "
        "external_delegated = ? WHERE pubkey = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, (int64_t)self_stake);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_delegated);
    sqlite3_bind_int64(stmt, 3, (int64_t)total_delegated);
    sqlite3_bind_blob(stmt, 4, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

int main(void) {
    char data_path[] = "/tmp/test_accumulator_math_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    /* Phase 10 / Task 53 — committee cache sentinel. Production path
     * sets this in nodus_witness_init; the test bypasses init to stay
     * standalone, so apply the same sentinel here. */
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0xE2, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* Phase 10 / Task 51 — seed the lookback block so committee
     * computation at e_start = 480 (block heights 500..505 all map to
     * this epoch) can read a state_root. lookback = e_start - EPOCH_LENGTH
     * - 1 = 359. */
    {
        sqlite3_stmt *stmt = NULL;
        int rcb = sqlite3_prepare_v2(w.db,
            "INSERT OR REPLACE INTO blocks "
            "(height, tx_root, tx_count, timestamp, proposer_id, "
            " prev_hash, state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
            -1, &stmt, NULL);
        CHECK_EQ(rcb, SQLITE_OK);
        uint8_t zeros[64] = {0};
        uint8_t proposer[32];
        memset(proposer, 0xAA, sizeof(proposer));
        uint8_t seed[64];
        memset(seed, 0x77, sizeof(seed));
        sqlite3_bind_int64(stmt, 1, (int64_t)359);
        sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, 1000);
        sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 6, seed, 64, SQLITE_STATIC);
        CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
    }

    /* Scenario 1 */
    printf("  single validator, no delegators\n");
    dnac_validator_record_t va;
    init_validator(&va, 0x01, 1, 0, 0);
    CHECK_EQ(nodus_validator_insert(&w, &va), 0);
    bump_active_count(&w);
    invalidate_committee_cache(&w);
    dnac_reward_record_t ra0;
    memset(&ra0, 0, sizeof(ra0));
    memcpy(ra0.validator_pubkey, va.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &ra0), 0);

    set_last_signed(&w, va.pubkey, 499);

    w.block_fee_pool = 1000;
    CHECK_EQ(run_finalize(&w, 500), 0);

    dnac_reward_record_t ra;
    CHECK_EQ(nodus_reward_get(&w, va.pubkey, &ra), 0);
    CHECK_EQ(ra.validator_unclaimed, 1000);
    CHECK_EQ(ra.residual_dust, 0);
    CHECK_EQ(w.block_fee_pool, 0);

    /* Scenario 2 */
    printf("  delegators + commission — piece-sum exact, dust carries\n");
    dnac_validator_record_t vb;
    init_validator(&vb, 0x02, 1, 500, 2000);
    vb.self_stake = 0;
    CHECK_EQ(nodus_validator_insert(&w, &vb), 0);
    bump_active_count(&w);
    invalidate_committee_cache(&w);
    /* insert set self_stake from the record, but the DB column is
     * NOT NULL with default -> re-enforce via our helper to be safe. */
    force_stake(&w, vb.pubkey, 0, 500);
    dnac_reward_record_t rb0;
    memset(&rb0, 0, sizeof(rb0));
    memcpy(rb0.validator_pubkey, vb.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &rb0), 0);

    set_last_signed(&w, va.pubkey, 0);
    set_last_signed(&w, vb.pubkey, 500);

    w.block_fee_pool = 700;
    CHECK_EQ(run_finalize(&w, 501), 0);

    dnac_reward_record_t rb;
    CHECK_EQ(nodus_reward_get(&w, vb.pubkey, &rb), 0);
    /* total_stake = 500, delegator_share_raw = 700*500/500 = 700
     * commission_skim = 700 * 2000 / 10000 = 140
     * delegator_pool  = 560
     * validator_share = per_member - delegator_pool = 700 - 560 = 140. */
    CHECK_EQ(rb.validator_unclaimed, 140);

    uint64_t per_member = 700;
    uint64_t validator_share = rb.validator_unclaimed;
    uint64_t delegator_pool = per_member - validator_share;
    CHECK_EQ(validator_share + delegator_pool, per_member);

    qgp_u128_t expected_num = qgp_u128_shl(qgp_u128_from_u64(560), 64);
    uint64_t expected_rem = 0;
    qgp_u128_t expected_inc = qgp_u128_div_u64(expected_num, 500, &expected_rem);
    qgp_u128_t actual_acc = qgp_u128_deserialize_be(rb.accumulator);
    CHECK(qgp_u128_cmp(actual_acc, expected_inc) == 0);
    CHECK_EQ(rb.residual_dust, expected_rem);

    /* Scenario 3 */
    printf("  liveness gate drops stale signer\n");
    dnac_validator_record_t vc;
    init_validator(&vc, 0x03, 1, 0, 0);
    CHECK_EQ(nodus_validator_insert(&w, &vc), 0);
    bump_active_count(&w);
    invalidate_committee_cache(&w);
    dnac_reward_record_t rc0;
    memset(&rc0, 0, sizeof(rc0));
    memcpy(rc0.validator_pubkey, vc.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &rc0), 0);

    /* B last_signed=480 at block 502 -> min_signed=486 -> B excluded. */
    set_last_signed(&w, vb.pubkey, 480);
    set_last_signed(&w, vc.pubkey, 501);

    dnac_reward_record_t rc_before, rb_before;
    CHECK_EQ(nodus_reward_get(&w, vc.pubkey, &rc_before), 0);
    CHECK_EQ(nodus_reward_get(&w, vb.pubkey, &rb_before), 0);

    w.block_fee_pool = 100;
    CHECK_EQ(run_finalize(&w, 502), 0);

    CHECK_EQ(nodus_reward_get(&w, vb.pubkey, &rb), 0);
    CHECK_EQ(rb.validator_unclaimed, rb_before.validator_unclaimed);

    dnac_reward_record_t rc_after;
    CHECK_EQ(nodus_reward_get(&w, vc.pubkey, &rc_after), 0);
    CHECK_EQ(rc_after.validator_unclaimed,
              rc_before.validator_unclaimed + 100);
    CHECK_EQ(w.block_fee_pool, 0);

    /* Scenario 4 */
    printf("  all offline — pool rolls forward\n");
    set_last_signed(&w, va.pubkey, 0);
    set_last_signed(&w, vb.pubkey, 0);
    set_last_signed(&w, vc.pubkey, 0);

    w.block_fee_pool = 999;
    CHECK_EQ(run_finalize(&w, 503), 0);
    CHECK_EQ(w.block_fee_pool, 999);

    /* Scenario 5 — dust carry across blocks */
    printf("  residual dust carries across blocks\n");
    w.block_fee_pool = 0;

    dnac_validator_record_t vd;
    init_validator(&vd, 0x04, 1, 7, 0);
    vd.self_stake = 0;
    CHECK_EQ(nodus_validator_insert(&w, &vd), 0);
    bump_active_count(&w);
    invalidate_committee_cache(&w);
    force_stake(&w, vd.pubkey, 0, 7);
    dnac_reward_record_t rd0;
    memset(&rd0, 0, sizeof(rd0));
    memcpy(rd0.validator_pubkey, vd.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &rd0), 0);

    set_last_signed(&w, vd.pubkey, 503);

    /* Block 504 pool=100. num1 = (100<<64), inc1 = num1/7, rem1 = num1%7. */
    w.block_fee_pool = 100;
    CHECK_EQ(run_finalize(&w, 504), 0);
    dnac_reward_record_t rd1;
    CHECK_EQ(nodus_reward_get(&w, vd.pubkey, &rd1), 0);

    qgp_u128_t num1 = qgp_u128_shl(qgp_u128_from_u64(100), 64);
    uint64_t rem1 = 0;
    qgp_u128_t inc1 = qgp_u128_div_u64(num1, 7, &rem1);
    CHECK_EQ(rd1.residual_dust, rem1);
    qgp_u128_t acc1 = qgp_u128_deserialize_be(rd1.accumulator);
    CHECK(qgp_u128_cmp(acc1, inc1) == 0);

    /* Block 505 pool=50. num2 = (50<<64) + rem1. */
    set_last_signed(&w, vd.pubkey, 504);
    w.block_fee_pool = 50;
    CHECK_EQ(run_finalize(&w, 505), 0);
    dnac_reward_record_t rd2;
    CHECK_EQ(nodus_reward_get(&w, vd.pubkey, &rd2), 0);

    qgp_u128_t num2 = qgp_u128_shl(qgp_u128_from_u64(50), 64);
    num2 = qgp_u128_add(num2, qgp_u128_from_u64(rem1));
    uint64_t rem2 = 0;
    qgp_u128_t inc2 = qgp_u128_div_u64(num2, 7, &rem2);
    CHECK_EQ(rd2.residual_dust, rem2);

    qgp_u128_t expected_acc = qgp_u128_add(inc1, inc2);
    qgp_u128_t acc2 = qgp_u128_deserialize_be(rd2.accumulator);
    CHECK(qgp_u128_cmp(acc2, expected_acc) == 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("\nAll Task 49 accumulator math tests passed.\n");
    return 0;
}
