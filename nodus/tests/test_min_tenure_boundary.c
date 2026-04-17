/**
 * Nodus — Task 30 MIN_TENURE (Rule R) committee eligibility boundary test
 *
 * Rule R (design §3.7 / committee selection): a validator is eligible for
 * the next committee epoch only when
 *
 *   active_since_block + DNAC_MIN_TENURE_BLOCKS <= lookback_block
 *
 * i.e. the validator must have been in ACTIVE status for at least
 * MIN_TENURE (240 blocks ≈ 2 × EPOCH_LENGTH) before the committee lookback.
 *
 * Task 12's test_validator_db.c already has a general MIN_TENURE scenario.
 * This test is a FOCUSED BOUNDARY regression:
 *
 *   Validator A: active_since = X, where X + 240 == lookback → eligible.
 *   Validator B: active_since = X + 1, where X + 1 + 240 > lookback → excluded.
 *
 * This nails down the boundary behavior of the SQL WHERE clause
 * (strict `<=`) — any off-by-one drift in the query predicate would flip
 * which of A or B is returned.
 *
 * Task 40 (Phase 8 STAKE state-apply) populates active_since_block =
 * current_block on validator insert; this test validates that once such
 * a value is written, the committee-eligibility query observes the
 * boundary correctly.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "dnac/validator.h"
#include "dnac/dnac.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); exit(1); \
    } } while (0)

static void make_validator(dnac_validator_record_t *v,
                           uint8_t pub_fill,
                           uint64_t active_since) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = DNAC_SELF_STAKE_AMOUNT;  /* 10M */
    v->total_delegated         = 0;
    v->external_delegated      = 0;
    v->commission_bps          = 500;
    v->pending_commission_bps  = 0;
    v->pending_effective_block = 0;
    v->status                  = DNAC_VALIDATOR_ACTIVE;
    v->active_since_block      = active_since;
    v->unstake_commit_block    = 0;
    memset(v->unstake_destination_fp, 'a', 128);
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, 0x77, DNAC_PUBKEY_SIZE);
    v->last_validator_update_block = 0;
    v->consecutive_missed_epochs   = 0;
    v->last_signed_block           = 0;
}

static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

int main(void) {
    char data_path[] = "/tmp/test_min_tenure_boundary_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xD3, sizeof(chain_id));

    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK(w.db != NULL);

    /* ── Pick a lookback_block well above MIN_TENURE for definiteness. */
    const uint64_t lookback = 5000ULL;
    const uint64_t min_tenure = DNAC_MIN_TENURE_BLOCKS;

    /* ── Validator A: active_since = lookback − min_tenure.
     *    A.active_since + min_tenure == lookback → boundary ELIGIBLE. */
    dnac_validator_record_t va;
    make_validator(&va, /*pub_fill=*/0xAA, /*active_since=*/lookback - min_tenure);
    rc = nodus_validator_insert(&w, &va);
    CHECK_EQ(rc, 0);

    /* ── Validator B: active_since = lookback − min_tenure + 1.
     *    B.active_since + min_tenure == lookback + 1 > lookback → EXCLUDED. */
    dnac_validator_record_t vb;
    make_validator(&vb, /*pub_fill=*/0xBB,
                   /*active_since=*/lookback - min_tenure + 1ULL);
    rc = nodus_validator_insert(&w, &vb);
    CHECK_EQ(rc, 0);

    /* ── Query top-7 validators eligible at `lookback`. ──────────────── */
    dnac_validator_record_t top[7];
    int count = -1;
    rc = nodus_validator_top_n(&w, 7, lookback, top, &count);
    CHECK_EQ(rc, 0);

    /* Exactly one validator should be returned — A (at boundary), not B. */
    CHECK_EQ(count, 1);
    CHECK_EQ(top[0].pubkey[0], 0xAA);
    CHECK_EQ(top[0].active_since_block, lookback - min_tenure);

    /* ── Bump lookback by +1 → B now becomes eligible too. ───────────── */
    const uint64_t lookback2 = lookback + 1ULL;
    rc = nodus_validator_top_n(&w, 7, lookback2, top, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 2);
    /* Both have identical stake (10M); tiebreak is pubkey ASC. 0xAA < 0xBB. */
    CHECK_EQ(top[0].pubkey[0], 0xAA);
    CHECK_EQ(top[1].pubkey[0], 0xBB);

    /* ── Drop lookback by 1 → even A becomes ineligible. ─────────────── */
    const uint64_t lookback3 = lookback - 1ULL;
    rc = nodus_validator_top_n(&w, 7, lookback3, top, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_min_tenure_boundary: ALL CHECKS PASSED\n");
    return 0;
}
