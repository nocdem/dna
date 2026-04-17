/**
 * Nodus — Task 12 validator CRUD test
 *
 * Exercises nodus_validator_{insert,get,update,top_n,active_count}
 * against a real witness chain DB under a mkdtemp tmp directory.
 * Mirrors test_stake_schema.c's init pattern.
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

#define CHECK_MEM_EQ(a, b, n) do { \
    if (memcmp((a),(b),(n)) != 0) { \
        fprintf(stderr, "CHECK_MEM_EQ fail at %s:%d (n=%zu)\n", \
                __FILE__, __LINE__, (size_t)(n)); \
        exit(1); \
    } } while (0)

/* rm -rf the test data directory (best-effort). */
static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

/* Populate a validator record with deterministic test data.
 *   pub_fill:     fill byte for pubkey
 *   dest_fill:    fill byte for unstake_destination_pubkey
 *   self_stake:   self_stake value
 *   ext_deleg:    external_delegated value
 *   active_since: active_since_block value
 *   status:       dnac_validator_status_t value
 */
static void make_validator(dnac_validator_record_t *v,
                           uint8_t pub_fill,
                           uint8_t dest_fill,
                           uint64_t self_stake,
                           uint64_t ext_deleg,
                           uint64_t active_since,
                           uint8_t status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = self_stake;
    v->total_delegated         = ext_deleg;  /* no self delegation by default */
    v->external_delegated      = ext_deleg;
    v->commission_bps          = 500;   /* 5% */
    v->pending_commission_bps  = 0;
    v->pending_effective_block = 0;
    v->status                  = status;
    v->active_since_block      = active_since;
    v->unstake_commit_block    = 0;
    /* TEXT column, must be NUL-terminated ASCII. Use a fake 128-hex string. */
    memset(v->unstake_destination_fp, 'a', 128);
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, dest_fill, DNAC_PUBKEY_SIZE);
    v->last_validator_update_block = 0;
    v->consecutive_missed_epochs   = 0;
    v->last_signed_block           = 0;
}

/* Assert two validator records are byte-equal (all fields). */
static void check_record_eq(const dnac_validator_record_t *a,
                            const dnac_validator_record_t *b) {
    CHECK_MEM_EQ(a->pubkey, b->pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(a->self_stake, b->self_stake);
    CHECK_EQ(a->total_delegated, b->total_delegated);
    CHECK_EQ(a->external_delegated, b->external_delegated);
    CHECK_EQ(a->commission_bps, b->commission_bps);
    CHECK_EQ(a->pending_commission_bps, b->pending_commission_bps);
    CHECK_EQ(a->pending_effective_block, b->pending_effective_block);
    CHECK_EQ(a->status, b->status);
    CHECK_EQ(a->active_since_block, b->active_since_block);
    CHECK_EQ(a->unstake_commit_block, b->unstake_commit_block);
    CHECK_EQ(strcmp((const char *)a->unstake_destination_fp,
                    (const char *)b->unstake_destination_fp), 0);
    CHECK_MEM_EQ(a->unstake_destination_pubkey,
                 b->unstake_destination_pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(a->last_validator_update_block, b->last_validator_update_block);
    CHECK_EQ(a->consecutive_missed_epochs, b->consecutive_missed_epochs);
    CHECK_EQ(a->last_signed_block, b->last_signed_block);
}

int main(void) {
    char data_path[] = "/tmp/test_validator_db_XXXXXX";
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

    /* ── Scenario 1: Insert + get roundtrip ────────────────────────── */
    dnac_validator_record_t v;
    make_validator(&v, /*pub_fill=*/0x11, /*dest_fill=*/0x22,
                   /*self_stake=*/1000000, /*ext_deleg=*/50000,
                   /*active_since=*/100, DNAC_VALIDATOR_ACTIVE);

    rc = nodus_validator_insert(&w, &v);
    CHECK_EQ(rc, 0);

    dnac_validator_record_t fetched;
    rc = nodus_validator_get(&w, v.pubkey, &fetched);
    CHECK_EQ(rc, 0);
    check_record_eq(&v, &fetched);

    /* ── Scenario 2: Get non-existent ──────────────────────────────── */
    uint8_t absent_pubkey[DNAC_PUBKEY_SIZE];
    memset(absent_pubkey, 0xFE, DNAC_PUBKEY_SIZE);
    rc = nodus_validator_get(&w, absent_pubkey, &fetched);
    CHECK_EQ(rc, 1);

    /* ── Scenario 3: Update existing ───────────────────────────────── */
    v.commission_bps = 1000;           /* 10% */
    v.total_delegated = 999999;
    v.last_signed_block = 42;
    rc = nodus_validator_update(&w, &v);
    CHECK_EQ(rc, 0);

    rc = nodus_validator_get(&w, v.pubkey, &fetched);
    CHECK_EQ(rc, 0);
    check_record_eq(&v, &fetched);

    /* ── Scenario 4: Update non-existent ───────────────────────────── */
    dnac_validator_record_t ghost;
    make_validator(&ghost, /*pub_fill=*/0xAB, /*dest_fill=*/0xCD,
                   500, 0, 0, DNAC_VALIDATOR_ACTIVE);
    rc = nodus_validator_update(&w, &ghost);
    CHECK_EQ(rc, 1);

    /* ── Scenario 5: Top-N ranking ─────────────────────────────────── */
    /* Start fresh DB to avoid interference from scenarios above. */
    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);
    char data_path2[] = "/tmp/test_validator_db_XXXXXX";
    CHECK_TRUE(mkdtemp(data_path2) != NULL);
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path2);
    rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    /* Insert 5 validators with ascending (self_stake + external_delegated).
     * Use active_since small enough that all clear the tenure filter. */
    dnac_validator_record_t vs[5];
    for (int i = 0; i < 5; i++) {
        /* Unique pubkey via fill byte (0x31 + i). Same destination fill. */
        make_validator(&vs[i],
                       /*pub_fill=*/(uint8_t)(0x31 + i),
                       /*dest_fill=*/0x77,
                       /*self_stake=*/1000 + (uint64_t)(i * 10),
                       /*ext_deleg=*/0,
                       /*active_since=*/0,
                       DNAC_VALIDATOR_ACTIVE);
        rc = nodus_validator_insert(&w, &vs[i]);
        CHECK_EQ(rc, 0);
    }

    /* lookback_block must be >= active_since + MIN_TENURE, i.e. >= 240. */
    dnac_validator_record_t top[3];
    int count = 0;
    rc = nodus_validator_top_n(&w, 3,
                               /*lookback_block=*/1000, top, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 3);

    /* Highest rank first: i=4 (1040), i=3 (1030), i=2 (1020). */
    CHECK_EQ(top[0].self_stake, (uint64_t)1040);
    CHECK_EQ(top[1].self_stake, (uint64_t)1030);
    CHECK_EQ(top[2].self_stake, (uint64_t)1020);

    /* ── Scenario 6: Top-N tiebreak on pubkey ASC ───────────────────── */
    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path2);
    char data_path3[] = "/tmp/test_validator_db_XXXXXX";
    CHECK_TRUE(mkdtemp(data_path3) != NULL);
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path3);
    rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    /* Two validators with identical stake; distinct pubkey fill bytes. */
    dnac_validator_record_t va, vb;
    make_validator(&va, 0x10, 0x77, 500, 0, 0, DNAC_VALIDATOR_ACTIVE);
    make_validator(&vb, 0x20, 0x77, 500, 0, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &vb), 0);  /* Insert higher pubkey first */
    CHECK_EQ(nodus_validator_insert(&w, &va), 0);

    dnac_validator_record_t tied[2];
    rc = nodus_validator_top_n(&w, 2, /*lookback_block=*/1000, tied, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 2);
    /* ASC on pubkey: 0x10 (va) before 0x20 (vb). */
    CHECK_EQ(tied[0].pubkey[0], 0x10);
    CHECK_EQ(tied[1].pubkey[0], 0x20);

    /* ── Scenario 7: Top-N excludes non-ACTIVE ──────────────────────── */
    dnac_validator_record_t vr;
    make_validator(&vr, 0x30, 0x77,
                   /*self_stake=*/9999999, /*ext_deleg=*/0,
                   /*active_since=*/0, DNAC_VALIDATOR_RETIRING);
    CHECK_EQ(nodus_validator_insert(&w, &vr), 0);

    dnac_validator_record_t after[5];
    rc = nodus_validator_top_n(&w, 5, /*lookback_block=*/1000, after, &count);
    CHECK_EQ(rc, 0);
    /* Only va + vb are ACTIVE; vr is RETIRING despite higher stake. */
    CHECK_EQ(count, 2);
    CHECK_EQ(after[0].pubkey[0], 0x10);
    CHECK_EQ(after[1].pubkey[0], 0x20);

    /* ── Scenario 8: Top-N excludes below MIN_TENURE ────────────────── */
    /* Insert a validator whose active_since + MIN_TENURE > lookback_block. */
    dnac_validator_record_t fresh;
    make_validator(&fresh, 0x40, 0x77,
                   /*self_stake=*/5000, /*ext_deleg=*/0,
                   /*active_since=*/900, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &fresh), 0);

    /* lookback=1000 means tenure needs 900 + 240 = 1140 <= 1000 → FAIL. */
    rc = nodus_validator_top_n(&w, 5, /*lookback_block=*/1000, after, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 2);  /* Still only va + vb. */

    /* Bump lookback above the threshold — fresh should now appear. */
    rc = nodus_validator_top_n(&w, 5,
                               /*lookback_block=*/900 + DNAC_MIN_TENURE_BLOCKS,
                               after, &count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(count, 3);
    /* fresh has the highest stake (5000) so it leads. */
    CHECK_EQ(after[0].pubkey[0], 0x40);

    /* ── Scenario 9: active_count seed value is 0 ───────────────────── */
    int active = -1;
    rc = nodus_validator_active_count(&w, &active);
    CHECK_EQ(rc, 0);
    CHECK_EQ(active, 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path3);

    printf("test_validator_db: ALL CHECKS PASSED\n");
    return 0;
}
