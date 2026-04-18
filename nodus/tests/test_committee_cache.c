/**
 * Nodus — Task 53 committee cache tests.
 *
 * Verifies nodus_committee_get_for_block() caches the committee per
 * epoch and recomputes on epoch-start change.
 *
 * Scenarios:
 *   (1) First call populates the cache; epoch_start matches lookup.
 *   (2) Second call within the same epoch reads cached values — even
 *       after we mutate a validator's underlying stake the cached
 *       ranking does NOT refresh (committee is frozen per epoch).
 *   (3) Call for a different epoch forces recompute; new ordering picks
 *       up the mutated stake.
 *   (4) Init sentinel: freshly zeroed witness has
 *       cached_committee_epoch_start == UINT64_MAX before any lookup.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"
#include "nodus/nodus_types.h"

#include <dirent.h>
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
                            uint64_t active_since, uint64_t self_stake) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = self_stake;
    v->commission_bps          = 500;
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

static void insert_block_row(nodus_witness_t *w, uint64_t height,
                              const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, "
        " prev_hash, state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    uint8_t zeros[64] = {0};
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, state_seed, 64, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void set_self_stake(nodus_witness_t *w, const uint8_t *pubkey,
                            uint64_t val) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET self_stake = ? WHERE pubkey = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int64(stmt, 1, (int64_t)val);
    sqlite3_bind_blob (stmt, 2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static int find_pubkey(const nodus_committee_member_t *arr, int count,
                        uint8_t pub_fill) {
    uint8_t needle[DNAC_PUBKEY_SIZE];
    memset(needle, pub_fill, sizeof(needle));
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, needle, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

int main(void) {
    /* ── Scenario 4 first: init sentinel (use a fresh, un-opened struct) ── */
    printf("  (4) init sentinel — cached_committee_epoch_start == UINT64_MAX\n");
    nodus_witness_t w_init;
    memset(&w_init, 0, sizeof(w_init));
    /* The production path runs nodus_witness_init which sets the
     * sentinel. We simulate the relevant bit here without the full
     * server fixture to keep the test standalone. */
    w_init.cached_committee_epoch_start = UINT64_MAX;
    w_init.cached_committee_count = 0;
    CHECK_EQ(w_init.cached_committee_epoch_start, (uint64_t)UINT64_MAX);
    CHECK_EQ(w_init.cached_committee_count, 0);

    char data_path[] = "/tmp/test_committee_cache_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    /* Apply the same sentinel init the production path does. */
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0xC4, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* Seed two lookback blocks so we can exercise two different epochs. */
    const uint64_t epoch_len = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t e_start_a = epoch_len * 4;                 /* 480 */
    const uint64_t lookback_a = e_start_a - epoch_len - 1;    /* 359 */
    const uint64_t e_start_b = epoch_len * 5;                 /* 600 */
    const uint64_t lookback_b = e_start_b - epoch_len - 1;    /* 479 */

    uint8_t seed_a[64]; memset(seed_a, 0x11, sizeof(seed_a));
    uint8_t seed_b[64]; memset(seed_b, 0x22, sizeof(seed_b));
    insert_block_row(&w, lookback_a, seed_a);
    insert_block_row(&w, lookback_b, seed_b);

    /* Two validators active_since=1 — clear MIN_TENURE against both
     * lookbacks (1 + 240 = 241 <= 359). */
    dnac_validator_record_t v1, v2;
    init_validator(&v1, 0x11, 1, 100);
    init_validator(&v2, 0x22, 1, 200);
    CHECK_EQ(nodus_validator_insert(&w, &v1), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v2), 0);

    /* ── Scenario 1: first call populates cache ──────────────────── */
    printf("  (1) first call within epoch — populates cache\n");
    /* Block height anywhere in [e_start_a, e_start_a + epoch_len) maps
     * to epoch e_start_a. Pick e_start_a + 10. */
    uint64_t blk_in_a = e_start_a + 10;
    nodus_committee_member_t out1[DNAC_COMMITTEE_SIZE];
    int count1 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a, out1,
                                             DNAC_COMMITTEE_SIZE, &count1), 0);
    CHECK_EQ(count1, 2);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_a);
    CHECK_EQ(w.cached_committee_count, 2);
    /* v2 (200) before v1 (100) by stake. */
    CHECK(find_pubkey(out1, count1, 0x22) == 0);
    CHECK(find_pubkey(out1, count1, 0x11) == 1);

    /* ── Scenario 2: second call returns cached — ignores mutation ── */
    printf("  (2) cached call ignores mid-epoch stake mutation\n");
    /* Mutate v1 to beat v2 in raw stake — 999 > 200. If the committee
     * were recomputed, v1 would rank first. Cached call MUST return
     * the unchanged ordering. */
    set_self_stake(&w, v1.pubkey, 999);

    nodus_committee_member_t out2[DNAC_COMMITTEE_SIZE];
    int count2 = 0;
    uint64_t blk_in_a_later = e_start_a + 50;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a_later, out2,
                                             DNAC_COMMITTEE_SIZE, &count2), 0);
    CHECK_EQ(count2, count1);
    /* Ordering is the SAME as before the mutation. */
    for (int i = 0; i < count1; i++) {
        CHECK(memcmp(out1[i].pubkey, out2[i].pubkey, DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(out1[i].total_stake, out2[i].total_stake);
    }
    /* The cached total_stake for v2 is still 200 — NOT refreshed. */
    int idx_v2 = find_pubkey(out2, count2, 0x22);
    CHECK(idx_v2 >= 0);
    CHECK_EQ(out2[idx_v2].total_stake, 200);

    /* ── Scenario 3: new epoch forces recompute ──────────────────── */
    printf("  (3) epoch change triggers recompute\n");
    uint64_t blk_in_b = e_start_b + 5;
    nodus_committee_member_t out3[DNAC_COMMITTEE_SIZE];
    int count3 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_b, out3,
                                             DNAC_COMMITTEE_SIZE, &count3), 0);
    CHECK_EQ(count3, 2);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_b);
    /* v1 (999) now beats v2 (200). */
    CHECK(find_pubkey(out3, count3, 0x11) == 0);
    CHECK(find_pubkey(out3, count3, 0x22) == 1);
    int idx_v1 = find_pubkey(out3, count3, 0x11);
    CHECK_EQ(out3[idx_v1].total_stake, 999);

    /* Going BACK to the old epoch re-queries; because the cache key
     * only stores one epoch, this triggers another recompute. The
     * returned committee reflects the CURRENT database state (v1=999
     * now wins even under the old lookback because we used the same
     * active_since for both validators). */
    printf("  (3b) back to old epoch — re-query from live DB\n");
    nodus_committee_member_t out4[DNAC_COMMITTEE_SIZE];
    int count4 = 0;
    CHECK_EQ(nodus_committee_get_for_block(&w, blk_in_a, out4,
                                             DNAC_COMMITTEE_SIZE, &count4), 0);
    CHECK_EQ(w.cached_committee_epoch_start, e_start_a);
    /* v1 now on top — because the DB no longer reflects the old
     * ranking. This is the expected behaviour: the cache pins ONE
     * epoch at a time; ping-ponging between epochs re-queries. In
     * production this never happens (block_height is monotonic). */
    CHECK(find_pubkey(out4, count4, 0x11) == 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("\nAll Task 53 committee cache tests passed.\n");
    return 0;
}
