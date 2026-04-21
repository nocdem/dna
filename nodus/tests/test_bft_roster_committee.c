/**
 * Nodus — Task 59 BFT roster sourced from committee snapshot.
 *
 * Verifies nodus_witness_peer_current_set() returns the same set as
 * nodus_committee_get_for_block() and transitions at the epoch boundary.
 *
 * Scenarios:
 *   (1) Fresh DB (no validators): helper returns count=0.
 *   (2) Validator table seeded with 7 entries: helper returns 7 members,
 *       matches direct committee call.
 *   (3) Cross-epoch transition — before and after block_height crosses an
 *       EPOCH boundary, the committee cache key differs, so a mid-epoch
 *       stake bump is reflected in the NEXT epoch but NOT the current one.
 *   (4) A mid-epoch stake mutation within the SAME epoch is ignored by
 *       the cache: the committee stays frozen per §3.6.
 *
 * Uses the bootstrap path by passing INT64_MAX-style lookback through
 * nodus_committee_bootstrap_for_epoch (e_start < EPOCH_LENGTH+1), which
 * keeps the test standalone — no genesis block required.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_peer.h"
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
    v->total_delegated         = 0;
    v->external_delegated      = 0;
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

/* Insert a block row so nodus_witness_block_get(height) succeeds. */
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

/* Locate a pubkey with the given fill byte in an array of committee
 * members; return its index or -1. */
static int find_pubkey(const nodus_committee_member_t *arr, int count,
                        uint8_t pub_fill) {
    uint8_t needle[DNAC_PUBKEY_SIZE];
    memset(needle, pub_fill, sizeof(needle));
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, needle, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

/* Direct stake mutation (bypass STAKE TX path). */
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

int main(void) {
    char data_path[] = "/tmp/test_bft_roster_committee_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    /* Cache sentinel mirrors the production init path. */
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0x59, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* ── Scenario 1: no validators yet ───────────────────────────── */
    printf("  (1) empty validator table → empty committee\n");
    nodus_committee_member_t roster0[DNAC_COMMITTEE_SIZE];
    int count0 = -1;
    /* Use a block_height inside the bootstrap range (e_start < EPOCH+1)
     * so the helper takes the bootstrap path; this avoids needing to
     * seed a lookback block row for the empty case. */
    CHECK_EQ(nodus_witness_peer_current_set(&w, 1, roster0,
                                              DNAC_COMMITTEE_SIZE, &count0), 0);
    CHECK_EQ(count0, 0);

    /* ── Scenario 2: seed 7 validators ───────────────────────────── */
    printf("  (2) 7 seeded validators → committee of 7\n");
    /* Active since block 1; bootstrap path ignores MIN_TENURE, so all
     * 7 are immediately eligible. */
    for (int i = 0; i < 7; i++) {
        dnac_validator_record_t v;
        /* Stakes increase by index so ordering is distinguishable. */
        init_validator(&v, /*pub_fill=*/(uint8_t)(0x10 + i),
                        /*active_since=*/1,
                        /*self_stake=*/1000000ULL + (uint64_t)i * 100);
        CHECK_EQ(nodus_validator_insert(&w, &v), 0);
    }

    /* block_height = 5 → e_start = 0 → bootstrap path. Fresh cache. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    nodus_committee_member_t roster_bft[DNAC_COMMITTEE_SIZE];
    int count_bft = -1;
    CHECK_EQ(nodus_witness_peer_current_set(&w, 5, roster_bft,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_bft), 0);
    CHECK_EQ(count_bft, 7);

    /* Direct committee call MUST return the same members. */
    nodus_committee_member_t roster_cm[DNAC_COMMITTEE_SIZE];
    int count_cm = -1;
    CHECK_EQ(nodus_committee_get_for_block(&w, 5, roster_cm,
                                             DNAC_COMMITTEE_SIZE,
                                             &count_cm), 0);
    CHECK_EQ(count_cm, count_bft);
    for (int i = 0; i < count_bft; i++) {
        CHECK(memcmp(roster_bft[i].pubkey, roster_cm[i].pubkey,
                     DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(roster_bft[i].total_stake, roster_cm[i].total_stake);
    }

    /* Validator with fill 0x16 (highest stake) must be in top-7. */
    CHECK(find_pubkey(roster_bft, count_bft, 0x16) >= 0);

    /* ── Scenario 3: cross-epoch transition ──────────────────────── */
    printf("  (3) epoch boundary transition — mid-epoch mutation "
           "applies to next epoch only\n");
    /* Seed block rows so the non-bootstrap path can compute committees
     * for later epochs. Math is parametric on DNAC_EPOCH_LENGTH:
     *   epoch 4 (e_start=4*EPOCH): lookback = 4*EPOCH - EPOCH - 1 = 3*EPOCH - 1
     *   epoch 5 (e_start=5*EPOCH): lookback = 4*EPOCH - 1
     * Both lookbacks are >= MIN_TENURE (2*EPOCH) past active_since=1,
     * so all 7 validators remain eligible without the bootstrap carve-out. */
    const uint64_t epoch_len = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t e_a = epoch_len * 4;
    const uint64_t lookback_a = e_a - epoch_len - 1;
    const uint64_t e_b = epoch_len * 5;
    const uint64_t lookback_b = e_b - epoch_len - 1;
    uint8_t seed_a[64]; memset(seed_a, 0xA1, sizeof(seed_a));
    uint8_t seed_b[64]; memset(seed_b, 0xB2, sizeof(seed_b));
    insert_block_row(&w, lookback_a, seed_a);
    insert_block_row(&w, lookback_b, seed_b);

    /* Fresh cache so the next call hits the lookback path. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    /* Within epoch A — should pick up lookback_a's seed. */
    nodus_committee_member_t roster_a[DNAC_COMMITTEE_SIZE];
    int count_a = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 10, roster_a,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a), 0);
    CHECK_EQ(count_a, 7);
    CHECK_EQ(w.cached_committee_epoch_start, e_a);

    /* Cross into epoch B — different e_start → recompute. We also push
     * a new stake on validator 0x10 so the ordering changes visibly. */
    uint8_t pk10[DNAC_PUBKEY_SIZE];
    memset(pk10, 0x10, sizeof(pk10));
    set_self_stake(&w, pk10, 9999999ULL);

    nodus_committee_member_t roster_b[DNAC_COMMITTEE_SIZE];
    int count_b = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_b + 10, roster_b,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_b), 0);
    CHECK_EQ(count_b, 7);
    CHECK_EQ(w.cached_committee_epoch_start, e_b);
    /* 0x10 now the top-stake entry (9_999_999 > every other stake). */
    CHECK(find_pubkey(roster_b, count_b, 0x10) == 0);

    /* ── Scenario 4: mid-epoch mutation ignored by cache ─────────── */
    printf("  (4) mid-epoch stake bump does not shift cached roster\n");
    /* Re-query epoch A → fresh DB read (cache pinned on B), so we see
     * the mutation. But a second query within epoch A returns the
     * cached result even after another mutation — that is the frozen
     * epoch guarantee we rely on for BFT roster stability. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    nodus_committee_member_t roster_a2[DNAC_COMMITTEE_SIZE];
    int count_a2 = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 5, roster_a2,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a2), 0);
    CHECK_EQ(count_a2, 7);
    /* Snapshot 0x10's cached total_stake. */
    int idx10 = find_pubkey(roster_a2, count_a2, 0x10);
    CHECK(idx10 >= 0);
    uint64_t snap_0x10 = roster_a2[idx10].total_stake;

    /* Double 0x10's stake — any recompute would move it. */
    set_self_stake(&w, pk10, snap_0x10 * 2ULL);

    nodus_committee_member_t roster_a3[DNAC_COMMITTEE_SIZE];
    int count_a3 = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, e_a + 50, roster_a3,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a3), 0);
    CHECK_EQ(count_a3, count_a2);
    int idx10b = find_pubkey(roster_a3, count_a3, 0x10);
    CHECK(idx10b >= 0);
    /* Cache intact — stake for 0x10 unchanged. */
    CHECK_EQ(roster_a3[idx10b].total_stake, snap_0x10);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("\nAll Task 59 BFT roster committee tests passed.\n");
    return 0;
}
