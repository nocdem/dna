/**
 * Nodus — Task 60 RETIRING validator stays in epoch committee until
 * graduation (F-CONS-03 regression lock).
 *
 * Locks in the design §3.6 guarantee: when a validator transitions to
 * RETIRING mid-epoch (via UNSTAKE), they STILL belong to the current
 * epoch's BFT committee. They only leave at the next epoch boundary
 * when Task 46's graduation flips them to UNSTAKED.
 *
 * This matters because BFT quorum depends on committee size. If a
 * mid-epoch UNSTAKE were to immediately shrink the committee from 7 to
 * 6, the honest quorum threshold (2n/3 + 1) would shift under the feet
 * of an in-flight block round — a liveness hazard.
 *
 * Scenarios:
 *   (1) Seed 7 ACTIVE validators; query committee → 7 members cached.
 *   (2) Flip validator 0x13 to RETIRING directly in the DB (simulates
 *       the state an UNSTAKE TX would leave behind at apply time).
 *   (3) Query the committee again for the SAME epoch → still 7 members;
 *       0x13 is still there (cache is frozen per §3.6).
 *   (4) Cross into the NEXT epoch → cache recomputes; RETIRING is
 *       excluded by the status filter → 6 members, 0x13 gone.
 *
 * Note: we mutate status directly rather than invoking an UNSTAKE TX +
 * apply_tx_to_state. This keeps the test focused on the committee-cache
 * semantics. Task 42 (apply_unstake) and Task 46 (epoch boundary
 * graduation) each have their own dedicated tests.
 *
 * No production code changes expected — the test is purely a regression
 * lock on the existing Task 46 + Task 53 interaction.
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

/* Direct status flip (simulates UNSTAKE post-apply state without going
 * through apply_tx_to_state). */
static void set_status(nodus_witness_t *w, const uint8_t *pubkey,
                        int status) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET status = ? WHERE pubkey = ?",
        -1, &stmt, NULL);
    CHECK_EQ(rc, SQLITE_OK);
    sqlite3_bind_int (stmt, 1, status);
    sqlite3_bind_blob(stmt, 2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
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
    char data_path[] = "/tmp/test_retiring_committee_membership_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);
    w.cached_committee_epoch_start = UINT64_MAX;

    uint8_t chain_id[16];
    memset(chain_id, 0x60, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* ── Seed 7 ACTIVE validators, active_since=1 ────────────────── */
    for (int i = 0; i < 7; i++) {
        dnac_validator_record_t v;
        init_validator(&v, /*pub_fill=*/(uint8_t)(0x10 + i),
                        /*active_since=*/1,
                        /*self_stake=*/1000000ULL + (uint64_t)i * 100);
        CHECK_EQ(nodus_validator_insert(&w, &v), 0);
    }

    /* ── Scenario 1: populate committee cache for an early epoch ── */
    printf("  (1) populate committee cache with 7 ACTIVE validators\n");
    /* Use the bootstrap path (e_start < EPOCH_LENGTH+1), which admits
     * every ACTIVE validator regardless of MIN_TENURE. block_height=5
     * → e_start=0 → bootstrap. */
    nodus_committee_member_t roster_a[DNAC_COMMITTEE_SIZE];
    int count_a = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, 5, roster_a,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_a), 0);
    CHECK_EQ(count_a, 7);
    /* Validator 0x13 (index 3) must be present. */
    CHECK(find_pubkey(roster_a, count_a, 0x13) >= 0);
    /* Cache is pinned to this epoch. */
    CHECK_EQ(w.cached_committee_epoch_start, 0ULL);

    /* ── Scenario 2: flip 0x13 to RETIRING mid-epoch ─────────────── */
    printf("  (2) flip validator 0x13 to RETIRING mid-epoch\n");
    uint8_t pk13[DNAC_PUBKEY_SIZE];
    memset(pk13, 0x13, sizeof(pk13));
    set_status(&w, pk13, DNAC_VALIDATOR_RETIRING);

    /* Sanity: the DB really did move. */
    dnac_validator_record_t vchk;
    CHECK_EQ(nodus_validator_get(&w, pk13, &vchk), 0);
    CHECK_EQ(vchk.status, (unsigned)DNAC_VALIDATOR_RETIRING);

    /* ── Scenario 3: same epoch — RETIRING still in committee ───── */
    printf("  (3) same-epoch query — RETIRING 0x13 still in committee\n");
    nodus_committee_member_t roster_b[DNAC_COMMITTEE_SIZE];
    int count_b = 0;
    /* Another block in the same epoch. */
    CHECK_EQ(nodus_witness_peer_current_set(&w, 50, roster_b,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_b), 0);
    /* KEY ASSERTION: the RETIRING validator is STILL in the current
     * epoch's committee. BFT quorum (2n/3+1) computed against this
     * committee size does not change mid-epoch. */
    CHECK_EQ(count_b, 7);
    CHECK(find_pubkey(roster_b, count_b, 0x13) >= 0);
    /* Cache was not invalidated. */
    CHECK_EQ(w.cached_committee_epoch_start, 0ULL);

    /* ── Scenario 4: next epoch — cache recomputes, RETIRING gone ─ */
    printf("  (4) next-epoch query — cache recomputes, 0x13 excluded\n");
    /* Epoch 1 starts at block EPOCH_LENGTH. To avoid MIN_TENURE
     * gymnastics, route through the bootstrap path one more time by
     * holding block_height inside epoch 0 first and then calling with
     * e_start exactly equal to DNAC_EPOCH_LENGTH. For e_start = 120
     * (still < EPOCH_LENGTH+1=121 — bootstrap just barely), we stay on
     * the bootstrap path but with a FRESH cache lookup because the key
     * (e_start) changed from 0 to 120. */
    const uint64_t next_e_start = (uint64_t)DNAC_EPOCH_LENGTH;

    /* Force a cache miss for the next epoch by explicitly invalidating —
     * alternatively, querying any block with a different e_start would
     * have the same effect. Explicit invalidation keeps the test
     * intent readable. */
    w.cached_committee_epoch_start = UINT64_MAX;
    w.cached_committee_count = 0;

    nodus_committee_member_t roster_c[DNAC_COMMITTEE_SIZE];
    int count_c = 0;
    CHECK_EQ(nodus_witness_peer_current_set(&w, next_e_start, roster_c,
                                              DNAC_COMMITTEE_SIZE,
                                              &count_c), 0);
    /* After recompute: RETIRING is filtered out by the status predicate
     * in nodus_validator_top_n → committee shrinks to 6. This is the
     * "next-epoch graduation in effect" behavior: Task 46 would have
     * flipped 0x13 to UNSTAKED at the real boundary, and the committee
     * cache would have independently re-elected without it. */
    CHECK_EQ(count_c, 6);
    /* 0x13 gone. */
    CHECK(find_pubkey(roster_c, count_c, 0x13) < 0);
    /* Other 6 ACTIVE validators still present. */
    CHECK(find_pubkey(roster_c, count_c, 0x10) >= 0);
    CHECK(find_pubkey(roster_c, count_c, 0x11) >= 0);
    CHECK(find_pubkey(roster_c, count_c, 0x12) >= 0);
    CHECK(find_pubkey(roster_c, count_c, 0x14) >= 0);
    CHECK(find_pubkey(roster_c, count_c, 0x15) >= 0);
    CHECK(find_pubkey(roster_c, count_c, 0x16) >= 0);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("\nAll Task 60 RETIRING-committee-membership tests passed.\n");
    return 0;
}
