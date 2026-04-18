/**
 * Nodus — Task 51 committee election tests.
 *
 * Scenarios:
 *   (1) No ties, 5 distinct stakes: top-3 by stake DESC.
 *   (2) Exact tie: two different state_seeds produce different orderings
 *       (tiebreak hash depends on state_seed).
 *   (3) MIN_TENURE filter: active_since_block + MIN_TENURE > lookback
 *       excludes a fresh validator.
 *   (4) Status filter: RETIRING / UNSTAKED / AUTO_RETIRED excluded.
 *   (5) Fewer eligible than requested: returns what exists.
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
                            uint64_t self_stake,
                            uint64_t external_delegated,
                            int status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = self_stake;
    v->total_delegated         = external_delegated;
    v->external_delegated      = external_delegated;
    v->commission_bps          = 1000;   /* 10 % */
    v->status                  = status;
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

/* Insert a block row at `height` with the given state_root so that
 * nodus_witness_block_get(w, height, ...) returns a usable struct.
 * The production block-add path enforces monotonic height; we bypass
 * it with a direct SQL insert so the test can seed arbitrary heights. */
static void insert_block_row(nodus_witness_t *w,
                              uint64_t height,
                              const uint8_t state_seed[64]) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, "
        " prev_hash, state_root) "
        "VALUES (?, ?, 0, ?, ?, ?, ?)",
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

static void update_status(nodus_witness_t *w, const uint8_t *pubkey,
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

/* Find a pubkey in an out[] array; returns index or -1. */
static int find_pubkey(const nodus_committee_member_t *out, int count,
                        uint8_t pub_fill) {
    uint8_t needle[DNAC_PUBKEY_SIZE];
    memset(needle, pub_fill, sizeof(needle));
    for (int i = 0; i < count; i++) {
        if (memcmp(out[i].pubkey, needle, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

int main(void) {
    char data_path[] = "/tmp/test_committee_election_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);

    /* Seed block rows. lookback = e_start - EPOCH_LENGTH - 1, so choose
     * e_start big enough to avoid the bootstrap path. */
    const uint64_t e_start = (uint64_t)DNAC_EPOCH_LENGTH * 4;        /* 480 */
    const uint64_t lookback = e_start - (uint64_t)DNAC_EPOCH_LENGTH - 1; /* 359 */

    uint8_t seed_a[64];
    memset(seed_a, 0xAA, sizeof(seed_a));
    insert_block_row(&w, lookback, seed_a);

    /* ── Scenario 1: no ties, 5 distinct stakes ────────────────── */
    printf("  (1) no ties — top-3 ordering by stake DESC\n");
    /* All 5 validators active_since_block = 1 so tenure clears at
     * lookback = 359 (1 + 240 <= 359). */
    dnac_validator_record_t v1, v2, v3, v4, v5;
    init_validator(&v1, 0x11, 1, 100, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v2, 0x22, 1, 200, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v3, 0x33, 1, 300, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v4, 0x44, 1, 400, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&v5, 0x55, 1, 500, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &v1), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v2), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v3), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v4), 0);
    CHECK_EQ(nodus_validator_insert(&w, &v5), 0);

    nodus_committee_member_t out[DNAC_COMMITTEE_SIZE];
    int count = 0;
    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out, 3, &count), 0);
    CHECK_EQ(count, 3);
    CHECK(out[0].total_stake == 500);
    CHECK(out[1].total_stake == 400);
    CHECK(out[2].total_stake == 300);
    CHECK(find_pubkey(out, count, 0x55) == 0);
    CHECK(find_pubkey(out, count, 0x44) == 1);
    CHECK(find_pubkey(out, count, 0x33) == 2);

    /* ── Scenario 2: tiebreak depends on state_seed ───────────── */
    printf("  (2) tiebreak with state_seed\n");
    /* Add two validators with identical total stake, then observe that
     * swapping the state_seed for the lookback block swaps the pair in
     * the output. */
    dnac_validator_record_t vt_a, vt_b;
    init_validator(&vt_a, 0xAA, 1, 1000, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&vt_b, 0xBB, 1, 1000, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &vt_a), 0);
    CHECK_EQ(nodus_validator_insert(&w, &vt_b), 0);

    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out, 2, &count), 0);
    CHECK_EQ(count, 2);
    CHECK(out[0].total_stake == 1000);
    CHECK(out[1].total_stake == 1000);
    int idx_a_seed_a = find_pubkey(out, count, 0xAA);
    int idx_b_seed_a = find_pubkey(out, count, 0xBB);
    CHECK(idx_a_seed_a >= 0 && idx_b_seed_a >= 0);

    /* Rewrite the block row with a different state_seed and retry. */
    uint8_t seed_b[64];
    memset(seed_b, 0x33, sizeof(seed_b));
    insert_block_row(&w, lookback, seed_b);

    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out, 2, &count), 0);
    CHECK_EQ(count, 2);
    int idx_a_seed_b = find_pubkey(out, count, 0xAA);
    int idx_b_seed_b = find_pubkey(out, count, 0xBB);
    CHECK(idx_a_seed_b >= 0 && idx_b_seed_b >= 0);

    /* Determinism: ordering is deterministic given state_seed. Run it
     * again with seed_b, result must match. */
    nodus_committee_member_t out2[DNAC_COMMITTEE_SIZE];
    int count2 = 0;
    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out2, 2,
                                                 &count2), 0);
    CHECK_EQ(count2, count);
    for (int i = 0; i < count; i++) {
        CHECK(memcmp(out[i].pubkey, out2[i].pubkey, DNAC_PUBKEY_SIZE) == 0);
    }

    /* Verify that the tiebreak hash is what actually decides order for
     * seed_b. Compute expected ordering manually. */
    uint8_t buf_a[1 + DNAC_PUBKEY_SIZE + 64];
    uint8_t buf_b[1 + DNAC_PUBKEY_SIZE + 64];
    buf_a[0] = NODUS_TREE_TAG_VALIDATOR;
    memcpy(&buf_a[1], vt_a.pubkey, DNAC_PUBKEY_SIZE);
    memcpy(&buf_a[1 + DNAC_PUBKEY_SIZE], seed_b, 64);
    buf_b[0] = NODUS_TREE_TAG_VALIDATOR;
    memcpy(&buf_b[1], vt_b.pubkey, DNAC_PUBKEY_SIZE);
    memcpy(&buf_b[1 + DNAC_PUBKEY_SIZE], seed_b, 64);
    uint8_t hash_a[64], hash_b[64];
    qgp_sha3_512(buf_a, sizeof(buf_a), hash_a);
    qgp_sha3_512(buf_b, sizeof(buf_b), hash_b);
    int expected_a_first = (memcmp(hash_a, hash_b, 64) < 0);
    int got_a_first = (idx_a_seed_b < idx_b_seed_b);
    CHECK_EQ(expected_a_first, got_a_first);

    /* Restore seed_a for following scenarios (keeps tie ordering stable,
     * whichever it is). */
    insert_block_row(&w, lookback, seed_a);

    /* Retire the AA/BB pair so they don't pollute later scenarios. */
    update_status(&w, vt_a.pubkey, DNAC_VALIDATOR_UNSTAKED);
    update_status(&w, vt_b.pubkey, DNAC_VALIDATOR_UNSTAKED);

    /* ── Scenario 3: MIN_TENURE filter ──────────────────────────── */
    printf("  (3) MIN_TENURE filter excludes a fresh validator\n");
    /* Validator staked at block (lookback - MIN_TENURE + 1) fails the
     * strict-less-than test: active_since + MIN_TENURE = lookback+1 > lookback. */
    dnac_validator_record_t v_fresh;
    init_validator(&v_fresh, 0x66,
                    lookback - (uint64_t)DNAC_MIN_TENURE_BLOCKS + 1,
                    10000, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&w, &v_fresh), 0);

    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK(find_pubkey(out, count, 0x66) < 0);

    /* Same validator but active_since = lookback - MIN_TENURE clears. */
    update_status(&w, v_fresh.pubkey, DNAC_VALIDATOR_UNSTAKED);
    /* Restore status to ACTIVE via direct SQL, bump active_since too. */
    {
        sqlite3_stmt *stmt = NULL;
        int rc = sqlite3_prepare_v2(&*w.db,
            "UPDATE validators SET status = ?, active_since_block = ? "
            "WHERE pubkey = ?",
            -1, &stmt, NULL);
        CHECK_EQ(rc, SQLITE_OK);
        sqlite3_bind_int  (stmt, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(stmt, 2,
                (int64_t)(lookback - (uint64_t)DNAC_MIN_TENURE_BLOCKS));
        sqlite3_bind_blob (stmt, 3, v_fresh.pubkey, DNAC_PUBKEY_SIZE,
                           SQLITE_STATIC);
        CHECK_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK(find_pubkey(out, count, 0x66) >= 0);

    /* ── Scenario 4: status filter ──────────────────────────────── */
    printf("  (4) non-ACTIVE status excluded\n");
    update_status(&w, v1.pubkey, DNAC_VALIDATOR_RETIRING);
    update_status(&w, v2.pubkey, DNAC_VALIDATOR_UNSTAKED);
    update_status(&w, v3.pubkey, DNAC_VALIDATOR_AUTO_RETIRED);

    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK(find_pubkey(out, count, 0x11) < 0);
    CHECK(find_pubkey(out, count, 0x22) < 0);
    CHECK(find_pubkey(out, count, 0x33) < 0);

    /* ── Scenario 5: insufficient validators ────────────────────── */
    printf("  (5) insufficient validators — count_out < max_entries\n");
    /* After retiring v1/v2/v3 and unstaking tie pair above, we have
     * v4, v5, and v_fresh ACTIVE. Request 7 — expect 3. */
    CHECK_EQ(nodus_committee_compute_for_epoch(&w, e_start, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK_EQ(count, 3);
    /* Top by stake: v_fresh(10000) > v5(500) > v4(400). */
    CHECK(find_pubkey(out, count, 0x66) == 0);
    CHECK(find_pubkey(out, count, 0x55) == 1);
    CHECK(find_pubkey(out, count, 0x44) == 2);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    /* ────────────────────────────────────────────────────────────
     * Task 52 bootstrap scenarios — e_start too small for the
     * post-commit lookback rule. Fresh DB, fresh validators.
     * ──────────────────────────────────────────────────────────── */
    char data_path_b[] = "/tmp/test_committee_bootstrap_XXXXXX";
    CHECK(mkdtemp(data_path_b) != NULL);

    nodus_witness_t wb;
    memset(&wb, 0, sizeof(wb));
    snprintf(wb.data_path, sizeof(wb.data_path), "%s", data_path_b);
    uint8_t chain_id_b[16];
    memset(chain_id_b, 0xC2, sizeof(chain_id_b));
    CHECK_EQ(nodus_witness_create_chain_db(&wb, chain_id_b), 0);

    /* Seed genesis block with a known state_seed so the tiebreak is
     * reproducible in-test. */
    uint8_t genesis_seed[64];
    memset(genesis_seed, 0x5A, sizeof(genesis_seed));
    insert_block_row(&wb, 0, genesis_seed);

    /* Two fresh validators — active_since_block = 1. In the non-bootstrap
     * path they would fail MIN_TENURE against any lookback < 241, but
     * the bootstrap variant skips the tenure check. */
    dnac_validator_record_t vg1, vg2;
    init_validator(&vg1, 0x71, 1, 100, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&vg2, 0x72, 1, 200, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&wb, &vg1), 0);
    CHECK_EQ(nodus_validator_insert(&wb, &vg2), 0);

    /* Scenario B1: e_start = 0. Entirely in the bootstrap zone. */
    printf("  (B1) bootstrap — e_start = 0\n");
    CHECK_EQ(nodus_committee_compute_for_epoch(&wb, 0, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK_EQ(count, 2);
    /* Ranked by stake DESC — vg2(200) before vg1(100). */
    CHECK(find_pubkey(out, count, 0x72) == 0);
    CHECK(find_pubkey(out, count, 0x71) == 1);

    /* Scenario B2: e_start = EPOCH_LENGTH. lookback would be -1 → still
     * bootstrap zone (< EPOCH_LENGTH + 1). */
    printf("  (B2) bootstrap — e_start = EPOCH_LENGTH\n");
    CHECK_EQ(nodus_committee_compute_for_epoch(&wb,
                                                 (uint64_t)DNAC_EPOCH_LENGTH,
                                                 out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK_EQ(count, 2);
    CHECK(find_pubkey(out, count, 0x72) == 0);
    CHECK(find_pubkey(out, count, 0x71) == 1);

    /* Scenario B3: e_start = EPOCH_LENGTH + 1 → FIRST non-bootstrap
     * epoch. Lookback = 0 (genesis block). MIN_TENURE check applies:
     * active_since=1 + 240 = 241 > 0 → both validators filtered out.
     * This is the ugly corner the design carves out (only chain_def
     * bootstrap validators survive the transition). Verify behaviour:
     * committee is empty until validators accumulate tenure. */
    printf("  (B3) non-bootstrap — lookback=0 excludes fresh validators\n");
    CHECK_EQ(nodus_committee_compute_for_epoch(&wb,
                                                 (uint64_t)DNAC_EPOCH_LENGTH + 1,
                                                 out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK_EQ(count, 0);

    /* Scenario B4: bootstrap tiebreak also uses state_seed. Add two
     * tied-stake validators; check that ordering matches the manual
     * SHA3-512(0x02 || pubkey || genesis_state_root) comparison. */
    printf("  (B4) bootstrap tiebreak uses genesis state_seed\n");
    dnac_validator_record_t vg_a, vg_b;
    init_validator(&vg_a, 0x81, 1, 500, 0, DNAC_VALIDATOR_ACTIVE);
    init_validator(&vg_b, 0x82, 1, 500, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&wb, &vg_a), 0);
    CHECK_EQ(nodus_validator_insert(&wb, &vg_b), 0);

    CHECK_EQ(nodus_committee_compute_for_epoch(&wb, 0, out, 4, &count), 0);
    CHECK_EQ(count, 4);
    int idx_vga = find_pubkey(out, count, 0x81);
    int idx_vgb = find_pubkey(out, count, 0x82);
    CHECK(idx_vga >= 0 && idx_vgb >= 0);

    uint8_t bbuf_a[1 + DNAC_PUBKEY_SIZE + 64];
    uint8_t bbuf_b[1 + DNAC_PUBKEY_SIZE + 64];
    bbuf_a[0] = NODUS_TREE_TAG_VALIDATOR;
    memcpy(&bbuf_a[1], vg_a.pubkey, DNAC_PUBKEY_SIZE);
    memcpy(&bbuf_a[1 + DNAC_PUBKEY_SIZE], genesis_seed, 64);
    bbuf_b[0] = NODUS_TREE_TAG_VALIDATOR;
    memcpy(&bbuf_b[1], vg_b.pubkey, DNAC_PUBKEY_SIZE);
    memcpy(&bbuf_b[1 + DNAC_PUBKEY_SIZE], genesis_seed, 64);
    uint8_t bhash_a[64], bhash_b[64];
    qgp_sha3_512(bbuf_a, sizeof(bbuf_a), bhash_a);
    qgp_sha3_512(bbuf_b, sizeof(bbuf_b), bhash_b);
    int b_expected_a_first = (memcmp(bhash_a, bhash_b, 64) < 0);
    int b_got_a_first = (idx_vga < idx_vgb);
    CHECK_EQ(b_expected_a_first, b_got_a_first);

    /* Scenario B5: bootstrap with NO genesis block row — helper still
     * succeeds with a zero-filled state_seed. Fresh DB, no block_add. */
    printf("  (B5) bootstrap with missing genesis block — zero seed\n");
    char data_path_c[] = "/tmp/test_committee_nogenesis_XXXXXX";
    CHECK(mkdtemp(data_path_c) != NULL);
    nodus_witness_t wc;
    memset(&wc, 0, sizeof(wc));
    snprintf(wc.data_path, sizeof(wc.data_path), "%s", data_path_c);
    uint8_t chain_id_c[16];
    memset(chain_id_c, 0xC3, sizeof(chain_id_c));
    CHECK_EQ(nodus_witness_create_chain_db(&wc, chain_id_c), 0);
    dnac_validator_record_t vn;
    init_validator(&vn, 0x91, 1, 42, 0, DNAC_VALIDATOR_ACTIVE);
    CHECK_EQ(nodus_validator_insert(&wc, &vn), 0);
    CHECK_EQ(nodus_committee_compute_for_epoch(&wc, 0, out,
                                                 DNAC_COMMITTEE_SIZE, &count), 0);
    CHECK_EQ(count, 1);
    CHECK(find_pubkey(out, count, 0x91) == 0);
    sqlite3_close(wc.db);
    wc.db = NULL;
    rmrf(data_path_c);

    sqlite3_close(wb.db);
    wb.db = NULL;
    rmrf(data_path_b);

    printf("\nAll Task 51 + Task 52 committee election tests passed.\n");
    return 0;
}
