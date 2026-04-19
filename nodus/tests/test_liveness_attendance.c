/**
 * Nodus - Task 48 liveness attendance tracking tests.
 *
 * Scenarios:
 *   1. record_attendance credits matching voters.
 *   2. Monotonic watermark - older block_height does not overwrite.
 *   3. Unknown voter_id is ignored.
 *   4. Epoch boundary - validators that signed within past epoch
 *      keep consecutive_missed_epochs = 0.
 *   5. Three consecutive missed epochs flip status to AUTO_RETIRED
 *      and decrement validator_stats.active_count.
 *   6. Signing resumes after partial streak resets the counter.
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
                           uint64_t active_since) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake              = DNAC_SELF_STAKE_AMOUNT;
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

static void bump_active_count(nodus_witness_t *w) {
    char *err = NULL;
    int rc = sqlite3_exec(w->db,
        "UPDATE validator_stats SET value = value + 1 WHERE key = 'active_count'",
        NULL, NULL, &err);
    CHECK(rc == SQLITE_OK);
    if (err) sqlite3_free(err);
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

static void derive_voter_id(const uint8_t *pubkey, uint8_t out_id[32]) {
    uint8_t digest[64];
    qgp_sha3_512(pubkey, DNAC_PUBKEY_SIZE, digest);
    memcpy(out_id, digest, 32);
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

int main(void) {
    char data_path[] = "/tmp/test_liveness_attendance_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xE1, sizeof(chain_id));
    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);

    dnac_validator_record_t va, vb;
    init_validator(&va, 0x11, 1);
    init_validator(&vb, 0x22, 1);
    CHECK_EQ(nodus_validator_insert(&w, &va), 0);
    CHECK_EQ(nodus_validator_insert(&w, &vb), 0);
    bump_active_count(&w);
    bump_active_count(&w);

    dnac_reward_record_t ra, rb;
    memset(&ra, 0, sizeof(ra));
    memset(&rb, 0, sizeof(rb));
    memcpy(ra.validator_pubkey, va.pubkey, DNAC_PUBKEY_SIZE);
    memcpy(rb.validator_pubkey, vb.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &ra), 0);
    CHECK_EQ(nodus_reward_upsert(&w, &rb), 0);

    CHECK_EQ(read_active_count(&w), 2);

    printf("  record_attendance credits block proposer\n");
    /* New API (2026-04-19): attendance credits the block's proposer only.
     * Simulate 2 blocks: block 50 proposed by va, then block 50 proposed
     * by vb (blocks are uniquely numbered but here we bump both to 50 to
     * match the original test's invariant). Single call per block. */
    uint8_t va_vid[NODUS_T3_WITNESS_ID_LEN];
    uint8_t vb_vid[NODUS_T3_WITNESS_ID_LEN];
    derive_voter_id(va.pubkey, va_vid);
    derive_voter_id(vb.pubkey, vb_vid);

    CHECK_EQ(nodus_witness_record_attendance(&w, 50, va_vid), 0);
    CHECK_EQ(nodus_witness_record_attendance(&w, 50, vb_vid), 0);

    dnac_validator_record_t chk;
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.last_signed_block, 50);
    CHECK_EQ(nodus_validator_get(&w, vb.pubkey, &chk), 0);
    CHECK_EQ(chk.last_signed_block, 50);

    printf("  monotonic watermark: older block does not step backwards\n");
    CHECK_EQ(nodus_witness_record_attendance(&w, 40, va_vid), 0);
    CHECK_EQ(nodus_witness_record_attendance(&w, 40, vb_vid), 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.last_signed_block, 50);

    printf("  unknown proposer_id is ignored\n");
    uint8_t stranger_vid[NODUS_T3_WITNESS_ID_LEN];
    memset(stranger_vid, 0xFF, sizeof(stranger_vid));
    CHECK_EQ(nodus_witness_record_attendance(&w, 60, stranger_vid), 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.last_signed_block, 50);
    CHECK_EQ(nodus_validator_get(&w, vb.pubkey, &chk), 0);
    CHECK_EQ(chk.last_signed_block, 50);

    /* Record attendance at 250 (within epoch [120..240] and [240..360]). */
    CHECK_EQ(nodus_witness_record_attendance(&w, 250, va_vid), 0);
    CHECK_EQ(nodus_witness_record_attendance(&w, 250, vb_vid), 0);

    /* Epoch boundary at 360 with last_signed_block=250 (>= epoch_start=240).
     * consecutive_missed_epochs stays 0. */
    rc = run_finalize(&w, 360);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 0);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_ACTIVE);

    printf("  three missed epochs -> AUTO_RETIRED + active_count drops\n");
    rc = run_finalize(&w, 480);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 1);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_ACTIVE);

    rc = run_finalize(&w, 600);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 2);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_ACTIVE);

    CHECK_EQ(read_active_count(&w), 2);

    rc = run_finalize(&w, 720);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, va.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 3);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_AUTO_RETIRED);

    CHECK_EQ(nodus_validator_get(&w, vb.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 3);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_AUTO_RETIRED);

    CHECK_EQ(read_active_count(&w), 0);

    printf("  signing resumes -> consecutive_missed_epochs drops to 0\n");
    dnac_validator_record_t vc;
    init_validator(&vc, 0x33, 100);
    CHECK_EQ(nodus_validator_insert(&w, &vc), 0);
    bump_active_count(&w);
    dnac_reward_record_t rc_row;
    memset(&rc_row, 0, sizeof(rc_row));
    memcpy(rc_row.validator_pubkey, vc.pubkey, DNAC_PUBKEY_SIZE);
    CHECK_EQ(nodus_reward_upsert(&w, &rc_row), 0);

    uint8_t vc_vid[NODUS_T3_WITNESS_ID_LEN];
    derive_voter_id(vc.pubkey, vc_vid);
    CHECK_EQ(nodus_witness_record_attendance(&w, 400, vc_vid), 0);

    rc = run_finalize(&w, 840);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, vc.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 1);

    rc = run_finalize(&w, 960);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, vc.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 2);

    CHECK_EQ(nodus_witness_record_attendance(&w, 1000, vc_vid), 0);

    rc = run_finalize(&w, 1080);
    CHECK_EQ(rc, 0);
    CHECK_EQ(nodus_validator_get(&w, vc.pubkey, &chk), 0);
    CHECK_EQ(chk.consecutive_missed_epochs, 0);
    CHECK_EQ(chk.status, DNAC_VALIDATOR_ACTIVE);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("\nAll Task 48 liveness attendance tests passed.\n");
    return 0;
}
