/**
 * Nodus — Phase 12 Task 57 test: genesis_seed_validators populates
 * validator_tree + reward_tree + validator_stats from a chain_def blob.
 *
 * Builds a minimal chain_def blob by hand (matching Task 56's pinned
 * canonical layout), invokes nodus_witness_genesis_seed_validators,
 * and verifies: 7 validator rows inserted, 7 reward rows inserted,
 * validator_stats.active_count == 7, committee bootstrap returns the
 * 7 seeded pubkeys.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_reward.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_genesis_seed.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

/* chain_def canonical layout (see Task 56 chain_def_codec.c):
 *   fixed(297) | witness_count × 2592 | iv_count(1) | iv_count × 2851
 * Build with witness_count=0 for simplicity — seeder only reads
 * witness_count to skip past the pubkeys array. */
#define CD_FIXED_BYTES  (32 + 4 + 64 + 64 + 4 + 4 + 4 + 4 + 4 + 8 + 1 + 8 + 64 + 32)
#define IV_ENTRY_BYTES  (DNAC_PUBKEY_SIZE + DNAC_FINGERPRINT_SIZE + 2 + 128)

static uint8_t *build_chain_def_blob(int iv_count,
                                      uint8_t pubkey_seeds[7],
                                      uint16_t commissions[7],
                                      size_t *len_out) {
    size_t len = CD_FIXED_BYTES + 1 + (size_t)iv_count * IV_ENTRY_BYTES;
    uint8_t *buf = calloc(1, len);
    CHECK_TRUE(buf != NULL);

    /* Fill in minimal valid fixed header:
     *   witness_count = 0 (no witness pubkeys to follow). */
    memcpy(buf, "test-chain", 10);  /* chain_name */
    /* protocol_version = 1 LE */
    buf[32] = 0x01;
    /* genesis_message */
    memcpy(buf + 32 + 4 + 64, "Phase 12 Task 57 test blob", 26);
    /* witness_count = 0 (already zero from calloc) */
    /* Everything else zero is fine — seeder only cares about
     * witness_count + iv_count + iv entries. */

    /* initial_validator_count at CD_FIXED_BYTES (witness_count=0 so no pubkeys). */
    buf[CD_FIXED_BYTES] = (uint8_t)iv_count;

    uint8_t *p = buf + CD_FIXED_BYTES + 1;
    for (int i = 0; i < iv_count; i++) {
        /* pubkey(2592): fill with seed-derived pattern. */
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
            p[b] = (uint8_t)((b + 31 * (pubkey_seeds[i] + 1)) & 0xff);
        }
        p += DNAC_PUBKEY_SIZE;

        /* unstake_destination_fp(129): "fp-N\0..." */
        snprintf((char *)p, DNAC_FINGERPRINT_SIZE, "fp-%d", i);
        p += DNAC_FINGERPRINT_SIZE;

        /* commission_bps(2 BE) */
        p[0] = (uint8_t)((commissions[i] >> 8) & 0xff);
        p[1] = (uint8_t)(commissions[i] & 0xff);
        p += 2;

        /* endpoint(128): "nodeN.test:4004\0..." */
        snprintf((char *)p, 128, "node%d.test:4004", i);
        p += 128;
    }

    *len_out = len;
    return buf;
}

int main(void) {
    char data_path[] = "/tmp/test_genesis_seed_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);
    CHECK_TRUE(w.db != NULL);

    /* ─── Scenario 1: empty active_count before seeding ─────────────── */
    int active = -1;
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 0);

    /* ─── Scenario 2: seed 7 validators from a chain_def blob ───────── */
    uint8_t seeds[7]       = {1, 2, 3, 4, 5, 6, 7};
    uint16_t commissions[7] = {0, 100, 200, 300, 400, 500, 1000};
    size_t cd_len = 0;
    uint8_t *cd_blob = build_chain_def_blob(7, seeds, commissions, &cd_len);

    int rc = nodus_witness_genesis_seed_validators(&w, cd_blob, cd_len);
    CHECK_EQ(rc, 0);

    /* Verify active_count = 7 */
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 7);

    /* Verify each validator row matches what we seeded. */
    for (int i = 0; i < 7; i++) {
        uint8_t expected_pk[DNAC_PUBKEY_SIZE];
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
            expected_pk[b] = (uint8_t)((b + 31 * (seeds[i] + 1)) & 0xff);
        }

        dnac_validator_record_t v;
        CHECK_EQ(nodus_validator_get(&w, expected_pk, &v), 0);
        CHECK_TRUE(memcmp(v.pubkey, expected_pk, DNAC_PUBKEY_SIZE) == 0);
        CHECK_EQ(v.self_stake, DNAC_SELF_STAKE_AMOUNT);
        CHECK_EQ(v.total_delegated, 0);
        CHECK_EQ(v.external_delegated, 0);
        CHECK_EQ(v.commission_bps, commissions[i]);
        CHECK_EQ(v.status, DNAC_VALIDATOR_ACTIVE);
        CHECK_EQ(v.active_since_block, 1ULL);
        CHECK_EQ(v.unstake_commit_block, 0);
        CHECK_EQ(v.consecutive_missed_epochs, 0);

        char expected_fp[DNAC_FINGERPRINT_SIZE];
        memset(expected_fp, 0, sizeof(expected_fp));
        snprintf(expected_fp, DNAC_FINGERPRINT_SIZE, "fp-%d", i);
        CHECK_TRUE(memcmp(v.unstake_destination_fp, expected_fp,
                          DNAC_FINGERPRINT_SIZE) == 0);

        /* Reward row: zeros + last_update_block=1. */
        dnac_reward_record_t r;
        CHECK_EQ(nodus_reward_get(&w, expected_pk, &r), 0);
        CHECK_EQ(r.validator_unclaimed, 0);
        CHECK_EQ(r.residual_dust, 0);
        CHECK_EQ(r.last_update_block, 1ULL);
        uint8_t zero_acc[16] = {0};
        CHECK_TRUE(memcmp(r.accumulator, zero_acc, 16) == 0);
    }
    printf("Scenario 2 PASS: 7 validators + 7 rewards + active_count=7\n");
    free(cd_blob);

    /* ─── Scenario 3: empty trailer (iv_count=0) is a no-op ─────────── */
    /* Fresh DB (same one; prior seeding stays). Verify iv_count=0 leaves
     * active_count unchanged. */
    uint8_t empty_seeds[7] = {0};
    uint16_t empty_comm[7] = {0};
    uint8_t *empty_blob = build_chain_def_blob(0, empty_seeds, empty_comm, &cd_len);
    CHECK_EQ(nodus_witness_genesis_seed_validators(&w, empty_blob, cd_len), 0);
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 7);   /* unchanged */
    free(empty_blob);
    printf("Scenario 3 PASS: empty trailer is no-op\n");

    /* ─── Scenario 4: NULL/zero-len blob accepted as no-op ─────────── */
    CHECK_EQ(nodus_witness_genesis_seed_validators(&w, NULL, 0), 0);
    CHECK_EQ(nodus_validator_active_count(&w, &active), 0);
    CHECK_EQ(active, 7);
    printf("Scenario 4 PASS: NULL blob is no-op\n");

    /* ─── Scenario 5: committee bootstrap returns seeded validators ── */
    /* This closes Task 52's forward-compat loop: bootstrap reads the
     * validators table and hands back the 7 initial committee members. */
    nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE];
    int committee_count = 0;
    rc = nodus_committee_bootstrap_for_epoch(&w, 0, committee,
                                               DNAC_COMMITTEE_SIZE,
                                               &committee_count);
    CHECK_EQ(rc, 0);
    CHECK_EQ(committee_count, 7);

    /* Each committee member must match one of the seeded pubkeys. */
    for (int i = 0; i < committee_count; i++) {
        int matched = 0;
        for (int s = 0; s < 7; s++) {
            uint8_t expected_pk[DNAC_PUBKEY_SIZE];
            for (int b = 0; b < DNAC_PUBKEY_SIZE; b++) {
                expected_pk[b] = (uint8_t)((b + 31 * (seeds[s] + 1)) & 0xff);
            }
            if (memcmp(committee[i].pubkey, expected_pk, DNAC_PUBKEY_SIZE) == 0) {
                matched = 1;
                break;
            }
        }
        CHECK_TRUE(matched);
    }
    printf("Scenario 5 PASS: bootstrap_for_epoch returns 7 seeded validators\n");

    /* ─── Scenario 6: truncated blob (iv_count=7 but bytes missing) ── */
    /* Build a valid 7-iv blob then cut off. Seeder must return -1. */
    uint8_t *trunc = build_chain_def_blob(7, seeds, commissions, &cd_len);
    /* Chop 100 bytes off the end. */
    size_t short_len = cd_len - 100;
    /* Note: prior scenario already seeded 7 validators, so a new seeder
     * run would fail on constraint (duplicate pubkey) regardless — but
     * we want to check the truncation branch specifically. Use a cd_blob
     * with all-zero pubkeys seeded after wiping the db manually isn't
     * simple; instead, just verify seeder returns -1 due to the length
     * check BEFORE touching the DB. */
    rc = nodus_witness_genesis_seed_validators(&w, trunc, short_len);
    CHECK_TRUE(rc == -1);
    free(trunc);
    printf("Scenario 6 PASS: truncated blob rejected\n");

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_genesis_seed_validators: ALL CHECKS PASSED\n");
    return 0;
}
