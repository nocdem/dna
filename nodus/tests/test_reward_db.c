/**
 * Nodus — Task 13 reward CRUD unit test
 *
 * Covers upsert / get / delete. Uses the same tmpdir-backed
 * nodus_witness_create_chain_db path as test_stake_schema.c.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_reward.h"

#include "dnac/validator.h"

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

#define CHECK_MEM_EQ(a, b, n) do { \
    if (memcmp((a), (b), (n)) != 0) { \
        fprintf(stderr, "CHECK_MEM_EQ fail at %s:%d\n", __FILE__, __LINE__); \
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

static void fill_pubkey(uint8_t *pk, uint8_t seed) {
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++) pk[i] = (uint8_t)(seed + i);
}

int main(void) {
    char data_path[] = "/tmp/test_reward_db_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xC3, sizeof(chain_id));

    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK_TRUE(w.db != NULL);

    dnac_reward_record_t r_in, r_out;

    /* ── 1: upsert fresh + get returns all fields ─────────────── */
    memset(&r_in, 0, sizeof(r_in));
    fill_pubkey(r_in.validator_pubkey, 0x11);
    for (int i = 0; i < 16; i++) r_in.accumulator[i] = (uint8_t)(0x80 + i);
    r_in.validator_unclaimed = 5000;
    r_in.last_update_block   = 42;
    r_in.residual_dust       = 7;

    CHECK_EQ(nodus_reward_upsert(&w, &r_in), 0);

    memset(&r_out, 0, sizeof(r_out));
    CHECK_EQ(nodus_reward_get(&w, r_in.validator_pubkey, &r_out), 0);
    CHECK_MEM_EQ(r_in.validator_pubkey, r_out.validator_pubkey,
                 DNAC_PUBKEY_SIZE);
    CHECK_MEM_EQ(r_in.accumulator, r_out.accumulator,
                 sizeof(r_in.accumulator));
    CHECK_EQ(r_in.validator_unclaimed, r_out.validator_unclaimed);
    CHECK_EQ(r_in.last_update_block,   r_out.last_update_block);
    CHECK_EQ(r_in.residual_dust,       r_out.residual_dust);

    /* ── 2: upsert same validator updates fields (no duplicate) ── */
    for (int i = 0; i < 16; i++) r_in.accumulator[i] = (uint8_t)(0xF0 - i);
    r_in.validator_unclaimed = 99999;
    r_in.last_update_block   = 1000;
    r_in.residual_dust       = 0;

    CHECK_EQ(nodus_reward_upsert(&w, &r_in), 0);

    /* Raw sqlite row count must remain 1 (upsert, not insert). */
    {
        sqlite3_stmt *stmt = NULL;
        int prc = sqlite3_prepare_v2(w.db,
            "SELECT COUNT(*) FROM rewards", -1, &stmt, NULL);
        CHECK_EQ(prc, SQLITE_OK);
        int step = sqlite3_step(stmt);
        CHECK_EQ(step, SQLITE_ROW);
        int n = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        CHECK_EQ(n, 1);
    }

    memset(&r_out, 0, sizeof(r_out));
    CHECK_EQ(nodus_reward_get(&w, r_in.validator_pubkey, &r_out), 0);
    CHECK_MEM_EQ(r_in.accumulator, r_out.accumulator,
                 sizeof(r_in.accumulator));
    CHECK_EQ(r_out.validator_unclaimed, 99999);
    CHECK_EQ(r_out.last_update_block,   1000);
    CHECK_EQ(r_out.residual_dust,       0);

    /* ── 3: get non-existent validator → 1 ────────────────────── */
    uint8_t missing[DNAC_PUBKEY_SIZE];
    fill_pubkey(missing, 0xAA);
    CHECK_EQ(nodus_reward_get(&w, missing, &r_out), 1);

    /* ── 4: delete + re-get returns 1; second delete returns 1 ── */
    CHECK_EQ(nodus_reward_delete(&w, r_in.validator_pubkey), 0);
    CHECK_EQ(nodus_reward_get(&w, r_in.validator_pubkey, &r_out), 1);
    CHECK_EQ(nodus_reward_delete(&w, r_in.validator_pubkey), 1);

    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_reward_db: ALL CHECKS PASSED\n");
    return 0;
}
