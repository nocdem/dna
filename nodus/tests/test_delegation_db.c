/**
 * Nodus — Task 13 delegation CRUD unit test
 *
 * Covers insert/get/update/delete + count-by-delegator + list by
 * delegator and validator. Uses mkdtemp + nodus_witness_create_chain_db
 * to spin up a real schema via the same production path as
 * test_stake_schema.c.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_delegation.h"

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

/* rm -rf the test data directory (best-effort). */
static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

/* Fill a pubkey buffer with a deterministic pattern. */
static void fill_pubkey(uint8_t *pk, uint8_t seed) {
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++) pk[i] = (uint8_t)(seed + i);
}

/* Build a canonical delegation record for testing. */
static void make_delegation(dnac_delegation_record_t *d,
                            uint8_t del_seed, uint8_t val_seed,
                            uint64_t amount, uint64_t block,
                            uint8_t snap_fill) {
    memset(d, 0, sizeof(*d));
    fill_pubkey(d->delegator_pubkey, del_seed);
    fill_pubkey(d->validator_pubkey, val_seed);
    d->amount = amount;
    d->delegated_at_block = block;
    memset(d->reward_snapshot, snap_fill, sizeof(d->reward_snapshot));
}

int main(void) {
    char data_path[] = "/tmp/test_delegation_db_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xB2, sizeof(chain_id));

    int rc = nodus_witness_create_chain_db(&w, chain_id);
    CHECK_EQ(rc, 0);
    CHECK_TRUE(w.db != NULL);

    /* ── 1: insert + get round-trip ───────────────────────────── */
    dnac_delegation_record_t d_in, d_out;
    make_delegation(&d_in, /*del*/ 0x10, /*val*/ 0x80,
                    /*amount*/ 1000000,
                    /*block*/ 42,
                    /*snap*/ 0x11);
    CHECK_EQ(nodus_delegation_insert(&w, &d_in), 0);

    memset(&d_out, 0, sizeof(d_out));
    CHECK_EQ(nodus_delegation_get(&w, d_in.delegator_pubkey,
                                   d_in.validator_pubkey, &d_out), 0);
    CHECK_MEM_EQ(d_in.delegator_pubkey, d_out.delegator_pubkey,
                 DNAC_PUBKEY_SIZE);
    CHECK_MEM_EQ(d_in.validator_pubkey, d_out.validator_pubkey,
                 DNAC_PUBKEY_SIZE);
    CHECK_EQ(d_in.amount, d_out.amount);
    CHECK_EQ(d_in.delegated_at_block, d_out.delegated_at_block);
    CHECK_MEM_EQ(d_in.reward_snapshot, d_out.reward_snapshot,
                 sizeof(d_in.reward_snapshot));

    /* ── 2: get on a non-existent pair → 1 ────────────────────── */
    uint8_t missing_del[DNAC_PUBKEY_SIZE], missing_val[DNAC_PUBKEY_SIZE];
    fill_pubkey(missing_del, 0xF0);
    fill_pubkey(missing_val, 0xF1);
    CHECK_EQ(nodus_delegation_get(&w, missing_del, missing_val, &d_out), 1);

    /* ── 3: update changes amount + reward_snapshot ───────────── */
    d_in.amount = 2000000;
    d_in.delegated_at_block = 100;
    memset(d_in.reward_snapshot, 0x22, sizeof(d_in.reward_snapshot));
    CHECK_EQ(nodus_delegation_update(&w, &d_in), 0);

    memset(&d_out, 0, sizeof(d_out));
    CHECK_EQ(nodus_delegation_get(&w, d_in.delegator_pubkey,
                                   d_in.validator_pubkey, &d_out), 0);
    CHECK_EQ(d_out.amount, 2000000);
    CHECK_EQ(d_out.delegated_at_block, 100);
    CHECK_MEM_EQ(d_in.reward_snapshot, d_out.reward_snapshot,
                 sizeof(d_in.reward_snapshot));

    /* update on non-existent row → 1 */
    dnac_delegation_record_t d_missing;
    make_delegation(&d_missing, 0xFA, 0xFB, 1, 1, 0);
    CHECK_EQ(nodus_delegation_update(&w, &d_missing), 1);

    /* ── 4: delete + re-get returns 1 ─────────────────────────── */
    CHECK_EQ(nodus_delegation_delete(&w, d_in.delegator_pubkey,
                                      d_in.validator_pubkey), 0);
    CHECK_EQ(nodus_delegation_get(&w, d_in.delegator_pubkey,
                                   d_in.validator_pubkey, &d_out), 1);
    /* second delete → 1 (not found) */
    CHECK_EQ(nodus_delegation_delete(&w, d_in.delegator_pubkey,
                                      d_in.validator_pubkey), 1);

    /* ── 5: count by delegator == 5 after 5 inserts ───────────── */
    uint8_t delegator_A[DNAC_PUBKEY_SIZE];
    fill_pubkey(delegator_A, 0x20);

    for (int i = 0; i < 5; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, delegator_A, DNAC_PUBKEY_SIZE);
        /* Distinct validator per insert */
        fill_pubkey(d.validator_pubkey, (uint8_t)(0x90 + i));
        d.amount = 1000 + (uint64_t)i;
        d.delegated_at_block = 50 + (uint64_t)i;
        memset(d.reward_snapshot, (uint8_t)(0x30 + i),
               sizeof(d.reward_snapshot));
        CHECK_EQ(nodus_delegation_insert(&w, &d), 0);
    }

    int count_A = -1;
    CHECK_EQ(nodus_delegation_count_by_delegator(&w, delegator_A,
                                                  &count_A), 0);
    CHECK_EQ(count_A, 5);

    /* ── 6: count by delegator == 0 when delegator has no rows ── */
    uint8_t delegator_Z[DNAC_PUBKEY_SIZE];
    fill_pubkey(delegator_Z, 0xEE);
    int count_Z = -1;
    CHECK_EQ(nodus_delegation_count_by_delegator(&w, delegator_Z,
                                                  &count_Z), 0);
    CHECK_EQ(count_Z, 0);

    /* ── 7: list by delegator across two delegators ───────────── */
    /* delegator_A already has 5. Add 2 rows for delegator_B. */
    uint8_t delegator_B[DNAC_PUBKEY_SIZE];
    fill_pubkey(delegator_B, 0x40);
    for (int i = 0; i < 2; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, delegator_B, DNAC_PUBKEY_SIZE);
        fill_pubkey(d.validator_pubkey, (uint8_t)(0xA0 + i));
        d.amount = 7777 + (uint64_t)i;
        d.delegated_at_block = 200 + (uint64_t)i;
        memset(d.reward_snapshot, (uint8_t)(0x50 + i),
               sizeof(d.reward_snapshot));
        CHECK_EQ(nodus_delegation_insert(&w, &d), 0);
    }

    dnac_delegation_record_t list_buf[16];
    int list_n = -1;

    /* Subtest 7a: list_by_delegator(A) returns 5 */
    CHECK_EQ(nodus_delegation_list_by_delegator(&w, delegator_A,
                                                 list_buf, 16, &list_n), 0);
    CHECK_EQ(list_n, 5);
    for (int i = 0; i < list_n; i++) {
        CHECK_MEM_EQ(list_buf[i].delegator_pubkey, delegator_A,
                     DNAC_PUBKEY_SIZE);
    }

    /* Subtest 7b: list_by_delegator(B) returns 2 */
    CHECK_EQ(nodus_delegation_list_by_delegator(&w, delegator_B,
                                                 list_buf, 16, &list_n), 0);
    CHECK_EQ(list_n, 2);
    for (int i = 0; i < list_n; i++) {
        CHECK_MEM_EQ(list_buf[i].delegator_pubkey, delegator_B,
                     DNAC_PUBKEY_SIZE);
    }

    /* ── 8: list by validator ─────────────────────────────────── */
    /* Three delegators all pointing at the same validator. */
    uint8_t validator_S[DNAC_PUBKEY_SIZE];
    fill_pubkey(validator_S, 0xC0);
    for (int i = 0; i < 3; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        fill_pubkey(d.delegator_pubkey, (uint8_t)(0x60 + i));
        memcpy(d.validator_pubkey, validator_S, DNAC_PUBKEY_SIZE);
        d.amount = 500 + (uint64_t)i;
        d.delegated_at_block = 300 + (uint64_t)i;
        memset(d.reward_snapshot, (uint8_t)(0x70 + i),
               sizeof(d.reward_snapshot));
        CHECK_EQ(nodus_delegation_insert(&w, &d), 0);
    }
    CHECK_EQ(nodus_delegation_list_by_validator(&w, validator_S,
                                                 list_buf, 16, &list_n), 0);
    CHECK_EQ(list_n, 3);
    for (int i = 0; i < list_n; i++) {
        CHECK_MEM_EQ(list_buf[i].validator_pubkey, validator_S,
                     DNAC_PUBKEY_SIZE);
    }

    /* ── 9: 64-cap simulation ─────────────────────────────────── */
    uint8_t delegator_C[DNAC_PUBKEY_SIZE];
    fill_pubkey(delegator_C, 0x70);
    for (int i = 0; i < 64; i++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, delegator_C, DNAC_PUBKEY_SIZE);
        /* 64 distinct validators — vary across 2 bytes to stay unique. */
        fill_pubkey(d.validator_pubkey, (uint8_t)(i + 1));
        d.validator_pubkey[1] = (uint8_t)(0xF0 + i);
        d.amount = 1;
        d.delegated_at_block = 400;
        CHECK_EQ(nodus_delegation_insert(&w, &d), 0);
    }
    int count_C = -1;
    CHECK_EQ(nodus_delegation_count_by_delegator(&w, delegator_C,
                                                  &count_C), 0);
    CHECK_EQ(count_C, 64);

    /* 65th row: CRUD layer does NOT enforce the 64 cap — that's a
     * verify-side rule. Just confirm the counter advances past 64 so
     * the verify check has a reliable signal. */
    {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, delegator_C, DNAC_PUBKEY_SIZE);
        fill_pubkey(d.validator_pubkey, 0x05);
        d.validator_pubkey[1] = 0xBE;  /* distinct from 64-cap pattern */
        d.validator_pubkey[2] = 0xEF;
        d.amount = 1;
        d.delegated_at_block = 401;
        CHECK_EQ(nodus_delegation_insert(&w, &d), 0);
    }
    CHECK_EQ(nodus_delegation_count_by_delegator(&w, delegator_C,
                                                  &count_C), 0);
    CHECK_EQ(count_C, 65);

    /* ── bonus: duplicate insert (same PK pair) returns -2 ───── */
    {
        dnac_delegation_record_t dup;
        memset(&dup, 0, sizeof(dup));
        memcpy(dup.delegator_pubkey, delegator_A, DNAC_PUBKEY_SIZE);
        /* Use validator from the 5-insert batch (0x90) */
        fill_pubkey(dup.validator_pubkey, 0x90);
        dup.amount = 1;
        dup.delegated_at_block = 1;
        CHECK_EQ(nodus_delegation_insert(&w, &dup), -2);
    }

    /* Tear down. */
    sqlite3_close(w.db);
    w.db = NULL;
    rmrf(data_path);

    printf("test_delegation_db: ALL CHECKS PASSED\n");
    return 0;
}
