/**
 * Hard-Fork v1 -- witness-side chain_config unit tests.
 *
 * Covers:
 *   - DB migration creates chain_config_history table (idempotent)
 *   - Empty-table lookup returns default_value
 *   - Manual INSERT + lookup semantics (before/at/after effective_block)
 *   - Monotonic latest-effective-wins
 *   - compute_root: tagged empty sentinel (CC-AUDIT-003)
 *   - compute_root: determinism + row-mutation sensitivity
 *   - 5-input combiner: version byte binding + order sensitivity vs legacy 4-input
 *
 * Full apply-path end-to-end (Dilithium5 vote verification against a
 * seeded committee) is deferred to Stage C integration tests once the
 * vote-collect RPC is wired.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"

#include "dnac/dnac.h"

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

/* Bring up a witness with a fresh data_path and chain DB; the
 * nodus_witness_create_chain_db call runs the full migration chain
 * including our new nodus_chain_config_db_migrate. Returns data_path
 * so the test can tear it down. */
static void setup_witness(nodus_witness_t *w, char data_path[64]) {
    memset(w, 0, sizeof(*w));
    snprintf(data_path, 64, "/tmp/test_chain_config_XXXXXX");
    CHECK(mkdtemp(data_path) != NULL);
    snprintf(w->data_path, sizeof(w->data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    CHECK(nodus_witness_create_chain_db(w, chain_id) == 0);
    CHECK(w->db != NULL);
}

static void teardown_witness(nodus_witness_t *w, const char *data_path) {
    if (w && w->db) { sqlite3_close(w->db); w->db = NULL; }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", data_path);
    int rc = system(cmd);
    (void)rc;
}

static void direct_insert(nodus_witness_t *w,
                           uint8_t  param_id,
                           uint64_t new_value,
                           uint64_t effective_block,
                           uint64_t commit_block,
                           uint64_t proposal_nonce) {
    uint8_t tx_hash[64];
    memset(tx_hash, (int)(param_id + (uint8_t)commit_block), 64);

    const char *sql =
        "INSERT INTO chain_config_history "
        "(param_id, new_value, effective_block, commit_block, tx_hash, "
        " proposal_nonce, created_at_unix) "
        "VALUES (?, ?, ?, ?, ?, ?, 0)";
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) == SQLITE_OK);
    sqlite3_bind_int  (st, 1, param_id);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)new_value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective_block);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)commit_block);
    sqlite3_bind_blob (st, 5, tx_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)proposal_nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    CHECK(rc == SQLITE_DONE);
}

int main(void) {
    /* Test 1: migration creates the table; idempotent. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        const char *q =
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='chain_config_history'";
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w.db, q, -1, &st, NULL) == SQLITE_OK);
        CHECK(sqlite3_step(st) == SQLITE_ROW);
        int count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        CHECK(count == 1);
        CHECK(nodus_chain_config_db_migrate(&w) == 0);   /* idempotent */
        teardown_witness(&w, data_path);
    }

    /* Test 2: empty-table lookup returns default_value. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           1000, 42ULL) == 42ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_INFLATION_START_BLOCK,
                                           5000, 1ULL) == 1ULL);
        teardown_witness(&w, data_path);
    }

    /* Test 3: single INSERT, lookup semantics before/at/after effective. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        direct_insert(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                       5ULL, 1000ULL, 800ULL, 0xABCDULL);

        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           999ULL,  10ULL) == 10ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           1000ULL, 10ULL) == 5ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           9999ULL, 10ULL) == 5ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_BLOCK_INTERVAL_SEC,
                                           9999ULL, 5ULL) == 5ULL);
        teardown_witness(&w, data_path);
    }

    /* Test 4: monotonic latest-effective-wins. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        direct_insert(&w, DNAC_CFG_MAX_TXS_PER_BLOCK, 3ULL, 1000ULL, 800ULL,  0x1ULL);
        direct_insert(&w, DNAC_CFG_MAX_TXS_PER_BLOCK, 7ULL, 2000ULL, 1500ULL, 0x2ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           1500ULL, 99ULL) == 3ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           2000ULL, 99ULL) == 7ULL);
        CHECK(nodus_chain_config_get_u64(&w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                           5000ULL, 99ULL) == 7ULL);
        teardown_witness(&w, data_path);
    }

    /* Test 5: compute_root on empty table = tagged empty sentinel. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        uint8_t root_empty[64];
        CHECK(nodus_chain_config_compute_root(&w, root_empty) == 0);

        uint8_t expected[64];
        nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG, expected);
        CHECK(memcmp(root_empty, expected, 64) == 0);

        uint8_t zeros[64] = {0};
        CHECK(memcmp(root_empty, zeros, 64) != 0);
        teardown_witness(&w, data_path);
    }

    /* Test 6: compute_root determinism + sensitivity. */
    {
        nodus_witness_t w;
        char data_path[64];
        setup_witness(&w, data_path);
        direct_insert(&w, DNAC_CFG_MAX_TXS_PER_BLOCK, 5ULL, 1000ULL, 800ULL,  0x11ULL);
        direct_insert(&w, DNAC_CFG_BLOCK_INTERVAL_SEC, 3ULL, 2000ULL, 1500ULL, 0x22ULL);
        uint8_t r1[64], r2[64];
        CHECK(nodus_chain_config_compute_root(&w, r1) == 0);
        CHECK(nodus_chain_config_compute_root(&w, r2) == 0);
        CHECK(memcmp(r1, r2, 64) == 0);

        char *err = NULL;
        int srv = sqlite3_exec(w.db,
            "UPDATE chain_config_history SET new_value = 99 "
            "WHERE param_id = 1", NULL, NULL, &err);
        CHECK(srv == SQLITE_OK);
        if (err) sqlite3_free(err);

        uint8_t r3[64];
        CHECK(nodus_chain_config_compute_root(&w, r3) == 0);
        CHECK(memcmp(r1, r3, 64) != 0);
        teardown_witness(&w, data_path);
    }

    /* Test 7: 5-input combiner domain separation vs legacy 4-input. */
    {
        uint8_t utxo_root[64]       = {0};
        uint8_t validator_root[64];  nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR,    validator_root);
        uint8_t delegation_root[64]; nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION,   delegation_root);
        uint8_t reward_root[64];     nodus_merkle_empty_root(NODUS_TREE_TAG_REWARD,       reward_root);
        uint8_t cc_root[64];         nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG, cc_root);

        uint8_t legacy[64], v2[64];
        nodus_merkle_combine_state_root_v1_legacy(utxo_root, validator_root,
                                                   delegation_root, reward_root,
                                                   legacy);
        nodus_merkle_combine_state_root_v2(utxo_root, validator_root,
                                            delegation_root, reward_root,
                                            cc_root, v2);
        CHECK(memcmp(legacy, v2, 64) != 0);

        uint8_t swapped[64];
        nodus_merkle_combine_state_root_v2(validator_root, utxo_root,
                                            delegation_root, reward_root,
                                            cc_root, swapped);
        CHECK(memcmp(v2, swapped, 64) != 0);

        uint8_t again[64];
        nodus_merkle_combine_state_root_v2(utxo_root, validator_root,
                                            delegation_root, reward_root,
                                            cc_root, again);
        CHECK(memcmp(v2, again, 64) == 0);

        uint8_t cc_root_2[64]; memset(cc_root_2, 0x42, 64);
        uint8_t v2_b[64];
        nodus_merkle_combine_state_root_v2(utxo_root, validator_root,
                                            delegation_root, reward_root,
                                            cc_root_2, v2_b);
        CHECK(memcmp(v2, v2_b, 64) != 0);
    }

    printf("test_chain_config_witness: ALL CHECKS PASSED\n");
    return 0;
}
