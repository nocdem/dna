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
 *   - S3: param 4 (TARGET_ACTIVE_COUNT) is reachable through the override
 *     cache and contributes to chain_config_root
 *
 * Full apply-path end-to-end (Dilithium5 vote verification against a
 * seeded committee) is deferred to Stage C integration tests once the
 * vote-collect RPC is wired.
 *
 * FIXTURE (S3): nodus_witness_t is multi-MB and grew again with the
 * active-validator generalization — calloc, never the stack. Same rule as
 * test_chain_config_cache_failclose.c.
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

/* O15J Block 2 (A2): nodus_chain_config_get_u64 is three-valued now —
 * 0 override present / 1 genuinely absent / -1 cannot determine — and
 * writes through an out-parameter. Every assertion in THIS file is about
 * the VALUE (override semantics, latest-effective-wins, param
 * reachability), none about the fault channel, so this helper keeps the
 * original one-line shape.
 *
 * A fault deliberately maps to UINT64_MAX, a value no assertion here
 * expects, so a fault that leaked into a value test fails loudly instead
 * of masquerading as the default. The fault channel itself is pinned by
 * test_chain_config_failclose.c. */
static uint64_t cfg_val(nodus_witness_t *w, uint8_t param_id,
                        uint64_t current_block, uint64_t default_value) {
    uint64_t v = 0;
    int rc = nodus_chain_config_get_u64(w, param_id, current_block,
                                        default_value, &v);
    if (rc < 0) {
        fprintf(stderr, "cfg_val: unexpected FAULT for param %u at %llu\n",
                (unsigned)param_id, (unsigned long long)current_block);
        return UINT64_MAX;
    }
    return v;
}

/* Bring up a witness with a fresh data_path and chain DB; the
 * nodus_witness_create_chain_db call runs the full migration chain
 * including our new nodus_chain_config_db_migrate. Returns data_path
 * so the test can tear it down.
 *
 * The context is HEAP allocated (see the FIXTURE note in the file header). */
static nodus_witness_t *setup_witness(char data_path[64]) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL);
    snprintf(data_path, 64, "/tmp/test_chain_config_XXXXXX");
    CHECK(mkdtemp(data_path) != NULL);
    snprintf(w->data_path, sizeof(w->data_path), "%s", data_path);
    uint8_t chain_id[16];
    memset(chain_id, 0xC1, sizeof(chain_id));
    CHECK(nodus_witness_create_chain_db(w, chain_id) == 0);
    CHECK(w->db != NULL);
    return w;
}

static void teardown_witness(nodus_witness_t *w, const char *data_path) {
    if (w && w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
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
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        const char *q =
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='chain_config_history'";
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, q, -1, &st, NULL) == SQLITE_OK);
        CHECK(sqlite3_step(st) == SQLITE_ROW);
        int count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        CHECK(count == 1);
        CHECK(nodus_chain_config_db_migrate(w) == 0);   /* idempotent */
        teardown_witness(w, data_path);
    }

    /* Test 2: empty-table lookup returns default_value. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 1000, 42ULL) == 42ULL);
        CHECK(cfg_val(w, DNAC_CFG_INFLATION_START_BLOCK, 5000, 1ULL) == 1ULL);
        /* O15J A2: an EMPTY table is ABSENT (rc 1), never a fault — this
         * is the pin that keeps a pre-genesis / freshly-bootstrapped node
         * starting. */
        {
            uint64_t v = 0;
            CHECK(nodus_chain_config_get_u64(w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                                             1000, 42ULL, &v) == 1);
            CHECK(v == 42ULL);
        }
        teardown_witness(w, data_path);
    }

    /* Test 3: single INSERT, lookup semantics before/at/after effective. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        direct_insert(w, DNAC_CFG_MAX_TXS_PER_BLOCK,
                       5ULL, 1000ULL, 800ULL, 0xABCDULL);

        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK,  999ULL, 10ULL) == 10ULL);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 1000ULL, 10ULL) ==  5ULL);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 9999ULL, 10ULL) ==  5ULL);
        CHECK(cfg_val(w, DNAC_CFG_BLOCK_INTERVAL_SEC, 9999ULL, 5ULL) ==  5ULL);
        teardown_witness(w, data_path);
    }

    /* Test 4: monotonic latest-effective-wins. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        direct_insert(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 3ULL, 1000ULL, 800ULL,  0x1ULL);
        direct_insert(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 7ULL, 2000ULL, 1500ULL, 0x2ULL);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 1500ULL, 99ULL) == 3ULL);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 2000ULL, 99ULL) == 7ULL);
        CHECK(cfg_val(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 5000ULL, 99ULL) == 7ULL);
        teardown_witness(w, data_path);
    }

    /* Test 5: compute_root on empty table = tagged empty sentinel. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        uint8_t root_empty[64];
        CHECK(nodus_chain_config_compute_root(w, root_empty) == 0);

        uint8_t expected[64];
        nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG, expected);
        CHECK(memcmp(root_empty, expected, 64) == 0);

        uint8_t zeros[64] = {0};
        CHECK(memcmp(root_empty, zeros, 64) != 0);
        teardown_witness(w, data_path);
    }

    /* Test 6: compute_root determinism + sensitivity. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);
        direct_insert(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 5ULL, 1000ULL, 800ULL,  0x11ULL);
        direct_insert(w, DNAC_CFG_BLOCK_INTERVAL_SEC, 3ULL, 2000ULL, 1500ULL, 0x22ULL);
        uint8_t r1[64], r2[64];
        CHECK(nodus_chain_config_compute_root(w, r1) == 0);
        CHECK(nodus_chain_config_compute_root(w, r2) == 0);
        CHECK(memcmp(r1, r2, 64) == 0);

        char *err = NULL;
        int srv = sqlite3_exec(w->db,
            "UPDATE chain_config_history SET new_value = 99 "
            "WHERE param_id = 1", NULL, NULL, &err);
        CHECK(srv == SQLITE_OK);
        if (err) sqlite3_free(err);

        uint8_t r3[64];
        CHECK(nodus_chain_config_compute_root(w, r3) == 0);
        CHECK(memcmp(r1, r3, 64) != 0);
        teardown_witness(w, data_path);
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

    /* Test 8 (S3): param 4 = TARGET_ACTIVE_COUNT is REACHABLE.
     *
     * Pre-S3 the override cache was dimensioned to a literal 4 and
     * nodus_chain_config_get_u64 short-circuited every param_id >= 4 to
     * default_value. If either literal survived the generalization, the
     * assertions below return the default and fail — this is the direct
     * regression pin for the cache-dimension change. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);

        /* Cold cache, DB-direct path. */
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 1000ULL, 7ULL) == 7ULL);

        direct_insert(w, DNAC_CFG_TARGET_ACTIVE_COUNT,
                       21ULL, 5000ULL, 4000ULL, 0x44ULL);
        w->chain_config_cache_warm = false;   /* force a re-warm over the new row */

        /* Before / at / after the effective height. */
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 4999ULL, 7ULL) ==  7ULL);
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 5000ULL, 7ULL) == 21ULL);
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 9999ULL, 7ULL) == 21ULL);

        /* Served from the warm cache (not just the DB fallback), and the
         * param-4 row really occupies a cache slot. */
        CHECK(w->chain_config_cache_warm);
        CHECK(w->chain_config_cache_count[DNAC_CFG_TARGET_ACTIVE_COUNT] == 1);

        /* Latest-effective-wins holds for the new param too. */
        direct_insert(w, DNAC_CFG_TARGET_ACTIVE_COUNT,
                       128ULL, 9000ULL, 8000ULL, 0x55ULL);
        w->chain_config_cache_warm = false;
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 8999ULL, 7ULL) ==  21ULL);
        CHECK(cfg_val(w, DNAC_CFG_TARGET_ACTIVE_COUNT, 9000ULL, 7ULL) == 128ULL);

        /* Still out of range one past the allowlist — the guard moved, it
         * did not disappear.
         *
         * O15J A2 changed what out-of-range MEANS: it used to hand back
         * default_value, which is the same answer as "this param has no
         * override" and so let a typo'd id read as unconfigured chain
         * state. An id outside the allowlist is a CALLER bug, and the
         * contract's answer for "I cannot tell you" is -1. The
         * out-parameter is left untouched. */
        {
            uint64_t v = 0xA5A5A5A5A5A5A5A5ULL;
            CHECK(nodus_chain_config_get_u64(
                      w, (uint8_t)(DNAC_CFG_PARAM_MAX_ID + 1),
                      9999ULL, 1234ULL, &v) == -1);
            CHECK(v == 0xA5A5A5A5A5A5A5A5ULL);
        }

        teardown_witness(w, data_path);
    }

    /* Test 9 (S3): a param-4 row changes chain_config_root, i.e. the new
     * parameter is bound into state_root like every other override. A
     * governed parameter that did NOT contribute would let two witnesses
     * hold different active-set targets under an identical state_root. */
    {
        char data_path[64];
        nodus_witness_t *w = setup_witness(data_path);

        uint8_t r_before[64], r_after[64], r_again[64];
        direct_insert(w, DNAC_CFG_MAX_TXS_PER_BLOCK, 5ULL, 1000ULL, 800ULL, 0x11ULL);
        CHECK(nodus_chain_config_compute_root(w, r_before) == 0);

        direct_insert(w, DNAC_CFG_TARGET_ACTIVE_COUNT,
                       21ULL, 5000ULL, 4000ULL, 0x66ULL);
        CHECK(nodus_chain_config_compute_root(w, r_after) == 0);
        CHECK(memcmp(r_before, r_after, 64) != 0);

        /* Deterministic: same rows, same root. */
        CHECK(nodus_chain_config_compute_root(w, r_again) == 0);
        CHECK(memcmp(r_after, r_again, 64) == 0);

        /* And the param-4 VALUE is bound, not just its presence. */
        char *err = NULL;
        int srv = sqlite3_exec(w->db,
            "UPDATE chain_config_history SET new_value = 22 "
            "WHERE param_id = 4", NULL, NULL, &err);
        CHECK(srv == SQLITE_OK);
        if (err) sqlite3_free(err);

        uint8_t r_mut[64];
        CHECK(nodus_chain_config_compute_root(w, r_mut) == 0);
        CHECK(memcmp(r_after, r_mut, 64) != 0);

        teardown_witness(w, data_path);
    }

    printf("test_chain_config_witness: ALL CHECKS PASSED\n");
    return 0;
}
