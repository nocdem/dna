/*
 * v0.16 Stage B.1 — epoch_state CRUD smoke test.
 *
 * Exercises insert / get / update / add_pool / delete over a freshly
 * created witness DB. No genesis, no BFT — pure schema-level coverage.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_epoch.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

#define CHECK_EQ(a, b) CHECK((int64_t)(a) == (int64_t)(b))

int main(void) {
    /* Run dir. */
    char data_path[] = "/tmp/test_epoch_state_XXXXXX";
    if (!mkdtemp(data_path)) {
        perror("mkdtemp");
        return 1;
    }

    /* Create witness + open chain DB (reuses the schema in
     * nodus_witness.c WITNESS_DB_SCHEMA, which includes epoch_state
     * from Stage B.1). */
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xEE, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);
    CHECK(w.db != NULL);

    /* Insert a row. */
    nodus_epoch_state_t e = {0};
    e.epoch_start_height = 120;
    e.epoch_pool_accum   = 0;
    memset(e.snapshot_hash, 0xA1, sizeof(e.snapshot_hash));
    /* No snapshot_blob this time. */
    CHECK_EQ(nodus_witness_epoch_insert(&w, &e), 0);

    /* Duplicate insert → -2 (PRIMARY KEY conflict). */
    CHECK_EQ(nodus_witness_epoch_insert(&w, &e), -2);

    /* Get it back. */
    nodus_epoch_state_t got = {0};
    CHECK_EQ(nodus_witness_epoch_get(&w, 120, &got), 0);
    CHECK_EQ(got.epoch_start_height, 120);
    CHECK_EQ(got.epoch_pool_accum, 0);
    CHECK(memcmp(got.snapshot_hash, e.snapshot_hash, 64) == 0);
    CHECK(got.snapshot_blob == NULL);
    nodus_witness_epoch_free(&got);

    /* add_pool: bump by 5000. */
    CHECK_EQ(nodus_witness_epoch_add_pool(&w, 120, 5000), 0);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get(&w, 120, &got), 0);
    CHECK_EQ(got.epoch_pool_accum, 5000);
    nodus_witness_epoch_free(&got);

    /* set_pool_accum overwrites. */
    CHECK_EQ(nodus_witness_epoch_set_pool_accum(&w, 120, 42), 0);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get(&w, 120, &got), 0);
    CHECK_EQ(got.epoch_pool_accum, 42);
    nodus_witness_epoch_free(&got);

    /* Insert a second row to test get_current. */
    nodus_epoch_state_t e2 = {0};
    e2.epoch_start_height = 240;
    e2.epoch_pool_accum   = 777;
    memset(e2.snapshot_hash, 0xB2, sizeof(e2.snapshot_hash));
    CHECK_EQ(nodus_witness_epoch_insert(&w, &e2), 0);

    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get_current(&w, &got), 0);
    CHECK_EQ(got.epoch_start_height, 240);
    CHECK_EQ(got.epoch_pool_accum, 777);
    nodus_witness_epoch_free(&got);

    /* Delete the older epoch. */
    CHECK_EQ(nodus_witness_epoch_delete(&w, 120), 0);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get(&w, 120, &got), 1);   /* miss */

    /* get_current still returns 240. */
    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get_current(&w, &got), 0);
    CHECK_EQ(got.epoch_start_height, 240);
    nodus_witness_epoch_free(&got);

    /* Delete the remaining row; table is now empty. */
    CHECK_EQ(nodus_witness_epoch_delete(&w, 240), 0);
    memset(&got, 0, sizeof(got));
    CHECK_EQ(nodus_witness_epoch_get_current(&w, &got), 1);

    /* Cleanup. */
    sqlite3_close(w.db);

    printf("test_epoch_state: ALL CHECKS PASSED\n");
    return 0;
}
