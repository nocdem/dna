/*
 * v0.16 Stage D.2 — epoch snapshot determinism smoke.
 *
 * The full canonical-ordering coverage (shuffle validator/delegation
 * insert order → identical snapshot_hash, RT-C3) is delegated to the
 * Stage F cluster harness where a live BFT run exercises the real
 * committee accessor + insertion path. Here we verify the two
 * properties that are cheap in isolation:
 *
 *   1. snapshot_apply on an empty chain succeeds and persists a
 *      deterministic hash of the canonical "empty snapshot".
 *   2. Running snapshot_apply twice in a row on identical DB state
 *      produces the same snapshot_hash (idempotence).
 *
 * The actual committee/delegation fixture requires a witness with
 * the full committee-election schema + populated validator rows;
 * Stage F's stagef_up harness builds that. This smoke is a
 * deliberate subset — byte-identical hash + idempotence.
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
    char data_path[] = "/tmp/test_epoch_snapshot_XXXXXX";
    CHECK(mkdtemp(data_path) != NULL);

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.data_path, sizeof(w.data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xD5, sizeof(chain_id));
    CHECK_EQ(nodus_witness_create_chain_db(&w, chain_id), 0);
    CHECK(w.db != NULL);

    /* Empty chain: snapshot_apply should succeed. committee_get_for_block
     * returns empty committee; snapshot_blob becomes 0x0000 (u16
     * committee_count=0) || 0x00000000 (u32 delegation_count=0). */
    uint64_t h = (uint64_t)DNAC_EPOCH_LENGTH;
    CHECK_EQ(nodus_witness_epoch_snapshot_apply(&w, h), 0);

    /* Fetch the row. */
    nodus_epoch_state_t e1 = {0};
    CHECK_EQ(nodus_witness_epoch_get(&w, h, &e1), 0);
    CHECK(e1.snapshot_blob != NULL);
    CHECK_EQ(e1.snapshot_blob_len, 6);   /* 2-byte u16 + 4-byte u32 */
    /* All zero body => 6 bytes of 0x00. */
    for (size_t i = 0; i < 6; i++) {
        CHECK_EQ(e1.snapshot_blob[i], 0);
    }

    /* Capture hash. */
    uint8_t hash_first[NODUS_EPOCH_SNAPSHOT_HASH_LEN];
    memcpy(hash_first, e1.snapshot_hash, sizeof(hash_first));
    nodus_witness_epoch_free(&e1);

    /* Idempotence: call snapshot_apply AGAIN with no state change →
     * identical snapshot_hash persists. */
    CHECK_EQ(nodus_witness_epoch_snapshot_apply(&w, h), 0);
    nodus_epoch_state_t e2 = {0};
    CHECK_EQ(nodus_witness_epoch_get(&w, h, &e2), 0);
    CHECK(memcmp(hash_first, e2.snapshot_hash, sizeof(hash_first)) == 0);
    CHECK_EQ(e2.snapshot_blob_len, 6);
    nodus_witness_epoch_free(&e2);

    /* A second epoch at a DIFFERENT height — with no committee change —
     * produces the same snapshot_hash (the hash is over blob contents,
     * not the key). */
    uint64_t h2 = 240;
    CHECK_EQ(nodus_witness_epoch_snapshot_apply(&w, h2), 0);
    nodus_epoch_state_t e3 = {0};
    CHECK_EQ(nodus_witness_epoch_get(&w, h2, &e3), 0);
    CHECK(memcmp(hash_first, e3.snapshot_hash, sizeof(hash_first)) == 0);
    nodus_witness_epoch_free(&e3);

    sqlite3_close(w.db);
    printf("test_epoch_snapshot: ALL CHECKS PASSED\n");
    return 0;
}
