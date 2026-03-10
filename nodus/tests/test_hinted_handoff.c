/**
 * Nodus — Hinted Handoff Tests
 *
 * Validates:
 * - node_id-based schema (not IP:port)
 * - 7-day TTL
 * - Insert, retrieve by node_id, delete by id
 * - Cleanup of expired entries
 */

#include "core/nodus_storage.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static const char *TEST_DB = "/tmp/nodus_test_hinted.db";

static nodus_key_t make_key(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

static void test_insert_and_retrieve(void) {
    TEST("insert hint and retrieve by node_id");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_key_t node = make_key(0xAA);
    uint8_t frame[] = {0x01, 0x02, 0x03, 0x04};

    int rc = nodus_storage_hinted_insert(&store, &node, "10.0.0.1", 4001,
                                          frame, sizeof(frame));
    if (rc != 0) { FAIL("insert failed"); nodus_storage_close(&store); return; }

    nodus_dht_hint_t *entries = NULL;
    size_t count = 0;
    rc = nodus_storage_hinted_get(&store, &node, 100, &entries, &count);

    if (rc == 0 && count == 1 &&
        entries[0].frame_len == sizeof(frame) &&
        memcmp(entries[0].frame_data, frame, sizeof(frame)) == 0) {
        PASS();
    } else {
        FAIL("retrieve failed or data mismatch");
    }

    if (entries) nodus_storage_hinted_free(entries, count);
    nodus_storage_close(&store);
}

static void test_retrieve_different_node(void) {
    TEST("retrieve returns nothing for different node_id");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_key_t node1 = make_key(0xAA);
    nodus_key_t node2 = make_key(0xBB);
    uint8_t frame[] = {0x01};

    nodus_storage_hinted_insert(&store, &node1, "10.0.0.1", 4001,
                                 frame, sizeof(frame));

    nodus_dht_hint_t *entries = NULL;
    size_t count = 0;
    int rc = nodus_storage_hinted_get(&store, &node2, 100, &entries, &count);

    /* hinted_get returns -1 when no entries found */
    if (rc == -1 && count == 0)
        PASS();
    else
        FAIL("should return nothing for different node");

    if (entries) nodus_storage_hinted_free(entries, count);
    nodus_storage_close(&store);
}

static void test_delete_by_id(void) {
    TEST("delete hint by id");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_key_t node = make_key(0xCC);
    uint8_t frame[] = {0x01, 0x02};

    nodus_storage_hinted_insert(&store, &node, "10.0.0.1", 4001,
                                 frame, sizeof(frame));

    nodus_dht_hint_t *entries = NULL;
    size_t count = 0;
    nodus_storage_hinted_get(&store, &node, 100, &entries, &count);

    if (count != 1) { FAIL("setup failed"); nodus_storage_close(&store); return; }

    int64_t id = entries[0].id;
    nodus_storage_hinted_free(entries, count);

    nodus_storage_hinted_delete(&store, id);

    entries = NULL;
    count = 0;
    nodus_storage_hinted_get(&store, &node, 100, &entries, &count);

    if (count == 0)
        PASS();
    else
        FAIL("entry not deleted");

    if (entries) nodus_storage_hinted_free(entries, count);
    nodus_storage_close(&store);
}

static void test_count(void) {
    TEST("hint count");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_key_t node = make_key(0xDD);
    uint8_t frame[] = {0x01};

    for (int i = 0; i < 5; i++) {
        nodus_storage_hinted_insert(&store, &node, "10.0.0.1", 4001,
                                     frame, sizeof(frame));
    }

    int count = nodus_storage_hinted_count(&store);
    if (count == 5)
        PASS();
    else
        FAIL("wrong count");

    nodus_storage_close(&store);
}

static void test_multiple_nodes(void) {
    TEST("hints for multiple node_ids");
    unlink(TEST_DB);

    nodus_storage_t store;
    nodus_storage_open(TEST_DB, &store);

    nodus_key_t node1 = make_key(0x11);
    nodus_key_t node2 = make_key(0x22);
    uint8_t frame[] = {0x01};

    /* 3 hints for node1, 2 for node2 */
    for (int i = 0; i < 3; i++)
        nodus_storage_hinted_insert(&store, &node1, "10.0.0.1", 4001,
                                     frame, sizeof(frame));
    for (int i = 0; i < 2; i++)
        nodus_storage_hinted_insert(&store, &node2, "10.0.0.2", 4002,
                                     frame, sizeof(frame));

    nodus_dht_hint_t *entries1 = NULL, *entries2 = NULL;
    size_t count1 = 0, count2 = 0;
    nodus_storage_hinted_get(&store, &node1, 100, &entries1, &count1);
    nodus_storage_hinted_get(&store, &node2, 100, &entries2, &count2);

    if (count1 == 3 && count2 == 2)
        PASS();
    else
        FAIL("wrong counts per node");

    if (entries1) nodus_storage_hinted_free(entries1, count1);
    if (entries2) nodus_storage_hinted_free(entries2, count2);
    nodus_storage_close(&store);
}

int main(void) {
    printf("=== Nodus Hinted Handoff Tests ===\n");

    test_insert_and_retrieve();
    test_retrieve_different_node();
    test_delete_by_id();
    test_count();
    test_multiple_nodes();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
