/**
 * Nodus — Consistent Hash Ring Tests
 */

#include "channel/nodus_hashring.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_key_t make_node_id(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

static void test_init(void) {
    TEST("init ring");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);
    if (ring.count == 0 && ring.version == 1)
        PASS();
    else
        FAIL("init wrong");
}

static void test_add_remove(void) {
    TEST("add and remove nodes");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t id1 = make_node_id(0x11);
    nodus_key_t id2 = make_node_id(0x22);
    nodus_key_t id3 = make_node_id(0x33);

    nodus_hashring_add(&ring, &id1, "10.0.0.1", 4001);
    nodus_hashring_add(&ring, &id2, "10.0.0.2", 4001);
    nodus_hashring_add(&ring, &id3, "10.0.0.3", 4001);

    if (nodus_hashring_count(&ring) != 3) {
        FAIL("wrong count after add");
        return;
    }

    nodus_hashring_remove(&ring, &id2);
    if (nodus_hashring_count(&ring) == 2 &&
        !nodus_hashring_contains(&ring, &id2))
        PASS();
    else
        FAIL("remove failed");
}

static void test_duplicate_rejected(void) {
    TEST("duplicate add rejected");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t id = make_node_id(0xAA);
    nodus_hashring_add(&ring, &id, "10.0.0.1", 4001);
    int rc = nodus_hashring_add(&ring, &id, "10.0.0.2", 4001);

    if (rc == -1 && nodus_hashring_count(&ring) == 1)
        PASS();
    else
        FAIL("should reject duplicate");
}

static void test_responsible_3_nodes(void) {
    TEST("responsible set with 3 nodes");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t id1 = make_node_id(0x11);
    nodus_key_t id2 = make_node_id(0x55);
    nodus_key_t id3 = make_node_id(0xAA);

    nodus_hashring_add(&ring, &id1, "10.0.0.1", 4001);
    nodus_hashring_add(&ring, &id2, "10.0.0.2", 4001);
    nodus_hashring_add(&ring, &id3, "10.0.0.3", 4001);

    uint8_t ch_uuid[16];
    memset(ch_uuid, 0x42, sizeof(ch_uuid));

    nodus_responsible_set_t result;
    int rc = nodus_hashring_responsible(&ring, ch_uuid, &result);

    if (rc == 0 && result.count == 3)
        PASS();
    else
        FAIL("expected 3 responsible nodes");
}

static void test_responsible_deterministic(void) {
    TEST("responsible set is deterministic");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t ids[5];
    for (int i = 0; i < 5; i++) {
        memset(ids[i].bytes, 0, NODUS_KEY_BYTES);
        ids[i].bytes[0] = (uint8_t)(0x10 * (i + 1));
        char ip[16];
        snprintf(ip, sizeof(ip), "10.0.0.%d", i + 1);
        nodus_hashring_add(&ring, &ids[i], ip, 4001);
    }

    uint8_t ch_uuid[16];
    memset(ch_uuid, 0x77, sizeof(ch_uuid));

    nodus_responsible_set_t r1, r2;
    nodus_hashring_responsible(&ring, ch_uuid, &r1);
    nodus_hashring_responsible(&ring, ch_uuid, &r2);

    if (r1.count == r2.count &&
        nodus_key_cmp(&r1.nodes[0].node_id, &r2.nodes[0].node_id) == 0 &&
        nodus_key_cmp(&r1.nodes[1].node_id, &r2.nodes[1].node_id) == 0 &&
        nodus_key_cmp(&r1.nodes[2].node_id, &r2.nodes[2].node_id) == 0)
        PASS();
    else
        FAIL("results differ");
}

static void test_responsible_fewer_than_r(void) {
    TEST("responsible set with fewer than R nodes");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    nodus_key_t id = make_node_id(0x01);
    nodus_hashring_add(&ring, &id, "10.0.0.1", 4001);

    uint8_t ch_uuid[16] = {0};
    nodus_responsible_set_t result;
    int rc = nodus_hashring_responsible(&ring, ch_uuid, &result);

    if (rc == 0 && result.count == 1 &&
        nodus_key_cmp(&result.nodes[0].node_id, &id) == 0)
        PASS();
    else
        FAIL("should return 1 node");
}

static void test_version_increments(void) {
    TEST("version increments on add/remove");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);
    uint32_t v0 = ring.version;

    nodus_key_t id = make_node_id(0x01);
    nodus_hashring_add(&ring, &id, "10.0.0.1", 4001);
    uint32_t v1 = ring.version;

    nodus_hashring_remove(&ring, &id);
    uint32_t v2 = ring.version;

    if (v1 > v0 && v2 > v1)
        PASS();
    else
        FAIL("version didn't increment");
}

static void test_different_channels_different_primary(void) {
    TEST("different channels may get different primaries");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    /* Add 10 well-distributed nodes */
    for (int i = 0; i < 10; i++) {
        nodus_key_t id;
        memset(id.bytes, 0, NODUS_KEY_BYTES);
        id.bytes[0] = (uint8_t)(25 * i);
        char ip[16];
        snprintf(ip, sizeof(ip), "10.0.%d.1", i);
        nodus_hashring_add(&ring, &id, ip, 4001);
    }

    /* Check 100 random UUIDs — at least some should have different primaries */
    int different_primaries = 0;
    nodus_key_t first_primary;
    memset(&first_primary, 0, sizeof(first_primary));

    for (int i = 0; i < 100; i++) {
        uint8_t ch_uuid[16];
        memset(ch_uuid, (uint8_t)i, sizeof(ch_uuid));
        ch_uuid[0] = (uint8_t)(i * 7);  /* Vary more */

        nodus_responsible_set_t result;
        nodus_hashring_responsible(&ring, ch_uuid, &result);

        if (i == 0) {
            first_primary = result.nodes[0].node_id;
        } else if (nodus_key_cmp(&result.nodes[0].node_id, &first_primary) != 0) {
            different_primaries++;
        }
    }

    if (different_primaries > 0)
        PASS();
    else
        FAIL("all 100 channels got same primary");
}

static void test_empty_ring(void) {
    TEST("responsible on empty ring returns error");
    nodus_hashring_t ring;
    nodus_hashring_init(&ring);

    uint8_t ch_uuid[16] = {0};
    nodus_responsible_set_t result;
    int rc = nodus_hashring_responsible(&ring, ch_uuid, &result);

    if (rc == -1)
        PASS();
    else
        FAIL("should return error");
}

int main(void) {
    printf("=== Nodus Hash Ring Tests ===\n");

    test_init();
    test_add_remove();
    test_duplicate_rejected();
    test_responsible_3_nodes();
    test_responsible_deterministic();
    test_responsible_fewer_than_r();
    test_version_increments();
    test_different_channels_different_primary();
    test_empty_ring();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
