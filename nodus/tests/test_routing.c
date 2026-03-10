/**
 * Nodus — Kademlia Routing Table Tests
 */

#include "core/nodus_routing.h"
#include "crypto/nodus_sign.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static nodus_key_t make_key(uint8_t fill) {
    nodus_key_t k;
    memset(k.bytes, fill, NODUS_KEY_BYTES);
    return k;
}

static nodus_peer_t make_peer(uint8_t id_fill, const char *ip, uint16_t port) {
    nodus_peer_t p;
    memset(&p, 0, sizeof(p));
    memset(p.node_id.bytes, id_fill, NODUS_KEY_BYTES);
    strncpy(p.ip, ip, sizeof(p.ip) - 1);
    p.udp_port = port;
    p.tcp_port = port + 1;
    p.last_seen = (uint64_t)time(NULL);
    return p;
}

static void test_init(void) {
    TEST("init routing table");
    nodus_key_t self = make_key(0x01);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    if (nodus_routing_count(&rt) == 0 &&
        nodus_key_cmp(&rt.self_id, &self) == 0)
        PASS();
    else
        FAIL("init failed");
}

static void test_insert_and_count(void) {
    TEST("insert peers and count");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    for (int i = 1; i <= 10; i++) {
        nodus_peer_t p = make_peer((uint8_t)i, "10.0.0.1", (uint16_t)(4000 + i));
        nodus_routing_insert(&rt, &p);
    }

    if (nodus_routing_count(&rt) == 10)
        PASS();
    else
        FAIL("wrong count");
}

static void test_insert_self_rejected(void) {
    TEST("insert self is rejected");
    nodus_key_t self = make_key(0x42);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_peer_t p;
    memset(&p, 0, sizeof(p));
    p.node_id = self;

    int rc = nodus_routing_insert(&rt, &p);
    if (rc == -1 && nodus_routing_count(&rt) == 0)
        PASS();
    else
        FAIL("should reject self");
}

static void test_insert_duplicate_updates(void) {
    TEST("insert duplicate updates existing");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_peer_t p = make_peer(0x01, "10.0.0.1", 4000);
    nodus_routing_insert(&rt, &p);

    /* Update IP */
    nodus_peer_t p2 = make_peer(0x01, "10.0.0.2", 5000);
    int rc = nodus_routing_insert(&rt, &p2);

    nodus_peer_t found;
    nodus_routing_lookup(&rt, &p2.node_id, &found);

    if (rc == 1 && nodus_routing_count(&rt) == 1 &&
        strcmp(found.ip, "10.0.0.2") == 0)
        PASS();
    else
        FAIL("update failed");
}

static void test_remove(void) {
    TEST("remove peer");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_peer_t p = make_peer(0x01, "10.0.0.1", 4000);
    nodus_routing_insert(&rt, &p);

    nodus_routing_remove(&rt, &p.node_id);
    if (nodus_routing_count(&rt) == 0)
        PASS();
    else
        FAIL("remove failed");
}

static void test_lookup(void) {
    TEST("lookup peer");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_peer_t p = make_peer(0xFF, "192.168.1.1", 4001);
    nodus_routing_insert(&rt, &p);

    nodus_peer_t found;
    int rc = nodus_routing_lookup(&rt, &p.node_id, &found);

    if (rc == 0 && strcmp(found.ip, "192.168.1.1") == 0 &&
        found.udp_port == 4001)
        PASS();
    else
        FAIL("lookup failed");
}

static void test_lookup_not_found(void) {
    TEST("lookup non-existent peer");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_key_t missing = make_key(0x99);
    int rc = nodus_routing_lookup(&rt, &missing, NULL);
    if (rc == -1)
        PASS();
    else
        FAIL("should return -1");
}

static void test_find_closest(void) {
    TEST("find k closest peers");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    /* Insert 20 peers with distinct IDs */
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 1; i <= 20; i++) {
        nodus_peer_t p;
        memset(&p, 0, sizeof(p));
        /* Create varied keys by setting specific bytes */
        memset(p.node_id.bytes, 0, NODUS_KEY_BYTES);
        p.node_id.bytes[0] = (uint8_t)i;
        snprintf(p.ip, sizeof(p.ip), "10.0.0.%d", i);
        p.udp_port = (uint16_t)(4000 + i);
        p.tcp_port = (uint16_t)(4001 + i);
        p.last_seen = now;
        nodus_routing_insert(&rt, &p);
    }

    /* Find 5 closest to key 0x01... */
    nodus_key_t target;
    memset(target.bytes, 0, NODUS_KEY_BYTES);
    target.bytes[0] = 0x01;

    nodus_peer_t results[5];
    int found = nodus_routing_find_closest(&rt, &target, results, 5);

    /* Should find 5, with the exact match (0x01) first */
    if (found == 5 && results[0].node_id.bytes[0] == 0x01)
        PASS();
    else
        FAIL("closest search wrong");
}

static void test_bucket_overflow_lru(void) {
    TEST("bucket overflow evicts LRU");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    /* Create k+1 peers that all land in the same bucket */
    /* All have the same high bit pattern differing from self (0x00),
       so they should all land in bucket 0 (first bit differs) */
    uint64_t base_time = (uint64_t)time(NULL);
    for (int i = 0; i <= NODUS_K; i++) {
        nodus_peer_t p;
        memset(&p, 0, sizeof(p));
        /* Set high byte to 0x80 so first bit differs from self (0x00) */
        p.node_id.bytes[0] = 0x80;
        p.node_id.bytes[1] = (uint8_t)i;
        snprintf(p.ip, sizeof(p.ip), "10.0.0.%d", i);
        p.last_seen = base_time + (uint64_t)i;  /* Increasing last_seen */
        nodus_routing_insert(&rt, &p);
    }

    /* The 9th insert (i=8) should have evicted the oldest (i=0, last_seen=100) */
    nodus_key_t evicted;
    memset(evicted.bytes, 0, NODUS_KEY_BYTES);
    evicted.bytes[0] = 0x80;
    evicted.bytes[1] = 0x00;

    int rc = nodus_routing_lookup(&rt, &evicted, NULL);
    /* Count should be exactly K */
    int count = nodus_routing_count(&rt);

    if (rc == -1 && count == NODUS_K)
        PASS();
    else
        FAIL("LRU eviction didn't work");
}

static void test_touch(void) {
    TEST("touch updates last_seen");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    nodus_peer_t p = make_peer(0x01, "10.0.0.1", 4000);
    uint64_t before = (uint64_t)time(NULL) - 10;  /* 10 seconds ago */
    p.last_seen = before;
    nodus_routing_insert(&rt, &p);

    nodus_routing_touch(&rt, &p.node_id);

    nodus_peer_t found;
    nodus_routing_lookup(&rt, &p.node_id, &found);

    if (found.last_seen > before)
        PASS();
    else
        FAIL("touch didn't update last_seen");
}

int main(void) {
    printf("=== Nodus Routing Table Tests ===\n");

    test_init();
    test_insert_and_count();
    test_insert_self_rejected();
    test_insert_duplicate_updates();
    test_remove();
    test_lookup();
    test_lookup_not_found();
    test_find_closest();
    test_bucket_overflow_lru();
    test_touch();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
