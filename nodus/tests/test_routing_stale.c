/**
 * Nodus v5 — Routing Table Stale Entry + Dead Node Tests
 *
 * Validates:
 * - Stale entries filtered from find_closest results
 * - Dead peer removal from routing table on PBFT transition
 */

#include "core/nodus_routing.h"
#include <stdio.h>
#include <string.h>
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

static void test_stale_entries_filtered(void) {
    TEST("stale entries excluded from find_closest");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    uint64_t now = (uint64_t)time(NULL);

    /* Insert 5 fresh peers */
    for (int i = 1; i <= 5; i++) {
        nodus_peer_t p;
        memset(&p, 0, sizeof(p));
        p.node_id.bytes[0] = (uint8_t)i;
        snprintf(p.ip, sizeof(p.ip), "10.0.0.%d", i);
        p.udp_port = (uint16_t)(4000 + i);
        p.tcp_port = (uint16_t)(4001 + i);
        p.last_seen = now;
        nodus_routing_insert(&rt, &p);
    }

    /* Insert 5 stale peers (last_seen > NODUS_ROUTING_STALE_SEC ago) */
    for (int i = 6; i <= 10; i++) {
        nodus_peer_t p;
        memset(&p, 0, sizeof(p));
        p.node_id.bytes[0] = (uint8_t)i;
        snprintf(p.ip, sizeof(p.ip), "10.0.0.%d", i);
        p.udp_port = (uint16_t)(4000 + i);
        p.tcp_port = (uint16_t)(4001 + i);
        p.last_seen = now - NODUS_ROUTING_STALE_SEC - 100;  /* Stale */
        nodus_routing_insert(&rt, &p);
    }

    /* Find closest — should only return fresh peers */
    nodus_key_t target = make_key(0x01);
    nodus_peer_t results[10];
    int found = nodus_routing_find_closest(&rt, &target, results, 10);

    /* Should find exactly 5 (the fresh ones) */
    if (found == 5) {
        /* Verify all results are fresh */
        bool all_fresh = true;
        for (int i = 0; i < found; i++) {
            if (now - results[i].last_seen > NODUS_ROUTING_STALE_SEC)
                all_fresh = false;
        }
        if (all_fresh)
            PASS();
        else
            FAIL("stale entry leaked into results");
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 5 results, got %d", found);
        FAIL(buf);
    }
}

static void test_zero_last_seen_not_filtered(void) {
    TEST("last_seen=0 entries are not stale-filtered");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    /* Insert peer with last_seen=0 (should NOT be filtered) */
    nodus_peer_t p;
    memset(&p, 0, sizeof(p));
    p.node_id.bytes[0] = 0x01;
    snprintf(p.ip, sizeof(p.ip), "10.0.0.1");
    p.udp_port = 4000;
    p.tcp_port = 4001;
    p.last_seen = 0;
    nodus_routing_insert(&rt, &p);

    nodus_key_t target = make_key(0x01);
    nodus_peer_t results[5];
    int found = nodus_routing_find_closest(&rt, &target, results, 5);

    if (found == 1)
        PASS();
    else
        FAIL("last_seen=0 should not be filtered");
}

static void test_remove_dead_peer(void) {
    TEST("dead peer removal from routing table");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    uint64_t now = (uint64_t)time(NULL);
    nodus_peer_t p;
    memset(&p, 0, sizeof(p));
    p.node_id.bytes[0] = 0xFF;
    snprintf(p.ip, sizeof(p.ip), "10.0.0.1");
    p.udp_port = 4000;
    p.tcp_port = 4001;
    p.last_seen = now;
    nodus_routing_insert(&rt, &p);

    if (nodus_routing_count(&rt) != 1) {
        FAIL("setup failed");
        return;
    }

    /* Simulate PBFT dead transition by removing from routing table */
    nodus_routing_remove(&rt, &p.node_id);

    if (nodus_routing_count(&rt) == 0 &&
        nodus_routing_lookup(&rt, &p.node_id, NULL) == -1)
        PASS();
    else
        FAIL("dead peer not removed");
}

static void test_fresh_peers_returned_first(void) {
    TEST("freshest peers returned closest");
    nodus_key_t self = make_key(0x00);
    nodus_routing_t rt;
    nodus_routing_init(&rt, &self);

    uint64_t now = (uint64_t)time(NULL);

    /* Insert peers at different distances, all fresh */
    for (int i = 1; i <= 8; i++) {
        nodus_peer_t p;
        memset(&p, 0, sizeof(p));
        p.node_id.bytes[0] = (uint8_t)i;
        snprintf(p.ip, sizeof(p.ip), "10.0.0.%d", i);
        p.udp_port = (uint16_t)(4000 + i);
        p.tcp_port = (uint16_t)(4001 + i);
        p.last_seen = now;
        nodus_routing_insert(&rt, &p);
    }

    nodus_key_t target;
    memset(target.bytes, 0, NODUS_KEY_BYTES);
    target.bytes[0] = 0x01;

    nodus_peer_t results[3];
    int found = nodus_routing_find_closest(&rt, &target, results, 3);

    /* First result should be exact match (0x01) */
    if (found == 3 && results[0].node_id.bytes[0] == 0x01)
        PASS();
    else
        FAIL("closest peer not returned first");
}

int main(void) {
    printf("=== Nodus Routing Stale/Dead Tests ===\n");

    test_stale_entries_filtered();
    test_zero_last_seen_not_filtered();
    test_remove_dead_peer();
    test_fresh_peers_returned_first();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
