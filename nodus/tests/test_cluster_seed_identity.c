/**
 * Nodus — seed placeholder identity + cluster seed admission (O15B.1).
 *
 * A configured seed has no known node_id until it answers a PONG, so
 * `nodus_server_init` registers it under a PLACEHOLDER id and
 * `nodus_cluster_on_pong` swaps in the real one (matched by ip + udp
 * port). `nodus_cluster_add_peer` deduplicates on that id.
 *
 * The placeholder must therefore identify an ENDPOINT, not a host. When
 * it was derived from the IP string alone, every seed sharing an IP
 * collapsed onto one id and six of seven seeds were silently discarded
 * by the duplicate check — leaving each node with a one-peer cluster,
 * a one-peer Kademlia routing table (the only cluster-side
 * `nodus_routing_insert` runs on that peer's first PONG), and a DHT
 * replication fan-out of one. On the Stage F harness, where all seven
 * seeds are 127.0.0.1, that starved a joining node's `nodus:pk`
 * registry entry: only the first seed ever stored it, so the other
 * committee members never learned the joiner and dropped its
 * `w_chain_q` as an unknown sender.
 *
 * These checks pin the endpoint property, and the admission count that
 * follows from it. Deriving the placeholder from the IP alone fails
 * both.
 */

#include "consensus/nodus_cluster.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-62s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* The Stage F port layout: one 10-port stride per node from 14000. */
#define SEED_N        7
#define SEED_IP       "127.0.0.1"
#define SEED_UDP(i)   ((uint16_t)(14000 + (i) * 10))

/* nodus_server_t embeds multi-MB session/transport arrays — heap only. */
static nodus_server_t *make_server(void) {
    nodus_server_t *srv = (nodus_server_t *)calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    /* A self id that no placeholder can collide with, so add_peer's
     * "don't add self" branch cannot mask a dedup result. */
    memset(srv->identity.node_id.bytes, 0xAB, NODUS_KEY_BYTES);
    nodus_cluster_init(&srv->cluster, srv);
    return srv;
}

static void test_placeholder_is_deterministic(void) {
    TEST("placeholder id is a pure function of (ip, udp_port)");

    nodus_key_t a, b;
    nodus_cluster_seed_placeholder_id(SEED_IP, 14000, &a);
    nodus_cluster_seed_placeholder_id(SEED_IP, 14000, &b);

    if (nodus_key_cmp(&a, &b) != 0) { FAIL("same input gave two ids"); return; }
    PASS();
}

static void test_placeholder_separates_ports(void) {
    TEST("seven same-IP seeds get seven DISTINCT placeholder ids");

    nodus_key_t ids[SEED_N];
    for (int i = 0; i < SEED_N; i++)
        nodus_cluster_seed_placeholder_id(SEED_IP, SEED_UDP(i), &ids[i]);

    for (int i = 0; i < SEED_N; i++) {
        for (int j = i + 1; j < SEED_N; j++) {
            if (nodus_key_cmp(&ids[i], &ids[j]) == 0) {
                FAIL("two seeds on one IP collapsed onto one id");
                return;
            }
        }
    }
    PASS();
}

static void test_placeholder_binds_the_port(void) {
    TEST("the udp port is part of the preimage, not decoration");

    /* The exact defect: SHA3 over the bare IP string. If the helper
     * still hashed only the host, this would match. */
    nodus_key_t host_only;
    if (nodus_hash((const uint8_t *)SEED_IP, strlen(SEED_IP), &host_only) != 0) {
        FAIL("nodus_hash failed");
        return;
    }

    for (int i = 0; i < SEED_N; i++) {
        nodus_key_t id;
        nodus_cluster_seed_placeholder_id(SEED_IP, SEED_UDP(i), &id);
        if (nodus_key_cmp(&id, &host_only) == 0) {
            FAIL("placeholder equals the host-only hash");
            return;
        }
    }
    PASS();
}

static void test_all_seeds_are_admitted(void) {
    TEST("all seven 127.0.0.1 seeds enter the cluster peer table");

    nodus_server_t *srv = make_server();
    if (!srv) { FAIL("calloc server"); return; }

    for (int i = 0; i < SEED_N; i++) {
        nodus_key_t id;
        nodus_cluster_seed_placeholder_id(SEED_IP, SEED_UDP(i), &id);
        nodus_cluster_add_peer(&srv->cluster, &id, SEED_IP,
                               SEED_UDP(i), (uint16_t)(SEED_UDP(i) + 2));
    }

    if (srv->cluster.peer_count != SEED_N) {
        char msg[96];
        snprintf(msg, sizeof(msg),
                 "peer_count=%d, expected %d — seeds were deduplicated away",
                 srv->cluster.peer_count, SEED_N);
        FAIL(msg);
        free(srv);
        return;
    }

    /* And each admitted peer must carry its OWN endpoint, so the
     * heartbeat reaches seven distinct sockets rather than one. */
    for (int i = 0; i < SEED_N; i++) {
        bool found = false;
        for (int p = 0; p < srv->cluster.peer_count; p++) {
            if (srv->cluster.peers[p].udp_port == SEED_UDP(i) &&
                strcmp(srv->cluster.peers[p].ip, SEED_IP) == 0) {
                found = true;
                break;
            }
        }
        if (!found) { FAIL("an admitted seed lost its udp port"); free(srv); return; }
    }

    free(srv);
    PASS();
}

static void test_duplicate_endpoint_still_dedups(void) {
    TEST("the SAME endpoint offered twice is still admitted once");

    nodus_server_t *srv = make_server();
    if (!srv) { FAIL("calloc server"); return; }

    nodus_key_t id;
    nodus_cluster_seed_placeholder_id(SEED_IP, 14000, &id);
    nodus_cluster_add_peer(&srv->cluster, &id, SEED_IP, 14000, 14002);
    nodus_cluster_add_peer(&srv->cluster, &id, SEED_IP, 14000, 14002);

    if (srv->cluster.peer_count != 1) {
        FAIL("duplicate endpoint was admitted twice");
        free(srv);
        return;
    }
    free(srv);
    PASS();
}

int main(void) {
    printf("\n=== Nodus seed placeholder identity (O15B.1) ===\n\n");

    test_placeholder_is_deterministic();
    test_placeholder_separates_ports();
    test_placeholder_binds_the_port();
    test_all_seeds_are_admitted();
    test_duplicate_endpoint_still_dedups();

    printf("\n  %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
