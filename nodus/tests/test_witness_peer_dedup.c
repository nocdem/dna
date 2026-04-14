/**
 * Nodus — Witness peer table dedup / slot leak regression tests
 *
 * Exercises nodus_witness_peer_ensure() and asserts the invariant
 *   peer_count == unique(witness_ids across identified slots)
 * under common sequences.
 *
 * One test (test_orphan_slot_from_init) is a documented XFAIL that
 * demonstrates the slot leak bug: when a pre-existing slot has a
 * zero witness_id (as created by nodus_witness_peer_init at startup
 * for seed addresses), a subsequent peer_ensure() call for the real
 * witness_id on the SAME conn creates a NEW slot instead of claiming
 * the orphan — peer_count grows by one despite no new peer.
 *
 * See memory/project_witness_peer_table_slot_leak.md for the full
 * root cause analysis and refactor direction.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_peer.h"
#include "transport/nodus_tcp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define XFAIL(msg) do { printf("XFAIL (known bug): %s\n", msg); xfailed++; } while(0)

static int passed = 0;
static int failed = 0;
static int xfailed = 0;

static void fill_id(uint8_t *out, uint8_t byte) {
    memset(out, byte, NODUS_T3_WITNESS_ID_LEN);
}

/* Count slots whose witness_id is unique among identified slots. */
static int unique_identified_peers(const nodus_witness_t *w) {
    int unique = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].identified) continue;
        int dup = 0;
        for (int j = 0; j < i; j++) {
            if (!w->peers[j].identified) continue;
            if (memcmp(w->peers[i].witness_id,
                       w->peers[j].witness_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = 1;
                break;
            }
        }
        if (!dup) unique++;
    }
    return unique;
}

/* ── Tests ───────────────────────────────────────────────────────── */

static void test_single_peer_baseline(void) {
    TEST("baseline: one peer_ensure creates exactly one identified slot");

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0xAA);
    struct nodus_tcp_conn c = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c);

    if (w.peer_count != 1)       { FAIL("peer_count != 1"); return; }
    if (!w.peers[0].identified)  { FAIL("slot not identified"); return; }
    if (w.peers[0].conn != &c)   { FAIL("conn mismatch"); return; }
    if (unique_identified_peers(&w) != 1) { FAIL("uniqueness broken"); return; }
    PASS();
}

static void test_distinct_peers_distinct_slots(void) {
    TEST("distinct witness_ids create distinct slots");

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));

    uint8_t id1[NODUS_T3_WITNESS_ID_LEN], id2[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id1, 0x11);
    fill_id(id2, 0x22);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id1, &c1);
    nodus_witness_peer_ensure(&w, id2, &c2);

    if (w.peer_count != 2) { FAIL("peer_count != 2"); return; }
    if (unique_identified_peers(&w) != 2) { FAIL("uniqueness broken"); return; }
    PASS();
}

static void test_reconnect_same_peer_dedupes(void) {
    TEST("reconnect: dead conn adopted by new conn, no new slot");

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0xBB);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c1);

    /* First conn dies */
    c1.state = NODUS_CONN_CLOSED;

    /* Same peer reconnects on a new conn */
    nodus_witness_peer_ensure(&w, id, &c2);

    if (w.peer_count != 1) {
        char buf[80];
        snprintf(buf, sizeof(buf), "peer_count=%d (expected 1)", w.peer_count);
        FAIL(buf);
        return;
    }
    if (w.peers[0].conn != &c2) { FAIL("did not adopt new conn"); return; }
    PASS();
}

static void test_second_inbound_keeps_existing(void) {
    TEST("second inbound on live peer: kept, no duplicate slot");

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));

    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id, 0x33);
    struct nodus_tcp_conn c1 = { .state = NODUS_CONN_CONNECTED };
    struct nodus_tcp_conn c2 = { .state = NODUS_CONN_CONNECTED };

    nodus_witness_peer_ensure(&w, id, &c1);
    nodus_witness_peer_ensure(&w, id, &c2);

    /* peer_ensure prefers existing live conn; c2 should be ignored */
    if (w.peer_count != 1) {
        char buf[80];
        snprintf(buf, sizeof(buf), "peer_count=%d (expected 1)", w.peer_count);
        FAIL(buf);
        return;
    }
    if (w.peers[0].conn != &c1) { FAIL("slot does not point to c1"); return; }
    PASS();
}

static void test_orphan_slot_from_init(void) {
    TEST("orphan slot (zero witness_id) + peer_ensure same conn");

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));

    /* Simulate nodus_witness_peer_init: a slot for a seed address is
     * created with a live conn but witness_id still zero — the real
     * witness_id will be filled when w_ident arrives. */
    struct nodus_tcp_conn c = { .state = NODUS_CONN_CONNECTED };
    w.peers[0].conn = &c;
    w.peers[0].identified = false;
    /* witness_id stays zero */
    w.peer_count = 1;

    /* Now dispatch_t3 receives a non-IDENT T3 message from witness_id=X
     * on the same conn and calls peer_ensure(X, &c). A CORRECT
     * implementation should recognize the orphan slot (by conn) and
     * fill in the witness_id without creating a new slot. */
    uint8_t id_x[NODUS_T3_WITNESS_ID_LEN];
    fill_id(id_x, 0xCC);
    nodus_witness_peer_ensure(&w, id_x, &c);

    if (w.peer_count == 1) {
        /* Correct behavior — either the bug was fixed or never existed
         * on this code path. Treat as PASS to future-proof the test. */
        PASS();
        return;
    }

    /* Current buggy behavior: peer_count grows because
     * find_peer_by_id(X) misses the orphan slot. */
    char buf[120];
    snprintf(buf, sizeof(buf),
             "peer_count=%d, orphan slot leaked (pre-existing bug)",
             w.peer_count);
    XFAIL(buf);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void) {
    printf("Witness peer table dedup / slot leak tests\n");
    printf("==========================================\n");

    test_single_peer_baseline();
    test_distinct_peers_distinct_slots();
    test_reconnect_same_peer_dedupes();
    test_second_inbound_keeps_existing();
    test_orphan_slot_from_init();

    printf("\nPassed: %d\nFailed: %d\nXFailed: %d\n", passed, failed, xfailed);

    /* XFAIL does not fail the test run — it documents a known bug
     * without blocking CI. Real failures still return nonzero. */
    return failed == 0 ? 0 : 1;
}
