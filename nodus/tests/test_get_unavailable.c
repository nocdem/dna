/**
 * Nodus — DHT Package A S6: "could not look" is an error, not "not found".
 *
 * Decision record: docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md
 * Q1 — a node that could not look must say so; an empty answer means
 * "looked, nothing there".
 *
 * Pins down the decision every read path takes (nodus_dht_read_outcome,
 * nodus_server.h internal section; used per key by get, get_all, get_batch
 * and the forward completion):
 *   1. rows found                         → ROWS (whatever else happened)
 *   2. no row, no other peer holds the key, local store read → EMPTY
 *      (single-node truth)
 *   3. no row, peers to ask, none answered → UNAVAILABLE (no forward slot,
 *      forward-context alloc failure, every forward failed / timed out /
 *      answered "u")
 *   4. no row, at least one source looked  → EMPTY (a real "not found")
 *   5. rev 2 item 13: no row, the local read FAULTED and nobody else
 *      answered → UNAVAILABLE, even with no peer to ask
 * and that the error frame carries NODUS_ERR_UNAVAILABLE (21) on the wire,
 * distinct from NODUS_ERR_NOT_FOUND.
 *
 * RED on the tree before Package A: the helper and the error code do not
 * exist; those paths answered result_empty. Before rev 2 a local storage
 * fault read as "no row" (case 5 answered EMPTY).
 */

#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)
#define CHECK(c, m) do { if (!(c)) { FAIL(m); return; } } while(0)

static int passed = 0;
static int failed = 0;

static void test_outcome_table(void) {
    TEST("read outcome: rows / empty / unavailable");
    CHECK(nodus_dht_read_outcome(3, 0, 0, false) == NODUS_DHT_READ_ROWS, "local rows, no peers");
    CHECK(nodus_dht_read_outcome(1, 5, 0, false) == NODUS_DHT_READ_ROWS, "local rows, no answer");
    CHECK(nodus_dht_read_outcome(2, 0, 0, true) == NODUS_DHT_READ_ROWS,
          "rows win over a local fault");
    CHECK(nodus_dht_read_outcome(0, 0, 0, false) == NODUS_DHT_READ_EMPTY,
          "no peers must stay empty");
    CHECK(nodus_dht_read_outcome(0, 1, 0, false) == NODUS_DHT_READ_UNAVAILABLE,
          "no answer reported as not-found");
    CHECK(nodus_dht_read_outcome(0, 8, 0, false) == NODUS_DHT_READ_UNAVAILABLE,
          "all forwards failed reported as not-found");
    CHECK(nodus_dht_read_outcome(0, 8, 1, false) == NODUS_DHT_READ_EMPTY,
          "an answering peer with no row is a real empty");
    CHECK(nodus_dht_read_outcome(0, 0, 0, true) == NODUS_DHT_READ_UNAVAILABLE,
          "local fault, no peers, reported as not-found");
    CHECK(nodus_dht_read_outcome(0, 3, 1, true) == NODUS_DHT_READ_EMPTY,
          "local fault but a peer looked: a real empty");
    PASS();
}

static void test_error_on_wire(void) {
    TEST("UNAVAILABLE error frame decodes as code 21");
    uint8_t buf[512];
    size_t len = 0;
    CHECK(NODUS_ERR_UNAVAILABLE == 21, "code value");
    CHECK(NODUS_ERR_UNAVAILABLE != NODUS_ERR_NOT_FOUND, "distinct from not-found");
    CHECK(nodus_t2_error(77, NODUS_ERR_UNAVAILABLE, "no forward slot",
                         buf, sizeof(buf), &len) == 0, "encode");
    nodus_tier2_msg_t m;
    CHECK(nodus_t2_decode(buf, len, &m) == 0, "decode");
    CHECK(m.type == 'e' && m.txn_id == 77 && m.error_code == NODUS_ERR_UNAVAILABLE,
          "fields");
    nodus_t2_msg_free(&m);
    PASS();
}

int main(void) {
    printf("=== DHT Package A S6: could-not-look → UNAVAILABLE ===\n");
    test_outcome_table();
    test_error_on_wire();
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
