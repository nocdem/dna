/**
 * Circuit table unit tests (Faz 1)
 */
#include "circuit/nodus_circuit.h"
#include "circuit/nodus_inter_circuit.h"
#include <stdio.h>
#include <string.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_session_alloc_lookup_free(void) {
    TEST("session: alloc/lookup/free");
    nodus_circuit_table_t t;
    nodus_circuit_table_init(&t);
    nodus_circuit_t *c = nodus_circuit_alloc(&t);
    if (!c || c->local_cid == 0 || !c->in_use) { FAIL("alloc"); return; }
    uint64_t cid = c->local_cid;
    nodus_circuit_t *got = nodus_circuit_lookup(&t, cid);
    if (got != c) { FAIL("lookup"); return; }
    if (nodus_circuit_count(&t) != 1) { FAIL("count=1"); return; }
    nodus_circuit_free(&t, cid);
    if (nodus_circuit_count(&t) != 0) { FAIL("count=0"); return; }
    if (nodus_circuit_lookup(&t, cid) != NULL) { FAIL("lookup after free"); return; }
    PASS();
}

static void test_session_unique_cids(void) {
    TEST("session: unique cids");
    nodus_circuit_table_t t;
    nodus_circuit_table_init(&t);
    uint64_t cids[NODUS_MAX_CIRCUITS_PER_SESSION];
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        nodus_circuit_t *c = nodus_circuit_alloc(&t);
        if (!c) { FAIL("alloc exhausted early"); return; }
        cids[i] = c->local_cid;
    }
    /* Check unique */
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        for (int j = i + 1; j < NODUS_MAX_CIRCUITS_PER_SESSION; j++) {
            if (cids[i] == cids[j]) { FAIL("duplicate cid"); return; }
        }
    }
    PASS();
}

static void test_session_limit(void) {
    TEST("session: limit enforced (16 max)");
    nodus_circuit_table_t t;
    nodus_circuit_table_init(&t);
    for (int i = 0; i < NODUS_MAX_CIRCUITS_PER_SESSION; i++) {
        nodus_circuit_alloc(&t);
    }
    if (nodus_circuit_count(&t) != NODUS_MAX_CIRCUITS_PER_SESSION) { FAIL("count"); return; }
    nodus_circuit_t *c = nodus_circuit_alloc(&t);
    if (c != NULL) { FAIL("should reject 17th"); return; }
    PASS();
}

static void test_inter_alloc_lookup_free(void) {
    TEST("inter: alloc/lookup/free");
    nodus_inter_circuit_table_t t;
    nodus_inter_circuit_table_init(&t);
    nodus_inter_circuit_t *c = nodus_inter_circuit_alloc(&t);
    if (!c || c->our_cid == 0 || !c->in_use) { FAIL("alloc"); return; }
    uint64_t cid = c->our_cid;
    if (nodus_inter_circuit_lookup(&t, cid) != c) { FAIL("lookup"); return; }
    nodus_inter_circuit_free(&t, cid);
    if (nodus_inter_circuit_count(&t) != 0) { FAIL("count after free"); return; }
    if (nodus_inter_circuit_lookup(&t, cid) != NULL) { FAIL("lookup after free"); return; }
    PASS();
}

static void test_inter_limit(void) {
    TEST("inter: limit enforced (256 max)");
    nodus_inter_circuit_table_t t;
    nodus_inter_circuit_table_init(&t);
    for (int i = 0; i < NODUS_INTER_CIRCUITS_MAX; i++) {
        nodus_inter_circuit_alloc(&t);
    }
    if (nodus_inter_circuit_alloc(&t) != NULL) { FAIL("should reject 257th"); return; }
    PASS();
}

int main(void) {
    printf("Circuit table tests:\n");
    test_session_alloc_lookup_free();
    test_session_unique_cids();
    test_session_limit();
    test_inter_alloc_lookup_free();
    test_inter_limit();
    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
