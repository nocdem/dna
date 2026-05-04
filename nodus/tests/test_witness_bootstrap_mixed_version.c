/**
 * Nodus — Witness Mixed-Version Detect Tests (PR 3 / E4)
 *
 * Verifies the H-9 mixed-version cluster detection. After the rolling
 * deploy reaches a fresh node, that node's bootstrap path scans peers
 * for any whose w_ident-reported nodus_version is strictly older than
 * the local one — if any such peer exists, the operator has not
 * finished the rolling upgrade and the new node MUST refuse to drive
 * bootstrap (the older peers cannot understand the T3 types 16-19
 * that bootstrap depends on).
 *
 * RED state for E4: the stub returns false unconditionally, so all
 * "older peer present" cases fail. The GREEN commit replaces the
 * stub with the real per-peer scan.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bootstrap.h"
#include "server/nodus_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

#define V(maj, min, pat) (((uint32_t)(maj) << 16) | \
                          ((uint32_t)(min) <<  8) | \
                           (uint32_t)(pat))

/* Populate w->peers[i].remote_nodus_version with the given list,
 * setting peer_count and a placeholder address so the log line in
 * the GREEN impl has something to print. */
static void seed_peers(nodus_witness_t *w,
                       const uint32_t *versions,
                       int n) {
    w->peer_count = n;
    for (int i = 0; i < n && i < (int)NODUS_T3_MAX_WITNESSES; i++) {
        w->peers[i].remote_nodus_version = versions[i];
        snprintf(w->peers[i].address,
                 sizeof(w->peers[i].address), "10.0.0.%d", i + 1);
    }
}

static void test_null_witness_returns_false(void) {
    TEST("NULL witness handle -> false (graceful)");
    if (nodus_witness_bootstrap_any_peer_older(NULL, V(0, 18, 5))) {
        FAIL("expected false for NULL");
        return;
    }
    PASS();
}

static void test_no_peers_returns_false(void) {
    TEST("peer_count=0 -> false");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    if (nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected false for empty peers");
        return;
    }
    PASS();
}

static void test_all_peers_same_version_returns_false(void) {
    TEST("all peers at local version -> false");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t v = V(0, 18, 5);
    uint32_t versions[] = {v, v, v, v, v, v, v};
    seed_peers(&w, versions, 7);
    if (nodus_witness_bootstrap_any_peer_older(&w, v)) {
        FAIL("expected false");
        return;
    }
    PASS();
}

static void test_all_peers_newer_returns_false(void) {
    TEST("all peers strictly newer than local -> false");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t newer = V(0, 19, 0);
    uint32_t versions[] = {newer, newer, newer};
    seed_peers(&w, versions, 3);
    if (nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected false (newer peers are not a mixed signal)");
        return;
    }
    PASS();
}

static void test_legacy_zero_version_skipped(void) {
    TEST("peer with remote_nodus_version=0 (not yet identified) -> false");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t versions[] = {0, 0, 0};  /* w_ident not yet completed */
    seed_peers(&w, versions, 3);
    if (nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected false (zero means unknown, not older)");
        return;
    }
    PASS();
}

static void test_one_older_peer_returns_true(void) {
    TEST("exactly one peer strictly older than local -> true");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t versions[] = {
        V(0, 18, 5),
        V(0, 18, 5),
        V(0, 18, 4),  /* one older */
        V(0, 18, 5),
    };
    seed_peers(&w, versions, 4);
    if (!nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected true (one peer at v0.18.4 < local v0.18.5)");
        return;
    }
    PASS();
}

static void test_minor_version_older_returns_true(void) {
    TEST("peer with older minor version -> true");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t versions[] = {
        V(0, 18, 5),
        V(0, 17, 9),  /* older minor */
    };
    seed_peers(&w, versions, 2);
    if (!nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected true (v0.17.9 < v0.18.5)");
        return;
    }
    PASS();
}

static void test_mixed_zeros_and_olders(void) {
    TEST("mix of legacy zeros + one older + one same -> true");
    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    uint32_t versions[] = {
        0,             /* legacy / unknown */
        V(0, 18, 5),   /* same as local */
        V(0, 18, 4),   /* older */
        0,
    };
    seed_peers(&w, versions, 4);
    if (!nodus_witness_bootstrap_any_peer_older(&w, V(0, 18, 5))) {
        FAIL("expected true (one peer at v0.18.4 trumps zeros + same)");
        return;
    }
    PASS();
}

int main(void) {
    printf("\nNodus Witness Mixed-Version Detect Tests (PR 3 / E4)\n");
    printf("=====================================================\n\n");

    test_null_witness_returns_false();
    test_no_peers_returns_false();
    test_all_peers_same_version_returns_false();
    test_all_peers_newer_returns_false();
    test_legacy_zero_version_skipped();
    test_one_older_peer_returns_true();
    test_minor_version_older_returns_true();
    test_mixed_zeros_and_olders();

    printf("\n=====================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
