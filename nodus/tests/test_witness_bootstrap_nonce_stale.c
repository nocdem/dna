/**
 * Nodus — Witness Bootstrap Nonce-Stale Filter Tests (PR 3 / F6)
 *
 * Verifies the C-4 stale-nonce drop in handle_chain_r — a captured
 * w_chain_r message replayed during a later bootstrap round whose
 * nonce has rotated MUST be silently dropped, not counted toward
 * quorum.
 *
 * Threat model: an off-path attacker captures w_chain_r packets from
 * round N (e.g., off the wire, or from a colluding peer). At round
 * N+1, the attacker injects the captured packet into a fresh node's
 * bootstrap state. Without the filter, the captured response would
 * count again toward the round N+1 quorum, letting the attacker
 * skew chain agreement with stale data. The filter rejects the
 * replay because round N+1's bootstrap_round_nonce != round N's.
 *
 * This unit test exercises that filter by constructing both stale
 * and fresh nonce variants of w_chain_r and checking
 * g_response_count via the test-build introspection hook.
 *
 * Replaces the formerly SKIP-by-default
 * test_bootstrap_replay_attack.sh integration scenario with
 * unit-level coverage of the same security property.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bootstrap.h"
#include "protocol/nodus_tier3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Test introspection helpers exposed by bootstrap.c when built with
 * NODUS_WITNESS_INTERNAL_API. */
extern int  nodus_witness_bootstrap_test_response_count(void);
extern void nodus_witness_bootstrap_test_reset_responses(void);

static void mk_chain_r_msg(nodus_t3_msg_t *m,
                            const uint8_t nonce[16],
                            const uint8_t sender_id[32],
                            const uint8_t cid[32]) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_CHAIN_R;
    m->header.version = 1;
    memcpy(m->header.sender_id, sender_id, 32);
    memcpy(m->w_chain_r.nonce, nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);
    memcpy(m->w_chain_r.cid, cid, 32);
    m->w_chain_r.tip = 1;
}

static void test_fresh_nonce_accepted(void) {
    TEST("fresh nonce (matches current round) -> response counted");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("calloc"); return; }
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DISCOVER;
    /* Set a known round nonce */
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        w->bootstrap_round_nonce[i] = (uint8_t)(0xAA ^ i);
    nodus_witness_bootstrap_test_reset_responses();

    uint8_t sender_id[32]; memset(sender_id, 0xBB, 32);
    uint8_t cid[32]; memset(cid, 0xCC, 32);
    nodus_t3_msg_t m;
    mk_chain_r_msg(&m, w->bootstrap_round_nonce, sender_id, cid);

    nodus_witness_bootstrap_handle_chain_r(w, &m);
    int count = nodus_witness_bootstrap_test_response_count();
    if (count != 1) { FAIL("expected count=1"); free(w); return; }
    PASS();
    free(w);
}

static void test_stale_nonce_dropped(void) {
    TEST("stale nonce (prior round) -> response dropped, count unchanged");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("calloc"); return; }
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DISCOVER;
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        w->bootstrap_round_nonce[i] = (uint8_t)(0x11 ^ i);
    nodus_witness_bootstrap_test_reset_responses();

    /* Stale nonce: differs by 1 bit from current round */
    uint8_t stale_nonce[NODUS_W_BOOTSTRAP_NONCE_LEN];
    memcpy(stale_nonce, w->bootstrap_round_nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);
    stale_nonce[0] ^= 0x01;

    uint8_t sender_id[32]; memset(sender_id, 0xDD, 32);
    uint8_t cid[32]; memset(cid, 0xEE, 32);
    nodus_t3_msg_t m;
    mk_chain_r_msg(&m, stale_nonce, sender_id, cid);

    nodus_witness_bootstrap_handle_chain_r(w, &m);
    int count = nodus_witness_bootstrap_test_response_count();
    if (count != 0) { FAIL("expected count=0 (stale dropped)"); free(w); return; }
    PASS();
    free(w);
}

static void test_stale_then_fresh_only_fresh_counted(void) {
    TEST("stale + fresh from same peer -> only fresh counted");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("calloc"); return; }
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DISCOVER;
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        w->bootstrap_round_nonce[i] = (uint8_t)(0x77);
    nodus_witness_bootstrap_test_reset_responses();

    uint8_t sender_id[32]; memset(sender_id, 0x55, 32);
    uint8_t cid[32]; memset(cid, 0x66, 32);

    /* Stale first */
    uint8_t stale[NODUS_W_BOOTSTRAP_NONCE_LEN];
    memcpy(stale, w->bootstrap_round_nonce, NODUS_W_BOOTSTRAP_NONCE_LEN);
    stale[0] ^= 0xFF;
    nodus_t3_msg_t m1;
    mk_chain_r_msg(&m1, stale, sender_id, cid);
    nodus_witness_bootstrap_handle_chain_r(w, &m1);
    if (nodus_witness_bootstrap_test_response_count() != 0) {
        FAIL("stale leaked into count"); free(w); return;
    }

    /* Fresh second */
    nodus_t3_msg_t m2;
    mk_chain_r_msg(&m2, w->bootstrap_round_nonce, sender_id, cid);
    nodus_witness_bootstrap_handle_chain_r(w, &m2);
    int count = nodus_witness_bootstrap_test_response_count();
    if (count != 1) { FAIL("fresh not counted"); free(w); return; }
    PASS();
    free(w);
}

static void test_non_discover_state_drops_all(void) {
    TEST("state != DISCOVER (e.g., DONE) -> drop even fresh nonce");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("calloc"); return; }
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DONE;
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        w->bootstrap_round_nonce[i] = 0x42;
    nodus_witness_bootstrap_test_reset_responses();

    uint8_t sender_id[32]; memset(sender_id, 0x99, 32);
    uint8_t cid[32]; memset(cid, 0xAA, 32);
    nodus_t3_msg_t m;
    mk_chain_r_msg(&m, w->bootstrap_round_nonce, sender_id, cid);

    nodus_witness_bootstrap_handle_chain_r(w, &m);
    int count = nodus_witness_bootstrap_test_response_count();
    if (count != 0) { FAIL("DONE state should drop"); free(w); return; }
    PASS();
    free(w);
}

static void test_dup_peer_only_counts_once(void) {
    TEST("two fresh-nonce responses from same peer -> count once");
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { FAIL("calloc"); return; }
    w->bootstrap_state = (int)NODUS_W_BOOTSTRAP_DISCOVER;
    for (int i = 0; i < NODUS_W_BOOTSTRAP_NONCE_LEN; i++)
        w->bootstrap_round_nonce[i] = 0x33;
    nodus_witness_bootstrap_test_reset_responses();

    uint8_t sender_id[32]; memset(sender_id, 0x77, 32);
    uint8_t cid[32]; memset(cid, 0x88, 32);
    nodus_t3_msg_t m;
    mk_chain_r_msg(&m, w->bootstrap_round_nonce, sender_id, cid);

    nodus_witness_bootstrap_handle_chain_r(w, &m);
    nodus_witness_bootstrap_handle_chain_r(w, &m);
    int count = nodus_witness_bootstrap_test_response_count();
    if (count != 1) { FAIL("dup peer should count once"); free(w); return; }
    PASS();
    free(w);
}

int main(void) {
    printf("\nNodus Witness Bootstrap Nonce-Stale Filter (PR 3 / F6)\n");
    printf("=======================================================\n\n");

    test_fresh_nonce_accepted();
    test_stale_nonce_dropped();
    test_stale_then_fresh_only_fresh_counted();
    test_non_discover_state_drops_all();
    test_dup_peer_only_counts_once();

    printf("\n=======================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
