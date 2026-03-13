/**
 * Nodus -- Channel Server Unit Tests
 *
 * Tests session allocation, lookup, subscription management,
 * and subscriber notification targeting.
 */

#include "channel/nodus_channel_server.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  [%d] %-45s ", tests_run, name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); } while (0)

/* Fake connection objects for testing (we only need the pointer identity) */
static nodus_tcp_conn_t fake_conns[8];

static void init_fake_conns(void) {
    memset(fake_conns, 0, sizeof(fake_conns));
    for (int i = 0; i < 8; i++) {
        fake_conns[i].fd = 100 + i;
        fake_conns[i].slot = i;
        fake_conns[i].state = NODUS_CONN_CONNECTED;
    }
}

static void make_uuid(uint8_t out[NODUS_UUID_BYTES], uint8_t fill) {
    memset(out, fill, NODUS_UUID_BYTES);
}

/* ---- Test: init zeroes everything -------------------------------------- */

static void test_init_zeroed(void) {
    TEST("init: all sessions zeroed");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    bool ok = true;
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        if (cs.clients[i].conn != NULL || cs.clients[i].authenticated) {
            ok = false;
            break;
        }
    }
    for (int i = 0; i < NODUS_CH_MAX_NODE_SESSIONS; i++) {
        if (cs.nodes[i].conn != NULL || cs.nodes[i].authenticated) {
            ok = false;
            break;
        }
    }
    if (ok)
        PASS();
    else
        FAIL("sessions not zeroed");
}

/* ---- Test: client session find ----------------------------------------- */

static void test_client_find(void) {
    TEST("client find: match by conn pointer");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    /* Place a client in slot 3 */
    cs.clients[3].conn = &fake_conns[3];
    fake_conns[3].slot = 3;

    nodus_ch_client_session_t *found = nodus_ch_find_client(&cs, &fake_conns[3]);
    if (found && found->conn == &fake_conns[3])
        PASS();
    else
        FAIL("did not find client");
}

static void test_client_find_wrong_slot(void) {
    TEST("client find: mismatch returns NULL");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    /* Slot 2 is empty, but conn says slot 2 */
    fake_conns[2].slot = 2;
    nodus_ch_client_session_t *found = nodus_ch_find_client(&cs, &fake_conns[2]);
    if (found == NULL)
        PASS();
    else
        FAIL("should return NULL");
}

/* ---- Test: node session find ------------------------------------------- */

static void test_node_find(void) {
    TEST("node find: match by conn pointer");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    cs.nodes[1].conn = &fake_conns[5];

    nodus_ch_node_session_t *found = nodus_ch_find_node(&cs, &fake_conns[5]);
    if (found && found->conn == &fake_conns[5])
        PASS();
    else
        FAIL("did not find node");
}

static void test_node_find_empty(void) {
    TEST("node find: empty returns NULL");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    nodus_ch_node_session_t *found = nodus_ch_find_node(&cs, &fake_conns[0]);
    if (found == NULL)
        PASS();
    else
        FAIL("should return NULL");
}

/* ---- Test: subscription management ------------------------------------- */

static void test_sub_add(void) {
    TEST("sub: add subscription");
    nodus_ch_client_session_t sess;
    memset(&sess, 0, sizeof(sess));

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xAA);

    int rc = nodus_ch_client_add_sub(&sess, uuid);
    if (rc == 0 && sess.ch_sub_count == 1 &&
        memcmp(sess.ch_subs[0], uuid, NODUS_UUID_BYTES) == 0)
        PASS();
    else
        FAIL("add failed");
}

static void test_sub_add_duplicate(void) {
    TEST("sub: reject duplicate");
    nodus_ch_client_session_t sess;
    memset(&sess, 0, sizeof(sess));

    uint8_t uuid[NODUS_UUID_BYTES];
    make_uuid(uuid, 0xBB);

    nodus_ch_client_add_sub(&sess, uuid);
    int rc = nodus_ch_client_add_sub(&sess, uuid);
    if (rc == -1 && sess.ch_sub_count == 1)
        PASS();
    else
        FAIL("should reject duplicate");
}

static void test_sub_add_full(void) {
    TEST("sub: reject when full");
    nodus_ch_client_session_t sess;
    memset(&sess, 0, sizeof(sess));

    /* Fill all slots */
    for (int i = 0; i < NODUS_CH_MAX_SUBS_PER_CLIENT; i++) {
        uint8_t uuid[NODUS_UUID_BYTES];
        make_uuid(uuid, (uint8_t)i);
        nodus_ch_client_add_sub(&sess, uuid);
    }

    uint8_t extra[NODUS_UUID_BYTES];
    make_uuid(extra, 0xFF);
    int rc = nodus_ch_client_add_sub(&sess, extra);
    if (rc == -1 && sess.ch_sub_count == NODUS_CH_MAX_SUBS_PER_CLIENT)
        PASS();
    else
        FAIL("should reject when full");
}

static void test_sub_remove(void) {
    TEST("sub: remove subscription");
    nodus_ch_client_session_t sess;
    memset(&sess, 0, sizeof(sess));

    uint8_t a[NODUS_UUID_BYTES], b[NODUS_UUID_BYTES];
    make_uuid(a, 0xAA);
    make_uuid(b, 0xBB);

    nodus_ch_client_add_sub(&sess, a);
    nodus_ch_client_add_sub(&sess, b);

    nodus_ch_client_remove_sub(&sess, a);
    if (sess.ch_sub_count == 1 &&
        memcmp(sess.ch_subs[0], b, NODUS_UUID_BYTES) == 0)
        PASS();
    else
        FAIL("remove failed");
}

static void test_sub_remove_nonexistent(void) {
    TEST("sub: remove nonexistent is no-op");
    nodus_ch_client_session_t sess;
    memset(&sess, 0, sizeof(sess));

    uint8_t a[NODUS_UUID_BYTES], b[NODUS_UUID_BYTES];
    make_uuid(a, 0xAA);
    make_uuid(b, 0xBB);

    nodus_ch_client_add_sub(&sess, a);
    nodus_ch_client_remove_sub(&sess, b);
    if (sess.ch_sub_count == 1)
        PASS();
    else
        FAIL("count changed");
}

/* ---- Test: subscriber notification targeting --------------------------- */

/*
 * We cannot call nodus_ch_notify_subscribers directly in a unit test
 * because it calls nodus_t2_ch_post_notify and nodus_tcp_send, which
 * require real sockets.  Instead we verify the targeting logic by
 * checking that only the right sessions have matching subscriptions.
 *
 * This test validates the subscription matching that notify_subscribers
 * iterates over.
 */
static void test_notify_targeting(void) {
    TEST("notify: targeting matches subscribed clients");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    uint8_t ch_a[NODUS_UUID_BYTES], ch_b[NODUS_UUID_BYTES];
    make_uuid(ch_a, 0x11);
    make_uuid(ch_b, 0x22);

    /* Client 0: subscribed to ch_a */
    cs.clients[0].conn = &fake_conns[0];
    cs.clients[0].authenticated = true;
    nodus_ch_client_add_sub(&cs.clients[0], ch_a);

    /* Client 1: subscribed to ch_a and ch_b */
    cs.clients[1].conn = &fake_conns[1];
    cs.clients[1].authenticated = true;
    nodus_ch_client_add_sub(&cs.clients[1], ch_a);
    nodus_ch_client_add_sub(&cs.clients[1], ch_b);

    /* Client 2: subscribed to ch_b only */
    cs.clients[2].conn = &fake_conns[2];
    cs.clients[2].authenticated = true;
    nodus_ch_client_add_sub(&cs.clients[2], ch_b);

    /* Check: for ch_a, clients 0 and 1 match */
    int ch_a_matches = 0;
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        nodus_ch_client_session_t *cl = &cs.clients[i];
        if (!cl->conn || !cl->authenticated) continue;
        for (int j = 0; j < cl->ch_sub_count; j++) {
            if (memcmp(cl->ch_subs[j], ch_a, NODUS_UUID_BYTES) == 0) {
                ch_a_matches++;
                break;
            }
        }
    }

    /* Check: for ch_b, clients 1 and 2 match */
    int ch_b_matches = 0;
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        nodus_ch_client_session_t *cl = &cs.clients[i];
        if (!cl->conn || !cl->authenticated) continue;
        for (int j = 0; j < cl->ch_sub_count; j++) {
            if (memcmp(cl->ch_subs[j], ch_b, NODUS_UUID_BYTES) == 0) {
                ch_b_matches++;
                break;
            }
        }
    }

    if (ch_a_matches == 2 && ch_b_matches == 2)
        PASS();
    else
        FAIL("wrong match count");
}

static void test_notify_unauthenticated_skipped(void) {
    TEST("notify: unauthenticated clients skipped");
    nodus_channel_server_t cs;
    nodus_channel_server_init(&cs);

    uint8_t ch[NODUS_UUID_BYTES];
    make_uuid(ch, 0x33);

    /* Client 0: authenticated, subscribed */
    cs.clients[0].conn = &fake_conns[0];
    cs.clients[0].authenticated = true;
    nodus_ch_client_add_sub(&cs.clients[0], ch);

    /* Client 1: NOT authenticated, subscribed */
    cs.clients[1].conn = &fake_conns[1];
    cs.clients[1].authenticated = false;
    nodus_ch_client_add_sub(&cs.clients[1], ch);

    int matches = 0;
    for (int i = 0; i < NODUS_CH_MAX_CLIENT_SESSIONS; i++) {
        nodus_ch_client_session_t *cl = &cs.clients[i];
        if (!cl->conn || !cl->authenticated) continue;
        for (int j = 0; j < cl->ch_sub_count; j++) {
            if (memcmp(cl->ch_subs[j], ch, NODUS_UUID_BYTES) == 0) {
                matches++;
                break;
            }
        }
    }

    if (matches == 1)
        PASS();
    else
        FAIL("should skip unauthenticated");
}

/* ---- Main -------------------------------------------------------------- */

int main(void) {
    printf("nodus_channel_server tests\n");
    init_fake_conns();

    test_init_zeroed();
    test_client_find();
    test_client_find_wrong_slot();
    test_node_find();
    test_node_find_empty();
    test_sub_add();
    test_sub_add_duplicate();
    test_sub_add_full();
    test_sub_remove();
    test_sub_remove_nonexistent();
    test_notify_targeting();
    test_notify_unauthenticated_skipped();

    printf("\n  %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
