/**
 * Nodus — Presence Table + Protocol Tests
 *
 * Tests:
 *   1. Presence table: add/remove/query/expire/merge
 *   2. Protocol: pq encode/decode roundtrip, p_sync encode/decode roundtrip
 *   3. Sparse result encoding (only online entries in response)
 */

#include "server/nodus_presence.h"
#include "server/nodus_server.h"
#include "protocol/nodus_tier2.h"
#include "crypto/nodus_identity.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define TEST(name)  do { printf("  %-55s", name); } while(0)
#define PASS()      do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)   do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static uint8_t msgbuf[32768];

/* Helper: create a deterministic fingerprint from index */
static void make_fp(nodus_key_t *fp, int index) {
    memset(fp->bytes, 0, NODUS_KEY_BYTES);
    fp->bytes[0] = (uint8_t)(index & 0xFF);
    fp->bytes[1] = (uint8_t)((index >> 8) & 0xFF);
}

/* ── Presence Table Tests ──────────────────────────────────────────── */

static void test_add_remove_local(void) {
    TEST("add_local + is_online + remove_local");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    nodus_key_t fp;
    make_fp(&fp, 1);

    /* Not online initially */
    uint8_t pi = 255;
    if (nodus_presence_is_online(&srv, &fp, &pi)) {
        FAIL("should not be online before add"); return;
    }

    /* Add local */
    nodus_presence_add_local(&srv, &fp);

    /* Now online with peer_index=0 */
    pi = 255;
    if (!nodus_presence_is_online(&srv, &fp, &pi) || pi != 0) {
        FAIL("should be online after add"); return;
    }

    /* Remove */
    nodus_presence_remove_local(&srv, &fp);

    if (nodus_presence_is_online(&srv, &fp, NULL)) {
        FAIL("should not be online after remove"); return;
    }

    PASS();
}

static void test_query_batch(void) {
    TEST("query_batch returns correct results");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    /* Add 3 local clients */
    nodus_key_t fp1, fp2, fp3, fp4;
    make_fp(&fp1, 10);
    make_fp(&fp2, 20);
    make_fp(&fp3, 30);
    make_fp(&fp4, 40);  /* Not added */

    nodus_presence_add_local(&srv, &fp1);
    nodus_presence_add_local(&srv, &fp2);
    nodus_presence_add_local(&srv, &fp3);

    /* Query 4 fps (3 online, 1 offline) */
    nodus_key_t query[4];
    memcpy(&query[0], &fp1, sizeof(nodus_key_t));
    memcpy(&query[1], &fp4, sizeof(nodus_key_t));  /* offline */
    memcpy(&query[2], &fp2, sizeof(nodus_key_t));
    memcpy(&query[3], &fp3, sizeof(nodus_key_t));

    bool online[4] = {false, false, false, false};
    uint8_t peers[4] = {255, 255, 255, 255};

    int count = nodus_presence_query_batch(&srv, query, 4, online, peers, NULL);
    if (count != 3) { FAIL("expected 3 online"); return; }
    if (!online[0] || online[1] || !online[2] || !online[3]) {
        FAIL("wrong online flags"); return;
    }
    if (peers[0] != 0 || peers[2] != 0 || peers[3] != 0) {
        FAIL("local peers should be 0"); return;
    }

    PASS();
}

static void test_merge_remote(void) {
    TEST("merge_remote + query shows remote online");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    nodus_key_t fps[2];
    make_fp(&fps[0], 100);
    make_fp(&fps[1], 200);

    /* Merge from peer 2 */
    nodus_presence_merge_remote(&srv, fps, 2, 2);

    /* Both should be online with peer_index=2 */
    uint8_t pi = 0;
    if (!nodus_presence_is_online(&srv, &fps[0], &pi) || pi != 2) {
        FAIL("fp[0] not online from peer 2"); return;
    }
    pi = 0;
    if (!nodus_presence_is_online(&srv, &fps[1], &pi) || pi != 2) {
        FAIL("fp[1] not online from peer 2"); return;
    }

    PASS();
}

static void test_expire(void) {
    TEST("expire removes stale remote entries");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    nodus_key_t fp_local, fp_remote;
    make_fp(&fp_local, 300);
    make_fp(&fp_remote, 400);

    /* Add local (never expires) */
    nodus_presence_add_local(&srv, &fp_local);

    /* Add remote */
    nodus_presence_merge_remote(&srv, &fp_remote, 1, 1);

    /* Both online */
    if (!nodus_presence_is_online(&srv, &fp_local, NULL) ||
        !nodus_presence_is_online(&srv, &fp_remote, NULL)) {
        FAIL("both should be online"); return;
    }

    /* Expire with future timestamp (TTL=45s) */
    uint64_t future = (uint64_t)time(NULL) + NODUS_PRESENCE_REMOTE_TTL + 10;
    nodus_presence_expire(&srv, future);

    /* Local still online, remote expired */
    if (!nodus_presence_is_online(&srv, &fp_local, NULL)) {
        FAIL("local should survive expire"); return;
    }
    if (nodus_presence_is_online(&srv, &fp_remote, NULL)) {
        FAIL("remote should be expired"); return;
    }

    PASS();
}

static void test_get_local(void) {
    TEST("get_local returns only local entries");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    nodus_key_t fp1, fp2, fp_remote;
    make_fp(&fp1, 500);
    make_fp(&fp2, 600);
    make_fp(&fp_remote, 700);

    nodus_presence_add_local(&srv, &fp1);
    nodus_presence_add_local(&srv, &fp2);
    nodus_presence_merge_remote(&srv, &fp_remote, 1, 1);

    nodus_key_t out[10];
    int count = nodus_presence_get_local(&srv, out, 10);
    if (count != 2) { FAIL("expected 2 local"); return; }

    PASS();
}

static void test_duplicate_add(void) {
    TEST("duplicate add_local does not create second entry");

    nodus_server_t srv;
    memset(&srv, 0, sizeof(srv));

    nodus_key_t fp;
    make_fp(&fp, 800);

    nodus_presence_add_local(&srv, &fp);
    nodus_presence_add_local(&srv, &fp);

    nodus_key_t out[10];
    int count = nodus_presence_get_local(&srv, out, 10);
    if (count != 1) { FAIL("duplicate should not create second entry"); return; }

    PASS();
}

/* ── Protocol Tests ────────────────────────────────────────────────── */

static void test_pq_encode_decode(void) {
    TEST("pq (presence query) encode/decode roundtrip");

    nodus_identity_t id;
    uint8_t seed[32];
    memset(seed, 0xAA, sizeof(seed));
    nodus_identity_from_seed(seed, &id);

    nodus_key_t fps[3];
    make_fp(&fps[0], 1000);
    make_fp(&fps[1], 2000);
    make_fp(&fps[2], 3000);

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x42, sizeof(token));

    size_t len = 0;
    int rc = nodus_t2_presence_query(99, token, fps, 3,
                                       msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 99 || msg.type != 'q' ||
        strcmp(msg.method, "pq") != 0 || msg.pq_count != 3) {
        FAIL("header mismatch"); nodus_t2_msg_free(&msg); return;
    }

    /* Verify fingerprints decoded correctly */
    for (int i = 0; i < 3; i++) {
        if (nodus_key_cmp(&msg.pq_fps[i], &fps[i]) != 0) {
            FAIL("fp mismatch"); nodus_t2_msg_free(&msg); return;
        }
    }

    nodus_t2_msg_free(&msg);
    nodus_identity_clear(&id);
    PASS();
}

static void test_pq_result_sparse(void) {
    TEST("pq result: sparse encoding (only online entries)");

    /* 5 fps, only 2 online */
    nodus_key_t fps[5];
    for (int i = 0; i < 5; i++) make_fp(&fps[i], 5000 + i);

    bool online[5] = {true, false, false, true, false};
    uint8_t peers[5] = {0, 0, 0, 2, 0};

    size_t len = 0;
    int rc = nodus_t2_presence_result(100, fps, online, peers, NULL, 5,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 100 || msg.type != 'r' ||
        strcmp(msg.method, "pq") != 0) {
        FAIL("header mismatch"); nodus_t2_msg_free(&msg); return;
    }

    /* Should have decoded 2 online entries */
    if (msg.pq_count != 2) {
        char buf[64];
        snprintf(buf, sizeof(buf), "expected 2 online, got %d", msg.pq_count);
        FAIL(buf); nodus_t2_msg_free(&msg); return;
    }

    /* Verify the two online fps */
    bool found_0 = false, found_3 = false;
    for (int i = 0; i < msg.pq_count; i++) {
        if (msg.pq_online[i]) {
            if (nodus_key_cmp(&msg.pq_fps[i], &fps[0]) == 0 && msg.pq_peers[i] == 0)
                found_0 = true;
            if (nodus_key_cmp(&msg.pq_fps[i], &fps[3]) == 0 && msg.pq_peers[i] == 2)
                found_3 = true;
        }
    }

    if (!found_0 || !found_3) {
        FAIL("online entries not decoded correctly"); nodus_t2_msg_free(&msg); return;
    }

    nodus_t2_msg_free(&msg);
    PASS();
}

static void test_psync_encode_decode(void) {
    TEST("p_sync encode/decode roundtrip");

    nodus_key_t fps[2];
    make_fp(&fps[0], 9000);
    make_fp(&fps[1], 9001);

    size_t len = 0;
    int rc = nodus_t2_presence_sync(200, fps, 2,
                                      msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 200 || msg.type != 'q' ||
        strcmp(msg.method, "p_sync") != 0 || msg.pq_count != 2) {
        FAIL("header mismatch"); nodus_t2_msg_free(&msg); return;
    }

    if (nodus_key_cmp(&msg.pq_fps[0], &fps[0]) != 0 ||
        nodus_key_cmp(&msg.pq_fps[1], &fps[1]) != 0) {
        FAIL("fp mismatch"); nodus_t2_msg_free(&msg); return;
    }

    nodus_t2_msg_free(&msg);
    PASS();
}

static void test_pq_empty_result(void) {
    TEST("pq result: empty (all offline)");

    nodus_key_t fps[3];
    for (int i = 0; i < 3; i++) make_fp(&fps[i], 7000 + i);

    bool online[3] = {false, false, false};
    uint8_t peers[3] = {0, 0, 0};

    size_t len = 0;
    int rc = nodus_t2_presence_result(101, fps, online, peers, NULL, 3,
                                        msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.pq_count != 0) {
        FAIL("expected 0 entries for all-offline"); nodus_t2_msg_free(&msg); return;
    }

    nodus_t2_msg_free(&msg);
    PASS();
}

/* ── Main ──────────────────────────────────────────────────────────── */

int main(void) {
    printf("=== Nodus Presence Tests ===\n\n");

    printf("  -- Table --\n");
    test_add_remove_local();
    test_query_batch();
    test_merge_remote();
    test_expire();
    test_get_local();
    test_duplicate_add();

    printf("\n  -- Protocol --\n");
    test_pq_encode_decode();
    test_pq_result_sparse();
    test_psync_encode_decode();
    test_pq_empty_result();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
