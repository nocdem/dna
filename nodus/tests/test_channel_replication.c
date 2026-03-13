/**
 * Nodus -- Channel Replication Tests
 *
 * Tests replication_receive, handle_sync_response, and retry timing.
 * Uses real SQLite channel store in /tmp.
 */

#include "channel/nodus_channel_replication.h"
#include "channel/nodus_channel_store.h"
#include "channel/nodus_hashring.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-50s ", tests_run, name); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

/* Fixed test UUID */
static const uint8_t test_uuid[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAB, 0xCD
};

static char db_path[256];
static nodus_channel_store_t store;
static nodus_channel_server_t cs;
static nodus_hashring_t ring;
static nodus_identity_t identity;
static nodus_ch_replication_t rep;

static void setup(void) {
    snprintf(db_path, sizeof(db_path), "/tmp/nodus_ch_repl_test_%d.db", getpid());

    memset(&store, 0, sizeof(store));
    memset(&cs, 0, sizeof(cs));
    memset(&ring, 0, sizeof(ring));
    memset(&identity, 0, sizeof(identity));

    nodus_channel_store_open(db_path, &store);
    nodus_hashring_init(&ring);

    /* Set up identity with a known node_id */
    memset(identity.node_id.bytes, 0x11, NODUS_KEY_BYTES);

    cs.ch_store = &store;
    cs.ring = &ring;
    cs.identity = &identity;

    nodus_ch_replication_init(&rep, &cs);
}

static void teardown(void) {
    nodus_channel_store_close(&store);
    unlink(db_path);

    char wal[270], shm[270];
    snprintf(wal, sizeof(wal), "%s-wal", db_path);
    snprintf(shm, sizeof(shm), "%s-shm", db_path);
    unlink(wal);
    unlink(shm);
}

/* ---- Tests -------------------------------------------------------------- */

static void test_init(void) {
    TEST("replication init");

    nodus_ch_replication_t r;
    nodus_ch_replication_init(&r, &cs);

    if (r.cs != &cs) { FAIL("cs not set"); return; }
    if (r.last_retry_ms != 0) { FAIL("last_retry_ms not zero"); return; }
    PASS();
}

static void test_receive_stores_post(void) {
    TEST("replication_receive stores post");

    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0x01, NODUS_UUID_BYTES);
    memset(post.author_fp.bytes, 0xAA, NODUS_KEY_BYTES);
    post.timestamp = 1700000000;
    char body[] = "Replicated post content";
    post.body = body;
    post.body_len = strlen(body);

    int rc = nodus_ch_replication_receive(&rep, test_uuid, &post);
    if (rc != 0) { FAIL("receive returned error"); return; }

    /* Verify post is stored */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 1) {
        FAIL("post not found in store");
        nodus_channel_posts_free(posts, count);
        return;
    }
    if (strcmp(posts[0].body, "Replicated post content") != 0) {
        FAIL("body mismatch");
        nodus_channel_posts_free(posts, count);
        return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_receive_dedup(void) {
    TEST("replication_receive deduplicates by post_uuid");

    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0x01, NODUS_UUID_BYTES);  /* Same UUID as above */
    memset(post.author_fp.bytes, 0xAA, NODUS_KEY_BYTES);
    post.timestamp = 1700000000;
    char body[] = "Duplicate post";
    post.body = body;
    post.body_len = strlen(body);

    int rc = nodus_ch_replication_receive(&rep, test_uuid, &post);
    if (rc != 0) { FAIL("receive returned error"); return; }

    /* Should still be only 1 post */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 1) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 1 post, got %zu", count);
        FAIL(msg);
        nodus_channel_posts_free(posts, count);
        return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_receive_creates_channel(void) {
    TEST("replication_receive creates channel if missing");

    uint8_t new_uuid[16];
    memset(new_uuid, 0xFF, 16);

    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, new_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0x02, NODUS_UUID_BYTES);
    char body[] = "Post in new channel";
    post.body = body;
    post.body_len = strlen(body);

    int rc = nodus_ch_replication_receive(&rep, new_uuid, &post);
    if (rc != 0) { FAIL("receive returned error"); return; }

    /* Channel should now exist */
    if (!nodus_channel_exists(&store, new_uuid)) {
        FAIL("channel was not created"); return;
    }

    /* Cleanup */
    nodus_channel_drop(&store, new_uuid);
    PASS();
}

static void test_sync_response_stores_batch(void) {
    TEST("handle_sync_response stores batch of posts");

    /* Drop and recreate channel to start clean */
    nodus_channel_drop(&store, test_uuid);

    /* Create a batch of posts */
    nodus_channel_post_t batch[5];
    char bodies[5][32];
    for (int i = 0; i < 5; i++) {
        memset(&batch[i], 0, sizeof(batch[i]));
        memcpy(batch[i].channel_uuid, test_uuid, NODUS_UUID_BYTES);
        memset(batch[i].post_uuid, (uint8_t)(0x20 + i), NODUS_UUID_BYTES);
        memset(batch[i].author_fp.bytes, 0xCC, NODUS_KEY_BYTES);
        batch[i].timestamp = 1700000000 + (uint64_t)i * 1000;
        batch[i].received_at = 1700000000 + (uint64_t)i * 1000;
        snprintf(bodies[i], sizeof(bodies[i]), "Sync post %d", i);
        batch[i].body = bodies[i];
        batch[i].body_len = strlen(bodies[i]);
    }

    int rc = nodus_ch_replication_handle_sync_response(&rep, test_uuid,
                                                        batch, 5);
    if (rc != 0) { FAIL("sync response handler failed"); return; }

    /* Verify all 5 posts stored */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 5) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 5 posts, got %zu", count);
        FAIL(msg);
        nodus_channel_posts_free(posts, count);
        return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_sync_response_dedup(void) {
    TEST("handle_sync_response deduplicates existing posts");

    /* Re-sync the same 5 posts + 2 new ones */
    nodus_channel_post_t batch[7];
    char bodies[7][32];
    for (int i = 0; i < 7; i++) {
        memset(&batch[i], 0, sizeof(batch[i]));
        memcpy(batch[i].channel_uuid, test_uuid, NODUS_UUID_BYTES);
        /* First 5 have same UUIDs as before, last 2 are new */
        memset(batch[i].post_uuid, (uint8_t)(0x20 + i), NODUS_UUID_BYTES);
        memset(batch[i].author_fp.bytes, 0xCC, NODUS_KEY_BYTES);
        batch[i].timestamp = 1700000000 + (uint64_t)i * 1000;
        batch[i].received_at = 1700000000 + (uint64_t)i * 1000;
        snprintf(bodies[i], sizeof(bodies[i]), "Sync post %d", i);
        batch[i].body = bodies[i];
        batch[i].body_len = strlen(bodies[i]);
    }

    int rc = nodus_ch_replication_handle_sync_response(&rep, test_uuid,
                                                        batch, 7);
    if (rc != 0) { FAIL("sync response handler failed"); return; }

    /* Should now have 7 total (5 existing + 2 new) */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 7) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 7 posts, got %zu", count);
        FAIL(msg);
        nodus_channel_posts_free(posts, count);
        return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_retry_timing(void) {
    TEST("replication_retry respects 30s interval");

    /* Set last_retry to a known value */
    rep.last_retry_ms = 100000;

    /* Call retry at 100001 (only 1ms later) -- should be a no-op */
    nodus_ch_replication_retry(&rep, 100001);
    if (rep.last_retry_ms != 100000) {
        FAIL("last_retry_ms should not have changed"); return;
    }

    /* Call retry at 131000 (31s later) -- should run */
    nodus_ch_replication_retry(&rep, 131000);
    if (rep.last_retry_ms != 131000) {
        FAIL("last_retry_ms should have updated to 131000"); return;
    }

    PASS();
}

static void test_retry_at_exact_boundary(void) {
    TEST("replication_retry triggers at exact 30s boundary");

    rep.last_retry_ms = 200000;

    /* 29999ms later -- should NOT trigger (< 30000) */
    nodus_ch_replication_retry(&rep, 229999);
    if (rep.last_retry_ms != 200000) {
        FAIL("should not trigger at 29999ms"); return;
    }

    /* Exactly 30s (30000ms) later -- SHOULD trigger (30000 < 30000 is false) */
    nodus_ch_replication_retry(&rep, 230000);
    if (rep.last_retry_ms != 230000) {
        FAIL("should trigger at exact 30s boundary"); return;
    }

    PASS();
}

/* ---- Main --------------------------------------------------------------- */

int main(void) {
    printf("test_channel_replication: Channel replication tests\n");

    setup();

    test_init();
    test_receive_stores_post();
    test_receive_dedup();
    test_receive_creates_channel();
    test_sync_response_stores_batch();
    test_sync_response_dedup();
    test_retry_timing();
    test_retry_at_exact_boundary();

    teardown();

    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
