/**
 * Nodus — Channel Storage Tests
 */

#include "channel/nodus_channel_store.h"
#include "crypto/nodus_sign.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %-45s ", tests_run, name); \
} while (0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while (0)

static char db_path[256];
static nodus_channel_store_t store;

/* Fixed test UUID (16 bytes) */
static const uint8_t test_uuid[16] = {
    0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
    0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00
};

static void test_open_close(void) {
    TEST("open and close channel store");

    snprintf(db_path, sizeof(db_path), "/tmp/nodus_ch_test_%d.db", getpid());
    if (nodus_channel_store_open(db_path, &store) != 0) {
        FAIL("open failed"); return;
    }
    PASS();
}

static void test_create_channel(void) {
    TEST("create channel table");

    if (nodus_channel_create(&store, test_uuid) != 0) {
        FAIL("create failed"); return;
    }
    if (!nodus_channel_exists(&store, test_uuid)) {
        FAIL("channel not found after create"); return;
    }
    PASS();
}

static void test_create_idempotent(void) {
    TEST("create channel is idempotent");

    /* Should succeed even though channel already exists */
    if (nodus_channel_create(&store, test_uuid) != 0) {
        FAIL("second create failed"); return;
    }
    PASS();
}

static void test_post_and_get(void) {
    TEST("post and get");

    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0x01, NODUS_UUID_BYTES);
    memset(post.author_fp.bytes, 0xAA, NODUS_KEY_BYTES);
    post.timestamp = 1709000000;
    post.body = strdup("Hello channel!");
    post.body_len = strlen(post.body);

    int rc = nodus_channel_post(&store, &post);
    free(post.body);
    if (rc != 0) { FAIL("post failed"); return; }
    if (post.seq_id != 1) { FAIL("expected seq_id=1"); return; }

    /* Get posts */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 1) { FAIL("get failed"); nodus_channel_posts_free(posts, count); return; }
    if (posts[0].seq_id != 1) { FAIL("seq_id mismatch"); nodus_channel_posts_free(posts, count); return; }
    if (strcmp(posts[0].body, "Hello channel!") != 0) {
        FAIL("body mismatch"); nodus_channel_posts_free(posts, count); return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_duplicate_post(void) {
    TEST("duplicate post_uuid returns 1");

    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0x01, NODUS_UUID_BYTES);  /* Same as first post */
    post.body = strdup("Duplicate");
    post.body_len = strlen(post.body);

    int rc = nodus_channel_post(&store, &post);
    free(post.body);
    if (rc != 1) { FAIL("expected rc=1 for duplicate"); return; }
    PASS();
}

static void test_sequential_seq_id(void) {
    TEST("sequential seq_id assignment");

    for (int i = 2; i <= 5; i++) {
        nodus_channel_post_t post;
        memset(&post, 0, sizeof(post));
        memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
        memset(post.post_uuid, (uint8_t)i, NODUS_UUID_BYTES);
        char body[32];
        snprintf(body, sizeof(body), "Post %d", i);
        post.body = body;
        post.body_len = strlen(body);

        int rc = nodus_channel_post(&store, &post);
        if (rc != 0) { FAIL("post failed"); return; }
        if ((int)post.seq_id != i) {
            char msg[64];
            snprintf(msg, sizeof(msg), "expected seq=%d, got %u", i, post.seq_id);
            FAIL(msg); return;
        }
    }
    PASS();
}

static void test_get_since_seq(void) {
    TEST("get posts since seq_id");

    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    int rc = nodus_channel_get_posts(&store, test_uuid, 3, 100, &posts, &count);
    if (rc != 0) { FAIL("get failed"); return; }
    if (count != 2) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 2 posts after seq 3, got %zu", count);
        FAIL(msg); nodus_channel_posts_free(posts, count); return;
    }
    if (posts[0].seq_id != 4 || posts[1].seq_id != 5) {
        FAIL("wrong seq_ids"); nodus_channel_posts_free(posts, count); return;
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_max_seq(void) {
    TEST("max_seq returns highest seq_id");

    uint32_t max = nodus_channel_max_seq(&store, test_uuid);
    if (max != 5) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 5, got %u", max);
        FAIL(msg); return;
    }
    PASS();
}

static void test_hinted_handoff(void) {
    TEST("hinted handoff insert + get + delete");

    nodus_key_t target;
    memset(target.bytes, 0xBB, NODUS_KEY_BYTES);

    const uint8_t data[] = "serialized post data";
    int rc = nodus_hinted_insert(&store, &target, test_uuid, data, sizeof(data));
    if (rc != 0) { FAIL("insert failed"); return; }

    nodus_hinted_entry_t *entries = NULL;
    size_t count = 0;
    rc = nodus_hinted_get(&store, &target, 100, &entries, &count);
    if (rc != 0 || count != 1) { FAIL("get failed"); nodus_hinted_entries_free(entries, count); return; }
    if (entries[0].post_data_len != sizeof(data)) {
        FAIL("data len mismatch"); nodus_hinted_entries_free(entries, count); return;
    }

    int64_t id = entries[0].id;
    nodus_hinted_entries_free(entries, count);

    /* Delete */
    rc = nodus_hinted_delete(&store, id);
    if (rc != 0) { FAIL("delete failed"); return; }

    /* Verify gone */
    rc = nodus_hinted_get(&store, &target, 100, &entries, &count);
    if (count != 0) { FAIL("entry still present"); nodus_hinted_entries_free(entries, count); return; }

    PASS();
}

static void test_channel_drop(void) {
    TEST("drop channel table");

    if (nodus_channel_drop(&store, test_uuid) != 0) {
        FAIL("drop failed"); return;
    }
    if (nodus_channel_exists(&store, test_uuid)) {
        FAIL("channel still exists after drop"); return;
    }
    PASS();
}

static void test_nonexistent_channel(void) {
    TEST("operations on nonexistent channel");

    uint8_t fake[16];
    memset(fake, 0xFF, 16);
    if (nodus_channel_exists(&store, fake)) {
        FAIL("fake channel should not exist"); return;
    }
    PASS();
}

int main(void) {
    printf("test_channel_store: Channel storage tests\n");

    test_open_close();
    test_create_channel();
    test_create_idempotent();
    test_post_and_get();
    test_duplicate_post();
    test_sequential_seq_id();
    test_get_since_seq();
    test_max_seq();
    test_hinted_handoff();
    test_channel_drop();
    test_nonexistent_channel();

    /* Cleanup */
    nodus_channel_store_close(&store);
    unlink(db_path);
    char wal[270], shm[270];
    snprintf(wal, sizeof(wal), "%s-wal", db_path);
    snprintf(shm, sizeof(shm), "%s-shm", db_path);
    unlink(wal);
    unlink(shm);

    printf("\n  %d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
