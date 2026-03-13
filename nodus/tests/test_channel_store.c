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
    if (post.received_at == 0) { FAIL("expected received_at to be assigned"); return; }

    /* Get posts */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 1) { FAIL("get failed"); nodus_channel_posts_free(posts, count); return; }
    if (posts[0].received_at == 0) { FAIL("received_at not returned"); nodus_channel_posts_free(posts, count); return; }
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

static void test_ordering_by_received_at(void) {
    TEST("ordering by received_at");

    /* Drop and recreate to start clean */
    nodus_channel_drop(&store, test_uuid);
    nodus_channel_create(&store, test_uuid);

    /* Insert posts with explicit received_at values in non-sequential order */
    uint64_t ra_values[] = { 5000, 3000, 7000, 1000 };
    for (int i = 0; i < 4; i++) {
        nodus_channel_post_t post;
        memset(&post, 0, sizeof(post));
        memcpy(post.channel_uuid, test_uuid, NODUS_UUID_BYTES);
        memset(post.post_uuid, (uint8_t)(0x10 + i), NODUS_UUID_BYTES);
        char body[32];
        snprintf(body, sizeof(body), "Post ra=%llu", (unsigned long long)ra_values[i]);
        post.body = body;
        post.body_len = strlen(body);
        post.received_at = ra_values[i];

        int rc = nodus_channel_post(&store, &post);
        if (rc != 0) { FAIL("post failed"); return; }
    }

    /* Get all posts — should be ordered by received_at ascending */
    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    int rc = nodus_channel_get_posts(&store, test_uuid, 0, 100, &posts, &count);
    if (rc != 0 || count != 4) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 4 posts, got %zu", count);
        FAIL(msg); nodus_channel_posts_free(posts, count); return;
    }
    /* Verify ordering: received_at should be monotonically non-decreasing */
    for (size_t i = 1; i < count; i++) {
        if (posts[i].received_at < posts[i-1].received_at) {
            FAIL("posts not ordered by received_at"); nodus_channel_posts_free(posts, count); return;
        }
    }
    nodus_channel_posts_free(posts, count);
    PASS();
}

static void test_get_since_received_at(void) {
    TEST("get posts since received_at");

    nodus_channel_post_t *posts = NULL;
    size_t count = 0;
    /* Get posts with received_at > 3000 (should be 5000 and 7000) */
    int rc = nodus_channel_get_posts(&store, test_uuid, 3000, 100, &posts, &count);
    if (rc != 0) { FAIL("get failed"); return; }
    if (count != 2) {
        char msg[64];
        snprintf(msg, sizeof(msg), "expected 2 posts after ra=3000, got %zu", count);
        FAIL(msg); nodus_channel_posts_free(posts, count); return;
    }
    /* Should be ra=5000 and ra=7000 */
    if (posts[0].received_at != 5000 || posts[1].received_at != 7000) {
        FAIL("wrong received_at values"); nodus_channel_posts_free(posts, count); return;
    }
    nodus_channel_posts_free(posts, count);
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

static void test_migration_from_old_schema(void) {
    TEST("migration from old seq_id schema");

    /* Create a channel table with the OLD schema (seq_id based) */
    uint8_t mig_uuid[16];
    int i;
    for (i = 0; i < 16; i++) mig_uuid[i] = (i % 2 == 0) ? 0xff : 0x00;
    /* This gives ff00ff00ff00ff00ff00ff00ff00ff00 */

    char sql[384];
    snprintf(sql, sizeof(sql),
        "CREATE TABLE channel_ff00ff00ff00ff00ff00ff00ff00ff00 ("
        "seq_id INTEGER NOT NULL,"
        "post_uuid BLOB NOT NULL,"
        "author_fp BLOB NOT NULL,"
        "timestamp INTEGER NOT NULL,"
        "body BLOB NOT NULL,"
        "signature BLOB NOT NULL,"
        "received_at INTEGER NOT NULL,"
        "PRIMARY KEY(seq_id))");
    char *err = NULL;
    sqlite3_exec(store.db, sql, NULL, NULL, &err);
    sqlite3_free(err);

    /* Now call nodus_channel_create — should detect old schema and migrate */
    int rc = nodus_channel_create(&store, mig_uuid);
    if (rc != 0) { FAIL("create after migration failed"); return; }
    if (!nodus_channel_exists(&store, mig_uuid)) {
        FAIL("channel not found after migration"); return;
    }

    /* Verify new schema works — post should succeed without seq_id */
    nodus_channel_post_t post;
    memset(&post, 0, sizeof(post));
    memcpy(post.channel_uuid, mig_uuid, NODUS_UUID_BYTES);
    memset(post.post_uuid, 0xAB, NODUS_UUID_BYTES);
    post.body = strdup("After migration");
    post.body_len = strlen(post.body);

    rc = nodus_channel_post(&store, &post);
    free(post.body);
    if (rc != 0) { FAIL("post after migration failed"); return; }

    /* Cleanup */
    nodus_channel_drop(&store, mig_uuid);
    PASS();
}

int main(void) {
    printf("test_channel_store: Channel storage tests\n");

    test_open_close();
    test_create_channel();
    test_create_idempotent();
    test_post_and_get();
    test_duplicate_post();
    test_ordering_by_received_at();
    test_get_since_received_at();
    test_hinted_handoff();
    test_channel_drop();
    test_nonexistent_channel();
    test_migration_from_old_schema();

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
