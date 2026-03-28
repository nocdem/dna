/**
 * Nodus — Media Storage Tests
 */

#include "core/nodus_media_storage.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static const char *TEST_DB = "/tmp/nodus_test_media_storage.db";

static void make_test_hash(uint8_t hash[64], uint8_t fill) {
    memset(hash, fill, 64);
}

static nodus_media_meta_t make_test_meta(uint8_t hash_fill, const char *owner,
                                          uint8_t media_type, uint64_t total_size,
                                          uint32_t chunk_count, uint32_t ttl) {
    nodus_media_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    make_test_hash(meta.content_hash, hash_fill);
    strncpy(meta.owner_fp, owner, sizeof(meta.owner_fp) - 1);
    meta.media_type = media_type;
    meta.total_size = total_size;
    meta.chunk_count = chunk_count;
    meta.encrypted = true;
    meta.ttl = ttl;
    meta.created_at = (uint64_t)time(NULL);
    meta.expires_at = (ttl > 0) ? meta.created_at + ttl : 0;
    meta.complete = false;
    return meta;
}

static sqlite3 *open_test_db(void) {
    unlink(TEST_DB);
    sqlite3 *db = NULL;
    int rc = sqlite3_open(TEST_DB, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open test DB\n");
        return NULL;
    }
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    return db;
}

static void test_media_open_close(void) {
    TEST("open and close media storage");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    int rc = nodus_media_storage_open(db, &ms);
    if (rc != 0) {
        FAIL("media storage open failed");
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Verify tables exist by querying them */
    sqlite3_stmt *s = NULL;
    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM media_meta", -1, &s, NULL);
    if (rc != SQLITE_OK) {
        FAIL("media_meta table not created");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }
    sqlite3_finalize(s);

    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM media_chunks", -1, &s, NULL);
    if (rc != SQLITE_OK) {
        FAIL("media_chunks table not created");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }
    sqlite3_finalize(s);

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
    PASS();
}

static void test_media_put_get_meta(void) {
    TEST("put and get meta");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    nodus_media_meta_t meta = make_test_meta(0xAA, "owner_abc123", NODUS_MEDIA_IMAGE,
                                              1024 * 1024, 4, 3600);

    int rc = nodus_media_put_meta(&ms, &meta);
    if (rc != 0) {
        FAIL("put_meta failed");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    nodus_media_meta_t got;
    rc = nodus_media_get_meta(&ms, meta.content_hash, &got);
    if (rc != 0) {
        FAIL("get_meta failed");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    if (memcmp(got.content_hash, meta.content_hash, 64) != 0) {
        FAIL("content_hash mismatch");
    } else if (strcmp(got.owner_fp, meta.owner_fp) != 0) {
        FAIL("owner_fp mismatch");
    } else if (got.media_type != meta.media_type) {
        FAIL("media_type mismatch");
    } else if (got.total_size != meta.total_size) {
        FAIL("total_size mismatch");
    } else if (got.chunk_count != meta.chunk_count) {
        FAIL("chunk_count mismatch");
    } else if (got.encrypted != meta.encrypted) {
        FAIL("encrypted mismatch");
    } else if (got.ttl != meta.ttl) {
        FAIL("ttl mismatch");
    } else if (got.complete != false) {
        FAIL("complete should be false");
    } else {
        PASS();
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_put_get_chunk(void) {
    TEST("put and get chunk");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    uint8_t hash[64];
    make_test_hash(hash, 0xBB);

    /* Put meta first */
    nodus_media_meta_t meta = make_test_meta(0xBB, "owner_chunk", NODUS_MEDIA_VIDEO,
                                              8192, 2, 3600);
    nodus_media_put_meta(&ms, &meta);

    /* Put chunk */
    uint8_t chunk_data[256];
    memset(chunk_data, 0xCC, sizeof(chunk_data));
    int rc = nodus_media_put_chunk(&ms, hash, 0, chunk_data, sizeof(chunk_data));
    if (rc != 0) {
        FAIL("put_chunk failed");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Get chunk */
    uint8_t *data_out = NULL;
    size_t data_len = 0;
    rc = nodus_media_get_chunk(&ms, hash, 0, &data_out, &data_len);
    if (rc != 0) {
        FAIL("get_chunk failed");
    } else if (data_len != sizeof(chunk_data)) {
        FAIL("chunk size mismatch");
    } else if (memcmp(data_out, chunk_data, data_len) != 0) {
        FAIL("chunk data mismatch");
    } else {
        PASS();
    }

    free(data_out);
    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_complete_flow(void) {
    TEST("complete upload flow");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    nodus_media_meta_t meta = make_test_meta(0xDD, "owner_flow", NODUS_MEDIA_AUDIO,
                                              768, 3, 7200);
    nodus_media_put_meta(&ms, &meta);

    /* Put 3 chunks */
    for (uint32_t i = 0; i < 3; i++) {
        uint8_t data[256];
        memset(data, (int)(0x10 + i), sizeof(data));
        nodus_media_put_chunk(&ms, meta.content_hash, i, data, sizeof(data));
    }

    /* Verify chunk count */
    int count = nodus_media_count_chunks(&ms, meta.content_hash);
    if (count != 3) {
        FAIL("wrong chunk count");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Mark complete */
    int rc = nodus_media_mark_complete(&ms, meta.content_hash);
    if (rc != 0) {
        FAIL("mark_complete failed");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Verify complete flag */
    nodus_media_meta_t got;
    nodus_media_get_meta(&ms, meta.content_hash, &got);
    if (got.complete) {
        PASS();
    } else {
        FAIL("complete flag not set");
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_exists(void) {
    TEST("exists check (present/absent/complete)");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    /* Check absent */
    uint8_t absent_hash[64];
    make_test_hash(absent_hash, 0x00);
    bool exists = true, complete = true;
    nodus_media_exists(&ms, absent_hash, &exists, &complete);
    if (exists) {
        FAIL("absent should not exist");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Insert incomplete */
    nodus_media_meta_t meta = make_test_meta(0xEE, "owner_exists", NODUS_MEDIA_IMAGE,
                                              512, 1, 3600);
    nodus_media_put_meta(&ms, &meta);

    nodus_media_exists(&ms, meta.content_hash, &exists, &complete);
    if (!exists || complete) {
        FAIL("should exist but be incomplete");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Mark complete */
    nodus_media_mark_complete(&ms, meta.content_hash);
    nodus_media_exists(&ms, meta.content_hash, &exists, &complete);
    if (!exists || !complete) {
        FAIL("should exist and be complete");
    } else {
        PASS();
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_dedup(void) {
    TEST("dedup (INSERT OR IGNORE on same hash)");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    nodus_media_meta_t meta1 = make_test_meta(0xFF, "owner_first", NODUS_MEDIA_IMAGE,
                                               1000, 1, 3600);
    nodus_media_put_meta(&ms, &meta1);

    /* Second insert with same content_hash but different owner — should be ignored */
    nodus_media_meta_t meta2 = make_test_meta(0xFF, "owner_second", NODUS_MEDIA_VIDEO,
                                               2000, 2, 7200);
    nodus_media_put_meta(&ms, &meta2);

    /* Get should return original meta */
    nodus_media_meta_t got;
    nodus_media_get_meta(&ms, meta1.content_hash, &got);

    if (strcmp(got.owner_fp, "owner_first") == 0 &&
        got.total_size == 1000 &&
        got.media_type == NODUS_MEDIA_IMAGE) {
        PASS();
    } else {
        FAIL("dedup failed — second insert overwrote first");
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_cleanup_expired(void) {
    TEST("cleanup removes expired media");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    /* Insert expired media (created_at and expires_at in the past) */
    nodus_media_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    make_test_hash(meta.content_hash, 0x11);
    strncpy(meta.owner_fp, "owner_expired", sizeof(meta.owner_fp) - 1);
    meta.media_type = NODUS_MEDIA_IMAGE;
    meta.total_size = 100;
    meta.chunk_count = 1;
    meta.encrypted = false;
    meta.ttl = 1;
    meta.created_at = 1000;
    meta.expires_at = 1001;  /* Long expired */
    meta.complete = true;
    nodus_media_put_meta(&ms, &meta);

    /* Add a chunk for it */
    uint8_t data[16] = {0};
    nodus_media_put_chunk(&ms, meta.content_hash, 0, data, sizeof(data));

    /* Insert non-expired media */
    nodus_media_meta_t meta2 = make_test_meta(0x22, "owner_alive", NODUS_MEDIA_VIDEO,
                                               200, 1, 86400);
    nodus_media_put_meta(&ms, &meta2);

    int cleaned = nodus_media_cleanup(&ms);
    if (cleaned < 1) {
        FAIL("should have cleaned at least 1");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    /* Verify expired is gone */
    bool exists = true, complete = false;
    nodus_media_exists(&ms, meta.content_hash, &exists, &complete);
    if (exists) {
        FAIL("expired media still exists");
    } else {
        /* Verify non-expired still there */
        nodus_media_exists(&ms, meta2.content_hash, &exists, &complete);
        if (exists) {
            PASS();
        } else {
            FAIL("non-expired media was deleted");
        }
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_cleanup_incomplete(void) {
    TEST("cleanup removes stale incomplete uploads");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    /* Insert incomplete media with old created_at (more than 5 min ago) */
    nodus_media_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    make_test_hash(meta.content_hash, 0x33);
    strncpy(meta.owner_fp, "owner_stale", sizeof(meta.owner_fp) - 1);
    meta.media_type = NODUS_MEDIA_AUDIO;
    meta.total_size = 500;
    meta.chunk_count = 2;
    meta.encrypted = false;
    meta.ttl = 86400;
    meta.created_at = (uint64_t)time(NULL) - 600;  /* 10 min ago */
    meta.expires_at = meta.created_at + 86400;
    meta.complete = false;  /* Incomplete */
    nodus_media_put_meta(&ms, &meta);

    /* Add a chunk for it */
    uint8_t data[16] = {0};
    nodus_media_put_chunk(&ms, meta.content_hash, 0, data, sizeof(data));

    int cleaned = nodus_media_cleanup(&ms);
    if (cleaned < 1) {
        FAIL("should have cleaned stale incomplete");
        nodus_media_storage_close(&ms);
        sqlite3_close(db);
        unlink(TEST_DB);
        return;
    }

    bool exists = false, complete = false;
    nodus_media_exists(&ms, meta.content_hash, &exists, &complete);
    if (!exists) {
        PASS();
    } else {
        FAIL("stale incomplete media still exists");
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

static void test_media_count_per_owner(void) {
    TEST("count per owner");

    sqlite3 *db = open_test_db();
    if (!db) { FAIL("db open"); return; }

    nodus_media_storage_t ms;
    nodus_media_storage_open(db, &ms);

    /* Insert 3 for owner_a, 2 for owner_b */
    for (int i = 0; i < 3; i++) {
        nodus_media_meta_t meta = make_test_meta((uint8_t)(0x40 + i), "owner_a",
                                                  NODUS_MEDIA_IMAGE, 100, 1, 3600);
        nodus_media_put_meta(&ms, &meta);
    }
    for (int i = 0; i < 2; i++) {
        nodus_media_meta_t meta = make_test_meta((uint8_t)(0x50 + i), "owner_b",
                                                  NODUS_MEDIA_VIDEO, 200, 1, 3600);
        nodus_media_put_meta(&ms, &meta);
    }

    int count_a = nodus_media_count_per_owner(&ms, "owner_a");
    int count_b = nodus_media_count_per_owner(&ms, "owner_b");
    int count_c = nodus_media_count_per_owner(&ms, "owner_c");

    if (count_a == 3 && count_b == 2 && count_c == 0) {
        PASS();
    } else {
        FAIL("wrong counts");
    }

    nodus_media_storage_close(&ms);
    sqlite3_close(db);
    unlink(TEST_DB);
}

int main(void) {
    printf("=== Nodus Media Storage Tests ===\n");

    test_media_open_close();
    test_media_put_get_meta();
    test_media_put_get_chunk();
    test_media_complete_flow();
    test_media_exists();
    test_media_dedup();
    test_media_cleanup_expired();
    test_media_cleanup_incomplete();
    test_media_count_per_owner();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
