/**
 * Nodus — Media Tier 2 Protocol Tests
 *
 * Tests encode/decode roundtrips for media Client-Nodus messages.
 */

#include "protocol/nodus_tier2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST(name) do { printf("  %-50s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Buffer for protocol messages (media chunks can be large, but test data is small) */
static uint8_t msgbuf[32768];

static void test_media_put_roundtrip(void) {
    TEST("media_put encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0xAA, sizeof(token));

    uint8_t content_hash[64];
    memset(content_hash, 0xBB, sizeof(content_hash));

    const uint8_t data[] = "test media chunk data payload";
    nodus_sig_t sig;
    memset(&sig, 0xCC, sizeof(sig));

    size_t len = 0;
    int rc = nodus_t2_media_put(42, token, content_hash,
                                 0, 3, 1024000, NODUS_MEDIA_IMAGE,
                                 86400, true,
                                 data, sizeof(data) - 1, &sig,
                                 msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 42) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'q') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_put") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_token) { FAIL("has_token"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.media_hash, content_hash, 64) != 0) { FAIL("media_hash"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_idx != 0) { FAIL("chunk_idx"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_count != 3) { FAIL("chunk_count"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_total_size != 1024000) { FAIL("total_size"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_type != NODUS_MEDIA_IMAGE) { FAIL("media_type"); nodus_t2_msg_free(&msg); return; }
    if (msg.ttl != 86400) { FAIL("ttl"); nodus_t2_msg_free(&msg); return; }
    if (!msg.media_encrypted) { FAIL("encrypted"); nodus_t2_msg_free(&msg); return; }
    if (msg.data_len != sizeof(data) - 1) { FAIL("data_len"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.data, data, msg.data_len) != 0) { FAIL("data"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.sig.bytes, sig.bytes, NODUS_SIG_BYTES) != 0) { FAIL("sig"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

static void test_media_get_meta_roundtrip(void) {
    TEST("media_get_meta encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x11, sizeof(token));

    uint8_t content_hash[64];
    memset(content_hash, 0x22, sizeof(content_hash));

    size_t len = 0;
    int rc = nodus_t2_media_get_meta(10, token, content_hash,
                                      msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 10) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'q') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_meta") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_token) { FAIL("has_token"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.media_hash, content_hash, 64) != 0) { FAIL("media_hash"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

static void test_media_get_chunk_roundtrip(void) {
    TEST("media_get_chunk encode/decode");

    uint8_t token[NODUS_SESSION_TOKEN_LEN];
    memset(token, 0x33, sizeof(token));

    uint8_t content_hash[64];
    memset(content_hash, 0x44, sizeof(content_hash));

    size_t len = 0;
    int rc = nodus_t2_media_get_chunk(20, token, content_hash, 5,
                                       msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 20) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'q') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_chunk") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_token) { FAIL("has_token"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.media_hash, content_hash, 64) != 0) { FAIL("media_hash"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_idx != 5) { FAIL("chunk_idx"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

static void test_media_put_ok_roundtrip(void) {
    TEST("media_put_ok encode/decode");

    size_t len = 0;
    int rc = nodus_t2_media_put_ok(30, 2, true,
                                    msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 30) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'r') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_put_ok") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_idx != 2) { FAIL("chunk_idx"); nodus_t2_msg_free(&msg); return; }
    if (!msg.media_complete) { FAIL("complete"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

static void test_media_meta_result_roundtrip(void) {
    TEST("media_meta_result encode/decode");

    nodus_media_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    memset(meta.content_hash, 0x55, 64);
    meta.media_type = NODUS_MEDIA_VIDEO;
    meta.total_size = 4096000;
    meta.chunk_count = 2;
    meta.encrypted = true;
    meta.ttl = 604800;
    meta.complete = true;

    size_t len = 0;
    int rc = nodus_t2_media_meta_result(40, &meta,
                                         msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 40) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'r') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_meta_r") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.media_hash, meta.content_hash, 64) != 0) { FAIL("media_hash"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_type != NODUS_MEDIA_VIDEO) { FAIL("media_type"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_total_size != 4096000) { FAIL("total_size"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_count != 2) { FAIL("chunk_count"); nodus_t2_msg_free(&msg); return; }
    if (!msg.media_encrypted) { FAIL("encrypted"); nodus_t2_msg_free(&msg); return; }
    if (msg.ttl != 604800) { FAIL("ttl"); nodus_t2_msg_free(&msg); return; }
    if (!msg.media_complete) { FAIL("complete"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

static void test_media_chunk_result_roundtrip(void) {
    TEST("media_chunk_result encode/decode");

    const uint8_t chunk_data[] = "this is chunk 3 data content for testing";

    size_t len = 0;
    int rc = nodus_t2_media_chunk_result(50, 3,
                                          chunk_data, sizeof(chunk_data) - 1,
                                          msgbuf, sizeof(msgbuf), &len);
    if (rc != 0) { FAIL("encode"); return; }

    nodus_tier2_msg_t msg;
    rc = nodus_t2_decode(msgbuf, len, &msg);
    if (rc != 0) { FAIL("decode"); nodus_t2_msg_free(&msg); return; }

    if (msg.txn_id != 50) { FAIL("txn_id"); nodus_t2_msg_free(&msg); return; }
    if (msg.type != 'r') { FAIL("type"); nodus_t2_msg_free(&msg); return; }
    if (strcmp(msg.method, "m_chunk_r") != 0) { FAIL("method"); nodus_t2_msg_free(&msg); return; }
    if (!msg.has_media) { FAIL("has_media"); nodus_t2_msg_free(&msg); return; }
    if (msg.media_chunk_idx != 3) { FAIL("chunk_idx"); nodus_t2_msg_free(&msg); return; }
    if (msg.data_len != sizeof(chunk_data) - 1) { FAIL("data_len"); nodus_t2_msg_free(&msg); return; }
    if (memcmp(msg.data, chunk_data, msg.data_len) != 0) { FAIL("data"); nodus_t2_msg_free(&msg); return; }

    PASS();
    nodus_t2_msg_free(&msg);
}

int main(void) {
    printf("=== Nodus Media Tier 2 Protocol Tests ===\n\n");

    test_media_put_roundtrip();
    test_media_get_meta_roundtrip();
    test_media_get_chunk_roundtrip();
    test_media_put_ok_roundtrip();
    test_media_meta_result_roundtrip();
    test_media_chunk_result_roundtrip();

    printf("\n  Results: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
