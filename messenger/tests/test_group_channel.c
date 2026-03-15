/**
 * @file test_group_channel.c
 * @brief End-to-end tests for Group Channel System (Phase 2)
 *
 * Tests:
 *  1. UUID mapping: deterministic, same input → same output
 *  2. Crypto roundtrip: encrypt → decrypt → verify plaintext matches
 *  3. Crypto tamper detection: modify ciphertext → decrypt fails
 *  4. Crypto wrong GEK: decrypt with wrong key → fails
 *  5. Connector init/shutdown
 *  6. Connect/disconnect lifecycle (mocked nodus_ops)
 *  7. Double connect (idempotent)
 *  8. Send without connect → error
 *  9. Subscribe without connect → error
 *
 * All tests run offline — no network required.
 * nodus_ops channel functions are mocked.
 *
 * Part of DNA Connect - Group Channel System (Phase 2)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/* ============================================================================
 * Mock nodus_ops channel functions (no network needed)
 * ============================================================================
 * We define these before including headers so the linker picks up our mocks
 * instead of the real nodus_ops implementations.
 * ============================================================================ */

/* Minimal types needed — match nodus_types.h layout */
#ifndef NODUS_KEY_BYTES
#define NODUS_KEY_BYTES   64
#define NODUS_SIG_BYTES   4627
#define NODUS_UUID_BYTES  16
#define NODUS_PK_BYTES    2592
#define NODUS_SK_BYTES    4896
#endif

typedef struct { uint8_t bytes[NODUS_KEY_BYTES]; } nodus_key_t;
typedef struct { uint8_t bytes[NODUS_SIG_BYTES]; } nodus_sig_t;
typedef struct { uint8_t bytes[NODUS_PK_BYTES]; }  nodus_pubkey_t;
typedef struct { uint8_t bytes[NODUS_SK_BYTES]; }  nodus_seckey_t;

typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint8_t     post_uuid[NODUS_UUID_BYTES];
    nodus_key_t author_fp;
    uint64_t    timestamp;
    uint64_t    received_at;
    char       *body;
    size_t      body_len;
    nodus_sig_t signature;
} nodus_channel_post_t;

/* Mock implementations — all succeed silently */
static int mock_ch_create_calls = 0;
static int mock_ch_subscribe_calls = 0;
static int mock_ch_unsubscribe_calls = 0;

int nodus_ops_ch_create(const uint8_t channel_uuid[16]) {
    (void)channel_uuid;
    mock_ch_create_calls++;
    return 0;
}

int nodus_ops_ch_subscribe(const uint8_t channel_uuid[16]) {
    (void)channel_uuid;
    mock_ch_subscribe_calls++;
    return 0;
}

int nodus_ops_ch_unsubscribe(const uint8_t channel_uuid[16]) {
    (void)channel_uuid;
    mock_ch_unsubscribe_calls++;
    return 0;
}

int nodus_ops_ch_post(const uint8_t channel_uuid[16],
                      const uint8_t post_uuid[16],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint64_t *received_at_out) {
    (void)channel_uuid; (void)post_uuid; (void)body; (void)body_len;
    (void)timestamp; (void)sig;
    if (received_at_out) *received_at_out = 12345;
    return 0;
}

int nodus_ops_ch_get_posts(const uint8_t channel_uuid[16],
                            uint64_t since, int max_count,
                            nodus_channel_post_t **posts_out,
                            size_t *count_out) {
    (void)channel_uuid; (void)since; (void)max_count;
    if (posts_out) *posts_out = NULL;
    if (count_out) *count_out = 0;
    return 0;
}

/* Mock gek_get_active_key — returns a fixed test key */
static uint8_t g_mock_gek[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};

int gek_get_active_key(const char *group_uuid, uint8_t *gek_out, uint32_t *version_out) {
    (void)group_uuid;
    memcpy(gek_out, g_mock_gek, 32);
    if (version_out) *version_out = 1;
    return 0;
}

/* Mock dna_engine identity functions */
static char g_mock_fingerprint[129];
static uint8_t *g_mock_sign_sk = NULL;

const char *dna_engine_get_fingerprint(void *engine) {
    (void)engine;
    return g_mock_fingerprint;
}

const uint8_t *dna_engine_get_sign_sk(void *engine) {
    (void)engine;
    return g_mock_sign_sk;
}

/* Now include the actual headers */
#include "dht/client/dna_group_channel.h"
#include "dht/client/dna_group_channel_crypto.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"
#include "messenger/gek.h"

/* ============================================================================
 * Test helpers
 * ============================================================================ */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) \
    do { printf("  Test: %-50s ", name); fflush(stdout); } while(0)

#define TEST_PASS() \
    do { printf("[PASS]\n"); tests_passed++; } while(0)

#define TEST_FAIL(msg) \
    do { printf("[FAIL] %s\n", msg); tests_failed++; } while(0)

#define ASSERT_EQ(a, b, msg) \
    do { if ((a) != (b)) { TEST_FAIL(msg); return; } } while(0)

#define ASSERT_NEQ(a, b, msg) \
    do { if ((a) == (b)) { TEST_FAIL(msg); return; } } while(0)

#define ASSERT_MEM_EQ(a, b, len, msg) \
    do { if (memcmp((a), (b), (len)) != 0) { TEST_FAIL(msg); return; } } while(0)

/* Generate a fake 128-char hex fingerprint */
static void make_fake_fingerprint(const char *seed, char fp_out[129]) {
    uint8_t hash[64];
    qgp_sha3_512((const uint8_t *)seed, strlen(seed), hash);
    for (int i = 0; i < 64; i++)
        snprintf(fp_out + i * 2, 3, "%02x", hash[i]);
    fp_out[128] = '\0';
}

/* ============================================================================
 * Test 1: UUID Mapping — deterministic
 * ============================================================================ */
static void test_uuid_mapping_deterministic(void) {
    TEST_START("UUID mapping: deterministic");

    const char *group_uuid = "550e8400-e29b-41d4-a716-446655440000";
    uint8_t ch_uuid1[16], ch_uuid2[16];

    int rc1 = dna_group_channel_uuid(group_uuid, ch_uuid1);
    int rc2 = dna_group_channel_uuid(group_uuid, ch_uuid2);

    ASSERT_EQ(rc1, 0, "first call failed");
    ASSERT_EQ(rc2, 0, "second call failed");
    ASSERT_MEM_EQ(ch_uuid1, ch_uuid2, 16, "same input produced different UUIDs");

    TEST_PASS();
}

/* Different input → different output */
static void test_uuid_mapping_different_input(void) {
    TEST_START("UUID mapping: different input → different output");

    uint8_t ch_uuid1[16], ch_uuid2[16];

    int rc1 = dna_group_channel_uuid("550e8400-e29b-41d4-a716-446655440000", ch_uuid1);
    int rc2 = dna_group_channel_uuid("660e8400-e29b-41d4-a716-446655440000", ch_uuid2);

    ASSERT_EQ(rc1, 0, "first call failed");
    ASSERT_EQ(rc2, 0, "second call failed");
    ASSERT_NEQ(memcmp(ch_uuid1, ch_uuid2, 16), 0, "different inputs produced same UUID");

    TEST_PASS();
}

/* NULL input → error */
static void test_uuid_mapping_null(void) {
    TEST_START("UUID mapping: NULL input → error");

    uint8_t ch_uuid[16];
    int rc = dna_group_channel_uuid(NULL, ch_uuid);
    ASSERT_EQ(rc, -1, "should fail with NULL");

    rc = dna_group_channel_uuid("test", NULL);
    ASSERT_EQ(rc, -1, "should fail with NULL output");

    TEST_PASS();
}

/* ============================================================================
 * Test 2: Crypto roundtrip
 * ============================================================================ */
static void test_crypto_roundtrip(void) {
    TEST_START("Crypto roundtrip: encrypt → decrypt → match");

    /* Generate Dilithium5 keypair */
    uint8_t *pk = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    assert(pk && sk);
    int rc = qgp_dsa87_keypair(pk, sk);
    ASSERT_EQ(rc, 0, "keypair gen failed");

    /* Sender fingerprint */
    char sender_fp[129];
    qgp_sha3_512_fingerprint(pk, QGP_DSA87_PUBLICKEYBYTES, sender_fp);

    /* GEK */
    uint8_t gek[GEK_KEY_SIZE];
    qgp_randombytes(gek, GEK_KEY_SIZE);

    const char *group_uuid = "550e8400-e29b-41d4-a716-446655440000";
    const uint8_t plaintext[] = "Hello, group channel!";
    size_t plaintext_len = sizeof(plaintext) - 1;

    /* Encrypt */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    rc = dna_group_channel_encrypt(group_uuid, plaintext, plaintext_len,
                                    gek, 1, sender_fp, sk,
                                    &blob, &blob_len);
    ASSERT_EQ(rc, DNA_GCH_OK, "encrypt failed");
    assert(blob != NULL);
    assert(blob_len > 0);

    /* Decrypt */
    char dec_sender_fp[129] = {0};
    uint64_t dec_timestamp = 0;
    uint8_t *dec_plaintext = NULL;
    size_t dec_plaintext_len = 0;

    rc = dna_group_channel_decrypt(blob, blob_len, gek, pk,
                                    dec_sender_fp, &dec_timestamp,
                                    &dec_plaintext, &dec_plaintext_len);
    ASSERT_EQ(rc, DNA_GCH_OK, "decrypt failed");
    ASSERT_EQ(dec_plaintext_len, plaintext_len, "plaintext length mismatch");
    ASSERT_MEM_EQ(dec_plaintext, plaintext, plaintext_len, "plaintext content mismatch");
    ASSERT_EQ(strcmp(sender_fp, dec_sender_fp), 0, "sender fingerprint mismatch");
    ASSERT_NEQ(dec_timestamp, (uint64_t)0, "timestamp should be non-zero");

    free(blob);
    free(dec_plaintext);
    free(pk);
    free(sk);

    TEST_PASS();
}

/* ============================================================================
 * Test 3: Crypto tamper detection
 * ============================================================================ */
static void test_crypto_tamper_detection(void) {
    TEST_START("Crypto tamper: modified ciphertext → decrypt fails");

    uint8_t *pk = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    assert(pk && sk);
    qgp_dsa87_keypair(pk, sk);

    char sender_fp[129];
    qgp_sha3_512_fingerprint(pk, QGP_DSA87_PUBLICKEYBYTES, sender_fp);

    uint8_t gek[GEK_KEY_SIZE];
    qgp_randombytes(gek, GEK_KEY_SIZE);

    const uint8_t plaintext[] = "Tamper test message";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = dna_group_channel_encrypt("test-uuid-tamper-01234567890",
                                        plaintext, plaintext_len,
                                        gek, 1, sender_fp, sk,
                                        &blob, &blob_len);
    ASSERT_EQ(rc, DNA_GCH_OK, "encrypt failed");

    /* Tamper with ciphertext (after header, before signature) */
    size_t tamper_offset = DNA_GCH_HEADER_SIZE + 2; /* inside ciphertext */
    if (tamper_offset < blob_len - DNA_GCH_SIG_SIZE) {
        blob[tamper_offset] ^= 0xFF;
    }

    /* Decrypt should fail — either sig verify or AES-GCM auth fails */
    uint8_t *dec_pt = NULL;
    size_t dec_pt_len = 0;
    char dec_fp[129];
    uint64_t dec_ts;

    rc = dna_group_channel_decrypt(blob, blob_len, gek, pk,
                                    dec_fp, &dec_ts, &dec_pt, &dec_pt_len);
    /* With signature verification (pk != NULL), signature check should fail */
    ASSERT_NEQ(rc, DNA_GCH_OK, "tampered blob should fail decrypt");

    free(blob);
    free(dec_pt); /* might be NULL, free(NULL) is safe */
    free(pk);
    free(sk);

    TEST_PASS();
}

/* ============================================================================
 * Test 4: Crypto wrong GEK
 * ============================================================================ */
static void test_crypto_wrong_gek(void) {
    TEST_START("Crypto wrong GEK: decrypt with wrong key → fails");

    uint8_t *pk = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    assert(pk && sk);
    qgp_dsa87_keypair(pk, sk);

    char sender_fp[129];
    qgp_sha3_512_fingerprint(pk, QGP_DSA87_PUBLICKEYBYTES, sender_fp);

    uint8_t gek_correct[GEK_KEY_SIZE];
    uint8_t gek_wrong[GEK_KEY_SIZE];
    qgp_randombytes(gek_correct, GEK_KEY_SIZE);
    qgp_randombytes(gek_wrong, GEK_KEY_SIZE);

    /* Make sure they're actually different */
    gek_wrong[0] ^= 0xFF;

    const uint8_t plaintext[] = "Wrong key test";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = dna_group_channel_encrypt("test-uuid-wrongkey-1234567890",
                                        plaintext, plaintext_len,
                                        gek_correct, 1, sender_fp, sk,
                                        &blob, &blob_len);
    ASSERT_EQ(rc, DNA_GCH_OK, "encrypt failed");

    /* Decrypt with wrong GEK — skip sig verify (pk=NULL) to isolate AES failure */
    uint8_t *dec_pt = NULL;
    size_t dec_pt_len = 0;
    char dec_fp[129];
    uint64_t dec_ts;

    rc = dna_group_channel_decrypt(blob, blob_len, gek_wrong, NULL,
                                    dec_fp, &dec_ts, &dec_pt, &dec_pt_len);
    ASSERT_NEQ(rc, DNA_GCH_OK, "wrong GEK should fail decrypt");

    free(blob);
    free(dec_pt);
    free(pk);
    free(sk);

    TEST_PASS();
}

/* ============================================================================
 * Test 5: Connector init/shutdown
 * ============================================================================ */
static void test_connector_init_shutdown(void) {
    TEST_START("Connector init/shutdown");

    int rc = dna_group_channel_init();
    ASSERT_EQ(rc, 0, "init failed");

    /* Double init should be idempotent */
    rc = dna_group_channel_init();
    ASSERT_EQ(rc, 0, "double init should succeed");

    dna_group_channel_shutdown();

    /* Init again after shutdown should work */
    rc = dna_group_channel_init();
    ASSERT_EQ(rc, 0, "re-init after shutdown failed");

    dna_group_channel_shutdown();

    TEST_PASS();
}

/* ============================================================================
 * Test 6: Connect/disconnect lifecycle
 * ============================================================================ */
static void test_connect_disconnect_lifecycle(void) {
    TEST_START("Connect/disconnect lifecycle");

    dna_group_channel_init();

    const char *group_uuid = "lifecycle-test-uuid-abcdef123456";

    mock_ch_create_calls = 0;

    int rc = dna_group_channel_connect(NULL, group_uuid);
    ASSERT_EQ(rc, DNA_GROUP_CH_OK, "connect failed");
    ASSERT_EQ(mock_ch_create_calls, 1, "should call ch_create once");

    /* Verify connected */
    int connected = dna_group_channel_is_connected(group_uuid);
    ASSERT_EQ(connected, 1, "should be connected");

    /* Disconnect */
    rc = dna_group_channel_disconnect(NULL, group_uuid);
    ASSERT_EQ(rc, DNA_GROUP_CH_OK, "disconnect failed");

    connected = dna_group_channel_is_connected(group_uuid);
    ASSERT_EQ(connected, 0, "should be disconnected");

    dna_group_channel_shutdown();

    TEST_PASS();
}

/* ============================================================================
 * Test 7: Double connect (idempotent)
 * ============================================================================ */
static void test_double_connect_idempotent(void) {
    TEST_START("Double connect: idempotent");

    dna_group_channel_init();

    const char *group_uuid = "double-connect-test-abcdef123456";

    mock_ch_create_calls = 0;

    int rc1 = dna_group_channel_connect(NULL, group_uuid);
    int rc2 = dna_group_channel_connect(NULL, group_uuid);

    ASSERT_EQ(rc1, DNA_GROUP_CH_OK, "first connect failed");
    ASSERT_EQ(rc2, DNA_GROUP_CH_OK, "second connect should succeed (idempotent)");

    /* ch_create should only be called once (second connect sees already-connected) */
    ASSERT_EQ(mock_ch_create_calls, 1, "ch_create should be called only once");

    dna_group_channel_shutdown();

    TEST_PASS();
}

/* ============================================================================
 * Test 8: Send without connect → error
 * ============================================================================ */
static void test_send_without_connect(void) {
    TEST_START("Send without connect → error");

    dna_group_channel_init();

    /* Set up mock identity */
    make_fake_fingerprint("test-sender", g_mock_fingerprint);
    /* We need a real sk for the mock, but it won't matter since send
     * should fail at the "not connected" check before reaching crypto */
    uint8_t dummy_sk[QGP_DSA87_SECRETKEYBYTES];
    memset(dummy_sk, 0, sizeof(dummy_sk));
    g_mock_sign_sk = dummy_sk;

    const uint8_t msg[] = "should not send";
    int dummy_engine = 42;

    int rc = dna_group_channel_send(&dummy_engine,
                                     "not-connected-uuid-1234567890ab",
                                     msg, sizeof(msg) - 1);
    ASSERT_NEQ(rc, DNA_GROUP_CH_OK, "send without connect should fail");

    g_mock_sign_sk = NULL;
    dna_group_channel_shutdown();

    TEST_PASS();
}

/* ============================================================================
 * Test 9: Subscribe without connect → error
 * ============================================================================ */
static void test_subscribe_without_connect(void) {
    TEST_START("Subscribe without connect → error");

    dna_group_channel_init();

    int rc = dna_group_channel_subscribe(NULL,
                                          "not-connected-uuid-abcdef123456");
    ASSERT_NEQ(rc, DNA_GROUP_CH_OK, "subscribe without connect should fail");

    dna_group_channel_shutdown();

    TEST_PASS();
}

/* ============================================================================
 * Test: Peek metadata extraction
 * ============================================================================ */
static void test_crypto_peek(void) {
    TEST_START("Crypto peek: extract metadata without decrypt");

    uint8_t *pk = malloc(QGP_DSA87_PUBLICKEYBYTES);
    uint8_t *sk = malloc(QGP_DSA87_SECRETKEYBYTES);
    assert(pk && sk);
    qgp_dsa87_keypair(pk, sk);

    char sender_fp[129];
    qgp_sha3_512_fingerprint(pk, QGP_DSA87_PUBLICKEYBYTES, sender_fp);

    uint8_t gek[GEK_KEY_SIZE];
    qgp_randombytes(gek, GEK_KEY_SIZE);

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    const uint8_t pt[] = "peek test";

    int rc = dna_group_channel_encrypt("peek-test-uuid-123456789012",
                                        pt, sizeof(pt) - 1,
                                        gek, 42, sender_fp, sk,
                                        &blob, &blob_len);
    ASSERT_EQ(rc, DNA_GCH_OK, "encrypt failed");

    uint32_t gek_ver = 0;
    char peek_fp[129] = {0};
    uint64_t peek_ts = 0;

    rc = dna_group_channel_peek(blob, blob_len, &gek_ver, peek_fp, &peek_ts);
    ASSERT_EQ(rc, DNA_GCH_OK, "peek failed");
    ASSERT_EQ(gek_ver, (uint32_t)42, "GEK version mismatch");
    ASSERT_EQ(strcmp(sender_fp, peek_fp), 0, "peek fingerprint mismatch");
    ASSERT_NEQ(peek_ts, (uint64_t)0, "peek timestamp should be non-zero");

    free(blob);
    free(pk);
    free(sk);

    TEST_PASS();
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main(void) {
    printf("\n=== Group Channel Tests (Phase 2) ===\n\n");

    printf("[UUID Mapping]\n");
    test_uuid_mapping_deterministic();
    test_uuid_mapping_different_input();
    test_uuid_mapping_null();

    printf("\n[Crypto]\n");
    test_crypto_roundtrip();
    test_crypto_tamper_detection();
    test_crypto_wrong_gek();
    test_crypto_peek();

    printf("\n[Connector]\n");
    test_connector_init_shutdown();
    test_connect_disconnect_lifecycle();
    test_double_connect_idempotent();
    test_send_without_connect();
    test_subscribe_without_connect();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
