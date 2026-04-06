/**
 * Test: Channel Crypto (Kyber1024 + AES-256-GCM)
 *
 * Real crypto operations — no mocks, no assert() (Release builds remove asserts).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/nodus_channel_crypto.h"
#include "crypto/enc/qgp_kyber.h"

extern void qgp_secure_memzero(void *ptr, size_t len);

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  TEST: %-50s ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define CHECK(expr, msg) do { if (!(expr)) { FAIL(msg); return; } } while(0)

/* ── Test 1: Basic init + roundtrip ─────────────────────────────── */
static void test_basic_roundtrip(void)
{
    TEST("basic encrypt/decrypt roundtrip");

    uint8_t shared_secret[32], nonce_c[32], nonce_s[32];
    memset(shared_secret, 0xAB, 32);
    memset(nonce_c, 0xCD, 32);
    memset(nonce_s, 0xEF, 32);

    nodus_channel_crypto_t sender, receiver;
    CHECK(nodus_channel_crypto_init(&sender, shared_secret, nonce_c, nonce_s) == 0, "sender init");
    CHECK(nodus_channel_crypto_init(&receiver, shared_secret, nonce_c, nonce_s) == 0, "receiver init");
    CHECK(sender.established, "sender not established");
    CHECK(receiver.established, "receiver not established");

    const char *msg = "Hello, post-quantum world!";
    size_t msg_len = strlen(msg);
    uint8_t encrypted[256];
    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&sender, (const uint8_t *)msg, msg_len,
                                 encrypted, sizeof(encrypted), &enc_len) == 0, "encrypt");
    CHECK(enc_len == msg_len + NODUS_CHANNEL_OVERHEAD, "wrong enc_len");

    uint8_t decrypted[256];
    size_t dec_len = 0;
    CHECK(nodus_channel_decrypt(&receiver, encrypted, enc_len,
                                 decrypted, sizeof(decrypted), &dec_len) == 0, "decrypt");
    CHECK(dec_len == msg_len, "wrong dec_len");
    CHECK(memcmp(decrypted, msg, msg_len) == 0, "plaintext mismatch");

    nodus_channel_crypto_clear(&sender);
    nodus_channel_crypto_clear(&receiver);
    PASS();
}

/* ── Test 2: Real Kyber KEM handshake ───────────────────────────── */
static void test_real_kyber_handshake(void)
{
    TEST("real Kyber1024 KEM -> channel crypto");

    uint8_t server_pk[1568], server_sk[3168];
    CHECK(qgp_kem1024_keypair(server_pk, server_sk) == 0, "keygen");

    uint8_t ct[1568], client_ss[32];
    CHECK(qgp_kem1024_encapsulate(ct, client_ss, server_pk) == 0, "encapsulate");

    uint8_t server_ss[32];
    CHECK(qgp_kem1024_decapsulate(server_ss, ct, server_sk) == 0, "decapsulate");
    CHECK(memcmp(client_ss, server_ss, 32) == 0, "shared secrets mismatch");

    uint8_t nonce_c[32], nonce_s[32];
    memset(nonce_c, 0x11, 32);
    memset(nonce_s, 0x22, 32);

    nodus_channel_crypto_t client_cc, server_cc;
    CHECK(nodus_channel_crypto_init(&client_cc, client_ss, nonce_c, nonce_s) == 0, "client init");
    CHECK(nodus_channel_crypto_init(&server_cc, server_ss, nonce_c, nonce_s) == 0, "server init");

    /* Client -> Server */
    const char *payload = "DHT GET request (encrypted)";
    size_t plen = strlen(payload);
    uint8_t enc_buf[256];
    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&client_cc, (const uint8_t *)payload, plen,
                                 enc_buf, sizeof(enc_buf), &enc_len) == 0, "client encrypt");

    uint8_t dec_buf[256];
    size_t dec_len = 0;
    CHECK(nodus_channel_decrypt(&server_cc, enc_buf, enc_len,
                                 dec_buf, sizeof(dec_buf), &dec_len) == 0, "server decrypt");
    CHECK(dec_len == plen && memcmp(dec_buf, payload, plen) == 0, "client->server mismatch");

    /* Server -> Client */
    const char *response = "DHT GET response (encrypted)";
    size_t rlen = strlen(response);
    CHECK(nodus_channel_encrypt(&server_cc, (const uint8_t *)response, rlen,
                                 enc_buf, sizeof(enc_buf), &enc_len) == 0, "server encrypt");
    CHECK(nodus_channel_decrypt(&client_cc, enc_buf, enc_len,
                                 dec_buf, sizeof(dec_buf), &dec_len) == 0, "client decrypt");
    CHECK(dec_len == rlen && memcmp(dec_buf, response, rlen) == 0, "server->client mismatch");

    nodus_channel_crypto_clear(&client_cc);
    nodus_channel_crypto_clear(&server_cc);
    PASS();
}

/* ── Test 3: Tamper detection ───────────────────────────────────── */
static void test_tamper_detection(void)
{
    TEST("tampered ciphertext detected");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x42, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t enc_cc, dec_cc;
    nodus_channel_crypto_init(&enc_cc, ss, nc, ns);
    nodus_channel_crypto_init(&dec_cc, ss, nc, ns);

    const char *msg = "sensitive data";
    uint8_t encrypted[256];
    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&enc_cc, (const uint8_t *)msg, strlen(msg),
                                 encrypted, sizeof(encrypted), &enc_len) == 0, "encrypt");

    encrypted[NODUS_CHANNEL_NONCE_LEN + 3] ^= 0xFF;

    uint8_t dec[256];
    size_t dec_len = 0;
    int rc = nodus_channel_decrypt(&dec_cc, encrypted, enc_len, dec, sizeof(dec), &dec_len);
    CHECK(rc != 0, "tampered data should fail");

    nodus_channel_crypto_clear(&enc_cc);
    nodus_channel_crypto_clear(&dec_cc);
    PASS();
}

/* ── Test 4: Wrong key ──────────────────────────────────────────── */
static void test_wrong_key(void)
{
    TEST("wrong key rejected");

    uint8_t ss1[32], ss2[32], nc[32], ns[32];
    memset(ss1, 0xAA, 32); memset(ss2, 0xBB, 32);
    memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t enc_cc, dec_cc;
    nodus_channel_crypto_init(&enc_cc, ss1, nc, ns);
    nodus_channel_crypto_init(&dec_cc, ss2, nc, ns);

    const char *msg = "secret";
    uint8_t encrypted[256];
    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&enc_cc, (const uint8_t *)msg, strlen(msg),
                                 encrypted, sizeof(encrypted), &enc_len) == 0, "encrypt");

    uint8_t dec[256];
    size_t dec_len = 0;
    CHECK(nodus_channel_decrypt(&dec_cc, encrypted, enc_len, dec, sizeof(dec), &dec_len) != 0,
          "wrong key should fail");

    nodus_channel_crypto_clear(&enc_cc);
    nodus_channel_crypto_clear(&dec_cc);
    PASS();
}

/* ── Test 5: Counter increment ──────────────────────────────────── */
static void test_counter_increment(void)
{
    TEST("tx counter increments per message");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x55, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t cc;
    nodus_channel_crypto_init(&cc, ss, nc, ns);
    CHECK(cc.tx_counter == 0, "initial counter != 0");

    uint8_t data[] = "x";
    uint8_t enc[64];
    size_t enc_len = 0;

    nodus_channel_encrypt(&cc, data, 1, enc, sizeof(enc), &enc_len);
    CHECK(cc.tx_counter == 1, "counter not 1");
    nodus_channel_encrypt(&cc, data, 1, enc, sizeof(enc), &enc_len);
    CHECK(cc.tx_counter == 2, "counter not 2");
    nodus_channel_encrypt(&cc, data, 1, enc, sizeof(enc), &enc_len);
    CHECK(cc.tx_counter == 3, "counter not 3");

    nodus_channel_crypto_clear(&cc);
    PASS();
}

/* ── Test 6: Replay protection ──────────────────────────────────── */
static void test_replay_protection(void)
{
    TEST("replay of old counter rejected");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x66, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t enc_cc, dec_cc;
    nodus_channel_crypto_init(&enc_cc, ss, nc, ns);
    nodus_channel_crypto_init(&dec_cc, ss, nc, ns);

    uint8_t msg[] = "message";
    uint8_t enc1[64], enc2[64];
    size_t len1 = 0, len2 = 0;

    CHECK(nodus_channel_encrypt(&enc_cc, msg, sizeof(msg), enc1, sizeof(enc1), &len1) == 0, "enc1");
    CHECK(nodus_channel_encrypt(&enc_cc, msg, sizeof(msg), enc2, sizeof(enc2), &len2) == 0, "enc2");

    uint8_t dec[64];
    size_t dec_len = 0;
    CHECK(nodus_channel_decrypt(&dec_cc, enc1, len1, dec, sizeof(dec), &dec_len) == 0, "dec1");
    CHECK(nodus_channel_decrypt(&dec_cc, enc2, len2, dec, sizeof(dec), &dec_len) == 0, "dec2");

    /* Replay first message */
    int rc = nodus_channel_decrypt(&dec_cc, enc1, len1, dec, sizeof(dec), &dec_len);
    CHECK(rc != 0, "replay should be rejected");

    nodus_channel_crypto_clear(&enc_cc);
    nodus_channel_crypto_clear(&dec_cc);
    PASS();
}

/* ── Test 7: Large payload ──────────────────────────────────────── */
static void test_large_payload(void)
{
    TEST("large payload (64KB)");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x77, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t enc_cc, dec_cc;
    nodus_channel_crypto_init(&enc_cc, ss, nc, ns);
    nodus_channel_crypto_init(&dec_cc, ss, nc, ns);

    size_t plen = 65536;
    uint8_t *plaintext = malloc(plen);
    uint8_t *encrypted = malloc(plen + NODUS_CHANNEL_OVERHEAD);
    uint8_t *decrypted = malloc(plen);
    CHECK(plaintext && encrypted && decrypted, "malloc");

    for (size_t i = 0; i < plen; i++)
        plaintext[i] = (uint8_t)(i & 0xFF);

    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&enc_cc, plaintext, plen,
                                 encrypted, plen + NODUS_CHANNEL_OVERHEAD, &enc_len) == 0, "encrypt");

    size_t dec_len = 0;
    int rc = nodus_channel_decrypt(&dec_cc, encrypted, enc_len, decrypted, plen, &dec_len);
    CHECK(rc == 0, "decrypt");
    CHECK(dec_len == plen, "wrong dec_len");
    CHECK(memcmp(decrypted, plaintext, plen) == 0, "data mismatch");

    free(plaintext); free(encrypted); free(decrypted);
    nodus_channel_crypto_clear(&enc_cc);
    nodus_channel_crypto_clear(&dec_cc);
    PASS();
}

/* ── Test 8: Empty payload ──────────────────────────────────────── */
static void test_empty_payload(void)
{
    TEST("empty payload (keepalive)");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x88, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t enc_cc, dec_cc;
    nodus_channel_crypto_init(&enc_cc, ss, nc, ns);
    nodus_channel_crypto_init(&dec_cc, ss, nc, ns);

    uint8_t encrypted[64];
    size_t enc_len = 0;
    CHECK(nodus_channel_encrypt(&enc_cc, (const uint8_t *)"", 0,
                                 encrypted, sizeof(encrypted), &enc_len) == 0, "encrypt empty");
    CHECK(enc_len == NODUS_CHANNEL_OVERHEAD, "wrong enc_len");

    uint8_t decrypted[1];
    size_t dec_len = 0;
    CHECK(nodus_channel_decrypt(&dec_cc, encrypted, enc_len,
                                 decrypted, sizeof(decrypted), &dec_len) == 0, "decrypt empty");
    CHECK(dec_len == 0, "dec_len should be 0");

    nodus_channel_crypto_clear(&enc_cc);
    nodus_channel_crypto_clear(&dec_cc);
    PASS();
}

/* ── Test 9: Key derivation determinism ─────────────────────────── */
static void test_key_derivation_determinism(void)
{
    TEST("same inputs -> same key");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x99, 32); memset(nc, 0xAA, 32); memset(ns, 0xBB, 32);

    nodus_channel_crypto_t cc1, cc2;
    nodus_channel_crypto_init(&cc1, ss, nc, ns);
    nodus_channel_crypto_init(&cc2, ss, nc, ns);
    CHECK(memcmp(cc1.key, cc2.key, NODUS_CHANNEL_KEY_LEN) == 0, "keys differ");

    uint8_t ns2[32];
    memset(ns2, 0xCC, 32);
    nodus_channel_crypto_t cc3;
    nodus_channel_crypto_init(&cc3, ss, nc, ns2);
    CHECK(memcmp(cc1.key, cc3.key, NODUS_CHANNEL_KEY_LEN) != 0, "diff nonces same key");

    nodus_channel_crypto_clear(&cc1);
    nodus_channel_crypto_clear(&cc2);
    nodus_channel_crypto_clear(&cc3);
    PASS();
}

/* ── Test 10: Secure clear ──────────────────────────────────────── */
static void test_secure_clear(void)
{
    TEST("clear zeros all key material");

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0xFF, 32); memset(nc, 0x01, 32); memset(ns, 0x02, 32);

    nodus_channel_crypto_t cc;
    nodus_channel_crypto_init(&cc, ss, nc, ns);
    CHECK(cc.established, "not established");

    nodus_channel_crypto_clear(&cc);

    uint8_t zero[NODUS_CHANNEL_KEY_LEN];
    memset(zero, 0, sizeof(zero));
    CHECK(!cc.established, "still established");
    CHECK(memcmp(cc.key, zero, NODUS_CHANNEL_KEY_LEN) == 0, "key not zeroed");

    PASS();
}

int main(void)
{
    printf("=== Channel Crypto Tests ===\n\n");

    test_basic_roundtrip();
    test_real_kyber_handshake();
    test_tamper_detection();
    test_wrong_key();
    test_counter_increment();
    test_replay_protection();
    test_large_payload();
    test_empty_payload();
    test_key_derivation_determinism();
    test_secure_clear();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
