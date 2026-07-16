/**
 * Test: AEAD completeness boundary (CRIT-3)
 *
 * Pins the boundary the CRIT-3 fix depends on: once a channel is established,
 * EVERY frame must go through nodus_channel_decrypt — never a raw/unauthenticated
 * dispatch. The gate is therefore:
 *
 *     payload_len >= NODUS_CHANNEL_OVERHEAD  -> decrypt   (28 B == valid EMPTY AEAD frame)
 *     payload_len <  NODUS_CHANNEL_OVERHEAD  -> fail-closed drop
 *
 * The old code used a strict '>' gate, so a <=28-byte payload skipped the decrypt
 * block entirely and was dispatched RAW (nodus_tcp.c:327 -> :364; circuit copy
 * nodus_client.c:389 -> :403), with rx_counter untouched (indefinitely replayable).
 *
 * These tests prove:
 *   1. an empty-plaintext frame really is exactly OVERHEAD (28) bytes,
 *   2. decrypt ACCEPTS it and yields 0-byte plaintext  -> '>=' is the correct
 *      boundary and a naive "drop <=28" would break legitimate empty frames,
 *   3. decrypt REJECTS anything shorter                -> '<28' is safe to drop,
 *   4. decrypt rejects a tampered/garbage frame of valid length (fail-closed),
 *   5. an unestablished channel never decrypts.
 *
 * Real crypto operations — no mocks, no assert() (Release builds remove asserts).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/nodus_channel_crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  TEST: %-50s ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define CHECK(expr, msg) do { if (!(expr)) { FAIL(msg); return; } } while(0)

static void init_pair(nodus_channel_crypto_t *tx, nodus_channel_crypto_t *rx)
{
    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0x11, sizeof(ss));
    memset(nc, 0x22, sizeof(nc));
    memset(ns, 0x33, sizeof(ns));
    nodus_channel_crypto_init(tx, ss, nc, ns);
    nodus_channel_crypto_init(rx, ss, nc, ns);
}

/* ── Test 1: an empty-plaintext frame is exactly OVERHEAD bytes ──────────── */
static void test_empty_frame_is_overhead_bytes(void)
{
    TEST("empty plaintext encrypts to exactly OVERHEAD bytes");

    nodus_channel_crypto_t tx, rx;
    init_pair(&tx, &rx);

    uint8_t out[64];
    size_t out_len = 0;
    CHECK(nodus_channel_encrypt(&tx, NULL, 0, out, sizeof(out), &out_len) == 0,
          "encrypt(len=0) failed");
    CHECK(out_len == NODUS_CHANNEL_OVERHEAD, "empty frame != NODUS_CHANNEL_OVERHEAD");
    CHECK(out_len == 28, "NODUS_CHANNEL_OVERHEAD is not 28 (nonce12+tag16)");
    PASS();
}

/* ── Test 2: decrypt ACCEPTS the 28-byte empty frame (the '>=' boundary) ─── */
static void test_28_byte_frame_decrypts(void)
{
    TEST("28-byte empty AEAD frame decrypts to 0-byte plaintext");

    nodus_channel_crypto_t tx, rx;
    init_pair(&tx, &rx);

    uint8_t frame[64];
    size_t frame_len = 0;
    CHECK(nodus_channel_encrypt(&tx, NULL, 0, frame, sizeof(frame), &frame_len) == 0,
          "encrypt(len=0) failed");
    CHECK(frame_len == 28, "not a 28-byte frame");

    /* out_cap may legitimately be 0-sized for an empty frame; pass a 1-byte
     * scratch the way the production callers do (malloc(pt_cap ? pt_cap : 1)). */
    uint8_t pt[1];
    size_t pt_len = 12345;
    CHECK(nodus_channel_decrypt(&rx, frame, frame_len, pt, 0, &pt_len) == 0,
          "28-byte empty frame REJECTED — '>=' boundary is wrong, "
          "a 'drop <=28' rule would break legitimate empty frames");
    CHECK(pt_len == 0, "empty frame did not yield 0-byte plaintext");
    PASS();
}

/* ── Test 3: decrypt REJECTS anything below OVERHEAD ('<28' is safe to drop) */
static void test_short_frames_rejected(void)
{
    TEST("frames shorter than OVERHEAD are rejected");

    nodus_channel_crypto_t tx, rx;
    init_pair(&tx, &rx);

    uint8_t pt[64];
    size_t pt_len = 0;

    /* 27 bytes: one below the boundary — the CRIT-3 injection size class. */
    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));
    CHECK(nodus_channel_decrypt(&rx, buf, 27, pt, sizeof(pt), &pt_len) != 0,
          "27-byte frame accepted");

    /* A minimal CBOR T2 query fits in ~20 bytes — the concrete CRIT-3 payload. */
    CHECK(nodus_channel_decrypt(&rx, buf, 20, pt, sizeof(pt), &pt_len) != 0,
          "20-byte frame accepted");
    CHECK(nodus_channel_decrypt(&rx, buf, 1, pt, sizeof(pt), &pt_len) != 0,
          "1-byte frame accepted");
    CHECK(nodus_channel_decrypt(&rx, buf, 0, pt, sizeof(pt), &pt_len) != 0,
          "0-byte frame accepted");
    PASS();
}

/* ── Test 4: a valid-length garbage frame fails closed (no raw fallthrough) ─ */
static void test_garbage_valid_length_rejected(void)
{
    TEST("garbage frame of valid length fails closed");

    nodus_channel_crypto_t tx, rx;
    init_pair(&tx, &rx);

    /* 28+ bytes of attacker garbage: passes the length gate, must fail AEAD. */
    uint8_t buf[64];
    memset(buf, 0x5A, sizeof(buf));
    uint8_t pt[64];
    size_t pt_len = 0;
    CHECK(nodus_channel_decrypt(&rx, buf, 40, pt, sizeof(pt), &pt_len) != 0,
          "garbage frame accepted — AEAD not enforced");
    PASS();
}

/* ── Test 5: tampered ciphertext fails closed ───────────────────────────── */
static void test_tampered_frame_rejected(void)
{
    TEST("tampered frame fails closed");

    nodus_channel_crypto_t tx, rx;
    init_pair(&tx, &rx);

    const char *msg = "media frame";
    uint8_t frame[128];
    size_t frame_len = 0;
    CHECK(nodus_channel_encrypt(&tx, (const uint8_t *)msg, strlen(msg),
                                frame, sizeof(frame), &frame_len) == 0, "encrypt failed");
    frame[NODUS_CHANNEL_NONCE_LEN] ^= 0x01;   /* flip a ciphertext bit */

    uint8_t pt[128];
    size_t pt_len = 0;
    CHECK(nodus_channel_decrypt(&rx, frame, frame_len, pt, sizeof(pt), &pt_len) != 0,
          "tampered frame accepted");
    PASS();
}

/* ── Test 6: unestablished channel never decrypts ───────────────────────── */
static void test_unestablished_rejects(void)
{
    TEST("unestablished channel never decrypts");

    nodus_channel_crypto_t rx;
    memset(&rx, 0, sizeof(rx));   /* established == false */

    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));
    uint8_t pt[64];
    size_t pt_len = 0;
    CHECK(nodus_channel_decrypt(&rx, buf, 40, pt, sizeof(pt), &pt_len) != 0,
          "unestablished channel decrypted");
    PASS();
}

int main(void)
{
    printf("\n=== AEAD Completeness Boundary (CRIT-3) ===\n\n");

    test_empty_frame_is_overhead_bytes();
    test_28_byte_frame_decrypts();
    test_short_frames_rejected();
    test_garbage_valid_length_rejected();
    test_tampered_frame_rejected();
    test_unestablished_rejects();

    printf("\n  Passed: %d, Failed: %d\n\n", tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
