/**
 * Test: Per-Connection Channel Crypto Storage Isolation (B3 fix)
 *
 * Regression test for the production-observed "Replay detected:
 * counter=N < expected=M" loop where multiple TCP conns aliased the
 * same nodus_channel_crypto_t struct via the legacy `void *crypto`
 * field on `nodus_tcp_conn_t`. After B3, each conn owns its
 * channel_crypto inline — pointer aliasing is structurally impossible.
 *
 * This test asserts the B3 invariants directly:
 *   1. Two conns have separate channel_crypto storage addresses.
 *   2. Initing one does not affect the other's keys/counters.
 *   3. Encrypting on one advances ONLY its own tx_counter.
 *   4. Clearing one (simulating conn_free) leaves the other intact.
 *   5. A freshly zeroed conn (simulating conn_alloc) starts with
 *      established=false and zero counters — no leak from previous
 *      conn that occupied any nearby memory.
 *
 * Real crypto operations — no mocks. Uses nodus_tcp_conn_t directly
 * (zero-init via memset) since this test is about layout invariants,
 * not the full TCP socket lifecycle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport/nodus_tcp.h"
#include "crypto/nodus_channel_crypto.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  TEST: %-60s ", name); } while(0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define CHECK(expr, msg) do { if (!(expr)) { FAIL(msg); return; } } while(0)

/** C1: rx_counter is per-role now — a clean instance has every slot at zero. */
static bool rx_counters_all_zero(const nodus_channel_crypto_t *cc)
{
    for (int r = 0; r < NODUS_CHANNEL_ROLE_COUNT; r++)
        if (cc->rx_counter[r] != 0) return false;
    return true;
}

/* ── Test 1: separate storage addresses ─────────────────────────── */
static void test_separate_storage(void)
{
    TEST("two conns have separate channel_crypto addresses");

    nodus_tcp_conn_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));

    /* Layout invariant: distinct conns → distinct cc addresses.
     * Pre-B3 this was sometimes equal (slot recycle aliasing). */
    CHECK(&c1.channel_crypto != &c2.channel_crypto,
          "channel_crypto addresses must differ");

    /* Zero-init invariant: established=false, counters=0 on fresh conn. */
    CHECK(c1.channel_crypto.established == false, "c1 not zero-init established");
    CHECK(c2.channel_crypto.established == false, "c2 not zero-init established");
    CHECK(c1.channel_crypto.tx_counter == 0, "c1 tx_counter not zero");
    /* C1: rx_counter is now per-role — every slot must start clean. */
    CHECK(rx_counters_all_zero(&c1.channel_crypto), "c1 rx_counter not zero");
    CHECK(c2.channel_crypto.tx_counter == 0, "c2 tx_counter not zero");
    CHECK(rx_counters_all_zero(&c2.channel_crypto), "c2 rx_counter not zero");

    PASS();
}

/* ── Test 2: independent init ────────────────────────────────────── */
static void test_independent_init(void)
{
    TEST("init on one conn does not affect the other");

    nodus_tcp_conn_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));

    uint8_t ss1[32], ss2[32], nc[32], ns[32];
    memset(ss1, 0xAA, 32);
    memset(ss2, 0xBB, 32);
    memset(nc, 0x11, 32);
    memset(ns, 0x22, 32);

    /* Init c1 only. */
    CHECK(nodus_channel_crypto_init(&c1.channel_crypto, ss1, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0,
          "c1 init failed");
    CHECK(c1.channel_crypto.established == true, "c1 not established post-init");
    CHECK(c2.channel_crypto.established == false,
          "c2 unexpectedly established (should be untouched)");

    /* Now init c2 with a different shared secret. */
    CHECK(nodus_channel_crypto_init(&c2.channel_crypto, ss2, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0,
          "c2 init failed");
    CHECK(c2.channel_crypto.established == true, "c2 not established post-init");

    /* Different shared secrets → different derived keys. */
    CHECK(memcmp(c1.channel_crypto.key, c2.channel_crypto.key,
                 sizeof(c1.channel_crypto.key)) != 0,
          "c1 and c2 derived the same AES key (storage aliasing?)");

    PASS();
}

/* ── Test 3: counters advance independently ─────────────────────── */
static void test_independent_counters(void)
{
    TEST("encrypt on one conn advances only its own tx_counter");

    nodus_tcp_conn_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));

    uint8_t ss1[32], ss2[32], nc[32], ns[32];
    memset(ss1, 0xAA, 32);
    memset(ss2, 0xBB, 32);
    memset(nc, 0x11, 32);
    memset(ns, 0x22, 32);

    CHECK(nodus_channel_crypto_init(&c1.channel_crypto, ss1, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "c1 init");
    CHECK(nodus_channel_crypto_init(&c2.channel_crypto, ss2, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "c2 init");

    uint8_t pt[32];
    memset(pt, 0xCC, sizeof(pt));
    uint8_t ct1[64], ct2[64];
    size_t ct1_len = 0, ct2_len = 0;

    /* Encrypt on c1 — only c1.tx_counter should advance. */
    CHECK(nodus_channel_encrypt(&c1.channel_crypto, pt, sizeof(pt),
                                  ct1, sizeof(ct1), &ct1_len) == 0,
          "c1 encrypt failed");
    CHECK(c1.channel_crypto.tx_counter == 1, "c1 tx_counter not advanced to 1");
    CHECK(c2.channel_crypto.tx_counter == 0,
          "c2 tx_counter unexpectedly advanced (storage aliasing?)");

    /* Encrypt on c2 — only c2.tx_counter should advance. */
    CHECK(nodus_channel_encrypt(&c2.channel_crypto, pt, sizeof(pt),
                                  ct2, sizeof(ct2), &ct2_len) == 0,
          "c2 encrypt failed");
    CHECK(c2.channel_crypto.tx_counter == 1, "c2 tx_counter not advanced to 1");
    CHECK(c1.channel_crypto.tx_counter == 1,
          "c1 tx_counter changed when encrypting on c2");

    /* Different keys → different ciphertexts for same plaintext. */
    CHECK(ct1_len == ct2_len, "ciphertext lengths differ");
    CHECK(memcmp(ct1, ct2, ct1_len) != 0,
          "c1 and c2 produced same ciphertext (key aliasing?)");

    PASS();
}

/* ── Test 4: clear isolation ────────────────────────────────────── */
static void test_clear_isolation(void)
{
    TEST("clearing one conn does not affect the other (conn_free path)");

    nodus_tcp_conn_t c1, c2;
    memset(&c1, 0, sizeof(c1));
    memset(&c2, 0, sizeof(c2));

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0xAA, 32);
    memset(nc, 0x11, 32);
    memset(ns, 0x22, 32);

    CHECK(nodus_channel_crypto_init(&c1.channel_crypto, ss, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "c1 init");
    CHECK(nodus_channel_crypto_init(&c2.channel_crypto, ss, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "c2 init");

    /* Both established. */
    CHECK(c1.channel_crypto.established == true, "c1 pre-clear");
    CHECK(c2.channel_crypto.established == true, "c2 pre-clear");

    /* Advance c2 a few frames so we can detect spurious resets later. */
    uint8_t pt[8] = {0};
    uint8_t ct[64];
    size_t ct_len = 0;
    for (int i = 0; i < 3; i++) {
        CHECK(nodus_channel_encrypt(&c2.channel_crypto, pt, sizeof(pt),
                                      ct, sizeof(ct), &ct_len) == 0,
              "c2 encrypt advance");
    }
    CHECK(c2.channel_crypto.tx_counter == 3, "c2 tx_counter not at 3");

    /* Clear c1 (simulating conn_free path on disconnect). */
    nodus_channel_crypto_clear(&c1.channel_crypto);
    CHECK(c1.channel_crypto.established == false, "c1 still established post-clear");
    CHECK(c1.channel_crypto.tx_counter == 0, "c1 tx_counter not zero post-clear");

    /* c2 must remain unaffected — different storage. */
    CHECK(c2.channel_crypto.established == true,
          "c2 became unestablished when c1 was cleared (alias bug)");
    CHECK(c2.channel_crypto.tx_counter == 3,
          "c2 tx_counter reset when c1 was cleared (alias bug)");

    PASS();
}

/* ── Test 5: fresh conn after recycle ───────────────────────────── */
static void test_recycle_no_leak(void)
{
    TEST("freshly zeroed conn has no state leak from previous use");

    nodus_tcp_conn_t c1;
    memset(&c1, 0, sizeof(c1));

    uint8_t ss[32], nc[32], ns[32];
    memset(ss, 0xAA, 32);
    memset(nc, 0x11, 32);
    memset(ns, 0x22, 32);

    /* Use c1, advance it, then clear (simulating conn_free). */
    CHECK(nodus_channel_crypto_init(&c1.channel_crypto, ss, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "c1 init");
    uint8_t pt[8] = {0}, ct[64];
    size_t ct_len = 0;
    for (int i = 0; i < 5; i++) {
        CHECK(nodus_channel_encrypt(&c1.channel_crypto, pt, sizeof(pt),
                                      ct, sizeof(ct), &ct_len) == 0, "encrypt");
    }
    CHECK(c1.channel_crypto.tx_counter == 5, "tx_counter not at 5");
    nodus_channel_crypto_clear(&c1.channel_crypto);

    /* "Recycle" same memory by re-zeroing (simulating fresh conn_alloc
     * in production: calloc gives all-zero conn struct including
     * embedded channel_crypto). */
    memset(&c1, 0, sizeof(c1));

    /* Pre-init invariants on the recycled struct: no leftover state. */
    CHECK(c1.channel_crypto.established == false, "recycle established leak");
    CHECK(c1.channel_crypto.tx_counter == 0, "recycle tx_counter leak");
    CHECK(rx_counters_all_zero(&c1.channel_crypto), "recycle rx_counter leak");

    /* New init on the recycled struct should produce a fresh session
     * with counter=0 — exactly the path that pre-B3 was racing on. */
    uint8_t ss2[32];
    memset(ss2, 0xCC, 32);
    CHECK(nodus_channel_crypto_init(&c1.channel_crypto, ss2, nc, ns,
                                     NODUS_CHANNEL_ROLE_INITIATOR) == 0, "recycle init");
    CHECK(c1.channel_crypto.tx_counter == 0, "post-recycle counter not zero");
    CHECK(c1.channel_crypto.established == true, "post-recycle not established");

    PASS();
}

/* ── Main ────────────────────────────────────────────────────────── */
int main(void)
{
    printf("Running B3 per-conn channel_crypto isolation tests\n");

    test_separate_storage();
    test_independent_init();
    test_independent_counters();
    test_clear_isolation();
    test_recycle_no_leak();

    printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
