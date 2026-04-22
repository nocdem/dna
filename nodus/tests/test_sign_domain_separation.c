/**
 * Nodus — Domain Separation Sign/Verify Tests (C2 fix)
 *
 * Verifies that signatures produced under one purpose byte cannot be relayed
 * against verifiers expecting a different purpose — closes the Dilithium5
 * signing oracle vulnerability at the challenge handler.
 */

#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Generate a keypair into global-ish state for test reuse. */
static nodus_pubkey_t g_pk;
static nodus_seckey_t g_sk;

static int setup_keypair(void) {
    /* qgp_dsa87_keypair expects raw buffers of the right sizes. */
    return qgp_dsa87_keypair(g_pk.bytes, g_sk.bytes);
}

/* ── Positive test: sign under X, verify under X → pass ───────────── */

static void test_auth_challenge_roundtrip(void) {
    TEST("auth_challenge sign+verify roundtrip");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    if (nodus_sign_auth_challenge(&sig, nonce, &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_auth_challenge(&sig, nonce, &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_kyber_bind_roundtrip(void) {
    TEST("kyber_bind sign+verify roundtrip");
    uint8_t data[1600];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_kyber_bind(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_kyber_bind(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_t3_envelope_roundtrip(void) {
    TEST("t3_envelope sign+verify roundtrip");
    uint8_t data[256];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_t3_envelope(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_t3_envelope(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_value_store_roundtrip(void) {
    TEST("value_store sign+verify roundtrip");
    uint8_t data[512];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_value_store(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_value_store(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_cert_roundtrip(void) {
    TEST("cert sign+verify roundtrip");
    uint8_t data[128];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_cert(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_cert(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

/* ── Negative: cross-domain verify must fail ──────────────────────── */

static void test_cross_domain_fails(void) {
    TEST("cross-domain verify rejects (auth_challenge → kyber_bind)");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    if (nodus_sign_auth_challenge(&sig, nonce, &g_sk) != 0) { FAIL("sign"); return; }

    /* Attempt to verify as KYBER_BIND with same bytes — must fail. */
    if (nodus_verify_kyber_bind(&sig, nonce, sizeof(nonce), &g_pk) == 0) {
        FAIL("cross-domain verify accepted sig — oracle still open");
        return;
    }
    PASS();
}

static void test_every_pair_rejects(void) {
    TEST("all 5 domains pairwise cross-reject (5x5 matrix, 20 negative tests)");
    uint8_t data[128];
    nodus_random(data, sizeof(data));

    /* Produce a sig under each domain */
    nodus_sig_t sigs[5];
    if (nodus_sign_auth_challenge(&sigs[0], data, &g_sk) != 0) { FAIL("sign ac"); return; }
    if (nodus_sign_kyber_bind(&sigs[1], data, sizeof(data), &g_sk) != 0) { FAIL("sign kb"); return; }
    if (nodus_sign_t3_envelope(&sigs[2], data, sizeof(data), &g_sk) != 0) { FAIL("sign t3"); return; }
    if (nodus_sign_value_store(&sigs[3], data, sizeof(data), &g_sk) != 0) { FAIL("sign vs"); return; }
    if (nodus_sign_cert(&sigs[4], data, sizeof(data), &g_sk) != 0) { FAIL("sign ct"); return; }

    /* For each sig, matching verifier passes, all 4 non-matching verifiers fail */
    int ac_len = NODUS_NONCE_LEN;  /* AUTH_CHALLENGE expects 32B */
    int other_len = (int)sizeof(data);

    /* Matching cases (5) */
    if (nodus_verify_auth_challenge(&sigs[0], data, &g_pk) != 0) { FAIL("ac→ac should pass"); return; }
    if (nodus_verify_kyber_bind(&sigs[1], data, other_len, &g_pk) != 0) { FAIL("kb→kb"); return; }
    if (nodus_verify_t3_envelope(&sigs[2], data, other_len, &g_pk) != 0) { FAIL("t3→t3"); return; }
    if (nodus_verify_value_store(&sigs[3], data, other_len, &g_pk) != 0) { FAIL("vs→vs"); return; }
    if (nodus_verify_cert(&sigs[4], data, other_len, &g_pk) != 0) { FAIL("ct→ct"); return; }

    /* Mismatch cases (20) — every sig must fail against every non-matching verifier.
     * We use AC's 32B verify path and other domains' full-size path. When sizes differ
     * (e.g., AC=32 vs others=128) the preimage also differs so verify fails for that
     * reason too — which is fine, still demonstrates domain separation. */
    #define CHECK_REJECT(fn, s, d, dl, name) \
        do { if (fn(s, d, dl, &g_pk) == 0) { FAIL(name " unexpectedly accepted"); return; } } while(0)

    /* sigs[0] (AC sig) attempted against every other verifier */
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[0], data, ac_len,    "ac→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[0], data, ac_len,    "ac→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[0], data, ac_len,    "ac→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[0], data, ac_len,    "ac→ct");
    /* sigs[1] (KB sig) */
    if (nodus_verify_auth_challenge(&sigs[1], data, &g_pk) == 0)     { FAIL("kb→ac"); return; }
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[1], data, other_len, "kb→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[1], data, other_len, "kb→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[1], data, other_len, "kb→ct");
    /* sigs[2] (T3 sig) */
    if (nodus_verify_auth_challenge(&sigs[2], data, &g_pk) == 0)     { FAIL("t3→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[2], data, other_len, "t3→kb");
    CHECK_REJECT(nodus_verify_value_store, &sigs[2], data, other_len, "t3→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[2], data, other_len, "t3→ct");
    /* sigs[3] (VS sig) */
    if (nodus_verify_auth_challenge(&sigs[3], data, &g_pk) == 0)     { FAIL("vs→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[3], data, other_len, "vs→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[3], data, other_len, "vs→t3");
    CHECK_REJECT(nodus_verify_cert,        &sigs[3], data, other_len, "vs→ct");
    /* sigs[4] (CT sig) */
    if (nodus_verify_auth_challenge(&sigs[4], data, &g_pk) == 0)     { FAIL("ct→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[4], data, other_len, "ct→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[4], data, other_len, "ct→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[4], data, other_len, "ct→vs");

    #undef CHECK_REJECT
    PASS();
}

/* ── Negative: raw sig cannot be verified under any tagged domain ─── */

static void test_raw_sig_rejected_by_tagged_verify(void) {
    TEST("raw nodus_sign sig rejected by tagged verify (legacy isolation)");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    /* Sign RAW (the old oracle path, no tag) */
    if (nodus_sign(&sig, nonce, sizeof(nonce), &g_sk) != 0) { FAIL("raw sign"); return; }

    /* Try to verify as auth_challenge — must fail because tagged verifier
     * prepends "NDS1"+purpose+len before dilithium_verify. */
    if (nodus_verify_auth_challenge(&sig, nonce, &g_pk) == 0) {
        FAIL("tagged verify accepted raw sig — migration compat broken");
        return;
    }
    PASS();
}

/* ── Negative: tampered preimage must fail ────────────────────────── */

static void test_tampered_data_fails(void) {
    TEST("tampered data byte fails verify");
    uint8_t data[64];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_cert(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }

    /* Flip a bit */
    data[7] ^= 0x01;
    if (nodus_verify_cert(&sig, data, sizeof(data), &g_pk) == 0) {
        FAIL("tampered data verified — impossible"); return;
    }
    PASS();
}

int main(void) {
    printf("Nodus domain-separation sign/verify tests (C2 fix)\n");
    printf("=================================================\n");

    if (setup_keypair() != 0) {
        fprintf(stderr, "FATAL: keypair generation failed\n");
        return 1;
    }

    test_auth_challenge_roundtrip();
    test_kyber_bind_roundtrip();
    test_t3_envelope_roundtrip();
    test_value_store_roundtrip();
    test_cert_roundtrip();
    test_cross_domain_fails();
    test_every_pair_rejects();
    test_raw_sig_rejected_by_tagged_verify();
    test_tampered_data_fails();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
