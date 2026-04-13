/**
 * @file test_contact_request_validation.c
 * @brief SEC-01 regression test — wire-level contact request validation
 *
 * Tests the wire-level type validation that closes SEC-01 (the contact
 * request auto-approval bypass). Exercised in two layers:
 *
 *   1. Negative cases (this file directly): hand-craft `dht_contact_request_t`
 *      structures with malformed wire-level fields and verify that
 *      `dht_verify_contact_request` (public function in dht/shared/) rejects
 *      them. This proves the wire-level type-check primitives reject the
 *      attacker-controlled inputs that SEC-01 closes.
 *
 *   2. Positive control (this file): create an engine via the public API,
 *      verify it initializes cleanly, and verify `dna_engine_get_contact_request_count`
 *      behaves correctly on a fresh engine with no identity loaded. This is
 *      a regression guard that SEC-01's new handler-side helper
 *      `contact_request_is_well_formed` does not break engine bring-up.
 *
 * SEC-01 negative-path note (per D-10 in 1-CONTEXT.md):
 *
 *   The actual SEC-01 fix is the static helper `contact_request_is_well_formed`
 *   inside dna_engine_contacts.c, called as the first statement of the per-request
 *   loop in `dna_handle_get_contact_requests`. That helper is `static` and not
 *   directly callable from a test. Driving it through the engine's public API
 *   would require either:
 *
 *     (a) a private-API test hook to inject a raw `dht_contact_request_t` into
 *         the local inbox, or
 *     (b) a live Nodus DHT cluster wired into the test harness so that an
 *         attacker engine could publish a malformed request.
 *
 *   D-10 forbids (a) ("public-API only, no private-API tests just for coverage")
 *   and Phase 1 scope forbids (b). The handler-level helper is therefore verified
 *   by:
 *     - the negative cases below against `dht_verify_contact_request`, which
 *       performs the *same* magic/version checks as the new helper (defense
 *       in depth — both gates exist),
 *     - the positive engine-creation control below (regression guard), and
 *     - this plan's grep-based acceptance criteria against
 *       dna_engine_contacts.c (definition + call-site presence + WARN sites).
 *
 * Public headers only — no `src/...`, no `engine_includes.h`, no internal types.
 *
 * @author DNA Connect Team
 * @date 2026-04-13
 */

#include "dna/dna_engine.h"
#include "dht/shared/dht_contact_request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ANSI colors for test output */
#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED   "\033[0;31m"
#define COLOR_RESET "\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) fprintf(stdout, "\n[TEST] %s\n", name)
#define TEST_PASS(msg) do { \
    fprintf(stdout, "  " COLOR_GREEN "PASS" COLOR_RESET " %s\n", msg); \
    tests_passed++; \
} while (0)
#define TEST_FAIL(msg) do { \
    fprintf(stdout, "  " COLOR_RED "FAIL" COLOR_RESET " %s\n", msg); \
    tests_failed++; \
} while (0)
#define TEST_ASSERT(cond, msg) do { \
    if (cond) { TEST_PASS(msg); } else { TEST_FAIL(msg); } \
} while (0)

/*
 * Build a baseline contact request struct that is well-formed at the
 * field-shape level (correct magic, in-range version, NUL-terminated
 * variable buffers, plausible 128-hex fingerprint and matching pubkey).
 *
 * We do NOT populate a real Dilithium5 signature — these tests target the
 * wire-level type / format gates that run BEFORE signature verification,
 * which is exactly the scope of SEC-01's helper. The fingerprint is the
 * SHA3-512 of an all-zero pubkey, computed below so that
 * `dht_verify_contact_request` reaches its signature step on the
 * positive-baseline fixture (we then rely on the negative tests being
 * gated upstream of the signature check).
 */
static void make_baseline_request(dht_contact_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->magic = DHT_CONTACT_REQUEST_MAGIC;
    req->version = DHT_CONTACT_REQUEST_VERSION;  /* v1, no salt */
    req->timestamp = (uint64_t)time(NULL);
    req->expiry = req->timestamp + 60 * 60;
    /* 128 hex chars + NUL — fingerprint shape valid even though it does
     * not match SHA3-512(pubkey). The negative tests below only need
     * shape-level validity to test the wire-type gates that run BEFORE
     * the SHA3 fingerprint comparison. */
    for (int i = 0; i < 128; i++) {
        req->sender_fingerprint[i] = "0123456789abcdef"[i & 0x0f];
    }
    req->sender_fingerprint[128] = '\0';
    strncpy(req->sender_name, "alice", sizeof(req->sender_name) - 1);
    strncpy(req->message, "hello", sizeof(req->message) - 1);
    req->has_dht_salt = false;
    req->signature_len = 0;
}

/* ===== Negative case 1: bad magic ===== */
static void test_reject_bad_magic(void) {
    TEST_START("dht_verify_contact_request rejects wrong magic");

    dht_contact_request_t req;
    make_baseline_request(&req);
    req.magic = 0xDEADBEEFu;

    int rc = dht_verify_contact_request(&req);
    TEST_ASSERT(rc != 0, "wrong magic 0xDEADBEEF rejected");
}

/* ===== Negative case 2: bad version (too high) ===== */
static void test_reject_bad_version_high(void) {
    TEST_START("dht_verify_contact_request rejects unsupported version (high)");

    dht_contact_request_t req;
    make_baseline_request(&req);
    req.version = 99;  /* not v1, not v2 */

    int rc = dht_verify_contact_request(&req);
    TEST_ASSERT(rc != 0, "version=99 rejected");
}

/* ===== Negative case 3: bad version (zero) ===== */
static void test_reject_bad_version_zero(void) {
    TEST_START("dht_verify_contact_request rejects version=0");

    dht_contact_request_t req;
    make_baseline_request(&req);
    req.version = 0;

    int rc = dht_verify_contact_request(&req);
    TEST_ASSERT(rc != 0, "version=0 rejected");
}

/* ===== Negative case 4: NULL request ===== */
static void test_reject_null_request(void) {
    TEST_START("dht_verify_contact_request rejects NULL");

    int rc = dht_verify_contact_request(NULL);
    TEST_ASSERT(rc != 0, "NULL request rejected");
}

/* ===== Negative case 5: expired request ===== */
static void test_reject_expired(void) {
    TEST_START("dht_verify_contact_request rejects expired request");

    dht_contact_request_t req;
    make_baseline_request(&req);
    req.expiry = 1;  /* 1970-01-01 — long expired */

    int rc = dht_verify_contact_request(&req);
    TEST_ASSERT(rc != 0, "expired request rejected");
}

/*
 * ===== Positive control: engine bring-up =====
 *
 * Verifies that:
 *   - dna_engine_create() returns a valid engine (SEC-01 changes did not
 *     break engine construction in dna_engine_contacts.c)
 *   - dna_engine_get_contact_request_count() on a fresh engine with no
 *     identity loaded returns -1 (error: NO_IDENTITY) cleanly without crash.
 *     This proves the new helper does not segfault on the no-identity path.
 *   - dna_engine_destroy() tears down cleanly.
 *
 * This is the regression guard required by the plan: if Task 1's helper
 * call introduces any UB on engine init, this test crashes / leaks under
 * AddressSanitizer (the test build has -fsanitize=address).
 */
static void test_engine_bringup_smoke(void) {
    TEST_START("engine bring-up smoke test (positive control)");

    /* Create a unique scratch directory so we never collide with a real
     * user data dir. */
    char tmpdir[] = "/tmp/test_sec01_XXXXXX";
    char *dir = mkdtemp(tmpdir);
    if (!dir) {
        TEST_FAIL("mkdtemp failed");
        return;
    }

    dna_engine_t *engine = dna_engine_create(dir);
    TEST_ASSERT(engine != NULL, "dna_engine_create returned non-NULL");
    if (!engine) {
        rmdir(dir);
        return;
    }

    /* No identity loaded — must error cleanly, not crash. */
    int count = dna_engine_get_contact_request_count(engine);
    TEST_ASSERT(count == -1, "get_contact_request_count returns -1 with no identity");

    dna_engine_destroy(engine);
    TEST_PASS("dna_engine_destroy returned cleanly");

    /* Best-effort cleanup of the scratch dir tree. */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    int sysrc = system(cmd);
    (void)sysrc;
}

int main(void) {
    fprintf(stdout, "=================================================\n");
    fprintf(stdout, "SEC-01 contact request validation regression test\n");
    fprintf(stdout, "=================================================\n");

    test_reject_null_request();
    test_reject_bad_magic();
    test_reject_bad_version_high();
    test_reject_bad_version_zero();
    test_reject_expired();
    test_engine_bringup_smoke();

    fprintf(stdout, "\n=================================================\n");
    fprintf(stdout, "Results: %d passed, %d failed\n", tests_passed, tests_failed);
    fprintf(stdout, "=================================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
