/**
 * Nodus — Witness w_chain_q Rate Limit Tests (PR 3 / E3)
 *
 * Verifies the H-1 per-source rate limit on incoming w_chain_q.
 * Without throttling a peer can extract one Dilithium5-signed
 * w_chain_r per request — at ~1ms/sign that is ~1000 sigs/sec/cpu
 * burned defending a non-attack (every legitimate bootstrap client
 * retries on its own round-timeout cadence anyway).
 *
 * The pure helper takes (last_response_ms, now_ms, min_interval_ms)
 * and returns true if the new request should be answered, false if
 * dropped. last_response_ms == 0 means "first contact" -> always
 * allow.
 *
 * RED state for E3: the stub returns true unconditionally, so the
 * "within window -> deny" cases fail. The GREEN commit replaces
 * the stub with the real (now - last >= min) check.
 */

#include "witness/nodus_witness_bootstrap.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static void test_first_contact_allowed(void) {
    TEST("first contact (last=0) -> allow regardless of min_interval");
    if (!nodus_witness_bootstrap_chain_q_rate_limit_allow(
            0, 12345, 1000)) {
        FAIL("expected true on first contact");
        return;
    }
    PASS();
}

static void test_well_outside_window_allowed(void) {
    TEST("now - last >> min_interval -> allow");
    if (!nodus_witness_bootstrap_chain_q_rate_limit_allow(
            1000, 100000, 1000)) {
        FAIL("expected true (gap=99000ms >> 1000ms)");
        return;
    }
    PASS();
}

static void test_exact_boundary_allowed(void) {
    TEST("now - last == min_interval (exact boundary) -> allow");
    if (!nodus_witness_bootstrap_chain_q_rate_limit_allow(
            1000, 2000, 1000)) {
        FAIL("expected true at exact boundary (>= contract)");
        return;
    }
    PASS();
}

static void test_one_ms_inside_window_denied(void) {
    TEST("now - last == min_interval - 1 (within window) -> deny");
    if (nodus_witness_bootstrap_chain_q_rate_limit_allow(
            1000, 1999, 1000)) {
        FAIL("expected false (1ms inside window)");
        return;
    }
    PASS();
}

static void test_immediate_repeat_denied(void) {
    TEST("now == last (repeat in same tick) -> deny");
    if (nodus_witness_bootstrap_chain_q_rate_limit_allow(
            5000, 5000, 1000)) {
        FAIL("expected false (no time elapsed)");
        return;
    }
    PASS();
}

static void test_negative_clock_skew_denied(void) {
    TEST("now < last (impossible monotonic, defensive) -> deny");
    if (nodus_witness_bootstrap_chain_q_rate_limit_allow(
            10000, 9999, 1000)) {
        FAIL("expected false (now before last is unsafe)");
        return;
    }
    PASS();
}

static void test_zero_min_interval_always_allow(void) {
    TEST("min_interval=0 (rate limit disabled) -> always allow");
    if (!nodus_witness_bootstrap_chain_q_rate_limit_allow(
            5000, 5000, 0)) {
        FAIL("expected true when interval=0");
        return;
    }
    PASS();
}

int main(void) {
    printf("\nNodus Witness w_chain_q Rate Limit Tests (PR 3 / E3)\n");
    printf("=====================================================\n\n");

    test_first_contact_allowed();
    test_well_outside_window_allowed();
    test_exact_boundary_allowed();
    test_one_ms_inside_window_denied();
    test_immediate_repeat_denied();
    test_negative_clock_skew_denied();
    test_zero_min_interval_always_allow();

    printf("\n=====================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
