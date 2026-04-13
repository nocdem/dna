/**
 * @file test_engine_destroy_during_backup.c
 * @brief SEC-05 regression test: engine destroy while backup is in flight.
 *
 * Phase 02-02 / plan 02-02 / requirement SEC-05.
 *
 * SEC-05 concurrent-destroy note
 * ------------------------------
 *
 * Per D-24 (2-CONTEXT.md), this test uses the public engine API only.
 * The true in-flight-backup race is only reachable when the engine has a
 * loaded identity (see dna_engine_backup_messages — it early-returns on
 * !engine->identity_loaded || !engine->messenger without spawning a
 * thread). Creating an identity from scratch would require a BIP39 seed
 * flow, DHT connectivity, and minutes of setup — way outside the scope
 * of a ctest regression guard, and D-24 forbids private test hooks.
 *
 * This test therefore follows Strategy C from the plan: a positive-
 * control regression guard that exercises the destroy path end-to-end.
 * Specifically:
 *
 *   1. create engine in a fresh scratch dir (no identity)
 *   2. call dna_engine_backup_messages() — returns -1 immediately
 *      because identity is not loaded, so the backup thread is never
 *      spawned and engine->backup_thread_running stays false
 *   3. immediately call dna_engine_destroy() — the destroy path
 *      executes the atomic_load(&engine->backup_thread_running) check
 *      from the SEC-05 fix, sees false, and skips the join
 *   4. the entire binary runs under AddressSanitizer (tests build with
 *      -fsanitize=address); any use-after-free, double-free, or leak
 *      inside dna_engine_destroy fails the test
 *
 * The race that the atomicity fix prevents — destroy reading a stale
 * false while the backup thread is still mid-write to
 * engine->messenger->backup_ctx — is verified by:
 *
 *   - Code review via the grep acceptance criteria in 02-02-PLAN.md
 *     (every read/write of backup_thread_running across dna_engine.c
 *     and dna_engine_backup.c uses atomic_load/atomic_store)
 *   - Plan 02-04's TSan ctest target running the full suite under
 *     ThreadSanitizer (planned Wave 2)
 *
 * This test is a hard regression guard against any future refactor that
 * either breaks dna_engine_backup_messages's early-return path or that
 * introduces UB into the destroy join sequence at dna_engine.c:1864+.
 *
 * Public headers only — no src/, no engine_includes.h, no
 * dna_engine_internal.h.
 *
 * @author DNA Connect Team
 * @date 2026-04-13
 */

#include "dna/dna_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

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

/* 15-second hard cap on total test runtime (per plan). */
#define TEST_HARD_CAP_SECONDS 15

static double elapsed_since(const struct timespec *t0) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - t0->tv_sec) +
           (double)(now.tv_nsec - t0->tv_nsec) / 1e9;
}

/* Callback used by dna_engine_backup_messages. We never expect it to be
 * invoked from the backup thread (since identity is not loaded), but we
 * still register one so the API call is well-formed. If it does fire from
 * the calling thread (immediate-error path), we simply record that. */
static volatile int g_backup_cb_fired = 0;
static volatile int g_backup_cb_error = 0;

static void backup_cb(
    dna_request_id_t request_id,
    int error,
    int count1,
    int count2,
    void *user_data)
{
    (void)request_id;
    (void)count1;
    (void)count2;
    (void)user_data;
    g_backup_cb_fired = 1;
    g_backup_cb_error = error;
}

/*
 * ===== SEC-05 destroy-during-backup regression =====
 *
 * Creates an engine, issues a backup request (which fast-fails because
 * no identity is loaded — backup thread is never spawned), then destroys
 * the engine. The destroy path exercises the SEC-05 atomic_load of
 * backup_thread_running and the preserved pthread_join ordering.
 *
 * Under AddressSanitizer any use-after-free in the destroy path fails.
 */
static void test_destroy_after_backup_request(void) {
    TEST_START("destroy after backup request (SEC-05 regression)");

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    char tmpdir[] = "/tmp/dna_sec05_XXXXXX";
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

    /* Issue a backup request. With no identity loaded this fast-fails
     * and does NOT spawn a thread — but it still exercises the public
     * API path that, in a fully-loaded engine, would set
     * engine->backup_thread_running via atomic_store. */
    g_backup_cb_fired = 0;
    g_backup_cb_error = 0;
    dna_request_id_t rid =
        dna_engine_backup_messages(engine, backup_cb, NULL);
    (void)rid;  /* request id may be 0 on immediate error — fine */

    /* Best-effort tiny sleep to let anything the engine scheduled run. */
    usleep(1000);

    /* Sanity: the callback must have fired with an error since there is
     * no identity. This proves the immediate-error path still works. */
    TEST_ASSERT(g_backup_cb_fired == 1,
                "backup callback fired (immediate error path)");
    TEST_ASSERT(g_backup_cb_error != 0,
                "backup reported error (no identity)");

    /* Bail out if we've somehow run over the hard cap. */
    if (elapsed_since(&t0) > (double)TEST_HARD_CAP_SECONDS) {
        TEST_FAIL("hard cap exceeded before destroy");
        dna_engine_destroy(engine);
        return;
    }

    /* The core SEC-05 regression guard: destroy must return cleanly.
     * Under ASan, any use-after-free inside the join sequence or any
     * leak from the engine teardown fails here. */
    dna_engine_destroy(engine);
    TEST_PASS("dna_engine_destroy returned cleanly");

    if (elapsed_since(&t0) > (double)TEST_HARD_CAP_SECONDS) {
        TEST_FAIL("hard cap exceeded during destroy");
    }

    /* Best-effort cleanup of the scratch dir tree. */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    int sysrc = system(cmd);
    (void)sysrc;
}

/*
 * ===== SEC-05 plain-destroy positive control =====
 *
 * Second smoke: create-then-destroy without ever touching the backup
 * API, to prove that the SEC-05 atomic_bool promotion did not change
 * the initialization of engine->backup_thread_running / restore_thread_running.
 * If the _Atomic bool field lands uninitialized at the destroy-site
 * atomic_load, ASan's MSan-style uninit checks (where available) or a
 * heap poisoning mismatch will catch it.
 */
static void test_plain_create_destroy(void) {
    TEST_START("plain create/destroy (SEC-05 init-path regression)");

    char tmpdir[] = "/tmp/dna_sec05_plain_XXXXXX";
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

    dna_engine_destroy(engine);
    TEST_PASS("dna_engine_destroy returned cleanly");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    int sysrc = system(cmd);
    (void)sysrc;
}

int main(void) {
    fprintf(stdout, "=================================================\n");
    fprintf(stdout, "SEC-05 engine destroy during backup regression\n");
    fprintf(stdout, "=================================================\n");

    test_plain_create_destroy();
    test_destroy_after_backup_request();

    fprintf(stdout, "\n=================================================\n");
    fprintf(stdout, "Results: %d passed, %d failed\n",
            tests_passed, tests_failed);
    fprintf(stdout, "=================================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
