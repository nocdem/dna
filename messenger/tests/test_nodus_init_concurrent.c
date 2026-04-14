/**
 * @file test_nodus_init_concurrent.c
 * @brief THR-02 regression test: concurrent first-time nodus init under ASan.
 *
 * Phase 02-03 / plan 02-03 / requirement THR-02.
 *
 * THR-02 concurrent-init note
 * ---------------------------
 *
 * Per D-24 (2-CONTEXT.md), this test uses the public API only. nodus_init.h
 * is an in-tree public header (same tier as messenger/gek.h used by
 * test_gek_concurrent — no src/, no engine_includes.h, no private headers).
 *
 * Strategy A: spawn N reader threads that each call nodus_messenger_init
 * simultaneously with the same zero-initialized identity. The mutex +
 * pthread_once path inside nodus_init.c must ensure:
 *
 *   (a) all threads return success (0)
 *   (b) nodus_messenger_is_initialized() returns true after any thread
 *       completes its init call
 *   (c) ASan observes no torn-read, use-after-free, or double-free on
 *       g_stored_identity, g_config, g_known_nodes[], or the status
 *       callback pair
 *   (d) nodus_messenger_close() runs clean, joining the background
 *       connect thread and clearing state without UAF
 *
 * The actual background connect thread will try to contact real bootstrap
 * nodes and will most likely fail on a test machine with no network or
 * firewalled egress. That is fine and expected — the test is specifically
 * exercising the LOCKED INIT PATH, not end-to-end DHT connectivity. Once
 * the init calls return, the test calls nodus_messenger_close which
 * force-disconnects the connect thread and joins it cleanly.
 *
 * Runtime: bounded by nodus_singleton's force-disconnect + join, typically
 * well under the 15-second hard cap.
 *
 * Public headers only — no src/, no engine_includes.h, no private headers.
 *
 * @author DNA Connect Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

#include "dht/shared/nodus_init.h"
#include "nodus/nodus_types.h"

#define TEST_PASS "\033[32mPASS\033[0m"
#define TEST_FAIL "\033[31mFAIL\033[0m"

#define NUM_THREADS 8

typedef struct {
    int                     thread_id;
    const nodus_identity_t *identity;
    int                     rc;
} worker_args_t;

static pthread_barrier_t g_start_barrier;

static void *init_worker(void *arg) {
    worker_args_t *args = (worker_args_t *)arg;

    /* Synchronize start across all worker threads so they race into
     * nodus_messenger_init at nearly the same moment. */
    pthread_barrier_wait(&g_start_barrier);

    args->rc = nodus_messenger_init(args->identity);
    return NULL;
}

int main(void) {
    fprintf(stderr, "[test_nodus_init_concurrent] THR-02 regression — start\n");

    /* Build a zeroed identity. nodus_messenger_init value-copies it into
     * g_stored_identity; the init path itself only reads fields for logging
     * and forwards the pointer to nodus_singleton_init. The goal of this
     * test is to stress the locked first-time init path, not the singleton's
     * crypto handshake. */
    nodus_identity_t identity;
    memset(&identity, 0, sizeof(identity));

    if (pthread_barrier_init(&g_start_barrier, NULL, NUM_THREADS) != 0) {
        fprintf(stderr, "[test_nodus_init_concurrent] %s: barrier_init failed\n", TEST_FAIL);
        return 1;
    }

    pthread_t     threads[NUM_THREADS];
    worker_args_t args[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].identity  = &identity;
        args[i].rc        = -99;
        if (pthread_create(&threads[i], NULL, init_worker, &args[i]) != 0) {
            fprintf(stderr, "[test_nodus_init_concurrent] %s: pthread_create %d\n",
                    TEST_FAIL, i);
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&g_start_barrier);

    /* All init calls must return 0. The lock + atomic double-check
     * guarantees that only the winning thread does the full init; all
     * others see g_initialized==true and return 0 immediately. */
    int failures = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        if (args[i].rc != 0) {
            fprintf(stderr, "[test_nodus_init_concurrent] thread %d rc=%d (expected 0)\n",
                    i, args[i].rc);
            failures++;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "[test_nodus_init_concurrent] %s: %d threads failed init\n",
                TEST_FAIL, failures);
        nodus_messenger_close();
        return 1;
    }

    /* After the init race, the singleton must be marked initialized. */
    if (!nodus_messenger_is_initialized()) {
        fprintf(stderr, "[test_nodus_init_concurrent] %s: not marked initialized after race\n",
                TEST_FAIL);
        nodus_messenger_close();
        return 1;
    }

    /* Close the singleton — this joins the background connect thread,
     * force-disconnects the nodus TCP socket, and clears g_stored_identity.
     * Under ASan, any use-after-free or torn read in the close path fails. */
    nodus_messenger_close();

    /* After close, is_initialized should return false. */
    if (nodus_messenger_is_initialized()) {
        fprintf(stderr, "[test_nodus_init_concurrent] %s: still marked initialized after close\n",
                TEST_FAIL);
        return 1;
    }

    fprintf(stderr, "[test_nodus_init_concurrent] %s: THR-02 concurrent init clean\n", TEST_PASS);
    return 0;
}
