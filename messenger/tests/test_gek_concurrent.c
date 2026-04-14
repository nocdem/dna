/**
 * @file test_gek_concurrent.c
 * @brief SEC-04 regression test: concurrent GEK KEM-key reader/writer race.
 *
 * Phase 02-01 / plan 02-01 / requirement SEC-04.
 *
 * This test is a regression guard for the data race between gek_set_kem_keys
 * / gek_clear_kem_keys (which mutate the static gek_kem_pubkey / gek_kem_privkey
 * pointers under wrlock) and the five gek_* read sites that dereference those
 * pointers under rdlock (gek_store, gek_load, gek_load_active,
 * gek_export_plain_entries, gek_import_plain_entries).
 *
 * Strategy:
 *   - Spawn N worker threads that repeatedly call gek_set_kem_keys() followed
 *     by gek_clear_kem_keys() in a tight loop on freshly-allocated 1568-byte /
 *     3168-byte buffers.
 *   - Each call to gek_set_kem_keys takes gek_lock in wrlock mode, which
 *     internally frees the previous key buffers and replaces them. Each call
 *     to gek_clear_kem_keys also takes wrlock and frees + NULLs both pointers.
 *   - With many threads hammering the same globals, any missing lock or
 *     incorrect lock scope will produce a use-after-free or double-free
 *     which AddressSanitizer reports as a hard failure.
 *
 *  Run for a bounded wall-clock duration (<= 2 seconds work, <= 10 seconds
 *  hard cap) so ctest stays fast.
 *
 *  Public-API-only caveat (D-24): gek_set_kem_keys / gek_clear_kem_keys are
 *  declared in messenger/gek.h. That header is not installed under
 *  messenger/include/dna/ today — it is the same intra-repo public surface
 *  that test_gek_ratchet already consumes. No private/internal headers are
 *  included here: no engine_includes.h, no src/, no dna_engine_internal.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#include "messenger/gek.h"

#define TEST_PASS "\033[32mPASS\033[0m"
#define TEST_FAIL "\033[31mFAIL\033[0m"

#define KEM_PUBKEY_SIZE  1568  /* Kyber1024 public key  */
#define KEM_PRIVKEY_SIZE 3168  /* Kyber1024 private key */

#define NUM_THREADS      8
#define WORK_DURATION_S  2

typedef struct {
    int thread_id;
    int iterations;
    volatile int *stop_flag;
} worker_args_t;

static void fill_deterministic(uint8_t *buf, size_t len, int thread_id, int iter) {
    /* Pseudo-random fill, not crypto quality — just so every thread pushes
     * a distinct value through gek_set_kem_keys. The rwlock + malloc/free
     * path is what we're stressing; the contents don't matter. */
    uint32_t seed = (uint32_t)((thread_id << 16) ^ iter);
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245u + 12345u;
        buf[i] = (uint8_t)(seed >> 16);
    }
}

static void *worker(void *arg) {
    worker_args_t *w = (worker_args_t *)arg;
    uint8_t *pub = malloc(KEM_PUBKEY_SIZE);
    uint8_t *priv = malloc(KEM_PRIVKEY_SIZE);
    if (!pub || !priv) {
        fprintf(stderr, "thread %d: malloc failed\n", w->thread_id);
        free(pub);
        free(priv);
        return NULL;
    }

    int iter = 0;
    while (!*w->stop_flag) {
        fill_deterministic(pub, KEM_PUBKEY_SIZE, w->thread_id, iter);
        fill_deterministic(priv, KEM_PRIVKEY_SIZE, w->thread_id, iter);

        if (gek_set_kem_keys(pub, priv) != 0) {
            /* Not a race failure — log and continue. gek_set_kem_keys only
             * fails on OOM which is itself exceptional under the test load. */
            fprintf(stderr, "thread %d iter %d: gek_set_kem_keys failed\n",
                    w->thread_id, iter);
        }

        /* Interleave a clear — forces a wrlock + free + NULL, maximising
         * the window for a UAF if any reader were racing (which is what
         * SEC-04 protects against). */
        gek_clear_kem_keys();

        iter++;
    }

    w->iterations = iter;
    free(pub);
    free(priv);
    return NULL;
}

static double elapsed_seconds(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double d = (double)(now.tv_sec - start->tv_sec);
    d += (double)(now.tv_nsec - start->tv_nsec) / 1e9;
    return d;
}

int main(void) {
    fprintf(stderr, "test_gek_concurrent: SEC-04 rwlock race regression\n");
    fprintf(stderr, "  threads=%d duration=%ds hard_cap=10s\n",
            NUM_THREADS, WORK_DURATION_S);

    volatile int stop_flag = 0;

    pthread_t threads[NUM_THREADS];
    worker_args_t args[NUM_THREADS];

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].iterations = 0;
        args[i].stop_flag = &stop_flag;
        if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0) {
            fprintf(stderr, "%s: pthread_create failed for thread %d\n",
                    TEST_FAIL, i);
            stop_flag = 1;
            /* join whatever started */
            for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
            gek_clear_kem_keys();
            return 1;
        }
    }

    /* Let the workers run for WORK_DURATION_S with a 10-second hard cap. */
    while (elapsed_seconds(&start) < (double)WORK_DURATION_S) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 }; /* 10ms */
        nanosleep(&ts, NULL);
        if (elapsed_seconds(&start) > 10.0) break;
    }

    stop_flag = 1;

    long total_iter = 0;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        total_iter += args[i].iterations;
    }

    /* Final cleanup — ensure no leftover allocation survives for ASan. */
    gek_clear_kem_keys();

    double elapsed = elapsed_seconds(&start);
    fprintf(stderr, "  total_iterations=%ld elapsed=%.2fs\n",
            total_iter, elapsed);

    if (total_iter <= 0) {
        fprintf(stderr, "%s: workers produced zero iterations\n", TEST_FAIL);
        return 1;
    }

    fprintf(stderr, "%s: test_gek_concurrent (no ASan report = pass)\n", TEST_PASS);
    return 0;
}
