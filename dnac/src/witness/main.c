/**
 * @file main.c
 * @brief DNAC Witness Server entry point
 *
 * The witness server provides double-spend prevention for DNAC transactions.
 * It communicates via DHT (no TCP ports required).
 *
 * Usage: dnac-witness [options]
 *   -d <dir>    Data directory (default: ~/.dna)
 *   -h          Show help
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <dna/dna_engine.h>
#include "dnac/witness.h"
#include "dnac/version.h"
#include "dnac/epoch.h"
#include "config.h"

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "WITNESS_MAIN"

/* External function to set replication engine */
extern void witness_set_replication_engine(dna_engine_t *engine);

/* Global state */
static volatile int g_running = 1;
static volatile int g_identity_loaded = 0;
static volatile int g_identity_result = -1;

/* Shared state for event-driven listeners */
static pthread_mutex_t g_work_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_work_cond = PTHREAD_COND_INITIALIZER;
static int g_pending_work = 0;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    /* Signal condvar to wake up main loop */
    pthread_mutex_lock(&g_work_mutex);
    pthread_cond_signal(&g_work_cond);
    pthread_mutex_unlock(&g_work_mutex);
    printf("\nShutting down...\n");
}

/* Callback for identity loading - matches dna_completion_cb signature */
static void identity_loaded_callback(unsigned long request_id, int result, void *user_data) {
    (void)request_id;
    (void)user_data;
    g_identity_result = result;
    g_identity_loaded = 1;
}

static void print_usage(const char *prog) {
    printf("DNAC Witness Server v%s\n", dnac_get_version());
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -d <dir>    Data directory (default: ~/.dna)\n");
    printf("  -h          Show this help\n");
}

static char* get_default_data_dir(void) {
    const char *home = qgp_platform_home_dir();
    if (!home) {
        return strdup(".dna");
    }

    size_t len = strlen(home) + strlen("/.dna") + 1;
    char *path = malloc(len);
    if (path) {
        snprintf(path, len, "%s/.dna", home);
    }
    return path;
}

static char* get_db_path(const char *data_dir) {
    size_t len = strlen(data_dir) + strlen("/") + strlen(WITNESS_DB_FILENAME) + 1;
    char *path = malloc(len);
    if (path) {
        snprintf(path, len, "%s/%s", data_dir, WITNESS_DB_FILENAME);
    }
    return path;
}

int main(int argc, char *argv[]) {
    char *data_dir = NULL;
    int opt;
    int rc;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "d:h")) != -1) {
        switch (opt) {
            case 'd':
                data_dir = strdup(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!data_dir) {
        data_dir = get_default_data_dir();
    }

    printf("DNAC Witness Server v%s\n", dnac_get_version());
    printf("Data directory: %s\n", data_dir);

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create DNA engine */
    dna_engine_t *engine = dna_engine_create(data_dir);
    if (!engine) {
        fprintf(stderr, "Failed to create DNA engine\n");
        free(data_dir);
        return 1;
    }

    /* Load identity */
    printf("Loading identity...\n");

    /* Check if identity exists */
    if (!dna_engine_has_identity(engine)) {
        fprintf(stderr, "No identity found. Create one with dna-messenger first.\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    /* Load identity using async API with minimal mode (DHT only) */
    /* NULL fingerprint = default/only identity */
    dna_engine_load_identity_minimal(engine, NULL, NULL,
                                     identity_loaded_callback, NULL);

    /* Wait for load to complete (max 30 seconds) */
    int wait_count = 0;
    while (!g_identity_loaded && wait_count < 300 && g_running) {
        usleep(100000); /* 100ms */
        wait_count++;
    }

    if (!g_identity_loaded || g_identity_result != 0) {
        fprintf(stderr, "Failed to load identity (result=%d, timeout=%d)\n",
                g_identity_result, !g_identity_loaded);
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    const char *fingerprint = dna_engine_get_fingerprint(engine);
    printf("Identity loaded: %.32s...\n", fingerprint ? fingerprint : "(unknown)");

    /* Initialize nullifier database */
    char *db_path = get_db_path(data_dir);
    if (!db_path) {
        fprintf(stderr, "Failed to allocate database path\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    rc = witness_nullifier_init(db_path);
    free(db_path);

    if (rc != 0) {
        fprintf(stderr, "Failed to initialize nullifier database\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    /* Set up replication */
    witness_set_replication_engine(engine);

    /* Publish identity to DHT */
    printf("Publishing identity to DHT...\n");
    rc = witness_publish_identity(engine);
    if (rc != 0) {
        fprintf(stderr, "Warning: Failed to publish identity to DHT\n");
        /* Continue anyway - may succeed later */
    }

    printf("Witness server running. Press Ctrl+C to stop.\n");
    printf("Fingerprint: %s\n", fingerprint ? fingerprint : "(unknown)");

    /* Setup listener contexts */
    witness_request_ctx_t req_ctx = {
        .engine = engine,
        .mutex = &g_work_mutex,
        .cond = &g_work_cond,
        .pending_count = &g_pending_work
    };

    witness_replication_ctx_t rep_ctx = {
        .engine = engine,
        .mutex = &g_work_mutex,
        .cond = &g_work_cond,
        .pending_count = &g_pending_work
    };

    /* Track current epoch */
    uint64_t current_epoch = dnac_get_current_epoch();
    uint64_t last_announced_epoch = 0;

    /* Publish initial epoch announcement */
    printf("Publishing epoch announcement (epoch %lu)...\n", (unsigned long)current_epoch);
    rc = witness_publish_announcement(engine);
    if (rc == 0) {
        last_announced_epoch = current_epoch;
    } else {
        fprintf(stderr, "Warning: Failed to publish epoch announcement\n");
    }

    /* Start listeners */
    printf("Starting DHT listeners...\n");

    /* Start legacy request listener (for backward compatibility during transition) */
    size_t req_token = witness_start_request_listener(engine, &req_ctx);

    /* Start epoch-based request listeners (current and previous epoch) */
    size_t epoch_token_current = witness_start_epoch_request_listener(engine, &req_ctx, current_epoch);
    size_t epoch_token_previous = 0;
    if (current_epoch > 0) {
        epoch_token_previous = witness_start_epoch_request_listener(engine, &req_ctx, current_epoch - 1);
    }

    /* Start replication listener */
    size_t rep_token = witness_start_replication_listener(engine, &rep_ctx);

    if (req_token == 0) {
        fprintf(stderr, "Warning: Failed to start legacy request listener\n");
    }
    if (epoch_token_current == 0) {
        fprintf(stderr, "Warning: Failed to start epoch request listener\n");
    }
    if (rep_token == 0) {
        fprintf(stderr, "Warning: Failed to start replication listener\n");
    }

    printf("Listening for requests (event-driven, epoch %lu)...\n", (unsigned long)current_epoch);

    /* Main loop - wait for events or periodic tasks */
    time_t last_identity_publish = time(NULL);
    const int IDENTITY_REFRESH_SEC = 1800; /* 30 minutes */

    while (g_running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 60;  /* Wake every 60s max for periodic checks */

        pthread_mutex_lock(&g_work_mutex);
        int work_done = g_pending_work;
        g_pending_work = 0;
        pthread_cond_timedwait(&g_work_cond, &g_work_mutex, &ts);
        pthread_mutex_unlock(&g_work_mutex);

        if (work_done > 0) {
            printf("Processed %d event(s)\n", work_done);
        }

        /* Check for epoch change */
        uint64_t new_epoch = dnac_get_current_epoch();
        if (new_epoch != current_epoch) {
            printf("Epoch changed: %lu -> %lu\n",
                   (unsigned long)current_epoch, (unsigned long)new_epoch);

            /* Stop old epoch listeners */
            if (epoch_token_previous != 0) {
                witness_stop_epoch_request_listener(engine, epoch_token_previous);
            }

            /* Rotate: current becomes previous */
            epoch_token_previous = epoch_token_current;

            /* Start listener for new epoch */
            epoch_token_current = witness_start_epoch_request_listener(engine, &req_ctx, new_epoch);

            current_epoch = new_epoch;

            /* Publish new announcement */
            if (witness_publish_announcement(engine) == 0) {
                last_announced_epoch = current_epoch;
                printf("Published epoch %lu announcement\n", (unsigned long)current_epoch);
            }
        }

        /* Periodically refresh identity in DHT */
        time_t now = time(NULL);
        if (now - last_identity_publish > IDENTITY_REFRESH_SEC) {
            witness_publish_identity(engine);
            last_identity_publish = now;
        }
    }

    /* Shutdown - cancel listeners */
    printf("Shutting down witness server...\n");
    if (req_token != 0) {
        witness_stop_request_listener(engine, req_token);
    }
    if (epoch_token_current != 0) {
        witness_stop_epoch_request_listener(engine, epoch_token_current);
    }
    if (epoch_token_previous != 0) {
        witness_stop_epoch_request_listener(engine, epoch_token_previous);
    }
    if (rep_token != 0) {
        witness_stop_replication_listener(engine, rep_token);
    }

    /* Cleanup */
    witness_nullifier_shutdown();
    dna_engine_destroy(engine);
    free(data_dir);

    pthread_mutex_destroy(&g_work_mutex);
    pthread_cond_destroy(&g_work_cond);

    printf("Witness server stopped.\n");
    return 0;
}
