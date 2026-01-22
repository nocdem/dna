/**
 * @file main.c
 * @brief DNAC Witness Server entry point
 *
 * The witness server provides double-spend prevention for DNAC transactions.
 * Two modes are supported:
 * - DHT mode (default): Communicates via DHT (no TCP ports required)
 * - BFT mode (--bft): Uses TCP for BFT consensus with other witnesses
 *
 * Usage: dnac-witness [options]
 *   -d <dir>    Data directory (default: ~/.dna)
 *   --bft       Enable BFT consensus mode
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
#include "crypto/utils/qgp_types.h"
#include "crypto/utils/qgp_sha3.h"

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

/* External BFT main function */
extern int bft_witness_main(int argc, char *argv[]);

static void print_usage(const char *prog) {
    printf("DNAC Witness Server v%s\n", dnac_get_version());
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -d <dir>    Data directory (default: ~/.dna)\n");
    printf("  --bft       Enable BFT consensus mode (TCP-based)\n");
    printf("  -p <port>   TCP port for BFT mode (default: 4200)\n");
    printf("  -a <addr>   My address for BFT roster (IP:port)\n");
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

/**
 * Compute fingerprint from identity key file
 * @param data_dir Data directory containing keys/identity.dsa
 * @param fingerprint_out Output buffer (must be at least 129 bytes)
 * @return 0 on success, -1 on error
 */
static int compute_identity_fingerprint(const char *data_dir, char *fingerprint_out) {
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    qgp_key_t *key = NULL;
    if (qgp_key_load(key_path, &key) != 0 || !key) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load signing key: %s", key_path);
        return -1;
    }

    if (key->type != QGP_KEY_TYPE_DSA87 || !key->public_key) {
        QGP_LOG_ERROR(LOG_TAG, "Not a Dilithium5 key or missing public key");
        qgp_key_free(key);
        return -1;
    }

    /* Compute SHA3-512 fingerprint of public key */
    int rc = qgp_sha3_512_fingerprint(key->public_key, key->public_key_size, fingerprint_out);

    qgp_key_free(key);
    return rc;
}

int main(int argc, char *argv[]) {
    char *data_dir = NULL;
    int opt;
    int rc;

    /* Check for --bft flag first */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bft") == 0) {
            return bft_witness_main(argc, argv);
        }
    }

    /* Parse arguments for DHT mode */
    while ((opt = getopt(argc, argv, "d:p:a:h")) != -1) {
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

    /* Enable file logging to <data_dir>/logs/dna.log */
    qgp_log_file_enable(true);
    qgp_log_set_level(QGP_LOG_LEVEL_DEBUG);
    printf("File logging enabled: %s/logs/dna.log\n", data_dir);

    /* Log version to file */
    QGP_LOG_INFO(LOG_TAG, "=== DNAC Witness Server v%s ===", dnac_get_version());

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

    /* Compute fingerprint from identity file */
    char fingerprint[129] = {0};
    rc = compute_identity_fingerprint(data_dir, fingerprint);
    if (rc != 0) {
        fprintf(stderr, "Failed to compute identity fingerprint\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }
    printf("Identity fingerprint: %.32s...\n", fingerprint);

    /* Load identity using async API with minimal mode (DHT only) */
    dna_engine_load_identity_minimal(engine, fingerprint, NULL,
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

    printf("Identity loaded: %.32s...\n", fingerprint);

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
    printf("Fingerprint: %s\n", fingerprint);

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

    /* Start epoch-based request listeners (current and previous epoch) */
    size_t epoch_token_current = witness_start_epoch_request_listener(engine, &req_ctx, current_epoch);
    size_t epoch_token_previous = 0;
    if (current_epoch > 0) {
        epoch_token_previous = witness_start_epoch_request_listener(engine, &req_ctx, current_epoch - 1);
    }

    /* Start replication listener */
    size_t rep_token = witness_start_replication_listener(engine, &rep_ctx);

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

        /* Process any queued responses (must be done from main thread) */
        int responses_sent = witness_process_pending_responses(engine);
        if (responses_sent > 0) {
            printf("Sent %d queued response(s)\n", responses_sent);
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
