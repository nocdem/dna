/**
 * @file main.c
 * @brief DNAC Anchor Server entry point
 *
 * The anchor server provides double-spend prevention for DNAC transactions.
 * It communicates via DHT (no TCP ports required).
 *
 * Usage: dnac-anchor [options]
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

#include <dna/dna_engine.h>
#include "dnac/anchor_server.h"
#include "dnac/version.h"
#include "config.h"

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "ANCHOR_MAIN"

/* External function to set replication engine */
extern void anchor_set_replication_engine(dna_engine_t *engine);

/* Global state */
static volatile int g_running = 1;
static volatile int g_identity_loaded = 0;
static volatile int g_identity_result = -1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
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
    printf("DNAC Anchor Server v%s\n", dnac_get_version());
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
    size_t len = strlen(data_dir) + strlen("/") + strlen(ANCHOR_DB_FILENAME) + 1;
    char *path = malloc(len);
    if (path) {
        snprintf(path, len, "%s/%s", data_dir, ANCHOR_DB_FILENAME);
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

    printf("DNAC Anchor Server v%s\n", dnac_get_version());
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

    rc = anchor_nullifier_init(db_path);
    free(db_path);

    if (rc != 0) {
        fprintf(stderr, "Failed to initialize nullifier database\n");
        dna_engine_destroy(engine);
        free(data_dir);
        return 1;
    }

    /* Set up replication */
    anchor_set_replication_engine(engine);

    /* Publish identity to DHT */
    printf("Publishing identity to DHT...\n");
    rc = anchor_publish_identity(engine);
    if (rc != 0) {
        fprintf(stderr, "Warning: Failed to publish identity to DHT\n");
        /* Continue anyway - may succeed later */
    }

    printf("Anchor server running. Press Ctrl+C to stop.\n");
    printf("Fingerprint: %s\n", fingerprint ? fingerprint : "(unknown)");

    /* Main loop */
    time_t last_identity_publish = time(NULL);
    const int IDENTITY_REFRESH_SEC = 1800; /* 30 minutes */

    while (g_running) {
        /* Process anchor requests */
        int processed = anchor_process_requests(engine);
        if (processed > 0) {
            printf("Processed %d anchor request(s)\n", processed);
        }

        /* Process incoming replications */
        int received = anchor_process_replications(engine);
        if (received > 0) {
            printf("Received %d replicated nullifier(s)\n", received);
        }

        /* Periodically refresh identity in DHT */
        time_t now = time(NULL);
        if (now - last_identity_publish > IDENTITY_REFRESH_SEC) {
            anchor_publish_identity(engine);
            last_identity_publish = now;
        }

        /* Sleep between polls */
        usleep(ANCHOR_POLL_INTERVAL_MS * 1000);
    }

    /* Cleanup */
    printf("Shutting down anchor server...\n");
    anchor_nullifier_shutdown();
    dna_engine_destroy(engine);
    free(data_dir);

    printf("Anchor server stopped.\n");
    return 0;
}
