/*
 * DNA Keyserver - Main Entry Point
 */

#include "keyserver.h"
#include "config.h"
#include "db.h"
#include "rate_limit.h"
#include "http_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <microhttpd.h>

// API handler declarations
enum MHD_Result api_health_handler(struct MHD_Connection *connection, sqlite3 *db_conn);
enum MHD_Result api_list_handler(struct MHD_Connection *connection, sqlite3 *db_conn, const char *url);
enum MHD_Result api_lookup_handler(struct MHD_Connection *connection, sqlite3 *db_conn, const char *identity);
enum MHD_Result api_register_handler(struct MHD_Connection *connection, sqlite3 *db_conn,
                                      const char *upload_data, size_t upload_data_size);
enum MHD_Result api_update_handler(struct MHD_Connection *connection, sqlite3 *db_conn,
                                    const char *upload_data, size_t upload_data_size);

// Global state
static struct MHD_Daemon *http_daemon = NULL;
static sqlite3 *db_conn = NULL;
static volatile sig_atomic_t running = 1;

// Logging
void log_message(const char *level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(stderr, "[%s] %s - ", level, timestamp);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

// POST data handler structure
struct post_data {
    char *data;
    size_t size;
};

// Request handler
static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                             const char *url, const char *method,
                                             const char *version, const char *upload_data,
                                             size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;

    // Handle POST data accumulation
    if (strcmp(method, "POST") == 0) {
        struct post_data *pd = *con_cls;

        if (pd == NULL) {
            // First call - allocate structure
            pd = calloc(1, sizeof(struct post_data));
            if (!pd) return MHD_NO;
            *con_cls = pd;
            return MHD_YES;
        }

        if (*upload_data_size > 0) {
            // Accumulate POST data
            char *new_data = realloc(pd->data, pd->size + *upload_data_size + 1);
            if (!new_data) {
                return MHD_NO;
            }
            pd->data = new_data;
            memcpy(pd->data + pd->size, upload_data, *upload_data_size);
            pd->size += *upload_data_size;
            pd->data[pd->size] = '\0';

            *upload_data_size = 0;
            return MHD_YES;
        }

        // All POST data received, process request
        enum MHD_Result ret;

        // Route: POST /api/keyserver/register
        if (strcmp(url, "/api/keyserver/register") == 0) {
            ret = api_register_handler(connection, db_conn, pd->data, pd->size);
        }
        // Route: POST /api/keyserver/update
        else if (strcmp(url, "/api/keyserver/update") == 0) {
            ret = api_update_handler(connection, db_conn, pd->data, pd->size);
        } else {
            ret = http_send_error(connection, HTTP_NOT_FOUND, "Not found");
        }

        // Cleanup
        if (pd->data) free(pd->data);
        free(pd);
        *con_cls = NULL;

        return ret;
    }

    // GET requests
    if (strcmp(method, "GET") == 0) {
        // Route: GET /api/keyserver/health
        if (strcmp(url, "/api/keyserver/health") == 0) {
            return api_health_handler(connection, db_conn);
        }

        // Route: GET /api/keyserver/list
        if (strcmp(url, "/api/keyserver/list") == 0 ||
            strncmp(url, "/api/keyserver/list?", 20) == 0) {
            return api_list_handler(connection, db_conn, url);
        }

        // Route: GET /api/keyserver/lookup/<dna>
        if (strncmp(url, "/api/keyserver/lookup/", 22) == 0) {
            const char *dna = url + 22;
            return api_lookup_handler(connection, db_conn, dna);
        }
    }

    // 404 Not Found
    return http_send_error(connection, HTTP_NOT_FOUND, "Not found");
}

// Signal handler
static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

// Cleanup on request completion
static void request_completed(void *cls, struct MHD_Connection *connection,
                             void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;

    struct post_data *pd = *con_cls;
    if (pd) {
        if (pd->data) free(pd->data);
        free(pd);
    }
}

int main(int argc, char *argv[]) {
    printf("====================================\n");
    printf(" DNA Keyserver v%s\n", KEYSERVER_VERSION);
    printf("====================================\n\n");

    // Load configuration
    config_init_defaults(&g_config);

    if (argc > 1) {
        if (config_load(argv[1], &g_config) != 0) {
            fprintf(stderr, "Using default configuration\n");
        } else {
            LOG_INFO("Loaded configuration from: %s", argv[1]);
        }
    } else {
        LOG_INFO("Using default configuration (no config file specified)");
    }

    config_print(&g_config);
    printf("\n");

    // Connect to database
    LOG_INFO("Connecting to SQLite database...");
    db_conn = db_connect(&g_config);
    if (!db_conn) {
        LOG_ERROR("Failed to connect to database");
        return 1;
    }

    // Initialize rate limiter
    rate_limit_init();
    LOG_INFO("Rate limiter initialized");

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start HTTP server
    LOG_INFO("Starting HTTP server on %s:%d", g_config.bind_address, g_config.port);

    http_daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
        g_config.port,
        NULL, NULL,
        &answer_to_connection, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        MHD_OPTION_CONNECTION_LIMIT, (unsigned int)g_config.max_connections,
        MHD_OPTION_END
    );

    if (!http_daemon) {
        LOG_ERROR("Failed to start HTTP server");
        db_disconnect(db_conn);
        return 1;
    }

    printf("\n");
    printf("====================================\n");
    printf(" Keyserver ONLINE\n");
    printf("====================================\n");
    printf("Endpoints:\n");
    printf("  POST /api/keyserver/register\n");
    printf("  POST /api/keyserver/update\n");
    printf("  GET  /api/keyserver/lookup/<dna>\n");
    printf("  GET  /api/keyserver/list\n");
    printf("  GET  /api/keyserver/health\n");
    printf("\n");
    printf("Press Ctrl+C to stop\n");
    printf("====================================\n\n");

    // Main loop
    while (running) {
        sleep(1);
    }

    // Cleanup
    LOG_INFO("Shutting down...");

    if (http_daemon) {
        MHD_stop_daemon(http_daemon);
    }

    rate_limit_cleanup();
    db_disconnect(db_conn);

    LOG_INFO("Keyserver stopped");
    return 0;
}
