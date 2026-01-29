/*
 * DNA Engine - Logging Module
 *
 * Log configuration and debug log API:
 *   - Log level management (DEBUG/INFO/WARN/ERROR/NONE)
 *   - Log tag filtering (whitelist/blacklist)
 *   - In-app debug log ring buffer for mobile debugging
 *   - Log export functionality
 *
 * Functions:
 *   - init_log_config()                      // Load log config from file
 *   - dna_engine_get_log_level()             // Get current log level
 *   - dna_engine_set_log_level()             // Set log level
 *   - dna_engine_get_log_tags()              // Get tag filter
 *   - dna_engine_set_log_tags()              // Set tag filter
 *   - dna_engine_debug_log_enable()          // Enable/disable debug log
 *   - dna_engine_debug_log_is_enabled()      // Check if enabled
 *   - dna_engine_debug_log_get_entries()     // Get log entries
 *   - dna_engine_debug_log_count()           // Get entry count
 *   - dna_engine_debug_log_clear()           // Clear log buffer
 *   - dna_engine_debug_log_message()         // Add log message
 *   - dna_engine_debug_log_message_level()   // Add log message with level
 *   - dna_engine_debug_log_export()          // Export to file
 */

#define DNA_ENGINE_LOGGING_IMPL
#include "engine_includes.h"

/* ============================================================================
 * LOG CONFIGURATION
 * ============================================================================ */

/* Static buffers for current log config (loaded from <data_dir>/config) */
static char g_log_level[16] = "WARN";
static char g_log_tags[512] = "";
/* v0.6.47: Mutex to protect concurrent access to log config buffers (security fix) */
static pthread_mutex_t g_log_config_mutex = PTHREAD_MUTEX_INITIALIZER;

const char* dna_engine_get_log_level(void) {
    /* v0.6.47: Use thread-local buffer to avoid race condition with setter.
     * Returns stable pointer - safe for caller to use until next call from same thread. */
    static _Thread_local char level_copy[16];
    pthread_mutex_lock(&g_log_config_mutex);
    strncpy(level_copy, g_log_level, sizeof(level_copy) - 1);
    level_copy[sizeof(level_copy) - 1] = '\0';
    pthread_mutex_unlock(&g_log_config_mutex);
    return level_copy;
}

int dna_engine_set_log_level(const char *level) {
    if (!level) return -1;

    /* Validate level */
    if (strcmp(level, "DEBUG") != 0 && strcmp(level, "INFO") != 0 &&
        strcmp(level, "WARN") != 0 && strcmp(level, "ERROR") != 0 &&
        strcmp(level, "NONE") != 0) {
        return -1;
    }

    /* v0.6.47: Update in-memory config under mutex (security fix) */
    pthread_mutex_lock(&g_log_config_mutex);
    strncpy(g_log_level, level, sizeof(g_log_level) - 1);
    g_log_level[sizeof(g_log_level) - 1] = '\0';
    pthread_mutex_unlock(&g_log_config_mutex);

    /* Apply to log system */
    qgp_log_level_t log_level = QGP_LOG_LEVEL_WARN;
    if (strcmp(level, "DEBUG") == 0) log_level = QGP_LOG_LEVEL_DEBUG;
    else if (strcmp(level, "INFO") == 0) log_level = QGP_LOG_LEVEL_INFO;
    else if (strcmp(level, "WARN") == 0) log_level = QGP_LOG_LEVEL_WARN;
    else if (strcmp(level, "ERROR") == 0) log_level = QGP_LOG_LEVEL_ERROR;
    else if (strcmp(level, "NONE") == 0) log_level = QGP_LOG_LEVEL_NONE;
    qgp_log_set_level(log_level);

    /* Save to config file */
    dna_config_t config;
    dna_config_load(&config);
    strncpy(config.log_level, level, sizeof(config.log_level) - 1);
    dna_config_save(&config);

    return 0;
}

const char* dna_engine_get_log_tags(void) {
    /* v0.6.47: Use thread-local buffer to avoid race condition with setter.
     * Returns stable pointer - safe for caller to use until next call from same thread. */
    static _Thread_local char tags_copy[512];
    pthread_mutex_lock(&g_log_config_mutex);
    strncpy(tags_copy, g_log_tags, sizeof(tags_copy) - 1);
    tags_copy[sizeof(tags_copy) - 1] = '\0';
    pthread_mutex_unlock(&g_log_config_mutex);
    return tags_copy;
}

int dna_engine_set_log_tags(const char *tags) {
    if (!tags) tags = "";

    /* v0.6.47: Update in-memory config under mutex (security fix) */
    pthread_mutex_lock(&g_log_config_mutex);
    strncpy(g_log_tags, tags, sizeof(g_log_tags) - 1);
    g_log_tags[sizeof(g_log_tags) - 1] = '\0';
    pthread_mutex_unlock(&g_log_config_mutex);

    /* Apply to log system */
    if (tags[0] == '\0') {
        /* Empty = show all (blacklist mode) */
        qgp_log_set_filter_mode(QGP_LOG_FILTER_BLACKLIST);
        qgp_log_clear_filters();
    } else {
        /* Whitelist mode - only show specified tags */
        qgp_log_set_filter_mode(QGP_LOG_FILTER_WHITELIST);
        qgp_log_clear_filters();

        /* Parse comma-separated tags */
        char tags_buf[512];
        strncpy(tags_buf, tags, sizeof(tags_buf) - 1);
        tags_buf[sizeof(tags_buf) - 1] = '\0';

        char *token = strtok(tags_buf, ",");
        while (token != NULL) {
            /* Trim whitespace */
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (*token != '\0') {
                qgp_log_enable_tag(token);
            }
            token = strtok(NULL, ",");
        }
    }

    /* Save to config file */
    dna_config_t config;
    dna_config_load(&config);
    strncpy(config.log_tags, tags, sizeof(config.log_tags) - 1);
    dna_config_save(&config);

    return 0;
}

/* Initialize log config from file (called during engine startup) */
void init_log_config(void) {
    dna_config_t config;
    if (dna_config_load(&config) == 0) {
        strncpy(g_log_level, config.log_level, sizeof(g_log_level) - 1);
        strncpy(g_log_tags, config.log_tags, sizeof(g_log_tags) - 1);
    }
}

/* ============================================================================
 * DEBUG LOG API - In-app log viewing for mobile debugging
 * ============================================================================ */

void dna_engine_debug_log_enable(bool enabled) {
    qgp_log_ring_enable(enabled);
}

bool dna_engine_debug_log_is_enabled(void) {
    return qgp_log_ring_is_enabled();
}

int dna_engine_debug_log_get_entries(dna_debug_log_entry_t *entries, int max_entries) {
    if (!entries || max_entries <= 0) {
        return 0;
    }

    /* Allocate temp buffer for qgp entries */
    qgp_log_entry_t *qgp_entries = calloc(max_entries, sizeof(qgp_log_entry_t));
    if (!qgp_entries) {
        return 0;
    }

    int count = qgp_log_ring_get_entries(qgp_entries, max_entries);

    /* Convert to dna_debug_log_entry_t (same structure, just copy) */
    for (int i = 0; i < count; i++) {
        entries[i].timestamp_ms = qgp_entries[i].timestamp_ms;
        entries[i].level = (int)qgp_entries[i].level;
        memcpy(entries[i].tag, qgp_entries[i].tag, sizeof(entries[i].tag));
        memcpy(entries[i].message, qgp_entries[i].message, sizeof(entries[i].message));
    }

    free(qgp_entries);
    return count;
}

int dna_engine_debug_log_count(void) {
    return qgp_log_ring_count();
}

void dna_engine_debug_log_clear(void) {
    qgp_log_ring_clear();
}

void dna_engine_debug_log_message(const char *tag, const char *message) {
    if (!tag || !message) return;
    qgp_log_ring_add(QGP_LOG_LEVEL_INFO, tag, "%s", message);
    qgp_log_file_write(QGP_LOG_LEVEL_INFO, tag, "%s", message);
}

void dna_engine_debug_log_message_level(const char *tag, const char *message, int level) {
    if (!tag || !message) return;
    qgp_log_level_t log_level = (level >= 0 && level <= 3) ? (qgp_log_level_t)level : QGP_LOG_LEVEL_INFO;
    qgp_log_ring_add(log_level, tag, "%s", message);
    qgp_log_file_write(log_level, tag, "%s", message);
}

int dna_engine_debug_log_export(const char *filepath) {
    if (!filepath) return -1;
    return qgp_log_export_to_file(filepath);
}
