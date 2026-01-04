/**
 * qgp_log.c - Cross-platform logging implementation with selective filtering
 *
 * Provides runtime control over log output:
 * - Set minimum log level (DEBUG, INFO, WARN, ERROR, NONE)
 * - Filter by tag (whitelist or blacklist mode)
 * - Loads settings from <data_dir>/config on first use
 */

#include "qgp_log.h"
#include "qgp_platform.h"
#include "dna_config.h"
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define stat _stat
#else
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* Maximum number of tags in filter list */
#define QGP_LOG_MAX_TAGS 64
#define QGP_LOG_MAX_TAG_LEN 32

/* Global log configuration */
/* Release builds (NDEBUG defined) default to INFO level */
#ifdef NDEBUG
static qgp_log_level_t g_log_level = QGP_LOG_LEVEL_INFO;
#else
static qgp_log_level_t g_log_level = QGP_LOG_LEVEL_DEBUG;
#endif
static qgp_log_filter_mode_t g_filter_mode = QGP_LOG_FILTER_BLACKLIST;
static bool g_config_loaded = false;

/* Tag filter lists */
static char g_enabled_tags[QGP_LOG_MAX_TAGS][QGP_LOG_MAX_TAG_LEN];
static int g_enabled_count = 0;

static char g_disabled_tags[QGP_LOG_MAX_TAGS][QGP_LOG_MAX_TAG_LEN];
static int g_disabled_count = 0;

/* Load config on first use */
static void ensure_config_loaded(void) {
    if (g_config_loaded) {
        return;
    }
    g_config_loaded = true;

    dna_config_t config;
    memset(&config, 0, sizeof(config));
    dna_config_load(&config);
    dna_config_apply_log_settings(&config);
}

/* Set minimum log level */
void qgp_log_set_level(qgp_log_level_t level) {
    if (level >= QGP_LOG_LEVEL_DEBUG && level <= QGP_LOG_LEVEL_NONE) {
        g_log_level = level;
    }
}

qgp_log_level_t qgp_log_get_level(void) {
    return g_log_level;
}

/* Set filter mode */
void qgp_log_set_filter_mode(qgp_log_filter_mode_t mode) {
    g_filter_mode = mode;
}

qgp_log_filter_mode_t qgp_log_get_filter_mode(void) {
    return g_filter_mode;
}

/* Enable a tag (for whitelist mode) */
void qgp_log_enable_tag(const char *tag) {
    if (!tag || g_enabled_count >= QGP_LOG_MAX_TAGS) {
        return;
    }

    /* Check if already in list */
    for (int i = 0; i < g_enabled_count; i++) {
        if (strcmp(g_enabled_tags[i], tag) == 0) {
            return;  /* Already enabled */
        }
    }

    /* Add to enabled list */
    strncpy(g_enabled_tags[g_enabled_count], tag, QGP_LOG_MAX_TAG_LEN - 1);
    g_enabled_tags[g_enabled_count][QGP_LOG_MAX_TAG_LEN - 1] = '\0';
    g_enabled_count++;

    /* Also remove from disabled list if present */
    for (int i = 0; i < g_disabled_count; i++) {
        if (strcmp(g_disabled_tags[i], tag) == 0) {
            /* Shift remaining tags */
            for (int j = i; j < g_disabled_count - 1; j++) {
                strcpy(g_disabled_tags[j], g_disabled_tags[j + 1]);
            }
            g_disabled_count--;
            break;
        }
    }
}

/* Disable a tag (for blacklist mode) */
void qgp_log_disable_tag(const char *tag) {
    if (!tag || g_disabled_count >= QGP_LOG_MAX_TAGS) {
        return;
    }

    /* Check if already in list */
    for (int i = 0; i < g_disabled_count; i++) {
        if (strcmp(g_disabled_tags[i], tag) == 0) {
            return;  /* Already disabled */
        }
    }

    /* Add to disabled list */
    strncpy(g_disabled_tags[g_disabled_count], tag, QGP_LOG_MAX_TAG_LEN - 1);
    g_disabled_tags[g_disabled_count][QGP_LOG_MAX_TAG_LEN - 1] = '\0';
    g_disabled_count++;

    /* Also remove from enabled list if present */
    for (int i = 0; i < g_enabled_count; i++) {
        if (strcmp(g_enabled_tags[i], tag) == 0) {
            /* Shift remaining tags */
            for (int j = i; j < g_enabled_count - 1; j++) {
                strcpy(g_enabled_tags[j], g_enabled_tags[j + 1]);
            }
            g_enabled_count--;
            break;
        }
    }
}

/* Clear all tag filters */
void qgp_log_clear_filters(void) {
    g_enabled_count = 0;
    g_disabled_count = 0;
}

/* Check if tag is in enabled list */
static bool is_tag_enabled(const char *tag) {
    for (int i = 0; i < g_enabled_count; i++) {
        if (strcmp(g_enabled_tags[i], tag) == 0) {
            return true;
        }
    }
    return false;
}

/* Check if tag is in disabled list */
static bool is_tag_disabled(const char *tag) {
    for (int i = 0; i < g_disabled_count; i++) {
        if (strcmp(g_disabled_tags[i], tag) == 0) {
            return true;
        }
    }
    return false;
}

/* Check if a tag should be logged at given level */
bool qgp_log_should_log(qgp_log_level_t level, const char *tag) {
    /* Load config on first call */
    ensure_config_loaded();

    /* Check log level first */
    if (level < g_log_level) {
        return false;
    }

    /* Check tag filters */
    if (g_filter_mode == QGP_LOG_FILTER_WHITELIST) {
        /* Whitelist mode: only show enabled tags */
        if (g_enabled_count == 0) {
            return true;  /* No whitelist = show all */
        }
        return is_tag_enabled(tag);
    } else {
        /* Blacklist mode: show all except disabled tags */
        return !is_tag_disabled(tag);
    }
}

/* Generic print function (for potential future use) */
void qgp_log_print(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    if (!qgp_log_should_log(level, tag)) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    const char *level_str;
    FILE *out = stdout;

    switch (level) {
        case QGP_LOG_LEVEL_DEBUG:
            level_str = "DEBUG";
            break;
        case QGP_LOG_LEVEL_INFO:
            level_str = "";
            break;
        case QGP_LOG_LEVEL_WARN:
            level_str = "WARN";
            out = stderr;
            break;
        case QGP_LOG_LEVEL_ERROR:
            level_str = "ERROR";
            out = stderr;
            break;
        default:
            level_str = "";
            break;
    }

    if (level_str[0] != '\0') {
        fprintf(out, "[%s] %s: ", tag, level_str);
    } else {
        fprintf(out, "[%s] ", tag);
    }

    vfprintf(out, fmt, args);
    fprintf(out, "\n");
    fflush(out);

    va_end(args);
}

/* ============================================================================
 * Ring Buffer Implementation
 * ============================================================================ */

static qgp_log_entry_t g_ring_buffer[QGP_LOG_RING_SIZE];
static int g_ring_head = 0;      /* Next write position */
static int g_ring_count = 0;     /* Number of entries in buffer */
static bool g_ring_enabled = false;
static pthread_mutex_t g_ring_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Get current time in milliseconds */
static uint64_t get_timestamp_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (t / 10000) - 11644473600000ULL;  /* Convert to Unix epoch ms */
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

void qgp_log_ring_enable(bool enabled) {
    pthread_mutex_lock(&g_ring_mutex);
    g_ring_enabled = enabled;
    if (!enabled) {
        /* Clear buffer when disabled */
        g_ring_head = 0;
        g_ring_count = 0;
    }
    pthread_mutex_unlock(&g_ring_mutex);
}

bool qgp_log_ring_is_enabled(void) {
    return g_ring_enabled;
}

void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    if (!g_ring_enabled) {
        return;
    }

    pthread_mutex_lock(&g_ring_mutex);

    qgp_log_entry_t *entry = &g_ring_buffer[g_ring_head];

    entry->timestamp_ms = get_timestamp_ms();
    entry->level = level;

    strncpy(entry->tag, tag, sizeof(entry->tag) - 1);
    entry->tag[sizeof(entry->tag) - 1] = '\0';

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry->message, sizeof(entry->message), fmt, args);
    va_end(args);

    /* Strip trailing newlines */
    size_t len = strlen(entry->message);
    while (len > 0 && (entry->message[len - 1] == '\n' || entry->message[len - 1] == '\r')) {
        entry->message[--len] = '\0';
    }

    /* Advance head (circular) */
    g_ring_head = (g_ring_head + 1) % QGP_LOG_RING_SIZE;
    if (g_ring_count < QGP_LOG_RING_SIZE) {
        g_ring_count++;
    }

    pthread_mutex_unlock(&g_ring_mutex);
}

int qgp_log_ring_count(void) {
    pthread_mutex_lock(&g_ring_mutex);
    int count = g_ring_count;
    pthread_mutex_unlock(&g_ring_mutex);
    return count;
}

int qgp_log_ring_get_entries(qgp_log_entry_t *entries, int max_entries) {
    if (!entries || max_entries <= 0) {
        return 0;
    }

    pthread_mutex_lock(&g_ring_mutex);

    int count = (g_ring_count < max_entries) ? g_ring_count : max_entries;

    /* Calculate start position (oldest entry) */
    int start;
    if (g_ring_count < QGP_LOG_RING_SIZE) {
        start = 0;
    } else {
        start = g_ring_head;  /* Oldest is at head when buffer is full */
    }

    /* Copy entries in chronological order */
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % QGP_LOG_RING_SIZE;
        memcpy(&entries[i], &g_ring_buffer[idx], sizeof(qgp_log_entry_t));
    }

    pthread_mutex_unlock(&g_ring_mutex);

    return count;
}

void qgp_log_ring_clear(void) {
    pthread_mutex_lock(&g_ring_mutex);
    g_ring_head = 0;
    g_ring_count = 0;
    pthread_mutex_unlock(&g_ring_mutex);
}

int qgp_log_export_to_file(const char *filepath) {
    if (!filepath) {
        return -1;
    }

    FILE *f = fopen(filepath, "w");
    if (!f) {
        return -1;
    }

    pthread_mutex_lock(&g_ring_mutex);

    /* Write header */
    fprintf(f, "DNA Messenger Log Export\n");
    fprintf(f, "========================\n");
    fprintf(f, "Entries: %d\n\n", g_ring_count);

    if (g_ring_count > 0) {
        /* Calculate start position (oldest entry) */
        int start;
        if (g_ring_count < QGP_LOG_RING_SIZE) {
            start = 0;
        } else {
            start = g_ring_head;
        }

        /* Write entries in chronological order */
        for (int i = 0; i < g_ring_count; i++) {
            int idx = (start + i) % QGP_LOG_RING_SIZE;
            qgp_log_entry_t *entry = &g_ring_buffer[idx];

            /* Format timestamp */
            time_t secs = entry->timestamp_ms / 1000;
            int ms = entry->timestamp_ms % 1000;
            struct tm *tm_info = localtime(&secs);

            char time_buf[32];
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

            /* Level string */
            const char *level_str;
            switch (entry->level) {
                case QGP_LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
                case QGP_LOG_LEVEL_INFO:  level_str = "INFO "; break;
                case QGP_LOG_LEVEL_WARN:  level_str = "WARN "; break;
                case QGP_LOG_LEVEL_ERROR: level_str = "ERROR"; break;
                default: level_str = "?????"; break;
            }

            fprintf(f, "%s.%03d [%s] %s: %s\n",
                    time_buf, ms, level_str, entry->tag, entry->message);
        }
    }

    pthread_mutex_unlock(&g_ring_mutex);

    fclose(f);
    return 0;
}

/* ============================================================================
 * File Logging Implementation - Cross-platform with rotation
 * ============================================================================ */

#define QGP_LOG_FILE_DEFAULT_MAX_SIZE_KB 51200  /* 50 MB default */
#define QGP_LOG_FILE_DEFAULT_MAX_FILES 3       /* Keep 3 rotated files */
#define QGP_LOG_FILE_PATH_MAX 512

static FILE *g_log_file = NULL;
static bool g_file_logging_enabled = false;
static int g_file_max_size_kb = QGP_LOG_FILE_DEFAULT_MAX_SIZE_KB;
static int g_file_max_files = QGP_LOG_FILE_DEFAULT_MAX_FILES;
static char g_log_file_path[QGP_LOG_FILE_PATH_MAX] = {0};
static char g_log_dir_path[QGP_LOG_FILE_PATH_MAX] = {0};
static pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_file_init_attempted = false;

/* Get file size in bytes (cross-platform) */
static long get_file_size(FILE *f) {
    if (!f) return 0;
    long current_pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, current_pos, SEEK_SET);
    return size;
}

/* Build log directory and file paths */
static void build_log_paths(void) {
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        return;
    }

    /* Build logs directory path */
#ifdef _WIN32
    snprintf(g_log_dir_path, sizeof(g_log_dir_path), "%s\\logs", data_dir);
    snprintf(g_log_file_path, sizeof(g_log_file_path), "%s\\dna.log", g_log_dir_path);
#else
    snprintf(g_log_dir_path, sizeof(g_log_dir_path), "%s/logs", data_dir);
    snprintf(g_log_file_path, sizeof(g_log_file_path), "%s/dna.log", g_log_dir_path);
#endif
}

/* Rotate log files: dna.log -> dna.1.log -> dna.2.log -> ... -> delete oldest */
static void rotate_log_files(void) {
    if (g_log_file_path[0] == '\0') {
        return;
    }

    char old_path[QGP_LOG_FILE_PATH_MAX];
    char new_path[QGP_LOG_FILE_PATH_MAX];

    /* Close current file before rotation */
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    /* Delete oldest file if it exists (e.g., dna.3.log when max_files=3) */
#ifdef _WIN32
    snprintf(old_path, sizeof(old_path), "%s\\dna.%d.log", g_log_dir_path, g_file_max_files);
#else
    snprintf(old_path, sizeof(old_path), "%s/dna.%d.log", g_log_dir_path, g_file_max_files);
#endif
    remove(old_path);

    /* Shift existing rotated files: dna.2.log -> dna.3.log, dna.1.log -> dna.2.log, etc. */
    for (int i = g_file_max_files - 1; i >= 1; i--) {
#ifdef _WIN32
        snprintf(old_path, sizeof(old_path), "%s\\dna.%d.log", g_log_dir_path, i);
        snprintf(new_path, sizeof(new_path), "%s\\dna.%d.log", g_log_dir_path, i + 1);
#else
        snprintf(old_path, sizeof(old_path), "%s/dna.%d.log", g_log_dir_path, i);
        snprintf(new_path, sizeof(new_path), "%s/dna.%d.log", g_log_dir_path, i + 1);
#endif
        rename(old_path, new_path);  /* Fails silently if old_path doesn't exist */
    }

    /* Rotate current log: dna.log -> dna.1.log */
#ifdef _WIN32
    snprintf(new_path, sizeof(new_path), "%s\\dna.1.log", g_log_dir_path);
#else
    snprintf(new_path, sizeof(new_path), "%s/dna.1.log", g_log_dir_path);
#endif
    rename(g_log_file_path, new_path);

    /* Reopen fresh log file */
    g_log_file = fopen(g_log_file_path, "a");
}

/* Initialize file logging (called on first write) */
static bool init_file_logging(void) {
    if (g_file_init_attempted) {
        return g_log_file != NULL;
    }
    g_file_init_attempted = true;

    /* Build paths if not already done */
    if (g_log_file_path[0] == '\0') {
        build_log_paths();
    }

    if (g_log_file_path[0] == '\0') {
        /* Log to ring buffer (viewable in-app) even if file logging fails */
        qgp_log_ring_add(QGP_LOG_LEVEL_ERROR, "LOG", "init_file_logging: No data directory");
        return false;
    }

    /* Log paths to ring buffer for debugging */
    qgp_log_ring_add(QGP_LOG_LEVEL_DEBUG, "LOG", "init_file_logging: dir='%s' file='%s'",
                     g_log_dir_path, g_log_file_path);

    /* Create logs directory if it doesn't exist */
    if (qgp_platform_mkdir(g_log_dir_path) != 0 && errno != EEXIST) {
        if (!qgp_platform_file_exists(g_log_dir_path)) {
            qgp_log_ring_add(QGP_LOG_LEVEL_ERROR, "LOG", "mkdir failed: dir='%s' errno=%d",
                             g_log_dir_path, errno);
            return false;
        }
    }

    /* Open log file in append mode */
    g_log_file = fopen(g_log_file_path, "a");
    if (!g_log_file) {
        qgp_log_ring_add(QGP_LOG_LEVEL_ERROR, "LOG", "fopen failed: file='%s' errno=%d",
                         g_log_file_path, errno);
        return false;
    }

    qgp_log_ring_add(QGP_LOG_LEVEL_INFO, "LOG", "File logging started: %s", g_log_file_path);

    /* Write startup marker */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(g_log_file, "\n=== DNA Messenger Log Started: %s ===\n", time_buf);
    fflush(g_log_file);

    return true;
}

void qgp_log_file_enable(bool enabled) {
    pthread_mutex_lock(&g_file_mutex);
    g_file_logging_enabled = enabled;

    if (enabled && !g_log_file) {
        init_file_logging();
    } else if (!enabled && g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    pthread_mutex_unlock(&g_file_mutex);
}

bool qgp_log_file_is_enabled(void) {
    return g_file_logging_enabled;
}

void qgp_log_file_set_options(int max_size_kb, int max_files) {
    pthread_mutex_lock(&g_file_mutex);
    if (max_size_kb > 0) {
        g_file_max_size_kb = max_size_kb;
    }
    if (max_files > 0 && max_files <= 10) {
        g_file_max_files = max_files;
    }
    pthread_mutex_unlock(&g_file_mutex);
}

void qgp_log_file_close(void) {
    pthread_mutex_lock(&g_file_mutex);
    if (g_log_file) {
        /* Write shutdown marker */
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(g_log_file, "=== DNA Messenger Log Closed: %s ===\n\n", time_buf);

        fflush(g_log_file);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    g_file_init_attempted = false;
    pthread_mutex_unlock(&g_file_mutex);
}

const char* qgp_log_file_get_path(void) {
    if (!g_file_logging_enabled || g_log_file_path[0] == '\0') {
        return NULL;
    }
    return g_log_file_path;
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    if (!g_file_logging_enabled) {
        return;
    }

    pthread_mutex_lock(&g_file_mutex);

    /* Initialize on first write */
    if (!g_log_file && !init_file_logging()) {
        pthread_mutex_unlock(&g_file_mutex);
        return;
    }

    /* Check file size and rotate if needed */
    long current_size = get_file_size(g_log_file);
    if (current_size > (long)g_file_max_size_kb * 1024) {
        rotate_log_files();
        if (!g_log_file) {
            pthread_mutex_unlock(&g_file_mutex);
            return;
        }
    }

    /* Get timestamp */
    uint64_t timestamp_ms;
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    timestamp_ms = (t / 10000) - 11644473600000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    timestamp_ms = (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif

    /* Format timestamp */
    time_t secs = (time_t)(timestamp_ms / 1000);
    int ms = (int)(timestamp_ms % 1000);
    struct tm *tm_info = localtime(&secs);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Level string */
    const char *level_str;
    switch (level) {
        case QGP_LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case QGP_LOG_LEVEL_INFO:  level_str = "INFO "; break;
        case QGP_LOG_LEVEL_WARN:  level_str = "WARN "; break;
        case QGP_LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        default: level_str = "?????"; break;
    }

    /* Format message to buffer first so we can strip trailing newlines */
    char msg_buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    /* Strip trailing newlines/whitespace */
    size_t len = strlen(msg_buf);
    while (len > 0 && (msg_buf[len - 1] == '\n' || msg_buf[len - 1] == '\r')) {
        msg_buf[--len] = '\0';
    }

    /* Write log entry with single newline */
    fprintf(g_log_file, "%s.%03d [%s] %s: %s\n", time_buf, ms, level_str, tag, msg_buf);
    fflush(g_log_file);

    pthread_mutex_unlock(&g_file_mutex);
}
