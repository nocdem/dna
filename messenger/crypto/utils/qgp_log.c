/**
 * qgp_log.c - Cross-platform logging implementation with selective filtering
 *
 * Provides runtime control over log output:
 * - Set minimum log level (DEBUG, INFO, WARN, ERROR, NONE)
 * - Filter by tag (whitelist or blacklist mode)
 * - Loads settings from <data_dir>/config on first use
 */

#include "qgp_log.h"
#include "dna_config.h"
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
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
