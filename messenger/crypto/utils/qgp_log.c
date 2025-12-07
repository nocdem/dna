/**
 * qgp_log.c - Cross-platform logging implementation with selective filtering
 *
 * Provides runtime control over log output:
 * - Set minimum log level (DEBUG, INFO, WARN, ERROR, NONE)
 * - Filter by tag (whitelist or blacklist mode)
 */

#include "qgp_log.h"
#include <string.h>
#include <stdarg.h>

/* Maximum number of tags in filter list */
#define QGP_LOG_MAX_TAGS 64
#define QGP_LOG_MAX_TAG_LEN 32

/* Global log configuration (thread-safe via simple atomics would be ideal) */
static qgp_log_level_t g_log_level = QGP_LOG_LEVEL_DEBUG;  /* Show all by default */
static qgp_log_filter_mode_t g_filter_mode = QGP_LOG_FILTER_BLACKLIST;

/* Tag filter lists */
static char g_enabled_tags[QGP_LOG_MAX_TAGS][QGP_LOG_MAX_TAG_LEN];
static int g_enabled_count = 0;

static char g_disabled_tags[QGP_LOG_MAX_TAGS][QGP_LOG_MAX_TAG_LEN];
static int g_disabled_count = 0;

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

    va_end(args);
}
