#ifndef QGP_LOG_H
#define QGP_LOG_H

/**
 * qgp_log.h - Cross-platform logging abstraction with selective filtering
 *
 * Provides unified logging API that works on all platforms:
 * - Android: Forwards to __android_log_print (logcat)
 * - Other platforms: Uses standard printf/fprintf
 *
 * Features:
 * - Log level control (DEBUG, INFO, WARN, ERROR)
 * - Tag-based filtering (whitelist/blacklist mode)
 * - Runtime enable/disable of specific tags
 *
 * Usage:
 *   #include "crypto/utils/qgp_log.h"
 *
 *   // Basic logging
 *   QGP_LOG_INFO("MyTag", "Value is %d", value);
 *   QGP_LOG_ERROR("MyTag", "Error: %s", error_msg);
 *
 *   // Enable only specific tags (whitelist mode)
 *   qgp_log_set_filter_mode(QGP_LOG_FILTER_WHITELIST);
 *   qgp_log_enable_tag("DHT");
 *   qgp_log_enable_tag("P2P");
 *
 *   // Disable specific tags (blacklist mode - default)
 *   qgp_log_set_filter_mode(QGP_LOG_FILTER_BLACKLIST);
 *   qgp_log_disable_tag("VERBOSE_TAG");
 *
 *   // Set minimum log level
 *   qgp_log_set_level(QGP_LOG_LEVEL_WARN);  // Only WARN and ERROR
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
typedef enum {
    QGP_LOG_LEVEL_DEBUG = 0,
    QGP_LOG_LEVEL_INFO  = 1,
    QGP_LOG_LEVEL_WARN  = 2,
    QGP_LOG_LEVEL_ERROR = 3,
    QGP_LOG_LEVEL_NONE  = 4   /* Disable all logging */
} qgp_log_level_t;

/* Filter modes */
typedef enum {
    QGP_LOG_FILTER_BLACKLIST = 0,  /* Show all except disabled tags (default) */
    QGP_LOG_FILTER_WHITELIST = 1   /* Show only enabled tags */
} qgp_log_filter_mode_t;

/* Configuration API */
void qgp_log_set_level(qgp_log_level_t level);
qgp_log_level_t qgp_log_get_level(void);

void qgp_log_set_filter_mode(qgp_log_filter_mode_t mode);
qgp_log_filter_mode_t qgp_log_get_filter_mode(void);

void qgp_log_enable_tag(const char *tag);
void qgp_log_disable_tag(const char *tag);
void qgp_log_clear_filters(void);

/* Check if a tag should be logged at given level */
bool qgp_log_should_log(qgp_log_level_t level, const char *tag);

/* Internal logging functions (use macros instead) */
void qgp_log_print(qgp_log_level_t level, const char *tag, const char *fmt, ...);

/* ============================================================================
 * Ring Buffer API - For in-app log viewing (Flutter debug screen)
 * ============================================================================ */

#define QGP_LOG_RING_SIZE 200       /* Number of entries to keep */
#define QGP_LOG_MSG_MAX_LEN 256     /* Max message length per entry */

/* Log entry structure */
typedef struct {
    uint64_t timestamp_ms;          /* Unix timestamp in milliseconds */
    qgp_log_level_t level;          /* Log level */
    char tag[32];                   /* Tag/module name */
    char message[QGP_LOG_MSG_MAX_LEN]; /* Log message */
} qgp_log_entry_t;

/* Enable/disable ring buffer storage (disabled by default for performance) */
void qgp_log_ring_enable(bool enabled);
bool qgp_log_ring_is_enabled(void);

/* Get all log entries (returns count, fills entries array up to max_entries) */
int qgp_log_ring_get_entries(qgp_log_entry_t *entries, int max_entries);

/* Get entry count in ring buffer */
int qgp_log_ring_count(void);

/* Clear all entries */
void qgp_log_ring_clear(void);

/* Export ring buffer to file (returns 0 on success, -1 on error) */
int qgp_log_export_to_file(const char *filepath);

/* Internal: add entry to ring buffer (called by macros) */
void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...);

/* ============================================================================
 * File Logging API - Persistent cross-platform logging with rotation
 * ============================================================================
 * Writes logs to <data_dir>/logs/dna.log with automatic rotation.
 * Thread-safe. Works on Linux, Windows, macOS, Android, iOS.
 */

/**
 * Enable or disable file logging
 *
 * When enabled, logs are written to <data_dir>/logs/dna.log
 * The logs directory is created automatically if it doesn't exist.
 *
 * @param enabled true to enable, false to disable
 */
void qgp_log_file_enable(bool enabled);

/**
 * Check if file logging is enabled
 *
 * @return true if file logging is active
 */
bool qgp_log_file_is_enabled(void);

/**
 * Set file logging rotation options
 *
 * @param max_size_kb  Maximum file size in KB before rotation (default: 5120 = 5MB)
 * @param max_files    Maximum number of rotated files to keep (default: 3)
 *                     e.g., max_files=3 keeps: dna.log, dna.1.log, dna.2.log, dna.3.log
 */
void qgp_log_file_set_options(int max_size_kb, int max_files);

/**
 * Flush and close the log file
 *
 * Call this before app shutdown to ensure all logs are written.
 */
void qgp_log_file_close(void);

/**
 * Get the current log file path
 *
 * @return Path to current log file, or NULL if file logging is disabled
 */
const char* qgp_log_file_get_path(void);

/* Internal: write entry to log file (called by macros) */
void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...);

#if defined(__ANDROID__)
    #include <android/log.h>

    /* All DNA logs use "DNA/" prefix for easy filtering: adb logcat -s "DNA/" */
    /* DEBUG logs are always compiled in and filtered at runtime via qgp_log_should_log() */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_DEBUG, tag)) { \
            __android_log_print(ANDROID_LOG_DEBUG, "DNA/" tag, fmt, ##__VA_ARGS__); \
            qgp_log_ring_add(QGP_LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_INFO, tag)) { \
            __android_log_print(ANDROID_LOG_INFO, "DNA/" tag, fmt, ##__VA_ARGS__); \
            qgp_log_ring_add(QGP_LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_WARN, tag)) { \
            __android_log_print(ANDROID_LOG_WARN, "DNA/" tag, fmt, ##__VA_ARGS__); \
            qgp_log_ring_add(QGP_LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_ERROR, tag)) { \
            __android_log_print(ANDROID_LOG_ERROR, "DNA/" tag, fmt, ##__VA_ARGS__); \
            qgp_log_ring_add(QGP_LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__); \
        } } while(0)

#else
    /* Non-Android: ring buffer + file logging only (no console output) */

    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_DEBUG, tag)) { \
            qgp_log_ring_add(QGP_LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_DEBUG, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_INFO, tag)) { \
            qgp_log_ring_add(QGP_LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_INFO, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_WARN, tag)) { \
            qgp_log_ring_add(QGP_LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_WARN, tag, fmt, ##__VA_ARGS__); \
        } } while(0)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_ERROR, tag)) { \
            qgp_log_ring_add(QGP_LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__); \
            qgp_log_file_write(QGP_LOG_LEVEL_ERROR, tag, fmt, ##__VA_ARGS__); \
        } } while(0)

#endif

#ifdef __cplusplus
}
#endif

#endif /* QGP_LOG_H */
