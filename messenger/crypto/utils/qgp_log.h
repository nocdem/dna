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

#if defined(__ANDROID__)
    #include <android/log.h>

    /* All DNA logs use "DNA/" prefix for easy filtering: adb logcat -s "DNA/" */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_DEBUG, tag)) \
            __android_log_print(ANDROID_LOG_DEBUG, "DNA/" tag, fmt, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_INFO, tag)) \
            __android_log_print(ANDROID_LOG_INFO, "DNA/" tag, fmt, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_WARN, tag)) \
            __android_log_print(ANDROID_LOG_WARN, "DNA/" tag, fmt, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_ERROR, tag)) \
            __android_log_print(ANDROID_LOG_ERROR, "DNA/" tag, fmt, ##__VA_ARGS__); } while(0)

#else
    /* Non-Android: use standard stdio with filtering */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_DEBUG, tag)) \
            fprintf(stdout, "[%s] DEBUG: " fmt "\n", tag, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_INFO, tag)) \
            fprintf(stdout, "[%s] " fmt "\n", tag, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_WARN, tag)) \
            fprintf(stderr, "[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__); } while(0)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        do { if (qgp_log_should_log(QGP_LOG_LEVEL_ERROR, tag)) \
            fprintf(stderr, "[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__); } while(0)

#endif

#ifdef __cplusplus
}
#endif

#endif /* QGP_LOG_H */
