#ifndef QGP_LOG_H
#define QGP_LOG_H

/**
 * qgp_log.h - Cross-platform logging abstraction
 *
 * Provides unified logging API that works on all platforms:
 * - Android: Forwards to __android_log_print (logcat)
 * - Other platforms: Uses standard printf/fprintf
 *
 * Usage:
 *   #include "crypto/utils/qgp_log.h"
 *
 *   QGP_LOG_INFO("MyTag", "Value is %d", value);
 *   QGP_LOG_ERROR("MyTag", "Error: %s", error_msg);
 *   QGP_LOG_DEBUG("MyTag", "Debug info");
 *   QGP_LOG_WARN("MyTag", "Warning message");
 */

#include <stdio.h>

#if defined(__ANDROID__)
    #include <android/log.h>

    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_DEBUG, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_INFO, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_WARN, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_ERROR, tag, fmt, ##__VA_ARGS__)

#else
    /* Non-Android: use standard stdio */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        fprintf(stdout, "[%s] DEBUG: " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        fprintf(stdout, "[%s] " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        fprintf(stderr, "[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        fprintf(stderr, "[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__)

#endif

#endif /* QGP_LOG_H */
