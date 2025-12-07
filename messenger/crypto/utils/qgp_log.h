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
 *   #include "qgp_log.h"
 *
 *   QGP_LOG_INFO("MyTag", "Value is %d", value);
 *   QGP_LOG_ERROR("MyTag", "Error: %s", error_msg);
 *   QGP_LOG_DEBUG("MyTag", "Debug info");
 *
 * For existing code using printf/fprintf, include this header AFTER stdio.h
 * and define QGP_LOG_TAG before including:
 *
 *   #include <stdio.h>
 *   #define QGP_LOG_TAG "DHT"
 *   #define QGP_LOG_REDIRECT_STDIO 1
 *   #include "qgp_log.h"
 *
 * This will redirect printf() -> QGP_LOG_INFO and fprintf(stderr, ...) -> QGP_LOG_ERROR
 */

#include <stdio.h>

#if defined(__ANDROID__)
    #include <android/log.h>

    /* Direct logging API */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_DEBUG, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_INFO, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_WARN, tag, fmt, ##__VA_ARGS__)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        __android_log_print(ANDROID_LOG_ERROR, tag, fmt, ##__VA_ARGS__)

    /* Stdio redirection (use with QGP_LOG_REDIRECT_STDIO=1 and QGP_LOG_TAG defined) */
    #if defined(QGP_LOG_REDIRECT_STDIO) && defined(QGP_LOG_TAG)
        /* Redirect printf to logcat INFO */
        #undef printf
        #define printf(fmt, ...) \
            __android_log_print(ANDROID_LOG_INFO, QGP_LOG_TAG, fmt, ##__VA_ARGS__)

        /* Redirect fprintf to logcat (stderr->ERROR, stdout->INFO) */
        #undef fprintf
        #define fprintf(stream, fmt, ...) \
            ((stream) == stderr \
                ? __android_log_print(ANDROID_LOG_ERROR, QGP_LOG_TAG, fmt, ##__VA_ARGS__) \
                : __android_log_print(ANDROID_LOG_INFO, QGP_LOG_TAG, fmt, ##__VA_ARGS__))
    #endif

#else
    /* Non-Android: use standard stdio */
    #define QGP_LOG_DEBUG(tag, fmt, ...) \
        fprintf(stdout, "[%s] DEBUG: " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_INFO(tag, fmt, ...) \
        fprintf(stdout, "[%s] INFO: " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_WARN(tag, fmt, ...) \
        fprintf(stderr, "[%s] WARN: " fmt "\n", tag, ##__VA_ARGS__)
    #define QGP_LOG_ERROR(tag, fmt, ...) \
        fprintf(stderr, "[%s] ERROR: " fmt "\n", tag, ##__VA_ARGS__)

    /* No redirection needed on non-Android */
#endif

#endif /* QGP_LOG_H */
