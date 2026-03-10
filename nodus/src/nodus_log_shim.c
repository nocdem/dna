/**
 * Nodus — Minimal log shim
 *
 * Provides qgp_log_should_log(), qgp_log_ring_add(), qgp_log_file_write()
 * stubs required by qgp_platform_linux.c and other shared crypto code.
 * This avoids pulling in the full qgp_log.c which depends on dna_config.h.
 */

#include "crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdarg.h>

bool qgp_log_should_log(qgp_log_level_t level, const char *tag) {
    (void)tag;
    /* For nodus standalone, log WARN and above */
    return level >= QGP_LOG_LEVEL_WARN;
}

void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    const char *level_str = "???";
    switch (level) {
        case QGP_LOG_LEVEL_NONE:  level_str = "---"; break;
        case QGP_LOG_LEVEL_DEBUG: level_str = "DBG"; break;
        case QGP_LOG_LEVEL_INFO:  level_str = "INF"; break;
        case QGP_LOG_LEVEL_WARN:  level_str = "WRN"; break;
        case QGP_LOG_LEVEL_ERROR: level_str = "ERR"; break;
    }

    fprintf(stderr, "[%s/%s] ", level_str, tag);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    /* No file logging in standalone nodus */
    (void)level;
    (void)tag;
    (void)fmt;
}
