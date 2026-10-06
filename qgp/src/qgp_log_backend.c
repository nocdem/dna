/**
 * qgp_log_backend.c - QGP_LOG_* backend for the standalone qgp tool.
 *
 * The shared qgp_log.c depends on the messenger's dna_config.h, so standalone
 * programs provide the three hooks the QGP_LOG_* macros call (nodus does the
 * same). Logs go to stderr; stdout carries command results only.
 * Level: INFO and above by default, DEBUG when QGP_DEBUG=1 in the environment.
 */
#include "crypto/utils/qgp_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_safe_string.h"

bool qgp_log_should_log(qgp_log_level_t level, const char *tag)
{
    (void)tag;
    if (level == QGP_LOG_LEVEL_DEBUG) {
        const char *e = getenv("QGP_DEBUG");
        return e && strcmp(e, "1") == 0;
    }
    return level >= QGP_LOG_LEVEL_INFO && level < QGP_LOG_LEVEL_NONE;
}

void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...)
{
    const char *lvl = "???";
    switch (level) {
    case QGP_LOG_LEVEL_DEBUG: lvl = "DBG"; break;
    case QGP_LOG_LEVEL_INFO:  lvl = "INF"; break;
    case QGP_LOG_LEVEL_WARN:  lvl = "WRN"; break;
    case QGP_LOG_LEVEL_ERROR: lvl = "ERR"; break;
    case QGP_LOG_LEVEL_NONE:  lvl = "---"; break;
    }
    fprintf(stderr, "[%s/%s] ", lvl, tag ? tag : "?");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...)
{
    (void)level;
    (void)tag;
    (void)fmt;
}
