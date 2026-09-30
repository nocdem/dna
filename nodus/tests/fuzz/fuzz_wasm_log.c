/**
 * @file fuzz_wasm_log.c
 * @brief QGP log back end for the wasm32 FUZZ build (nodus and messenger).
 *
 * TEST CODE ONLY — linked by the build_wasm32.sh scripts, never shipped.
 *
 * The QGP_LOG_* macros (shared/crypto/utils/qgp_log.h) call
 * qgp_log_should_log, qgp_log_ring_add and qgp_log_file_write. The full
 * qgp_log.c pulls in messenger configuration, and nodus's standalone shim
 * (nodus/src/nodus_log_shim.c) has no qgp_log_set_level, which the
 * messenger harnesses call to silence per-input parse errors. This back end
 * honours the level (default INFO) and prints to stderr; file logging is
 * off.
 */

#include <stdio.h>
#include <stdarg.h>

#include "crypto/utils/qgp_log.h"

static qgp_log_level_t g_level = QGP_LOG_LEVEL_INFO;

void qgp_log_set_level(qgp_log_level_t level) {
    g_level = level;
}

qgp_log_level_t qgp_log_get_level(void) {
    return g_level;
}

bool qgp_log_should_log(qgp_log_level_t level, const char *tag) {
    (void)tag;
    return g_level != QGP_LOG_LEVEL_NONE && level >= g_level;
}

void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    static const char *const names[] = { "DBG", "INF", "WRN", "ERR", "---" };
    const char *name = (level >= QGP_LOG_LEVEL_DEBUG && level <= QGP_LOG_LEVEL_NONE)
                       ? names[level] : "???";
    fprintf(stderr, "[%s/%s] ", name, tag);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    (void)level;
    (void)tag;
    (void)fmt;
}
