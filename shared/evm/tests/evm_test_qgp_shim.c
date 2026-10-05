/**
 * @file evm_test_qgp_shim.c
 * @brief Link support for shared/crypto/hash/keccak256.c in the standalone
 *        EVM test programs — TEST-ONLY.
 *
 * keccak256.c logs through the QGP_LOG_* macros (qgp_log.h) and wipes its
 * buffers with qgp_secure_memzero (qgp_platform.h). The real providers
 * (crypto/utils/qgp_log.c, qgp_platform_linux.c) pull in the messenger's
 * dna_config.h and platform layer, which the standalone test build does not
 * have. This file gives functional equivalents of exactly the symbols the
 * macros and keccak256.c reference:
 *   - WARN and ERROR messages are written to stderr; DEBUG/INFO are dropped
 *   - the ring buffer is not kept (no viewer in a test run)
 *   - qgp_secure_memzero wipes through a volatile pointer
 * If the engine library (libevm.a) ever provides these symbols itself, drop
 * this object from the link (Makefile.statetest: QGP_SHIM_OBJ=).
 */
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#include <stdarg.h>
#include <stdio.h>

bool qgp_log_should_log(qgp_log_level_t level, const char *tag)
{
    (void)tag;
    return level >= QGP_LOG_LEVEL_WARN;
}

void qgp_log_ring_add(qgp_log_level_t level, const char *tag,
                      const char *fmt, ...)
{
    (void)level;
    (void)tag;
    (void)fmt;
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag,
                        const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[%s] %s: ",
            level >= QGP_LOG_LEVEL_ERROR ? "ERROR" : "WARN", tag);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void qgp_secure_memzero(void *ptr, size_t len)
{
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}
