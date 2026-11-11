/**
 * Nodus — Minimal log shim
 *
 * Provides qgp_log_should_log(), qgp_log_ring_add(), qgp_log_file_write()
 * stubs required by qgp_platform_linux.c and other shared crypto code.
 * This avoids pulling in the full qgp_log.c which depends on dna_config.h.
 *
 * qgp_log_file_write() is a no-op until nodus_log_file_open() (nodus_log_shim.h)
 * is called; then it appends a timestamped line to the opt-in log file.
 */

#define _GNU_SOURCE
#include "crypto/utils/qgp_log.h"
#include "nodus_log_shim.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_FILE_NAME      "nodus-amm.log"
#define LOG_DIR_MAX        200
#define LOG_PATH_MAX       (LOG_DIR_MAX + 1 + sizeof(LOG_FILE_NAME) + 12)
#define LOG_LINE_MAX       1024

bool qgp_log_should_log(qgp_log_level_t level, const char *tag) {
    (void)tag;
    /* For nodus standalone, log INFO and above */
    return level >= QGP_LOG_LEVEL_INFO;
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

/* ── the opt-in log file ─────────────────────────────────────────────── */

static atomic_int      g_file_on = 0;        /* set only between open and close */
static pthread_mutex_t g_file_mu = PTHREAD_MUTEX_INITIALIZER;
static int             g_fd = -1;
static char            g_path[LOG_PATH_MAX];
static size_t          g_max_bytes;
static int             g_keep;
static size_t          g_size;               /* bytes in the current file       */

/* open the current file; g_mu held. 0 / -1 */
static int open_current(void) {
    int fd = open(g_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0640);
    if (fd < 0) return -1;
    struct stat st;
    g_size = fstat(fd, &st) == 0 ? (size_t)st.st_size : 0;
    g_fd = fd;
    return 0;
}

/* "<file>.1" ... "<file>.<keep>"; the oldest is dropped; g_mu held */
static void rotate(void) {
    close(g_fd);
    g_fd = -1;
    char from[LOG_PATH_MAX + 8], to[LOG_PATH_MAX + 8];
    snprintf(to, sizeof(to), "%s.%d", g_path, g_keep);
    unlink(to);
    for (int i = g_keep - 1; i >= 1; i--) {
        snprintf(from, sizeof(from), "%s.%d", g_path, i);
        snprintf(to, sizeof(to), "%s.%d", g_path, i + 1);
        (void)rename(from, to);
    }
    snprintf(to, sizeof(to), "%s.1", g_path);
    (void)rename(g_path, to);
    (void)open_current();                    /* on failure g_fd stays -1; the next call retries */
}

int nodus_log_file_open(const char *dir, size_t max_bytes, int keep_files) {
    if (!dir || !*dir || strlen(dir) > LOG_DIR_MAX || max_bytes == 0 || keep_files < 1)
        return -1;
    pthread_mutex_lock(&g_file_mu);
    atomic_store(&g_file_on, 0);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    (void)mkdir(dir, 0750);                  /* an existing directory is fine; open() decides */
    snprintf(g_path, sizeof(g_path), "%s/%s", dir, LOG_FILE_NAME);
    g_max_bytes = max_bytes;
    g_keep = keep_files;
    int rc = open_current();
    if (rc == 0) atomic_store(&g_file_on, 1);
    pthread_mutex_unlock(&g_file_mu);
    return rc;
}

void nodus_log_file_close(void) {
    pthread_mutex_lock(&g_file_mu);
    atomic_store(&g_file_on, 0);
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    pthread_mutex_unlock(&g_file_mu);
}

void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {
    if (!atomic_load(&g_file_on)) return;    /* the default: nothing, no lock */

    const char *level_str = "???";
    switch (level) {
        case QGP_LOG_LEVEL_NONE:  level_str = "---"; break;
        case QGP_LOG_LEVEL_DEBUG: level_str = "DBG"; break;
        case QGP_LOG_LEVEL_INFO:  level_str = "INF"; break;
        case QGP_LOG_LEVEL_WARN:  level_str = "WRN"; break;
        case QGP_LOG_LEVEL_ERROR: level_str = "ERR"; break;
    }

    char line[LOG_LINE_MAX];
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    time_t secs = ts.tv_sec;
    char stamp[32] = "0000-00-00T00:00:00";
    if (gmtime_r(&secs, &tm)) strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);
    int n = snprintf(line, sizeof(line) - 1, "%s.%03ldZ [%s] %s: ", stamp,
                     ts.tv_nsec / 1000000L, level_str, tag ? tag : "?");
    if (n < 0 || n >= (int)sizeof(line) - 1) return;
    va_list args;
    va_start(args, fmt);
    int m = vsnprintf(line + n, sizeof(line) - 1 - (size_t)n, fmt, args);
    va_end(args);
    if (m < 0) return;
    size_t len = (size_t)n + (size_t)m;
    if (len > sizeof(line) - 2) len = sizeof(line) - 2;      /* cut, never overflow */
    for (size_t i = (size_t)n; i < len; i++)
        if (line[i] == '\n' || line[i] == '\r') line[i] = ' ';
    while (len > (size_t)n && line[len - 1] == ' ') len--;   /* trailing newlines */
    line[len++] = '\n';

    pthread_mutex_lock(&g_file_mu);
    if (atomic_load(&g_file_on)) {
        if (g_fd < 0) (void)open_current();                  /* a failed rotation: retry */
        if (g_fd >= 0 && g_size >= g_max_bytes) rotate();
        if (g_fd >= 0) {
            /* the whole line: EINTR is retried, a short write continues with the
             * rest; any other error (or a write of 0 bytes) drops the rest of the
             * line. g_size counts only the bytes that were written. */
            size_t off = 0;
            while (off < len) {
                ssize_t w = write(g_fd, line + off, len - off);
                if (w > 0) { off += (size_t)w; g_size += (size_t)w; continue; }
                if (w < 0 && errno == EINTR) continue;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_file_mu);
}
