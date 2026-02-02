#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "PLATFORM"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>
#include <sys/file.h>  /* For flock() */

#ifdef __linux__
#include <sys/random.h>
#endif

/* ============================================================================
 * Random Number Generation (Linux Implementation)
 * ============================================================================ */

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

#ifdef __linux__
    /* Try getrandom() syscall first (Linux 3.17+) */
    ssize_t ret = getrandom(buf, len, 0);
    if (ret >= 0 && (size_t)ret == len) {
        return 0;  /* Success */
    }

    /* If getrandom() failed (older kernel), fall through to /dev/urandom */
    if (ret < 0 && errno != ENOSYS) {
        /* Real error, not just "syscall not available" */
        QGP_LOG_ERROR(LOG_TAG, "getrandom() failed: %s", strerror(errno));
        /* Continue to fallback */
    }
#endif

    /* Fallback: /dev/urandom (always available on Linux) */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open /dev/urandom: %s", strerror(errno));
        return -1;
    }

    size_t bytes_read = fread(buf, 1, len, fp);
    fclose(fp);

    if (bytes_read != len) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read %zu bytes from /dev/urandom (got %zu)",
                len, bytes_read);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Directory Operations (Linux Implementation)
 * ============================================================================ */

int qgp_platform_mkdir(const char *path) {
    if (!path) {
        return -1;
    }

    /* Create directory with owner-only permissions (rwx------) */
    if (mkdir(path, 0700) != 0) {
        if (errno == EEXIST) {
            /* Directory already exists - check if it's actually a directory */
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                return 0;  /* Already exists as directory, that's fine */
            }
        }
        return -1;
    }

    return 0;
}

int qgp_platform_file_exists(const char *path) {
    if (!path) {
        return 0;
    }

    return (access(path, F_OK) == 0) ? 1 : 0;
}

int qgp_platform_is_directory(const char *path) {
    if (!path) {
        return 0;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return 0;  /* stat() failed, not a directory */
    }

    return S_ISDIR(st.st_mode) ? 1 : 0;
}

int qgp_platform_rmdir_recursive(const char *path) {
    if (!path) {
        return -1;
    }

    DIR *dir = opendir(path);
    if (!dir) {
        return -1;
    }

    struct dirent *entry;
    char child_path[4096];
    int result = 0;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name);

        if (qgp_platform_is_directory(child_path)) {
            /* Recurse into subdirectory */
            if (qgp_platform_rmdir_recursive(child_path) != 0) {
                result = -1;
            }
        } else {
            /* Delete file */
            if (unlink(child_path) != 0) {
                result = -1;
            }
        }
    }
    closedir(dir);

    /* Remove the now-empty directory */
    if (rmdir(path) != 0) {
        result = -1;
    }

    return result;
}

int qgp_platform_read_file(const char *path, uint8_t **data, size_t *size) {
    if (!path || !data || !size) {
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0) {
        fclose(f);
        return -1;
    }

    /* Allocate buffer */
    *data = malloc((size_t)file_size);
    if (!*data) {
        fclose(f);
        return -1;
    }

    /* Read data */
    size_t read_bytes = fread(*data, 1, (size_t)file_size, f);
    fclose(f);

    if (read_bytes != (size_t)file_size) {
        free(*data);
        *data = NULL;
        return -1;
    }

    *size = (size_t)file_size;
    return 0;
}

int qgp_platform_write_file(const char *path, const uint8_t *data, size_t size) {
    if (!path || !data) {
        return -1;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }

    size_t written = fwrite(data, 1, size, f);
    fclose(f);

    if (written != size) {
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Path Operations (Linux Implementation)
 * ============================================================================ */

const char* qgp_platform_home_dir(void) {
    const char *home = getenv("HOME");
    if (!home) {
        /* Fallback: Try to get from /etc/passwd */
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }

    if (!home) {
        /* CRITICAL: Cannot determine home directory */
        QGP_LOG_ERROR(LOG_TAG, "FATAL: Cannot determine home directory (HOME not set and getpwuid failed)");
        return NULL;
    }

    return home;
}

char* qgp_platform_join_path(const char *dir, const char *file) {
    if (!dir || !file) {
        return NULL;
    }

    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);

    /* Check if dir already ends with '/' */
    int need_separator = (dir_len > 0 && dir[dir_len - 1] != '/') ? 1 : 0;

    /* Allocate: dir + '/' + file + '\0' */
    size_t total_len = dir_len + need_separator + file_len + 1;
    char *result = malloc(total_len);
    if (!result) {
        return NULL;
    }

    /* Copy dir */
    memcpy(result, dir, dir_len);
    size_t pos = dir_len;

    /* Add separator if needed */
    if (need_separator) {
        result[pos++] = '/';
    }

    /* Copy file */
    memcpy(result + pos, file, file_len);
    result[pos + file_len] = '\0';

    return result;
}

/* ============================================================================
 * Application Data Directories (Linux Implementation)
 * ============================================================================ */

/* Static storage for app directories (set via qgp_platform_set_app_dirs) */
static char g_app_data_dir[4096] = {0};
static char g_app_cache_dir[4096] = {0};
static int g_dirs_initialized = 0;

const char* qgp_platform_app_data_dir(void) {
    /* If already set via qgp_platform_set_app_dirs, return that */
    if (g_dirs_initialized && g_app_data_dir[0]) {
        return g_app_data_dir;
    }

    /* Default for Linux: ~/.dna */
    const char *home = qgp_platform_home_dir();
    if (!home) {
        return NULL;
    }

    /* Build path ~/.dna */
    snprintf(g_app_data_dir, sizeof(g_app_data_dir), "%s/.dna", home);

    /* Create directory if it doesn't exist */
    qgp_platform_mkdir(g_app_data_dir);

    return g_app_data_dir;
}

const char* qgp_platform_cache_dir(void) {
    /* If already set via qgp_platform_set_app_dirs, return that */
    if (g_dirs_initialized && g_app_cache_dir[0]) {
        return g_app_cache_dir;
    }

    /* Default for Linux: ~/.cache/dna */
    const char *home = qgp_platform_home_dir();
    if (!home) {
        return NULL;
    }

    /* Check XDG_CACHE_HOME first */
    const char *cache_home = getenv("XDG_CACHE_HOME");
    if (cache_home && cache_home[0]) {
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s/dna", cache_home);
    } else {
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s/.cache/dna", home);
    }

    /* Create cache directory hierarchy */
    char parent[4096];
    if (cache_home && cache_home[0]) {
        snprintf(parent, sizeof(parent), "%s", cache_home);
    } else {
        snprintf(parent, sizeof(parent), "%s/.cache", home);
    }
    qgp_platform_mkdir(parent);
    qgp_platform_mkdir(g_app_cache_dir);

    return g_app_cache_dir;
}

int qgp_platform_set_app_dirs(const char *data_dir, const char *cache_dir) {
    if (!data_dir) {
        return -1;
    }

    /* Copy data directory */
    size_t data_len = strlen(data_dir);
    if (data_len >= sizeof(g_app_data_dir)) {
        return -1;  /* Path too long */
    }
    memcpy(g_app_data_dir, data_dir, data_len + 1);

    /* Copy cache directory (or use data_dir/cache as fallback) */
    if (cache_dir) {
        size_t cache_len = strlen(cache_dir);
        if (cache_len >= sizeof(g_app_cache_dir)) {
            return -1;  /* Path too long */
        }
        memcpy(g_app_cache_dir, cache_dir, cache_len + 1);
    } else {
        /* Default: data_dir/cache */
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s/cache", data_dir);
    }

    /* Create directories */
    qgp_platform_mkdir(g_app_data_dir);
    qgp_platform_mkdir(g_app_cache_dir);

    g_dirs_initialized = 1;
    return 0;
}

/* ============================================================================
 * Network State (Linux Desktop Implementation)
 * Desktop Linux returns UNKNOWN as there's no system API for network state
 * Mobile platforms (Android/iOS) provide actual network state tracking
 * ============================================================================ */

static qgp_network_callback_t g_network_callback = NULL;
static void *g_network_callback_data = NULL;

qgp_network_state_t qgp_platform_network_state(void) {
    /* Desktop Linux doesn't track network state via this API */
    /* Mobile implementations will return actual state */
    return QGP_NETWORK_UNKNOWN;
}

void qgp_platform_set_network_callback(qgp_network_callback_t callback, void *user_data) {
    g_network_callback = callback;
    g_network_callback_data = user_data;
    /* On desktop Linux, callback is never called (network state not tracked) */
    /* Mobile implementations will call this on state changes */
}

/* ============================================================================
 * Secure Memory Wiping (Prevents compiler optimization)
 * ============================================================================ */

void qgp_secure_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

#if defined(__linux__) || defined(__unix__)
    /* Use explicit_bzero if available (glibc 2.25+, BSD) */
    #if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
        explicit_bzero(ptr, len);
    #elif defined(__OpenBSD__) || defined(__FreeBSD__)
        explicit_bzero(ptr, len);
    #else
        /* Fallback: Use volatile pointer to prevent optimization */
        volatile uint8_t *volatile vptr = (volatile uint8_t *volatile)ptr;
        while (len--) {
            *vptr++ = 0;
        }
    #endif
#elif defined(_WIN32)
    /* Windows: Use SecureZeroMemory */
    SecureZeroMemory(ptr, len);
#else
    /* Generic fallback: Use volatile pointer */
    volatile uint8_t *volatile vptr = (volatile uint8_t *volatile)ptr;
    while (len--) {
        *vptr++ = 0;
    }
#endif
}

/* ============================================================================
 * SSL/TLS Certificate Bundle (Linux Implementation)
 * On Linux, curl uses the system certificate store automatically
 * ============================================================================ */

const char* qgp_platform_ca_bundle_path(void) {
    /* On Linux, curl automatically uses system certificates from:
     * - /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu)
     * - /etc/pki/tls/certs/ca-bundle.crt (RHEL/CentOS)
     * - /etc/ssl/ca-bundle.pem (OpenSUSE)
     *
     * Return NULL to let curl use system defaults */
    return NULL;
}

/* ============================================================================
 * Timing / Delay Operations (Linux Implementation)
 * ============================================================================ */

void qgp_platform_sleep(unsigned int seconds) {
    sleep(seconds);
}

void qgp_platform_sleep_ms(unsigned int milliseconds) {
    usleep(milliseconds * 1000);
}

/* ============================================================================
 * Path Security (M9 - Path Traversal Prevention)
 * ============================================================================ */

int qgp_platform_sanitize_filename(const char *filename) {
    if (!filename || filename[0] == '\0') {
        return 0;  /* Empty or NULL filename is unsafe */
    }

    /* Check for path traversal sequences and dangerous characters */
    for (const char *p = filename; *p != '\0'; p++) {
        char c = *p;

        /* Check for directory separators */
        if (c == '/' || c == '\\') {
            return 0;  /* Contains directory separator */
        }

        /* Check for null byte (shouldn't happen with strlen, but defensive) */
        if (c == '\0') {
            break;
        }

        /* Only allow: alphanumeric, dash, underscore, dot */
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_' || c == '.')) {
            return 0;  /* Contains unsafe character */
        }
    }

    /* Check for ".." path traversal sequence */
    if (strstr(filename, "..") != NULL) {
        return 0;  /* Contains path traversal */
    }

    /* Check that filename doesn't start with a dot (hidden file prevention) */
    if (filename[0] == '.') {
        return 0;  /* Starts with dot */
    }

    return 1;  /* Filename is safe */
}

/* ============================================================================
 * System Information
 * ============================================================================ */

int qgp_platform_cpu_count(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) {
        return 1;  /* Fallback to 1 if detection fails */
    }
    return (int)n;
}

/* ============================================================================
 * Identity Lock (v0.6.0+ - Single-Owner Engine Model)
 * Uses flock() for file-based locking across processes
 * ============================================================================ */

int qgp_platform_acquire_identity_lock(const char *data_dir) {
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "acquire_identity_lock: NULL data_dir");
        return -1;
    }

    /* Build lock file path: data_dir/identity.lock */
    char lock_path[4096];
    snprintf(lock_path, sizeof(lock_path), "%s/identity.lock", data_dir);

    /* Ensure data directory exists */
    qgp_platform_mkdir(data_dir);

    /* Open/create lock file */
    int fd = open(lock_path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "acquire_identity_lock: failed to open %s: %s",
                      lock_path, strerror(errno));
        return -1;
    }

    /* v0.6.109: Try to acquire exclusive lock with retry
     * Retry up to 10 times with 100ms delay (1 second total) for consistency
     * with Android behavior and to handle edge cases on desktop. */
    const int max_retries = 10;
    const int retry_delay_ms = 100;

    for (int attempt = 0; attempt < max_retries; attempt++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            /* Lock acquired successfully */
            QGP_LOG_INFO(LOG_TAG, "acquire_identity_lock: lock acquired (fd=%d, attempt=%d)",
                         fd, attempt + 1);
            return fd;
        }

        /* Lock failed - check if we should retry */
        if (errno == EWOULDBLOCK && attempt < max_retries - 1) {
            QGP_LOG_INFO(LOG_TAG, "acquire_identity_lock: lock held, retry %d/%d in %dms",
                         attempt + 1, max_retries, retry_delay_ms);
            usleep(retry_delay_ms * 1000);  /* Convert ms to microseconds */
        } else if (errno != EWOULDBLOCK) {
            QGP_LOG_ERROR(LOG_TAG, "acquire_identity_lock: flock failed: %s", strerror(errno));
            break;
        }
    }

    /* All retries exhausted */
    QGP_LOG_WARN(LOG_TAG, "acquire_identity_lock: lock still held after %d retries", max_retries);
    close(fd);
    return -1;
}

void qgp_platform_release_identity_lock(int lock_fd) {
    if (lock_fd < 0) {
        return;  /* No lock to release */
    }

    /* Release the lock and close the file descriptor */
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    QGP_LOG_INFO(LOG_TAG, "release_identity_lock: lock released (fd=%d)", lock_fd);
}

int qgp_platform_is_identity_locked(const char *data_dir) {
    if (!data_dir) {
        return 0;
    }

    /* Build lock file path */
    char lock_path[4096];
    snprintf(lock_path, sizeof(lock_path), "%s/identity.lock", data_dir);

    /* Try to open lock file */
    int fd = open(lock_path, O_RDONLY);
    if (fd < 0) {
        /* Lock file doesn't exist - not locked */
        return 0;
    }

    /* Try to acquire shared lock (non-blocking) to check status */
    if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
        /* Got the lock - it was available, release immediately */
        flock(fd, LOCK_UN);
        close(fd);
        return 0;  /* Not locked */
    }

    close(fd);
    return 1;  /* Lock is held by another process */
}
