#include "crypto/utils/qgp_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>

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
        perror("getrandom() failed");
        /* Continue to fallback */
    }
#endif

    /* Fallback: /dev/urandom (always available on Linux) */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("Failed to open /dev/urandom");
        return -1;
    }

    size_t bytes_read = fread(buf, 1, len, fp);
    fclose(fp);

    if (bytes_read != len) {
        fprintf(stderr, "Failed to read %zu bytes from /dev/urandom (got %zu)\n",
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
        fprintf(stderr, "FATAL: Cannot determine home directory (HOME not set and getpwuid failed)\n");
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
 * Network State (Linux Implementation - Stub)
 * On desktop Linux, network state is always UNKNOWN (use other methods)
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
