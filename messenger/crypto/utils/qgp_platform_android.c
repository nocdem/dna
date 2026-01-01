/*
 * qgp_platform_android.c - Android Platform Implementation
 *
 * This file implements the qgp_platform API for Android.
 * The native app must call qgp_platform_set_app_dirs() during JNI_OnLoad
 * to set the sandboxed data and cache directories from Java.
 *
 * Example JNI initialization:
 *   String dataDir = context.getFilesDir().getAbsolutePath();
 *   String cacheDir = context.getCacheDir().getAbsolutePath();
 *   nativeSetAppDirs(dataDir, cacheDir);
 */

#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "PLATFORM"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* For explicit_bzero on newer Android */
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

/* Android random: getrandom() available in API 28+, use syscall for API 24-27 */
#if __ANDROID_API__ >= 28
#include <sys/random.h>
#else
/* For API 24-27, use syscall directly */
#include <sys/syscall.h>
#define getrandom(buf, len, flags) syscall(SYS_getrandom, buf, len, flags)
#endif

/* ============================================================================
 * Application Data Directories (Android Implementation)
 * These MUST be set by the Java/Kotlin app via JNI before using the library
 * ============================================================================ */

static char g_app_data_dir[4096] = {0};
static char g_app_cache_dir[4096] = {0};
static int g_dirs_initialized = 0;

const char* qgp_platform_app_data_dir(void) {
    if (!g_dirs_initialized || !g_app_data_dir[0]) {
        fprintf(stderr, "[DNA] ERROR: qgp_platform_set_app_dirs() not called!\n");
        fprintf(stderr, "[DNA] Android apps must call this during JNI initialization\n");
        return NULL;
    }
    return g_app_data_dir;
}

const char* qgp_platform_cache_dir(void) {
    if (!g_dirs_initialized || !g_app_cache_dir[0]) {
        fprintf(stderr, "[DNA] ERROR: qgp_platform_set_app_dirs() not called!\n");
        return NULL;
    }
    return g_app_cache_dir;
}

int qgp_platform_set_app_dirs(const char *data_dir, const char *cache_dir) {
    if (!data_dir) {
        fprintf(stderr, "[DNA] ERROR: data_dir cannot be NULL\n");
        return -1;
    }

    /* Copy data directory */
    size_t data_len = strlen(data_dir);
    if (data_len >= sizeof(g_app_data_dir)) {
        fprintf(stderr, "[DNA] ERROR: data_dir path too long\n");
        return -1;
    }
    memcpy(g_app_data_dir, data_dir, data_len + 1);

    /* Copy cache directory */
    if (cache_dir) {
        size_t cache_len = strlen(cache_dir);
        if (cache_len >= sizeof(g_app_cache_dir)) {
            fprintf(stderr, "[DNA] ERROR: cache_dir path too long\n");
            return -1;
        }
        memcpy(g_app_cache_dir, cache_dir, cache_len + 1);
    } else {
        /* Default: data_dir/cache */
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s/cache", data_dir);
    }

    /* Create directories if needed */
    qgp_platform_mkdir(g_app_data_dir);
    qgp_platform_mkdir(g_app_cache_dir);

    g_dirs_initialized = 1;

    fprintf(stderr, "[DNA] Initialized:\n");
    fprintf(stderr, "[DNA]   Data: %s\n", g_app_data_dir);
    fprintf(stderr, "[DNA]   Cache: %s\n", g_app_cache_dir);

    return 0;
}

/* ============================================================================
 * Random Number Generation (Android Implementation)
 * Uses getrandom() syscall (Android 7.0+ / API 24+)
 * Falls back to /dev/urandom for older devices
 * ============================================================================ */

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

    /* Try getrandom() syscall first (Android 7.0+ / API 24+) */
    ssize_t ret = getrandom(buf, len, 0);
    if (ret >= 0 && (size_t)ret == len) {
        return 0;
    }

    /* Fallback: /dev/urandom */
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        perror("[DNA] Failed to open /dev/urandom");
        return -1;
    }

    size_t bytes_read = fread(buf, 1, len, fp);
    fclose(fp);

    if (bytes_read != len) {
        fprintf(stderr, "[DNA] Failed to read %zu bytes from /dev/urandom\n", len);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Directory Operations (Android Implementation)
 * Same as Linux - POSIX compatible
 * ============================================================================ */

int qgp_platform_mkdir(const char *path) {
    if (!path) {
        return -1;
    }

    if (mkdir(path, 0700) != 0) {
        if (errno == EEXIST) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                return 0;  /* Already exists as directory */
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
        return 0;
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
 * Path Operations (Android Implementation)
 * ============================================================================ */

const char* qgp_platform_home_dir(void) {
    /* On Android, there's no traditional home directory
     * Apps should use qgp_platform_app_data_dir() instead
     * This function is provided for API compatibility
     */
    if (g_dirs_initialized && g_app_data_dir[0]) {
        return g_app_data_dir;
    }

    /* Fallback: Try getenv (unlikely to work on Android) */
    const char *home = getenv("HOME");
    if (home) {
        return home;
    }

    fprintf(stderr, "[DNA] WARNING: qgp_platform_home_dir() called before initialization\n");
    return "/data/local/tmp";  /* Emergency fallback */
}

char* qgp_platform_join_path(const char *dir, const char *file) {
    if (!dir || !file) {
        return NULL;
    }

    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);

    int need_separator = (dir_len > 0 && dir[dir_len - 1] != '/') ? 1 : 0;

    size_t total_len = dir_len + need_separator + file_len + 1;
    char *result = malloc(total_len);
    if (!result) {
        return NULL;
    }

    memcpy(result, dir, dir_len);
    size_t pos = dir_len;

    if (need_separator) {
        result[pos++] = '/';
    }

    memcpy(result + pos, file, file_len);
    result[pos + file_len] = '\0';

    return result;
}

/* ============================================================================
 * Secure Memory Wiping
 * ============================================================================ */

void qgp_secure_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    /* Use explicit_bzero if available (Android API 28+)
     * For API 24-27, use volatile memset fallback */
#if defined(__ANDROID_API__) && __ANDROID_API__ >= 28
    explicit_bzero(ptr, len);
#else
    /* Fallback: volatile pointer prevents optimization */
    volatile uint8_t *volatile vptr = (volatile uint8_t *volatile)ptr;
    while (len--) {
        *vptr++ = 0;
    }
#endif
}

/* ============================================================================
 * Timing / Delay Operations (Android Implementation)
 * ============================================================================ */

void qgp_platform_sleep(unsigned int seconds) {
    sleep(seconds);
}

void qgp_platform_sleep_ms(unsigned int milliseconds) {
    usleep(milliseconds * 1000);
}

/* ============================================================================
 * Network State (Android Implementation)
 * Actual network state should be queried from Java and pushed via callback
 * ============================================================================ */

static qgp_network_state_t g_network_state = QGP_NETWORK_UNKNOWN;
static qgp_network_callback_t g_network_callback = NULL;
static void *g_network_callback_data = NULL;

qgp_network_state_t qgp_platform_network_state(void) {
    return g_network_state;
}

void qgp_platform_set_network_callback(qgp_network_callback_t callback, void *user_data) {
    g_network_callback = callback;
    g_network_callback_data = user_data;
}

/**
 * Called from JNI when Android network state changes
 * Java code should call: nativeSetNetworkState(state)
 *
 * @param state Network state (0=unknown, 1=none, 2=wifi, 3=cellular, 4=ethernet)
 */
void qgp_platform_update_network_state(int state) {
    qgp_network_state_t new_state = (qgp_network_state_t)state;

    if (new_state != g_network_state) {
        g_network_state = new_state;

        if (g_network_callback) {
            g_network_callback(new_state, g_network_callback_data);
        }
    }
}

/* ============================================================================
 * SSL/TLS Certificate Bundle (Android Implementation)
 * On Android, we bundle cacert.pem in the app's data directory
 * ============================================================================ */

static char g_ca_bundle_path[4096] = {0};

const char* qgp_platform_ca_bundle_path(void) {
    /* Return cached path if already computed */
    if (g_ca_bundle_path[0]) {
        return g_ca_bundle_path;
    }

    /* Need app data directory to be set */
    if (!g_dirs_initialized || !g_app_data_dir[0]) {
        QGP_LOG_ERROR(LOG_TAG, "CA bundle requested before app dirs initialized");
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Searching for CA bundle (data_dir=%s)", g_app_data_dir);

    /* Try multiple possible locations for CA bundle */
    const char *locations[] = {
        "%s/cacert.pem",                       /* Direct in app data dir */
        "%s/../cacert.pem",                    /* Parent directory (filesDir) */
        NULL
    };

    char test_path[4096];
    for (int i = 0; locations[i] != NULL; i++) {
        snprintf(test_path, sizeof(test_path), locations[i], g_app_data_dir);
        QGP_LOG_DEBUG(LOG_TAG, "Checking: %s", test_path);

        if (access(test_path, R_OK) == 0) {
            strncpy(g_ca_bundle_path, test_path, sizeof(g_ca_bundle_path) - 1);
            QGP_LOG_INFO(LOG_TAG, "Found CA bundle: %s", g_ca_bundle_path);
            return g_ca_bundle_path;
        } else {
            QGP_LOG_WARN(LOG_TAG, "Not found: %s", test_path);
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "CA bundle NOT FOUND - HTTPS will fail!");
    return NULL;
}
