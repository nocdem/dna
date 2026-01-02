#include "crypto/utils/qgp_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <direct.h>  /* _mkdir */
#include <io.h>      /* _access */

/* Link against bcrypt.lib for BCryptGenRandom */
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

/* ============================================================================
 * Random Number Generation (Windows Implementation)
 * ============================================================================ */

int qgp_platform_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

    /* Use Windows Cryptography API: Next Generation (CNG)
     * BCryptGenRandom() is the modern replacement for CryptGenRandom()
     * Available since Windows Vista / Server 2008
     */
    NTSTATUS status = BCryptGenRandom(
        NULL,                                   /* Default provider */
        buf,                                    /* Output buffer */
        (ULONG)len,                             /* Buffer size */
        BCRYPT_USE_SYSTEM_PREFERRED_RNG         /* Use system RNG */
    );

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "BCryptGenRandom failed: 0x%08lx\n", (unsigned long)status);
        return -1;
    }

    return 0;
}

/* ============================================================================
 * Directory Operations (Windows Implementation)
 * ============================================================================ */

int qgp_platform_mkdir(const char *path) {
    if (!path) {
        return -1;
    }

    /* Windows _mkdir() does not support Unix-style mode parameter
     * Directory inherits parent's ACL (Access Control List)
     * Returns 0 on success, -1 on failure
     */
    if (_mkdir(path) != 0) {
        if (errno == EEXIST) {
            /* Directory already exists - check if it's actually a directory */
            DWORD attrs = GetFileAttributesA(path);
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
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

    DWORD attrs = GetFileAttributesA(path);
    return (attrs != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
}

int qgp_platform_is_directory(const char *path) {
    if (!path) {
        return 0;
    }

    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;  /* Path doesn't exist or error */
    }

    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
}

int qgp_platform_rmdir_recursive(const char *path) {
    if (!path) {
        return -1;
    }

    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s\\*", path);

    WIN32_FIND_DATAA find_data;
    HANDLE find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return -1;
    }

    char child_path[MAX_PATH];
    int result = 0;

    do {
        /* Skip . and .. */
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        snprintf(child_path, sizeof(child_path), "%s\\%s", path, find_data.cFileName);

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Recurse into subdirectory */
            if (qgp_platform_rmdir_recursive(child_path) != 0) {
                result = -1;
            }
        } else {
            /* Delete file */
            if (!DeleteFileA(child_path)) {
                result = -1;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);

    /* Remove the now-empty directory */
    if (!RemoveDirectoryA(path)) {
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
 * Path Operations (Windows Implementation)
 * ============================================================================ */

const char* qgp_platform_home_dir(void) {
    /* Windows uses USERPROFILE environment variable
     * Example: C:\Users\username
     */
    const char *home = getenv("USERPROFILE");
    if (home) {
        return home;
    }

    /* Fallback: Try HOMEDRIVE + HOMEPATH
     * HOMEDRIVE: Usually "C:"
     * HOMEPATH: Usually "\Users\username"
     */
    const char *drive = getenv("HOMEDRIVE");
    const char *path = getenv("HOMEPATH");
    if (drive && path) {
        static char combined[MAX_PATH];
        snprintf(combined, sizeof(combined), "%s%s", drive, path);
        return combined;
    }

    /* Last resort: Use temp directory */
    return getenv("TEMP") ? getenv("TEMP") : "C:\\Temp";
}

char* qgp_platform_join_path(const char *dir, const char *file) {
    if (!dir || !file) {
        return NULL;
    }

    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);

    /* Check if dir already ends with '\' or '/' */
    int need_separator = 0;
    if (dir_len > 0) {
        char last = dir[dir_len - 1];
        need_separator = (last != '\\' && last != '/') ? 1 : 0;
    }

    /* Allocate: dir + '\\' + file + '\0' */
    size_t total_len = dir_len + need_separator + file_len + 1;
    char *result = malloc(total_len);
    if (!result) {
        return NULL;
    }

    /* Copy dir */
    memcpy(result, dir, dir_len);
    size_t pos = dir_len;

    /* Add separator if needed (Windows prefers backslash) */
    if (need_separator) {
        result[pos++] = '\\';
    }

    /* Copy file */
    memcpy(result + pos, file, file_len);
    result[pos + file_len] = '\0';

    return result;
}

/* ============================================================================
 * SSL/TLS Certificate Bundle (Windows Implementation)
 * On Windows with OpenSSL backend, we need to provide a CA bundle
 * ============================================================================ */

static char g_ca_bundle_path[MAX_PATH] = {0};

const char* qgp_platform_ca_bundle_path(void) {
    /* Return cached path if already computed */
    if (g_ca_bundle_path[0]) {
        return g_ca_bundle_path;
    }

    /* Need app data directory to be set */
    if (!g_dirs_initialized || !g_app_data_dir[0]) {
        QGP_LOG_DEBUG(LOG_TAG, "CA bundle requested before app dirs initialized");
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "Searching for CA bundle (data_dir=%s)", g_app_data_dir);

    /* Try multiple possible locations for CA bundle */
    char test_path[MAX_PATH];

    /* Location 1: In app data dir */
    snprintf(test_path, sizeof(test_path), "%s\\cacert.pem", g_app_data_dir);
    QGP_LOG_DEBUG(LOG_TAG, "Checking: %s", test_path);
    if (_access(test_path, 04) == 0) {  /* 04 = read permission */
        strncpy(g_ca_bundle_path, test_path, sizeof(g_ca_bundle_path) - 1);
        QGP_LOG_INFO(LOG_TAG, "Found CA bundle: %s", g_ca_bundle_path);
        return g_ca_bundle_path;
    }

    /* Location 2: Next to executable (Flutter bundles assets there) */
    char exe_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_path, sizeof(exe_path))) {
        char *last_slash = strrchr(exe_path, '\\');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(test_path, sizeof(test_path), "%s\\data\\flutter_assets\\assets\\cacert.pem", exe_path);
            QGP_LOG_DEBUG(LOG_TAG, "Checking: %s", test_path);
            if (_access(test_path, 04) == 0) {
                strncpy(g_ca_bundle_path, test_path, sizeof(g_ca_bundle_path) - 1);
                QGP_LOG_INFO(LOG_TAG, "Found CA bundle: %s", g_ca_bundle_path);
                return g_ca_bundle_path;
            }
        }
    }

    QGP_LOG_WARN(LOG_TAG, "CA bundle NOT FOUND - HTTPS may fail");
    return NULL;
}

/* ============================================================================
 * App Directory Management (Windows Implementation)
 * ============================================================================ */

/* Static storage for app directories (set via qgp_platform_set_app_dirs) */
static char g_app_data_dir[MAX_PATH] = {0};
static char g_app_cache_dir[MAX_PATH] = {0};
static int g_dirs_initialized = 0;

const char* qgp_platform_app_data_dir(void) {
    /* If already set via qgp_platform_set_app_dirs, return that */
    if (g_dirs_initialized && g_app_data_dir[0]) {
        return g_app_data_dir;
    }

    /* Default for Windows: %APPDATA%\DNA */
    const char *appdata = getenv("APPDATA");
    if (!appdata) {
        /* Fallback to home directory */
        const char *home = qgp_platform_home_dir();
        if (!home) {
            return NULL;
        }
        snprintf(g_app_data_dir, sizeof(g_app_data_dir), "%s\\.dna", home);
    } else {
        snprintf(g_app_data_dir, sizeof(g_app_data_dir), "%s\\DNA", appdata);
    }

    /* Create directory if it doesn't exist */
    qgp_platform_mkdir(g_app_data_dir);

    return g_app_data_dir;
}

const char* qgp_platform_cache_dir(void) {
    /* If already set via qgp_platform_set_app_dirs, return that */
    if (g_dirs_initialized && g_app_cache_dir[0]) {
        return g_app_cache_dir;
    }

    /* Default for Windows: %LOCALAPPDATA%\DNA\cache */
    const char *localappdata = getenv("LOCALAPPDATA");
    if (!localappdata) {
        /* Fallback to app data dir */
        const char *data_dir = qgp_platform_app_data_dir();
        if (!data_dir) {
            return NULL;
        }
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s\\cache", data_dir);
    } else {
        char parent[MAX_PATH];
        snprintf(parent, sizeof(parent), "%s\\DNA", localappdata);
        qgp_platform_mkdir(parent);
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s\\cache", parent);
    }

    /* Create cache directory */
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

    /* Copy cache directory (or use data_dir\cache as fallback) */
    if (cache_dir) {
        size_t cache_len = strlen(cache_dir);
        if (cache_len >= sizeof(g_app_cache_dir)) {
            return -1;  /* Path too long */
        }
        memcpy(g_app_cache_dir, cache_dir, cache_len + 1);
    } else {
        snprintf(g_app_cache_dir, sizeof(g_app_cache_dir), "%s\\cache", data_dir);
    }

    g_dirs_initialized = 1;

    /* Create directories if they don't exist */
    qgp_platform_mkdir(g_app_data_dir);
    qgp_platform_mkdir(g_app_cache_dir);

    return 0;
}

/* ============================================================================
 * Timing / Delay Operations (Windows Implementation)
 * ============================================================================ */

void qgp_platform_sleep(unsigned int seconds) {
    Sleep(seconds * 1000);
}

void qgp_platform_sleep_ms(unsigned int milliseconds) {
    Sleep(milliseconds);
}

/* ============================================================================
 * Secure Memory Wiping (Windows Implementation)
 * ============================================================================ */

void qgp_secure_memzero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }
    /* Use Windows SecureZeroMemory - guaranteed not to be optimized away */
    SecureZeroMemory(ptr, len);
}

#endif /* _WIN32 */
