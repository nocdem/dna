#include "qgp_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <direct.h>  /* _mkdir */

/* Link against bcrypt.lib for BCryptGenRandom */
#pragma comment(lib, "bcrypt.lib")

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

#endif /* _WIN32 */
