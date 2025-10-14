#include "qgp_platform.h"

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
        home = getpwuid(getuid())->pw_dir;
    }
    return home ? home : "/tmp";  /* Last resort fallback */
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
