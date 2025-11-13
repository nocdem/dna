#ifndef QGP_PLATFORM_H
#define QGP_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/**
 * qgp_platform.h - Cross-platform abstraction layer
 *
 * Provides unified API for platform-specific operations:
 * - Random number generation (cryptographically secure)
 * - Directory operations (creation, existence checks)
 * - File system operations (path resolution, home directory)
 * - Path operations (joining, normalization)
 *
 * Platform-specific implementations:
 * - Linux: qgp_platform_linux.c
 * - Windows: qgp_platform_windows.c
 */

/* ============================================================================
 * Random Number Generation (Cryptographically Secure)
 * ============================================================================ */

/**
 * Generate cryptographically secure random bytes
 *
 * Linux: Uses getrandom() syscall or /dev/urandom
 * Windows: Uses BCryptGenRandom() (CNG API)
 *
 * @param buf Output buffer for random bytes
 * @param len Number of random bytes to generate
 * @return 0 on success, -1 on failure
 */
int qgp_platform_random(uint8_t *buf, size_t len);

/* ============================================================================
 * Directory Operations
 * ============================================================================ */

/**
 * Create a directory with secure permissions
 *
 * Linux: mkdir(path, 0700) - Owner read/write/execute only
 * Windows: CreateDirectoryA(path, NULL) - Inherits parent ACL
 *
 * @param path Directory path to create
 * @return 0 on success, -1 on failure
 */
int qgp_platform_mkdir(const char *path);

/**
 * Check if a file or directory exists
 *
 * Linux: access(path, F_OK)
 * Windows: GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES
 *
 * @param path File or directory path to check
 * @return 1 if exists, 0 if not exists
 */
int qgp_platform_file_exists(const char *path);

/**
 * Check if a path is a directory
 *
 * Linux: stat(path, &st) and S_ISDIR(st.st_mode)
 * Windows: GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY
 *
 * @param path Path to check
 * @return 1 if directory, 0 if not
 */
int qgp_platform_is_directory(const char *path);

/* ============================================================================
 * Path Operations
 * ============================================================================ */

/**
 * Get the user's home directory
 *
 * Linux: getenv("HOME")
 * Windows: getenv("USERPROFILE") or HOMEDRIVE + HOMEPATH
 *
 * @return Home directory path (read-only, do not free)
 */
const char* qgp_platform_home_dir(void);

/**
 * Join two path components with platform-specific separator
 *
 * Linux: Uses '/' separator
 * Windows: Uses '\\' separator (but also accepts '/')
 *
 * @param dir Directory path
 * @param file File or subdirectory name
 * @return Joined path (caller must free with free())
 */
char* qgp_platform_join_path(const char *dir, const char *file);

/* ============================================================================
 * Platform Detection Macros
 * ============================================================================ */

#ifdef _WIN32
    #define QGP_PLATFORM_WINDOWS 1
    #define QGP_PLATFORM_LINUX 0
    #define QGP_PATH_SEPARATOR "\\"
#else
    #define QGP_PLATFORM_WINDOWS 0
    #define QGP_PLATFORM_LINUX 1
    #define QGP_PATH_SEPARATOR "/"
#endif

#endif /* QGP_PLATFORM_H */
