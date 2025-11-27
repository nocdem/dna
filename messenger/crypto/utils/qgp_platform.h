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
 * Secure Memory Operations
 * ============================================================================ */

/**
 * Securely zero memory (prevents compiler optimization)
 *
 * Unlike memset(ptr, 0, len), this function guarantees that the memory
 * will be zeroed and not optimized away by the compiler. Use this for
 * wiping sensitive data like keys, passphrases, or plaintext.
 *
 * Linux: Uses explicit_bzero() if available, or volatile pointer fallback
 * Windows: Uses SecureZeroMemory()
 *
 * @param ptr Pointer to memory to zero
 * @param len Number of bytes to zero
 */
void qgp_secure_memzero(void *ptr, size_t len);

/* ============================================================================
 * Application Data Directories (Mobile-Ready)
 * ============================================================================ */

/**
 * Get the application data directory
 *
 * Desktop (Linux): ~/.dna/
 * Desktop (Windows): %APPDATA%/dna/
 * Mobile (Android): Set via qgp_platform_set_app_dirs() -> Context.getFilesDir()
 * Mobile (iOS): Set via qgp_platform_set_app_dirs() -> ~/Library/Application Support/dna/
 *
 * The directory is created if it doesn't exist.
 *
 * @return Application data directory path (read-only, do not free)
 *         Returns NULL if not set on mobile and qgp_platform_set_app_dirs() not called
 */
const char* qgp_platform_app_data_dir(void);

/**
 * Get the application cache directory
 *
 * Desktop (Linux): ~/.cache/dna/
 * Desktop (Windows): %LOCALAPPDATA%/dna/cache/
 * Mobile (Android): Set via qgp_platform_set_app_dirs() -> Context.getCacheDir()
 * Mobile (iOS): Set via qgp_platform_set_app_dirs() -> ~/Library/Caches/dna/
 *
 * Note: Cache directory contents may be cleared by OS when storage is low.
 * Do not store critical data here.
 *
 * @return Cache directory path (read-only, do not free)
 */
const char* qgp_platform_cache_dir(void);

/**
 * Set application directories (required for mobile platforms)
 *
 * On mobile platforms, the native app must call this function during
 * initialization to provide the sandboxed data and cache directories.
 *
 * On desktop, this function is optional - default paths are used if not called.
 *
 * @param data_dir  Application data directory (must not be NULL)
 * @param cache_dir Application cache directory (can be NULL, will use data_dir/cache)
 * @return 0 on success, -1 on failure
 */
int qgp_platform_set_app_dirs(const char *data_dir, const char *cache_dir);

/* ============================================================================
 * Network State (Mobile Network Handling)
 * ============================================================================ */

/**
 * Network connectivity state
 */
typedef enum {
    QGP_NETWORK_UNKNOWN = 0,   /* Network state unknown */
    QGP_NETWORK_NONE = 1,      /* No network connectivity */
    QGP_NETWORK_WIFI = 2,      /* Connected via WiFi */
    QGP_NETWORK_CELLULAR = 3,  /* Connected via cellular */
    QGP_NETWORK_ETHERNET = 4   /* Connected via ethernet */
} qgp_network_state_t;

/**
 * Get current network connectivity state
 *
 * Desktop: Always returns QGP_NETWORK_UNKNOWN (use other methods)
 * Mobile: Returns actual network state (WiFi, Cellular, None)
 *
 * @return Current network state
 */
qgp_network_state_t qgp_platform_network_state(void);

/**
 * Network state change callback type
 */
typedef void (*qgp_network_callback_t)(qgp_network_state_t new_state, void *user_data);

/**
 * Set callback for network state changes (mobile only)
 *
 * @param callback Function to call when network state changes
 * @param user_data User data passed to callback
 */
void qgp_platform_set_network_callback(qgp_network_callback_t callback, void *user_data);

/* ============================================================================
 * Platform Detection Macros
 * ============================================================================ */

#if defined(__ANDROID__)
    #define QGP_PLATFORM_ANDROID 1
    #define QGP_PLATFORM_IOS 0
    #define QGP_PLATFORM_WINDOWS 0
    #define QGP_PLATFORM_LINUX 0
    #define QGP_PLATFORM_MOBILE 1
    #define QGP_PATH_SEPARATOR "/"
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IOS || TARGET_OS_IPHONE
        #define QGP_PLATFORM_ANDROID 0
        #define QGP_PLATFORM_IOS 1
        #define QGP_PLATFORM_WINDOWS 0
        #define QGP_PLATFORM_LINUX 0
        #define QGP_PLATFORM_MOBILE 1
        #define QGP_PATH_SEPARATOR "/"
    #else
        /* macOS */
        #define QGP_PLATFORM_ANDROID 0
        #define QGP_PLATFORM_IOS 0
        #define QGP_PLATFORM_WINDOWS 0
        #define QGP_PLATFORM_LINUX 0
        #define QGP_PLATFORM_MACOS 1
        #define QGP_PLATFORM_MOBILE 0
        #define QGP_PATH_SEPARATOR "/"
    #endif
#elif defined(_WIN32)
    #define QGP_PLATFORM_ANDROID 0
    #define QGP_PLATFORM_IOS 0
    #define QGP_PLATFORM_WINDOWS 1
    #define QGP_PLATFORM_LINUX 0
    #define QGP_PLATFORM_MOBILE 0
    #define QGP_PATH_SEPARATOR "\\"
#else
    /* Linux/Unix */
    #define QGP_PLATFORM_ANDROID 0
    #define QGP_PLATFORM_IOS 0
    #define QGP_PLATFORM_WINDOWS 0
    #define QGP_PLATFORM_LINUX 1
    #define QGP_PLATFORM_MOBILE 0
    #define QGP_PATH_SEPARATOR "/"
#endif

#endif /* QGP_PLATFORM_H */
