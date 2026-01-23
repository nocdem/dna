/*
 * DNA Messenger Version
 *
 * Single source of truth for app version (CLI + Flutter + Android SDK).
 * Update this file when releasing new versions.
 */

#ifndef DNA_VERSION_H
#define DNA_VERSION_H

#define DNA_VERSION_MAJOR 0
#define DNA_VERSION_MINOR 6
#define DNA_VERSION_PATCH 27

#define DNA_VERSION_STRING "0.6.27"

/* Build info (set by CMake) */
#ifndef BUILD_HASH
#define BUILD_HASH "unknown"
#endif

#ifndef BUILD_TS
#define BUILD_TS "unknown"
#endif

#endif /* DNA_VERSION_H */
