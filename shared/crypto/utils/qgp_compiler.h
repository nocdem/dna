/*
 * qgp_compiler.h - Cross-platform compiler compatibility
 *
 * This header provides macros for cross-platform compiler features:
 * - Struct packing (MSVC pragma pack vs GCC __attribute__)
 * - POSIX function replacements for Windows
 */

#ifndef QGP_COMPILER_H
#define QGP_COMPILER_H

// ============================================================================
// STRUCT PACKING MACROS
// ============================================================================

/*
 * Usage:
 *   PACK_STRUCT_BEGIN
 *   typedef struct {
 *       ...
 *   } PACK_STRUCT_END my_struct_t;
 */

#ifdef _MSC_VER
    // MSVC: Use #pragma pack
    #define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
    #define PACK_STRUCT_END __pragma(pack(pop))
#else
    // GCC/Clang: Use __attribute__((packed))
    #define PACK_STRUCT_BEGIN
    #define PACK_STRUCT_END __attribute__((packed))
#endif

// ============================================================================
// POSIX FUNCTION REPLACEMENTS (Windows)
// ============================================================================

#ifdef _MSC_VER
    // String comparison
    #define strcasecmp _stricmp
    #define strncasecmp _strnicmp

    // String duplication
    #define strdup _strdup

    // File operations (already handled by qgp_platform.h)
    // #define unlink _unlink
    // #define mkdir _mkdir
#endif

#endif // QGP_COMPILER_H
