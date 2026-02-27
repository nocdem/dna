# WindowsBuild.cmake - Windows Build Configuration
#
# Supports: MSVC, MinGW (cross-compilation)
# Sets: PLATFORM_SOURCES, PLATFORM_LIBS, static linking flags

if(WIN32)
    message(STATUS "=== Windows Build Configuration ===")

    add_definitions(-D_WIN32)

    # Platform sources - POSIX compatibility layer
    set(PLATFORM_SOURCES
        crypto/utils/qgp_platform_windows.c
        win32/getopt.c      # POSIX getopt for Windows
        win32/dirent.c      # POSIX dirent for Windows
        win32/strndup.c     # POSIX strndup for Windows
    )

    # Windows CNG for random number generation
    set(PLATFORM_LIBS bcrypt)

    # Static linking configuration
    if(MSVC)
        message(STATUS "Compiler: MSVC")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        # Use /MT or /MTd for static runtime
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    elseif(MINGW)
        message(STATUS "Compiler: MinGW")
        # Static linking for MinGW
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")

        # Note: CMAKE_PREFIX_PATH already includes lib64 (set by build-cross-compile.sh)
        # No need to append lib64 here as it would create invalid paths
    endif()

    # Prefer static libraries on Windows
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)

    # Fix msgpack boost dependency: use msgpack's own predef headers
    add_definitions(-DMSGPACK_NO_BOOST)

    # Windows system libraries required by dna_lib (for target_link_libraries)
    # These are linked in CMakeLists.txt after dna_lib is defined
    set(WINDOWS_SYSTEM_LIBS
        # GnuTLS and its dependencies (required by OpenDHT on Windows)
        gnutls      # TLS library used by OpenDHT
        tasn1       # ASN.1 library (required by GnuTLS)
        unistring   # Unicode string library (required by GnuTLS)
        intl        # Internationalization (required by GnuTLS)
        idn2        # Internationalized Domain Names (required by GnuTLS)
        brotlienc   # Brotli encoder (required by GnuTLS)
        brotlidec   # Brotli decoder (required by GnuTLS)
        brotlicommon # Brotli common (required by brotlienc/dec)
        zstd        # Zstandard compression (required by GnuTLS)
        z           # zlib compression (required by GnuTLS)
        nettle      # Crypto library (required by GnuTLS)
        hogweed     # Public-key crypto (required by GnuTLS)
        gmp         # Big integer library (required by GnuTLS)
        # Windows system libraries
        ws2_32      # Windows Sockets
        crypt32     # Cryptography
        secur32     # Security functions (SSPI)
        advapi32    # Advanced Windows API
        ncrypt      # Windows cryptography
        bcrypt      # Windows cryptography
        iphlpapi    # IP Helper API
    )

    message(STATUS "Windows build configured successfully")
    message(STATUS "=====================================")
endif()
