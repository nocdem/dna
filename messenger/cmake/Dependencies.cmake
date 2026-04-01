# Dependencies.cmake - External Dependency Management
#
# Finds and configures all external dependencies.
# For Android, dependencies are pre-set by AndroidBuild.cmake.
#
# Sets: OPENSSL_*, CURL_*, JSONC_*, SQLite3_*, HAS_CURL

# =============================================================================
# OpenSSL (AES-256, SHA256, Base64, Random)
# =============================================================================
if(ANDROID)
    # Android: OpenSSL is set by AndroidBuild.cmake (pre-built static library)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found for Android: ${OPENSSL_VERSION}")
        message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    else()
        message(FATAL_ERROR "OpenSSL not found for Android - build openssl-arm64 first!")
    endif()
else()
    find_package(OpenSSL REQUIRED)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    endif()
endif()

# =============================================================================
# CURL (Blockchain RPC client)
# =============================================================================
if(ANDROID)
    # Android: CURL is set by AndroidBuild.cmake (pre-built static library)
    if(CURL_FOUND)
        message(STATUS "CURL found for Android: ${CURL_LIBRARIES}")
        set(HAS_CURL ON)
    else()
        message(FATAL_ERROR "CURL not found for Android - build curl-arm64 first!")
    endif()
else()
    find_package(CURL REQUIRED)
    if(CURL_FOUND)
        message(STATUS "CURL found: ${CURL_VERSION_STRING}")
        set(HAS_CURL ON)
    endif()
endif()

# =============================================================================
# json-c (JSON parsing for keyserver API)
# =============================================================================
# For Android, JSON-C is set by AndroidBuild.cmake
if(JSON-C_FOUND)
    message(STATUS "json-c found (Android): ${JSON-C_LIBRARY}")
    set(JSONC_LIBRARIES ${JSON-C_LIBRARY})
    set(JSONC_INCLUDE_DIRS ${JSON-C_INCLUDE_DIR})
else()
    find_package(json-c CONFIG QUIET)
    if(json-c_FOUND)
        message(STATUS "json-c found via CMake config")
        set(JSONC_LIBRARIES json-c::json-c)
    else()
        # Fallback for systems without CMake config (e.g., older Linux)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(JSONC QUIET json-c)
        endif()

        if(NOT JSONC_FOUND)
            find_library(JSONC_LIBRARIES NAMES json-c jsonc libjson-c)
            find_path(JSONC_INCLUDE_DIRS json-c/json.h PATH_SUFFIXES include)
        endif()

        if(JSONC_LIBRARIES)
            message(STATUS "json-c found: ${JSONC_LIBRARIES}")
            if(JSONC_INCLUDE_DIRS)
                message(STATUS "json-c include: ${JSONC_INCLUDE_DIRS}")
            endif()
        else()
            message(FATAL_ERROR "json-c not found. Install: apt install libjson-c-dev (Linux) or use llvm-mingw for Windows cross-compilation")
        endif()
    endif()
endif()

# =============================================================================
# SQLCipher (Encrypted local storage — replaces plain SQLite3)
# =============================================================================
# NOTE: PostgreSQL removed 2025-11-03 - migrated to SQLite for decentralization
# NOTE: SQLCipher v4.6.1+ required — AES-256 encrypted SQLite (2026-04-02)
if(ANDROID)
    # Android: SQLCipher is set by AndroidBuild.cmake (pre-built static library in sqlite-arm64/)
    if(SQLCIPHER_FOUND)
        message(STATUS "SQLCipher found for Android: ${SQLCIPHER_VERSION}")
        message(STATUS "SQLCipher library: ${SQLCIPHER_LIBRARIES}")
        message(STATUS "SQLCipher include: ${SQLCIPHER_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "SQLCipher not found for Android - build sqlcipher in sqlite-arm64 first!")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)
    if(SQLCIPHER_FOUND)
        message(STATUS "SQLCipher found: ${SQLCIPHER_VERSION}")
        message(STATUS "SQLCipher library: ${SQLCIPHER_LIBRARIES}")
        message(STATUS "SQLCipher include: ${SQLCIPHER_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "SQLCipher not found. Install: apt install -t bookworm-backports libsqlcipher-dev")
    endif()
endif()

message(STATUS "All dependencies configured successfully")
