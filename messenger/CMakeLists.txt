cmake_minimum_required(VERSION 3.10)
project(dna C CXX)  # Support both C and C++ for Qt GUI

# Version (DNA Messenger starts fresh)
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)

# Auto-increment patch version based on git commit count since last minor version bump
# This gives us: 1.2.0, 1.2.1, 1.2.2, etc. automatically with each commit
execute_process(
    COMMAND git rev-list --count HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_COUNT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# If git command fails (e.g., not a git repo), default to 0
if(NOT GIT_COMMIT_COUNT)
    set(GIT_COMMIT_COUNT 0)
endif()

# Use commit count as patch version for continuous versioning
set(VERSION_PATCH ${GIT_COMMIT_COUNT})

# Build info
execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%d")
message("Build date: ${BUILD_TIMESTAMP}")
message("Git SHA: ${GIT_COMMIT_HASH}")

set(DNA_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(BUILD_TS "${BUILD_TIMESTAMP}")
set(BUILD_HASH "${GIT_COMMIT_HASH}")

add_definitions("-DPQSIGNUM_VERSION=\"${DNA_VERSION}\"")
add_definitions("-DBUILD_TS=\"${BUILD_TS}\"")
add_definitions("-DBUILD_HASH=\"${BUILD_HASH}\"")

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32)
    message(STATUS "Platform: Windows")
    set(PLATFORM_SOURCES
        qgp_platform_windows.c
        win32/getopt.c      # POSIX getopt for Windows
        win32/dirent.c      # POSIX dirent for Windows
    )
    set(PLATFORM_LIBS bcrypt)  # Windows CNG for random number generation
else()
    message(STATUS "Platform: Linux/Unix")
    set(PLATFORM_SOURCES qgp_platform_linux.c)
    set(PLATFORM_LIBS)  # No extra libs needed on Linux
endif()

# SDK Independence: OpenSSL for AES-256, SHA256, Base64, Random
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif()

# CURL for RPC client (Cellframe API)
find_package(CURL REQUIRED)
if(CURL_FOUND)
    message(STATUS "CURL found: ${CURL_VERSION_STRING}")
endif()

# json-c for JSON parsing (keyserver API)
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
        find_library(JSONC_LIBRARIES NAMES json-c jsonc)
        find_path(JSONC_INCLUDE_DIRS json-c/json.h)
    endif()

    if(JSONC_LIBRARIES)
        message(STATUS "json-c found: ${JSONC_LIBRARIES}")
    else()
        message(WARNING "json-c not found. Install: vcpkg install json-c (Windows) or apt install libjson-c-dev (Linux)")
    endif()
endif()

# PostgreSQL for keyserver and message storage (Phase 3+4)
find_library(PQ_LIBRARY pq)
find_path(PQ_INCLUDE_DIR libpq-fe.h PATHS /usr/include/postgresql)
if(NOT PQ_LIBRARY OR NOT PQ_INCLUDE_DIR)
    message(FATAL_ERROR "PostgreSQL libpq not found. Install libpq-dev")
endif()
message(STATUS "PostgreSQL libpq found: ${PQ_LIBRARY}")
message(STATUS "PostgreSQL include: ${PQ_INCLUDE_DIR}")

# SDK Independence: Vendored cryptographic implementations
add_subdirectory(crypto/kyber512)   # Kyber512 KEM (includes FIPS202/SHAKE256)
add_subdirectory(crypto/dilithium)  # Dilithium3 signatures
add_subdirectory(crypto/cellframe_dilithium)  # Cellframe-compatible Dilithium (for CF20 wallet)

# Utility programs (export_pubkey, sign_json, verify_json) - DISABLED
# These are no longer needed as keyserver_register.c uses inline functions
# add_subdirectory(utils)

# Common source files (shared between CLI and library)
set(COMMON_SOURCES
    keygen.c
    sign.c
    verify.c
    export.c
    encrypt.c
    decrypt.c
    keyring.c
    utils.c
    armor.c
    aes_keywrap.c
    bip39.c
    bip39_pbkdf2.c
    seed_derivation.c
    kyber_deterministic.c
    dna_config.c
    # SDK Independence: New crypto modules
    qgp_random.c
    qgp_aes.c
    qgp_kyber.c
    qgp_dilithium.c
    # SDK Independence: Infrastructure modules
    qgp_key.c
    qgp_signature.c
    qgp_utils_standalone.c
    # Cross-platform abstraction layer
    ${PLATFORM_SOURCES}
)

# DNA Messenger Library (libdna)
add_library(dna_lib STATIC
    dna_api.c
    messenger.c
    ${COMMON_SOURCES}
)

target_link_libraries(dna_lib
    OpenSSL::Crypto
    kyber512
    dilithium
    ${PQ_LIBRARY}
    ${PLATFORM_LIBS}
)

if(NOT WIN32)
    target_link_libraries(dna_lib m pthread)
endif()

target_include_directories(dna_lib PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PQ_INCLUDE_DIR}
)

if(WIN32)
    target_include_directories(dna_lib PUBLIC
        ${CMAKE_SOURCE_DIR}/win32
    )
endif()

# DNA Messenger CLI (Phase 3)
add_executable(dna_messenger
    messenger/main.c
    messenger/keyserver_register.c
    messenger.c
)
target_link_libraries(dna_messenger dna_lib ${PQ_LIBRARY} ${JSONC_LIBRARIES})
target_include_directories(dna_messenger PRIVATE ${CMAKE_SOURCE_DIR} ${PQ_INCLUDE_DIR})

# DNA Messenger GUI (Phase 5) - Optional Qt GUI
option(BUILD_GUI "Build Qt GUI application" ON)
if(BUILD_GUI)
    find_package(Qt5 QUIET COMPONENTS Core Widgets)
    if(Qt5_FOUND)
        message(STATUS "Qt5 found: ${Qt5_VERSION}")
        message(STATUS "Building GUI application")
        add_subdirectory(gui)
    else()
        message(STATUS "Qt5 not found. Skipping GUI build.")
        if(WIN32)
            message(STATUS "Install Qt5: vcpkg install qt5-base:x64-windows")
        else()
            message(STATUS "Install Qt5: sudo apt-get install qtbase5-dev")
        endif()
    endif()
endif()

# Build type configuration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /DDEBUG")
    else()
        set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
    endif()
    add_definitions("-DDEBUG")
    message(STATUS "Debug build enabled")
else()
    if(MSVC)
        set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
    else()
        set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    endif()
    message(STATUS "Release build enabled")
endif()

# Platform-specific install paths
if(WIN32)
    # Windows: Install to current directory
    install(TARGETS dna_messenger DESTINATION .)
else()
    # Linux/Unix: Install to /usr/local/bin
    install(TARGETS dna_messenger DESTINATION bin)
endif()

# Cellframe minimal library (transaction building and signing)
add_library(cellframe_minimal STATIC
    cellframe_tx_builder_minimal.c
    cellframe_sign_minimal.c
    cellframe_json_minimal.c
    base58.c
)
target_link_libraries(cellframe_minimal
    cellframe_dilithium
    ${OPENSSL_LIBRARIES}
    m
)

# DNA-Send CLI Tool
add_executable(dna-send
    dna-send.c
    wallet.c
    cellframe_addr.c
    cellframe_rpc.c
    base58.c
)
target_link_libraries(dna-send
    cellframe_minimal
    cellframe_dilithium
    ${OPENSSL_LIBRARIES}
    ${CURL_LIBRARIES}
    ${JSONC_LIBRARIES}
    m
)
target_include_directories(dna-send PRIVATE ${CMAKE_SOURCE_DIR})
