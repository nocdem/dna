cmake_minimum_required(VERSION 3.10)
project(dna C)

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
    ${COMMON_SOURCES}
)

target_link_libraries(dna_lib
    OpenSSL::Crypto
    kyber512
    dilithium
    ${PLATFORM_LIBS}
)

if(NOT WIN32)
    target_link_libraries(dna_lib m pthread)
endif()

target_include_directories(dna_lib PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

if(WIN32)
    target_include_directories(dna_lib PUBLIC
        ${CMAKE_SOURCE_DIR}/win32
    )
endif()

# DNA Messenger CLI (Phase 3)
add_executable(dna_messenger messenger/main.c messenger.c)
target_link_libraries(dna_messenger dna_lib ${PQ_LIBRARY})
target_include_directories(dna_messenger PRIVATE ${CMAKE_SOURCE_DIR} ${PQ_INCLUDE_DIR})

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
