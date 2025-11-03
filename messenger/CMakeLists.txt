cmake_minimum_required(VERSION 3.10)
project(dna C CXX)  # Support both C and C++ for Qt GUI

# Static linking configuration for Windows
if(WIN32)
    # Force static runtime library on Windows
    if(MSVC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        # Use /MT or /MTd for static runtime
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    elseif(MINGW)
        # Static linking for MinGW
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
    
    # Prefer static libraries on Windows
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
endif()

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
# Support for static linking on Windows
if(WIN32)
    # On Windows, prefer static libraries
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
endif()

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
        message(FATAL_ERROR "json-c not found. Install: apt install libjson-c-dev (Linux) or build with MXE for Windows cross-compilation")
    endif()
endif()

# NOTE: PostgreSQL removed 2025-11-03 - migrated to SQLite for decentralization
# SQLite3 for all local storage (messages, keyserver cache)
find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "SQLite3 found: ${SQLite3_VERSION}")
    message(STATUS "SQLite3 library: ${SQLite3_LIBRARIES}")
    message(STATUS "SQLite3 include: ${SQLite3_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "SQLite3 not found. Install: apt install libsqlite3-dev (Linux)")
endif()

# SDK Independence: Vendored cryptographic implementations
add_subdirectory(crypto/kyber512)   # Kyber512 KEM (includes FIPS202/SHAKE256)
add_subdirectory(crypto/dilithium)  # Dilithium3 signatures
add_subdirectory(crypto/cellframe_dilithium)  # Cellframe-compatible Dilithium (for CF20 wallet)

# Phase 9.1: DHT and P2P Transport Layer
add_subdirectory(dht)               # OpenDHT integration
add_subdirectory(p2p)               # P2P transport layer

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
    # Phase 9.3: Local message backup (SQLite)
    message_backup.c
)

# DNA Messenger Library (libdna)
add_library(dna_lib STATIC
    dna_api.c
    messenger.c
    messenger_p2p.c  # Phase 9.1b: P2P integration layer
    messenger_stubs.c  # DHT-based group functions (Phase 3)
    keyserver_cache.c  # Phase 4: SQLite keyserver cache
    ${COMMON_SOURCES}
)

target_link_libraries(dna_lib
    OpenSSL::Crypto
    kyber512
    dilithium
    dht_lib        # Phase 9.1: DHT library (MUST come BEFORE p2p_transport for Windows stub symbols)
    p2p_transport  # Phase 9.1b: P2P transport layer (links OpenDHT, needs dht_lib stubs first)
    dht_lib        # Link dht_lib again to resolve circular deps with p2p_transport
    p2p_transport  # Link p2p_transport again for static linking order
    stdc++         # C++ standard library (required by dht_lib and OpenDHT)
    ${JSONC_LIBRARIES}
    ${PLATFORM_LIBS}
)

# On Windows with static linking, link Windows system libs
if(WIN32)
    # Windows system libraries (required by OpenSSL and DHT)
    target_link_libraries(dna_lib
        ws2_32      # Windows Sockets
        crypt32     # Cryptography
        secur32     # Security functions (SSPI)
    )
endif()

if(NOT WIN32)
    target_link_libraries(dna_lib m pthread)
endif()

target_include_directories(dna_lib PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/p2p  # Phase 9.1b: P2P transport headers
    ${CMAKE_SOURCE_DIR}/dht  # Phase 9.1: DHT headers
    ${OPENSSL_INCLUDE_DIR}
)

# Add json-c include directories if found
if(JSONC_INCLUDE_DIRS)
    target_include_directories(dna_lib PUBLIC ${JSONC_INCLUDE_DIRS})
endif()

# Add SQLite3 include directories
if(SQLite3_INCLUDE_DIRS)
    target_include_directories(dna_lib PUBLIC ${SQLite3_INCLUDE_DIRS})
endif()

if(WIN32)
    target_include_directories(dna_lib PUBLIC
        ${CMAKE_SOURCE_DIR}/win32
    )
endif()

# DNA Messenger CLI (Phase 3) - DISABLED
# CLI messenger has complex OpenDHT dependency chain for Windows static linking.
# Use GUI application instead (dna_messenger_gui).
#
# To re-enable: set BUILD_CLI_MESSENGER to ON
option(BUILD_CLI_MESSENGER "Build command-line messenger (requires complex OpenDHT dependencies)" OFF)

if(BUILD_CLI_MESSENGER)
    add_executable(dna_messenger
        messenger/main.c
        messenger/keyserver_register.c
        messenger.c
    )
    target_link_libraries(dna_messenger
        dna_lib
        ${JSONC_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
    )

    # On Windows, add zlib, C++ standard library, and OpenDHT dependencies (libfmt, jsoncpp, gnutls, argon2)
    if(WIN32)
        # Find libfmt (required by OpenDHT)
        find_library(FMT_LIBRARY NAMES fmt libfmt PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        if(FMT_LIBRARY)
            message(STATUS "libfmt found: ${FMT_LIBRARY}")
        else()
            message(WARNING "libfmt not found - may cause linking errors with OpenDHT")
        endif()

        # Find jsoncpp (required by OpenDHT)
        find_library(JSONCPP_LIBRARY NAMES jsoncpp libjsoncpp PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        if(JSONCPP_LIBRARY)
            message(STATUS "jsoncpp found: ${JSONCPP_LIBRARY}")
        else()
            message(WARNING "jsoncpp not found - may cause linking errors with OpenDHT")
        endif()

        # Find gnutls (required by OpenDHT for TLS/crypto)
        find_library(GNUTLS_LIBRARY NAMES gnutls libgnutls PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        if(GNUTLS_LIBRARY)
            message(STATUS "gnutls found: ${GNUTLS_LIBRARY}")
        else()
            message(WARNING "gnutls not found - may cause linking errors with OpenDHT")
        endif()

        # Find argon2 (required by OpenDHT for password hashing)
        find_library(ARGON2_LIBRARY NAMES argon2 libargon2 PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        if(ARGON2_LIBRARY)
            message(STATUS "argon2 found: ${ARGON2_LIBRARY}")
        else()
            message(WARNING "argon2 not found - may cause linking errors with OpenDHT")
        endif()

        # Find gnutls dependencies
        find_library(TASN1_LIBRARY NAMES tasn1 libtasn1 PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(NETTLE_LIBRARY NAMES nettle libnettle PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(HOGWEED_LIBRARY NAMES hogweed libhogweed PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(GMP_LIBRARY NAMES gmp libgmp PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(UNISTRING_LIBRARY NAMES unistring libunistring PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(ZSTD_LIBRARY NAMES zstd libzstd PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(IDN2_LIBRARY NAMES idn2 libidn2 PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(ICONV_LIBRARY NAMES iconv libiconv PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(BROTLIENC_LIBRARY NAMES brotlienc libbrotlienc PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(BROTLIDEC_LIBRARY NAMES brotlidec libbrotlidec PATHS ${CMAKE_FIND_ROOT_PATH}/lib)
        find_library(BROTLICOMMON_LIBRARY NAMES brotlicommon libbrotlicommon PATHS ${CMAKE_FIND_ROOT_PATH}/lib)

        # Link all dependencies (order matters for static linking)
        # IMPORTANT: Dependencies must be linked BEFORE the libraries that use them
        target_link_libraries(dna_messenger
            z stdc++
            ${FMT_LIBRARY}
            ${JSONCPP_LIBRARY}
            ${GNUTLS_LIBRARY}
            ${TASN1_LIBRARY}
            ${HOGWEED_LIBRARY}
            ${NETTLE_LIBRARY}
            ${GMP_LIBRARY}
            ${BROTLIENC_LIBRARY}
            ${BROTLIDEC_LIBRARY}
            ${BROTLICOMMON_LIBRARY}
            ${ZSTD_LIBRARY}
            ${IDN2_LIBRARY}
            ${UNISTRING_LIBRARY}
            ${ICONV_LIBRARY}
            ${ARGON2_LIBRARY}
            # Windows system libraries (gnutls, OpenSSL, DHT dependencies)
            ${GNUTLS_LIBRARY}    # Link gnutls again for circular dependencies
            bcrypt       # Windows BCrypt API (random number generation)
            ncrypt       # Windows NCrypt API (CNG key storage)
            crypt32      # Windows certificate store
            ws2_32       # Windows Sockets
            iphlpapi     # IP Helper API (inet_ntop)
        )
    endif()

    target_include_directories(dna_messenger PRIVATE ${CMAKE_SOURCE_DIR} ${PQ_INCLUDE_DIR})

    # Platform-specific install paths
    if(WIN32)
        install(TARGETS dna_messenger DESTINATION .)
    else()
        install(TARGETS dna_messenger DESTINATION bin)
    endif()
else()
    message(STATUS "CLI messenger disabled. Use GUI application (dna_messenger_gui) instead.")
endif()

# Cellframe minimal library (transaction building and signing)
# MUST be defined BEFORE GUI subdirectories that depend on it
add_library(cellframe_minimal STATIC
    cellframe_tx_builder_minimal.c
    cellframe_sign_minimal.c
    cellframe_json_minimal.c
    base58.c
)
target_link_libraries(cellframe_minimal
    cellframe_dilithium
    ${OPENSSL_LIBRARIES}
)
# Math library only on non-Windows
if(NOT WIN32)
    target_link_libraries(cellframe_minimal m)
endif()

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
        message(STATUS "Install Qt5: sudo apt-get install qtbase5-dev (Linux) or build with MXE for Windows cross-compilation")
    endif()
endif()

# cpunk-wallet-gui (Phase 8) - Optional Standalone CF20 Wallet GUI
# Disabled: wallet functionality now integrated into messenger GUI
option(BUILD_WALLET_GUI "Build standalone wallet GUI" OFF)
if(BUILD_WALLET_GUI)
    if(Qt5_FOUND)
        message(STATUS "Building cpunk-wallet-gui application")
        add_subdirectory(wallet-gui)
    else()
        message(STATUS "Qt5 not found. Skipping cpunk-wallet-gui build.")
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

# DNA-Send CLI Tool
# Disabled: send functionality now integrated into messenger GUI
option(BUILD_DNA_SEND "Build dna-send CLI tool" OFF)
if(BUILD_DNA_SEND)
    add_executable(dna-send
        dna-send.c
        wallet.c
        cellframe_addr.c
        cellframe_rpc.c
        base58.c
    )

    # For static CURL on Windows, define CURL_STATICLIB
    if(WIN32)
        target_compile_definitions(dna-send PRIVATE CURL_STATICLIB)
    endif()

    target_link_libraries(dna-send
        cellframe_minimal
        cellframe_dilithium
        ${JSONC_LIBRARIES}
    )

    # Link CURL and OpenSSL (order matters for static linking)
    if(WIN32)
        # For Windows static builds, CURL needs OpenSSL before and after
        if(TARGET CURL::libcurl)
            target_link_libraries(dna-send CURL::libcurl)
        else()
            target_link_libraries(dna-send ${CURL_LIBRARIES})
        endif()

        # Static CURL requires OpenSSL and zlib
        target_link_libraries(dna-send
            OpenSSL::SSL
            OpenSSL::Crypto
            z  # zlib
        )

        # CURL dependencies (static linking requires all)
        target_link_libraries(dna-send
            nghttp2     # HTTP/2 support
            ssh2        # SSH/SFTP support
            psl         # Public Suffix List
            idn2        # Internationalized Domain Names
            unistring   # Unicode string library (required by psl and idn2)
            iconv       # Character encoding conversion (required by unistring)
            zstd        # ZSTD compression
            brotlidec   # Brotli decompression
            brotlicommon # Brotli common functions
        )

        # Windows system libraries (required by OpenSSL and CURL)
        target_link_libraries(dna-send
            bcrypt      # Windows Cryptography API
            ws2_32      # Windows Sockets
            crypt32     # Cryptography
            secur32     # Security functions (SSPI)
            wldap32     # LDAP support
            normaliz    # Internationalization (CURL)
        )
    else()
        # Linux: simple CURL and OpenSSL linking
        target_link_libraries(dna-send ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} m)
    endif()

    target_include_directories(dna-send PRIVATE ${CMAKE_SOURCE_DIR})
endif()
