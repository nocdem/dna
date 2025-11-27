cmake_minimum_required(VERSION 3.10)
project(dna C CXX)  # C for core library, C++ for ImGui GUI

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

        # Note: CMAKE_PREFIX_PATH already includes lib64 (set by build-cross-compile.sh)
        # No need to append lib64 here as it would create invalid paths
    endif()

    # Prefer static libraries on Windows
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)

    # Fix msgpack boost dependency: use msgpack's own predef headers
    add_definitions(-DMSGPACK_NO_BOOST)
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
if(ANDROID)
    # Include Android-specific configuration
    include(${CMAKE_SOURCE_DIR}/cmake/AndroidBuild.cmake)
    message(STATUS "Platform: Android")
    set(PLATFORM_SOURCES crypto/utils/qgp_platform_android.c)
    set(PLATFORM_LIBS)  # pthread is part of bionic on Android
elseif(WIN32)
    add_definitions(-D_WIN32)
    message(STATUS "Platform: Windows")
    set(PLATFORM_SOURCES
        crypto/utils/qgp_platform_windows.c
        win32/getopt.c      # POSIX getopt for Windows
        win32/dirent.c      # POSIX dirent for Windows
        win32/strndup.c     # POSIX strndup for Windows
    )
    set(PLATFORM_LIBS bcrypt)  # Windows CNG for random number generation
else()
    message(STATUS "Platform: Linux/Unix")
    set(PLATFORM_SOURCES crypto/utils/qgp_platform_linux.c)
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

# libjuice for NAT traversal (ICE/STUN) - replaces libnice + glib
# Vendored as ExternalProject to ensure availability across all platforms
include(ExternalProject)

# Create include directory at configure time to avoid CMake errors
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include)

ExternalProject_Add(libjuice_external
    GIT_REPOSITORY https://github.com/paullouisageneau/libjuice.git
    GIT_TAG v1.7.0
    PREFIX ${CMAKE_BINARY_DIR}/vendor/libjuice
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/vendor/libjuice/install
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DBUILD_SHARED_LIBS=OFF
        -DUSE_NETTLE=OFF
        -DNO_TESTS=ON
        $<$<BOOL:${CMAKE_TOOLCHAIN_FILE}>:-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}>
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}juice${CMAKE_STATIC_LIBRARY_SUFFIX}
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)

# Create imported target for libjuice
add_library(libjuice STATIC IMPORTED GLOBAL)
add_dependencies(libjuice libjuice_external)
set_target_properties(libjuice PROPERTIES
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}juice${CMAKE_STATIC_LIBRARY_SUFFIX}
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include
)

set(JUICE_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include)
set(JUICE_LIBRARIES libjuice)
message(STATUS "libjuice will be built from source (v1.7.0)")

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

# libnice + glib REMOVED (2025-11-19)
# Replaced with libjuice (no glib dependency, simpler cross-compilation)
# See docs/LIBJUICE_MIGRATION.md for details

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
add_subdirectory(crypto/kem)        # ML-KEM-1024 KEM (includes FIPS202/SHAKE256)
add_subdirectory(crypto/dsa)        # ML-DSA-87 signatures (NIST Category 5)
add_subdirectory(crypto/cellframe_dilithium)  # Cellframe-compatible Dilithium (for CF20 wallet)

# Phase 9.1: DHT and P2P Transport Layer
# Force OpenDHT-PQ to build as static library (not shared)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static OpenDHT-PQ library" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Disable OpenDHT-PQ tests (not updated for Dilithium5)" FORCE)
set(OPENDHT_TOOLS ON CACHE BOOL "Enable OpenDHT-PQ tools for dna-nodus" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "Skip install for vendored opendht-pq" FORCE)
add_subdirectory(vendor/opendht-pq)  # OpenDHT-PQ with Dilithium5 support
add_subdirectory(dht)               # DHT integration (uses vendor/opendht-pq)
add_subdirectory(p2p)               # P2P transport layer

# Utility programs (export_pubkey, sign_json, verify_json) - DISABLED
# These are no longer needed as keyserver_register.c uses inline functions

# Common source files (shared between CLI and library)
set(COMMON_SOURCES
    archive/legacy-tools/keygen.c
    archive/legacy-tools/sign.c
    archive/legacy-tools/verify.c
    archive/legacy-tools/export.c
    archive/legacy-tools/encrypt.c
    archive/legacy-tools/decrypt.c
    archive/legacy-tools/keyring.c
    archive/legacy-tools/utils.c
    crypto/utils/armor.c
    crypto/utils/aes_keywrap.c
    crypto/bip39/bip39.c
    crypto/bip39/bip39_pbkdf2.c
    crypto/bip39/seed_derivation.c
    crypto/utils/kyber_deterministic.c
    dna_config.c
    # SDK Independence: New crypto modules
    crypto/utils/qgp_random.c
    crypto/utils/qgp_aes.c
    crypto/utils/qgp_kyber.c
    crypto/utils/qgp_dilithium.c
    crypto/utils/qgp_sha3.c         # Phase 10: SHA3-512 for Category 5 security
    # SDK Independence: Infrastructure modules
    crypto/utils/qgp_key.c
    crypto/utils/qgp_signature.c
    crypto/utils/qgp_utils_standalone.c
    crypto/utils/avatar_utils.c        # Phase 10.2: Avatar processing (stb_image)
    # Cross-platform abstraction layer
    ${PLATFORM_SOURCES}
)

# DNA Messenger Library (libdna)
add_library(dna_lib STATIC
    dna_api.c
    # Unified Engine API (Core/GUI separation)
    src/api/dna_engine.c
    # Modular messenger components (Phase: Modularization)
    messenger/identity.c
    messenger/init.c
    messenger/status.c
    messenger/keys.c
    messenger/contacts.c
    messenger/keygen.c
    messenger/messages.c
    messenger/gsk.c  # Phase 13: Group Symmetric Key (v0.09)
    messenger/gsk_packet.c  # Phase 13: GSK packet builder
    messenger/group_ownership.c  # Phase 13: Ownership transfer (v0.09)
    # Messenger facade (delegates to messenger/ modules)
    messenger.c
    messenger_p2p.c  # Phase 9.1b: P2P integration layer
    # Phase 9.3: Local message backup (SQLite)
    message_backup.c
    database/presence_cache.c  # Phase 9.1c: Fast presence cache (O(1) lookup, no DHT queries)
    messenger_groups.c  # DHT-based group messaging (Phase 5.6 - complete)
    database/keyserver_cache.c  # Phase 4: SQLite keyserver cache
    database/contacts_db.c      # Phase 9.5: Local contacts database
    database/profile_cache.c    # Phase 10.1: Profile cache database (7-day TTL)
    database/profile_manager.c  # Phase 10.1: Smart profile fetching (cache + DHT)
    database/cache_manager.c    # Phase 7: Unified cache lifecycle manager
    database/group_invitations.c  # Phase 6.1: Group invitation tracking database
    blockchain/wallet.c           # Phase 8: Cellframe wallet integration
    blockchain/blockchain_rpc.c    # Phase 8: Blockchain RPC client
    blockchain/blockchain_addr.c   # Phase 8: Blockchain address utilities
    crypto/utils/base58.c           # Phase 8: Base58 encoding for addresses
    ${COMMON_SOURCES}
)

target_link_libraries(dna_lib
    OpenSSL::Crypto
    kem
    dsa
    dht_lib        # Phase 9.1: DHT library (MUST come BEFORE p2p_transport for Windows stub symbols)
    p2p_transport  # Phase 9.1b: P2P transport layer (links libjuice for NAT traversal)
    dht_lib        # Link dht_lib again to resolve circular deps with p2p_transport
    p2p_transport  # Link p2p_transport again for static linking order
    stdc++         # C++ standard library (required by dht_lib and OpenDHT)
    ${JSONC_LIBRARIES}
    ${PLATFORM_LIBS}
    CURL::libcurl  # Phase 8: CURL for RPC calls
)

# On Windows with static linking, link Windows system libs
if(WIN32)
    # Windows system libraries (required by OpenSSL, OpenDHT and GnuTLS)
    # IMPORTANT: Link order matters! Libraries must come AFTER libraries that depend on them
    target_link_libraries(dna_lib
        # GnuTLS and its dependencies (required by OpenDHT on Windows)
        gnutls      # TLS library used by OpenDHT
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
endif()

if(NOT WIN32)
    target_link_libraries(dna_lib m pthread)
endif()

target_include_directories(dna_lib PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include  # Unified Engine API headers
    ${CMAKE_SOURCE_DIR}/src/api  # Internal API headers
    ${CMAKE_SOURCE_DIR}/p2p  # Phase 9.1b: P2P transport headers
    ${CMAKE_SOURCE_DIR}/dht  # Phase 9.1: DHT headers
    ${OPENSSL_INCLUDE_DIR}
    ${JUICE_INCLUDE_DIRS}  # Phase 11: libjuice headers (replaces libnice + glib)
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

# DNA Messenger CLI - REMOVED
# CLI messenger has been removed (unmaintained).
# Use GUI application (dna_messenger_gui) for all functionality.

# Blockchain minimal library (transaction building and signing)
# MUST be defined BEFORE GUI subdirectories that depend on it
add_library(cellframe_minimal STATIC
    blockchain/blockchain_tx_builder_minimal.c
    blockchain/blockchain_sign_minimal.c
    blockchain/blockchain_json_minimal.c
    crypto/utils/base58.c
)
target_link_libraries(cellframe_minimal
    cellframe_dilithium
    ${OPENSSL_LIBRARIES}
)
# Math library only on non-Windows
if(NOT WIN32)
    target_link_libraries(cellframe_minimal m)
endif()

# Qt GUI removed - migrated to ImGui (see imgui_gui/ subdirectory)
# Old Qt GUI code archived in archive/legacy-gui/ directory (deprecated, not maintained)

# Build type configuration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /DDEBUG")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /DDEBUG")
    else()
        set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer")
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
    endif()
    add_definitions("-DDEBUG")
    message(STATUS "Debug build enabled with AddressSanitizer")
else()
    if(MSVC)
        set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG")
        set(CMAKE_CXX_FLAGS_RELEASE "/O2 /DNDEBUG")
    else()
        set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
        set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
    endif()
    message(STATUS "Release build enabled")
endif()

# DNA-Send CLI Tool
# Disabled: send functionality now integrated into messenger GUI
option(BUILD_DNA_SEND "Build dna-send CLI tool" OFF)
if(BUILD_DNA_SEND)
    add_executable(dna-send
        blockchain/dna-send.c
        blockchain/wallet.c
        blockchain/blockchain_addr.c
        blockchain/blockchain_rpc.c
        crypto/utils/base58.c
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

# ImGui GUI (Phase 11: Modern GUI)
option(BUILD_GUI "Build ImGui GUI" ON)
if(BUILD_GUI)
    add_subdirectory(imgui_gui)
endif()
