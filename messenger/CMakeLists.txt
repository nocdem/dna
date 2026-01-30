cmake_minimum_required(VERSION 3.10)
project(dna C CXX)  # C for core library, C++ for DHT components

# =============================================================================
# Build Options
# =============================================================================
# Default to SHARED on Linux desktop (needed for Flutter Linux native library loading)
if(UNIX AND NOT APPLE AND NOT ANDROID)
    option(BUILD_SHARED_LIB "Build dna_lib as shared library (for Flutter)" ON)
else()
    option(BUILD_SHARED_LIB "Build dna_lib as shared library (for Flutter)" OFF)
endif()

option(BUILD_DNA_SEND "Build dna-send CLI tool" OFF)

# Shared libs need PIC; harmless to enable globally and avoids PIC linker surprises
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# =============================================================================
# Compiler Warnings
# =============================================================================
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
    # Suppress some noisy warnings that are not useful
    add_compile_options(-Wno-unused-parameter)       # Many callback functions have unused params
    add_compile_options(-Wno-unused-function)        # Many "ready for future" helper functions
endif()
# GCC-specific warnings (not supported by Clang)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-stringop-truncation)    # strncpy used correctly with sized buffers
    add_compile_options(-Wno-format-truncation)      # snprintf used correctly with sized buffers
endif()

# =============================================================================
# Security Hardening (L1 - SECURITY_AUDIT.md)
# =============================================================================
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Stack buffer overflow protection
    add_compile_options(-fstack-protector-strong)

    # Format string vulnerability warnings
    add_compile_options(-Wformat -Wformat-security)

    # Position Independent Executables (ASLR support)
    if(NOT BUILD_SHARED_LIB)
        add_compile_options(-fPIE)
        add_link_options(-pie)
    endif()

    # Full RELRO - makes GOT read-only after relocation (Linux only)
    if(NOT WIN32 AND NOT ANDROID AND NOT APPLE)
        add_link_options(-Wl,-z,relro,-z,now)
    endif()
endif()

# FORTIFY_SOURCE requires optimization level >= -O1
# Only enable for Release builds (Debug uses -O0 with AddressSanitizer)
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()
endif()

# =============================================================================
# CMake Module Includes
# =============================================================================
# Version and build metadata
include(${CMAKE_SOURCE_DIR}/cmake/Version.cmake)

# Platform detection and configuration (sets PLATFORM_SOURCES, PLATFORM_LIBS)
include(${CMAKE_SOURCE_DIR}/cmake/PlatformDetect.cmake)

# External dependencies (OpenSSL, CURL, json-c, SQLite3)
include(${CMAKE_SOURCE_DIR}/cmake/Dependencies.cmake)

# libjuice removed in v0.4.61 for privacy (was ICE/STUN NAT traversal)
# include(${CMAKE_SOURCE_DIR}/cmake/Libjuice.cmake)

# =============================================================================
# Vendored Cryptographic Libraries
# =============================================================================
add_subdirectory(crypto/kem)        # ML-KEM-1024 KEM (includes FIPS202/SHAKE256)
add_subdirectory(crypto/dsa)        # ML-DSA-87 signatures (NIST Category 5)
add_subdirectory(crypto/cellframe_dilithium)  # Cellframe-compatible Dilithium (for CF20 wallet)

# secp256k1 for Ethereum/Bitcoin key derivation (BIP-32/BIP-44)
include(${CMAKE_SOURCE_DIR}/cmake/Secp256k1.cmake)

# =============================================================================
# DHT and P2P Transport Layer
# =============================================================================
# Force OpenDHT-PQ to build as static library (not shared) WITHOUT poisoning the whole build
set(_SAVED_BUILD_SHARED_LIBS "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries (OpenDHT-PQ only)" FORCE)

set(BUILD_TESTING OFF CACHE BOOL "Disable OpenDHT-PQ tests (not updated for Dilithium5)" FORCE)
set(OPENDHT_TOOLS ON CACHE BOOL "Enable OpenDHT-PQ tools for dna-nodus" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "Skip install for vendored opendht-pq" FORCE)

add_subdirectory(vendor/opendht-pq)  # OpenDHT-PQ with Dilithium5 support

# Restore whatever the parent project wanted
set(BUILD_SHARED_LIBS "${_SAVED_BUILD_SHARED_LIBS}" CACHE BOOL "Build shared libraries" FORCE)
unset(_SAVED_BUILD_SHARED_LIBS)

add_subdirectory(dht)               # DHT integration (uses vendor/opendht-pq)
add_subdirectory(transport)         # Transport layer (DHT-only messaging)

# =============================================================================
# Blockchain Minimal Library
# =============================================================================
# MUST be defined BEFORE other targets that depend on it
add_library(cellframe_minimal STATIC
    blockchain/cellframe/cellframe_tx_builder.c
    blockchain/cellframe/cellframe_sign.c
    blockchain/cellframe/cellframe_json.c
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

# =============================================================================
# Common Source Files
# =============================================================================
set(COMMON_SOURCES
    # NOTE: archive/legacy-tools/ removed - functions moved to:
    #   cmd_export_pubkey → crypto/utils/qgp_key.c
    #   cmd_restore_key_from_seed → messenger/keygen.c
    #   read_file_data → qgp_platform_*.c
    #   get_home_dir, build_path, file_exists → replaced with qgp_platform_* calls
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
    crypto/utils/seed_storage.c
    crypto/utils/qgp_sha3.c         # SHA3-512 for Category 5 security
    # NOTE: qgp_log.c is ONLY in dht_lib to ensure single copy of static vars
    # SDK Independence: Infrastructure modules
    crypto/utils/qgp_key.c
    crypto/utils/key_encryption.c
    crypto/utils/qgp_signature.c
    crypto/utils/qgp_utils_standalone.c
    crypto/utils/threadpool.c       # Centralized thread pool for parallel I/O
    # Cross-platform abstraction layer
    ${PLATFORM_SOURCES}
)

# =============================================================================
# DNA Messenger Library (libdna)
# =============================================================================

# Windows DLL export macro
if(BUILD_SHARED_LIB AND WIN32)
    add_compile_definitions(DNA_LIB_EXPORTS)
endif()

# Build dna_lib as either SHARED or STATIC based on BUILD_SHARED_LIB
if(BUILD_SHARED_LIB)
    add_library(dna_lib SHARED
        dna_api.c
        # Unified Engine API (Core/GUI separation)
        src/api/dna_engine.c
        # Modular engine components
        src/api/engine/dna_engine_feed.c
        src/api/engine/dna_engine_presence.c
        src/api/engine/dna_engine_wallet.c
        src/api/engine/dna_engine_groups.c
        src/api/engine/dna_engine_messaging.c
        src/api/engine/dna_engine_contacts.c
        src/api/engine/dna_engine_identity.c
        src/api/engine/dna_engine_listeners.c
        src/api/engine/dna_engine_logging.c
        src/api/engine/dna_engine_addressbook.c
        src/api/engine/dna_engine_backup.c
        src/api/engine/dna_engine_lifecycle.c
        src/api/engine/dna_engine_helpers.c
        src/api/engine/dna_engine_workers.c
        src/api/engine/dna_engine_version.c
        src/api/engine/dna_engine_signing.c
        # Modular messenger components
        messenger/identity.c
        messenger/init.c
        messenger/status.c
        messenger/keys.c
        messenger/contacts.c
        messenger/keygen.c
        messenger/messages.c
        messenger/gek.c             # Group Encryption Key (GEK system)
        messenger/groups.c          # Group management (GEK system)
        messenger/group_database.c  # Group database (separate from messages.db)
        # Messenger facade (delegates to messenger/ modules)
        messenger.c
        messenger_transport.c       # Transport integration layer
        # Local message backup (SQLite)
        message_backup.c
        database/presence_cache.c   # Fast presence cache (O(1) lookup)
        messenger_groups.c          # DHT-based group messaging
        database/keyserver_cache.c  # SQLite keyserver cache
        database/contacts_db.c      # Local contacts database
        database/addressbook_db.c   # Wallet address book database
        database/feed_subscriptions_db.c # Feed topic subscriptions database
        database/profile_cache.c    # Profile cache database (7-day TTL)
        database/profile_manager.c  # Smart profile fetching (cache + DHT)
        database/cache_manager.c    # Unified cache lifecycle manager
        database/group_invitations.c # Group invitation tracking database
        blockchain/cellframe/cellframe_wallet.c        # Cellframe wallet integration
        blockchain/cellframe/cellframe_wallet_create.c # Cellframe wallet creation from seed
        blockchain/cellframe/cellframe_rpc.c           # Blockchain RPC client
        blockchain/cellframe/cellframe_addr.c          # Blockchain address utilities
        blockchain/blockchain_wallet.c                 # Generic multi-chain wallet interface
        blockchain/blockchain_registry.c               # Modular blockchain registry
        blockchain/ethereum/eth_chain.c                # Ethereum blockchain_ops implementation
        blockchain/cellframe/cell_chain.c              # Cellframe blockchain_ops implementation
        blockchain/ethereum/eth_wallet_create.c        # Ethereum wallet creation (BIP-44)
        blockchain/ethereum/eth_rpc.c                  # Ethereum JSON-RPC client
        blockchain/ethereum/eth_rlp.c                  # Ethereum RLP encoding
        blockchain/ethereum/eth_tx.c                   # Ethereum transaction building/signing
        blockchain/solana/sol_chain.c                  # Solana blockchain_ops implementation
        blockchain/solana/sol_wallet.c                 # Solana wallet (SLIP-10 Ed25519)
        blockchain/solana/sol_rpc.c                    # Solana JSON-RPC client
        blockchain/solana/sol_tx.c                     # Solana transaction building/signing
        blockchain/solana/sol_spl.c                    # SPL token support (USDT, USDC)
        blockchain/ethereum/eth_erc20.c                # ERC-20 token support (USDT, USDC)
        blockchain/tron/trx_base58.c                   # TRON Base58Check encoding
        blockchain/tron/trx_wallet_create.c            # TRON wallet creation (BIP-44)
        blockchain/tron/trx_rpc.c                      # TRON JSON-RPC client (TronGrid)
        blockchain/tron/trx_chain.c                    # TRON blockchain_ops implementation
        blockchain/tron/trx_tx.c                       # TRON transaction building/signing
        blockchain/tron/trx_trc20.c                    # TRC-20 token support (USDT, USDC)
        crypto/bip32/bip32.c                           # BIP-32 HD key derivation
        crypto/utils/keccak256.c                       # Keccak-256 (Ethereum hash)
        crypto/utils/base58.c       # Base58 encoding for addresses
        ${COMMON_SOURCES}
    )
else()
    add_library(dna_lib STATIC
        dna_api.c
        # Unified Engine API (Core/GUI separation)
        src/api/dna_engine.c
        # Modular engine components
        src/api/engine/dna_engine_feed.c
        src/api/engine/dna_engine_presence.c
        src/api/engine/dna_engine_wallet.c
        src/api/engine/dna_engine_groups.c
        src/api/engine/dna_engine_messaging.c
        src/api/engine/dna_engine_contacts.c
        src/api/engine/dna_engine_identity.c
        src/api/engine/dna_engine_listeners.c
        src/api/engine/dna_engine_logging.c
        src/api/engine/dna_engine_addressbook.c
        src/api/engine/dna_engine_backup.c
        src/api/engine/dna_engine_lifecycle.c
        src/api/engine/dna_engine_helpers.c
        src/api/engine/dna_engine_workers.c
        src/api/engine/dna_engine_version.c
        src/api/engine/dna_engine_signing.c
        # Modular messenger components
        messenger/identity.c
        messenger/init.c
        messenger/status.c
        messenger/keys.c
        messenger/contacts.c
        messenger/keygen.c
        messenger/messages.c
        messenger/gek.c             # Group Encryption Key (GEK system)
        messenger/groups.c          # Group management (GEK system)
        messenger/group_database.c  # Group database (separate from messages.db)
        # Messenger facade (delegates to messenger/ modules)
        messenger.c
        messenger_transport.c       # Transport integration layer
        # Local message backup (SQLite)
        message_backup.c
        database/presence_cache.c   # Fast presence cache (O(1) lookup)
        messenger_groups.c          # DHT-based group messaging
        database/keyserver_cache.c  # SQLite keyserver cache
        database/contacts_db.c      # Local contacts database
        database/addressbook_db.c   # Wallet address book database
        database/feed_subscriptions_db.c # Feed topic subscriptions database
        database/profile_cache.c    # Profile cache database (7-day TTL)
        database/profile_manager.c  # Smart profile fetching (cache + DHT)
        database/cache_manager.c    # Unified cache lifecycle manager
        database/group_invitations.c # Group invitation tracking database
        blockchain/cellframe/cellframe_wallet.c        # Cellframe wallet integration
        blockchain/cellframe/cellframe_wallet_create.c # Cellframe wallet creation from seed
        blockchain/cellframe/cellframe_rpc.c           # Blockchain RPC client
        blockchain/cellframe/cellframe_addr.c          # Blockchain address utilities
        blockchain/blockchain_wallet.c                 # Generic multi-chain wallet interface
        blockchain/blockchain_registry.c               # Modular blockchain registry
        blockchain/ethereum/eth_chain.c                # Ethereum blockchain_ops implementation
        blockchain/cellframe/cell_chain.c              # Cellframe blockchain_ops implementation
        blockchain/ethereum/eth_wallet_create.c        # Ethereum wallet creation (BIP-44)
        blockchain/ethereum/eth_rpc.c                  # Ethereum JSON-RPC client
        blockchain/ethereum/eth_rlp.c                  # Ethereum RLP encoding
        blockchain/ethereum/eth_tx.c                   # Ethereum transaction building/signing
        blockchain/solana/sol_chain.c                  # Solana blockchain_ops implementation
        blockchain/solana/sol_wallet.c                 # Solana wallet (SLIP-10 Ed25519)
        blockchain/solana/sol_rpc.c                    # Solana JSON-RPC client
        blockchain/solana/sol_tx.c                     # Solana transaction building/signing
        blockchain/solana/sol_spl.c                    # SPL token support (USDT, USDC)
        blockchain/ethereum/eth_erc20.c                # ERC-20 token support (USDT, USDC)
        blockchain/tron/trx_base58.c                   # TRON Base58Check encoding
        blockchain/tron/trx_wallet_create.c            # TRON wallet creation (BIP-44)
        blockchain/tron/trx_rpc.c                      # TRON JSON-RPC client (TronGrid)
        blockchain/tron/trx_chain.c                    # TRON blockchain_ops implementation
        blockchain/tron/trx_tx.c                       # TRON transaction building/signing
        blockchain/tron/trx_trc20.c                    # TRC-20 token support (USDT, USDC)
        crypto/bip32/bip32.c                           # BIP-32 HD key derivation
        crypto/utils/keccak256.c                       # Keccak-256 (Ethereum hash)
        crypto/utils/base58.c       # Base58 encoding for addresses
        ${COMMON_SOURCES}
    )
endif()

# Core library dependencies
target_link_libraries(dna_lib
    OpenSSL::Crypto
    kem
    dsa
    secp256k1          # secp256k1 for Ethereum/Bitcoin key derivation
    cellframe_minimal  # Blockchain transaction building (uint256, signing)
    dht_lib            # DHT library (MUST come BEFORE transport_lib for Windows stub symbols)
    transport_lib      # Transport layer (DHT-only messaging)
    dht_lib            # Link dht_lib again to resolve circular deps with transport_lib
    transport_lib      # Link transport_lib again for static linking order
    ${JSONC_LIBRARIES}
    ${PLATFORM_LIBS}
)

# secp256k1 include directory for BIP-32 derivation
target_include_directories(dna_lib PRIVATE ${SECP256K1_INCLUDE_DIR})

# C++ standard library linking
# On Android, don't explicitly link stdc++ - let ANDROID_STL handle it
# On other platforms, link stdc++ for OpenDHT compatibility
if(NOT ANDROID)
    target_link_libraries(dna_lib stdc++)
endif()

# CURL linking
if(HAS_CURL)
    if(ANDROID)
        # Android: Use static library path directly
        target_link_libraries(dna_lib ${CURL_LIBRARIES})
    else()
        target_link_libraries(dna_lib CURL::libcurl)
    endif()
endif()

# =============================================================================
# Platform-Specific Linking
# =============================================================================
if(WIN32)
    # Windows system libraries (from WindowsBuild.cmake)
    target_link_libraries(dna_lib ${WINDOWS_SYSTEM_LIBS})
elseif(ANDROID)
    # Android: Include JNI bindings in dna_lib
    target_sources(dna_lib PRIVATE ${CMAKE_SOURCE_DIR}/jni/dna_jni.c)
    target_include_directories(dna_lib PRIVATE ${CMAKE_SOURCE_DIR}/jni)
    # Android: Link GnuTLS and its dependencies (from AndroidBuild.cmake)
    target_link_libraries(dna_lib ${ANDROID_GNUTLS_LIBS} m log)
    # C++ STL is handled by ANDROID_STL=c++_static in the toolchain
    # Don't explicitly link stdc++ on Android - it will pull in libc++_shared.so
else()
    # Linux/Unix
    target_link_libraries(dna_lib m pthread)
endif()

# =============================================================================
# Include Directories
# =============================================================================
target_include_directories(dna_lib PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include       # Unified Engine API headers
    ${CMAKE_SOURCE_DIR}/src/api       # Internal API headers
    ${CMAKE_SOURCE_DIR}/transport      # Transport layer headers
    ${CMAKE_SOURCE_DIR}/dht           # DHT headers
    ${CMAKE_SOURCE_DIR}/blockchain/cellframe  # Cellframe blockchain headers
    ${CMAKE_SOURCE_DIR}/blockchain/solana     # Solana blockchain headers
    ${CMAKE_SOURCE_DIR}/blockchain/tron       # TRON blockchain headers
    ${OPENSSL_INCLUDE_DIR}
    # JUICE_INCLUDE_DIRS removed in v0.4.61 - libjuice no longer used
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
    target_include_directories(dna_lib PUBLIC ${CMAKE_SOURCE_DIR}/win32)
endif()

# =============================================================================
# Build Type Configuration
# =============================================================================

# Option to disable AddressSanitizer in Debug builds (useful when ASAN causes issues)
option(ENABLE_ASAN "Enable AddressSanitizer in Debug builds" ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /DDEBUG")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /DDEBUG")
    else()
        if(ENABLE_ASAN)
            set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer")
            set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
            message(STATUS "Debug build enabled with AddressSanitizer")
        else()
            set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -fno-omit-frame-pointer")
            set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG -fno-omit-frame-pointer")
            message(STATUS "Debug build enabled (ASAN disabled)")
        endif()
    endif()
    add_definitions("-DDEBUG")
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

# =============================================================================
# Optional: DNA-Send CLI Tool
# =============================================================================
if(BUILD_DNA_SEND)
    add_executable(dna-send
        blockchain/cellframe/cellframe_send.c
        blockchain/cellframe/cellframe_wallet.c
        blockchain/cellframe/cellframe_wallet_create.c
        blockchain/cellframe/cellframe_addr.c
        blockchain/cellframe/cellframe_rpc.c
        crypto/utils/base58.c
        crypto/utils/qgp_platform_linux.c
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

# =============================================================================
# JNI Bindings for Android
# =============================================================================
if(ANDROID)
    add_subdirectory(jni)
endif()

# =============================================================================
# CLI Testing Tool
# =============================================================================
option(BUILD_CLI_TOOL "Build dna-messenger-cli tool for testing" ON)
if(BUILD_CLI_TOOL AND NOT ANDROID)
    add_subdirectory(cli)
endif()
