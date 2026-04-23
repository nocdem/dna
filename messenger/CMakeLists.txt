cmake_minimum_required(VERSION 3.10)
project(dna C CXX)  # C for core library, C++ for DHT components

# =============================================================================
# Build Options
# =============================================================================
# Default to SHARED on Linux desktop (needed for Flutter Linux native library loading)
if(UNIX AND NOT APPLE AND NOT ANDROID)
    option(BUILD_SHARED_LIB "Build dna as shared library (for Flutter)" ON)
else()
    option(BUILD_SHARED_LIB "Build dna as shared library (for Flutter)" OFF)
endif()



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
# Shared Libraries (monorepo: shared/ at repo root)
# =============================================================================
set(SHARED_DIR "${CMAKE_SOURCE_DIR}/../shared")

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

# Vendored Cryptographic Libraries (in shared/crypto/)
add_subdirectory(${SHARED_DIR}/crypto/enc/kem ${CMAKE_BINARY_DIR}/crypto/kem)          # ML-KEM-1024 KEM
add_subdirectory(${SHARED_DIR}/crypto/sign/dsa ${CMAKE_BINARY_DIR}/crypto/dsa)          # ML-DSA-87 signatures
add_subdirectory(${SHARED_DIR}/crypto/sign/cellframe_dilithium ${CMAKE_BINARY_DIR}/crypto/cellframe_dilithium)  # Cellframe Dilithium

# secp256k1 for Ethereum/Bitcoin key derivation (BIP-32/BIP-44)
include(${CMAKE_SOURCE_DIR}/cmake/Secp256k1.cmake)

# =============================================================================
# DHT and P2P Transport Layer — Nodus v5
# =============================================================================
# NODUS_STANDALONE=OFF: shared crypto already compiled in dht_lib, skip duplicates
set(NODUS_STANDALONE OFF CACHE BOOL "Nodus built within messenger tree" FORCE)
add_subdirectory(${CMAKE_SOURCE_DIR}/../nodus ${CMAKE_BINARY_DIR}/nodus)

add_subdirectory(dht)               # DHT integration (uses Nodus v5 compat shim)
add_subdirectory(transport)         # Transport layer (DHT-only messaging)

# =============================================================================
# Blockchain Minimal Library
# =============================================================================
# MUST be defined BEFORE other targets that depend on it
add_library(cellframe_minimal STATIC
    blockchain/cellframe/cellframe_tx_builder.c
    blockchain/cellframe/cellframe_sign.c
    blockchain/cellframe/cellframe_json.c
    ${SHARED_DIR}/crypto/utils/base58.c
)
target_include_directories(cellframe_minimal PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${SHARED_DIR}
    ${SHARED_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/include
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
    #   cmd_export_pubkey → crypto/key/qgp_key.c
    #   cmd_restore_key_from_seed → messenger/keygen.c
    #   read_file_data → qgp_platform_*.c
    #   get_home_dir, build_path, file_exists → replaced with qgp_platform_* calls
    ${SHARED_DIR}/crypto/utils/armor.c
    ${SHARED_DIR}/crypto/enc/aes_keywrap.c
    ${SHARED_DIR}/crypto/key/bip39/bip39.c
    ${SHARED_DIR}/crypto/key/bip39/bip39_pbkdf2.c
    ${SHARED_DIR}/crypto/key/bip39/seed_derivation.c
    ${SHARED_DIR}/crypto/enc/kyber_deterministic.c
    dna_config.c
    # SDK Independence: New crypto modules
    ${SHARED_DIR}/crypto/utils/qgp_random.c
    ${SHARED_DIR}/crypto/enc/qgp_aes.c
    ${SHARED_DIR}/crypto/enc/qgp_kyber.c
    ${SHARED_DIR}/crypto/sign/qgp_dilithium.c
    ${SHARED_DIR}/crypto/key/seed_storage.c
    ${SHARED_DIR}/crypto/hash/qgp_sha3.c         # SHA3-512 for Category 5 security
    ${SHARED_DIR}/crypto/hash/hkdf_sha3.c        # HKDF-SHA3-256 key derivation
    # NOTE: qgp_log.c is ONLY in dht_lib to ensure single copy of static vars
    # SDK Independence: Infrastructure modules
    ${SHARED_DIR}/crypto/key/qgp_key.c
    ${SHARED_DIR}/crypto/key/key_encryption.c
    ${SHARED_DIR}/crypto/sign/qgp_signature.c
    ${SHARED_DIR}/crypto/sign/secp256k1_sign.c        # secp256k1 ECDSA recoverable signing
    ${SHARED_DIR}/crypto/sign/ed25519_sign.c           # Ed25519 signing (Solana)
    ${SHARED_DIR}/crypto/utils/qgp_utils_standalone.c
    ${SHARED_DIR}/crypto/utils/qgp_u128.c         # Portable u128 for DNAC reward accumulator (F-CRYPTO-08)
    ${SHARED_DIR}/crypto/utils/qgp_fingerprint.c  # Shared fp hex<->raw converters
    ${SHARED_DIR}/crypto/utils/threadpool.c       # Centralized thread pool for parallel I/O
    # Cross-platform abstraction layer
    ${PLATFORM_SOURCES}
)

# Platform keystore: TEE on Android, noop on desktop
if(ANDROID)
    set(PLATFORM_KEYSTORE_SRC ${SHARED_DIR}/crypto/utils/platform_keystore_android.c)
else()
    set(PLATFORM_KEYSTORE_SRC ${SHARED_DIR}/crypto/utils/platform_keystore_noop.c)
endif()
list(APPEND COMMON_SOURCES ${PLATFORM_KEYSTORE_SRC})

# =============================================================================
# DNA Connect Library (libdna)
# =============================================================================

# Windows DLL export macro
if(BUILD_SHARED_LIB AND WIN32)
    add_compile_definitions(DNA_LIB_EXPORTS)
endif()

# Build dna as either SHARED or STATIC based on BUILD_SHARED_LIB
if(BUILD_SHARED_LIB)
    add_library(dna SHARED
        dna_api.c
        # Unified Engine API (Core/GUI separation)
        src/api/dna_engine.c
        # Modular engine components
        src/api/engine/dna_engine_channels.c
        src/api/engine/dna_engine_wall.c
        src/api/engine/dna_engine_wall_poll.c
        src/api/engine/dna_engine_follow.c
        src/api/engine/dna_engine_media.c
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
        src/api/engine/dna_engine_debug_log.c
        src/api/engine/dna_debug_log_wire.c
        src/api/engine/dna_engine_dnac.c
        src/reaction/reaction_json.c
        # DNAC (digital cash) — compiled into libdna for single .so
        ${CMAKE_SOURCE_DIR}/../dnac/src/version.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/wallet.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/utxo.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/balance.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/selection.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/transaction.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/builder.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/serialize.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/genesis.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/nullifier.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/block.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/chain_def_codec.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/genesis_prepare.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/merkle_verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/anchor_verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/current_trust.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/client.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/discovery.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/tcp_client.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/token_create.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/stake.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/delegate.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/validator_update.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/chain_config.c
        # Note: shared/dnac/chain_config_wire.c (Hard-Fork v1) is linked in
        # via libnodus.a — no separate entry needed here. See nodus/CMakeLists.txt.
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/validator_queries.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/db/db.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/utils/crypto_helpers.c
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
        database/following_db.c     # Following list database
        database/addressbook_db.c   # Wallet address book database
        database/channel_subscriptions_db.c # Channel subscriptions database
        database/channel_cache.c    # Channel cache (metadata, posts, staleness)
        database/wall_cache.c       # Wall post cache (timeline, staleness)
        database/wallet_cache.c     # Wallet balance cache (stale-while-revalidate)
        database/profile_cache.c    # Profile cache database (7-day TTL)
        database/profile_manager.c  # Smart profile fetching (cache + DHT)
        database/cache_manager.c    # Unified cache lifecycle manager
        database/db_encryption.c    # SQLCipher key derivation + encrypted open wrapper
        database/group_invitations.c # Group invitation tracking database
        blockchain/cellframe/cellframe_wallet_create.c # Cellframe wallet derivation (seed-based)
        blockchain/cellframe/cellframe_rpc.c           # Blockchain RPC client
        blockchain/cellframe/cellframe_dex.c           # DEX quote (Cellframe order book)
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
        blockchain/solana/sol_dex.c                    # DEX quote (Raydium AMM on-chain)
        blockchain/ethereum/eth_dex.c                  # DEX quote (Uniswap v2/v3 on-chain)
        blockchain/ethereum/eth_eip712.c               # EIP-712 typed data signing
        blockchain/ethereum/eth_erc20.c                # ERC-20 token support (USDT, USDC)
        blockchain/tron/trx_base58.c                   # TRON Base58Check encoding
        blockchain/tron/trx_wallet_create.c            # TRON wallet creation (BIP-44)
        blockchain/tron/trx_rpc.c                      # TRON JSON-RPC client (TronGrid)
        blockchain/tron/trx_chain.c                    # TRON blockchain_ops implementation
        blockchain/tron/trx_tx.c                       # TRON transaction building/signing
        blockchain/tron/trx_trc20.c                    # TRC-20 token support (USDT, USDC)
        blockchain/bsc/bsc_chain.c                     # BSC blockchain_ops implementation
        blockchain/bsc/bsc_rpc.c                       # BSC JSON-RPC client
        blockchain/bsc/bsc_tx.c                        # BSC transaction building/signing
        blockchain/bsc/bsc_bep20.c                     # BEP-20 token support (USDT, USDC)
        ${SHARED_DIR}/crypto/key/bip32/bip32.c                           # BIP-32 HD key derivation
        ${SHARED_DIR}/crypto/hash/keccak256.c                       # Keccak-256 (Ethereum hash)
        ${SHARED_DIR}/crypto/utils/base58.c       # Base58 encoding for addresses
        ${COMMON_SOURCES}
    )
else()
    add_library(dna STATIC
        dna_api.c
        # Unified Engine API (Core/GUI separation)
        src/api/dna_engine.c
        # Modular engine components
        src/api/engine/dna_engine_channels.c
        src/api/engine/dna_engine_wall.c
        src/api/engine/dna_engine_wall_poll.c
        src/api/engine/dna_engine_follow.c
        src/api/engine/dna_engine_media.c
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
        src/api/engine/dna_engine_debug_log.c
        src/api/engine/dna_debug_log_wire.c
        src/api/engine/dna_engine_dnac.c
        src/reaction/reaction_json.c
        # DNAC (digital cash) — compiled into libdna for single .so
        ${CMAKE_SOURCE_DIR}/../dnac/src/version.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/wallet.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/utxo.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/balance.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/wallet/selection.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/transaction.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/builder.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/serialize.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/genesis.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/nullifier.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/block.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/chain_def_codec.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/genesis_prepare.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/merkle_verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/anchor_verify.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/ledger/current_trust.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/client.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/discovery.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/nodus/tcp_client.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/token_create.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/stake.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/delegate.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/validator_update.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/chain_config.c
        # Note: shared/dnac/chain_config_wire.c (Hard-Fork v1) is linked in
        # via libnodus.a — no separate entry needed here. See nodus/CMakeLists.txt.
        ${CMAKE_SOURCE_DIR}/../dnac/src/transaction/validator_queries.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/db/db.c
        ${CMAKE_SOURCE_DIR}/../dnac/src/utils/crypto_helpers.c
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
        database/following_db.c     # Following list database
        database/addressbook_db.c   # Wallet address book database
        database/channel_subscriptions_db.c # Channel subscriptions database
        database/channel_cache.c    # Channel cache (metadata, posts, staleness)
        database/wall_cache.c       # Wall post cache (timeline, staleness)
        database/wallet_cache.c     # Wallet balance cache (stale-while-revalidate)
        database/profile_cache.c    # Profile cache database (7-day TTL)
        database/profile_manager.c  # Smart profile fetching (cache + DHT)
        database/cache_manager.c    # Unified cache lifecycle manager
        database/db_encryption.c    # SQLCipher key derivation + encrypted open wrapper
        database/group_invitations.c # Group invitation tracking database
        blockchain/cellframe/cellframe_wallet_create.c # Cellframe wallet derivation (seed-based)
        blockchain/cellframe/cellframe_rpc.c           # Blockchain RPC client
        blockchain/cellframe/cellframe_dex.c           # DEX quote (Cellframe order book)
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
        blockchain/solana/sol_dex.c                    # DEX quote (Raydium AMM on-chain)
        blockchain/ethereum/eth_dex.c                  # DEX quote (Uniswap v2/v3 on-chain)
        blockchain/ethereum/eth_eip712.c               # EIP-712 typed data signing
        blockchain/ethereum/eth_erc20.c                # ERC-20 token support (USDT, USDC)
        blockchain/tron/trx_base58.c                   # TRON Base58Check encoding
        blockchain/tron/trx_wallet_create.c            # TRON wallet creation (BIP-44)
        blockchain/tron/trx_rpc.c                      # TRON JSON-RPC client (TronGrid)
        blockchain/tron/trx_chain.c                    # TRON blockchain_ops implementation
        blockchain/tron/trx_tx.c                       # TRON transaction building/signing
        blockchain/tron/trx_trc20.c                    # TRC-20 token support (USDT, USDC)
        blockchain/bsc/bsc_chain.c                     # BSC blockchain_ops implementation
        blockchain/bsc/bsc_rpc.c                       # BSC JSON-RPC client
        blockchain/bsc/bsc_tx.c                        # BSC transaction building/signing
        blockchain/bsc/bsc_bep20.c                     # BEP-20 token support (USDT, USDC)
        ${SHARED_DIR}/crypto/key/bip32/bip32.c                           # BIP-32 HD key derivation
        ${SHARED_DIR}/crypto/hash/keccak256.c                       # Keccak-256 (Ethereum hash)
        ${SHARED_DIR}/crypto/utils/base58.c       # Base58 encoding for addresses
        ${COMMON_SOURCES}
    )
endif()

# Core library dependencies
target_link_libraries(dna
    OpenSSL::Crypto
    kem
    dsa
    secp256k1          # secp256k1 for Ethereum/Bitcoin key derivation
    cellframe_minimal  # Blockchain transaction building (uint256, signing)
    dht_lib            # DHT library (MUST come BEFORE transport_lib for Windows stub symbols)
    transport_lib      # Transport layer (DHT-only messaging)
    dht_lib            # Link dht_lib again to resolve circular deps with transport_lib
    transport_lib      # Link transport_lib again for static linking order
    ${SQLCIPHER_LIBRARIES}  # SQLCipher (encrypted SQLite — database/db_encryption.c)
    ${JSONC_LIBRARIES}
    ${PLATFORM_LIBS}
)

# secp256k1 include directory for BIP-32 derivation
target_include_directories(dna PRIVATE ${SECP256K1_INCLUDE_DIR})

# C++ standard library no longer needed (pure C with Nodus v5)

# CURL linking
if(HAS_CURL)
    if(ANDROID)
        # Android: Use static library path directly
        target_link_libraries(dna ${CURL_LIBRARIES})
    else()
        target_link_libraries(dna CURL::libcurl)
    endif()
endif()

# =============================================================================
# Platform-Specific Linking
# =============================================================================
if(WIN32)
    # Windows system libraries (from WindowsBuild.cmake)
    target_link_libraries(dna ${WINDOWS_SYSTEM_LIBS})
elseif(ANDROID)
    # Android: Include JNI bindings in dna
    target_sources(dna PRIVATE ${CMAKE_SOURCE_DIR}/jni/dna_jni.c)
    target_include_directories(dna PRIVATE ${CMAKE_SOURCE_DIR}/jni)
    # Android: Link GnuTLS and its dependencies (from AndroidBuild.cmake)
    target_link_libraries(dna ${ANDROID_GNUTLS_LIBS} m log)
    # C++ STL is handled by ANDROID_STL=c++_static in the toolchain
    # Don't explicitly link stdc++ on Android - it will pull in libc++_shared.so
else()
    # Linux/Unix
    target_link_libraries(dna m pthread)
endif()

# =============================================================================
# Include Directories
# =============================================================================
target_include_directories(dna PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${SHARED_DIR}                      # Shared code root (crypto/utils/*.h)
    ${CMAKE_SOURCE_DIR}/include       # Unified Engine API headers
    ${CMAKE_SOURCE_DIR}/src/api       # Internal API headers
    ${CMAKE_SOURCE_DIR}/transport      # Transport layer headers
    ${CMAKE_SOURCE_DIR}/dht           # DHT headers
    ${CMAKE_SOURCE_DIR}/blockchain/cellframe  # Cellframe blockchain headers
    ${CMAKE_SOURCE_DIR}/blockchain/solana     # Solana blockchain headers
    ${CMAKE_SOURCE_DIR}/blockchain/tron       # TRON blockchain headers
    ${CMAKE_SOURCE_DIR}/../dnac/include       # DNAC (digital cash) headers
    ${CMAKE_SOURCE_DIR}/../dnac/src           # DNAC internal headers
    ${OPENSSL_INCLUDE_DIR}
    # JUICE_INCLUDE_DIRS removed in v0.4.61 - libjuice no longer used
)

# Add json-c include directories if found
if(JSONC_INCLUDE_DIRS)
    target_include_directories(dna PUBLIC ${JSONC_INCLUDE_DIRS})
endif()

# Add SQLCipher include directories (provides sqlite3.h via -I/usr/include/sqlcipher)
if(SQLCIPHER_INCLUDE_DIRS)
    target_include_directories(dna PUBLIC ${SQLCIPHER_INCLUDE_DIRS})
endif()

if(WIN32)
    target_include_directories(dna PUBLIC ${CMAKE_SOURCE_DIR}/win32)
endif()

# =============================================================================
# Build Type Configuration
# =============================================================================

# Option to disable AddressSanitizer in Debug builds (useful when ASAN causes issues)
option(ENABLE_ASAN "Enable AddressSanitizer in Debug builds" ON)

# Phase 2 (02-04): ThreadSanitizer for concurrency tests. Opt-in via
# -DENABLE_TSAN=ON. Mutually exclusive with ASan in the same binary.
# See messenger/docs/CONCURRENCY.md for usage.
option(ENABLE_TSAN "Build with ThreadSanitizer for concurrency tests (conflicts with ASan)" OFF)

if(ENABLE_TSAN AND ENABLE_ASAN)
    # TSan and ASan cannot coexist in the same binary. When ENABLE_TSAN is
    # requested, automatically disable ENABLE_ASAN below. Emit a fatal error
    # only if the user explicitly set BOTH to ON on the cmake command line.
    if(DEFINED CACHE{ENABLE_ASAN_EXPLICIT} AND ENABLE_ASAN_EXPLICIT)
        message(FATAL_ERROR
            "ENABLE_TSAN and ENABLE_ASAN are mutually exclusive. "
            "Pick one: -DENABLE_TSAN=ON (concurrency tests) OR "
            "-DENABLE_ASAN=ON (default, memory-safety tests).")
    endif()
    message(STATUS "ENABLE_TSAN=ON — disabling ENABLE_ASAN (mutually exclusive)")
    set(ENABLE_ASAN OFF CACHE BOOL "Disabled automatically by ENABLE_TSAN" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(MSVC)
        set(CMAKE_C_FLAGS_DEBUG "/Od /Zi /DDEBUG")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /DDEBUG")
    else()
        if(ENABLE_TSAN)
            set(CMAKE_C_FLAGS_DEBUG "-g -O1 -DDEBUG -fsanitize=thread -fno-omit-frame-pointer")
            set(CMAKE_CXX_FLAGS_DEBUG "-g -O1 -DDEBUG -fsanitize=thread -fno-omit-frame-pointer")
            set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=thread")
            set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=thread")
            message(STATUS "Debug build enabled with ThreadSanitizer (Phase 02-04)")
        elseif(ENABLE_ASAN)
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
# JNI Bindings for Android
# =============================================================================
if(ANDROID)
    add_subdirectory(jni)
endif()

# =============================================================================
# CLI Testing Tool
# =============================================================================
option(BUILD_CLI_TOOL "Build dna-connect-cli tool for testing" ON)
if(BUILD_CLI_TOOL AND NOT ANDROID)
    add_subdirectory(cli)
endif()
