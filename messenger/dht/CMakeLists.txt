cmake_minimum_required(VERSION 3.10)
project(dna_dht C)

# Nodus v5 replaces OpenDHT-PQ. The nodus_init module handles lifecycle,
# nodus_ops handles all DHT operations. No compat shim needed.
# The nodus_lib target is built by add_subdirectory(../nodus) in root CMakeLists.txt.
message(STATUS "Using Nodus v5 (post-quantum DHT — pure C, direct integration)")
set(DHT_COMMON_SOURCES
    # Core modules
    core/dht_keyserver.c
    core/dht_bootstrap_registry.c
    # Shared modules
    shared/dht_offline_queue.c
    shared/dht_dm_outbox.c    # Daily bucket DM outbox (v0.4.81+)
    shared/dht_groups.c
    shared/dht_profile.c
    shared/dht_gek_storage.c  # GEK chunked storage
    shared/dht_publish_queue.c  # Non-blocking publish queue (v0.6.80+)
    shared/dht_contact_request.c  # ICQ-style contact request system
    shared/dht_channel_subscriptions.c  # Channel subscription DHT sync
    shared/nodus_ops.c                  # Nodus v5 direct operations layer
    shared/nodus_init.c                 # Nodus v5 messenger init/lifecycle
    # Client modules
    client/bootstrap_cache.c          # Bootstrap node SQLite cache
    client/dht_contactlist.c
    client/dht_grouplist.c        # Group list DHT sync (v0.5.26+)
    client/dht_geks.c             # GEK DHT sync (v0.6.49+)
    client/dht_addressbook.c      # Wallet address book DHT sync
    client/dht_message_backup.c
    client/dna_profile.c
    client/dna_channels.c       # Channels: DHT channel operations
    client/dna_group_outbox.c   # Group message outbox (feed pattern)
    client/dna_wall.c           # Personal wall posts (DHT)
    client/dna_wall_comments.c  # Wall post comments (v0.7.0+)
    # Keyserver modules
    keyserver/keyserver_helpers.c
    keyserver/keyserver_publish.c
    keyserver/keyserver_lookup.c
    keyserver/keyserver_names.c
    keyserver/keyserver_profiles.c
    keyserver/keyserver_addresses.c
    # Crypto utilities
    ${SHARED_DIR}/crypto/utils/qgp_sha3.c
    ${SHARED_DIR}/crypto/utils/qgp_dilithium.c
    ${SHARED_DIR}/crypto/utils/qgp_random.c
    ${SHARED_DIR}/crypto/utils/qgp_aes.c
    ${SHARED_DIR}/crypto/utils/qgp_log.c
    # Config (needed by qgp_log.c for auto-loading log settings)
    ../dna_config.c
)

if(WIN32)
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        # Platform-specific
        gnutls_win_shim.c
        ../blockchain/cellframe/cellframe_rpc.c
        ${SHARED_DIR}/crypto/utils/qgp_platform_windows.c
    )
elseif(ANDROID)
    # Android: No curl (no wallet RPC), use Android platform source
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        ${SHARED_DIR}/crypto/utils/qgp_platform_android.c
    )
else()
    # Linux/Unix
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        ../blockchain/cellframe/cellframe_rpc.c
        ${SHARED_DIR}/crypto/utils/qgp_platform_linux.c
    )
endif()
target_include_directories(dht_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core      # Stats/keyserver headers
    ${CMAKE_CURRENT_SOURCE_DIR}/client    # Identity/singleton headers
    ${CMAKE_CURRENT_SOURCE_DIR}/shared    # Shared DHT modules
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/include           # For dna/dna_engine.h (dna_profile_t)
    ${SHARED_DIR}                         # shared/ root (for crypto/... includes)
    ${SHARED_DIR}/crypto                  # shared/crypto/ (for utils/*.h includes)
    ${CMAKE_CURRENT_SOURCE_DIR}/../blockchain/cellframe)

# Nodus v5 include paths
get_filename_component(NODUS_DIR "${CMAKE_SOURCE_DIR}/../nodus" ABSOLUTE)
target_include_directories(dht_lib PUBLIC
    ${NODUS_DIR}/include                  # nodus/nodus.h, nodus/nodus_types.h
    ${NODUS_DIR}/src                      # client/nodus_singleton.h, crypto/nodus_identity.h
)

if(WIN32)
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa nodus_lib ${SQLite3_LIBRARIES})
elseif(ANDROID)
    target_link_libraries(dht_lib
        ${OPENSSL_LIBRARIES}
        dsa
        nodus_lib
        ${SQLite3_LIBRARIES}
        ${ANDROID_DEPS_DIR}/jsonc-arm64/lib/libjson-c.a
        z
    )
else()
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa nodus_lib ${SQLite3_LIBRARIES} json-c curl z)
endif()

# Note: persistent_bootstrap has been moved to bootstrap/CMakeLists.txt
# Note: Debug tools (quick_lookup, clear_outbox, query_outbox) moved to archive/dht-tools/
