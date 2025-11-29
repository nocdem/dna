cmake_minimum_required(VERSION 3.10)
project(dna_dht C CXX)

# Use vendor/opendht-pq (Dilithium5 post-quantum DHT)
# The library is built by add_subdirectory(vendor/opendht-pq) in root CMakeLists.txt
set(OPENDHT_LIBRARIES opendht)
set(OPENDHT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/vendor/opendht-pq/include")
set(OPENDHT_DEPS "")  # Dependencies are handled by opendht target

message(STATUS "Using vendor/opendht-pq (Dilithium5 post-quantum DHT)")
message(STATUS "OpenDHT-PQ include: ${OPENDHT_INCLUDE_DIRS}")

# DHT library
# Common DHT sources (shared across all platforms)
set(DHT_COMMON_SOURCES
    # Core modules (Phase 3/4)
    core/dht_context.cpp
    core/dht_listen.cpp
    core/dht_stats.cpp
    core/dht_keyserver.c
    core/dht_bootstrap_registry.c
    # Shared modules (Phase 4)
    shared/dht_value_storage.cpp
    shared/dht_offline_queue.c
    shared/dht_groups.c
    shared/dht_profile.c
    shared/dht_gsk_storage.c  # Phase 13: GSK chunked storage
    shared/dht_chunked.c      # Generic chunked storage layer
    # Client modules (Phase 3/4)
    client/dht_identity.cpp
    client/dht_singleton.c
    client/dht_contactlist.c
    client/dht_identity_backup.c
    client/dna_profile.c
    client/dna_message_wall.c
    client/dna_wall_votes.c
    client/dna_feed_channels.c
    client/dna_feed_posts.c
    client/dna_feed_votes.c
    client/dna_group_outbox.c   # Group message outbox (feed pattern)
    # Keyserver modules
    keyserver/keyserver_helpers.c
    keyserver/keyserver_publish.c
    keyserver/keyserver_lookup.c
    keyserver/keyserver_names.c
    keyserver/keyserver_profiles.c
    keyserver/keyserver_addresses.c
    # Crypto utilities
    ../crypto/utils/qgp_sha3.c
    ../crypto/utils/qgp_dilithium.c
    ../crypto/utils/qgp_random.c
    ../crypto/utils/qgp_aes.c
)

if(WIN32)
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        # Platform-specific
        gnutls_win_shim.c
        ../blockchain/blockchain_rpc.c
        ../crypto/utils/qgp_platform_windows.c
    )
elseif(ANDROID)
    # Android: No curl (no wallet RPC), use Android platform source
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        ../crypto/utils/qgp_platform_android.c
    )
else()
    # Linux/Unix
    add_library(dht_lib STATIC
        ${DHT_COMMON_SOURCES}
        ../blockchain/blockchain_rpc.c
        ../crypto/utils/qgp_platform_linux.c
    )
endif()
target_include_directories(dht_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core      # Phase 3: Stats module
    ${CMAKE_CURRENT_SOURCE_DIR}/client    # Phase 3: Identity module
    ${CMAKE_CURRENT_SOURCE_DIR}/shared    # Phase 4: Shared modules
    ${OPENDHT_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../crypto)
if(WIN32)
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES} zstd)
elseif(ANDROID)
    # Android: Link against pre-built Android deps, no curl
    target_link_libraries(dht_lib
        ${OPENSSL_LIBRARIES}
        dsa
        ${OPENDHT_LIBRARIES}
        ${OPENDHT_DEPS}
        ${SQLite3_LIBRARIES}
        ${ANDROID_DEPS_DIR}/jsonc-arm64/lib/libjson-c.a
        ${ANDROID_DEPS_DIR}/zstd-arm64/lib/libzstd.a
        z
    )
else()
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES} json-c curl zstd z)
endif()
set_property(TARGET dht_lib PROPERTY CXX_STANDARD 17)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD_REQUIRED ON)

# Note: persistent_bootstrap has been moved to bootstrap/CMakeLists.txt
