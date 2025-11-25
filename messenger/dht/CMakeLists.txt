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
if(WIN32)
    add_library(dht_lib STATIC
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
        # Client modules (Phase 3/4)
        client/dht_identity.cpp
        client/dht_singleton.c
        client/dht_contactlist.c
        client/dht_identity_backup.c
        client/dna_profile.c
        client/dna_message_wall.c
        client/dna_wall_votes.c
        # Keyserver modules
        keyserver/keyserver_helpers.c
        keyserver/keyserver_publish.c
        keyserver/keyserver_lookup.c
        keyserver/keyserver_names.c
        keyserver/keyserver_profiles.c
        keyserver/keyserver_addresses.c
        # Platform-specific
        gnutls_stubs_win.c
        ../crypto/utils/qgp_sha3.c
        ../crypto/utils/qgp_dilithium.c
        ../blockchain/blockchain_rpc.c
        ../crypto/utils/qgp_random.c
        ../crypto/utils/qgp_platform_windows.c
        ../crypto/utils/qgp_aes.c)
else()
    add_library(dht_lib STATIC
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
        # Client modules (Phase 3/4)
        client/dht_identity.cpp
        client/dht_singleton.c
        client/dht_contactlist.c
        client/dht_identity_backup.c
        client/dna_profile.c
        client/dna_message_wall.c
        client/dna_wall_votes.c
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
        ../blockchain/blockchain_rpc.c
        ../crypto/utils/qgp_random.c
        ../crypto/utils/qgp_platform_linux.c
        ../crypto/utils/qgp_aes.c)
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
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES})
else()
    target_link_libraries(dht_lib ${OPENSSL_LIBRARIES} dsa ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES} json-c curl)
endif()
set_property(TARGET dht_lib PROPERTY CXX_STANDARD 17)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD_REQUIRED ON)

# Note: persistent_bootstrap has been moved to bootstrap/CMakeLists.txt
