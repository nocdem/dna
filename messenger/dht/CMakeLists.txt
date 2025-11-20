cmake_minimum_required(VERSION 3.10)
project(dna_dht C CXX)

# Find OpenDHT
if(WIN32)
    # Windows cross-compile: OpenDHT found via CMAKE_PREFIX_PATH (llvm-mingw)
    # CMAKE_PREFIX_PATH is set in main CMakeLists.txt to point to llvm-mingw x86_64-w64-mingw32/
    find_library(OPENDHT_LIB opendht REQUIRED)
    find_library(JSONCPP_LIB jsoncpp REQUIRED)
    find_library(FMT_LIB fmt REQUIRED)
    find_library(ARGON2_LIB argon2 REQUIRED)
    # Note: SSL and crypto libraries are handled by ${OPENSSL_LIBRARIES} in target_link_libraries
    find_library(JSONC_LIB json-c REQUIRED)
    find_library(CURL_LIB curl REQUIRED)

    set(OPENDHT_LIBRARIES "${OPENDHT_LIB}")
    set(OPENDHT_INCLUDE_DIRS "${CMAKE_PREFIX_PATH}/include")

    # OpenDHT dependencies for Windows (order matters for static linking!)
    # Dependencies must come AFTER the libraries that use them
    # Note: OpenSSL (ssl/crypto) is linked via ${OPENSSL_LIBRARIES} in target_link_libraries below
    set(OPENDHT_DEPS
        "${JSONCPP_LIB}"
        "${FMT_LIB}"
        "${ARGON2_LIB}"
        "${JSONC_LIB}"                       # json-c for contact lists
        "${CURL_LIB}"                        # CURL for HTTP
        ws2_32 crypt32 bcrypt ncrypt         # Windows system libraries
    )
    message(STATUS "Using OpenDHT from CMAKE_PREFIX_PATH for Windows (DHT)")
    message(STATUS "OpenDHT library: ${OPENDHT_LIBRARIES}")
else()
    # Linux: Use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENDHT REQUIRED opendht>=3.0)
    set(OPENDHT_DEPS ${OPENDHT_LIBRARIES})
    # Add library directories so linker can find libopendht.a
    link_directories(${OPENDHT_LIBRARY_DIRS})
    # Export to parent scope so test executables can find the library
    set(OPENDHT_LIBRARY_DIRS ${OPENDHT_LIBRARY_DIRS} PARENT_SCOPE)
endif()

# DHT library
if(WIN32)
    add_library(dht_lib STATIC
        # Core modules (Phase 3/4)
        core/dht_context.cpp
        core/dht_stats.cpp
        core/dht_keyserver.c
        # Shared modules (Phase 4)
        shared/dht_value_storage.cpp
        shared/dht_offline_queue.c
        shared/dht_groups.c
        shared/dht_profile.c
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
        core/dht_stats.cpp
        core/dht_keyserver.c
        # Shared modules (Phase 4)
        shared/dht_value_storage.cpp
        shared/dht_offline_queue.c
        shared/dht_groups.c
        shared/dht_profile.c
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
