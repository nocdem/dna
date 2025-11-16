cmake_minimum_required(VERSION 3.10)
project(dna_dht C CXX)

# Find OpenDHT
if(WIN32)
    # Windows cross-compile: Use manually-built OpenDHT
    set(MXE_PREFIX "$ENV{HOME}/.cache/mxe/usr/x86_64-w64-mingw32.static")
    set(OPENDHT_INCLUDE_DIRS "${MXE_PREFIX}/include")
    set(OPENDHT_LIBRARIES "${MXE_PREFIX}/lib/libopendht.a")

    # OpenDHT dependencies for Windows (order matters for static linking!)
    # Dependencies must come AFTER the libraries that use them
    set(OPENDHT_DEPS
        "${MXE_PREFIX}/lib/libjsoncpp.a"
        "${MXE_PREFIX}/lib/libfmt.a"
        "${MXE_PREFIX}/lib/libargon2.a"
        "${MXE_PREFIX}/lib/libgnutls.a"
        "${MXE_PREFIX}/lib/libhogweed.a"
        "${MXE_PREFIX}/lib/libnettle.a"
        "${MXE_PREFIX}/lib/libtasn1.a"       # ASN.1 parsing (gnutls dependency)
        "${MXE_PREFIX}/lib/libidn2.a"        # IDN support (needs libunistring)
        "${MXE_PREFIX}/lib/libunistring.a"   # Unicode strings (needs libiconv)
        "${MXE_PREFIX}/lib/libiconv.a"       # Character encoding (must be AFTER libunistring)
        "${MXE_PREFIX}/lib/libzstd.a"        # ZSTD compression (gnutls dependency)
        "${MXE_PREFIX}/lib/libbrotlidec.a"   # Brotli decompression (gnutls dependency)
        "${MXE_PREFIX}/lib/libbrotlienc.a"   # Brotli compression (gnutls dependency)
        "${MXE_PREFIX}/lib/libbrotlicommon.a" # Brotli common (must be AFTER enc/dec)
        "${MXE_PREFIX}/lib/libgmp.a"
        ws2_32 crypt32 bcrypt ncrypt        # Windows system libraries
    )
    message(STATUS "Using manually-built OpenDHT for Windows")
    message(STATUS "OpenDHT library: ${OPENDHT_LIBRARIES}")
else()
    # Linux: Use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENDHT REQUIRED opendht>=2.0)
    set(OPENDHT_DEPS ${OPENDHT_LIBRARIES})
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
target_link_libraries(dht_lib crypto dsa ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES} gnutls json-c curl)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD 17)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD_REQUIRED ON)

# Note: persistent_bootstrap has been moved to bootstrap/CMakeLists.txt
