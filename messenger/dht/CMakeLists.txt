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
    add_library(dht_lib STATIC dht_context.cpp dht_offline_queue.c dht_groups.c dht_keyserver.c dht_contactlist.c dht_singleton.c dna_profile.c dna_message_wall.c gnutls_stubs_win.c)
else()
    add_library(dht_lib STATIC dht_context.cpp dht_offline_queue.c dht_groups.c dht_keyserver.c dht_contactlist.c dht_singleton.c dna_profile.c dna_message_wall.c)
endif()
target_include_directories(dht_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${OPENDHT_INCLUDE_DIRS})
target_link_libraries(dht_lib ${OPENDHT_LIBRARIES} ${OPENDHT_DEPS} ${SQLite3_LIBRARIES} crypto dsa)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD 17)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD_REQUIRED ON)

# Persistent bootstrap node (only build on Linux)
if(NOT WIN32)
    add_executable(persistent_bootstrap persistent_bootstrap.c)
    target_link_libraries(persistent_bootstrap dht_lib)
    target_include_directories(persistent_bootstrap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()
