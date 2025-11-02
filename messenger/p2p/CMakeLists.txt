cmake_minimum_required(VERSION 3.10)
project(dna_p2p C)

set(CMAKE_C_STANDARD 11)

# Find required packages
find_package(OpenSSL REQUIRED)

if(WIN32)
    # Windows cross-compile: Use manually-built OpenDHT
    set(MXE_PREFIX "$ENV{HOME}/.cache/mxe/usr/x86_64-w64-mingw32.static")
    set(OPENDHT_INCLUDE_DIRS "${MXE_PREFIX}/include")
    set(OPENDHT_LIBRARIES "${MXE_PREFIX}/lib/libopendht.a")
    message(STATUS "Using manually-built OpenDHT for Windows (P2P)")
else()
    # Linux: Use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENDHT REQUIRED opendht>=2.0)
endif()

# Get absolute path to DHT directory
get_filename_component(DHT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dht" ABSOLUTE)

# DHT library is built as part of the main build (via add_subdirectory)
# We reference it as a target, not as a file path
set(DHT_LIB dht_lib)

# P2P Transport library
add_library(p2p_transport STATIC
    p2p_transport.c
)

target_include_directories(p2p_transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DHT_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${OPENDHT_INCLUDE_DIRS}
)

target_link_libraries(p2p_transport
    ${DHT_LIB}
    ${OPENDHT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(p2p_transport ws2_32 iphlpapi)
else()
    target_link_libraries(p2p_transport pthread)
endif()

# Test program (only build on Linux)
if(NOT WIN32)
    add_executable(test_p2p_basic test_p2p_basic.c)

    target_include_directories(test_p2p_basic PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${DHT_DIR}
        ${OPENDHT_INCLUDE_DIRS}
    )

    target_link_libraries(test_p2p_basic
        p2p_transport
        ${DHT_LIB}
        ${OPENDHT_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        stdc++
        pthread
    )
endif()

message(STATUS "DHT directory: ${DHT_DIR}")
message(STATUS "DHT library: ${DHT_LIB}")
message(STATUS "OpenDHT include dirs: ${OPENDHT_INCLUDE_DIRS}")
message(STATUS "OpenDHT libraries: ${OPENDHT_LIBRARIES}")
