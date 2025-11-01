cmake_minimum_required(VERSION 3.10)
project(dna_p2p C)

set(CMAKE_C_STANDARD 11)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENDHT REQUIRED opendht>=2.0)

# Get absolute path to DHT directory
get_filename_component(DHT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dht" ABSOLUTE)
set(DHT_LIB "${DHT_DIR}/build/libdht_lib.a")

# Check if DHT library exists
if(NOT EXISTS "${DHT_LIB}")
    message(FATAL_ERROR "DHT library not found at ${DHT_LIB}. Please build DHT first: cd ../dht && mkdir -p build && cd build && cmake .. && make")
endif()

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
    pthread
)

# Test program
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
    pthread
    stdc++
)

message(STATUS "DHT directory: ${DHT_DIR}")
message(STATUS "DHT library: ${DHT_LIB}")
message(STATUS "OpenDHT include dirs: ${OPENDHT_INCLUDE_DIRS}")
message(STATUS "OpenDHT libraries: ${OPENDHT_LIBRARIES}")
