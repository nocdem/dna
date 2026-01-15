cmake_minimum_required(VERSION 3.10)
project(dna_transport C)

set(CMAKE_C_STANDARD 11)

# Find required packages
find_package(OpenSSL REQUIRED)

if(WIN32)
    # Windows cross-compile: OpenDHT found via CMAKE_PREFIX_PATH
    message(STATUS "Using OpenDHT from CMAKE_PREFIX_PATH for Windows (Transport)")
else()
    # Linux/Android: Use vendored OpenDHT-PQ
    message(STATUS "Using vendor OpenDHT-PQ (Transport)")
    set(OPENDHT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/vendor/opendht-pq/include")
    set(OPENDHT_LIBRARIES opendht)
endif()

# Get absolute path to DHT directory
get_filename_component(DHT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dht" ABSOLUTE)

# DHT library is built as part of the main build (via add_subdirectory)
set(DHT_LIB dht_lib)

# Transport library (DHT-only messaging)
add_library(transport_lib STATIC
    transport.c
    internal/transport_helpers.c
    internal/transport_discovery.c
    internal/transport_offline.c
)

target_include_directories(transport_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DHT_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${OPENDHT_INCLUDE_DIRS}
)

target_link_libraries(transport_lib
    ${DHT_LIB}
    ${OPENDHT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(transport_lib ws2_32 pthread)
elseif(ANDROID)
    # Android: pthread is part of bionic libc, no explicit linking needed
else()
    target_link_libraries(transport_lib pthread)
endif()

message(STATUS "DHT directory: ${DHT_DIR}")
message(STATUS "DHT library: ${DHT_LIB}")
message(STATUS "OpenDHT include dirs: ${OPENDHT_INCLUDE_DIRS}")
message(STATUS "OpenDHT libraries: ${OPENDHT_LIBRARIES}")
