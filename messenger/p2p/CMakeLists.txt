cmake_minimum_required(VERSION 3.10)
project(dna_p2p C)

set(CMAKE_C_STANDARD 11)

# Find required packages
find_package(OpenSSL REQUIRED)

if(WIN32)
    # Windows cross-compile: OpenDHT found via CMAKE_PREFIX_PATH
    message(STATUS "Using OpenDHT from CMAKE_PREFIX_PATH for Windows (P2P)")
elseif(ANDROID)
    # Android: OpenDHT is built as part of vendor/opendht-pq
    message(STATUS "Using vendor OpenDHT-PQ for Android (P2P)")
    set(OPENDHT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/vendor/opendht-pq/include")
    set(OPENDHT_LIBRARIES opendht)
else()
    # Linux: Use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENDHT REQUIRED opendht>=3.0)
endif()

# Get absolute path to DHT directory
get_filename_component(DHT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dht" ABSOLUTE)

# DHT library is built as part of the main build (via add_subdirectory)
# We reference it as a target, not as a file path
set(DHT_LIB dht_lib)

# P2P Transport library (modular architecture)
add_library(p2p_transport STATIC
    p2p_transport.c
    transport/transport_helpers.c
    transport/transport_tcp.c
    transport/transport_discovery.c
    transport/transport_offline.c
    transport/transport_juice.c            # NAT traversal (libjuice - replaces libnice)
    transport/turn_credentials.c           # TURN credential client (requests from dna-nodus)
)

target_include_directories(p2p_transport PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DHT_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${OPENDHT_INCLUDE_DIRS}
    ${JUICE_INCLUDE_DIRS}  # libjuice headers (replaces libnice + glib)
)

target_link_libraries(p2p_transport
    ${DHT_LIB}
    ${OPENDHT_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${JUICE_LIBRARIES}     # libjuice for NAT traversal (replaces libnice + glib)
)

# Platform-specific libraries
if(WIN32)
    target_link_libraries(p2p_transport ws2_32 iphlpapi pthread)
elseif(ANDROID)
    # Android: pthread is part of bionic libc, no explicit linking needed
else()
    target_link_libraries(p2p_transport pthread)
endif()


message(STATUS "DHT directory: ${DHT_DIR}")
message(STATUS "DHT library: ${DHT_LIB}")
message(STATUS "OpenDHT include dirs: ${OPENDHT_INCLUDE_DIRS}")
message(STATUS "OpenDHT libraries: ${OPENDHT_LIBRARIES}")
