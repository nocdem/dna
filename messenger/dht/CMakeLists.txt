cmake_minimum_required(VERSION 3.10)
project(dna_dht C CXX)

# Find OpenDHT
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENDHT REQUIRED opendht>=2.0)

# DHT library
add_library(dht_lib STATIC dht_context.cpp)
target_include_directories(dht_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${OPENDHT_INCLUDE_DIRS})
target_link_libraries(dht_lib ${OPENDHT_LIBRARIES})
set_property(TARGET dht_lib PROPERTY CXX_STANDARD 17)
set_property(TARGET dht_lib PROPERTY CXX_STANDARD_REQUIRED ON)

# Test programs
add_executable(test_dht_basic test_dht_basic.c)
target_link_libraries(test_dht_basic dht_lib)
target_include_directories(test_dht_basic PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_dht_3nodes test_dht_3nodes.c)
target_link_libraries(test_dht_3nodes dht_lib)
target_include_directories(test_dht_3nodes PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Persistent bootstrap node
add_executable(persistent_bootstrap persistent_bootstrap.c)
target_link_libraries(persistent_bootstrap dht_lib)
target_include_directories(persistent_bootstrap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
