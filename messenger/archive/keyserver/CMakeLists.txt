cmake_minimum_required(VERSION 3.10)
project(dna_keyserver C)

set(CMAKE_C_STANDARD 11)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")

# Find dependencies
find_package(PkgConfig REQUIRED)

# libmicrohttpd
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
include_directories(${MICROHTTPD_INCLUDE_DIRS})
link_directories(${MICROHTTPD_LIBRARY_DIRS})

# SQLite3 (migrated from PostgreSQL 2025-11-03)
find_package(SQLite3 REQUIRED)
if(SQLite3_FOUND)
    message(STATUS "SQLite3 found:")
    message(STATUS "  Version: ${SQLite3_VERSION}")
    message(STATUS "  Include: ${SQLite3_INCLUDE_DIRS}")
    message(STATUS "  Library: ${SQLite3_LIBRARIES}")
    include_directories(${SQLite3_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "SQLite3 not found")
endif()

# json-c
pkg_check_modules(JSON_C REQUIRED json-c)
include_directories(${JSON_C_INCLUDE_DIRS})
link_directories(${JSON_C_LIBRARY_DIRS})

# Source files
set(SOURCES
    src/main.c
    src/config.c
    src/db.c
    src/validation.c
    src/signature.c
    src/rate_limit.c
    src/api_register.c
    src/api_update.c
    src/api_lookup.c
    src/api_list.c
    src/api_health.c
    src/http_utils.c
)

# Headers
set(HEADERS
    src/keyserver.h
    src/config.h
    src/db.h
    src/validation.h
    src/signature.h
    src/rate_limit.h
    src/http_utils.h
)

# Executable
add_executable(keyserver ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(keyserver
    ${MICROHTTPD_LIBRARIES}
    ${SQLite3_LIBRARIES}
    ${JSON_C_LIBRARIES}
    m  # math library
)

# Install target
install(TARGETS keyserver DESTINATION bin)
install(FILES config/keyserver.conf.example DESTINATION etc/dna-keyserver)
install(FILES sql/schema_sqlite.sql DESTINATION share/dna-keyserver/sql)

# Print configuration
message(STATUS "")
message(STATUS "Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C flags: ${CMAKE_C_FLAGS}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  libmicrohttpd: ${MICROHTTPD_VERSION}")
message(STATUS "  json-c: ${JSON_C_VERSION}")
message(STATUS "")
