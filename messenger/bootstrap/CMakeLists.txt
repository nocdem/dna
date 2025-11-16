# Bootstrap Server Build System
# Minimal dependencies - no messenger, wallet, or GUI components

cmake_minimum_required(VERSION 3.10)

# Bootstrap Value Storage Library (SQLite persistence)
add_library(bootstrap_value_storage STATIC
    services/value_storage/dht_value_storage.cpp
    services/value_storage/dht_value_storage.h
)

target_include_directories(bootstrap_value_storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/services/value_storage
    ${CMAKE_SOURCE_DIR}/dht
    ${CMAKE_SOURCE_DIR}/dht/core
    ${CMAKE_SOURCE_DIR}/dht/shared
)

target_link_libraries(bootstrap_value_storage
    SQLite::SQLite3
    pthread
)

# Bootstrap binary
if(NOT WIN32)
    add_executable(persistent_bootstrap
        core/bootstrap_main.c
    )

    target_include_directories(persistent_bootstrap PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/core
        ${CMAKE_CURRENT_SOURCE_DIR}/services/value_storage
        ${CMAKE_SOURCE_DIR}/dht
        ${CMAKE_SOURCE_DIR}/dht/core
        ${CMAKE_SOURCE_DIR}/dht/shared
        ${CMAKE_SOURCE_DIR}/crypto/utils
    )

    target_link_libraries(persistent_bootstrap
        bootstrap_value_storage
        dht_lib
    )

    # Installation
    install(TARGETS persistent_bootstrap
            RUNTIME DESTINATION bin)

    install(FILES deployment/dna-dht-bootstrap.service
            DESTINATION /etc/systemd/system/
            OPTIONAL)
endif()

# Migration utility
if(NOT WIN32)
    add_executable(migrate_storage_once
        services/value_storage/migrate_storage_once.cpp
    )

    target_include_directories(migrate_storage_once PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/services/value_storage
        ${CMAKE_SOURCE_DIR}/dht
        ${CMAKE_SOURCE_DIR}/dht/core
        ${CMAKE_SOURCE_DIR}/dht/shared
    )

    target_link_libraries(migrate_storage_once
        bootstrap_value_storage
        dht_lib
    )
endif()
