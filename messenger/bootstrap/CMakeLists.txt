# Bootstrap Server Build System
# Minimal dependencies - no messenger, wallet, or GUI components

cmake_minimum_required(VERSION 3.10)

# Add OpenDHT library directories for bootstrap executables (Linux only)
if(OPENDHT_LIBRARY_DIRS)
    link_directories(${OPENDHT_LIBRARY_DIRS})
endif()

# Bootstrap Value Storage Library - REMOVED (now in dht_lib/shared)
# The dht_value_storage is now part of dht_lib (dht/shared/dht_value_storage.cpp)
# No need for separate bootstrap_value_storage library

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
        -Wl,--start-group
        dht_lib    # Contains qgp_randombytes
        opendht    # Dilithium5 DHT (needs dsa)
        dsa        # Dilithium5 crypto (needs qgp_randombytes from dht_lib)
        -Wl,--end-group
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
        -Wl,--start-group
        dht_lib  # Circular dependency with opendht/dsa
        -Wl,--end-group
    )
endif()
