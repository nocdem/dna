# Dilithium5 (ML-DSA-87) signature scheme library
# SDK Independence: Vendored from pq-crystals/dilithium reference implementation
# FIPS 204 compliant - NIST Category 5 security (256-bit quantum)

cmake_minimum_required(VERSION 3.10)

project(dsa C)

# Source files
set(DILITHIUM_SOURCES
    fips202.c
    ntt.c
    packing.c
    poly.c
    polyvec.c
    reduce.c
    rounding.c
    sign.c
    symmetric-shake.c
)

# Header files
set(DILITHIUM_HEADERS
    api.h
    config.h
    fips202.h
    ntt.h
    packing.h
    params.h
    poly.h
    polyvec.h
    randombytes.h
    reduce.h
    rounding.h
    sign.h
    symmetric.h
)

# Create static library
add_library(dsa STATIC ${DILITHIUM_SOURCES})

# Include directories
target_include_directories(dsa PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..  # For qgp_random.h
)

# Compiler flags (cross-platform)
if(MSVC)
    # MSVC compiler flags
    target_compile_options(dsa PRIVATE
        /W3           # Warning level 3
        /O2           # Optimize for speed
    )
    # DILITHIUM_MODE now defined in config.h (Category 5: ML-DSA-87)
else()
    # GCC/Clang compiler flags
    target_compile_options(dsa PRIVATE
        -Wall
        -Wextra
        -O3
        -fPIC  # Position Independent Code for shared library linking
    )
    # DILITHIUM_MODE now defined in config.h (Category 5: ML-DSA-87)
endif()

# Installation
install(TARGETS dsa
    ARCHIVE DESTINATION lib
)

install(FILES ${DILITHIUM_HEADERS}
    DESTINATION include/dsa
)
