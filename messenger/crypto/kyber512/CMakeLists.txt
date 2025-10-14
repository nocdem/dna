# Kyber512 KEM Implementation
# Reference: pq-crystals/kyber (vendored from Cellframe SDK)
# NIST FIPS 203 (ML-KEM)
# SDK Independence: Removed dap_core/dap_crypto dependencies

cmake_minimum_required(VERSION 3.10)

project(kyber512 C)
set(CMAKE_C_STANDARD 11)

# Platform-specific definitions
if(NOT MSVC)
    add_definitions("-D_GNU_SOURCE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-stringop-overflow")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12.2)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Warray-parameter=0")
    endif()
endif()

# Kyber512 source files
set(KYBER512_SOURCES
    kem.c
    indcpa.c
    poly_kyber.c
    polyvec.c
    ntt_kyber.c
    cbd.c
    reduce_kyber.c
    verify.c
    symmetric-shake.c
    fips202_kyber.c
)

# Kyber512 headers
set(KYBER512_HEADERS
    kem.h
    indcpa.h
    params.h
    poly_kyber.h
    polyvec.h
    ntt_kyber.h
    cbd.h
    reduce_kyber.h
    verify.h
    symmetric.h
    fips202_kyber.h
)

# Create Kyber512 static library
add_library(${PROJECT_NAME} STATIC ${KYBER512_SOURCES} ${KYBER512_HEADERS})

# Include directory for Kyber headers
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# No external dependencies - uses qgp_randombytes via #define in kem.c and indcpa.c