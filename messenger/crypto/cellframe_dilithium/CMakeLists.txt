cmake_minimum_required(VERSION 3.10)
project(cellframe_dilithium C)

set(CELLFRAME_DILITHIUM_SOURCES
    fips202.c
    dilithium_params.c
    dilithium_poly.c
    dilithium_polyvec.c
    dilithium_packing.c
    dilithium_rounding_reduce.c
    dilithium_sign.c
    cellframe_dilithium_api.c
    dap_compat.c
)

add_library(cellframe_dilithium STATIC ${CELLFRAME_DILITHIUM_SOURCES})

target_include_directories(cellframe_dilithium PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
