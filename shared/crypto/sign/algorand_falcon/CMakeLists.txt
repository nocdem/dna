cmake_minimum_required(VERSION 3.16)
project(qgp_algorand_falcon LANGUAGES C)

add_library(qgp_algorand_falcon STATIC
    qgp_algorand_falcon.c
    upstream/codec.c upstream/common.c upstream/falcon.c upstream/fft.c
    upstream/fpr.c upstream/keygen.c upstream/rng.c upstream/shake.c
    upstream/sign.c upstream/vrfy.c upstream/deterministic1024.c)
target_compile_features(qgp_algorand_falcon PUBLIC c_std_99)
target_compile_definitions(qgp_algorand_falcon PRIVATE FALCON_UNALIGNED=0)
target_include_directories(qgp_algorand_falcon PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
get_filename_component(QGP_SHARED_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
target_include_directories(qgp_algorand_falcon PRIVATE "${QGP_SHARED_ROOT}")
set_target_properties(qgp_algorand_falcon PROPERTIES POSITION_INDEPENDENT_CODE ON)
