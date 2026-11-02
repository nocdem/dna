cmake_minimum_required(VERSION 3.16)
project(tidecoin_sign LANGUAGES C)
if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure with emcmake")
endif()
get_filename_component(DNA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
add_subdirectory("${DNA_ROOT}/shared/crypto/sign/tidecoin_falcon" "${CMAKE_CURRENT_BINARY_DIR}/falcon")
add_executable(tidecoin_sign "${CMAKE_CURRENT_SOURCE_DIR}/../tidecoin-sign.c")
target_include_directories(tidecoin_sign PRIVATE "${DNA_ROOT}/shared")
target_link_libraries(tidecoin_sign PRIVATE qgp_tidecoin_falcon)
target_compile_options(tidecoin_sign PRIVATE -O2 -Wall -Wextra -Werror)
set_target_properties(tidecoin_sign PROPERTIES OUTPUT_NAME tidecoin-sign SUFFIX .wasm)
target_link_options(tidecoin_sign PRIVATE -O2 --no-entry
    "-sSTANDALONE_WASM=1" "-sFILESYSTEM=0" "-sSTACK_SIZE=1048576"
    "-sINITIAL_MEMORY=4194304" "-sALLOW_MEMORY_GROWTH=0"
    "-sEXPORTED_FUNCTIONS=['_tdc_seed','_tdc_message','_tdc_public_key','_tdc_signature','_tdc_signature_length','_tdc_sign','_tdc_clear','_tdc_random','_tdc_verify']"
    -Wl,--export-memory -Wl,--gc-sections -Wl,--strip-all)
