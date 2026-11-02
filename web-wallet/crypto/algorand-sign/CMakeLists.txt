cmake_minimum_required(VERSION 3.16)
project(algorand_sign LANGUAGES C)
if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure with emcmake")
endif()
get_filename_component(DNA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
add_subdirectory("${DNA_ROOT}/shared/crypto/sign/algorand_falcon" "${CMAKE_CURRENT_BINARY_DIR}/falcon")
add_executable(algorand_sign "${CMAKE_CURRENT_SOURCE_DIR}/../algorand-sign-wasm.c")
target_include_directories(algorand_sign PRIVATE "${DNA_ROOT}/shared")
target_link_libraries(algorand_sign PRIVATE qgp_algorand_falcon)
target_compile_options(algorand_sign PRIVATE -O2 -Wall -Wextra -Werror)
set_target_properties(algorand_sign PROPERTIES OUTPUT_NAME algorand-sign SUFFIX .wasm)
target_link_options(algorand_sign PRIVATE -O2 --no-entry
    "-sSTANDALONE_WASM=1" "-sFILESYSTEM=0" "-sSTACK_SIZE=1048576"
    "-sINITIAL_MEMORY=4194304" "-sALLOW_MEMORY_GROWTH=0"
    "-sEXPORTED_FUNCTIONS=['_algo_seed','_algo_message','_algo_public_key','_algo_signature','_algo_signature_length','_algo_sign','_algo_clear']"
    -Wl,--export-memory -Wl,--gc-sections -Wl,--strip-all)
