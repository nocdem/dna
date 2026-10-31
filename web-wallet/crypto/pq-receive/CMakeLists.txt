cmake_minimum_required(VERSION 3.16)
project(pq_receive_keygen LANGUAGES C)
if(NOT EMSCRIPTEN)
    message(FATAL_ERROR "Configure this standalone module with emcmake")
endif()
get_filename_component(DNA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
foreach(algorithm algorand_falcon tidecoin_falcon mldsa slhdsa)
    add_subdirectory("${DNA_ROOT}/shared/crypto/sign/${algorithm}"
        "${CMAKE_CURRENT_BINARY_DIR}/${algorithm}")
endforeach()
add_executable(pq_receive_keygen "${CMAKE_CURRENT_SOURCE_DIR}/../pq-receive-wasm.c")
target_include_directories(pq_receive_keygen PRIVATE "${DNA_ROOT}/shared")
target_link_libraries(pq_receive_keygen PRIVATE qgp_algorand_falcon
    qgp_tidecoin_falcon qgp_mldsa qgp_slhdsa)
set_target_properties(pq_receive_keygen PROPERTIES OUTPUT_NAME receive-keygen SUFFIX .wasm)
target_link_options(pq_receive_keygen PRIVATE
    -O2 --no-entry
    "-sSTANDALONE_WASM=1"
    "-sFILESYSTEM=0"
    "-sSTACK_SIZE=1048576"
    "-sINITIAL_MEMORY=4194304"
    "-sALLOW_MEMORY_GROWTH=0"
    "-sEXPORTED_FUNCTIONS=['_pq_receive_input','_pq_receive_output','_pq_receive_seed_size','_pq_receive_public_size','_pq_receive_derive','_pq_receive_clear']"
    -Wl,--export-memory -Wl,--gc-sections -Wl,--strip-all)
