# =============================================================================
# DNA Connect — libFuzzer targets (standalone build, clang only)
# =============================================================================
# Usage (messenger/docs/FUZZING.md has the full guide):
#   cd messenger/build && cmake .. && make -j$(nproc)        # libdna.so first
#   mkdir -p messenger/tests/fuzz/build && cd messenger/tests/fuzz/build
#   CC=clang cmake .. && make -j$(nproc)
#
# Why a separate project from tests/CMakeLists.txt's ENABLE_FUZZING block:
# every target here compiles the PARSER'S OWN SOURCE FILE into the fuzz
# executable with -fsanitize=fuzzer,address, so libFuzzer gets coverage from
# inside the parser. The older block links the five original harnesses
# against the gcc-built libdna.so, where the parser code carries no coverage
# instrumentation (the fuzzer then only sees the harness). Everything a
# target does not compile itself (shared crypto, gek.c, json-c, OpenSSL)
# still comes from libdna.so / the system, uninstrumented.
#
# Symbols the executable defines take precedence over libdna.so's, which is
# how fuzz_dht_stub.c replaces the nodus_ops I/O for the parsers that live
# inside DHT I/O files (dht_contactlist.c, dht_salt_agreement.c).
#
# NC-1 moved the parsers those I/O files call into messenger/codec/; each
# target compiles the codec unit as well, so the parser code is instrumented
# here instead of being resolved (uninstrumented) from libdna.so.
#
# Nothing here is registered with ctest; fuzzers are run by hand.
# =============================================================================

cmake_minimum_required(VERSION 3.10)
project(dna_fuzz C)

if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR
        "libFuzzer requires clang.\n"
        "Usage: CC=clang cmake ..")
endif()

get_filename_component(DNA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(MONOREPO_ROOT "${DNA_ROOT}/.." ABSOLUTE)
if(NOT DEFINED DNA_BUILD OR DNA_BUILD STREQUAL "")
    set(DNA_BUILD "${DNA_ROOT}/build")
endif()
set(SHARED_DIR "${MONOREPO_ROOT}/shared")
set(FUZZ_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

if(NOT EXISTS "${DNA_BUILD}/libdna.so")
    message(FATAL_ERROR
        "Main project not built. Run:\n"
        "  cd ${DNA_ROOT}/build && cmake .. && make -j$(nproc)\n"
        "Then try again.")
endif()

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)
pkg_check_modules(JSONC REQUIRED json-c)

# Same include set the messenger build uses for the dht_lib / dna sources
# compiled here (messenger/build/compile_commands.json).
include_directories(
    ${FUZZ_DIR}
    ${DNA_ROOT}
    ${DNA_ROOT}/include
    ${DNA_ROOT}/dht
    ${DNA_ROOT}/dht/client
    ${DNA_ROOT}/dht/shared
    ${MONOREPO_ROOT}/nodus/include
    ${MONOREPO_ROOT}/nodus/src
    ${SHARED_DIR}
    ${SHARED_DIR}/crypto
    ${MONOREPO_ROOT}/dnac/include
    ${SQLCIPHER_INCLUDE_DIRS}
    ${JSONC_INCLUDE_DIRS}
)
add_compile_definitions(NODUS_CHANNELS_DISABLED)

set(FUZZ_LIBS
    ${DNA_BUILD}/libdna.so
    ${JSONC_LIBRARIES}
    ${SQLCIPHER_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    pthread
    m
)
set(CMAKE_BUILD_RPATH "${DNA_BUILD}")

set(FUZZ_WARN -Wall -Wextra -Wno-unused-parameter)
set(FUZZ_CFLAGS -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1)

# add_fuzz_target(<name> <sources...>) — every source is instrumented
function(add_fuzz_target TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})
    target_compile_options(${TARGET_NAME} PRIVATE ${FUZZ_CFLAGS} ${FUZZ_WARN})
    target_link_options(${TARGET_NAME} PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(${TARGET_NAME} ${FUZZ_LIBS})
endfunction()

# ── Web Connect NC-5 targets ─────────────────────────────────────────────────
add_fuzz_target(fuzz_anchor_json
    ${FUZZ_DIR}/fuzz_anchor_json.c
    ${DNA_ROOT}/dht/client/dna_profile.c)

add_fuzz_target(fuzz_seal_decode
    ${FUZZ_DIR}/fuzz_seal_decode.c
    ${FUZZ_DIR}/fuzz_keys.c
    ${DNA_ROOT}/dna_api.c)

add_fuzz_target(fuzz_contactlist
    ${FUZZ_DIR}/fuzz_contactlist.c
    ${FUZZ_DIR}/fuzz_keys.c
    ${FUZZ_DIR}/fuzz_dht_stub.c
    ${DNA_ROOT}/dht/client/dht_contactlist.c
    ${DNA_ROOT}/codec/contactlist_codec.c
    ${DNA_ROOT}/dna_api.c)

add_fuzz_target(fuzz_salt_packet
    ${FUZZ_DIR}/fuzz_salt_packet.c
    ${FUZZ_DIR}/fuzz_keys.c
    ${FUZZ_DIR}/fuzz_dht_stub.c
    ${DNA_ROOT}/dht/shared/dht_salt_agreement.c
    ${DNA_ROOT}/codec/salt_agreement_codec.c)

# ── The original five harnesses, now with their parser instrumented ──────────
add_fuzz_target(fuzz_offline_queue
    ${FUZZ_DIR}/fuzz_offline_queue.c
    ${DNA_ROOT}/dht/shared/dht_offline_queue.c
    ${DNA_ROOT}/codec/offline_queue_codec.c)

add_fuzz_target(fuzz_contact_request
    ${FUZZ_DIR}/fuzz_contact_request.c
    ${DNA_ROOT}/dht/shared/dht_contact_request.c
    ${DNA_ROOT}/codec/contact_request_codec.c)

add_fuzz_target(fuzz_message_decrypt
    ${FUZZ_DIR}/fuzz_message_decrypt.c
    ${FUZZ_DIR}/fuzz_common.c
    ${DNA_ROOT}/dna_api.c)

add_fuzz_target(fuzz_profile_json
    ${FUZZ_DIR}/fuzz_profile_json.c)

add_fuzz_target(fuzz_base58
    ${FUZZ_DIR}/fuzz_base58.c
    ${SHARED_DIR}/crypto/utils/base58.c)

# ── Seed generator (ordinary program, ASan only) ─────────────────────────────
add_executable(fuzz_seed_gen
    ${FUZZ_DIR}/fuzz_seed_gen.c
    ${FUZZ_DIR}/fuzz_keys.c
    ${FUZZ_DIR}/fuzz_dht_stub.c
    ${DNA_ROOT}/dht/client/dht_contactlist.c
    ${DNA_ROOT}/codec/contactlist_codec.c
    ${DNA_ROOT}/dht/shared/dht_salt_agreement.c
    ${DNA_ROOT}/codec/salt_agreement_codec.c)
target_compile_options(fuzz_seed_gen PRIVATE
    -fsanitize=address -fno-omit-frame-pointer -g -O1 ${FUZZ_WARN})
target_link_options(fuzz_seed_gen PRIVATE -fsanitize=address)
target_link_libraries(fuzz_seed_gen ${FUZZ_LIBS})
