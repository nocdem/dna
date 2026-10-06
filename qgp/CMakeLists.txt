cmake_minimum_required(VERSION 3.16)
project(qgp VERSION 0.1.0 LANGUAGES C)

# QGP phase 1 (signing): the `qgp` tool for the apt / validator package path.
# Bytes: docs/plans/2026-10-05-apt-qgp-signing-bytes.md items 1-3 + REV 2 (APPROVED).
# Linux only (Debian 12/13, Ubuntu 24.04 validators): memfd_create, flock.

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Paths (same layout as nodus/CMakeLists.txt) ─────────────────────
get_filename_component(QGP_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)
get_filename_component(MONOREPO_ROOT "${QGP_DIR}/.." ABSOLUTE)
set(SHARED_DIR "${MONOREPO_ROOT}/shared")

find_package(OpenSSL REQUIRED)       # qgp_sha3.c uses OpenSSL EVP SHA3-512

# ── Crypto sub-library (shared/): ML-DSA-87 pq-crystals reference ───
if(NOT TARGET dsa)
    add_subdirectory(${SHARED_DIR}/crypto/sign/dsa ${CMAKE_BINARY_DIR}/dsa)
endif()

# ── Shared crypto sources (as nodus standalone; qgp_log.c is replaced by
#    src/qgp_log_backend.c because it depends on the messenger's dna_config.h)
add_library(qgp_shared_crypto STATIC
    ${SHARED_DIR}/crypto/hash/qgp_sha3.c
    ${SHARED_DIR}/crypto/sign/qgp_dilithium.c
    ${SHARED_DIR}/crypto/utils/qgp_random.c
    ${SHARED_DIR}/crypto/utils/qgp_platform_linux.c
    src/qgp_log_backend.c
)
target_include_directories(qgp_shared_crypto PUBLIC ${SHARED_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(qgp_shared_crypto PUBLIC dsa OpenSSL::Crypto)
# dsa's randombytes is qgp_randombytes (shared/crypto/sign/dsa/randombytes.h),
# which lives in qgp_shared_crypto: a static-library cycle. Declaring it lets
# CMake repeat the pair on the link line (CMP0079, CMake >= 3.13).
target_link_libraries(dsa INTERFACE qgp_shared_crypto)

# ── qgp core library (everything except main) ───────────────────────
add_library(qgp_core STATIC
    src/qgp_core.c
    src/qgp_debver.c
    src/qgp_deb.c
    src/qgp_trust.c
    src/qgp_filesig.c
    src/qgp_io.c
    src/qgp_state.c
)
target_include_directories(qgp_core PUBLIC ${QGP_DIR}/src)
target_link_libraries(qgp_core PUBLIC qgp_shared_crypto)

set(QGP_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wno-sign-conversion)
target_compile_options(qgp_core PRIVATE ${QGP_WARNINGS})

add_executable(qgp src/main.c)
target_link_libraries(qgp PRIVATE qgp_core)
target_compile_options(qgp PRIVATE ${QGP_WARNINGS})

# ── Tests (built here; run only by the ORCHESTRATOR via ctest) ──────
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED json-c)

enable_testing()
add_executable(test_qgp_deb tests/test_qgp_deb.c)
target_include_directories(test_qgp_deb PRIVATE ${JSONC_INCLUDE_DIRS})
target_link_libraries(test_qgp_deb PRIVATE qgp_core ${JSONC_LIBRARIES})
target_compile_options(test_qgp_deb PRIVATE ${QGP_WARNINGS})
target_compile_definitions(test_qgp_deb PRIVATE
    QGP_KAT_PATH="${MONOREPO_ROOT}/scripts/qgp-sign/qgp_deb_kat.json")
add_test(NAME test_qgp_deb COMMAND test_qgp_deb)
